#include "mylang/backend/codegen_internal.h"

static void append_typedef_info(CompilerContext *cc, ASTNode *node) {
    LocalInfo tmp = {0};
    set_localinfo_from_type(cc, &tmp, node->typedef_stmt.src_type);

    cg_typedefs = (TypedefInfo*)realloc(cg_typedefs, sizeof(TypedefInfo) * (cg_typedef_count + 1));
    cg_typedefs[cg_typedef_count].alias = node->typedef_stmt.alias;
    cg_typedefs[cg_typedef_count].info.base_type = tmp.base_type;
    cg_typedefs[cg_typedef_count].info.pointer_level = tmp.pointer_level;
    cg_typedefs[cg_typedef_count].info.type_modifiers = tmp.type_modifiers;
    cg_typedefs[cg_typedef_count].info.is_array = tmp.is_array;
    cg_typedefs[cg_typedef_count].info.dims_count = tmp.dims_count;
    for (int k = 0; k < 8; k++) cg_typedefs[cg_typedef_count].info.dims[k] = tmp.dims[k];
    cg_typedef_count++;
}

static void fill_member_info(CompilerContext *cc, ASTNode *mem, MemberInfo *out, int offset) {
    const char *mname = "";
    LocalInfo tmp = {0};
    int member_slots = 1;
    if (mem->type == AST_VAR_DECL) {
        mname = mem->var_decl.name ? mem->var_decl.name : "";
        set_localinfo_from_type(cc, &tmp, mem->var_decl.var_type);
        if (mem->var_decl.var_type) {
            member_slots = slots_for_type(cc, mem->var_decl.var_type);
            if (member_slots < 1) member_slots = 1;
        }
    } else if (mem->type == AST_STRUCT_MEMBER) {
        mname = mem->struct_member.name ? mem->struct_member.name : "";
        tmp.base_type = mem->struct_member.type ? mem->struct_member.type : "";
        tmp.pointer_level = 0;
        tmp.is_array = 0;
        tmp.array_length = 0;
    } else {
        tmp.base_type = "";
        tmp.pointer_level = 0;
        tmp.is_array = 0;
        tmp.array_length = 0;
    }
    out->name = mname;
    out->base_type = tmp.base_type ? tmp.base_type : "";
    out->pointer_level = tmp.pointer_level;
    out->is_array = tmp.is_array;
    out->array_length = tmp.array_length;
    out->size_bytes = (tmp.pointer_level == 0 && !tmp.is_array && base_type_is_char(tmp.base_type)) ? 1 : SLOT_SIZE;
    out->offset = offset;
    out->total_size_bytes = member_slots * SLOT_SIZE;
}

static void append_struct_info(CompilerContext *cc, const char *type_name, ASTNode **members_ast, int count) {
    MemberInfo *members = NULL;
    int struct_bytes = 0;
    if (count > 0) {
        members = (MemberInfo*)malloc(sizeof(MemberInfo) * count);
        int offset = 0;
        for (int m = 0; m < count; m++) {
            fill_member_info(cc, members_ast[m], &members[m], offset);
            offset += members[m].total_size_bytes;
        }
        struct_bytes = offset;
    }
    cg_structs = (StructInfo*)realloc(cg_structs, sizeof(StructInfo) * (cg_struct_count + 1));
    cg_structs[cg_struct_count].type_name = type_name;
    cg_structs[cg_struct_count].members = members;
    cg_structs[cg_struct_count].member_count = count;
    cg_structs[cg_struct_count].size_bytes = struct_bytes > 0 ? struct_bytes : SLOT_SIZE;
    cg_struct_count++;
}

void build_codegen_toplevel_info(CompilerContext *cc, ASTNode *root) {
    cg_struct_count = 0;
    cg_structs = NULL;
    cg_typedef_count = 0;
    cg_typedefs = NULL;
    if (!root || root->type != AST_BLOCK) return;

    for (int i = 0; i < root->block.count; i++) {
        ASTNode *n = root->block.stmts[i];
        if (n->type == AST_TYPEDEF) {
            append_typedef_info(cc, n);
        }
    }

    for (int i = 0; i < root->block.count; i++) {
        ASTNode *n = root->block.stmts[i];
        if (n->type == AST_TYPEDEF_STRUCT) {
            append_struct_info(cc, n->typedef_struct.typedef_name, n->typedef_struct.members, n->typedef_struct.member_count);
        } else if (n->type == AST_STRUCT && n->struct_stmt.name) {
            append_struct_info(cc, n->struct_stmt.name, n->struct_stmt.members, n->struct_stmt.member_count);
        }
    }
}

void collect_codegen_globals(CompilerContext *cc, ASTNode *root) {
    if (!root || root->type != AST_BLOCK) return;
    for (int i = 0; i < root->block.count; i++) {
        ASTNode *n = root->block.stmts[i];
        if (n->type == AST_VAR_DECL) {
            cg_globals_info = (LocalInfo*)realloc(cg_globals_info, sizeof(LocalInfo) * (cg_globals_count + 1));
            cg_globals_info[cg_globals_count].name = n->var_decl.name;
            set_localinfo_from_type(cc, &cg_globals_info[cg_globals_count], n->var_decl.var_type);
            cg_globals_count++;
            emit_global_decl(cc, n);
        }
    }
}

void emit_codegen_functions(CompilerContext *cc, ASTNode *root, StringBuilder *sb) {
    if (!root || root->type != AST_BLOCK) return;
    for (int i = 0; i < root->block.count; i++) {
        ASTNode *fn = root->block.stmts[i];
        if (fn->type == AST_FUNDEF && is_entry_name(fn->fundef.name)) {
            gen_func(cc, fn, sb);
            break;
        }
    }
    for (int i = 0; i < root->block.count; i++) {
        ASTNode *fn = root->block.stmts[i];
        if (fn->type == AST_FUNDEF && !is_entry_name(fn->fundef.name)) {
            gen_func(cc, fn, sb);
        }
    }
}

char *prepend_codegen_imports(CompilerContext *cc, StringBuilder *body) {
    StringBuilder final_sb;
    sb_init(&final_sb);
    if (cc->import_count > 0) {
        sb_append(&final_sb, "; imports\n");
        for (int i = 0; i < cc->import_count; i++) {
            sb_append(&final_sb, "import f_%s\n", cc->imports[i]);
        }
        sb_append(&final_sb, "\n");
    }
    sb_append(&final_sb, "%s", body->buf ? body->buf : "");
    return sb_dump(&final_sb);
}

void cleanup_codegen_context(CompilerContext *cc) {
    if (cg_structs) {
        for (int i = 0; i < cg_struct_count; i++) {
            free(cg_structs[i].members);
        }
        free(cg_structs);
        cg_structs = NULL;
        cg_struct_count = 0;
    }
    if (cg_typedefs) {
        free(cg_typedefs);
        cg_typedefs = NULL;
        cg_typedef_count = 0;
    }
    if (cg_globals_info) {
        free(cg_globals_info);
        cg_globals_info = NULL;
        cg_globals_count = 0;
    }
    if (cg_strings) {
        for (int i = 0; i < cg_string_count; i++) {
            free(cg_strings[i].text);
            free(cg_strings[i].label);
        }
        free(cg_strings);
        cg_strings = NULL;
        cg_string_count = 0;
    }
    if (cg_data_sb_inited) {
        sb_free(&cg_data_sb);
        cg_data_sb_inited = 0;
    }
    if (cc->imports) {
        for (int i = 0; i < cc->import_count; i++) free(cc->imports[i]);
        free(cc->imports);
        cc->imports = NULL;
        cc->import_count = 0;
    }
    if (cc->defined_funcs) {
        free(cc->defined_funcs);
        cc->defined_funcs = NULL;
        cc->defined_func_count = 0;
    }
}
