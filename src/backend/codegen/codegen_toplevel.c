#include "mylang/backend/codegen_internal.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/resolver.h"

#include <limits.h>

static ASTNode *cg_fundef_with_name(ASTNode *node) {
    ASTNode *fn = cg_as_fundef(node);
    return (fn && fn->fundef.name) ? fn : NULL;
}

static ASTNode *cg_fundef_with_body(ASTNode *node) {
    ASTNode *fn = cg_fundef_with_name(node);
    return (fn && fn->fundef.body) ? fn : NULL;
}

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

static void append_type_alias(CompilerContext *cc, const char *alias, const char *base_type) {
    cg_typedefs = (TypedefInfo*)realloc(cg_typedefs, sizeof(TypedefInfo) * (cg_typedef_count + 1));
    cg_typedefs[cg_typedef_count].alias = alias;
    cg_typedefs[cg_typedef_count].info.base_type = base_type;
    cg_typedefs[cg_typedef_count].info.pointer_level = 0;
    cg_typedefs[cg_typedef_count].info.type_modifiers = 0;
    cg_typedefs[cg_typedef_count].info.is_array = 0;
    cg_typedefs[cg_typedef_count].info.dims_count = 0;
    for (int k = 0; k < 8; k++) cg_typedefs[cg_typedef_count].info.dims[k] = 0;
    cg_typedef_count++;
}

static void fill_member_info(CompilerContext *cc, ASTNode *mem, MemberInfo *out, int offset) {
    const char *mname = "";
    LocalInfo tmp = {0};
    int total_size_bytes = SLOT_SIZE;
    if (mem->type == AST_VAR_DECL) {
        mname = mem->var_decl.name ? mem->var_decl.name : "";
        set_localinfo_from_type(cc, &tmp, mem->var_decl.var_type);
        if (mem->var_decl.var_type) {
            TypeInfo ti = {0};
            if (typeinfo_from_type_ast(cc, mem->var_decl.var_type, &ti)) {
                total_size_bytes = typeinfo_total_size_bytes(cc, &ti);
            }
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
    out->size_bytes = typeinfo_elem_size_bytes(cc, &(TypeInfo){
        .base_type = tmp.base_type,
        .pointer_level = tmp.pointer_level,
        .type_modifiers = tmp.type_modifiers,
        .is_array = 0,
        .dims_count = 0,
    });
    out->offset = offset;
    out->total_size_bytes = total_size_bytes > 0 ? total_size_bytes : SLOT_SIZE;
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

// Per-parameter and return-type aggregate flags let a call site (gen_call)
// and the callee's own prologue (gen_func) agree on which words in the
// existing register/stack argument mechanism carry a value directly and
// which carry a hidden pointer instead (MLC-015).
static void append_func_sig(CompilerContext *cc, ASTNode *node) {
    ASTNode *fn = cg_fundef_with_name(node);
    if (!cc || !fn) return;
    if (find_func_sig(cc, fn->fundef.name)) return;
    cc->func_sigs = (FunctionSig*)realloc(cc->func_sigs, sizeof(FunctionSig) * (cc->func_sig_count + 1));
    FunctionSig *sig = &cc->func_sigs[cc->func_sig_count];
    sig->name = fn->fundef.name;
    sig->param_count = fn->fundef.param_count;
    sig->fixed_param_count =
        fn->fundef.is_variadic ? (fn->fundef.param_count - 1) : fn->fundef.param_count;
    sig->is_variadic = fn->fundef.is_variadic;
    sig->ret_size_bytes = fn->fundef.ret_type ? aggregate_type_size(cc, fn->fundef.ret_type) : 0;
    sig->ret_is_aggregate = sig->ret_size_bytes > 0;
    sig->param_is_aggregate = NULL;
    if (sig->param_count > 0) {
        sig->param_is_aggregate = (bool*)calloc((size_t)sig->param_count, sizeof(bool));
        for (int i = 0; i < sig->param_count; i++) {
            ASTNode *p = fn->fundef.params[i];
            if (p->param.is_rest) continue; // rest args are always i32
            sig->param_is_aggregate[i] = aggregate_type_size(cc, p->param.type) > 0;
        }
    }
    cc->func_sig_count++;
}

static void append_imported_func_sig(CompilerContext *cc, const char *name,
                                     const ResolverFunctionInfo *fn_info) {
    if (!cc || !name || !fn_info || find_func_sig(cc, name)) return;
    cc->func_sigs = (FunctionSig*)realloc(cc->func_sigs, sizeof(FunctionSig) * (cc->func_sig_count + 1));
    FunctionSig *sig = &cc->func_sigs[cc->func_sig_count];
    sig->name = strdup(name);
    sig->param_count = fn_info->param_count;
    sig->fixed_param_count = fn_info->is_variadic ? (fn_info->param_count - 1) : fn_info->param_count;
    sig->is_variadic = fn_info->is_variadic;
    sig->ret_size_bytes = aggregate_type_size(cc, fn_info->ret_type_ast);
    sig->ret_is_aggregate = sig->ret_size_bytes > 0;
    sig->param_is_aggregate = NULL;
    if (sig->param_count > 0) {
        sig->param_is_aggregate = (bool*)calloc((size_t)sig->param_count, sizeof(bool));
        for (int i = 0; i < sig->param_count; i++) {
            if (fn_info->params[i].is_rest) continue;
            sig->param_is_aggregate[i] = aggregate_type_size(cc, fn_info->params[i].type_ast) > 0;
        }
    }
    cc->func_sig_count++;
}

/*
 * Registers exported function signatures from an imported .mln source module
 * using the shared ModuleLoader and Resolver.
 */
static void append_import_sigs_from_source(CompilerContext *cc, ASTNode *node) {
    if (!cc || !node || node->type != AST_IMPORT || !node->import_stmt.path) return;
    if (!module_loader_is_mylang_source(node->import_stmt.path)) return;

    FrontendSession *session = cc->session;
    if (!session || !session->loader) return;

    const char *source_path = codegen_current_source_path();
    Module *mod = module_loader_load(session->loader, source_path, node->import_stmt.path);
    if (!mod || mod->state != MODULE_LOADED) return;

    int is_package_import = (node->import_stmt.symbol_count == 0);

    if (is_package_import) {
        for (int i = 0; i < mod->symbol_count; i++) {
            ModuleSymbol *sym = &mod->symbols[i];
            if (!sym->is_exported || sym->kind != SYMBOL_FUNCTION) continue;

            ResolverFunctionInfo fn_info;
            if (resolver_get_function_info(sym, &fn_info)) {
                append_imported_func_sig(cc, sym->link_name, &fn_info);
                resolver_free_function_info(&fn_info);
            }
        }
    } else {
        for (int i = 0; i < node->import_stmt.symbol_count; i++) {
            const char *req_name = node->import_stmt.symbols[i];
            if (!req_name) continue;

            ModuleSymbol *sym = resolver_lookup_import_symbol(node, mod, req_name);
            if (!sym || sym->kind != SYMBOL_FUNCTION) continue;

            ResolverFunctionInfo fn_info;
            if (resolver_get_function_info(sym, &fn_info)) {
                append_imported_func_sig(cc, sym->source_name, &fn_info);
                resolver_free_function_info(&fn_info);
            }
        }
    }
}

static void append_enum_info(CompilerContext *cc, ASTNode *node) {
    if (!cc || !node || node->type != AST_ENUM || !node->enum_stmt.name) return;
    append_type_alias(cc, node->enum_stmt.name, "i32");
    for (int i = 0; i < node->enum_stmt.member_count; i++) {
        ASTNode *member = node->enum_stmt.members[i];
        if (!member || member->type != AST_ENUM_MEMBER) continue;
        cc->enum_values = (EnumValueInfo*)realloc(cc->enum_values, sizeof(EnumValueInfo) * (cc->enum_value_count + 1));
        cc->enum_values[cc->enum_value_count].name = member->enum_member.name;
        cc->enum_values[cc->enum_value_count].value = member->enum_member.resolved_value;
        cc->enum_value_count++;
    }
}

void build_codegen_toplevel_info(CompilerContext *cc, ASTNode *root) {
    ASTNode *block = cg_as_block(root);
    cg_struct_count = 0;
    cg_structs = NULL;
    cg_typedef_count = 0;
    cg_typedefs = NULL;
    cc->func_sig_count = 0;
    cc->func_sigs = NULL;
    cc->enum_value_count = 0;
    cc->enum_values = NULL;
    if (!block) return;

    // Struct layouts have to exist before function signatures are registered:
    // append_func_sig/append_imported_func_sig now ask find_struct whether a
    // parameter or return type is an aggregate (MLC-015), and a struct's own
    // members can reference a typedef or an enum's constants, so the order
    // below is typedef/enum, then struct, then function -- each pass only
    // depending on tables the earlier ones already filled in.
    for (int i = 0; i < block->block.count; i++) {
        ASTNode *n = block->block.stmts[i];
        if (n->type == AST_TYPEDEF) {
            append_typedef_info(cc, n);
        } else if (n->type == AST_ENUM) {
            append_enum_info(cc, n);
        }
    }

    for (int i = 0; i < block->block.count; i++) {
        ASTNode *n = block->block.stmts[i];
        if (n->type == AST_TYPEDEF_STRUCT) {
            append_struct_info(cc, n->typedef_struct.typedef_name, n->typedef_struct.members, n->typedef_struct.member_count);
        } else if (n->type == AST_STRUCT && n->struct_stmt.name) {
            append_struct_info(cc, n->struct_stmt.name, n->struct_stmt.members, n->struct_stmt.member_count);
        }
    }

    for (int i = 0; i < block->block.count; i++) {
        ASTNode *n = block->block.stmts[i];
        if (cg_as_fundef(n)) {
            append_func_sig(cc, n);
        } else if (n->type == AST_IMPORT) {
            append_import_sigs_from_source(cc, n);
        }
    }
}

void collect_codegen_globals(CompilerContext *cc, ASTNode *root) {
    ASTNode *block = cg_as_block(root);
    if (!block) return;
    for (int i = 0; i < block->block.count; i++) {
        ASTNode *n = block->block.stmts[i];
        if (cg_as_var_decl(n)) {
            cg_globals_info = (LocalInfo*)realloc(cg_globals_info, sizeof(LocalInfo) * (cg_globals_count + 1));
            cg_globals_info[cg_globals_count].name = n->var_decl.name;
            set_localinfo_from_type(cc, &cg_globals_info[cg_globals_count], n->var_decl.var_type);
            cg_globals_count++;
            emit_global_decl(cc, n);
        }
    }
}

void emit_codegen_functions(CompilerContext *cc, ASTNode *root, StringBuilder *sb) {
    ASTNode *block = cg_as_block(root);
    if (!block) return;
    for (int i = 0; i < block->block.count; i++) {
        ASTNode *fn = cg_fundef_with_body(block->block.stmts[i]);
        if (fn && is_entry_name(fn->fundef.name)) {
            gen_func(cc, fn, sb);
            break;
        }
    }
    for (int i = 0; i < block->block.count; i++) {
        ASTNode *fn = cg_fundef_with_body(block->block.stmts[i]);
        if (fn && !is_entry_name(fn->fundef.name)) {
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
            sb_append(&final_sb, "import %s\n", cc->imports[i]);
        }
        sb_append(&final_sb, "\n");
    }
    if (cc->defined_func_count > 0) {
        sb_append(&final_sb, "; exports\n");
        for (int i = 0; i < cc->defined_func_count; i++) {
            /* Specializations (including their lowered lambdas) are local to
             * this object, even when the source template was exported. */
            if (!is_entry_name(cc->defined_funcs[i]) &&
                strncmp(cc->defined_funcs[i], "__mlg_", 6) != 0) {
                sb_append(&final_sb, "export %s\n", cc->defined_funcs[i]);
            }
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
    if (cc->func_sigs) {
        for (int i = 0; i < cc->func_sig_count; i++) {
            free(cc->func_sigs[i].param_is_aggregate);
        }
        free(cc->func_sigs);
        cc->func_sigs = NULL;
        cc->func_sig_count = 0;
    }
    if (cc->enum_values) {
        free(cc->enum_values);
        cc->enum_values = NULL;
        cc->enum_value_count = 0;
    }
}
