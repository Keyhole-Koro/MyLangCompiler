#include "mylang/backend/codegen_internal.h"

const TypedefInfo *find_typedef(CompilerContext *cc, const char *alias) {
    for (int i = 0; i < cg_typedef_count; i++) {
        if (strcmp(cg_typedefs[i].alias, alias) == 0) return &cg_typedefs[i];
    }
    return NULL;
}

void resolve_type(CompilerContext *cc, TypeInfo *ti) {
    if (!ti || !ti->base_type) return;
    for (int depth = 0; depth < 10; depth++) {
        const TypedefInfo *td = find_typedef(cc, ti->base_type);
        if (!td) break;
        ti->base_type = td->info.base_type;
        ti->pointer_level += td->info.pointer_level;
        ti->type_modifiers |= td->info.type_modifiers;
        if (td->info.is_array) {
            ti->is_array = 1;
            int offset = ti->dims_count;
            int new_count = ti->dims_count + td->info.dims_count;
            if (new_count > 8) new_count = 8;
            for (int k = 0; k < td->info.dims_count && (offset + k) < 8; k++) {
                ti->dims[offset + k] = td->info.dims[k];
            }
            ti->dims_count = new_count;
        }
    }
}

const StructInfo *find_struct(CompilerContext *cc, const char *type_name) {
    for (int i = 0; i < cg_struct_count; i++) {
        if (strcmp(cg_structs[i].type_name, type_name) == 0) return &cg_structs[i];
    }
    return NULL;
}

const MemberInfo *find_member_info(CompilerContext *cc, const char *type_name, const char *member) {
    const StructInfo *si = find_struct(cc, type_name);
    if (!si) return NULL;
    for (int i = 0; i < si->member_count; i++)
        if (strcmp(si->members[i].name, member) == 0) return &si->members[i];
    return NULL;
}

int base_type_is_char(const char *name) {
    return name && strcmp(name, "char") == 0;
}

int ast_type_is_char_scalar(ASTNode *type_node) {
    if (!type_node || type_node->type != AST_TYPE) return 0;
    if (type_node->type_node.pointer_level != 0) return 0;
    ASTNode *bt = type_node->type_node.base_type;
    if (bt && bt->type == AST_IDENTIFIER)
        return base_type_is_char(bt->identifier.name);
    return 0;
}

int is_char_scalar_var(CompilerContext *cc, const char *name) {
    const LocalInfo *li = find_local_info(cc, name);
    if (!li) li = find_global_info(cc, name);
    return (li && li->pointer_level == 0 && !li->is_array && base_type_is_char(li->base_type));
}

int typeinfo_is_byte(const TypeInfo *info) {
    return info && info->pointer_level == 0 && info->dims_count == 0 && base_type_is_char(info->base_type);
}

int typeinfo_elem_size_bytes(CompilerContext *cc, const TypeInfo *info) {
    if (!info || !info->base_type) return SLOT_SIZE;
    if (base_type_is_char(info->base_type)) return 1;
    const StructInfo *si = find_struct(cc, info->base_type);
    if (si && si->size_bytes > 0) return si->size_bytes;
    return SLOT_SIZE;
}

int typeinfo_total_size_bytes(CompilerContext *cc, const TypeInfo *info) {
    if (!info) return SLOT_SIZE;
    if (info->pointer_level > 0 && info->dims_count == 0) return SLOT_SIZE;
    long sz = typeinfo_elem_size_bytes(cc, info);
    for (int i = 0; i < info->dims_count; i++) {
        int len = info->dims[i] > 0 ? info->dims[i] : 1;
        sz *= len;
    }
    if (sz <= 0) sz = SLOT_SIZE;
    return (int)sz;
}

const LocalInfo *find_local_info(CompilerContext *cc, const char *name) {
    for (int i = 0; i < cg_locals_count; i++) {
        if (strcmp(cg_locals_info[i].name, name) == 0) return &cg_locals_info[i];
    }
    return NULL;
}

const LocalInfo *find_global_info(CompilerContext *cc, const char *name) {
    for (int i = 0; i < cg_globals_count; i++) {
        if (strcmp(cg_globals_info[i].name, name) == 0) return &cg_globals_info[i];
    }
    return NULL;
}
