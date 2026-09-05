#include "mylang/backend/codegen_internal.h"

void set_localinfo_from_type(CompilerContext *cc, LocalInfo *info, ASTNode *type_node) {
    MylangType type;

    if (!info) return;
    info->base_type = "";
    info->pointer_level = 0;
    info->type_modifiers = 0;
    info->is_array = 0;
    info->array_length = 0;
    info->dims_count = 0;
    for (int i = 0; i < 8; i++) info->dims[i] = 0;
    if (!mylang_type_from_ast(type_node, &type)) return;

    info->base_type = type.base_type;
    info->pointer_level = type.pointer_level + (type.ref_kind != REFKIND_NONE);
    info->type_modifiers = type.type_modifiers;
    info->is_array = type.is_array;
    info->dims_count = type.dims_count;
    for (int i = 0; i < type.dims_count; i++) info->dims[i] = type.dims[i];
    if (info->is_array && info->dims_count > 0) info->array_length = info->dims[0];

    TypeInfo ti;
    ti.base_type = info->base_type;
    ti.pointer_level = info->pointer_level;
    ti.type_modifiers = info->type_modifiers;
    ti.ref_kind = REFKIND_NONE;
    ti.is_array = info->is_array;
    ti.dims_count = info->dims_count;
    for (int i = 0; i < 8; i++) ti.dims[i] = info->dims[i];

    resolve_type(cc, &ti);

    info->base_type = ti.base_type;
    info->pointer_level = ti.pointer_level;
    info->type_modifiers = ti.type_modifiers;
    info->is_array = ti.is_array;
    info->dims_count = ti.dims_count;
    for (int i = 0; i < 8; i++) info->dims[i] = ti.dims[i];
    if (info->is_array && info->dims_count > 0) info->array_length = info->dims[0];
}

int typeinfo_from_type_ast(CompilerContext *cc, ASTNode *type_node, TypeInfo *out) {
    if (!out) return 0;
    LocalInfo tmp = {0};
    set_localinfo_from_type(cc, &tmp, type_node);
    out->base_type = tmp.base_type;
    out->pointer_level = tmp.pointer_level;
    out->type_modifiers = tmp.type_modifiers;
    out->is_array = tmp.is_array;
    out->dims_count = tmp.dims_count;
    for (int i = 0; i < tmp.dims_count && i < 8; i++) out->dims[i] = tmp.dims[i];
    return tmp.base_type != NULL;
}
