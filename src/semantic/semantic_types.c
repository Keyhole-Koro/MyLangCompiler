#include "mylang/semantic/semantic_internal.h"

void semantic_typeinfo_clear(SemanticTypeInfo *out) {
    if (!out) return;
    out->base_type = "";
    out->pointer_level = 0;
    out->type_modifiers = 0;
    out->ref_kind = REFKIND_NONE;
    out->is_array = 0;
    out->dims_count = 0;
    for (int i = 0; i < 8; i++) out->dims[i] = 0;
}

int semantic_typeinfo_from_type_ast(ASTNode *type_node, SemanticTypeInfo *out) {
    if (!out) return 0;
    semantic_typeinfo_clear(out);
    if (!type_node) return 0;

    int tmp_dims[8] = {0};
    int tmp_count = 0;
    ASTNode *node = type_node;
    while (node && node->type == AST_TYPE_ARRAY && tmp_count < 8) {
        tmp_dims[tmp_count++] = node->type_array.array_size;
        node = node->type_array.element_type;
    }

    if (!node) return 0;
    if (tmp_count > 0) out->is_array = 1;
    for (int i = 0; i < tmp_count; i++) {
        out->dims[i] = tmp_dims[tmp_count - 1 - i];
        out->dims_count++;
    }

    if (node->type != AST_TYPE) return 0;
    if (node->type_node.base_type && node->type_node.base_type->type == AST_IDENTIFIER) {
        out->base_type = node->type_node.base_type->identifier.name;
    }
    out->pointer_level = node->type_node.pointer_level;
    out->type_modifiers = node->type_node.type_modifiers;
    out->ref_kind = node->type_node.ref_kind;
    return 1;
}

int semantic_is_builtin_type(const char *base_type) {
    if (!base_type) return 0;
    return strcmp(base_type, "bool") == 0 ||
           strcmp(base_type, "u8") == 0 ||
           strcmp(base_type, "u16") == 0 ||
           strcmp(base_type, "i32") == 0 ||
           strcmp(base_type, "u32") == 0 ||
           strcmp(base_type, "char") == 0 ||
           strcmp(base_type, "float") == 0 ||
           strcmp(base_type, "double") == 0 ||
           strcmp(base_type, "long") == 0 ||
           strcmp(base_type, "short") == 0 ||
           strcmp(base_type, "void") == 0;
}
