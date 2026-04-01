#include "mylang/semantic/semantic_internal.h"

void semantic_typeinfo_clear(SemanticTypeInfo *out) {
    if (!out) return;
    out->base_type = "";
    out->pointer_level = 0;
    out->type_modifiers = 0;
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
    return 1;
}
