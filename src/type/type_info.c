#include <string.h>

#include "mylang/type/type_info.h"

void mylang_type_clear(MylangType *type) {
    if (!type) return;
    *type = (MylangType){
        .base_type = "",
        .ref_kind = REFKIND_NONE,
    };
}

int mylang_type_from_ast(const ASTNode *type_node, MylangType *out) {
    int dimensions[MYLANG_TYPE_MAX_DIMS] = {0};
    int dimension_count = 0;
    const ASTNode *node = type_node;

    if (!out) return 0;
    mylang_type_clear(out);
    if (!node) return 0;

    while (node && node->type == AST_TYPE_ARRAY &&
           dimension_count < MYLANG_TYPE_MAX_DIMS) {
        dimensions[dimension_count++] = node->type_array.array_size;
        node = node->type_array.element_type;
    }
    if (!node || node->type != AST_TYPE) return 0;

    out->is_array = dimension_count > 0;
    out->dims_count = dimension_count;
    for (int i = 0; i < dimension_count; i++) {
        out->dims[i] = dimensions[dimension_count - 1 - i];
    }

    if (node->type_node.base_type &&
        node->type_node.base_type->type == AST_IDENTIFIER) {
        out->base_type = node->type_node.base_type->identifier.name;
    }
    out->pointer_level = node->type_node.pointer_level;
    out->type_modifiers = node->type_node.type_modifiers;
    out->ref_kind = node->type_node.ref_kind;
    return 1;
}

int mylang_type_is_builtin(const char *base_type) {
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
