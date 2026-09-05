#include "mylang/semantic/semantic_types.h"

void semantic_typeinfo_clear(SemanticTypeInfo *out) {
    mylang_type_clear(out);
}

int semantic_typeinfo_from_type_ast(ASTNode *type_node, SemanticTypeInfo *out) {
    return mylang_type_from_ast(type_node, out);
}

int semantic_is_builtin_type(const char *base_type) {
    return mylang_type_is_builtin(base_type);
}
