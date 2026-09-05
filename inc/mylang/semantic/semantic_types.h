#ifndef MYLANG_SEMANTIC_TYPES_H
#define MYLANG_SEMANTIC_TYPES_H

#include "mylang/type/type_info.h"

typedef MylangType SemanticTypeInfo;

void semantic_typeinfo_clear(SemanticTypeInfo *out);
int semantic_typeinfo_from_type_ast(ASTNode *type_node, SemanticTypeInfo *out);
int semantic_is_builtin_type(const char *base_type);

#endif
