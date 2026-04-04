#ifndef MYLANG_SEMANTIC_TYPES_H
#define MYLANG_SEMANTIC_TYPES_H

#include "mylang/ast/AST.h"

typedef struct {
    const char *base_type;
    int pointer_level;
    int type_modifiers;
    int ref_kind;
    int is_array;
    int dims[8];
    int dims_count;
} SemanticTypeInfo;

void semantic_typeinfo_clear(SemanticTypeInfo *out);
int semantic_typeinfo_from_type_ast(ASTNode *type_node, SemanticTypeInfo *out);

#endif
