#ifndef MYLANG_TYPE_TYPE_INFO_H
#define MYLANG_TYPE_TYPE_INFO_H

#include "mylang/ast/AST.h"

#define MYLANG_TYPE_MAX_DIMS 8

/* Phase-neutral type shape. Names remain borrowed from the AST or symbol
 * tables; ownership stays with the phase that created them. */
typedef struct MylangType {
    const char *base_type;
    int pointer_level;
    int type_modifiers;
    int ref_kind;
    int is_array;
    int dims[MYLANG_TYPE_MAX_DIMS];
    int dims_count;
} MylangType;

void mylang_type_clear(MylangType *type);
int mylang_type_from_ast(const ASTNode *type_node, MylangType *out);
int mylang_type_is_builtin(const char *base_type);

#endif
