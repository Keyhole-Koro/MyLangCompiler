#ifndef MYLANG_SEMANTIC_INTERNAL_H
#define MYLANG_SEMANTIC_INTERNAL_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mylang/semantic/semantic.h"
#include "mylang/semantic/semantic_types.h"

typedef struct {
    const char *name;
    int is_copy;
    int moved;
    int scope_depth;
    int is_param;
    int is_global;
    const char *borrowed_from;
    int borrow_is_mut;
    int shared_borrow_count;
    int mutable_borrow_active;
} SemanticBinding;

typedef struct {
    const char *filename;
    int error_count;
    int scope_depth;
    int function_depth;
    int binding_count;
    SemanticBinding bindings[256];
} SemanticContext;

typedef struct {
    int line;
    int col;
} SemanticLocation;

SemanticLocation semantic_location_unknown(void);
SemanticLocation semantic_location_from_ast(ASTNode *node);
void semantic_error_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...);
void semantic_walk_ast(SemanticContext *ctx, ASTNode *node);

#endif
