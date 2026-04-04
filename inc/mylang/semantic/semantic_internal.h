#ifndef MYLANG_SEMANTIC_INTERNAL_H
#define MYLANG_SEMANTIC_INTERNAL_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mylang/semantic/semantic.h"
#include "mylang/semantic/semantic_types.h"

typedef struct {
    int line;
    int col;
} SemanticLocation;

typedef struct {
    const char *name;
    int is_copy;
    int moved;
    int scope_depth;
    int is_param;
    int is_global;
    SemanticLocation decl_loc;
    SemanticLocation move_loc;
    const char *borrowed_from;
    int borrow_is_mut;
    int shared_borrow_count;
    int mutable_borrow_active;
    SemanticLocation last_shared_borrow_loc;
    SemanticLocation last_mut_borrow_loc;
} SemanticBinding;

typedef struct {
    const char *filename;
    int error_count;
    int scope_depth;
    int function_depth;
    int binding_count;
    SemanticBinding bindings[256];
} SemanticContext;

SemanticLocation semantic_location_unknown(void);
SemanticLocation semantic_location_from_ast(ASTNode *node);
void semantic_error_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...);
void semantic_note_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...);
void semantic_walk_ast(SemanticContext *ctx, ASTNode *node);

#endif
