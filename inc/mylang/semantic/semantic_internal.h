#ifndef MYLANG_SEMANTIC_INTERNAL_H
#define MYLANG_SEMANTIC_INTERNAL_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mylang/semantic/semantic.h"
#include "mylang/semantic/semantic_types.h"

typedef struct {
    const char *filename;
    int error_count;
} SemanticContext;

typedef struct {
    int line;
    int col;
} SemanticLocation;

SemanticLocation semantic_location_unknown(void);
void semantic_error_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...);
void semantic_walk_ast(SemanticContext *ctx, ASTNode *node);

#endif
