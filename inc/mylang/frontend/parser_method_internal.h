#ifndef MYLANG_FRONTEND_PARSER_METHOD_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_METHOD_INTERNAL_H

#include "mylang/frontend/parser_internal.h"

/* name -> declared type AST (borrowed from the declaration; never owned
 * here). */
typedef struct {
    char **names;
    ASTNode **types;
    int count;
    int cap;
} MethodScope;

/* An expression's static shape: base type name (borrowed from the type AST)
 * plus pointer level and borrow kind. Arrays and modifiers don't matter to
 * what asks, so they're not tracked here. */
typedef struct {
    const char *base_name;
    int pointer_level;
    int borrow_kind;
} RecvShape;

void method_scope_push(MethodScope *scope, const char *name, ASTNode *type);
ASTNode *method_scope_lookup(MethodScope *scope, const char *name);
MethodScope method_scope_clone(MethodScope *src);
void method_scope_free(MethodScope *scope);

/* Makes infer_recv_shape() see `program`: its struct layouts and its imports. */
void method_shapes_begin(ParserContext *context, ASTNode *program);
int infer_recv_shape(ParserContext *ctx, MethodScope *scope, ASTNode *expr, RecvShape *out);

#endif
