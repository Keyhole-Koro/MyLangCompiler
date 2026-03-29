#ifndef MYLANG_FRONTEND_PARSER_REWRITE_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_REWRITE_INTERNAL_H

#include "mylang/frontend/parser_internal.h"

int rewrite_scope_contains(char **scope, int scope_count, const char *name);
char **rewrite_scope_alloc(int capacity);
char **rewrite_scope_clone(char **scope, int scope_count, int capacity);
void rewrite_scope_push(char ***scope, int *scope_count, int *scope_cap, char *name);
char **rewrite_scope_from_params(ASTNode *fn, int *scope_count, int *scope_cap);
void rewrite_scope_free(char **scope);
void rewrite_node(ASTNode *node, char **scope, int scope_count);

const char *lower_alias_lookup(FunAlias *aliases, int count, const char *name);
void lower_alias_push(FunAlias **aliases, int *count, const char *name, const char *target);
FunAlias *lower_alias_copy(FunAlias *aliases, int count, int *out_count);
void lower_alias_free_all(FunAlias *aliases, int count);
void lower_fun_literals_block(ASTNode *block, const char *func_prefix, FunAlias *aliases, int alias_count);
void ensure_no_fun_literals(ASTNode *node);

#endif
