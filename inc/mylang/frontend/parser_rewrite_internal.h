#ifndef MYLANG_FRONTEND_PARSER_REWRITE_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_REWRITE_INTERNAL_H

#include "mylang/frontend/parser_internal.h"

int rewrite_scope_contains(char **scope, int scope_count, const char *name);
char **rewrite_scope_alloc(int capacity);
char **rewrite_scope_clone(char **scope, int scope_count, int capacity);
void rewrite_scope_push(char ***scope, int *scope_count, int *scope_cap, char *name);
char **rewrite_scope_from_params(ASTNode *fn, int *scope_count, int *scope_cap);
void rewrite_scope_free(char **scope);
void rewrite_node(ParserContext *context, ASTNode *node, char **scope, int scope_count);

const char *lower_alias_lookup(FunAlias *aliases, int count, const char *name);
void lower_alias_push(FunAlias **aliases, int *count, const char *name, const char *target);
FunAlias *lower_alias_copy(FunAlias *aliases, int count, int *out_count);
void lower_alias_free_all(FunAlias *aliases, int count);
void lower_fun_literals_block(ParserContext *context, ASTNode *block, const char *func_prefix, FunAlias *aliases, int alias_count);
void ensure_no_fun_literals(ASTNode *node);

/* Rewrites every `recv.method(args)` / `recv->method(args)` call in the
 * program into an ordinary call to `<ReceiverType>__method`, with `recv`
 * (auto-ref'd/deref'd as the method's declared receiver needs) moved into
 * args[0]. Must run once every method in the file has been parsed and added
 * to the method table (parser_state_tables.c's add_method) -- i.e. after
 * parsing completes, from frontend_pipeline.c's lower_program(). */
void resolve_method_calls(ParserContext *context, ASTNode *program);
void ensure_no_unresolved_method_calls(ASTNode *node);

#endif
