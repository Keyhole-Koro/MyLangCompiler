#ifndef MYLANG_FRONTEND_PARSER_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mylang/frontend/parser.h"
#include "mylang/frontend/lexer.h"
#include "mylang/ast/AST.h"
#include "mylang/frontend/parser_state_internal.h"

typedef struct FunAlias FunAlias;

static inline void set_node_loc_from_tokens(ASTNode *node, Token *primary, Token *fallback) {
    Token *tok = primary ? primary : fallback;
    if (!node) return;
    node->line = tok ? tok->line : 0;
    node->col = tok ? tok->col : 0;
}

void parse_error(const char *msg, Token *head, Token *cur);
int expect(Token **cur, TokenKind kind);
int is_type(TokenKind kind, Token *cur);
ASTNode *parse_expr_until_arrow(Token **cur);
int looks_like_function(Token *cur);
int looks_like_fun_literal(Token *cur);

ASTNode *parse_base_type(Token **cur);
void parse_struct_members(Token **cur, ASTNode ***members, int *member_count);
ASTNode *parse_struct(Token **cur);
ASTNode *parse_typedef(Token **cur);
ASTNode *parse_type(Token **cur);
ASTNode *parse_primary(Token **cur);
ASTNode *parse_postfix(Token **cur);
ASTNode *parse_unary(Token **cur);
ASTNode *parse_mul(Token **cur);
ASTNode *parse_add(Token **cur);
ASTNode *parse_shift(Token **cur);
ASTNode *parse_relational(Token **cur);
ASTNode *parse_equality(Token **cur);
ASTNode *parse_bitwise_and(Token **cur);
ASTNode *parse_bitwise_xor(Token **cur);
ASTNode *parse_bitwise_or(Token **cur);
ASTNode *parse_logical_and(Token **cur);
ASTNode *parse_logical_or(Token **cur);
ASTNode *parse_conditional(Token **cur);
ASTNode *parse_assign_expr(Token **cur);
ASTNode *parse_expr(Token **cur);
ASTNode *parse_param(Token **cur);
ASTNode **parse_param_list(Token **cur, int *out_count, bool *out_is_variadic);
ASTNode *parse_block(Token **cur);
ASTNode *parse_while_stmt(Token **cur);
ASTNode *parse_do_while_stmt(Token **cur);
ASTNode *parse_for_stmt(Token **cur);
ASTNode *parse_if_stmt(Token **cur);
ASTNode *parse_return_stmt(Token **cur);
ASTNode *parse_expr_stmt(Token **cur);
ASTNode *parse_variable_declaration(Token **cur, int need_semicolon);
ASTNode *parse_variable_assignment(Token **cur);
ASTNode *parse_stmt(Token **cur);
ASTNode *parse_fundef(Token **cur);
ASTNode *parse_import(Token **cur);
ASTNode *parse_toplevel(Token **cur);

void rewrite_node(ASTNode *node, char **scope, int scope_count);
void lower_fun_literals_block(ASTNode *block, const char *func_prefix, FunAlias *aliases, int alias_count);
void ensure_no_fun_literals(ASTNode *node);

#endif
#include <stdbool.h>
