#ifndef MYLANG_FRONTEND_PARSER_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mylang/frontend/parser.h"
#include "mylang/frontend/lexer.h"
#include "mylang/ast/AST.h"
#include "mylang/frontend/parser_state_internal.h"
#include "mylang/semantic/diagnostic_codes.h"

typedef struct FunAlias FunAlias;

static inline void set_node_loc_from_tokens(ASTNode *node, Token *primary, Token *fallback) {
    Token *tok = primary ? primary : fallback;
    if (!node) return;
    node->line = tok ? tok->line : 0;
    node->col = tok ? tok->col : 0;
    node->end_line = tok ? tok->line : 0;
    node->end_col = tok ? tok->col + tok->length : 0;
}

static inline void set_node_end_from_token(ASTNode *node, Token *tok) {
    if (!node || !tok) return;
    node->end_line = tok->line;
    node->end_col = tok->col + tok->length;
}

static inline void set_node_range_from_children(ASTNode *node, ASTNode *start, ASTNode *end) {
    if (!node) return;
    if (start) {
        node->line = start->line;
        node->col = start->col;
    }
    if (end) {
        node->end_line = end->end_line ? end->end_line : end->line;
        node->end_col = end->end_col ? end->end_col : end->col;
    }
}

void parse_error(ParserContext *context, const char *msg, Token *cur);
void parse_error_code(ParserContext *context, const char *code, const char *msg, Token *cur);
int expect(Token **cur, TokenKind kind);
int is_type(ParserContext *context, TokenKind kind, Token *cur);
ASTNode *parse_expr_until_arrow(ParserContext *context, Token **cur);
int looks_like_function(ParserContext *context, Token *cur);
int looks_like_generic_function(ParserContext *context, Token *cur);
Token *generic_function_type_params_start(ParserContext *context, Token *cur);
int looks_like_fun_literal(ParserContext *context, Token *cur);

ASTNode *parse_base_type(ParserContext *context, Token **cur);
void parse_struct_members(ParserContext *context, Token **cur, ASTNode ***members, int *member_count);
ASTNode *parse_struct(ParserContext *context, Token **cur);
ASTNode *parse_enum(ParserContext *context, Token **cur);
ASTNode *parse_typedef(ParserContext *context, Token **cur);
ASTNode *parse_type(ParserContext *context, Token **cur);
ASTNode *parse_primary(ParserContext *context, Token **cur);
ASTNode *parse_postfix(ParserContext *context, Token **cur);
ASTNode *parse_unary(ParserContext *context, Token **cur);
ASTNode *parse_mul(ParserContext *context, Token **cur);
ASTNode *parse_add(ParserContext *context, Token **cur);
ASTNode *parse_shift(ParserContext *context, Token **cur);
ASTNode *parse_relational(ParserContext *context, Token **cur);
ASTNode *parse_equality(ParserContext *context, Token **cur);
ASTNode *parse_bitwise_and(ParserContext *context, Token **cur);
ASTNode *parse_bitwise_xor(ParserContext *context, Token **cur);
ASTNode *parse_bitwise_or(ParserContext *context, Token **cur);
ASTNode *parse_logical_and(ParserContext *context, Token **cur);
ASTNode *parse_logical_or(ParserContext *context, Token **cur);
ASTNode *parse_conditional(ParserContext *context, Token **cur);
ASTNode *parse_assign_expr(ParserContext *context, Token **cur);
ASTNode *parse_expr(ParserContext *context, Token **cur);
ASTNode *parse_param(ParserContext *context, Token **cur);
ASTNode **parse_param_list(ParserContext *context, Token **cur, int *out_count, bool *out_is_variadic);
ASTNode *parse_block(ParserContext *context, Token **cur);
ASTNode *parse_while_stmt(ParserContext *context, Token **cur);
ASTNode *parse_do_while_stmt(ParserContext *context, Token **cur);
ASTNode *parse_for_stmt(ParserContext *context, Token **cur);
ASTNode *parse_if_stmt(ParserContext *context, Token **cur);
ASTNode *parse_return_stmt(ParserContext *context, Token **cur);
ASTNode *parse_expr_stmt(ParserContext *context, Token **cur);
ASTNode *parse_variable_declaration(ParserContext *context, Token **cur, int need_semicolon);
ASTNode *parse_variable_assignment(ParserContext *context, Token **cur);
ASTNode *parse_stmt(ParserContext *context, Token **cur);
ASTNode *parse_fundef(ParserContext *context, Token **cur);
ASTNode *parse_generic_fundef(ParserContext *context, Token **cur);
char **parse_type_params(ParserContext *context, Token **cur, int *out_count, int add_to_scope);
ASTNode **parse_type_args(ParserContext *context, Token **cur, int *out_count);
void instantiate_generics(ParserContext *context, ASTNode *program);
void load_imported_generic_templates(ParserContext *context, ASTNode *import_node, const char *source_path);
ASTNode *parse_import(ParserContext *context, Token **cur);
ASTNode *parse_toplevel(ParserContext *context, Token **cur);
ASTNode *parse_program_syntax(ParserContext *context, Token **cur);

void rewrite_node(ParserContext *context, ASTNode *node, char **scope, int scope_count);
void lower_fun_literals_block(ParserContext *context, ASTNode *block, const char *func_prefix, FunAlias *aliases, int alias_count);
void ensure_no_fun_literals(ASTNode *node);

#endif
#include <stdbool.h>
