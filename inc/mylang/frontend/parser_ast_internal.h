#ifndef MYLANG_FRONTEND_PARSER_AST_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_AST_INTERNAL_H

#include "mylang/frontend/parser_internal.h"

ASTNode *new_string_literal(char *str);
ASTNode *new_char_literal(char *str);
ASTNode *new_sizeof(ASTNode *expr);
ASTNode *new_type_array(ASTNode *elem_type, int size);
ASTNode *new_var_decl(ASTNode *type, char *name, ASTNode *init);
ASTNode *new_param(ASTNode *type, char *name);
ASTNode *new_fundef(ASTNode *ret_type, char *name, ASTNode **params, int param_count, ASTNode *body);
ASTNode *new_fun_literal(ASTNode **params, int param_count, ASTNode *body);
ASTNode *new_number(char *val);
ASTNode *new_identifier(char *name);
ASTNode *new_binary(TokenKind op, ASTNode *left, ASTNode *right);
ASTNode *new_unary(TokenKind op, ASTNode *operand);
ASTNode *new_cast(ASTNode *type, ASTNode *expr);
ASTNode *new_assign(ASTNode *left, ASTNode *right);
ASTNode *new_ternary(ASTNode *cond, ASTNode *then_expr, ASTNode *else_expr);
ASTNode *new_type_node(ASTNode *base_type, int pointer_level, int modifiers);
ASTNode *new_expr_stmt(ASTNode *expr);
ASTNode *new_typedef(ASTNode *src_type, char *alias);
ASTNode *new_typedef_struct(char *struct_name, ASTNode **members, int member_count, char *typedef_name);
ASTNode *new_struct(char *name, ASTNode **members, int member_count);
ASTNode *new_import_stmt(char *path, char **symbols, int count);
ASTNode *new_member_access(ASTNode *lhs, char *member_name);
ASTNode *new_arrow_access(ASTNode *lhs, char *member_name);
ASTNode *new_struct_member(char *type, char *name);
ASTNode *new_init_list(ASTNode **elems, int count);
ASTNode *new_while(ASTNode *cond, ASTNode *body);
ASTNode *new_do_while(ASTNode *cond, ASTNode *body);
ASTNode *new_for(ASTNode *init, ASTNode *cond, ASTNode *inc, ASTNode *body);
ASTNode *new_break(void);
ASTNode *new_continue(void);
ASTNode *new_if(ASTNode *cond, ASTNode *then_stmt, ASTNode *else_stmt);
ASTNode *new_return(ASTNode *expr);
ASTNode *new_yield(ASTNode *expr);
ASTNode *new_block(ASTNode **stmts, int count);
ASTNode *new_stmt_expr(ASTNode *block);
ASTNode *new_case_expr(ASTNode *target, CaseItem *cases, int case_count, ASTNode *default_expr);
ASTNode *new_call(char *name, ASTNode **args, int arg_count);

#endif
