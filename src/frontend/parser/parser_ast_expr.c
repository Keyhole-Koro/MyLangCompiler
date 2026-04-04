#include "mylang/frontend/parser_ast_internal.h"

ASTNode *new_binary(TokenKind op, ASTNode *left, ASTNode *right) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_BINARY;
    node->binary.op = op;
    node->binary.left = left;
    node->binary.right = right;
    return node;
}

ASTNode *new_unary(TokenKind op, ASTNode *operand) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_UNARY;
    node->unary.op = op;
    node->unary.operand = operand;
    return node;
}

ASTNode *new_borrow(ASTNode *expr) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_BORROW;
    node->borrow.expr = expr;
    return node;
}

ASTNode *new_borrow_mut(ASTNode *expr) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_BORROW_MUT;
    node->borrow_mut.expr = expr;
    return node;
}

ASTNode *new_cast(ASTNode *type, ASTNode *expr) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_CAST;
    node->cast.type = type;
    node->cast.expr = expr;
    return node;
}

ASTNode *new_assign(ASTNode *left, ASTNode *right) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_ASSIGN;
    node->assign.left = left;
    node->assign.right = right;
    return node;
}

ASTNode *new_ternary(ASTNode *cond, ASTNode *then_expr, ASTNode *else_expr) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_TERNARY;
    node->ternary.cond = cond;
    node->ternary.then_expr = then_expr;
    node->ternary.else_expr = else_expr;
    return node;
}

ASTNode *new_member_access(ASTNode *lhs, char *member_name) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_MEMBER_ACCESS;
    node->member_access.lhs = lhs;
    node->member_access.member = strdup(member_name);
    return node;
}

ASTNode *new_arrow_access(ASTNode *lhs, char *member_name) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_ARROW_ACCESS;
    node->arrow_access.lhs = lhs;
    node->arrow_access.member = strdup(member_name);
    return node;
}

ASTNode *new_init_list(ASTNode **elems, int count) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_INIT_LIST;
    node->init_list.elements = elems;
    node->init_list.count = count;
    return node;
}

ASTNode *new_stmt_expr(ASTNode *block) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_STMT_EXPR;
    node->stmt_expr.block = block;
    return node;
}

ASTNode *new_case_expr(ASTNode *target, CaseItem *cases, int case_count, ASTNode *default_expr) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_CASE;
    node->case_expr.target = target;
    node->case_expr.cases = cases;
    node->case_expr.case_count = case_count;
    node->case_expr.default_expr = default_expr;
    return node;
}

ASTNode *new_call(char *name, ASTNode **args, int arg_count) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_CALL;
    node->call.name = strdup(name);
    node->call.args = args;
    node->call.arg_count = arg_count;
    return node;
}
