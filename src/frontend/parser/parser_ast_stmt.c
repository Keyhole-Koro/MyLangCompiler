#include "mylang/frontend/parser_ast_internal.h"

ASTNode *new_expr_stmt(ASTNode *expr) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_EXPR_STMT;
    node->expr_stmt.expr = expr;
    return node;
}

ASTNode *new_while(ASTNode *cond, ASTNode *body) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_WHILE;
    node->while_stmt.cond = cond;
    node->while_stmt.body = body;
    return node;
}

ASTNode *new_do_while(ASTNode *cond, ASTNode *body) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_DO_WHILE;
    node->do_while_stmt.cond = cond;
    node->do_while_stmt.body = body;
    return node;
}

ASTNode *new_for(ASTNode *init, ASTNode *cond, ASTNode *inc, ASTNode *body) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_FOR;
    node->for_stmt.init = init;
    node->for_stmt.cond = cond;
    node->for_stmt.inc = inc;
    node->for_stmt.body = body;
    return node;
}

ASTNode *new_break() {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_BREAK;
    return node;
}

ASTNode *new_continue() {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_CONTINUE;
    return node;
}

ASTNode *new_if(ASTNode *cond, ASTNode *then_stmt, ASTNode *else_stmt) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_IF;
    node->if_stmt.cond = cond;
    node->if_stmt.then_stmt = then_stmt;
    node->if_stmt.else_stmt = else_stmt;
    return node;
}

ASTNode *new_return(ASTNode *expr) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_RETURN;
    node->ret.expr = expr;
    return node;
}

ASTNode *new_yield(ASTNode *expr) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_YIELD;
    node->yield_stmt.expr = expr;
    return node;
}

ASTNode *new_block(ASTNode **stmts, int count) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_BLOCK;
    node->block.stmts = stmts;
    node->block.count = count;
    return node;
}

ASTNode *new_unchecked_block(ASTNode *body) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_UNCHECKED;
    node->unchecked_block.body = body;
    return node;
}
