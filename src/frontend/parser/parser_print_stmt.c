#include "mylang/frontend/parser_internal.h"

static void fprint_indent(FILE *out, int indent) {
    for (int i = 0; i < indent; i++) fprintf(out, "  ");
}

int fprint_ast_stmt_node(FILE *out, ASTNode *node, int indent) {
    switch (node->type) {
    case AST_EXPR_STMT:
        fprint_indent(out, indent); fprintf(out, "ExprStmt\n");
        fprint_ast(out, node->expr_stmt.expr, indent + 1);
        return 1;
    case AST_IF:
        fprint_indent(out, indent); fprintf(out, "If\n");
        fprint_ast(out, node->if_stmt.cond, indent + 1);
        fprint_ast(out, node->if_stmt.then_stmt, indent + 1);
        if (node->if_stmt.else_stmt) fprint_ast(out, node->if_stmt.else_stmt, indent + 1);
        return 1;
    case AST_RETURN:
        fprint_indent(out, indent); fprintf(out, "Return\n");
        fprint_ast(out, node->ret.expr, indent + 1);
        return 1;
    case AST_YIELD:
        fprint_indent(out, indent); fprintf(out, "Yield\n");
        fprint_ast(out, node->yield_stmt.expr, indent + 1);
        return 1;
    case AST_BLOCK:
        fprint_indent(out, indent); fprintf(out, "Block\n");
        for (int i = 0; i < node->block.count; i++) fprint_ast(out, node->block.stmts[i], indent + 1);
        return 1;
    case AST_STMT_EXPR:
        fprint_indent(out, indent); fprintf(out, "StmtExpr\n");
        fprint_ast(out, node->stmt_expr.block, indent + 1);
        return 1;
    case AST_WHILE:
        fprint_indent(out, indent); fprintf(out, "While\n");
        fprint_ast(out, node->while_stmt.cond, indent + 1);
        fprint_ast(out, node->while_stmt.body, indent + 1);
        return 1;
    case AST_FOR:
        fprint_indent(out, indent); fprintf(out, "For\n");
        if (node->for_stmt.init) {
            fprint_indent(out, indent); fprintf(out, "  Init:\n");
            fprint_ast(out, node->for_stmt.init, indent + 2);
        }
        if (node->for_stmt.cond) {
            fprint_indent(out, indent); fprintf(out, "  Cond:\n");
            fprint_ast(out, node->for_stmt.cond, indent + 2);
        }
        if (node->for_stmt.inc) {
            fprint_indent(out, indent); fprintf(out, "  Inc:\n");
            fprint_ast(out, node->for_stmt.inc, indent + 2);
        }
        fprint_ast(out, node->for_stmt.body, indent + 1);
        return 1;
    case AST_BREAK:
        fprint_indent(out, indent); fprintf(out, "Break\n");
        return 1;
    case AST_CONTINUE:
        fprint_indent(out, indent); fprintf(out, "Continue\n");
        return 1;
    default:
        return 0;
    }
}
