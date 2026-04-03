#include "mylang/semantic/semantic_internal.h"

SemanticLocation semantic_location_unknown(void) {
    SemanticLocation loc;
    loc.line = 0;
    loc.col = 0;
    return loc;
}

SemanticLocation semantic_location_from_ast(ASTNode *node) {
    SemanticLocation loc = semantic_location_unknown();

    if (!node) return loc;
    if (node->line > 0 || node->col > 0) {
        loc.line = node->line;
        loc.col = node->col;
        return loc;
    }

    switch (node->type) {
    case AST_MEMBER_ACCESS:
        return semantic_location_from_ast(node->member_access.lhs);
    case AST_ARROW_ACCESS:
        return semantic_location_from_ast(node->arrow_access.lhs);
    case AST_UNARY:
        return semantic_location_from_ast(node->unary.operand);
    case AST_BORROW:
        return semantic_location_from_ast(node->borrow.expr);
    case AST_BORROW_MUT:
        return semantic_location_from_ast(node->borrow_mut.expr);
    case AST_ASSIGN:
        return semantic_location_from_ast(node->assign.left);
    case AST_EXPR_STMT:
        return semantic_location_from_ast(node->expr_stmt.expr);
    case AST_RETURN:
        return semantic_location_from_ast(node->ret.expr);
    default:
        return loc;
    }
}

void semantic_error_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "%s:%d:%d: error: ",
            (ctx && ctx->filename) ? ctx->filename : "<input>",
            loc.line,
            loc.col);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    if (ctx) ctx->error_count++;
}
