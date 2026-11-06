#include "mylang/semantic/semantic_internal.h"
#include "mylang/semantic/diagnostic_codes.h"

/* Reachability: whether control can pass from a statement to the one after
 * it. The answer errs towards "yes", so what this cannot see through asks the
 * programmer for a `return` rather than letting a missing one through. */

static int expr_completes(SemanticContext *ctx, ASTNode *expr);

static int is_constant_true(ASTNode *cond) {
    return cond && cond->type == AST_NUMBER && cond->number.value &&
           strtol(cond->number.value, NULL, 0) != 0;
}

typedef struct {
    ASTNodeType wanted;
    int found;
} LoopExitSearch;

/* A nested loop owns its own `break` and `continue`, and a function literal
 * is another function. A case arm owns neither, so it is searched. */
static void find_loop_exit(ASTNode **slot, void *data) {
    LoopExitSearch *search = data;
    ASTNode *node = *slot;
    if (!node || search->found) return;
    if (node->type == search->wanted) {
        search->found = 1;
        return;
    }
    if (node->type == AST_WHILE || node->type == AST_DO_WHILE ||
        node->type == AST_FOR || node->type == AST_FUN_LITERAL) return;
    ast_visit_children(node, find_loop_exit, search);
}

static int body_has_loop_exit(ASTNode *body, ASTNodeType wanted) {
    LoopExitSearch search = {wanted, 0};
    find_loop_exit(&body, &search);
    return search.found;
}

static int call_never_returns(SemanticContext *ctx, ASTNode *call) {
    SemanticFunctionSig *sig = semantic_find_function_sig(ctx, call->call.name);
    return sig && sig->declaration && sig->declaration->type == AST_FUNDEF &&
           sig->declaration->fundef.is_noreturn;
}

static int case_completes(SemanticContext *ctx, ASTNode *node) {
    if (!node->case_expr.default_expr && !node->case_expr.is_exhaustive) return 1;
    if (node->case_expr.default_is_noop) return 1;
    for (int i = 0; i < node->case_expr.case_count; i++) {
        CaseItem *item = &node->case_expr.cases[i];
        if (item->is_noop || !item->expr || expr_completes(ctx, item->expr)) return 1;
    }
    return node->case_expr.default_expr &&
           expr_completes(ctx, node->case_expr.default_expr);
}

static int expr_completes(SemanticContext *ctx, ASTNode *expr) {
    if (!expr) return 1;
    switch (expr->type) {
    case AST_STMT_EXPR:
        return semantic_stmt_completes(ctx, expr->stmt_expr.block);
    case AST_CASE:
        return case_completes(ctx, expr);
    case AST_CALL:
        return !call_never_returns(ctx, expr);
    case AST_ASSIGN:
        return expr_completes(ctx, expr->assign.right);
    default:
        return 1;
    }
}

int semantic_stmt_completes(SemanticContext *ctx, ASTNode *node) {
    if (!node) return 1;
    switch (node->type) {
    case AST_RETURN:
    case AST_BREAK:
    case AST_CONTINUE:
        return 0;
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++) {
            if (!semantic_stmt_completes(ctx, node->block.stmts[i])) return 0;
        }
        return 1;
    case AST_IF:
        return !node->if_stmt.else_stmt ||
               semantic_stmt_completes(ctx, node->if_stmt.then_stmt) ||
               semantic_stmt_completes(ctx, node->if_stmt.else_stmt);
    case AST_WHILE:
        return !is_constant_true(node->while_stmt.cond) ||
               body_has_loop_exit(node->while_stmt.body, AST_BREAK);
    case AST_FOR:
        return (node->for_stmt.cond && !is_constant_true(node->for_stmt.cond)) ||
               body_has_loop_exit(node->for_stmt.body, AST_BREAK);
    case AST_DO_WHILE:
        if (body_has_loop_exit(node->do_while_stmt.body, AST_BREAK)) return 1;
        if (is_constant_true(node->do_while_stmt.cond)) return 0;
        return semantic_stmt_completes(ctx, node->do_while_stmt.body) ||
               body_has_loop_exit(node->do_while_stmt.body, AST_CONTINUE);
    case AST_EXPR_STMT:
        return expr_completes(ctx, node->expr_stmt.expr);
    case AST_VAR_DECL:
        return expr_completes(ctx, node->var_decl.init);
    default:
        return expr_completes(ctx, node);
    }
}

void semantic_check_function_end(SemanticContext *ctx, ASTNode *fn) {
    SemanticLocation loc = semantic_location_from_ast(fn);
    const char *name = fn->fundef.name;
    int is_void = !fn->fundef.ret_type || semantic_type_is_void(fn->fundef.ret_type);

    if (fn->fundef.is_noreturn && !is_void) {
        semantic_error_code_at(ctx, loc, SEMCODE_NORETURN_RETURNS,
                               "@noreturn function '%s' must be declared void", name);
    }
    if (!fn->fundef.body || !semantic_stmt_completes(ctx, fn->fundef.body)) return;
    if (fn->fundef.is_noreturn) {
        semantic_error_code_at(ctx, loc, SEMCODE_NORETURN_RETURNS,
                               "@noreturn function '%s' can reach its end", name);
    } else if (!is_void) {
        semantic_error_code_at(ctx, loc, SEMCODE_MISSING_RETURN,
                               "'%s' can reach its end without returning a value", name);
    }
}
