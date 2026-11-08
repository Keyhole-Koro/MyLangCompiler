#include "mylang/frontend/parser_rewrite_internal.h"

/* Verifies that parser lowering removed every transient function literal node
 * before semantic analysis and code generation consume the AST. */

static void find_fun_literal(ASTNode **slot, void *unused) {
    ASTNode *node = *slot;
    (void)unused;
    if (!node) return;
    if (node->type == AST_FUN_LITERAL) {
        fprintf(stderr, "internal error: leftover function literal after lowering\n");
        exit(1);
    }
    ast_visit_children(node, find_fun_literal, NULL);
}

void ensure_no_fun_literals(ASTNode *node) {
    find_fun_literal(&node, NULL);
}
