#include "mylang/frontend/parser_internal.h"

static void fprint_indent(FILE *out, int indent) {
    for (int i = 0; i < indent; i++) fprintf(out, "  ");
}

int fprint_ast_decl_node(FILE *out, ASTNode *node, int indent);
int fprint_ast_stmt_node(FILE *out, ASTNode *node, int indent);
int fprint_ast_expr_node(FILE *out, ASTNode *node, int indent);

void print_ast(ASTNode *node, int indent) {
    fprint_ast(stdout, node, indent);
}

void fprint_ast(FILE *out, ASTNode *node, int indent) {
    if (!node) return;
    if (fprint_ast_decl_node(out, node, indent)) return;
    if (fprint_ast_stmt_node(out, node, indent)) return;
    if (fprint_ast_expr_node(out, node, indent)) return;
    fprint_indent(out, indent);
    fprintf(out, "Unknown AST Node Type: %d\n", node->type);
}
