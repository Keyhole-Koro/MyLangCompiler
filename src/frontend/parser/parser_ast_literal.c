#include "mylang/frontend/parser_ast_internal.h"

ASTNode *new_string_literal(char *str) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_STRING_LITERAL;
    node->string_literal.value = strdup(str);
    return node;
}

ASTNode *new_char_literal(char *str) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_CHAR_LITERAL;
    node->char_literal.value = strdup(str);
    return node;
}

ASTNode *new_number(char *val) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_NUMBER;
    node->number.value = strdup(val);
    return node;
}

ASTNode *new_identifier(char *name) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_IDENTIFIER;
    node->identifier.name = strdup(name);
    return node;
}

ASTNode *new_sizeof(ASTNode *expr) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_SIZEOF;
    node->sizeof_expr.expr = expr;
    return node;
}
