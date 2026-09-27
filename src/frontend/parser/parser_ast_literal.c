#include "mylang/frontend/parser_ast_internal.h"

ASTNode *new_string_literal(char *str) {
    return new_string_literal_n(str, str ? (int)strlen(str) : 0);
}

ASTNode *new_string_literal_n(const char *str, int length) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_STRING_LITERAL;
    if (length < 0) length = 0;
    node->string_literal.value = malloc((size_t)length + 1);
    if (length > 0 && str) memcpy(node->string_literal.value, str, (size_t)length);
    node->string_literal.value[length] = '\0';
    node->string_literal.length = length;
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
    set_node_range_from_children(node, expr, expr);
    return node;
}
