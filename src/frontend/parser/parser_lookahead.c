#include "mylang/frontend/parser_internal.h"

int is_type(TokenKind kind, Token *cur) {
    if (kind == CONST || kind == REF) return 1;

    if (kind == VOID ||
        kind == U8 ||
        kind == U16 ||
        kind == I32 ||
        kind == U32 ||
        kind == CHAR ||
        kind == FLOAT ||
        kind == DOUBLE ||
        kind == BOOL
    ) return 1;
    if (kind == IDENTIFIER && is_user_typename(cur->value)) return 1;
    return 0;
}

// Parse an expression but stop before consuming an ARROW token (used for
// distinguishing case-pattern arrows from member access).
ASTNode *parse_expr_until_arrow(Token **cur) {
    int prev = g_stop_at_arrow;
    g_stop_at_arrow = 1;
    ASTNode *node = parse_expr(cur);
    g_stop_at_arrow = prev;
    return node;
}

// Look ahead to see if the current tokens form a function declaration/defn.
int looks_like_function(Token *cur) {
    Token *t = cur;
    while (t && (t->kind == CONST || t->kind == REF || t->kind == MUT)) {
        t = t->next;
    }
    if (!t || !is_type(t->kind, t)) return 0;
    t = t->next; // past base type
    while (t && t->kind == ASTARISK) t = t->next;
    return t && t->kind == IDENTIFIER && t->next && t->next->kind == L_PARENTHESES;
}

// Detect (param list) { ... } function literals without consuming tokens.
int looks_like_fun_literal(Token *cur) {
    if (!cur || cur->kind != L_PARENTHESES) return 0;
    Token *t = cur->next;
    if (!t) return 0;
    // Empty parameter list
    if (t->kind == R_PARENTHESES) {
        return t->next && t->next->kind == L_BRACE;
    }
    while (1) {
        if (t && t->kind == REST) {
            t = t->next;
            if (t && t->kind == IDENTIFIER) t = t->next;
            if (t && t->kind == R_PARENTHESES) {
                t = t->next;
                return t && t->kind == L_BRACE;
            }
            return 0;
        }
        if (t && t->kind == MUT) t = t->next;
        while (t && (t->kind == CONST || t->kind == REF)) {
            t = t->next;
            if (t && t->kind == MUT) t = t->next;
        }
        if (!t || !is_type(t->kind, t)) return 0;
        t = t->next; // base type
        while (t && t->kind == ASTARISK) t = t->next;
        if (!t || t->kind != IDENTIFIER) return 0;
        t = t->next;
        // optional array suffixes
        while (t && t->kind == L_BRACKET) {
            t = t->next;
            if (!t) return 0;
            if (t->kind == NUMBER) t = t->next;
            if (!t || t->kind != R_BRACKET) return 0;
            t = t->next;
        }
        if (t && t->kind == COMMA) {
            t = t->next;
            continue;
        }
        if (t && t->kind == R_PARENTHESES) {
            t = t->next;
            return t && t->kind == L_BRACE;
        }
        return 0;
    }
}
