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

Token *generic_function_type_params_start(Token *cur) {
    Token *t = cur;
    while (t && (t->kind == CONST || t->kind == REF || t->kind == MUT)) t = t->next;
    if (!t || !(is_type(t->kind, t) || t->kind == IDENTIFIER)) return NULL;
    t = t->next;

    if (t && t->kind == LT) {
        int depth = 1;
        t = t->next;
        while (t && depth > 0) {
            if (t->kind == LT) depth++;
            else if (t->kind == GT) depth--;
            else if (t->kind == RSH) depth -= 2;
            t = t->next;
        }
        if (depth != 0) return NULL;
    }
    while (t && t->kind == ASTARISK) t = t->next;
    if (!t || t->kind != IDENTIFIER || !t->next || t->next->kind != LT) return NULL;

    Token *params_start = t->next;
    Token *p = params_start->next;
    if (!p || p->kind != IDENTIFIER) return NULL;
    while (p && p->kind == IDENTIFIER) {
        p = p->next;
        if (p && p->kind == COMMA) {
            p = p->next;
            continue;
        }
        break;
    }
    if (!p || p->kind != GT || !p->next || p->next->kind != L_PARENTHESES) return NULL;
    return params_start;
}

int looks_like_generic_function(Token *cur) {
    return generic_function_type_params_start(cur) != NULL;
}

static int token_starts_fun_literal_body(Token *t) {
    if (!t) return 0;
    if (t->kind == L_BRACE) return 1;
    return t->kind == FAT_ARROW && t->next && t->next->kind == L_BRACE;
}

// Detect (param list) { ... } and (param list) => { ... } function literals
// without consuming tokens.
int looks_like_fun_literal(Token *cur) {
    if (!cur || cur->kind != L_PARENTHESES) return 0;
    Token *t = cur->next;
    if (!t) return 0;
    // Empty parameter list
    if (t->kind == R_PARENTHESES) {
        return token_starts_fun_literal_body(t->next);
    }
    while (1) {
        if (t && t->kind == REST) {
            t = t->next;
            if (t && t->kind == IDENTIFIER) t = t->next;
            if (t && t->kind == R_PARENTHESES) {
                t = t->next;
                return token_starts_fun_literal_body(t);
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
            return token_starts_fun_literal_body(t);
        }
        return 0;
    }
}
