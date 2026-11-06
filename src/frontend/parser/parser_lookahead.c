#include "mylang/frontend/parser_internal.h"

int is_type(ParserContext *context, TokenKind kind, Token *cur) {
    if (kind == CONST || kind == BORROW) return 1;
    if (kind == FN) return 1;

    /* Keep `str` context-sensitive instead of reserving the word: package
     * declarations and imports named `str` remain source-compatible. */
    if (kind == IDENTIFIER && cur && strcmp(cur->value, "str") == 0 &&
        (!cur->next || cur->next->kind != DOT)) return 1;

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
    if (kind == IDENTIFIER && is_user_typename(context, cur->value)) return 1;
    /* `_` is the unit type used as a generic argument when a payload has no
     * useful value, e.g. `Result<_, FsError>`. */
    if (kind == UNDERSCORE) return 1;
    return 0;
}

static Token *skip_type_tokens(ParserContext *context, Token *t) {
    while (t && (t->kind == CONST || t->kind == BORROW || t->kind == MUT)) t = t->next;
    if (!t || !is_type(context, t->kind, t)) return NULL;
    if (t->kind == FN) {
        t = t->next;
        if (!t || t->kind != L_PARENTHESES) return NULL;
        int depth = 1;
        t = t->next;
        while (t && depth > 0) {
            if (t->kind == L_PARENTHESES) depth++;
            else if (t->kind == R_PARENTHESES) depth--;
            t = t->next;
        }
        if (!t || t->kind != ARROW) return NULL;
        return skip_type_tokens(context, t->next);
    }
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
    return t;
}

// Parse an expression but stop before consuming an ARROW token (used for
// distinguishing case-pattern arrows from member access).
ASTNode *parse_expr_until_arrow(ParserContext *context, Token **cur) {
    int prev = context->control.stop_at_arrow;
    context->control.stop_at_arrow = 1;
    ASTNode *node = parse_expr(context, cur);
    context->control.stop_at_arrow = prev;
    return node;
}

// `for (T x in iter)`: a type, the loop variable, then the contextual `in`.
int looks_like_for_in(ParserContext *context, Token *cur) {
    Token *t = skip_type_tokens(context, cur);
    return t && t->kind == IDENTIFIER && t->next && t->next->kind == IDENTIFIER &&
           t->next->value && strcmp(t->next->value, "in") == 0;
}

// Look ahead to see if the current tokens form a function declaration/defn.
int looks_like_function(ParserContext *context, Token *cur) {
    Token *t = skip_type_tokens(context, cur);
    return token_is_name(t) && t->next && t->next->kind == L_PARENTHESES;
}

// A function type begins with `fn`, which is also a valid expression name.
// In statement position it is a declaration only when a variable name follows
// the complete function type; otherwise `fn(...)` is an ordinary call.
int looks_like_function_type_declaration(ParserContext *context, Token *cur) {
    if (!cur || cur->kind != FN) return 0;
    Token *name = skip_type_tokens(context, cur);
    return token_is_name(name);
}

// Look ahead to see if the current tokens form a method: `type (recv)
// name(...)`. The receiver parenthesis is what tells a method's return type
// apart from a plain function's name -- `void display()` has an IDENTIFIER
// right after the type, `void (borrow User u) display()` has '('.
int looks_like_method(ParserContext *context, Token *cur) {
    Token *t = cur;
    while (t && (t->kind == CONST || t->kind == BORROW || t->kind == MUT)) {
        t = t->next;
    }
    /* A receiver-bound generic method may use its receiver's formal type
     * parameter as the return type (`T (borrow Box<T> self) get()`).  `T` is
     * deliberately not in the ordinary type table yet, so accept an
     * identifier here and let parse_method establish the short-lived scope
     * before parsing it for real. */
    if (!t || !(is_type(context, t->kind, t) || t->kind == IDENTIFIER)) return 0;
    t = t->next; // past base type
    if (t && t->kind == LT) {
        int depth = 1;
        t = t->next;
        while (t && depth > 0) {
            if (t->kind == LT) depth++;
            else if (t->kind == GT) depth--;
            else if (t->kind == RSH) depth -= 2;
            t = t->next;
        }
        if (depth != 0) return 0;
    }
    while (t && t->kind == ASTARISK) t = t->next;
    if (!t || t->kind != L_PARENTHESES) return 0;

    // Skip the receiver's own parentheses (its contents are just one `param`,
    // validated for real by parse_param() once we commit to this branch).
    t = t->next;
    int depth = 1;
    while (t && depth > 0) {
        if (t->kind == L_PARENTHESES) depth++;
        else if (t->kind == R_PARENTHESES) depth--;
        t = t->next;
    }
    if (depth != 0) return 0;

    if (!token_is_member_name(t)) return 0;
    t = t->next;
    /* A generic receiver may repeat its receiver-bound parameters here to
     * attach trait bounds: `Box<T>::put<T: Eq>(...)`. */
    if (t && t->kind == LT) {
        int generic_depth = 1;
        t = t->next;
        while (t && generic_depth > 0) {
            if (t->kind == LT) generic_depth++;
            else if (t->kind == GT) generic_depth--;
            else if (t->kind == RSH) generic_depth -= 2;
            t = t->next;
        }
        if (generic_depth != 0) return 0;
    }
    return t && t->kind == L_PARENTHESES;
}

Token *generic_function_type_params_start(ParserContext *context, Token *cur) {
    Token *t = cur;
    while (t && (t->kind == CONST || t->kind == BORROW || t->kind == MUT)) t = t->next;
    if (!t || !(is_type(context, t->kind, t) || t->kind == IDENTIFIER)) return NULL;
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
    if (!token_is_name(t) || !t->next || t->next->kind != LT) return NULL;

    Token *params_start = t->next;
    Token *p = params_start->next;
    if (!p || (p->kind != IDENTIFIER && p->kind != CONST)) return NULL;
    while (p && (p->kind == IDENTIFIER || (p->kind == CONST && p->next && p->next->kind == IDENTIFIER))) {
        if (p->kind == CONST) p = p->next;
        p = p->next;
        /* `T: Eq + From<S>`: skip the bound list, including the bound's own
         * type arguments. */
        if (p && p->kind == COLON) {
            p = p->next;
            while (p && p->kind == IDENTIFIER) {
                p = p->next;
                if (p && p->kind == LT) {
                    int depth = 1;
                    p = p->next;
                    while (p && depth > 0) {
                        if (p->kind == LT) depth++;
                        else if (p->kind == GT) depth--;
                        else if (p->kind == RSH) depth -= 2;
                        if (depth > 0) p = p->next;
                    }
                    /* `>>` closing both the bound and the parameter list. */
                    if (!p) return NULL;
                    if (p->kind == RSH) {
                        if (!p->next || p->next->kind != L_PARENTHESES) return NULL;
                        return params_start;
                    }
                    p = p->next;
                }
                if (p && p->kind == ADD) {
                    p = p->next;
                    continue;
                }
                break;
            }
        }
        if (p && p->kind == COMMA) {
            p = p->next;
            continue;
        }
        break;
    }
    if (!p || p->kind != GT || !p->next || p->next->kind != L_PARENTHESES) return NULL;
    return params_start;
}

int looks_like_generic_function(ParserContext *context, Token *cur) {
    return generic_function_type_params_start(context, cur) != NULL;
}

static int token_starts_fun_literal_body(Token *t) {
    if (!t) return 0;
    if (t->kind == L_BRACE) return 1;
    return t->kind == FAT_ARROW && t->next && t->next->kind == L_BRACE;
}

// Detect (param list) { ... } and (param list) => { ... } function literals
// without consuming tokens.
int looks_like_fun_literal(ParserContext *context, Token *cur) {
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
        while (t && (t->kind == CONST || t->kind == BORROW)) {
            t = t->next;
            if (t && t->kind == MUT) t = t->next;
        }
        if (!t || !is_type(context, t->kind, t)) return 0;
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
