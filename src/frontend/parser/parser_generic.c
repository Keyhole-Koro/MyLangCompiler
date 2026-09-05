#include "mylang/frontend/parser_internal.h"

static int contains_name(char **names, int count, const char *name) {
    for (int i = 0; i < count; i++) {
        if (strcmp(names[i], name) == 0) return 1;
    }
    return 0;
}

static int expect_type_arg_close(Token **cur) {
    if (expect(cur, GT)) return 1;
    if (*cur && (*cur)->kind == RSH) {
        /* In a type context, the lexer token `>>` closes two nested generic
         * argument lists. Split it into two tokens, consume the first, and
         * leave the second for the enclosing list. */
        Token *first = *cur;
        Token *second = calloc(1, sizeof(Token));
        second->kind = GT;
        second->value = strdup(">");
        second->line = first->line;
        second->col = first->col + 1;
        second->length = 1;
        second->next = first->next;
        first->kind = GT;
        first->length = 1;
        free(first->value);
        first->value = strdup(">");
        first->next = second;
        *cur = second;
        return 1;
    }
    return 0;
}

char **parse_type_params(Token **cur, int *out_count, int add_to_scope) {
    char **params = NULL;
    int count = 0;

    if (!expect(cur, LT)) parse_error("expected '<' before type parameters", *cur);
    if ((*cur)->kind == GT) parse_error("generic declaration requires at least one type parameter", *cur);

    while (1) {
        if ((*cur)->kind != IDENTIFIER)
            parse_error("expected type parameter name", *cur);
        if (contains_name(params, count, (*cur)->value))
            parse_error("duplicate type parameter", *cur);

        params = realloc(params, sizeof(char *) * (count + 1));
        params[count] = strdup((*cur)->value);
        if (add_to_scope) add_typename((*cur)->value);
        count++;
        *cur = (*cur)->next;

        if ((*cur)->kind != COMMA) break;
        *cur = (*cur)->next;
        if ((*cur)->kind == GT)
            parse_error("trailing comma in type parameter list", *cur);
    }

    if (!expect(cur, GT)) parse_error("expected '>' after type parameters", *cur);
    *out_count = count;
    return params;
}

ASTNode **parse_type_args(Token **cur, int *out_count) {
    ASTNode **args = NULL;
    int count = 0;

    if (!expect(cur, LT)) parse_error("expected '<' before type arguments", *cur);
    if ((*cur)->kind == GT) parse_error("generic use requires at least one type argument", *cur);

    while (1) {
        ASTNode *arg = parse_type(cur);
        args = realloc(args, sizeof(ASTNode *) * (count + 1));
        args[count++] = arg;
        if ((*cur)->kind != COMMA) break;
        *cur = (*cur)->next;
        if ((*cur)->kind == GT)
            parse_error("trailing comma in type argument list", *cur);
    }

    if (!expect_type_arg_close(cur)) parse_error("expected '>' after type arguments", *cur);
    *out_count = count;
    return args;
}

ASTNode *parse_generic_fundef(Token **cur) {
    Token *params_start = generic_function_type_params_start(*cur);
    if (!params_start) parse_error("invalid generic function declaration", *cur);

    Token *name_tok = *cur;
    while (name_tok && name_tok->next != params_start) name_tok = name_tok->next;
    if (!name_tok || name_tok->kind != IDENTIFIER)
        parse_error("expected generic function name", *cur);

    int mark = typename_scope_mark();
    int scope_param_count = 0;
    Token *lookahead = params_start;
    char **scope_params = parse_type_params(&lookahead, &scope_param_count, 1);
    for (int i = 0; i < scope_param_count; i++) free(scope_params[i]);
    free(scope_params);

    const char *previous_generic_function = parser_context_current()->control.current_generic_function_name;
    parser_context_current()->control.current_generic_function_name = name_tok->value;
    parser_context_current()->control.generic_decl_depth++;
    ASTNode *fn = parse_fundef(cur);
    parser_context_current()->control.generic_decl_depth--;
    parser_context_current()->control.current_generic_function_name = previous_generic_function;
    restore_typenames(mark);
    return fn;
}
