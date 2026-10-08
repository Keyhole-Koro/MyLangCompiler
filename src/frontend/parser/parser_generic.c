#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

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

/* `Bound (+ Bound)*` after `T:`. A bound names a trait, optionally with type
 * arguments: `Eq`, `From<SsdError>`. Traits are not types, so the name is
 * taken as written and checked when the template is instantiated. */
static ASTNode *parse_type_param_bounds(ParserContext *context, Token **cur) {
    ASTNode **bounds = NULL;
    int count = 0;
    while (1) {
        if ((*cur)->kind != IDENTIFIER) parse_error(context, "expected trait name in type parameter bound", *cur);
        Token *name_tok = *cur;
        *cur = (*cur)->next;
        ASTNode *base;
        if ((*cur)->kind == LT) {
            int arg_count = 0;
            ASTNode **args = parse_type_args(context, cur, &arg_count);
            base = new_generic_type(name_tok->value, args, arg_count);
        } else {
            base = new_identifier(name_tok->value);
        }
        set_node_loc_from_tokens(base, name_tok, NULL);
        ASTNode *bound = new_type_node(base, 0, 0, REFKIND_NONE);
        set_node_loc_from_tokens(bound, name_tok, NULL);
        bounds = realloc(bounds, sizeof(ASTNode *) * (count + 1));
        bounds[count++] = bound;
        if ((*cur)->kind != ADD) break;
        *cur = (*cur)->next;
    }
    return new_block(bounds, count);
}

/* A bound may name a parameter declared later in the same list
 * (`<T: From<S>, S>`), so every parameter name enters the scope before any
 * bound is parsed. */
static void scope_type_param_names(ParserContext *context, Token *lt) {
    int depth = 1;
    int expect_name = 1;
    for (Token *t = lt->next; t && depth > 0; t = t->next) {
        if (depth == 1 && expect_name) {
            if (t->kind == CONST) continue;
            if (t->kind == IDENTIFIER) add_typename(context, t->value);
            expect_name = 0;
        }
        if (t->kind == LT) depth++;
        else if (t->kind == GT) depth--;
        else if (t->kind == RSH) depth -= 2;
        else if (t->kind == COMMA && depth == 1) expect_name = 1;
    }
}

char **parse_type_params(ParserContext *context, Token **cur, int *out_count,
                         unsigned char **out_is_const, int add_to_scope,
                         ASTNode ***out_bounds) {
    char **params = NULL;
    unsigned char *is_const = NULL;
    ASTNode **bounds = NULL;
    int any_bound = 0;
    int count = 0;

    if ((*cur)->kind != LT) parse_error(context, "expected '<' before type parameters", *cur);
    if (add_to_scope) scope_type_param_names(context, *cur);
    expect(cur, LT);
    if ((*cur)->kind == GT) parse_error(context, "generic declaration requires at least one type parameter", *cur);

    while (1) {
        int param_is_const = expect(cur, CONST);
        if ((*cur)->kind != IDENTIFIER)
            parse_error(context, param_is_const ? "expected const parameter name" :
                                               "expected type parameter name", *cur);
        if (contains_name(params, count, (*cur)->value))
            parse_error(context, "duplicate type parameter", *cur);

        params = realloc(params, sizeof(char *) * (count + 1));
        is_const = realloc(is_const, sizeof(unsigned char) * (count + 1));
        bounds = realloc(bounds, sizeof(ASTNode *) * (count + 1));
        params[count] = strdup((*cur)->value);
        is_const[count] = (unsigned char)param_is_const;
        bounds[count] = NULL;
        count++;
        *cur = (*cur)->next;

        if ((*cur)->kind == COLON) {
            if (param_is_const) parse_error(context, "a const parameter cannot have trait bounds", *cur);
            *cur = (*cur)->next;
            bounds[count - 1] = parse_type_param_bounds(context, cur);
            any_bound = 1;
        }

        if ((*cur)->kind != COMMA) break;
        *cur = (*cur)->next;
        if ((*cur)->kind == GT)
            parse_error(context, "trailing comma in type parameter list", *cur);
    }

    if (!expect_type_arg_close(cur)) parse_error(context, "expected '>' after type parameters", *cur);
    *out_count = count;
    if (out_is_const) *out_is_const = is_const;
    else free(is_const);
    if (out_bounds && any_bound) {
        *out_bounds = bounds;
    } else {
        if (out_bounds) *out_bounds = NULL;
        for (int i = 0; i < count; i++) free_ast(bounds[i]);
        free(bounds);
    }
    return params;
}

ASTNode **parse_type_args(ParserContext *context, Token **cur, int *out_count) {
    ASTNode **args = NULL;
    int count = 0;

    if (!expect(cur, LT)) parse_error(context, "expected '<' before type arguments", *cur);
    if ((*cur)->kind == GT) parse_error(context, "generic use requires at least one type argument", *cur);

    while (1) {
        ASTNode *arg;
        if ((*cur)->kind == NUMBER) {
            Token *number = *cur;
            arg = new_number(number->value);
            set_node_loc_from_tokens(arg, number, NULL);
            *cur = number->next;
        } else {
            arg = parse_type(context, cur);
        }
        args = realloc(args, sizeof(ASTNode *) * (count + 1));
        args[count++] = arg;
        if ((*cur)->kind != COMMA) break;
        *cur = (*cur)->next;
        if ((*cur)->kind == GT)
            parse_error(context, "trailing comma in type argument list", *cur);
    }

    if (!expect_type_arg_close(cur)) parse_error(context, "expected '>' after type arguments", *cur);
    *out_count = count;
    return args;
}

ASTNode *parse_generic_fundef(ParserContext *context, Token **cur) {
    Token *params_start = generic_function_type_params_start(context, *cur);
    if (!params_start) parse_error(context, "invalid generic function declaration", *cur);

    Token *name_tok = *cur;
    while (name_tok && name_tok->next != params_start) name_tok = name_tok->next;
    if (!token_is_name(name_tok))
        parse_error(context, "expected generic function name", *cur);

    int mark = typename_scope_mark(context);
    int scope_param_count = 0;
    unsigned char *scope_param_is_const = NULL;
    Token *lookahead = params_start;
    char **scope_params = parse_type_params(context, &lookahead, &scope_param_count,
                                            &scope_param_is_const, 1, NULL);
    for (int i = 0; i < scope_param_count; i++) free(scope_params[i]);
    free(scope_params);
    free(scope_param_is_const);

    const char *previous_generic_function = context->control.current_generic_function_name;
    context->control.current_generic_function_name = name_tok->value;
    context->control.generic_decl_depth++;
    ASTNode *fn = parse_fundef(context, cur);
    context->control.generic_decl_depth--;
    context->control.current_generic_function_name = previous_generic_function;
    restore_typenames(context, mark);
    return fn;
}
