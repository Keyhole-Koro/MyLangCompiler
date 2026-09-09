#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode* parse_param(ParserContext *context, Token **cur) {
    if ((*cur)->kind == REST) {
        Token *rest_tok = *cur;
        *cur = (*cur)->next;
        if ((*cur)->kind != IDENTIFIER) parse_error(context, "expected rest parameter name", *cur);
        Token *name_tok = *cur;
        char *name = name_tok->value;
        *cur = (*cur)->next;
        ASTNode *param = new_param_rest(name);
        param->line = rest_tok->line;
        param->col = rest_tok->col;
        return param;
    }

    int is_mut = 0;
    Token *start = *cur;
    if ((*cur)->kind == MUT) {
        is_mut = 1;
        *cur = (*cur)->next;
        start = *cur;
    }
    ASTNode *type = parse_type(context, cur);
    if ((*cur)->kind != IDENTIFIER) parse_error(context, "expected param name", *cur);
    Token *name_tok = *cur;
    char *name = name_tok->value;
    *cur = (*cur)->next;

    ASTNode *final_type = type;
    while ((*cur)->kind == L_BRACKET) {
        *cur = (*cur)->next;
        int size = -1;
        if ((*cur)->kind == NUMBER) {
            size = atoi((*cur)->value);
            *cur = (*cur)->next;
        }
        if (!expect(cur, R_BRACKET)) parse_error(context, "expected ']' for parameter array", *cur);
        final_type = new_type_array(final_type, size);
    }

    ASTNode *param = new_param_mut(final_type, name, is_mut);
    set_node_loc_from_tokens(param, start, name_tok);
    return param;
}

ASTNode** parse_param_list(ParserContext *context, Token **cur, int *out_count, bool *out_is_variadic) {
    ASTNode **params = NULL;
    int count = 0;
    *out_is_variadic = 0;
    if ((*cur)->kind == R_PARENTHESES) { *out_count = 0; return NULL; }
    while (1) {
        ASTNode *param = parse_param(context, cur);
        if (param->type == AST_PARAM && param->param.is_rest) {
            *out_is_variadic = 1;
        }
        params = realloc(params, sizeof(ASTNode*) * (count + 1));
        params[count++] = param;
        if ((*cur)->kind == COMMA) {
            if (param->type == AST_PARAM && param->param.is_rest) {
                parse_error(context, "rest parameter must be the final parameter", *cur);
            }
            *cur = (*cur)->next;
            if ((*cur)->kind == R_PARENTHESES) parse_error(context, "trailing comma in parameter list", *cur);
            continue;
        }
        break;
    }
    *out_count = count;
    return params;
}

ASTNode* parse_fundef(ParserContext *context, Token **cur) {
    Token *start = *cur;
    ASTNode *ret_type = parse_type(context, cur);
    if ((*cur)->kind != IDENTIFIER) parse_error(context, "expected function name", *cur);
    Token *name_tok = *cur;
    char *name = name_tok->value;
    *cur = (*cur)->next;
    char **type_params = NULL;
    int type_param_count = 0;
    if ((*cur)->kind == LT) {
        type_params = parse_type_params(context, cur, &type_param_count, 0);
    }
    if (!expect(cur, L_PARENTHESES)) parse_error(context, "expected '(' after function name", *cur);

    int param_count = 0;
    bool is_variadic = false;
    ASTNode **params = NULL;
    if ((*cur)->kind != R_PARENTHESES)
        params = parse_param_list(context, cur, &param_count, &is_variadic);

    if (!expect(cur, R_PARENTHESES)) parse_error(context, "expected ')' after parameter list", *cur);

    if ((*cur)->kind == SEMICOLON) {
        *cur = (*cur)->next;
        // For now, treat declarations as fundefs with no body
        ASTNode *fndef = new_fundef(ret_type, name, params, param_count, NULL, is_variadic);
        fndef->fundef.type_params = type_params;
        fndef->fundef.type_param_count = type_param_count;
        set_node_loc_from_tokens(fndef, start, name_tok);
        if (type_param_count == 0) add_function(context, fndef);
        return fndef;
    }

    ASTNode *body = parse_block(context, cur);
    ASTNode *fndef = new_fundef(ret_type, name, params, param_count, body, is_variadic);
    fndef->fundef.type_params = type_params;
    fndef->fundef.type_param_count = type_param_count;
    set_node_loc_from_tokens(fndef, start, name_tok);
    if (type_param_count == 0) add_function(context, fndef);
    return fndef;
}

// The base type name a receiver's `type` AST names -- a plain identifier or a
// generic type's own name (never resolved further). NULL for anything a
// receiver can't legally be (an array type, or a bare `rest` receiver, which
// parse_param would have already rejected as nonsensical here for other
// reasons: `param.type` is NULL for `rest`).
static const char *receiver_base_type_name(ASTNode *type_node) {
    if (!type_node || type_node->type != AST_TYPE) return NULL;
    ASTNode *base = type_node->type_node.base_type;
    if (!base) return NULL;
    if (base->type == AST_IDENTIFIER) return base->identifier.name;
    if (base->type == AST_TYPE_GENERIC) return base->generic_type.name;
    return NULL;
}

/* Before parsing a method, discover a receiver written as `Box<T, E>`.  Its
 * type arguments are declaration-site parameters, not ordinary in-scope
 * types, so they must be visible while parsing both the return type and body.
 * We intentionally keep this v1 form simple: each argument is a distinct
 * identifier.  That is exactly the receiver-bound form needed by
 * `Mock<Args, Ret>` and avoids inventing a second, competing generic-method
 * syntax. */
static char **receiver_bound_type_params(Token *cur, int *out_count) {
    Token *t = cur;
    while (t && (t->kind == CONST || t->kind == REF || t->kind == MUT)) t = t->next;
    if (!t) return NULL;
    t = t->next; /* return type's base token */
    if (t && t->kind == LT) {
        int depth = 1;
        t = t->next;
        while (t && depth > 0) {
            if (t->kind == LT) depth++;
            else if (t->kind == GT) depth--;
            else if (t->kind == RSH) depth -= 2;
            t = t->next;
        }
    }
    while (t && t->kind == ASTARISK) t = t->next;
    if (!t || t->kind != L_PARENTHESES) return NULL;

    t = t->next;
    while (t && (t->kind == CONST || t->kind == REF || t->kind == MUT)) t = t->next;
    if (!t || t->kind != IDENTIFIER || !t->next || t->next->kind != LT) return NULL;
    t = t->next->next;

    char **params = NULL;
    int count = 0;
    while (t && t->kind == IDENTIFIER) {
        for (int i = 0; i < count; i++) {
            if (strcmp(params[i], t->value) == 0) {
                for (int j = 0; j < count; j++) free(params[j]);
                free(params);
                return NULL;
            }
        }
        params = realloc(params, sizeof(char *) * (count + 1));
        params[count++] = strdup(t->value);
        t = t->next;
        if (t && t->kind == COMMA) {
            t = t->next;
            continue;
        }
        break;
    }
    if (count == 0 || !t || t->kind != GT) goto invalid;
    t = t->next;
    if (!t || t->kind != IDENTIFIER) goto invalid; /* receiver variable */
    t = t->next;
    if (!t || t->kind != R_PARENTHESES) goto invalid;
    t = t->next;
    if (!t || t->kind != IDENTIFIER || !t->next || t->next->kind != L_PARENTHESES) goto invalid;

    *out_count = count;
    return params;

invalid:
    for (int i = 0; i < count; i++) free(params[i]);
    free(params);
    return NULL;
}

// Parses `type (recv) name(...) (block | ;)` -- a method. The receiver is
// exactly one `param` (see recv in docs/grammar.md), prepended to the
// parameter list so a method is an ordinary function everywhere past this
// point: semantic analysis and codegen never learn methods exist. The name
// is mangled to `<ReceiverType>__<name>` immediately, and `.`-call sites are
// resolved back to it later, once every method in the file is known
// (parser_method_resolve.c's resolve_method_calls(), run from
// frontend_pipeline.c's lower_program()).
ASTNode *parse_method(ParserContext *context, Token **cur) {
    Token *start = *cur;
    int type_param_count = 0;
    char **type_params = receiver_bound_type_params(*cur, &type_param_count);
    int type_scope_mark = typename_scope_mark(context);
    for (int i = 0; i < type_param_count; i++) add_typename(context, type_params[i]);

    ASTNode *ret_type = parse_type(context, cur);

    if (!expect(cur, L_PARENTHESES)) parse_error(context, "expected '(' for method receiver", *cur);
    ASTNode *recv = parse_param(context, cur);
    if (!expect(cur, R_PARENTHESES)) parse_error(context, "expected ')' after method receiver", *cur);

    const char *recv_type = receiver_base_type_name(recv->param.type);
    if (!recv_type) parse_error(context, "method receiver must name a type", start);
    int generic_receiver = recv->param.type->type_node.base_type->type == AST_TYPE_GENERIC;

    if ((*cur)->kind != IDENTIFIER) parse_error(context, "expected method name", *cur);
    Token *name_tok = *cur;
    char *method_name = name_tok->value;
    *cur = (*cur)->next;

    if ((*cur)->kind == LT) {
        if (generic_receiver)
            parse_error(context, "generic receiver methods cannot declare additional type parameters", *cur);
        type_params = parse_type_params(context, cur, &type_param_count, 0);
    }
    if (!expect(cur, L_PARENTHESES)) parse_error(context, "expected '(' after method name", *cur);

    int rest_count = 0;
    bool is_variadic = false;
    ASTNode **rest_params = NULL;
    if ((*cur)->kind != R_PARENTHESES)
        rest_params = parse_param_list(context, cur, &rest_count, &is_variadic);
    if (!expect(cur, R_PARENTHESES)) parse_error(context, "expected ')' after parameter list", *cur);

    ASTNode **params = malloc(sizeof(ASTNode *) * (rest_count + 1));
    params[0] = recv;
    for (int i = 0; i < rest_count; i++) params[i + 1] = rest_params[i];
    free(rest_params);
    int param_count = rest_count + 1;

    char mangled[256];
    snprintf(mangled, sizeof(mangled), "%s__%s", recv_type, method_name);

    ASTNode *body = NULL;
    if ((*cur)->kind == SEMICOLON) {
        *cur = (*cur)->next;
    } else {
        body = parse_block(context, cur);
    }

    ASTNode *fndef = new_fundef(ret_type, mangled, params, param_count, body, is_variadic);
    fndef->fundef.type_params = type_params;
    fndef->fundef.type_param_count = type_param_count;
    fndef->fundef.recv_type_name = strdup(recv_type);
    set_node_loc_from_tokens(fndef, start, name_tok);
    restore_typenames(context, type_scope_mark);
    if (generic_receiver) {
        if (type_param_count == 0)
            parse_error(context, "generic receiver methods require receiver-bound type parameters", start);
        add_generic_method(context, recv_type, method_name, fndef);
        return NULL;
    }
    if (type_param_count == 0) {
        add_function(context, fndef);
        add_method(context, recv_type, method_name, mangled, fndef);
    }
    return fndef;
}
