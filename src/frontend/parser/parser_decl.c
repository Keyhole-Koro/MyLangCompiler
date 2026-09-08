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
    ASTNode *ret_type = parse_type(context, cur);

    if (!expect(cur, L_PARENTHESES)) parse_error(context, "expected '(' for method receiver", *cur);
    ASTNode *recv = parse_param(context, cur);
    if (!expect(cur, R_PARENTHESES)) parse_error(context, "expected ')' after method receiver", *cur);

    const char *recv_type = receiver_base_type_name(recv->param.type);
    if (!recv_type) parse_error(context, "method receiver must name a type", start);
    if (recv->param.type->type_node.base_type->type == AST_TYPE_GENERIC) {
        parse_error(context, "methods on a generic type are not yet supported", start);
    }

    if ((*cur)->kind != IDENTIFIER) parse_error(context, "expected method name", *cur);
    Token *name_tok = *cur;
    char *method_name = name_tok->value;
    *cur = (*cur)->next;

    char **type_params = NULL;
    int type_param_count = 0;
    if ((*cur)->kind == LT) {
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
    if (type_param_count == 0) {
        add_function(context, fndef);
        add_method(context, recv_type, method_name, mangled, fndef);
    }
    return fndef;
}
