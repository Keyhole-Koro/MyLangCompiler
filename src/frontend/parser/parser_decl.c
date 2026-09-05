#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode* parse_param(Token **cur) {
    if ((*cur)->kind == REST) {
        Token *rest_tok = *cur;
        *cur = (*cur)->next;
        if ((*cur)->kind != IDENTIFIER) parse_error("expected rest parameter name", *cur);
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
    ASTNode *type = parse_type(cur);
    if ((*cur)->kind != IDENTIFIER) parse_error("expected param name", *cur);
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
        if (!expect(cur, R_BRACKET)) parse_error("expected ']' for parameter array", *cur);
        final_type = new_type_array(final_type, size);
    }

    ASTNode *param = new_param_mut(final_type, name, is_mut);
    set_node_loc_from_tokens(param, start, name_tok);
    return param;
}

ASTNode** parse_param_list(Token **cur, int *out_count, bool *out_is_variadic) {
    ASTNode **params = NULL;
    int count = 0;
    *out_is_variadic = 0;
    if ((*cur)->kind == R_PARENTHESES) { *out_count = 0; return NULL; }
    while (1) {
        ASTNode *param = parse_param(cur);
        if (param->type == AST_PARAM && param->param.is_rest) {
            *out_is_variadic = 1;
        }
        params = realloc(params, sizeof(ASTNode*) * (count + 1));
        params[count++] = param;
        if ((*cur)->kind == COMMA) {
            if (param->type == AST_PARAM && param->param.is_rest) {
                parse_error("rest parameter must be the final parameter", *cur);
            }
            *cur = (*cur)->next;
            if ((*cur)->kind == R_PARENTHESES) parse_error("trailing comma in parameter list", *cur);
            continue;
        }
        break;
    }
    *out_count = count;
    return params;
}

ASTNode* parse_fundef(Token **cur) {
    Token *start = *cur;
    ASTNode *ret_type = parse_type(cur);
    if ((*cur)->kind != IDENTIFIER) parse_error("expected function name", *cur);
    Token *name_tok = *cur;
    char *name = name_tok->value;
    *cur = (*cur)->next;
    char **type_params = NULL;
    int type_param_count = 0;
    if ((*cur)->kind == LT) {
        type_params = parse_type_params(cur, &type_param_count, 0);
    }
    if (!expect(cur, L_PARENTHESES)) parse_error("expected '(' after function name", *cur);

    int param_count = 0;
    bool is_variadic = false;
    ASTNode **params = NULL;
    if ((*cur)->kind != R_PARENTHESES)
        params = parse_param_list(cur, &param_count, &is_variadic);

    if (!expect(cur, R_PARENTHESES)) parse_error("expected ')' after parameter list", *cur);

    if ((*cur)->kind == SEMICOLON) {
        *cur = (*cur)->next;
        // For now, treat declarations as fundefs with no body
        ASTNode *fndef = new_fundef(ret_type, name, params, param_count, NULL, is_variadic);
        fndef->fundef.type_params = type_params;
        fndef->fundef.type_param_count = type_param_count;
        set_node_loc_from_tokens(fndef, start, name_tok);
        if (type_param_count == 0) add_function(fndef);
        return fndef;
    }

    ASTNode *body = parse_block(cur);
    ASTNode *fndef = new_fundef(ret_type, name, params, param_count, body, is_variadic);
    fndef->fundef.type_params = type_params;
    fndef->fundef.type_param_count = type_param_count;
    set_node_loc_from_tokens(fndef, start, name_tok);
    if (type_param_count == 0) add_function(fndef);
    return fndef;
}
