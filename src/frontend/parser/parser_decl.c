#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode* parse_param(Token **cur) {
    int is_mut = 0;
    Token *start = *cur;
    if ((*cur)->kind == MUT) {
        is_mut = 1;
        *cur = (*cur)->next;
        start = *cur;
    }
    ASTNode *type = parse_type(cur);
    if ((*cur)->kind != IDENTIFIER) parse_error("expected param name", token_head, *cur);
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
        if (!expect(cur, R_BRACKET)) parse_error("expected ']' for parameter array", token_head, *cur);
        final_type = new_type_array(final_type, size);
    }

    ASTNode *param = new_param_mut(final_type, name, is_mut);
    param->line = start ? start->line : name_tok->line;
    param->col = start ? start->col : name_tok->col;
    return param;
}

ASTNode** parse_param_list(Token **cur, int *out_count) {
    ASTNode **params = NULL;
    int count = 0;
    if ((*cur)->kind == R_PARENTHESES) { *out_count = 0; return NULL; }
    while (1) {
        ASTNode *param = parse_param(cur);
        params = realloc(params, sizeof(ASTNode*) * (count + 1));
        params[count++] = param;
        if ((*cur)->kind == COMMA) { *cur = (*cur)->next; continue; }
        break;
    }
    *out_count = count;
    return params;
}

ASTNode* parse_fundef(Token **cur) {
    Token *start = *cur;
    ASTNode *ret_type = parse_type(cur);
    if ((*cur)->kind != IDENTIFIER) parse_error("expected function name", token_head, *cur);
    Token *name_tok = *cur;
    char *name = name_tok->value;
    *cur = (*cur)->next;
    if (!expect(cur, L_PARENTHESES)) parse_error("expected '(' after function name", token_head, *cur);

    int param_count = 0;
    ASTNode **params = NULL;
    if ((*cur)->kind != R_PARENTHESES)
        params = parse_param_list(cur, &param_count);

    if (!expect(cur, R_PARENTHESES)) parse_error("expected ')' after parameter list", token_head, *cur);

    if ((*cur)->kind == SEMICOLON) {
        *cur = (*cur)->next;
        return NULL;
    }

    ASTNode *body = parse_block(cur);
    ASTNode *fndef = new_fundef(ret_type, name, params, param_count, body);
    fndef->line = start ? start->line : name_tok->line;
    fndef->col = start ? start->col : name_tok->col;
    add_function(fndef);
    return fndef;
}
