#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

static ASTNode *parse_case_primary(Token **cur) {
    *cur = (*cur)->next;
    ASTNode *target = parse_expr(cur);
    if (!expect(cur, OF)) parse_error("expected 'of' after case target", token_head, *cur);
    if (!expect(cur, L_BRACE)) parse_error("expected '{' after of", token_head, *cur);

    CaseItem *cases = NULL;
    int count = 0;
    ASTNode *default_expr = NULL;

    while ((*cur)->kind != R_BRACE && (*cur)->kind != EOT) {
        if ((*cur)->kind == UNDERSCORE) {
            *cur = (*cur)->next;
            if (!expect(cur, ARROW)) parse_error("expected '->' after _", token_head, *cur);
            if (default_expr) parse_error("duplicate default case", token_head, *cur);
            default_expr = parse_expr(cur);
        } else {
            ASTNode *key = parse_expr_until_arrow(cur);
            if (!expect(cur, ARROW)) parse_error("expected '->' after case key", token_head, *cur);
            ASTNode *expr = parse_expr(cur);
            cases = realloc(cases, sizeof(CaseItem) * (count + 1));
            cases[count].key = key;
            cases[count].expr = expr;
            count++;
        }
        if (!expect(cur, SEMICOLON)) parse_error("expected ';' after case expression", token_head, *cur);
    }
    if (!expect(cur, R_BRACE)) parse_error("expected '}'", token_head, *cur);
    return new_case_expr(target, cases, count, default_expr);
}

static ASTNode *parse_identifier_primary(Token **cur) {
    Token *tok = *cur;
    char *name = tok->value;
    *cur = (*cur)->next;

    if ((*cur)->kind == L_PARENTHESES) {
        *cur = (*cur)->next;
        ASTNode **args = NULL;
        int arg_count = 0;
        if ((*cur)->kind != R_PARENTHESES) {
            while (1) {
                ASTNode *arg = parse_expr(cur);
                args = realloc(args, sizeof(ASTNode*) * (arg_count + 1));
                args[arg_count++] = arg;
                if ((*cur)->kind == COMMA) {
                    *cur = (*cur)->next;
                    continue;
                }
                break;
            }
        }

        Token *end_tok = *cur;
        if (!expect(cur, R_PARENTHESES))
            parse_error("expected ')' after args", token_head, *cur);
        ASTNode *call = new_call(name, args, arg_count);
        set_node_loc_from_tokens(call, tok, NULL);
        set_node_end_from_token(call, end_tok);
        return call;
    }

    long enum_val;
    if (find_enum_constant(name, &enum_val)) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%ld", enum_val);
        ASTNode *node = new_number(buf);
        set_node_loc_from_tokens(node, tok, NULL);
        return node;
    }

    ASTNode *node = new_identifier(name);
    set_node_loc_from_tokens(node, tok, NULL);
    while ((*cur)->kind == L_BRACKET) {
        *cur = (*cur)->next;
        ASTNode *index = parse_expr(cur);

        Token *end_tok = *cur;
        if (!expect(cur, R_BRACKET))
            parse_error("expected ']' after array index", token_head, *cur);

        ASTNode *add = new_binary(ADD, node, index);
        node = new_unary(ASTARISK, add);
        set_node_end_from_token(node, end_tok);
    }

    return node;
}

ASTNode *parse_primary(Token **cur) {
    if ((*cur)->kind == NUMBER) {
        Token *tok = *cur;
        ASTNode *node = new_number((*cur)->value);
        set_node_loc_from_tokens(node, tok, NULL);
        *cur = (*cur)->next;
        return node;
    }
    if ((*cur)->kind == STRING_LITERAL) {
        Token *tok = *cur;
        ASTNode *node = new_string_literal((*cur)->value);
        set_node_loc_from_tokens(node, tok, NULL);
        *cur = (*cur)->next;
        return node;
    }
    if ((*cur)->kind == CASE) {
        return parse_case_primary(cur);
    }
    if ((*cur)->kind == IDENTIFIER) {
        return parse_identifier_primary(cur);
    }
    if ((*cur)->kind == L_PARENTHESES && looks_like_fun_literal(*cur)) {
        *cur = (*cur)->next;
        ASTNode **params = NULL;
        int param_count = 0;
        bool is_variadic = false;
        if ((*cur)->kind != R_PARENTHESES) {
            params = parse_param_list(cur, &param_count, &is_variadic);
        }
        if (!expect(cur, R_PARENTHESES)) parse_error("expected ')' after function literal parameters", token_head, *cur);
        if ((*cur)->kind == FAT_ARROW) {
            *cur = (*cur)->next;
        }
        ASTNode *body = parse_block(cur);
        return new_fun_literal(params, param_count, body, is_variadic);
    }
    if ((*cur)->kind == L_PARENTHESES) {
        *cur = (*cur)->next;
        if ((*cur)->kind == L_BRACE) {
            ASTNode *block = parse_block(cur);
            if (!expect(cur, R_PARENTHESES)) parse_error("expected ')' after statement expression", token_head, *cur);
            return new_stmt_expr(block);
        }
        ASTNode *node = parse_expr(cur);
        if (!expect(cur, R_PARENTHESES)) parse_error("expected ')'", token_head, *cur);
        return node;
    }
    parse_error("expected primary", token_head, *cur);
    return NULL;
}
