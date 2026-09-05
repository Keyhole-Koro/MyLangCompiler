#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode *parse_unary(Token **cur) {
    if ((*cur)->kind == L_PARENTHESES) {
        Token *tmp = (*cur)->next;
        if (tmp && is_type(tmp->kind, tmp)) {
            Token *after_type = tmp;
            ASTNode *cast_type = parse_type(&after_type);
            if (after_type && after_type->kind == R_PARENTHESES) {
                *cur = after_type->next;
                return new_cast(cast_type, parse_unary(cur));
            }
        }
    }
    if ((*cur)->kind == SUB) {
        *cur = (*cur)->next;
        return new_unary(SUB, parse_unary(cur));
    }
    if ((*cur)->kind == BITNOT) {
        *cur = (*cur)->next;
        return new_unary(BITNOT, parse_unary(cur));
    }
    if ((*cur)->kind == NOT) {
        *cur = (*cur)->next;
        return new_unary(NOT, parse_unary(cur));
    }
    if ((*cur)->kind == AMPERSAND) {
        *cur = (*cur)->next;
        if (parser_context_current()->control.unchecked_depth == 0 && (*cur)->kind == MUT) {
            *cur = (*cur)->next;
            return new_borrow_mut(parse_unary(cur));
        }
        if (parser_context_current()->control.unchecked_depth == 0) {
            return new_borrow(parse_unary(cur));
        }
        return new_unary(AMPERSAND, parse_unary(cur));
    }
    if ((*cur)->kind == ASTARISK) {
        *cur = (*cur)->next;
        return new_unary(ASTARISK, parse_unary(cur));
    }
    if ((*cur)->kind == INC) {
        *cur = (*cur)->next;
        return new_unary(INC, parse_unary(cur));
    }
    if ((*cur)->kind == DEC) {
        *cur = (*cur)->next;
        return new_unary(DEC, parse_unary(cur));
    }
    if ((*cur)->kind == SIZEOF) {
        *cur = (*cur)->next;
        if (!expect(cur, L_PARENTHESES)) parse_error("expected '(' after sizeof", *cur);
        ASTNode *inner = parse_expr(cur);
        if (!expect(cur, R_PARENTHESES)) parse_error("expected ')' after sizeof expression", *cur);
        return new_sizeof(inner);
    }
    if ((*cur)->kind == STRING_LITERAL) {
        Token *tok = *cur;
        ASTNode *node = new_string_literal((*cur)->value);
        set_node_loc_from_tokens(node, tok, NULL);
        *cur = (*cur)->next;
        return node;
    }
    if ((*cur)->kind == CHAR_LITERAL) {
        Token *tok = *cur;
        ASTNode *node = new_char_literal((*cur)->value);
        set_node_loc_from_tokens(node, tok, NULL);
        *cur = (*cur)->next;
        return node;
    }

    return parse_postfix(cur);
}
