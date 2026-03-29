#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode *parse_mul(Token **cur) {
    ASTNode *node = parse_unary(cur);
    while ((*cur)->kind == ASTARISK || (*cur)->kind == DIV || (*cur)->kind == MOD) {
        TokenKind op = (*cur)->kind;
        *cur = (*cur)->next;
        node = new_binary(op, node, parse_unary(cur));
    }
    return node;
}

ASTNode *parse_add(Token **cur) {
    ASTNode *node = parse_mul(cur);
    while ((*cur)->kind == ADD || (*cur)->kind == SUB) {
        TokenKind op = (*cur)->kind;
        *cur = (*cur)->next;
        node = new_binary(op, node, parse_mul(cur));
    }
    return node;
}

ASTNode *parse_shift(Token **cur) {
    ASTNode *node = parse_add(cur);
    while (1) {
        if ((*cur)->kind == LSH) {
            *cur = (*cur)->next;
            node = new_binary(LSH, node, parse_add(cur));
        } else if ((*cur)->kind == RSH) {
            *cur = (*cur)->next;
            node = new_binary(RSH, node, parse_add(cur));
        } else {
            break;
        }
    }
    return node;
}

ASTNode *parse_relational(Token **cur) {
    ASTNode *node = parse_shift(cur);
    while (1) {
        if ((*cur)->kind == LT) {
            *cur = (*cur)->next;
            node = new_binary(LT, node, parse_add(cur));
        } else if ((*cur)->kind == GT) {
            *cur = (*cur)->next;
            node = new_binary(GT, node, parse_add(cur));
        } else if ((*cur)->kind == LTE) {
            *cur = (*cur)->next;
            node = new_binary(LTE, node, parse_add(cur));
        } else if ((*cur)->kind == GTE) {
            *cur = (*cur)->next;
            node = new_binary(GTE, node, parse_add(cur));
        } else break;
    }
    return node;
}

ASTNode *parse_equality(Token **cur) {
    ASTNode *node = parse_relational(cur);
    while (1) {
        if ((*cur)->kind == EQ) {
            *cur = (*cur)->next;
            node = new_binary(EQ, node, parse_relational(cur));
        } else if ((*cur)->kind == NEQ) {
            *cur = (*cur)->next;
            node = new_binary(NEQ, node, parse_relational(cur));
        } else break;
    }
    return node;
}

ASTNode *parse_bitwise_and(Token **cur) {
    ASTNode *node = parse_equality(cur);
    while ((*cur)->kind == AMPERSAND) {
        *cur = (*cur)->next;
        node = new_binary(AMPERSAND, node, parse_equality(cur));
    }
    return node;
}

ASTNode *parse_bitwise_xor(Token **cur) {
    ASTNode *node = parse_bitwise_and(cur);
    while ((*cur)->kind == BITXOR) {
        *cur = (*cur)->next;
        node = new_binary(BITXOR, node, parse_bitwise_and(cur));
    }
    return node;
}

ASTNode *parse_bitwise_or(Token **cur) {
    ASTNode *node = parse_bitwise_xor(cur);
    while ((*cur)->kind == BITOR) {
        *cur = (*cur)->next;
        node = new_binary(BITOR, node, parse_bitwise_xor(cur));
    }
    return node;
}

ASTNode *parse_logical_and(Token **cur) {
    ASTNode *node = parse_bitwise_or(cur);
    while ((*cur)->kind == LAND) {
        *cur = (*cur)->next;
        node = new_binary(LAND, node, parse_bitwise_or(cur));
    }
    return node;
}

ASTNode *parse_logical_or(Token **cur) {
    ASTNode *node = parse_logical_and(cur);
    while ((*cur)->kind == LOR) {
        *cur = (*cur)->next;
        node = new_binary(LOR, node, parse_logical_and(cur));
    }
    return node;
}

ASTNode *parse_conditional(Token **cur) {
    ASTNode *cond = parse_logical_or(cur);
    if ((*cur)->kind == QUESTION) {
        *cur = (*cur)->next;
        ASTNode *then_expr = parse_expr(cur);
        if (!expect(cur, COLON))
            parse_error("expected ':' in ternary expression", token_head, *cur);
        ASTNode *else_expr = parse_conditional(cur);
        return new_ternary(cond, then_expr, else_expr);
    }
    return cond;
}

ASTNode *parse_assign_expr(Token **cur) {
    ASTNode *node = parse_conditional(cur);
    if ((*cur)->kind == ASSIGN) {
        *cur = (*cur)->next;
        node = new_assign(node, parse_assign_expr(cur));
    }
    return node;
}

ASTNode *parse_expr(Token **cur) {
    return parse_assign_expr(cur);
}
