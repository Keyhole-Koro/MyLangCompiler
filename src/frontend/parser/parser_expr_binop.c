#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode *parse_mul(ParserContext *context, Token **cur) {
    ASTNode *node = parse_unary(context, cur);
    while ((*cur)->kind == ASTARISK || (*cur)->kind == DIV || (*cur)->kind == MOD) {
        TokenKind op = (*cur)->kind;
        *cur = (*cur)->next;
        node = new_binary(op, node, parse_unary(context, cur));
    }
    return node;
}

ASTNode *parse_add(ParserContext *context, Token **cur) {
    ASTNode *node = parse_mul(context, cur);
    while ((*cur)->kind == ADD || (*cur)->kind == SUB) {
        TokenKind op = (*cur)->kind;
        *cur = (*cur)->next;
        node = new_binary(op, node, parse_mul(context, cur));
    }
    return node;
}

ASTNode *parse_shift(ParserContext *context, Token **cur) {
    ASTNode *node = parse_add(context, cur);
    while (1) {
        if ((*cur)->kind == LSH) {
            *cur = (*cur)->next;
            node = new_binary(LSH, node, parse_add(context, cur));
        } else if ((*cur)->kind == RSH) {
            *cur = (*cur)->next;
            node = new_binary(RSH, node, parse_add(context, cur));
        } else {
            break;
        }
    }
    return node;
}

ASTNode *parse_relational(ParserContext *context, Token **cur) {
    ASTNode *node = parse_shift(context, cur);
    while (1) {
        if ((*cur)->kind == LT) {
            *cur = (*cur)->next;
            node = new_binary(LT, node, parse_add(context, cur));
        } else if ((*cur)->kind == GT) {
            *cur = (*cur)->next;
            node = new_binary(GT, node, parse_add(context, cur));
        } else if ((*cur)->kind == LTE) {
            *cur = (*cur)->next;
            node = new_binary(LTE, node, parse_add(context, cur));
        } else if ((*cur)->kind == GTE) {
            *cur = (*cur)->next;
            node = new_binary(GTE, node, parse_add(context, cur));
        } else break;
    }
    return node;
}

ASTNode *parse_equality(ParserContext *context, Token **cur) {
    ASTNode *node = parse_relational(context, cur);
    while (1) {
        if ((*cur)->kind == EQ) {
            *cur = (*cur)->next;
            node = new_binary(EQ, node, parse_relational(context, cur));
        } else if ((*cur)->kind == NEQ) {
            *cur = (*cur)->next;
            node = new_binary(NEQ, node, parse_relational(context, cur));
        } else break;
    }
    return node;
}

ASTNode *parse_bitwise_and(ParserContext *context, Token **cur) {
    ASTNode *node = parse_equality(context, cur);
    while ((*cur)->kind == AMPERSAND) {
        *cur = (*cur)->next;
        node = new_binary(AMPERSAND, node, parse_equality(context, cur));
    }
    return node;
}

ASTNode *parse_bitwise_xor(ParserContext *context, Token **cur) {
    ASTNode *node = parse_bitwise_and(context, cur);
    while ((*cur)->kind == BITXOR) {
        *cur = (*cur)->next;
        node = new_binary(BITXOR, node, parse_bitwise_and(context, cur));
    }
    return node;
}

ASTNode *parse_bitwise_or(ParserContext *context, Token **cur) {
    ASTNode *node = parse_bitwise_xor(context, cur);
    while ((*cur)->kind == BITOR) {
        *cur = (*cur)->next;
        node = new_binary(BITOR, node, parse_bitwise_xor(context, cur));
    }
    return node;
}

ASTNode *parse_logical_and(ParserContext *context, Token **cur) {
    ASTNode *node = parse_bitwise_or(context, cur);
    while ((*cur)->kind == LAND) {
        *cur = (*cur)->next;
        node = new_binary(LAND, node, parse_bitwise_or(context, cur));
    }
    return node;
}

ASTNode *parse_logical_or(ParserContext *context, Token **cur) {
    ASTNode *node = parse_logical_and(context, cur);
    while ((*cur)->kind == LOR) {
        *cur = (*cur)->next;
        node = new_binary(LOR, node, parse_logical_and(context, cur));
    }
    return node;
}

ASTNode *parse_conditional(ParserContext *context, Token **cur) {
    ASTNode *cond = parse_logical_or(context, cur);
    if ((*cur)->kind == QUESTION) {
        *cur = (*cur)->next;
        ASTNode *then_expr = parse_expr(context, cur);
        if (!expect(cur, COLON))
            parse_error(context, "expected ':' in ternary expression", *cur);
        ASTNode *else_expr = parse_conditional(context, cur);
        return new_ternary(cond, then_expr, else_expr);
    }
    return cond;
}

ASTNode *parse_assign_expr(ParserContext *context, Token **cur) {
    ASTNode *node = parse_conditional(context, cur);
    if ((*cur)->kind == ASSIGN) {
        *cur = (*cur)->next;
        node = new_assign(node, parse_assign_expr(context, cur));
    }
    return node;
}

ASTNode *parse_expr(ParserContext *context, Token **cur) {
    return parse_assign_expr(context, cur);
}
