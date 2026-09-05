#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode *parse_stmt(ParserContext *context, Token **cur);
ASTNode *parse_block(ParserContext *context, Token **cur);

ASTNode *parse_block(ParserContext *context, Token **cur) {
    Token *start = *cur;
    if (!expect(cur, L_BRACE)) parse_error(context, "expected '{'", *cur);
    ASTNode **stmts = NULL;
    int count = 0;
    while ((*cur)->kind != R_BRACE && (*cur)->kind != EOT) {
        stmts = realloc(stmts, sizeof(ASTNode*) * (count+1));
        stmts[count++] = parse_stmt(context, cur);
    }
    if (!expect(cur, R_BRACE)) parse_error(context, "expected '}'", *cur);
    ASTNode *block = new_block(stmts, count);
    set_node_loc_from_tokens(block, start, NULL);
    return block;
}

ASTNode *parse_while_stmt(ParserContext *context, Token **cur) {
    if (!expect(cur, WHILE)) parse_error(context, "expected 'while'", *cur);
    if (!expect(cur, L_PARENTHESES)) parse_error(context, "expected '(' after while", *cur);
    ASTNode *cond = parse_expr(context, cur);
    if (!expect(cur, R_PARENTHESES)) parse_error(context, "expected ')'", *cur);
    ASTNode *body = parse_stmt(context, cur);
    return new_while(cond, body);
}

ASTNode *parse_do_while_stmt(ParserContext *context, Token **cur) {
    if (!expect(cur, DO)) parse_error(context, "expected 'do'", *cur);
    ASTNode *body = parse_stmt(context, cur);
    if (!expect(cur, WHILE)) parse_error(context, "expected 'while' after do-body", *cur);
    if (!expect(cur, L_PARENTHESES)) parse_error(context, "expected '(' after while", *cur);
    ASTNode *cond = parse_expr(context, cur);
    if (!expect(cur, R_PARENTHESES)) parse_error(context, "expected ')'", *cur);
    if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';' after do-while", *cur);
    return new_do_while(cond, body);
}

ASTNode *parse_for_stmt(ParserContext *context, Token **cur) {
    if (!expect(cur, FOR)) parse_error(context, "expected 'for'", *cur);
    if (!expect(cur, L_PARENTHESES)) parse_error(context, "expected '(' after for", *cur);

    // for (init; cond; inc)
    ASTNode *init = NULL, *cond = NULL, *inc = NULL;

    if ((*cur)->kind != SEMICOLON) {
        if (is_type(context, (*cur)->kind, *cur) ||
            ((*cur)->kind == MUT && (*cur)->next && is_type(context, (*cur)->next->kind, (*cur)->next))) {
            init = parse_variable_declaration(context, cur, 0);
        } else {
            init = parse_expr(context, cur);
        }
    }
    if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';' after for-init", *cur);

    if ((*cur)->kind != SEMICOLON) {
        cond = parse_expr(context, cur);
    }
    if (!expect(cur, SEMICOLON)) parse_error(context, "expected second ';' in for", *cur);

    if ((*cur)->kind != R_PARENTHESES) {
        inc = parse_expr(context, cur);
    }
    if (!expect(cur, R_PARENTHESES)) parse_error(context, "expected ')' after for", *cur);

    ASTNode *body = parse_stmt(context, cur);
    return new_for(init, cond, inc, body);
}

ASTNode *parse_if_stmt(ParserContext *context, Token **cur) {
    if (!expect(cur, IF)) parse_error(context, "expected 'if'", *cur);
    if (!expect(cur, L_PARENTHESES)) parse_error(context, "expected '(' after if", *cur);
    ASTNode *cond = parse_expr(context, cur);
    if (!expect(cur, R_PARENTHESES)) parse_error(context, "expected ')'", *cur);
    ASTNode *then_stmt = parse_stmt(context, cur);
    ASTNode *else_stmt = NULL;
    if ((*cur)->kind == ELSE) {
        expect(cur, ELSE);
        else_stmt = parse_stmt(context, cur);
    }
    return new_if(cond, then_stmt, else_stmt);
}
ASTNode *parse_return_stmt(ParserContext *context, Token **cur) {
    Token *start = *cur;
    if (!expect(cur, RETURN)) parse_error(context, "expected 'return'", *cur);
    ASTNode *expr = NULL;
    if ((*cur)->kind != SEMICOLON) {
        expr = parse_expr(context, cur);
    }
    Token *end_tok = *cur;
    if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';' after return", *cur);
    ASTNode *node = new_return(expr);
    set_node_loc_from_tokens(node, start, NULL);
    if (expr) {
        set_node_range_from_children(node, node, expr);
    } else {
        set_node_end_from_token(node, end_tok);
    }
    return node;
}
ASTNode *parse_expr_stmt(ParserContext *context, Token **cur) {
    ASTNode *expr = parse_expr(context, cur);
    if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';' after expression", *cur);
    return new_expr_stmt(expr);
}

static ASTNode *parse_init_list(ParserContext *context, Token **cur) {
    if (!expect(cur, L_BRACE)) parse_error(context, "expected '{' for initializer list", *cur);
    ASTNode **elems = NULL;
    int count = 0;
    if ((*cur)->kind != R_BRACE) {
        while (1) {
            ASTNode *e = parse_expr(context, cur);
            elems = realloc(elems, sizeof(ASTNode*) * (count + 1));
            elems[count++] = e;
            if ((*cur)->kind == COMMA) {
                *cur = (*cur)->next;
                continue;
            }
            break;
        }
    }
    if (!expect(cur, R_BRACE)) parse_error(context, "expected '}' to close initializer list", *cur);
    return new_init_list(elems, count);
}
ASTNode *parse_variable_declaration(ParserContext *context, Token **cur, int need_semicolon) {
    int is_mut = 0;
    Token *start = *cur;
    if ((*cur)->kind == MUT) {
        is_mut = 1;
        *cur = (*cur)->next;
        start = *cur;
    }
    ASTNode *type = parse_type(context, cur);
    if ((*cur)->kind != IDENTIFIER)
        parse_error(context, "expected identifier for variable name", *cur);
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
        if (!expect(cur, R_BRACKET)) parse_error(context, "expected ']' for array", *cur);
        final_type = new_type_array(final_type, size);
    }

    ASTNode *init = NULL;
    if (expect(cur, ASSIGN)) {
        if ((*cur)->kind == L_BRACE) {
            init = parse_init_list(context, cur);
        } else {
            init = parse_expr(context, cur);
        }
        if (final_type && final_type->type == AST_TYPE_ARRAY && final_type->type_array.array_size <= 0) {
            if (init && init->type == AST_STRING_LITERAL) {
                int inferred = (int)strlen(init->string_literal.value) + 1; // include NUL
                final_type->type_array.array_size = inferred;
            } else if (init && init->type == AST_INIT_LIST) {
                final_type->type_array.array_size = init->init_list.count;
            }
        }
    }
    Token *end_tok = *cur;
    if (need_semicolon) {
        if (!expect(cur, SEMICOLON))
            parse_error(context, "expected ';' after variable declaration", *cur);
    }
    ASTNode *decl = new_var_decl_mut(final_type, name, init, is_mut);
    set_node_loc_from_tokens(decl, start, name_tok);
    if (init) {
        set_node_range_from_children(decl, decl, init);
    } else if (need_semicolon) {
        set_node_end_from_token(decl, end_tok);
    } else {
        set_node_end_from_token(decl, name_tok);
    }
    return decl;
}


ASTNode *parse_variable_assignment(ParserContext *context, Token **cur) {
    if ((*cur)->kind != IDENTIFIER) parse_error(context, "expected identifier for assignment", *cur);
    Token *name_tok = *cur;
    char *name = name_tok->value;
    *cur = (*cur)->next;
    if (!expect(cur, ASSIGN)) parse_error(context, "expected '=' for assignment", *cur);
    ASTNode *expr = parse_expr(context, cur);
    Token *end_tok = *cur;
    if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';' after assignment", *cur);
    ASTNode *lhs = new_identifier(name);
    set_node_loc_from_tokens(lhs, name_tok, NULL);
    ASTNode *assign = new_assign(lhs, expr);
    set_node_loc_from_tokens(assign, name_tok, NULL);
    if (expr) {
        set_node_range_from_children(assign, assign, expr);
    } else {
        set_node_end_from_token(assign, end_tok);
    }
    return assign;
}

ASTNode *parse_stmt(ParserContext *context, Token **cur) {
    if ((*cur)->kind == IF) return parse_if_stmt(context, cur);
    if ((*cur)->kind == WHILE) return parse_while_stmt(context, cur);
    if ((*cur)->kind == DO) return parse_do_while_stmt(context, cur);
    if ((*cur)->kind == FOR) return parse_for_stmt(context, cur);
    if ((*cur)->kind == UNCHECKED) {
        *cur = (*cur)->next;
        context->control.unchecked_depth++;
        ASTNode *body = parse_block(context, cur);
        context->control.unchecked_depth--;
        return new_unchecked_block(body);
    }
    if ((*cur)->kind == RETURN) return parse_return_stmt(context, cur);
    if ((*cur)->kind == YIELD) {
        *cur = (*cur)->next;
        ASTNode *expr = parse_expr(context, cur);
        if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';' after yield", *cur);
        return new_yield(expr);
    }

    if ((*cur)->kind == BREAK) {
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';' after break", *cur);
        return new_break();
    }
    if ((*cur)->kind == CONTINUE) {
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';' after continue", *cur);
        return new_continue();
    }

    if ((*cur)->kind == L_BRACE) return parse_block(context, cur);
    if ((*cur)->kind == MUT && (*cur)->next && is_type(context, (*cur)->next->kind, (*cur)->next)) return parse_variable_declaration(context, cur, 1);
    if (is_type(context, (*cur)->kind, *cur)) return parse_variable_declaration(context, cur, 1);

    return parse_expr_stmt(context, cur);
}
