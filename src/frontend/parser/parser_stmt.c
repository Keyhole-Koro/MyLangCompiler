#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode *parse_stmt(Token **cur);
ASTNode *parse_block(Token **cur);

ASTNode *parse_block(Token **cur) {
    if (!expect(cur, L_BRACE)) parse_error("expected '{'", token_head, *cur);
    ASTNode **stmts = NULL;
    int count = 0;
    while ((*cur)->kind != R_BRACE && (*cur)->kind != EOT) {
        stmts = realloc(stmts, sizeof(ASTNode*) * (count+1));
        stmts[count++] = parse_stmt(cur);
    }
    if (!expect(cur, R_BRACE)) parse_error("expected '}'", token_head, *cur);
    root = new_block(stmts, count);
    return root;
}

ASTNode *parse_while_stmt(Token **cur) {
    if (!expect(cur, WHILE)) parse_error("expected 'while'", token_head, *cur);
    if (!expect(cur, L_PARENTHESES)) parse_error("expected '(' after while", token_head, *cur);
    ASTNode *cond = parse_expr(cur);
    if (!expect(cur, R_PARENTHESES)) parse_error("expected ')'", token_head, *cur);
    ASTNode *body = parse_stmt(cur);
    return new_while(cond, body);
}

ASTNode *parse_do_while_stmt(Token **cur) {
    if (!expect(cur, DO)) parse_error("expected 'do'", token_head, *cur);
    ASTNode *body = parse_stmt(cur);
    if (!expect(cur, WHILE)) parse_error("expected 'while' after do-body", token_head, *cur);
    if (!expect(cur, L_PARENTHESES)) parse_error("expected '(' after while", token_head, *cur);
    ASTNode *cond = parse_expr(cur);
    if (!expect(cur, R_PARENTHESES)) parse_error("expected ')'", token_head, *cur);
    if (!expect(cur, SEMICOLON)) parse_error("expected ';' after do-while", token_head, *cur);
    return new_do_while(cond, body);
}

ASTNode *parse_for_stmt(Token **cur) {
    if (!expect(cur, FOR)) parse_error("expected 'for'", token_head, *cur);
    if (!expect(cur, L_PARENTHESES)) parse_error("expected '(' after for", token_head, *cur);

    // for (init; cond; inc)
    ASTNode *init = NULL, *cond = NULL, *inc = NULL;

    if ((*cur)->kind != SEMICOLON) {
        if (is_type((*cur)->kind, *cur)) {
            init = parse_variable_declaration(cur, 0);
        } else {
            init = parse_expr(cur);
        }
    }
    if (!expect(cur, SEMICOLON)) parse_error("expected ';' after for-init", token_head, *cur);

    if ((*cur)->kind != SEMICOLON) {
        cond = parse_expr(cur);
    }
    if (!expect(cur, SEMICOLON)) parse_error("expected second ';' in for", token_head, *cur);

    if ((*cur)->kind != R_PARENTHESES) {
        inc = parse_expr(cur);
    }
    if (!expect(cur, R_PARENTHESES)) parse_error("expected ')' after for", token_head, *cur);

    ASTNode *body = parse_stmt(cur);
    return new_for(init, cond, inc, body);
}

ASTNode *parse_if_stmt(Token **cur) {
    if (!expect(cur, IF)) parse_error("expected 'if'", token_head, *cur);
    if (!expect(cur, L_PARENTHESES)) parse_error("expected '(' after if", token_head, *cur);
    ASTNode *cond = parse_expr(cur);
    if (!expect(cur, R_PARENTHESES)) parse_error("expected ')'", token_head, *cur);
    ASTNode *then_stmt = parse_stmt(cur);
    ASTNode *else_stmt = NULL;
    if ((*cur)->kind == ELSE) {
        expect(cur, ELSE);
        else_stmt = parse_stmt(cur);
    }
    return new_if(cond, then_stmt, else_stmt);
}
ASTNode *parse_return_stmt(Token **cur) {
    if (!expect(cur, RETURN)) parse_error("expected 'return'", token_head, *cur);
    ASTNode *expr = parse_expr(cur);
    if (!expect(cur, SEMICOLON)) parse_error("expected ';' after return", token_head, *cur);
    return new_return(expr);
}
ASTNode *parse_expr_stmt(Token **cur) {
    ASTNode *expr = parse_expr(cur);
    if (!expect(cur, SEMICOLON)) parse_error("expected ';' after expression", token_head, *cur);
    return new_expr_stmt(expr);
}

static ASTNode *parse_init_list(Token **cur) {
    if (!expect(cur, L_BRACE)) parse_error("expected '{' for initializer list", token_head, *cur);
    ASTNode **elems = NULL;
    int count = 0;
    if ((*cur)->kind != R_BRACE) {
        while (1) {
            ASTNode *e = parse_expr(cur);
            elems = realloc(elems, sizeof(ASTNode*) * (count + 1));
            elems[count++] = e;
            if ((*cur)->kind == COMMA) {
                *cur = (*cur)->next;
                continue;
            }
            break;
        }
    }
    if (!expect(cur, R_BRACE)) parse_error("expected '}' to close initializer list", token_head, *cur);
    return new_init_list(elems, count);
}
ASTNode *parse_variable_declaration(Token **cur, int need_semicolon) {
    ASTNode *type = parse_type(cur);
    if ((*cur)->kind != IDENTIFIER)
        parse_error("expected identifier for variable name", token_head, *cur);
    char *name = (*cur)->value;
    *cur = (*cur)->next;

    ASTNode *final_type = type;
    while ((*cur)->kind == L_BRACKET) {
        *cur = (*cur)->next;
        int size = -1;
        if ((*cur)->kind == NUMBER) {
            size = atoi((*cur)->value);
            *cur = (*cur)->next;
        }
        if (!expect(cur, R_BRACKET)) parse_error("expected ']' for array", token_head, *cur);
        final_type = new_type_array(final_type, size);
    }

    ASTNode *init = NULL;
    if (expect(cur, ASSIGN)) {
        if ((*cur)->kind == L_BRACE) {
            init = parse_init_list(cur);
        } else {
            init = parse_expr(cur);
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
    if (need_semicolon) {
        if (!expect(cur, SEMICOLON))
            parse_error("expected ';' after variable declaration", token_head, *cur);
    }
    return new_var_decl(final_type, name, init);
}


ASTNode *parse_variable_assignment(Token **cur) {
    if ((*cur)->kind != IDENTIFIER) parse_error("expected identifier for assignment", token_head, *cur);
    char *name = (*cur)->value;
    *cur = (*cur)->next;
    if (!expect(cur, ASSIGN)) parse_error("expected '=' for assignment", token_head, *cur);
    ASTNode *expr = parse_expr(cur);
    if (!expect(cur, SEMICOLON)) parse_error("expected ';' after assignment", token_head, *cur);
    return new_assign(new_identifier(name), expr);
}

ASTNode *parse_stmt(Token **cur) {
    if ((*cur)->kind == IF) return parse_if_stmt(cur);
    if ((*cur)->kind == WHILE) return parse_while_stmt(cur);
    if ((*cur)->kind == DO) return parse_do_while_stmt(cur);
    if ((*cur)->kind == FOR) return parse_for_stmt(cur);
    if ((*cur)->kind == RETURN) return parse_return_stmt(cur);
    if ((*cur)->kind == YIELD) {
        *cur = (*cur)->next;
        ASTNode *expr = parse_expr(cur);
        if (!expect(cur, SEMICOLON)) parse_error("expected ';' after yield", token_head, *cur);
        return new_yield(expr);
    }

    if ((*cur)->kind == BREAK) {
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON)) parse_error("expected ';' after break", token_head, *cur);
        return new_break();
    }
    if ((*cur)->kind == CONTINUE) {
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON)) parse_error("expected ';' after continue", token_head, *cur);
        return new_continue();
    }

    if ((*cur)->kind == L_BRACE) return parse_block(cur);
    if (is_type((*cur)->kind, *cur)) return parse_variable_declaration(cur, 1);

    printf("DEBUG: parse_stmt falling back to expr_stmt at token kind %s\n", tokenkind2str((*cur)->kind));
    return parse_expr_stmt(cur);
}
