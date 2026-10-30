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

/* `for (T x in iter) body` asks `iter` for items until its Iterator's next()
 * returns None:
 *
 *     {
 *         <iter type> __mlg_for_iter_N = iter;        // unless iter is a local
 *         while (1) {
 *             Option<T> __mlg_for_next_N = __mlg_for_iter_N.next();
 *             case __mlg_for_next_N of {
 *                 Option::Some(__mlg_for_item_N) -> 0;
 *                 Option::None -> ({ break; });
 *             };
 *             T x = __mlg_for_next_N.Some;
 *             body
 *         }
 *     }
 *
 * The item is read from the Some payload's field (Option lowers to a tagged
 * struct with one field per variant) rather than yielded by the case: a case
 * that yields a struct does not copy it into its destination yet.
 *
 * The iterator temporary's type is filled in by lower_trait_uses(), which
 * also requires an Iterator impl for it. A local is iterated in place, so it
 * is advanced by the loop just as next() calls would advance it. */
static ASTNode *parse_for_in(ParserContext *context, Token **cur, Token *for_tok) {
    ASTNode *item_type = parse_type(context, cur);
    Token *name_tok = *cur;
    *cur = (*cur)->next; /* loop variable */
    *cur = (*cur)->next; /* in */
    ASTNode *iter = parse_expr(context, cur);
    if (!expect(cur, R_PARENTHESES)) parse_error(context, "expected ')' after for-in iterator", *cur);
    ASTNode *body = parse_stmt(context, cur);
    if (!find_generic_type_template(context, "Option"))
        parse_error(context, "for-in needs Option: import { Option } from \"@std/core/option.mln\";",
                    for_tok);

    int id = context->lowering.payload_case_counter++;
    char iter_name[48], next_name[48], item_name[48];
    snprintf(iter_name, sizeof(iter_name), "__mlg_for_iter_%d", id);
    snprintf(next_name, sizeof(next_name), "__mlg_for_next_%d", id);
    snprintf(item_name, sizeof(item_name), "__mlg_for_item_%d", id);

    ASTNode **outer = malloc(sizeof(ASTNode *) * 2);
    int outer_count = 0;
    ASTNode *iter_ref = iter;
    if (iter->type != AST_IDENTIFIER || strstr(iter->identifier.name, "::")) {
        ASTNode *placeholder = new_type_node(new_identifier("__mlg_for_iter_type"), 0, 0, REFKIND_NONE);
        ASTNode *decl = new_var_decl_mut(placeholder, iter_name, iter, 1);
        set_node_loc_from_tokens(decl, for_tok, NULL);
        outer[outer_count++] = decl;
        iter_ref = new_identifier(iter_name);
    }

    ASTNode **option_args = malloc(sizeof(ASTNode *));
    option_args[0] = ast_clone(item_type);
    ASTNode *option_type = new_type_node(new_generic_type("Option", option_args, 1), 0, 0, REFKIND_NONE);
    ASTNode *next_call = new_call("next", NULL, 0);
    next_call->call.recv = iter_ref;
    set_node_loc_from_tokens(next_call, for_tok, NULL);
    ASTNode *next_decl = new_var_decl(option_type, next_name, next_call);
    set_node_loc_from_tokens(next_decl, for_tok, NULL);

    CaseItem *arms = calloc(2, sizeof(CaseItem));
    ASTNode **some_args = malloc(sizeof(ASTNode *));
    some_args[0] = new_identifier(item_name);
    arms[0].key = new_call("Option::Some", some_args, 1);
    arms[0].expr = new_number("0");
    arms[1].key = new_identifier("Option::None");
    ASTNode **break_stmt = malloc(sizeof(ASTNode *));
    break_stmt[0] = new_break();
    arms[1].expr = new_stmt_expr(new_block(break_stmt, 1));
    ASTNode *match = new_case_expr(new_identifier(next_name), arms, 2, NULL, 0);
    set_node_loc_from_tokens(match, for_tok, NULL);
    ASTNode *stop = new_expr_stmt(match);
    ASTNode *item = new_member_access(new_identifier(next_name), "Some");
    ASTNode *item_decl = new_var_decl(item_type, name_tok->value, item);
    set_node_loc_from_tokens(item_decl, name_tok, NULL);

    ASTNode **loop_stmts = malloc(sizeof(ASTNode *) * 4);
    loop_stmts[0] = next_decl;
    loop_stmts[1] = stop;
    loop_stmts[2] = item_decl;
    loop_stmts[3] = body;
    ASTNode *loop = new_while(new_number("1"), new_block(loop_stmts, 4));
    set_node_loc_from_tokens(loop, for_tok, NULL);
    outer[outer_count++] = loop;
    return new_block(outer, outer_count);
}

ASTNode *parse_for_stmt(ParserContext *context, Token **cur) {
    Token *for_tok = *cur;
    if (!expect(cur, FOR)) parse_error(context, "expected 'for'", *cur);
    if (!expect(cur, L_PARENTHESES)) parse_error(context, "expected '(' after for", *cur);
    if (looks_like_for_in(context, *cur)) return parse_for_in(context, cur, for_tok);

    // for (init; cond; inc)
    ASTNode *init = NULL, *cond = NULL, *inc = NULL;

    if ((*cur)->kind != SEMICOLON) {
        if ((is_type(context, (*cur)->kind, *cur) &&
             ((*cur)->kind != FN || looks_like_function_type_declaration(context, *cur))) ||
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
    // `return Err(...)` is where an error return trace starts.
    if (expr && expr->type == AST_CALL && expr->call.name && strcmp(expr->call.name, "Err") == 0)
        node->ret.trace_kind = RET_TRACE_ORIGIN;
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

static ASTNode *parse_defer_stmt(ParserContext *context, Token **cur) {
    Token *start = *cur;
    if (!expect(cur, DEFER)) parse_error(context, "expected 'defer'", *cur);
    ASTNode *body = (*cur)->kind == L_BRACE
        ? parse_block(context, cur)
        : parse_expr_stmt(context, cur);
    ASTNode *node = new_defer(body);
    set_node_loc_from_tokens(node, start, NULL);
    set_node_range_from_children(node, node, body);
    return node;
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
    if (!token_is_name(*cur))
        parse_error(context, "expected identifier for variable name", *cur);
    Token *name_tok = *cur;
    char *name = name_tok->value;
    *cur = (*cur)->next;

    ASTNode *final_type = type;
    while ((*cur)->kind == L_BRACKET) {
        *cur = (*cur)->next;
        int size = -1;
        const char *size_param = NULL;
        if ((*cur)->kind == NUMBER) {
            size = atoi((*cur)->value);
            *cur = (*cur)->next;
        } else if ((*cur)->kind == IDENTIFIER && context->control.generic_decl_depth > 0) {
            size_param = (*cur)->value;
            *cur = (*cur)->next;
        }
        if (!expect(cur, R_BRACKET)) parse_error(context, "expected ']' for array", *cur);
        final_type = size_param
            ? new_type_array_param(final_type, size_param)
            : new_type_array(final_type, size);
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
    if (!token_is_name(*cur)) parse_error(context, "expected identifier for assignment", *cur);
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
    if ((*cur)->kind == DEFER) return parse_defer_stmt(context, cur);
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
    if (is_type(context, (*cur)->kind, *cur) &&
        ((*cur)->kind != FN || looks_like_function_type_declaration(context, *cur)))
        return parse_variable_declaration(context, cur, 1);

    return parse_expr_stmt(context, cur);
}
