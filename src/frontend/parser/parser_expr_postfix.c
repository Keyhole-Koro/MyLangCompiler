#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode *parse_postfix(ParserContext *context, Token **cur) {
    ASTNode *node = parse_primary(context, cur);
    while (1) {
        if ((*cur)->kind == INC) {
            *cur = (*cur)->next;
            node = new_unary(POST_INC, node);
        } else if ((*cur)->kind == DEC) {
            *cur = (*cur)->next;
            node = new_unary(POST_DEC, node);
        } else if ((*cur)->kind == DOT) {
            *cur = (*cur)->next;
            if ((*cur)->kind != IDENTIFIER)
                parse_error(context, "expected identifier after '.'", *cur);
            char *member_name = (*cur)->value;
            *cur = (*cur)->next;
            if (node->type == AST_IDENTIFIER && is_imported_package(context, node->identifier.name)) {
                char buf[256];
                snprintf(buf, sizeof(buf), "%s_%s", node->identifier.name, member_name);
                node = new_identifier(buf);
            } else {
                node = new_member_access(node, member_name);
            }
        } else if ((*cur)->kind == ARROW) {
            if (!(*cur)->next || (*cur)->next->kind != IDENTIFIER) break;
            if (context->control.stop_at_arrow) {
                /* Inside a case key, `->` is ambiguous after a bare name: it
                 * reads as an access in `addr->val -> 100` and as the arm arrow
                 * in `None -> fallback`, and a payload variant carrying nothing
                 * is spelled exactly like the latter. One token of lookahead
                 * separates them -- an access is followed by another arrow,
                 * which is the arm's. Once the key is already an access there is
                 * no ambiguity left, so chains keep working. */
                if (node->type == AST_IDENTIFIER) {
                    Token *after_member = (*cur)->next->next;
                    if (!after_member || after_member->kind != ARROW) break;
                } else if (!(node->type == AST_MEMBER_ACCESS ||
                             node->type == AST_ARROW_ACCESS)) {
                    break;
                }
            }
            *cur = (*cur)->next;
            if ((*cur)->kind != IDENTIFIER)
                parse_error(context, "expected identifier after '->'", *cur);
            char *member_name = (*cur)->value;
            *cur = (*cur)->next;
            node = new_arrow_access(node, member_name);
        } else if ((*cur)->kind == L_PARENTHESES && node->type == AST_IDENTIFIER) {
            int line = node->line;
            int col = node->col;
            *cur = (*cur)->next;
            ASTNode **args = NULL;
            int arg_count = 0;
            if ((*cur)->kind != R_PARENTHESES) {
                while (1) {
                    ASTNode *arg = parse_expr(context, cur);
                    args = realloc(args, sizeof(ASTNode*) * (arg_count + 1));
                    args[arg_count++] = arg;
                    if ((*cur)->kind == COMMA) {
                        *cur = (*cur)->next;
                        continue;
                    }
                    break;
                }
            }
            if (!expect(cur, R_PARENTHESES))
                parse_error(context, "expected ')' after args", *cur);
            node = new_call(node->identifier.name, args, arg_count);
            node->line = line;
            node->col = col;
        } else {
            break;
        }
    }
    return node;
}
