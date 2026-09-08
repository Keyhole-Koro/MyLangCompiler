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
            if (!token_is_name(*cur))
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
        } else if ((*cur)->kind == COLONCOLON) {
            /* Preserve enum qualification as one name.  Payload-enum lowering
             * resolves it after every enum declaration is available, whereas
             * a numeric enum can be resolved here from its constant table. */
            if (node->type != AST_IDENTIFIER)
                parse_error(context, "'::' must follow a plain name", *cur);

            int line = node->line;
            int col = node->col;
            *cur = (*cur)->next;
            if ((*cur)->kind != IDENTIFIER)
                parse_error(context, "expected identifier after '::'", *cur);

            Token *member_tok = *cur;
            char qualified[256];
            snprintf(qualified, sizeof(qualified), "%s::%s", node->identifier.name,
                     member_tok->value);
            *cur = (*cur)->next;
            free_ast(node);

            long enum_value;
            if (find_enum_constant(context, qualified, &enum_value)) {
                char text[32];
                snprintf(text, sizeof(text), "%ld", enum_value);
                node = new_number(text);
            } else {
                node = new_identifier(qualified);
            }
            node->line = line;
            node->col = col;
            set_node_end_from_token(node, member_tok);
        } else if ((*cur)->kind == ARROW) {
            if (!token_is_name((*cur)->next)) break;
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
            if (!token_is_name(*cur))
                parse_error(context, "expected identifier after '->'", *cur);
            char *member_name = (*cur)->value;
            *cur = (*cur)->next;
            node = new_arrow_access(node, member_name);
        } else if ((*cur)->kind == L_PARENTHESES &&
                   (node->type == AST_IDENTIFIER ||
                    node->type == AST_MEMBER_ACCESS ||
                    node->type == AST_ARROW_ACCESS)) {
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
            if (node->type == AST_IDENTIFIER) {
                node = new_call(node->identifier.name, args, arg_count);
            } else {
                /* `recv.method(args)` / `recv->method(args)`: leave the call
                 * unresolved (bare method name, `recv` set) for
                 * resolve_method_calls() to mangle once every method
                 * declared in this file is known. `.` and `->` are treated
                 * identically here -- which conversion the declared receiver
                 * needs (none, `&`, `&mut`, or `*`) is decided from `recv`'s
                 * static type during resolution, not from which token got us
                 * here. */
                int is_member = node->type == AST_MEMBER_ACCESS;
                ASTNode *recv = is_member ? node->member_access.lhs : node->arrow_access.lhs;
                char *method_name = is_member ? node->member_access.member : node->arrow_access.member;
                ASTNode *call = new_call(method_name, args, arg_count);
                call->call.recv = recv;
                free(method_name);
                free(node);
                node = call;
            }
            node->line = line;
            node->col = col;
        } else {
            break;
        }
    }
    return node;
}
