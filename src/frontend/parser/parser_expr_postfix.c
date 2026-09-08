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
            /* `EnumName::Variant` -- collapses to a single identifier named
             * "EnumName::Variant", literal colons included, the same way a
             * package-qualified call collapses to "pkg_func" just above.
             * Nothing else in the language gives `::` a meaning, so this
             * collapses unconditionally rather than checking `node` against
             * a registry first (parser_payload_enum.c's find_variant, and
             * numeric enums' own EnumConstant lookup, resolve the qualifier
             * once every enum in the program is known, not while parsing one
             * file's tokens left to right); whichever of those it does not
             * resolve to fails the same way any other undefined name would.
             * Followed by `(args)`, the L_PARENTHESES branch below turns
             * this into a call exactly as it would an unqualified name. */
            *cur = (*cur)->next;
            if ((*cur)->kind != IDENTIFIER)
                parse_error(context, "expected identifier after '::'", *cur);
            if (node->type != AST_IDENTIFIER)
                parse_error(context, "'::' must follow a plain name", *cur);
            char *member_name = (*cur)->value;
            *cur = (*cur)->next;
            char buf[256];
            snprintf(buf, sizeof(buf), "%s::%s", node->identifier.name, member_name);
            free_ast(node);

            /* A numeric enum's members are constants substituted at parse
             * time (parse_identifier_primary) -- which already ran, on just
             * "EnumName", before "::Member" was even in view. Registered
             * under this same qualified spelling (parser_type.c), so the
             * lookup this collapse just missed happens here instead. A
             * payload enum's variant is not resolved until every enum in the
             * program has been seen (parser_payload_enum.c), so it stays a
             * qualified identifier/call for that pass to resolve later. */
            long enum_val;
            if (find_enum_constant(context, buf, &enum_val)) {
                char num[32];
                snprintf(num, sizeof(num), "%ld", enum_val);
                node = new_number(num);
            } else {
                node = new_identifier(buf);
            }
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
