#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode *parse_postfix(Token **cur) {
    ASTNode *node = parse_primary(cur);
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
                parse_error("expected identifier after '.'", token_head, *cur);
            char *member_name = (*cur)->value;
            *cur = (*cur)->next;
            if (node->type == AST_IDENTIFIER && is_imported_package(node->identifier.name)) {
                char buf[256];
                snprintf(buf, sizeof(buf), "%s_%s", node->identifier.name, member_name);
                node = new_identifier(buf);
            } else {
                node = new_member_access(node, member_name);
            }
        } else if ((*cur)->kind == ARROW) {
            if (!(*cur)->next || (*cur)->next->kind != IDENTIFIER) break;
            if (g_stop_at_arrow) {
                if (!(node->type == AST_IDENTIFIER ||
                      node->type == AST_MEMBER_ACCESS ||
                      node->type == AST_ARROW_ACCESS)) {
                    break;
                }
            }
            *cur = (*cur)->next;
            if ((*cur)->kind != IDENTIFIER)
                parse_error("expected identifier after '->'", token_head, *cur);
            char *member_name = (*cur)->value;
            *cur = (*cur)->next;
            node = new_arrow_access(node, member_name);
        } else if ((*cur)->kind == L_PARENTHESES && node->type == AST_IDENTIFIER) {
            int line = node->line;
            int col = node->col;
            *cur = (*cur)->next;
            ASTNode **args = NULL;
            char **arg_names = NULL;
            int arg_count = 0;
            int saw_named = 0;
            if ((*cur)->kind != R_PARENTHESES) {
                while (1) {
                    char *arg_name = NULL;
                    if ((*cur)->kind == IDENTIFIER && (*cur)->next && (*cur)->next->kind == COLON) {
                        arg_name = strdup((*cur)->value);
                        saw_named = 1;
                        *cur = (*cur)->next->next;
                    } else if (saw_named) {
                        parse_error("positional argument cannot follow a named argument", token_head, *cur);
                    }

                    ASTNode *arg = parse_expr(cur);
                    args = realloc(args, sizeof(ASTNode*) * (arg_count + 1));
                    arg_names = realloc(arg_names, sizeof(char*) * (arg_count + 1));
                    args[arg_count] = arg;
                    arg_names[arg_count] = arg_name;
                    arg_count++;
                    if ((*cur)->kind == COMMA) {
                        *cur = (*cur)->next;
                        continue;
                    }
                    break;
                }
            }
            if (!expect(cur, R_PARENTHESES))
                parse_error("expected ')' after args", token_head, *cur);
            node = new_call(node->identifier.name, args, arg_names, arg_count);
            node->line = line;
            node->col = col;
        } else {
            break;
        }
    }
    return node;
}