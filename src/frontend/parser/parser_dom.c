#include "mylang/frontend/parser_dom_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

/* Parses the DOM syntax extension into AST_DOM_ELEMENT nodes.
 *
 *   element  := '<' IDENT prop* ( '/>' | '>' child* '</' IDENT '>' )
 *   prop     := IDENT '=' ( STRING | '{' expr '}' )
 *   child    := element | whitespace text
 *
 * The lexer only opens DOM mode after `return`, `=`, `(`, `=>` or `:`, and the
 * driver rejects DOM tokens outside a .dom.mln source, so reaching here already
 * implies the DOM syntax profile. Element and property vocabularies are checked
 * later, during lowering.
 */

static int text_is_blank(const char *text) {
    if (!text) return 1;
    for (const char *p = text; *p; ++p) {
        if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') return 0;
    }
    return 1;
}

static DomProp *parse_dom_props(ParserContext *context, Token **cur, int *out_count) {
    DomProp *props = NULL;
    int count = 0;

    while ((*cur)->kind == IDENTIFIER) {
        Token *name_tok = *cur;
        char *name = name_tok->value;
        *cur = (*cur)->next;

        if (!expect(cur, ASSIGN))
            parse_error(context, "expected '=' after DOM property name", *cur);

        ASTNode *value = NULL;
        if ((*cur)->kind == STRING_LITERAL) {
            Token *tok = *cur;
            value = new_string_literal(tok->value);
            set_node_loc_from_tokens(value, tok, NULL);
            *cur = (*cur)->next;
        } else if ((*cur)->kind == L_BRACE) {
            *cur = (*cur)->next;
            value = parse_expr(context, cur);
            if (!expect(cur, R_BRACE))
                parse_error(context, "expected '}' after DOM property expression", *cur);
        } else {
            parse_error(context, "expected a string or '{expr}' as the DOM property value", *cur);
        }

        props = realloc(props, sizeof(DomProp) * (count + 1));
        props[count].name = strdup(name);
        props[count].value = value;
        props[count].line = name_tok->line;
        props[count].col = name_tok->col;
        count++;
    }

    *out_count = count;
    return props;
}

ASTNode *parse_dom_element(ParserContext *context, Token **cur) {
    Token *open_tok = *cur;
    if (!expect(cur, MLX_TAG_OPEN))
        parse_error(context, "expected '<' to open a DOM element", *cur);

    if ((*cur)->kind != IDENTIFIER)
        parse_error(context, "expected an element name after '<'", *cur);
    char *tag = strdup((*cur)->value);
    *cur = (*cur)->next;

    int prop_count = 0;
    DomProp *props = parse_dom_props(context, cur, &prop_count);

    ASTNode **children = NULL;
    int child_count = 0;
    Token *end_tok = *cur;

    if ((*cur)->kind == MLX_TAG_SELF_CLOSE) {
        *cur = (*cur)->next;
    } else if ((*cur)->kind == MLX_TAG_CLOSE) {
        *cur = (*cur)->next;
        while (1) {
            if ((*cur)->kind == MLX_TEXT) {
                if (!text_is_blank((*cur)->value))
                    parse_error(context, "text children are not supported; use <Text text=\"...\"/>", *cur);
                *cur = (*cur)->next;
                continue;
            }
            if ((*cur)->kind == MLX_TAG_OPEN) {
                ASTNode *child = parse_dom_element(context, cur);
                children = realloc(children, sizeof(ASTNode*) * (child_count + 1));
                children[child_count++] = child;
                continue;
            }
            break;
        }

        if (!expect(cur, MLX_CLOSE_TAG_OPEN))
            parse_error(context, "expected '</' to close a DOM element", *cur);
        if ((*cur)->kind != IDENTIFIER)
            parse_error(context, "expected an element name after '</'", *cur);
        if (strcmp((*cur)->value, tag) != 0)
            parse_error(context, "closing tag does not match the opening element name", *cur);
        *cur = (*cur)->next;
        end_tok = *cur;
        if (!expect(cur, MLX_TAG_CLOSE))
            parse_error(context, "expected '>' after a closing tag name", *cur);
    } else {
        parse_error(context, "expected '>' or '/>' after DOM element properties", *cur);
    }

    ASTNode *node = new_dom_element(tag, props, prop_count, children, child_count);
    set_node_loc_from_tokens(node, open_tok, NULL);
    set_node_end_from_token(node, end_tok);
    free(tag);
    return node;
}
