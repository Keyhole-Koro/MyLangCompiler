#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode *parse_base_type(Token **cur) {
    if (!is_type((*cur)->kind, *cur))
        parse_error("expected type", token_head, *cur);
    ASTNode *base = new_identifier((*cur)->value);
    *cur = (*cur)->next;
    return base;
}

void parse_struct_members(Token **cur, ASTNode ***members, int *member_count) {
    *members = NULL;
    *member_count = 0;
    if (!expect(cur, L_BRACE)) parse_error("expected '{' in struct", token_head, *cur);
    while ((*cur)->kind != R_BRACE) {
        ASTNode *member = parse_variable_declaration(cur, 1);
        *members = realloc(*members, sizeof(ASTNode*) * (*member_count + 1));
        (*members)[(*member_count)++] = member;
    }
    if (!expect(cur, R_BRACE)) parse_error("expected '}' to close struct definition", token_head, *cur);
}

ASTNode *parse_struct(Token **cur) {
    if (!expect(cur, STRUCT))
        parse_error("expected 'struct'", token_head, *cur);

    char *name = NULL;
    if ((*cur)->kind == IDENTIFIER) {
        name = strdup((*cur)->value);
        *cur = (*cur)->next;
    }

    ASTNode **members = NULL;
    int member_count = 0;

    if ((*cur)->kind == L_BRACE) {
        parse_struct_members(cur, &members, &member_count);
        if ((*cur)->kind == IDENTIFIER) {
            char *typedef_name = strdup((*cur)->value);
            *cur = (*cur)->next;
            if (!expect(cur, SEMICOLON))
                parse_error("expected ';' after typedef struct", token_head, *cur);
            add_typename(typedef_name);
            return new_typedef_struct(name ? name : "", members, member_count, typedef_name);
        }
        if (!expect(cur, SEMICOLON))
            parse_error("expected ';' after struct definition", token_head, *cur);
        if (name) add_typename(name);
        return new_struct(name ? name : "", members, member_count);
    }
    if (!expect(cur, SEMICOLON))
        parse_error("expected ';' after struct declaration", token_head, *cur);
    if (name) add_typename(name);
    return new_struct(name ? name : "", NULL, 0);
}

ASTNode *parse_enum(Token **cur) {
    if (!expect(cur, ENUM))
        parse_error("expected 'enum'", token_head, *cur);
    if ((*cur)->kind != IDENTIFIER)
        parse_error("expected enum name", token_head, *cur);

    Token *name_tok = *cur;
    char *name = strdup((*cur)->value);
    *cur = (*cur)->next;

    if (!expect(cur, L_BRACE))
        parse_error("expected '{' in enum definition", token_head, *cur);

    ASTNode **members = NULL;
    int member_count = 0;
    long next_value = 0;

    while ((*cur)->kind != R_BRACE) {
        if ((*cur)->kind != IDENTIFIER)
            parse_error("expected enum member name", token_head, *cur);

        Token *member_tok = *cur;
        char *member_name = strdup((*cur)->value);
        *cur = (*cur)->next;

        ASTNode *value_expr = NULL;
        long resolved_value = next_value;
        if ((*cur)->kind == ASSIGN) {
            *cur = (*cur)->next;
            if ((*cur)->kind != NUMBER) {
                parse_error("enum member value must be a number literal", token_head, *cur);
            }
            value_expr = new_number((*cur)->value);
            resolved_value = strtol((*cur)->value, NULL, 10);
            *cur = (*cur)->next;
        }

        ASTNode *member = new_enum_member(member_name, value_expr, resolved_value);
        set_node_loc_from_tokens(member, member_tok, NULL);
        members = realloc(members, sizeof(ASTNode*) * (member_count + 1));
        members[member_count++] = member;
        add_enum_constant(member_name, resolved_value);
        next_value = resolved_value + 1;
        free(member_name);

        if ((*cur)->kind == COMMA) {
            *cur = (*cur)->next;
            if ((*cur)->kind == R_BRACE) break;
            continue;
        }
        break;
    }

    if (!expect(cur, R_BRACE))
        parse_error("expected '}' after enum body", token_head, *cur);
    if (!expect(cur, SEMICOLON))
        parse_error("expected ';' after enum definition", token_head, *cur);

    add_typename(name);
    ASTNode *node = new_enum(name, members, member_count);
    set_node_loc_from_tokens(node, name_tok, NULL);
    free(name);
    return node;
}

ASTNode *parse_typedef(Token **cur) {
    if (!expect(cur, TYPEDEF)) parse_error("expected 'typedef'", token_head, *cur);

    if ((*cur)->kind == STRUCT) {
        *cur = (*cur)->next;
        char *struct_name = NULL;
        if ((*cur)->kind == IDENTIFIER) {
            struct_name = strdup((*cur)->value);
            *cur = (*cur)->next;
        }
        ASTNode **members = NULL;
        int member_count = 0;
        parse_struct_members(cur, &members, &member_count);
        if ((*cur)->kind != IDENTIFIER)
            parse_error("expected typedef name after struct definition", token_head, *cur);
        char *typedef_name = strdup((*cur)->value);
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON))
            parse_error("expected ';' after typedef", token_head, *cur);
        add_typename(typedef_name);
        return new_typedef_struct(struct_name ? struct_name : "", members, member_count, typedef_name);
    }

    ASTNode *type = parse_type(cur);
    if ((*cur)->kind != IDENTIFIER)
        parse_error("expected typedef name", token_head, *cur);
    char *typedef_name = strdup((*cur)->value);
    *cur = (*cur)->next;
    if (!expect(cur, SEMICOLON))
        parse_error("expected ';' after typedef", token_head, *cur);
    add_typename(typedef_name);
    return new_typedef(type, typedef_name);
}

ASTNode *parse_type(Token **cur) {
    int modifiers = 0;
    int ref_kind = REFKIND_NONE;

    while ((*cur)->kind == CONST) {
        modifiers |= TYPEMOD_CONST;
        *cur = (*cur)->next;
    }

    if ((*cur)->kind == REF) {
        ref_kind = REFKIND_SHARED;
        *cur = (*cur)->next;
        if ((*cur)->kind == MUT) {
            ref_kind = REFKIND_MUT;
            *cur = (*cur)->next;
        }
    }

    if (!is_type((*cur)->kind, *cur))
        parse_error("expected base type", token_head, *cur);

    ASTNode *base_type = parse_base_type(cur);

    int pointer_level = 0;
    while ((*cur)->kind == ASTARISK) {
        pointer_level++;
        *cur = (*cur)->next;
    }
    return new_type_node(base_type, pointer_level, modifiers, ref_kind);
}
