#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode *parse_base_type(ParserContext *context, Token **cur) {
    if (!is_type(context, (*cur)->kind, *cur))
        parse_error(context, "expected type", *cur);
    Token *name_tok = *cur;
    char *name = (*cur)->value;
    *cur = (*cur)->next;
    ASTNode *generic_declaration = find_generic_type_template(context, name);
    if ((*cur)->kind != LT) {
        if (generic_declaration) {
            char message[256];
            snprintf(message, sizeof(message), "generic type '%s' requires type arguments", name);
            parse_error_code(context,
                SEMCODE_GENERIC_ARGS_REQUIRED,
                message,
                name_tok
            );
        }
        return new_identifier(name);
    }

    int arg_count = 0;
    ASTNode **args = parse_type_args(context, cur, &arg_count);
    ASTNode *base = new_generic_type(name, args, arg_count);
    set_node_loc_from_tokens(base, name_tok, NULL);
    int expected_type_args = generic_declaration && generic_declaration->type == AST_ENUM
        ? generic_declaration->enum_stmt.type_param_count
        : generic_declaration ? generic_declaration->struct_stmt.type_param_count : 0;
    if (generic_declaration &&
        arg_count != expected_type_args) {
        char message[256];
        snprintf(
            message,
            sizeof(message),
            "generic type '%s' expects %d type argument%s but got %d",
            name,
            expected_type_args,
            expected_type_args == 1 ? "" : "s",
            arg_count
        );
        parse_error_code(context,
            SEMCODE_GENERIC_ARG_COUNT_MISMATCH,
            message,
            name_tok
        );
    }
    return base;
}

void parse_struct_members(ParserContext *context, Token **cur, ASTNode ***members, int *member_count) {
    *members = NULL;
    *member_count = 0;
    if (!expect(cur, L_BRACE)) parse_error(context, "expected '{' in struct", *cur);
    while ((*cur)->kind != R_BRACE) {
        ASTNode *member = parse_variable_declaration(context, cur, 1);
        *members = realloc(*members, sizeof(ASTNode*) * (*member_count + 1));
        (*members)[(*member_count)++] = member;
    }
    if (!expect(cur, R_BRACE)) parse_error(context, "expected '}' to close struct definition", *cur);
}

ASTNode *parse_struct(ParserContext *context, Token **cur) {
    if (!expect(cur, STRUCT))
        parse_error(context, "expected 'struct'", *cur);

    char *name = NULL;
    char **type_params = NULL;
    int type_param_count = 0;
    int type_scope_mark = -1;
    if ((*cur)->kind == IDENTIFIER) {
        name = strdup((*cur)->value);
        *cur = (*cur)->next;
    }

    if ((*cur)->kind == LT) {
        if (!name) parse_error(context, "generic struct requires a name", *cur);
        add_typename(context, name);
        type_scope_mark = typename_scope_mark(context);
        type_params = parse_type_params(context, cur, &type_param_count, 1);
        context->control.generic_decl_depth++;
    } else if (name) {
        /* Make a named struct visible while parsing its own pointer members. */
        add_typename(context, name);
    }

    ASTNode **members = NULL;
    int member_count = 0;

    if ((*cur)->kind == L_BRACE) {
        parse_struct_members(context, cur, &members, &member_count);
        if ((*cur)->kind == IDENTIFIER) {
            char *typedef_name = strdup((*cur)->value);
            *cur = (*cur)->next;
            if (!expect(cur, SEMICOLON))
                parse_error(context, "expected ';' after typedef struct", *cur);
            add_typename(context, typedef_name);
            if (type_param_count > 0)
                parse_error(context, "generic typedef struct is not supported", *cur);
            ASTNode *node = new_typedef_struct(name ? name : "", members, member_count, typedef_name);
            free(name);
            free(typedef_name);
            return node;
        }
        if (!expect(cur, SEMICOLON))
            parse_error(context, "expected ';' after struct definition", *cur);
        ASTNode *node = new_struct(name ? name : "", members, member_count);
        node->struct_stmt.type_params = type_params;
        node->struct_stmt.type_param_count = type_param_count;
        if (type_param_count > 0) {
            context->control.generic_decl_depth--;
            restore_typenames(context, type_scope_mark);
        }
        free(name);
        return node;
    }
    if (!expect(cur, SEMICOLON))
        parse_error(context, "expected ';' after struct declaration", *cur);
    ASTNode *node = new_struct(name ? name : "", NULL, 0);
    node->struct_stmt.type_params = type_params;
    node->struct_stmt.type_param_count = type_param_count;
    if (type_param_count > 0) {
        context->control.generic_decl_depth--;
        restore_typenames(context, type_scope_mark);
    }
    free(name);
    return node;
}

ASTNode *parse_enum(ParserContext *context, Token **cur) {
    if (!expect(cur, ENUM))
        parse_error(context, "expected 'enum'", *cur);
    if ((*cur)->kind != IDENTIFIER)
        parse_error(context, "expected enum name", *cur);

    Token *name_tok = *cur;
    char *name = strdup((*cur)->value);
    *cur = (*cur)->next;

    char **type_params = NULL;
    int type_param_count = 0;
    int type_scope_mark = -1;
    if ((*cur)->kind == LT) {
        add_typename(context, name);
        type_scope_mark = typename_scope_mark(context);
        type_params = parse_type_params(context, cur, &type_param_count, 1);
        context->control.generic_decl_depth++;
    }

    if (!expect(cur, L_BRACE))
        parse_error(context, "expected '{' in enum definition", *cur);

    ASTNode **members = NULL;
    int member_count = 0;
    long next_value = 0;
    /* An enum is a payload enum as soon as any member carries one, which is
     * only settled at the closing brace: `Opt<T> { None, Some(T) }` looks
     * numeric until its second member. Numeric constants are therefore
     * registered after the body rather than while walking it, and a member
     * with neither a payload nor a value is legal in both kinds -- it is a
     * plain constant in one and a variant with nothing to carry in the other.
     * Only an explicit `= N` alongside a payload is a genuine mix. */
    int has_payload = 0;
    Token *explicit_value_tok = NULL;

    while ((*cur)->kind != R_BRACE) {
        if ((*cur)->kind != IDENTIFIER)
            parse_error(context, "expected enum member name", *cur);

        Token *member_tok = *cur;
        char *member_name = strdup((*cur)->value);
        *cur = (*cur)->next;

        ASTNode *value_expr = NULL;
        ASTNode *payload_type = NULL;
        long resolved_value = next_value;
        if ((*cur)->kind == L_PARENTHESES) {
            has_payload = 1;
            *cur = (*cur)->next;
            if ((*cur)->kind == R_PARENTHESES)
                parse_error(context, "payload enum member requires exactly one payload type", *cur);
            payload_type = parse_type(context, cur);
            if (!expect(cur, R_PARENTHESES))
                parse_error(context, "expected ')' after enum payload type", *cur);
        } else if ((*cur)->kind == ASSIGN) {
            if (!explicit_value_tok) explicit_value_tok = *cur;
            *cur = (*cur)->next;
            if ((*cur)->kind != NUMBER) {
                parse_error(context, "enum member value must be a number literal", *cur);
            }
            value_expr = new_number((*cur)->value);
            resolved_value = strtol((*cur)->value, NULL, 10);
            *cur = (*cur)->next;
        }

        ASTNode *member = new_enum_member(member_name, value_expr, payload_type, resolved_value);
        set_node_loc_from_tokens(member, member_tok, NULL);
        members = realloc(members, sizeof(ASTNode*) * (member_count + 1));
        members[member_count++] = member;
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
        parse_error(context, "expected '}' after enum body", *cur);
    if ((*cur)->kind == SEMICOLON)
        *cur = (*cur)->next;

    if (has_payload && explicit_value_tok)
        parse_error(context, "cannot mix payload and numeric enum members", explicit_value_tok);

    /* Only a numeric enum's members are constants. A variant is constructed and
     * matched by name, and its tag belongs to the layout rather than the
     * surrounding scope. */
    if (!has_payload)
        for (int i = 0; i < member_count; i++)
            add_enum_constant(context, members[i]->enum_member.name,
                              members[i]->enum_member.resolved_value);

    if (type_param_count == 0) add_typename(context, name);
    ASTNode *node = new_enum(name, members, member_count);
    node->enum_stmt.type_params = type_params;
    node->enum_stmt.type_param_count = type_param_count;
    node->enum_stmt.has_payloads = has_payload;
    set_node_loc_from_tokens(node, name_tok, NULL);
    if (type_param_count > 0) {
        context->control.generic_decl_depth--;
        restore_typenames(context, type_scope_mark);
    }
    free(name);
    return node;
}

ASTNode *parse_typedef(ParserContext *context, Token **cur) {
    if (!expect(cur, TYPEDEF)) parse_error(context, "expected 'typedef'", *cur);

    if ((*cur)->kind == STRUCT) {
        *cur = (*cur)->next;
        char *struct_name = NULL;
        if ((*cur)->kind == IDENTIFIER) {
            struct_name = strdup((*cur)->value);
            *cur = (*cur)->next;
        }
        ASTNode **members = NULL;
        int member_count = 0;
        parse_struct_members(context, cur, &members, &member_count);
        if ((*cur)->kind != IDENTIFIER)
            parse_error(context, "expected typedef name after struct definition", *cur);
        char *typedef_name = strdup((*cur)->value);
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON))
            parse_error(context, "expected ';' after typedef", *cur);
        add_typename(context, typedef_name);
        ASTNode *node = new_typedef_struct(struct_name ? struct_name : "", members, member_count, typedef_name);
        free(struct_name);
        free(typedef_name);
        return node;
    }

    ASTNode *type = parse_type(context, cur);
    if ((*cur)->kind != IDENTIFIER)
        parse_error(context, "expected typedef name", *cur);
    char *typedef_name = strdup((*cur)->value);
    *cur = (*cur)->next;
    if (!expect(cur, SEMICOLON))
        parse_error(context, "expected ';' after typedef", *cur);
    add_typename(context, typedef_name);
    ASTNode *node = new_typedef(type, typedef_name);
    free(typedef_name);
    return node;
}

ASTNode *parse_type(ParserContext *context, Token **cur) {
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

    if (!is_type(context, (*cur)->kind, *cur))
        parse_error(context, "expected base type", *cur);

    ASTNode *base_type = parse_base_type(context, cur);

    int pointer_level = 0;
    while ((*cur)->kind == ASTARISK) {
        pointer_level++;
        *cur = (*cur)->next;
    }
    return new_type_node(base_type, pointer_level, modifiers, ref_kind);
}
