#include "mylang/frontend/parser_internal.h"

void free_attributes(Attribute *attrs, int count) {
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < attrs[i].arg_count; j++) {
            free(attrs[i].args[j].name);
            free_ast(attrs[i].args[j].value);
        }
        free(attrs[i].args);
        free(attrs[i].name);
    }
    free(attrs);
}

static void free_child(ASTNode **slot, void *unused) {
    (void)unused;
    free_ast(*slot);
    *slot = NULL;
}

static void free_strings(char **strings, int count) {
    for (int i = 0; strings && i < count; i++) free(strings[i]);
    free(strings);
}

static void free_type_params(char **names, unsigned char *is_const, ASTNode **bounds, int count) {
    free_strings(names, count);
    free(is_const);
    for (int i = 0; bounds && i < count; i++) free_ast(bounds[i]);
    free(bounds);
}

/* The mirror of ast_clone (AST.c): the children go through ast_visit_children,
 * then each kind frees the strings and arrays it owns. A struct's payload enum
 * and type parameter bounds are not children, so they are freed here. */
void free_ast(ASTNode *node) {
    if (!node) return;
    free_attributes(node->attrs, node->attr_count);
    node->attrs = NULL;
    node->attr_count = 0;
    ast_visit_children(node, free_child, NULL);
    switch (node->type) {
    case AST_NUMBER:
        free(node->number.value);
        free(node->number.enum_name);
        break;
    case AST_IDENTIFIER: free(node->identifier.name); break;
    case AST_TYPE_GENERIC:
        free(node->generic_type.name);
        free(node->generic_type.args);
        break;
    case AST_TYPE_ARRAY: free(node->type_array.array_size_param); break;
    case AST_TYPE_FUNCTION: free(node->function_type.param_types); break;
    case AST_VAR_DECL:
        free(node->var_decl.name);
        free(node->var_decl.package);
        free(node->var_decl.link_name);
        break;
    case AST_TYPEDEF:
        free(node->typedef_stmt.alias);
        free(node->typedef_stmt.package);
        break;
    case AST_BLOCK: free(node->block.stmts); break;
    case AST_FUN_LITERAL: free(node->fun_literal.params); break;
    case AST_CASE: free(node->case_expr.cases); break;
    case AST_FUNDEF:
        free(node->fundef.name);
        free(node->fundef.package);
        free(node->fundef.link_name);
        free(node->fundef.recv_type_name);
        free(node->fundef.origin_path);
        free(node->fundef.params);
        free_type_params(node->fundef.type_params, node->fundef.type_param_is_const,
                         node->fundef.type_param_bounds, node->fundef.type_param_count);
        break;
    case AST_PARAM: free(node->param.name); break;
    case AST_CALL:
        free(node->call.name);
        free(node->call.type_args);
        free(node->call.args);
        break;
    case AST_DOM_ELEMENT:
        for (int i = 0; i < node->dom_element.prop_count; i++) free(node->dom_element.props[i].name);
        free(node->dom_element.props);
        free(node->dom_element.children);
        free(node->dom_element.tag);
        break;
    case AST_STRUCT:
        free(node->struct_stmt.name);
        free(node->struct_stmt.package);
        free(node->struct_stmt.members);
        free_ast(node->struct_stmt.payload_enum);
        free_type_params(node->struct_stmt.type_params, node->struct_stmt.type_param_is_const,
                         node->struct_stmt.type_param_bounds, node->struct_stmt.type_param_count);
        break;
    case AST_TYPEDEF_STRUCT:
        free(node->typedef_struct.struct_name);
        free(node->typedef_struct.typedef_name);
        free(node->typedef_struct.package);
        free(node->typedef_struct.members);
        break;
    case AST_ENUM:
        free(node->enum_stmt.name);
        free(node->enum_stmt.package);
        free(node->enum_stmt.members);
        free_type_params(node->enum_stmt.type_params, node->enum_stmt.type_param_is_const,
                         node->enum_stmt.type_param_bounds, node->enum_stmt.type_param_count);
        break;
    case AST_ENUM_MEMBER: free(node->enum_member.name); break;
    case AST_CHAR_LITERAL: free(node->char_literal.value); break;
    case AST_STRING_LITERAL: free(node->string_literal.value); break;
    case AST_MEMBER_ACCESS: free(node->member_access.member); break;
    case AST_ARROW_ACCESS: free(node->arrow_access.member); break;
    case AST_INIT_LIST:
        free(node->init_list.elements);
        free(node->init_list.struct_type_args);
        free(node->init_list.struct_type_name);
        free_strings(node->init_list.field_names, node->init_list.count);
        break;
    case AST_IMPORT:
        free(node->import_stmt.path);
        free_strings(node->import_stmt.symbols, node->import_stmt.symbol_count);
        break;
    case AST_RETURN: free(node->ret.trace_note); break;
    case AST_BINARY: case AST_ASSIGN: case AST_TYPE: case AST_BORROW: case AST_UNARY:
    case AST_CAST: case AST_EXPR_STMT: case AST_IF: case AST_DEFER: case AST_YIELD:
    case AST_STMT_EXPR: case AST_WHILE: case AST_DO_WHILE: case AST_FOR: case AST_SIZEOF:
    case AST_TERNARY: case AST_BREAK: case AST_CONTINUE:
        break;
    default:
        fprintf(stderr, "Unknown AST Node Type: %d\n", node->type);
        exit(1);
    }
    free(node);
}
