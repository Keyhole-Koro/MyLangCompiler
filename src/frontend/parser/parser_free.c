#include "mylang/frontend/parser_internal.h"

void free_ast(ASTNode *node) {
    if (!node) return;
    switch (node->type) {
        case AST_NUMBER:
            free(node->number.value);
            break;
        case AST_IDENTIFIER:
            free(node->identifier.name);
            break;
        case AST_BINARY:
            free_ast(node->binary.left);
            free_ast(node->binary.right);
            break;
        case AST_ASSIGN:
            free_ast(node->assign.left);
            free_ast(node->assign.right);
            break;
        case AST_VAR_DECL:
            free_ast(node->var_decl.var_type);
            free(node->var_decl.name);
            free(node->var_decl.package);
            if (node->var_decl.init) free_ast(node->var_decl.init);
            break;
        case AST_BORROW:
            free_ast(node->borrow.expr);
            break;
        case AST_BORROW_MUT:
            free_ast(node->borrow_mut.expr);
            break;
        case AST_TYPE:
            free_ast(node->type_node.base_type);
            break;
        case AST_TYPE_GENERIC:
            free(node->generic_type.name);
            for (int i = 0; i < node->generic_type.arg_count; i++)
                free_ast(node->generic_type.args[i]);
            free(node->generic_type.args);
            break;
        case AST_TYPE_ARRAY:
            free_ast(node->type_array.element_type);
            break;
        case AST_STRING_LITERAL:
            free(node->string_literal.value);
            break;
        case AST_CHAR_LITERAL:
            free(node->char_literal.value);
            break;
        case AST_UNARY:
            free_ast(node->unary.operand);
            break;
        case AST_CAST:
            if (node->cast.type) free_ast(node->cast.type);
            if (node->cast.expr) free_ast(node->cast.expr);
            break;
        case AST_TERNARY:
            free_ast(node->ternary.cond);
            free_ast(node->ternary.then_expr);
            free_ast(node->ternary.else_expr);
            break;
        case AST_IMPORT:
            free(node->import_stmt.path);
            for(int i=0; i<node->import_stmt.symbol_count; i++) free(node->import_stmt.symbols[i]);
            free(node->import_stmt.symbols);
            break;
        case AST_EXPR_STMT:
            free_ast(node->expr_stmt.expr);
            break;
        case AST_IF:
            free_ast(node->if_stmt.cond);
            free_ast(node->if_stmt.then_stmt);
            if (node->if_stmt.else_stmt) free_ast(node->if_stmt.else_stmt);
            break;
            case AST_RETURN:
                    free_ast(node->ret.expr);
                    break;
            case AST_YIELD:
                    free_ast(node->yield_stmt.expr);
                    break;
            case AST_BLOCK:
                    for (int i = 0; i < node->block.count; i++)
                        free_ast(node->block.stmts[i]);
                    free(node->block.stmts);
                    break;
        case AST_UNCHECKED:
            free_ast(node->unchecked_block.body);
            break;
        case AST_STMT_EXPR:
                free_ast(node->stmt_expr.block);
                break;
            case AST_CASE:
                    free_ast(node->case_expr.target);
                    for(int i=0; i<node->case_expr.case_count; i++) {
                        free_ast(node->case_expr.cases[i].key);
                        free_ast(node->case_expr.cases[i].expr);
                    }
                    free(node->case_expr.cases);
                    if (node->case_expr.default_expr) free_ast(node->case_expr.default_expr);
                    break;                case AST_FUN_LITERAL:
            for (int i = 0; i < node->fun_literal.param_count; i++)
                free_ast(node->fun_literal.params[i]);
            free(node->fun_literal.params);
            free_ast(node->fun_literal.body);
            break;
                case AST_FUNDEF:            if (node->fundef.ret_type) free_ast(node->fundef.ret_type);
            free(node->fundef.name);
            free(node->fundef.package);
            for (int i = 0; i < node->fundef.type_param_count; i++)
                free(node->fundef.type_params[i]);
            free(node->fundef.type_params);
            for (int i = 0; i < node->fundef.param_count; i++)
                free_ast(node->fundef.params[i]);
            free(node->fundef.params);
            free_ast(node->fundef.body);
            break;
        case AST_CALL:
            free(node->call.name);
            for (int i = 0; i < node->call.type_arg_count; i++)
                free_ast(node->call.type_args[i]);
            free(node->call.type_args);
            for (int i = 0; i < node->call.arg_count; i++)
                free_ast(node->call.args[i]);
            free(node->call.args);
            break;
        case AST_PARAM:
            if (node->param.type) free_ast(node->param.type);
            free(node->param.name);
            break;
        case AST_STRUCT:
            free(node->struct_stmt.name);
            free(node->struct_stmt.package);
            for (int i = 0; i < node->struct_stmt.type_param_count; i++)
                free(node->struct_stmt.type_params[i]);
            free(node->struct_stmt.type_params);
            for (int i = 0; i < node->struct_stmt.member_count; i++)
                free_ast(node->struct_stmt.members[i]);
            free(node->struct_stmt.members);
            break;
        case AST_STRUCT_MEMBER:
            free(node->struct_member.type);
            free(node->struct_member.name);
            break;
        case AST_TYPEDEF:
            free(node->typedef_stmt.alias);
            free_ast(node->typedef_stmt.src_type);
            break;
        case AST_TYPEDEF_STRUCT:
            free(node->typedef_struct.struct_name);
            for (int i = 0; i < node->typedef_struct.member_count; i++)
                free_ast(node->typedef_struct.members[i]);
            free(node->typedef_struct.members);
            free(node->typedef_struct.typedef_name);
            break;
        case AST_ENUM:
            free(node->enum_stmt.name);
            for (int i = 0; i < node->enum_stmt.member_count; i++)
                free_ast(node->enum_stmt.members[i]);
            free(node->enum_stmt.members);
            break;
        case AST_ENUM_MEMBER:
            free(node->enum_member.name);
            free_ast(node->enum_member.value);
            break;
        case AST_MEMBER_ACCESS:
            free(node->member_access.member);
            free_ast(node->member_access.lhs);
            break;
        case AST_ARROW_ACCESS:
            free(node->arrow_access.member);
            free_ast(node->arrow_access.lhs);
            break;
        case AST_INIT_LIST:
            for (int i = 0; i < node->init_list.count; i++)
                free_ast(node->init_list.elements[i]);
            free(node->init_list.elements);
            break;
        case AST_SIZEOF:
            free_ast(node->sizeof_expr.expr);
            break;
        case AST_WHILE:
            free_ast(node->while_stmt.cond);
            free_ast(node->while_stmt.body);
            break;
        case AST_DO_WHILE:
            free_ast(node->do_while_stmt.cond);
            free_ast(node->do_while_stmt.body);
            break;
        case AST_FOR:
            if (node->for_stmt.init) free_ast(node->for_stmt.init);
            if (node->for_stmt.cond) free_ast(node->for_stmt.cond);
            if (node->for_stmt.inc) free_ast(node->for_stmt.inc);
            free_ast(node->for_stmt.body);
            break;
        case AST_BREAK:
        case AST_CONTINUE:
            break;
        case AST_DOM_ELEMENT:
            for (int i = 0; i < node->dom_element.prop_count; i++) {
                free(node->dom_element.props[i].name);
                if (node->dom_element.props[i].value) free_ast(node->dom_element.props[i].value);
            }
            free(node->dom_element.props);
            for (int i = 0; i < node->dom_element.child_count; i++) {
                free_ast(node->dom_element.children[i]);
            }
            free(node->dom_element.children);
            free(node->dom_element.tag);
            break;
        default:
            fprintf(stderr, "Unknown AST Node Type: %d\n", node->type);
            exit(1);
    }
    free(node);
}
