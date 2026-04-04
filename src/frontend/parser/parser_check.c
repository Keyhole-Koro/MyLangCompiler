#include "mylang/frontend/parser_rewrite_internal.h"

void ensure_no_fun_literals(ASTNode *node) {
    if (!node) return;
    switch (node->type) {
    case AST_FUN_LITERAL:
        fprintf(stderr, "internal error: leftover function literal after lowering\n");
        exit(1);
    case AST_VAR_DECL:
        ensure_no_fun_literals(node->var_decl.var_type);
        ensure_no_fun_literals(node->var_decl.init);
        break;
    case AST_ASSIGN:
        ensure_no_fun_literals(node->assign.left);
        ensure_no_fun_literals(node->assign.right);
        break;
    case AST_BORROW:
        ensure_no_fun_literals(node->borrow.expr);
        break;
    case AST_BORROW_MUT:
        ensure_no_fun_literals(node->borrow_mut.expr);
        break;
    case AST_BINARY:
        ensure_no_fun_literals(node->binary.left);
        ensure_no_fun_literals(node->binary.right);
        break;
    case AST_UNARY:
        ensure_no_fun_literals(node->unary.operand);
        break;
    case AST_TERNARY:
        ensure_no_fun_literals(node->ternary.cond);
        ensure_no_fun_literals(node->ternary.then_expr);
        ensure_no_fun_literals(node->ternary.else_expr);
        break;
    case AST_IF:
        ensure_no_fun_literals(node->if_stmt.cond);
        ensure_no_fun_literals(node->if_stmt.then_stmt);
        ensure_no_fun_literals(node->if_stmt.else_stmt);
        break;
    case AST_WHILE:
        ensure_no_fun_literals(node->while_stmt.cond);
        ensure_no_fun_literals(node->while_stmt.body);
        break;
    case AST_DO_WHILE:
        ensure_no_fun_literals(node->do_while_stmt.cond);
        ensure_no_fun_literals(node->do_while_stmt.body);
        break;
    case AST_FOR:
        ensure_no_fun_literals(node->for_stmt.init);
        ensure_no_fun_literals(node->for_stmt.cond);
        ensure_no_fun_literals(node->for_stmt.inc);
        ensure_no_fun_literals(node->for_stmt.body);
        break;
    case AST_RETURN:
        ensure_no_fun_literals(node->ret.expr);
        break;
    case AST_YIELD:
        ensure_no_fun_literals(node->yield_stmt.expr);
        break;
    case AST_EXPR_STMT:
        ensure_no_fun_literals(node->expr_stmt.expr);
        break;
    case AST_MEMBER_ACCESS:
        ensure_no_fun_literals(node->member_access.lhs);
        break;
    case AST_ARROW_ACCESS:
        ensure_no_fun_literals(node->arrow_access.lhs);
        break;
    case AST_CAST:
        ensure_no_fun_literals(node->cast.type);
        ensure_no_fun_literals(node->cast.expr);
        break;
    case AST_CALL:
        for (int i = 0; i < node->call.arg_count; i++) {
            ensure_no_fun_literals(node->call.args[i]);
        }
        break;
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++) {
            ensure_no_fun_literals(node->block.stmts[i]);
        }
        break;
    case AST_UNCHECKED:
        ensure_no_fun_literals(node->unchecked_block.body);
        break;
    case AST_STMT_EXPR:
        ensure_no_fun_literals(node->stmt_expr.block);
        break;
    case AST_CASE:
        ensure_no_fun_literals(node->case_expr.target);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            ensure_no_fun_literals(node->case_expr.cases[i].key);
            ensure_no_fun_literals(node->case_expr.cases[i].expr);
        }
        ensure_no_fun_literals(node->case_expr.default_expr);
        break;
    case AST_FUNDEF:
        ensure_no_fun_literals(node->fundef.ret_type);
        for (int i = 0; i < node->fundef.param_count; i++) {
            ensure_no_fun_literals(node->fundef.params[i]);
        }
        ensure_no_fun_literals(node->fundef.body);
        break;
    case AST_PARAM:
        ensure_no_fun_literals(node->param.type);
        break;
    case AST_TYPE:
        ensure_no_fun_literals(node->type_node.base_type);
        break;
    case AST_TYPE_ARRAY:
        ensure_no_fun_literals(node->type_array.element_type);
        break;
    case AST_INIT_LIST:
        for (int i = 0; i < node->init_list.count; i++) {
            ensure_no_fun_literals(node->init_list.elements[i]);
        }
        break;
    case AST_SIZEOF:
        ensure_no_fun_literals(node->sizeof_expr.expr);
        break;
    default:
        break;
    }
}
