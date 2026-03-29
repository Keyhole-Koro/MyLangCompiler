#include "mylang/backend/codegen_internal.h"

int collect_local_type_info(CompilerContext *cc, ASTNode *node, LocalInfo *arr) {
    int n = 0;
    if (!node) return 0;
    switch (node->type) {
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++)
            n += collect_local_type_info(cc, node->block.stmts[i], arr ? (arr + n) : NULL);
        break;
    case AST_VAR_DECL:
        if (arr) {
            arr[n].name = node->var_decl.name;
            set_localinfo_from_type(cc, &arr[n], node->var_decl.var_type);
        }
        n++;
        if (node->var_decl.init) n += collect_local_type_info(cc, node->var_decl.init, arr ? (arr + n) : NULL);
        break;
    case AST_FOR:
        if (node->for_stmt.init) n += collect_local_type_info(cc, node->for_stmt.init, arr ? (arr + n) : NULL);
        n += collect_local_type_info(cc, node->for_stmt.body, arr ? (arr + n) : NULL);
        if (node->for_stmt.inc) n += collect_local_type_info(cc, node->for_stmt.inc, arr ? (arr + n) : NULL);
        break;
    case AST_IF:
        n += collect_local_type_info(cc, node->if_stmt.then_stmt, arr ? (arr + n) : NULL);
        if (node->if_stmt.else_stmt) n += collect_local_type_info(cc, node->if_stmt.else_stmt, arr ? (arr + n) : NULL);
        n += collect_local_type_info(cc, node->if_stmt.cond, arr ? (arr + n) : NULL);
        break;
    case AST_STMT_EXPR:
        n += collect_local_type_info(cc, node->stmt_expr.block, arr ? (arr + n) : NULL);
        break;
    case AST_EXPR_STMT:
        n += collect_local_type_info(cc, node->expr_stmt.expr, arr ? (arr + n) : NULL);
        break;
    case AST_RETURN:
        n += collect_local_type_info(cc, node->ret.expr, arr ? (arr + n) : NULL);
        break;
    case AST_YIELD:
        n += collect_local_type_info(cc, node->yield_stmt.expr, arr ? (arr + n) : NULL);
        break;
    case AST_CASE:
        n += collect_local_type_info(cc, node->case_expr.target, arr ? (arr + n) : NULL);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            n += collect_local_type_info(cc, node->case_expr.cases[i].key, arr ? (arr + n) : NULL);
            n += collect_local_type_info(cc, node->case_expr.cases[i].expr, arr ? (arr + n) : NULL);
        }
        if (node->case_expr.default_expr) n += collect_local_type_info(cc, node->case_expr.default_expr, arr ? (arr + n) : NULL);
        break;
    case AST_WHILE:
        n += collect_local_type_info(cc, node->while_stmt.cond, arr ? (arr + n) : NULL);
        n += collect_local_type_info(cc, node->while_stmt.body, arr ? (arr + n) : NULL);
        break;
    case AST_DO_WHILE:
        n += collect_local_type_info(cc, node->do_while_stmt.cond, arr ? (arr + n) : NULL);
        n += collect_local_type_info(cc, node->do_while_stmt.body, arr ? (arr + n) : NULL);
        break;
    case AST_BINARY:
        n += collect_local_type_info(cc, node->binary.left, arr ? (arr + n) : NULL);
        n += collect_local_type_info(cc, node->binary.right, arr ? (arr + n) : NULL);
        break;
    case AST_ASSIGN:
        n += collect_local_type_info(cc, node->assign.left, arr ? (arr + n) : NULL);
        n += collect_local_type_info(cc, node->assign.right, arr ? (arr + n) : NULL);
        break;
    case AST_UNARY:
        n += collect_local_type_info(cc, node->unary.operand, arr ? (arr + n) : NULL);
        break;
    case AST_TERNARY:
        n += collect_local_type_info(cc, node->ternary.cond, arr ? (arr + n) : NULL);
        n += collect_local_type_info(cc, node->ternary.then_expr, arr ? (arr + n) : NULL);
        n += collect_local_type_info(cc, node->ternary.else_expr, arr ? (arr + n) : NULL);
        break;
    case AST_CALL:
        for (int i = 0; i < node->call.arg_count; i++)
            n += collect_local_type_info(cc, node->call.args[i], arr ? (arr + n) : NULL);
        break;
    case AST_MEMBER_ACCESS:
        n += collect_local_type_info(cc, node->member_access.lhs, arr ? (arr + n) : NULL);
        break;
    case AST_ARROW_ACCESS:
        n += collect_local_type_info(cc, node->arrow_access.lhs, arr ? (arr + n) : NULL);
        break;
    case AST_SIZEOF:
        n += collect_local_type_info(cc, node->sizeof_expr.expr, arr ? (arr + n) : NULL);
        break;
    default:
        break;
    }
    return n;
}
