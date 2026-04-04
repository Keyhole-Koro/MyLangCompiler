#include "mylang/backend/codegen_internal.h"

int collect_locals(CompilerContext *cc, ASTNode *node, char **locals)
{
    int count = 0;
    if (!node)
        return 0;
    switch (node->type)
    {
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++)
            count += collect_locals(cc, node->block.stmts[i], locals + count);
        break;
    case AST_UNCHECKED:
        count += collect_locals(cc, node->unchecked_block.body, locals + count);
        break;
    case AST_VAR_DECL: {
        int slots = slots_for_type(cc, node->var_decl.var_type);
        if (slots < 1) slots = 1;
        for (int s = 0; s < slots; s++) locals[count++] = node->var_decl.name;
        if (node->var_decl.init)
            count += collect_locals(cc, node->var_decl.init, locals + count);
        break; }
    case AST_FOR:
        if (node->for_stmt.init) count += collect_locals(cc, node->for_stmt.init, locals + count);
        if (node->for_stmt.body) count += collect_locals(cc, node->for_stmt.body, locals + count);
        if (node->for_stmt.inc) count += collect_locals(cc, node->for_stmt.inc, locals + count);
        break;
    case AST_IF:
        if (node->if_stmt.then_stmt) count += collect_locals(cc, node->if_stmt.then_stmt, locals + count);
        if (node->if_stmt.else_stmt) count += collect_locals(cc, node->if_stmt.else_stmt, locals + count);
        count += collect_locals(cc, node->if_stmt.cond, locals + count);
        break;
    case AST_STMT_EXPR:
        count += collect_locals(cc, node->stmt_expr.block, locals + count);
        break;
    case AST_EXPR_STMT:
        count += collect_locals(cc, node->expr_stmt.expr, locals + count);
        break;
    case AST_RETURN:
        count += collect_locals(cc, node->ret.expr, locals + count);
        break;
    case AST_YIELD:
        count += collect_locals(cc, node->yield_stmt.expr, locals + count);
        break;
    case AST_CASE:
        count += collect_locals(cc, node->case_expr.target, locals + count);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            count += collect_locals(cc, node->case_expr.cases[i].key, locals + count);
            count += collect_locals(cc, node->case_expr.cases[i].expr, locals + count);
        }
        if (node->case_expr.default_expr)
            count += collect_locals(cc, node->case_expr.default_expr, locals + count);
        break;
    case AST_WHILE:
        count += collect_locals(cc, node->while_stmt.cond, locals + count);
        count += collect_locals(cc, node->while_stmt.body, locals + count);
        break;
    case AST_DO_WHILE:
        count += collect_locals(cc, node->do_while_stmt.cond, locals + count);
        count += collect_locals(cc, node->do_while_stmt.body, locals + count);
        break;
    case AST_BINARY:
        count += collect_locals(cc, node->binary.left, locals + count);
        count += collect_locals(cc, node->binary.right, locals + count);
        break;
    case AST_ASSIGN:
        count += collect_locals(cc, node->assign.left, locals + count);
        count += collect_locals(cc, node->assign.right, locals + count);
        break;
    case AST_UNARY:
        count += collect_locals(cc, node->unary.operand, locals + count);
        break;
    case AST_CAST:
        count += collect_locals(cc, node->cast.expr, locals + count);
        break;
    case AST_TERNARY:
        count += collect_locals(cc, node->ternary.cond, locals + count);
        count += collect_locals(cc, node->ternary.then_expr, locals + count);
        count += collect_locals(cc, node->ternary.else_expr, locals + count);
        break;
    case AST_CALL:
        for (int i = 0; i < node->call.arg_count; i++)
             count += collect_locals(cc, node->call.args[i], locals + count);
        break;
    case AST_MEMBER_ACCESS:
        count += collect_locals(cc, node->member_access.lhs, locals + count);
        break;
    case AST_ARROW_ACCESS:
        count += collect_locals(cc, node->arrow_access.lhs, locals + count);
        break;
    case AST_SIZEOF:
        count += collect_locals(cc, node->sizeof_expr.expr, locals + count);
        break;
    default:
        break;
    }
    return count;
}

int find_var_offset(const char *name, char **params, int param_count,
                    char **locals, int local_count, int *is_param)
{
    int idx = param_index(name, params, param_count);
    if (idx >= 0)
    {
        if (is_param) *is_param = 1;
        if (idx < 3) return param_offset(idx);
        return 8 + (idx - 3) * SLOT_SIZE;
    }
    idx = local_index_last(name, locals, local_count);
    if (idx >= 0)
    {
        if (is_param) *is_param = 0;
        return local_offset(idx);
    }
    if (is_param) *is_param = -1;
    return 0;
}
