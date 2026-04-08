#include "mylang/backend/codegen_internal.h"

int collect_locals(CompilerContext *cc, ASTNode *node, char **locals)
{
    int count = 0;
    (void)cc;
    if (!node)
        return 0;
    switch (node->type)
    {
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++)
            count += collect_locals(cc, node->block.stmts[i], locals ? (locals + count) : NULL);
        break;
    case AST_UNCHECKED:
        count += collect_locals(cc, node->unchecked_block.body, locals ? (locals + count) : NULL);
        break;
    case AST_VAR_DECL: {
        int slots = slots_for_type(cc, node->var_decl.var_type);
        if (slots < 1) slots = 1;
        for (int s = 0; s < slots; s++) {
            if (locals) locals[count] = node->var_decl.name;
            count++;
        }
        if (node->var_decl.init)
            count += collect_locals(cc, node->var_decl.init, locals ? (locals + count) : NULL);
        break; }
    case AST_FOR:
        if (node->for_stmt.init) count += collect_locals(cc, node->for_stmt.init, locals ? (locals + count) : NULL);
        if (node->for_stmt.body) count += collect_locals(cc, node->for_stmt.body, locals ? (locals + count) : NULL);
        if (node->for_stmt.inc) count += collect_locals(cc, node->for_stmt.inc, locals ? (locals + count) : NULL);
        break;
    case AST_IF:
        if (node->if_stmt.then_stmt) count += collect_locals(cc, node->if_stmt.then_stmt, locals ? (locals + count) : NULL);
        if (node->if_stmt.else_stmt) count += collect_locals(cc, node->if_stmt.else_stmt, locals ? (locals + count) : NULL);
        count += collect_locals(cc, node->if_stmt.cond, locals ? (locals + count) : NULL);
        break;
    case AST_STMT_EXPR:
        count += collect_locals(cc, node->stmt_expr.block, locals ? (locals + count) : NULL);
        break;
    case AST_EXPR_STMT:
        count += collect_locals(cc, node->expr_stmt.expr, locals ? (locals + count) : NULL);
        break;
    case AST_RETURN:
        count += collect_locals(cc, node->ret.expr, locals ? (locals + count) : NULL);
        break;
    case AST_YIELD:
        count += collect_locals(cc, node->yield_stmt.expr, locals ? (locals + count) : NULL);
        break;
    case AST_CASE:
        count += collect_locals(cc, node->case_expr.target, locals ? (locals + count) : NULL);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            count += collect_locals(cc, node->case_expr.cases[i].key, locals ? (locals + count) : NULL);
            count += collect_locals(cc, node->case_expr.cases[i].expr, locals ? (locals + count) : NULL);
        }
        if (node->case_expr.default_expr)
            count += collect_locals(cc, node->case_expr.default_expr, locals ? (locals + count) : NULL);
        break;
    case AST_WHILE:
        count += collect_locals(cc, node->while_stmt.cond, locals ? (locals + count) : NULL);
        count += collect_locals(cc, node->while_stmt.body, locals ? (locals + count) : NULL);
        break;
    case AST_DO_WHILE:
        count += collect_locals(cc, node->do_while_stmt.cond, locals ? (locals + count) : NULL);
        count += collect_locals(cc, node->do_while_stmt.body, locals ? (locals + count) : NULL);
        break;
    case AST_BINARY:
        count += collect_locals(cc, node->binary.left, locals ? (locals + count) : NULL);
        count += collect_locals(cc, node->binary.right, locals ? (locals + count) : NULL);
        break;
    case AST_ASSIGN:
        count += collect_locals(cc, node->assign.left, locals ? (locals + count) : NULL);
        count += collect_locals(cc, node->assign.right, locals ? (locals + count) : NULL);
        break;
    case AST_UNARY:
        count += collect_locals(cc, node->unary.operand, locals ? (locals + count) : NULL);
        break;
    case AST_CAST:
        count += collect_locals(cc, node->cast.expr, locals ? (locals + count) : NULL);
        break;
    case AST_TERNARY:
        count += collect_locals(cc, node->ternary.cond, locals ? (locals + count) : NULL);
        count += collect_locals(cc, node->ternary.then_expr, locals ? (locals + count) : NULL);
        count += collect_locals(cc, node->ternary.else_expr, locals ? (locals + count) : NULL);
        break;
    case AST_CALL:
        for (int i = 0; i < node->call.arg_count; i++)
             count += collect_locals(cc, node->call.args[i], locals ? (locals + count) : NULL);
        break;
    case AST_MEMBER_ACCESS:
        count += collect_locals(cc, node->member_access.lhs, locals ? (locals + count) : NULL);
        break;
    case AST_ARROW_ACCESS:
        count += collect_locals(cc, node->arrow_access.lhs, locals ? (locals + count) : NULL);
        break;
    case AST_SIZEOF:
        count += collect_locals(cc, node->sizeof_expr.expr, locals ? (locals + count) : NULL);
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
        return local_offset(param_count, idx);
    }
    if (is_param) *is_param = -1;
    return 0;
}
