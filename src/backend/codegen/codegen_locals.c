#include "mylang/backend/codegen_internal.h"

typedef void (*LocalDeclVisitor)(CompilerContext *cc, ASTNode *var_decl, void *data);

/* Calls `visit` for each variable `node` declares, in the order the frame
 * gives them slots: a declaration before the temporaries of its own
 * initializer, an if's branches before its condition, a for's body before
 * its increment. collect_locals and collect_local_type_info both walk with
 * this, so the slot names and the types they record line up. Changing the
 * order moves locals to other stack offsets. */
static void walk_local_decls(CompilerContext *cc, ASTNode *node,
                             LocalDeclVisitor visit, void *data)
{
    if (!node)
        return;
    switch (node->type)
    {
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++)
            walk_local_decls(cc, node->block.stmts[i], visit, data);
        break;
    case AST_DEFER:
        walk_local_decls(cc, node->defer_stmt.body, visit, data);
        break;
    case AST_VAR_DECL:
        visit(cc, node, data);
        walk_local_decls(cc, node->var_decl.init, visit, data);
        break;
    case AST_FOR:
        walk_local_decls(cc, node->for_stmt.init, visit, data);
        walk_local_decls(cc, node->for_stmt.cond, visit, data);
        walk_local_decls(cc, node->for_stmt.body, visit, data);
        walk_local_decls(cc, node->for_stmt.inc, visit, data);
        break;
    case AST_IF:
        walk_local_decls(cc, node->if_stmt.then_stmt, visit, data);
        walk_local_decls(cc, node->if_stmt.else_stmt, visit, data);
        walk_local_decls(cc, node->if_stmt.cond, visit, data);
        break;
    case AST_STMT_EXPR:
        walk_local_decls(cc, node->stmt_expr.block, visit, data);
        break;
    case AST_EXPR_STMT:
        walk_local_decls(cc, node->expr_stmt.expr, visit, data);
        break;
    case AST_RETURN:
        walk_local_decls(cc, node->ret.expr, visit, data);
        break;
    case AST_YIELD:
        walk_local_decls(cc, node->yield_stmt.expr, visit, data);
        break;
    case AST_CASE:
        walk_local_decls(cc, node->case_expr.target, visit, data);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            walk_local_decls(cc, node->case_expr.cases[i].key, visit, data);
            walk_local_decls(cc, node->case_expr.cases[i].expr, visit, data);
        }
        walk_local_decls(cc, node->case_expr.default_expr, visit, data);
        break;
    case AST_WHILE:
        walk_local_decls(cc, node->while_stmt.cond, visit, data);
        walk_local_decls(cc, node->while_stmt.body, visit, data);
        break;
    case AST_DO_WHILE:
        walk_local_decls(cc, node->do_while_stmt.cond, visit, data);
        walk_local_decls(cc, node->do_while_stmt.body, visit, data);
        break;
    case AST_BINARY:
        walk_local_decls(cc, node->binary.left, visit, data);
        walk_local_decls(cc, node->binary.right, visit, data);
        break;
    case AST_ASSIGN:
        walk_local_decls(cc, node->assign.left, visit, data);
        walk_local_decls(cc, node->assign.right, visit, data);
        break;
    case AST_UNARY:
        walk_local_decls(cc, node->unary.operand, visit, data);
        break;
    case AST_CAST:
        walk_local_decls(cc, node->cast.expr, visit, data);
        break;
    case AST_TERNARY:
        walk_local_decls(cc, node->ternary.cond, visit, data);
        walk_local_decls(cc, node->ternary.then_expr, visit, data);
        walk_local_decls(cc, node->ternary.else_expr, visit, data);
        break;
    case AST_CALL:
        for (int i = 0; i < node->call.arg_count; i++)
            walk_local_decls(cc, node->call.args[i], visit, data);
        break;
    case AST_MEMBER_ACCESS:
        walk_local_decls(cc, node->member_access.lhs, visit, data);
        break;
    case AST_ARROW_ACCESS:
        walk_local_decls(cc, node->arrow_access.lhs, visit, data);
        break;
    case AST_SIZEOF:
        walk_local_decls(cc, node->sizeof_expr.expr, visit, data);
        break;
    case AST_INIT_LIST:
        /* `FileHandle { fd: open(path)? }`: a field value may declare the
         * temporaries of a statement expression. */
        for (int i = 0; i < node->init_list.count; i++)
            walk_local_decls(cc, node->init_list.elements[i], visit, data);
        break;
    default:
        break;
    }
}

typedef struct {
    char **names; /* NULL to only count */
    int count;
} LocalSlotNames;

static void add_local_slot_names(CompilerContext *cc, ASTNode *var_decl, void *data)
{
    LocalSlotNames *slots = data;
    int slots_needed = slots_for_type(cc, var_decl->var_decl.var_type);
    if (slots_needed < 1) slots_needed = 1;
    for (int s = 0; s < slots_needed; s++) {
        if (slots->names) slots->names[slots->count] = var_decl->var_decl.name;
        slots->count++;
    }
}

/* One name per frame slot: a local that needs several slots is listed once
 * for each. Fills `locals` when it is not NULL; returns the count. */
int collect_locals(CompilerContext *cc, ASTNode *node, char **locals)
{
    LocalSlotNames slots = { .names = locals, .count = 0 };
    walk_local_decls(cc, node, add_local_slot_names, &slots);
    return slots.count;
}

typedef struct {
    LocalInfo *infos; /* NULL to only count */
    int count;
} LocalTypes;

static void add_local_type(CompilerContext *cc, ASTNode *var_decl, void *data)
{
    LocalTypes *types = data;
    if (types->infos) {
        types->infos[types->count].name = var_decl->var_decl.name;
        set_localinfo_from_type(cc, &types->infos[types->count], var_decl->var_decl.var_type);
    }
    types->count++;
}

/* One LocalInfo per declared local, in collect_locals' order. Fills `arr`
 * when it is not NULL; returns the count. */
int collect_local_type_info(CompilerContext *cc, ASTNode *node, LocalInfo *arr)
{
    LocalTypes types = { .infos = arr, .count = 0 };
    walk_local_decls(cc, node, add_local_type, &types);
    return types.count;
}

int find_var_offset(const char *name, char **params, int param_count,
                    char **locals, int local_count, int *is_param)
{
    int idx = param_index(name, params, param_count);
    if (idx >= 0)
    {
        if (is_param) *is_param = 1;
        if (idx < REG_ARG_COUNT) return param_offset(idx);
        return 8 + (idx - REG_ARG_COUNT) * SLOT_SIZE;
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
