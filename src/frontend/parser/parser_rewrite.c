#include "mylang/frontend/parser_rewrite_internal.h"

/* Rewrites parsed AST names into their exported/mangled form while preserving
 * local scope bindings so later semantic/codegen passes see canonical names. */

static void rewrite_case_expr(ASTNode *node, char **scope, int scope_count) {
    rewrite_node(node->case_expr.target, scope, scope_count);
    for (int i = 0; i < node->case_expr.case_count; i++) {
        rewrite_node(node->case_expr.cases[i].key, scope, scope_count);
        rewrite_node(node->case_expr.cases[i].expr, scope, scope_count);
    }
    if (node->case_expr.default_expr) rewrite_node(node->case_expr.default_expr, scope, scope_count);
}

void rewrite_node(ASTNode *node, char **scope, int scope_count) {
    if (!node) return;
    switch (node->type) {
    case AST_IDENTIFIER: {
        const char *m = NULL;
        if (!rewrite_scope_contains(scope, scope_count, node->identifier.name)) {
            m = find_export_mangled(node->identifier.name);
        }
        if (m) {
            free(node->identifier.name);
            node->identifier.name = strdup(m);
        }
        break;
    }
    case AST_CALL: {
        const char *m = NULL;
        if (!rewrite_scope_contains(scope, scope_count, node->call.name)) {
            m = find_export_mangled(node->call.name);
        }
        if (m) {
            free(node->call.name);
            node->call.name = strdup(m);
        }
        for (int i = 0; i < node->call.arg_count; i++) {
            rewrite_node(node->call.args[i], scope, scope_count);
        }
        break;
    }
    case AST_VAR_DECL:
        rewrite_node(node->var_decl.var_type, scope, scope_count);
        if (node->var_decl.init) rewrite_node(node->var_decl.init, scope, scope_count);
        break;
    case AST_PARAM:
        break;
    case AST_FUNDEF: {
        int local_count = 0;
        int local_cap = 0;
        char **local_scope = rewrite_scope_from_params(node, &local_count, &local_cap);
        rewrite_node(node->fundef.body, local_scope, local_count);
        rewrite_scope_free(local_scope);
        break;
    }
    case AST_BLOCK: {
        int local_cap = scope_count > 64 ? scope_count * 2 : 64;
        int local_count = scope_count;
        char **local_scope = rewrite_scope_clone(scope, scope_count, local_cap);
        for (int i = 0; i < node->block.count; i++) {
            if (node->block.stmts[i] && node->block.stmts[i]->type == AST_VAR_DECL) {
                rewrite_node(node->block.stmts[i], local_scope, local_count);
                rewrite_scope_push(&local_scope, &local_count, &local_cap, node->block.stmts[i]->var_decl.name);
            } else {
                rewrite_node(node->block.stmts[i], local_scope, local_count);
            }
        }
        rewrite_scope_free(local_scope);
        break;
    }
    case AST_ASSIGN:
        rewrite_node(node->assign.left, scope, scope_count);
        rewrite_node(node->assign.right, scope, scope_count);
        break;
    case AST_BINARY:
        rewrite_node(node->binary.left, scope, scope_count);
        rewrite_node(node->binary.right, scope, scope_count);
        break;
    case AST_UNARY:
        rewrite_node(node->unary.operand, scope, scope_count);
        break;
    case AST_TERNARY:
        rewrite_node(node->ternary.cond, scope, scope_count);
        rewrite_node(node->ternary.then_expr, scope, scope_count);
        rewrite_node(node->ternary.else_expr, scope, scope_count);
        break;
    case AST_IF:
        rewrite_node(node->if_stmt.cond, scope, scope_count);
        rewrite_node(node->if_stmt.then_stmt, scope, scope_count);
        if (node->if_stmt.else_stmt) rewrite_node(node->if_stmt.else_stmt, scope, scope_count);
        break;
    case AST_WHILE:
        rewrite_node(node->while_stmt.cond, scope, scope_count);
        rewrite_node(node->while_stmt.body, scope, scope_count);
        break;
    case AST_DO_WHILE:
        rewrite_node(node->do_while_stmt.cond, scope, scope_count);
        rewrite_node(node->do_while_stmt.body, scope, scope_count);
        break;
    case AST_FOR:
        rewrite_node(node->for_stmt.init, scope, scope_count);
        rewrite_node(node->for_stmt.cond, scope, scope_count);
        rewrite_node(node->for_stmt.inc, scope, scope_count);
        rewrite_node(node->for_stmt.body, scope, scope_count);
        break;
    case AST_RETURN:
        rewrite_node(node->ret.expr, scope, scope_count);
        break;
    case AST_EXPR_STMT:
        rewrite_node(node->expr_stmt.expr, scope, scope_count);
        break;
    case AST_MEMBER_ACCESS:
        rewrite_node(node->member_access.lhs, scope, scope_count);
        break;
    case AST_ARROW_ACCESS:
        rewrite_node(node->arrow_access.lhs, scope, scope_count);
        break;
    case AST_CASE:
        rewrite_case_expr(node, scope, scope_count);
        break;
    case AST_ENUM:
        for (int i = 0; i < node->enum_stmt.member_count; i++) {
            rewrite_node(node->enum_stmt.members[i], scope, scope_count);
        }
        break;
    case AST_ENUM_MEMBER:
        rewrite_node(node->enum_member.value, scope, scope_count);
        break;
    case AST_STMT_EXPR:
        rewrite_node(node->stmt_expr.block, scope, scope_count);
        break;
    case AST_IMPORT:
    case AST_STRING_LITERAL:
    case AST_CHAR_LITERAL:
    case AST_SIZEOF:
    case AST_INIT_LIST:
    case AST_TYPE:
    case AST_TYPE_ARRAY:
    case AST_STRUCT:
    case AST_STRUCT_MEMBER:
    case AST_TYPEDEF_STRUCT:
    case AST_TYPEDEF:
        break;
    default:
        break;
    }
}
