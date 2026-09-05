#include "mylang/frontend/parser_rewrite_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

/* Lowers function literals into synthetic top-level function definitions and
 * rewrites local aliases so later passes only need to handle normalized AST. */

static void lower_fun_literals_node(ASTNode *node, const char *func_prefix, FunAlias **aliases, int *alias_count);

void lower_fun_literals_block(ASTNode *block, const char *func_prefix, FunAlias *aliases, int alias_count) {
    if (!block || block->type != AST_BLOCK) return;
    int local_count = 0;
    FunAlias *local_aliases = lower_alias_copy(aliases, alias_count, &local_count);

    ASTNode **new_stmts = NULL;
    int new_count = 0;

    for (int i = 0; i < block->block.count; i++) {
        ASTNode *stmt = block->block.stmts[i];
        if (!stmt) continue;

        if (stmt->type == AST_VAR_DECL &&
            stmt->var_decl.init &&
            stmt->var_decl.init->type == AST_FUN_LITERAL) {
            char buf[128];
            snprintf(buf, sizeof(buf), "%s_lam%d", func_prefix ? func_prefix : "g", parser_context_current()->lowering.function_literal_counter++);
            ASTNode *lit = stmt->var_decl.init;
            ASTNode *fn = new_fundef(stmt->var_decl.var_type, buf,
                                     lit->fun_literal.params, lit->fun_literal.param_count,
                                     lit->fun_literal.body, lit->fun_literal.is_variadic);
            fn->fundef.is_exported = 0;
            fn->fundef.package = NULL;
            add_function(fn);
            parser_context_current()->lowering.hoisted_functions = realloc(parser_context_current()->lowering.hoisted_functions, sizeof(ASTNode*) * (parser_context_current()->lowering.hoisted_function_count + 1));
            parser_context_current()->lowering.hoisted_functions[parser_context_current()->lowering.hoisted_function_count++] = fn;
            lower_fun_literals_block(fn->fundef.body, buf, NULL, 0);
            lower_alias_push(&local_aliases, &local_count, stmt->var_decl.name, buf);
            continue;
        }

        if (stmt->type == AST_VAR_DECL) {
            lower_alias_push(&local_aliases, &local_count, stmt->var_decl.name, NULL);
            if (stmt->var_decl.init)
                lower_fun_literals_node(stmt->var_decl.init, func_prefix, &local_aliases, &local_count);
            new_stmts = realloc(new_stmts, sizeof(ASTNode*) * (new_count + 1));
            new_stmts[new_count++] = stmt;
            continue;
        }

        lower_fun_literals_node(stmt, func_prefix, &local_aliases, &local_count);
        new_stmts = realloc(new_stmts, sizeof(ASTNode*) * (new_count + 1));
        new_stmts[new_count++] = stmt;
    }

    free(block->block.stmts);
    block->block.stmts = new_stmts;
    block->block.count = new_count;
    lower_alias_free_all(local_aliases, local_count);
}

static void lower_fun_literals_node(ASTNode *node, const char *func_prefix, FunAlias **aliases, int *alias_count) {
    if (!node) return;
    switch (node->type) {
    case AST_IDENTIFIER: {
        const char *rep = lower_alias_lookup(*aliases, *alias_count, node->identifier.name);
        if (rep) {
            free(node->identifier.name);
            node->identifier.name = strdup(rep);
        }
        break;
    }
    case AST_CALL: {
        const char *rep = lower_alias_lookup(*aliases, *alias_count, node->call.name);
        if (rep) {
            free(node->call.name);
            node->call.name = strdup(rep);
        }
        for (int i = 0; i < node->call.arg_count; i++)
            lower_fun_literals_node(node->call.args[i], func_prefix, aliases, alias_count);
        break;
    }
    case AST_ASSIGN:
        lower_fun_literals_node(node->assign.left, func_prefix, aliases, alias_count);
        lower_fun_literals_node(node->assign.right, func_prefix, aliases, alias_count);
        break;
    case AST_BINARY:
        lower_fun_literals_node(node->binary.left, func_prefix, aliases, alias_count);
        lower_fun_literals_node(node->binary.right, func_prefix, aliases, alias_count);
        break;
    case AST_UNARY:
        lower_fun_literals_node(node->unary.operand, func_prefix, aliases, alias_count);
        break;
    case AST_TERNARY:
        lower_fun_literals_node(node->ternary.cond, func_prefix, aliases, alias_count);
        lower_fun_literals_node(node->ternary.then_expr, func_prefix, aliases, alias_count);
        lower_fun_literals_node(node->ternary.else_expr, func_prefix, aliases, alias_count);
        break;
    case AST_IF:
        lower_fun_literals_node(node->if_stmt.cond, func_prefix, aliases, alias_count);
        lower_fun_literals_node(node->if_stmt.then_stmt, func_prefix, aliases, alias_count);
        lower_fun_literals_node(node->if_stmt.else_stmt, func_prefix, aliases, alias_count);
        break;
    case AST_WHILE:
        lower_fun_literals_node(node->while_stmt.cond, func_prefix, aliases, alias_count);
        lower_fun_literals_node(node->while_stmt.body, func_prefix, aliases, alias_count);
        break;
    case AST_DO_WHILE:
        lower_fun_literals_node(node->do_while_stmt.cond, func_prefix, aliases, alias_count);
        lower_fun_literals_node(node->do_while_stmt.body, func_prefix, aliases, alias_count);
        break;
    case AST_FOR:
        lower_fun_literals_node(node->for_stmt.init, func_prefix, aliases, alias_count);
        lower_fun_literals_node(node->for_stmt.cond, func_prefix, aliases, alias_count);
        lower_fun_literals_node(node->for_stmt.inc, func_prefix, aliases, alias_count);
        lower_fun_literals_node(node->for_stmt.body, func_prefix, aliases, alias_count);
        break;
    case AST_RETURN:
        lower_fun_literals_node(node->ret.expr, func_prefix, aliases, alias_count);
        break;
    case AST_YIELD:
        lower_fun_literals_node(node->yield_stmt.expr, func_prefix, aliases, alias_count);
        break;
    case AST_EXPR_STMT:
        lower_fun_literals_node(node->expr_stmt.expr, func_prefix, aliases, alias_count);
        break;
    case AST_MEMBER_ACCESS:
        lower_fun_literals_node(node->member_access.lhs, func_prefix, aliases, alias_count);
        break;
    case AST_ARROW_ACCESS:
        lower_fun_literals_node(node->arrow_access.lhs, func_prefix, aliases, alias_count);
        break;
    case AST_CAST:
        lower_fun_literals_node(node->cast.expr, func_prefix, aliases, alias_count);
        break;
    case AST_BLOCK:
        lower_fun_literals_block(node, func_prefix, *aliases, *alias_count);
        break;
    case AST_FUNDEF: {
        int copy_count = 0;
        FunAlias *copy = lower_alias_copy(*aliases, *alias_count, &copy_count);
        for (int i = 0; i < node->fundef.param_count; i++) {
            lower_alias_push(&copy, &copy_count, node->fundef.params[i]->param.name, NULL);
        }
        lower_fun_literals_block(node->fundef.body, node->fundef.name, copy, copy_count);
        lower_alias_free_all(copy, copy_count);
        break;
    }
    case AST_CASE:
        lower_fun_literals_node(node->case_expr.target, func_prefix, aliases, alias_count);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            lower_fun_literals_node(node->case_expr.cases[i].key, func_prefix, aliases, alias_count);
            lower_fun_literals_node(node->case_expr.cases[i].expr, func_prefix, aliases, alias_count);
        }
        lower_fun_literals_node(node->case_expr.default_expr, func_prefix, aliases, alias_count);
        break;
    case AST_STMT_EXPR:
        lower_fun_literals_node(node->stmt_expr.block, func_prefix, aliases, alias_count);
        break;
    case AST_ENUM:
        for (int i = 0; i < node->enum_stmt.member_count; i++) {
            lower_fun_literals_node(node->enum_stmt.members[i], func_prefix, aliases, alias_count);
        }
        break;
    case AST_ENUM_MEMBER:
        lower_fun_literals_node(node->enum_member.value, func_prefix, aliases, alias_count);
        break;
    default:
        break;
    }
}
