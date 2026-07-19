#include "mylang/frontend/parser_rewrite_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/parser_state_internal.h"

/* Lowers function literals into synthetic top-level function definitions and
 * rewrites local aliases so later passes only need to handle normalized AST. */

static void lower_fun_literals_node(ASTNode *node, const char *func_prefix, FunAlias **aliases, int *alias_count);

static void named_arg_error(ASTNode *call, const char *message, const char *name) {
    fprintf(stderr, "Parse error at %d:%d: ", call ? call->line : 0, call ? call->col : 0);
    fprintf(stderr, message, name ? name : "");
    fputc('\n', stderr);
    exit(1);
}

static void normalize_named_call_args(ASTNode *call) {
    int has_named = 0;
    if (!call || call->type != AST_CALL || !call->call.arg_names) return;
    for (int i = 0; i < call->call.arg_count; i++) {
        if (call->call.arg_names[i]) {
            has_named = 1;
            break;
        }
    }
    if (!has_named) return;

    ASTNode *fn = find_function(call->call.name);
    if (!fn || fn->type != AST_FUNDEF) {
        named_arg_error(call, "named arguments are unavailable for function '%s'", call->call.name);
    }

    int argc = call->call.arg_count;
    int fixed_count = fn->fundef.is_variadic ? fn->fundef.param_count - 1 : fn->fundef.param_count;
    ASTNode **ordered = calloc((size_t)argc, sizeof(ASTNode*));
    int *source_indices = malloc(sizeof(int) * (size_t)argc);
    int next_positional = 0;
    int next_rest = fixed_count;

    for (int i = 0; i < argc; i++) source_indices[i] = -1;

    for (int source = 0; source < argc; source++) {
        char *arg_name = call->call.arg_names[source];
        int target = -1;

        if (arg_name) {
            for (int p = 0; p < fixed_count; p++) {
                ASTNode *param = fn->fundef.params[p];
                if (param && param->type == AST_PARAM && param->param.name &&
                    strcmp(param->param.name, arg_name) == 0) {
                    target = p;
                    break;
                }
            }
            if (target < 0) {
                named_arg_error(call, "unknown named argument '%s'", arg_name);
            }
        } else {
            while (next_positional < fixed_count && ordered[next_positional]) next_positional++;
            if (next_positional < fixed_count) {
                target = next_positional++;
            } else if (fn->fundef.is_variadic && next_rest < argc) {
                target = next_rest++;
            } else {
                named_arg_error(call, "too many arguments for function '%s'", call->call.name);
            }
        }

        if (target >= argc || ordered[target]) {
            named_arg_error(call, "duplicate named argument '%s'", arg_name ? arg_name : call->call.name);
        }
        ordered[target] = call->call.args[source];
        source_indices[target] = source;
    }

    for (int p = 0; p < fixed_count; p++) {
        if (p >= argc || !ordered[p]) {
            const char *param_name = fn->fundef.params[p] && fn->fundef.params[p]->type == AST_PARAM
                ? fn->fundef.params[p]->param.name : call->call.name;
            named_arg_error(call, "missing argument '%s'", param_name);
        }
    }

    for (int i = 0; i < argc; i++) free(call->call.arg_names[i]);
    free(call->call.arg_names);
    free(call->call.args);
    call->call.args = ordered;
    call->call.arg_names = NULL;
    call->call.arg_source_indices = source_indices;
}

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
            snprintf(buf, sizeof(buf), "%s_lam%d", func_prefix ? func_prefix : "g", g_funlit_counter++);
            ASTNode *lit = stmt->var_decl.init;
            ASTNode *fn = new_fundef(stmt->var_decl.var_type, buf,
                                     lit->fun_literal.params, lit->fun_literal.param_count,
                                     lit->fun_literal.body, lit->fun_literal.is_variadic);
            fn->fundef.is_exported = 0;
            fn->fundef.package = NULL;
            add_function(fn);
            g_hoisted_funcs = realloc(g_hoisted_funcs, sizeof(ASTNode*) * (g_hoisted_count + 1));
            g_hoisted_funcs[g_hoisted_count++] = fn;
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
        normalize_named_call_args(node);
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