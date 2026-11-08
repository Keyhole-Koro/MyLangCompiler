#include "mylang/frontend/parser_rewrite_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

/* Lowers function literals into synthetic top-level function definitions and
 * rewrites local aliases so later passes only need to handle normalized AST. */

static void lower_fun_literals_node(ParserContext *context, ASTNode *node,
                                    const char *func_prefix, FunAlias **aliases,
                                    int *alias_count);

void lower_fun_literals_block(ParserContext *context, ASTNode *block,
                              const char *func_prefix, FunAlias *aliases,
                              int alias_count) {
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
            snprintf(buf, sizeof(buf), "%s_lam%d", func_prefix ? func_prefix : "g", context->lowering.function_literal_counter++);
            ASTNode *lit = stmt->var_decl.init;
            ASTNode *fn = new_fundef(stmt->var_decl.var_type, buf,
                                     lit->fun_literal.params, lit->fun_literal.param_count,
                                     lit->fun_literal.body, lit->fun_literal.is_variadic);
            fn->fundef.is_exported = 0;
            fn->fundef.package = NULL;
            /* A diagnostic about the function has no other place to point. */
            if (fn->fundef.body) {
                fn->line = fn->fundef.body->line;
                fn->col = fn->fundef.body->col;
                fn->end_line = fn->fundef.body->end_line;
                fn->end_col = fn->fundef.body->end_col;
            }
            add_function(context, fn);
            context->lowering.hoisted_functions = realloc(context->lowering.hoisted_functions, sizeof(ASTNode*) * (context->lowering.hoisted_function_count + 1));
            context->lowering.hoisted_functions[context->lowering.hoisted_function_count++] = fn;
            lower_fun_literals_block(context, fn->fundef.body, buf, NULL, 0);
            lower_alias_push(&local_aliases, &local_count, stmt->var_decl.name, buf);
            continue;
        }

        if (stmt->type == AST_VAR_DECL) {
            lower_alias_push(&local_aliases, &local_count, stmt->var_decl.name, NULL);
            if (stmt->var_decl.init)
                lower_fun_literals_node(context, stmt->var_decl.init, func_prefix, &local_aliases, &local_count);
            new_stmts = realloc(new_stmts, sizeof(ASTNode*) * (new_count + 1));
            new_stmts[new_count++] = stmt;
            continue;
        }

        lower_fun_literals_node(context, stmt, func_prefix, &local_aliases, &local_count);
        new_stmts = realloc(new_stmts, sizeof(ASTNode*) * (new_count + 1));
        new_stmts[new_count++] = stmt;
    }

    free(block->block.stmts);
    block->block.stmts = new_stmts;
    block->block.count = new_count;
    lower_alias_free_all(local_aliases, local_count);
}

typedef struct {
    ParserContext *context;
    const char *func_prefix;
    FunAlias **aliases;
    int *alias_count;
} LowerScope;

static void lower_child(ASTNode **slot, void *data) {
    LowerScope *scope = data;
    lower_fun_literals_node(scope->context, *slot, scope->func_prefix, scope->aliases,
                            scope->alias_count);
}

/* A function literal is lowered to a function only where a declaration in a
 * block initializes it, which names that function: lower_fun_literals_block
 * takes those. Anywhere else it would be a value, and it is not one. */
static void reject_fun_literal(ParserContext *context, const ASTNode *literal) {
    fprintf(stderr, "%s:%d:%d: error: a function literal is only allowed as the initializer "
            "of a declaration, such as `i32 twice = (i32 x) { return x + x; };`\n",
            context->module.filename ? context->module.filename : "<input>",
            literal->line, literal->col);
    exit(1);
}

static void rename_alias(FunAlias *aliases, int alias_count, char **name) {
    const char *rep = lower_alias_lookup(aliases, alias_count, *name);
    if (!rep) return;
    free(*name);
    *name = strdup(rep);
}

static void lower_fun_literals_node(ParserContext *context, ASTNode *node,
                                    const char *func_prefix, FunAlias **aliases,
                                    int *alias_count) {
    if (!node) return;
    switch (node->type) {
    case AST_IDENTIFIER:
        rename_alias(*aliases, *alias_count, &node->identifier.name);
        return;
    case AST_CALL:
        rename_alias(*aliases, *alias_count, &node->call.name);
        break;
    case AST_BLOCK:
        lower_fun_literals_block(context, node, func_prefix, *aliases, *alias_count);
        return;
    case AST_FUNDEF: {
        int copy_count = 0;
        FunAlias *copy = lower_alias_copy(*aliases, *alias_count, &copy_count);
        for (int i = 0; i < node->fundef.param_count; i++) {
            lower_alias_push(&copy, &copy_count, node->fundef.params[i]->param.name, NULL);
        }
        lower_fun_literals_block(context, node->fundef.body, node->fundef.name, copy, copy_count);
        lower_alias_free_all(copy, copy_count);
        return;
    }
    case AST_FOR: {
        /* A variable the init declares hides an alias of its name for the
         * rest of the loop. */
        int copy_count = 0;
        FunAlias *copy = lower_alias_copy(*aliases, *alias_count, &copy_count);
        ASTNode *init = node->for_stmt.init;
        lower_fun_literals_node(context, init, func_prefix, &copy, &copy_count);
        if (init && init->type == AST_VAR_DECL)
            lower_alias_push(&copy, &copy_count, init->var_decl.name, NULL);
        lower_fun_literals_node(context, node->for_stmt.cond, func_prefix, &copy, &copy_count);
        lower_fun_literals_node(context, node->for_stmt.inc, func_prefix, &copy, &copy_count);
        lower_fun_literals_node(context, node->for_stmt.body, func_prefix, &copy, &copy_count);
        lower_alias_free_all(copy, copy_count);
        return;
    }
    case AST_FUN_LITERAL:
        reject_fun_literal(context, node);
        return;
    /* A type names no value. */
    case AST_TYPE:
    case AST_TYPE_ARRAY:
    case AST_TYPE_GENERIC:
    case AST_TYPE_FUNCTION:
        return;
    default:
        break;
    }
    LowerScope scope = { context, func_prefix, aliases, alias_count };
    ast_visit_children(node, lower_child, &scope);
}
