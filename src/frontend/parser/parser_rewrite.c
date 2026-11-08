#include "mylang/frontend/parser_rewrite_internal.h"

/* Rewrites parsed AST names into their exported/mangled form while preserving
 * local scope bindings so later semantic/codegen passes see canonical names. */

typedef struct {
    ParserContext *context;
    char **scope;
    int scope_count;
} RewriteScope;

static void rewrite_child(ASTNode **slot, void *data) {
    RewriteScope *rewrite = data;
    rewrite_node(rewrite->context, *slot, rewrite->scope, rewrite->scope_count);
}

static const char *exported_name(ParserContext *context, char **scope, int scope_count,
                                 const char *name) {
    return rewrite_scope_contains(scope, scope_count, name) ? NULL : find_export_mangled(context, name);
}

void rewrite_node(ParserContext *context, ASTNode *node, char **scope, int scope_count) {
    if (!node) return;
    switch (node->type) {
    case AST_IDENTIFIER: {
        const char *m = exported_name(context, scope, scope_count, node->identifier.name);
        if (m) {
            free(node->identifier.name);
            node->identifier.name = strdup(m);
        }
        return;
    }
    case AST_CALL: {
        const char *m = exported_name(context, scope, scope_count, node->call.name);
        if (m) {
            free(node->call.name);
            node->call.name = strdup(m);
        }
        for (int i = 0; i < node->call.arg_count; i++) {
            rewrite_node(context, node->call.args[i], scope, scope_count);
        }
        rewrite_node(context, node->call.recv, scope, scope_count);
        return;
    }
    case AST_VAR_DECL:
        rewrite_node(context, node->var_decl.init, scope, scope_count);
        return;
    case AST_FUNDEF: {
        int local_count = 0;
        int local_cap = 0;
        char **local_scope = rewrite_scope_from_params(node, &local_count, &local_cap);
        rewrite_node(context, node->fundef.body, local_scope, local_count);
        rewrite_scope_free(local_scope);
        return;
    }
    case AST_BLOCK: {
        int local_cap = scope_count > 64 ? scope_count * 2 : 64;
        int local_count = scope_count;
        char **local_scope = rewrite_scope_clone(scope, scope_count, local_cap);
        for (int i = 0; i < node->block.count; i++) {
            if (node->block.stmts[i] && node->block.stmts[i]->type == AST_VAR_DECL) {
                rewrite_node(context, node->block.stmts[i], local_scope, local_count);
                rewrite_scope_push(&local_scope, &local_count, &local_cap, node->block.stmts[i]->var_decl.name);
            } else {
                rewrite_node(context, node->block.stmts[i], local_scope, local_count);
            }
        }
        rewrite_scope_free(local_scope);
        return;
    }
    case AST_CAST:
        rewrite_node(context, node->cast.expr, scope, scope_count);
        return;
    case AST_ENUM_MEMBER:
        rewrite_node(context, node->enum_member.value, scope, scope_count);
        return;
    case AST_INIT_LIST:
        for (int i = 0; i < node->init_list.count; i++) {
            rewrite_node(context, node->init_list.elements[i], scope, scope_count);
        }
        return;
    /* Types, declarations and parameters name no value to rewrite, and a
     * function literal or markup is lowered before this pass. */
    case AST_PARAM:
    case AST_SIZEOF:
    case AST_TYPE:
    case AST_TYPE_ARRAY:
    case AST_TYPE_GENERIC:
    case AST_TYPE_FUNCTION:
    case AST_STRUCT:
    case AST_TYPEDEF_STRUCT:
    case AST_TYPEDEF:
    case AST_IMPORT:
    case AST_FUN_LITERAL:
    case AST_DOM_ELEMENT:
        return;
    default:
        break;
    }
    RewriteScope rewrite = { context, scope, scope_count };
    ast_visit_children(node, rewrite_child, &rewrite);
}
