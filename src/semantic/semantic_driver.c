#include "mylang/semantic/semantic_internal.h"

/* Initializes a fresh semantic context for one AST and runs the semantic walk
 * that validates ownership, bindings, and enum metadata for the whole unit. */

static const char *g_semantic_filename = NULL;

void semantic_set_filename(const char *name) {
    g_semantic_filename = name;
}

int semantic_check(ASTNode *root) {
    SemanticContext ctx;
    ctx.filename = g_semantic_filename;
    ctx.error_count = 0;
    ctx.scope_depth = 0;
    ctx.function_depth = 0;
    ctx.binding_count = 0;
    ctx.enum_type_count = 0;
    ctx.enum_value_count = 0;
    ctx.function_sig_count = 0;
    ctx.user_type_count = 0;

    semantic_walk_ast(&ctx, root);
    return ctx.error_count == 0;
}
