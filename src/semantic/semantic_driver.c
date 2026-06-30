#include "mylang/semantic/semantic_internal.h"

/* Initializes a fresh semantic context for one AST and runs the semantic walk
 * that validates ownership, bindings, and enum metadata for the whole unit. */

static const char *g_semantic_filename = NULL;
static int g_warnings_as_errors = 0;

void semantic_set_filename(const char *name) {
    g_semantic_filename = name;
}

void semantic_set_warnings_as_errors(int enabled) {
    g_warnings_as_errors = enabled ? 1 : 0;
}

int semantic_check(ASTNode *root) {
    SemanticContext ctx;
    ctx.filename = g_semantic_filename;
    ctx.error_count = 0;
    ctx.warning_count = 0;
    ctx.warnings_as_errors = g_warnings_as_errors;
    ctx.diagnostic_count = 0;
    ctx.scope_depth = 0;
    ctx.function_depth = 0;
    ctx.current_function = NULL;
    ctx.binding_count = 0;
    ctx.enum_type_count = 0;
    ctx.enum_value_count = 0;
    ctx.function_sig_count = 0;
    ctx.user_type_count = 0;

    semantic_walk_ast(&ctx, root);
    semantic_emit_diagnostics(&ctx);
    return ctx.error_count == 0 && (!ctx.warnings_as_errors || ctx.warning_count == 0);
}
