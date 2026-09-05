#include "mylang/semantic/semantic_internal.h"
#include "mylang/frontend/module.h"

/* Initializes a fresh semantic context for one AST and runs the semantic walk
 * that validates ownership, bindings, and enum metadata for the whole unit. */

static const char *g_semantic_filename = NULL;
static int g_warnings_as_errors = 0;
static SemanticSafetyProfile g_safety_profile = SEMANTIC_SAFETY_DEFAULT;

void semantic_set_filename(const char *name) {
    g_semantic_filename = name;
}

void semantic_set_warnings_as_errors(int enabled) {
    g_warnings_as_errors = enabled ? 1 : 0;
}

void semantic_set_safety_profile(SemanticSafetyProfile profile) {
    g_safety_profile = profile;
}

SemanticSafetyProfile semantic_get_safety_profile(void) {
    return g_safety_profile;
}

int semantic_check_with_session(ASTNode *root, FrontendSession *session) {
    SemanticContext ctx;
    ctx.filename = g_semantic_filename;
    ctx.session = session;
    ctx.safety_profile = g_safety_profile;
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
    ctx.imported_package_count = 0;

    if (session) {
        for (int i = 0; i < session->root_imported_package_count; i++) {
            semantic_register_imported_package(&ctx, session->root_imported_packages[i]);
        }
    }

    semantic_walk_ast(&ctx, root);
    semantic_emit_diagnostics(&ctx);

    for (int i = 0; i < ctx.imported_package_count; i++) {
        free(ctx.imported_packages[i]);
    }

    return ctx.error_count == 0 && (!ctx.warnings_as_errors || ctx.warning_count == 0);
}

int semantic_check(ASTNode *root) {
    return semantic_check_with_session(root, frontend_session_current());
}
