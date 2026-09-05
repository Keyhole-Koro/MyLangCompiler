#include "mylang/semantic/semantic_internal.h"
#include "mylang/frontend/parser.h"

/* Initializes a fresh semantic context for one AST and runs the semantic walk
 * that validates ownership, bindings, and enum metadata for the whole unit. */

static const char *g_semantic_filename = NULL;
static int g_warnings_as_errors = 0;
static SemanticSafetyProfile g_safety_profile = SEMANTIC_SAFETY_DEFAULT;
static int g_imported_package_count = 0;
static char *g_imported_packages[64];

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

void semantic_add_imported_package(const char *name) {
    if (!name || g_imported_package_count >= 64) return;
    for (int i = 0; i < g_imported_package_count; i++) {
        if (g_imported_packages[i] && strcmp(g_imported_packages[i], name) == 0) return;
    }
    g_imported_packages[g_imported_package_count++] = strdup(name);
}

void semantic_reset_imported_packages(void) {
    for (int i = 0; i < g_imported_package_count; i++) {
        free(g_imported_packages[i]);
        g_imported_packages[i] = NULL;
    }
    g_imported_package_count = 0;
}

int semantic_check(ASTNode *root) {
    SemanticContext ctx;
    ctx.filename = g_semantic_filename;
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

    if (g_imported_package_count == 0) {
        int pkg_count = parser_get_imported_package_count();
        for (int i = 0; i < pkg_count; i++) {
            const char *pkg = parser_get_imported_package(i);
            if (pkg) semantic_register_imported_package(&ctx, pkg);
        }
    } else {
        for (int i = 0; i < g_imported_package_count; i++) {
            semantic_register_imported_package(&ctx, g_imported_packages[i]);
        }
    }

    semantic_walk_ast(&ctx, root);
    semantic_emit_diagnostics(&ctx);

    for (int i = 0; i < ctx.imported_package_count; i++) {
        free(ctx.imported_packages[i]);
    }

    return ctx.error_count == 0 && (!ctx.warnings_as_errors || ctx.warning_count == 0);
}
