#include "mylang/frontend/module.h"
#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_state_internal.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ModuleLoader *module_loader_create(ModuleGraph *graph, FrontendSession *session) {
    if (!graph || !session) return NULL;
    ModuleLoader *loader = calloc(1, sizeof(ModuleLoader));
    if (!loader) return NULL;
    loader->graph = graph;
    loader->session = session;
    return loader;
}

void module_loader_destroy(ModuleLoader *loader) {
    if (!loader) return;
    free(loader);
}

int module_loader_is_mylang_source(const char *path) {
    if (!path) return 0;
    size_t len = strlen(path);
    return len >= 4 && strcmp(path + len - 4, ".mln") == 0;
}

int module_loader_resolve_path(const char *importer_path, const char *rel_path,
                               char *out_canonical, size_t out_size) {
    char raw_buf[PATH_MAX];
    char resolved[PATH_MAX];

    if (!rel_path || !out_canonical || out_size == 0) return 0;

    if (rel_path[0] == '/') {
        snprintf(raw_buf, sizeof(raw_buf), "%s", rel_path);
    } else if (importer_path && importer_path[0]) {
        const char *slash = strrchr(importer_path, '/');
        if (slash) {
            size_t dir_len = (size_t)(slash - importer_path);
            if (dir_len >= sizeof(raw_buf)) return 0;
            memcpy(raw_buf, importer_path, dir_len);
            raw_buf[dir_len] = '\0';
            snprintf(raw_buf + dir_len, sizeof(raw_buf) - dir_len, "/%s", rel_path);
        } else {
            snprintf(raw_buf, sizeof(raw_buf), "%s", rel_path);
        }
    } else {
        snprintf(raw_buf, sizeof(raw_buf), "%s", rel_path);
    }

    if (!realpath(raw_buf, resolved)) {
        return 0;
    }

    if (strlen(resolved) >= out_size) return 0;
    snprintf(out_canonical, out_size, "%s", resolved);
    return 1;
}

static const char *find_export_orig_by_mangled(ParserContext *ctx, const char *mangled) {
    if (!ctx || !mangled) return NULL;
    for (int i = 0; i < ctx->module.export_count; i++) {
        if (ctx->module.exports[i].mangled &&
            strcmp(ctx->module.exports[i].mangled, mangled) == 0) {
            return ctx->module.exports[i].orig;
        }
    }
    return NULL;
}

static void collect_module_symbols(Module *module, ParserContext *ctx) {
    if (!module) return;

    /* Collect from program AST if available */
    if (module->program && module->program->type == AST_BLOCK) {
        for (int i = 0; i < module->program->block.count; i++) {
            ASTNode *stmt = module->program->block.stmts[i];
            if (!stmt) continue;

            if (stmt->type == AST_FUNDEF) {
                const char *current_name = stmt->fundef.name;
                const char *orig = find_export_orig_by_mangled(ctx, current_name);
                const char *source_name = orig ? orig : current_name;
                const char *link_name = current_name;
                module_add_symbol(module, SYMBOL_FUNCTION, source_name, link_name,
                                  stmt, stmt->fundef.is_exported);
            } else if (stmt->type == AST_STRUCT) {
                const char *name = stmt->struct_stmt.name;
                module_add_symbol(module, SYMBOL_STRUCT, name, name,
                                  stmt, stmt->struct_stmt.is_exported);
            } else if (stmt->type == AST_TYPEDEF) {
                const char *alias = stmt->typedef_stmt.alias;
                module_add_symbol(module, SYMBOL_TYPEDEF, alias, alias,
                                  stmt, 0);
            } else if (stmt->type == AST_ENUM) {
                const char *name = stmt->enum_stmt.name;
                module_add_symbol(module, SYMBOL_ENUM, name, name,
                                  stmt, 1);
            } else if (stmt->type == AST_VAR_DECL) {
                const char *current_name = stmt->var_decl.name;
                const char *orig = find_export_orig_by_mangled(ctx, current_name);
                const char *source_name = orig ? orig : current_name;
                const char *link_name = current_name;
                module_add_symbol(module, SYMBOL_GLOBAL, source_name, link_name,
                                  stmt, stmt->var_decl.is_exported);
            }
        }
    }

    /* Collect from generic templates */
    for (int i = 0; i < module->generic_template_count; i++) {
        ASTNode *tpl = module->generic_templates[i];
        if (!tpl) continue;

        if (tpl->type == AST_FUNDEF) {
            module_add_symbol(module, SYMBOL_GENERIC_FUNCTION,
                              tpl->fundef.name, tpl->fundef.name,
                              tpl, tpl->fundef.is_exported);
        } else if (tpl->type == AST_STRUCT) {
            module_add_symbol(module, SYMBOL_GENERIC_STRUCT,
                              tpl->struct_stmt.name, tpl->struct_stmt.name,
                              tpl, tpl->struct_stmt.is_exported);
        } else if (tpl->type == AST_ENUM) {
            module_add_symbol(module, SYMBOL_GENERIC_ENUM,
                              tpl->enum_stmt.name, tpl->enum_stmt.name,
                              tpl, tpl->enum_stmt.is_exported);
        }
    }
}

static void free_local_tokens(Token *tokens) {
    while (tokens) {
        Token *next = tokens->next;
        free(tokens->value);
        free(tokens);
        tokens = next;
    }
}

Module *module_loader_load(ModuleLoader *loader, const char *importer_path, const char *rel_path) {
    if (!loader || !loader->graph || !rel_path) return NULL;

    /* Non-.mln files (such as .masm) are linker imports, not source modules */
    if (!module_loader_is_mylang_source(rel_path)) {
        return NULL;
    }

    char canonical[PATH_MAX];
    if (!module_loader_resolve_path(importer_path, rel_path, canonical, sizeof(canonical))) {
        fprintf(stderr, "module_loader: failed to resolve path '%s' relative to '%s'\n",
                rel_path, importer_path ? importer_path : "(none)");
        return NULL;
    }

    Module *existing = module_graph_find(loader->graph, canonical);
    if (existing) {
        /* Cycle detection: if MODULE_LOADING, return it directly to avoid infinite recursion */
        return existing;
    }

    Module *module = module_graph_add(loader->graph, canonical);
    if (!module) return NULL;
    module->state = MODULE_LOADING;

    Token *tokens = lexer_from_file(canonical);
    if (!tokens) {
        fprintf(stderr, "module_loader: failed to read source file: %s\n", canonical);
        module->state = MODULE_FAILED;
        return module;
    }

    ParserContext ctx;
    parser_context_init(&ctx);
    ctx.module.filename = module->canonical_path; /* borrowed */
    ctx.session = loader->session;

    Token *cur = tokens;
    ASTNode *program = parse_program_syntax(&ctx, &cur);
    if (!program) {
        fprintf(stderr, "module_loader: failed to parse module: %s\n", canonical);
        free_local_tokens(tokens);
        parser_context_reset(&ctx);
        module->state = MODULE_FAILED;
        return module;
    }

    /* The main compilation unit runs instantiate_generics() (as part of
     * lower_program()) right after parsing, which both specializes generic
     * uses into concrete `__mlg_s_...`-named structs and lowers payload-enum
     * construction/matching onto them. A module loaded here for cross-file
     * symbol resolution skipped that: parse_program_syntax() alone leaves a
     * function like `Result<i32, i32> f() {...}` with its declared return
     * type exactly as written -- the plain generic name "Result", not the
     * mangled struct name a receiving Result<i32, i32> local elsewhere would
     * be registered under. append_imported_func_sig() (codegen_toplevel.c)
     * then can't recognize such a return as an aggregate, so a caller in
     * another file falls back to treating the call as a plain one-word
     * return instead of the hidden-out-pointer convention the callee (built
     * through the real, fully-lowered compile of this same file) actually
     * uses -- silently reading garbage instead of the struct's fields.
     * Running the same pass here keeps this module's own declarations in
     * sync with how its real compilation sees them. */
    instantiate_generics(&ctx, program);

    module->program = program; /* module owns program */

    /* Record declared package name if any */
    if (ctx.module.current_package &&
        strcmp(ctx.module.current_package, g_default_package) != 0) {
        module->package_name = strdup(ctx.module.current_package);
    } else {
        module->package_name = NULL;
    }

    /* Transfer ownership of generic templates before parser_context_reset */
    if (ctx.symbols.generic_templates.count > 0) {
        module->generic_template_count = ctx.symbols.generic_templates.count;
        module->generic_templates = ctx.symbols.generic_templates.declarations;
        /* Nullify in ctx to prevent parser_context_reset from freeing them */
        ctx.symbols.generic_templates.declarations = NULL;
        ctx.symbols.generic_templates.count = 0;
    }

    /* Same transfer, for the pre-lowering clone of each exported payload
     * enum staged during parsing (see add_exported_payload_enum() and its
     * call site in parser_toplevel.c). */
    if (ctx.symbols.exported_payload_enums.count > 0) {
        module->exported_payload_enum_count = ctx.symbols.exported_payload_enums.count;
        module->exported_payload_enums = ctx.symbols.exported_payload_enums.declarations;
        ctx.symbols.exported_payload_enums.declarations = NULL;
        ctx.symbols.exported_payload_enums.count = 0;
    }

    /* Collect symbol declarations and exports */
    collect_module_symbols(module, &ctx);

    /* Free temporary parser state and tokens */
    free_local_tokens(tokens);
    parser_context_reset(&ctx);

    module->state = MODULE_LOADED;
    return module;
}
