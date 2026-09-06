#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/resolver.h"

static int import_requests_symbol(const ASTNode *node, const char *name) {
    if (!node || node->type != AST_IMPORT || !name) return 0;
    for (int i = 0; i < node->import_stmt.symbol_count; i++) {
        if (node->import_stmt.symbols[i] && strcmp(node->import_stmt.symbols[i], name) == 0)
            return 1;
    }
    return 0;
}

static int template_is_exported(const ASTNode *node) {
    if (!node) return 0;
    if (node->type == AST_FUNDEF) return node->fundef.is_exported;
    if (node->type == AST_STRUCT) return node->struct_stmt.is_exported;
    if (node->type == AST_ENUM) return node->enum_stmt.is_exported;
    return 0;
}

static const char *template_name(const ASTNode *node) {
    if (!node) return NULL;
    if (node->type == AST_FUNDEF) return node->fundef.name;
    if (node->type == AST_STRUCT) return node->struct_stmt.name;
    if (node->type == AST_ENUM) return node->enum_stmt.name;
    return NULL;
}

static void remove_import_symbol(ASTNode *node, const char *name) {
    if (!node || node->type != AST_IMPORT || !name) return;
    for (int i = 0; i < node->import_stmt.symbol_count; i++) {
        if (!node->import_stmt.symbols[i] || strcmp(node->import_stmt.symbols[i], name) != 0)
            continue;
        free(node->import_stmt.symbols[i]);
        for (int j = i + 1; j < node->import_stmt.symbol_count; j++)
            node->import_stmt.symbols[j - 1] = node->import_stmt.symbols[j];
        node->import_stmt.symbol_count--;
        if (node->import_stmt.symbol_count == 0) {
            free(node->import_stmt.symbols);
            node->import_stmt.symbols = NULL;
        }
        return;
    }
}

void load_imported_generic_templates(ParserContext *context, ASTNode *import_node,
                                     const char *source_path) {
    if (!import_node || import_node->type != AST_IMPORT ||
        !source_path || import_node->import_stmt.symbol_count == 0)
        return;

    FrontendSession *session = context->session;
    if (!session || !session->loader) return;

    Module *mod = module_loader_load(session->loader, context->module.filename, source_path);
    if (!mod || mod->state != MODULE_LOADED) return;

    for (int i = 0; i < mod->generic_template_count; i++) {
        ASTNode *template = mod->generic_templates[i];
        const char *name = template_name(template);
        if (!template_is_exported(template) || !import_requests_symbol(import_node, name))
            continue;

        ASTNode *copy = ast_clone(template);
        if (copy->type == AST_STRUCT || copy->type == AST_ENUM) {
            const char *type_name = copy->type == AST_STRUCT
                ? copy->struct_stmt.name : copy->enum_stmt.name;
            add_typename(context, type_name);
        }
        add_generic_template(context, copy);
        remove_import_symbol(import_node, name);
    }
}

/* Same idea as load_imported_generic_templates(), for a plain (non-generic)
 * struct or enum: `import { FsError } from "fs.mln";` needs "FsError" to
 * parse as a type name from here on in this file (add_typename(), exactly
 * as if it had been declared locally), and needs its layout to reach this
 * file's own codegen -- which only happens by giving it a copy of the
 * declaration to see, since a generic-typed function crossing the file
 * boundary is the only cross-file case codegen otherwise resolves (via
 * ModuleLoader's Resolver, function signatures only). The copy is staged in
 * imported_plain_types until instantiate_generics() splices it into this
 * file's own program->block.stmts, the same way a generic template's
 * concrete instantiation is spliced in.
 *
 * Unlike a generic template, a plain type has no per-use instantiation site
 * to specialize from -- it's already concrete -- so it's simply spliced in
 * unconditionally instead of being matched against uses in the program. */
void load_imported_plain_types(ParserContext *context, ASTNode *import_node,
                               const char *source_path) {
    if (!import_node || import_node->type != AST_IMPORT ||
        !source_path || import_node->import_stmt.symbol_count == 0)
        return;

    FrontendSession *session = context->session;
    if (!session || !session->loader) return;

    Module *mod = module_loader_load(session->loader, context->module.filename, source_path);
    if (!mod || mod->state != MODULE_LOADED) return;

    for (int i = 0; i < mod->symbol_count; i++) {
        ModuleSymbol *sym = &mod->symbols[i];
        if (sym->kind != SYMBOL_STRUCT && sym->kind != SYMBOL_ENUM) continue;
        if (!sym->is_exported || !sym->source_name) continue;
        if (!import_requests_symbol(import_node, sym->source_name)) continue;

        /* Already declared or imported under this name in this file
         * (including by an earlier import statement pulling in the same
         * re-exported type transitively) -- nothing left to stage. */
        if (is_user_typename(context, sym->source_name)) {
            remove_import_symbol(import_node, sym->source_name);
            continue;
        }

        /* A payload enum's own declaration (`sym->declaration`) is, by this
         * point, already the *lowered* struct -- module_loader_load() ran
         * instantiate_generics() on `mod` before collecting symbols, the
         * same as it does for the main compilation unit. That's the right
         * form for this file's own codegen to see, but not for this file's
         * own payload-enum lowering pass: it needs the original enum's
         * variant table (name -> tag, has-payload) to rewrite this file's
         * own `Variant(x) -> ...` uses, and the struct no longer carries
         * that. Prefer the pre-lowering clone stashed for exactly this. */
        ASTNode *preserved = NULL;
        for (int j = 0; j < mod->exported_payload_enum_count; j++) {
            ASTNode *candidate = mod->exported_payload_enums[j];
            if (candidate && candidate->type == AST_ENUM &&
                candidate->enum_stmt.name &&
                strcmp(candidate->enum_stmt.name, sym->source_name) == 0) {
                preserved = candidate;
                break;
            }
        }

        ASTNode *copy = ast_clone(preserved ? preserved : sym->declaration);
        add_typename(context, sym->source_name);
        add_imported_plain_type(context, copy);
        remove_import_symbol(import_node, sym->source_name);
    }
}
