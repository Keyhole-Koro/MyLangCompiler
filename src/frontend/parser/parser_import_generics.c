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

typedef struct GenericImportClosure {
    ParserContext *context;
    Module *module;
} GenericImportClosure;

static void import_generic_template_closure(GenericImportClosure *closure, ASTNode *template);

static void import_generic_dependency(ASTNode **slot, void *user_data) {
    ASTNode *node = slot ? *slot : NULL;
    GenericImportClosure *closure = user_data;
    const char *name = NULL;
    if (node && node->type == AST_TYPE_GENERIC) name = node->generic_type.name;
    if (node && node->type == AST_CALL && node->call.type_arg_count) name = node->call.name;
    if (name) {
        for (int i = 0; i < closure->module->generic_template_count; i++) {
            ASTNode *candidate = closure->module->generic_templates[i];
            const char *candidate_name = template_name(candidate);
            if (candidate_name && strcmp(candidate_name, name) == 0) {
                import_generic_template_closure(closure, candidate);
                break;
            }
        }
    }
    ast_visit_children(node, import_generic_dependency, closure);
}

static int generic_template_is_already_imported(ParserContext *context, ASTNode *template) {
    const char *name = template_name(template);
    if (template->type == AST_STRUCT || template->type == AST_ENUM)
        return find_generic_type_template(context, name) != NULL;
    return find_generic_function_template(context, name) != NULL;
}

static int generic_method_is_already_imported(ParserContext *context,
                                              const char *receiver, const char *method) {
    for (int i = 0; i < generic_method_count(context); i++) {
        GenericMethodDef *candidate = generic_method_at(context, i);
        if (strcmp(candidate->receiver_template_name, receiver) == 0 &&
            strcmp(candidate->method_name, method) == 0) return 1;
    }
    return 0;
}

/* A public generic declaration is only useful if the importer also receives
 * the generic declarations used in its fields, signatures and body.  Copy
 * that closure here rather than requiring users to know implementation types
 * such as Mock's Rule and CallHistory. */
static void import_generic_template_closure(GenericImportClosure *closure, ASTNode *template) {
    if (!template || !template_is_exported(template) ||
        generic_template_is_already_imported(closure->context, template)) return;

    ASTNode *copy = ast_clone(template);
    /* Register before traversing methods/dependencies: a generic type is
     * allowed to refer to itself through a pointer or a method signature. */
    add_generic_template(closure->context, copy);
    if (copy->type == AST_STRUCT || copy->type == AST_ENUM) {
        const char *type_name = copy->type == AST_STRUCT
            ? copy->struct_stmt.name : copy->enum_stmt.name;
        add_typename(closure->context, type_name);
        for (int i = 0; i < closure->module->generic_method_count; i++) {
            ModuleGenericMethod *method = &closure->module->generic_methods[i];
            if (!method->receiver_template_name ||
                strcmp(method->receiver_template_name, type_name) != 0 ||
                generic_method_is_already_imported(closure->context, type_name,
                                                   method->method_name)) continue;
            add_generic_method(closure->context, method->receiver_template_name,
                               method->method_name, ast_clone(method->fundef));
            ast_visit_children(method->fundef, import_generic_dependency, closure);
        }
    }
    ast_visit_children(template, import_generic_dependency, closure);
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

        GenericImportClosure closure = {context, mod};
        import_generic_template_closure(&closure, template);

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
