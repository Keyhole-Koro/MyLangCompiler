#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/module.h"

void set_current_package(ParserContext *context, const char *name) {
    if (context->module.current_package_heap && context->module.current_package) {
        free(context->module.current_package);
    }
    context->module.current_package = strdup(name ? name : g_default_package);
    context->module.current_package_heap = 1;
}

void add_export(ParserContext *context, const char *orig, const char *mangled) {
    context->module.exports = realloc(context->module.exports, sizeof(ExportEntry) * (context->module.export_count + 1));
    context->module.exports[context->module.export_count].orig = strdup(orig);
    context->module.exports[context->module.export_count].mangled = strdup(mangled);
    context->module.export_count++;
}

const char *find_export_mangled(ParserContext *context, const char *orig) {
    for (int i = 0; i < context->module.export_count; i++) {
        if (strcmp(context->module.exports[i].orig, orig) == 0) return context->module.exports[i].mangled;
    }
    return NULL;
}

int is_imported_package(ParserContext *context, const char *name) {
    for (int i = 0; i < context->module.imported_package_count; i++) {
        if (strcmp(context->module.imported_packages[i], name) == 0) return 1;
    }
    return 0;
}

char *mangle(const char *pkg, const char *name) {
    size_t len = strlen(pkg) + 1 + strlen(name) + 1;
    char *buf = malloc(len);
    snprintf(buf, len, "%s_%s", pkg, name);
    return buf;
}

/* Whether `symbol` is a name an import of `module` under its namespace reaches
 * as `ns.name`: a function or global the module defines and exports, whose
 * link name carries the namespace, or a generic function written in the module
 * (an importer instantiates it). Prototypes, imported copies and methods are
 * someone else's or travel with their type. */
static int is_namespace_member(const Module *module, const ModuleSymbol *symbol) {
    if (!symbol->is_exported || !symbol->source_name || !module->package_name) return 0;
    const ASTNode *declaration = symbol->declaration;
    if (symbol->kind == SYMBOL_GENERIC_FUNCTION) {
        return declaration && declaration->type == AST_FUNDEF &&
               (!declaration->fundef.origin_path ||
                strcmp(declaration->fundef.origin_path, module->canonical_path) == 0);
    }
    if (symbol->kind == SYMBOL_FUNCTION) {
        if (!declaration || declaration->type != AST_FUNDEF || !declaration->fundef.body) return 0;
    } else if (symbol->kind == SYMBOL_GLOBAL) {
        if (!declaration || declaration->type != AST_VAR_DECL || declaration->var_decl.is_extern) return 0;
    } else {
        return 0;
    }
    size_t namespace_length = strlen(module->package_name);
    return symbol->link_name && strncmp(symbol->link_name, module->package_name, namespace_length) == 0 &&
           symbol->link_name[namespace_length] == '_' &&
           strcmp(symbol->link_name + namespace_length + 1, symbol->source_name) == 0;
}

static int module_has_namespace_member(const Module *module, const char *name) {
    for (int i = 0; i < module->symbol_count; i++) {
        const ModuleSymbol *symbol = &module->symbols[i];
        if (strcmp(symbol->source_name ? symbol->source_name : "", name) == 0 &&
            is_namespace_member(module, symbol))
            return 1;
    }
    return 0;
}

/* Records `import binding from "path";` of a file that declares `namespace
 * binding;`. Another file taken under the same name joins it: `binding.a` is
 * whichever exports `a`, and a name both export is ambiguous -- and would be
 * defined twice at link time -- so it is an error naming the two files. A
 * module still loading is in an import cycle and has no symbols yet to compare. */
void add_namespace_import(ParserContext *context, const char *binding, const char *path,
                          Module *module, Token *at) {
    for (int i = 0; i < context->module.namespace_import_count; i++) {
        NamespaceImport *earlier = &context->module.namespace_imports[i];
        if (strcmp(earlier->binding, binding) != 0) continue;
        if (earlier->module == module) return;
        if (module->state != MODULE_LOADED || earlier->module->state != MODULE_LOADED) continue;
        for (int s = 0; s < module->symbol_count; s++) {
            const ModuleSymbol *symbol = &module->symbols[s];
            if (!is_namespace_member(module, symbol) ||
                !module_has_namespace_member(earlier->module, symbol->source_name))
                continue;
            char message[1024];
            snprintf(message, sizeof(message),
                     "'%s' and '%s' both export '%s' in namespace '%s', so '%s.%s' is ambiguous",
                     earlier->path, path, symbol->source_name, binding, binding, symbol->source_name);
            parse_error(context, message, at);
        }
    }
    context->module.namespace_imports = realloc(context->module.namespace_imports,
        sizeof(NamespaceImport) * (context->module.namespace_import_count + 1));
    NamespaceImport *entry = &context->module.namespace_imports[context->module.namespace_import_count++];
    entry->binding = strdup(binding);
    entry->path = strdup(path);
    entry->module = module;
    entry->at = at;
}

/* A file that imports another file of its own namespace shares the names that
 * file exports: `ns.a` would be either file's `a`, and the two would define
 * one link name. Checked once the file's own exports are all known. */
void check_own_namespace_exports(ParserContext *context) {
    if (!context->module.namespace_declared) return;
    const char *own = context->module.current_package;
    for (int i = 0; i < context->module.namespace_import_count; i++) {
        NamespaceImport *import = &context->module.namespace_imports[i];
        if (strcmp(import->binding, own) != 0 || import->module->state != MODULE_LOADED) continue;
        const char *clash = NULL;
        for (int e = 0; !clash && e < context->module.export_count; e++) {
            const ExportEntry *entry = &context->module.exports[e];
            char *link = mangle(own, entry->orig);
            if (strcmp(link, entry->mangled) == 0 &&
                module_has_namespace_member(import->module, entry->orig))
                clash = entry->orig;
            free(link);
        }
        for (int t = 0; !clash && t < context->symbols.generic_templates.count; t++) {
            ASTNode *template = context->symbols.generic_templates.declarations[t];
            if (template && template->type == AST_FUNDEF && template->fundef.is_exported &&
                !template->fundef.origin_path && template->fundef.name &&
                module_has_namespace_member(import->module, template->fundef.name))
                clash = template->fundef.name;
        }
        if (!clash) continue;
        char message[1024];
        snprintf(message, sizeof(message),
                 "this file and '%s' both export '%s' in namespace '%s', so '%s.%s' is ambiguous",
                 import->path, clash, own, own, clash);
        parse_error(context, message, import->at);
    }
}
