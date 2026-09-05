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
