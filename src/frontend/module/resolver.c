#include "mylang/frontend/resolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *resolver_import_package_name(const ASTNode *import_node, const Module *target_module) {
    if (!import_node || import_node->type != AST_IMPORT || !target_module) return NULL;
    /* A package import has symbol_count == 0 and imports the whole target package */
    if (import_node->import_stmt.symbol_count == 0) {
        return target_module->package_name;
    }
    return NULL;
}

static int import_stmt_requests_symbol(const ASTNode *import_node, const char *symbol_name) {
    if (!import_node || import_node->type != AST_IMPORT || !symbol_name) return 0;
    for (int i = 0; i < import_node->import_stmt.symbol_count; i++) {
        const char *req = import_node->import_stmt.symbols[i];
        if (req && strcmp(req, symbol_name) == 0) return 1;
    }
    return 0;
}

ModuleSymbol *resolver_lookup_import_symbol(const ASTNode *import_node, const Module *target_module,
                                            const char *symbol_name) {
    if (!import_node || import_node->type != AST_IMPORT || !target_module || !symbol_name) return NULL;

    if (import_node->import_stmt.symbol_count == 0) {
        /* Package import: all exported symbols in target_module are visible */
        return module_find_exported_symbol(target_module, symbol_name);
    }

    /* Symbol-list import: only explicitly requested symbols are visible */
    if (!import_stmt_requests_symbol(import_node, symbol_name)) {
        return NULL;
    }
    return module_find_exported_symbol(target_module, symbol_name);
}

void resolver_fill_dom_signature(const ASTNode *fundef_node, const char *call_name, DomSignature *out) {
    if (!fundef_node || fundef_node->type != AST_FUNDEF || !out) return;

    memset(out, 0, sizeof(*out));
    out->call_name = call_name ? strdup(call_name) : strdup(fundef_node->fundef.name ? fundef_node->fundef.name : "");
    out->return_type = fundef_node->fundef.ret_type;
    out->param_count = fundef_node->fundef.param_count;

    if (out->param_count > 0) {
        out->param_names = malloc(sizeof(char *) * out->param_count);
        out->param_defaults = malloc(sizeof(ASTNode *) * out->param_count);
        for (int i = 0; i < out->param_count; i++) {
            ASTNode *p = fundef_node->fundef.params[i];
            const char *pname = (p && p->type == AST_PARAM && p->param.name) ? p->param.name : "";
            out->param_names[i] = strdup(pname);
            out->param_defaults[i] = (p && p->type == AST_PARAM) ? p->param.default_value : NULL;
        }
    } else {
        out->param_names = NULL;
        out->param_defaults = NULL;
    }
}
