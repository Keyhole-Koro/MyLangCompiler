#include "mylang/frontend/resolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int resolver_get_function_info(const ModuleSymbol *sym, ResolverFunctionInfo *out_info) {
    if (!sym || !out_info || !sym->declaration) return 0;
    ASTNode *fn = sym->declaration;
    if (fn->type != AST_FUNDEF) return 0;

    memset(out_info, 0, sizeof(*out_info));
    out_info->source_name = sym->source_name;
    out_info->link_name = sym->link_name;
    out_info->ret_type_ast = fn->fundef.ret_type;
    out_info->param_count = fn->fundef.param_count;
    out_info->is_variadic = fn->fundef.is_variadic;
    out_info->fixed_param_count = fn->fundef.is_variadic
        ? (fn->fundef.param_count > 0 ? fn->fundef.param_count - 1 : 0)
        : fn->fundef.param_count;
    out_info->is_exported = sym->is_exported;
    out_info->package_name = fn->fundef.package;

    if (fn->fundef.param_count > 0) {
        out_info->params = calloc(fn->fundef.param_count, sizeof(ResolverParamInfo));
        if (!out_info->params) return 0;

        for (int i = 0; i < fn->fundef.param_count; i++) {
            ASTNode *p = fn->fundef.params[i];
            if (p && p->type == AST_PARAM) {
                out_info->params[i].name = p->param.name ? p->param.name : "";
                out_info->params[i].type_ast = p->param.type;
                out_info->params[i].is_mut = p->param.is_mut;
                out_info->params[i].is_rest = p->param.is_rest;
            } else {
                out_info->params[i].name = "";
                out_info->params[i].type_ast = NULL;
                out_info->params[i].is_mut = 0;
                out_info->params[i].is_rest = 0;
            }
        }
    }
    return 1;
}

void resolver_free_function_info(ResolverFunctionInfo *info) {
    if (!info) return;
    if (info->params) {
        free(info->params);
        info->params = NULL;
    }
    info->param_count = 0;
}

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

ASTNode *resolver_find_exported_generic_template(const Module *module, const char *name) {
    if (!module || !name) return NULL;

    for (int i = 0; i < module->generic_template_count; i++) {
        ASTNode *tpl = module->generic_templates[i];
        if (!tpl) continue;

        if (tpl->type == AST_FUNDEF && tpl->fundef.is_exported &&
            tpl->fundef.name && strcmp(tpl->fundef.name, name) == 0) {
            return tpl;
        }
        if (tpl->type == AST_STRUCT && tpl->struct_stmt.is_exported &&
            tpl->struct_stmt.name && strcmp(tpl->struct_stmt.name, name) == 0) {
            return tpl;
        }
        if (tpl->type == AST_ENUM && tpl->enum_stmt.is_exported &&
            tpl->enum_stmt.name && strcmp(tpl->enum_stmt.name, name) == 0) {
            return tpl;
        }
    }
    return NULL;
}

void resolver_fill_dom_signature(const ASTNode *fundef_node, const char *call_name, DomSignature *out) {
    if (!fundef_node || fundef_node->type != AST_FUNDEF || !out) return;

    memset(out, 0, sizeof(*out));
    out->call_name = call_name ? strdup(call_name) : strdup(fundef_node->fundef.name ? fundef_node->fundef.name : "");
    out->param_count = fundef_node->fundef.param_count;

    if (out->param_count > 0) {
        out->param_names = malloc(sizeof(char *) * out->param_count);
        for (int i = 0; i < out->param_count; i++) {
            ASTNode *p = fundef_node->fundef.params[i];
            const char *pname = (p && p->type == AST_PARAM && p->param.name) ? p->param.name : "";
            out->param_names[i] = strdup(pname);
        }
    } else {
        out->param_names = NULL;
    }
}
