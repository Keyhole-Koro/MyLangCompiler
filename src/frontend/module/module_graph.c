#include "mylang/frontend/module.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void module_destroy(Module *module) {
    if (!module) return;

    if (module->canonical_path) {
        free(module->canonical_path);
        module->canonical_path = NULL;
    }
    if (module->package_name) {
        free(module->package_name);
        module->package_name = NULL;
    }
    if (module->program) {
        free_ast(module->program);
        module->program = NULL;
    }
    if (module->generic_templates) {
        for (int i = 0; i < module->generic_template_count; i++) {
            if (module->generic_templates[i]) {
                free_ast(module->generic_templates[i]);
            }
        }
        free(module->generic_templates);
        module->generic_templates = NULL;
        module->generic_template_count = 0;
    }
    if (module->symbols) {
        for (int i = 0; i < module->symbol_count; i++) {
            free(module->symbols[i].source_name);
            free(module->symbols[i].link_name);
        }
        free(module->symbols);
        module->symbols = NULL;
        module->symbol_count = 0;
        module->symbol_capacity = 0;
    }
    free(module);
}

ModuleGraph *module_graph_create(void) {
    ModuleGraph *graph = calloc(1, sizeof(ModuleGraph));
    return graph;
}

void module_graph_destroy(ModuleGraph *graph) {
    if (!graph) return;
    if (graph->modules) {
        for (int i = 0; i < graph->module_count; i++) {
            module_destroy(graph->modules[i]);
        }
        free(graph->modules);
        graph->modules = NULL;
    }
    graph->module_count = 0;
    graph->module_capacity = 0;
    free(graph);
}

Module *module_graph_find(ModuleGraph *graph, const char *canonical_path) {
    if (!graph || !canonical_path) return NULL;
    for (int i = 0; i < graph->module_count; i++) {
        Module *m = graph->modules[i];
        if (m && m->canonical_path && strcmp(m->canonical_path, canonical_path) == 0) {
            return m;
        }
    }
    return NULL;
}

Module *module_graph_add(ModuleGraph *graph, const char *canonical_path) {
    if (!graph || !canonical_path) return NULL;

    Module *existing = module_graph_find(graph, canonical_path);
    if (existing) return existing;

    if (graph->module_count >= graph->module_capacity) {
        int new_cap = graph->module_capacity == 0 ? 8 : graph->module_capacity * 2;
        Module **new_modules = realloc(graph->modules, sizeof(Module *) * new_cap);
        if (!new_modules) return NULL;
        graph->modules = new_modules;
        graph->module_capacity = new_cap;
    }

    Module *mod = calloc(1, sizeof(Module));
    if (!mod) return NULL;
    mod->canonical_path = strdup(canonical_path);
    mod->state = MODULE_LOADING;

    graph->modules[graph->module_count++] = mod;
    return mod;
}

void module_add_symbol(Module *module, SymbolKind kind, const char *source_name,
                       const char *link_name, ASTNode *declaration, int is_exported) {
    if (!module || !source_name) return;

    if (module->symbol_count >= module->symbol_capacity) {
        int new_cap = module->symbol_capacity == 0 ? 16 : module->symbol_capacity * 2;
        ModuleSymbol *new_syms = realloc(module->symbols, sizeof(ModuleSymbol) * new_cap);
        if (!new_syms) return;
        module->symbols = new_syms;
        module->symbol_capacity = new_cap;
    }

    ModuleSymbol *sym = &module->symbols[module->symbol_count++];
    sym->kind = kind;
    sym->source_name = strdup(source_name);
    sym->link_name = link_name ? strdup(link_name) : strdup(source_name);
    sym->declaration = declaration;
    sym->is_exported = is_exported;
}

ModuleSymbol *module_find_symbol(const Module *module, const char *source_name) {
    if (!module || !source_name) return NULL;
    for (int i = 0; i < module->symbol_count; i++) {
        if (strcmp(module->symbols[i].source_name, source_name) == 0) {
            return &module->symbols[i];
        }
    }
    return NULL;
}

ModuleSymbol *module_find_exported_symbol(const Module *module, const char *source_name) {
    if (!module || !source_name) return NULL;
    for (int i = 0; i < module->symbol_count; i++) {
        if (module->symbols[i].is_exported &&
            strcmp(module->symbols[i].source_name, source_name) == 0) {
            return &module->symbols[i];
        }
    }
    return NULL;
}
