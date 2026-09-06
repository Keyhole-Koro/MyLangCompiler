#ifndef MYLANG_FRONTEND_MODULE_H
#define MYLANG_FRONTEND_MODULE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "mylang/ast/AST.h"
#include "mylang/frontend/lexer.h"
#include "mylang/frontend/parser.h"

/*
 * Module load state used for cycle detection and cache tracking.
 */
typedef enum ModuleLoadState {
    MODULE_LOADING,
    MODULE_LOADED,
    MODULE_FAILED,
} ModuleLoadState;

/*
 * Kinds of top-level declarations tracked in a Module.
 */
typedef enum SymbolKind {
    SYMBOL_FUNCTION,
    SYMBOL_STRUCT,
    SYMBOL_TYPEDEF,
    SYMBOL_ENUM,
    SYMBOL_GLOBAL,
    SYMBOL_GENERIC_FUNCTION,
    SYMBOL_GENERIC_STRUCT,
    SYMBOL_GENERIC_ENUM,
} SymbolKind;

/*
 * A single top-level symbol declared or exported by a Module.
 *
 * Ownership:
 * - source_name: owned string (freed on Module destroy)
 * - link_name: owned string (freed on Module destroy)
 * - declaration: borrowed pointer into Module->program or Module->generic_templates.
 *   DO NOT free declaration individually.
 */
typedef struct ModuleSymbol {
    SymbolKind kind;
    char *source_name;
    char *link_name;
    ASTNode *declaration;
    int is_exported;
} ModuleSymbol;

/*
 * Represents a parsed MyLang source module.
 *
 * Ownership:
 * - canonical_path: owned string (realpath of the source file)
 * - package_name: owned string (package identifier if declared, otherwise NULL)
 * - program: owned ASTNode (the AST_BLOCK from parse_program_syntax)
 * - generic_templates: owned array of ASTNodes (generic templates not stored in program block)
 * - exported_payload_enums: owned array of ASTNodes -- a clone of each
 *   exported payload enum's declaration, taken before instantiate_generics()
 *   lowers the one actually left in `program` into its backing struct (which
 *   erases the variant table an importer's own lowering pass needs; see
 *   load_imported_plain_types() in parser_import_generics.c).
 * - symbols: owned array of ModuleSymbol structs
 * - All owned memory is freed when the enclosing ModuleGraph is destroyed.
 */
typedef struct Module {
    char *canonical_path;
    char *package_name;
    ASTNode *program;
    ASTNode **generic_templates;
    int generic_template_count;
    ASTNode **exported_payload_enums;
    int exported_payload_enum_count;
    ModuleSymbol *symbols;
    int symbol_count;
    int symbol_capacity;
    ModuleLoadState state;
} Module;

/*
 * Cache of parsed modules indexed by canonical path.
 *
 * Ownership:
 * - modules: owned array of Module pointers.
 * - ModuleGraph owns all Module instances and their syntax ASTs.
 */
typedef struct ModuleGraph {
    Module **modules;
    int module_count;
    int module_capacity;
} ModuleGraph;

typedef struct FrontendSession FrontendSession;

/*
 * Loader responsible for resolving relative import paths, canonicalizing them,
 * and caching parsed Module representations.
 */
typedef struct ModuleLoader {
    ModuleGraph *graph;
    /* Borrowed. Every parser context created by this loader inherits it. */
    FrontendSession *session;
} ModuleLoader;

/*
 * FrontendSession encapsulates a single compilation unit or driver invocation.
 * It owns the ModuleGraph, ModuleLoader, and manages the root parser context.
 */
struct FrontendSession {
    ModuleGraph *graph;
    ModuleLoader *loader;
    /* Owned package namespaces imported by the root translation unit. */
    char **root_imported_packages;
    int root_imported_package_count;
    int is_implicit;
};

/* ModuleGraph lifecycle */
ModuleGraph *module_graph_create(void);
void module_graph_destroy(ModuleGraph *graph);
Module *module_graph_find(ModuleGraph *graph, const char *canonical_path);
Module *module_graph_add(ModuleGraph *graph, const char *canonical_path);

/* ModuleSymbol queries */
ModuleSymbol *module_find_symbol(const Module *module, const char *source_name);
ModuleSymbol *module_find_exported_symbol(const Module *module, const char *source_name);
void module_add_symbol(Module *module, SymbolKind kind, const char *source_name,
                       const char *link_name, ASTNode *declaration, int is_exported);

/* ModuleLoader operations */
ModuleLoader *module_loader_create(ModuleGraph *graph, FrontendSession *session);
void module_loader_destroy(ModuleLoader *loader);
int module_loader_is_mylang_source(const char *path);
int module_loader_resolve_path(const char *importer_path, const char *rel_path,
                               char *out_canonical, size_t out_size);
Module *module_loader_load(ModuleLoader *loader, const char *importer_path, const char *rel_path);

/* FrontendSession lifecycle */
FrontendSession *frontend_session_create(void);
void frontend_session_destroy(FrontendSession *session);
FrontendSession *frontend_session_current(void);
void frontend_session_set_current(FrontendSession *session);
/* Releases only a compatibility session created by frontend_session_current(). */
void frontend_session_destroy_implicit_current(void);
void frontend_session_add_root_imported_package(FrontendSession *session, const char *name);

#endif /* MYLANG_FRONTEND_MODULE_H */
