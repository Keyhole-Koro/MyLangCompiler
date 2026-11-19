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

/* Generic receiver methods are stored outside a module program just like
 * generic type/function templates.  Importing their receiver type transfers
 * a clone into the importer, where its concrete specializations are emitted. */
typedef struct ModuleGenericMethod {
    char *receiver_template_name;
    char *method_name;
    ASTNode *fundef;
} ModuleGenericMethod;

/*
 * Represents a parsed MyLang source module.
 *
 * Ownership:
 * - canonical_path: owned string (realpath of the source file)
 * - package_name: owned string (package identifier if declared, otherwise NULL)
 * - program: owned ASTNode (the AST_BLOCK from parse_program_syntax)
 * - generic_templates: owned array of ASTNodes (generic templates not stored in program block)
 * - generic_methods: owned receiver-method templates associated with generic
 *   types, likewise not stored in program block.
 * - exported_payload_enums: owned array of ASTNodes -- a clone of each
 *   exported payload enum's declaration, taken before instantiate_generics()
 *   lowers the one actually left in `program` into its backing struct (which
 *   erases the variant table an importer's own lowering pass needs; see
 *   load_imported_plain_types() in parser_import_generics.c).
 * - traits: owned TraitDefs this module declares (exported or not; an
 *   importer only takes exported ones).
 * - impls: owned ImplDefs of this module's exported impls. Their items are
 *   ordinary exported fundefs in `program`.
 * - symbols: owned array of ModuleSymbol structs
 * - All owned memory is freed when the enclosing ModuleGraph is destroyed.
 */
typedef struct Module {
    char *canonical_path;
    char *package_name;
    /* The file's source profile is `.unsafe.mln`: an importer checks the
     * generic code it copies from this module under that profile. */
    int is_unsafe;
    ASTNode *program;
    ASTNode **generic_templates;
    int generic_template_count;
    ModuleGenericMethod *generic_methods;
    int generic_method_count;
    ASTNode **exported_payload_enums;
    int exported_payload_enum_count;
    struct TraitDef **traits;
    int trait_count;
    struct ImplDef **impls;
    int impl_count;
    ModuleSymbol *symbols;
    int symbol_count;
    int symbol_capacity;
    ModuleLoadState state;
    /* Kept by module_cache.c for the units after this one; a ModuleGraph that
     * holds it does not own it. */
    int cached;
} Module;

/*
 * Cache of parsed modules indexed by canonical path.
 *
 * Ownership:
 * - modules: owned array of Module pointers.
 * - ModuleGraph owns all Module instances and their syntax ASTs, except a
 *   module the module cache keeps (Module.cached).
 */
typedef struct ModuleGraph {
    Module **modules;
    int module_count;
    int module_capacity;
} ModuleGraph;

typedef struct FrontendSession FrontendSession;

typedef struct ModuleAlias {
    char *name;
    char *target;
} ModuleAlias;

/* What an import path came to on disk, so that the next import of it need not
 * ask the disk. `raw` has the importer's directory and any alias applied. */
typedef struct ResolvedPath {
    char *raw;
    char *canonical;
    struct ResolvedPath *next;
} ResolvedPath;

#define RESOLVED_PATH_BUCKETS 256

/*
 * Loader responsible for resolving relative import paths, canonicalizing them,
 * and caching parsed Module representations.
 */
typedef struct ModuleLoader {
    ModuleGraph *graph;
    ResolvedPath *resolved_paths[RESOLVED_PATH_BUCKETS];
    /* Borrowed. Every parser context created by this loader inherits it. */
    FrontendSession *session;
    ModuleAlias *aliases;
    int alias_count;
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

/* Whether a lookup across the graph may see what module publishes. A module
 * still loading has published nothing yet -- its symbols and payload enums
 * are filled in as its load ends -- unless the module cache is replaying a
 * kept one, which holds them already and must keep them out of sight until
 * that point all the same. */
static inline int module_is_published(const Module *module) {
    return module && module->state != MODULE_LOADING;
}

/* ModuleGraph lifecycle */
ModuleGraph *module_graph_create(void);
void module_graph_destroy(ModuleGraph *graph);
Module *module_graph_find(ModuleGraph *graph, const char *canonical_path);
Module *module_graph_add(ModuleGraph *graph, const char *canonical_path);
/* Appends a module the graph does not own (Module.cached). */
int module_graph_add_existing(ModuleGraph *graph, Module *module);

/* ModuleSymbol queries */
ModuleSymbol *module_find_exported_symbol(const Module *module, const char *source_name);
void module_add_symbol(Module *module, SymbolKind kind, const char *source_name,
                       const char *link_name, ASTNode *declaration, int is_exported);

/* ModuleLoader operations */
ModuleLoader *module_loader_create(ModuleGraph *graph, FrontendSession *session);
void module_loader_destroy(ModuleLoader *loader);
int module_loader_is_mylang_source(const char *path);
int module_loader_resolve_import_path(ModuleLoader *loader,
                                      const char *importer_path,
                                      const char *import_path,
                                      char *out_canonical,
                                      size_t out_size);
int module_loader_add_alias(ModuleLoader *loader, const char *name, const char *target);
Module *module_loader_load(ModuleLoader *loader, const char *importer_path, const char *rel_path);
Module *module_loader_load_canonical(ModuleLoader *loader, const char *canonical);

/* Module cache (module_cache.c): a process that compiles several units keeps
 * the modules one unit loads for the next. Off unless enabled. */
typedef enum ModuleLookupKind {
    /* The module one of whose symbols has this link name (import_private_name). */
    MODULE_LOOKUP_LINK_NAME,
    /* The module exporting a payload enum of this name (preserved_payload_enum). */
    MODULE_LOOKUP_PAYLOAD_ENUM,
} ModuleLookupKind;

void module_cache_enable(void);
/* Whether a kept module could not be given to the unit just compiled, which
 * then has to be compiled again by a fresh process. Clears it. */
int module_cache_take_conflict(void);
/* The kept module for canonical, entered into the loader's graph, or NULL. */
Module *module_cache_load(ModuleLoader *loader, const char *canonical);
/* What the loader and the parser tell the cache about the load in progress. */
void module_cache_begin_load(void);
void module_cache_end_load(ModuleLoader *loader, Module *module);
void module_cache_note_load(const char *canonical, Module *existing);
void module_cache_note_loaded(const char *canonical, Module *module);
void module_cache_note_lookup(ModuleLookupKind lookup, const char *key, Module *found);
void module_cache_note_unrecorded_lookup(void);

/* FrontendSession lifecycle */
FrontendSession *frontend_session_create(void);
void frontend_session_destroy(FrontendSession *session);
FrontendSession *frontend_session_current(void);
void frontend_session_set_current(FrontendSession *session);
/* Releases only a compatibility session created by frontend_session_current(). */
void frontend_session_destroy_implicit_current(void);
void frontend_session_add_root_imported_package(FrontendSession *session, const char *name);
int frontend_session_add_alias(FrontendSession *session, const char *name, const char *target);

#endif /* MYLANG_FRONTEND_MODULE_H */
