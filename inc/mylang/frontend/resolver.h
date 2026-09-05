#ifndef MYLANG_FRONTEND_RESOLVER_H
#define MYLANG_FRONTEND_RESOLVER_H

#include <stdbool.h>
#include <stddef.h>

#include "mylang/ast/AST.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/parser_dom_internal.h"

/*
 * Detailed function information extracted from a ModuleSymbol or AST_FUNDEF.
 * Strings and AST pointers are borrowed; call resolver_free_function_info
 * to free the allocated parameter array.
 */
typedef struct ResolverParamInfo {
    const char *name;      /* borrowed */
    ASTNode *type_ast;     /* borrowed */
    int is_mut;
    int is_rest;
} ResolverParamInfo;

typedef struct ResolverFunctionInfo {
    const char *source_name;  /* borrowed */
    const char *link_name;    /* borrowed */
    ASTNode *ret_type_ast;    /* borrowed */
    ResolverParamInfo *params; /* allocated array */
    int param_count;
    int fixed_param_count;
    bool is_variadic;
    bool is_exported;
    const char *package_name; /* borrowed */
} ResolverFunctionInfo;

/* Extract function signature metadata (parameter names, types, variadic flag). */
int resolver_get_function_info(const ModuleSymbol *sym, ResolverFunctionInfo *out_info);
void resolver_free_function_info(ResolverFunctionInfo *info);

/*
 * Inspects an import node against a loaded target module.
 * Returns the package name if this import functions as a package import
 * (i.e. target module declares `package <name>;`), or NULL if it is a symbol import.
 */
const char *resolver_import_package_name(const ASTNode *import_node, const Module *target_module);

/*
 * Resolves whether `symbol_name` is visible through the given `import_node`.
 * If visible and exported by `target_module`, returns the ModuleSymbol.
 * Returns NULL if not visible or not exported.
 */
ModuleSymbol *resolver_lookup_import_symbol(const ASTNode *import_node, const Module *target_module,
                                            const char *symbol_name);

/*
 * Finds an exported generic template (function or struct) in `module` by name.
 * Returns borrowed ASTNode pointer, or NULL if not found or not exported.
 */
ASTNode *resolver_find_exported_generic_template(const Module *module, const char *name);

/*
 * Fills a DomSignature struct from a parsed function definition ASTNode.
 * Allocates param_names and call_name in out (caller frees with dom_signature_free).
 */
void resolver_fill_dom_signature(const ASTNode *fundef_node, const char *call_name, DomSignature *out);

#endif /* MYLANG_FRONTEND_RESOLVER_H */
