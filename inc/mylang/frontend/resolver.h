#ifndef MYLANG_FRONTEND_RESOLVER_H
#define MYLANG_FRONTEND_RESOLVER_H

#include <stdbool.h>
#include <stddef.h>

#include "mylang/ast/AST.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/parser_dom_internal.h"

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
 * Fills a DomSignature struct from a parsed function definition ASTNode.
 * Allocates param_names and call_name in out (caller frees with dom_signature_free).
 */
void resolver_fill_dom_signature(const ASTNode *fundef_node, const char *call_name, DomSignature *out);

#endif /* MYLANG_FRONTEND_RESOLVER_H */
