#include "mylang/frontend/parser_dom_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/resolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void dom_signature_free(DomSignature *sig) {
    if (!sig) return;
    for (int i = 0; i < sig->param_count; i++) free(sig->param_names[i]);
    free(sig->param_names);
    free(sig->call_name);
    sig->param_names = NULL;
    sig->param_count = 0;
    sig->call_name = NULL;
}

int dom_signature_lookup(ParserContext *context, ASTNode *program,
                         const char *tag, DomSignature *out) {
    if (!tag || !out) return 0;
    memset(out, 0, sizeof(*out));

    /* 1. Local function in the current file wins */
    ASTNode *local = find_function(context, tag);
    if (local && local->type == AST_FUNDEF) {
        resolver_fill_dom_signature(local, tag, out);
        return 1;
    }

    if (!program || program->type != AST_BLOCK) return 0;

    /* 2. Check imported modules via module loader and resolver */
    FrontendSession *session = frontend_session_current();
    if (!session || !session->loader) return 0;

    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->type != AST_IMPORT || !node->import_stmt.path) continue;
        if (!module_loader_is_mylang_source(node->import_stmt.path)) continue;

        Module *mod = module_loader_load(session->loader, context->module.filename,
                                         node->import_stmt.path);
        if (!mod || mod->state != MODULE_LOADED) continue;

        ModuleSymbol *sym = resolver_lookup_import_symbol(node, mod, tag);
        if (!sym || sym->kind != SYMBOL_FUNCTION || !sym->declaration) continue;

        if (node->import_stmt.symbol_count == 0 && mod->package_name) {
            char call_name[256];
            snprintf(call_name, sizeof(call_name), "%s_%s", mod->package_name, tag);
            resolver_fill_dom_signature(sym->declaration, call_name, out);
        } else {
            resolver_fill_dom_signature(sym->declaration, tag, out);
        }
        return 1;
    }

    return 0;
}
