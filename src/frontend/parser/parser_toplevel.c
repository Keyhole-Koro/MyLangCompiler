#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/lexer.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/resolver.h"
#include <limits.h>

/* Returns 1 if the .mln file at `rel_path` declares `package <pkg>;` at its top.
 * Used to let `import pkg from "path"` act as a package import (enabling
 * `pkg.func()` qualified calls) when the target file is that package's source. */
static int import_path_declares_package(ParserContext *context, const char *rel_path,
                                        const char *pkg) {
    if (!rel_path || !pkg || !module_loader_is_mylang_source(rel_path)) return 0;
    FrontendSession *session = frontend_session_current();
    if (!session || !session->loader) return 0;

    Module *mod = module_loader_load(session->loader, context->module.filename, rel_path);
    if (!mod || !mod->package_name) return 0;
    return strcmp(mod->package_name, pkg) == 0;
}

static ASTNode *make_import_node_with_templates(ParserContext *context, char *path,
                                                char **symbols, int count) {
    ASTNode *node = new_import_stmt(path, symbols, count);
    if (!module_loader_is_mylang_source(path)) return node;
    load_imported_generic_templates(context, node, path);
    return node;
}

ASTNode *parse_import(ParserContext *context, Token **cur) {
    if (!expect(cur, IMPORT)) parse_error(context, "expected 'import'", *cur);

    if ((*cur)->kind == IDENTIFIER && (*cur)->next && (*cur)->next->kind == SEMICOLON) {
        context->module.imported_packages = realloc(context->module.imported_packages, sizeof(char*) * (context->module.imported_package_count + 1));
        context->module.imported_packages[context->module.imported_package_count++] = strdup((*cur)->value);
        *cur = (*cur)->next;
        expect(cur, SEMICOLON);
        return NULL;
    }

    if ((*cur)->kind == IDENTIFIER && (*cur)->next && (*cur)->next->kind == FROM) {
        char *ident = strdup((*cur)->value);
        *cur = (*cur)->next;

        if (!expect(cur, FROM)) parse_error(context, "expected 'from'", *cur);
        if ((*cur)->kind != STRING_LITERAL) parse_error(context, "expected file path string", *cur);
        char *path = (*cur)->value;
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';'", *cur);

        /* If the target file declares `package <ident>;`, treat this as a
         * package import: register the namespace so `ident.func()` qualified
         * calls rewrite to `ident_func`, while still emitting an import node so
         * codegen scans the file for (variadic-aware) exported signatures. */
        if (import_path_declares_package(context, path, ident)) {
            context->module.imported_packages = realloc(context->module.imported_packages, sizeof(char*) * (context->module.imported_package_count + 1));
            context->module.imported_packages[context->module.imported_package_count++] = ident;
            char **symbols = NULL;
            return make_import_node_with_templates(context, path, symbols, 0);
        }

        char **symbols = malloc(sizeof(char *));
        symbols[0] = ident;
        return make_import_node_with_templates(context, path, symbols, 1);
    }

    if (!expect(cur, L_BRACE)) parse_error(context, "expected '{'", *cur);

    char **symbols = NULL;
    int count = 0;

    if ((*cur)->kind != R_BRACE) {
        while (1) {
            if ((*cur)->kind != IDENTIFIER) parse_error(context, "expected identifier in import list", *cur);
            symbols = realloc(symbols, sizeof(char*) * (count + 1));
            symbols[count++] = strdup((*cur)->value);
            *cur = (*cur)->next;
            if ((*cur)->kind == COMMA) {
                *cur = (*cur)->next;
                continue;
            }
            break;
        }
    }

    if (!expect(cur, R_BRACE)) parse_error(context, "expected '}'", *cur);
    if (!expect(cur, FROM)) parse_error(context, "expected 'from'", *cur);

    if ((*cur)->kind != STRING_LITERAL) parse_error(context, "expected file path string", *cur);
    char *path = (*cur)->value;
    *cur = (*cur)->next;

    if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';'", *cur);

    return make_import_node_with_templates(context, path, symbols, count);
}

ASTNode* parse_toplevel(ParserContext *context, Token **cur) {
    if ((*cur)->kind == PACKAGE) {
        *cur = (*cur)->next;
        if ((*cur)->kind != IDENTIFIER) parse_error(context, "expected package name", *cur);
        set_current_package(context, (*cur)->value);
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';' after package name", *cur);
        return NULL;
    }

    int want_export = 0;
    if ((*cur)->kind == EXPORT) {
        want_export = 1;
        *cur = (*cur)->next;
    }
    if ((*cur)->kind == EXTERN) {
        *cur = (*cur)->next;
    }

    if ((*cur)->kind == IMPORT) return parse_import(context, cur);
    if ((*cur)->kind == TYPEDEF) return parse_typedef(context, cur);
    if ((*cur)->kind == STRUCT) {
        ASTNode *declaration = parse_struct(context, cur);
        if (declaration && declaration->type == AST_STRUCT && declaration->struct_stmt.type_param_count > 0) {
            declaration->struct_stmt.is_exported = want_export;
            if (want_export) declaration->struct_stmt.package = strdup(context->module.current_package);
            add_generic_template(context, declaration);
            return NULL;
        }
        return declaration;
    }
    if ((*cur)->kind == ENUM) return parse_enum(context, cur);
    if (looks_like_generic_function(context, *cur)) {
        ASTNode *fn = parse_generic_fundef(context, cur);
        if (fn && fn->fundef.type_param_count > 0) {
            fn->fundef.is_exported = want_export;
            if (want_export) fn->fundef.package = strdup(context->module.current_package);
            add_generic_template(context, fn);
            return NULL;
        }
        parse_error(context, "generic function must declare type parameters", *cur);
    }
    if (is_type(context, (*cur)->kind, *cur)) {
        if (looks_like_function(context, *cur)) {
            ASTNode *fn = parse_fundef(context, cur);
            if (fn && want_export) {
                fn->fundef.is_exported = 1;
                fn->fundef.package = strdup(context->module.current_package);
                const char *m = mangle(context->module.current_package, fn->fundef.name);
                add_export(context, fn->fundef.name, m);
                free(fn->fundef.name);
                fn->fundef.name = strdup(m);
            }
            return fn;
        }
        ASTNode *vd = parse_variable_declaration(context, cur, 1);
        if (vd && want_export) {
            vd->var_decl.is_exported = 1;
            vd->var_decl.package = strdup(context->module.current_package);
            const char *m = mangle(context->module.current_package, vd->var_decl.name);
            add_export(context, vd->var_decl.name, m);
            free(vd->var_decl.name);
            vd->var_decl.name = strdup(m);
        }
        return vd;
    }

    parse_error(context, "unexpected toplevel construct: only declarations and definitions are allowed", *cur);
    return NULL;
}

ASTNode *parse_program_syntax(ParserContext *context, Token **cur) {
    context->token_head = cur ? *cur : NULL;
    ASTNode **nodes = NULL;
    int count = 0;
    while ((*cur)->kind != EOT) {
        ASTNode *node = parse_toplevel(context, cur);
        if (!node) continue;
        nodes = realloc(nodes, sizeof(ASTNode*) * (count + 1));
        nodes[count++] = node;
    }
    return new_block(nodes, count);
}
