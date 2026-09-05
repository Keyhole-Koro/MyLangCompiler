#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/lexer.h"
#include <limits.h>

/* Resolves an import path relative to the file currently being parsed so that
 * `import x from "libs/foo.mln"` finds foo.mln next to the importer. */
static void resolve_relative_to_source(const char *rel_path, char *out, size_t out_size) {
    const char *slash;
    char dir_buf[PATH_MAX];

    if (!rel_path || !out || out_size == 0) return;
    if (rel_path[0] == '/' || !parser_context_current()->module.filename) {
        snprintf(out, out_size, "%s", rel_path);
        return;
    }
    snprintf(dir_buf, sizeof(dir_buf), "%s", parser_context_current()->module.filename);
    slash = strrchr(dir_buf, '/');
    if (!slash) {
        snprintf(out, out_size, "%s", rel_path);
        return;
    }
    dir_buf[(size_t)(slash - dir_buf)] = '\0';
    snprintf(out, out_size, "%s/%s", dir_buf, rel_path);
}

/* Returns 1 if the .mln file at `rel_path` declares `package <pkg>;` at its top.
 * Used to let `import pkg from "path"` act as a package import (enabling
 * `pkg.func()` qualified calls) when the target file is that package's source. */
static int import_path_declares_package(const char *rel_path, const char *pkg) {
    char path[PATH_MAX];
    Token *tokens;
    int matched = 0;

    if (!rel_path || !pkg) return 0;
    if (strlen(rel_path) < 4 || strcmp(rel_path + strlen(rel_path) - 4, ".mln") != 0) return 0;

    resolve_relative_to_source(rel_path, path, sizeof(path));
    tokens = lexer_from_file(path);
    if (!tokens) return 0;

    for (Token *t = tokens; t && t->kind != EOT; t = t->next) {
        if (t->kind == PACKAGE && t->next && t->next->kind == IDENTIFIER) {
            matched = (strcmp(t->next->value, pkg) == 0);
            break;
        }
        /* package decl must come first; stop at the first non-package toplevel token */
        break;
    }

    for (Token *t = tokens; t;) {
        Token *next = t->next;
        free(t->value);
        free(t);
        t = next;
    }
    return matched;
}

/* True for an import target the MyLang parser can read. Generic templates are
 * recovered by parsing the imported file, so only .mln sources qualify: an
 * `import { hw_irq_enable } from "interrupt.masm"` names assembler symbols,
 * and handing that to parse_program fails on the first line. The same
 * extension check guards import_path_declares_package above. */
static int import_path_is_mylang(const char *rel_path) {
    size_t len;
    if (!rel_path) return 0;
    len = strlen(rel_path);
    return len >= 4 && strcmp(rel_path + len - 4, ".mln") == 0;
}

static ASTNode *make_import_node_with_templates(char *path, char **symbols, int count) {
    ASTNode *node = new_import_stmt(path, symbols, count);
    char resolved_path[PATH_MAX];
    if (!import_path_is_mylang(path)) return node;
    resolve_relative_to_source(path, resolved_path, sizeof(resolved_path));
    load_imported_generic_templates(node, resolved_path);
    return node;
}

ASTNode *parse_import(Token **cur) {
    if (!expect(cur, IMPORT)) parse_error("expected 'import'", *cur);

    if ((*cur)->kind == IDENTIFIER && (*cur)->next && (*cur)->next->kind == SEMICOLON) {
        parser_context_current()->module.imported_packages = realloc(parser_context_current()->module.imported_packages, sizeof(char*) * (parser_context_current()->module.imported_package_count + 1));
        parser_context_current()->module.imported_packages[parser_context_current()->module.imported_package_count++] = strdup((*cur)->value);
        *cur = (*cur)->next;
        expect(cur, SEMICOLON);
        return NULL;
    }

    if ((*cur)->kind == IDENTIFIER && (*cur)->next && (*cur)->next->kind == FROM) {
        char *ident = strdup((*cur)->value);
        *cur = (*cur)->next;

        if (!expect(cur, FROM)) parse_error("expected 'from'", *cur);
        if ((*cur)->kind != STRING_LITERAL) parse_error("expected file path string", *cur);
        char *path = (*cur)->value;
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON)) parse_error("expected ';'", *cur);

        /* If the target file declares `package <ident>;`, treat this as a
         * package import: register the namespace so `ident.func()` qualified
         * calls rewrite to `ident_func`, while still emitting an import node so
         * codegen scans the file for (variadic-aware) exported signatures. */
        if (import_path_declares_package(path, ident)) {
            parser_context_current()->module.imported_packages = realloc(parser_context_current()->module.imported_packages, sizeof(char*) * (parser_context_current()->module.imported_package_count + 1));
            parser_context_current()->module.imported_packages[parser_context_current()->module.imported_package_count++] = ident;
            char **symbols = NULL;
            return make_import_node_with_templates(path, symbols, 0);
        }

        char **symbols = malloc(sizeof(char *));
        symbols[0] = ident;
        return make_import_node_with_templates(path, symbols, 1);
    }

    if (!expect(cur, L_BRACE)) parse_error("expected '{'", *cur);

    char **symbols = NULL;
    int count = 0;

    if ((*cur)->kind != R_BRACE) {
        while (1) {
            if ((*cur)->kind != IDENTIFIER) parse_error("expected identifier in import list", *cur);
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

    if (!expect(cur, R_BRACE)) parse_error("expected '}'", *cur);
    if (!expect(cur, FROM)) parse_error("expected 'from'", *cur);

    if ((*cur)->kind != STRING_LITERAL) parse_error("expected file path string", *cur);
    char *path = (*cur)->value;
    *cur = (*cur)->next;

    if (!expect(cur, SEMICOLON)) parse_error("expected ';'", *cur);

    return make_import_node_with_templates(path, symbols, count);
}

ASTNode* parse_toplevel(Token **cur) {
    if ((*cur)->kind == PACKAGE) {
        *cur = (*cur)->next;
        if ((*cur)->kind != IDENTIFIER) parse_error("expected package name", *cur);
        set_current_package((*cur)->value);
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON)) parse_error("expected ';' after package name", *cur);
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

    if ((*cur)->kind == IMPORT) return parse_import(cur);
    if ((*cur)->kind == TYPEDEF) return parse_typedef(cur);
    if ((*cur)->kind == STRUCT) {
        ASTNode *declaration = parse_struct(cur);
        if (declaration && declaration->type == AST_STRUCT && declaration->struct_stmt.type_param_count > 0) {
            declaration->struct_stmt.is_exported = want_export;
            if (want_export) declaration->struct_stmt.package = strdup(parser_context_current()->module.current_package);
            add_generic_template(declaration);
            return NULL;
        }
        return declaration;
    }
    if ((*cur)->kind == ENUM) return parse_enum(cur);
    if (looks_like_generic_function(*cur)) {
        ASTNode *fn = parse_generic_fundef(cur);
        if (fn && fn->fundef.type_param_count > 0) {
            fn->fundef.is_exported = want_export;
            if (want_export) fn->fundef.package = strdup(parser_context_current()->module.current_package);
            add_generic_template(fn);
            return NULL;
        }
        parse_error("generic function must declare type parameters", *cur);
    }
    if (is_type((*cur)->kind, *cur)) {
        if (looks_like_function(*cur)) {
            ASTNode *fn = parse_fundef(cur);
            if (fn && want_export) {
                fn->fundef.is_exported = 1;
                fn->fundef.package = strdup(parser_context_current()->module.current_package);
                const char *m = mangle(parser_context_current()->module.current_package, fn->fundef.name);
                add_export(fn->fundef.name, m);
                free(fn->fundef.name);
                fn->fundef.name = strdup(m);
            }
            return fn;
        }
        ASTNode *vd = parse_variable_declaration(cur, 1);
        if (vd && want_export) {
            vd->var_decl.is_exported = 1;
            vd->var_decl.package = strdup(parser_context_current()->module.current_package);
            const char *m = mangle(parser_context_current()->module.current_package, vd->var_decl.name);
            add_export(vd->var_decl.name, m);
            free(vd->var_decl.name);
            vd->var_decl.name = strdup(m);
        }
        return vd;
    }

    parse_error("unexpected toplevel construct: only declarations and definitions are allowed", *cur);
    return NULL;
}

ASTNode *parse_program_syntax(Token **cur) {
    parser_context_current()->token_head = cur ? *cur : NULL;
    ASTNode **nodes = NULL;
    int count = 0;
    while ((*cur)->kind != EOT) {
        ASTNode *node = parse_toplevel(cur);
        if (!node) continue;
        nodes = realloc(nodes, sizeof(ASTNode*) * (count + 1));
        nodes[count++] = node;
    }
    return new_block(nodes, count);
}
