#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

ASTNode *parse_import(Token **cur) {
    if (!expect(cur, IMPORT)) parse_error("expected 'import'", token_head, *cur);

    if ((*cur)->kind == IDENTIFIER && (*cur)->next && (*cur)->next->kind == SEMICOLON) {
        g_imported_packages = realloc(g_imported_packages, sizeof(char*) * (g_imported_pkg_count + 1));
        g_imported_packages[g_imported_pkg_count++] = strdup((*cur)->value);
        *cur = (*cur)->next;
        expect(cur, SEMICOLON);
        return NULL;
    }

    if ((*cur)->kind == IDENTIFIER && (*cur)->next && (*cur)->next->kind == FROM) {
        char **symbols = malloc(sizeof(char *));
        int count = 1;
        symbols[0] = strdup((*cur)->value);
        *cur = (*cur)->next;

        if (!expect(cur, FROM)) parse_error("expected 'from'", token_head, *cur);
        if ((*cur)->kind != STRING_LITERAL) parse_error("expected file path string", token_head, *cur);
        char *path = (*cur)->value;
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON)) parse_error("expected ';'", token_head, *cur);
        return new_import_stmt(path, symbols, count);
    }

    if (!expect(cur, L_BRACE)) parse_error("expected '{'", token_head, *cur);

    char **symbols = NULL;
    int count = 0;

    if ((*cur)->kind != R_BRACE) {
        while (1) {
            if ((*cur)->kind != IDENTIFIER) parse_error("expected identifier in import list", token_head, *cur);
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

    if (!expect(cur, R_BRACE)) parse_error("expected '}'", token_head, *cur);
    if (!expect(cur, FROM)) parse_error("expected 'from'", token_head, *cur);

    if ((*cur)->kind != STRING_LITERAL) parse_error("expected file path string", token_head, *cur);
    char *path = (*cur)->value;
    *cur = (*cur)->next;

    if (!expect(cur, SEMICOLON)) parse_error("expected ';'", token_head, *cur);

    return new_import_stmt(path, symbols, count);
}

ASTNode* parse_toplevel(Token **cur) {
    if ((*cur)->kind == PACKAGE) {
        *cur = (*cur)->next;
        if ((*cur)->kind != IDENTIFIER) parse_error("expected package name", token_head, *cur);
        set_current_package((*cur)->value);
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON)) parse_error("expected ';' after package name", token_head, *cur);
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
    if ((*cur)->kind == STRUCT) return parse_struct(cur);
    if ((*cur)->kind == ENUM) return parse_enum(cur);
    if (is_type((*cur)->kind, *cur)) {
        if (looks_like_function(*cur)) {
            ASTNode *fn = parse_fundef(cur);
            if (fn && want_export) {
                fn->fundef.is_exported = 1;
                fn->fundef.package = strdup(g_current_package);
                const char *m = mangle(g_current_package, fn->fundef.name);
                add_export(fn->fundef.name, m);
                free(fn->fundef.name);
                fn->fundef.name = strdup(m);
            }
            return fn;
        }
        ASTNode *vd = parse_variable_declaration(cur, 1);
        if (vd && want_export) {
            vd->var_decl.is_exported = 1;
            vd->var_decl.package = strdup(g_current_package);
            const char *m = mangle(g_current_package, vd->var_decl.name);
            add_export(vd->var_decl.name, m);
            free(vd->var_decl.name);
            vd->var_decl.name = strdup(m);
        }
        return vd;
    }

    parse_error("unexpected toplevel construct: only declarations and definitions are allowed", token_head, *cur);
    return NULL;
}

ASTNode* parse_program(Token **cur) {
    ASTNode **nodes = NULL;
    int count = 0;
    while ((*cur)->kind != EOT) {
        ASTNode *node = parse_toplevel(cur);
        if (!node) continue;
        nodes = realloc(nodes, sizeof(ASTNode*) * (count + 1));
        nodes[count++] = node;
    }
    ASTNode *prog = new_block(nodes, count);
    lower_fun_literals_block(prog, "g", NULL, 0);
    if (g_hoisted_count > 0) {
        prog->block.stmts = realloc(prog->block.stmts, sizeof(ASTNode*) * (prog->block.count + g_hoisted_count));
        for (int i = 0; i < g_hoisted_count; i++) {
            prog->block.stmts[prog->block.count + i] = g_hoisted_funcs[i];
        }
        prog->block.count += g_hoisted_count;
        g_hoisted_count = 0;
        free(g_hoisted_funcs);
        g_hoisted_funcs = NULL;
    }
    ensure_no_fun_literals(prog);
    char *scope_buf[128] = {0};
    rewrite_node(prog, scope_buf, 0);
    return prog;
}
