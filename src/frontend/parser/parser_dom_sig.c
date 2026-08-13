#include "mylang/frontend/parser_dom_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

#include <limits.h>

/* Resolves the function that backs a DOM element and reports its parameter
 * names, so DOM lowering can order properties by signature instead of by a
 * table of element names baked into the compiler.
 *
 * A tag resolves like an ordinary identifier: a function defined in this file
 * wins, otherwise every import is searched. Imported signatures are not known
 * to the parser (imports only register a package namespace), so the imported
 * source is lexed here the same way `import pkg from "..."` already lexes it to
 * read its package declaration.
 *
 * TODO: that token scan is a stand-in for symbol resolution the compiler does
 * not have. It reads parameter *names* only, so imported parameter types go
 * unchecked, and it takes a parameter's name to be the last identifier before
 * the comma -- which holds for `char *title` but not for declarators that end
 * in something else, such as a function-pointer parameter. Cross-package
 * lookup belongs in a shared resolution layer that DOM lowering, type checking
 * and imports can all use; until that exists this stays DOM-local.
 */

static void dom_resolve_path(const char *rel_path, char *out, size_t out_size) {
    const char *slash;
    char dir_buf[PATH_MAX];

    if (!rel_path || !out || out_size == 0) return;
    if (rel_path[0] == '/' || !g_parse_filename) {
        snprintf(out, out_size, "%s", rel_path);
        return;
    }
    snprintf(dir_buf, sizeof(dir_buf), "%s", g_parse_filename);
    slash = strrchr(dir_buf, '/');
    if (!slash) {
        snprintf(out, out_size, "%s", rel_path);
        return;
    }
    dir_buf[(size_t)(slash - dir_buf)] = '\0';
    snprintf(out, out_size, "%s/%s", dir_buf, rel_path);
}

static void free_scan_tokens(Token *tokens) {
    for (Token *t = tokens; t;) {
        Token *next = t->next;
        free(t->value);
        free(t);
        t = next;
    }
}

void dom_signature_free(DomSignature *sig) {
    if (!sig) return;
    for (int i = 0; i < sig->param_count; i++) free(sig->param_names[i]);
    free(sig->param_names);
    free(sig->call_name);
    sig->param_names = NULL;
    sig->param_count = 0;
    sig->call_name = NULL;
}

static void sig_push_param(DomSignature *sig, const char *name) {
    sig->param_names = realloc(sig->param_names, sizeof(char*) * (sig->param_count + 1));
    sig->param_names[sig->param_count++] = strdup(name ? name : "");
}

// Collects parameter names from a token run that starts just after '('. A
// parameter's name is its last identifier, so `char *title` yields "title".
static void collect_param_names_from_tokens(Token *after_lparen, DomSignature *sig) {
    const char *pending = NULL;
    int depth = 0;

    for (Token *p = after_lparen; p && p->kind != EOT; p = p->next) {
        if (p->kind == L_PARENTHESES) { depth++; continue; }
        if (p->kind == R_PARENTHESES) {
            if (depth == 0) {
                if (pending) sig_push_param(sig, pending);
                return;
            }
            depth--;
            continue;
        }
        if (depth == 0 && p->kind == COMMA) {
            sig_push_param(sig, pending ? pending : "");
            pending = NULL;
            continue;
        }
        if (p->kind == IDENTIFIER) pending = p->value;
    }
}

static int scan_source_for_signature(const char *path, const char *tag,
                                     int require_export, const char *pkg_prefix,
                                     DomSignature *out) {
    Token *tokens = lexer_from_file(path);
    if (!tokens) return 0;

    int found = 0;
    int exported = 0;

    for (Token *tok = tokens; tok && tok->kind != EOT; tok = tok->next) {
        if (tok->kind == EXPORT || tok->kind == EXTERN) {
            exported = 1;
            continue;
        }
        if (tok->kind == SEMICOLON || tok->kind == R_BRACE) {
            exported = 0;
            continue;
        }
        if (tok->kind != IDENTIFIER || !tok->next || tok->next->kind != L_PARENTHESES) continue;
        if (strcmp(tok->value, tag) != 0) {
            exported = 0;
            continue;
        }
        if (require_export && !exported) {
            exported = 0;
            continue;
        }

        memset(out, 0, sizeof(*out));
        collect_param_names_from_tokens(tok->next->next, out);
        if (pkg_prefix && pkg_prefix[0]) {
            char buf[256];
            snprintf(buf, sizeof(buf), "%s_%s", pkg_prefix, tag);
            out->call_name = strdup(buf);
        } else {
            out->call_name = strdup(tag);
        }
        found = 1;
        break;
    }

    free_scan_tokens(tokens);
    return found;
}

static int import_requests(ASTNode *import_node, const char *tag) {
    for (int i = 0; i < import_node->import_stmt.symbol_count; i++) {
        if (import_node->import_stmt.symbols[i] &&
            strcmp(import_node->import_stmt.symbols[i], tag) == 0) return 1;
    }
    return 0;
}

static int package_name_of(const char *path, char *out, size_t out_size) {
    Token *tokens = lexer_from_file(path);
    int found = 0;
    if (!tokens) return 0;
    // The declaration is not always the first token: a file may open with
    // imports or comments the lexer has already dropped.
    for (Token *t = tokens; t && t->kind != EOT; t = t->next) {
        if (t->kind == PACKAGE && t->next && t->next->kind == IDENTIFIER) {
            snprintf(out, out_size, "%s", t->next->value);
            found = 1;
            break;
        }
    }
    free_scan_tokens(tokens);
    return found;
}

int dom_signature_lookup(ASTNode *program, const char *tag, DomSignature *out) {
    if (!tag || !out) return 0;
    memset(out, 0, sizeof(*out));

    ASTNode *local = find_function(tag);
    if (local && local->type == AST_FUNDEF) {
        out->call_name = strdup(tag);
        for (int i = 0; i < local->fundef.param_count; i++) {
            ASTNode *p = local->fundef.params[i];
            sig_push_param(out, p && p->type == AST_PARAM ? p->param.name : "");
        }
        return 1;
    }

    if (!program || program->type != AST_BLOCK) return 0;

    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->type != AST_IMPORT || !node->import_stmt.path) continue;

        char path[PATH_MAX];
        dom_resolve_path(node->import_stmt.path, path, sizeof(path));
        size_t len = strlen(path);
        if (len < 4 || strcmp(path + len - 4, ".mln") != 0) continue;

        if (node->import_stmt.symbol_count == 0) {
            char pkg[256];
            if (!package_name_of(path, pkg, sizeof(pkg))) continue;
            if (scan_source_for_signature(path, tag, 1, pkg, out)) return 1;
        } else if (import_requests(node, tag)) {
            if (scan_source_for_signature(path, tag, 0, NULL, out)) return 1;
        }
    }

    return 0;
}
