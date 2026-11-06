#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/lexer.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/resolver.h"
#include "mylang/frontend/parser_trait_internal.h"
#include <limits.h>

/* Returns 1 if the .mln file at `rel_path` declares `package <pkg>;` at its top.
 * Used to let `import pkg from "path"` act as a package import (enabling
 * `pkg.func()` qualified calls) when the target file is that package's source. */
static int import_path_declares_package(ParserContext *context, const char *rel_path,
                                        const char *pkg) {
    if (!rel_path || !pkg || !module_loader_is_mylang_source(rel_path)) return 0;
    FrontendSession *session = context->session;
    if (!session || !session->loader) return 0;

    Module *mod = module_loader_load(session->loader, context->module.filename, rel_path);
    if (!mod || !mod->package_name) return 0;
    return strcmp(mod->package_name, pkg) == 0;
}

static int module_declares(const Module *module, const char *name) {
    for (int i = 0; i < module->symbol_count; i++)
        if (module->symbols[i].source_name && strcmp(module->symbols[i].source_name, name) == 0)
            return 1;
    for (int i = 0; i < module->trait_count; i++)
        if (strcmp(module->traits[i]->name, name) == 0) return 1;
    return 0;
}

/* `import X from "f.mln";` imports the package when f.mln declares
 * `package X;` and otherwise the symbol X. A name that is neither -- an
 * attempt to give the package another name -- would silently import nothing
 * and leave every `X.f()` unresolved, so it is rejected here. */
static void check_imported_names(ParserContext *context, Module *module, const char *path,
                                 char **symbols, int count, Token *at) {
    for (int i = 0; i < count; i++) {
        if (module_declares(module, symbols[i])) continue;
        char message[512];
        if (module->package_name && count == 1) {
            snprintf(message, sizeof(message),
                     "'%s' declares package '%s' and nothing named '%s'; a package is imported "
                     "by its own name: import %s from \"%s\";",
                     path, module->package_name, symbols[i], module->package_name, path);
        } else {
            snprintf(message, sizeof(message), "'%s' declares nothing named '%s'", path, symbols[i]);
        }
        parse_error(context, message, at);
    }
}

static ASTNode *make_import_node_with_templates(ParserContext *context, char *path,
                                                char **symbols, int count, Token *at) {
    ASTNode *node = new_import_stmt(path, symbols, count);
    if (!module_loader_is_mylang_source(path)) return node;

    if (!context->session || !context->session->loader) {
        parse_error(context, "missing frontend session while loading import", context->token_head);
    }
    Module *module = module_loader_load(context->session->loader,
                                        context->module.filename, path);
    if (!module || module->state == MODULE_FAILED) {
        parse_error(context, "failed to load imported MyLang module", context->token_head);
    }
    /* A module still loading is part of an import cycle; its symbols are not
     * collected yet. */
    if (module->state == MODULE_LOADED) check_imported_names(context, module, path, symbols, count, at);
    /* Traits first: they take their own names out of the import list, and
     * an `@alias/...` import marks every listed name foreign before the type
     * loaders below remove the names they handle. */
    load_imported_traits(context, node, path, module);
    load_imported_generic_templates(context, node, path);
    load_imported_plain_types(context, node, path);
    return node;
}

ASTNode *parse_import(ParserContext *context, Token **cur) {
    Token *import_tok = *cur;
    if (!expect(cur, IMPORT)) parse_error(context, "expected 'import'", *cur);

    if (token_is_name(*cur) && (*cur)->next && (*cur)->next->kind == SEMICOLON) {
        context->module.imported_packages = realloc(context->module.imported_packages, sizeof(char*) * (context->module.imported_package_count + 1));
        context->module.imported_packages[context->module.imported_package_count++] = strdup((*cur)->value);
        if (context->is_root_module) {
            frontend_session_add_root_imported_package(context->session, (*cur)->value);
        }
        *cur = (*cur)->next;
        expect(cur, SEMICOLON);
        return NULL;
    }

    if (token_is_name(*cur) && (*cur)->next && (*cur)->next->kind == FROM) {
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
            if (context->is_root_module) {
                frontend_session_add_root_imported_package(context->session, ident);
            }
            char **symbols = NULL;
            return make_import_node_with_templates(context, path, symbols, 0, import_tok);
        }

        char **symbols = malloc(sizeof(char *));
        symbols[0] = ident;
        return make_import_node_with_templates(context, path, symbols, 1, import_tok);
    }

    if (!expect(cur, L_BRACE)) parse_error(context, "expected '{'", *cur);

    char **symbols = NULL;
    int count = 0;

    if ((*cur)->kind != R_BRACE) {
        while (1) {
            if (!token_is_name(*cur)) parse_error(context, "expected identifier in import list", *cur);
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

    return make_import_node_with_templates(context, path, symbols, count, import_tok);
}

/* `@name`, `@name(arg, key = literal, ...)`. The parser only records
 * attributes; what each one means (and which are legal) is decided by the
 * lowering pass that consumes them, see parser_lower_app.c. */
Attribute *parse_attributes(ParserContext *context, Token **cur, int *out_count) {
    Attribute *attrs = NULL;
    int count = 0;
    while ((*cur)->kind == AT) {
        Token *at = *cur;
        *cur = (*cur)->next;
        if (!token_is_name(*cur)) parse_error(context, "expected attribute name after '@'", *cur);
        Attribute a = {0};
        a.name = strdup((*cur)->value);
        a.line = at->line;
        a.col = at->col;
        *cur = (*cur)->next;
        if ((*cur)->kind == L_PARENTHESES) {
            *cur = (*cur)->next;
            while ((*cur)->kind != R_PARENTHESES) {
                AttrArg arg = {0};
                arg.line = (*cur)->line;
                arg.col = (*cur)->col;
                if (token_is_name(*cur) && (*cur)->next && (*cur)->next->kind == ASSIGN) {
                    arg.name = strdup((*cur)->value);
                    *cur = (*cur)->next->next;
                    arg.value = parse_literal_value(context, cur);
                    if (!arg.value) parse_error(context, "expected a literal after '=' in attribute argument", *cur);
                } else if (token_is_name(*cur)) {
                    arg.value = new_identifier((*cur)->value);
                    set_node_loc_from_tokens(arg.value, *cur, NULL);
                    *cur = (*cur)->next;
                } else {
                    arg.value = parse_literal_value(context, cur);
                    if (!arg.value) parse_error(context, "expected an identifier or literal in attribute argument", *cur);
                }
                a.args = realloc(a.args, sizeof(AttrArg) * (a.arg_count + 1));
                a.args[a.arg_count++] = arg;
                if ((*cur)->kind == COMMA) {
                    *cur = (*cur)->next;
                    if ((*cur)->kind == R_PARENTHESES) parse_error(context, "trailing comma in attribute arguments", *cur);
                    continue;
                }
                if ((*cur)->kind != R_PARENTHESES) parse_error(context, "expected ',' or ')' in attribute arguments", *cur);
            }
            *cur = (*cur)->next;
        }
        attrs = realloc(attrs, sizeof(Attribute) * (count + 1));
        attrs[count++] = a;
    }
    *out_count = count;
    return attrs;
}

static ASTNode *parse_toplevel_decl(ParserContext *context, Token **cur);

ASTNode* parse_toplevel(ParserContext *context, Token **cur) {
    if ((*cur)->kind != AT) return parse_toplevel_decl(context, cur);

    int attr_count = 0;
    Token *first = *cur;
    Attribute *attrs = parse_attributes(context, cur, &attr_count);
    /* `@safe` and `@noreturn` belong to the language, not to an `annotation`
     * declaration: they never reach the metadata rows. `@safe`, unlike those
     * rows, may also precede a generic template or an impl. */
    int is_safe = 0;
    int is_noreturn = 0;
    for (int i = 0; i < attr_count;) {
        int is_safe_attr = strcmp(attrs[i].name, "safe") == 0;
        if (is_safe_attr || strcmp(attrs[i].name, "noreturn") == 0) {
            if (is_safe_attr) is_safe = 1;
            else is_noreturn = 1;
            memmove(&attrs[i], &attrs[i + 1], sizeof(Attribute) * (size_t)(attr_count - i - 1));
            attr_count--;
        } else {
            i++;
        }
    }
    int outer_safe = g_parsing_safe_decl;
    g_parsing_safe_decl = is_safe;
    ASTNode *decl = parse_toplevel_decl(context, cur);
    g_parsing_safe_decl = outer_safe;
    if (!decl) {
        /* Package/import lines and generic templates come back NULL; none of
         * them can carry an attribute today. */
        if (is_safe && !is_noreturn && attr_count == 0) return NULL;
        parse_error(context, "attributes may only precede a function or method declaration", first);
    }
    if (is_noreturn) {
        if (decl->type != AST_FUNDEF)
            parse_error(context, "@noreturn may only precede a function or method declaration", first);
        decl->fundef.is_noreturn = 1;
    }
    if ((is_safe || is_noreturn) && attr_count == 0) return decl;
    decl->attrs = attrs;
    decl->attr_count = attr_count;
    return decl;
}


static ASTNode *parse_toplevel_decl(ParserContext *context, Token **cur) {
    if ((*cur)->kind == PACKAGE) {
        *cur = (*cur)->next;
        if (!token_is_name(*cur)) parse_error(context, "expected package name", *cur);
        set_current_package(context, (*cur)->value);
        *cur = (*cur)->next;
        if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';' after package name", *cur);
        return NULL;
    }

    int want_export = 0;
    int want_extern = 0;
    if ((*cur)->kind == EXPORT) {
        want_export = 1;
        *cur = (*cur)->next;
    }
    if ((*cur)->kind == EXTERN) {
        want_extern = 1;
        *cur = (*cur)->next;
    }

    if ((*cur)->kind == IMPORT) return parse_import(context, cur);
    if ((*cur)->kind == TRAIT) return parse_trait(context, cur, want_export);
    if ((*cur)->kind == IMPL) return parse_impl(context, cur, want_export);
    if ((*cur)->kind == TYPEDEF) return parse_typedef(context, cur, want_export);
    if ((*cur)->kind == NEWTYPE) return parse_newtype(context, cur, want_export);
    if ((*cur)->kind == STRUCT) {
        ASTNode *declaration = parse_struct(context, cur);
        if (declaration && declaration->type == AST_STRUCT && declaration->struct_stmt.type_param_count > 0) {
            declaration->struct_stmt.is_exported = want_export;
            if (want_export) declaration->struct_stmt.package = strdup(context->module.current_package);
            add_generic_template(context, declaration);
            return NULL;
        }
        /* A plain (non-generic) struct never reaches the branch above, so
         * `export struct Foo {...};` was otherwise parsed same as an
         * unexported one -- new_struct() defaults is_exported to 0 and
         * nothing else here ever set it from `want_export`. This only ever
         * mattered for cross-file visibility (module_loader.c's
         * collect_module_symbols reads it), so a single-file compile never
         * showed the gap. */
        if (declaration && declaration->type == AST_STRUCT) {
            declaration->struct_stmt.is_exported = want_export;
            if (want_export) declaration->struct_stmt.package = strdup(context->module.current_package);
        }
        return declaration;
    }
    if ((*cur)->kind == ENUM) {
        ASTNode *declaration = parse_enum(context, cur);
        if (declaration && declaration->enum_stmt.type_param_count > 0) {
            declaration->enum_stmt.is_exported = want_export;
            if (want_export) declaration->enum_stmt.package = strdup(context->module.current_package);
            add_generic_template(context, declaration);
            return NULL;
        }
        /* Same gap as the plain-struct case above. Cross-file lookup of a
         * plain enum by name (collect_module_symbols) happens to hardcode
         * is_exported=1 regardless, so this only actually mattered once a
         * payload enum's *lowered struct* (parser_instantiate.c's
         * lower_payload_enum, which does read this flag) needed to cross a
         * file boundary. */
        if (declaration) {
            declaration->enum_stmt.is_exported = want_export;
            if (want_export) declaration->enum_stmt.package = strdup(context->module.current_package);
            /* instantiate_generics() (parser_instantiate.c) replaces a
             * payload enum's own AST_ENUM node with its lowered struct once
             * this file reaches that pass -- fine for this file's own
             * codegen, but it also erases the variant table (name -> tag,
             * has-payload) an *importer's* own lowering pass needs to
             * rewrite its own `Variant(x) -> ...` case arms and
             * constructions. Stash a clone now, before that happens, so
             * load_imported_plain_types() has the original to hand an
             * importer instead of the lowered struct. */
            if (want_export && declaration->enum_stmt.has_payloads) {
                add_exported_payload_enum(context, ast_clone(declaration));
            }
        }
        return declaration;
    }
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
    /* Test a method before requiring the leading token to be an already-known
     * type.  Receiver-bound generic methods can start with their own formal
     * parameter, e.g. `T (borrow Box<T> self) get()`. */
    if (looks_like_method(context, *cur)) {
        ASTNode *fn = parse_method(context, cur);
        /* Unlike a plain exported function, an exported method is not
         * mangled with the package prefix or added to the export table:
         * it is never called by a bare name (only ever `.method()`), and
         * its `Type__method` label is already unique per type. An importer
         * of the receiver type gets the method through
         * import_type_methods() (parser_import_generics.c), which is where
         * `is_exported` matters. */
        if (fn && want_export) {
            fn->fundef.is_exported = 1;
            fn->fundef.package = strdup(context->module.current_package);
        }
        return fn;
    }
    if (is_type(context, (*cur)->kind, *cur)) {
        if (looks_like_function(context, *cur)) {
            ASTNode *fn = parse_fundef(context, cur);
            if (fn && want_export) {
                fn->fundef.is_exported = 1;
                fn->fundef.package = strdup(context->module.current_package);
                char *m = mangle(context->module.current_package, fn->fundef.name);
                add_export(context, fn->fundef.name, m);
                free(fn->fundef.name);
                fn->fundef.name = strdup(m);
                free(m);
            }
            return fn;
        }
        ASTNode *vd = parse_variable_declaration(context, cur, 1);
        if (vd) vd->var_decl.is_extern = want_extern;
        if (vd && want_export) {
            vd->var_decl.is_exported = 1;
            vd->var_decl.package = strdup(context->module.current_package);
            char *m = mangle(context->module.current_package, vd->var_decl.name);
            add_export(context, vd->var_decl.name, m);
            free(vd->var_decl.name);
            vd->var_decl.name = strdup(m);
            free(m);
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
        Token *head = *cur;
        while (head->kind == AT && head->next && head->next->next) head = head->next->next;
        int is_impl = head->kind == IMPL ||
                      (head->kind == EXPORT && head->next && head->next->kind == IMPL);
        ASTNode *node = parse_toplevel(context, cur);
        if (!node) continue;
        if (is_impl) {
            /* An impl's items are ordinary top-level functions from here on. */
            nodes = realloc(nodes, sizeof(ASTNode*) * (count + node->block.count));
            for (int i = 0; i < node->block.count; i++) nodes[count++] = node->block.stmts[i];
            free(node->block.stmts);
            free(node);
            continue;
        }
        nodes = realloc(nodes, sizeof(ASTNode*) * (count + 1));
        nodes[count++] = node;
    }
    resolve_imported_impls(context);
    return new_block(nodes, count);
}
