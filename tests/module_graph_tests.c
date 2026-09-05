#include "mylang/frontend/module.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_module_caching(void) {
    FrontendSession *session = frontend_session_create();
    assert(session != NULL);

    Module *m1 = module_loader_load(session->loader, NULL, "tests/succeed/package/pkg_math.mln");
    assert(m1 != NULL);
    assert(m1->state == MODULE_LOADED);
    assert(session->graph->module_count == 1);

    Module *m2 = module_loader_load(session->loader, NULL, "tests/succeed/package/pkg_math.mln");
    assert(m2 == m1);
    assert(session->graph->module_count == 1);

    frontend_session_destroy(session);
    printf("[PASS] module caching: same file yields single module instance\n");
}

static void test_relative_path_canonicalization(void) {
    FrontendSession *session = frontend_session_create();
    assert(session != NULL);

    Module *m1 = module_loader_load(session->loader, NULL, "./tests/succeed/package/pkg_math.mln");
    assert(m1 != NULL);

    Module *m2 = module_loader_load(session->loader, NULL, "tests/succeed/package/../package/pkg_math.mln");
    assert(m2 == m1);
    assert(session->graph->module_count == 1);

    frontend_session_destroy(session);
    printf("[PASS] relative path canonicalization: resolves to same canonical module\n");
}

static void test_circular_import_detection(void) {
    FrontendSession *session = frontend_session_create();
    FrontendSession *unrelated = frontend_session_create();
    assert(session != NULL && unrelated != NULL);

    /* The loader must use its own session, not the process-global current one. */
    frontend_session_set_current(unrelated);

    /* cycle_a.mln imports cycle_b.mln, and cycle_b.mln imports cycle_a.mln */
    Module *ma = module_loader_load(session->loader, NULL, "tests/fixtures/module/cycle_a.mln");
    assert(ma != NULL);
    assert(ma->state == MODULE_LOADED);
    assert(session->graph->module_count == 2);
    assert(unrelated->graph->module_count == 0);

    frontend_session_destroy(session);
    frontend_session_destroy(unrelated);
    printf("[PASS] circular import detection: does not infinitely recurse\n");
}

static void test_package_and_symbols_metadata(void) {
    FrontendSession *session = frontend_session_create();
    assert(session != NULL);

    Module *m = module_loader_load(session->loader, NULL, "tests/succeed/package/pkg_math.mln");
    assert(m != NULL);
    assert(m->package_name != NULL);
    assert(strcmp(m->package_name, "math") == 0);

    ModuleSymbol *sym_add = module_find_exported_symbol(m, "Add");
    assert(sym_add != NULL);
    assert(sym_add->kind == SYMBOL_FUNCTION);
    assert(sym_add->is_exported == 1);
    assert(strcmp(sym_add->source_name, "Add") == 0);
    assert(strcmp(sym_add->link_name, "math_Add") == 0);

    ModuleSymbol *sym_mul = module_find_exported_symbol(m, "Mul");
    assert(sym_mul != NULL);
    assert(sym_mul->is_exported == 1);
    assert(strcmp(sym_mul->link_name, "math_Mul") == 0);

    frontend_session_destroy(session);
    printf("[PASS] package and symbols metadata: extracted correctly\n");
}

static void test_non_mylang_import_ignored(void) {
    FrontendSession *session = frontend_session_create();
    assert(session != NULL);

    Module *m = module_loader_load(session->loader, NULL, "tests/fixtures/module/sample.masm");
    assert(m == NULL);
    assert(session->graph->module_count == 0);

    frontend_session_destroy(session);
    printf("[PASS] non-mylang import ignored: .masm not loaded into module graph\n");
}

static void test_session_isolation(void) {
    FrontendSession *s1 = frontend_session_create();
    FrontendSession *s2 = frontend_session_create();
    assert(s1 != NULL && s2 != NULL);

    Module *m1 = module_loader_load(s1->loader, NULL, "tests/succeed/package/pkg_math.mln");
    assert(m1 != NULL);
    assert(s1->graph->module_count == 1);
    assert(s2->graph->module_count == 0);

    Module *m2 = module_loader_load(s2->loader, NULL, "tests/succeed/package/pkg_math.mln");
    assert(m2 != NULL);
    assert(m2 != m1); /* Both live simultaneously; separate module instances */
    assert(s2->graph->module_count == 1);
    assert(s1->graph->module_count == 1);

    frontend_session_destroy(s1);
    assert(s2->graph->module_count == 1);

    frontend_session_destroy(s2);
    printf("[PASS] session isolation: independent sessions do not leak state\n");
}

#include "mylang/frontend/resolver.h"
#include "mylang/frontend/parser_ast_internal.h"

static void test_resolver_visibility_and_function_info(void) {
    FrontendSession *session = frontend_session_create();
    assert(session != NULL);

    Module *mod = module_loader_load(session->loader, NULL, "tests/fixtures/module/sample_lib.mln");
    assert(mod != NULL);
    assert(mod->state == MODULE_LOADED);

    /* 1. Package import test */
    ASTNode *pkg_import = new_import_stmt("sample_lib.mln", NULL, 0);
    const char *pkg_name = resolver_import_package_name(pkg_import, mod);
    assert(pkg_name != NULL && strcmp(pkg_name, "sample_lib") == 0);

    ModuleSymbol *sym_exp = resolver_lookup_import_symbol(pkg_import, mod, "exported_add");
    assert(sym_exp != NULL);
    assert(strcmp(sym_exp->source_name, "exported_add") == 0);
    assert(strcmp(sym_exp->link_name, "sample_lib_exported_add") == 0);

    ModuleSymbol *sym_priv = resolver_lookup_import_symbol(pkg_import, mod, "private_add");
    assert(sym_priv == NULL); /* Private symbol not visible */

    /* 2. Symbol-list import test */
    char **symbols = malloc(sizeof(char *) * 1);
    symbols[0] = strdup("exported_add");
    ASTNode *sym_import = new_import_stmt("sample_lib.mln", symbols, 1);

    ModuleSymbol *sym_visible = resolver_lookup_import_symbol(sym_import, mod, "exported_add");
    assert(sym_visible != NULL);

    ModuleSymbol *sym_unrequested = resolver_lookup_import_symbol(sym_import, mod, "variadic_log");
    assert(sym_unrequested == NULL); /* Exported but unrequested symbol is not visible */

    /* 3. Function signature and variadic info test */
    ModuleSymbol *sym_variadic = module_find_exported_symbol(mod, "variadic_log");
    assert(sym_variadic != NULL);

    ResolverFunctionInfo fn_info;
    assert(resolver_get_function_info(sym_variadic, &fn_info) == 1);
    assert(fn_info.param_count == 2);
    assert(fn_info.fixed_param_count == 1);
    assert(fn_info.is_variadic == true);
    assert(strcmp(fn_info.params[0].name, "level") == 0);
    assert(strcmp(fn_info.params[1].name, "args") == 0);
    assert(fn_info.params[1].is_rest == 1);
    resolver_free_function_info(&fn_info);

    /* 4. Exported generic template lookup test */
    ASTNode *gen_exp = resolver_find_exported_generic_template(mod, "exported_identity");
    assert(gen_exp != NULL);
    assert(gen_exp->type == AST_FUNDEF);

    ASTNode *gen_priv = resolver_find_exported_generic_template(mod, "private_identity");
    assert(gen_priv == NULL); /* Non-exported generic template must not be found */

    /* 5. DOM signature helper test */
    DomSignature dom_sig;
    resolver_fill_dom_signature(sym_exp->declaration, "sample_lib_exported_add", &dom_sig);
    assert(strcmp(dom_sig.call_name, "sample_lib_exported_add") == 0);
    assert(dom_sig.param_count == 2);
    assert(strcmp(dom_sig.param_names[0], "x") == 0);
    assert(strcmp(dom_sig.param_names[1], "y") == 0);
    dom_signature_free(&dom_sig);

    free_ast(pkg_import);
    free_ast(sym_import);
    frontend_session_destroy(session);
    printf("[PASS] resolver: visibility, function info, generic exports, and DOM signature\n");
}

void test_module_graph_all(void) {
    test_module_caching();
    test_relative_path_canonicalization();
    test_circular_import_detection();
    test_package_and_symbols_metadata();
    test_non_mylang_import_ignored();
    test_session_isolation();
    test_resolver_visibility_and_function_info();
}
