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
    assert(session != NULL);

    /* cycle_a.mln imports cycle_b.mln, and cycle_b.mln imports cycle_a.mln */
    Module *ma = module_loader_load(session->loader, NULL, "tests/fixtures/module/cycle_a.mln");
    assert(ma != NULL);
    assert(ma->state == MODULE_LOADED);

    frontend_session_destroy(session);
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

void test_module_graph_all(void) {
    test_module_caching();
    test_relative_path_canonicalization();
    test_circular_import_detection();
    test_package_and_symbols_metadata();
    test_non_mylang_import_ignored();
    test_session_isolation();
}
