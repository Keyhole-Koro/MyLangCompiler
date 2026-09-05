#include "mylang/frontend/module.h"

#include <stdlib.h>
#include <string.h>

static FrontendSession *g_current_session = NULL;

FrontendSession *frontend_session_create(void) {
    FrontendSession *session = calloc(1, sizeof(FrontendSession));
    if (!session) return NULL;
    session->graph = module_graph_create();
    session->loader = module_loader_create(session->graph, session);
    if (!session->graph || !session->loader) {
        module_loader_destroy(session->loader);
        module_graph_destroy(session->graph);
        free(session);
        return NULL;
    }
    return session;
}

void frontend_session_destroy(FrontendSession *session) {
    if (!session) return;
    if (g_current_session == session) {
        g_current_session = NULL;
    }
    if (session->loader) {
        module_loader_destroy(session->loader);
        session->loader = NULL;
    }
    if (session->graph) {
        module_graph_destroy(session->graph);
        session->graph = NULL;
    }
    for (int i = 0; i < session->root_imported_package_count; i++) {
        free(session->root_imported_packages[i]);
    }
    free(session->root_imported_packages);
    free(session);
}

FrontendSession *frontend_session_current(void) {
    if (!g_current_session) {
        g_current_session = frontend_session_create();
        if (g_current_session) g_current_session->is_implicit = 1;
    }
    return g_current_session;
}

void frontend_session_set_current(FrontendSession *session) {
    if (session) session->is_implicit = 0;
    g_current_session = session;
}

void frontend_session_destroy_implicit_current(void) {
    if (g_current_session && g_current_session->is_implicit) {
        frontend_session_destroy(g_current_session);
    }
}

void frontend_session_add_root_imported_package(FrontendSession *session, const char *name) {
    if (!session || !name || !name[0]) return;
    for (int i = 0; i < session->root_imported_package_count; i++) {
        if (strcmp(session->root_imported_packages[i], name) == 0) return;
    }
    session->root_imported_packages = realloc(
        session->root_imported_packages,
        sizeof(char *) * (session->root_imported_package_count + 1)
    );
    session->root_imported_packages[session->root_imported_package_count++] = strdup(name);
}
