#include "mylang/frontend/module.h"

#include <stdlib.h>

static FrontendSession *g_current_session = NULL;

FrontendSession *frontend_session_create(void) {
    FrontendSession *session = calloc(1, sizeof(FrontendSession));
    if (!session) return NULL;
    session->graph = module_graph_create();
    session->loader = module_loader_create(session->graph);
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
    free(session);
}

FrontendSession *frontend_session_current(void) {
    if (!g_current_session) {
        g_current_session = frontend_session_create();
    }
    return g_current_session;
}

void frontend_session_set_current(FrontendSession *session) {
    g_current_session = session;
}
