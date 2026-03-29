#include "mylang/frontend/parser_rewrite_internal.h"

int rewrite_scope_contains(char **scope, int scope_count, const char *name) {
    for (int i = scope_count - 1; i >= 0; i--) {
        if (strcmp(scope[i], name) == 0) return 1;
    }
    return 0;
}

char **rewrite_scope_alloc(int capacity) {
    return malloc(sizeof(char*) * capacity);
}

char **rewrite_scope_clone(char **scope, int scope_count, int capacity) {
    char **copy = rewrite_scope_alloc(capacity);
    memcpy(copy, scope, sizeof(char*) * scope_count);
    return copy;
}

void rewrite_scope_push(char ***scope, int *scope_count, int *scope_cap, char *name) {
    if (*scope_count >= *scope_cap) {
        *scope_cap *= 2;
        *scope = realloc(*scope, sizeof(char*) * (*scope_cap));
    }
    (*scope)[(*scope_count)++] = name;
}

char **rewrite_scope_from_params(ASTNode *fn, int *scope_count, int *scope_cap) {
    *scope_cap = 64;
    *scope_count = 0;
    char **scope = rewrite_scope_alloc(*scope_cap);
    for (int i = 0; i < fn->fundef.param_count; i++) {
        rewrite_scope_push(&scope, scope_count, scope_cap, fn->fundef.params[i]->param.name);
    }
    return scope;
}

void rewrite_scope_free(char **scope) {
    free(scope);
}
