#include "mylang/frontend/parser_rewrite_internal.h"

typedef struct FunAlias {
    char *name;
    char *target;
} FunAlias;

const char *lower_alias_lookup(FunAlias *aliases, int count, const char *name) {
    for (int i = count - 1; i >= 0; i--) {
        if (strcmp(aliases[i].name, name) == 0) return aliases[i].target;
    }
    return NULL;
}

void lower_alias_push(FunAlias **aliases, int *count, const char *name, const char *target) {
    *aliases = realloc(*aliases, sizeof(FunAlias) * (*count + 1));
    (*aliases)[*count].name = strdup(name);
    (*aliases)[*count].target = target ? strdup(target) : NULL;
    (*count)++;
}

FunAlias *lower_alias_copy(FunAlias *aliases, int count, int *out_count) {
    FunAlias *copy = NULL;
    *out_count = 0;
    for (int i = 0; i < count; i++) {
        lower_alias_push(&copy, out_count, aliases[i].name, aliases[i].target);
    }
    return copy;
}

void lower_alias_free_all(FunAlias *aliases, int count) {
    for (int i = 0; i < count; i++) {
        free(aliases[i].name);
        if (aliases[i].target) free(aliases[i].target);
    }
    free(aliases);
}
