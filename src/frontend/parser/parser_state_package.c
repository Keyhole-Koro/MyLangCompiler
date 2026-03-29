#include "mylang/frontend/parser_internal.h"

void set_current_package(const char *name) {
    if (g_current_package_heap && g_current_package) {
        free(g_current_package);
    }
    g_current_package = strdup(name ? name : g_default_package);
    g_current_package_heap = 1;
}

void add_export(const char *orig, const char *mangled) {
    g_exports = realloc(g_exports, sizeof(ExportEntry) * (g_export_count + 1));
    g_exports[g_export_count].orig = strdup(orig);
    g_exports[g_export_count].mangled = strdup(mangled);
    g_export_count++;
}

const char *find_export_mangled(const char *orig) {
    for (int i = 0; i < g_export_count; i++) {
        if (strcmp(g_exports[i].orig, orig) == 0) return g_exports[i].mangled;
    }
    return NULL;
}

int is_imported_package(const char *name) {
    for (int i = 0; i < g_imported_pkg_count; i++) {
        if (strcmp(g_imported_packages[i], name) == 0) return 1;
    }
    return 0;
}

char *mangle(const char *pkg, const char *name) {
    size_t len = strlen(pkg) + 1 + strlen(name) + 1;
    char *buf = malloc(len);
    snprintf(buf, len, "%s_%s", pkg, name);
    return buf;
}
