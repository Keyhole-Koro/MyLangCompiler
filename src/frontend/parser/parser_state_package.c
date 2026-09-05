#include "mylang/frontend/parser_internal.h"

void set_current_package(ParserContext *context, const char *name) {
    if (context->module.current_package_heap && context->module.current_package) {
        free(context->module.current_package);
    }
    context->module.current_package = strdup(name ? name : g_default_package);
    context->module.current_package_heap = 1;
}

void add_export(ParserContext *context, const char *orig, const char *mangled) {
    context->module.exports = realloc(context->module.exports, sizeof(ExportEntry) * (context->module.export_count + 1));
    context->module.exports[context->module.export_count].orig = strdup(orig);
    context->module.exports[context->module.export_count].mangled = strdup(mangled);
    context->module.export_count++;
}

const char *find_export_mangled(ParserContext *context, const char *orig) {
    for (int i = 0; i < context->module.export_count; i++) {
        if (strcmp(context->module.exports[i].orig, orig) == 0) return context->module.exports[i].mangled;
    }
    return NULL;
}

int is_imported_package(ParserContext *context, const char *name) {
    for (int i = 0; i < context->module.imported_package_count; i++) {
        if (strcmp(context->module.imported_packages[i], name) == 0) return 1;
    }
    return 0;
}

char *mangle(const char *pkg, const char *name) {
    size_t len = strlen(pkg) + 1 + strlen(name) + 1;
    char *buf = malloc(len);
    snprintf(buf, len, "%s_%s", pkg, name);
    return buf;
}
