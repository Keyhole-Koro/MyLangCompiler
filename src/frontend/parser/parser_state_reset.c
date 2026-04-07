#include "mylang/frontend/parser_internal.h"

void parser_set_filename(const char *name) {
    g_parse_filename = name;
}

void parser_reset(void) {
    if (g_func_table.funcs) {
        free(g_func_table.funcs);
        g_func_table.funcs = NULL;
        g_func_table.count = 0;
    }

    if (g_type_table.typenames) {
        for (int i = 0; i < g_type_table.count; i++) {
            free(g_type_table.typenames[i]);
        }
        free(g_type_table.typenames);
        g_type_table.typenames = NULL;
        g_type_table.count = 0;
    }

    if (g_struct_table.structs) {
        for (int i = 0; i < g_struct_table.count; i++) {
            if (g_struct_table.structs[i]) {
                free(g_struct_table.structs[i]->name);
                free(g_struct_table.structs[i]);
            }
        }
        free(g_struct_table.structs);
        g_struct_table.structs = NULL;
        g_struct_table.count = 0;
    }

    if (g_exports) {
        for (int i = 0; i < g_export_count; i++) {
            free(g_exports[i].orig);
            free(g_exports[i].mangled);
        }
        free(g_exports);
        g_exports = NULL;
        g_export_count = 0;
    }

    if (g_imported_packages) {
        for (int i = 0; i < g_imported_pkg_count; i++) {
            free(g_imported_packages[i]);
        }
        free(g_imported_packages);
        g_imported_packages = NULL;
        g_imported_pkg_count = 0;
    }

    if (g_hoisted_funcs) {
        free(g_hoisted_funcs);
        g_hoisted_funcs = NULL;
    }
    g_hoisted_count = 0;
    g_funlit_counter = 0;

    if (g_enum_constants) {
        for (int i = 0; i < g_enum_constant_count; i++) {
            free(g_enum_constants[i].name);
        }
        free(g_enum_constants);
        g_enum_constants = NULL;
        g_enum_constant_count = 0;
    }

    if (g_current_package_heap && g_current_package) {
        free(g_current_package);
    }
    g_current_package = (char *)g_default_package;
    g_current_package_heap = 0;

    token_head = NULL;
    root = NULL;
    g_stop_at_arrow = 0;
    g_unchecked_depth = 0;
    g_parse_filename = NULL;
}
