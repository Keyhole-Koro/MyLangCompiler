#include "mylang/frontend/parser_internal.h"

/* Centralized bridge for the incremental parser-context migration.  The
 * parser's public helpers still reference globals, so context activation is
 * deliberately explicit at module boundaries rather than copying selected
 * globals ad hoc. */
void parser_context_save(ParserContext *context) {
    if (!context) return;
    context->token_head = token_head;
    context->root = root;
    context->struct_table = g_struct_table;
    context->func_table = g_func_table;
    context->type_table = g_type_table;
    context->generic_template_table = g_generic_template_table;
    context->generic_decl_depth = g_generic_decl_depth;
    context->current_generic_function_name = g_current_generic_function_name;
    context->stop_at_arrow = g_stop_at_arrow;
    context->unchecked_depth = g_unchecked_depth;
    context->current_package = g_current_package;
    context->current_package_heap = g_current_package_heap;
    context->exports = g_exports;
    context->export_count = g_export_count;
    context->imported_packages = g_imported_packages;
    context->imported_pkg_count = g_imported_pkg_count;
    context->hoisted_funcs = g_hoisted_funcs;
    context->hoisted_count = g_hoisted_count;
    context->funlit_counter = g_funlit_counter;
    context->parse_filename = g_parse_filename;
    context->enum_constants = g_enum_constants;
    context->enum_constant_count = g_enum_constant_count;
}

void parser_context_activate_empty(void) {
    token_head = NULL;
    root = NULL;
    g_struct_table = (StructTable){ NULL, 0 };
    g_func_table = (FunctionTable){ NULL, 0 };
    g_type_table = (TypeTable){ NULL, 0 };
    g_generic_template_table = (GenericTemplateTable){ NULL, 0 };
    g_generic_decl_depth = 0;
    g_current_generic_function_name = NULL;
    g_stop_at_arrow = 0;
    g_unchecked_depth = 0;
    g_current_package = (char *)g_default_package;
    g_current_package_heap = 0;
    g_exports = NULL;
    g_export_count = 0;
    g_imported_packages = NULL;
    g_imported_pkg_count = 0;
    g_hoisted_funcs = NULL;
    g_hoisted_count = 0;
    g_funlit_counter = 0;
    g_parse_filename = NULL;
    g_enum_constants = NULL;
    g_enum_constant_count = 0;
}

void parser_context_restore(const ParserContext *context) {
    if (!context) return;
    token_head = context->token_head;
    root = context->root;
    g_struct_table = context->struct_table;
    g_func_table = context->func_table;
    g_type_table = context->type_table;
    g_generic_template_table = context->generic_template_table;
    g_generic_decl_depth = context->generic_decl_depth;
    g_current_generic_function_name = context->current_generic_function_name;
    g_stop_at_arrow = context->stop_at_arrow;
    g_unchecked_depth = context->unchecked_depth;
    g_current_package = context->current_package;
    g_current_package_heap = context->current_package_heap;
    g_exports = context->exports;
    g_export_count = context->export_count;
    g_imported_packages = context->imported_packages;
    g_imported_pkg_count = context->imported_pkg_count;
    g_hoisted_funcs = context->hoisted_funcs;
    g_hoisted_count = context->hoisted_count;
    g_funlit_counter = context->funlit_counter;
    g_parse_filename = context->parse_filename;
    g_enum_constants = context->enum_constants;
    g_enum_constant_count = context->enum_constant_count;
}
