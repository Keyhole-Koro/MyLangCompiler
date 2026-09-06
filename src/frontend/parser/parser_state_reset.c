#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/module.h"

/* Clears the active parser context so declarations cannot leak between
 * independent translation units. */

void parser_set_filename(const char *name) {
    ParserContext *context = parser_context_current();
    context->module.filename = name;
}

void parser_reset(void) {
    frontend_session_destroy_implicit_current();
    parser_context_reset(parser_context_current());
}

void parser_context_reset(ParserContext *context) {
    if (context->symbols.generic_templates.declarations) {
        for (int i = 0; i < context->symbols.generic_templates.count; i++) {
            free_ast(context->symbols.generic_templates.declarations[i]);
        }
        free(context->symbols.generic_templates.declarations);
        context->symbols.generic_templates.declarations = NULL;
        context->symbols.generic_templates.count = 0;
    }

    /* Normally already emptied by instantiate_generics(), which moves each
     * declaration into program->block.stmts (the program owns it from
     * there); this only catches a context that never reached that pass
     * (e.g. a parse error abort), so nothing here has been moved yet. */
    if (context->symbols.imported_plain_types.declarations) {
        for (int i = 0; i < context->symbols.imported_plain_types.count; i++) {
            free_ast(context->symbols.imported_plain_types.declarations[i]);
        }
        free(context->symbols.imported_plain_types.declarations);
        context->symbols.imported_plain_types.declarations = NULL;
        context->symbols.imported_plain_types.count = 0;
    }

    /* Normally already emptied by module_loader.c's transfer to
     * Module->exported_payload_enums; this only catches a context that
     * never reached that transfer (parsed directly via parse_program(), or
     * a parse error abort). */
    if (context->symbols.exported_payload_enums.declarations) {
        for (int i = 0; i < context->symbols.exported_payload_enums.count; i++) {
            free_ast(context->symbols.exported_payload_enums.declarations[i]);
        }
        free(context->symbols.exported_payload_enums.declarations);
        context->symbols.exported_payload_enums.declarations = NULL;
        context->symbols.exported_payload_enums.count = 0;
    }

    if (context->symbols.functions.funcs) {
        free(context->symbols.functions.funcs);
        context->symbols.functions.funcs = NULL;
        context->symbols.functions.count = 0;
    }

    if (context->symbols.types.typenames) {
        for (int i = 0; i < context->symbols.types.count; i++) {
            free(context->symbols.types.typenames[i]);
        }
        free(context->symbols.types.typenames);
        context->symbols.types.typenames = NULL;
        context->symbols.types.count = 0;
    }

    if (context->symbols.structs.structs) {
        for (int i = 0; i < context->symbols.structs.count; i++) {
            if (context->symbols.structs.structs[i]) {
                free(context->symbols.structs.structs[i]->name);
                free(context->symbols.structs.structs[i]);
            }
        }
        free(context->symbols.structs.structs);
        context->symbols.structs.structs = NULL;
        context->symbols.structs.count = 0;
    }

    if (context->module.exports) {
        for (int i = 0; i < context->module.export_count; i++) {
            free(context->module.exports[i].orig);
            free(context->module.exports[i].mangled);
        }
        free(context->module.exports);
        context->module.exports = NULL;
        context->module.export_count = 0;
    }

    if (context->module.imported_packages) {
        for (int i = 0; i < context->module.imported_package_count; i++) {
            free(context->module.imported_packages[i]);
        }
        free(context->module.imported_packages);
        context->module.imported_packages = NULL;
        context->module.imported_package_count = 0;
    }

    if (context->lowering.hoisted_functions) {
        free(context->lowering.hoisted_functions);
        context->lowering.hoisted_functions = NULL;
    }
    context->lowering.hoisted_function_count = 0;
    context->lowering.function_literal_counter = 0;

    if (context->symbols.enum_constants) {
        for (int i = 0; i < context->symbols.enum_constant_count; i++) {
            free(context->symbols.enum_constants[i].name);
        }
        free(context->symbols.enum_constants);
        context->symbols.enum_constants = NULL;
        context->symbols.enum_constant_count = 0;
    }

    if (context->module.current_package_heap && context->module.current_package) {
        free(context->module.current_package);
    }
    context->module.current_package = (char *)g_default_package;
    context->module.current_package_heap = 0;

    context->token_head = NULL;
    context->session = NULL;
    context->is_root_module = 0;
    context->control.stop_at_arrow = 0;
    context->control.unchecked_depth = 0;
    context->control.generic_decl_depth = 0;
    context->control.current_generic_function_name = NULL;
    context->module.filename = NULL;
}
