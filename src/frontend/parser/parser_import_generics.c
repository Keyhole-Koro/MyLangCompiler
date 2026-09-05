#include "mylang/frontend/parser_internal.h"

/* Import parsing normally only records linker-visible symbols. Generic
 * definitions need their bodies at the use site, so parse an imported source
 * in an isolated parser state and retain clones of the requested exports. */
typedef struct {
    Token *token_head;
    ASTNode *root;
    StructTable struct_table;
    FunctionTable func_table;
    TypeTable type_table;
    GenericTemplateTable generic_template_table;
    int generic_decl_depth;
    const char *current_generic_function_name;
    int stop_at_arrow;
    int unchecked_depth;
    char *current_package;
    int current_package_heap;
    ExportEntry *exports;
    int export_count;
    char **imported_packages;
    int imported_pkg_count;
    ASTNode **hoisted_funcs;
    int hoisted_count;
    int funlit_counter;
    const char *parse_filename;
    EnumConstant *enum_constants;
    int enum_constant_count;
} ParserState;

static void free_import_tokens(Token *tokens) {
    while (tokens) {
        Token *next = tokens->next;
        free(tokens->value);
        free(tokens);
        tokens = next;
    }
}

static void save_parser_state(ParserState *state) {
    state->token_head = token_head;
    state->root = root;
    state->struct_table = g_struct_table;
    state->func_table = g_func_table;
    state->type_table = g_type_table;
    state->generic_template_table = g_generic_template_table;
    state->generic_decl_depth = g_generic_decl_depth;
    state->current_generic_function_name = g_current_generic_function_name;
    state->stop_at_arrow = g_stop_at_arrow;
    state->unchecked_depth = g_unchecked_depth;
    state->current_package = g_current_package;
    state->current_package_heap = g_current_package_heap;
    state->exports = g_exports;
    state->export_count = g_export_count;
    state->imported_packages = g_imported_packages;
    state->imported_pkg_count = g_imported_pkg_count;
    state->hoisted_funcs = g_hoisted_funcs;
    state->hoisted_count = g_hoisted_count;
    state->funlit_counter = g_funlit_counter;
    state->parse_filename = g_parse_filename;
    state->enum_constants = g_enum_constants;
    state->enum_constant_count = g_enum_constant_count;
}

static void activate_empty_parser_state(void) {
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

static void restore_parser_state(const ParserState *state) {
    token_head = state->token_head;
    root = state->root;
    g_struct_table = state->struct_table;
    g_func_table = state->func_table;
    g_type_table = state->type_table;
    g_generic_template_table = state->generic_template_table;
    g_generic_decl_depth = state->generic_decl_depth;
    g_current_generic_function_name = state->current_generic_function_name;
    g_stop_at_arrow = state->stop_at_arrow;
    g_unchecked_depth = state->unchecked_depth;
    g_current_package = state->current_package;
    g_current_package_heap = state->current_package_heap;
    g_exports = state->exports;
    g_export_count = state->export_count;
    g_imported_packages = state->imported_packages;
    g_imported_pkg_count = state->imported_pkg_count;
    g_hoisted_funcs = state->hoisted_funcs;
    g_hoisted_count = state->hoisted_count;
    g_funlit_counter = state->funlit_counter;
    g_parse_filename = state->parse_filename;
    g_enum_constants = state->enum_constants;
    g_enum_constant_count = state->enum_constant_count;
}

static int import_requests_symbol(const ASTNode *node, const char *name) {
    if (!node || node->type != AST_IMPORT || !name) return 0;
    for (int i = 0; i < node->import_stmt.symbol_count; i++) {
        if (node->import_stmt.symbols[i] && strcmp(node->import_stmt.symbols[i], name) == 0)
            return 1;
    }
    return 0;
}

static int template_is_exported(const ASTNode *node) {
    if (!node) return 0;
    if (node->type == AST_FUNDEF) return node->fundef.is_exported;
    if (node->type == AST_STRUCT) return node->struct_stmt.is_exported;
    return 0;
}

static const char *template_name(const ASTNode *node) {
    if (!node) return NULL;
    if (node->type == AST_FUNDEF) return node->fundef.name;
    if (node->type == AST_STRUCT) return node->struct_stmt.name;
    return NULL;
}

static void remove_import_symbol(ASTNode *node, const char *name) {
    if (!node || node->type != AST_IMPORT || !name) return;
    for (int i = 0; i < node->import_stmt.symbol_count; i++) {
        if (!node->import_stmt.symbols[i] || strcmp(node->import_stmt.symbols[i], name) != 0)
            continue;
        free(node->import_stmt.symbols[i]);
        for (int j = i + 1; j < node->import_stmt.symbol_count; j++)
            node->import_stmt.symbols[j - 1] = node->import_stmt.symbols[j];
        node->import_stmt.symbol_count--;
        if (node->import_stmt.symbol_count == 0) {
            free(node->import_stmt.symbols);
            node->import_stmt.symbols = NULL;
        }
        return;
    }
}

void load_imported_generic_templates(ASTNode *import_node, const char *source_path) {
    ParserState saved;
    Token *tokens;
    Token *cur;
    ASTNode *program;
    ASTNode **copies = NULL;
    int copy_count = 0;

    if (!import_node || import_node->type != AST_IMPORT ||
        !source_path || import_node->import_stmt.symbol_count == 0)
        return;

    tokens = lexer_from_file(source_path);
    if (!tokens) return; /* Imports may also name linker-provided symbols. */

    save_parser_state(&saved);
    activate_empty_parser_state();
    token_head = tokens;
    parser_set_filename(source_path);
    cur = tokens;
    program = parse_program(&cur);

    for (int i = 0; i < g_generic_template_table.count; i++) {
        ASTNode *template = g_generic_template_table.declarations[i];
        const char *name = template_name(template);
        if (!template_is_exported(template) || !import_requests_symbol(import_node, name))
            continue;

        copies = realloc(copies, sizeof(ASTNode *) * (copy_count + 1));
        copies[copy_count++] = ast_clone(template);
    }

    free_ast(program);
    free_import_tokens(tokens);
    parser_reset();
    restore_parser_state(&saved);

    for (int i = 0; i < copy_count; i++) {
        ASTNode *copy = copies[i];
        const char *name = template_name(copy);
        if (copy->type == AST_STRUCT) add_typename(copy->struct_stmt.name);
        add_generic_template(copy);
        remove_import_symbol(import_node, name);
    }
    free(copies);
}
