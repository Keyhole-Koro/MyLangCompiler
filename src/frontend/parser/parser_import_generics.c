#include "mylang/frontend/parser_internal.h"

/* Import parsing normally only records linker-visible symbols. Generic
 * definitions need their bodies at the use site, so parse an imported source
 * in an isolated parser state and retain clones of the requested exports. */
static void free_import_tokens(Token *tokens) {
    while (tokens) {
        Token *next = tokens->next;
        free(tokens->value);
        free(tokens);
        tokens = next;
    }
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

void load_imported_generic_templates(ParserContext *context, ASTNode *import_node,
                                     const char *source_path) {
    ParserContext imported_context;
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

    parser_context_init(&imported_context);
    imported_context.module.filename = source_path;
    cur = tokens;
    /* Templates are copied in syntax form. The importing program's normal
     * frontend pipeline specializes and lowers them after instantiation. */
    program = parse_program_syntax(&imported_context, &cur);

    for (int i = 0; i < imported_context.symbols.generic_templates.count; i++) {
        ASTNode *template = imported_context.symbols.generic_templates.declarations[i];
        const char *name = template_name(template);
        if (!template_is_exported(template) || !import_requests_symbol(import_node, name))
            continue;

        copies = realloc(copies, sizeof(ASTNode *) * (copy_count + 1));
        copies[copy_count++] = ast_clone(template);
    }

    free_ast(program);
    free_import_tokens(tokens);
    parser_context_reset(&imported_context);

    for (int i = 0; i < copy_count; i++) {
        ASTNode *copy = copies[i];
        const char *name = template_name(copy);
        if (copy->type == AST_STRUCT) add_typename(context, copy->struct_stmt.name);
        add_generic_template(context, copy);
        remove_import_symbol(import_node, name);
    }
    free(copies);
}
