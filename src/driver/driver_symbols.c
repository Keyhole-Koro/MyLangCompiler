#include "mylang/driver/driver_internal.h"
#include "mylang/frontend/parser_trait_internal.h"

/* `--emit-symbols`: what a translation unit exports and what it uses, for
 * qa/tools/unused_exports.py. Uses are read from the finished assembly rather
 * than the AST: by then everything the compiler added is there as well, such
 * as DOM calls, drops, `==` on a trait, trampolines and annotation rows. */

typedef struct {
    char **items;
    int count;
} NameList;

static void name_list_add(NameList *list, const char *name) {
    list->items = realloc(list->items, sizeof(char *) * (size_t)(list->count + 1));
    list->items[list->count++] = strdup(name);
}

static void name_list_free(NameList *list) {
    for (int i = 0; i < list->count; i++) free(list->items[i]);
    free(list->items);
}

static int compare_names(const void *left, const void *right) {
    return strcmp(*(char *const *)left, *(char *const *)right);
}

static void name_list_sort(NameList *list) {
    if (list->count > 0) qsort(list->items, (size_t)list->count, sizeof(char *), compare_names);
}

static int name_list_has(const NameList *list, const char *name) {
    return list->count > 0 &&
           bsearch(&name, list->items, (size_t)list->count, sizeof(char *), compare_names) != NULL;
}

static int is_impl_item(ParserContext *parser, const char *name) {
    for (int i = 0; i < impl_count(parser); i++) {
        ImplDef *impl = impl_at(parser, i);
        for (int k = 0; impl->item_mangled && k < impl->item_count; k++) {
            if (impl->item_mangled[k] && strcmp(impl->item_mangled[k], name) == 0) return 1;
        }
    }
    return 0;
}

/* Generic functions and methods are not in the AST: only their instances are.
 * One copied from an import belongs to the module that wrote it. */
static void write_template(FILE *file, const ASTNode *fn, const char *path) {
    if (fn->fundef.origin_path) return;
    fprintf(file, "template\t%s\t%s\t%d\n", fn->fundef.name, path, fn->line);
}

static void write_definitions(FILE *file, ASTNode *root, const char *path, ParserContext *parser,
                              NameList *defined) {
    for (int i = 0; i < root->block.count; i++) {
        ASTNode *node = root->block.stmts[i];
        if (node && node->type == AST_VAR_DECL && node->var_decl.name) {
            name_list_add(defined, node->var_decl.name);
            if (node->var_decl.is_exported && !node->var_decl.is_extern)
                fprintf(file, "global\t%s\t%s\t%d\n", node->var_decl.name, path, node->line);
        }
        if (!node || node->type != AST_FUNDEF || !node->fundef.name || !node->fundef.body) continue;
        const char *name = node->fundef.name;
        name_list_add(defined, name);
        if (strncmp(name, "__mlg_", 6) == 0) {
            /* An instance keeps the line of the template it was made from. */
            char origin[PATH_MAX];
            const char *written = node->fundef.origin_path && realpath(node->fundef.origin_path, origin)
                ? origin : path;
            fprintf(file, "instance\t%s\t%s\t%d\n", name, written, node->line);
        } else if (node->fundef.is_exported) {
            const char *kind = is_impl_item(parser, name) ? "impl"
                : node->fundef.recv_type_name ? "method" : "function";
            fprintf(file, "%s\t%s\t%s\t%d\n", kind, name, path, node->line);
        }
    }
    for (int i = 0; i < generic_template_count(parser); i++) {
        ASTNode *template = generic_template_at(parser, i);
        if (template && template->type == AST_FUNDEF && template->fundef.is_exported)
            write_template(file, template, path);
    }
    for (int i = 0; i < generic_method_count(parser); i++) {
        GenericMethodDef *method = generic_method_at(parser, i);
        if (method->is_exported) write_template(file, method->fundef, path);
    }
}

static int is_symbol_char(char c) {
    return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/* The names the assembly's `import` lines list. */
static void collect_imports(const char *assembly, NameList *known) {
    const char *line = assembly;
    while (line && *line) {
        const char *end = strchr(line, '\n');
        size_t length = end ? (size_t)(end - line) : strlen(line);
        if (strncmp(line, "import ", 7) == 0) {
            char *name = strndup(line + 7, length - 7);
            name_list_add(known, name);
            free(name);
        }
        line = end ? end + 1 : NULL;
    }
}

/* Every symbol a line's operands name. The first word is a mnemonic or a
 * directive, and the rest of the line past `;` is a comment. */
static void collect_line_uses(const char *line, size_t length, const char *from,
                              const NameList *known, NameList *uses) {
    size_t at = 0;
    while (at < length && (line[at] == ' ' || line[at] == '\t')) at++;
    if (at < length && line[at] == ';') return;
    while (at < length && line[at] != ' ' && line[at] != '\t') at++;
    while (at < length && line[at] != ';') {
        if (!is_symbol_char(line[at])) {
            at++;
            continue;
        }
        size_t start = at;
        while (at < length && is_symbol_char(line[at])) at++;
        char *name = strndup(line + start, at - start);
        if (name_list_has(known, name)) {
            char *use = malloc(strlen(from) + strlen(name) + 2);
            sprintf(use, "%s\t%s", from, name);
            name_list_add(uses, use);
            free(use);
        }
        free(name);
    }
}

static void collect_uses(const char *assembly, const NameList *defined, const NameList *known,
                         NameList *uses) {
    const char *from = "-";
    char *label = NULL;
    const char *line = assembly;
    while (line && *line) {
        const char *end = strchr(line, '\n');
        size_t length = end ? (size_t)(end - line) : strlen(line);
        if (length > 1 && line[length - 1] == ':' && line[0] != ' ') {
            /* A label of ours starts a function or a global. */
            char *name = strndup(line, length - 1);
            if (name_list_has(defined, name)) {
                free(label);
                label = name;
                from = label;
            } else {
                free(name);
            }
        } else if (strncmp(line, "import ", 7) != 0 && strncmp(line, "export ", 7) != 0) {
            collect_line_uses(line, length, from, known, uses);
        }
        line = end ? end + 1 : NULL;
    }
    free(label);
}

int write_symbol_file(const char *symbols_path, const char *input_path, ASTNode *root,
                      const char *assembly) {
    if (!symbols_path) return 1;
    if (!root || root->type != AST_BLOCK) return 0;
    char path[PATH_MAX];
    if (!realpath(input_path, path) || strchr(path, '\t') || strchr(path, '\n')) {
        fprintf(stderr, "cannot name this source in a symbol file: %s\n", input_path);
        return 0;
    }
    FILE *file = fopen(symbols_path, "wb");
    if (!file) {
        fprintf(stderr, "failed to open symbol file: %s\n", symbols_path);
        return 0;
    }

    NameList defined = {0}, known = {0}, uses = {0};
    fprintf(file, "MYSYMBOLS 1\n");
    write_definitions(file, root, path, parser_context_current(), &defined);
    name_list_add(&defined, "__START__");
    name_list_sort(&defined);

    for (int i = 0; i < defined.count; i++) name_list_add(&known, defined.items[i]);
    collect_imports(assembly, &known);
    name_list_sort(&known);

    collect_uses(assembly, &defined, &known, &uses);
    name_list_sort(&uses);
    for (int i = 0; i < uses.count; i++) {
        if (i == 0 || strcmp(uses.items[i], uses.items[i - 1]) != 0)
            fprintf(file, "use\t%s\n", uses.items[i]);
    }

    name_list_free(&defined);
    name_list_free(&known);
    name_list_free(&uses);
    int ok = fclose(file) == 0;
    if (!ok) fprintf(stderr, "failed to write symbol file: %s\n", symbols_path);
    return ok;
}
