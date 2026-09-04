#include "mylang/frontend/parser_internal.h"

Token *token_head = NULL;
ASTNode *root;
StructTable g_struct_table = { NULL, 0 };
FunctionTable g_func_table = { NULL, 0 };
TypeTable g_type_table = { NULL, 0 };
GenericTemplateTable g_generic_template_table = { NULL, 0 };
int g_generic_decl_depth = 0;
const char *g_current_generic_function_name = NULL;
int g_stop_at_arrow = 0;
int g_unchecked_depth = 0;
const char g_default_package[] = "main";
char *g_current_package = (char *)g_default_package;
int g_current_package_heap = 0;
ExportEntry *g_exports = NULL;
int g_export_count = 0;
char **g_imported_packages = NULL;
int g_imported_pkg_count = 0;
ASTNode **g_hoisted_funcs = NULL;
int g_hoisted_count = 0;
int g_funlit_counter = 0;
const char *g_parse_filename = NULL;
EnumConstant *g_enum_constants = NULL;
int g_enum_constant_count = 0;

void add_function(ASTNode *fn) {
    g_func_table.funcs = realloc(g_func_table.funcs, sizeof(ASTNode*) * (g_func_table.count + 1));
    g_func_table.funcs[g_func_table.count++] = fn;
}

ASTNode *find_function(const char *name) {
    for (int i = 0; i < g_func_table.count; i++) {
        if (strcmp(g_func_table.funcs[i]->fundef.name, name) == 0) {
            return g_func_table.funcs[i];
        }
    }
    return NULL;
}

void add_typename(const char *name) {
    g_type_table.typenames = realloc(g_type_table.typenames, sizeof(char*) * (g_type_table.count + 1));
    g_type_table.typenames[g_type_table.count++] = strdup(name);
}

int is_user_typename(const char *name) {
    for (int i = 0; i < g_type_table.count; i++) {
        if (strcmp(g_type_table.typenames[i], name) == 0) return 1;
    }
    return 0;
}

int typename_scope_mark(void) {
    return g_type_table.count;
}

void restore_typenames(int mark) {
    if (mark < 0 || mark > g_type_table.count) return;
    for (int i = mark; i < g_type_table.count; i++) {
        free(g_type_table.typenames[i]);
    }
    g_type_table.count = mark;
    if (mark == 0) {
        free(g_type_table.typenames);
        g_type_table.typenames = NULL;
        return;
    }
    g_type_table.typenames = realloc(g_type_table.typenames, sizeof(char *) * mark);
}

static const char *generic_declaration_name(ASTNode *declaration) {
    if (!declaration) return NULL;
    if (declaration->type == AST_FUNDEF) return declaration->fundef.name;
    if (declaration->type == AST_STRUCT) return declaration->struct_stmt.name;
    return NULL;
}

void add_generic_template(ASTNode *declaration) {
    const char *name = generic_declaration_name(declaration);
    if (!name) return;
    ASTNode *existing = declaration->type == AST_STRUCT
        ? find_generic_type_template(name)
        : find_generic_function_template(name);
    if (existing) {
        fprintf(stderr, "duplicate generic declaration '%s'\n", name);
        exit(1);
    }
    g_generic_template_table.declarations = realloc(
        g_generic_template_table.declarations,
        sizeof(ASTNode *) * (g_generic_template_table.count + 1)
    );
    g_generic_template_table.declarations[g_generic_template_table.count++] = declaration;
}

static ASTNode *find_generic_template(const char *name, ASTNodeType declaration_type) {
    if (!name) return NULL;
    for (int i = 0; i < g_generic_template_table.count; i++) {
        ASTNode *declaration = g_generic_template_table.declarations[i];
        const char *candidate = generic_declaration_name(declaration);
        if (declaration->type == declaration_type &&
            candidate && strcmp(candidate, name) == 0)
            return declaration;
    }
    return NULL;
}

ASTNode *find_generic_type_template(const char *name) {
    return find_generic_template(name, AST_STRUCT);
}

ASTNode *find_generic_function_template(const char *name) {
    return find_generic_template(name, AST_FUNDEF);
}

ASTNode *generic_template_at(int index) {
    if (index < 0 || index >= g_generic_template_table.count) return NULL;
    return g_generic_template_table.declarations[index];
}

int generic_template_count(void) {
    return g_generic_template_table.count;
}

void add_structdef(char *name, ASTNode **members, int member_count) {
    StructDef *def = malloc(sizeof(StructDef));
    def->name = strdup(name);
    def->members = members;
    def->member_count = member_count;
    g_struct_table.structs = realloc(g_struct_table.structs, sizeof(StructDef*) * (g_struct_table.count + 1));
    g_struct_table.structs[g_struct_table.count++] = def;
}

StructDef *find_structdef(const char *name) {
    for (int i = 0; i < g_struct_table.count; i++) {
        if (strcmp(g_struct_table.structs[i]->name, name) == 0) return g_struct_table.structs[i];
    }
    return NULL;
}

void add_enum_constant(const char *name, long value) {
    g_enum_constants = realloc(g_enum_constants, sizeof(EnumConstant) * (g_enum_constant_count + 1));
    g_enum_constants[g_enum_constant_count].name = strdup(name);
    g_enum_constants[g_enum_constant_count].value = value;
    g_enum_constant_count++;
}

int find_enum_constant(const char *name, long *out_value) {
    if (!name) return 0;
    for (int i = g_enum_constant_count - 1; i >= 0; i--) {
        if (strcmp(g_enum_constants[i].name, name) == 0) {
            if (out_value) *out_value = g_enum_constants[i].value;
            return 1;
        }
    }
    return 0;
}
