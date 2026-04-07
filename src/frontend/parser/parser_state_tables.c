#include "mylang/frontend/parser_internal.h"

Token *token_head = NULL;
ASTNode *root;
StructTable g_struct_table = { NULL, 0 };
FunctionTable g_func_table = { NULL, 0 };
TypeTable g_type_table = { NULL, 0 };
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
