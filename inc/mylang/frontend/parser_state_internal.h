#ifndef MYLANG_FRONTEND_PARSER_STATE_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_STATE_INTERNAL_H

#include "mylang/frontend/parser.h"
#include "mylang/frontend/lexer.h"
#include "mylang/ast/AST.h"

typedef struct FunctionTable {
    ASTNode **funcs;
    int count;
} FunctionTable;

#define MAX_TYPE_NAME 128

typedef struct TypeTable {
    char **typenames;
    int count;
} TypeTable;

typedef struct StructDef {
    char *name;
    ASTNode **members;
    int member_count;
} StructDef;

typedef struct StructTable {
    StructDef **structs;
    int count;
} StructTable;

typedef struct ExportEntry {
    char *orig;
    char *mangled;
} ExportEntry;

extern Token *token_head;
extern ASTNode *root;
extern StructTable g_struct_table;
extern FunctionTable g_func_table;
extern TypeTable g_type_table;
extern int g_stop_at_arrow;
extern int g_unchecked_depth;
extern const char g_default_package[];
extern char *g_current_package;
extern int g_current_package_heap;
extern ExportEntry *g_exports;
extern int g_export_count;
extern char **g_imported_packages;
extern int g_imported_pkg_count;
extern ASTNode **g_hoisted_funcs;
extern int g_hoisted_count;
extern int g_funlit_counter;
extern const char *g_parse_filename;

void set_current_package(const char *name);
void add_function(ASTNode *fn);
ASTNode *find_function(const char *name);
void add_typename(const char *name);
int is_user_typename(const char *name);
void add_structdef(char *name, ASTNode **members, int member_count);
StructDef *find_structdef(const char *name);
void parser_reset(void);
void parser_set_filename(const char *name);
void add_export(const char *orig, const char *mangled);
const char *find_export_mangled(const char *orig);
int is_imported_package(const char *name);
char *mangle(const char *pkg, const char *name);

#endif
