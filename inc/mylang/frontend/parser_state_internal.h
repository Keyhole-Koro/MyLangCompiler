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

typedef struct GenericTemplateTable {
    ASTNode **declarations;
    int count;
} GenericTemplateTable;

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

typedef struct EnumConstant {
    char *name;
    long value;
} EnumConstant;

typedef struct ParserSymbolState {
    StructTable structs;
    FunctionTable functions;
    TypeTable types;
    GenericTemplateTable generic_templates;
    EnumConstant *enum_constants;
    int enum_constant_count;
} ParserSymbolState;

typedef struct ParserModuleState {
    char *current_package;
    int current_package_heap;
    ExportEntry *exports;
    int export_count;
    char **imported_packages;
    int imported_package_count;
    const char *filename;
} ParserModuleState;

typedef struct ParserControlState {
    int generic_decl_depth;
    const char *current_generic_function_name;
    int stop_at_arrow;
    int unchecked_depth;
} ParserControlState;

typedef struct ParserLoweringState {
    ASTNode **hoisted_functions;
    int hoisted_function_count;
    int function_literal_counter;
    int dom_node_counter;
    ASTNode *dom_program;
} ParserLoweringState;

/* One complete parser session. Nested module parsing switches the active
 * context as one unit, so parser state never needs a field-by-field snapshot. */
typedef struct ParserContext {
    Token *token_head;
    ParserSymbolState symbols;
    ParserModuleState module;
    ParserControlState control;
    ParserLoweringState lowering;
} ParserContext;

extern const char g_default_package[];

/* Parser state has one owner. Parsing an imported module temporarily
 * activates another context instead of copying a collection of globals. */
ParserContext *parser_context_current(void);
void parser_context_init(ParserContext *context);
ParserContext *parser_context_activate(ParserContext *context);

void set_current_package(const char *name);
void add_function(ASTNode *fn);
ASTNode *find_function(const char *name);
void add_typename(const char *name);
int is_user_typename(const char *name);
int typename_scope_mark(void);
void restore_typenames(int mark);
void add_generic_template(ASTNode *declaration);
ASTNode *find_generic_type_template(const char *name);
ASTNode *find_generic_function_template(const char *name);
ASTNode *generic_template_at(int index);
int generic_template_count(void);
void add_structdef(char *name, ASTNode **members, int member_count);
StructDef *find_structdef(const char *name);
void add_enum_constant(const char *name, long value);
int find_enum_constant(const char *name, long *out_value);
void parser_reset(void);
void parser_set_filename(const char *name);
void add_export(const char *orig, const char *mangled);
const char *find_export_mangled(const char *orig);
int is_imported_package(const char *name);
char *mangle(const char *pkg, const char *name);

#endif
