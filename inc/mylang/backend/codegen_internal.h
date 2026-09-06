#ifndef MYLANG_BACKEND_CODEGEN_INTERNAL_H
#define MYLANG_BACKEND_CODEGEN_INTERNAL_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mylang/backend/codegen.h"
#include "mylang/type/type_info.h"

#define SLOT_SIZE 4

typedef struct FrontendSession FrontendSession;

typedef struct {
    const char *name;
    int offset;
    int size_bytes;
    int total_size_bytes;
    const char *base_type;
    int pointer_level;
    int is_array;
    int array_length;
} MemberInfo;

typedef struct {
    const char *type_name;
    MemberInfo *members;
    int member_count;
    int size_bytes;
} StructInfo;

typedef struct {
    const char *name;
    const char *base_type;
    int pointer_level;
    int type_modifiers;
    int is_array;
    int array_length;
    int dims[8];
    int dims_count;
} LocalInfo;

typedef MylangType TypeInfo;

typedef struct {
    char *text;
    char *label;
} StrItem;

// A 32-bit constant parked in the data section. `movi` carries only a 21-bit
// immediate, so anything wider is loaded from here instead.
typedef struct {
    long value;
    char *label;
} ConstItem;

typedef struct {
    const char *name;
    int param_count;
    int fixed_param_count;
    bool is_variadic;
    // A struct or array returned/taken by value has no register wide enough
    // to hold it, so the calling convention passes its address instead (see
    // MLC-015: gen_func reserves a hidden out-pointer slot for ret_is_aggregate,
    // and gen_call passes &arg rather than arg's value for a param this marks).
    // ret_size_bytes is 0 exactly when ret_is_aggregate is false.
    bool ret_is_aggregate;
    int ret_size_bytes;
    bool *param_is_aggregate; // param_count entries, or NULL if param_count == 0
} FunctionSig;

typedef struct {
    const char *name;
    long value;
} EnumValueInfo;

typedef struct {
    const char *alias;
    TypeInfo info;
} TypedefInfo;

typedef struct {
    FrontendSession *session;
    StructInfo *structs;
    int struct_count;
    TypedefInfo *typedefs;
    int typedef_count;
    LocalInfo *globals_info;
    int globals_count;
    LocalInfo *locals_info;
    int locals_count;
    StrItem *strings;
    int string_count;
    ConstItem *consts;
    int const_count;
    StringBuilder data_sb;
    int data_sb_inited;
    int label_counter;
    const char *return_label;
    char **defined_funcs;
    int defined_func_count;
    char **imports;
    int import_count;
    FunctionSig *func_sigs;
    int func_sig_count;
    ASTNode *current_func;
    EnumValueInfo *enum_values;
    int enum_value_count;
    // Set for the duration of gen_func when the function being compiled
    // returns an aggregate by value: sret_offset is where its hidden
    // out-pointer parameter (passed in r4) is stashed in the frame, and
    // sret_size_bytes is how much a `return expr;` there must copy through it.
    bool sret_active;
    int sret_offset;
    int sret_size_bytes;
} CompilerContext;

#define cg_structs        (cc->structs)
#define cg_struct_count   (cc->struct_count)
#define cg_typedefs       (cc->typedefs)
#define cg_typedef_count  (cc->typedef_count)
#define cg_globals_info   (cc->globals_info)
#define cg_globals_count  (cc->globals_count)
#define cg_locals_info    (cc->locals_info)
#define cg_locals_count   (cc->locals_count)
#define cg_strings        (cc->strings)
#define cg_string_count   (cc->string_count)
#define cg_consts         (cc->consts)
#define cg_const_count    (cc->const_count)
#define cg_data_sb        (cc->data_sb)
#define cg_data_sb_inited (cc->data_sb_inited)

extern const char *arg_regs[];

static inline ASTNode *cg_as_block(ASTNode *node) {
    return (node && node->type == AST_BLOCK) ? node : NULL;
}

static inline ASTNode *cg_as_fundef(ASTNode *node) {
    return (node && node->type == AST_FUNDEF) ? node : NULL;
}

static inline ASTNode *cg_as_var_decl(ASTNode *node) {
    return (node && node->type == AST_VAR_DECL) ? node : NULL;
}

static inline ASTNode *cg_as_type_array(ASTNode *node) {
    return (node && node->type == AST_TYPE_ARRAY) ? node : NULL;
}

void codegen_set_entry(const char *name);
void codegen_set_source_path(const char *path);
const char *codegen_current_source_path(void);
int is_entry_name(const char *name);
int next_label(CompilerContext *cc);
void note_defined_func(CompilerContext *cc, const char *name);
bool func_is_defined(CompilerContext *cc, const char *name);
int is_codegen_builtin(const char *name);
ASTNode *cg_current_fundef_node(CompilerContext *cc);
int cg_current_rest_info(CompilerContext *cc, const char *name, int *out_rest_index, int *out_fixed_count);
int cg_rest_stack_base(CompilerContext *cc, const char *name, int *out_rest_stack_base);
const FunctionSig *find_func_sig(CompilerContext *cc, const char *name);
const EnumValueInfo *find_enum_value(CompilerContext *cc, const char *name);
void note_import_func(CompilerContext *cc, const char *name);
void collect_imports_from_toplevel(CompilerContext *cc, ASTNode *root);
void build_codegen_toplevel_info(CompilerContext *cc, ASTNode *root);
void collect_codegen_globals(CompilerContext *cc, ASTNode *root);
void emit_codegen_functions(CompilerContext *cc, ASTNode *root, StringBuilder *sb);
char *prepend_codegen_imports(CompilerContext *cc, StringBuilder *body);
void cleanup_codegen_context(CompilerContext *cc);
const char *intern_string_literal(CompilerContext *cc, const char *s);
const char *intern_word_constant(CompilerContext *cc, long value);
void emit_load_const(CompilerContext *cc, StringBuilder *sb, const char *target_reg, long value);

int param_offset(int n);
int local_offset(int param_count, int n);
int param_index(const char *name, char **params, int param_count);
int local_index_last(const char *name, char **locals, int local_count);
int find_name(char **arr, int count, const char *name);

const TypedefInfo *find_typedef(CompilerContext *cc, const char *alias);
void resolve_type(CompilerContext *cc, TypeInfo *ti);
const StructInfo *find_struct(CompilerContext *cc, const char *type_name);
const MemberInfo *find_member_info(CompilerContext *cc, const char *type_name, const char *member);
int base_type_is_char(const char *name);
int ast_type_is_char_scalar(ASTNode *type_node);
int is_char_scalar_var(CompilerContext *cc, const char *name);
int scalar_var_width_bytes(CompilerContext *cc, const char *name);
int typeinfo_is_byte(const TypeInfo *info);
int typeinfo_scalar_width_bytes(const TypeInfo *info);
int infer_expr_type(CompilerContext *cc, ASTNode *expr, TypeInfo *out);
int typeinfo_elem_size_bytes(CompilerContext *cc, const TypeInfo *info);
int typeinfo_total_size_bytes(CompilerContext *cc, const TypeInfo *info);
int pointer_step_bytes(CompilerContext *cc, const TypeInfo *info);
int array_element_size_bytes(ASTNode *array_type);
int array_total_elements(ASTNode *array_type);
int lvalue_is_byte(CompilerContext *cc, ASTNode *node);
int lvalue_width_bytes(CompilerContext *cc, ASTNode *node);
int lvalue_is_const(CompilerContext *cc, ASTNode *node);
const LocalInfo *find_local_info(CompilerContext *cc, const char *name);
const LocalInfo *find_global_info(CompilerContext *cc, const char *name);
void set_localinfo_from_type(CompilerContext *cc, LocalInfo *info, ASTNode *type_node);
int typeinfo_from_type_ast(CompilerContext *cc, ASTNode *type_node, TypeInfo *out);
int collect_local_type_info(CompilerContext *cc, ASTNode *node, LocalInfo *arr);
int slots_for_type(CompilerContext *cc, ASTNode *type_node);
int collect_locals(CompilerContext *cc, ASTNode *node, char **locals);
int find_var_offset(const char *name, char **params, int param_count, char **locals, int local_count, int *is_param);
int is_comparison_op(TokenKind op);

void ensure_data_section(CompilerContext *cc);
void emit_zero_bytes(StringBuilder *sb, int count);
void emit_global_init(CompilerContext *cc, StringBuilder *sb, ASTNode *init_expr,
                      int expected_bytes, int elem_bytes);
void emit_global_decl(CompilerContext *cc, ASTNode *var_decl);

void emit_load_from_addr(StringBuilder *sb, const char *target_reg, const char *addr_reg, int is_byte);
void emit_load_width_from_addr(StringBuilder *sb, const char *target_reg, const char *addr_reg, int width_bytes);
void emit_store_to_addr(StringBuilder *sb, const char *addr_reg, const char *value_reg, int is_byte);
void emit_store_width_to_addr(StringBuilder *sb, const char *addr_reg, const char *value_reg, int width_bytes);
void emit_scale_reg_const(CompilerContext *cc, StringBuilder *sb, const char *reg, long factor);
void emit_unary_inc_dec(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg, char **params, int param_count, char **locals, int local_count);
void emit_load_var(CompilerContext *cc, StringBuilder *sb, const char *name, const char *target_reg, char **params, int param_count, char **locals, int local_count);
void emit_store_var(CompilerContext *cc, StringBuilder *sb, const char *name, const char *src_reg, char **params, int param_count, char **locals, int local_count);
void emit_addr_of_var(CompilerContext *cc, StringBuilder *sb, const char *name, const char *target_reg, char **params, int param_count, char **locals, int local_count);
void emit_cond_jump(CompilerContext *cc, ASTNode *left, ASTNode *right, TokenKind op, StringBuilder *sb, char **params, int param_count, char **locals, int local_count, const char *trueLabel, const char *falseLabel);
void gen_lvalue_addr(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg, char **params, int param_count, char **locals, int local_count);
void gen_expr(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg, char **params, int param_count, char **locals, int local_count);
void _gen_expr(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg, char **params, int param_count, char **locals, int local_count, int want_address);
void gen_expr_binop(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg, char **params, int param_count, char **locals, int local_count);
void gen_call(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg, char **params, int param_count, char **locals, int local_count);
void gen_call_sret(CompilerContext *cc, ASTNode *node, StringBuilder *sb, char **params, int param_count, char **locals, int local_count);
void gen_assign(CompilerContext *cc, ASTNode *node, StringBuilder *sb, char **params, int param_count, char **locals, int local_count, const char *target_reg);
void gen_struct_literal_into_addr(CompilerContext *cc, ASTNode *literal,
                                  StringBuilder *sb, const char *dest_addr_reg,
                                  char **params, int param_count,
                                  char **locals, int local_count);

// -- Aggregate (struct/array) by-value calling convention (MLC-015) --
// Bytes occupied by `type_ast` when passed/returned as a whole aggregate, or
// 0 if it is an ordinary scalar/pointer.
int aggregate_type_size(CompilerContext *cc, ASTNode *type_ast);
// Forms gen_lvalue_addr can take the address of: an identifier, a member or
// arrow chain rooted in one, or a dereference. Every aggregate argument,
// aggregate return source, and sret destination has to be one of these.
int is_addressable_expr(ASTNode *node);
// True when `name` is a struct/array PARAMETER of the function currently
// being compiled. Its slot holds the hidden pointer the caller supplied
// rather than the aggregate's own bytes; see emit_addr_of_var.
int is_byval_aggregate_param(CompilerContext *cc, const char *name, char **params, int param_count);
// node's signature when node is a direct call to a function returning a
// struct or array by value, or NULL otherwise (not a call, or an ordinary
// scalar/pointer return).
const FunctionSig *call_returns_aggregate(CompilerContext *cc, ASTNode *node);
// Copies total_bytes from [src_addr_reg] to [dest_addr_reg], word by word
// with a byte tail. Clobbers r1 and r4; neither address register may be one
// of those.
void emit_aggregate_copy(StringBuilder *sb, const char *dest_addr_reg, const char *src_addr_reg, int total_bytes);

void gen_if(CompilerContext *cc, ASTNode *node, StringBuilder *sb, char **params, int param_count, char **locals, int local_count, const char *break_label, const char *continue_label);
void gen_for(CompilerContext *cc, ASTNode *node, StringBuilder *sb, char **params, int param_count, char **locals, int local_count, const char *break_label, const char *continue_label);
void gen_while(CompilerContext *cc, ASTNode *node, StringBuilder *sb, char **params, int param_count, char **locals, int local_count, const char *break_label, const char *continue_label);
void gen_do_while(CompilerContext *cc, ASTNode *node, StringBuilder *sb, char **params, int param_count, char **locals, int local_count, const char *break_label, const char *continue_label);
void gen_stmt(CompilerContext *cc, ASTNode *node, StringBuilder *sb, char **params, int param_count, char **locals, int local_count);
void gen_stmt_internal(CompilerContext *cc, ASTNode *node, StringBuilder *sb, char **params, int param_count, char **locals, int local_count, const char *break_label, const char *continue_label);
void gen_func(CompilerContext *cc, ASTNode *node, StringBuilder *sb);

#endif
