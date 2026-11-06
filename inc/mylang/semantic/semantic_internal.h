#ifndef MYLANG_SEMANTIC_INTERNAL_H
#define MYLANG_SEMANTIC_INTERNAL_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mylang/semantic/semantic.h"
#include "mylang/semantic/semantic_types.h"

typedef struct FrontendSession FrontendSession;

#define SEMANTIC_MAX_FUNCTION_PARAMS 32

typedef struct { int line; int col; int end_line; int end_col; } SemanticLocation;

typedef enum {
    SEMANTIC_DIAG_ERROR = 1,
    SEMANTIC_DIAG_NOTE = 2,
    SEMANTIC_DIAG_WARNING = 3,
} SemanticDiagnosticSeverity;

typedef struct {
    SemanticDiagnosticSeverity severity;
    SemanticLocation loc;
    const char *code;
    /* The file the location is in, when it is not the one being compiled:
     * the body of a generic copied from another module. */
    const char *file;
    char message[256];
} SemanticDiagnostic;

typedef struct {
    const char *name;
    int is_copy;
    int moved;
    int scope_depth;
    int is_param;
    int is_global;
    int has_type;
    SemanticTypeInfo type_info;
    SemanticLocation decl_loc;
    SemanticLocation move_loc;
    /* A parameter: `move T x`, written in the function's body, and a plain
     * parameter of a type that cannot be copied, which can only be read. */
    int param_is_move;
    int param_is_written;
    int reads_owned_value;
    const char *borrowed_from;  /* root owner this local borrows, or NULL */
    /* Derived from another borrow (`borrow T r2 = r1;`, `r1.at(0)`): the
     * owner's counts belong to that borrow, not to this one. */
    int borrow_is_reborrow;
    /* Holds a borrow whose owner could not be determined. */
    int borrow_origin_unknown;
    /* The borrow this local's borrow was taken through (a `borrow` parameter
     * or local), which stays borrowed for as long as this one does. */
    const char *reborrowed_via;
    /* How many arguments of the call being checked read this value in place:
     * an aggregate travels as an address, so `&` of it in the same call would
     * overlap (rule B8). */
    int read_in_place_arg_count;
    int borrow_active;
    /* A local holds a borrow of this value, so the value itself cannot be
     * used until that local goes out of scope. Unlike borrow_active, the
     * borrows a call argument takes for the duration of the call do not set
     * it. */
    int borrow_held;
    /* A `str` taken from a local's own storage: it may not be returned. */
    int str_views_local;
    SemanticLocation last_borrow_loc;
} SemanticBinding;

/* What a loop needs to know to reject a value moved by one iteration and used
 * by the next: which bindings existed before it, which of those were already
 * moved, and which were moved at a `continue`. */
typedef struct SemanticLoopFrame {
    int binding_count;
    unsigned char moved_before[256];
    unsigned char moved_at_continue[256];
    SemanticLocation continue_move_loc[256];
    struct SemanticLoopFrame *outer;
} SemanticLoopFrame;

/* `enum_name` is the declaring enum, so a match can list the members it misses. */
typedef struct { const char *name; long value; const char *enum_name; } SemanticEnumValue;
typedef struct { const char *name; ASTNode *base_type; } SemanticNewtype;

typedef struct {
    const char *name;
    int param_count;
    int fixed_param_count;
    int is_variadic;
    int is_imported;
    int from_unsafe_module;
    int has_return_type;
    int has_param_types;
    SemanticTypeInfo return_type;
    SemanticTypeInfo param_types[SEMANTIC_MAX_FUNCTION_PARAMS];
    const char *param_names[SEMANTIC_MAX_FUNCTION_PARAMS];
    int param_borrow_kinds[SEMANTIC_MAX_FUNCTION_PARAMS];
    int param_is_move[SEMANTIC_MAX_FUNCTION_PARAMS];
    ASTNode *declaration;
    SemanticLocation decl_loc;
} SemanticFunctionSig;

#define SEMANTIC_MAX_STRUCT_MEMBERS 64

typedef struct {
    const char *name;
    SemanticTypeInfo type;
} SemanticStructMember;

typedef struct {
    const char *name;
    SemanticStructMember members[SEMANTIC_MAX_STRUCT_MEMBERS];
    int member_count;
} SemanticStructLayout;

typedef struct {
    const char *filename;
    FrontendSession *session;
    SemanticSafetyProfile safety_profile;
    /* Raw-pointer operations in a checked source (W0003): the first few are
     * reported where they are, the rest counted into one summary. */
    int unsafe_operation_count;
    const ASTNode *unsafe_index_operand; /* `p + i` already reported as `p[i]` */
    int error_count;
    int warning_count;
    int warnings_as_errors;
    int diagnostic_count;
    SemanticDiagnostic diagnostics[512];
    int scope_depth;
    int function_depth;
    int defer_depth;
    /* The innermost loop being walked, or NULL. */
    SemanticLoopFrame *loop;
    /* Walking the operand of `&`: the borrow checks report a
     * conflict there, so a use of the operand is not reported again. */
    int in_borrow_operand;
    ASTNode *current_function;
    /* While walking a function copied from another module's generic, the
     * file it was written in and whether that file is `.unsafe.mln`
     * (fundef.origin_path / origin_unsafe); NULL otherwise. */
    const char *origin_path;
    int origin_unsafe;
    int binding_count;
    SemanticBinding bindings[256];
    int enum_type_count;
    const char *enum_types[128];
    int enum_value_count;
    SemanticEnumValue enum_values[512];
    int function_sig_count;
    /* Own + imported functions of one module. dom.mln alone imports graphics,
     * theme, debug, heap, serial and scheduler, which together with its own
     * functions passed 256 (MYOS-014). */
    SemanticFunctionSig function_sigs[512];
    int user_type_count;
    const char *user_types[256];
    int newtype_count;
    SemanticNewtype newtypes[128];
    /* Struct layouts, so a member access can be given a type. Without them
     * `p.a = "no"` had no left-hand type to compare against and the assignment
     * check returned early, which also let an entirely unknown field through. */
    int struct_layout_count;
    SemanticStructLayout struct_layouts[256];
    int imported_package_count;
    char *imported_packages[64];
} SemanticContext;

typedef enum {
    EXPRCTX_READ = 0,
    EXPRCTX_MOVE,
    EXPRCTX_WRITE,
} ExprContext;

/* A write to a place: the left side of `=`, the operand of `++` / `--`, or of
 * `&`. */
typedef enum { WRITE_ASSIGN, WRITE_STEP, WRITE_BORROW } WriteKind;

typedef struct {
    int binding_count;
    SemanticBinding bindings[256];
} SemanticBindingSnapshot;

/* The states around a two-way branch. Each is a copy of the whole binding
 * table and branches nest as deep as the code does, so they live on the heap
 * rather than the walker's stack. */
typedef struct {
    SemanticBindingSnapshot base;
    SemanticBindingSnapshot then_state;
    SemanticBindingSnapshot else_state;
} BranchSnapshots;

static inline ASTNode *semantic_as_identifier(ASTNode *node) {
    return (node && node->type == AST_IDENTIFIER) ? node : NULL;
}

static inline ASTNode *semantic_as_var_decl(ASTNode *node) {
    return (node && node->type == AST_VAR_DECL) ? node : NULL;
}

static inline ASTNode *semantic_as_param(ASTNode *node) {
    return (node && node->type == AST_PARAM) ? node : NULL;
}

/* semantic_error.c */
SemanticLocation semantic_location_unknown(void);
SemanticLocation semantic_location_from_ast(ASTNode *node);
void semantic_error_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...);
void semantic_error_code_at(SemanticContext *ctx, SemanticLocation loc, const char *code, const char *fmt, ...);
void semantic_warning_code_at(SemanticContext *ctx, SemanticLocation loc, const char *code, const char *fmt, ...);
void semantic_note_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...);
void semantic_emit_diagnostics(SemanticContext *ctx);

/* semantic_flow.c */
int semantic_stmt_completes(SemanticContext *ctx, ASTNode *node);
void semantic_check_function_end(SemanticContext *ctx, ASTNode *fn);

/* semantic_symbols.c */
int semantic_enum_type_exists(SemanticContext *ctx, const char *name);
int semantic_find_enum_value(SemanticContext *ctx, const char *name, long *out_value);
int semantic_is_builtin_call(const char *name);
SemanticFunctionSig *semantic_find_function_sig(SemanticContext *ctx, const char *name);
SemanticNewtype *semantic_find_newtype(SemanticContext *ctx, const char *name);
void semantic_register_imported_package(SemanticContext *ctx, const char *name);
int semantic_call_may_be_package_import(SemanticContext *ctx, const char *name);
void semantic_register_enum(SemanticContext *ctx, ASTNode *node);
void semantic_collect_function_sigs(SemanticContext *ctx, ASTNode *node);
const SemanticStructMember *semantic_find_struct_member(SemanticContext *ctx,
                                                        const char *struct_name,
                                                        const char *member_name);
int semantic_struct_is_known(SemanticContext *ctx, const char *struct_name);
void semantic_collect_imported_globals(SemanticContext *ctx, ASTNode *node);
void semantic_collect_user_types(SemanticContext *ctx, ASTNode *node);
void semantic_check_type_exists(SemanticContext *ctx, ASTNode *type_node);

/* semantic_bindings.c */
int semantic_location_is_known(SemanticLocation loc);
int semantic_binding_owns_value(const SemanticBinding *binding);
void semantic_note_binding_decl_if_known(SemanticContext *ctx, SemanticBinding *binding,
                                         const char *what);
SemanticBinding *semantic_find_binding(SemanticContext *ctx, const char *name);
void semantic_snapshot_bindings(SemanticContext *ctx, SemanticBindingSnapshot *snapshot);
void semantic_restore_bindings(SemanticContext *ctx, const SemanticBindingSnapshot *snapshot);
void semantic_merge_if_binding_states(SemanticContext *ctx, const SemanticBindingSnapshot *base,
                                      const SemanticBindingSnapshot *then_state,
                                      const SemanticBindingSnapshot *else_state);
void semantic_enter_scope(SemanticContext *ctx);
void semantic_leave_scope(SemanticContext *ctx);
void semantic_declare_binding(SemanticContext *ctx, const char *name, ASTNode *type_node,
                              int is_copy, int is_param, SemanticLocation decl_loc);
void semantic_revive_binding_if_identifier(SemanticContext *ctx, ASTNode *node);

/* semantic_type_rules.c */
int semantic_typeinfo_is_copy(SemanticContext *ctx, const SemanticTypeInfo *info);
int semantic_typeinfo_has_drop(SemanticContext *ctx, const SemanticTypeInfo *info);
int semantic_type_is_copy(SemanticContext *ctx, ASTNode *type_node);
int semantic_type_is_void(ASTNode *type_node);
int semantic_typeinfo_is_integer_like_or_enum(SemanticContext *ctx, const SemanticTypeInfo *info);
int semantic_function_type_parts(const SemanticTypeInfo *info, ASTNode ***params, int *param_count,
                                 ASTNode **return_type, int *is_variadic);
ASTNode *semantic_function_param_type(ASTNode *param, int declaration_form);
void semantic_typeinfo_format(const SemanticTypeInfo *info, char *buf, size_t buf_size);
int semantic_typeinfo_same_base(const SemanticTypeInfo *a, const SemanticTypeInfo *b);
int semantic_literal_to_legacy_c_string(const SemanticTypeInfo *expected,
                                        const SemanticTypeInfo *actual, ASTNode *expr);
int semantic_null_function_literal(const SemanticTypeInfo *expected, ASTNode *expr);
int semantic_default_of_newtype(const SemanticTypeInfo *expected, ASTNode *expr);
int semantic_typeinfo_compatible(SemanticContext *ctx, const SemanticTypeInfo *expected,
                                 const SemanticTypeInfo *actual);
int semantic_call_arg_compatible(SemanticContext *ctx, const SemanticTypeInfo *expected,
                                 const SemanticTypeInfo *actual);
void semantic_report_type_mismatch(SemanticContext *ctx, SemanticLocation loc, const char *code,
                                   const char *what, const SemanticTypeInfo *expected,
                                   const SemanticTypeInfo *actual);

/* semantic_infer.c */
int semantic_binary_is_comparison(TokenKind op);
int semantic_binary_is_logical(TokenKind op);
int semantic_binary_is_arithmetic(TokenKind op);
int semantic_infer_expr_type(SemanticContext *ctx, ASTNode *expr, SemanticTypeInfo *out);

/* semantic_check.c */
void semantic_check_return_type(SemanticContext *ctx, ASTNode *return_node);
void semantic_check_binary_type(SemanticContext *ctx, ASTNode *node);
void semantic_check_assignment_type(SemanticContext *ctx, ASTNode *node);
void semantic_check_initializer_type(SemanticContext *ctx, ASTNode *node);
void semantic_check_condition_type(SemanticContext *ctx, ASTNode *cond);
void semantic_check_struct_literal(SemanticContext *ctx, ASTNode *node);
void semantic_check_call_signature(SemanticContext *ctx, ASTNode *node);
void semantic_check_constant_index(SemanticContext *ctx, ASTNode *node);
void semantic_check_dereference(SemanticContext *ctx, ASTNode *node);

/* semantic_borrow.c */
void semantic_check_borrow_kept_as_pointer(SemanticContext *ctx, const SemanticTypeInfo *expected,
                                           const SemanticTypeInfo *actual, ASTNode *at);
SemanticBinding *semantic_borrow_target_binding(SemanticContext *ctx, ASTNode *expr);
void semantic_release_borrow(SemanticContext *ctx, SemanticBinding *binding);
void semantic_register_borrow_binding(SemanticContext *ctx, ASTNode *binding_node);
void semantic_hold_payload_borrow(SemanticContext *ctx, ASTNode *assign);
void semantic_check_returned_borrow(SemanticContext *ctx, ASTNode *return_node);
void semantic_check_write_place(SemanticContext *ctx, ASTNode *place, WriteKind kind);
int semantic_expr_views_local(SemanticContext *ctx, ASTNode *expr);
void semantic_check_returned_str(SemanticContext *ctx, ASTNode *node);

/* semantic_unsafe.c */
void semantic_check_unsafe_call(SemanticContext *ctx, ASTNode *node,
                                const SemanticFunctionSig *sig);
int semantic_in_unsafe_source(SemanticContext *ctx);
void semantic_report_unsafe_operation(SemanticContext *ctx, ASTNode *at, const char *what);
void semantic_check_unsafe_operation(SemanticContext *ctx, ASTNode *node);
void semantic_report_remaining_unsafe_operations(SemanticContext *ctx, ASTNode *root);

/* semantic_mock.c */
int semantic_mock_return_uses_hidden_buffer(SemanticContext *ctx, const SemanticTypeInfo *type);
void semantic_check_mock_stored_return(SemanticContext *ctx, ASTNode *call);
void semantic_check_mock_abi_limit(SemanticContext *ctx, ASTNode *call);
void semantic_check_mock_callback_signature(SemanticContext *ctx, ASTNode *call);
int semantic_is_mock_call_original_expr(ASTNode *expr);

/* semantic_walk_expr.c */
void semantic_walk_case(SemanticContext *ctx, ASTNode *node, int allow_noop);
void semantic_walk_expr(SemanticContext *ctx, ASTNode *node, ExprContext expr_ctx);

/* semantic_walk_stmt.c */
void semantic_walk_stmt(SemanticContext *ctx, ASTNode *node);
void semantic_walk_ast(SemanticContext *ctx, ASTNode *node);

#endif
