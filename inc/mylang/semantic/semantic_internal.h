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
    const char *borrowed_from;  /* root owner this local borrows, or NULL */
    int borrow_is_mut;
    /* Derived from another borrow (`borrow T r2 = r1;`, `r1.at(0)`): the
     * owner's counts belong to that borrow, not to this one. */
    int borrow_is_reborrow;
    /* Holds a borrow whose owner could not be determined. */
    int borrow_origin_unknown;
    int shared_borrow_count;
    int mutable_borrow_active;
    SemanticLocation last_shared_borrow_loc;
    SemanticLocation last_mut_borrow_loc;
} SemanticBinding;

typedef struct { const char *name; long value; } SemanticEnumValue;
typedef struct { const char *name; ASTNode *base_type; } SemanticNewtype;

typedef struct {
    const char *name;
    int param_count;
    int fixed_param_count;
    int is_variadic;
    int is_imported;
    int has_return_type;
    int has_param_types;
    SemanticTypeInfo return_type;
    SemanticTypeInfo param_types[SEMANTIC_MAX_FUNCTION_PARAMS];
    const char *param_names[SEMANTIC_MAX_FUNCTION_PARAMS];
    int param_borrow_kinds[SEMANTIC_MAX_FUNCTION_PARAMS];
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
    ASTNode *current_function;
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

void semantic_register_imported_package(SemanticContext *ctx, const char *name);

SemanticLocation semantic_location_unknown(void);
SemanticLocation semantic_location_from_ast(ASTNode *node);
void semantic_error_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...);
void semantic_error_code_at(SemanticContext *ctx, SemanticLocation loc, const char *code, const char *fmt, ...);
void semantic_warning_code_at(SemanticContext *ctx, SemanticLocation loc, const char *code, const char *fmt, ...);
void semantic_note_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...);
void semantic_emit_diagnostics(SemanticContext *ctx);
void semantic_walk_ast(SemanticContext *ctx, ASTNode *node);

#endif
