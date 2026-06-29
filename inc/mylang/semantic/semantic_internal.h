#ifndef MYLANG_SEMANTIC_INTERNAL_H
#define MYLANG_SEMANTIC_INTERNAL_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mylang/semantic/semantic.h"
#include "mylang/semantic/semantic_types.h"

typedef struct {
    int line;
    int col;
} SemanticLocation;

typedef enum {
    SEMANTIC_DIAG_ERROR = 1,
    SEMANTIC_DIAG_NOTE = 2,
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
    const char *borrowed_from;
    int borrow_is_mut;
    int shared_borrow_count;
    int mutable_borrow_active;
    SemanticLocation last_shared_borrow_loc;
    SemanticLocation last_mut_borrow_loc;
} SemanticBinding;

typedef struct {
    const char *name;
    long value;
} SemanticEnumValue;

typedef struct {
    const char *name;
    int param_count;
    int fixed_param_count;
    int is_variadic;
    int is_imported;
    SemanticLocation decl_loc;
} SemanticFunctionSig;

typedef struct {
    const char *filename;
    int error_count;
    int diagnostic_count;
    SemanticDiagnostic diagnostics[512];
    int scope_depth;
    int function_depth;
    ASTNode *current_function;
    int binding_count;
    SemanticBinding bindings[256];
    int enum_type_count;
    const char *enum_types[128];
    int enum_value_count;
    SemanticEnumValue enum_values[512];
    int function_sig_count;
    SemanticFunctionSig function_sigs[256];
    int user_type_count;
    const char *user_types[256];
} SemanticContext;

SemanticLocation semantic_location_unknown(void);
SemanticLocation semantic_location_from_ast(ASTNode *node);
void semantic_error_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...);
void semantic_error_code_at(SemanticContext *ctx, SemanticLocation loc, const char *code, const char *fmt, ...);
void semantic_note_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...);
void semantic_emit_diagnostics(SemanticContext *ctx);
void semantic_walk_ast(SemanticContext *ctx, ASTNode *node);

#endif
