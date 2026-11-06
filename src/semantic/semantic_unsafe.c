#include "mylang/semantic/semantic_internal.h"
#include "mylang/semantic/diagnostic_codes.h"

/* What a checked source may not do: raw-pointer operations and calls into
 * unsafe code. */

/* Rule U4: an `.unsafe.mln` file's functions are out of a checked file's
 * reach unless a person vouched for them with `@safe`. A function that takes
 * an address as an i32 passes only values, so its signature cannot tell. */
void semantic_check_unsafe_call(SemanticContext *ctx, ASTNode *node, const SemanticFunctionSig *sig) {
    const ASTNode *decl = sig->declaration;
    int fn = decl && decl->type == AST_FUNDEF;
    if (fn && decl->fundef.is_safe) return;
    if (!sig->from_unsafe_module && !(fn && decl->fundef.origin_unsafe)) return;
    char what[160];
    snprintf(what, sizeof what, "calling '%s', which is not @safe,", node->call.name);
    semantic_report_unsafe_operation(ctx, node, what);
}

/* ---- raw pointers outside `.unsafe.mln` ------------------------------- */

#ifndef UNSAFE_OPERATIONS_REPORTED
#define UNSAFE_OPERATIONS_REPORTED 8
#endif

/* The code being walked was written in an `.unsafe.mln` file: this file, or
 * for a generic copied from another module, the file it came from. */
int semantic_in_unsafe_source(SemanticContext *ctx) {
    if (ctx->origin_path) return ctx->origin_unsafe;
    return ctx->safety_profile == SEMANTIC_SAFETY_UNSAFE;
}

static int semantic_is_raw_pointer(SemanticContext *ctx, ASTNode *expr) {
    SemanticTypeInfo type;
    if (!semantic_infer_expr_type(ctx, expr, &type)) return 0;
    return type.pointer_level > 0 && type.borrow_kind == REFKIND_NONE && !type.is_array &&
           !type.is_function;
}

static int semantic_type_ast_is_raw_pointer(ASTNode *type_node) {
    SemanticTypeInfo type;
    if (!semantic_typeinfo_from_type_ast(type_node, &type)) return 0;
    return type.pointer_level > 0 && type.borrow_kind == REFKIND_NONE && !type.is_array &&
           !type.is_function;
}

void semantic_report_unsafe_operation(SemanticContext *ctx, ASTNode *at, const char *what) {
    if (semantic_in_unsafe_source(ctx)) return;
    if (ctx->unsafe_operation_count++ >= UNSAFE_OPERATIONS_REPORTED) return;
    semantic_error_code_at(ctx, semantic_location_from_ast(at), SEMCODE_UNSAFE_OPERATION,
                           "%s outside an .unsafe.mln file", what);
}

/* `*p`, `p[i]`, `p->x` through a raw pointer, `p + n`, and casts to or from
 * a pointer are unchecked memory access. A `borrow` and an array are not raw
 * pointers. */
void semantic_check_unsafe_operation(SemanticContext *ctx, ASTNode *node) {
    if (!node || semantic_in_unsafe_source(ctx)) return;
    switch (node->type) {
    case AST_UNARY: {
        if (node->unary.op != ASTARISK) return;
        ASTNode *operand = node->unary.operand;
        if (operand && operand->type == AST_BINARY &&
            (operand->binary.op == ADD || operand->binary.op == SUB)) {
            /* `a[i]` is `*(a + i)`: an array's own index is not a raw
             * pointer's. */
            ctx->unsafe_index_operand = operand;
            if (semantic_is_raw_pointer(ctx, operand->binary.left))
                semantic_report_unsafe_operation(ctx, node, "indexing a raw pointer");
            return;
        }
        if (semantic_is_raw_pointer(ctx, operand)) {
            semantic_report_unsafe_operation(ctx, node, "dereferencing a raw pointer");
        }
        return;
    }
    case AST_ARROW_ACCESS:
        if (semantic_is_raw_pointer(ctx, node->arrow_access.lhs))
            semantic_report_unsafe_operation(ctx, node, "'->' through a raw pointer");
        return;
    case AST_BINARY:
        if (node == ctx->unsafe_index_operand) return;
        if ((node->binary.op == ADD || node->binary.op == SUB) &&
            (semantic_is_raw_pointer(ctx, node->binary.left) ||
             semantic_is_raw_pointer(ctx, node->binary.right)))
            semantic_report_unsafe_operation(ctx, node, "pointer arithmetic");
        return;
    case AST_CAST:
        if (semantic_type_ast_is_raw_pointer(node->cast.type) ||
            semantic_is_raw_pointer(ctx, node->cast.expr))
            semantic_report_unsafe_operation(ctx, node->line ? node : node->cast.expr,
                                    "a cast to or from a raw pointer");
        return;
    default:
        return;
    }
}

void semantic_report_remaining_unsafe_operations(SemanticContext *ctx, ASTNode *root) {
    if (ctx->unsafe_operation_count <= UNSAFE_OPERATIONS_REPORTED) return;
    semantic_error_code_at(ctx, semantic_location_from_ast(root), SEMCODE_UNSAFE_OPERATION,
                           "%d more raw-pointer operations in this file; move them to an "
                           ".unsafe.mln file or use borrow",
                           ctx->unsafe_operation_count - UNSAFE_OPERATIONS_REPORTED);
}
