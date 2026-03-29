#include "mylang/backend/codegen_internal.h"

void emit_unary_inc_dec(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
                        char **params, int param_count,
                        char **locals, int local_count)
{
    if (!node || node->type != AST_UNARY) {
        fprintf(stderr, "Codegen error: emit_unary_inc_dec on non-unary node\n");
        exit(1);
    }
    if (lvalue_is_const(cc, node->unary.operand)) {
        fprintf(stderr, "Codegen error: modifying a const value is not allowed\n");
        exit(1);
    }

    // Compute address of operand lvalue into r3
    gen_lvalue_addr(cc, node->unary.operand, sb, "r3", params, param_count, locals, local_count);
    int is_byte = lvalue_is_byte(cc, node->unary.operand);
    // Load current value into r1
    emit_load_from_addr(sb, "r1", "r3", is_byte);

    int delta = 1;
    TypeInfo operand_type = (TypeInfo){0};
    if (infer_expr_type(cc, node->unary.operand, &operand_type) && operand_type.pointer_level > 0) {
        delta = pointer_step_bytes(cc, &operand_type);
    }

    switch (node->unary.op) {
    case POST_INC: {
        // result is original value
        if (strcmp(target_reg, "r1") != 0)
            sb_append(sb, "  mov %s, r1\n", target_reg);
        sb_append(sb, "  addis r1, %d\n", delta);
        emit_store_to_addr(sb, "r3", "r1", is_byte);
        break; }
    case POST_DEC: {
        if (strcmp(target_reg, "r1") != 0)
            sb_append(sb, "  mov %s, r1\n", target_reg);
        sb_append(sb, "  addis r1, -%d\n", delta);
        emit_store_to_addr(sb, "r3", "r1", is_byte);
        break; }
    case INC: {
        sb_append(sb, "  addis r1, %d\n", delta);
        emit_store_to_addr(sb, "r3", "r1", is_byte);
        if (strcmp(target_reg, "r1") != 0)
            sb_append(sb, "  mov %s, r1\n", target_reg);
        break; }
    case DEC: {
        sb_append(sb, "  addis r1, -%d\n", delta);
        emit_store_to_addr(sb, "r3", "r1", is_byte);
        if (strcmp(target_reg, "r1") != 0)
            sb_append(sb, "  mov %s, r1\n", target_reg);
        break; }
    default:
        fprintf(stderr, "Codegen error: unknown unary inc/dec op\n");
        exit(1);
    }
}

// Emit code to load variable (param/local/global) to target_reg
