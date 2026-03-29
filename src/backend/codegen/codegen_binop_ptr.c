#include "mylang/backend/codegen_internal.h"

static void gen_loaded_operand(CompilerContext *cc, ASTNode *expr, StringBuilder *sb,
                               const char *target_reg,
                               char **params, int param_count,
                               char **locals, int local_count) {
    if (expr->type == AST_UNARY && expr->unary.op == ASTARISK) {
        gen_expr(cc, expr->unary.operand, sb, target_reg, params, param_count, locals, local_count);
        int isb = lvalue_is_byte(cc, expr);
        emit_load_from_addr(sb, target_reg, target_reg, isb);
        return;
    }
    gen_expr(cc, expr, sb, target_reg, params, param_count, locals, local_count);
}

void gen_binop_operands(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
                        char **params, int param_count,
                        char **locals, int local_count) {
    gen_loaded_operand(cc, node->binary.left, sb, "r2", params, param_count, locals, local_count);
    sb_append(sb, "  push r2\n");
    gen_loaded_operand(cc, node->binary.right, sb, "r1", params, param_count, locals, local_count);
    sb_append(sb, "  pop r2\n");
}

int gen_pointer_binop(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
                      const char *target_reg,
                      char **params, int param_count,
                      char **locals, int local_count) {
    TypeInfo lhs_t = {0}, rhs_t = {0};
    int lhs_ptr = infer_expr_type(cc, node->binary.left, &lhs_t) &&
                  (lhs_t.pointer_level > 0 || lhs_t.dims_count > 0);
    int rhs_ptr = infer_expr_type(cc, node->binary.right, &rhs_t) &&
                  (rhs_t.pointer_level > 0 || rhs_t.dims_count > 0);

    if ((node->binary.op != ADD && node->binary.op != SUB) || lhs_ptr == rhs_ptr) {
        return 0;
    }

    ASTNode *ptr_expr = lhs_ptr ? node->binary.left : node->binary.right;
    ASTNode *idx_expr = lhs_ptr ? node->binary.right : node->binary.left;
    TypeInfo *ptr_t = lhs_ptr ? &lhs_t : &rhs_t;
    long step = pointer_step_bytes(cc, ptr_t);

    if (idx_expr->type == AST_NUMBER) {
        long idx_val = strtol(idx_expr->number.value, NULL, 10);
        long offset = idx_val * step;
        if (node->binary.op == SUB && lhs_ptr) offset = -offset;
        gen_expr(cc, ptr_expr, sb, target_reg, params, param_count, locals, local_count);
        if (offset != 0) sb_append(sb, "  addis %s, %ld\n", target_reg, offset);
        return 1;
    }

    gen_expr(cc, ptr_expr, sb, target_reg, params, param_count, locals, local_count);
    gen_expr(cc, idx_expr, sb, "r1", params, param_count, locals, local_count);
    emit_scale_reg_const(cc, sb, "r1", step);
    if (node->binary.op == SUB && lhs_ptr) {
        sb_append(sb, "  sub %s, r1\n", target_reg);
    } else {
        sb_append(sb, "  add %s, r1\n", target_reg);
    }
    return 1;
}
