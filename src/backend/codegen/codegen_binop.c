#include "mylang/backend/codegen_internal.h"

int gen_short_circuit_binop(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
                            const char *target_reg,
                            char **params, int param_count,
                            char **locals, int local_count);
int gen_pointer_binop(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
                      const char *target_reg,
                      char **params, int param_count,
                      char **locals, int local_count);
void gen_binop_operands(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
                        char **params, int param_count,
                        char **locals, int local_count);
int gen_math_binop(CompilerContext *cc, ASTNode *node, StringBuilder *sb);
int gen_compare_binop(CompilerContext *cc, ASTNode *node, StringBuilder *sb);

static int expr_is_str(CompilerContext *cc, ASTNode *expr) {
    TypeInfo info = {0};
    return infer_expr_type(cc, expr, &info) && info.base_type &&
           strcmp(info.base_type, "str") == 0 && info.pointer_level == 0 &&
           !info.is_array;
}

static int gen_str_addr(CompilerContext *cc, ASTNode *expr, StringBuilder *sb,
                        const char *target_reg, char **params, int param_count,
                        char **locals, int local_count) {
    if (expr->type == AST_STRING_LITERAL) {
        const char *view = intern_string_view_n(cc, expr->string_literal.value,
                                                expr->string_literal.length);
        sb_append(sb, "  movi %s, %s\n", target_reg, view);
        return 0;
    }
    const FunctionSig *result = call_returns_aggregate(cc, expr);
    if (result) {
        int bytes = ((result->ret_size_bytes + SLOT_SIZE - 1) / SLOT_SIZE) * SLOT_SIZE;
        sb_append(sb, "  ; materialize str comparison operand\n");
        sb_append(sb, "  addis sp, -%d\n", bytes);
        sb_append(sb, "  mov r1, sp\n  push r1\n");
        gen_call_sret(cc, expr, sb, params, param_count, locals, local_count);
        if (strcmp(target_reg, "sp") != 0) sb_append(sb, "  mov %s, sp\n", target_reg);
        return bytes;
    }
    if (!is_addressable_expr(expr)) {
        fprintf(stderr, "Codegen error: str comparison operand must be a value or literal\n");
        exit(1);
    }
    gen_lvalue_addr(cc, expr, sb, target_reg, params, param_count, locals, local_count);
    return 0;
}

int gen_str_equality(CompilerContext *cc, ASTNode *left, ASTNode *right,
                     TokenKind op, StringBuilder *sb, const char *target_reg,
                     char **params, int param_count, char **locals, int local_count) {
    if ((op != EQ && op != NEQ) || !expr_is_str(cc, left) || !expr_is_str(cc, right))
        return 0;

    int id = next_label(cc);
    char unequal[40], equal[40], done[40], loop[40];
    snprintf(unequal, sizeof(unequal), "b_str_unequal_%d", id);
    snprintf(equal, sizeof(equal), "b_str_equal_%d", id);
    snprintf(done, sizeof(done), "b_str_cmp_end_%d", id);
    snprintf(loop, sizeof(loop), "b_str_cmp_loop_%d", id);

    int left_temp = gen_str_addr(cc, left, sb, "r1", params, param_count, locals, local_count);
    sb_append(sb, "  push r1\n");
    int right_temp = gen_str_addr(cc, right, sb, "r2", params, param_count, locals, local_count);
    sb_append(sb, "  mov r1, sp\n");
    if (right_temp) sb_append(sb, "  addis r1, %d\n", right_temp);
    sb_append(sb, "  load r1, r1\n");
    sb_append(sb, "  mov r5, r1\n  addis r5, 4\n  load r3, r5\n");
    sb_append(sb, "  mov r5, r2\n  addis r5, 4\n  load r4, r5\n");
    sb_append(sb, "  cmp r3, r4\n  jnz %s\n", unequal);
    sb_append(sb, "  load r5, r1\n  load r6, r2\n");
    sb_append(sb, "%s:\n  cmp r3, 0\n  jz %s\n", loop, equal);
    sb_append(sb, "  loadb r1, r5\n  loadb r2, r6\n  cmp r1, r2\n  jnz %s\n", unequal);
    sb_append(sb, "  addis r5, 1\n  addis r6, 1\n  addis r3, -1\n  jmp %s\n", loop);
    sb_append(sb, "%s:\n  movi r1, %d\n  jmp %s\n", equal, op == EQ ? 1 : 0, done);
    sb_append(sb, "%s:\n  movi r1, %d\n", unequal, op == NEQ ? 1 : 0);
    sb_append(sb, "%s:\n", done);
    sb_append(sb, "  addis sp, %d\n", left_temp + SLOT_SIZE + right_temp);
    if (strcmp(target_reg, "r1") != 0) sb_append(sb, "  mov %s, r1\n", target_reg);
    return 1;
}

void gen_expr_binop(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
                    char **params, int param_count, char **locals, int local_count)
{
    if (gen_str_equality(cc, node->binary.left, node->binary.right,
                         node->binary.op, sb, target_reg,
                         params, param_count, locals, local_count)) {
        return;
    }
    if (gen_short_circuit_binop(cc, node, sb, target_reg, params, param_count, locals, local_count)) {
        return;
    }

    if (gen_pointer_binop(cc, node, sb, target_reg, params, param_count, locals, local_count)) {
        return;
    }

    gen_binop_operands(cc, node, sb, params, param_count, locals, local_count);

    if (!gen_math_binop(cc, node, sb) && !gen_compare_binop(cc, node, sb)) {
        fprintf(stderr, "Codegen error: unknown binary op\n");
        exit(1);
    }

    if (strcmp(target_reg, "r1") != 0)
        sb_append(sb, "  mov %s, r1\n", target_reg);
}
