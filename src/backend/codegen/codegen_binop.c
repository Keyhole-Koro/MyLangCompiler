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

void gen_expr_binop(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
                    char **params, int param_count, char **locals, int local_count)
{
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
