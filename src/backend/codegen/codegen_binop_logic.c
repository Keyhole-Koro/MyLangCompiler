#include "mylang/backend/codegen_internal.h"

int gen_short_circuit_binop(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
                            const char *target_reg,
                            char **params, int param_count,
                            char **locals, int local_count) {
    if (node->binary.op == LAND) {
        int label = next_label(cc);
        char label_false[32], label_end[32];
        snprintf(label_false, sizeof(label_false), "b_land_false_%d", label);
        snprintf(label_end, sizeof(label_end), "b_land_end_%d", label);

        gen_expr(cc, node->binary.left, sb, "r1", params, param_count, locals, local_count);
        sb_append(sb, "  cmp r1, 0\n");
        sb_append(sb, "  jz %s\n", label_false);

        gen_expr(cc, node->binary.right, sb, "r1", params, param_count, locals, local_count);
        sb_append(sb, "  cmp r1, 0\n");
        sb_append(sb, "  jz %s\n", label_false);

        sb_append(sb, "  movi r1, 1\n");
        sb_append(sb, "  jmp %s\n", label_end);
        sb_append(sb, "%s:\n", label_false);
        sb_append(sb, "  movi r1, 0\n");
        sb_append(sb, "%s:\n", label_end);

        if (strcmp(target_reg, "r1") != 0)
            sb_append(sb, "  mov %s, r1\n", target_reg);
        return 1;
    }

    if (node->binary.op == LOR) {
        int label = next_label(cc);
        char label_true[32], label_end[32];
        snprintf(label_true, sizeof(label_true), "b_lor_true_%d", label);
        snprintf(label_end, sizeof(label_end), "b_lor_end_%d", label);

        gen_expr(cc, node->binary.left, sb, "r1", params, param_count, locals, local_count);
        sb_append(sb, "  cmp r1, 0\n");
        sb_append(sb, "  jnz %s\n", label_true);

        gen_expr(cc, node->binary.right, sb, "r1", params, param_count, locals, local_count);
        sb_append(sb, "  cmp r1, 0\n");
        sb_append(sb, "  jnz %s\n", label_true);

        sb_append(sb, "  movi r1, 0\n");
        sb_append(sb, "  jmp %s\n", label_end);
        sb_append(sb, "%s:\n", label_true);
        sb_append(sb, "  movi r1, 1\n");
        sb_append(sb, "%s:\n", label_end);

        if (strcmp(target_reg, "r1") != 0)
            sb_append(sb, "  mov %s, r1\n", target_reg);
        return 1;
    }

    return 0;
}

int gen_compare_binop(CompilerContext *cc, ASTNode *node, StringBuilder *sb) {
    switch (node->binary.op) {
    case EQ:
    case NEQ:
    case LT:
    case GT:
    case LTE:
    case GTE: {
        int label = next_label(cc);
        char label_true[32], label_end[32];
        snprintf(label_true, sizeof(label_true), "b_cmp_true_%d", label);
        snprintf(label_end, sizeof(label_end), "b_cmp_end_%d", label);
        sb_append(sb, "  cmp r2, r1\n");
        switch (node->binary.op) {
        case EQ:
            sb_append(sb, "  jz %s\n", label_true);
            break;
        case NEQ:
            sb_append(sb, "  jnz %s\n", label_true);
            break;
        case LT:
            sb_append(sb, "  jl %s\n", label_true);
            break;
        case GT:
            sb_append(sb, "  jg %s\n", label_true);
            break;
        case LTE:
            sb_append(sb, "  jl %s\n", label_true);
            sb_append(sb, "  jz %s\n", label_true);
            break;
        case GTE:
            sb_append(sb, "  jg %s\n", label_true);
            sb_append(sb, "  jz %s\n", label_true);
            break;
        default:
            break;
        }
        sb_append(sb, "  movi r1, 0\n");
        sb_append(sb, "  jmp %s\n", label_end);
        sb_append(sb, "%s:\n", label_true);
        sb_append(sb, "  movi r1, 1\n");
        sb_append(sb, "%s:\n", label_end);
        return 1;
    }
    default:
        return 0;
    }
}
