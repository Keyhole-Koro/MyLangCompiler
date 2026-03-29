#include "mylang/backend/codegen_internal.h"

static void emit_branch_on_condition(CompilerContext *cc, ASTNode *cond, StringBuilder *sb,
    char **params, int param_count,
    char **locals, int local_count,
    const char *true_label,
    const char *false_label)
{
    if (cond->type == AST_BINARY && is_comparison_op(cond->binary.op)) {
        emit_cond_jump(cc, cond->binary.left, cond->binary.right, cond->binary.op, sb,
                       params, param_count, locals, local_count, true_label, false_label);
        return;
    }

    gen_expr(cc, cond, sb, "r1", params, param_count, locals, local_count);
    sb_append(sb, "  cmp r1, 0\n");
    sb_append(sb, "  jnz %s\n", true_label);
    sb_append(sb, "  jmp %s\n", false_label);
}

void gen_if(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
    char **params, int param_count,
    char **locals, int local_count,
    const char *break_label,
    const char *continue_label)
{
    int cur_label = next_label(cc);

    char then_label[32], else_label[32], end_label[32];
    snprintf(then_label, sizeof(then_label), "b_L_then_%d", cur_label);
    snprintf(end_label, sizeof(end_label), "b_L_end_%d", cur_label);

    if (node->if_stmt.else_stmt)
        snprintf(else_label, sizeof(else_label), "b_L_else_%d", cur_label);
    else
        strcpy(else_label, end_label);

    emit_branch_on_condition(cc, node->if_stmt.cond, sb,
                             params, param_count, locals, local_count,
                             then_label, else_label);

    sb_append(sb, "%s:\n", then_label);
    gen_stmt_internal(cc, node->if_stmt.then_stmt, sb, params, param_count, locals, local_count,
        break_label, continue_label);
    sb_append(sb, "  jmp %s\n", end_label);

    if (node->if_stmt.else_stmt) {
        sb_append(sb, "%s:\n", else_label);
        gen_stmt_internal(cc, node->if_stmt.else_stmt, sb, params, param_count, locals, local_count,
            break_label, continue_label);
    }
    sb_append(sb, "%s:\n", end_label);
}
