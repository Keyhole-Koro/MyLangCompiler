#include "mylang/backend/codegen_internal.h"

static void emit_loop_condition(CompilerContext *cc, ASTNode *cond, StringBuilder *sb,
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

void gen_for(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
    char **params, int param_count,
    char **locals, int local_count,
    const char *break_label,
    const char *continue_label)
{
    (void)break_label; (void)continue_label;
    int cur_label = next_label(cc);
    char for_cond[32], for_body[32], for_inc[32], for_end[32];
    snprintf(for_cond, sizeof(for_cond), "b_L_for_cond_%d", cur_label);
    snprintf(for_body, sizeof(for_body), "b_L_for_body_%d", cur_label);
    snprintf(for_inc, sizeof(for_inc), "b_L_for_inc_%d", cur_label);
    snprintf(for_end, sizeof(for_end), "b_L_for_end_%d", cur_label);

    if (node->for_stmt.init)
        gen_stmt(cc, node->for_stmt.init, sb, params, param_count, locals, local_count);

    sb_append(sb, "%s:\n", for_cond);

    if (node->for_stmt.cond) {
        emit_loop_condition(cc, node->for_stmt.cond, sb,
                            params, param_count, locals, local_count,
                            for_body, for_end);
    } else {
        sb_append(sb, "  jmp %s\n", for_body);
    }

    sb_append(sb, "%s:\n", for_body);
    gen_stmt_internal(cc, node->for_stmt.body, sb, params, param_count, locals, local_count,
        for_end, for_inc);

    sb_append(sb, "%s:\n", for_inc);
    if (node->for_stmt.inc)
        gen_stmt(cc, node->for_stmt.inc, sb, params, param_count, locals, local_count);

    sb_append(sb, "  jmp %s\n", for_cond);
    sb_append(sb, "%s:\n", for_end);
}

void gen_while(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
    char **params, int param_count,
    char **locals, int local_count,
    const char *break_label,
    const char *continue_label)
{
    (void)break_label; (void)continue_label;
    int cur = next_label(cc);

    char cond_label[32], body_label[32], end_label[32];
    snprintf(cond_label, sizeof(cond_label), "b_L_while_cond_%d", cur);
    snprintf(body_label, sizeof(body_label), "b_L_while_body_%d", cur);
    snprintf(end_label, sizeof(end_label), "b_L_while_end_%d", cur);

    sb_append(sb, "%s:\n", cond_label);
    emit_loop_condition(cc, node->while_stmt.cond, sb,
                        params, param_count, locals, local_count,
                        body_label, end_label);

    sb_append(sb, "%s:\n", body_label);
    gen_stmt_internal(cc, node->while_stmt.body, sb,
        params, param_count, locals, local_count,
        end_label, cond_label);

    sb_append(sb, "  jmp %s\n", cond_label);
    sb_append(sb, "%s:\n", end_label);
}

void gen_do_while(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
    char **params, int param_count,
    char **locals, int local_count,
    const char *break_label,
    const char *continue_label)
{
    (void)break_label; (void)continue_label;
    int cur = next_label(cc);

    char cond_label[32], body_label[32], end_label[32];
    snprintf(cond_label, sizeof(cond_label), "b_L_dowhile_cond_%d", cur);
    snprintf(body_label, sizeof(body_label), "b_L_dowhile_body_%d", cur);
    snprintf(end_label, sizeof(end_label), "b_L_dowhile_end_%d", cur);

    sb_append(sb, "%s:\n", body_label);
    gen_stmt_internal(cc, node->do_while_stmt.body, sb,
        params, param_count, locals, local_count,
        end_label, cond_label);

    sb_append(sb, "%s:\n", cond_label);
    emit_loop_condition(cc, node->do_while_stmt.cond, sb,
                        params, param_count, locals, local_count,
                        body_label, end_label);

    sb_append(sb, "%s:\n", end_label);
}
