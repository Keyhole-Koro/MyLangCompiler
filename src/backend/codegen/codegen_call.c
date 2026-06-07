#include "mylang/backend/codegen_internal.h"

static void gen_builtin_rest_len(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg)
{
    if (node->call.arg_count != 1 || !node->call.args[0] || node->call.args[0]->type != AST_IDENTIFIER) {
        fprintf(stderr, "Codegen error at %d:%d: __rest_len expects a rest parameter identifier\n",
                node->line, node->col);
        exit(1);
    }

    int rest_index = 0;
    if (!cg_current_rest_info(cc, node->call.args[0]->identifier.name, &rest_index, NULL)) {
        fprintf(stderr, "Codegen error at %d:%d: __rest_len requires a variadic function rest parameter\n",
                node->line, node->col);
        exit(1);
    }

    sb_append(sb, "  ; load rest argument count\n");
    sb_append(sb, "  mov r3, bp\n");
    sb_append(sb, "  addis r3, %d\n", param_offset(rest_index));
    emit_load_from_addr(sb, target_reg, "r3", 0);
}

static void gen_builtin_rest_get(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
                                 char **params, int param_count, char **locals, int local_count)
{
    if (node->call.arg_count != 2 || !node->call.args[0] || node->call.args[0]->type != AST_IDENTIFIER) {
        fprintf(stderr, "Codegen error at %d:%d: __rest_get expects (__rest_param, index)\n",
                node->line, node->col);
        exit(1);
    }

    int fixed_count = 0;
    if (!cg_current_rest_info(cc, node->call.args[0]->identifier.name, NULL, &fixed_count)) {
        fprintf(stderr, "Codegen error at %d:%d: __rest_get requires a variadic function rest parameter\n",
                node->line, node->col);
        exit(1);
    }

    int rest_stack_base = 8 + ((fixed_count > 3) ? ((fixed_count - 3) * SLOT_SIZE) : 0);
    gen_expr(cc, node->call.args[1], sb, "r1", params, param_count, locals, local_count);
    emit_scale_reg_const(cc, sb, "r1", SLOT_SIZE);
    sb_append(sb, "  mov r3, bp\n");
    sb_append(sb, "  addis r3, %d\n", rest_stack_base);
    sb_append(sb, "  add r3, r1\n");
    emit_load_from_addr(sb, target_reg, "r3", 0);
}

static void gen_builtin_call(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
                             char **params, int param_count, char **locals, int local_count)
{
    if (strcmp(node->call.name, "__rest_len") == 0) {
        gen_builtin_rest_len(cc, node, sb, target_reg);
        return;
    }
    if (strcmp(node->call.name, "__rest_get") == 0) {
        gen_builtin_rest_get(cc, node, sb, target_reg, params, param_count, locals, local_count);
        return;
    }

    fprintf(stderr, "Codegen error at %d:%d: unknown builtin call '%s'\n",
            node->line, node->col, node->call.name);
    exit(1);
}

void gen_call(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
              char **params, int param_count, char **locals, int local_count)
{
    if (is_codegen_builtin(node->call.name)) {
        gen_builtin_call(cc, node, sb, target_reg, params, param_count, locals, local_count);
        return;
    }

    const FunctionSig *sig = find_func_sig(cc, node->call.name);
    int argc = node->call.arg_count;

    if (sig && sig->is_variadic) {
        int fixed = sig->fixed_param_count;
        if (argc < fixed) {
            fprintf(stderr, "Codegen error at %d:%d: variadic call to '%s' is missing fixed arguments\n",
                    node->line, node->col, node->call.name);
            exit(1);
        }

        int fixed_stack_count = fixed > 3 ? (fixed - 3) : 0;
        int rest_count = argc - fixed;
        int stack_args = fixed_stack_count + rest_count;

        note_import_func(cc, node->call.name);

        if (stack_args > 0) {
            sb_append(sb, "  ; push variadic stack arguments\n");
            sb_append(sb, "  addis sp, -%d\n", stack_args * SLOT_SIZE);

            for (int i = 3; i < fixed; i++) {
                gen_expr(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count);
                sb_append(sb, "  mov r2, sp\n");
                sb_append(sb, "  addis r2, %d\n", (i - 3) * SLOT_SIZE);
                sb_append(sb, "  store r2, r1\n");
            }

            for (int i = fixed; i < argc; i++) {
                int offset = (fixed_stack_count + (i - fixed)) * SLOT_SIZE;
                gen_expr(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count);
                sb_append(sb, "  mov r2, sp\n");
                sb_append(sb, "  addis r2, %d\n", offset);
                sb_append(sb, "  store r2, r1\n");
            }
        }

        for (int i = 0; i < fixed && i < 3; i++) {
            gen_expr(cc, node->call.args[i], sb, arg_regs[i], params, param_count, locals, local_count);
        }
        sb_append(sb, "  movi r4, %d\n", rest_count);
        sb_append(sb, "  call %s\n", node->call.name);

        if (stack_args > 0) {
            sb_append(sb, "  ; restore sp after variadic call\n");
            sb_append(sb, "  addis sp, %d\n", stack_args * SLOT_SIZE);
        }

        if (strcmp(target_reg, "r1") != 0)
            sb_append(sb, "  mov %s, r1\n", target_reg);
        return;
    }

    note_import_func(cc, node->call.name);
    int stack_args = argc > 3 ? (argc - 3) : 0;

    if (stack_args > 0)
    {
        sb_append(sb, "  ; push stack arguments\n");
        sb_append(sb, "  addis sp, -%d\n", stack_args * SLOT_SIZE);
        for (int i = 3; i < argc; i++)
        {
            gen_expr(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count);
            sb_append(sb, "  mov r2, sp\n");
            sb_append(sb, "  addis r2, %d\n", (i - 3) * SLOT_SIZE);
            sb_append(sb, "  store r2, r1\n");
        }
    }

    for (int i = 0; i < argc && i < 3; i++)
    {
        gen_expr(cc, node->call.args[i], sb, arg_regs[i], params, param_count, locals, local_count);
    }

    sb_append(sb, "  call %s\n", node->call.name);

    if (stack_args > 0)
    {
        sb_append(sb, "  ; restore sp after call\n");
        sb_append(sb, "  addis sp, %d\n", stack_args * SLOT_SIZE);
    }

    if (strcmp(target_reg, "r1") != 0)
        sb_append(sb, "  mov %s, r1\n", target_reg);
}
