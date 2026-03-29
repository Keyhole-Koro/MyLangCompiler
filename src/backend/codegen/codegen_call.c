#include "mylang/backend/codegen_internal.h"

void gen_call(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
              char **params, int param_count, char **locals, int local_count)
{
    note_import_func(cc, node->call.name);
    int argc = node->call.arg_count;
    int stack_args = argc > 3 ? (argc - 3) : 0;

    // Allocate space for stack-passed arguments (4th and beyond)
    if (stack_args > 0)
    {
        sb_append(sb, "  ; push stack arguments\n");
        sb_append(sb, "  addis sp, -%d\n", stack_args * SLOT_SIZE);
        for (int i = 3; i < argc; i++)
        {
            gen_expr(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count);
            sb_append(sb, "  mov r2, sp\n");
            sb_append(sb, "  addis r2, %d\n", (i - 3) * SLOT_SIZE);
            sb_append(sb, "  store r2, r1\n"); // Store the argument value at [sp + offset]
        }
    }

    // Pass the first 3 arguments via registers r5, r6, r7 (left to right)
    for (int i = 0; i < argc && i < 3; i++)
    {
        gen_expr(cc, node->call.args[i], sb, arg_regs[i], params, param_count, locals, local_count);
    }

    sb_append(sb, "  call f_%s\n", node->call.name);

    // After call, restore stack pointer
    if (stack_args > 0)
    {
        sb_append(sb, "  ; restore sp after call\n");
        sb_append(sb, "  addis sp, %d\n", stack_args * SLOT_SIZE);
    }

    // Move return value to target register if needed
    if (strcmp(target_reg, "r1") != 0)
        sb_append(sb, "  mov %s, r1\n", target_reg);
}
