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

// True when `name` is a value in scope (param/local/global) rather than a known
// function. Such a call is an indirect call through a function-pointer value.
static int is_indirect_callee(CompilerContext *cc, const char *name,
                              char **params, int param_count,
                              char **locals, int local_count)
{
    if (find_func_sig(cc, name)) return 0;      // a known function -> direct call
    if (is_codegen_builtin(name)) return 0;
    if (param_index(name, params, param_count) >= 0) return 1;
    if (local_index_last(name, locals, local_count) >= 0) return 1;
    if (find_global_info(cc, name)) return 1;
    return 0;
}

// Emit an indirect call: `callee(args)` where `callee` is a variable holding a
// function pointer (an i32, as taken by naming a function bare). Args are passed
// exactly like a direct call. Instead of `call <label>`, the pointer is loaded
// and jumped to via `mov pc, reg` with LR set to the return label, mirroring the
// `mov pc, lr` return convention. Rest/variadic indirect calls are not supported.
static void gen_indirect_call(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
                              char **params, int param_count, char **locals, int local_count)
{
    int argc = node->call.arg_count;
    int stack_args = argc > 3 ? (argc - 3) : 0;

    if (stack_args > 0) {
        sb_append(sb, "  ; push stack arguments (indirect call)\n");
        sb_append(sb, "  addis sp, -%d\n", stack_args * SLOT_SIZE);
        for (int i = 3; i < argc; i++) {
            gen_expr(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count);
            sb_append(sb, "  mov r2, sp\n");
            sb_append(sb, "  addis r2, %d\n", (i - 3) * SLOT_SIZE);
            sb_append(sb, "  store r2, r1\n");
        }
    }

    // Evaluate the callee and register args, pushing each so a nested call in a
    // later arg cannot clobber an earlier result. Then pop them into place. The
    // callee address goes to r2: args are already in r5-r7 by then, r1 is the
    // return slot, and r0 must stay 0 (codegen emits `cmp reg, 0` as `cmp reg, r0`,
    // relying on r0 being zero). r2 is arg-eval scratch, free once args are placed.
    sb_append(sb, "  ; evaluate indirect callee '%s'\n", node->call.name);
    emit_load_var(cc, sb, node->call.name, "r1", params, param_count, locals, local_count);
    sb_append(sb, "  push r1\n");

    int reg_argc = argc < 3 ? argc : 3;
    for (int i = 0; i < reg_argc; i++) {
        gen_expr(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count);
        sb_append(sb, "  push r1\n");
    }
    for (int i = reg_argc - 1; i >= 0; i--) {
        sb_append(sb, "  pop %s\n", arg_regs[i]);
    }
    sb_append(sb, "  pop r2\n"); // callee address (r2 is free once args are placed)

    int ret = next_label(cc);
    sb_append(sb, "  movi lr, icall_ret_%d\n", ret);
    sb_append(sb, "  mov pc, r2\n");
    sb_append(sb, "icall_ret_%d:\n", ret);

    if (stack_args > 0) {
        sb_append(sb, "  ; restore sp after indirect call\n");
        sb_append(sb, "  addis sp, %d\n", stack_args * SLOT_SIZE);
    }

    if (strcmp(target_reg, "r1") != 0)
        sb_append(sb, "  mov %s, r1\n", target_reg);
}

// The one word an argument contributes is either its value (gen_expr) or, for
// a struct/array parameter, the address of the caller's own copy (MLC-015):
// gen_lvalue_addr, the same address computation aggregate assignment and a
// hidden-pointer return already use. Passing anything that isn't addressable
// that way (a call result, an arithmetic expression) is a codegen error
// rather than the one-word truncation this used to silently produce.
static void gen_arg_word(CompilerContext *cc, ASTNode *arg, StringBuilder *sb, const char *target_reg,
                         char **params, int param_count, char **locals, int local_count,
                         int is_aggregate, const char *callee_name, int arg_index)
{
    if (!is_aggregate) {
        gen_expr(cc, arg, sb, target_reg, params, param_count, locals, local_count);
        return;
    }
    if (!is_addressable_expr(arg)) {
        fprintf(stderr,
                "Codegen error: argument %d of '%s' takes a struct or array by "
                "value, and only a variable, a field of one, or a dereference "
                "can be passed that way; bind it to one first\n",
                arg_index + 1, callee_name ? callee_name : "?");
        exit(1);
    }
    gen_lvalue_addr(cc, arg, sb, target_reg, params, param_count, locals, local_count);
}

// True when sig says argument index i is a by-value struct or array.
static int sig_arg_is_aggregate(const FunctionSig *sig, int i)
{
    return sig && sig->param_is_aggregate && i < sig->param_count && sig->param_is_aggregate[i];
}

void gen_call(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
              char **params, int param_count, char **locals, int local_count)
{
    if (is_codegen_builtin(node->call.name)) {
        gen_builtin_call(cc, node, sb, target_reg, params, param_count, locals, local_count);
        return;
    }

    if (is_indirect_callee(cc, node->call.name, params, param_count, locals, local_count)) {
        gen_indirect_call(cc, node, sb, target_reg, params, param_count, locals, local_count);
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
                gen_arg_word(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count,
                            sig_arg_is_aggregate(sig, i), node->call.name, i);
                sb_append(sb, "  mov r2, sp\n");
                sb_append(sb, "  addis r2, %d\n", (i - 3) * SLOT_SIZE);
                sb_append(sb, "  store r2, r1\n");
            }

            // Rest arguments have no per-argument declared type -- they are
            // the variadic tail, always passed as plain i32 values.
            for (int i = fixed; i < argc; i++) {
                int offset = (fixed_stack_count + (i - fixed)) * SLOT_SIZE;
                gen_expr(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count);
                sb_append(sb, "  mov r2, sp\n");
                sb_append(sb, "  addis r2, %d\n", offset);
                sb_append(sb, "  store r2, r1\n");
            }
        }

        for (int i = 0; i < fixed && i < 3; i++) {
            gen_arg_word(cc, node->call.args[i], sb, arg_regs[i], params, param_count, locals, local_count,
                        sig_arg_is_aggregate(sig, i), node->call.name, i);
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
            gen_arg_word(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count,
                        sig_arg_is_aggregate(sig, i), node->call.name, i);
            sb_append(sb, "  mov r2, sp\n");
            sb_append(sb, "  addis r2, %d\n", (i - 3) * SLOT_SIZE);
            sb_append(sb, "  store r2, r1\n");
        }
    }

    // Evaluate register arguments left-to-right, pushing each result, then pop
    // them into the argument registers just before the call. Evaluating an
    // argument may involve a nested call that clobbers the argument registers,
    // so earlier results must not be left sitting in those registers.
    int reg_argc = argc < 3 ? argc : 3;
    for (int i = 0; i < reg_argc; i++)
    {
        gen_arg_word(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count,
                    sig_arg_is_aggregate(sig, i), node->call.name, i);
        sb_append(sb, "  push r1\n");
    }
    for (int i = reg_argc - 1; i >= 0; i--)
    {
        sb_append(sb, "  pop %s\n", arg_regs[i]);
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

// Calls a function that returns a struct or array by value (MLC-015). The
// caller has already computed the destination's address and pushed it, before
// evaluating any argument -- exactly like gen_assign's aggregate path
// computes both addresses before copying, so that evaluating one does not
// clobber a register the other is still using. This consumes that push,
// loading it into r4 (the hidden out-pointer argument) once every real
// argument is in place, right before `call`.
//
// Aggregate-returning functions can't be variadic (gen_func refuses to
// compile one that is) and aren't called indirectly here: there is no
// per-argument aggregate information for a function-pointer value, the way
// FunctionSig carries it for a direct callee.
void gen_call_sret(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
                   char **params, int param_count, char **locals, int local_count)
{
    if (is_codegen_builtin(node->call.name) ||
        is_indirect_callee(cc, node->call.name, params, param_count, locals, local_count)) {
        fprintf(stderr,
                "Codegen error: '%s' cannot be called indirectly or as a "
                "builtin while returning a struct or array by value\n",
                node->call.name);
        exit(1);
    }

    const FunctionSig *sig = find_func_sig(cc, node->call.name);
    int argc = node->call.arg_count;
    note_import_func(cc, node->call.name);

    int stack_args = argc > 3 ? (argc - 3) : 0;
    if (stack_args > 0)
    {
        sb_append(sb, "  ; push stack arguments (sret call)\n");
        sb_append(sb, "  addis sp, -%d\n", stack_args * SLOT_SIZE);
        for (int i = 3; i < argc; i++)
        {
            gen_arg_word(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count,
                        sig_arg_is_aggregate(sig, i), node->call.name, i);
            sb_append(sb, "  mov r2, sp\n");
            sb_append(sb, "  addis r2, %d\n", (i - 3) * SLOT_SIZE);
            sb_append(sb, "  store r2, r1\n");
        }
    }

    int reg_argc = argc < 3 ? argc : 3;
    for (int i = 0; i < reg_argc; i++)
    {
        gen_arg_word(cc, node->call.args[i], sb, "r1", params, param_count, locals, local_count,
                    sig_arg_is_aggregate(sig, i), node->call.name, i);
        sb_append(sb, "  push r1\n");
    }
    for (int i = reg_argc - 1; i >= 0; i--)
    {
        sb_append(sb, "  pop %s\n", arg_regs[i]);
    }

    // The destination address sits just past the stack-args reservation
    // (net zero from the register push/pop pairs above), so it is read at a
    // fixed offset from the current sp rather than popped -- popping it now
    // would put it below the reservation this function is about to tear down.
    sb_append(sb, "  ; load hidden out-pointer for by-value return\n");
    sb_append(sb, "  mov r4, sp\n");
    if (stack_args > 0) sb_append(sb, "  addis r4, %d\n", stack_args * SLOT_SIZE);
    sb_append(sb, "  load r4, r4\n");

    sb_append(sb, "  call %s\n", node->call.name);

    if (stack_args > 0)
    {
        sb_append(sb, "  ; restore sp after sret call\n");
        sb_append(sb, "  addis sp, %d\n", stack_args * SLOT_SIZE);
    }
    // Drop the destination-address slot the caller pushed.
    sb_append(sb, "  addis sp, 4\n");
}
