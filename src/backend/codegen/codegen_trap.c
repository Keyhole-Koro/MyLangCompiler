#include "mylang/backend/codegen_internal.h"

/* A trap stops the program where a run-time check failed. It needs no
 * runtime library: `halt` stops the machine in kernel mode, and in a user
 * process it is a privilege violation, which the kernel answers by ending
 * the process. r1 holds MYLANG_TRAP_BASE | kind and r2 the source line, so
 * a register dump (or the kernel's fault handler) shows what failed where. */
void emit_trap(CompilerContext *cc, StringBuilder *sb, int kind, int line) {
    (void)cc;
    sb_append(sb, "  movi r1, %d\n", MYLANG_TRAP_BASE | kind);
    sb_append(sb, "  movi r2, %d\n", line > 0 ? line : 0);
    sb_append(sb, "  halt\n");
}

/* Traps unless 0 <= index < length. `chk` compares unsigned, so a negative
 * index fails too, and on failure stops like a trap: r1 = 0x1BAD01 and r2 =
 * the address of the `chk` instead of the line (the map file names the
 * function). A length too large for its 21-bit immediate falls back to the
 * longer sequence. */
void emit_index_check(CompilerContext *cc, StringBuilder *sb, const char *index_reg,
                      const char *keep_reg, int length, int line) {
    codegen_cost_begin(sb, "check");
    if (length > 0 && length <= 0x1FFFFF) {
        sb_append(sb, "  chk %s, %d\n", index_reg, length);
        codegen_cost_end(sb);
        return;
    }
    static const char *candidates[] = { "r3", "r4", "r2", "r5" };
    const char *scratch = "r3";
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (strcmp(candidates[i], index_reg) != 0 &&
            (!keep_reg || strcmp(candidates[i], keep_reg) != 0)) {
            scratch = candidates[i];
            break;
        }
    }
    int label = next_label(cc);
    sb_append(sb, "  ; index must be below %d\n", length);
    sb_append(sb, "  push %s\n", scratch);
    sb_append(sb, "  movi %s, %d\n", scratch, length);
    sb_append(sb, "  cmp %s, %s\n", index_reg, scratch);
    sb_append(sb, "  pop %s\n", scratch);
    sb_append(sb, "  jb b_L_index_ok_%d\n", label);
    emit_trap(cc, sb, MYLANG_TRAP_INDEX, line);
    sb_append(sb, "b_L_index_ok_%d:\n", label);
    codegen_cost_end(sb);
}
