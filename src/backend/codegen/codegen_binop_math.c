#include "mylang/backend/codegen_internal.h"

// If `n` is a power of two (> 0), return its log2 exponent, else -1.
static int pow2_shift(long n) {
    if (n <= 0) return -1;
    int s = 0;
    while ((n & 1) == 0) { n >>= 1; s++; }
    return (n == 1) ? s : -1;
}

// If `node` is an integer literal, store its value in *out and return 1.
static int literal_value(ASTNode *node, long *out) {
    if (node && node->type == AST_NUMBER) {
        *out = strtol(node->number.value, NULL, 10);
        return 1;
    }
    return 0;
}

int gen_math_binop(CompilerContext *cc, ASTNode *node, StringBuilder *sb) {
    switch (node->binary.op)
    {
    case ADD:
        sb_append(sb, "\n; addition\n  add  r1, r2\n");
        return 1;
    case SUB:
        sb_append(sb, "\n; subtraction\n  sub  r2, r1\n");
        sb_append(sb, "  mov r1, r2\n");
        return 1;
    case ASTARISK: {
        // Fast path: multiplying by a power-of-two literal is a left shift.
        // The target has no multiply instruction, so the generic loop below
        // runs `min(operands)` times — e.g. `row * 1024` would loop 1024x per
        // pixel row. Operands are pre-loaded left->r2, right->r1; if one side
        // is a constant 2^k, shift the other operand's register instead.
        long lit;
        int shift;
        if (literal_value(node->binary.right, &lit) && (shift = pow2_shift(lit)) >= 0) {
            sb_append(sb, "\n; multiply r2 * %ld (<< %d)\n", lit, shift);
            for (int i = 0; i < shift; i++) sb_append(sb, "  shl r2\n");
            sb_append(sb, "  mov r1, r2\n");
            return 1;
        }
        if (literal_value(node->binary.left, &lit) && (shift = pow2_shift(lit)) >= 0) {
            sb_append(sb, "\n; multiply %ld * r1 (<< %d)\n", lit, shift);
            for (int i = 0; i < shift; i++) sb_append(sb, "  shl r1\n");
            return 1;
        }
        sb_append(sb, "\n; multiply r2 * r1\n");
        sb_append(sb, "  movi r4, 0      ; r4 = result\n");
        sb_append(sb, "  mov r5, r1     ; r5 = count\n");
        int lbl_mul = next_label(cc);
        sb_append(sb, "b_mul_loop_%d:\n", lbl_mul);
        sb_append(sb, "  cmp r5, 0\n");
        sb_append(sb, "  jz b_mul_end_%d\n", lbl_mul);
        sb_append(sb, "  add r4, r2\n");
        sb_append(sb, "  addis r5, -1\n");
        sb_append(sb, "  jmp b_mul_loop_%d\n", lbl_mul);
        sb_append(sb, "b_mul_end_%d:\n", lbl_mul);
        sb_append(sb, "  mov r1, r4\n");
        return 1;
    }
    case DIV: {
        sb_append(sb, "\n; divide r2 / r1\n");
        sb_append(sb, "  movi r4, 0      ; r4 = result (quotient)\n");
        int lbl_div = next_label(cc);
        sb_append(sb, "b_div_loop_%d:\n", lbl_div);
        sb_append(sb, "  cmp r2, r1\n");
        sb_append(sb, "  jl b_div_end_%d\n", lbl_div);
        sb_append(sb, "  sub r2, r1\n");
        sb_append(sb, "  addis r4, 1\n");
        sb_append(sb, "  jmp b_div_loop_%d\n", lbl_div);
        sb_append(sb, "b_div_end_%d:\n", lbl_div);
        sb_append(sb, "  mov r1, r4\n");
        return 1;
    }
    case MOD: {
        sb_append(sb, "\n; modulo r2 %% r1\n");
        sb_append(sb, "  mov r6, r2     ; r6 = dividend backup (r2)\n");
        sb_append(sb, "  movi r4, 0      ; r4 = result (quotient)\n");
        int lbl_mod = next_label(cc);
        sb_append(sb, "b_mod_loop_%d:\n", lbl_mod);
        sb_append(sb, "  cmp r2, r1\n");
        sb_append(sb, "  jl b_mod_end_%d\n", lbl_mod);
        sb_append(sb, "  sub r2, r1\n");
        sb_append(sb, "  addis r4, 1\n");
        sb_append(sb, "  jmp b_mod_loop_%d\n", lbl_mod);
        sb_append(sb, "b_mod_end_%d:\n", lbl_mod);
        sb_append(sb, "  ; r2 now contains remainder\n");
        sb_append(sb, "  mov r1, r2\n");
        return 1;
    }
    case AMPERSAND:
        sb_append(sb, "\n; bitwise AND\n  and r1, r2\n");
        return 1;
    case BITOR:
        sb_append(sb, "\n; bitwise OR\n  or r1, r2\n");
        return 1;
    case BITXOR:
        sb_append(sb, "\n; bitwise XOR\n  xor r1, r2\n");
        return 1;
    case LSH: {
        sb_append(sb, "\n; bitwise left shift\n");
        sb_append(sb, "  mov r4, r2\n");
        sb_append(sb, "  mov r5, r1\n");
        int lbl = next_label(cc);
        sb_append(sb, "b_lsh_loop_%d:\n", lbl);
        sb_append(sb, "  cmp r5, 0\n");
        sb_append(sb, "  jz b_lsh_end_%d\n", lbl);
        sb_append(sb, "  shl r4\n");
        sb_append(sb, "  addis r5, -1\n");
        sb_append(sb, "  jmp b_lsh_loop_%d\n", lbl);
        sb_append(sb, "b_lsh_end_%d:\n", lbl);
        sb_append(sb, "  mov r1, r4\n");
        return 1;
    }
    case RSH: {
        sb_append(sb, "\n; bitwise right shift\n");
        sb_append(sb, "  mov r4, r2\n");
        sb_append(sb, "  mov r5, r1\n");
        int lbl = next_label(cc);
        sb_append(sb, "b_rsh_loop_%d:\n", lbl);
        sb_append(sb, "  cmp r5, 0\n");
        sb_append(sb, "  jz b_rsh_end_%d\n", lbl);
        sb_append(sb, "  shr r4\n");
        sb_append(sb, "  addis r5, -1\n");
        sb_append(sb, "  jmp b_rsh_loop_%d\n", lbl);
        sb_append(sb, "b_rsh_end_%d:\n", lbl);
        sb_append(sb, "  mov r1, r4\n");
        return 1;
    }
    default:
        return 0;
    }
}
