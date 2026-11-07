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

// Replaces reg with its negation. r5 is scratch.
static void emit_negate(StringBuilder *sb, const char *reg) {
    sb_append(sb, "  movi r5, 0\n");
    sb_append(sb, "  sub r5, %s\n", reg);
    sb_append(sb, "  mov %s, r5\n", reg);
}

// The target has no divide instruction. Divides r2 by r1 as constant folding
// does: a quotient truncates toward zero and a remainder takes the dividend's
// sign. The loop works on magnitudes, compared unsigned so that -2147483648 has
// one, and a word on the stack says whether to negate the answer. Dividing by
// zero gives a quotient of 0 and leaves the dividend as the remainder.
// Leaves a DIV's quotient in r4 and a MOD's remainder in r2.
static void emit_divide(CompilerContext *cc, StringBuilder *sb, int op, int positive_divisor) {
    int lbl = next_label(cc);
    sb_append(sb, "  movi r4, 0\n");
    if (!positive_divisor) {
        sb_append(sb, "  cmp r1, 0\n");
        sb_append(sb, "  jz b_div_done_%d\n", lbl);
    }
    sb_append(sb, "  mov r5, r2\n");
    if (op == DIV && !positive_divisor) sb_append(sb, "  xor r5, r1\n");
    sb_append(sb, "  push r5\n");
    sb_append(sb, "  cmp r2, 0\n");
    sb_append(sb, "  jg b_div_dividend_%d\n", lbl);
    emit_negate(sb, "r2");
    sb_append(sb, "b_div_dividend_%d:\n", lbl);
    if (!positive_divisor) {
        sb_append(sb, "  cmp r1, 0\n");
        sb_append(sb, "  jg b_div_divisor_%d\n", lbl);
        emit_negate(sb, "r1");
        sb_append(sb, "b_div_divisor_%d:\n", lbl);
    }
    sb_append(sb, "  mov r5, r1\n");
    sb_append(sb, "  movi r6, 1\n");
    sb_append(sb, "b_div_grow_%d:\n", lbl);
    sb_append(sb, "  cmp r5, r2\n");
    sb_append(sb, "  ja b_div_step_%d\n", lbl);
    sb_append(sb, "  cmp r5, 0\n");
    sb_append(sb, "  jl b_div_step_%d\n", lbl);
    sb_append(sb, "  shl r5\n");
    sb_append(sb, "  shl r6\n");
    sb_append(sb, "  jmp b_div_grow_%d\n", lbl);
    sb_append(sb, "b_div_step_%d:\n", lbl);
    sb_append(sb, "  cmp r6, 0\n");
    sb_append(sb, "  jz b_div_sign_%d\n", lbl);
    sb_append(sb, "  cmp r2, r5\n");
    sb_append(sb, "  jb b_div_next_%d\n", lbl);
    sb_append(sb, "  sub r2, r5\n");
    sb_append(sb, "  add r4, r6\n");
    sb_append(sb, "b_div_next_%d:\n", lbl);
    sb_append(sb, "  shr r5\n");
    sb_append(sb, "  shr r6\n");
    sb_append(sb, "  jmp b_div_step_%d\n", lbl);
    sb_append(sb, "b_div_sign_%d:\n", lbl);
    sb_append(sb, "  pop r5\n");
    sb_append(sb, "  cmp r5, 0\n");
    sb_append(sb, "  jg b_div_done_%d\n", lbl);
    // Only a quotient from two equal numbers has a zero sign word and a nonzero
    // answer; a zero answer comes to no harm from being negated.
    if (op == DIV && !positive_divisor) sb_append(sb, "  jz b_div_done_%d\n", lbl);
    emit_negate(sb, op == DIV ? "r4" : "r2");
    sb_append(sb, "b_div_done_%d:\n", lbl);
}

// Whether `node` is a literal that needs no sign or zero check as a divisor.
static int is_positive_literal(ASTNode *node) {
    long value;
    return literal_value(node, &value) && value > 0;
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
        // Repeated-add multiply: r4 += r2, `count` (r5) times. The count must
        // be non-negative or the decrement loop never reaches 0, so if r1 is
        // negative we negate both the count and the addend: (-a)*b == a*(-b).
        sb_append(sb, "\n; multiply r2 * r1\n");
        codegen_cost_begin(sb, "arith");
        sb_append(sb, "  movi r4, 0      ; r4 = result\n");
        sb_append(sb, "  mov r5, r1     ; r5 = count\n");
        int lbl_mul = next_label(cc);
        // If the count (r5) is negative the decrement loop would never reach 0,
        // so negate both count and addend first: (-a)*b == a*(-b).
        sb_append(sb, "  cmp r5, 0\n");
        sb_append(sb, "  jl b_mul_neg_%d\n", lbl_mul);
        sb_append(sb, "  jmp b_mul_loop_%d\n", lbl_mul);
        sb_append(sb, "b_mul_neg_%d:\n", lbl_mul);
        sb_append(sb, "  movi r6, 0\n");
        sb_append(sb, "  sub r6, r5     ; r6 = -count\n");
        sb_append(sb, "  mov r5, r6\n");
        sb_append(sb, "  movi r6, 0\n");
        sb_append(sb, "  sub r6, r2     ; r6 = -addend\n");
        sb_append(sb, "  mov r2, r6\n");
        sb_append(sb, "b_mul_loop_%d:\n", lbl_mul);
        sb_append(sb, "  cmp r5, 0\n");
        sb_append(sb, "  jz b_mul_end_%d\n", lbl_mul);
        sb_append(sb, "  add r4, r2\n");
        sb_append(sb, "  addis r5, -1\n");
        sb_append(sb, "  jmp b_mul_loop_%d\n", lbl_mul);
        sb_append(sb, "b_mul_end_%d:\n", lbl_mul);
        sb_append(sb, "  mov r1, r4\n");
        codegen_cost_end(sb);
        return 1;
    }
    case DIV:
        sb_append(sb, "\n; divide r2 / r1\n");
        codegen_cost_begin(sb, "arith");
        emit_divide(cc, sb, DIV, is_positive_literal(node->binary.right));
        sb_append(sb, "  mov r1, r4\n");
        codegen_cost_end(sb);
        return 1;
    case MOD:
        sb_append(sb, "\n; modulo r2 %% r1\n");
        codegen_cost_begin(sb, "arith");
        emit_divide(cc, sb, MOD, is_positive_literal(node->binary.right));
        sb_append(sb, "  mov r1, r2\n");
        codegen_cost_end(sb);
        return 1;
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
