#include "mylang/backend/codegen_internal.h"

int is_comparison_op(TokenKind op) {
    return op == EQ || op == NEQ || op == LT || op == GT || op == LTE || op == GTE;
}

// Emit conditional jump based on binary comparison operator
// If the condition is true, jump to `trueLabel`
// If the condition is false, jump to `falseLabel` (optional)
// Supported operators: ==, !=, <, >, <=, >= using basic jz, jnz, jl, jg
void emit_cond_jump(CompilerContext *cc, ASTNode *left, ASTNode *right, TokenKind op, StringBuilder *sb,
                    char **params, int param_count, char **locals, int local_count,
                    const char *trueLabel, const char *falseLabel)
{
    // Generate left and right expressions into r2 and r3. The right operand may
    // itself be an expression that clobbers r2 (e.g. a binary op evaluates its
    // own operands through r2/r1), so preserve the left result across it.
    gen_expr(cc, left, sb, "r2", params, param_count, locals, local_count);
    sb_append(sb, "  push r2\n");
    gen_expr(cc, right, sb, "r3", params, param_count, locals, local_count);
    sb_append(sb, "  pop r2\n");
    sb_append(sb, "  cmp r2, r3\n");

    // Emit jump instructions based on operator
    switch (op)
    {
    case EQ: // ==
        sb_append(sb, "  jz %s\n", trueLabel);
        if (falseLabel)
            sb_append(sb, "  jmp %s\n", falseLabel);
        break;
    case NEQ: // !=
        sb_append(sb, "  jnz %s\n", trueLabel);
        if (falseLabel)
            sb_append(sb, "  jmp %s\n", falseLabel);
        break;
    case LT: // <
        sb_append(sb, "  jl %s\n", trueLabel);
        if (falseLabel)
            sb_append(sb, "  jmp %s\n", falseLabel);
        break;
    case GT: // >
        sb_append(sb, "  jg %s\n", trueLabel);
        if (falseLabel)
            sb_append(sb, "  jmp %s\n", falseLabel);
        break;
    case LTE: // <= → !(a > b)
        if (falseLabel)
            sb_append(sb, "  jg %s\n", falseLabel); // if a > b → jump to false
        sb_append(sb, "  jmp %s\n", trueLabel);     // else → true
        break;
    case GTE: // >= → !(a < b)
        if (falseLabel)
            sb_append(sb, "  jl %s\n", falseLabel); // if a < b → jump to false
        sb_append(sb, "  jmp %s\n", trueLabel);     // else → true
        break;
    default:
        // Fallback: treat nonzero as true
        sb_append(sb, "  jnz %s\n", trueLabel);
        if (falseLabel)
            sb_append(sb, "  jmp %s\n", falseLabel);
        break;
    }
}
