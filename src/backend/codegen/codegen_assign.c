#include "mylang/backend/codegen_internal.h"

void gen_assign(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
              char **params, int param_count,
              char **locals, int local_count,
              const char *target_reg) {
    if (!node || node->type != AST_ASSIGN) {
        fprintf(stderr, "Codegen error: gen_assign called on non-assignment node\n");
        exit(1);
    }
    if (lvalue_is_const(cc, node->assign.left)) {
        fprintf(stderr, "Codegen error: assignment to const lvalue is not allowed\n");
        exit(1);
    }
    gen_expr(cc, node->assign.right, sb, "r1", params, param_count, locals, local_count);
    sb_append(sb, "  push r1\n");
    gen_lvalue_addr(cc, node->assign.left, sb, "r3", params, param_count, locals, local_count);
    int width = lvalue_width_bytes(cc, node->assign.left);
    sb_append(sb, "  pop r1\n");
    emit_store_width_to_addr(sb, "r3", "r1", width);
    if (target_reg && strcmp(target_reg, "r1") != 0) {
        sb_append(sb, "  mov %s, r1\n", target_reg);
    }
}

