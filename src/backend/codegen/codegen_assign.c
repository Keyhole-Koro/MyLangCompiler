#include "mylang/backend/codegen_internal.h"

// Size in bytes of a struct or array being assigned as a whole, or 0 when the
// target is an ordinary scalar that a single store covers. A pointer is a
// scalar however aggregate the thing it points at is.
static int aggregate_assign_size(CompilerContext *cc, ASTNode *lhs) {
    TypeInfo ti = {0};
    if (!infer_expr_type(cc, lhs, &ti)) return 0;
    if (ti.pointer_level != 0) return 0;
    if (!ti.is_array && !find_struct(cc, ti.base_type)) return 0;

    int total = typeinfo_total_size_bytes(cc, &ti);
    return total > 4 ? total : 0;
}

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
    int total = aggregate_assign_size(cc, node->assign.left);
    if (total > 0) {
        if (call_returns_aggregate(cc, node->assign.right)) {
            // `y = callee(args);` -- same hidden out-pointer convention as a
            // var-decl initializer (codegen_stmt.c), just with y's address
            // computed generally since it may be a field or a deref, not
            // only a plain name.
            gen_lvalue_addr(cc, node->assign.left, sb, "r1", params, param_count, locals, local_count);
            sb_append(sb, "  push r1\n");
            gen_call_sret(cc, node->assign.right, sb, params, param_count, locals, local_count);
            // The value of the assignment expression is the destination
            // itself; recomputing its address is safe here because every
            // addressable form (identifier/member/arrow/deref) reads it
            // without side effects.
            if (target_reg) {
                gen_lvalue_addr(cc, node->assign.left, sb, target_reg, params, param_count, locals, local_count);
            }
            return;
        }

        // Assigning a whole struct or array copies every byte. Evaluating the
        // right side with gen_expr would load only its first word, which used
        // to make `b = a;` silently keep b's other members -- a wrong answer
        // with no diagnostic.
        if (!is_addressable_expr(node->assign.right)) {
            fprintf(stderr,
                    "Codegen error: assigning a struct or array from a "
                    "non-lvalue is not supported yet\n");
            exit(1);
        }

        gen_lvalue_addr(cc, node->assign.right, sb, "r1", params, param_count, locals, local_count);
        sb_append(sb, "  push r1\n");
        gen_lvalue_addr(cc, node->assign.left, sb, "r3", params, param_count, locals, local_count);
        sb_append(sb, "  pop r2\n");

        emit_aggregate_copy(sb, "r3", "r2", total);

        // The value of an aggregate assignment is the destination itself;
        // r3 still holds its address.
        if (target_reg && strcmp(target_reg, "r3") != 0) {
            sb_append(sb, "  mov %s, r3\n", target_reg);
        }
        return;
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

