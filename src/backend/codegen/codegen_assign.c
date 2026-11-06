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
    return total > 0 ? total : 0;
}

// True when building this named literal touches no memory but its destination:
// every field is a constant, or a nested literal of constants.
static bool literal_reads_no_memory(ASTNode *literal) {
    for (int i = 0; i < literal->init_list.count; i++) {
        ASTNode *field = literal->init_list.elements[i];
        switch (field->type) {
        case AST_NUMBER:
        case AST_CHAR_LITERAL:
        case AST_STRING_LITERAL:
            break;
        case AST_INIT_LIST:
            if (!field->init_list.struct_type_name ||
                !literal_reads_no_memory(field))
                return false;
            break;
        default:
            return false;
        }
    }
    return true;
}

// `dest = <literal or aggregate call>` when the right side may read dest. Both
// write their result in place and start by clearing or filling it, so building
// straight into dest would let the right side see a half-written value: `v =
// P { x: v.y, y: v.x }` read zeros, and so did `v = f(v)`, whose by-value
// argument and hidden out-pointer are the same address. The value is built in
// a stack temporary instead and copied once it is complete.
//
// dest's address is still computed first, so an index in it is evaluated
// before the right side. The old value is dropped last, because the right side
// may read it or move it away. Leaves dest's address in r3.
static void gen_assign_through_temp(CompilerContext *cc, ASTNode *node, int bytes,
                                    DropBinding *old_value, StringBuilder *sb,
                                    char **params, int param_count,
                                    char **locals, int local_count) {
    ASTNode *rhs = node->assign.right;
    int reserved = (bytes + SLOT_SIZE - 1) / SLOT_SIZE * SLOT_SIZE;

    gen_lvalue_addr(cc, node->assign.left, sb, "r3",
                    params, param_count, locals, local_count);
    sb_append(sb, "  ; build assigned value in a temporary\n");
    sb_append(sb, "  push r3\n");
    sb_append(sb, "  addis sp, -%d\n", reserved);
    if (rhs->type == AST_INIT_LIST) {
        sb_append(sb, "  mov r3, sp\n");
        gen_struct_literal_into_addr(cc, rhs, sb, "r3",
                                     params, param_count, locals, local_count);
    } else {
        sb_append(sb, "  mov r1, sp\n");
        sb_append(sb, "  push r1\n");
        gen_call_sret(cc, rhs, sb, params, param_count, locals, local_count);
    }
    if (old_value)
        emit_drop_binding(cc, old_value, sb, params, param_count, locals, local_count);
    sb_append(sb, "  mov r2, sp\n");
    sb_append(sb, "  mov r3, sp\n");
    sb_append(sb, "  addis r3, %d\n", reserved);
    sb_append(sb, "  load r3, r3\n");
    emit_aggregate_copy(sb, "r3", "r2", bytes);
    sb_append(sb, "  addis sp, %d\n", reserved + SLOT_SIZE);
}

static void finish_drop_assignment(CompilerContext *cc, DropBinding *dest,
                                   DropBinding *source, StringBuilder *sb) {
    if (!dest) return;
    activate_drop_binding(cc, dest->name, sb);
    if (source && source != dest) emit_drop_flag(cc, source, false, sb);
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
    if (node->assign.left->type != AST_IDENTIFIER &&
        expr_needs_drop(cc, node->assign.left)) {
        fprintf(stderr,
                "Codegen error at %d:%d: replacing a droppable field or "
                "dereference is not supported yet; replace its containing "
                "owner instead\n",
                node->assign.left->line, node->assign.left->col);
        exit(1);
    }
    DropBinding *dest_drop = node->assign.left->type == AST_IDENTIFIER
        ? find_drop_binding(cc, node->assign.left->identifier.name) : NULL;
    DropBinding *source_drop = drop_binding_for_expr(cc, node->assign.right);
    bool self_move = dest_drop && source_drop == dest_drop;
    DropBinding *old_value = self_move ? NULL : dest_drop;
    bool literal = node->assign.right->type == AST_INIT_LIST &&
                   node->assign.right->init_list.struct_type_name;
    int total = aggregate_assign_size(cc, node->assign.left);
    int temp_bytes = 0;
    if (literal && !literal_reads_no_memory(node->assign.right)) {
        temp_bytes = find_struct(cc, node->assign.right->init_list.struct_type_name)->size_bytes;
    } else if (!literal && total > 0 && call_return_aggregate_size(cc, node->assign.right) > 0) {
        temp_bytes = total;
    }
    if (temp_bytes > 0) {
        gen_assign_through_temp(cc, node, temp_bytes, old_value, sb,
                                params, param_count, locals, local_count);
        if (target_reg && strcmp(target_reg, "r3") != 0)
            sb_append(sb, "  mov %s, r3\n", target_reg);
        finish_drop_assignment(cc, dest_drop, source_drop, sb);
        return;
    }
    if (old_value)
        emit_drop_binding(cc, old_value, sb, params, param_count, locals, local_count);
    if (literal) {
        gen_lvalue_addr(cc, node->assign.left, sb, "r3",
                        params, param_count, locals, local_count);
        gen_struct_literal_into_addr(cc, node->assign.right, sb, "r3",
                                     params, param_count, locals, local_count);
        if (target_reg && strcmp(target_reg, "r3") != 0)
            sb_append(sb, "  mov %s, r3\n", target_reg);
        finish_drop_assignment(cc, dest_drop, source_drop, sb);
        return;
    }
    if (total > 0) {
        if (node->assign.right->type == AST_STRING_LITERAL && total == SLOT_SIZE * 2) {
            gen_lvalue_addr(cc, node->assign.left, sb, "r3",
                            params, param_count, locals, local_count);
            emit_string_literal_into_addr(cc, node->assign.right, sb, "r3");
            if (target_reg && strcmp(target_reg, "r3") != 0)
                sb_append(sb, "  mov %s, r3\n", target_reg);
            finish_drop_assignment(cc, dest_drop, source_drop, sb);
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
        finish_drop_assignment(cc, dest_drop, source_drop, sb);
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
    finish_drop_assignment(cc, dest_drop, source_drop, sb);
}
