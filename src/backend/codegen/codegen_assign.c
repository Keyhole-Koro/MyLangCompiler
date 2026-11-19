#include "mylang/frontend/parser_ast_internal.h"
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
//
// A write through a borrow of an owned value comes here as well, with any right
// side: no binding owns what the place holds, so it is dropped where it sits.
static void gen_assign_through_temp(CompilerContext *cc, ASTNode *node, int bytes,
                                    DropBinding *old_value, bool drops_place, StringBuilder *sb,
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
    } else if (call_return_aggregate_size(cc, rhs) > 0) {
        sb_append(sb, "  mov r1, sp\n");
        sb_append(sb, "  push r1\n");
        gen_call_sret(cc, rhs, sb, params, param_count, locals, local_count);
    } else {
        gen_lvalue_addr(cc, rhs, sb, "r2", params, param_count, locals, local_count);
        sb_append(sb, "  mov r3, sp\n");
        emit_aggregate_copy(sb, "r3", "r2", bytes);
    }
    if (old_value)
        emit_drop_binding(cc, old_value, sb, params, param_count, locals, local_count);
    if (drops_place) {
        sb_append(sb, "  mov r5, sp\n");
        sb_append(sb, "  addis r5, %d\n", reserved);
        sb_append(sb, "  load r5, r5\n");
        emit_drop_value_at(cc, node->assign.left, "r5", sb);
    }
    sb_append(sb, "  mov r2, sp\n");
    sb_append(sb, "  mov r3, sp\n");
    sb_append(sb, "  addis r3, %d\n", reserved);
    sb_append(sb, "  load r3, r3\n");
    emit_aggregate_copy(sb, "r3", "r2", bytes);
    sb_append(sb, "  addis sp, %d\n", reserved + SLOT_SIZE);
}

typedef struct {
    ASTNode *(*map)(const void *data, ASTNode *value);
    const void *data;
} YieldMap;

static void map_yields(ASTNode **slot, void *context) {
    ASTNode *node = slot ? *slot : NULL;
    /* A nested statement expression's yields are its own. */
    if (!node || node->type == AST_STMT_EXPR || node->type == AST_FUN_LITERAL) return;
    YieldMap *yields = context;
    if (node->type == AST_YIELD) {
        if (node->yield_stmt.expr) node->yield_stmt.expr = yields->map(yields->data, node->yield_stmt.expr);
        return;
    }
    ast_visit_children(node, map_yields, context);
}

void map_stmt_expr_yields(ASTNode *stmt_expr, ASTNode *(*map)(const void *data, ASTNode *value),
                          const void *data) {
    YieldMap yields = { map, data };
    ast_visit_children(stmt_expr, map_yields, &yields);
}

static ASTNode *assigning_arm(const ASTNode *dest, ASTNode *arm);

static ASTNode *assign_yielded(const void *dest, ASTNode *value) {
    return assigning_arm(dest, value);
}

int is_selection(const ASTNode *expr) {
    return expr && (expr->type == AST_TERNARY || expr->type == AST_CASE);
}

void map_selection_arms(ASTNode *selection, ASTNode *(*map)(const void *data, ASTNode *arm),
                        const void *data) {
    if (selection->type == AST_TERNARY) {
        selection->ternary.then_expr = map(data, selection->ternary.then_expr);
        selection->ternary.else_expr = map(data, selection->ternary.else_expr);
        return;
    }
    for (int i = 0; i < selection->case_expr.case_count; i++) {
        CaseItem *arm = &selection->case_expr.cases[i];
        if (!arm->is_noop) arm->expr = map(data, arm->expr);
    }
    if (selection->case_expr.default_expr)
        selection->case_expr.default_expr = map(data, selection->case_expr.default_expr);
}

void gen_selection_into(CompilerContext *cc, const ASTNode *dest, ASTNode *selection,
                        StringBuilder *sb, char **params, int param_count,
                        char **locals, int local_count) {
    map_selection_arms(selection, assign_yielded, dest);
    gen_expr(cc, selection, sb, "r1", params, param_count, locals, local_count);
}

/* An arm of a case or conditional whose value belongs in `dest`, made to
 * assign it there: `({ dest = arm; })`, or a statement expression's yields
 * made to. `dest` is cloned for each use. The selection then yields nothing
 * anyone reads, so an aggregate never passes through its register. */
static ASTNode *assigning_arm(const ASTNode *dest, ASTNode *arm) {
    if (!arm) return arm;
    if (arm->type == AST_STMT_EXPR) {
        /* `({ ...; yield v; })` assigns v where it yields it. An arm that
         * leaves instead (`({ return y; })`) yields nothing to assign. */
        map_stmt_expr_yields(arm, assign_yielded, dest);
        return arm;
    }
    ASTNode **stmts = malloc(sizeof(ASTNode *));
    stmts[0] = new_expr_stmt(new_assign(ast_clone(dest), arm));
    return new_stmt_expr(new_block(stmts, 1));
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
    if (is_selection(node->assign.right) && aggregate_assign_size(cc, node->assign.left) > 0) {
        /* Only one arm runs, so x is evaluated once. */
        gen_selection_into(cc, node->assign.left, node->assign.right, sb,
                           params, param_count, locals, local_count);
        if (target_reg)
            gen_lvalue_addr(cc, node->assign.left, sb, target_reg, params, param_count, locals, local_count);
        return;
    }
    bool construction = node->assign.fills_new_value;
    bool through_borrow = node->assign.left->type == AST_UNARY &&
                          node->assign.left->unary.is_implicit &&
                          expr_needs_drop(cc, node->assign.left);
    if (node->assign.left->type != AST_IDENTIFIER && !construction && !through_borrow &&
        expr_needs_drop(cc, node->assign.left)) {
        fprintf(stderr,
                "Codegen error at %d:%d: replacing a droppable field or "
                "dereference is not supported yet; replace its containing "
                "owner instead\n",
                node->assign.left->line, node->assign.left->col);
        exit(1);
    }
    DropBinding *dest_drop = node->assign.left->type == AST_IDENTIFIER || construction
        ? drop_binding_for_expr(cc, node->assign.left) : NULL;
    DropBinding *source_drop = drop_binding_for_expr(cc, node->assign.right);
    bool self_move = dest_drop && source_drop == dest_drop;
    DropBinding *old_value = self_move || construction ? NULL : dest_drop;
    bool literal = node->assign.right->type == AST_INIT_LIST &&
                   node->assign.right->init_list.struct_type_name;
    int total = aggregate_assign_size(cc, node->assign.left);
    int temp_bytes = 0;
    if (literal && !literal_reads_no_memory(node->assign.right)) {
        temp_bytes = find_struct(cc, node->assign.right->init_list.struct_type_name)->size_bytes;
    } else if (!literal && total > 0 && call_return_aggregate_size(cc, node->assign.right) > 0) {
        temp_bytes = total;
    }
    if (through_borrow) temp_bytes = total;
    if (temp_bytes > 0) {
        gen_assign_through_temp(cc, node, temp_bytes, old_value, through_borrow, sb,
                                params, param_count, locals, local_count);
        if (target_reg && strcmp(target_reg, "r3") != 0)
            sb_append(sb, "  mov %s, r3\n", target_reg);
        finish_drop_assignment(cc, dest_drop, source_drop, sb);
        if (through_borrow) emit_drop_flag(cc, source_drop, false, sb);
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
