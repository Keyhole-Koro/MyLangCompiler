#include "mylang/semantic/semantic_internal.h"
#include "mylang/semantic/diagnostic_codes.h"
#include "mylang/frontend/parser_ast_internal.h"

/* The walk over expressions: uses of names, calls and their arguments, and
 * `case`. */

static void use_identifier(SemanticContext *ctx, ASTNode *node, ExprContext expr_ctx) {
    SemanticBinding *binding;
    ASTNode *ident = semantic_as_identifier(node);

    if (!ctx || !ident) return;
    if (strcmp(ident->identifier.name, "_") == 0) return;
    if (semantic_find_enum_value(ctx, ident->identifier.name, NULL)) {
        if (expr_ctx == EXPRCTX_WRITE) {
            semantic_error_at(ctx, semantic_location_from_ast(node),
                              "cannot assign to enum constant '%s'", ident->identifier.name);
        }
        return;
    }
    if (semantic_find_function_sig(ctx, ident->identifier.name)) {
        if (expr_ctx == EXPRCTX_WRITE) {
            semantic_error_at(ctx, semantic_location_from_ast(node),
                              "cannot assign to function '%s'", ident->identifier.name);
        }
        return;
    }
    binding = semantic_find_binding(ctx, ident->identifier.name);
    if (!binding && semantic_call_may_be_package_import(ctx, ident->identifier.name)) {
        if (expr_ctx == EXPRCTX_WRITE) {
            semantic_error_at(ctx, semantic_location_from_ast(node),
                              "cannot assign to imported symbol '%s'", ident->identifier.name);
        }
        return;
    }
    if (!binding) {
        semantic_error_code_at(ctx, semantic_location_from_ast(node),
                               SEMCODE_UNDEFINED_IDENTIFIER,
                               "undefined identifier '%s'", ident->identifier.name);
        return;
    }

    if (expr_ctx == EXPRCTX_WRITE && binding->has_type &&
        (binding->type_info.type_modifiers & TYPEMOD_CONST) != 0) {
        semantic_error_at(ctx, semantic_location_from_ast(node),
                          "cannot assign to const value '%s'", ident->identifier.name);
        return;
    }

    if (expr_ctx == EXPRCTX_MOVE && binding->reads_owned_value) {
        semantic_error_code_at(ctx, semantic_location_from_ast(node), SEMCODE_WRITE_TO_READ_PARAM,
                               "cannot move '%s', which this function only reads", ident->identifier.name);
        semantic_note_binding_decl_if_known(ctx, binding, "here; declare it `move`");
        return;
    }

    if (expr_ctx == EXPRCTX_MOVE &&
        (binding->borrow_active || binding->read_in_place_arg_count > 0)) {
        semantic_error_at(ctx, semantic_location_from_ast(node),
                          "cannot move '%s' while it is borrowed", ident->identifier.name);
        if (binding->borrow_active && semantic_location_is_known(binding->last_borrow_loc)) {
            semantic_note_at(ctx, binding->last_borrow_loc,
                             "borrow of '%s' starts here", binding->name);
        }
        return;
    }

    /* Rule B5: while a local holds `&x`, `x` is used only through it. */
    if (expr_ctx != EXPRCTX_WRITE && binding->borrow_held && !ctx->in_borrow_operand) {
        semantic_error_code_at(ctx, semantic_location_from_ast(node), SEMCODE_USE_WHILE_BORROWED,
                               "cannot use '%s' while it is borrowed", ident->identifier.name);
        if (semantic_location_is_known(binding->last_borrow_loc)) {
            semantic_note_at(ctx, binding->last_borrow_loc,
                             "borrow of '%s' starts here", binding->name);
        }
        return;
    }

    if (binding->moved && expr_ctx != EXPRCTX_WRITE) {
        semantic_error_at(ctx, semantic_location_from_ast(node),
                          "use of moved value '%s'", ident->identifier.name);
        if (semantic_location_is_known(binding->move_loc)) {
            semantic_note_at(ctx, binding->move_loc, "'%s' moved here", binding->name);
        }
        return;
    }

    if (expr_ctx == EXPRCTX_MOVE && !binding->is_copy) {
        binding->moved = 1;
        binding->move_loc = semantic_location_from_ast(node);
    }
}

/* `({ ...; return x; })` and the like leave instead of producing a value, so
 * whatever they move is not moved for the code after the case. */
static int case_arm_diverges(ASTNode *expr) {
    if (!expr || expr->type != AST_STMT_EXPR || !expr->stmt_expr.block ||
        expr->stmt_expr.block->type != AST_BLOCK || expr->stmt_expr.block->block.count == 0)
        return 0;
    ASTNode *last = expr->stmt_expr.block->block.stmts[expr->stmt_expr.block->block.count - 1];
    return last && (last->type == AST_RETURN || last->type == AST_BREAK || last->type == AST_CONTINUE);
}

/* Each arm starts from the state before the case: only one of them runs, so
 * a value moved by one arm is still available to the others. After the case,
 * a value counts as moved if any arm that falls through moved it. */
static void walk_case_items(SemanticContext *ctx, ASTNode *node, int allow_noop) {
    SemanticBindingSnapshot *base = malloc(sizeof(SemanticBindingSnapshot));
    SemanticBindingSnapshot *merged = malloc(sizeof(SemanticBindingSnapshot));
    SemanticBindingSnapshot *arm = malloc(sizeof(SemanticBindingSnapshot));
    int have_merged = 0;
    semantic_snapshot_bindings(ctx, base);

    int arm_count = node->case_expr.case_count + 1;
    for (int i = 0; i < arm_count; i++) {
        int is_default = i == node->case_expr.case_count;
        ASTNode *expr = is_default ? node->case_expr.default_expr : node->case_expr.cases[i].expr;
        int is_noop = is_default ? node->case_expr.default_is_noop : node->case_expr.cases[i].is_noop;
        semantic_restore_bindings(ctx, base);
        if (!is_default) semantic_walk_expr(ctx, node->case_expr.cases[i].key, EXPRCTX_READ);
        if (is_noop) {
            if (!allow_noop) {
                semantic_error_at(ctx, semantic_location_from_ast(node),
                                  "a `-> _` case arm is only valid when the case is used as a statement");
            }
        } else if (allow_noop && expr && expr->type == AST_CASE) {
            /* An arm of a statement is a statement, as a nested pattern's is. */
            semantic_walk_case(ctx, expr, 1);
        } else {
            semantic_walk_expr(ctx, expr, EXPRCTX_READ);
        }
        if (case_arm_diverges(expr)) continue;
        semantic_snapshot_bindings(ctx, arm);
        if (!have_merged) {
            *merged = *arm;
            have_merged = 1;
        } else {
            semantic_merge_if_binding_states(ctx, base, merged, arm);
            semantic_snapshot_bindings(ctx, merged);
        }
    }
    semantic_restore_bindings(ctx, have_merged ? merged : base);
    free(base);
    free(merged);
    free(arm);
}

static int case_key_matches(SemanticContext *ctx, ASTNode *key, long value) {
    long key_value = 0;
    if (!key) return 0;
    if (key->type == AST_NUMBER && key->number.value)
        return strtol(key->number.value, NULL, 10) == value;
    if (key->type == AST_IDENTIFIER && semantic_find_enum_value(ctx, key->identifier.name, &key_value))
        return key_value == value;
    return 0;
}

/* A match on a plain enum without a `_` arm must name every member: an
 * unmatched value would otherwise yield zero, a silently wrong answer.
 * Payload enums get the same check when their arms are lowered
 * (parser_payload_enum.c). */
static void check_enum_case_coverage(SemanticContext *ctx, ASTNode *node) {
    if (node->case_expr.default_expr || node->case_expr.default_is_noop) return;
    SemanticTypeInfo type;
    if (!semantic_infer_expr_type(ctx, node->case_expr.target, &type)) return;
    if (!type.base_type || type.pointer_level > 0 || type.is_array) return;

    char missing[192];
    size_t used = 0;
    int count = 0;
    int members = 0;
    missing[0] = '\0';
    for (int i = 0; i < ctx->enum_value_count; i++) {
        SemanticEnumValue *member = &ctx->enum_values[i];
        if (!member->enum_name || strcmp(member->enum_name, type.base_type) != 0) continue;
        members++;
        int seen = 0;
        for (int c = 0; c < node->case_expr.case_count && !seen; c++)
            seen = case_key_matches(ctx, node->case_expr.cases[c].key, member->value);
        if (seen) continue;
        int written = snprintf(missing + used, sizeof(missing) - used, "%s%s",
                               count ? ", " : "", member->name);
        if (written > 0 && used + (size_t)written < sizeof(missing)) used += (size_t)written;
        count++;
    }
    if (!count) {
        if (members > 0) node->case_expr.is_exhaustive = 1;
        return;
    }
    semantic_error_at(ctx, semantic_location_from_ast(node),
                      "this match does not cover %s of '%s': %s. Add %s, or a `_` arm",
                      count == 1 ? "one member" : "every member", type.base_type, missing,
                      count == 1 ? "an arm for it" : "arms for them");
}

void semantic_walk_case(SemanticContext *ctx, ASTNode *node, int allow_noop) {
    semantic_walk_expr(ctx, node->case_expr.target, EXPRCTX_READ);
    check_enum_case_coverage(ctx, node);
    walk_case_items(ctx, node, allow_noop);
}

/* `move T x`: the callee takes the argument, and the caller's name is spent. */
static int call_takes_argument(const SemanticFunctionSig *callee, int i) {
    return callee && i < SEMANTIC_MAX_FUNCTION_PARAMS && callee->param_is_move[i];
}

static int call_reads_argument(const SemanticFunctionSig *callee, int i) {
    return callee && callee->has_param_types && i < callee->fixed_param_count &&
           i < SEMANTIC_MAX_FUNCTION_PARAMS && !callee->param_is_move[i] &&
           callee->param_types[i].borrow_kind == REFKIND_NONE &&
           callee->param_types[i].pointer_level == 0;
}

/* Nothing would drop an owned value that a call makes and another only reads. */
static void check_read_temporary(SemanticContext *ctx, const SemanticFunctionSig *callee, int i, ASTNode *arg) {
    SemanticTypeInfo type;
    if (!arg || arg->type != AST_CALL || !call_reads_argument(callee, i) ||
        !semantic_infer_expr_type(ctx, arg, &type) || !semantic_typeinfo_has_drop(ctx, &type))
        return;
    semantic_error_code_at(ctx, semantic_location_from_ast(arg), SEMCODE_WRITE_TO_READ_PARAM,
                           "this value has no owner; give it a name before passing it to a parameter that only reads");
}

static int arg_is_read_in_place(SemanticContext *ctx, const SemanticFunctionSig *callee, int i, ASTNode *arg) {
    SemanticTypeInfo type;
    if (!arg || (arg->type != AST_IDENTIFIER && arg->type != AST_MEMBER_ACCESS) ||
        !call_reads_argument(callee, i) || !semantic_infer_expr_type(ctx, arg, &type))
        return 0;
    if (type.is_array) return 1;
    for (int s = 0; type.base_type && s < ctx->struct_layout_count; s++) {
        if (strcmp(ctx->struct_layouts[s].name, type.base_type) == 0) return 1;
    }
    return 0;
}

void semantic_walk_expr(SemanticContext *ctx, ASTNode *node, ExprContext expr_ctx) {
    if (!ctx || !node) return;

    switch (node->type) {
    case AST_NUMBER:
    case AST_STRING_LITERAL:
    case AST_CHAR_LITERAL:
        break;
    case AST_IDENTIFIER:
        use_identifier(ctx, node, expr_ctx);
        break;
    case AST_BINARY:
        semantic_walk_expr(ctx, node->binary.left, EXPRCTX_READ);
        semantic_walk_expr(ctx, node->binary.right, EXPRCTX_READ);
        semantic_check_binary_type(ctx, node);
        semantic_check_unsafe_operation(ctx, node);
        break;
    case AST_ASSIGN:
        semantic_walk_expr(ctx, node->assign.right, EXPRCTX_MOVE);
        semantic_walk_expr(ctx, node->assign.left, EXPRCTX_WRITE);
        semantic_check_write_place(ctx, node->assign.left, WRITE_ASSIGN);
        semantic_check_assignment_type(ctx, node);
        semantic_revive_binding_if_identifier(ctx, node->assign.left);
        if (node->assign.is_construction) semantic_hold_payload_borrow(ctx, node);
        break;
    case AST_BORROW:
        ctx->in_borrow_operand++;
        semantic_walk_expr(ctx, node->borrow.expr, EXPRCTX_READ);
        ctx->in_borrow_operand--;
        semantic_check_write_place(ctx, node->borrow.expr, WRITE_BORROW);
        break;
    case AST_UNARY:
        semantic_check_dereference(ctx, node);
        /* Checked before the operand, which it marks when it is the
         * `p + i` of an index. */
        semantic_check_unsafe_operation(ctx, node);
        semantic_check_constant_index(ctx, node);
        semantic_walk_expr(ctx, node->unary.operand, EXPRCTX_READ);
        if (node->unary.op == INC || node->unary.op == DEC ||
            node->unary.op == POST_INC || node->unary.op == POST_DEC)
            semantic_check_write_place(ctx, node->unary.operand, WRITE_STEP);
        break;
    case AST_CAST:
        semantic_walk_stmt(ctx, node->cast.type);
        semantic_walk_expr(ctx, node->cast.expr, EXPRCTX_READ);
        semantic_check_unsafe_operation(ctx, node);
        break;
    case AST_CALL: {
        /* Keep temporary argument borrows alive until the entire call has
         * been checked, including nested calls in later arguments. */
        int saved_read_in_place[256], saved_borrow_active[256];
        int saved_count = ctx->binding_count;
        for (int i = 0; i < saved_count; i++) {
            saved_read_in_place[i] = ctx->bindings[i].read_in_place_arg_count;
            saved_borrow_active[i] = ctx->bindings[i].borrow_active;
        }
        SemanticFunctionSig *callee = semantic_find_function_sig(ctx, node->call.name);
        /* Every argument is evaluated before the call lends anything, so
         * `buf.truncate(buf.len() - 1)` reads `buf` first: only what is
         * still lent when the call starts can conflict. */
        for (int i = 0; i < node->call.arg_count; i++) {
            ASTNode *arg = node->call.args[i];
            SemanticBinding *reference = arg && arg->type == AST_IDENTIFIER
                ? semantic_find_binding(ctx, arg->identifier.name) : NULL;
            if (reference && (!reference->has_type || reference->type_info.borrow_kind == REFKIND_NONE))
                reference = NULL;
            /* Passing a named borrow on reborrows it: a conflict is reported
             * below, as for `&x`. */
            if (reference) ctx->in_borrow_operand++;
            semantic_walk_expr(ctx, arg, !reference && call_takes_argument(callee, i) ? EXPRCTX_MOVE : EXPRCTX_READ);
            if (reference) ctx->in_borrow_operand--;
            check_read_temporary(ctx, callee, i, arg);
        }
        for (int i = 0; i < node->call.arg_count; i++) {
            ASTNode *arg = node->call.args[i];
            SemanticBinding *reference = arg && arg->type == AST_IDENTIFIER
                ? semantic_find_binding(ctx, arg->identifier.name) : NULL;
            if (reference && (!reference->has_type || reference->type_info.borrow_kind == REFKIND_NONE))
                reference = NULL;
            /* An address handed to a raw pointer is no longer tracked (B9). */
            if (callee && callee->has_param_types && i < callee->fixed_param_count &&
                i < SEMANTIC_MAX_FUNCTION_PARAMS && callee->param_types[i].pointer_level > 0 &&
                callee->param_types[i].borrow_kind == REFKIND_NONE)
                continue;
            int lends = arg && arg->type == AST_BORROW;
            ASTNode *target = lends ? arg->borrow.expr : NULL;
            /* A nested call that returns a borrow keeps its first argument
             * lent (rule B6) through this call too. */
            if (!target && arg && arg->type == AST_CALL && arg->call.arg_count > 0) {
                SemanticTypeInfo returned;
                if (semantic_infer_expr_type(ctx, arg, &returned) && returned.borrow_kind != REFKIND_NONE) {
                    ASTNode *first = arg->call.args[0];
                    target = first && first->type == AST_BORROW ? first->borrow.expr : first;
                    lends = 1;
                }
            }
            /* A read argument travels as an address when it is an aggregate:
             * the same place must not be lent for writing in this call. */
            if (!target && arg_is_read_in_place(ctx, callee, i, arg)) target = arg;
            SemanticBinding *owner = semantic_borrow_target_binding(ctx, target);
            /* Reborrowing a named reference uses that reference as the
             * capability. Its owner's lexical borrow remains active, while
             * two uses of the same capability in one call conflict. */
            if (reference) {
                owner = reference;
                lends = reference->type_info.borrow_kind == REFKIND_BORROW;
            }
            if (!owner) continue;
            if (owner->borrow_active || (lends && owner->read_in_place_arg_count)) {
                semantic_error_at(ctx, semantic_location_from_ast(arg),
                                  "conflicting borrow of '%s' in function call", owner->name);
            }
            if (lends) owner->borrow_active = 1;
            else owner->read_in_place_arg_count++;
        }
        semantic_check_call_signature(ctx, node);
        for (int i = 0; i < saved_count; i++) {
            ctx->bindings[i].read_in_place_arg_count = saved_read_in_place[i];
            ctx->bindings[i].borrow_active = saved_borrow_active[i];
        }
        break;
    }
    case AST_MEMBER_ACCESS: {
        /* `a.length` on a fixed-size array is a compile-time constant: it
         * neither reads nor moves `a`, so `f(a, a.length)` is fine even
         * when passing `a` moves it. */
        SemanticTypeInfo lhs_type;
        if (node->member_access.member && strcmp(node->member_access.member, "length") == 0 &&
            semantic_infer_expr_type(ctx, node->member_access.lhs, &lhs_type) &&
            lhs_type.is_array && lhs_type.dims_count > 0) {
            break;
        }
        SemanticTypeInfo member_type;
        int move = expr_ctx == EXPRCTX_MOVE &&
            !(semantic_infer_expr_type(ctx, node, &member_type) && semantic_typeinfo_is_copy(ctx, &member_type));
        semantic_walk_expr(ctx, node->member_access.lhs, move ? EXPRCTX_MOVE : EXPRCTX_READ);
        break; }
    case AST_ARROW_ACCESS:
        semantic_check_dereference(ctx, node);
        semantic_walk_expr(ctx, node->arrow_access.lhs, expr_ctx == EXPRCTX_MOVE ? EXPRCTX_MOVE : EXPRCTX_READ);
        semantic_check_unsafe_operation(ctx, node);
        break;
    case AST_INIT_LIST:
        for (int i = 0; i < node->init_list.count; i++) {
            semantic_walk_expr(ctx, node->init_list.elements[i], EXPRCTX_READ);
        }
        semantic_check_struct_literal(ctx, node);
        break;
    case AST_SIZEOF:
        semantic_walk_expr(ctx, node->sizeof_expr.expr, EXPRCTX_READ);
        break;
    case AST_TERNARY: {
        BranchSnapshots *s = malloc(sizeof(*s));
        semantic_walk_expr(ctx, node->ternary.cond, EXPRCTX_READ);
        semantic_check_condition_type(ctx, node->ternary.cond);
        semantic_snapshot_bindings(ctx, &s->base);
        semantic_walk_expr(ctx, node->ternary.then_expr, expr_ctx);
        semantic_snapshot_bindings(ctx, &s->then_state);
        semantic_restore_bindings(ctx, &s->base);
        semantic_walk_expr(ctx, node->ternary.else_expr, expr_ctx);
        semantic_snapshot_bindings(ctx, &s->else_state);
        semantic_merge_if_binding_states(ctx, &s->base, &s->then_state, &s->else_state);
        free(s);
        break;
    }
    case AST_CASE:
        semantic_walk_case(ctx, node, 0);
        break;
    case AST_STMT_EXPR:
        semantic_walk_stmt(ctx, node->stmt_expr.block);
        break;
    case AST_TYPE:
    case AST_TYPE_ARRAY:
    case AST_TYPE_FUNCTION:
    case AST_VAR_DECL:
    case AST_EXPR_STMT:
    case AST_IF:
    case AST_RETURN:
    case AST_DEFER:
    case AST_BLOCK:
    case AST_FUN_LITERAL:
    case AST_FUNDEF:
    case AST_PARAM:
    case AST_WHILE:
    case AST_FOR:
    case AST_TYPEDEF:
    case AST_STRUCT:
    case AST_TYPEDEF_STRUCT:
    case AST_ENUM:
    case AST_ENUM_MEMBER:
    case AST_IMPORT:
    case AST_DO_WHILE:
    case AST_YIELD:
        semantic_walk_stmt(ctx, node);
        break;
    default:
        semantic_error_at(ctx, semantic_location_unknown(),
                          "semantic walker encountered unknown AST node type %d", node->type);
        break;
    }
}
