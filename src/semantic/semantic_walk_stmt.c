#include "mylang/semantic/semantic_internal.h"
#include "mylang/semantic/diagnostic_codes.h"
#include "mylang/frontend/parser_trait_internal.h"

/* The walk over statements, declarations and whole functions, and the entry
 * point of the pass. */

/* A `drop()` method still runs automatically without `impl Drop` (the
 * compatibility path), but the impl is what says so. Generic instances are
 * skipped: impls for them are not supported yet. */
static void semantic_warn_drop_without_impl(SemanticContext *ctx, ASTNode *root) {
    ParserContext *parser = parser_context_current();
    if (!parser || !root || root->type != AST_BLOCK) return;
    for (int i = 0; i < root->block.count; i++) {
        ASTNode *fn = root->block.stmts[i];
        if (!fn || fn->type != AST_FUNDEF || !fn->fundef.body || !fn->fundef.recv_type_name) continue;
        const char *recv = fn->fundef.recv_type_name;
        size_t len = strlen(recv);
        if (recv[0] == '_' && recv[1] == '_') continue;
        if (strncmp(fn->fundef.name, recv, len) != 0 || strcmp(fn->fundef.name + len, "__drop") != 0) continue;
        if (find_impl_for_name(parser, "Drop", recv)) continue;
        semantic_warning_code_at(ctx, semantic_location_from_ast(fn), SEMCODE_DROP_WITHOUT_IMPL,
                                 "%s has drop() without `impl Drop`; write `impl Drop for %s { ... }`",
                                 recv, recv);
    }
}

static void walk_params(SemanticContext *ctx, ASTNode **params, int param_count, ASTNode *body) {
    for (int i = 0; i < param_count; i++) {
        ASTNode *param = semantic_as_param(params[i]);
        semantic_walk_stmt(ctx, param);
        if (param) {
            int is_copy = param->param.is_rest ? 1 : semantic_type_is_copy(ctx, param->param.type);
            semantic_declare_binding(ctx, param->param.name, param->param.type, is_copy, 1,
                            semantic_location_from_ast(param));
            SemanticBinding *binding = semantic_find_binding(ctx, param->param.name);
            if (!binding) continue;
            binding->param_is_move = param->param.is_move;
            binding->param_is_written = ast_writes_name(body, param->param.name);
            binding->reads_owned_value = !param->param.is_move && binding->has_type &&
                semantic_typeinfo_has_drop(ctx, &binding->type_info);
        }
    }
}

/* ---- branches that leave, and loops -------------------------------------
 *
 * Rule V4 of docs/design/mylang-values.md.
 */

/* The statement leaves on every path -- by `return`, `break` or `continue`
 * -- so what it moves does not reach the code after it. A loop inside it is
 * not looked into: its `break` leaves only that loop. */
static int stmt_always_exits(ASTNode *node) {
    if (!node) return 0;
    switch (node->type) {
    case AST_RETURN:
    case AST_BREAK:
    case AST_CONTINUE:
        return 1;
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++) {
            if (stmt_always_exits(node->block.stmts[i])) return 1;
        }
        return 0;
    case AST_IF:
        return node->if_stmt.else_stmt && stmt_always_exits(node->if_stmt.then_stmt) &&
               stmt_always_exits(node->if_stmt.else_stmt);
    case AST_EXPR_STMT:
        return stmt_always_exits(node->expr_stmt.expr);
    case AST_STMT_EXPR:
        return stmt_always_exits(node->stmt_expr.block);
    default:
        return 0;
    }
}

static SemanticLoopFrame *loop_enter(SemanticContext *ctx) {
    SemanticLoopFrame *frame = malloc(sizeof(*frame));
    int count = ctx->binding_count < 256 ? ctx->binding_count : 256;
    frame->binding_count = count;
    for (int i = 0; i < count; i++) {
        frame->moved_before[i] = (unsigned char)(ctx->bindings[i].moved != 0);
        frame->moved_at_continue[i] = 0;
        frame->continue_move_loc[i] = semantic_location_unknown();
    }
    frame->outer = ctx->loop;
    ctx->loop = frame;
    return frame;
}

/* A `continue` carries the state it is reached in to the next iteration. */
static void loop_note_continue(SemanticContext *ctx) {
    SemanticLoopFrame *frame = ctx->loop;
    if (!frame) return;
    for (int i = 0; i < frame->binding_count && i < ctx->binding_count; i++) {
        if (ctx->bindings[i].moved && !frame->moved_at_continue[i]) {
            frame->moved_at_continue[i] = 1;
            frame->continue_move_loc[i] = ctx->bindings[i].move_loc;
        }
    }
}

/* Rule V4: a value from outside the loop that an iteration moves, and does
 * not assign again, would be used after the move by the next iteration.
 * `falls_through` is whether the end of the body can be reached at all. */
static void loop_leave(SemanticContext *ctx, SemanticLoopFrame *frame, int falls_through) {
    ctx->loop = frame->outer;
    for (int i = 0; i < frame->binding_count && i < ctx->binding_count; i++) {
        SemanticBinding *binding = &ctx->bindings[i];
        SemanticLocation at;
        if (frame->moved_before[i]) continue;
        if (falls_through && binding->moved) {
            at = binding->move_loc;
        } else if (frame->moved_at_continue[i]) {
            at = frame->continue_move_loc[i];
        } else {
            continue;
        }
        if (!semantic_location_is_known(at)) at = binding->decl_loc;
        semantic_error_code_at(ctx, at, SEMCODE_MOVE_IN_LOOP,
                               "'%s' is moved inside a loop, so the next iteration would use it after the move",
                               binding->name);
        semantic_note_binding_decl_if_known(ctx, binding,
                                   "outside the loop; assign it again before the next iteration, or leave the loop after the move");
    }
    free(frame);
}

static void walk_block_items(SemanticContext *ctx, ASTNode **items, int count) {
    int unreachable = 0;
    for (int i = 0; i < count; i++) {
        /* A statement the compiler added has no place in the source to point
         * at, and the one written after it is reported anyway. */
        if (unreachable && items[i] && semantic_location_is_known(semantic_location_from_ast(items[i]))) {
            semantic_warning_code_at(ctx, semantic_location_from_ast(items[i]),
                                     SEMCODE_UNREACHABLE_STATEMENT,
                                     "unreachable statement");
        }
        semantic_walk_stmt(ctx, items[i]);
        if (!semantic_stmt_completes(ctx, items[i])) unreachable = 1;
    }
}

void semantic_walk_stmt(SemanticContext *ctx, ASTNode *node) {
    int is_copy;

    if (!ctx || !node) return;

    switch (node->type) {
    case AST_NUMBER:
    case AST_IDENTIFIER:
    case AST_BINARY:
    case AST_ASSIGN:
    case AST_BORROW:
    case AST_UNARY:
    case AST_CAST:
    case AST_CALL:
    case AST_MEMBER_ACCESS:
    case AST_ARROW_ACCESS:
    case AST_INIT_LIST:
    case AST_SIZEOF:
    case AST_TERNARY:
        semantic_walk_expr(ctx, node, EXPRCTX_READ);
        break;
    case AST_CASE:
        semantic_walk_case(ctx, node, 1);
        break;
    case AST_TYPE:
    case AST_TYPE_FUNCTION:
        semantic_check_type_exists(ctx, node);
        break;
    case AST_TYPE_ARRAY:
        semantic_walk_stmt(ctx, node->type_array.element_type);
        break;
    case AST_VAR_DECL:
        semantic_walk_stmt(ctx, node->var_decl.var_type);
        if (node->var_decl.init) {
            semantic_walk_expr(ctx, node->var_decl.init, EXPRCTX_MOVE);
            semantic_check_initializer_type(ctx, node);
            semantic_check_kept_view(ctx, node->var_decl.init, node);
        }
        is_copy = semantic_type_is_copy(ctx, node->var_decl.var_type);
        semantic_declare_binding(ctx, node->var_decl.name, node->var_decl.var_type, is_copy, 0, semantic_location_from_ast(node));
        semantic_register_borrow_binding(ctx, node);
        {
            SemanticBinding *declared = semantic_find_binding(ctx, node->var_decl.name);
            if (declared && semantic_expr_views_local(ctx, node->var_decl.init)) declared->str_views_local = 1;
        }
        break;
    case AST_EXPR_STMT:
        if (node->expr_stmt.expr && node->expr_stmt.expr->type == AST_CASE) {
            semantic_walk_case(ctx, node->expr_stmt.expr, 1);
        } else {
            semantic_walk_expr(ctx, node->expr_stmt.expr, EXPRCTX_READ);
        }
        break;
    case AST_IF:
    {
        BranchSnapshots *s = malloc(sizeof(*s));

        semantic_walk_expr(ctx, node->if_stmt.cond, EXPRCTX_READ);
        semantic_check_condition_type(ctx, node->if_stmt.cond);
        semantic_snapshot_bindings(ctx, &s->base);

        semantic_restore_bindings(ctx, &s->base);
        semantic_walk_stmt(ctx, node->if_stmt.then_stmt);
        semantic_snapshot_bindings(ctx, &s->then_state);

        semantic_restore_bindings(ctx, &s->base);
        semantic_walk_stmt(ctx, node->if_stmt.else_stmt);
        semantic_snapshot_bindings(ctx, &s->else_state);

        /* A branch that leaves (`return`, `break`, `continue`) does not reach
         * the code after the `if`, so only the other branch's moves do. */
        int then_exits = stmt_always_exits(node->if_stmt.then_stmt);
        int else_exits = node->if_stmt.else_stmt && stmt_always_exits(node->if_stmt.else_stmt);
        if (then_exits && !else_exits) {
            semantic_restore_bindings(ctx, &s->else_state);
        } else if (else_exits && !then_exits) {
            semantic_restore_bindings(ctx, &s->then_state);
        } else {
            semantic_merge_if_binding_states(ctx, &s->base, &s->then_state, &s->else_state);
        }
        free(s);
        break;
    }
    case AST_RETURN:
        if (ctx->defer_depth > 0) {
            semantic_error_at(ctx, semantic_location_from_ast(node),
                              "return is not allowed inside defer");
        }
        semantic_check_return_type(ctx, node);
        semantic_check_returned_borrow(ctx, node);
        semantic_check_returned_str(ctx, node);
        semantic_walk_expr(ctx, node->ret.expr, EXPRCTX_MOVE);
        break;
    case AST_DEFER:
        if (ctx->defer_depth > 0) {
            semantic_error_at(ctx, semantic_location_from_ast(node),
                              "defer is not allowed inside defer");
        }
        ctx->defer_depth++;
        semantic_walk_stmt(ctx, node->defer_stmt.body);
        ctx->defer_depth--;
        break;
    case AST_YIELD:
        semantic_walk_expr(ctx, node->yield_stmt.expr, EXPRCTX_MOVE);
        break;
    case AST_BLOCK:
        semantic_enter_scope(ctx);
        walk_block_items(ctx, node->block.stmts, node->block.count);
        semantic_leave_scope(ctx);
        break;
    case AST_STMT_EXPR:
        semantic_walk_stmt(ctx, node->stmt_expr.block);
        break;
    case AST_FUN_LITERAL: {
        SemanticLoopFrame *outer_loop = ctx->loop;
        ctx->loop = NULL;
        ctx->function_depth++;
        semantic_enter_scope(ctx);
        walk_params(ctx, node->fun_literal.params, node->fun_literal.param_count, node->fun_literal.body);
        semantic_walk_stmt(ctx, node->fun_literal.body);
        semantic_leave_scope(ctx);
        ctx->function_depth--;
        ctx->loop = outer_loop;
        break;
    }
    case AST_FUNDEF:
    {
        ASTNode *prev_function = ctx->current_function;
        const char *prev_origin = ctx->origin_path;
        int prev_origin_unsafe = ctx->origin_unsafe;
        ctx->current_function = node;
        if (node->fundef.origin_path) {
            ctx->origin_path = node->fundef.origin_path;
            ctx->origin_unsafe = node->fundef.origin_unsafe;
        }
        ctx->function_depth++;
        semantic_enter_scope(ctx);
        semantic_walk_stmt(ctx, node->fundef.ret_type);
        walk_params(ctx, node->fundef.params, node->fundef.param_count, node->fundef.body);
        semantic_walk_stmt(ctx, node->fundef.body);
        semantic_check_function_end(ctx, node);
        semantic_leave_scope(ctx);
        ctx->function_depth--;
        ctx->current_function = prev_function;
        ctx->origin_path = prev_origin;
        ctx->origin_unsafe = prev_origin_unsafe;
        break;
    }
    case AST_PARAM:
        semantic_walk_stmt(ctx, node->param.type);
        break;
    case AST_WHILE: {
        SemanticLoopFrame *frame = loop_enter(ctx);
        semantic_walk_expr(ctx, node->while_stmt.cond, EXPRCTX_READ);
        semantic_check_condition_type(ctx, node->while_stmt.cond);
        semantic_walk_stmt(ctx, node->while_stmt.body);
        loop_leave(ctx, frame, !stmt_always_exits(node->while_stmt.body));
        break;
    }
    case AST_FOR: {
        semantic_enter_scope(ctx);
        semantic_walk_stmt(ctx, node->for_stmt.init);
        SemanticLoopFrame *frame = loop_enter(ctx);
        semantic_walk_expr(ctx, node->for_stmt.cond, EXPRCTX_READ);
        semantic_check_condition_type(ctx, node->for_stmt.cond);
        semantic_walk_stmt(ctx, node->for_stmt.inc);
        semantic_walk_stmt(ctx, node->for_stmt.body);
        loop_leave(ctx, frame, !stmt_always_exits(node->for_stmt.body));
        semantic_leave_scope(ctx);
        break;
    }
    case AST_TYPEDEF:
        semantic_walk_stmt(ctx, node->typedef_stmt.src_type);
        if (node->typedef_stmt.is_newtype) {
            SemanticTypeInfo base;
            if (!semantic_typeinfo_from_type_ast(node->typedef_stmt.src_type, &base) ||
                base.pointer_level != 0 || base.borrow_kind != BORROWKIND_NONE ||
                base.is_array || base.is_function ||
                !semantic_is_builtin_type(base.base_type) ||
                strcmp(base.base_type, "void") == 0 || strcmp(base.base_type, "str") == 0) {
                semantic_error_at(ctx, semantic_location_from_ast(node),
                                  "newtype '%s' must wrap a scalar builtin type",
                                  node->typedef_stmt.alias);
            }
        }
        break;
    case AST_ENUM:
        semantic_register_enum(ctx, node);
        for (int i = 0; i < node->enum_stmt.member_count; i++) {
            semantic_walk_stmt(ctx, node->enum_stmt.members[i]);
        }
        break;
    case AST_ENUM_MEMBER:
        semantic_walk_expr(ctx, node->enum_member.value, EXPRCTX_READ);
        break;
    case AST_STRUCT:
        walk_block_items(ctx, node->struct_stmt.members, node->struct_stmt.member_count);
        break;
    case AST_TYPEDEF_STRUCT:
        walk_block_items(ctx, node->typedef_struct.members, node->typedef_struct.member_count);
        break;
    case AST_BREAK:
    case AST_CONTINUE:
        if (ctx->defer_depth > 0) {
            semantic_error_at(ctx, semantic_location_from_ast(node),
                              "loop control is not allowed inside defer");
        }
        if (node->type == AST_CONTINUE) loop_note_continue(ctx);
        break;
    case AST_IMPORT:
        break;
    case AST_DO_WHILE: {
        SemanticLoopFrame *frame = loop_enter(ctx);
        semantic_walk_stmt(ctx, node->do_while_stmt.body);
        semantic_walk_expr(ctx, node->do_while_stmt.cond, EXPRCTX_READ);
        semantic_check_condition_type(ctx, node->do_while_stmt.cond);
        loop_leave(ctx, frame, !stmt_always_exits(node->do_while_stmt.body));
        break;
    }
    default:
        semantic_error_at(ctx, semantic_location_from_ast(node),
                          "semantic walker encountered unknown AST node type %d", node->type);
        break;
    }
}

void semantic_walk_ast(SemanticContext *ctx, ASTNode *node) {
    semantic_collect_user_types(ctx, node);
    semantic_collect_function_sigs(ctx, node);
    semantic_collect_imported_globals(ctx, node);
    semantic_warn_drop_without_impl(ctx, node);
    semantic_walk_stmt(ctx, node);
    semantic_report_remaining_unsafe_operations(ctx, node);
}
