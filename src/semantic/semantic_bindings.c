#include "mylang/semantic/semantic_internal.h"

/* The table of variables in scope, and its snapshots around a branch. */

int semantic_location_is_known(SemanticLocation loc) {
    return loc.line > 0 || loc.col > 0;
}

/* The value lives in this binding's own storage: not a borrow, not behind a
 * pointer. */
int semantic_binding_owns_value(const SemanticBinding *binding) {
    return binding->has_type && binding->type_info.borrow_kind == BORROWKIND_NONE &&
           binding->type_info.pointer_level == 0;
}

void semantic_note_binding_decl_if_known(SemanticContext *ctx, SemanticBinding *binding, const char *what) {
    if (!ctx || !binding || !semantic_location_is_known(binding->decl_loc)) return;
    semantic_note_at(ctx, binding->decl_loc, "'%s' declared here%s%s",
                     binding->name,
                     what ? " " : "",
                     what ? what : "");
}

SemanticBinding *semantic_find_binding(SemanticContext *ctx, const char *name) {
    if (!ctx || !name) return NULL;
    for (int i = ctx->binding_count - 1; i >= 0; i--) {
        if (ctx->bindings[i].name && strcmp(ctx->bindings[i].name, name) == 0) {
            return &ctx->bindings[i];
        }
    }
    return NULL;
}

void semantic_snapshot_bindings(SemanticContext *ctx, SemanticBindingSnapshot *snapshot) {
    if (!ctx || !snapshot) return;
    snapshot->binding_count = ctx->binding_count;
    for (int i = 0; i < ctx->binding_count; i++) {
        snapshot->bindings[i] = ctx->bindings[i];
    }
}

void semantic_restore_bindings(SemanticContext *ctx, const SemanticBindingSnapshot *snapshot) {
    if (!ctx || !snapshot) return;
    ctx->binding_count = snapshot->binding_count;
    for (int i = 0; i < snapshot->binding_count; i++) {
        ctx->bindings[i] = snapshot->bindings[i];
    }
}

void semantic_merge_if_binding_states(SemanticContext *ctx,
                                      const SemanticBindingSnapshot *base,
                                      const SemanticBindingSnapshot *then_state,
                                      const SemanticBindingSnapshot *else_state) {
    if (!ctx || !base || !then_state || !else_state) return;

    semantic_restore_bindings(ctx, base);
    for (int i = 0; i < base->binding_count; i++) {
        SemanticBinding *out = &ctx->bindings[i];
        const SemanticBinding *then_binding = &then_state->bindings[i];
        const SemanticBinding *else_binding = &else_state->bindings[i];

        out->moved = then_binding->moved || else_binding->moved;
        if (then_binding->moved && semantic_location_is_known(then_binding->move_loc)) {
            out->move_loc = then_binding->move_loc;
        } else if (else_binding->moved && semantic_location_is_known(else_binding->move_loc)) {
            out->move_loc = else_binding->move_loc;
        } else {
            out->move_loc = base->bindings[i].move_loc;
        }
    }
}

void semantic_enter_scope(SemanticContext *ctx) {
    if (!ctx) return;
    ctx->scope_depth++;
}

void semantic_leave_scope(SemanticContext *ctx) {
    if (!ctx) return;
    while (ctx->binding_count > 0 &&
           ctx->bindings[ctx->binding_count - 1].scope_depth >= ctx->scope_depth) {
        semantic_release_borrow(ctx, &ctx->bindings[ctx->binding_count - 1]);
        ctx->binding_count--;
    }
    if (ctx->scope_depth > 0) ctx->scope_depth--;
}

void semantic_declare_binding(SemanticContext *ctx, const char *name, ASTNode *type_node,
                              int is_copy, int is_param, SemanticLocation decl_loc) {
    SemanticBinding *binding;
    SemanticTypeInfo type_info;
    int has_type = semantic_typeinfo_from_type_ast(type_node, &type_info);

    if (!ctx || !name) return;
    binding = semantic_find_binding(ctx, name);
    if (binding && binding->scope_depth == ctx->scope_depth) {
        binding->is_copy = is_copy;
        binding->param_is_move = 0;
        binding->param_is_written = 0;
        binding->reads_owned_value = 0;
        binding->moved = 0;
        binding->has_type = has_type;
        if (has_type) binding->type_info = type_info;
        binding->decl_loc = decl_loc;
        binding->move_loc = semantic_location_unknown();
        binding->is_param = is_param;
        binding->is_global = (!is_param && ctx->function_depth == 0);
        return;
    }

    if (ctx->binding_count >= (int)(sizeof(ctx->bindings) / sizeof(ctx->bindings[0]))) {
        semantic_error_at(ctx, semantic_location_unknown(),
                          "semantic binding table exhausted while tracking '%s'", name);
        return;
    }

    binding = &ctx->bindings[ctx->binding_count++];
    binding->name = name;
    binding->is_copy = is_copy;
    binding->param_is_move = 0;
    binding->param_is_written = 0;
    binding->reads_owned_value = 0;
    binding->moved = 0;
    binding->scope_depth = ctx->scope_depth;
    binding->is_param = is_param;
    binding->is_global = (!is_param && ctx->function_depth == 0);
    binding->has_type = has_type;
    if (has_type) binding->type_info = type_info;
    binding->decl_loc = decl_loc;
    binding->move_loc = semantic_location_unknown();
    binding->borrowed_from = NULL;
    binding->borrow_is_reborrow = 0;
    binding->borrow_origin_unknown = 0;
    binding->reborrowed_via = NULL;
    binding->read_in_place_arg_count = 0;
    binding->borrow_active = 0;
    binding->borrow_held = 0;
    binding->last_borrow_loc = semantic_location_unknown();
}

void semantic_revive_binding_if_identifier(SemanticContext *ctx, ASTNode *node) {
    SemanticBinding *binding;
    ASTNode *ident = semantic_as_identifier(node);

    if (!ctx || !ident) return;
    binding = semantic_find_binding(ctx, ident->identifier.name);
    if (!binding) return;
    binding->moved = 0;
    binding->move_loc = semantic_location_unknown();
}
