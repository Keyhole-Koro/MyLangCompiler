#include "mylang/semantic/semantic_internal.h"
#include "mylang/semantic/diagnostic_codes.h"

/* Borrow tracking: where a borrow comes from, what it keeps locked, what may
 * be written while it lasts, and what may be returned. */

/* `&g` of a global lives as long as the program, and `&p->x` was taken
 * through a raw pointer, whose dereference is already reported. */
static int borrow_is_static_or_unchecked(SemanticContext *ctx, ASTNode *expr) {
    if (!expr || expr->type != AST_BORROW) return 0;
    ASTNode *place = expr->borrow.expr;
    while (place) {
        switch (place->type) {
        case AST_IDENTIFIER: {
            SemanticBinding *binding = semantic_find_binding(ctx, place->identifier.name);
            return binding && binding->is_global;
        }
        case AST_MEMBER_ACCESS:
            place = place->member_access.lhs;
            break;
        case AST_UNARY: {
            if (place->unary.op != ASTARISK) return 0;
            ASTNode *operand = place->unary.operand;
            if (operand && operand->type == AST_BINARY &&
                (operand->binary.op == ADD || operand->binary.op == SUB))
                operand = operand->binary.left;
            SemanticTypeInfo type;
            if (operand && semantic_infer_expr_type(ctx, operand, &type) &&
                type.pointer_level > 0 && type.borrow_kind == BORROWKIND_NONE && !type.is_array)
                return 1;
            place = operand;
            break;
        }
        case AST_ARROW_ACCESS:
            return 1;
        default:
            return 0;
        }
    }
    return 0;
}

/* Rule B9: a borrow kept as a raw pointer or an integer address is no longer
 * tracked, so it can outlive what it borrows. Like the other raw-pointer
 * operations it is error E0701. Passing a
 * borrow to a pointer parameter is left alone: a checked file cannot name one. */
void semantic_check_borrow_kept_as_pointer(SemanticContext *ctx, const SemanticTypeInfo *expected,
                                           const SemanticTypeInfo *actual, ASTNode *at) {
    if (actual->borrow_kind == BORROWKIND_NONE || actual->is_function ||
        expected->borrow_kind != BORROWKIND_NONE || expected->is_array || expected->is_function)
        return;
    int to_pointer = expected->pointer_level > 0;
    if (!to_pointer && !semantic_typeinfo_is_integer_like_or_enum(ctx, expected)) return;
    if (borrow_is_static_or_unchecked(ctx, at)) return;
    semantic_report_unsafe_operation(ctx, at, to_pointer ? "keeping a borrow as a raw pointer"
                                                : "keeping a borrow as an integer address");
}

SemanticBinding *semantic_borrow_target_binding(SemanticContext *ctx, ASTNode *expr) {
    ASTNode *ident = semantic_as_identifier(expr);

    if (!ctx || !expr) return NULL;
    if (ident) {
        return semantic_find_binding(ctx, ident->identifier.name);
    }
    if (expr->type == AST_MEMBER_ACCESS) {
        return semantic_borrow_target_binding(ctx, expr->member_access.lhs);
    }
    return NULL;
}

static void lock_borrowed(SemanticBinding *owner, SemanticLocation at) {
    owner->borrow_active = 1;
    owner->borrow_held = 1;
    owner->last_borrow_loc = at;
}

static void unlock_borrowed(SemanticBinding *owner) {
    owner->borrow_active = 0;
    owner->borrow_held = 0;
    owner->last_borrow_loc = semantic_location_unknown();
}

/* Ends the borrow `binding` holds, if any. */
void semantic_release_borrow(SemanticContext *ctx, SemanticBinding *binding) {
    if (!binding->borrowed_from) return;
    SemanticBinding *owner = binding->borrow_is_reborrow ? NULL : semantic_find_binding(ctx, binding->borrowed_from);
    if (owner) unlock_borrowed(owner);
    if (binding->reborrowed_via) {
        SemanticBinding *via = semantic_find_binding(ctx, binding->reborrowed_via);
        if (via && via != binding) unlock_borrowed(via);
    }
    binding->borrowed_from = NULL;
    binding->reborrowed_via = NULL;
    binding->borrow_is_reborrow = 0;
}

static void check_return_reference_escape(SemanticContext *ctx, ASTNode *expr) {
    SemanticBinding *binding;
    SemanticBinding *owner;
    ASTNode *borrowed_expr = NULL;

    if (!ctx || !expr) return;

    if (expr->type == AST_BORROW) {
        borrowed_expr = expr->borrow.expr;
        owner = semantic_borrow_target_binding(ctx, borrowed_expr);
        if (owner && !owner->is_global && (!owner->is_param || semantic_binding_owns_value(owner))) {
            semantic_error_at(ctx, semantic_location_from_ast(expr),
                              "cannot return reference to local '%s'", owner->name);
            semantic_note_binding_decl_if_known(ctx, owner, NULL);
        }
        return;
    }

    if (expr->type != AST_IDENTIFIER) return;

    binding = semantic_find_binding(ctx, expr->identifier.name);
    if (!binding || !binding->borrowed_from) return;

    owner = semantic_find_binding(ctx, binding->borrowed_from);
    if (owner && !owner->is_global && (!owner->is_param || semantic_binding_owns_value(owner))) {
        semantic_error_at(ctx, semantic_location_from_ast(expr),
                          "cannot return reference to local '%s'", owner->name);
        semantic_note_binding_decl_if_known(ctx, owner, NULL);
    }
}

/* ---- where a borrow comes from -----------------------------------------
 *
 * A borrow lives only in a local, a parameter or a return value (fields
 * cannot hold one: parser_borrow_positions.c); `Option<borrow T>` and
 * `Result` carry one in their payload. A local that carries a borrow records
 * the value it borrows in `borrowed_from` -- always the root owner, never
 * another borrow -- and moving or borrowing that owner while the
 * local is in scope is an error.
 *
 * A function returning a borrow returns one of its first borrow (or
 * pointer) parameter, which is the receiver of a method. A caller therefore
 * treats the result as borrowing whatever it passed there:
 * `Option<borrow T> o = v.at(0);` keeps `v` borrowed while `o` is in scope.
 */

/* BORROWKIND_BORROW or BORROWKIND_NONE: the borrow a value of this type carries,
 * directly or in a payload field. */
static int typeinfo_borrow_kind_at(SemanticContext *ctx, const SemanticTypeInfo *info, int depth) {
    if (!info || depth > 4) return BORROWKIND_NONE;
    if (info->borrow_kind != BORROWKIND_NONE) return info->borrow_kind;
    if (info->pointer_level > 0 || info->is_array || !info->base_type) return BORROWKIND_NONE;
    for (int i = 0; i < ctx->struct_layout_count; i++) {
        const SemanticStructLayout *layout = &ctx->struct_layouts[i];
        if (strcmp(layout->name, info->base_type) != 0) continue;
        for (int m = 0; m < layout->member_count; m++) {
            if (typeinfo_borrow_kind_at(ctx, &layout->members[m].type, depth + 1) == BORROWKIND_BORROW)
                return BORROWKIND_BORROW;
        }
        break;
    }
    return BORROWKIND_NONE;
}

static int typeinfo_borrow_kind(SemanticContext *ctx, const SemanticTypeInfo *info) {
    return typeinfo_borrow_kind_at(ctx, info, 0);
}

static int type_ast_borrow_kind(SemanticContext *ctx, ASTNode *type) {
    SemanticTypeInfo info;
    if (!type || !semantic_typeinfo_from_type_ast(type, &info)) return BORROWKIND_NONE;
    return typeinfo_borrow_kind(ctx, &info);
}

/* A parameter a returned borrow may come from: a borrow, a pointer, or a
 * value that itself carries a borrow (`Option<borrow T> self`). */
static int typeinfo_is_borrow_source(SemanticContext *ctx, const SemanticTypeInfo *info) {
    return info->borrow_kind != BORROWKIND_NONE || info->pointer_level > 0 ||
           typeinfo_borrow_kind(ctx, info) != BORROWKIND_NONE;
}

/* The parameter a function's returned borrow comes from, or NULL. */
static ASTNode *returned_borrow_source(SemanticContext *ctx, ASTNode *fn) {
    for (int i = 0; i < fn->fundef.param_count; i++) {
        ASTNode *param = fn->fundef.params[i];
        SemanticTypeInfo info;
        if (param && param->type == AST_PARAM &&
            semantic_typeinfo_from_type_ast(param->param.type, &info) &&
            typeinfo_is_borrow_source(ctx, &info))
            return param;
    }
    return NULL;
}

typedef enum { BORROW_ORIGIN_NONE, BORROW_ORIGIN_BINDING, BORROW_ORIGIN_UNKNOWN } BorrowOrigin;

/* The binding a place (`x`, `x.f`, `p->f`, `*(p + i)`) lives in. */
static SemanticBinding *place_root_binding(SemanticContext *ctx, ASTNode *place) {
    while (place) {
        switch (place->type) {
        case AST_IDENTIFIER: return semantic_find_binding(ctx, place->identifier.name);
        case AST_MEMBER_ACCESS: place = place->member_access.lhs; break;
        case AST_ARROW_ACCESS: place = place->arrow_access.lhs; break;
        case AST_UNARY:
            if (place->unary.op != ASTARISK) return NULL;
            place = place->unary.operand;
            break;
        case AST_BINARY:
            if (place->binary.op != ADD && place->binary.op != SUB) return NULL;
            place = place->binary.left;
            break;
        case AST_CAST: place = place->cast.expr; break;
        default: return NULL;
        }
    }
    return NULL;
}

/* An assignment target that is a local itself or one of its fields. */
static SemanticBinding *assigned_binding(SemanticContext *ctx, ASTNode *target) {
    while (target && target->type == AST_MEMBER_ACCESS) target = target->member_access.lhs;
    return target && target->type == AST_IDENTIFIER ? semantic_find_binding(ctx, target->identifier.name) : NULL;
}

/* Which value the borrow `expr` evaluates to is taken from. `*reborrow` is
 * set when it is taken through another borrow, whose own borrow of the
 * owner already counts; `*via` (when not NULL) is then that borrow -- a
 * `borrow` parameter or a local holding one -- which must stay borrowed
 * itself, or it could be used to change what the new borrow points into. */
static BorrowOrigin borrow_origin(SemanticContext *ctx, ASTNode *expr,
                                  SemanticBinding **owner, int *reborrow,
                                  SemanticBinding **via) {
    *owner = NULL;
    if (!expr) return BORROW_ORIGIN_NONE;
    switch (expr->type) {
    case AST_NUMBER:
        return BORROW_ORIGIN_NONE;
    case AST_BORROW:
    case AST_IDENTIFIER:
    case AST_MEMBER_ACCESS: {
        int taken = expr->type == AST_BORROW;
        ASTNode *place = taken ? expr->borrow.expr : expr;
        SemanticBinding *root = place_root_binding(ctx, place);
        if (!root) return BORROW_ORIGIN_UNKNOWN;
        if (root->borrowed_from) {
            *owner = semantic_find_binding(ctx, root->borrowed_from);
            *reborrow = 1;
            if (via) *via = root;
            return *owner ? BORROW_ORIGIN_BINDING : BORROW_ORIGIN_UNKNOWN;
        }
        if (root->borrow_origin_unknown) return BORROW_ORIGIN_UNKNOWN;
        /* A borrow local that holds nothing yet, such as a None. */
        if (!taken && !root->is_param && !root->is_global && root->has_type &&
            typeinfo_borrow_kind(ctx, &root->type_info) != BORROWKIND_NONE)
            return BORROW_ORIGIN_NONE;
        *owner = root;
        if (root->is_param && root->has_type && root->type_info.borrow_kind != BORROWKIND_NONE) {
            *reborrow = 1;
            if (via) *via = root;
        }
        return BORROW_ORIGIN_BINDING;
    }
    case AST_CALL: {
        SemanticFunctionSig *sig = semantic_find_function_sig(ctx, expr->call.name);
        if (!sig || !sig->has_return_type) return BORROW_ORIGIN_UNKNOWN;
        if (typeinfo_borrow_kind(ctx, &sig->return_type) == BORROWKIND_NONE) return BORROW_ORIGIN_NONE;
        if (!sig->has_param_types) return BORROW_ORIGIN_UNKNOWN;
        int count = sig->param_count < SEMANTIC_MAX_FUNCTION_PARAMS ? sig->param_count : SEMANTIC_MAX_FUNCTION_PARAMS;
        for (int i = 0; i < count; i++) {
            if (!typeinfo_is_borrow_source(ctx, &sig->param_types[i])) continue;
            if (i >= expr->call.arg_count) return BORROW_ORIGIN_UNKNOWN;
            return borrow_origin(ctx, expr->call.args[i], owner, reborrow, via);
        }
        /* No parameter to borrow from: the callee returns a global's. */
        return BORROW_ORIGIN_NONE;
    }
    case AST_CAST:
        return borrow_origin(ctx, expr->cast.expr, owner, reborrow, via);
    default:
        return BORROW_ORIGIN_UNKNOWN;
    }
}

static void report_borrow_conflict(SemanticContext *ctx, SemanticBinding *owner, ASTNode *at) {
    semantic_error_at(ctx, semantic_location_from_ast(at),
                      "cannot borrow '%s' while it is already borrowed", owner->name);
    if (semantic_location_is_known(owner->last_borrow_loc)) {
        semantic_note_at(ctx, owner->last_borrow_loc, "borrow of '%s' starts here", owner->name);
    } else {
        semantic_note_binding_decl_if_known(ctx, owner, NULL);
    }
}

static int borrow_conflicts(const SemanticBinding *owner) {
    return owner->borrow_active || owner->read_in_place_arg_count > 0;
}

/* Makes `binding`, whose type carries a borrow, hold the borrow `expr`
 * evaluates to. */
static void hold_borrow(SemanticContext *ctx, SemanticBinding *binding, ASTNode *expr) {
    SemanticBinding *owner = NULL;
    SemanticBinding *via = NULL;
    int reborrow = 0;
    BorrowOrigin origin = borrow_origin(ctx, expr, &owner, &reborrow, &via);

    binding->borrow_origin_unknown = origin == BORROW_ORIGIN_UNKNOWN;
    if (origin != BORROW_ORIGIN_BINDING || !owner || owner == binding) return;
    /* Taken through a raw pointer (`p->rows.at(i)`): the pointer does not
     * own what it points at, so there is no owner here to keep borrowed. */
    if (owner->has_type && owner->type_info.pointer_level > 0 &&
        owner->type_info.borrow_kind == BORROWKIND_NONE)
        return;

    SemanticLocation at = semantic_location_from_ast(expr);
    if (!reborrow) {
        if (borrow_conflicts(owner)) {
            report_borrow_conflict(ctx, owner, expr);
            return;
        }
        lock_borrowed(owner, at);
    }
    /* Taken through a `borrow` parameter or local: that one stays borrowed
     * too, so it cannot change (`v.push(..)`) what this borrow points into. */
    if (via && via != binding) {
        if (borrow_conflicts(via)) {
            report_borrow_conflict(ctx, via, expr);
            return;
        }
        lock_borrowed(via, at);
        binding->reborrowed_via = via->name;
    }
    binding->borrowed_from = owner->name;
    binding->borrow_is_reborrow = reborrow;
}

void semantic_register_borrow_binding(SemanticContext *ctx, ASTNode *binding_node) {
    ASTNode *var_decl = semantic_as_var_decl(binding_node);
    if (!ctx || !var_decl || !var_decl->var_decl.init) return;
    int kind = type_ast_borrow_kind(ctx, var_decl->var_decl.var_type);
    if (kind == BORROWKIND_NONE) return;
    SemanticBinding *binding = semantic_find_binding(ctx, var_decl->var_decl.name);
    if (binding) hold_borrow(ctx, binding, var_decl->var_decl.init);
}

/* `opt = Some(&y);` moves the local's borrow to a new owner. A borrow itself
 * stays with its place: assigning one writes through it. */
void semantic_hold_payload_borrow(SemanticContext *ctx, ASTNode *assign) {
    SemanticBinding *binding = assigned_binding(ctx, assign->assign.left);
    SemanticTypeInfo target;
    if (!binding || binding->is_param || binding->is_global ||
        !semantic_infer_expr_type(ctx, assign->assign.left, &target))
        return;
    int kind = typeinfo_borrow_kind(ctx, &target);
    if (kind == BORROWKIND_NONE) return;
    semantic_release_borrow(ctx, binding);
    hold_borrow(ctx, binding, assign->assign.right);
}

/* A returned borrow must come from the function's first borrow parameter
 * (the receiver of a method) or from a global. */
void semantic_check_returned_borrow(SemanticContext *ctx, ASTNode *return_node) {
    ASTNode *fn = ctx->current_function;
    ASTNode *expr = return_node->ret.expr;
    /* A lowered `return Some(&x)` returns a temporary with no location. */
    ASTNode *at = expr && expr->line ? expr : return_node;
    if (!fn || fn->type != AST_FUNDEF || !expr ||
        type_ast_borrow_kind(ctx, fn->fundef.ret_type) == BORROWKIND_NONE) {
        check_return_reference_escape(ctx, expr);
        return;
    }

    SemanticBinding *owner = NULL;
    int reborrow = 0;
    BorrowOrigin origin = borrow_origin(ctx, expr, &owner, &reborrow, NULL);
    if (origin == BORROW_ORIGIN_NONE) return;
    /* An instance of a generic written over `T` (`T (Option<T> self)
     * unwrap_or(T fallback)` with T = borrow i32) did not choose to return a
     * borrow, so only a borrow of its own local is rejected there. */
    int generic_instance = fn->fundef.name && strncmp(fn->fundef.name, "__mlg_", 6) == 0;
    if (origin == BORROW_ORIGIN_UNKNOWN) {
        if (ctx->safety_profile == SEMANTIC_SAFETY_UNSAFE || generic_instance) return;
        semantic_error_at(ctx, semantic_location_from_ast(at),
                          "cannot tell which value this returned borrow comes from");
        semantic_note_at(ctx, semantic_location_from_ast(at),
                         "return a borrow taken from the first borrow parameter, such as `&self.field`");
        return;
    }
    if (owner->is_global) return;
    if (!owner->is_param) {
        semantic_error_at(ctx, semantic_location_from_ast(at),
                          "cannot return reference to local '%s'", owner->name);
        semantic_note_binding_decl_if_known(ctx, owner, NULL);
        return;
    }
    ASTNode *source = returned_borrow_source(ctx, fn);
    if (generic_instance || (source && strcmp(source->param.name, owner->name) == 0)) return;
    if (source) {
        semantic_error_at(ctx, semantic_location_from_ast(at),
                          "a returned borrow must come from '%s', the first borrow parameter, not '%s'",
                          source->param.name, owner->name);
    } else {
        semantic_error_at(ctx, semantic_location_from_ast(at),
                          "'%s' has no borrow parameter, so it cannot return a borrow of '%s'",
                          fn->fundef.name, owner->name);
    }
}

/* ---- writes ------------------------------------------------------------
 *
 * Rules B1, B4 and B5 of docs/design/mylang-values.md.
 */

/* A write to `place`: the left side of `=` (WRITE_ASSIGN), the operand of
 * `++` / `--` (WRITE_STEP), or of `&` (WRITE_BORROW). The place is
 * followed through fields, indexes and `*` of a borrow to the variable it is
 * in. A write through a raw pointer (`p->x`, `p[i]`) is unchecked: E0701. */
void semantic_check_write_place(SemanticContext *ctx, ASTNode *place, WriteKind kind) {
    ASTNode *at = place;
    int whole = 1;
    while (place && place->type != AST_IDENTIFIER) {
        if (place->type == AST_MEMBER_ACCESS) {
            place = place->member_access.lhs;
        } else if (place->type == AST_UNARY && place->unary.op == ASTARISK) {
            ASTNode *operand = place->unary.operand;
            /* `a[i]` is `*(a + i)`. */
            if (operand && operand->type == AST_BINARY &&
                (operand->binary.op == ADD || operand->binary.op == SUB))
                operand = operand->binary.left;
            SemanticTypeInfo type;
            if (!operand || !semantic_infer_expr_type(ctx, operand, &type) ||
                (type.pointer_level > 0 && type.borrow_kind == BORROWKIND_NONE && !type.is_array))
                return;
            place = operand;
        } else {
            return;
        }
        whole = 0;
    }
    if (!place) return;
    SemanticBinding *binding = semantic_find_binding(ctx, place->identifier.name);
    if (!binding) return;

    /* A parameter that only reads an owned value has nothing to copy it into. */
    if (binding->reads_owned_value) {
        semantic_error_code_at(ctx, semantic_location_from_ast(at), SEMCODE_WRITE_TO_READ_PARAM,
                               "cannot change '%s', which this function only reads", binding->name);
        semantic_note_binding_decl_if_known(ctx, binding, "here; declare it `borrow` or `move`");
        return;
    }

    /* `r = &other;` re-points a borrow instead of writing through it, and
     * `c = 1;` on a const is reported where the name is written. */
    if (kind != WRITE_ASSIGN || !whole) {
        if (binding->has_type && (binding->type_info.type_modifiers & TYPEMOD_CONST) != 0) {
            semantic_error_code_at(ctx, semantic_location_from_ast(at), SEMCODE_WRITE_TO_CONST,
                                   kind == WRITE_BORROW
                                       ? "cannot borrow const value '%s'"
                                       : "cannot modify const value '%s'",
                                   binding->name);
            return;
        }
    }
    /* A `&` that conflicts with another borrow is reported where the borrow
     * is held or passed (hold_borrow, the call check). Reading the place to
     * write into it already reported a value held by `&`. */
    if (kind == WRITE_BORROW) return;
    if (binding->borrow_held && !(kind == WRITE_ASSIGN && whole)) return;
    if (binding->read_in_place_arg_count > 0 || binding->borrow_active) {
        semantic_error_code_at(ctx, semantic_location_from_ast(at), SEMCODE_WRITE_WHILE_BORROWED,
                               "cannot modify '%s' while it is borrowed", binding->name);
        if (binding->borrow_active && semantic_location_is_known(binding->last_borrow_loc)) {
            semantic_note_at(ctx, binding->last_borrow_loc,
                             "borrow of '%s' starts here", binding->name);
        }
    }
}

static int typeinfo_holds_bytes_inline(SemanticContext *ctx, const SemanticTypeInfo *info, int depth) {
    if (!info || depth > 4 || info->pointer_level > 0 || info->borrow_kind != BORROWKIND_NONE) return 0;
    if (info->is_array) return 1;
    if (!info->base_type) return 0;
    for (int i = 0; i < ctx->struct_layout_count; i++) {
        const SemanticStructLayout *layout = &ctx->struct_layouts[i];
        if (strcmp(layout->name, info->base_type) != 0) continue;
        for (int m = 0; m < layout->member_count; m++) {
            if (typeinfo_holds_bytes_inline(ctx, &layout->members[m].type, depth + 1)) return 1;
        }
        break;
    }
    return 0;
}

/* `t.as_str()` on a local Text is a view of this frame: rule B2 keeps a `str`
 * out of fields and globals, and this keeps it from being returned. */
int semantic_expr_views_local(SemanticContext *ctx, ASTNode *expr) {
    if (!expr) return 0;
    if (expr->type == AST_IDENTIFIER) {
        SemanticBinding *binding = semantic_find_binding(ctx, expr->identifier.name);
        return binding && binding->str_views_local;
    }
    if (expr->type != AST_CALL || expr->call.arg_count == 0) return 0;
    SemanticTypeInfo type;
    if (!semantic_infer_expr_type(ctx, expr, &type) || !type.base_type ||
        strcmp(type.base_type, "str") != 0 || type.pointer_level != 0) return 0;
    ASTNode *first = expr->call.args[0];
    SemanticTypeInfo first_type;
    ASTNode *target = first && first->type == AST_BORROW ? first->borrow.expr : first;
    if (!target || !semantic_infer_expr_type(ctx, target, &first_type)) return 0;
    if (first_type.base_type && strcmp(first_type.base_type, "str") == 0) return semantic_expr_views_local(ctx, target);
    /* A view reaches into a value only where its bytes are held inline. */
    if (!typeinfo_holds_bytes_inline(ctx, &first_type, 0)) return 0;
    SemanticBinding *owner = semantic_borrow_target_binding(ctx, target);
    if (!owner || owner->is_global || !owner->has_type || owner->type_info.borrow_kind != BORROWKIND_NONE)
        return 0;
    /* A parameter that is only read is the caller's value. */
    return !owner->is_param || owner->param_is_move || owner->param_is_written;
}

void semantic_check_returned_str(SemanticContext *ctx, ASTNode *node) {
    if (semantic_in_unsafe_source(ctx) || !semantic_expr_views_local(ctx, node->ret.expr)) return;
    semantic_error_at(ctx, semantic_location_from_ast(node),
                      "a str viewing a local cannot be returned; copy it into a Text");
}
