#include "mylang/frontend/parser_method_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/parser_annot_internal.h"
#include "mylang/frontend/module.h"

/* A `borrow T` is an alias of its place: source reads and writes the T, and
 * `&b` names the place. Underneath it is a word holding the place's address,
 * and that is what the checks and the backend work on, so this pass spells a
 * source's uses out in that form:
 *
 *     written    after this pass
 *     b          *b       a use of the value, read or written
 *     &b         b        the same place
 *     b.f, b[i]  b.f, b[i]
 *
 * Whether a use wants the value or the place follows from where it stands: the
 * base of a field or an index, the operand of `&`, and anything going into a
 * `borrow` destination (a local, a returned borrow, the payload of an
 * `Option<borrow T>`) keep the place. Everything else reads or writes through.
 *
 * It runs last, when calls are ordinary calls and a `case` binding has become
 * the payload field it stands for, so the declared types are all it needs. */

typedef struct {
    ParserContext *context;
    ASTNode *program;
    MethodScope *scope;
    ASTNode *function;
    /* An instance of a generic written over `T`: its body could not spell the
     * `&` an argument needs when T happens to be a borrow. */
    int in_instance;
    int yield_keeps_place;
    int error_count;
} BorrowPlaces;

static void lower_expr(BorrowPlaces *L, ASTNode **slot, int keep_place);
static void lower_stmt(BorrowPlaces *L, ASTNode **slot);

static void place_error(BorrowPlaces *L, ASTNode *at, const char *code, const char *message,
                        const char *name) {
    const char *origin = L->function ? L->function->fundef.origin_path : NULL;
    fprintf(stderr, "%s:%d:%d: error%s: ",
            origin ? origin : L->context->module.filename ? L->context->module.filename : "<input>",
            at ? at->line : 0, at ? at->col : 0, code);
    fprintf(stderr, message, name);
    fprintf(stderr, "\n");
    L->error_count++;
}

static const char *written_name(ASTNode *expr) {
    while (expr && expr->type == AST_MEMBER_ACCESS) expr = expr->member_access.lhs;
    const char *name = !expr ? NULL : expr->type == AST_IDENTIFIER ? expr->identifier.name
                     : expr->type == AST_CALL ? expr->call.name : NULL;
    return name && strncmp(name, "__mlg_", 6) != 0 ? name : "this value";
}

static int is_borrow(BorrowPlaces *L, ASTNode *expr) {
    RecvShape shape;
    return infer_recv_shape(L->context, L->scope, expr, &shape) && shape.borrow_kind != REFKIND_NONE;
}

/* `borrow T *p`: the place holds a pointer, and using `p` as one reads it. */
static int is_borrow_of_pointer(BorrowPlaces *L, ASTNode *expr) {
    RecvShape shape;
    return infer_recv_shape(L->context, L->scope, expr, &shape) &&
           shape.borrow_kind != REFKIND_NONE && shape.pointer_level > 0;
}

static int type_is_borrow(ASTNode *type) {
    return type && type->type == AST_TYPE && type->type_node.borrow_kind != REFKIND_NONE &&
           type->type_node.pointer_level == 0;
}

static void use_value(BorrowPlaces *L, ASTNode **slot, int keep_place) {
    if (keep_place || !is_borrow(L, *slot)) return;
    ASTNode *place = *slot;
    ASTNode *value = new_unary(ASTARISK, place);
    value->unary.is_implicit = 1;
    value->line = place->line;
    value->col = place->col;
    value->end_line = place->end_line;
    value->end_col = place->end_col;
    *slot = value;
}

static ASTNode *parameter_type(ASTNode *param) {
    return param && param->type == AST_PARAM ? param->param.type : param;
}

/* What a call's arguments go into: a function's parameters, or the parameter
 * types of the function value it calls through. */
static int call_parameters(BorrowPlaces *L, ASTNode *call, ASTNode ***params) {
    ASTNode *fn = callee_declaration(L->context, L->program, call->call.name);
    if (fn) {
        *params = fn->fundef.params;
        return fn->fundef.is_variadic ? fn->fundef.param_count - 1 : fn->fundef.param_count;
    }
    ASTNode *type = method_scope_lookup(L->scope, call->call.name);
    if (!type || type->type != AST_TYPE_FUNCTION) return 0;
    *params = type->function_type.param_types;
    return type->function_type.is_variadic ? type->function_type.param_count - 1
                                           : type->function_type.param_count;
}

static int names_generated_value(ASTNode *arg) {
    return arg->type == AST_IDENTIFIER && strncmp(arg->identifier.name, "__mlg_", 6) == 0;
}

static void lower_call(BorrowPlaces *L, ASTNode *call) {
    ASTNode **params = NULL;
    int known = call_parameters(L, call, &params);
    for (int i = 0; i < call->call.arg_count; i++) {
        ASTNode **arg = &call->call.args[i];
        int lends = i < known && type_is_borrow(parameter_type(params[i]));
        if (lends && (*arg)->type != AST_BORROW && !L->in_instance &&
            !names_generated_value(*arg) && is_borrow(L, *arg))
            place_error(L, *arg, "", "'%s' goes to a `borrow` parameter, so the call has to say so: "
                                     "write it with `&`", written_name(*arg));
        lower_expr(L, arg, lends);
    }
}

static void lower_assign(BorrowPlaces *L, ASTNode *node) {
    if (node->assign.is_construction) {
        int payload_is_borrow = is_borrow(L, node->assign.left);
        lower_expr(L, &node->assign.left, 1);
        lower_expr(L, &node->assign.right, payload_is_borrow);
        return;
    }
    if (node->assign.right && node->assign.right->type == AST_BORROW &&
        is_borrow(L, node->assign.left))
        place_error(L, node, "", "'%s' stays an alias of its place: an assignment writes through it, "
                                 "and `&` cannot point it at another", written_name(node->assign.left));
    lower_expr(L, &node->assign.left, 0);
    lower_expr(L, &node->assign.right, 0);
}

/* `&b`, for a `b` that already is a place. */
static void lower_borrow(BorrowPlaces *L, ASTNode **slot) {
    ASTNode *node = *slot;
    ASTNode *operand = node->borrow.expr;
    if ((operand->type == AST_IDENTIFIER || operand->type == AST_MEMBER_ACCESS ||
         operand->type == AST_CALL) && is_borrow(L, operand)) {
        node->borrow.expr = NULL;
        free_ast(node);
        *slot = operand;
        lower_expr(L, slot, 1);
        return;
    }
    lower_expr(L, &node->borrow.expr, 1);
}

static void lower_deref(BorrowPlaces *L, ASTNode *node) {
    ASTNode *operand = node->unary.operand;
    if (node->unary.is_implicit) return;
    if (operand && operand->type == AST_BINARY && operand->binary.subscript) {
        lower_expr(L, &operand->binary.left, !is_borrow_of_pointer(L, operand->binary.left));
        lower_expr(L, &operand->binary.right, 0);
        return;
    }
    if (is_borrow(L, operand) && !is_borrow_of_pointer(L, operand))
        place_error(L, node, "[E0305]", "'%s' is a borrow: writing its name reads the value, "
                                        "so it takes no `*`", written_name(operand));
    lower_expr(L, &node->unary.operand, !is_borrow_of_pointer(L, operand));
}

static void lower_expr_child(ASTNode **slot, void *user_data) {
    lower_expr(user_data, slot, 0);
}

static void lower_expr(BorrowPlaces *L, ASTNode **slot, int keep_place) {
    ASTNode *node = *slot;
    if (!node) return;
    switch (node->type) {
    case AST_IDENTIFIER:
        use_value(L, slot, keep_place);
        return;
    case AST_MEMBER_ACCESS:
        lower_expr(L, &node->member_access.lhs, !is_borrow_of_pointer(L, node->member_access.lhs));
        use_value(L, slot, keep_place);
        return;
    case AST_ARROW_ACCESS:
        lower_expr(L, &node->arrow_access.lhs, !is_borrow_of_pointer(L, node->arrow_access.lhs));
        use_value(L, slot, keep_place);
        return;
    case AST_CALL:
        lower_call(L, node);
        use_value(L, slot, keep_place);
        return;
    case AST_BORROW:
        lower_borrow(L, slot);
        return;
    case AST_UNARY:
        if (node->unary.op == ASTARISK) lower_deref(L, node);
        else lower_expr(L, &node->unary.operand, 0);
        return;
    case AST_ASSIGN:
        lower_assign(L, node);
        return;
    case AST_TERNARY:
        lower_expr(L, &node->ternary.cond, 0);
        lower_expr(L, &node->ternary.then_expr, keep_place);
        lower_expr(L, &node->ternary.else_expr, keep_place);
        return;
    case AST_CASE:
        lower_expr(L, &node->case_expr.target, 0);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            lower_expr(L, &node->case_expr.cases[i].key, 0);
            lower_expr(L, &node->case_expr.cases[i].expr, keep_place);
        }
        lower_expr(L, &node->case_expr.default_expr, keep_place);
        return;
    case AST_STMT_EXPR: {
        int outer = L->yield_keeps_place;
        L->yield_keeps_place = keep_place;
        lower_stmt(L, &node->stmt_expr.block);
        L->yield_keeps_place = outer;
        return;
    }
    case AST_SIZEOF:
    case AST_TYPE:
    case AST_TYPE_ARRAY:
    case AST_TYPE_FUNCTION:
        return;
    case AST_CAST:
        lower_expr(L, &node->cast.expr, 0);
        return;
    default:
        ast_visit_children(node, lower_expr_child, L);
        return;
    }
}

static void lower_block(BorrowPlaces *L, ASTNode *block) {
    MethodScope *outer = L->scope;
    MethodScope local = method_scope_clone(outer);
    L->scope = &local;
    for (int i = 0; i < block->block.count; i++) lower_stmt(L, &block->block.stmts[i]);
    L->scope = outer;
    method_scope_free(&local);
}

static void lower_stmt(BorrowPlaces *L, ASTNode **slot) {
    ASTNode *node = *slot;
    if (!node) return;
    switch (node->type) {
    case AST_BLOCK:
        lower_block(L, node);
        return;
    case AST_VAR_DECL:
        lower_expr(L, &node->var_decl.init, type_is_borrow(node->var_decl.var_type));
        method_scope_push(L->scope, node->var_decl.name, node->var_decl.var_type);
        return;
    case AST_RETURN:
        lower_expr(L, &node->ret.expr, type_is_borrow(L->function->fundef.ret_type));
        return;
    case AST_YIELD:
        lower_expr(L, &node->yield_stmt.expr, L->yield_keeps_place);
        return;
    case AST_EXPR_STMT:
        lower_expr(L, &node->expr_stmt.expr, 1); /* nothing reads what it leaves */
        return;
    case AST_IF:
        lower_expr(L, &node->if_stmt.cond, 0);
        lower_stmt(L, &node->if_stmt.then_stmt);
        lower_stmt(L, &node->if_stmt.else_stmt);
        return;
    case AST_WHILE:
        lower_expr(L, &node->while_stmt.cond, 0);
        lower_stmt(L, &node->while_stmt.body);
        return;
    case AST_DO_WHILE:
        lower_stmt(L, &node->do_while_stmt.body);
        lower_expr(L, &node->do_while_stmt.cond, 0);
        return;
    case AST_FOR: {
        MethodScope *outer = L->scope;
        MethodScope local = method_scope_clone(outer);
        L->scope = &local;
        lower_stmt(L, &node->for_stmt.init);
        lower_expr(L, &node->for_stmt.cond, 0);
        lower_expr(L, &node->for_stmt.inc, 0);
        lower_stmt(L, &node->for_stmt.body);
        L->scope = outer;
        method_scope_free(&local);
        return;
    }
    case AST_DEFER:
        lower_stmt(L, &node->defer_stmt.body);
        return;
    case AST_BREAK:
    case AST_CONTINUE:
    case AST_IMPORT:
        return;
    default:
        lower_expr(L, slot, 0);
        return;
    }
}

void lower_borrow_places(ParserContext *context, ASTNode *program) {
    if (!program || program->type != AST_BLOCK) return;
    method_shapes_begin(context, program);

    MethodScope global = {0};
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *stmt = program->block.stmts[i];
        if (stmt && stmt->type == AST_VAR_DECL)
            method_scope_push(&global, stmt->var_decl.name, stmt->var_decl.var_type);
    }

    BorrowPlaces L = {.context = context, .program = program};
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *fn = program->block.stmts[i];
        if (!fn || fn->type != AST_FUNDEF || !fn->fundef.body) continue;
        MethodScope scope = method_scope_clone(&global);
        for (int p = 0; p < fn->fundef.param_count; p++) {
            ASTNode *param = fn->fundef.params[p];
            if (param && param->type == AST_PARAM && param->param.type)
                method_scope_push(&scope, param->param.name, param->param.type);
        }
        L.scope = &scope;
        L.function = fn;
        L.in_instance = strncmp(fn->fundef.name, "__mlg_", 6) == 0;
        lower_stmt(&L, &fn->fundef.body);
        method_scope_free(&scope);
    }
    method_scope_free(&global);
    if (L.error_count) exit(1);
}
