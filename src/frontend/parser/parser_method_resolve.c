#include "mylang/frontend/parser_rewrite_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include <stdarg.h>

/* Resolves `recv.method(args)` / `recv->method(args)` calls left by the
 * parser (parser_expr_postfix.c) into ordinary calls to the method's mangled
 * name, with `recv` moved into args[0]. This is the only place a method call
 * needs a receiver's static type, and MyLang requires every local's type to
 * be written out (no `let`), so a plain scope of declared types -- built the
 * same way rewrite_node threads a scope of names -- is all inference needs;
 * no real type-inference engine is required. */

/* name -> declared type AST (borrowed from the declaration; never owned
 * here). */
typedef struct {
    char **names;
    ASTNode **types;
    int count;
    int cap;
} MethodScope;

static void method_scope_push(MethodScope *scope, const char *name, ASTNode *type) {
    if (!name || !type) return;
    if (scope->count == scope->cap) {
        scope->cap = scope->cap ? scope->cap * 2 : 8;
        scope->names = realloc(scope->names, sizeof(char *) * scope->cap);
        scope->types = realloc(scope->types, sizeof(ASTNode *) * scope->cap);
    }
    scope->names[scope->count] = strdup(name);
    scope->types[scope->count] = type;
    scope->count++;
}

static ASTNode *method_scope_lookup(MethodScope *scope, const char *name) {
    for (int i = scope->count - 1; i >= 0; i--) {
        if (strcmp(scope->names[i], name) == 0) return scope->types[i];
    }
    return NULL;
}

static MethodScope method_scope_clone(MethodScope *src) {
    MethodScope out = {0};
    for (int i = 0; i < src->count; i++) method_scope_push(&out, src->names[i], src->types[i]);
    return out;
}

static void method_scope_free(MethodScope *scope) {
    for (int i = 0; i < scope->count; i++) free(scope->names[i]);
    free(scope->names);
    free(scope->types);
}

/* A receiver's static shape: base type name (borrowed from the type AST) plus
 * pointer level and ref kind. Arrays and modifiers don't matter for method
 * dispatch, so they're not tracked here. */
typedef struct {
    const char *base_name;
    int pointer_level;
    int ref_kind;
} RecvShape;

static int shape_from_type_ast(ASTNode *type_node, RecvShape *out) {
    if (!type_node || type_node->type != AST_TYPE) return 0;
    ASTNode *base = type_node->type_node.base_type;
    if (!base) return 0;
    if (base->type == AST_IDENTIFIER) out->base_name = base->identifier.name;
    else if (base->type == AST_TYPE_GENERIC) out->base_name = base->generic_type.name;
    else return 0;
    out->pointer_level = type_node->type_node.pointer_level;
    out->ref_kind = type_node->type_node.ref_kind;
    return 1;
}

static ASTNode *find_member_type(ParserContext *ctx, const char *struct_name, const char *member) {
    StructDef *def = find_structdef(ctx, struct_name);
    if (!def) return NULL;
    for (int i = 0; i < def->member_count; i++) {
        ASTNode *m = def->members[i];
        if (m && m->type == AST_VAR_DECL && strcmp(m->var_decl.name, member) == 0) return m->var_decl.var_type;
    }
    return NULL;
}

static void resolve_calls_node(ParserContext *context, MethodScope *scope, ASTNode *node);

/* The public mock facade deliberately hides its generated TargetMock and
 * TargetRule types. Package imports expose ordinary function signatures to
 * codegen but do not copy non-generic receiver methods into this parser's
 * method table. Resolve just this compiler-owned fluent surface directly. */
static const char *mock_facade_method(const ASTNode *receiver, const char *method) {
    if (!receiver || receiver->type != AST_CALL || !method) return NULL;
    const char *callee = receiver->call.name;
    if (!callee) return NULL;
    if ((strcmp(callee, "mock_target") == 0 || strcmp(callee, "mock_spy") == 0) &&
        strcmp(method, "when") == 0) return "TargetMock__when";
    if ((strcmp(callee, "TargetMock__when") == 0 ||
         strcmp(callee, "TargetRule__ret") == 0 ||
         strcmp(callee, "TargetRule__then_ret") == 0) &&
        strcmp(method, "ret") == 0) return "TargetRule__ret";
    if ((strcmp(callee, "TargetMock__when") == 0 ||
         strcmp(callee, "TargetRule__ret") == 0 ||
         strcmp(callee, "TargetRule__then_ret") == 0) &&
        strcmp(method, "then_ret") == 0) return "TargetRule__then_ret";
    return NULL;
}

static void resolve_mock_facade_method(ASTNode *call, const char *mangled) {
    ASTNode **new_args = malloc(sizeof(ASTNode *) * (call->call.arg_count + 1));
    new_args[0] = call->call.recv;
    for (int i = 0; i < call->call.arg_count; i++) new_args[i + 1] = call->call.args[i];
    free(call->call.args);
    call->call.args = new_args;
    call->call.arg_count += 1;
    free(call->call.name);
    call->call.name = strdup(mangled);
    call->call.recv = NULL;
}

static int infer_recv_shape(ParserContext *ctx, MethodScope *scope, ASTNode *expr, RecvShape *out) {
    if (!expr) return 0;
    switch (expr->type) {
    case AST_IDENTIFIER: {
        ASTNode *t = method_scope_lookup(scope, expr->identifier.name);
        return t && shape_from_type_ast(t, out);
    }
    case AST_MEMBER_ACCESS:
    case AST_ARROW_ACCESS: {
        ASTNode *lhs = expr->type == AST_MEMBER_ACCESS ? expr->member_access.lhs : expr->arrow_access.lhs;
        const char *member = expr->type == AST_MEMBER_ACCESS ? expr->member_access.member : expr->arrow_access.member;
        RecvShape lhs_shape;
        if (!infer_recv_shape(ctx, scope, lhs, &lhs_shape)) return 0;
        ASTNode *member_type = find_member_type(ctx, lhs_shape.base_name, member);
        return member_type && shape_from_type_ast(member_type, out);
    }
    case AST_CALL: {
        /* Reached only after any method call nested inside this one has
         * already been resolved (resolve_calls_node visits call.recv and
         * call.args before inspecting the call itself), so `.name` is always
         * an ordinary function name here. */
        ASTNode *fn = find_function(ctx, expr->call.name);
        return fn && fn->type == AST_FUNDEF && shape_from_type_ast(fn->fundef.ret_type, out);
    }
    case AST_CAST:
        return shape_from_type_ast(expr->cast.type, out);
    case AST_UNARY:
        if (expr->unary.op == ASTARISK) {
            RecvShape inner;
            if (!infer_recv_shape(ctx, scope, expr->unary.operand, &inner)) return 0;
            if (inner.pointer_level <= 0) return 0;
            *out = inner;
            out->pointer_level -= 1;
            return 1;
        }
        if (expr->unary.op == AMPERSAND) {
            RecvShape inner;
            if (!infer_recv_shape(ctx, scope, expr->unary.operand, &inner)) return 0;
            *out = inner;
            out->pointer_level += 1;
            return 1;
        }
        return 0;
    case AST_BORROW:
    case AST_BORROW_MUT: {
        ASTNode *inner_expr = expr->type == AST_BORROW ? expr->borrow.expr : expr->borrow_mut.expr;
        RecvShape inner;
        if (!infer_recv_shape(ctx, scope, inner_expr, &inner)) return 0;
        *out = inner;
        out->ref_kind = expr->type == AST_BORROW ? REFKIND_SHARED : REFKIND_MUT;
        return 1;
    }
    default:
        return 0;
    }
}

static void method_error(ParserContext *ctx, ASTNode *node, const char *fmt, ...) {
    fprintf(stderr, "%s:%d:%d: error: ",
            ctx->module.filename ? ctx->module.filename : "<input>",
            node ? node->line : 0, node ? node->col : 0);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

/* Builds the expression that goes into args[0] to turn `recv` (whose static
 * shape is `actual`) into what the method's declared receiver (`expected`)
 * needs -- see docs/grammar.md's receiver table. An exact match (including
 * both being plain values, which is a move) passes through unchanged.
 * Reconciling a raw pointer with a `ref`/`ref mut` receiver, or vice versa,
 * has no auto-conversion yet -- it needs an explicit local. */
static ASTNode *convert_receiver(ParserContext *ctx, ASTNode *call, ASTNode *recv,
                                 const RecvShape *actual, const RecvShape *expected) {
    if (actual->pointer_level == expected->pointer_level && actual->ref_kind == expected->ref_kind) {
        return recv;
    }

    int actual_plain = actual->pointer_level == 0 && actual->ref_kind == REFKIND_NONE;
    int expected_plain_value = expected->pointer_level == 0 && expected->ref_kind == REFKIND_NONE;

    if (actual_plain) {
        if (expected->pointer_level == 0 && expected->ref_kind == REFKIND_SHARED) return new_borrow(recv);
        if (expected->pointer_level == 0 && expected->ref_kind == REFKIND_MUT) return new_borrow_mut(recv);
        if (expected->pointer_level == 1 && expected->ref_kind == REFKIND_NONE) return new_borrow(recv);
    }
    if (actual->pointer_level == 1 && actual->ref_kind == REFKIND_NONE && expected_plain_value) {
        return new_unary(ASTARISK, recv);
    }

    method_error(ctx, call,
        "cannot call method '%s' on this receiver: its declared kind (value/ref/ref mut/pointer) "
        "doesn't match what the method expects, and auto-ref/deref doesn't bridge them -- bind it "
        "to a local of the exact receiver type first",
        call->call.name);
    return NULL; /* unreachable: method_error() exits */
}

static void resolve_method_call(ParserContext *ctx, MethodScope *scope, ASTNode *call) {
    const char *mock_mangled = mock_facade_method(call->call.recv, call->call.name);
    if (mock_mangled) {
        resolve_mock_facade_method(call, mock_mangled);
        return;
    }
    RecvShape actual;
    if (!infer_recv_shape(ctx, scope, call->call.recv, &actual)) {
        method_error(ctx, call, "cannot determine the type of this method call's receiver");
    }
    const MethodDef *m = find_method(ctx, actual.base_name, call->call.name);
    if (!m) {
        method_error(ctx, call, "type '%s' has no method '%s'", actual.base_name, call->call.name);
    }

    RecvShape expected;
    if (!shape_from_type_ast(m->fundef->fundef.params[0]->param.type, &expected)) {
        method_error(ctx, call, "internal error: method '%s' has no receiver type", m->mangled);
    }

    ASTNode *arg0 = convert_receiver(ctx, call, call->call.recv, &actual, &expected);

    ASTNode **new_args = malloc(sizeof(ASTNode *) * (call->call.arg_count + 1));
    new_args[0] = arg0;
    for (int i = 0; i < call->call.arg_count; i++) new_args[i + 1] = call->call.args[i];
    free(call->call.args);
    call->call.args = new_args;
    call->call.arg_count += 1;

    free(call->call.name);
    call->call.name = strdup(m->mangled);
    call->call.recv = NULL;
}

static void resolve_calls_block(ParserContext *context, MethodScope *outer, ASTNode *block) {
    if (!block || block->type != AST_BLOCK) return;
    MethodScope local = method_scope_clone(outer);
    for (int i = 0; i < block->block.count; i++) {
        ASTNode *stmt = block->block.stmts[i];
        resolve_calls_node(context, &local, stmt);
        if (stmt && stmt->type == AST_VAR_DECL) {
            method_scope_push(&local, stmt->var_decl.name, stmt->var_decl.var_type);
        }
    }
    method_scope_free(&local);
}

static void resolve_calls_node(ParserContext *context, MethodScope *scope, ASTNode *node) {
    if (!node) return;
    switch (node->type) {
    case AST_CALL:
        for (int i = 0; i < node->call.arg_count; i++) resolve_calls_node(context, scope, node->call.args[i]);
        if (node->call.recv) {
            /* Resolve any method call nested inside the receiver first
             * (`a.b().c()`), so its return type is known once we get here. */
            resolve_calls_node(context, scope, node->call.recv);
            resolve_method_call(context, scope, node);
        }
        break;
    case AST_VAR_DECL:
        resolve_calls_node(context, scope, node->var_decl.init);
        break;
    case AST_BLOCK:
        resolve_calls_block(context, scope, node);
        break;
    case AST_FUNDEF: {
        MethodScope fn_scope = method_scope_clone(scope);
        for (int i = 0; i < node->fundef.param_count; i++) {
            ASTNode *p = node->fundef.params[i];
            if (p && p->type == AST_PARAM && p->param.type) {
                method_scope_push(&fn_scope, p->param.name, p->param.type);
            }
        }
        resolve_calls_block(context, &fn_scope, node->fundef.body);
        method_scope_free(&fn_scope);
        break;
    }
    case AST_ASSIGN:
        resolve_calls_node(context, scope, node->assign.left);
        resolve_calls_node(context, scope, node->assign.right);
        break;
    case AST_BINARY:
        resolve_calls_node(context, scope, node->binary.left);
        resolve_calls_node(context, scope, node->binary.right);
        break;
    case AST_UNARY:
        resolve_calls_node(context, scope, node->unary.operand);
        break;
    case AST_CAST:
        resolve_calls_node(context, scope, node->cast.expr);
        break;
    case AST_BORROW:
        resolve_calls_node(context, scope, node->borrow.expr);
        break;
    case AST_BORROW_MUT:
        resolve_calls_node(context, scope, node->borrow_mut.expr);
        break;
    case AST_TERNARY:
        resolve_calls_node(context, scope, node->ternary.cond);
        resolve_calls_node(context, scope, node->ternary.then_expr);
        resolve_calls_node(context, scope, node->ternary.else_expr);
        break;
    case AST_IF:
        resolve_calls_node(context, scope, node->if_stmt.cond);
        resolve_calls_node(context, scope, node->if_stmt.then_stmt);
        resolve_calls_node(context, scope, node->if_stmt.else_stmt);
        break;
    case AST_WHILE:
        resolve_calls_node(context, scope, node->while_stmt.cond);
        resolve_calls_node(context, scope, node->while_stmt.body);
        break;
    case AST_DO_WHILE:
        resolve_calls_node(context, scope, node->do_while_stmt.cond);
        resolve_calls_node(context, scope, node->do_while_stmt.body);
        break;
    case AST_FOR:
        resolve_calls_node(context, scope, node->for_stmt.init);
        resolve_calls_node(context, scope, node->for_stmt.cond);
        resolve_calls_node(context, scope, node->for_stmt.inc);
        resolve_calls_node(context, scope, node->for_stmt.body);
        break;
    case AST_RETURN:
        resolve_calls_node(context, scope, node->ret.expr);
        break;
    case AST_YIELD:
        resolve_calls_node(context, scope, node->yield_stmt.expr);
        break;
    case AST_EXPR_STMT:
        resolve_calls_node(context, scope, node->expr_stmt.expr);
        break;
    case AST_MEMBER_ACCESS:
        resolve_calls_node(context, scope, node->member_access.lhs);
        break;
    case AST_ARROW_ACCESS:
        resolve_calls_node(context, scope, node->arrow_access.lhs);
        break;
    case AST_CASE:
        resolve_calls_node(context, scope, node->case_expr.target);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            resolve_calls_node(context, scope, node->case_expr.cases[i].key);
            resolve_calls_node(context, scope, node->case_expr.cases[i].expr);
        }
        resolve_calls_node(context, scope, node->case_expr.default_expr);
        break;
    case AST_STMT_EXPR:
        resolve_calls_node(context, scope, node->stmt_expr.block);
        break;
    case AST_UNCHECKED:
        resolve_calls_node(context, scope, node->unchecked_block.body);
        break;
    case AST_INIT_LIST:
        for (int i = 0; i < node->init_list.count; i++) resolve_calls_node(context, scope, node->init_list.elements[i]);
        break;
    case AST_SIZEOF:
        resolve_calls_node(context, scope, node->sizeof_expr.expr);
        break;
    case AST_ENUM:
        for (int i = 0; i < node->enum_stmt.member_count; i++) resolve_calls_node(context, scope, node->enum_stmt.members[i]);
        break;
    case AST_ENUM_MEMBER:
        resolve_calls_node(context, scope, node->enum_member.value);
        break;
    default:
        break;
    }
}

void resolve_method_calls(ParserContext *context, ASTNode *program) {
    if (!program || program->type != AST_BLOCK) return;

    MethodScope global = {0};
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *stmt = program->block.stmts[i];
        if (stmt && stmt->type == AST_VAR_DECL) {
            method_scope_push(&global, stmt->var_decl.name, stmt->var_decl.var_type);
        }
    }

    for (int i = 0; i < program->block.count; i++) {
        ASTNode *stmt = program->block.stmts[i];
        if (stmt && stmt->type == AST_FUNDEF) {
            resolve_calls_node(context, &global, stmt);
        }
    }

    method_scope_free(&global);
}

static void check_no_unresolved_method_call(ASTNode **child, void *unused) {
    (void)unused;
    ensure_no_unresolved_method_calls(*child);
}

void ensure_no_unresolved_method_calls(ASTNode *node) {
    if (!node) return;
    if (node->type == AST_CALL && node->call.recv) {
        fprintf(stderr, "internal error: leftover unresolved method call '%s' after lowering\n", node->call.name);
        exit(1);
    }
    ast_visit_children(node, check_no_unresolved_method_call, NULL);
}
