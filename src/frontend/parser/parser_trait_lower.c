#include "mylang/frontend/parser_trait_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/parser_annot_internal.h"

/* Trait-backed uses that need a static type, lowered once every generic use
 * in the program is concrete and before payload enum uses are rewritten
 * (instantiate_generics()):
 *
 *   FsError::from(e)       -> FsError__From_SsdError__from(e)
 *   a == b  (A: Eq)        -> a.eq(&b)        (!a.eq(&b) for !=)
 *   for (T x in iter())    -> the iterator temporary gets iter()'s type
 *
 * MyLang spells every local's type, so a scope of declared types is all the
 * inference this needs -- the same approach parser_method_resolve.c takes. */

typedef struct {
    char **names;
    ASTNode **types; /* borrowed from declarations */
    int count;
    int cap;
} TypeScope;

typedef struct {
    ParserContext *context;
    ASTNode *program;
    TypeScope scope;
    int temp_counter;
    ASTNode *return_type; /* of the function being lowered; borrowed */
} TraitLowering;

static void scope_push(TypeScope *scope, const char *name, ASTNode *type) {
    if (!name || !type) return;
    if (scope->count == scope->cap) {
        scope->cap = scope->cap ? scope->cap * 2 : 16;
        scope->names = realloc(scope->names, sizeof(char *) * (size_t)scope->cap);
        scope->types = realloc(scope->types, sizeof(ASTNode *) * (size_t)scope->cap);
    }
    scope->names[scope->count] = (char *)name;
    scope->types[scope->count] = type;
    scope->count++;
}

static ASTNode *scope_lookup(TypeScope *scope, const char *name) {
    for (int i = scope->count - 1; i >= 0; i--)
        if (strcmp(scope->names[i], name) == 0) return scope->types[i];
    return NULL;
}

static void lower_error(TraitLowering *L, ASTNode *at, const char *message, const char *note) {
    fprintf(stderr, "%s:%d:%d: error: %s\n",
            L->context->module.filename ? L->context->module.filename : "<input>",
            at ? at->line : 0, at ? at->col : 0, message);
    if (note) fprintf(stderr, "  note: %s\n", note);
    exit(1);
}

static ASTNode *plain_type(const char *name) {
    return new_type_node(new_identifier((char *)name), 0, 0, REFKIND_NONE);
}

static const char *named_type(ASTNode *type) {
    if (!type || type->type != AST_TYPE || !type->type_node.base_type ||
        type->type_node.base_type->type != AST_IDENTIFIER)
        return NULL;
    return type->type_node.base_type->identifier.name;
}

static ASTNode *find_struct_member_type(TraitLowering *L, const char *struct_name, const char *member) {
    for (int i = 0; i < L->program->block.count; i++) {
        ASTNode *node = L->program->block.stmts[i];
        ASTNode **members = NULL;
        int count = 0;
        if (node && node->type == AST_STRUCT && node->struct_stmt.name &&
            strcmp(node->struct_stmt.name, struct_name) == 0) {
            members = node->struct_stmt.members;
            count = node->struct_stmt.member_count;
        } else if (node && node->type == AST_TYPEDEF_STRUCT && node->typedef_struct.typedef_name &&
                   strcmp(node->typedef_struct.typedef_name, struct_name) == 0) {
            members = node->typedef_struct.members;
            count = node->typedef_struct.member_count;
        } else {
            continue;
        }
        for (int m = 0; m < count; m++) {
            if (members[m] && members[m]->type == AST_VAR_DECL &&
                strcmp(members[m]->var_decl.name, member) == 0)
                return members[m]->var_decl.var_type;
        }
    }
    return NULL;
}

static ASTNode *function_return_type(TraitLowering *L, const char *name) {
    ASTNode *fn = find_function(L->context, name);
    if (!fn) {
        const char *mangled = find_export_mangled(L->context, name);
        if (mangled) fn = find_function(L->context, mangled);
    }
    if (!fn) fn = callee_declaration(L->context, L->program, name);
    return fn && fn->type == AST_FUNDEF ? fn->fundef.ret_type : NULL;
}

/* The candidate impls for `Type::name(...)`: impls of `Type` with an
 * associated function `name`. */
static int assoc_candidates(TraitLowering *L, const char *type_name, const char *item,
                            ImplDef **out, int max) {
    int count = 0;
    for (int i = 0; i < impl_count(L->context); i++) {
        ImplDef *impl = impl_at(L->context, i);
        if (impl->is_template || strcmp(impl->self_name, type_name) != 0) continue;
        const char *mangled = impl_item_mangled(impl, item);
        if (!mangled) continue;
        ASTNode *fn = find_function(L->context, mangled);
        if (fn && fn->fundef.recv_type_name) continue; /* a method, not `Type::` */
        if (count < max) out[count] = impl;
        count++;
    }
    return count;
}

/* The static type of `expr`, as an owned AST_TYPE, or NULL when this pass
 * cannot tell (the caller then leaves the expression alone). */
static ASTNode *infer_type(TraitLowering *L, ASTNode *expr) {
    if (!expr) return NULL;
    switch (expr->type) {
    case AST_NUMBER:
        return plain_type(expr->number.enum_name ? expr->number.enum_name : "i32");
    case AST_CHAR_LITERAL:
        return plain_type("char");
    case AST_IDENTIFIER: {
        const char *name = expr->identifier.name;
        const char *qualified = strstr(name, "::");
        if (qualified) {
            /* `Enum::Variant` -- the enum is the value's type. */
            char enum_name[256];
            snprintf(enum_name, sizeof(enum_name), "%.*s", (int)(qualified - name), name);
            return plain_type(enum_name);
        }
        ASTNode *type = scope_lookup(&L->scope, name);
        return type ? ast_clone(type) : NULL;
    }
    case AST_MEMBER_ACCESS:
    case AST_ARROW_ACCESS: {
        int arrow = expr->type == AST_ARROW_ACCESS;
        ASTNode *lhs = infer_type(L, arrow ? expr->arrow_access.lhs : expr->member_access.lhs);
        const char *name = named_type(lhs);
        ASTNode *member = NULL;
        if (name && lhs->type_node.pointer_level == (arrow ? 1 : 0))
            member = find_struct_member_type(L, name, arrow ? expr->arrow_access.member
                                                             : expr->member_access.member);
        free_ast(lhs);
        return member ? ast_clone(member) : NULL;
    }
    case AST_CALL: {
        if (expr->call.recv) {
            ASTNode *recv = infer_type(L, expr->call.recv);
            const char *name = named_type(recv);
            const MethodDef *method = name ? find_method(L->context, name, expr->call.name) : NULL;
            free_ast(recv);
            return method ? ast_clone(method->fundef->fundef.ret_type) : NULL;
        }
        const char *qualified = strstr(expr->call.name, "::");
        if (qualified) {
            char type_name[256];
            snprintf(type_name, sizeof(type_name), "%.*s", (int)(qualified - expr->call.name),
                     expr->call.name);
            ImplDef *impls[1];
            if (assoc_candidates(L, type_name, qualified + 2, impls, 1) > 0) {
                ASTNode *ret = function_return_type(L, impl_item_mangled(impls[0], qualified + 2));
                return ret ? ast_clone(ret) : NULL;
            }
            return plain_type(type_name); /* payload variant construction */
        }
        ASTNode *ret = function_return_type(L, expr->call.name);
        return ret ? ast_clone(ret) : NULL;
    }
    case AST_CAST:
        return ast_clone(expr->cast.type);
    case AST_BORROW:
    case AST_BORROW_MUT: {
        /* `&x` is the address of x, as a pointer would be. */
        ASTNode *inner = infer_type(L, expr->type == AST_BORROW ? expr->borrow.expr : expr->borrow_mut.expr);
        if (!inner || inner->type != AST_TYPE) {
            free_ast(inner);
            return NULL;
        }
        inner->type_node.pointer_level++;
        return inner;
    }
    case AST_BINARY: {
        /* `items[i]` is `*(items + i)`: pointer arithmetic keeps the
         * pointer's type. */
        if (expr->binary.op != ADD && expr->binary.op != SUB) return NULL;
        ASTNode *left = infer_type(L, expr->binary.left);
        if (left && left->type == AST_TYPE && left->type_node.pointer_level > 0) return left;
        if (left && left->type == AST_TYPE_ARRAY && left->type_array.element_type) {
            /* An array decays to a pointer to its first element. */
            ASTNode *element = ast_clone(left->type_array.element_type);
            free_ast(left);
            if (element->type != AST_TYPE) {
                free_ast(element);
                return NULL;
            }
            element->type_node.pointer_level++;
            return element;
        }
        free_ast(left);
        ASTNode *right = infer_type(L, expr->binary.right);
        if (right && right->type == AST_TYPE && right->type_node.pointer_level > 0) return right;
        free_ast(right);
        return NULL;
    }
    case AST_UNARY: {
        if (expr->unary.op != ASTARISK && expr->unary.op != AMPERSAND) return NULL;
        ASTNode *inner = infer_type(L, expr->unary.operand);
        if (!inner || inner->type != AST_TYPE) {
            free_ast(inner);
            return NULL;
        }
        if (expr->unary.op == AMPERSAND) {
            inner->type_node.pointer_level++;
        } else if (inner->type_node.pointer_level > 0) {
            inner->type_node.pointer_level--;
        } else {
            free_ast(inner);
            return NULL;
        }
        return inner;
    }
    default:
        return NULL;
    }
}

static int is_place(ASTNode *expr) {
    if (!expr) return 0;
    if (expr->type == AST_IDENTIFIER) return strstr(expr->identifier.name, "::") == NULL;
    if (expr->type == AST_MEMBER_ACCESS || expr->type == AST_ARROW_ACCESS) return 1;
    return expr->type == AST_UNARY && expr->unary.op == ASTARISK;
}

/* ---- Type::name(...) --------------------------------------------------- */

static void lower_assoc_call(TraitLowering *L, ASTNode *call) {
    const char *qualified = strstr(call->call.name, "::");
    if (!qualified || call->call.recv) return;
    char type_name[256];
    snprintf(type_name, sizeof(type_name), "%.*s", (int)(qualified - call->call.name), call->call.name);
    const char *item = qualified + 2;

    ImplDef *impls[16];
    int count = assoc_candidates(L, type_name, item, impls, 16);
    if (count == 0) return; /* an enum variant, handled by payload lowering */
    if (count > 16) count = 16;

    ImplDef *chosen = count == 1 ? impls[0] : NULL;
    if (!chosen) {
        /* From<A> and From<B>: pick the impl whose parameters match the
         * arguments' types. */
        for (int c = 0; c < count; c++) {
            ASTNode *fn = find_function(L->context, impl_item_mangled(impls[c], item));
            if (!fn || fn->fundef.param_count != call->call.arg_count) continue;
            int matches = 1;
            for (int a = 0; a < call->call.arg_count && matches; a++) {
                ASTNode *arg = infer_type(L, call->call.args[a]);
                char *want = trait_type_key(fn->fundef.params[a]->param.type);
                char *got = arg ? trait_type_key(arg) : strdup("?");
                matches = strcmp(want, got) == 0;
                free(want);
                free(got);
                free_ast(arg);
            }
            if (!matches) continue;
            if (chosen) lower_error(L, call, "ambiguous associated function call", NULL);
            chosen = impls[c];
        }
        if (!chosen) {
            char message[640];
            snprintf(message, sizeof(message),
                     "no impl of '%s::%s' takes arguments of these types", type_name, item);
            lower_error(L, call, message, "bind the argument to a typed local to make its type explicit");
        }
    }
    char *label = strdup(impl_item_mangled(chosen, item)); /* `item` points into the old name */
    free(call->call.name);
    call->call.name = label;
}

/* ---- == and != via Eq --------------------------------------------------- */

static ASTNode *hoist_operand(TraitLowering *L, ASTNode *expr, ASTNode *type,
                              ASTNode ***decls, int *decl_count) {
    if (is_place(expr)) return expr;
    char name[48];
    snprintf(name, sizeof(name), "__mlg_eq_%d", L->temp_counter++);
    ASTNode *decl = new_var_decl(ast_clone(type), name, expr);
    decl->line = expr->line;
    decl->col = expr->col;
    *decls = realloc(*decls, sizeof(ASTNode *) * (size_t)(*decl_count + 1));
    (*decls)[(*decl_count)++] = decl;
    return new_identifier(name);
}

static void lower_equality(TraitLowering *L, ASTNode **slot) {
    ASTNode *node = *slot;
    if (node->binary.op != EQ && node->binary.op != NEQ) return;
    ASTNode *type = infer_type(L, node->binary.left);
    const char *name = named_type(type);
    if (!name || type->type_node.pointer_level || type->type_node.ref_kind != REFKIND_NONE ||
        !find_impl_for_name(L->context, "Eq", name)) {
        free_ast(type);
        return;
    }

    ASTNode **decls = NULL;
    int decl_count = 0;
    ASTNode *left = hoist_operand(L, node->binary.left, type, &decls, &decl_count);
    ASTNode *right = hoist_operand(L, node->binary.right, type, &decls, &decl_count);
    ASTNode **args = malloc(sizeof(ASTNode *));
    args[0] = new_unary(AMPERSAND, right);
    ASTNode *call = new_call("eq", args, 1);
    call->call.recv = left;
    call->line = node->line;
    call->col = node->col;
    ASTNode *result = node->binary.op == NEQ ? new_unary(NOT, call) : call;
    if (decl_count) {
        decls = realloc(decls, sizeof(ASTNode *) * (size_t)(decl_count + 1));
        decls[decl_count++] = new_yield(result);
        result = new_stmt_expr(new_block(decls, decl_count));
    } else {
        free(decls);
    }
    result->line = node->line;
    result->col = node->col;
    node->binary.left = NULL;
    node->binary.right = NULL;
    free_ast(node);
    *slot = result;
    free_ast(type);
}

/* ---- for-in ------------------------------------------------------------- */

static int is_for_iter_placeholder(ASTNode *type) {
    const char *name = named_type(type);
    return name && strcmp(name, "__mlg_for_iter_type") == 0;
}

static void require_iterator(TraitLowering *L, ASTNode *at, ASTNode *iter_type) {
    const char *name = named_type(iter_type);
    if (name && iter_type->type_node.pointer_level == 0 &&
        find_impl_for_name(L->context, "Iterator", name))
        return;
    char *key = iter_type ? trait_type_key(iter_type) : strdup("this value");
    char message[256];
    snprintf(message, sizeof(message), "for-in needs an Iterator, but %s does not implement Iterator", key);
    free(key);
    lower_error(L, at, message, NULL);
}

static void lower_var_decl(TraitLowering *L, ASTNode *decl) {
    if (is_for_iter_placeholder(decl->var_decl.var_type)) {
        ASTNode *type = infer_type(L, decl->var_decl.init);
        if (!type)
            lower_error(L, decl, "cannot determine the type of the for-in iterator",
                        "bind the iterator to a typed local first and iterate that local");
        require_iterator(L, decl, type);
        free_ast(decl->var_decl.var_type);
        decl->var_decl.var_type = type;
    } else if (decl->var_decl.name && strncmp(decl->var_decl.name, "__mlg_for_next_", 15) == 0) {
        ASTNode *init = decl->var_decl.init;
        ASTNode *type = init && init->type == AST_CALL ? infer_type(L, init->call.recv) : NULL;
        require_iterator(L, decl, type);
        free_ast(type);
    }
}

/* ---- dyn conversions -------------------------------------------------------- */

/* A `T *` where a dyn value is expected becomes one (coerce_to_dyn). */
static void coerce(TraitLowering *L, ASTNode **slot, ASTNode *target) {
    if (!*slot || !dyn_use_for_type(L->context, target)) return;
    ASTNode *source = infer_type(L, *slot);
    coerce_to_dyn(L->context, L->program, slot, source, target);
    free_ast(source);
}

static ASTNode *callee_of(TraitLowering *L, ASTNode *call, int *first_arg) {
    *first_arg = 0;
    if (call->call.recv) {
        ASTNode *recv = infer_type(L, call->call.recv);
        const char *name = named_type(recv);
        const MethodDef *method = name ? find_method(L->context, name, call->call.name) : NULL;
        free_ast(recv);
        *first_arg = 1; /* params[0] is the receiver */
        return method ? method->fundef : NULL;
    }
    ASTNode *fn = find_function(L->context, call->call.name);
    if (!fn) {
        const char *mangled = find_export_mangled(L->context, call->call.name);
        if (mangled) fn = find_function(L->context, mangled);
    }
    return fn && fn->type == AST_FUNDEF ? fn : NULL;
}

static void coerce_call_args(TraitLowering *L, ASTNode *call) {
    int first = 0;
    ASTNode *fn = callee_of(L, call, &first);
    if (!fn) return;
    for (int a = 0; a < call->call.arg_count && a + first < fn->fundef.param_count; a++) {
        ASTNode *param = fn->fundef.params[a + first];
        if (param && param->type == AST_PARAM) coerce(L, &call->call.args[a], param->param.type);
    }
}

static void coerce_literal_fields(TraitLowering *L, ASTNode *literal) {
    if (!literal->init_list.struct_type_name || !literal->init_list.field_names) return;
    for (int i = 0; i < literal->init_list.count; i++) {
        ASTNode *field = find_struct_member_type(L, literal->init_list.struct_type_name,
                                                 literal->init_list.field_names[i]);
        coerce(L, &literal->init_list.elements[i], field);
    }
}

/* ---- walk ---------------------------------------------------------------- */

static void lower_node(TraitLowering *L, ASTNode **slot);

static void lower_child(ASTNode **slot, void *user_data) {
    lower_node(user_data, slot);
}

static void lower_node(TraitLowering *L, ASTNode **slot) {
    ASTNode *node = *slot;
    if (!node) return;
    switch (node->type) {
    case AST_FUNDEF: {
        int mark = L->scope.count;
        for (int i = 0; i < node->fundef.param_count; i++) {
            ASTNode *p = node->fundef.params[i];
            if (p && p->type == AST_PARAM) scope_push(&L->scope, p->param.name, p->param.type);
        }
        L->return_type = node->fundef.ret_type;
        lower_node(L, &node->fundef.body);
        L->return_type = NULL;
        L->scope.count = mark;
        return;
    }
    case AST_BLOCK: {
        int mark = L->scope.count;
        for (int i = 0; i < node->block.count; i++) {
            lower_node(L, &node->block.stmts[i]);
            ASTNode *stmt = node->block.stmts[i];
            if (stmt && stmt->type == AST_VAR_DECL)
                scope_push(&L->scope, stmt->var_decl.name, stmt->var_decl.var_type);
        }
        L->scope.count = mark;
        return;
    }
    case AST_FOR: {
        int mark = L->scope.count;
        lower_node(L, &node->for_stmt.init);
        if (node->for_stmt.init && node->for_stmt.init->type == AST_VAR_DECL)
            scope_push(&L->scope, node->for_stmt.init->var_decl.name, node->for_stmt.init->var_decl.var_type);
        lower_node(L, &node->for_stmt.cond);
        lower_node(L, &node->for_stmt.inc);
        lower_node(L, &node->for_stmt.body);
        L->scope.count = mark;
        return;
    }
    case AST_VAR_DECL:
        lower_node(L, &node->var_decl.init);
        lower_var_decl(L, node);
        coerce(L, &node->var_decl.init, node->var_decl.var_type);
        return;
    case AST_CALL:
        ast_visit_children(node, lower_child, L);
        lower_assoc_call(L, node);
        coerce_call_args(L, node);
        return;
    case AST_ASSIGN: {
        ast_visit_children(node, lower_child, L);
        ASTNode *target = infer_type(L, node->assign.left);
        coerce(L, &node->assign.right, target);
        free_ast(target);
        return;
    }
    case AST_RETURN:
        ast_visit_children(node, lower_child, L);
        coerce(L, &node->ret.expr, L->return_type);
        return;
    case AST_INIT_LIST:
        ast_visit_children(node, lower_child, L);
        coerce_literal_fields(L, node);
        return;
    case AST_BINARY:
        ast_visit_children(node, lower_child, L);
        lower_equality(L, slot);
        return;
    default:
        ast_visit_children(node, lower_child, L);
        return;
    }
}

void lower_trait_uses(ParserContext *context, ASTNode *program) {
    if (!program || program->type != AST_BLOCK) return;
    TraitLowering L = {.context = context, .program = program};
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (node && node->type == AST_VAR_DECL)
            scope_push(&L.scope, node->var_decl.name, node->var_decl.var_type);
    }
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (node && node->type == AST_FUNDEF && node->fundef.body) lower_node(&L, &program->block.stmts[i]);
    }
    free(L.scope.names);
    free(L.scope.types);
}
