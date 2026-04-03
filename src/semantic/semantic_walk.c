#include "mylang/semantic/semantic_internal.h"

typedef enum {
    EXPRCTX_READ = 0,
    EXPRCTX_MOVE,
    EXPRCTX_WRITE,
} ExprContext;

static int semantic_type_is_copy(ASTNode *type_node) {
    SemanticTypeInfo info;
    const char *base_type;

    if (!semantic_typeinfo_from_type_ast(type_node, &info)) return 0;
    if (info.ref_kind != REFKIND_NONE) return 1;
    if (info.pointer_level > 0) return 1;
    if (info.is_array) return 0;

    base_type = info.base_type;
    if (!base_type) return 0;
    return strcmp(base_type, "bool") == 0 ||
           strcmp(base_type, "i32") == 0 ||
           strcmp(base_type, "u32") == 0 ||
           strcmp(base_type, "char") == 0 ||
           strcmp(base_type, "float") == 0 ||
           strcmp(base_type, "double") == 0 ||
           strcmp(base_type, "long") == 0 ||
           strcmp(base_type, "short") == 0 ||
           strcmp(base_type, "void") == 0;
}

static SemanticBinding *find_binding(SemanticContext *ctx, const char *name) {
    if (!ctx || !name) return NULL;
    for (int i = ctx->binding_count - 1; i >= 0; i--) {
        if (ctx->bindings[i].name && strcmp(ctx->bindings[i].name, name) == 0) {
            return &ctx->bindings[i];
        }
    }
    return NULL;
}

static SemanticBinding *borrow_target_binding(SemanticContext *ctx, ASTNode *expr) {
    if (!ctx || !expr) return NULL;
    if (expr->type == AST_IDENTIFIER) {
        return find_binding(ctx, expr->identifier.name);
    }
    if (expr->type == AST_MEMBER_ACCESS) {
        return borrow_target_binding(ctx, expr->member_access.lhs);
    }
    return NULL;
}

static void enter_scope(SemanticContext *ctx) {
    if (!ctx) return;
    ctx->scope_depth++;
}

static void leave_scope(SemanticContext *ctx) {
    if (!ctx) return;
    while (ctx->binding_count > 0 &&
           ctx->bindings[ctx->binding_count - 1].scope_depth >= ctx->scope_depth) {
        SemanticBinding *binding = &ctx->bindings[ctx->binding_count - 1];
        if (binding->borrowed_from) {
            SemanticBinding *owner = find_binding(ctx, binding->borrowed_from);
            if (owner) {
                if (binding->borrow_is_mut) {
                    owner->mutable_borrow_active = 0;
                } else if (owner->shared_borrow_count > 0) {
                    owner->shared_borrow_count--;
                }
            }
        }
        ctx->binding_count--;
    }
    if (ctx->scope_depth > 0) ctx->scope_depth--;
}

static void declare_binding(SemanticContext *ctx, const char *name, int is_copy, int is_param) {
    SemanticBinding *binding;

    if (!ctx || !name) return;
    binding = find_binding(ctx, name);
    if (binding && binding->scope_depth == ctx->scope_depth) {
        binding->is_copy = is_copy;
        binding->moved = 0;
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
    binding->moved = 0;
    binding->scope_depth = ctx->scope_depth;
    binding->is_param = is_param;
    binding->is_global = (!is_param && ctx->function_depth == 0);
    binding->borrowed_from = NULL;
    binding->borrow_is_mut = 0;
    binding->shared_borrow_count = 0;
    binding->mutable_borrow_active = 0;
}

static void check_return_reference_escape(SemanticContext *ctx, ASTNode *expr) {
    SemanticBinding *binding;
    SemanticBinding *owner;
    ASTNode *borrowed_expr = NULL;

    if (!ctx || !expr) return;

    if (expr->type == AST_BORROW) {
        borrowed_expr = expr->borrow.expr;
        owner = borrow_target_binding(ctx, borrowed_expr);
        if (owner && !owner->is_param && !owner->is_global) {
            semantic_error_at(ctx, semantic_location_from_ast(expr),
                              "cannot return reference to local '%s'", owner->name);
        }
        return;
    }

    if (expr->type == AST_BORROW_MUT) {
        borrowed_expr = expr->borrow_mut.expr;
        owner = borrow_target_binding(ctx, borrowed_expr);
        if (owner && !owner->is_param && !owner->is_global) {
            semantic_error_at(ctx, semantic_location_from_ast(expr),
                              "cannot return reference to local '%s'", owner->name);
        }
        return;
    }

    if (expr->type != AST_IDENTIFIER) return;

    binding = find_binding(ctx, expr->identifier.name);
    if (!binding || !binding->borrowed_from) return;

    owner = find_binding(ctx, binding->borrowed_from);
    if (owner && !owner->is_param && !owner->is_global) {
        semantic_error_at(ctx, semantic_location_from_ast(expr),
                          "cannot return reference to local '%s'", owner->name);
    }
}

static void revive_binding_if_identifier(SemanticContext *ctx, ASTNode *node) {
    SemanticBinding *binding;

    if (!ctx || !node || node->type != AST_IDENTIFIER) return;
    binding = find_binding(ctx, node->identifier.name);
    if (!binding) return;
    binding->moved = 0;
}

static void register_borrow_binding(SemanticContext *ctx, ASTNode *binding_node) {
    SemanticBinding *binding;
    SemanticBinding *owner;
    ASTNode *borrowed_expr;
    SemanticTypeInfo type_info;
    int is_mut;

    if (!ctx || !binding_node || binding_node->type != AST_VAR_DECL) return;
    if (!semantic_typeinfo_from_type_ast(binding_node->var_decl.var_type, &type_info)) return;
    if (type_info.ref_kind == REFKIND_NONE) return;

    binding = find_binding(ctx, binding_node->var_decl.name);
    if (!binding || !binding_node->var_decl.init) return;

    if (binding_node->var_decl.init->type == AST_BORROW) {
        borrowed_expr = binding_node->var_decl.init->borrow.expr;
        is_mut = 0;
    } else if (binding_node->var_decl.init->type == AST_BORROW_MUT) {
        borrowed_expr = binding_node->var_decl.init->borrow_mut.expr;
        is_mut = 1;
    } else {
        return;
    }

    owner = borrow_target_binding(ctx, borrowed_expr);
    if (!owner) return;

    if (is_mut) {
        if (owner->mutable_borrow_active || owner->shared_borrow_count > 0) {
            semantic_error_at(ctx, semantic_location_from_ast(binding_node->var_decl.init),
                              "cannot mutably borrow '%s' while it is already borrowed", owner->name);
            return;
        }
        owner->mutable_borrow_active = 1;
    } else {
        if (owner->mutable_borrow_active) {
            semantic_error_at(ctx, semantic_location_from_ast(binding_node->var_decl.init),
                              "cannot borrow '%s' while it is mutably borrowed", owner->name);
            return;
        }
        owner->shared_borrow_count++;
    }

    binding->borrowed_from = owner->name;
    binding->borrow_is_mut = is_mut;
}

static void use_identifier(SemanticContext *ctx, ASTNode *node, ExprContext expr_ctx) {
    SemanticBinding *binding;

    if (!ctx || !node || node->type != AST_IDENTIFIER) return;
    binding = find_binding(ctx, node->identifier.name);
    if (!binding) return;

    if (expr_ctx == EXPRCTX_MOVE &&
        (binding->mutable_borrow_active || binding->shared_borrow_count > 0)) {
        semantic_error_at(ctx, semantic_location_from_ast(node),
                          "cannot move '%s' while it is borrowed", node->identifier.name);
        return;
    }

    if (binding->moved && expr_ctx != EXPRCTX_WRITE) {
        semantic_error_at(ctx, semantic_location_from_ast(node),
                          "use of moved value '%s'", node->identifier.name);
        return;
    }

    if (expr_ctx == EXPRCTX_MOVE && !binding->is_copy) {
        binding->moved = 1;
    }
}

static void semantic_walk_expr(SemanticContext *ctx, ASTNode *node, ExprContext expr_ctx);
static void semantic_walk_stmt(SemanticContext *ctx, ASTNode *node);

static void walk_case_items(SemanticContext *ctx, ASTNode *node) {
    for (int i = 0; i < node->case_expr.case_count; i++) {
        semantic_walk_expr(ctx, node->case_expr.cases[i].key, EXPRCTX_READ);
        semantic_walk_expr(ctx, node->case_expr.cases[i].expr, EXPRCTX_READ);
    }
    semantic_walk_expr(ctx, node->case_expr.default_expr, EXPRCTX_READ);
}

static void walk_params(SemanticContext *ctx, ASTNode **params, int param_count) {
    for (int i = 0; i < param_count; i++) {
        ASTNode *param = params[i];
        semantic_walk_stmt(ctx, param);
        if (param && param->type == AST_PARAM) {
            declare_binding(ctx, param->param.name, semantic_type_is_copy(param->param.type), 1);
        }
    }
}

static void walk_block_items(SemanticContext *ctx, ASTNode **items, int count) {
    for (int i = 0; i < count; i++) {
        semantic_walk_stmt(ctx, items[i]);
    }
}

static void semantic_walk_expr(SemanticContext *ctx, ASTNode *node, ExprContext expr_ctx) {
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
        break;
    case AST_ASSIGN:
        semantic_walk_expr(ctx, node->assign.right, EXPRCTX_READ);
        semantic_walk_expr(ctx, node->assign.left, EXPRCTX_WRITE);
        revive_binding_if_identifier(ctx, node->assign.left);
        break;
    case AST_BORROW:
        semantic_walk_expr(ctx, node->borrow.expr, EXPRCTX_READ);
        break;
    case AST_BORROW_MUT:
        semantic_walk_expr(ctx, node->borrow_mut.expr, EXPRCTX_READ);
        break;
    case AST_UNARY:
        if (node->unary.op == AMPERSAND) {
            semantic_walk_expr(ctx, node->unary.operand, EXPRCTX_READ);
        } else if (node->unary.op == ASTARISK) {
            semantic_walk_expr(ctx, node->unary.operand, EXPRCTX_READ);
        } else {
            semantic_walk_expr(ctx, node->unary.operand, EXPRCTX_READ);
        }
        break;
    case AST_CAST:
        semantic_walk_stmt(ctx, node->cast.type);
        semantic_walk_expr(ctx, node->cast.expr, EXPRCTX_READ);
        break;
    case AST_CALL:
        for (int i = 0; i < node->call.arg_count; i++) {
            semantic_walk_expr(ctx, node->call.args[i], EXPRCTX_MOVE);
        }
        break;
    case AST_MEMBER_ACCESS:
        semantic_walk_expr(ctx, node->member_access.lhs, expr_ctx == EXPRCTX_MOVE ? EXPRCTX_MOVE : EXPRCTX_READ);
        break;
    case AST_ARROW_ACCESS:
        semantic_walk_expr(ctx, node->arrow_access.lhs, expr_ctx == EXPRCTX_MOVE ? EXPRCTX_MOVE : EXPRCTX_READ);
        break;
    case AST_INIT_LIST:
        for (int i = 0; i < node->init_list.count; i++) {
            semantic_walk_expr(ctx, node->init_list.elements[i], EXPRCTX_READ);
        }
        break;
    case AST_SIZEOF:
        semantic_walk_expr(ctx, node->sizeof_expr.expr, EXPRCTX_READ);
        break;
    case AST_TERNARY:
        semantic_walk_expr(ctx, node->ternary.cond, EXPRCTX_READ);
        semantic_walk_expr(ctx, node->ternary.then_expr, EXPRCTX_READ);
        semantic_walk_expr(ctx, node->ternary.else_expr, EXPRCTX_READ);
        break;
    case AST_CASE:
        semantic_walk_expr(ctx, node->case_expr.target, EXPRCTX_READ);
        walk_case_items(ctx, node);
        break;
    case AST_STMT_EXPR:
        semantic_walk_stmt(ctx, node->stmt_expr.block);
        break;
    case AST_TYPE:
    case AST_TYPE_ARRAY:
    case AST_VAR_DECL:
    case AST_EXPR_STMT:
    case AST_IF:
    case AST_RETURN:
    case AST_BLOCK:
    case AST_FUN_LITERAL:
    case AST_FUNDEF:
    case AST_PARAM:
    case AST_WHILE:
    case AST_FOR:
    case AST_TYPEDEF:
    case AST_STRUCT:
    case AST_STRUCT_MEMBER:
    case AST_TYPEDEF_STRUCT:
    case AST_IMPORT:
    case AST_DO_WHILE:
    case AST_UNCHECKED:
    case AST_YIELD:
        semantic_walk_stmt(ctx, node);
        break;
    default:
        semantic_error_at(ctx, semantic_location_unknown(),
                          "semantic walker encountered unknown AST node type %d", node->type);
        break;
    }
}

static void semantic_walk_stmt(SemanticContext *ctx, ASTNode *node) {
    int is_copy;

    if (!ctx || !node) return;

    switch (node->type) {
    case AST_NUMBER:
    case AST_IDENTIFIER:
    case AST_BINARY:
    case AST_ASSIGN:
    case AST_BORROW:
    case AST_BORROW_MUT:
    case AST_UNARY:
    case AST_CAST:
    case AST_CALL:
    case AST_MEMBER_ACCESS:
    case AST_ARROW_ACCESS:
    case AST_INIT_LIST:
    case AST_SIZEOF:
    case AST_TERNARY:
    case AST_CASE:
        semantic_walk_expr(ctx, node, EXPRCTX_READ);
        break;
    case AST_TYPE:
        semantic_walk_stmt(ctx, node->type_node.base_type);
        break;
    case AST_TYPE_ARRAY:
        semantic_walk_stmt(ctx, node->type_array.element_type);
        break;
    case AST_VAR_DECL:
        semantic_walk_stmt(ctx, node->var_decl.var_type);
        if (node->var_decl.init) {
            semantic_walk_expr(ctx, node->var_decl.init, EXPRCTX_MOVE);
        }
        is_copy = semantic_type_is_copy(node->var_decl.var_type);
        declare_binding(ctx, node->var_decl.name, is_copy, 0);
        register_borrow_binding(ctx, node);
        break;
    case AST_EXPR_STMT:
        semantic_walk_expr(ctx, node->expr_stmt.expr, EXPRCTX_READ);
        break;
    case AST_IF:
        semantic_walk_expr(ctx, node->if_stmt.cond, EXPRCTX_READ);
        semantic_walk_stmt(ctx, node->if_stmt.then_stmt);
        semantic_walk_stmt(ctx, node->if_stmt.else_stmt);
        break;
    case AST_RETURN:
        check_return_reference_escape(ctx, node->ret.expr);
        semantic_walk_expr(ctx, node->ret.expr, EXPRCTX_MOVE);
        break;
    case AST_YIELD:
        semantic_walk_expr(ctx, node->yield_stmt.expr, EXPRCTX_MOVE);
        break;
    case AST_BLOCK:
        enter_scope(ctx);
        walk_block_items(ctx, node->block.stmts, node->block.count);
        leave_scope(ctx);
        break;
    case AST_UNCHECKED:
        semantic_walk_stmt(ctx, node->unchecked_block.body);
        break;
    case AST_STMT_EXPR:
        semantic_walk_stmt(ctx, node->stmt_expr.block);
        break;
    case AST_FUN_LITERAL:
        ctx->function_depth++;
        enter_scope(ctx);
        walk_params(ctx, node->fun_literal.params, node->fun_literal.param_count);
        semantic_walk_stmt(ctx, node->fun_literal.ret_type);
        semantic_walk_stmt(ctx, node->fun_literal.body);
        leave_scope(ctx);
        ctx->function_depth--;
        break;
    case AST_FUNDEF:
        ctx->function_depth++;
        enter_scope(ctx);
        semantic_walk_stmt(ctx, node->fundef.ret_type);
        walk_params(ctx, node->fundef.params, node->fundef.param_count);
        semantic_walk_stmt(ctx, node->fundef.body);
        leave_scope(ctx);
        ctx->function_depth--;
        break;
    case AST_PARAM:
        semantic_walk_stmt(ctx, node->param.type);
        break;
    case AST_WHILE:
        semantic_walk_expr(ctx, node->while_stmt.cond, EXPRCTX_READ);
        semantic_walk_stmt(ctx, node->while_stmt.body);
        break;
    case AST_FOR:
        enter_scope(ctx);
        semantic_walk_stmt(ctx, node->for_stmt.init);
        semantic_walk_expr(ctx, node->for_stmt.cond, EXPRCTX_READ);
        semantic_walk_stmt(ctx, node->for_stmt.inc);
        semantic_walk_stmt(ctx, node->for_stmt.body);
        leave_scope(ctx);
        break;
    case AST_TYPEDEF:
        semantic_walk_stmt(ctx, node->typedef_stmt.src_type);
        break;
    case AST_STRUCT:
        walk_block_items(ctx, node->struct_stmt.members, node->struct_stmt.member_count);
        break;
    case AST_STRUCT_MEMBER:
        break;
    case AST_TYPEDEF_STRUCT:
        walk_block_items(ctx, node->typedef_struct.members, node->typedef_struct.member_count);
        break;
    case AST_BREAK:
    case AST_CONTINUE:
        break;
    case AST_IMPORT:
        break;
    case AST_DO_WHILE:
        semantic_walk_stmt(ctx, node->do_while_stmt.body);
        semantic_walk_expr(ctx, node->do_while_stmt.cond, EXPRCTX_READ);
        break;
    default:
        semantic_error_at(ctx, semantic_location_from_ast(node),
                          "semantic walker encountered unknown AST node type %d", node->type);
        break;
    }
}

void semantic_walk_ast(SemanticContext *ctx, ASTNode *node) {
    semantic_walk_stmt(ctx, node);
}
