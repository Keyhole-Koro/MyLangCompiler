#include "mylang/semantic/semantic_internal.h"
#include "mylang/frontend/parser_state_internal.h"

typedef enum {
    EXPRCTX_READ = 0,
    EXPRCTX_MOVE,
    EXPRCTX_WRITE,
} ExprContext;

#define SEMCODE_UNDEFINED_IDENTIFIER "E0001"
#define SEMCODE_UNDEFINED_FUNCTION "E0002"
#define SEMCODE_ARG_COUNT_MISMATCH "E0101"
#define SEMCODE_RETURN_TYPE_MISMATCH "E0201"
#define SEMCODE_ASSIGNMENT_TYPE_MISMATCH "E0301"
#define SEMCODE_INVALID_BINARY_OPERANDS "E0302"
#define SEMCODE_INVALID_CONDITION_TYPE "E0303"

static int semantic_infer_expr_type(SemanticContext *ctx, ASTNode *expr, SemanticTypeInfo *out);

static ASTNode *semantic_as_identifier(ASTNode *node) {
    return (node && node->type == AST_IDENTIFIER) ? node : NULL;
}

static ASTNode *semantic_as_var_decl(ASTNode *node) {
    return (node && node->type == AST_VAR_DECL) ? node : NULL;
}

static ASTNode *semantic_as_param(ASTNode *node) {
    return (node && node->type == AST_PARAM) ? node : NULL;
}

static int semantic_enum_type_exists(SemanticContext *ctx, const char *name) {
    if (!ctx || !name) return 0;
    for (int i = 0; i < ctx->enum_type_count; i++) {
        if (ctx->enum_types[i] && strcmp(ctx->enum_types[i], name) == 0) return 1;
    }
    return 0;
}

static int semantic_find_enum_value(SemanticContext *ctx, const char *name, long *out_value) {
    if (!ctx || !name) return 0;
    for (int i = ctx->enum_value_count - 1; i >= 0; i--) {
        if (ctx->enum_values[i].name && strcmp(ctx->enum_values[i].name, name) == 0) {
            if (out_value) *out_value = ctx->enum_values[i].value;
            return 1;
        }
    }
    return 0;
}

static int semantic_is_builtin_call(const char *name) {
    return name &&
           (strcmp(name, "__rest_len") == 0 ||
            strcmp(name, "__rest_get") == 0);
}

static SemanticFunctionSig *find_function_sig(SemanticContext *ctx, const char *name) {
    if (!ctx || !name) return NULL;
    for (int i = ctx->function_sig_count - 1; i >= 0; i--) {
        if (ctx->function_sigs[i].name && strcmp(ctx->function_sigs[i].name, name) == 0) {
            return &ctx->function_sigs[i];
        }
    }
    return NULL;
}

static void register_function_sig(SemanticContext *ctx, const char *name, int param_count,
                                  int is_variadic, int is_imported, SemanticLocation loc) {
    SemanticFunctionSig *sig;

    if (!ctx || !name) return;
    sig = find_function_sig(ctx, name);
    if (sig && !sig->is_imported) return;
    if (sig && sig->is_imported && !is_imported) {
        sig->param_count = param_count;
        sig->fixed_param_count = is_variadic ? param_count - 1 : param_count;
        sig->is_variadic = is_variadic;
        sig->is_imported = 0;
        sig->decl_loc = loc;
        return;
    }

    if (ctx->function_sig_count >= (int)(sizeof(ctx->function_sigs) / sizeof(ctx->function_sigs[0]))) {
        semantic_error_at(ctx, loc, "semantic function table exhausted while tracking '%s'", name);
        return;
    }

    sig = &ctx->function_sigs[ctx->function_sig_count++];
    sig->name = name;
    sig->param_count = param_count;
    sig->fixed_param_count = is_variadic ? param_count - 1 : param_count;
    sig->is_variadic = is_variadic;
    sig->is_imported = is_imported;
    sig->decl_loc = loc;
}

static int call_may_be_package_import(const char *name) {
    if (!name) return 0;
    for (int i = 0; i < g_imported_pkg_count; i++) {
        const char *pkg = g_imported_packages[i];
        size_t len = pkg ? strlen(pkg) : 0;
        if (len > 0 && strncmp(name, pkg, len) == 0 && name[len] == '_') return 1;
    }
    return 0;
}

static void semantic_register_enum(SemanticContext *ctx, ASTNode *node) {
    if (!ctx || !node || node->type != AST_ENUM) return;
    if (node->enum_stmt.name && ctx->enum_type_count < (int)(sizeof(ctx->enum_types) / sizeof(ctx->enum_types[0]))) {
        ctx->enum_types[ctx->enum_type_count++] = node->enum_stmt.name;
    }
    for (int i = 0; i < node->enum_stmt.member_count; i++) {
        ASTNode *member = node->enum_stmt.members[i];
        if (!member || member->type != AST_ENUM_MEMBER) continue;
        if (ctx->enum_value_count >= (int)(sizeof(ctx->enum_values) / sizeof(ctx->enum_values[0]))) {
            semantic_error_at(ctx, semantic_location_from_ast(member),
                              "semantic enum table exhausted while tracking '%s'", member->enum_member.name);
            return;
        }
        ctx->enum_values[ctx->enum_value_count].name = member->enum_member.name;
        ctx->enum_values[ctx->enum_value_count].value = member->enum_member.resolved_value;
        ctx->enum_value_count++;
    }
}

static void semantic_collect_function_sigs(SemanticContext *ctx, ASTNode *node) {
    if (!ctx || !node) return;

    switch (node->type) {
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++) {
            semantic_collect_function_sigs(ctx, node->block.stmts[i]);
        }
        break;
    case AST_FUNDEF:
        register_function_sig(ctx,
                              node->fundef.name,
                              node->fundef.param_count,
                              node->fundef.is_variadic ? 1 : 0,
                              0,
                              semantic_location_from_ast(node));
        break;
    case AST_IMPORT:
        for (int i = 0; i < node->import_stmt.symbol_count; i++) {
            register_function_sig(ctx,
                                  node->import_stmt.symbols[i],
                                  -1,
                                  0,
                                  1,
                                  semantic_location_from_ast(node));
        }
        break;
    default:
        break;
    }
}

static int semantic_type_is_copy(SemanticContext *ctx, ASTNode *type_node) {
    if (!type_node) return 1;
    SemanticTypeInfo info;
    const char *base_type;

    if (!semantic_typeinfo_from_type_ast(type_node, &info)) return 0;
    if (info.ref_kind != REFKIND_NONE) return 1;
    if (info.pointer_level > 0) return 1;
    if (info.is_array) return 0;

    base_type = info.base_type;
    if (!base_type) return 0;
    if (semantic_enum_type_exists(ctx, base_type)) return 1;
    return semantic_is_builtin_type(base_type);
}

static const char *semantic_type_base_name(ASTNode *type_node) {
    SemanticTypeInfo info;
    if (!semantic_typeinfo_from_type_ast(type_node, &info)) return "";
    return info.base_type ? info.base_type : "";
}

static int semantic_type_is_void(ASTNode *type_node) {
    const char *base = semantic_type_base_name(type_node);
    return strcmp(base, "void") == 0;
}

static int semantic_typeinfo_is_integer_like(const SemanticTypeInfo *info) {
    if (!info || info->pointer_level > 0 || info->ref_kind != REFKIND_NONE || info->is_array) return 0;
    return strcmp(info->base_type, "bool") == 0 ||
           strcmp(info->base_type, "u8") == 0 ||
           strcmp(info->base_type, "u16") == 0 ||
           strcmp(info->base_type, "i32") == 0 ||
           strcmp(info->base_type, "u32") == 0 ||
           strcmp(info->base_type, "char") == 0 ||
           strcmp(info->base_type, "long") == 0 ||
           strcmp(info->base_type, "short") == 0;
}

static int semantic_typeinfo_is_integer_like_or_enum(SemanticContext *ctx, const SemanticTypeInfo *info) {
    if (semantic_typeinfo_is_integer_like(info)) return 1;
    if (!ctx || !info || info->pointer_level > 0 || info->ref_kind != REFKIND_NONE || info->is_array) return 0;
    return semantic_enum_type_exists(ctx, info->base_type);
}

static void semantic_typeinfo_format(const SemanticTypeInfo *info, char *buf, size_t buf_size) {
    size_t used;

    if (!buf || buf_size == 0) return;
    if (!info || !info->base_type || info->base_type[0] == '\0') {
        snprintf(buf, buf_size, "<unknown>");
        return;
    }

    used = 0;
    if (info->ref_kind == REFKIND_SHARED) {
        used += (size_t)snprintf(buf + used, buf_size - used, "ref ");
    } else if (info->ref_kind == REFKIND_MUT) {
        used += (size_t)snprintf(buf + used, buf_size - used, "ref mut ");
    }
    if (used >= buf_size) return;
    used += (size_t)snprintf(buf + used, buf_size - used, "%s", info->base_type);
    for (int i = 0; i < info->pointer_level && used < buf_size; i++) {
        used += (size_t)snprintf(buf + used, buf_size - used, "*");
    }
    for (int i = 0; i < info->dims_count && used < buf_size; i++) {
        if (info->dims[i] > 0) {
            used += (size_t)snprintf(buf + used, buf_size - used, "[%d]", info->dims[i]);
        } else {
            used += (size_t)snprintf(buf + used, buf_size - used, "[]");
        }
    }
}

static int semantic_typeinfo_same_base(const SemanticTypeInfo *a, const SemanticTypeInfo *b) {
    return a && b && a->base_type && b->base_type && strcmp(a->base_type, b->base_type) == 0;
}

static int semantic_typeinfo_compatible(SemanticContext *ctx, const SemanticTypeInfo *expected, const SemanticTypeInfo *actual) {
    if (!expected || !actual) return 0;
    if (semantic_typeinfo_is_integer_like_or_enum(ctx, expected) &&
        semantic_typeinfo_is_integer_like_or_enum(ctx, actual)) return 1;

    if (semantic_typeinfo_same_base(expected, actual) &&
        expected->ref_kind == actual->ref_kind &&
        expected->pointer_level == actual->pointer_level &&
        expected->is_array == actual->is_array &&
        expected->dims_count == actual->dims_count) {
        for (int i = 0; i < expected->dims_count; i++) {
            if (expected->dims[i] > 0 && actual->dims[i] > 0 && expected->dims[i] != actual->dims[i]) return 0;
        }
        return 1;
    }

    if (semantic_typeinfo_same_base(expected, actual) &&
        expected->ref_kind == REFKIND_NONE &&
        actual->ref_kind == REFKIND_NONE) {
        if (expected->pointer_level == actual->pointer_level + 1 && actual->is_array) return 1;
        if (expected->is_array && expected->pointer_level == 0 && actual->pointer_level == 1) return 1;
    }

    if (semantic_typeinfo_same_base(expected, actual) &&
        expected->pointer_level > 0 && actual->ref_kind != REFKIND_NONE &&
        expected->pointer_level == actual->pointer_level + 1) {
        return 1;
    }

    if (semantic_typeinfo_is_integer_like_or_enum(ctx, expected) &&
        (actual->pointer_level > 0 || actual->ref_kind != REFKIND_NONE) &&
        !actual->is_array) {
        return 1;
    }

    return 0;
}

static void semantic_report_type_mismatch(SemanticContext *ctx, SemanticLocation loc,
                                          const char *code,
                                          const char *what,
                                          const SemanticTypeInfo *expected,
                                          const SemanticTypeInfo *actual) {
    char expected_buf[96];
    char actual_buf[96];

    semantic_typeinfo_format(expected, expected_buf, sizeof(expected_buf));
    semantic_typeinfo_format(actual, actual_buf, sizeof(actual_buf));
    semantic_error_code_at(ctx, loc, code, "%s type mismatch: expected %s, got %s",
                           what ? what : "expression", expected_buf, actual_buf);
}

static int expr_is_obviously_value(ASTNode *expr) {
    return expr != NULL;
}

static void check_return_type(SemanticContext *ctx, ASTNode *return_node) {
    ASTNode *fn;
    SemanticTypeInfo expected;
    SemanticTypeInfo actual;

    if (!ctx || !return_node || return_node->type != AST_RETURN) return;
    fn = ctx->current_function;
    if (!fn || fn->type != AST_FUNDEF) return;

    if (!semantic_typeinfo_from_type_ast(fn->fundef.ret_type, &expected)) return;
    if (!expected.base_type || expected.base_type[0] == '\0') return;

    if (semantic_type_is_void(fn->fundef.ret_type)) {
        if (expr_is_obviously_value(return_node->ret.expr)) {
            semantic_error_code_at(ctx, semantic_location_from_ast(return_node),
                                   SEMCODE_RETURN_TYPE_MISMATCH,
                                   "void function '%s' should not return a value", fn->fundef.name);
        }
        return;
    }

    if (!return_node->ret.expr) {
        semantic_error_code_at(ctx, semantic_location_from_ast(return_node),
                               SEMCODE_RETURN_TYPE_MISMATCH,
                               "function '%s' must return a value", fn->fundef.name);
        return;
    }

    if (semantic_infer_expr_type(ctx, return_node->ret.expr, &actual) &&
        !semantic_typeinfo_compatible(ctx, &expected, &actual)) {
        semantic_report_type_mismatch(ctx, semantic_location_from_ast(return_node->ret.expr),
                                      SEMCODE_RETURN_TYPE_MISMATCH,
                                      "return", &expected, &actual);
    }
}

static int semantic_location_is_known(SemanticLocation loc) {
    return loc.line > 0 || loc.col > 0;
}

static void note_binding_decl_if_known(SemanticContext *ctx, SemanticBinding *binding, const char *what) {
    if (!ctx || !binding || !semantic_location_is_known(binding->decl_loc)) return;
    semantic_note_at(ctx, binding->decl_loc, "'%s' declared here%s%s",
                     binding->name,
                     what ? " " : "",
                     what ? what : "");
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
    ASTNode *ident = semantic_as_identifier(expr);

    if (!ctx || !expr) return NULL;
    if (ident) {
        return find_binding(ctx, ident->identifier.name);
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
                    owner->last_mut_borrow_loc = semantic_location_unknown();
                } else if (owner->shared_borrow_count > 0) {
                    owner->shared_borrow_count--;
                    if (owner->shared_borrow_count == 0) {
                        owner->last_shared_borrow_loc = semantic_location_unknown();
                    }
                }
            }
        }
        ctx->binding_count--;
    }
    if (ctx->scope_depth > 0) ctx->scope_depth--;
}

static void declare_binding(SemanticContext *ctx, const char *name, ASTNode *type_node,
                            int is_copy, int is_param, SemanticLocation decl_loc) {
    SemanticBinding *binding;
    SemanticTypeInfo type_info;
    int has_type = semantic_typeinfo_from_type_ast(type_node, &type_info);

    if (!ctx || !name) return;
    binding = find_binding(ctx, name);
    if (binding && binding->scope_depth == ctx->scope_depth) {
        binding->is_copy = is_copy;
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
    binding->moved = 0;
    binding->scope_depth = ctx->scope_depth;
    binding->is_param = is_param;
    binding->is_global = (!is_param && ctx->function_depth == 0);
    binding->has_type = has_type;
    if (has_type) binding->type_info = type_info;
    binding->decl_loc = decl_loc;
    binding->move_loc = semantic_location_unknown();
    binding->borrowed_from = NULL;
    binding->borrow_is_mut = 0;
    binding->shared_borrow_count = 0;
    binding->mutable_borrow_active = 0;
    binding->last_shared_borrow_loc = semantic_location_unknown();
    binding->last_mut_borrow_loc = semantic_location_unknown();
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
            note_binding_decl_if_known(ctx, owner, NULL);
        }
        return;
    }

    if (expr->type == AST_BORROW_MUT) {
        borrowed_expr = expr->borrow_mut.expr;
        owner = borrow_target_binding(ctx, borrowed_expr);
        if (owner && !owner->is_param && !owner->is_global) {
            semantic_error_at(ctx, semantic_location_from_ast(expr),
                              "cannot return reference to local '%s'", owner->name);
            note_binding_decl_if_known(ctx, owner, NULL);
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
        note_binding_decl_if_known(ctx, owner, NULL);
    }
}

static void revive_binding_if_identifier(SemanticContext *ctx, ASTNode *node) {
    SemanticBinding *binding;
    ASTNode *ident = semantic_as_identifier(node);

    if (!ctx || !ident) return;
    binding = find_binding(ctx, ident->identifier.name);
    if (!binding) return;
    binding->moved = 0;
    binding->move_loc = semantic_location_unknown();
}

static void register_borrow_binding(SemanticContext *ctx, ASTNode *binding_node) {
    SemanticBinding *binding;
    SemanticBinding *owner;
    ASTNode *borrowed_expr;
    ASTNode *var_decl = semantic_as_var_decl(binding_node);
    SemanticTypeInfo type_info;
    int is_mut;

    if (!ctx || !var_decl) return;
    if (!semantic_typeinfo_from_type_ast(var_decl->var_decl.var_type, &type_info)) return;
    if (type_info.ref_kind == REFKIND_NONE) return;

    binding = find_binding(ctx, var_decl->var_decl.name);
    if (!binding || !var_decl->var_decl.init) return;

    if (var_decl->var_decl.init->type == AST_BORROW) {
        borrowed_expr = var_decl->var_decl.init->borrow.expr;
        is_mut = 0;
    } else if (var_decl->var_decl.init->type == AST_BORROW_MUT) {
        borrowed_expr = var_decl->var_decl.init->borrow_mut.expr;
        is_mut = 1;
    } else {
        return;
    }

    owner = borrow_target_binding(ctx, borrowed_expr);
    if (!owner) return;

    if (is_mut) {
        if (owner->mutable_borrow_active || owner->shared_borrow_count > 0) {
            semantic_error_at(ctx, semantic_location_from_ast(var_decl->var_decl.init),
                              "cannot mutably borrow '%s' while it is already borrowed", owner->name);
            if (semantic_location_is_known(owner->last_mut_borrow_loc)) {
                semantic_note_at(ctx, owner->last_mut_borrow_loc,
                                 "mutable borrow of '%s' starts here", owner->name);
            } else if (semantic_location_is_known(owner->last_shared_borrow_loc)) {
                semantic_note_at(ctx, owner->last_shared_borrow_loc,
                                 "shared borrow of '%s' starts here", owner->name);
            } else {
                note_binding_decl_if_known(ctx, owner, NULL);
            }
            return;
        }
        owner->mutable_borrow_active = 1;
        owner->last_mut_borrow_loc = semantic_location_from_ast(var_decl->var_decl.init);
    } else {
        if (owner->mutable_borrow_active) {
            semantic_error_at(ctx, semantic_location_from_ast(var_decl->var_decl.init),
                              "cannot borrow '%s' while it is mutably borrowed", owner->name);
            if (semantic_location_is_known(owner->last_mut_borrow_loc)) {
                semantic_note_at(ctx, owner->last_mut_borrow_loc,
                                 "mutable borrow of '%s' starts here", owner->name);
            } else {
                note_binding_decl_if_known(ctx, owner, NULL);
            }
            return;
        }
        owner->shared_borrow_count++;
        owner->last_shared_borrow_loc = semantic_location_from_ast(var_decl->var_decl.init);
    }

    binding->borrowed_from = owner->name;
    binding->borrow_is_mut = is_mut;
}

static void use_identifier(SemanticContext *ctx, ASTNode *node, ExprContext expr_ctx) {
    SemanticBinding *binding;
    ASTNode *ident = semantic_as_identifier(node);

    if (!ctx || !ident) return;
    if (semantic_find_enum_value(ctx, ident->identifier.name, NULL)) {
        if (expr_ctx == EXPRCTX_WRITE) {
            semantic_error_at(ctx, semantic_location_from_ast(node),
                              "cannot assign to enum constant '%s'", ident->identifier.name);
        }
        return;
    }
    binding = find_binding(ctx, ident->identifier.name);
    if (!binding) {
        semantic_error_code_at(ctx, semantic_location_from_ast(node),
                               SEMCODE_UNDEFINED_IDENTIFIER,
                               "undefined identifier '%s'", ident->identifier.name);
        return;
    }

    if (expr_ctx == EXPRCTX_MOVE &&
        (binding->mutable_borrow_active || binding->shared_borrow_count > 0)) {
        semantic_error_at(ctx, semantic_location_from_ast(node),
                          "cannot move '%s' while it is borrowed", ident->identifier.name);
        if (binding->mutable_borrow_active && semantic_location_is_known(binding->last_mut_borrow_loc)) {
            semantic_note_at(ctx, binding->last_mut_borrow_loc,
                             "mutable borrow of '%s' starts here", binding->name);
        } else if (binding->shared_borrow_count > 0 &&
                   semantic_location_is_known(binding->last_shared_borrow_loc)) {
            semantic_note_at(ctx, binding->last_shared_borrow_loc,
                             "shared borrow of '%s' starts here", binding->name);
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

static const char *semantic_binary_op_name(TokenKind op) {
    switch (op) {
    case ADD: return "+";
    case SUB: return "-";
    case ASTARISK: return "*";
    case DIV: return "/";
    case MOD: return "%";
    case LSH: return "<<";
    case RSH: return ">>";
    case LT: return "<";
    case GT: return ">";
    case LTE: return "<=";
    case GTE: return ">=";
    case EQ: return "==";
    case NEQ: return "!=";
    case AMPERSAND: return "&";
    case BITXOR: return "^";
    case BITOR: return "|";
    case LAND: return "&&";
    case LOR: return "||";
    default: return tokenkind2str(op);
    }
}

static void semantic_typeinfo_make_scalar(SemanticTypeInfo *out, const char *base_type) {
    semantic_typeinfo_clear(out);
    out->base_type = base_type;
}

static int semantic_infer_identifier_type(SemanticContext *ctx, ASTNode *expr, SemanticTypeInfo *out) {
    SemanticBinding *binding;
    long enum_value;

    if (!ctx || !expr || expr->type != AST_IDENTIFIER || !out) return 0;
    if (semantic_find_enum_value(ctx, expr->identifier.name, &enum_value)) {
        (void)enum_value;
        semantic_typeinfo_make_scalar(out, "i32");
        return 1;
    }
    binding = find_binding(ctx, expr->identifier.name);
    if (!binding || !binding->has_type) return 0;
    *out = binding->type_info;
    return 1;
}

static int semantic_infer_unary_type(SemanticContext *ctx, ASTNode *expr, SemanticTypeInfo *out) {
    SemanticTypeInfo operand;

    if (!ctx || !expr || expr->type != AST_UNARY || !out) return 0;
    if (!semantic_infer_expr_type(ctx, expr->unary.operand, &operand)) return 0;

    if (expr->unary.op == AMPERSAND) {
        *out = operand;
        out->pointer_level++;
        out->is_array = 0;
        out->dims_count = 0;
        return 1;
    }
    if (expr->unary.op == ASTARISK) {
        if (operand.ref_kind != REFKIND_NONE) {
            *out = operand;
            out->ref_kind = REFKIND_NONE;
            return 1;
        }
        if (operand.pointer_level <= 0) return 0;
        *out = operand;
        out->pointer_level--;
        return 1;
    }

    if (!semantic_typeinfo_is_integer_like_or_enum(ctx, &operand)) return 0;
    *out = operand;
    return 1;
}

static int semantic_binary_is_comparison(TokenKind op) {
    return op == LT || op == GT || op == LTE || op == GTE || op == EQ || op == NEQ;
}

static int semantic_binary_is_logical(TokenKind op) {
    return op == LAND || op == LOR;
}

static int semantic_binary_is_arithmetic(TokenKind op) {
    return op == ADD || op == SUB || op == ASTARISK || op == DIV || op == MOD ||
           op == LSH || op == RSH || op == AMPERSAND || op == BITXOR || op == BITOR;
}

static int semantic_infer_binary_type(SemanticContext *ctx, ASTNode *expr, SemanticTypeInfo *out) {
    SemanticTypeInfo left;
    SemanticTypeInfo right;

    if (!ctx || !expr || expr->type != AST_BINARY || !out) return 0;
    if (!semantic_infer_expr_type(ctx, expr->binary.left, &left)) return 0;
    if (!semantic_infer_expr_type(ctx, expr->binary.right, &right)) return 0;

    if (semantic_binary_is_comparison(expr->binary.op) || semantic_binary_is_logical(expr->binary.op)) {
        semantic_typeinfo_make_scalar(out, "i32");
        return 1;
    }

    if ((expr->binary.op == ADD || expr->binary.op == SUB) &&
        left.pointer_level > 0 && semantic_typeinfo_is_integer_like_or_enum(ctx, &right)) {
        *out = left;
        return 1;
    }
    if ((expr->binary.op == ADD || expr->binary.op == SUB) &&
        left.is_array && semantic_typeinfo_is_integer_like_or_enum(ctx, &right)) {
        *out = left;
        out->is_array = 0;
        out->dims_count = 0;
        out->pointer_level++;
        return 1;
    }
    if (expr->binary.op == ADD &&
        right.pointer_level > 0 && semantic_typeinfo_is_integer_like_or_enum(ctx, &left)) {
        *out = right;
        return 1;
    }
    if (expr->binary.op == ADD &&
        right.is_array && semantic_typeinfo_is_integer_like_or_enum(ctx, &left)) {
        *out = right;
        out->is_array = 0;
        out->dims_count = 0;
        out->pointer_level++;
        return 1;
    }

    if (semantic_binary_is_arithmetic(expr->binary.op) &&
        semantic_typeinfo_is_integer_like_or_enum(ctx, &left) &&
        semantic_typeinfo_is_integer_like_or_enum(ctx, &right)) {
        if (strcmp(left.base_type, "char") == 0 || strcmp(left.base_type, "bool") == 0) {
            semantic_typeinfo_make_scalar(out, "i32");
        } else {
            *out = left;
        }
        return 1;
    }

    return 0;
}

static int semantic_infer_expr_type(SemanticContext *ctx, ASTNode *expr, SemanticTypeInfo *out) {
    SemanticTypeInfo target;

    if (!ctx || !expr || !out) return 0;
    switch (expr->type) {
    case AST_NUMBER:
        semantic_typeinfo_make_scalar(out, "i32");
        return 1;
    case AST_CHAR_LITERAL:
        semantic_typeinfo_make_scalar(out, "char");
        return 1;
    case AST_STRING_LITERAL:
        semantic_typeinfo_make_scalar(out, "char");
        out->is_array = 1;
        out->dims_count = 1;
        return 1;
    case AST_IDENTIFIER:
        return semantic_infer_identifier_type(ctx, expr, out);
    case AST_BORROW:
        if (!semantic_infer_expr_type(ctx, expr->borrow.expr, out)) return 0;
        out->ref_kind = REFKIND_SHARED;
        return 1;
    case AST_BORROW_MUT:
        if (!semantic_infer_expr_type(ctx, expr->borrow_mut.expr, out)) return 0;
        out->ref_kind = REFKIND_MUT;
        return 1;
    case AST_UNARY:
        return semantic_infer_unary_type(ctx, expr, out);
    case AST_CAST:
        return semantic_typeinfo_from_type_ast(expr->cast.type, out);
    case AST_BINARY:
        return semantic_infer_binary_type(ctx, expr, out);
    case AST_ASSIGN:
        return semantic_infer_expr_type(ctx, expr->assign.left, out);
    case AST_TERNARY:
        if (!semantic_infer_expr_type(ctx, expr->ternary.then_expr, out)) return 0;
        if (!semantic_infer_expr_type(ctx, expr->ternary.else_expr, &target)) return 1;
        if (!semantic_typeinfo_compatible(ctx, out, &target)) return 0;
        return 1;
    default:
        return 0;
    }
}

static void check_binary_type(SemanticContext *ctx, ASTNode *node) {
    SemanticTypeInfo left;
    SemanticTypeInfo right;
    char left_buf[96];
    char right_buf[96];

    if (!ctx || !node || node->type != AST_BINARY) return;
    if (!semantic_infer_expr_type(ctx, node->binary.left, &left)) return;
    if (!semantic_infer_expr_type(ctx, node->binary.right, &right)) return;

    if (semantic_binary_is_comparison(node->binary.op) || semantic_binary_is_logical(node->binary.op)) {
        if ((semantic_typeinfo_is_integer_like_or_enum(ctx, &left) || left.pointer_level > 0 || left.ref_kind != REFKIND_NONE) &&
            (semantic_typeinfo_is_integer_like_or_enum(ctx, &right) || right.pointer_level > 0 || right.ref_kind != REFKIND_NONE)) {
            return;
        }
    } else if (semantic_binary_is_arithmetic(node->binary.op)) {
        if (semantic_typeinfo_is_integer_like_or_enum(ctx, &left) && semantic_typeinfo_is_integer_like_or_enum(ctx, &right)) return;
        if ((node->binary.op == ADD || node->binary.op == SUB) &&
            left.pointer_level > 0 && semantic_typeinfo_is_integer_like_or_enum(ctx, &right)) return;
        if ((node->binary.op == ADD || node->binary.op == SUB) &&
            left.is_array && semantic_typeinfo_is_integer_like_or_enum(ctx, &right)) return;
        if (node->binary.op == ADD &&
            right.pointer_level > 0 && semantic_typeinfo_is_integer_like_or_enum(ctx, &left)) return;
        if (node->binary.op == ADD &&
            right.is_array && semantic_typeinfo_is_integer_like_or_enum(ctx, &left)) return;
    }

    semantic_typeinfo_format(&left, left_buf, sizeof(left_buf));
    semantic_typeinfo_format(&right, right_buf, sizeof(right_buf));
    semantic_error_code_at(ctx, semantic_location_from_ast(node),
                           SEMCODE_INVALID_BINARY_OPERANDS,
                           "invalid operands to '%s': %s and %s",
                           semantic_binary_op_name(node->binary.op), left_buf, right_buf);
}

static void check_assignment_type(SemanticContext *ctx, ASTNode *node) {
    SemanticTypeInfo left;
    SemanticTypeInfo right;

    if (!ctx || !node || node->type != AST_ASSIGN) return;
    if (!semantic_infer_expr_type(ctx, node->assign.left, &left)) return;
    if (!semantic_infer_expr_type(ctx, node->assign.right, &right)) return;
    if (semantic_typeinfo_compatible(ctx, &left, &right)) return;
    semantic_report_type_mismatch(ctx, semantic_location_from_ast(node->assign.right),
                                  SEMCODE_ASSIGNMENT_TYPE_MISMATCH,
                                  "assignment", &left, &right);
}

static void check_initializer_type(SemanticContext *ctx, ASTNode *node) {
    SemanticTypeInfo expected;
    SemanticTypeInfo actual;

    if (!ctx || !node || node->type != AST_VAR_DECL || !node->var_decl.init) return;
    if (!semantic_typeinfo_from_type_ast(node->var_decl.var_type, &expected)) return;
    if (!semantic_infer_expr_type(ctx, node->var_decl.init, &actual)) return;
    if (semantic_typeinfo_compatible(ctx, &expected, &actual)) return;
    semantic_report_type_mismatch(ctx, semantic_location_from_ast(node->var_decl.init),
                                  SEMCODE_ASSIGNMENT_TYPE_MISMATCH,
                                  "initializer", &expected, &actual);
}

static void check_condition_type(SemanticContext *ctx, ASTNode *cond) {
    SemanticTypeInfo info;
    char type_buf[96];

    if (!ctx || !cond) return;
    if (!semantic_infer_expr_type(ctx, cond, &info)) return;
    if (semantic_typeinfo_is_integer_like_or_enum(ctx, &info) || info.pointer_level > 0 || info.ref_kind != REFKIND_NONE) return;

    semantic_typeinfo_format(&info, type_buf, sizeof(type_buf));
    semantic_error_code_at(ctx, semantic_location_from_ast(cond),
                           SEMCODE_INVALID_CONDITION_TYPE,
                           "condition must be integer-like, pointer, or reference, got %s", type_buf);
}

static void semantic_walk_expr(SemanticContext *ctx, ASTNode *node, ExprContext expr_ctx);
static void semantic_walk_stmt(SemanticContext *ctx, ASTNode *node);
static void semantic_check_type_exists(SemanticContext *ctx, ASTNode *type_node);

static void check_call_signature(SemanticContext *ctx, ASTNode *node) {
    SemanticFunctionSig *sig;
    int argc;

    if (!ctx || !node || node->type != AST_CALL || !node->call.name) return;
    if (semantic_is_builtin_call(node->call.name)) return;

    sig = find_function_sig(ctx, node->call.name);
    if (!sig) {
        if (call_may_be_package_import(node->call.name)) return;
        semantic_error_code_at(ctx, semantic_location_from_ast(node),
                               SEMCODE_UNDEFINED_FUNCTION,
                               "undefined function '%s'", node->call.name);
        return;
    }

    if (sig->is_imported || sig->param_count < 0) return;

    argc = node->call.arg_count;
    if (sig->is_variadic) {
        if (argc < sig->fixed_param_count) {
            semantic_error_code_at(ctx, semantic_location_from_ast(node),
                                   SEMCODE_ARG_COUNT_MISMATCH,
                                   "function '%s' expects at least %d arguments but got %d",
                                   node->call.name, sig->fixed_param_count, argc);
            if (semantic_location_is_known(sig->decl_loc)) {
                semantic_note_at(ctx, sig->decl_loc, "'%s' declared here", sig->name);
            }
        }
        return;
    }

    if (argc != sig->param_count) {
        semantic_error_code_at(ctx, semantic_location_from_ast(node),
                               SEMCODE_ARG_COUNT_MISMATCH,
                               "function '%s' expects %d arguments but got %d",
                               node->call.name, sig->param_count, argc);
        if (semantic_location_is_known(sig->decl_loc)) {
            semantic_note_at(ctx, sig->decl_loc, "'%s' declared here", sig->name);
        }
    }
}

static void walk_case_items(SemanticContext *ctx, ASTNode *node) {
    for (int i = 0; i < node->case_expr.case_count; i++) {
        semantic_walk_expr(ctx, node->case_expr.cases[i].key, EXPRCTX_READ);
        semantic_walk_expr(ctx, node->case_expr.cases[i].expr, EXPRCTX_READ);
    }
    semantic_walk_expr(ctx, node->case_expr.default_expr, EXPRCTX_READ);
}

static void walk_params(SemanticContext *ctx, ASTNode **params, int param_count) {
    for (int i = 0; i < param_count; i++) {
        ASTNode *param = semantic_as_param(params[i]);
        semantic_walk_stmt(ctx, param);
        if (param) {
            declare_binding(ctx, param->param.name,
                            param->param.type,
                            param->param.is_rest ? 1 : semantic_type_is_copy(ctx, param->param.type), 1,
                            semantic_location_from_ast(param));
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
        check_binary_type(ctx, node);
        break;
    case AST_ASSIGN:
        semantic_walk_expr(ctx, node->assign.right, EXPRCTX_READ);
        semantic_walk_expr(ctx, node->assign.left, EXPRCTX_WRITE);
        check_assignment_type(ctx, node);
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
        check_call_signature(ctx, node);
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
        check_condition_type(ctx, node->ternary.cond);
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
    case AST_ENUM:
    case AST_ENUM_MEMBER:
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
        semantic_check_type_exists(ctx, node);
        break;
    case AST_TYPE_ARRAY:
        semantic_walk_stmt(ctx, node->type_array.element_type);
        break;
    case AST_VAR_DECL:
        semantic_walk_stmt(ctx, node->var_decl.var_type);
        if (node->var_decl.init) {
            semantic_walk_expr(ctx, node->var_decl.init, EXPRCTX_MOVE);
            check_initializer_type(ctx, node);
        }
        is_copy = semantic_type_is_copy(ctx, node->var_decl.var_type);
        declare_binding(ctx, node->var_decl.name, node->var_decl.var_type, is_copy, 0, semantic_location_from_ast(node));
        register_borrow_binding(ctx, node);
        break;
    case AST_EXPR_STMT:
        semantic_walk_expr(ctx, node->expr_stmt.expr, EXPRCTX_READ);
        break;
    case AST_IF:
        semantic_walk_expr(ctx, node->if_stmt.cond, EXPRCTX_READ);
        check_condition_type(ctx, node->if_stmt.cond);
        semantic_walk_stmt(ctx, node->if_stmt.then_stmt);
        semantic_walk_stmt(ctx, node->if_stmt.else_stmt);
        break;
    case AST_RETURN:
        check_return_type(ctx, node);
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
    {
        ASTNode *prev_function = ctx->current_function;
        ctx->current_function = node;
        ctx->function_depth++;
        enter_scope(ctx);
        semantic_walk_stmt(ctx, node->fundef.ret_type);
        walk_params(ctx, node->fundef.params, node->fundef.param_count);
        semantic_walk_stmt(ctx, node->fundef.body);
        leave_scope(ctx);
        ctx->function_depth--;
        ctx->current_function = prev_function;
        break;
    }
    case AST_PARAM:
        semantic_walk_stmt(ctx, node->param.type);
        break;
    case AST_WHILE:
        semantic_walk_expr(ctx, node->while_stmt.cond, EXPRCTX_READ);
        check_condition_type(ctx, node->while_stmt.cond);
        semantic_walk_stmt(ctx, node->while_stmt.body);
        break;
    case AST_FOR:
        enter_scope(ctx);
        semantic_walk_stmt(ctx, node->for_stmt.init);
        semantic_walk_expr(ctx, node->for_stmt.cond, EXPRCTX_READ);
        check_condition_type(ctx, node->for_stmt.cond);
        semantic_walk_stmt(ctx, node->for_stmt.inc);
        semantic_walk_stmt(ctx, node->for_stmt.body);
        leave_scope(ctx);
        break;
    case AST_TYPEDEF:
        semantic_walk_stmt(ctx, node->typedef_stmt.src_type);
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
        check_condition_type(ctx, node->do_while_stmt.cond);
        break;
    default:
        semantic_error_at(ctx, semantic_location_from_ast(node),
                          "semantic walker encountered unknown AST node type %d", node->type);
        break;
    }
}

static void semantic_register_user_type(SemanticContext *ctx, const char *name) {
    if (!ctx || !name) return;
    if (ctx->user_type_count < (int)(sizeof(ctx->user_types) / sizeof(ctx->user_types[0]))) {
        ctx->user_types[ctx->user_type_count++] = name;
    }
}

static void semantic_collect_user_types(SemanticContext *ctx, ASTNode *node) {
    if (!ctx || !node) return;
    if (node->type == AST_BLOCK) {
        for (int i = 0; i < node->block.count; i++) {
            semantic_collect_user_types(ctx, node->block.stmts[i]);
        }
    } else if (node->type == AST_STRUCT && node->struct_stmt.name) {
        semantic_register_user_type(ctx, node->struct_stmt.name);
    } else if (node->type == AST_TYPEDEF_STRUCT && node->typedef_struct.typedef_name) {
        semantic_register_user_type(ctx, node->typedef_struct.typedef_name);
    } else if (node->type == AST_TYPEDEF && node->typedef_stmt.alias) {
        semantic_register_user_type(ctx, node->typedef_stmt.alias);
    }
}

static void semantic_check_type_exists(SemanticContext *ctx, ASTNode *type_node) {
    if (!ctx || !type_node) return;
    SemanticTypeInfo info;
    if (!semantic_typeinfo_from_type_ast(type_node, &info)) return;

    const char *base_type = info.base_type;
    if (!base_type || base_type[0] == '\0') return;

    if (semantic_enum_type_exists(ctx, base_type)) return;

    for (int i = 0; i < ctx->user_type_count; i++) {
        if (strcmp(ctx->user_types[i], base_type) == 0) return;
    }

    if (semantic_is_builtin_type(base_type)) {
        return;
    }

    if (strcmp(base_type, "rest") == 0) return; // For variadic params

    semantic_error_at(ctx, semantic_location_from_ast(type_node), "unknown type '%s'", base_type);
}

void semantic_walk_ast(SemanticContext *ctx, ASTNode *node) {
    semantic_collect_user_types(ctx, node);
    semantic_collect_function_sigs(ctx, node);
    semantic_walk_stmt(ctx, node);
}
