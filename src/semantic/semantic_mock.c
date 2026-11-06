#include "mylang/semantic/semantic_internal.h"
#include "mylang/semantic/diagnostic_codes.h"

/* The compiler-owned mock facade: the calls it is lowered to are checked here
 * as intrinsics, against the signature of the target they stand in for. */

static int semantic_typeinfo_exact(const SemanticTypeInfo *left,
                                   const SemanticTypeInfo *right) {
    if (!left || !right || !left->base_type || !right->base_type ||
        strcmp(left->base_type, right->base_type) != 0 ||
        left->borrow_kind != right->borrow_kind ||
        left->pointer_level != right->pointer_level ||
        left->is_array != right->is_array ||
        left->dims_count != right->dims_count) {
        return 0;
    }
    for (int i = 0; i < left->dims_count; i++) {
        if (left->dims[i] != right->dims[i]) return 0;
    }
    return 1;
}

static ASTNode *unwrap_mock_target_cast(ASTNode *expr) {
    while (expr && expr->type == AST_CAST) expr = expr->cast.expr;
    return expr;
}

static ASTNode *mock_rule_target_expr(ASTNode *call, const char *rule_name) {
    ASTNode *when;
    ASTNode *factory;
    if (!call || call->type != AST_CALL || !rule_name ||
        !call->call.name || strcmp(call->call.name, rule_name) != 0 ||
        call->call.arg_count != 2) return NULL;
    when = call->call.args[0];
    if (!when || when->type != AST_CALL ||
        !when->call.name || strcmp(when->call.name, "TargetMock__when") != 0 ||
        when->call.arg_count < 1) return NULL;
    factory = when->call.args[0];
    if (!factory || factory->type != AST_CALL || !factory->call.name ||
        (strcmp(factory->call.name, "mock_target") != 0 &&
         strcmp(factory->call.name, "mock_spy") != 0) ||
        factory->call.arg_count != 1) return NULL;
    return unwrap_mock_target_cast(factory->call.args[0]);
}

static ASTNode *mock_callback_target_expr(ASTNode *call) {
    return mock_rule_target_expr(call, "TargetRule__call");
}

int semantic_mock_return_uses_hidden_buffer(SemanticContext *ctx,
                                            const SemanticTypeInfo *type) {
    if (!ctx || !type) return 0;
    if (type->pointer_level > 0 || type->borrow_kind != REFKIND_NONE) return 0;
    if (type->is_array) return 1;
    // Payload enums are lowered to a struct before semantic/codegen, so the
    // struct table is also the authoritative answer for local Result<T, E>.
    if (type->base_type && semantic_struct_is_known(ctx, type->base_type)) return 1;
    // Imported function signatures do not copy every foreign struct layout
    // into the semantic context. A non-builtin, non-enum value type there is
    // nevertheless a by-value aggregate in the ABI (the common case is an
    // imported Result<T, E>), so reject a stored word return conservatively.
    return type->base_type && !semantic_is_builtin_type(type->base_type) &&
           !semantic_enum_type_exists(ctx, type->base_type);
}

void semantic_check_mock_stored_return(SemanticContext *ctx, ASTNode *call) {
    ASTNode *target_expr;
    SemanticFunctionSig *target;

    if (!ctx || !call) return;
    target_expr = mock_rule_target_expr(call, call->call.name);
    if (!target_expr || target_expr->type != AST_IDENTIFIER) return;
    target = semantic_find_function_sig(ctx, target_expr->identifier.name);
    if (!target || !target->has_return_type) return;
    if (target->return_type.base_type &&
        strcmp(target->return_type.base_type, "void") == 0 &&
        target->return_type.pointer_level == 0) {
        semantic_error_code_at(ctx, semantic_location_from_ast(call),
                               SEMCODE_MOCK_ABI_LIMIT,
                               "mock .ret(...) cannot configure void target '%s'; use .call(fake)",
                               target_expr->identifier.name);
        return;
    }
    if (!semantic_mock_return_uses_hidden_buffer(ctx, &target->return_type)) return;

    semantic_error_code_at(ctx, semantic_location_from_ast(call),
                           SEMCODE_MOCK_AGGREGATE_STORED_RETURN,
                           "mock .ret(...) cannot return aggregate target '%s'; use .call(fake)",
                           target_expr->identifier.name);
}

void semantic_check_mock_abi_limit(SemanticContext *ctx, ASTNode *call) {
    if (!ctx || !call || !call->call.name) return;
    if (strcmp(call->call.name, "TargetMock__when") == 0 &&
        call->call.arg_count - 1 > 6) {
        semantic_error_code_at(ctx, semantic_location_from_ast(call),
                               SEMCODE_MOCK_ABI_LIMIT,
                               "mock .when(...) supports at most six arguments");
    } else if (strcmp(call->call.name, "mock_call_original") == 0 &&
               call->call.arg_count > 6) {
        semantic_error_code_at(ctx, semantic_location_from_ast(call),
                               SEMCODE_MOCK_ABI_LIMIT,
                               "mock.call_original(...) supports at most six arguments");
    }
}

void semantic_check_mock_callback_signature(SemanticContext *ctx, ASTNode *call) {
    ASTNode *target_expr;
    ASTNode *fake_expr;
    SemanticFunctionSig *target;
    SemanticFunctionSig *fake;
    const char *target_name;
    const char *fake_name;

    if (!ctx || !call) return;
    target_expr = mock_callback_target_expr(call);
    fake_expr = call->call.arg_count == 2 ? call->call.args[1] : NULL;
    if (!target_expr || target_expr->type != AST_IDENTIFIER ||
        !fake_expr || fake_expr->type != AST_IDENTIFIER) {
        semantic_error_code_at(ctx, semantic_location_from_ast(call),
                               SEMCODE_MOCK_CALLBACK_SIGNATURE_MISMATCH,
                               "mock .call(...) requires a direct target and fake function name");
        return;
    }

    target_name = target_expr->identifier.name;
    fake_name = fake_expr->identifier.name;
    target = semantic_find_function_sig(ctx, target_name);
    fake = semantic_find_function_sig(ctx, fake_name);
    if (!target || !fake || !target->has_return_type || !fake->has_return_type ||
        !target->has_param_types || !fake->has_param_types) {
        semantic_error_code_at(ctx, semantic_location_from_ast(fake_expr),
                               SEMCODE_MOCK_CALLBACK_SIGNATURE_MISMATCH,
                               "cannot determine the complete signature for mock target '%s' or fake '%s'",
                               target_name ? target_name : "<target>",
                               fake_name ? fake_name : "<fake>");
        return;
    }
    if (target->is_variadic || fake->is_variadic) {
        semantic_error_code_at(ctx, semantic_location_from_ast(fake_expr),
                               SEMCODE_MOCK_CALLBACK_SIGNATURE_MISMATCH,
                               "mock .call(...) does not support variadic target or fake functions");
        return;
    }
    if (target->param_count != fake->param_count) {
        semantic_error_code_at(ctx, semantic_location_from_ast(fake_expr),
                               SEMCODE_MOCK_CALLBACK_SIGNATURE_MISMATCH,
                               "mock fake '%s' has %d parameters but target '%s' has %d",
                               fake_name, fake->param_count, target_name, target->param_count);
        return;
    }
    for (int i = 0; i < target->param_count; i++) {
        if (semantic_typeinfo_exact(&target->param_types[i], &fake->param_types[i])) continue;
        semantic_error_code_at(ctx, semantic_location_from_ast(fake_expr),
                               SEMCODE_MOCK_CALLBACK_SIGNATURE_MISMATCH,
                               "mock fake '%s' parameter %d does not match target '%s'",
                               fake_name, i + 1, target_name);
        return;
    }
    if (!semantic_typeinfo_exact(&target->return_type, &fake->return_type)) {
        semantic_error_code_at(ctx, semantic_location_from_ast(fake_expr),
                               SEMCODE_MOCK_CALLBACK_SIGNATURE_MISMATCH,
                               "mock fake '%s' return type does not match target '%s'",
                               fake_name, target_name);
    }
}

int semantic_is_mock_call_original_expr(ASTNode *expr) {
    return expr && expr->type == AST_CALL && expr->call.name &&
           strcmp(expr->call.name, "mock_call_original") == 0;
}
