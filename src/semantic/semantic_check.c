#include "mylang/semantic/semantic_internal.h"
#include "mylang/semantic/diagnostic_codes.h"

/* Type checks of single constructs: operands, assignments, initializers,
 * conditions, struct literals, calls and returns. */

static int expr_is_obviously_value(ASTNode *expr) {
    return expr != NULL;
}

void semantic_check_return_type(SemanticContext *ctx, ASTNode *return_node) {
    ASTNode *fn;
    SemanticTypeInfo expected;
    SemanticTypeInfo actual;

    if (!ctx || !return_node || return_node->type != AST_RETURN) return;
    fn = ctx->current_function;
    if (!fn || fn->type != AST_FUNDEF) return;

    if (fn->fundef.is_noreturn) {
        semantic_error_code_at(ctx, semantic_location_from_ast(return_node),
                               SEMCODE_NORETURN_RETURNS,
                               "@noreturn function '%s' cannot return", fn->fundef.name);
        return;
    }

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

    // `mock.call_original(...)` is a compiler-recognized forwarding form
    // when it is returned directly from an aggregate fake. Its public facade
    // declaration is word-returning for scalar targets, but codegen forwards
    // this function's hidden result buffer to the active original target.
    if (semantic_mock_return_uses_hidden_buffer(ctx, &expected) &&
        semantic_is_mock_call_original_expr(return_node->ret.expr)) {
        return;
    }

    if (!semantic_infer_expr_type(ctx, return_node->ret.expr, &actual)) return;
    semantic_check_borrow_kept_as_pointer(ctx, &expected, &actual, return_node->ret.expr);
    if (!semantic_typeinfo_compatible(ctx, &expected, &actual) &&
        !semantic_null_function_literal(&expected, return_node->ret.expr) &&
        !semantic_literal_to_legacy_c_string(&expected, &actual,
                                             return_node->ret.expr)) {
        semantic_report_type_mismatch(ctx, semantic_location_from_ast(return_node->ret.expr),
                                      SEMCODE_RETURN_TYPE_MISMATCH,
                                      "return", &expected, &actual);
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

void semantic_check_binary_type(SemanticContext *ctx, ASTNode *node) {
    SemanticTypeInfo left;
    SemanticTypeInfo right;
    char left_buf[96];
    char right_buf[96];

    if (!ctx || !node || node->type != AST_BINARY) return;
    if (!semantic_infer_expr_type(ctx, node->binary.left, &left)) return;
    if (!semantic_infer_expr_type(ctx, node->binary.right, &right)) return;

    if ((node->binary.op == EQ || node->binary.op == NEQ) &&
        semantic_typeinfo_same_base(&left, &right) &&
        strcmp(left.base_type, "str") == 0 &&
        left.pointer_level == 0 && right.pointer_level == 0 &&
        !left.is_array && !right.is_array) {
        return;
    }
    if (semantic_binary_is_comparison(node->binary.op) || semantic_binary_is_logical(node->binary.op)) {
        if ((node->binary.op == EQ || node->binary.op == NEQ) &&
            ((left.is_function && semantic_null_function_literal(&left, node->binary.right)) ||
             (right.is_function && semantic_null_function_literal(&right, node->binary.left)))) return;
        if ((node->binary.op == EQ || node->binary.op == NEQ) &&
            semantic_find_newtype(ctx, left.base_type) &&
            semantic_typeinfo_compatible(ctx, &left, &right)) return;
        if ((semantic_typeinfo_is_integer_like_or_enum(ctx, &left) || left.pointer_level > 0 || left.borrow_kind != REFKIND_NONE) &&
            (semantic_typeinfo_is_integer_like_or_enum(ctx, &right) || right.pointer_level > 0 || right.borrow_kind != REFKIND_NONE)) {
            return;
        }
    } else if (semantic_binary_is_arithmetic(node->binary.op)) {
        /* A pointer-like operand is a raw pointer (`*`), an array (decays to a
         * pointer), or a reference (`borrow`): all support pointer +/-
         * integer arithmetic. */
        int left_ptrish = left.pointer_level > 0 || left.is_array || left.borrow_kind != REFKIND_NONE;
        int right_ptrish = right.pointer_level > 0 || right.is_array || right.borrow_kind != REFKIND_NONE;
        if (semantic_typeinfo_is_integer_like_or_enum(ctx, &left) && semantic_typeinfo_is_integer_like_or_enum(ctx, &right)) return;
        if ((node->binary.op == ADD || node->binary.op == SUB) &&
            left_ptrish && semantic_typeinfo_is_integer_like_or_enum(ctx, &right)) return;
        if (node->binary.op == ADD &&
            right_ptrish && semantic_typeinfo_is_integer_like_or_enum(ctx, &left)) return;
    }

    semantic_typeinfo_format(&left, left_buf, sizeof(left_buf));
    semantic_typeinfo_format(&right, right_buf, sizeof(right_buf));
    semantic_error_code_at(ctx, semantic_location_from_ast(node),
                           SEMCODE_INVALID_BINARY_OPERANDS,
                           "invalid operands to '%s': %s and %s",
                           semantic_binary_op_name(node->binary.op), left_buf, right_buf);
}

void semantic_check_assignment_type(SemanticContext *ctx, ASTNode *node) {
    SemanticTypeInfo left;
    SemanticTypeInfo right;

    if (!ctx || !node || node->type != AST_ASSIGN) return;
    if (!semantic_infer_expr_type(ctx, node->assign.left, &left)) return;
    if (!semantic_infer_expr_type(ctx, node->assign.right, &right)) return;
    semantic_check_borrow_kept_as_pointer(ctx, &left, &right, node->assign.right);
    if (semantic_typeinfo_compatible(ctx, &left, &right) ||
        semantic_null_function_literal(&left, node->assign.right) ||
        semantic_literal_to_legacy_c_string(&left, &right, node->assign.right)) return;
    semantic_report_type_mismatch(ctx, semantic_location_from_ast(node->assign.right),
                                  SEMCODE_ASSIGNMENT_TYPE_MISMATCH,
                                  "assignment", &left, &right);
}

void semantic_check_initializer_type(SemanticContext *ctx, ASTNode *node) {
    SemanticTypeInfo expected;
    SemanticTypeInfo actual;

    if (!ctx || !node || node->type != AST_VAR_DECL || !node->var_decl.init) return;
    if (!semantic_typeinfo_from_type_ast(node->var_decl.var_type, &expected)) return;
    if (expected.is_array && node->var_decl.init->type == AST_INIT_LIST) {
        /* Array lists are flat, including multidimensional arrays. */
        long capacity = 1;
        for (int i = 0; i < expected.dims_count; i++) {
            if (expected.dims[i] <= 0) { capacity = 0; break; }
            if (capacity > node->var_decl.init->init_list.count) break;
            capacity *= expected.dims[i];
        }
        if (capacity > 0 && node->var_decl.init->init_list.count > capacity) {
            semantic_error_at(ctx, semantic_location_from_ast(node->var_decl.init),
                              "too many elements in array initializer (capacity %ld)", capacity);
        }
    }
    if (!semantic_infer_expr_type(ctx, node->var_decl.init, &actual)) return;
    semantic_check_borrow_kept_as_pointer(ctx, &expected, &actual, node->var_decl.init);
    if (semantic_typeinfo_compatible(ctx, &expected, &actual) ||
        semantic_null_function_literal(&expected, node->var_decl.init) ||
        semantic_literal_to_legacy_c_string(&expected, &actual, node->var_decl.init)) return;
    semantic_report_type_mismatch(ctx, semantic_location_from_ast(node->var_decl.init),
                                  SEMCODE_ASSIGNMENT_TYPE_MISMATCH,
                                  "initializer", &expected, &actual);
}

void semantic_check_condition_type(SemanticContext *ctx, ASTNode *cond) {
    SemanticTypeInfo info;
    char type_buf[96];

    if (!ctx || !cond) return;
    if (!semantic_infer_expr_type(ctx, cond, &info)) return;
    if (semantic_typeinfo_is_integer_like_or_enum(ctx, &info) || info.pointer_level > 0 || info.borrow_kind != REFKIND_NONE) return;

    semantic_typeinfo_format(&info, type_buf, sizeof(type_buf));
    semantic_error_code_at(ctx, semantic_location_from_ast(cond),
                           SEMCODE_INVALID_CONDITION_TYPE,
                           "condition must be integer-like, pointer, or reference, got %s", type_buf);
}

void semantic_check_struct_literal(SemanticContext *ctx, ASTNode *node) {
    if (!ctx || !node || node->type != AST_INIT_LIST ||
        !node->init_list.struct_type_name) return;

    const char *type_name = node->init_list.struct_type_name;
    if (!semantic_struct_is_known(ctx, type_name)) {
        semantic_error_at(ctx, semantic_location_from_ast(node),
                          "unknown struct type '%s' in literal", type_name);
        return;
    }

    for (int i = 0; i < node->init_list.count; i++) {
        const char *field_name = node->init_list.field_names
            ? node->init_list.field_names[i] : NULL;
        const SemanticStructMember *member =
            semantic_find_struct_member(ctx, type_name, field_name);
        if (!member) {
            semantic_error_at(ctx, semantic_location_from_ast(node->init_list.elements[i]),
                              "'%s' has no member named '%s'", type_name,
                              field_name ? field_name : "");
            continue;
        }
        for (int j = 0; j < i; j++) {
            if (strcmp(node->init_list.field_names[j], field_name) == 0) {
                semantic_error_at(ctx, semantic_location_from_ast(node->init_list.elements[i]),
                                  "struct literal for '%s' sets '%s' more than once",
                                  type_name, field_name);
                break;
            }
        }
        SemanticTypeInfo actual;
        if (!semantic_infer_expr_type(ctx, node->init_list.elements[i], &actual)) continue;
        semantic_check_borrow_kept_as_pointer(ctx, &member->type, &actual, node->init_list.elements[i]);
        if (!semantic_typeinfo_compatible(ctx, &member->type, &actual) &&
            !semantic_null_function_literal(&member->type, node->init_list.elements[i]) &&
            !semantic_literal_to_legacy_c_string(&member->type, &actual,
                                                 node->init_list.elements[i])) {
            semantic_report_type_mismatch(ctx,
                                          semantic_location_from_ast(node->init_list.elements[i]),
                                          SEMCODE_ASSIGNMENT_TYPE_MISMATCH,
                                          "struct literal field", &member->type, &actual);
        }
    }
}

void semantic_check_call_signature(SemanticContext *ctx, ASTNode *node) {
    SemanticFunctionSig *sig;
    int argc;
    int fixed_to_check;

    if (!ctx || !node || node->type != AST_CALL || !node->call.name) return;
    if (semantic_is_builtin_call(node->call.name)) return;
    {
        SemanticNewtype *newtype = semantic_find_newtype(ctx, node->call.name);
        if (newtype) {
            if (node->call.arg_count != 1) {
                semantic_error_code_at(ctx, semantic_location_from_ast(node),
                                       SEMCODE_ARG_COUNT_MISMATCH,
                                       "newtype constructor '%s' expects 1 argument but got %d",
                                       node->call.name, node->call.arg_count);
                return;
            }
            SemanticTypeInfo expected, actual;
            if (semantic_typeinfo_from_type_ast(newtype->base_type, &expected) &&
                semantic_infer_expr_type(ctx, node->call.args[0], &actual) &&
                !semantic_typeinfo_compatible(ctx, &expected, &actual)) {
                semantic_report_type_mismatch(ctx,
                    semantic_location_from_ast(node->call.args[0]),
                    SEMCODE_ARG_TYPE_MISMATCH, "newtype constructor", &expected, &actual);
            }
            return;
        }
    }
    // The parser lowers the public mock facade chain to these imported
    // receiver-method symbols. Their declarations are carried by the module
    // resolver for codegen, while semantic analysis intentionally treats the
    // compiler-owned fluent surface as an intrinsic.
    if (strcmp(node->call.name, "TargetRule__call") == 0) {
        semantic_check_mock_callback_signature(ctx, node);
        return;
    }
    if (strcmp(node->call.name, "TargetMock__when") == 0 ||
        strcmp(node->call.name, "TargetRule__ret") == 0 ||
        strcmp(node->call.name, "TargetRule__then_ret") == 0) {
        semantic_check_mock_abi_limit(ctx, node);
        if (strcmp(node->call.name, "TargetRule__ret") == 0 ||
            strcmp(node->call.name, "TargetRule__then_ret") == 0) {
            semantic_check_mock_stored_return(ctx, node);
        }
        return;
    }
    if (strcmp(node->call.name, "mock_call_original") == 0) {
        semantic_check_mock_abi_limit(ctx, node);
        return;
    }

    sig = semantic_find_function_sig(ctx, node->call.name);
    if (sig) semantic_check_unsafe_call(ctx, node, sig);
    if (!sig) {
        if (semantic_call_may_be_package_import(ctx, node->call.name)) return;
        SemanticBinding *callee = semantic_find_binding(ctx, node->call.name);
        if (callee) {
            ASTNode **params = NULL;
            ASTNode *return_type = NULL;
            int param_count = 0, is_variadic = 0;
            int form = callee->has_type
                ? semantic_function_type_parts(&callee->type_info, &params, &param_count,
                                      &return_type, &is_variadic)
                : 0;
            if (!form) {
                semantic_error_at(ctx, semantic_location_from_ast(node),
                                  "'%s' is not callable; expected a fn(...) -> ... value",
                                  node->call.name);
                return;
            }
            int argc = node->call.arg_count;
            if ((!is_variadic && argc != param_count) ||
                (is_variadic && argc < param_count)) {
                semantic_error_code_at(ctx, semantic_location_from_ast(node),
                                       SEMCODE_ARG_COUNT_MISMATCH,
                                       "function value '%s' expects %s%d arguments but got %d",
                                       node->call.name, is_variadic ? "at least " : "",
                                       param_count, argc);
            }
            int checked = argc < param_count ? argc : param_count;
            for (int i = 0; i < checked; i++) {
                SemanticTypeInfo expected, actual;
                if (!semantic_typeinfo_from_type_ast(semantic_function_param_type(params[i], form), &expected) ||
                    !semantic_infer_expr_type(ctx, node->call.args[i], &actual)) continue;
                if (!semantic_call_arg_compatible(ctx, &expected, &actual)) {
                    semantic_report_type_mismatch(ctx,
                        semantic_location_from_ast(node->call.args[i]),
                        SEMCODE_ARG_TYPE_MISMATCH, "function argument", &expected, &actual);
                }
            }
            return;
        }
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
    } else if (argc != sig->param_count) {
        semantic_error_code_at(ctx, semantic_location_from_ast(node),
                               SEMCODE_ARG_COUNT_MISMATCH,
                               "function '%s' expects %d arguments but got %d",
                               node->call.name, sig->param_count, argc);
        if (semantic_location_is_known(sig->decl_loc)) {
            semantic_note_at(ctx, sig->decl_loc, "'%s' declared here", sig->name);
        }
    }

    if (!sig->has_param_types) return;
    fixed_to_check = sig->fixed_param_count;
    if (fixed_to_check > argc) fixed_to_check = argc;
    if (fixed_to_check > SEMANTIC_MAX_FUNCTION_PARAMS) fixed_to_check = SEMANTIC_MAX_FUNCTION_PARAMS;

    for (int i = 0; i < fixed_to_check; i++) {
        SemanticTypeInfo actual;
        char expected_buf[96];
        char actual_buf[96];

        if (!semantic_infer_expr_type(ctx, node->call.args[i], &actual)) continue;
        if (semantic_call_arg_compatible(ctx, &sig->param_types[i], &actual) ||
            semantic_null_function_literal(&sig->param_types[i], node->call.args[i]) ||
            semantic_default_of_newtype(&sig->param_types[i], node->call.args[i]) ||
            semantic_literal_to_legacy_c_string(&sig->param_types[i], &actual,
                                                node->call.args[i])) continue;

        semantic_typeinfo_format(&sig->param_types[i], expected_buf, sizeof(expected_buf));
        semantic_typeinfo_format(&actual, actual_buf, sizeof(actual_buf));
        semantic_error_code_at(ctx, semantic_location_from_ast(node->call.args[i]),
                               SEMCODE_ARG_TYPE_MISMATCH,
                               "function argument type mismatch: parameter %d of '%s' expected %s, got %s",
                               i + 1, node->call.name, expected_buf, actual_buf);
        if (semantic_location_is_known(sig->decl_loc)) {
            semantic_note_at(ctx, sig->decl_loc, "'%s' declared here", sig->name);
        }
    }
}

/* `a[3]` on a fixed-size array is checked here. A computed index is
 * checked when the program runs: codegen emits a trap (codegen_trap.c). */
void semantic_check_constant_index(SemanticContext *ctx, ASTNode *node) {
    if (!node || node->type != AST_UNARY || node->unary.op != ASTARISK) return;
    ASTNode *add = node->unary.operand;
    if (!add || add->type != AST_BINARY || !add->binary.subscript) return;
    ASTNode *index = add->binary.right;
    long value = 0;
    if (index && index->type == AST_NUMBER && index->number.value) {
        value = strtol(index->number.value, NULL, 10);
    } else if (index && index->type == AST_UNARY && index->unary.op == SUB &&
               index->unary.operand && index->unary.operand->type == AST_NUMBER &&
               index->unary.operand->number.value) {
        value = -strtol(index->unary.operand->number.value, NULL, 10);
    } else {
        return;
    }
    SemanticTypeInfo type;
    if (!semantic_infer_expr_type(ctx, add->binary.left, &type)) return;
    if (!type.is_array || type.pointer_level > 0 || type.dims_count <= 0 || type.dims[0] <= 0) return;
    if (value >= 0 && value < type.dims[0]) return;
    semantic_error_code_at(ctx, semantic_location_from_ast(index), SEMCODE_INDEX_OUT_OF_RANGE,
                           "index %ld is out of range for an array of %d elements",
                           value, type.dims[0]);
}

/* `*x` needs an address: a borrow, a pointer or an array. `a[i]` is `*(a + i)`. */
void semantic_check_dereference(SemanticContext *ctx, ASTNode *node) {
    if (node->type == AST_UNARY && node->unary.op != ASTARISK) return;
    ASTNode *operand = node->type == AST_UNARY ? node->unary.operand : node->arrow_access.lhs;
    SemanticTypeInfo type;
    if (!operand || operand->type == AST_BINARY || !semantic_infer_expr_type(ctx, operand, &type)) return;
    if (type.pointer_level > 0 || type.borrow_kind != REFKIND_NONE || type.is_array || type.is_function) return;
    char shown[128];
    semantic_typeinfo_format(&type, shown, sizeof(shown));
    semantic_error_code_at(ctx, semantic_location_from_ast(node), SEMCODE_INVALID_DEREFERENCE,
                           "cannot dereference a value of type '%s'", shown);
}
