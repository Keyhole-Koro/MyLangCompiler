#include "mylang/semantic/semantic_internal.h"

/* The type of an expression, where it can be told. */

static void semantic_typeinfo_make_scalar(SemanticTypeInfo *out, const char *base_type) {
    semantic_typeinfo_clear(out);
    out->base_type = base_type;
}

static int semantic_infer_identifier_type(SemanticContext *ctx, ASTNode *expr, SemanticTypeInfo *out) {
    SemanticBinding *binding;
    long enum_value;

    if (!ctx || !expr || expr->type != AST_IDENTIFIER || !out) return 0;
    if (strcmp(expr->identifier.name, "_") == 0) {
        semantic_typeinfo_make_scalar(out, "_");
        return 1;
    }
    if (semantic_find_enum_value(ctx, expr->identifier.name, &enum_value)) {
        (void)enum_value;
        semantic_typeinfo_make_scalar(out, "i32");
        return 1;
    }
    /* A local or parameter shadows a function of the same name. */
    binding = semantic_find_binding(ctx, expr->identifier.name);
    if (binding && binding->has_type) {
        *out = binding->type_info;
        return 1;
    }
    SemanticFunctionSig *function = semantic_find_function_sig(ctx, expr->identifier.name);
    if (function && function->declaration) {
        semantic_typeinfo_clear(out);
        out->base_type = "fn";
        out->is_function = 1;
        out->function_decl = function->declaration;
        return 1;
    }
    if (function) {
        semantic_typeinfo_make_scalar(out, "i32");
        return 1;
    }
    if (semantic_call_may_be_package_import(ctx, expr->identifier.name)) {
        semantic_typeinfo_make_scalar(out, "i32");
        return 1;
    }
    return 0;
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
        if (operand.borrow_kind != BORROWKIND_NONE) {
            *out = operand;
            out->borrow_kind = BORROWKIND_NONE;
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

int semantic_binary_is_comparison(TokenKind op) {
    return op == LT || op == GT || op == LTE || op == GTE || op == EQ || op == NEQ;
}

int semantic_binary_is_logical(TokenKind op) {
    return op == LAND || op == LOR;
}

int semantic_binary_is_arithmetic(TokenKind op) {
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
        semantic_typeinfo_make_scalar(out, "bool");
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

int semantic_infer_expr_type(SemanticContext *ctx, ASTNode *expr, SemanticTypeInfo *out) {
    SemanticTypeInfo target;
    SemanticFunctionSig *sig;

    if (!ctx || !expr || !out) return 0;
    switch (expr->type) {
    case AST_MEMBER_ACCESS:
    case AST_ARROW_ACCESS: {
        /* `p.a` is the type the struct gives `a`. Inferring it is what lets the
         * assignment and initializer checks apply to fields at all; without it
         * they returned early and a field took anything. */
        ASTNode *lhs = expr->type == AST_MEMBER_ACCESS ? expr->member_access.lhs
                                                       : expr->arrow_access.lhs;
        const char *field = expr->type == AST_MEMBER_ACCESS ? expr->member_access.member
                                                            : expr->arrow_access.member;
        if (!semantic_infer_expr_type(ctx, lhs, &target)) return 0;
        /* `a.length` on a fixed-size array is its element count (i32). */
        if (expr->type == AST_MEMBER_ACCESS && target.is_array && target.dims_count > 0 &&
            field && strcmp(field, "length") == 0) {
            semantic_typeinfo_make_scalar(out, "i32");
            return 1;
        }
        if (!target.base_type || !semantic_struct_is_known(ctx, target.base_type)) return 0;

        const SemanticStructMember *member =
            semantic_find_struct_member(ctx, target.base_type, field);
        if (!member) {
            semantic_error_at(ctx, semantic_location_from_ast(expr),
                              "'%s' has no member named '%s'", target.base_type, field);
            return 0;
        }
        *out = member->type;
        return 1;
    }
    case AST_NUMBER:
        semantic_typeinfo_make_scalar(out, "i32");
        return 1;
    case AST_CHAR_LITERAL:
        semantic_typeinfo_make_scalar(out, "char");
        return 1;
    case AST_STRING_LITERAL:
        semantic_typeinfo_make_scalar(out, "str");
        return 1;
    case AST_IDENTIFIER:
        return semantic_infer_identifier_type(ctx, expr, out);
    case AST_BORROW:
        if (!semantic_infer_expr_type(ctx, expr->borrow.expr, out)) return 0;
        out->borrow_kind = BORROWKIND_BORROW;
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
    case AST_CALL:
        if (semantic_is_builtin_call(expr->call.name)) {
            semantic_typeinfo_make_scalar(out, "i32");
            return 1;
        }
        {
            SemanticNewtype *newtype = semantic_find_newtype(ctx, expr->call.name);
            if (newtype) {
                semantic_typeinfo_make_scalar(out, newtype->name);
                return 1;
            }
        }
        sig = semantic_find_function_sig(ctx, expr->call.name);
        if (!sig) {
            SemanticBinding *callee = semantic_find_binding(ctx, expr->call.name);
            ASTNode **params = NULL;
            ASTNode *return_type = NULL;
            int count = 0, variadic = 0;
            if (!callee || !callee->has_type ||
                !semantic_function_type_parts(&callee->type_info, &params, &count,
                                     &return_type, &variadic)) return 0;
            return semantic_typeinfo_from_type_ast(return_type, out);
        }
        if (!sig->has_return_type) return 0;
        *out = sig->return_type;
        return 1;
    case AST_INIT_LIST:
        if (!expr->init_list.struct_type_name) return 0;
        semantic_typeinfo_make_scalar(out, expr->init_list.struct_type_name);
        return 1;
    default:
        return 0;
    }
}
