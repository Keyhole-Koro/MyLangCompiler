#include "mylang/backend/codegen_internal.h"

static void clear_typeinfo(TypeInfo *out) {
    out->base_type = "";
    out->pointer_level = 0;
    out->type_modifiers = 0;
    out->is_array = 0;
    out->dims_count = 0;
    for (int i = 0; i < 8; i++) out->dims[i] = 0;
}

static int infer_identifier_type(CompilerContext *cc, ASTNode *expr, TypeInfo *out) {
    if (find_enum_value(cc, expr->identifier.name)) {
        out->base_type = "i32";
        out->pointer_level = 0;
        out->type_modifiers = 0;
        out->is_array = 0;
        out->dims_count = 0;
        return 1;
    }
    const LocalInfo *li = find_local_info(cc, expr->identifier.name);
    if (!li) li = find_global_info(cc, expr->identifier.name);
    if (!li) return 0;
    out->base_type = li->base_type;
    out->pointer_level = li->pointer_level;
    out->type_modifiers = li->type_modifiers;
    out->is_array = li->is_array;
    out->dims_count = li->dims_count;
    for (int i = 0; i < li->dims_count && i < 8; i++) out->dims[i] = li->dims[i];
    if (li->is_array && li->dims_count > 0) {
        out->pointer_level += 1;
        for (int i = 1; i < li->dims_count; i++) out->dims[i - 1] = li->dims[i];
        out->dims_count = li->dims_count - 1;
        out->is_array = out->dims_count > 0;
    }
    return 1;
}

static int infer_member_type(CompilerContext *cc, ASTNode *lhs_expr, const char *member, int deref_ptr, TypeInfo *out) {
    TypeInfo lhs = {0};
    if (!infer_expr_type(cc, lhs_expr, &lhs)) return 0;
    if (deref_ptr) {
        if (lhs.pointer_level <= 0 || !lhs.base_type || lhs.base_type[0] == '\0') return 0;
    } else {
        if (!lhs.base_type || lhs.base_type[0] == '\0') return 0;
    }
    const MemberInfo *mi = find_member_info(cc, lhs.base_type, member);
    if (!mi) return 0;
    out->base_type = mi->base_type ? mi->base_type : "";
    out->pointer_level = mi->pointer_level;
    out->type_modifiers = lhs.type_modifiers;
    out->is_array = mi->is_array;
    if (mi->is_array) out->pointer_level += 1;
    out->dims_count = 0;
    return 1;
}

static int infer_binary_type(CompilerContext *cc, ASTNode *expr, TypeInfo *out) {
    TypeInfo lhs = {0};
    TypeInfo rhs = {0};
    if (!infer_expr_type(cc, expr->binary.left, &lhs) || !infer_expr_type(cc, expr->binary.right, &rhs)) return 0;
    if (expr->binary.op == ADD || expr->binary.op == SUB) {
        if (lhs.pointer_level > 0 && rhs.pointer_level == 0) { *out = lhs; return 1; }
        if (expr->binary.op == ADD && rhs.pointer_level > 0 && lhs.pointer_level == 0) { *out = rhs; return 1; }
        if (expr->binary.op == SUB && lhs.pointer_level > 0 && rhs.pointer_level > 0) {
            out->base_type = "i32";
            out->pointer_level = 0;
            out->is_array = 0;
            out->dims_count = 0;
            return 1;
        }
    }
    if (lhs.pointer_level == 0 && rhs.pointer_level == 0) { *out = lhs; return 1; }
    return 0;
}

static int infer_unary_type(CompilerContext *cc, ASTNode *expr, TypeInfo *out) {
    TypeInfo inner = {0};
    if (!infer_expr_type(cc, expr->unary.operand, &inner)) return 0;
    if (expr->unary.op == ASTARISK) {
        if (inner.pointer_level <= 0) return 0;
        out->base_type = inner.base_type;
        out->pointer_level = inner.pointer_level - 1;
        out->type_modifiers = inner.type_modifiers;
        out->dims_count = inner.dims_count;
        for (int i = 0; i < inner.dims_count; i++) out->dims[i] = inner.dims[i];
        out->is_array = (out->dims_count > 0);
        return 1;
    }
    if (expr->unary.op == AMPERSAND) {
        out->base_type = inner.base_type;
        out->pointer_level = inner.pointer_level + 1;
        out->type_modifiers = inner.type_modifiers;
        out->dims_count = inner.dims_count;
        for (int i = 0; i < inner.dims_count; i++) out->dims[i] = inner.dims[i];
        out->is_array = inner.is_array;
        return 1;
    }
    return 0;
}

int infer_expr_type(CompilerContext *cc, ASTNode *expr, TypeInfo *out) {
    if (!expr || !out) return 0;
    clear_typeinfo(out);
    switch (expr->type) {
    case AST_IDENTIFIER:
        return infer_identifier_type(cc, expr, out);
    case AST_NUMBER:
        out->base_type = "i32";
        return 1;
    case AST_MEMBER_ACCESS:
        return infer_member_type(cc, expr->member_access.lhs, expr->member_access.member, 0, out);
    case AST_ARROW_ACCESS:
        return infer_member_type(cc, expr->arrow_access.lhs, expr->arrow_access.member, 1, out);
    case AST_SIZEOF:
        out->base_type = "i32";
        return 1;
    case AST_BINARY:
        return infer_binary_type(cc, expr, out);
    case AST_BORROW:
        if (!infer_expr_type(cc, expr->borrow.expr, out)) return 0;
        out->pointer_level += 1;
        return 1;
    case AST_BORROW_MUT:
        if (!infer_expr_type(cc, expr->borrow_mut.expr, out)) return 0;
        out->pointer_level += 1;
        return 1;
    case AST_UNARY:
        return infer_unary_type(cc, expr, out);
    case AST_CAST:
        if (expr->cast.type && typeinfo_from_type_ast(cc, expr->cast.type, out)) return 1;
        if (expr->cast.expr) return infer_expr_type(cc, expr->cast.expr, out);
        return 0;
    case AST_CASE: {
        TypeInfo t = {0};
        if (expr->case_expr.case_count > 0 && infer_expr_type(cc, expr->case_expr.cases[0].expr, &t)) { *out = t; return 1; }
        if (expr->case_expr.default_expr && infer_expr_type(cc, expr->case_expr.default_expr, &t)) { *out = t; return 1; }
        return 0;
    }
    case AST_TERNARY: {
        TypeInfo t = {0};
        if (infer_expr_type(cc, expr->ternary.then_expr, &t)) { *out = t; return 1; }
        if (infer_expr_type(cc, expr->ternary.else_expr, &t)) { *out = t; return 1; }
        return 0;
    }
    case AST_CALL:
        if (expr->call.name &&
            (strcmp(expr->call.name, "__rest_len") == 0 ||
             strcmp(expr->call.name, "__rest_get") == 0)) {
            out->base_type = "i32";
            return 1;
        }
        return 0;
    default:
        return 0;
    }
}
