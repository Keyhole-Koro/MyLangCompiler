#include "mylang/semantic/semantic_internal.h"
#include "mylang/semantic/diagnostic_codes.h"
#include "mylang/frontend/parser_trait_internal.h"

/* What types mean to the checks: a value's kind, which types are compatible,
 * and how a type is spelled in a diagnostic. */

/* Rule V2 of docs/design/mylang-values.md: a value's kind follows from its
 * type, and a struct or array is the strongest of what it holds. */
typedef enum {
    VALUE_DATA,
    /* Moved with nothing to drop. A raw pointer field may own what it points
     * at: Vec has no drop yet, and copying its header would alias its buffer
     * until shared values land (MLC-025). A type this module cannot see into
     * is treated the same, as it may hold either. */
    VALUE_MOVED,
    /* Moved, and has a drop, here or in a field. */
    VALUE_OWNED,
} SemanticValueKind;

/* A value cannot hold itself, so this only stops a declaration that tries. */
#define SEMANTIC_MAX_VALUE_NESTING 32

static SemanticValueKind semantic_value_kind(SemanticContext *ctx, const SemanticTypeInfo *info, int depth);

static int semantic_type_declares_drop(SemanticContext *ctx, const char *name) {
    ParserContext *parser = parser_context_current();
    char drop_name[256];
    snprintf(drop_name, sizeof(drop_name), "%s__drop", name);
    return (parser && (find_impl_for_name(parser, "Drop", name) || find_method(parser, name, "drop"))) ||
           semantic_find_function_sig(ctx, drop_name);
}

static SemanticValueKind field_value_kind(SemanticContext *ctx, const SemanticTypeInfo *field, int depth) {
    return field->pointer_level > 0 ? VALUE_MOVED : semantic_value_kind(ctx, field, depth);
}

/* The parser's table holds a module's own structs and those an import brought
 * along. One an import names is in the layouts, under its link name. */
static SemanticValueKind struct_value_kind(SemanticContext *ctx, const char *name, int depth) {
    ParserContext *parser = parser_context_current();
    StructDef *def = parser ? find_structdef(parser, name) : NULL;
    SemanticValueKind kind = VALUE_DATA;
    if (def) {
        for (int i = 0; i < def->member_count; i++) {
            ASTNode *member = def->members[i];
            SemanticTypeInfo field;
            SemanticValueKind held = VALUE_MOVED;
            if (member && member->type == AST_VAR_DECL &&
                semantic_typeinfo_from_type_ast(member->var_decl.var_type, &field))
                held = field_value_kind(ctx, &field, depth + 1);
            if (held > kind) kind = held;
        }
        return kind;
    }
    for (int i = 0; i < ctx->struct_layout_count; i++) {
        const SemanticStructLayout *layout = &ctx->struct_layouts[i];
        if (strcmp(layout->name, name) != 0) continue;
        for (int m = 0; m < layout->member_count; m++) {
            SemanticValueKind held = field_value_kind(ctx, &layout->members[m].type, depth + 1);
            if (held > kind) kind = held;
        }
        return kind;
    }
    return VALUE_MOVED;
}

static SemanticValueKind semantic_value_kind(SemanticContext *ctx, const SemanticTypeInfo *info, int depth) {
    if (info->is_function || info->borrow_kind != REFKIND_NONE || info->pointer_level > 0) return VALUE_DATA;
    const char *name = info->base_type;
    if (!name || depth > SEMANTIC_MAX_VALUE_NESTING) return VALUE_MOVED;
    /* `_` is the unit payload of `Result<_, E>`. */
    if (semantic_is_builtin_type(name) || strcmp(name, "_") == 0) return VALUE_DATA;
    if (semantic_type_declares_drop(ctx, name)) return VALUE_OWNED;
    if (semantic_enum_type_exists(ctx, name) || semantic_find_newtype(ctx, name)) return VALUE_DATA;
    return struct_value_kind(ctx, name, depth);
}

int semantic_typeinfo_is_copy(SemanticContext *ctx, const SemanticTypeInfo *info) {
    return semantic_value_kind(ctx, info, 0) == VALUE_DATA;
}

/* An owned value: a `drop` runs when its owner goes away, here or in a field. */
int semantic_typeinfo_has_drop(SemanticContext *ctx, const SemanticTypeInfo *info) {
    return info && semantic_value_kind(ctx, info, 0) == VALUE_OWNED;
}

int semantic_type_is_copy(SemanticContext *ctx, ASTNode *type_node) {
    if (!type_node) return 1;
    SemanticTypeInfo info;
    return semantic_typeinfo_from_type_ast(type_node, &info) && semantic_typeinfo_is_copy(ctx, &info);
}

/* `void *` is a value, so only plain `void` counts. */
int semantic_type_is_void(ASTNode *type_node) {
    SemanticTypeInfo info;
    return semantic_typeinfo_from_type_ast(type_node, &info) && info.base_type &&
           strcmp(info.base_type, "void") == 0 && info.pointer_level == 0;
}

static int semantic_typeinfo_is_integer_like(const SemanticTypeInfo *info) {
    if (!info || info->pointer_level > 0 || info->borrow_kind != REFKIND_NONE || info->is_array) return 0;
    return strcmp(info->base_type, "bool") == 0 ||
           strcmp(info->base_type, "u8") == 0 ||
           strcmp(info->base_type, "u16") == 0 ||
           strcmp(info->base_type, "i32") == 0 ||
           strcmp(info->base_type, "u32") == 0 ||
           strcmp(info->base_type, "char") == 0 ||
           strcmp(info->base_type, "long") == 0 ||
           strcmp(info->base_type, "short") == 0;
}

int semantic_typeinfo_is_integer_like_or_enum(SemanticContext *ctx, const SemanticTypeInfo *info) {
    if (semantic_typeinfo_is_integer_like(info)) return 1;
    if (!ctx || !info || info->pointer_level > 0 || info->borrow_kind != REFKIND_NONE || info->is_array) return 0;
    return semantic_enum_type_exists(ctx, info->base_type);
}

int semantic_function_type_parts(const SemanticTypeInfo *info,
                                 ASTNode ***params, int *param_count,
                                 ASTNode **return_type, int *is_variadic) {
    if (!info || !info->is_function) return 0;
    if (info->function_type && info->function_type->type == AST_TYPE_FUNCTION) {
        *params = info->function_type->function_type.param_types;
        *param_count = info->function_type->function_type.param_count;
        *return_type = info->function_type->function_type.return_type;
        *is_variadic = info->function_type->function_type.is_variadic ? 1 : 0;
        return 1;
    }
    if (info->function_decl && info->function_decl->type == AST_FUNDEF) {
        ASTNode *decl = (ASTNode *)info->function_decl;
        *params = decl->fundef.params;
        *param_count = decl->fundef.param_count;
        *return_type = decl->fundef.ret_type;
        *is_variadic = decl->fundef.is_variadic ? 1 : 0;
        return 2;
    }
    return 0;
}

ASTNode *semantic_function_param_type(ASTNode *param, int declaration_form) {
    if (!param) return NULL;
    return declaration_form == 2 && param->type == AST_PARAM ? param->param.type : param;
}

static int semantic_function_type_compatible(SemanticContext *ctx,
                                             const SemanticTypeInfo *expected,
                                             const SemanticTypeInfo *actual) {
    ASTNode **expected_params = NULL, **actual_params = NULL;
    ASTNode *expected_return = NULL, *actual_return = NULL;
    int expected_count = 0, actual_count = 0;
    int expected_variadic = 0, actual_variadic = 0;
    int expected_form = semantic_function_type_parts(expected, &expected_params, &expected_count,
                                            &expected_return, &expected_variadic);
    int actual_form = semantic_function_type_parts(actual, &actual_params, &actual_count,
                                          &actual_return, &actual_variadic);
    if (!expected_form || !actual_form || expected_count != actual_count ||
        expected_variadic != actual_variadic) return 0;

    SemanticTypeInfo expected_info, actual_info;
    if (!semantic_typeinfo_from_type_ast(expected_return, &expected_info) ||
        !semantic_typeinfo_from_type_ast(actual_return, &actual_info) ||
        !semantic_typeinfo_compatible(ctx, &expected_info, &actual_info)) return 0;
    for (int i = 0; i < expected_count; i++) {
        ASTNode *ep = semantic_function_param_type(expected_params[i], expected_form);
        ASTNode *ap = semantic_function_param_type(actual_params[i], actual_form);
        if (!semantic_typeinfo_from_type_ast(ep, &expected_info) ||
            !semantic_typeinfo_from_type_ast(ap, &actual_info) ||
            !semantic_typeinfo_compatible(ctx, &expected_info, &actual_info)) return 0;
        /* An address and a word convert at a call, not across a function
         * value: nothing there says which of the two is really passed. */
        if (expected_info.pointer_level != actual_info.pointer_level ||
            expected_info.borrow_kind != actual_info.borrow_kind) return 0;
    }
    return 1;
}

void semantic_typeinfo_format(const SemanticTypeInfo *info, char *buf, size_t buf_size) {
    size_t used;

    if (!buf || buf_size == 0) return;
    if (!info || !info->base_type || info->base_type[0] == '\0') {
        snprintf(buf, buf_size, "<unknown>");
        return;
    }

    if (info->is_function) {
        ASTNode **params = NULL;
        ASTNode *ret = NULL;
        int count = 0, variadic = 0;
        int form = semantic_function_type_parts(info, &params, &count, &ret, &variadic);
        if (!form) { snprintf(buf, buf_size, "fn(?)"); return; }
        size_t at = (size_t)snprintf(buf, buf_size, "fn(");
        for (int i = 0; i < count && at < buf_size; i++) {
            SemanticTypeInfo param_info;
            char part[48];
            semantic_typeinfo_from_type_ast(semantic_function_param_type(params[i], form), &param_info);
            semantic_typeinfo_format(&param_info, part, sizeof(part));
            at += (size_t)snprintf(buf + at, buf_size - at, "%s%s", i ? ", " : "", part);
        }
        if (variadic && at < buf_size)
            at += (size_t)snprintf(buf + at, buf_size - at, "%srest", count ? ", " : "");
        if (at < buf_size) {
            SemanticTypeInfo ret_info;
            char part[48];
            semantic_typeinfo_from_type_ast(ret, &ret_info);
            semantic_typeinfo_format(&ret_info, part, sizeof(part));
            snprintf(buf + at, buf_size - at, ") -> %s", part);
        }
        return;
    }

    used = 0;
    if (info->borrow_kind == REFKIND_BORROW) {
        used += (size_t)snprintf(buf + used, buf_size - used, "borrow ");
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

int semantic_typeinfo_same_base(const SemanticTypeInfo *a, const SemanticTypeInfo *b) {
    return a && b && a->base_type && b->base_type && strcmp(a->base_type, b->base_type) == 0;
}

static int semantic_typeinfo_is_code_address(const SemanticTypeInfo *info) {
    return info && info->base_type && strcmp(info->base_type, "CodeAddress") == 0 &&
           info->borrow_kind == REFKIND_NONE && info->pointer_level == 0 && !info->is_array;
}

int semantic_literal_to_legacy_c_string(const SemanticTypeInfo *expected,
                                        const SemanticTypeInfo *actual,
                                        ASTNode *expr) {
    if (!expected || !actual || !expr || expr->type != AST_STRING_LITERAL) return 0;
    if (!actual->base_type || strcmp(actual->base_type, "str") != 0 ||
        actual->pointer_level != 0 || actual->is_array) return 0;
    if (!expected->base_type || strcmp(expected->base_type, "char") != 0) return 0;
    return expected->pointer_level == 1 || expected->is_array;
}

int semantic_null_function_literal(const SemanticTypeInfo *expected,
                                   ASTNode *expr) {
    return expected && expected->is_function && expr && expr->type == AST_NUMBER &&
           expr->number.value && strcmp(expr->number.value, "0") == 0;
}

int semantic_typeinfo_compatible(SemanticContext *ctx, const SemanticTypeInfo *expected, const SemanticTypeInfo *actual) {
    if (!expected || !actual) return 0;
    // Function values occupy one code address at the ABI. Only the nominal
    // CodeAddress type accepts that representation implicitly; a function
    // must not silently become an unrelated integer.
    if (semantic_typeinfo_is_code_address(expected) && actual->is_function) return 1;
    if (expected->is_function || actual->is_function)
        return semantic_function_type_compatible(ctx, expected, actual);
    if (semantic_typeinfo_is_integer_like_or_enum(ctx, expected) &&
        semantic_typeinfo_is_integer_like_or_enum(ctx, actual)) return 1;

    if (semantic_typeinfo_same_base(expected, actual) &&
        expected->borrow_kind == actual->borrow_kind &&
        expected->pointer_level == actual->pointer_level &&
        expected->is_array == actual->is_array &&
        expected->dims_count == actual->dims_count) {
        for (int i = 0; i < expected->dims_count; i++) {
            if (expected->dims[i] > 0 && actual->dims[i] > 0 && expected->dims[i] != actual->dims[i]) return 0;
        }
        return 1;
    }

    if (semantic_typeinfo_same_base(expected, actual) &&
        expected->borrow_kind == REFKIND_NONE &&
        actual->borrow_kind == REFKIND_NONE) {
        if (expected->pointer_level == actual->pointer_level + 1 && actual->is_array) return 1;
        if (expected->is_array && expected->pointer_level == 0 && actual->pointer_level == 1) return 1;
    }

    if (semantic_typeinfo_same_base(expected, actual) &&
        expected->pointer_level > 0 && actual->borrow_kind != REFKIND_NONE &&
        expected->pointer_level == actual->pointer_level + 1) {
        return 1;
    }

    if (semantic_typeinfo_is_integer_like_or_enum(ctx, expected) &&
        (actual->pointer_level > 0 || actual->borrow_kind != REFKIND_NONE) &&
        !actual->is_array) {
        return 1;
    }

    return 0;
}

int semantic_call_arg_compatible(SemanticContext *ctx, const SemanticTypeInfo *expected, const SemanticTypeInfo *actual) {
    if (!expected || !actual) return 0;
    if (semantic_typeinfo_is_code_address(expected) && actual->is_function) return 1;
    if (semantic_typeinfo_is_integer_like_or_enum(ctx, expected) &&
        semantic_typeinfo_is_integer_like_or_enum(ctx, actual)) return 1;

    if (semantic_typeinfo_same_base(expected, actual) &&
        expected->borrow_kind == actual->borrow_kind &&
        expected->pointer_level == actual->pointer_level &&
        expected->is_array == actual->is_array &&
        expected->dims_count == actual->dims_count) {
        for (int i = 0; i < expected->dims_count; i++) {
            if (expected->dims[i] > 0 && actual->dims[i] > 0 && expected->dims[i] != actual->dims[i]) return 0;
        }
        return 1;
    }

    if (semantic_typeinfo_same_base(expected, actual) &&
        expected->borrow_kind == REFKIND_NONE &&
        actual->borrow_kind == REFKIND_NONE) {
        if (expected->pointer_level == actual->pointer_level + 1 && actual->is_array) return 1;
        if (expected->is_array && expected->pointer_level == 0 && actual->pointer_level == 1) return 1;
    }

    if (semantic_typeinfo_same_base(expected, actual) &&
        expected->pointer_level > 0 && actual->borrow_kind != REFKIND_NONE &&
        expected->pointer_level == actual->pointer_level + 1) {
        return 1;
    }

    return 0;
}

void semantic_report_type_mismatch(SemanticContext *ctx, SemanticLocation loc,
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
