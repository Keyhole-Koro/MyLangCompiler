#include "mylang/backend/codegen_internal.h"

static int gen_rest_len_access(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg) {
    if (!cc || !node || node->type != AST_MEMBER_ACCESS) return 0;
    if (!node->member_access.member || strcmp(node->member_access.member, "len") != 0) return 0;
    if (!node->member_access.lhs || node->member_access.lhs->type != AST_IDENTIFIER) return 0;

    int rest_index = 0;
    if (!cg_current_rest_info(cc, node->member_access.lhs->identifier.name, &rest_index, NULL)) return 0;

    sb_append(sb, "  ; load rest argument count\n");
    sb_append(sb, "  mov r3, bp\n");
    sb_append(sb, "  addis r3, %d\n", param_offset(rest_index));
    emit_load_from_addr(sb, target_reg, "r3", 0);
    return 1;
}

/**                                                                                                                        │
* Generates code for accessing variadic (rest) parameters via subscripting/pointer arithmetic.                            │
* Handles patterns like *(rest + index) or *(rest - index) by calculating the stack offset.                               │
*/
static int gen_rest_subscript_access(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
                                     char **params, int param_count, char **locals, int local_count, int want_address) {
    ASTNode *expr;
    ASTNode *rest_ident = NULL;
    ASTNode *index_expr = NULL;
    int rest_stack_base = 0;
    int is_sub = 0;

    if (!cc || !node || node->type != AST_UNARY || node->unary.op != ASTARISK) return 0;
    expr = node->unary.operand;
    if (!expr || expr->type != AST_BINARY) return 0;
    if (expr->binary.op != ADD && expr->binary.op != SUB) return 0;

    if (expr->binary.left && expr->binary.left->type == AST_IDENTIFIER &&
        cg_rest_stack_base(cc, expr->binary.left->identifier.name, &rest_stack_base)) {
        rest_ident = expr->binary.left;
        index_expr = expr->binary.right;
        is_sub = (expr->binary.op == SUB);
    } else if (expr->binary.op == ADD &&
               expr->binary.right && expr->binary.right->type == AST_IDENTIFIER &&
               cg_rest_stack_base(cc, expr->binary.right->identifier.name, &rest_stack_base)) {
        rest_ident = expr->binary.right;
        index_expr = expr->binary.left;
    }

    if (!rest_ident || !index_expr) return 0;

    gen_expr(cc, index_expr, sb, "r1", params, param_count, locals, local_count);
    emit_scale_reg_const(cc, sb, "r1", SLOT_SIZE);
    sb_append(sb, "  ; load rest argument base '%s' into r3\n", rest_ident->identifier.name);
    sb_append(sb, "  mov r3, bp\n");
    sb_append(sb, "  addis r3, %d\n", rest_stack_base);
    if (is_sub) sb_append(sb, "  sub r3, r1\n");
    else sb_append(sb, "  add r3, r1\n");
    if (want_address) {
        if (strcmp(target_reg, "r3") != 0) sb_append(sb, "  mov %s, r3\n", target_reg);
    } else {
        emit_load_from_addr(sb, target_reg, "r3", 0);
    }
    return 1;
}

void gen_expr(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
              char **params, int param_count,
              char **locals, int local_count) {
    _gen_expr(cc, node, sb, target_reg, params, param_count, locals, local_count, 0);
}

void _gen_expr(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
               char **params, int param_count, char **locals, int local_count,
               int want_address)
{
    switch (node->type)
    {
    case AST_SIZEOF: {
        int sz = SLOT_SIZE;
        int determined = 0;
        if (node->sizeof_expr.expr && node->sizeof_expr.expr->type == AST_IDENTIFIER) {
            const LocalInfo *li = find_local_info(cc, node->sizeof_expr.expr->identifier.name);
            if (li) {
                TypeInfo ti = {0};
                ti.base_type = li->base_type;
                ti.pointer_level = li->pointer_level;
                ti.is_array = li->is_array;
                ti.dims_count = li->dims_count;
                for (int i = 0; i < li->dims_count && i < 8; i++) ti.dims[i] = li->dims[i];
                sz = typeinfo_total_size_bytes(cc, &ti);
                determined = 1;
            }
        }
        if (!determined) {
            TypeInfo ti = {0};
            if (infer_expr_type(cc, node->sizeof_expr.expr, &ti)) {
                sz = typeinfo_total_size_bytes(cc, &ti);
            }
        }
        sb_append(sb, "  movi %s, %d\n", target_reg, sz);
        break; }
    case AST_STRING_LITERAL: {
        const char *label = intern_string_literal(cc, node->string_literal.value ? node->string_literal.value : "");
        sb_append(sb, "  movi  %s, %s\n", target_reg, label);
        break; }
    case AST_CHAR_LITERAL: {
        unsigned char v = 0;
        if (node->char_literal.value)
            v = (unsigned char)node->char_literal.value[0];
        sb_append(sb, "  \n; load char %u into %s\n", (unsigned)v, target_reg);
        sb_append(sb, "  movi  %s, %u\n", target_reg, (unsigned)v);
        break; }
    case AST_ASSIGN:
        gen_assign(cc, node, sb, params, param_count, locals, local_count, target_reg);
        break;
    case AST_TERNARY: {
        int lbl = next_label(cc);
        char label_else[32], label_end[32];
        snprintf(label_else, sizeof(label_else), "b_ternary_else_%d", lbl);
        snprintf(label_end, sizeof(label_end), "b_ternary_end_%d", lbl);
        gen_expr(cc, node->ternary.cond, sb, "r1", params, param_count, locals, local_count);
        sb_append(sb, "  cmp r1, 0\n");
        sb_append(sb, "  jz %s\n", label_else);
        gen_expr(cc, node->ternary.then_expr, sb, target_reg, params, param_count, locals, local_count);
        sb_append(sb, "  jmp %s\n", label_end);
        sb_append(sb, "%s:\n", label_else);
        gen_expr(cc, node->ternary.else_expr, sb, target_reg, params, param_count, locals, local_count);
        sb_append(sb, "%s:\n", label_end);
        break;
    }
    case AST_STMT_EXPR:
        gen_stmt(cc, node->stmt_expr.block, sb, params, param_count, locals, local_count);
        if (strcmp(target_reg, "r1") != 0)
            sb_append(sb, "  mov %s, r1\n", target_reg);
        break;
    case AST_CASE: {
        int lbl_end = next_label(cc);
        int lbl_default = next_label(cc);
        gen_expr(cc, node->case_expr.target, sb, "r1", params, param_count, locals, local_count);
        sb_append(sb, "  push r1\n");

        int *case_lbls = malloc(sizeof(int) * node->case_expr.case_count);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            case_lbls[i] = next_label(cc);
            gen_expr(cc, node->case_expr.cases[i].key, sb, "r1", params, param_count, locals, local_count);
            sb_append(sb, "  mov r2, r1\n");
            sb_append(sb, "  load r1, sp\n");
            sb_append(sb, "  cmp r1, r2\n");
            sb_append(sb, "  jz b_case_%d\n", case_lbls[i]);
        }

        sb_append(sb, "  pop r1\n");
        sb_append(sb, "  jmp b_default_%d\n", lbl_default);

        for (int i = 0; i < node->case_expr.case_count; i++) {
            sb_append(sb, "b_case_%d:\n", case_lbls[i]);
            sb_append(sb, "  pop r1\n");
            gen_expr(cc, node->case_expr.cases[i].expr, sb, target_reg, params, param_count, locals, local_count);
            sb_append(sb, "  jmp b_case_end_%d\n", lbl_end);
        }
        free(case_lbls);

        sb_append(sb, "b_default_%d:\n", lbl_default);
        if (node->case_expr.default_expr) {
            gen_expr(cc, node->case_expr.default_expr, sb, target_reg, params, param_count, locals, local_count);
        } else {
            sb_append(sb, "  movi %s, 0\n", target_reg);
        }
        sb_append(sb, "b_case_end_%d:\n", lbl_end);
        break;
    }
    case AST_NUMBER:
        sb_append(sb, "  \n; load constant %s into %s\n", node->number.value, target_reg);
        sb_append(sb, "  movi  %s, %s\n", target_reg, node->number.value);
        break;
    case AST_CAST:
        _gen_expr(cc, node->cast.expr, sb, target_reg, params, param_count, locals, local_count, 0);
        break;
    case AST_BORROW:
        gen_lvalue_addr(cc, node->borrow.expr, sb, target_reg, params, param_count, locals, local_count);
        break;
    case AST_BORROW_MUT:
        gen_lvalue_addr(cc, node->borrow_mut.expr, sb, target_reg, params, param_count, locals, local_count);
        break;
    case AST_UNARY:
        switch (node->unary.op)
        {
        case SUB: {
            _gen_expr(cc, node->unary.operand, sb, target_reg, params, param_count, locals, local_count, 0);
            const char *zero_reg = (strcmp(target_reg, "r1") == 0) ? "r2" : "r1";
            sb_append(sb, "  mov %s, 0\n", zero_reg);
            sb_append(sb, "  sub %s, %s\n", zero_reg, target_reg);
            sb_append(sb, "  mov %s, %s\n", target_reg, zero_reg);
            break;
        }
        case BITNOT:
            _gen_expr(cc, node->unary.operand, sb, target_reg, params, param_count, locals, local_count, 0);
            sb_append(sb, "  movi r3, -1\n");
            sb_append(sb, "  xor %s, r3\n", target_reg);
            break;
        case NOT: {
            _gen_expr(cc, node->unary.operand, sb, target_reg, params, param_count, locals, local_count, 0);
            int lbl_true = next_label(cc);
            int lbl_end = next_label(cc);
            sb_append(sb, "  cmp %s, 0\n", target_reg);
            sb_append(sb, "  jz b_not_true_%d\n", lbl_true);
            sb_append(sb, "  movi %s, 0\n", target_reg);
            sb_append(sb, "  jmp b_not_end_%d\n", lbl_end);
            sb_append(sb, "b_not_true_%d:\n", lbl_true);
            sb_append(sb, "  movi %s, 1\n", target_reg);
            sb_append(sb, "b_not_end_%d:\n", lbl_end);
            break; }
        case ASTARISK:
            if (gen_rest_subscript_access(cc, node, sb, target_reg, params, param_count, locals, local_count, want_address)) {
                break;
            }
            _gen_expr(cc, node->unary.operand, sb, "r3", params, param_count, locals, local_count, 0);
            TypeInfo result_type = (TypeInfo){0};
            int have_type = infer_expr_type(cc, node, &result_type);
            int is_array_result = have_type && result_type.dims_count > 0;
            if (!want_address) {
                if (is_array_result) {
                    sb_append(sb, "  ; dereference array -> decay to pointer\n");
                    sb_append(sb, "  mov %s, r3\n", target_reg);
                } else {
                    sb_append(sb, "  ; dereference *expr\n");
                    int width = have_type ? typeinfo_scalar_width_bytes(&result_type) : SLOT_SIZE;
                    emit_load_width_from_addr(sb, target_reg, "r3", width);
                }
            } else {
                sb_append(sb, "  mov %s, r3\n", target_reg);
            }
            break;
        case AMPERSAND:
            gen_lvalue_addr(cc, node->unary.operand, sb, target_reg, params, param_count, locals, local_count);
            break;
        default:
            emit_unary_inc_dec(cc, node, sb, target_reg, params, param_count, locals, local_count);
        }
        break;

    case AST_IDENTIFIER:
        if (find_enum_value(cc, node->identifier.name)) {
            sb_append(sb, "  movi %s, %ld\n", target_reg, find_enum_value(cc, node->identifier.name)->value);
        } else if (find_func_sig(cc, node->identifier.name)) {
            note_import_func(cc, node->identifier.name);
            sb_append(sb, "  \n; load function pointer '%s'\n", node->identifier.name);
            sb_append(sb, "  movi %s, %s\n", target_reg, node->identifier.name);
        } else {
            emit_load_var(cc, sb, node->identifier.name, target_reg, params, param_count, locals, local_count);
        }
        break;
    case AST_BINARY:
        gen_expr_binop(cc, node, sb, target_reg, params, param_count, locals, local_count);
        break;
    case AST_CALL:
        gen_call(cc, node, sb, target_reg, params, param_count, locals, local_count);
        break;
    case AST_MEMBER_ACCESS: {
        if (gen_rest_len_access(cc, node, sb, target_reg)) {
            break;
        }
        gen_lvalue_addr(cc, node, sb, "r3", params, param_count, locals, local_count);
        {
            emit_load_width_from_addr(sb, target_reg, "r3", lvalue_width_bytes(cc, node));
        }
        break; }
    case AST_ARROW_ACCESS: {
        gen_lvalue_addr(cc, node, sb, "r3", params, param_count, locals, local_count);
        {
            emit_load_width_from_addr(sb, target_reg, "r3", lvalue_width_bytes(cc, node));
        }
        break; }
    case AST_IMPORT:
        break;
    default:
        fprintf(stderr, "Codegen error: unknown expr node %s\n", astType2str(node->type));
        exit(1);
    }
}
