#include "mylang/backend/codegen_internal.h"

void emit_load_var(CompilerContext *cc, StringBuilder *sb, const char *name, const char *target_reg,
                   char **params, int param_count,
                   char **locals, int local_count)
{
    int rest_stack_base = 0;
    if (cg_rest_stack_base(cc, name, &rest_stack_base)) {
        sb_append(sb, "  \n; load rest argument base '%s' into %s\n", name, target_reg);
        sb_append(sb, "  mov %s, bp\n", target_reg);
        sb_append(sb, "  addis %s, %d\n", target_reg, rest_stack_base);
        return;
    }

    const LocalInfo *li_info = find_local_info(cc, name);
    if (!li_info) li_info = find_global_info(cc, name);
    if (li_info && li_info->is_array) {
        // arrays decay to pointers
        emit_addr_of_var(cc, sb, name, target_reg, params, param_count, locals, local_count);
        return;
    }

    int idx = param_index(name, params, param_count);
    int offset;
    if (idx >= 0)
    {
        if (idx < 3)
        {
            // bp-4, bp-8, bp-12…
            offset = -(4 + idx * SLOT_SIZE);
            sb_append(sb, "  \n; load param '%s' (arg%d, reg) into %s\n", name, idx + 1, target_reg);
            sb_append(sb, "  mov   r3, bp\n");
            sb_append(sb, "  addis r3, %d\n", offset);
            emit_load_width_from_addr(sb, target_reg, "r3", scalar_var_width_bytes(cc, name));
        }
        else
        {
            // bp+N
            offset = 8 + (idx - 3) * SLOT_SIZE;
            sb_append(sb, "  \n; load param '%s' (arg%d, stack) into %s\n", name, idx + 1, target_reg);
            sb_append(sb, "  mov   r3, bp\n");
            sb_append(sb, "  addis r3, %d\n", offset);
            emit_load_width_from_addr(sb, target_reg, "r3", scalar_var_width_bytes(cc, name));
        }
    }
    else
    {
        int local_idx = local_index_last(name, locals, local_count);
        if (local_idx >= 0)
        {
            offset = local_offset(param_count, local_idx);
            sb_append(sb, "  \n; load local '%s' into %s\n", name, target_reg);
            sb_append(sb, "  mov   r3, bp\n");
            sb_append(sb, "  addis r3, %d\n", offset);
            emit_load_width_from_addr(sb, target_reg, "r3", scalar_var_width_bytes(cc, name));
        }
        else
        {
            // fallback global. Use r3 as the address scratch (as every other
            // branch above does); r2 may hold a pending operand of an enclosing
            // binary expression and must not be clobbered here.
            sb_append(sb, "  movi  r3, %s\n", name);
            emit_load_width_from_addr(sb, target_reg, "r3", scalar_var_width_bytes(cc, name));
        }
    }
}

// Emit code to store target_reg to variable (param/local/global)
void emit_store_var(CompilerContext *cc, StringBuilder *sb, const char *name, const char *src_reg,
                    char **params, int param_count,
                    char **locals, int local_count)
{
    int is_param = 0;
    int offset = find_var_offset(name, params, param_count, locals, local_count, &is_param);
    if (is_param == 1 || is_param == 0)
    {
        sb_append(sb, "  \n; store %s to var '%s'\n", src_reg, name);
        sb_append(sb, "  mov   r3, bp\n");
        sb_append(sb, "  addis r3, %d\n", offset);
        emit_store_width_to_addr(sb, "r3", src_reg, scalar_var_width_bytes(cc, name));
    }
    else
    {
        // fallback global
        sb_append(sb, "  movi  r3, %s\n", name);
        emit_store_width_to_addr(sb, "r3", src_reg, scalar_var_width_bytes(cc, name));
    }
}

void emit_addr_of_var(CompilerContext *cc, StringBuilder *sb, const char *name, const char *target_reg,
                      char **params, int param_count, char **locals, int local_count)
{
    int is_param = 0;
    int offset = find_var_offset(name, params, param_count, locals, local_count, &is_param);
    if (is_param == 0) {
        const LocalInfo *li = find_local_info(cc, name);
        int occur = 0;
        for (int i = 0; i < local_count; i++) {
            if (locals[i] && strcmp(locals[i], name) == 0) occur++;
        }
        if ((li && li->is_array) || occur > 1) {
            int last = local_index_last(name, locals, local_count);
            if (last >= 0) offset = local_offset(param_count, last);
        }
    }
    if (is_param == -1) {
        sb_append(sb, "  \n; address of global '%s'\n", name);
        sb_append(sb, "  movi %s, %s\n", target_reg, name);
        return;
    }
    sb_append(sb, "  \n; address of '%s'\n", name);
    sb_append(sb, "  mov   %s, bp\n", target_reg);
    sb_append(sb, "  addis %s, %d\n", target_reg, offset);
}

void gen_lvalue_addr(CompilerContext *cc, ASTNode *node, StringBuilder *sb, const char *target_reg,
                            char **params, int param_count,
                            char **locals, int local_count) {
    if (!node) { sb_append(sb, "  ; gen_lvalue_addr: null\n"); return; }
    switch (node->type) {
    case AST_IDENTIFIER: {
        emit_addr_of_var(cc, sb, node->identifier.name, target_reg, params, param_count, locals, local_count);
        break; }
    case AST_UNARY: {
        if (node->unary.op == ASTARISK) {
            // address is the value of operand
            gen_expr(cc, node->unary.operand, sb, target_reg, params, param_count, locals, local_count);
        } else {
            sb_append(sb, "  ; unsupported lvalue op\n");
        }
        break; }
    case AST_MEMBER_ACCESS: {
        TypeInfo lhs_type = (TypeInfo){0};
        if (!infer_expr_type(cc, node->member_access.lhs, &lhs_type) ||
            !lhs_type.base_type || lhs_type.base_type[0] == '\0') {
            sb_append(sb, "  ; unknown member base type\n");
            break;
        }
        const MemberInfo *mi = find_member_info(cc, lhs_type.base_type, node->member_access.member);
        if (!mi) {
            sb_append(sb, "  ; unknown member %s of %s\n", node->member_access.member, lhs_type.base_type);
            break;
        }
        gen_lvalue_addr(cc, node->member_access.lhs, sb, target_reg, params, param_count, locals, local_count);
        sb_append(sb, "  addis %s, %d\n", target_reg, mi->offset);
        break; }
    case AST_ARROW_ACCESS: {
        TypeInfo lhs_type = (TypeInfo){0};
        if (!infer_expr_type(cc, node->arrow_access.lhs, &lhs_type) ||
            lhs_type.pointer_level <= 0 ||
            !lhs_type.base_type || lhs_type.base_type[0] == '\0') {
            sb_append(sb, "  ; unknown pointer base for arrow access\n");
            break;
        }
        const MemberInfo *mi = find_member_info(cc, lhs_type.base_type, node->arrow_access.member);
        if (!mi) {
            sb_append(sb, "  ; unknown member %s of %s\n", node->arrow_access.member, lhs_type.base_type);
            break;
        }
        gen_expr(cc, node->arrow_access.lhs, sb, target_reg, params, param_count, locals, local_count);
        sb_append(sb, "  addis %s, %d\n", target_reg, mi->offset);
        break; }
    default:
        sb_append(sb, "  ; unsupported lvalue kind: %s\n", astType2str(node->type));
    }
}

