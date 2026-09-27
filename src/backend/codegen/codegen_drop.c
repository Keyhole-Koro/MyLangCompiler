#include "mylang/backend/codegen_internal.h"

static const char *drop_func_for_base(CompilerContext *cc, const char *base_type) {
    char name[512];
    if (!base_type) return NULL;
    snprintf(name, sizeof(name), "%s__drop", base_type);
    const FunctionSig *sig = find_func_sig(cc, name);
    if (!sig || sig->param_count != 1 || !sig->has_return_type ||
        !sig->return_type.base_type || strcmp(sig->return_type.base_type, "void") != 0 ||
        !sig->param_has_type || !sig->param_has_type[0] ||
        (sig->param_types[0].pointer_level == 0 &&
         sig->param_types[0].ref_kind == REFKIND_NONE)) return NULL;
    return sig->name;
}

static bool base_needs_drop(CompilerContext *cc, const char *base_type, int depth) {
    if (!base_type || depth > 32) return false;
    if (drop_func_for_base(cc, base_type)) return true;
    const StructInfo *info = find_struct(cc, base_type);
    if (!info) return false;
    for (int i = 0; i < info->member_count; i++) {
        const MemberInfo *member = &info->members[i];
        if (member->pointer_level == 0 && base_needs_drop(cc, member->base_type, depth + 1))
            return true;
    }
    return false;
}

bool type_needs_drop(CompilerContext *cc, ASTNode *type_node) {
    TypeInfo type = {0};
    if (!type_node || !typeinfo_from_type_ast(cc, type_node, &type)) return false;
    resolve_type(cc, &type);
    return type.pointer_level == 0 && type.ref_kind == REFKIND_NONE &&
           type.dims_count == 0 &&
           base_needs_drop(cc, type.base_type, 0);
}

bool expr_needs_drop(CompilerContext *cc, ASTNode *expr) {
    TypeInfo type = {0};
    if (!expr || !infer_expr_type(cc, expr, &type)) return false;
    resolve_type(cc, &type);
    return type.pointer_level == 0 && type.ref_kind == REFKIND_NONE &&
           type.dims_count == 0 && base_needs_drop(cc, type.base_type, 0);
}

DropBinding *find_drop_binding(CompilerContext *cc, const char *name) {
    if (!cc || !name) return NULL;
    for (int i = cc->drop_binding_count - 1; i >= 0; i--) {
        if (strcmp(cc->drop_bindings[i].name, name) == 0)
            return &cc->drop_bindings[i];
    }
    return NULL;
}

static void add_drop_binding(CompilerContext *cc, const char *name,
                             ASTNode *type_node, bool is_param,
                             int param_count, int local_count) {
    TypeInfo type = {0};
    if (!cc || !name || !type_needs_drop(cc, type_node) ||
        !typeinfo_from_type_ast(cc, type_node, &type) || find_drop_binding(cc, name)) return;
    resolve_type(cc, &type);
    int index = cc->drop_binding_count++;
    cc->drop_bindings = realloc(cc->drop_bindings,
        sizeof(DropBinding) * (size_t)cc->drop_binding_count);
    DropBinding *binding = &cc->drop_bindings[index];
    binding->name = name;
    binding->base_type = type.base_type;
    binding->is_param = is_param;
    binding->flag_offset = local_offset(param_count, local_count + index);
}

void collect_drop_bindings(CompilerContext *cc, ASTNode *node, bool is_param,
                           int param_count, int local_count) {
    if (!node) return;
    if (node->type == AST_PARAM) {
        if (type_needs_drop(cc, node->param.type))
            add_drop_binding(cc, node->param.name, node->param.type, true,
                             param_count, local_count);
        return;
    }
    if (node->type == AST_VAR_DECL) {
        if (type_needs_drop(cc, node->var_decl.var_type))
            add_drop_binding(cc, node->var_decl.name, node->var_decl.var_type, is_param,
                             param_count, local_count);
        if (node->var_decl.init)
            collect_drop_bindings(cc, node->var_decl.init, false, param_count, local_count);
        return;
    }
    switch (node->type) {
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++)
            collect_drop_bindings(cc, node->block.stmts[i], false, param_count, local_count);
        break;
    case AST_IF:
        collect_drop_bindings(cc, node->if_stmt.then_stmt, false, param_count, local_count);
        collect_drop_bindings(cc, node->if_stmt.else_stmt, false, param_count, local_count);
        break;
    case AST_FOR:
        collect_drop_bindings(cc, node->for_stmt.init, false, param_count, local_count);
        collect_drop_bindings(cc, node->for_stmt.body, false, param_count, local_count);
        break;
    case AST_WHILE:
        collect_drop_bindings(cc, node->while_stmt.body, false, param_count, local_count);
        break;
    case AST_DO_WHILE:
        collect_drop_bindings(cc, node->do_while_stmt.body, false, param_count, local_count);
        break;
    case AST_UNCHECKED:
        collect_drop_bindings(cc, node->unchecked_block.body, false, param_count, local_count);
        break;
    case AST_STMT_EXPR:
        collect_drop_bindings(cc, node->stmt_expr.block, false, param_count, local_count);
        break;
    case AST_EXPR_STMT:
        collect_drop_bindings(cc, node->expr_stmt.expr, false, param_count, local_count);
        break;
    case AST_RETURN:
        collect_drop_bindings(cc, node->ret.expr, false, param_count, local_count);
        break;
    case AST_YIELD:
        collect_drop_bindings(cc, node->yield_stmt.expr, false, param_count, local_count);
        break;
    case AST_ASSIGN:
        collect_drop_bindings(cc, node->assign.left, false, param_count, local_count);
        collect_drop_bindings(cc, node->assign.right, false, param_count, local_count);
        break;
    case AST_BINARY:
        collect_drop_bindings(cc, node->binary.left, false, param_count, local_count);
        collect_drop_bindings(cc, node->binary.right, false, param_count, local_count);
        break;
    case AST_TERNARY:
        collect_drop_bindings(cc, node->ternary.cond, false, param_count, local_count);
        collect_drop_bindings(cc, node->ternary.then_expr, false, param_count, local_count);
        collect_drop_bindings(cc, node->ternary.else_expr, false, param_count, local_count);
        break;
    case AST_CASE:
        collect_drop_bindings(cc, node->case_expr.target, false, param_count, local_count);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            collect_drop_bindings(cc, node->case_expr.cases[i].key, false, param_count, local_count);
            collect_drop_bindings(cc, node->case_expr.cases[i].expr, false, param_count, local_count);
        }
        collect_drop_bindings(cc, node->case_expr.default_expr, false, param_count, local_count);
        break;
    case AST_CALL:
        for (int i = 0; i < node->call.arg_count; i++)
            collect_drop_bindings(cc, node->call.args[i], false, param_count, local_count);
        break;
    case AST_UNARY:
        collect_drop_bindings(cc, node->unary.operand, false, param_count, local_count);
        break;
    case AST_CAST:
        collect_drop_bindings(cc, node->cast.expr, false, param_count, local_count);
        break;
    case AST_MEMBER_ACCESS:
        collect_drop_bindings(cc, node->member_access.lhs, false, param_count, local_count);
        break;
    case AST_ARROW_ACCESS:
        collect_drop_bindings(cc, node->arrow_access.lhs, false, param_count, local_count);
        break;
    default:
        break;
    }
}

DropBinding *drop_binding_for_expr(CompilerContext *cc, ASTNode *expr) {
    if (!expr) return NULL;
    if (expr->type == AST_IDENTIFIER)
        return find_drop_binding(cc, expr->identifier.name);
    if (expr->type == AST_MEMBER_ACCESS)
        return drop_binding_for_expr(cc, expr->member_access.lhs);
    return NULL;
}

void emit_drop_flag(CompilerContext *cc, DropBinding *binding, bool active,
                    StringBuilder *sb) {
    (void)cc;
    if (!binding) return;
    sb_append(sb, "  mov r3, bp\n");
    sb_append(sb, "  addis r3, %d\n", binding->flag_offset);
    sb_append(sb, "  movi r1, %d\n", active ? 1 : 0);
    sb_append(sb, "  store r3, r1\n");
}

static void emit_drop_type_at(CompilerContext *cc, const char *base_type,
                              const char *address_reg, int depth,
                              StringBuilder *sb) {
    if (!base_type || depth > 32) return;
    const char *drop_func = drop_func_for_base(cc, base_type);
    if (drop_func) {
        sb_append(sb, "  push %s\n", address_reg);
        sb_append(sb, "  mov r5, %s\n", address_reg);
        note_import_func(cc, drop_func);
        sb_append(sb, "  call %s\n", codegen_redirect_call_target(drop_func));
        sb_append(sb, "  pop %s\n", address_reg);
    }

    const StructInfo *info = find_struct(cc, base_type);
    if (!info) return;
    for (int i = info->member_count - 1; i >= 0; i--) {
        const MemberInfo *member = &info->members[i];
        if (member->pointer_level != 0 ||
            !base_needs_drop(cc, member->base_type, depth + 1)) continue;
        const StructInfo *element = find_struct(cc, member->base_type);
        int element_size = element && element->size_bytes > 0 ? element->size_bytes : SLOT_SIZE;
        int count = member->is_array && element_size > 0
            ? member->total_size_bytes / element_size : 1;
        if (count < 1) count = 1;
        for (int index = count - 1; index >= 0; index--) {
            int offset = member->offset + index * element_size;
            sb_append(sb, "  push %s\n", address_reg);
            sb_append(sb, "  mov r2, %s\n", address_reg);
            if (offset) sb_append(sb, "  addis r2, %d\n", offset);
            emit_drop_type_at(cc, member->base_type, "r2", depth + 1, sb);
            sb_append(sb, "  pop %s\n", address_reg);
        }
    }
}

void emit_drop_binding(CompilerContext *cc, DropBinding *binding, StringBuilder *sb,
                       char **params, int param_count, char **locals, int local_count) {
    if (!binding) return;
    int done = next_label(cc);
    sb_append(sb, "  ; drop '%s' when it still owns a value\n", binding->name);
    sb_append(sb, "  mov r3, bp\n");
    sb_append(sb, "  addis r3, %d\n", binding->flag_offset);
    sb_append(sb, "  load r1, r3\n");
    sb_append(sb, "  cmp r1, 0\n");
    sb_append(sb, "  jz drop_done_%d\n", done);
    emit_addr_of_var(cc, sb, binding->name, "r5", params, param_count,
                     locals, local_count);
    emit_drop_type_at(cc, binding->base_type, "r5", 0, sb);
    emit_drop_flag(cc, binding, false, sb);
    sb_append(sb, "drop_done_%d:\n", done);
}

void emit_drop_all(CompilerContext *cc, StringBuilder *sb,
                   char **params, int param_count, char **locals, int local_count) {
    for (int i = cc->drop_binding_count - 1; i >= 0; i--)
        emit_drop_binding(cc, &cc->drop_bindings[i], sb,
                          params, param_count, locals, local_count);
}

void clear_moved_drop_binding(CompilerContext *cc, ASTNode *expr, StringBuilder *sb) {
    if (expr && expr->type == AST_INIT_LIST) {
        for (int i = 0; i < expr->init_list.count; i++)
            clear_moved_drop_binding(cc, expr->init_list.elements[i], sb);
        return;
    }
    if (expr && expr->type != AST_IDENTIFIER && is_addressable_expr(expr) &&
        expr_needs_drop(cc, expr)) {
        fprintf(stderr,
                "Codegen error at %d:%d: moving a droppable field or "
                "dereference is not supported yet; move its containing "
                "owner instead\n",
                expr->line, expr->col);
        exit(1);
    }
    emit_drop_flag(cc, drop_binding_for_expr(cc, expr), false, sb);
}

void activate_drop_binding(CompilerContext *cc, const char *name, StringBuilder *sb) {
    emit_drop_flag(cc, find_drop_binding(cc, name), true, sb);
}

void cleanup_drop_bindings(CompilerContext *cc) {
    free(cc->drop_bindings);
    free(cc->active_drop_bindings);
    cc->drop_bindings = NULL;
    cc->drop_binding_count = 0;
    cc->drop_return_offset = 0;
    cc->active_drop_bindings = NULL;
    cc->active_drop_count = 0;
    cc->loop_drop_base = 0;
}

void push_active_drop_binding(CompilerContext *cc, DropBinding *binding) {
    if (!binding) return;
    cc->active_drop_bindings = realloc(cc->active_drop_bindings,
        sizeof(DropBinding *) * (size_t)(cc->active_drop_count + 1));
    cc->active_drop_bindings[cc->active_drop_count++] = binding;
}

void emit_drop_active_from(CompilerContext *cc, int first, StringBuilder *sb,
                           char **params, int param_count, char **locals, int local_count) {
    if (first < 0) first = 0;
    for (int i = cc->active_drop_count - 1; i >= first; i--)
        emit_drop_binding(cc, cc->active_drop_bindings[i], sb,
                          params, param_count, locals, local_count);
}

void pop_drop_scope(CompilerContext *cc, int mark, StringBuilder *sb,
                    char **params, int param_count, char **locals, int local_count) {
    emit_drop_active_from(cc, mark, sb, params, param_count, locals, local_count);
    cc->active_drop_count = mark;
}
