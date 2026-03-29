#include "mylang/backend/codegen_internal.h"

void gen_func(CompilerContext *cc, ASTNode *node, StringBuilder *sb)
{
    if (node->type != AST_FUNDEF) return;

    char *fname = is_entry_name(node->fundef.name) ? "__START__" : node->fundef.name;
    int param_count = node->fundef.param_count;
    char *params[16] = {0};
    for (int i = 0; i < param_count; i++) {
        params[i] = node->fundef.params[i]->param.name;
    }

    char *locals[32] = {0};
    int local_count = collect_locals(cc, node->fundef.body, locals);

    int locals_only_count = collect_local_type_info(cc, node->fundef.body, NULL);
    cg_locals_count = param_count + locals_only_count;
    if (cg_locals_count > 0) {
        cg_locals_info = (LocalInfo*)malloc(sizeof(LocalInfo) * cg_locals_count);
        int idx = 0;
        for (int i = 0; i < param_count; i++, idx++) {
            ASTNode *p = node->fundef.params[i];
            cg_locals_info[idx].name = p->param.name;
            set_localinfo_from_type(cc, &cg_locals_info[idx], p->param.type);
        }
        if (locals_only_count > 0) {
            collect_local_type_info(cc, node->fundef.body, cg_locals_info + idx);
        }
    } else {
        cg_locals_info = NULL;
    }

    sb_append(sb, "\n");
    sb_append(sb, "%s%s:\n", strcmp(fname, "__START__") == 0 ? "" : "f_", fname);
    sb_append(sb, "; prologue\n");
    sb_append(sb, "  push lr\n");
    sb_append(sb, "  push bp\n");
    sb_append(sb, "  mov bp, sp\n  addis sp, -%d\n", (local_count + param_count) * SLOT_SIZE);

    for (int i = 0; i < param_count && i < 3; i++) {
        sb_append(sb, "  ; store parameter '%s' from register %s\n", params[i], arg_regs[i]);
        sb_append(sb, "  mov   r3, bp\n");
        sb_append(sb, "  addis r3, %d\n", param_offset(i));
        sb_append(sb, "  store r3, %s\n", arg_regs[i]);
    }

    char ret_label[32];
    snprintf(ret_label, sizeof(ret_label), "b_L_ret_%d", next_label(cc));
    cc->return_label = ret_label;

    gen_stmt(cc, node->fundef.body, sb, params, param_count, locals, local_count);

    sb_append(sb, "%s:\n", ret_label);
    sb_append(sb, "  addis sp, %d\n", (local_count + param_count) * SLOT_SIZE);
    sb_append(sb, "; epilogue\n  pop  bp\n  pop  lr\n");

    if (strcmp(fname, "__START__") != 0)
        sb_append(sb, "  mov  pc, lr\n");
    if (strcmp(fname, "__START__") == 0)
        sb_append(sb, "  halt");

    cc->return_label = NULL;
    if (cg_locals_info) {
        free(cg_locals_info);
        cg_locals_info = NULL;
    }
    cg_locals_count = 0;
}
