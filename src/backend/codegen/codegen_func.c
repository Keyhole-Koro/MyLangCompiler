#include "mylang/backend/codegen_internal.h"

void gen_func(CompilerContext *cc, ASTNode *node, StringBuilder *sb)
{
    ASTNode *fn = cg_as_fundef(node);
    if (!fn) return;

    char *fname = is_entry_name(fn->fundef.name) ? "__START__" : fn->fundef.name;

    // A struct or array returned by value needs a hidden destination pointer,
    // supplied by the caller in r4 and stashed in this extra frame slot for
    // `return expr;` (below) to copy through. Variadic already uses r4 for its
    // rest-argument count, so the two are mutually exclusive for now; nothing
    // upstream constructs that combination (a variadic function returning an
    // aggregate), so this is a latent restriction rather than one anything
    // hits.
    int ret_agg_size = fn->fundef.ret_type ? aggregate_type_size(cc, fn->fundef.ret_type) : 0;
    if (ret_agg_size > 0 && fn->fundef.is_variadic) {
        fprintf(stderr,
                "Codegen error: '%s' cannot both be variadic and return a "
                "struct or array by value; both need the hidden r4 argument\n",
                fn->fundef.name ? fn->fundef.name : "?");
        exit(1);
    }

    int param_count = fn->fundef.param_count;
    int fixed_param_count = fn->fundef.is_variadic ? (param_count - 1) : param_count;
    char **params = NULL;
    for (int i = 0; i < param_count; i++) {
        if (!params) params = (char**)calloc((size_t)param_count, sizeof(char*));
        params[i] = fn->fundef.params[i]->param.name;
    }

    int local_count = collect_locals(cc, fn->fundef.body, NULL);
    char **locals = NULL;
    if (local_count > 0) {
        locals = (char**)calloc((size_t)local_count, sizeof(char*));
        collect_locals(cc, fn->fundef.body, locals);
    }

    int locals_only_count = collect_local_type_info(cc, fn->fundef.body, NULL);
    cg_locals_count = param_count + locals_only_count;
    if (cg_locals_count > 0) {
        cg_locals_info = (LocalInfo*)malloc(sizeof(LocalInfo) * cg_locals_count);
        int idx = 0;
        for (int i = 0; i < param_count; i++, idx++) {
            ASTNode *p = fn->fundef.params[i];
            cg_locals_info[idx].name = p->param.name;
            if (p->param.is_rest) {
                cg_locals_info[idx].base_type = "i32";
                cg_locals_info[idx].pointer_level = 1;
                cg_locals_info[idx].type_modifiers = 0;
                cg_locals_info[idx].is_array = 0;
                cg_locals_info[idx].array_length = 0;
                cg_locals_info[idx].dims_count = 0;
                for (int d = 0; d < 8; d++) cg_locals_info[idx].dims[d] = 0;
            } else {
                set_localinfo_from_type(cc, &cg_locals_info[idx], p->param.type);
                // A struct or array parameter's slot holds one word regardless
                // (scalar_var_width_bytes already treats it that way); what
                // that word means -- the aggregate's bytes vs. a hidden
                // pointer to them -- is settled by is_byval_aggregate_param
                // wherever the parameter's address is computed
                // (emit_addr_of_var), not here.
            }
        }
        if (locals_only_count > 0) {
            collect_local_type_info(cc, fn->fundef.body, cg_locals_info + idx);
        }
    } else {
        cg_locals_info = NULL;
    }

    // One more slot, past every named local/param, to stash the hidden
    // out-pointer -- computed the same way local_offset gives each declared
    // local its own slot, just one index past the last of them, so it can
    // never collide with a real name (nothing is ever declared there).
    int frame_slots = local_count + param_count + (ret_agg_size > 0 ? 1 : 0);
    int sret_offset = ret_agg_size > 0 ? local_offset(param_count, local_count) : 0;

    sb_append(sb, "\n");
    sb_append(sb, "%s:\n", fname);
    sb_append(sb, "; prologue\n");
    sb_append(sb, "  push lr\n");
    sb_append(sb, "  push bp\n");
    sb_append(sb, "  mov bp, sp\n  addis sp, -%d\n", frame_slots * SLOT_SIZE);

    for (int i = 0; i < fixed_param_count && i < 3; i++) {
        int param_width = scalar_var_width_bytes(cc, params[i]);
        sb_append(sb, "  ; store parameter '%s' from register %s\n", params[i], arg_regs[i]);
        sb_append(sb, "  mov   r3, bp\n");
        sb_append(sb, "  addis r3, %d\n", param_offset(i));
        emit_store_width_to_addr(sb, "r3", arg_regs[i], param_width);
    }
    if (fn->fundef.is_variadic) {
        int rest_index = param_count - 1;
        sb_append(sb, "  ; store rest count from register r4\n");
        sb_append(sb, "  mov   r3, bp\n");
        sb_append(sb, "  addis r3, %d\n", param_offset(rest_index));
        sb_append(sb, "  store r3, r4\n");
    }
    if (ret_agg_size > 0) {
        sb_append(sb, "  ; store hidden out-pointer (r4) for by-value return\n");
        sb_append(sb, "  mov   r3, bp\n");
        sb_append(sb, "  addis r3, %d\n", sret_offset);
        sb_append(sb, "  store r3, r4\n");
    }

    char ret_label[32];
    snprintf(ret_label, sizeof(ret_label), "b_L_ret_%d", next_label(cc));
    cc->return_label = ret_label;
    cc->current_func = fn;
    cc->sret_active = ret_agg_size > 0;
    cc->sret_offset = sret_offset;
    cc->sret_size_bytes = ret_agg_size;

    gen_stmt(cc, fn->fundef.body, sb, params, param_count, locals, local_count);

    sb_append(sb, "%s:\n", ret_label);
    sb_append(sb, "  addis sp, %d\n", frame_slots * SLOT_SIZE);
    sb_append(sb, "; epilogue\n  pop  bp\n  pop  lr\n");

    if (strcmp(fname, "__START__") != 0)
        sb_append(sb, "  mov  pc, lr\n");
    if (strcmp(fname, "__START__") == 0)
        sb_append(sb, "  halt");

    cc->return_label = NULL;
    cc->current_func = NULL;
    cc->sret_active = false;
    cc->sret_offset = 0;
    cc->sret_size_bytes = 0;
    if (cg_locals_info) {
        free(cg_locals_info);
        cg_locals_info = NULL;
    }
    cg_locals_count = 0;
    free(locals);
    free(params);
}
