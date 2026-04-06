#include "mylang/backend/codegen_internal.h"

char *codegen(ASTNode *root)
{
    CompilerContext ctx = {0};
    CompilerContext *cc = &ctx;
    ASTNode *block = cg_as_block(root);
    StringBuilder sb;
    sb_init(&sb);

    if (block) {
        for (int i = 0; i < block->block.count; i++) {
            ASTNode *fn = cg_as_fundef(block->block.stmts[i]);
            if (fn && fn->fundef.name && fn->fundef.body) {
                note_defined_func(cc, fn->fundef.name);
            }
        }
    }
    collect_imports_from_toplevel(cc, root);
    build_codegen_toplevel_info(cc, root);
    collect_codegen_globals(cc, root);
    emit_codegen_functions(cc, root, &sb);

    if (cg_data_sb_inited) {
        sb_append(&sb, "\n; data\n");
        sb_append(&sb, "%s", cg_data_sb.buf);
    }

    char *result = prepend_codegen_imports(cc, &sb);
    cleanup_codegen_context(cc);
    sb_free(&sb);
    return result;
}
