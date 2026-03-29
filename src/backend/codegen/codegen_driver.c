#include "mylang/backend/codegen_internal.h"

char *codegen(ASTNode *root)
{
    CompilerContext ctx = {0};
    CompilerContext *cc = &ctx;
    StringBuilder sb;
    sb_init(&sb);

    if (root && root->type == AST_BLOCK) {
        for (int i = 0; i < root->block.count; i++) {
            ASTNode *n = root->block.stmts[i];
            if (n->type == AST_FUNDEF && n->fundef.name) {
                note_defined_func(cc, n->fundef.name);
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
