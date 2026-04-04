#include "mylang/backend/codegen_internal.h"

static void gen_array_init(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
                           char **params, int param_count,
                           char **locals, int local_count) {
    ASTNode *vtype = node->var_decl.var_type;
    sb_append(sb, "  ; init array '%s'\n", node->var_decl.name);
    emit_addr_of_var(cc, sb, node->var_decl.name, "r3", params, param_count, locals, local_count);

    int elem_size = array_element_size_bytes(vtype);
    int is_byte_elem = (elem_size == 1);
    int total_elems = array_total_elements(vtype);

    if (node->var_decl.init->type == AST_STRING_LITERAL &&
        vtype->type_array.element_type &&
        vtype->type_array.element_type->type != AST_TYPE_ARRAY) {
        const char *str = node->var_decl.init->string_literal.value ? node->var_decl.init->string_literal.value : "";
        int len = (int)strlen(str);
        int total = total_elems > 0 ? total_elems : (len + 1);
        for (int i = 0; i < total; i++) {
            unsigned char val = 0;
            if (i < len) {
                val = (unsigned char)str[i];
            }
            int offset = elem_size * i;
            sb_append(sb, "  movi r1, %u\n", (unsigned)val);
            if (offset == 0) {
                emit_store_to_addr(sb, "r3", "r1", 1);
            } else {
                sb_append(sb, "  mov r2, r3\n");
                sb_append(sb, "  addis r2, %d\n", offset);
                emit_store_to_addr(sb, "r2", "r1", 1);
            }
        }
        return;
    }

    if (node->var_decl.init->type == AST_INIT_LIST) {
        int count = node->var_decl.init->init_list.count;
        int total = total_elems > 0 ? total_elems : count;
        int limit = count < total ? count : total;
        for (int i = 0; i < limit; i++) {
            gen_expr(cc, node->var_decl.init->init_list.elements[i], sb, "r1", params, param_count, locals, local_count);
            int offset = elem_size * i;
            if (offset == 0) {
                emit_store_to_addr(sb, "r3", "r1", is_byte_elem);
            } else {
                sb_append(sb, "  mov r2, r3\n");
                sb_append(sb, "  addis r2, %d\n", offset);
                emit_store_to_addr(sb, "r2", "r1", is_byte_elem);
            }
        }
        if (total > limit) {
            sb_append(sb, "  movi r1, 0\n");
            for (int i = limit; i < total; i++) {
                int offset = elem_size * i;
                if (offset == 0) {
                    emit_store_to_addr(sb, "r3", "r1", is_byte_elem);
                } else {
                    sb_append(sb, "  mov r2, r3\n");
                    sb_append(sb, "  addis r2, %d\n", offset);
                    emit_store_to_addr(sb, "r2", "r1", is_byte_elem);
                }
            }
        }
    }
}

void gen_stmt(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
              char **params, int param_count,
              char **locals, int local_count)
{
    gen_stmt_internal(cc, node, sb, params, param_count, locals, local_count,
                      NULL, NULL);
}

void gen_stmt_internal(CompilerContext *cc, ASTNode *node, StringBuilder *sb,
                       char **params, int param_count,
                       char **locals, int local_count,
                       const char *break_label,
                       const char *continue_label)
{
    switch (node->type)
    {
    case AST_VAR_DECL:
        if (node->var_decl.init)
        {
            ASTNode *vtype = node->var_decl.var_type;
            if (vtype && vtype->type == AST_TYPE_ARRAY &&
                (node->var_decl.init->type == AST_INIT_LIST || node->var_decl.init->type == AST_STRING_LITERAL)) {
                gen_array_init(cc, node, sb, params, param_count, locals, local_count);
            } else {
                gen_expr(cc, node->var_decl.init, sb, "r1", params, param_count, locals, local_count);
                emit_store_var(cc, sb, node->var_decl.name, "r1", params, param_count, locals, local_count);
            }
        }
        break;
    case AST_UNARY:
        emit_unary_inc_dec(cc, node, sb, "r1", params, param_count, locals, local_count);
        break;
    case AST_ASSIGN:
        gen_assign(cc, node, sb, params, param_count, locals, local_count, "r1");
        break;
    case AST_BREAK:
        if (break_label)
            sb_append(sb, "  jmp %s\n", break_label);
        else
            sb_append(sb, "  ; error: break used outside loop\n");
        break;
    case AST_CONTINUE:
        if (continue_label)
            sb_append(sb, "  jmp %s\n", continue_label);
        else
            sb_append(sb, "  ; error: continue used outside loop\n");
        break;
    case AST_EXPR_STMT:
        gen_expr(cc, node->expr_stmt.expr, sb, "r1", params, param_count, locals, local_count);
        break;
    case AST_IF:
        gen_if(cc, node, sb, params, param_count, locals, local_count, break_label, continue_label);
        break;
    case AST_FOR:
        gen_for(cc, node, sb, params, param_count, locals, local_count,
                break_label, continue_label);
        break;
    case AST_WHILE:
        gen_while(cc, node, sb, params, param_count, locals, local_count,
                  break_label, continue_label);
        break;
    case AST_DO_WHILE:
        gen_do_while(cc, node, sb, params, param_count, locals, local_count,
                     break_label, continue_label);
        break;
    case AST_RETURN:
        gen_expr(cc, node->ret.expr, sb, "r1", params, param_count, locals, local_count);
        sb_append(sb, "  \n; return\n");
        if (cc->return_label)
            sb_append(sb, "  jmp %s\n", cc->return_label);
        break;
    case AST_YIELD:
        gen_expr(cc, node->yield_stmt.expr, sb, "r1", params, param_count, locals, local_count);
        break;
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++)
        {
            gen_stmt_internal(cc, node->block.stmts[i], sb, params, param_count, locals, local_count,
                              break_label, continue_label);
        }
        break;
    case AST_UNCHECKED:
        gen_stmt_internal(cc, node->unchecked_block.body, sb, params, param_count, locals, local_count,
                          break_label, continue_label);
        break;
    case AST_IMPORT:
        break;
    default:
        fprintf(stderr, "Codegen error: unknown stmt node %s\n", astType2str(node->type));
        exit(1);
    }
}
