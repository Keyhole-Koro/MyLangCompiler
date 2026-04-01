#include "mylang/semantic/semantic_internal.h"

static void walk_case_items(SemanticContext *ctx, ASTNode *node) {
    for (int i = 0; i < node->case_expr.case_count; i++) {
        semantic_walk_ast(ctx, node->case_expr.cases[i].key);
        semantic_walk_ast(ctx, node->case_expr.cases[i].expr);
    }
    semantic_walk_ast(ctx, node->case_expr.default_expr);
}

static void walk_params(SemanticContext *ctx, ASTNode **params, int param_count) {
    for (int i = 0; i < param_count; i++) {
        semantic_walk_ast(ctx, params[i]);
    }
}

static void walk_block_items(SemanticContext *ctx, ASTNode **items, int count) {
    for (int i = 0; i < count; i++) {
        semantic_walk_ast(ctx, items[i]);
    }
}

void semantic_walk_ast(SemanticContext *ctx, ASTNode *node) {
    if (!ctx || !node) return;

    switch (node->type) {
    case AST_NUMBER:
    case AST_IDENTIFIER:
    case AST_STRING_LITERAL:
    case AST_CHAR_LITERAL:
    case AST_BREAK:
    case AST_CONTINUE:
        break;
    case AST_BINARY:
        semantic_walk_ast(ctx, node->binary.left);
        semantic_walk_ast(ctx, node->binary.right);
        break;
    case AST_ASSIGN:
        semantic_walk_ast(ctx, node->assign.left);
        semantic_walk_ast(ctx, node->assign.right);
        break;
    case AST_TYPE:
        semantic_walk_ast(ctx, node->type_node.base_type);
        break;
    case AST_TYPE_ARRAY:
        semantic_walk_ast(ctx, node->type_array.element_type);
        break;
    case AST_VAR_DECL:
        semantic_walk_ast(ctx, node->var_decl.var_type);
        semantic_walk_ast(ctx, node->var_decl.init);
        break;
    case AST_UNARY:
        semantic_walk_ast(ctx, node->unary.operand);
        break;
    case AST_CAST:
        semantic_walk_ast(ctx, node->cast.type);
        semantic_walk_ast(ctx, node->cast.expr);
        break;
    case AST_EXPR_STMT:
        semantic_walk_ast(ctx, node->expr_stmt.expr);
        break;
    case AST_IF:
        semantic_walk_ast(ctx, node->if_stmt.cond);
        semantic_walk_ast(ctx, node->if_stmt.then_stmt);
        semantic_walk_ast(ctx, node->if_stmt.else_stmt);
        break;
    case AST_RETURN:
        semantic_walk_ast(ctx, node->ret.expr);
        break;
    case AST_YIELD:
        semantic_walk_ast(ctx, node->yield_stmt.expr);
        break;
    case AST_BLOCK:
        walk_block_items(ctx, node->block.stmts, node->block.count);
        break;
    case AST_STMT_EXPR:
        semantic_walk_ast(ctx, node->stmt_expr.block);
        break;
    case AST_FUN_LITERAL:
        walk_params(ctx, node->fun_literal.params, node->fun_literal.param_count);
        semantic_walk_ast(ctx, node->fun_literal.ret_type);
        semantic_walk_ast(ctx, node->fun_literal.body);
        break;
    case AST_FUNDEF:
        semantic_walk_ast(ctx, node->fundef.ret_type);
        walk_params(ctx, node->fundef.params, node->fundef.param_count);
        semantic_walk_ast(ctx, node->fundef.body);
        break;
    case AST_PARAM:
        semantic_walk_ast(ctx, node->param.type);
        break;
    case AST_CALL:
        walk_block_items(ctx, node->call.args, node->call.arg_count);
        break;
    case AST_WHILE:
        semantic_walk_ast(ctx, node->while_stmt.cond);
        semantic_walk_ast(ctx, node->while_stmt.body);
        break;
    case AST_FOR:
        semantic_walk_ast(ctx, node->for_stmt.init);
        semantic_walk_ast(ctx, node->for_stmt.cond);
        semantic_walk_ast(ctx, node->for_stmt.inc);
        semantic_walk_ast(ctx, node->for_stmt.body);
        break;
    case AST_TYPEDEF:
        semantic_walk_ast(ctx, node->typedef_stmt.src_type);
        break;
    case AST_STRUCT:
        walk_block_items(ctx, node->struct_stmt.members, node->struct_stmt.member_count);
        break;
    case AST_STRUCT_MEMBER:
        break;
    case AST_TYPEDEF_STRUCT:
        walk_block_items(ctx, node->typedef_struct.members, node->typedef_struct.member_count);
        break;
    case AST_MEMBER_ACCESS:
        semantic_walk_ast(ctx, node->member_access.lhs);
        break;
    case AST_ARROW_ACCESS:
        semantic_walk_ast(ctx, node->arrow_access.lhs);
        break;
    case AST_DO_WHILE:
        semantic_walk_ast(ctx, node->do_while_stmt.cond);
        semantic_walk_ast(ctx, node->do_while_stmt.body);
        break;
    case AST_INIT_LIST:
        walk_block_items(ctx, node->init_list.elements, node->init_list.count);
        break;
    case AST_SIZEOF:
        semantic_walk_ast(ctx, node->sizeof_expr.expr);
        break;
    case AST_TERNARY:
        semantic_walk_ast(ctx, node->ternary.cond);
        semantic_walk_ast(ctx, node->ternary.then_expr);
        semantic_walk_ast(ctx, node->ternary.else_expr);
        break;
    case AST_IMPORT:
        break;
    case AST_CASE:
        semantic_walk_ast(ctx, node->case_expr.target);
        walk_case_items(ctx, node);
        break;
    default:
        semantic_error_at(ctx, semantic_location_unknown(),
                          "semantic walker encountered unknown AST node type %d", node->type);
        break;
    }
}
