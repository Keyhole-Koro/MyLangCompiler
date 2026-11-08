#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mylang/driver/driver_internal.h"
#include "mylang/frontend/parser_internal.h"
#include "mylang/semantic/semantic_types.h"

static ASTNode *parse_source(const char *source, Token **out_tokens) {
    char *buffer = strdup(source);
    assert(buffer);

    parser_reset();
    parser_set_filename("<parser-ast-test>");

    Token *tokens = lexer(buffer);
    free(buffer);
    assert(tokens);

    token_head = tokens;
    Token *cur = tokens;
    ASTNode *root = parse_program(&cur);
    assert(root);

    if (out_tokens) *out_tokens = tokens;
    return root;
}

static ASTNode *first_function(ASTNode *root) {
    assert(root);
    assert(root->type == AST_BLOCK);
    assert(root->block.count > 0);
    ASTNode *fn = root->block.stmts[0];
    assert(fn->type == AST_FUNDEF);
    return fn;
}

static void test_ref_borrow_ast(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "i32 main() { i32 x = 7; ref i32 rx = &x; return *rx; }",
        &tokens
    );

    ASTNode *fn = first_function(root);
    ASTNode *body = fn->fundef.body;
    assert(body->type == AST_BLOCK);
    assert(body->block.count == 3);

    ASTNode *decl = body->block.stmts[1];
    assert(decl->type == AST_VAR_DECL);
    assert(decl->var_decl.is_mut == 0);
    assert(decl->var_decl.var_type->type == AST_TYPE);
    assert(decl->var_decl.var_type->type_node.ref_kind == REFKIND_SHARED);
    assert(decl->var_decl.init->type == AST_BORROW);
    assert(decl->var_decl.init->borrow.expr->type == AST_IDENTIFIER);

    SemanticTypeInfo ti = {0};
    assert(semantic_typeinfo_from_type_ast(decl->var_decl.var_type, &ti) == 1);
    assert(ti.ref_kind == REFKIND_SHARED);

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

static void test_ref_mut_ast(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "i32 main() { i32 x = 7; { ref mut i32 rx = &mut x; *rx = 9; } return x; }",
        &tokens
    );

    ASTNode *fn = first_function(root);
    ASTNode *body = fn->fundef.body;
    assert(body->type == AST_BLOCK);
    assert(body->block.count == 3);

    ASTNode *owner = body->block.stmts[0];
    assert(owner->type == AST_VAR_DECL);
    assert(owner->var_decl.is_mut == 0);

    ASTNode *inner = body->block.stmts[1];
    assert(inner->type == AST_BLOCK);
    assert(inner->block.count == 2);

    ASTNode *decl = inner->block.stmts[0];
    assert(decl->type == AST_VAR_DECL);
    assert(decl->var_decl.var_type->type == AST_TYPE);
    assert(decl->var_decl.var_type->type_node.ref_kind == REFKIND_MUT);
    assert(decl->var_decl.init->type == AST_BORROW_MUT);

    ASTNode *assign_stmt = inner->block.stmts[1];
    assert(assign_stmt->type == AST_EXPR_STMT);
    assert(assign_stmt->expr_stmt.expr->type == AST_ASSIGN);
    assert(assign_stmt->expr_stmt.expr->assign.left->type == AST_UNARY);

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

static void test_unchecked_ast(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "i32 main() { i32 x = 7; unchecked { i32* p = &x; *p = 9; } return x; }",
        &tokens
    );

    ASTNode *fn = first_function(root);
    ASTNode *body = fn->fundef.body;
    assert(body->type == AST_BLOCK);
    assert(body->block.count == 3);

    ASTNode *unchecked_node = body->block.stmts[1];
    assert(unchecked_node->type == AST_UNCHECKED);
    assert(unchecked_node->unchecked_block.body);
    assert(unchecked_node->unchecked_block.body->type == AST_BLOCK);
    assert(unchecked_node->unchecked_block.body->block.count == 2);

    ASTNode *raw_decl = unchecked_node->unchecked_block.body->block.stmts[0];
    assert(raw_decl->type == AST_VAR_DECL);
    assert(raw_decl->var_decl.var_type->type == AST_TYPE);
    assert(raw_decl->var_decl.var_type->type_node.pointer_level == 1);
    assert(raw_decl->var_decl.var_type->type_node.ref_kind == REFKIND_NONE);
    assert(raw_decl->var_decl.init->type == AST_UNARY);
    assert(raw_decl->var_decl.init->unary.op == AMPERSAND);

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

static void test_borrow_boundary_ast(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "i32 main() { i32 x = 7; ref i32 rx = &x; unchecked { i32* p = &x; } return *rx; }",
        &tokens
    );

    ASTNode *fn = first_function(root);
    ASTNode *body = fn->fundef.body;
    assert(body->type == AST_BLOCK);
    assert(body->block.count == 4);

    ASTNode *safe_decl = body->block.stmts[1];
    assert(safe_decl->type == AST_VAR_DECL);
    assert(safe_decl->var_decl.init->type == AST_BORROW);

    ASTNode *unchecked_node = body->block.stmts[2];
    assert(unchecked_node->type == AST_UNCHECKED);
    ASTNode *raw_decl = unchecked_node->unchecked_block.body->block.stmts[0];
    assert(raw_decl->type == AST_VAR_DECL);
    assert(raw_decl->var_decl.init->type == AST_UNARY);
    assert(raw_decl->var_decl.init->unary.op == AMPERSAND);

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

static void test_ref_param_ast(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "i32 load(ref mut i32 rx) { *rx = *rx + 1; return *rx; }",
        &tokens
    );

    ASTNode *fn = first_function(root);
    assert(fn->fundef.param_count == 1);

    ASTNode *param = fn->fundef.params[0];
    assert(param->type == AST_PARAM);
    assert(param->param.is_mut == 0);
    assert(param->param.type);
    assert(param->param.type->type == AST_TYPE);
    assert(param->param.type->type_node.ref_kind == REFKIND_MUT);

    SemanticTypeInfo ti = {0};
    assert(semantic_typeinfo_from_type_ast(param->param.type, &ti) == 1);
    assert(ti.ref_kind == REFKIND_MUT);

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

static void test_loop_control_ast(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "i32 main() { while (1) { continue; break; } return 0; }",
        &tokens
    );

    ASTNode *fn = first_function(root);
    ASTNode *body = fn->fundef.body;
    assert(body->type == AST_BLOCK);
    assert(body->block.count == 2);

    ASTNode *loop = body->block.stmts[0];
    assert(loop->type == AST_WHILE);
    assert(loop->while_stmt.body->type == AST_BLOCK);
    assert(loop->while_stmt.body->block.count == 2);
    assert(loop->while_stmt.body->block.stmts[0]->type == AST_CONTINUE);
    assert(loop->while_stmt.body->block.stmts[1]->type == AST_BREAK);

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

static void test_case_expr_ast(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "i32 main() { i32 x = 2; i32 y = case x of { 0 -> 10; 2 -> 30; _ -> -1; }; return y; }",
        &tokens
    );

    ASTNode *fn = first_function(root);
    ASTNode *body = fn->fundef.body;
    assert(body->type == AST_BLOCK);
    assert(body->block.count == 3);

    ASTNode *decl = body->block.stmts[1];
    assert(decl->type == AST_VAR_DECL);
    assert(decl->var_decl.init->type == AST_CASE);
    assert(decl->var_decl.init->case_expr.case_count == 2);
    assert(decl->var_decl.init->case_expr.default_expr != NULL);

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

int main(void) {
    test_ref_borrow_ast();
    test_ref_mut_ast();
    test_unchecked_ast();
    test_borrow_boundary_ast();
    test_ref_param_ast();
    test_loop_control_ast();
    test_case_expr_ast();
    printf("parser AST tests passed\n");
    return 0;
}
