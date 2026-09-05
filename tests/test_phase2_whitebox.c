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
    parser_set_filename("<whitebox>");

    Token *tokens = lexer(buffer);
    free(buffer);
    assert(tokens);

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

static void test_generic_declaration_ast(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "struct Pair<T, U> { T first; U second; }; "
        "Pair<T, T> make_pair<T>(T value) { Pair<T, T> result; return result; } "
        "i32 main() { return 0; }",
        &tokens
    );

    assert(root->type == AST_BLOCK);
    assert(root->block.count == 1);
    assert(root->block.stmts[0]->type == AST_FUNDEF);
    assert(strcmp(root->block.stmts[0]->fundef.name, "main") == 0);

    assert(generic_template_count(parser_context_current()) == 2);
    ASTNode *pair = generic_template_at(parser_context_current(), 0);
    assert(pair && pair->type == AST_STRUCT);
    assert(strcmp(pair->struct_stmt.name, "Pair") == 0);
    assert(pair->struct_stmt.type_param_count == 2);
    assert(strcmp(pair->struct_stmt.type_params[0], "T") == 0);
    assert(strcmp(pair->struct_stmt.type_params[1], "U") == 0);
    assert(pair->struct_stmt.member_count == 2);
    assert(pair->struct_stmt.members[0]->var_decl.var_type->type == AST_TYPE);
    assert(strcmp(
        pair->struct_stmt.members[0]->var_decl.var_type->type_node.base_type->identifier.name,
        "T"
    ) == 0);

    ASTNode *make_pair = generic_template_at(parser_context_current(), 1);
    assert(make_pair && make_pair->type == AST_FUNDEF);
    assert(strcmp(make_pair->fundef.name, "make_pair") == 0);
    assert(make_pair->fundef.type_param_count == 1);
    assert(strcmp(make_pair->fundef.type_params[0], "T") == 0);
    assert(make_pair->fundef.ret_type->type == AST_TYPE);
    ASTNode *ret_base = make_pair->fundef.ret_type->type_node.base_type;
    assert(ret_base->type == AST_TYPE_GENERIC);
    assert(strcmp(ret_base->generic_type.name, "Pair") == 0);
    assert(ret_base->generic_type.arg_count == 2);
    assert(!is_user_typename(parser_context_current(), "T"));
    assert(is_user_typename(parser_context_current(), "Pair"));

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

static void test_generic_call_ast_inside_template(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "T identity<T>(T value) { return identity<T>(value); } "
        "i32 main() { return 0; }",
        &tokens
    );

    assert(generic_template_count(parser_context_current()) == 1);
    ASTNode *identity = generic_template_at(parser_context_current(), 0);
    ASTNode *ret = identity->fundef.body->block.stmts[0];
    assert(ret->type == AST_RETURN);
    assert(ret->ret.expr->type == AST_CALL);
    assert(ret->ret.expr->call.type_arg_count == 1);
    assert(ret->ret.expr->call.type_args[0]->type == AST_TYPE);

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

static void test_nested_generic_type_ast(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "struct Pair<T> { T value; }; "
        "struct Wrapper<T> { T value; }; "
        "Wrapper<Pair<T>> wrap<T>(T value) { Wrapper<Pair<T>> result; return result; } "
        "i32 main() { return 0; }",
        &tokens
    );

    assert(generic_template_count(parser_context_current()) == 3);
    ASTNode *wrap = generic_template_at(parser_context_current(), 2);
    ASTNode *outer = wrap->fundef.ret_type->type_node.base_type;
    assert(outer->type == AST_TYPE_GENERIC);
    assert(strcmp(outer->generic_type.name, "Wrapper") == 0);
    assert(outer->generic_type.arg_count == 1);
    ASTNode *inner_type = outer->generic_type.args[0];
    assert(inner_type->type == AST_TYPE);
    ASTNode *inner = inner_type->type_node.base_type;
    assert(inner->type == AST_TYPE_GENERIC);
    assert(strcmp(inner->generic_type.name, "Pair") == 0);

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

static void test_generic_prototype_ast(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "T identity<T>(T value); i32 main() { return 0; }",
        &tokens
    );

    assert(generic_template_count(parser_context_current()) == 1);
    ASTNode *identity = find_generic_function_template(parser_context_current(), "identity");
    assert(identity && identity->type == AST_FUNDEF);
    assert(identity->fundef.body == NULL);
    assert(identity->fundef.type_param_count == 1);
    assert(identity->fundef.param_count == 1);

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

static void test_exported_generic_metadata_and_namespaces(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "package collections; "
        "export struct Factory<T> { T value; }; "
        "export T Factory<T>(T value) { return value; } "
        "i32 main() { return 0; }",
        &tokens
    );

    assert(generic_template_count(parser_context_current()) == 2);
    ASTNode *type_template = find_generic_type_template(parser_context_current(), "Factory");
    ASTNode *function_template = find_generic_function_template(parser_context_current(), "Factory");
    assert(type_template && type_template->type == AST_STRUCT);
    assert(function_template && function_template->type == AST_FUNDEF);
    assert(type_template != function_template);
    assert(type_template->struct_stmt.is_exported == 1);
    assert(strcmp(type_template->struct_stmt.package, "collections") == 0);
    assert(function_template->fundef.is_exported == 1);
    assert(strcmp(function_template->fundef.package, "collections") == 0);
    assert(strcmp(type_template->struct_stmt.name, "Factory") == 0);
    assert(strcmp(function_template->fundef.name, "Factory") == 0);

    free_ast(root);
    free_tokens(tokens);
    parser_reset();
}

static void test_generic_state_reset(void) {
    Token *tokens = NULL;
    ASTNode *root = parse_source(
        "struct Box<T> { T value; }; i32 main() { return 0; }",
        &tokens
    );

    assert(generic_template_count(parser_context_current()) == 1);
    assert(find_generic_type_template(parser_context_current(), "Box") != NULL);
    assert(is_user_typename(parser_context_current(), "Box"));

    free_ast(root);
    free_tokens(tokens);
    parser_reset();

    assert(generic_template_count(parser_context_current()) == 0);
    assert(find_generic_type_template(parser_context_current(), "Box") == NULL);
    assert(!is_user_typename(parser_context_current(), "Box"));
    assert(!is_user_typename(parser_context_current(), "T"));
}

static void test_parser_context_isolation(void) {
    ParserContext imported_context;
    ParserContext *outer_context = parser_context_current();

    parser_reset();
    add_typename(outer_context, "OuterType");

    parser_context_init(&imported_context);
    assert(!is_user_typename(&imported_context, "OuterType"));
    add_typename(&imported_context, "ImportedType");
    assert(is_user_typename(&imported_context, "ImportedType"));

    assert(is_user_typename(outer_context, "OuterType"));
    assert(!is_user_typename(outer_context, "ImportedType"));

    parser_context_reset(&imported_context);
    parser_context_reset(outer_context);
}

void test_generic_instantiation(void);

int main(void) {
    test_generic_instantiation();
    test_ref_borrow_ast();
    test_ref_mut_ast();
    test_unchecked_ast();
    test_borrow_boundary_ast();
    test_ref_param_ast();
    test_loop_control_ast();
    test_case_expr_ast();
    test_generic_declaration_ast();
    test_generic_call_ast_inside_template();
    test_nested_generic_type_ast();
    test_generic_prototype_ast();
    test_exported_generic_metadata_and_namespaces();
    test_generic_state_reset();
    test_parser_context_isolation();
    printf("phase2 whitebox tests passed\n");
    return 0;
}
