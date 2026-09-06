#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "mylang/driver/driver_internal.h"
#include "mylang/frontend/parser_internal.h"

static void assert_concrete(ASTNode **slot, void *unused) {
    (void)unused;
    ASTNode *node = *slot;
    if (!node) return;
    assert(node->type != AST_TYPE_GENERIC);
    if (node->type == AST_CALL) assert(node->call.type_arg_count == 0);
    if (node->type == AST_FUNDEF) assert(node->fundef.type_param_count == 0);
    if (node->type == AST_STRUCT) assert(node->struct_stmt.type_param_count == 0);
    ast_visit_children(node, assert_concrete, NULL);
}

void test_generic_instantiation(void) {
    const char *source =
        "struct Box<T> { T value; }; "
        "T identity<T>(T value) { return value; } "
        "T *address<T>(T *value) { return value; } "
        "T read<T>(ref T value) { return *value; } "
        "typedef i32 Int; "
        "i32 main() { Box<i32> a; Box<Int> b; Box<char> c; "
        "i32 n = identity<i32>(3); i32 m = identity<Int>(4); "
        "i32 *p = address<i32>(&n); return read<i32>(&m); }";
    parser_reset();
    char *buffer = strdup(source);
    Token *tokens = lexer(buffer);
    free(buffer);
    Token *cur = tokens;
    ASTNode *program = parse_program(&cur);
    assert_concrete(&program, NULL);
    assert(semantic_check(program));
    int structs = 0, functions = 0;
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        structs += node->type == AST_STRUCT;
        functions += node->type == AST_FUNDEF;
    }
    assert(structs == 2); /* Box<Int> and Box<i32> share a specialization. */
    assert(functions == 4); /* main, identity<i32>, address<i32>, read<i32>. */
    ASTNode *tpl = find_generic_type_template(parser_context_current(), "Box");
    assert(strcmp(tpl->struct_stmt.members[0]->var_decl.var_type->type_node.base_type->identifier.name, "T") == 0);
    ASTNode *read = find_generic_function_template(parser_context_current(), "read");
    assert(read->fundef.params[0]->param.type->type_node.ref_kind == REFKIND_SHARED);
    assert(strcmp(read->fundef.params[0]->param.type->type_node.base_type->identifier.name, "T") == 0);

    /* Program and templates can be cloned and freed independently. */
    ASTNode *copy = ast_clone(program);
    free_ast(program);
    parser_reset();
    assert_concrete(&copy, NULL);
    free_ast(copy);
    free_tokens(tokens);

    const char *payload_source =
        "enum Result<T, E> { Ok(T), Err(E) }; "
        "i32 main() { Result<i32, char> value; return sizeof(value); }";
    parser_reset();
    buffer = strdup(payload_source);
    tokens = lexer(buffer);
    free(buffer);
    cur = tokens;
    program = parse_program(&cur);
    assert_concrete(&program, NULL);
    assert(semantic_check(program));

    ASTNode *result_template = find_generic_type_template(parser_context_current(), "Result");
    assert(result_template && result_template->type == AST_ENUM);
    assert(result_template->enum_stmt.has_payloads);
    assert(result_template->enum_stmt.type_param_count == 2);
    assert(result_template->enum_stmt.member_count == 2);
    assert(result_template->enum_stmt.members[0]->enum_member.payload_type != NULL);

    ASTNode *result_layout = NULL;
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (node->type == AST_STRUCT && strncmp(node->struct_stmt.name, "__mlg_s_", 8) == 0) {
            result_layout = node;
            break;
        }
    }
    assert(result_layout);
    assert(result_layout->struct_stmt.member_count == 3);
    assert(strcmp(result_layout->struct_stmt.members[0]->var_decl.name, "__tag") == 0);
    assert(strcmp(result_layout->struct_stmt.members[1]->var_decl.name, "Ok") == 0);
    assert(strcmp(result_layout->struct_stmt.members[2]->var_decl.name, "Err") == 0);

    char *assembly = codegen(program);
    assert(assembly != NULL);
    assert(strstr(assembly, "movi r1, 9") != NULL);
    free(assembly);

    free_ast(program);
    parser_reset();
    free_tokens(tokens);
}
