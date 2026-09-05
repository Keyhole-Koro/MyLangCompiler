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
    ASTNode *tpl = find_generic_type_template("Box");
    assert(strcmp(tpl->struct_stmt.members[0]->var_decl.var_type->type_node.base_type->identifier.name, "T") == 0);
    ASTNode *read = find_generic_function_template("read");
    assert(read->fundef.params[0]->param.type->type_node.ref_kind == REFKIND_SHARED);
    assert(strcmp(read->fundef.params[0]->param.type->type_node.base_type->identifier.name, "T") == 0);

    /* Program and templates can be cloned and freed independently. */
    ASTNode *copy = ast_clone(program);
    free_ast(program);
    parser_reset();
    assert_concrete(&copy, NULL);
    free_ast(copy);
    free_tokens(tokens);
}
