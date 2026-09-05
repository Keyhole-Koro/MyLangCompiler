#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_dom_internal.h"
#include "mylang/frontend/parser_rewrite_internal.h"

static void append_hoisted_functions(ASTNode *program) {
    ParserLoweringState *lowering = &parser_context_current()->lowering;
    if (lowering->hoisted_function_count == 0) return;

    program->block.stmts = realloc(
        program->block.stmts,
        sizeof(ASTNode *) * (program->block.count + lowering->hoisted_function_count)
    );
    for (int i = 0; i < lowering->hoisted_function_count; i++) {
        program->block.stmts[program->block.count + i] = lowering->hoisted_functions[i];
    }
    program->block.count += lowering->hoisted_function_count;
    free(lowering->hoisted_functions);
    lowering->hoisted_functions = NULL;
    lowering->hoisted_function_count = 0;
}

static void lower_program(ASTNode *program) {
    char *scope[128] = {0};

    instantiate_generics(program);

    dom_lowering_reset();
    dom_lowering_set_program(program);
    lower_dom_block(program);
    ensure_no_dom_elements(program);

    lower_fun_literals_block(program, "g", NULL, 0);
    append_hoisted_functions(program);
    ensure_no_fun_literals(program);

    rewrite_node(program, scope, 0);
}

ASTNode *parse_program(Token **cur) {
    ASTNode *program = parse_program_syntax(cur);
    lower_program(program);
    return program;
}
