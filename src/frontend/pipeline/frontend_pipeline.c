#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_dom_internal.h"
#include "mylang/frontend/parser_rewrite_internal.h"
#include "mylang/frontend/module.h"

static void append_hoisted_functions(ParserContext *context, ASTNode *program) {
    ParserLoweringState *lowering = &context->lowering;
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

static void lower_program(ParserContext *context, ASTNode *program) {
    char *scope[128] = {0};

    instantiate_generics(context, program);

    dom_lowering_reset(context);
    dom_lowering_set_program(context, program);
    lower_dom_block(context, program);
    ensure_no_dom_elements(context, program);

    lower_fun_literals_block(context, program, "g", NULL, 0);
    append_hoisted_functions(context, program);
    ensure_no_fun_literals(program);

    rewrite_node(context, program, scope, 0);
}

ASTNode *parse_program(Token **cur) {
    ParserContext *context = parser_context_current();
    if (!context->session) context->session = frontend_session_current();
    context->is_root_module = 1;
    ASTNode *program = parse_program_syntax(context, cur);
    lower_program(context, program);
    return program;
}
