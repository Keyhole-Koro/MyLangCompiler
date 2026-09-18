#ifndef MYLANG_FRONTEND_PARSER_APP_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_APP_INTERNAL_H

#include "mylang/frontend/parser_internal.h"

/* Attribute lowering (`@app` and the method attributes that go with it) and
 * the handler trampolines shared with DOM lowering. See parser_lower_app.c. */

void lower_app_program(ParserContext *context, ASTNode *program);

/* Parses generated MyLang top-level source and appends its declarations to
 * `program`, registering functions/methods as the ordinary parser would. */
void parse_generated_toplevels(ParserContext *context, ASTNode *program, const char *source);

/* Returns the name of `void <Type>__<method>__tramp(i32 owner, i32 id, i32 arg)`,
 * generating it on first use. The method must take a pointer receiver and at
 * most (i32 id, i32 arg) after it. */
const char *ensure_method_trampoline(ParserContext *context, ASTNode *program,
                                     const char *type_name, const char *method_name,
                                     int line, int col);

/* For a plain local function with fewer than three parameters, returns the
 * name of a trampoline adapting it to the handler ABI; for one that already
 * takes three, the function's own name. NULL when `function_name` is not a
 * local function (an imported one, or a variable holding a handler), in
 * which case the value is passed through unchanged. */
const char *ensure_function_trampoline(ParserContext *context, ASTNode *program,
                                       const char *function_name, int line, int col);

/* Appends the defaults a positional call left out (see parser_lower_app.c). */
void fill_default_arguments(ParserContext *context, ASTNode *program);

#endif
