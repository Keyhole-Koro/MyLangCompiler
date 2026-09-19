#ifndef MYLANG_FRONTEND_PARSER_ANNOT_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_ANNOT_INTERNAL_H

#include "mylang/frontend/parser_internal.h"

/* Annotation lowering: turns `@a(args)` on a function or method into a call
 * to the function `a` in the module's generated __annotations_init(). Also
 * provides the plain-function handler trampoline DOM lowering uses. See
 * parser_lower_annot.c. */

void lower_annotations(ParserContext *context, ASTNode *program);

/* Parses generated MyLang top-level source and appends its declarations to
 * `program`, registering functions/methods as the ordinary parser would. */
void parse_generated_toplevels(ParserContext *context, ASTNode *program, const char *source);

/* For a plain local function with fewer than three parameters, returns the
 * name of a trampoline adapting it to the handler ABI; for one that already
 * takes three, the function's own name. NULL when `function_name` is not a
 * local function (an imported one, or a variable holding a handler), in
 * which case the value is passed through unchanged. */
const char *ensure_function_trampoline(ParserContext *context, ASTNode *program,
                                       const char *function_name, int line, int col);

/* Appends the defaults a positional call left out (see parser_lower_annot.c). */
void fill_default_arguments(ParserContext *context, ASTNode *program);

/* The declaration a call by (post-rewrite) name resolves to: a function in
 * this file, else an exported function of an imported module. NULL when
 * unknown. Borrowed. */
ASTNode *callee_declaration(ParserContext *context, ASTNode *program, const char *name);

#endif
