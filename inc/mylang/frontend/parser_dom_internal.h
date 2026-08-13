#ifndef MYLANG_FRONTEND_PARSER_DOM_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_DOM_INTERNAL_H

#include "mylang/frontend/parser_internal.h"

/* The DOM syntax extension: parsing `.dom.mln` elements and lowering them into
 * ordinary calls. Nothing outside these three translation units and the
 * parse_program driver needs any of it. */

ASTNode *parse_dom_element(Token **cur);

// Signature backing a DOM element: the name to call and its parameter names,
// which give properties their argument order.
typedef struct {
    char *call_name;
    char **param_names;
    int param_count;
} DomSignature;

int dom_signature_lookup(ASTNode *program, const char *tag, DomSignature *out);
void dom_signature_free(DomSignature *sig);

// Rewrites DOM elements into OS DOM API calls hoisted ahead of their statement.
void lower_dom_block(ASTNode *block);
void ensure_no_dom_elements(ASTNode *node);
void dom_lowering_reset(void);
void dom_lowering_set_program(ASTNode *program);

#endif
