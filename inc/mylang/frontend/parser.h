#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>
#include "mylang/frontend/lexer.h"
#include "mylang/ast/AST.h"

ASTNode* parse_program(Token **cur);
void parser_set_filename(const char *name);
// Reset the active parser context between independent compilation units.
void parser_reset(void);
void print_ast(ASTNode *node, int indent);
// Writes the AST to a FILE* instead of stdout.
void fprint_ast(FILE *out, ASTNode *node, int indent);
void free_ast(ASTNode *node);
void free_attributes(Attribute *attrs, int count);

/* Annotation rows the frontend recorded for the file just parsed, for
 * codegen to emit into the `annotations` collected section. */
#define ANNOTATION_MAX_ARGS 3
typedef struct {
    int is_string;   // text is the string literal; else value holds the number
    char *text;
    long value;
} AnnotationArg;
typedef struct {
    char *name;      // annotation name
    char *fn;        // annotated function's (mangled) name
    char *type;      // receiver type name, or NULL for a plain function
    int argc;
    AnnotationArg args[ANNOTATION_MAX_ARGS];
} AnnotationRow;
int annotation_row_count(void);
const AnnotationRow *annotation_row(int index);
void annotation_rows_reset(void);

#endif
