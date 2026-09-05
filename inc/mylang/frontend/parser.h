#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>
#include "mylang/frontend/lexer.h"
#include "mylang/ast/AST.h"

ASTNode* parse_program(Token **cur);
void parser_set_filename(const char *name);
int parser_name_has_imported_package_prefix(const char *name);
int parser_get_imported_package_count(void);
const char *parser_get_imported_package(int index);
// Reset the active parser context between independent compilation units.
void parser_reset(void);
void print_ast(ASTNode *node, int indent);
// Writes the AST to a FILE* instead of stdout.
void fprint_ast(FILE *out, ASTNode *node, int indent);
void free_ast(ASTNode *node);

#endif
