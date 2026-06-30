#ifndef MYLANG_SEMANTIC_H
#define MYLANG_SEMANTIC_H

#include "mylang/ast/AST.h"

void semantic_set_filename(const char *name);
void semantic_set_warnings_as_errors(int enabled);
int semantic_check(ASTNode *root);

#endif
