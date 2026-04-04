#ifndef MYLANG_SEMANTIC_H
#define MYLANG_SEMANTIC_H

#include "mylang/ast/AST.h"

void semantic_set_filename(const char *name);
int semantic_check(ASTNode *root);

#endif
