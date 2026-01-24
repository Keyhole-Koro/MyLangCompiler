#ifndef MASM_GEN_H
#define MASM_GEN_H

#include <stdio.h>

#include "AST.h"
#include "parser.h"
#include "stringBuilder.h"

char *codegen(ASTNode *root);
// Set the entry function name that maps to __START__ (default: "main").
void codegen_set_entry(const char *name);

#endif
