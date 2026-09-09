#ifndef MASM_GEN_H
#define MASM_GEN_H

#include <stdio.h>

#include "mylang/ast/AST.h"
#include "mylang/frontend/parser.h"
#include "mylang/support/stringBuilder.h"

typedef struct FrontendSession FrontendSession;

char *codegen(ASTNode *root);
char *codegen_with_session(ASTNode *root, FrontendSession *session);
// Set the entry function name that maps to __START__ (default: "main").
void codegen_set_entry(const char *name);
void codegen_set_source_path(const char *path);
// Redirect direct calls while preserving bare function values. Each entry is
// `source=destination`; this is consumed by test build tooling.
void codegen_set_call_redirects(const char **redirects, int count);
const char *codegen_redirect_call_target(const char *name);

#endif
