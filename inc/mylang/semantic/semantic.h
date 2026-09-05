#ifndef MYLANG_SEMANTIC_H
#define MYLANG_SEMANTIC_H

#include "mylang/ast/AST.h"

typedef enum {
    SEMANTIC_SAFETY_DEFAULT = 0,
    SEMANTIC_SAFETY_STRICT
} SemanticSafetyProfile;

void semantic_set_filename(const char *name);
void semantic_set_warnings_as_errors(int enabled);
void semantic_set_safety_profile(SemanticSafetyProfile profile);
SemanticSafetyProfile semantic_get_safety_profile(void);
void semantic_add_imported_package(const char *name);
void semantic_reset_imported_packages(void);
int semantic_check(ASTNode *root);

#endif
