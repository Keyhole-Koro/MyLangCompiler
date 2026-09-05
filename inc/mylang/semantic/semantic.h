#ifndef MYLANG_SEMANTIC_H
#define MYLANG_SEMANTIC_H

#include "mylang/ast/AST.h"

typedef struct FrontendSession FrontendSession;

typedef enum {
    SEMANTIC_SAFETY_DEFAULT = 0,
    SEMANTIC_SAFETY_STRICT
} SemanticSafetyProfile;

void semantic_set_filename(const char *name);
void semantic_set_warnings_as_errors(int enabled);
void semantic_set_safety_profile(SemanticSafetyProfile profile);
SemanticSafetyProfile semantic_get_safety_profile(void);
int semantic_check(ASTNode *root);
int semantic_check_with_session(ASTNode *root, FrontendSession *session);

#endif
