#ifndef MYLANG_SEMANTIC_H
#define MYLANG_SEMANTIC_H

#include "mylang/ast/AST.h"

typedef struct FrontendSession FrontendSession;

typedef enum {
    SEMANTIC_SAFETY_CHECKED = 0, /* raw-pointer operations are reported */
    SEMANTIC_SAFETY_UNSAFE       /* an `.unsafe.mln` source: they are allowed */
} SemanticSafetyProfile;

void semantic_set_filename(const char *name);
void semantic_set_warnings_as_errors(int enabled);
void semantic_set_safety_profile(SemanticSafetyProfile profile);
int semantic_check_with_session(ASTNode *root, FrontendSession *session);

#endif
