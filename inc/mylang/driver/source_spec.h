#ifndef MYLANG_DRIVER_SOURCE_SPEC_H
#define MYLANG_DRIVER_SOURCE_SPEC_H

#include <stdbool.h>

#define MYLANG_SOURCE_SPEC_ERROR_CAP 160

typedef enum {
    MYLANG_SYNTAX_CORE = 0,
    MYLANG_SYNTAX_DOM
} MyLangSyntaxProfile;

typedef enum {
    MYLANG_SAFETY_DEFAULT = 0,
    MYLANG_SAFETY_STRICT
} MyLangSafetyProfile;

typedef struct {
    MyLangSyntaxProfile syntax;
    MyLangSafetyProfile safety;
} MyLangSourceSpec;

typedef struct {
    bool ok;
    MyLangSourceSpec spec;
    char error[MYLANG_SOURCE_SPEC_ERROR_CAP];
} MyLangSourceSpecResult;

/*
 * Parse a canonical MyLang source filename.
 *
 * Accepted forms:
 *   name.mln
 *   name.safe.mln
 *   name.dom.mln
 *   name.dom.safe.mln
 *
 * Modifier order is canonical and enforced: syntax modifiers precede semantic
 * policy modifiers. Unknown and duplicate modifiers are rejected. The legacy
 * .mlx extension is intentionally unsupported.
 */
MyLangSourceSpecResult mylang_source_spec_parse(const char *path);

const char *mylang_syntax_profile_name(MyLangSyntaxProfile profile);
const char *mylang_safety_profile_name(MyLangSafetyProfile profile);

#endif
