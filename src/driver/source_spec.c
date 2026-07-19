#include "mylang/driver/source_spec.h"

#include <stdio.h>
#include <string.h>

static const char *basename_of(const char *path) {
    const char *base = path;
    if (!path) return NULL;
    for (const char *p = path; *p; ++p) {
        if (*p == '/' || *p == '\\') base = p + 1;
    }
    return base;
}

static void fail(MyLangSourceSpecResult *result, const char *message, const char *value) {
    result->ok = false;
    if (value) {
        snprintf(result->error, sizeof(result->error), message, value);
    } else {
        snprintf(result->error, sizeof(result->error), "%s", message);
    }
}

MyLangSourceSpecResult mylang_source_spec_parse(const char *path) {
    MyLangSourceSpecResult result;
    memset(&result, 0, sizeof(result));
    result.spec.syntax = MYLANG_SYNTAX_CORE;
    result.spec.safety = MYLANG_SAFETY_DEFAULT;

    const char *base = basename_of(path);
    if (!base || !*base) {
        fail(&result, "source path is empty", NULL);
        return result;
    }

    size_t len = strlen(base);
    if (len < 5 || strcmp(base + len - 4, ".mln") != 0) {
        fail(&result, "unsupported source filename '%s'; expected a canonical .mln filename", base);
        return result;
    }

    char name[512];
    if (len - 4 >= sizeof(name)) {
        fail(&result, "source filename is too long", NULL);
        return result;
    }
    memcpy(name, base, len - 4);
    name[len - 4] = '\0';

    char *segments[MYLANG_SOURCE_SPEC_MAX_MODIFIERS + 2];
    size_t segment_count = 0;
    char *cursor = name;
    segments[segment_count++] = cursor;
    while (*cursor) {
        if (*cursor == '.') {
            *cursor = '\0';
            if (segment_count >= sizeof(segments) / sizeof(segments[0])) {
                fail(&result, "too many source modifiers", NULL);
                return result;
            }
            segments[segment_count++] = cursor + 1;
        }
        ++cursor;
    }

    if (!segments[0][0]) {
        fail(&result, "source filename must have a name before its modifiers", NULL);
        return result;
    }

    bool saw_dom = false;
    bool saw_safe = false;
    bool semantic_phase = false;

    for (size_t i = 1; i < segment_count; ++i) {
        const char *modifier = segments[i];
        if (!modifier[0]) {
            fail(&result, "source filename contains an empty modifier", NULL);
            return result;
        }
        if (result.spec.modifier_count >= MYLANG_SOURCE_SPEC_MAX_MODIFIERS) {
            fail(&result, "too many source modifiers", NULL);
            return result;
        }

        if (strcmp(modifier, "dom") == 0) {
            if (saw_dom) {
                fail(&result, "duplicate source modifier '%s'", modifier);
                return result;
            }
            if (semantic_phase) {
                fail(&result, "syntax modifier '%s' must precede semantic policy modifiers", modifier);
                return result;
            }
            saw_dom = true;
            result.spec.syntax = MYLANG_SYNTAX_DOM;
        } else if (strcmp(modifier, "safe") == 0) {
            if (saw_safe) {
                fail(&result, "duplicate source modifier '%s'", modifier);
                return result;
            }
            saw_safe = true;
            semantic_phase = true;
            result.spec.safety = MYLANG_SAFETY_STRICT;
        } else {
            fail(&result, "unknown source modifier '%s'", modifier);
            return result;
        }

        result.spec.modifiers[result.spec.modifier_count++] = modifier;
    }

    result.ok = true;
    return result;
}

const char *mylang_syntax_profile_name(MyLangSyntaxProfile profile) {
    switch (profile) {
        case MYLANG_SYNTAX_CORE: return "core";
        case MYLANG_SYNTAX_DOM: return "dom";
        default: return "unknown";
    }
}

const char *mylang_safety_profile_name(MyLangSafetyProfile profile) {
    switch (profile) {
        case MYLANG_SAFETY_DEFAULT: return "default";
        case MYLANG_SAFETY_STRICT: return "safe";
        default: return "unknown";
    }
}
