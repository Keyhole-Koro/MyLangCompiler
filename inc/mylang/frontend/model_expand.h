#ifndef MYLANG_FRONTEND_MODEL_EXPAND_H
#define MYLANG_FRONTEND_MODEL_EXPAND_H

/*
 * Expands a `.model.mln` source into ordinary MyLang source text.
 *
 * Entity and relationship declarations become structs, row tables and
 * methods; every other line passes through unchanged. Nothing downstream
 * knows models exist, and the result is checked like any other source.
 * See docs/design/mylang-model.md in MyComputer.
 *
 * Returns a malloc'd string. A malformed declaration is reported on stderr
 * and exits.
 */
char *model_expand(const char *source, const char *path);

#endif
