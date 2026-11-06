#ifndef MYLANG_FRONTEND_MODEL_EXPAND_H
#define MYLANG_FRONTEND_MODEL_EXPAND_H

#include <stddef.h>

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

/* A stretch of one line of the model source. Line and column count from zero,
 * and the column and length are in bytes. */
typedef struct {
    int line;
    int column;
    int length;
} ModelSpan;

/* A word of the model's own syntax, which no MyLang parser can classify. */
typedef struct {
    ModelSpan span;
    const char *kind;      /* the token kind an editor should read it as */
    const char *role;      /* its semantic role, or "" */
    ModelSpan declaration; /* the entity, relation or column it names; length 0 if none */
} ModelWord;

typedef struct {
    ModelSpan span;
    char message[256];
} ModelError;

/*
 * What an editor needs to see through the expansion.
 *
 * `text` is ordinary MyLang in two parts. Before `generated_offset` is the
 * outline: the model source with every word on the line it was written, an
 * entity's header rewritten as a struct's and the other declarations blanked,
 * so its tokens are at their source positions. From `generated_offset`, on
 * line `generated_line`, is the code model_expand() generates.
 *
 * `origins` has one span per generated line: the word in the source that
 * produced it. Every name the generator makes is therefore traceable without
 * repeating its naming rules.
 *
 * Unlike model_expand(), this does not exit on a malformed declaration. It
 * records one error per bad statement and generates nothing, leaving only the
 * imports the generated code would have needed.
 */
typedef struct {
    char *text;
    size_t generated_offset;
    size_t generated_line;
    ModelSpan *origins;
    size_t origin_count;
    ModelWord *words;
    size_t word_count;
    ModelError *errors;
    size_t error_count;
} ModelTrace;

ModelTrace *model_trace(const char *source);
void model_trace_free(ModelTrace *trace);

#endif
