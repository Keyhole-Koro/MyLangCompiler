#include "mylang/frontend/model_expand.h"

#include <ctype.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MODEL_MAX_ENTITIES 32
#define MODEL_MAX_COLUMNS 64
#define MODEL_MAX_RELATIONS 64
#define MODEL_MAX_INDEXES 32
#define MODEL_NAME_CAP 64
#define MODEL_TYPE_CAP 96
/* An id is `generation << ID_SLOT_BITS | slot + 1`: one word, zero means none. */
#define ID_SLOT_BITS 12
#define ID_MAX_ROWS 4095

typedef struct {
    char type[MODEL_TYPE_CAP];
    char name[MODEL_NAME_CAP];
    char suffix[MODEL_NAME_CAP]; /* `[8]` of an array column */
    ModelSpan span;
} Column;

typedef struct {
    char name[MODEL_NAME_CAP];
    char lower[MODEL_NAME_CAP];
    int max;
    Column columns[MODEL_MAX_COLUMNS];
    int column_count;
    ModelSpan span;
    /* Where the header's words are, for the outline. */
    const char *keyword;
    const char *name_end;
    const char *body_open;
    const char *body_close;
} Entity;

typedef struct {
    int owns;       /* `has`: the left side's death takes the right side along */
    int many;
    Entity *left;
    Entity *right;
    char name[MODEL_NAME_CAP];
    char inverse[MODEL_NAME_CAP];
    ModelSpan span;
    ModelSpan inverse_span;
} Relation;

typedef struct {
    Entity *entity;
    char column[MODEL_NAME_CAP];
    int unique;
    int buckets;
    ModelSpan span; /* the column's own declaration */
} Index;

typedef struct {
    char *text;
    size_t length;
    size_t capacity;
} Out;

typedef struct {
    const char *path;
    const char *source;
    Entity entities[MODEL_MAX_ENTITIES];
    int entity_count;
    Relation relations[MODEL_MAX_RELATIONS];
    int relation_count;
    Index indexes[MODEL_MAX_INDEXES];
    int index_count;
    Out out;
    /* Set only by model_trace(). */
    int tracing;
    jmp_buf *recover;
    Out outline;
    const Entity *closed_entity; /* the statement just parsed, if an entity */
    int generating;
    ModelSpan origin;            /* the source word of what is being emitted */
    ModelTrace trace;
    size_t origin_capacity;
    size_t word_capacity;
    size_t error_capacity;
} Model;

static const ModelSpan NO_SPAN = {0, 0, 0};

static void *grown(void *items, size_t count, size_t *capacity, size_t item_size) {
    if (count < *capacity) return items;
    *capacity = *capacity ? *capacity * 2 : 64;
    items = realloc(items, *capacity * item_size);
    if (!items) { fprintf(stderr, "out of memory\n"); exit(1); }
    return items;
}

static ModelSpan span_at(const Model *model, const char *at, size_t length) {
    ModelSpan span = {0, 0, (int)length};
    for (const char *c = model->source; c < at; c++) {
        if (*c == '\n') {
            span.line++;
            span.column = 0;
        } else {
            span.column++;
        }
    }
    return span;
}

/* Reports the words at `at`. A trace goes on with the next statement. */
static void model_error(Model *model, const char *at, size_t length, const char *fmt, ...) {
    ModelSpan span = span_at(model, at, length);
    va_list ap;
    va_start(ap, fmt);
    if (model->tracing) {
        ModelTrace *trace = &model->trace;
        trace->errors = grown(trace->errors, trace->error_count, &model->error_capacity, sizeof(ModelError));
        ModelError *error = &trace->errors[trace->error_count++];
        error->span = span;
        vsnprintf(error->message, sizeof(error->message), fmt, ap);
        va_end(ap);
        longjmp(*model->recover, 1);
    }
    fprintf(stderr, "%s:%d:1: error: ", model->path ? model->path : "<model>", span.line + 1);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

static void mark(Model *model, const char *at, size_t length, const char *kind, const char *role,
                 ModelSpan declaration) {
    if (!model->tracing || !length) return;
    ModelTrace *trace = &model->trace;
    trace->words = grown(trace->words, trace->word_count, &model->word_capacity, sizeof(ModelWord));
    ModelWord *word = &trace->words[trace->word_count++];
    word->span = span_at(model, at, length);
    word->kind = kind;
    word->role = role;
    word->declaration = declaration;
}

static void mark_keyword(Model *model, const char *at, size_t length) {
    mark(model, at, length, "MODEL", "keyword", NO_SPAN);
}

/* One origin per line that `added`, just emitted, completes. */
static void note_origins(Model *model, const char *added) {
    ModelTrace *trace = &model->trace;
    for (; *added; added++) {
        if (*added != '\n') continue;
        trace->origins = grown(trace->origins, trace->origin_count, &model->origin_capacity, sizeof(ModelSpan));
        trace->origins[trace->origin_count++] = model->origin;
    }
}

static void emit(Model *model, const char *fmt, ...) {
    Out *out = &model->out;
    for (;;) {
        va_list ap;
        va_start(ap, fmt);
        size_t room = out->capacity - out->length;
        int wanted = vsnprintf(out->text ? out->text + out->length : NULL, room, fmt, ap);
        va_end(ap);
        if (wanted >= 0 && (size_t)wanted < room) {
            const char *added = out->text + out->length;
            out->length += (size_t)wanted;
            if (model->tracing && model->generating) note_origins(model, added);
            return;
        }
        out->capacity = out->capacity ? out->capacity * 2 : 4096;
        if (wanted >= 0 && out->capacity < out->length + (size_t)wanted + 1)
            out->capacity = out->length + (size_t)wanted + 1;
        out->text = realloc(out->text, out->capacity);
        if (!out->text) { fprintf(stderr, "out of memory\n"); exit(1); }
    }
}

static const char *skip_space(const char *p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static const char *read_word(const char *p, char *word, size_t cap) {
    size_t n = 0;
    while ((isalnum((unsigned char)*p) || *p == '_') && n + 1 < cap) word[n++] = *p++;
    word[n] = '\0';
    return p;
}

typedef struct {
    const char *at;
    size_t length;
    char text[MODEL_NAME_CAP];
} Word;

/* The next word of a statement, remembering where it stood. */
static const char *next_word(const char *p, Word *word) {
    word->at = skip_space(p);
    p = read_word(word->at, word->text, sizeof(word->text));
    word->length = (size_t)(p - word->at);
    return p;
}

static Entity *find_entity(Model *model, const char *name) {
    for (int i = 0; i < model->entity_count; i++)
        if (strcmp(model->entities[i].name, name) == 0) return &model->entities[i];
    return NULL;
}

static Entity *require_entity(Model *model, const Word *name) {
    Entity *entity = find_entity(model, name->text);
    if (!entity) model_error(model, name->at, name->length, "unknown entity '%s'", name->text);
    return entity;
}

static void mark_entity_use(Model *model, const Word *name) {
    const Entity *entity = find_entity(model, name->text);
    mark(model, name->at, name->length, "IDENTIFIER", "struct", entity ? entity->span : NO_SPAN);
}

/* `i32 kind;` or `Text<64> text;` or `i32 samples[8];`. */
static const char *parse_column(Model *model, Entity *entity, const char *p) {
    if (entity->column_count >= MODEL_MAX_COLUMNS) model_error(model, p, 1, "too many columns");
    Column *column = &entity->columns[entity->column_count++];
    const char *end = strchr(p, ';');
    if (!end) model_error(model, p, strcspn(p, "\n"), "expected ';' after a column of entity '%s'", entity->name);
    const char *q = end;
    while (q > p && isspace((unsigned char)q[-1])) q--;
    const char *suffix = NULL;
    if (q > p && q[-1] == ']') {
        const char *open = q;
        while (open > p && *open != '[') open--;
        suffix = open;
        snprintf(column->suffix, sizeof(column->suffix), "%.*s", (int)(q - open), open);
        q = open;
        while (q > p && isspace((unsigned char)q[-1])) q--;
    }
    const char *name_end = q;
    while (q > p && (isalnum((unsigned char)q[-1]) || q[-1] == '_')) q--;
    snprintf(column->name, sizeof(column->name), "%.*s", (int)(name_end - q), q);
    column->span = span_at(model, q, (size_t)(name_end - q));
    while (q > p && isspace((unsigned char)q[-1])) q--;
    snprintf(column->type, sizeof(column->type), "%.*s", (int)(q - p), p);
    if (!column->name[0] || !column->type[0])
        model_error(model, p, (size_t)(end - p), "malformed column in entity '%s'", entity->name);
    (void)suffix;
    return end + 1;
}

/* `entity Node max 512 { ... }`. */
static const char *parse_entity(Model *model, const char *p) {
    const char *keyword = p;
    mark_keyword(model, keyword, strlen("entity"));
    if (model->entity_count >= MODEL_MAX_ENTITIES) model_error(model, keyword, strlen("entity"), "too many entities");
    Entity *entity = &model->entities[model->entity_count++];
    memset(entity, 0, sizeof(*entity));
    entity->keyword = keyword;
    p = skip_space(p + strlen("entity"));
    const char *name = p;
    p = read_word(p, entity->name, sizeof(entity->name));
    entity->name_end = p;
    entity->span = span_at(model, name, (size_t)(p - name));
    for (int i = 0; entity->name[i]; i++) entity->lower[i] = (char)tolower((unsigned char)entity->name[i]);
    if (!entity->name[0]) model_error(model, keyword, strlen("entity"), "expected an entity name");
    mark(model, name, (size_t)(p - name), "IDENTIFIER", "struct", entity->span);
    Word word;
    p = next_word(p, &word);
    if (strcmp(word.text, "max") != 0)
        model_error(model, name, (size_t)(entity->name_end - name), "entity '%s' needs `max N`", entity->name);
    mark_keyword(model, word.at, word.length);
    const char *number = skip_space(p);
    entity->max = (int)strtol(number, (char **)&p, 10);
    mark(model, number, (size_t)(p - number), "NUMBER", "number", NO_SPAN);
    if (entity->max <= 0 || entity->max > ID_MAX_ROWS)
        model_error(model, number, p > number ? (size_t)(p - number) : 1,
                    "entity '%s': max must be between 1 and %d", entity->name, ID_MAX_ROWS);
    p = skip_space(p);
    if (*p != '{') model_error(model, p, 1, "expected '{' after `max %d`", entity->max);
    entity->body_open = p;
    p = skip_space(p + 1);
    while (*p && *p != '}') {
        if (*p == '/' && p[1] == '/') {
            while (*p && *p != '\n') p++;
        } else {
            p = parse_column(model, entity, p);
        }
        p = skip_space(p);
    }
    if (*p != '}') model_error(model, name, (size_t)(entity->name_end - name), "unterminated entity '%s'", entity->name);
    entity->body_close = p;
    p++;
    p = skip_space(p);
    if (*p == ';') p++;
    model->closed_entity = entity;
    return p;
}

/* `Node has many Node as children / parent;`, `Window knows one Node as focus;`. */
static const char *parse_relation(Model *model, const char *p) {
    const char *statement = p;
    if (model->relation_count >= MODEL_MAX_RELATIONS) model_error(model, statement, strcspn(p, "\n"), "too many relations");
    Relation *relation = &model->relations[model->relation_count++];
    memset(relation, 0, sizeof(*relation));
    Word left, verb, count, right, as, name;
    p = next_word(p, &left);
    p = next_word(p, &verb);
    p = next_word(p, &count);
    p = next_word(p, &right);
    p = next_word(p, &as);
    mark_entity_use(model, &left);
    mark_keyword(model, verb.at, verb.length);
    mark_keyword(model, count.at, count.length);
    mark_entity_use(model, &right);
    if (strcmp(as.text, "as") != 0)
        model_error(model, as.at, as.length ? as.length : 1, "expected `as name` in the relation of '%s'", left.text);
    mark_keyword(model, as.at, as.length);
    p = next_word(p, &name);
    snprintf(relation->name, sizeof(relation->name), "%s", name.text);
    relation->span = span_at(model, name.at, name.length);
    mark(model, name.at, name.length, "IDENTIFIER", "method", relation->span);
    relation->left = require_entity(model, &left);
    relation->right = require_entity(model, &right);
    relation->owns = strcmp(verb.text, "has") == 0;
    if (strcmp(count.text, "many") == 0) relation->many = 1;
    else if (strcmp(count.text, "one") != 0)
        model_error(model, count.at, count.length ? count.length : 1, "expected `one` or `many`, got '%s'", count.text);
    p = skip_space(p);
    if (*p == '/') {
        mark(model, p, 1, "DIV", "operator", NO_SPAN);
        Word first;
        const char *after = next_word(p + 1, &first);
        if (strcmp(first.text, "many") == 0) {
            mark_keyword(model, first.at, first.length);
            model_error(model, first.at, first.length, "a many-to-many relation is not supported yet: keep the pairs in an entity of their own");
        }
        snprintf(relation->inverse, sizeof(relation->inverse), "%s", first.text);
        relation->inverse_span = span_at(model, first.at, first.length);
        mark(model, first.at, first.length, "IDENTIFIER", "method", relation->inverse_span);
        p = skip_space(after);
    }
    /* `ordered` documents the contract: every chain keeps insertion order. */
    if (*p == ',') {
        mark(model, p, 1, "COMMA", "", NO_SPAN);
        Word option;
        p = next_word(p + 1, &option);
        if (strcmp(option.text, "ordered") != 0)
            model_error(model, option.at, option.length ? option.length : 1, "unknown relation option '%s'", option.text);
        mark_keyword(model, option.at, option.length);
        p = skip_space(p);
    }
    if (*p != ';') model_error(model, statement, strcspn(statement, "\n"), "expected ';' after the relation '%s'", relation->name);
    mark(model, p, 1, "SEMICOLON", "", NO_SPAN);
    return p + 1;
}

/* `index Node.owner;`, `unique Process.pid;`. */
static const char *parse_index(Model *model, const char *p, int unique) {
    const char *statement = p;
    size_t keyword_length = unique ? strlen("unique") : strlen("index");
    mark_keyword(model, statement, keyword_length);
    if (model->index_count >= MODEL_MAX_INDEXES) model_error(model, statement, keyword_length, "too many indexes");
    Index *index = &model->indexes[model->index_count++];
    memset(index, 0, sizeof(*index));
    index->unique = unique;
    Word entity;
    p = next_word(p + keyword_length, &entity);
    mark_entity_use(model, &entity);
    index->entity = require_entity(model, &entity);
    if (*p != '.') model_error(model, statement, strcspn(statement, "\n"), "expected Entity.column after `index`");
    mark(model, p, 1, "DOT", "", NO_SPAN);
    const char *column_at = p + 1;
    p = read_word(column_at, index->column, sizeof(index->column));
    size_t column_length = (size_t)(p - column_at);
    int found = 0;
    for (int i = 0; i < index->entity->column_count; i++) {
        Column *column = &index->entity->columns[i];
        if (strcmp(column->name, index->column) == 0) {
            mark(model, column_at, column_length, "IDENTIFIER", "variable", column->span);
            if (strcmp(column->type, "i32") != 0)
                model_error(model, column_at, column_length, "only an i32 column can be indexed: '%s'", index->column);
            index->span = column->span;
            found = 1;
        }
    }
    if (!found)
        model_error(model, column_at, column_length ? column_length : 1, "entity '%s' has no column '%s'", entity.text, index->column);
    index->buckets = 1;
    while (index->buckets < index->entity->max) index->buckets *= 2;
    p = skip_space(p);
    if (*p != ';') model_error(model, statement, strcspn(statement, "\n"), "expected ';' after the index");
    mark(model, p, 1, "SEMICOLON", "", NO_SPAN);
    return p + 1;
}

static int column_is_indexed(const Model *model, const Entity *entity, const char *column) {
    for (int i = 0; i < model->index_count; i++)
        if (model->indexes[i].entity == entity && strcmp(model->indexes[i].column, column) == 0)
            return 1;
    return 0;
}

static void emit_row_struct(Model *model, const Entity *entity) {
    model->origin = entity->span;
    emit(model, "export struct %sRow {\n", entity->name);
    for (int i = 0; i < entity->column_count; i++) {
        const Column *column = &entity->columns[i];
        /* An indexed column changes through its setter only, which keeps the
         * index right; row() does not expose it. */
        const char *prefix = column_is_indexed(model, entity, column->name) ? "__ix_" : "";
        model->origin = column->span;
        emit(model, "    %s %s%s%s;\n", column->type, prefix, column->name, column->suffix);
    }
    model->origin = entity->span;
    emit(model, "    bool __used;\n    i32 __gen;\n    i32 __next_free;\n");
    for (int i = 0; i < model->relation_count; i++) {
        const Relation *r = &model->relations[i];
        if (r->owns || r->many) {
            if (r->left == entity)
                emit(model, "    i32 __%s_first;\n    i32 __%s_last;\n    i32 __%s_count;\n", r->name, r->name, r->name);
            if (r->right == entity)
                emit(model, "    i32 __%s_owner;\n    i32 __%s_prev;\n    i32 __%s_next;\n", r->name, r->name, r->name);
        } else {
            if (r->left == entity)
                emit(model, "    i32 __%s_to;\n    i32 __%s_prev;\n    i32 __%s_next;\n", r->name, r->name, r->name);
            if (r->right == entity)
                emit(model, "    i32 __%s_head;\n", r->name);
        }
    }
    for (int i = 0; i < model->index_count; i++) {
        const Index *index = &model->indexes[i];
        if (index->entity == entity)
            emit(model, "    i32 __ixn_%s;\n    i32 __ixp_%s;\n", index->column, index->column);
    }
    emit(model, "};\n\n");
}

static void emit_entity_core(Model *model, const Entity *e) {
    const char *T = e->name, *t = e->lower;
    model->origin = e->span;
    emit(model, "%sRow g_%s_rows[%d];\n", T, t, e->max);
    emit(model, "i32 g_%s_high = 0;\ni32 g_%s_free = 0;\n\n", t, t);
    emit(model, "i32 %s_slot(%s x) { return (x.id & %d) - 1; }\n\n", t, T, (1 << ID_SLOT_BITS) - 1);
    emit(model,
         "/** True while the row this id named still exists. */\n"
         "export bool (%s x) is_live() {\n"
         "    i32 s = %s_slot(x);\n"
         "    if (s < 0 || s >= %d) { return false; }\n"
         "    return g_%s_rows[s].__used && g_%s_rows[s].__gen == ((x.id >> %d) & 0xFFFFF);\n"
         "}\n\n",
         T, t, e->max, t, t, ID_SLOT_BITS);
    /* A stale id indexes past the table, and the bounds check traps. */
    emit(model,
         "i32 %s_checked(%s x) {\n"
         "    if (x.is_live()) { return %s_slot(x); }\n"
         "    return %d;\n"
         "}\n\n", t, T, t, e->max);
    emit(model,
         "%s %s_at(i32 ref) { return %s { id: (g_%s_rows[ref - 1].__gen << %d) | ref }; }\n\n",
         T, t, T, t, ID_SLOT_BITS);
    emit(model, "/** The id as a plain word, to cross a boundary. */\n"
                "export i32 (%s x) raw() { return x.id; }\n\n", T);
    emit(model, "/** An id received as a plain word. */\n"
                "export %s %s_from_raw(i32 id) { return %s { id: id }; }\n\n", T, t, T);
    emit(model,
         "/** The row's columns. A stale id traps. */\n"
         "export borrow %sRow (%s x) row() { return &g_%s_rows[%s_checked(x)]; }\n\n",
         T, T, t, t);
    emit(model,
         "export struct %s_all_Iter { i32 next; };\n\n"
         "export impl Iterator<%s> for %s_all_Iter {\n"
         "    Option<%s> (borrow Self self) next() {\n"
         "        while (self.next < g_%s_high) {\n"
         "            i32 slot = self.next;\n"
         "            self.next = slot + 1;\n"
         "            if (g_%s_rows[slot].__used) {\n"
         "                %s found = %s_at(slot + 1);\n"
         "                return Some(found);\n"
         "            }\n"
         "        }\n"
         "        return None;\n"
         "    }\n"
         "}\n\n"
         "/** Every live row, in table order. A row deleted ahead is skipped. */\n"
         "export %s_all_Iter %s_all() { return %s_all_Iter { next: 0 }; }\n\n",
         t, T, t, T, t, t, T, t, t, t, t);
    /* The same as is_live() and row() on a plain word, for code that keeps
     * ids as words and asks often: no struct, one call. */
    emit(model,
         "/** True while the id, as a word, names a row. */\n"
         "export bool %s_live_id(i32 id) {\n"
         "    i32 s = (id & %d) - 1;\n"
         "    if (s < 0 || s >= %d) { return false; }\n"
         "    return g_%s_rows[s].__used && g_%s_rows[s].__gen == ((id >> %d) & 0xFFFFF);\n"
         "}\n\n",
         t, (1 << ID_SLOT_BITS) - 1, e->max, t, t, ID_SLOT_BITS);
    emit(model,
         "/** The row of an id given as a word. A stale id traps. */\n"
         "export borrow %sRow %s_row_id(i32 id) {\n"
         "    i32 s = (id & %d) - 1;\n"
         "    if (s < 0 || s >= %d || !g_%s_rows[s].__used || g_%s_rows[s].__gen != ((id >> %d) & 0xFFFFF)) {\n"
         "        s = %d;\n"
         "    }\n"
         "    return &g_%s_rows[s];\n"
         "}\n\n",
         T, t, (1 << ID_SLOT_BITS) - 1, e->max, t, t, ID_SLOT_BITS, e->max, t);
    emit(model,
         "/** Adds a row with zero columns, or None when the table is full. */\n"
         "export Option<%s> new_%s() {\n"
         "    i32 ref = g_%s_free;\n"
         "    if (ref != 0) {\n"
         "        g_%s_free = g_%s_rows[ref - 1].__next_free;\n"
         "    } else {\n"
         "        if (g_%s_high >= %d) { return None; }\n"
         "        g_%s_high = g_%s_high + 1;\n"
         "        ref = g_%s_high;\n"
         "    }\n"
         "    i32 gen = g_%s_rows[ref - 1].__gen;\n"
         "    %sRow fresh = %sRow {};\n"
         "    fresh.__gen = gen;\n"
         "    fresh.__used = true;\n"
         "    g_%s_rows[ref - 1] = fresh;\n"
         "    %s made = %s_at(ref);\n"
         "    return Some(made);\n"
         "}\n\n",
         T, t, t, t, t, t, e->max, t, t, t, t, T, T, t, T, t);
}

/* A chain: `owner` rows hold first/last/count, member rows prev/next. */
static void emit_chain(Model *model, const Relation *r) {
    const char *A = r->left->name, *a = r->left->lower;
    const char *B = r->right->name, *b = r->right->lower;
    const char *n = r->name;
    model->origin = r->span;
    emit(model,
         "void %s_%s_unlink(i32 ref) {\n"
         "    i32 owner = g_%s_rows[ref - 1].__%s_owner;\n"
         "    if (owner == 0) { return; }\n"
         "    i32 before = g_%s_rows[ref - 1].__%s_prev;\n"
         "    i32 after = g_%s_rows[ref - 1].__%s_next;\n"
         "    if (before != 0) { g_%s_rows[before - 1].__%s_next = after; }\n"
         "    else { g_%s_rows[owner - 1].__%s_first = after; }\n"
         "    if (after != 0) { g_%s_rows[after - 1].__%s_prev = before; }\n"
         "    else { g_%s_rows[owner - 1].__%s_last = before; }\n"
         "    g_%s_rows[owner - 1].__%s_count = g_%s_rows[owner - 1].__%s_count - 1;\n"
         "    g_%s_rows[ref - 1].__%s_owner = 0;\n"
         "    g_%s_rows[ref - 1].__%s_prev = 0;\n"
         "    g_%s_rows[ref - 1].__%s_next = 0;\n"
         "}\n\n",
         b, n, b, n, b, n, b, n, b, n, a, n, b, n, a, n, a, n, a, n, b, n, b, n, b, n);
    emit(model,
         "/** Appends `member`, taking it from any previous owner. */\n"
         "export bool (%s owner) %s_add(%s member) {\n"
         "    if (!owner.is_live() || !member.is_live()) { return false; }\n"
         "    i32 ref = %s_slot(member) + 1;\n"
         "    i32 home = %s_slot(owner) + 1;\n"
         "    %s_%s_unlink(ref);\n"
         "    i32 tail = g_%s_rows[home - 1].__%s_last;\n"
         "    g_%s_rows[ref - 1].__%s_owner = home;\n"
         "    g_%s_rows[ref - 1].__%s_prev = tail;\n"
         "    if (tail != 0) { g_%s_rows[tail - 1].__%s_next = ref; }\n"
         "    else { g_%s_rows[home - 1].__%s_first = ref; }\n"
         "    g_%s_rows[home - 1].__%s_last = ref;\n"
         "    g_%s_rows[home - 1].__%s_count = g_%s_rows[home - 1].__%s_count + 1;\n"
         "    return true;\n"
         "}\n\n",
         A, n, B, b, a, b, n, a, n, b, n, b, n, b, n, a, n, a, n, a, n, a, n);
    emit(model,
         "/** Takes `member` out of its owner without deleting it. */\n"
         "export void (%s member) %s_detach() {\n"
         "    if (member.is_live()) { %s_%s_unlink(%s_slot(member) + 1); }\n"
         "}\n\n", B, n, b, n, b);
    emit(model,
         "export i32 (%s owner) %s_count() { return g_%s_rows[%s_checked(owner)].__%s_count; }\n\n",
         A, n, a, a, n);
    emit(model,
         "export Option<%s> (%s owner) %s_first() {\n"
         "    i32 ref = g_%s_rows[%s_checked(owner)].__%s_first;\n"
         "    if (ref == 0) { return None; }\n"
         "    %s found = %s_at(ref);\n"
         "    return Some(found);\n"
         "}\n\n", B, A, n, a, a, n, B, b);
    emit(model,
         "export Option<%s> (%s owner) %s_last() {\n"
         "    i32 ref = g_%s_rows[%s_checked(owner)].__%s_last;\n"
         "    if (ref == 0) { return None; }\n"
         "    %s found = %s_at(ref);\n"
         "    return Some(found);\n"
         "}\n\n", B, A, n, a, a, n, B, b);
    emit(model,
         "export Option<%s> (%s member) %s_next() {\n"
         "    i32 ref = g_%s_rows[%s_checked(member)].__%s_next;\n"
         "    if (ref == 0) { return None; }\n"
         "    %s found = %s_at(ref);\n"
         "    return Some(found);\n"
         "}\n\n", B, B, n, b, b, n, B, b);
    emit(model,
         "export Option<%s> (%s member) %s_prev() {\n"
         "    i32 ref = g_%s_rows[%s_checked(member)].__%s_prev;\n"
         "    if (ref == 0) { return None; }\n"
         "    %s found = %s_at(ref);\n"
         "    return Some(found);\n"
         "}\n\n", B, B, n, b, b, n, B, b);
    if (r->inverse[0]) {
        model->origin = r->inverse_span;
        emit(model,
             "export Option<%s> (%s member) %s() {\n"
             "    i32 ref = g_%s_rows[%s_checked(member)].__%s_owner;\n"
             "    if (ref == 0) { return None; }\n"
             "    %s found = %s_at(ref);\n"
             "    return Some(found);\n"
             "}\n\n", A, B, r->inverse, b, b, n, A, a);
        model->origin = r->span;
    }
    /* Walking a chain by plain words: zero ends it. */
    emit(model,
         "export i32 %s_%s_first_id(i32 owner) {\n"
         "    i32 ref = %s_row_id(owner).__%s_first;\n"
         "    if (ref == 0) { return 0; }\n"
         "    return (g_%s_rows[ref - 1].__gen << %d) | ref;\n"
         "}\n\n", a, n, a, n, b, ID_SLOT_BITS);
    emit(model,
         "export i32 %s_%s_next_id(i32 member) {\n"
         "    i32 ref = %s_row_id(member).__%s_next;\n"
         "    if (ref == 0) { return 0; }\n"
         "    return (g_%s_rows[ref - 1].__gen << %d) | ref;\n"
         "}\n\n", b, n, b, n, b, ID_SLOT_BITS);
    if (r->inverse[0]) {
        model->origin = r->inverse_span;
        emit(model,
             "export i32 %s_%s_id(i32 member) {\n"
             "    i32 ref = %s_row_id(member).__%s_owner;\n"
             "    if (ref == 0) { return 0; }\n"
             "    return (g_%s_rows[ref - 1].__gen << %d) | ref;\n"
             "}\n\n", b, r->inverse, b, n, a, ID_SLOT_BITS);
        model->origin = r->span;
    }
    /* The next member is read before one is handed out, so the loop body may
     * move or delete the member it was given. */
    emit(model,
         "export struct %s_%s_Iter { i32 next; };\n\n"
         "export impl Iterator<%s> for %s_%s_Iter {\n"
         "    Option<%s> (borrow Self self) next() {\n"
         "        if (self.next == 0) { return None; }\n"
         "        i32 ref = self.next;\n"
         "        self.next = g_%s_rows[ref - 1].__%s_next;\n"
         "        %s found = %s_at(ref);\n"
         "        return Some(found);\n"
         "    }\n"
         "}\n\n",
         a, n, B, a, n, B, b, n, B, b);
    emit(model,
         "export %s_%s_Iter (%s owner) %s() {\n"
         "    return %s_%s_Iter { next: g_%s_rows[%s_checked(owner)].__%s_first };\n"
         "}\n\n", a, n, A, n, a, n, a, a, n);
}

/* One association: the left row points at a right row, and the right row
 * lists who points at it so its death can clear them. */
static void emit_reference(Model *model, const Relation *r) {
    const char *A = r->left->name, *a = r->left->lower;
    const char *B = r->right->name, *b = r->right->lower;
    const char *n = r->name;
    model->origin = r->span;
    emit(model,
         "void %s_%s_clear(i32 ref) {\n"
         "    i32 target = g_%s_rows[ref - 1].__%s_to;\n"
         "    if (target == 0) { return; }\n"
         "    i32 before = g_%s_rows[ref - 1].__%s_prev;\n"
         "    i32 after = g_%s_rows[ref - 1].__%s_next;\n"
         "    if (before != 0) { g_%s_rows[before - 1].__%s_next = after; }\n"
         "    else { g_%s_rows[target - 1].__%s_head = after; }\n"
         "    if (after != 0) { g_%s_rows[after - 1].__%s_prev = before; }\n"
         "    g_%s_rows[ref - 1].__%s_to = 0;\n"
         "    g_%s_rows[ref - 1].__%s_prev = 0;\n"
         "    g_%s_rows[ref - 1].__%s_next = 0;\n"
         "}\n\n",
         a, n, a, n, a, n, a, n, a, n, b, n, a, n, a, n, a, n, a, n);
    emit(model,
         "/** Points this row at `target`; a row that dies clears the link. */\n"
         "export bool (%s origin) set_%s(%s target) {\n"
         "    if (!origin.is_live() || !target.is_live()) { return false; }\n"
         "    i32 ref = %s_slot(origin) + 1;\n"
         "    i32 to = %s_slot(target) + 1;\n"
         "    %s_%s_clear(ref);\n"
         "    i32 head = g_%s_rows[to - 1].__%s_head;\n"
         "    g_%s_rows[ref - 1].__%s_to = to;\n"
         "    g_%s_rows[ref - 1].__%s_next = head;\n"
         "    if (head != 0) { g_%s_rows[head - 1].__%s_prev = ref; }\n"
         "    g_%s_rows[to - 1].__%s_head = ref;\n"
         "    return true;\n"
         "}\n\n",
         A, n, B, a, b, a, n, b, n, a, n, a, n, a, n, b, n);
    emit(model,
         "export void (%s origin) clear_%s() {\n"
         "    if (origin.is_live()) { %s_%s_clear(%s_slot(origin) + 1); }\n"
         "}\n\n", A, n, a, n, a);
    emit(model,
         "export Option<%s> (%s origin) %s() {\n"
         "    i32 ref = g_%s_rows[%s_checked(origin)].__%s_to;\n"
         "    if (ref == 0) { return None; }\n"
         "    %s found = %s_at(ref);\n"
         "    return Some(found);\n"
         "}\n\n", B, A, n, a, a, n, B, b);
}

static void emit_index(Model *model, const Index *index) {
    const Entity *e = index->entity;
    const char *T = e->name, *t = e->lower, *c = index->column;
    int mask = index->buckets - 1;
    model->origin = index->span;
    emit(model, "i32 g_%s_ix_%s[%d];\n\n", t, c, index->buckets);
    emit(model,
         "void %s_ix_%s_unlink(i32 ref) {\n"
         "    i32 value = g_%s_rows[ref - 1].__ix_%s;\n"
         "    i32 before = g_%s_rows[ref - 1].__ixp_%s;\n"
         "    i32 after = g_%s_rows[ref - 1].__ixn_%s;\n"
         "    if (before != 0) { g_%s_rows[before - 1].__ixn_%s = after; }\n"
         "    else if (g_%s_ix_%s[value & %d] == ref) { g_%s_ix_%s[value & %d] = after; }\n"
         "    if (after != 0) { g_%s_rows[after - 1].__ixp_%s = before; }\n"
         "    g_%s_rows[ref - 1].__ixp_%s = 0;\n"
         "    g_%s_rows[ref - 1].__ixn_%s = 0;\n"
         "}\n\n",
         t, c, t, c, t, c, t, c, t, c, t, c, mask, t, c, mask, t, c, t, c, t, c);
    emit(model,
         "void %s_ix_%s_link(i32 ref) {\n"
         "    i32 bucket = g_%s_rows[ref - 1].__ix_%s & %d;\n"
         "    i32 head = g_%s_ix_%s[bucket];\n"
         "    g_%s_rows[ref - 1].__ixn_%s = head;\n"
         "    g_%s_rows[ref - 1].__ixp_%s = 0;\n"
         "    if (head != 0) { g_%s_rows[head - 1].__ixp_%s = ref; }\n"
         "    g_%s_ix_%s[bucket] = ref;\n"
         "}\n\n",
         t, c, t, c, mask, t, c, t, c, t, c, t, c, t, c);
    emit(model, "export i32 (%s x) %s() { return g_%s_rows[%s_checked(x)].__ix_%s; }\n\n", T, c, t, t, c);
    emit(model,
         "/** Sets the indexed column; `row()` does not expose it. */\n"
         "export void (%s x) set_%s(i32 value) {\n"
         "    i32 ref = %s_checked(x) + 1;\n"
         "    %s_ix_%s_unlink(ref);\n"
         "    g_%s_rows[ref - 1].__ix_%s = value;\n"
         "    %s_ix_%s_link(ref);\n"
         "}\n\n", T, c, t, t, c, t, c, t, c);
    if (index->unique) {
        emit(model,
             "export Option<%s> %s_by_%s(i32 value) {\n"
             "    i32 ref = g_%s_ix_%s[value & %d];\n"
             "    while (ref != 0) {\n"
             "        if (g_%s_rows[ref - 1].__ix_%s == value) {\n"
             "            %s found = %s_at(ref);\n"
             "            return Some(found);\n"
             "        }\n"
             "        ref = g_%s_rows[ref - 1].__ixn_%s;\n"
             "    }\n"
             "    return None;\n"
             "}\n\n", T, t, c, t, c, mask, t, c, T, t, t, c);
        return;
    }
    emit(model,
         "export struct %s_by_%s_Iter { i32 next; i32 value; };\n\n"
         "export impl Iterator<%s> for %s_by_%s_Iter {\n"
         "    Option<%s> (borrow Self self) next() {\n"
         "        while (self.next != 0) {\n"
         "            i32 ref = self.next;\n"
         "            self.next = g_%s_rows[ref - 1].__ixn_%s;\n"
         "            if (g_%s_rows[ref - 1].__ix_%s == self.value) {\n"
         "                %s found = %s_at(ref);\n"
         "                return Some(found);\n"
         "            }\n"
         "        }\n"
         "        return None;\n"
         "    }\n"
         "}\n\n",
         t, c, T, t, c, T, t, c, t, c, T, t);
    emit(model,
         "export %s_by_%s_Iter %s_by_%s(i32 value) {\n"
         "    return %s_by_%s_Iter { next: g_%s_ix_%s[value & %d], value: value };\n"
         "}\n\n", t, c, t, c, t, c, t, c, mask);
}

static void emit_delete(Model *model, const Entity *e) {
    const char *T = e->name, *t = e->lower;
    model->origin = e->span;
    emit(model, "void %s_delete_ref(i32 ref) {\n", t);
    for (int i = 0; i < model->relation_count; i++) {
        const Relation *r = &model->relations[i];
        int chain = r->owns || r->many;
        if (chain && r->left == e) {
            if (r->owns) {
                emit(model, "    while (g_%s_rows[ref - 1].__%s_first != 0) {\n"
                            "        %s_delete_ref(g_%s_rows[ref - 1].__%s_first);\n"
                            "    }\n", t, r->name, r->right->lower, t, r->name);
            } else {
                emit(model, "    while (g_%s_rows[ref - 1].__%s_first != 0) {\n"
                            "        %s_%s_unlink(g_%s_rows[ref - 1].__%s_first);\n"
                            "    }\n", t, r->name, r->right->lower, r->name, t, r->name);
            }
        }
        if (chain && r->right == e) emit(model, "    %s_%s_unlink(ref);\n", t, r->name);
        if (!chain && r->left == e) emit(model, "    %s_%s_clear(ref);\n", t, r->name);
        if (!chain && r->right == e) {
            emit(model, "    while (g_%s_rows[ref - 1].__%s_head != 0) {\n"
                        "        %s_%s_clear(g_%s_rows[ref - 1].__%s_head);\n"
                        "    }\n", t, r->name, r->left->lower, r->name, t, r->name);
        }
    }
    for (int i = 0; i < model->index_count; i++) {
        if (model->indexes[i].entity == e)
            emit(model, "    %s_ix_%s_unlink(ref);\n", t, model->indexes[i].column);
    }
    emit(model,
         "    g_%s_rows[ref - 1].__used = false;\n"
         "    g_%s_rows[ref - 1].__gen = (g_%s_rows[ref - 1].__gen + 1) & 0xFFFFF;\n"
         "    g_%s_rows[ref - 1].__next_free = g_%s_free;\n"
         "    g_%s_free = ref;\n"
         "}\n\n", t, t, t, t, t, t);
    emit(model,
         "/** Deletes the row: what it owns dies too, links to it are cleared. */\n"
         "export void (%s x) delete() {\n"
         "    if (x.is_live()) { %s_delete_ref(%s_slot(x) + 1); }\n"
         "}\n\n", T, t, t);
}

static int is_relation_line(const char *p) {
    char first[MODEL_NAME_CAP], verb[MODEL_NAME_CAP];
    if (!isupper((unsigned char)*p)) return 0;
    p = read_word(p, first, sizeof(first));
    if (!isspace((unsigned char)*p)) return 0;
    read_word(skip_space(p), verb, sizeof(verb));
    return strcmp(verb, "has") == 0 || strcmp(verb, "knows") == 0;
}

static int starts_with_word(const char *p, const char *word) {
    size_t n = strlen(word);
    return strncmp(p, word, n) == 0 && isspace((unsigned char)p[n]);
}

/* NULL for a line that is not a declaration. */
static const char *parse_statement(Model *model, const char *s) {
    if (starts_with_word(s, "entity")) return parse_entity(model, s);
    if (starts_with_word(s, "unique")) return parse_index(model, s, 1);
    if (starts_with_word(s, "index")) return parse_index(model, s, 0);
    if (is_relation_line(s)) return parse_relation(model, s);
    return NULL;
}

/* Where to go on after the bad statement at `s`. */
static const char *skip_statement(const char *s) {
    const char *p = s;
    while (*p && *p != ';' && *p != '{' && *p != '\n') p++;
    if (*p == ';') return p + 1;
    if (*p != '{') return p;
    int depth = 0;
    for (; *p; p++) {
        if (*p == '{') depth++;
        else if (*p == '}' && --depth == 0) break;
    }
    if (!*p) return p;
    p = skip_space(p + 1);
    return *p == ';' ? p + 1 : p;
}

static const char *parse_recovering(Model *model, const char *s) {
    jmp_buf recover;
    model->recover = &recover;
    if (setjmp(recover)) return skip_statement(s);
    return parse_statement(model, s);
}

static void outline_write(Model *model, const char *text, size_t length) {
    Out *out = &model->outline;
    if (out->capacity < out->length + length + 1) {
        out->capacity = (out->length + length + 1) * 2;
        out->text = realloc(out->text, out->capacity);
        if (!out->text) { fprintf(stderr, "out of memory\n"); exit(1); }
    }
    memcpy(out->text + out->length, text, length);
    out->length += length;
    out->text[out->length] = '\0';
}

static void outline_keep(Model *model, const char *from, const char *to) {
    outline_write(model, from, (size_t)(to - from));
}

static void outline_blank(Model *model, const char *from, const char *to) {
    for (const char *c = from; c < to; c++) outline_write(model, *c == '\n' ? "\n" : " ", 1);
}

/* Every word stays where it was written, so what parses here has source
 * positions. `entity` and `struct` have the same length, and a struct's
 * column declarations are already a struct's fields. */
static void outline_statement(Model *model, const char *line, const char *end) {
    const Entity *entity = model->closed_entity;
    model->closed_entity = NULL;
    if (!entity) {
        outline_blank(model, line, end);
        return;
    }
    outline_keep(model, line, entity->keyword);
    outline_write(model, "struct", strlen("struct"));
    outline_keep(model, entity->keyword + strlen("entity"), entity->name_end);
    outline_blank(model, entity->name_end, entity->body_open);
    const char *after = entity->body_close + 1;
    outline_keep(model, entity->body_open, after);
    if (end > after && end[-1] == ';') {
        outline_keep(model, after, end);
        return;
    }
    /* A struct needs the `;` that an entity may leave out. */
    outline_write(model, ";", 1);
    if (after < end && (*after == ' ' || *after == '\t')) after++;
    outline_keep(model, after, end);
}

static void expand(Model *model) {
    /* The relations of an entity generate into its row, so everything is
     * read before anything is written. Other lines pass straight through. */
    const char *source = model->source;
    const char *p = source;
    while (*p) {
        const char *line = p;
        const char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        const char *end = model->tracing ? parse_recovering(model, s) : parse_statement(model, s);
        if (end) {
            if (model->tracing) outline_statement(model, line, end);
            p = end;
            continue;
        }
        const char *newline = strchr(line, '\n');
        size_t length = newline ? (size_t)(newline - line) + 1 : strlen(line);
        emit(model, "%.*s", (int)length, line);
        if (model->tracing) outline_write(model, line, length);
        p = line + length;
    }

    model->generating = 1;
    model->trace.generated_offset = model->out.length;
    model->origin = NO_SPAN;
    if (!strstr(source, "core/option.mln")) emit(model, "\nimport { Option } from \"@std/core/option.mln\";\n");
    if (!strstr(source, "core/iter.mln")) emit(model, "import { Iterator } from \"@std/core/iter.mln\";\n\n");
    if (model->trace.error_count) return;

    for (int i = 0; i < model->entity_count; i++) {
        model->origin = model->entities[i].span;
        emit(model, "/** The id of a %s row. Zero names no row. */\nexport struct %s { i32 id; };\n\n",
             model->entities[i].name, model->entities[i].name);
    }
    for (int i = 0; i < model->entity_count; i++) emit_row_struct(model, &model->entities[i]);
    for (int i = 0; i < model->entity_count; i++) emit_entity_core(model, &model->entities[i]);
    for (int i = 0; i < model->relation_count; i++) {
        const Relation *r = &model->relations[i];
        if (r->owns || r->many) emit_chain(model, r);
        else emit_reference(model, r);
    }
    for (int i = 0; i < model->index_count; i++) emit_index(model, &model->indexes[i]);
    for (int i = 0; i < model->entity_count; i++) emit_delete(model, &model->entities[i]);
}

static Model *model_create(const char *source, const char *path) {
    Model *model = calloc(1, sizeof(Model));
    if (!model) { fprintf(stderr, "out of memory\n"); exit(1); }
    model->path = path;
    model->source = source;
    return model;
}

char *model_expand(const char *source, const char *path) {
    Model *model = model_create(source, path);
    expand(model);
    char *text = model->out.text ? model->out.text : strdup("");
    free(model);
    return text;
}

ModelTrace *model_trace(const char *source) {
    Model *model = model_create(source, NULL);
    model->tracing = 1;
    expand(model);

    ModelTrace *trace = malloc(sizeof(ModelTrace));
    if (!trace) { fprintf(stderr, "out of memory\n"); exit(1); }
    *trace = model->trace;
    const Out *outline = &model->outline;
    if (outline->length && outline->text[outline->length - 1] != '\n') outline_write(model, "\n", 1);
    const char *generated = model->out.text ? model->out.text + trace->generated_offset : "";
    trace->generated_offset = outline->length;
    trace->generated_line = 0;
    for (size_t i = 0; i < outline->length; i++)
        if (outline->text[i] == '\n') trace->generated_line++;
    trace->text = malloc(outline->length + strlen(generated) + 1);
    if (!trace->text) { fprintf(stderr, "out of memory\n"); exit(1); }
    if (outline->length) memcpy(trace->text, outline->text, outline->length);
    strcpy(trace->text + outline->length, generated);
    free(model->outline.text);
    free(model->out.text);
    free(model);
    return trace;
}

void model_trace_free(ModelTrace *trace) {
    free(trace->text);
    free(trace->origins);
    free(trace->words);
    free(trace->errors);
    free(trace);
}
