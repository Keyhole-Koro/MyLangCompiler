#include "mylang/frontend/model_expand.h"

#include <ctype.h>
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
} Column;

typedef struct {
    char name[MODEL_NAME_CAP];
    char lower[MODEL_NAME_CAP];
    int max;
    Column columns[MODEL_MAX_COLUMNS];
    int column_count;
} Entity;

typedef struct {
    int owns;       /* `has`: the left side's death takes the right side along */
    int many;
    Entity *left;
    Entity *right;
    char name[MODEL_NAME_CAP];
    char inverse[MODEL_NAME_CAP];
} Relation;

typedef struct {
    Entity *entity;
    char column[MODEL_NAME_CAP];
    int unique;
    int buckets;
} Index;

typedef struct {
    char *text;
    size_t length;
    size_t capacity;
} Out;

typedef struct {
    const char *path;
    int line;
    Entity entities[MODEL_MAX_ENTITIES];
    int entity_count;
    Relation relations[MODEL_MAX_RELATIONS];
    int relation_count;
    Index indexes[MODEL_MAX_INDEXES];
    int index_count;
    Out out;
} Model;

static void model_error(const Model *model, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "%s:%d:1: error: ", model->path ? model->path : "<model>", model->line);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
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
            out->length += (size_t)wanted;
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

static Entity *find_entity(Model *model, const char *name) {
    for (int i = 0; i < model->entity_count; i++)
        if (strcmp(model->entities[i].name, name) == 0) return &model->entities[i];
    return NULL;
}

static Entity *require_entity(Model *model, const char *name) {
    Entity *entity = find_entity(model, name);
    if (!entity) model_error(model, "unknown entity '%s'", name);
    return entity;
}

/* `i32 kind;` or `Text<64> text;` or `i32 samples[8];`. */
static const char *parse_column(Model *model, Entity *entity, const char *p) {
    if (entity->column_count >= MODEL_MAX_COLUMNS) model_error(model, "too many columns");
    Column *column = &entity->columns[entity->column_count++];
    const char *end = strchr(p, ';');
    if (!end) model_error(model, "expected ';' after a column of entity '%s'", entity->name);
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
    while (q > p && isspace((unsigned char)q[-1])) q--;
    snprintf(column->type, sizeof(column->type), "%.*s", (int)(q - p), p);
    if (!column->name[0] || !column->type[0]) model_error(model, "malformed column in entity '%s'", entity->name);
    (void)suffix;
    return end + 1;
}

/* `entity Node max 512 { ... }`. */
static const char *parse_entity(Model *model, const char *p) {
    if (model->entity_count >= MODEL_MAX_ENTITIES) model_error(model, "too many entities");
    Entity *entity = &model->entities[model->entity_count++];
    memset(entity, 0, sizeof(*entity));
    p = skip_space(p + strlen("entity"));
    p = read_word(p, entity->name, sizeof(entity->name));
    for (int i = 0; entity->name[i]; i++) entity->lower[i] = (char)tolower((unsigned char)entity->name[i]);
    if (!entity->name[0]) model_error(model, "expected an entity name");
    p = skip_space(p);
    char word[MODEL_NAME_CAP];
    p = read_word(p, word, sizeof(word));
    if (strcmp(word, "max") != 0) model_error(model, "entity '%s' needs `max N`", entity->name);
    entity->max = (int)strtol(skip_space(p), (char **)&p, 10);
    if (entity->max <= 0 || entity->max > ID_MAX_ROWS)
        model_error(model, "entity '%s': max must be between 1 and %d", entity->name, ID_MAX_ROWS);
    p = skip_space(p);
    if (*p != '{') model_error(model, "expected '{' after `max %d`", entity->max);
    p = skip_space(p + 1);
    while (*p && *p != '}') {
        if (*p == '/' && p[1] == '/') {
            while (*p && *p != '\n') p++;
        } else {
            p = parse_column(model, entity, p);
        }
        p = skip_space(p);
    }
    if (*p != '}') model_error(model, "unterminated entity '%s'", entity->name);
    p++;
    p = skip_space(p);
    if (*p == ';') p++;
    return p;
}

/* `Node has many Node as children / parent;`, `Window knows one Node as focus;`. */
static const char *parse_relation(Model *model, const char *p) {
    if (model->relation_count >= MODEL_MAX_RELATIONS) model_error(model, "too many relations");
    Relation *relation = &model->relations[model->relation_count++];
    memset(relation, 0, sizeof(*relation));
    char left[MODEL_NAME_CAP], verb[MODEL_NAME_CAP], count[MODEL_NAME_CAP];
    char right[MODEL_NAME_CAP], as[MODEL_NAME_CAP];
    p = read_word(p, left, sizeof(left));
    p = read_word(skip_space(p), verb, sizeof(verb));
    p = read_word(skip_space(p), count, sizeof(count));
    p = read_word(skip_space(p), right, sizeof(right));
    p = read_word(skip_space(p), as, sizeof(as));
    if (strcmp(as, "as") != 0) model_error(model, "expected `as name` in the relation of '%s'", left);
    p = read_word(skip_space(p), relation->name, sizeof(relation->name));
    relation->left = require_entity(model, left);
    relation->right = require_entity(model, right);
    relation->owns = strcmp(verb, "has") == 0;
    if (strcmp(count, "many") == 0) relation->many = 1;
    else if (strcmp(count, "one") != 0) model_error(model, "expected `one` or `many`, got '%s'", count);
    p = skip_space(p);
    if (*p == '/') {
        p = skip_space(p + 1);
        char first[MODEL_NAME_CAP];
        const char *after = read_word(p, first, sizeof(first));
        if (strcmp(first, "many") == 0) {
            model_error(model, "a many-to-many relation is not supported yet: keep the pairs in an entity of their own");
        }
        snprintf(relation->inverse, sizeof(relation->inverse), "%s", first);
        p = skip_space(after);
    }
    /* `ordered` documents the contract: every chain keeps insertion order. */
    if (*p == ',') {
        char option[MODEL_NAME_CAP];
        p = read_word(skip_space(p + 1), option, sizeof(option));
        if (strcmp(option, "ordered") != 0) model_error(model, "unknown relation option '%s'", option);
        p = skip_space(p);
    }
    if (*p != ';') model_error(model, "expected ';' after the relation '%s'", relation->name);
    return p + 1;
}

/* `index Node.owner;`, `unique Process.pid;`. */
static const char *parse_index(Model *model, const char *p, int unique) {
    if (model->index_count >= MODEL_MAX_INDEXES) model_error(model, "too many indexes");
    Index *index = &model->indexes[model->index_count++];
    memset(index, 0, sizeof(*index));
    index->unique = unique;
    p = skip_space(p + (unique ? strlen("unique") : strlen("index")));
    char entity[MODEL_NAME_CAP];
    p = read_word(p, entity, sizeof(entity));
    index->entity = require_entity(model, entity);
    if (*p != '.') model_error(model, "expected Entity.column after `index`");
    p = read_word(p + 1, index->column, sizeof(index->column));
    int found = 0;
    for (int i = 0; i < index->entity->column_count; i++) {
        Column *column = &index->entity->columns[i];
        if (strcmp(column->name, index->column) == 0) {
            if (strcmp(column->type, "i32") != 0)
                model_error(model, "only an i32 column can be indexed: '%s'", index->column);
            found = 1;
        }
    }
    if (!found) model_error(model, "entity '%s' has no column '%s'", entity, index->column);
    index->buckets = 1;
    while (index->buckets < index->entity->max) index->buckets *= 2;
    p = skip_space(p);
    if (*p != ';') model_error(model, "expected ';' after the index");
    return p + 1;
}

static int column_is_indexed(const Model *model, const Entity *entity, const char *column) {
    for (int i = 0; i < model->index_count; i++)
        if (model->indexes[i].entity == entity && strcmp(model->indexes[i].column, column) == 0)
            return 1;
    return 0;
}

static void emit_row_struct(Model *model, const Entity *entity) {
    emit(model, "export struct %sRow {\n", entity->name);
    for (int i = 0; i < entity->column_count; i++) {
        const Column *column = &entity->columns[i];
        /* An indexed column changes through its setter only, which keeps the
         * index right; row() does not expose it. */
        const char *prefix = column_is_indexed(model, entity, column->name) ? "__ix_" : "";
        emit(model, "    %s %s%s%s;\n", column->type, prefix, column->name, column->suffix);
    }
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
         "export borrow mut %sRow (%s x) row() { return &mut g_%s_rows[%s_checked(x)]; }\n\n",
         T, T, t, t);
    emit(model,
         "export struct %s_all_Iter { i32 next; };\n\n"
         "export impl Iterator<%s> for %s_all_Iter {\n"
         "    Option<%s> (borrow mut Self self) next() {\n"
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
         "export borrow mut %sRow %s_row_id(i32 id) {\n"
         "    i32 s = (id & %d) - 1;\n"
         "    if (s < 0 || s >= %d || !g_%s_rows[s].__used || g_%s_rows[s].__gen != ((id >> %d) & 0xFFFFF)) {\n"
         "        s = %d;\n"
         "    }\n"
         "    return &mut g_%s_rows[s];\n"
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
        emit(model,
             "export Option<%s> (%s member) %s() {\n"
             "    i32 ref = g_%s_rows[%s_checked(member)].__%s_owner;\n"
             "    if (ref == 0) { return None; }\n"
             "    %s found = %s_at(ref);\n"
             "    return Some(found);\n"
             "}\n\n", A, B, r->inverse, b, b, n, A, a);
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
        emit(model,
             "export i32 %s_%s_id(i32 member) {\n"
             "    i32 ref = %s_row_id(member).__%s_owner;\n"
             "    if (ref == 0) { return 0; }\n"
             "    return (g_%s_rows[ref - 1].__gen << %d) | ref;\n"
             "}\n\n", b, r->inverse, b, n, a, ID_SLOT_BITS);
    }
    /* The next member is read before one is handed out, so the loop body may
     * move or delete the member it was given. */
    emit(model,
         "export struct %s_%s_Iter { i32 next; };\n\n"
         "export impl Iterator<%s> for %s_%s_Iter {\n"
         "    Option<%s> (borrow mut Self self) next() {\n"
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
         "    Option<%s> (borrow mut Self self) next() {\n"
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

char *model_expand(const char *source, const char *path) {
    Model *model = calloc(1, sizeof(Model));
    if (!model) { fprintf(stderr, "out of memory\n"); exit(1); }
    model->path = path;
    model->line = 1;

    /* The relations of an entity generate into its row, so everything is
     * read before anything is written. Other lines pass straight through. */
    const char *p = source;
    while (*p) {
        const char *line = p;
        const char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        const char *end = NULL;
        if (starts_with_word(s, "entity")) end = parse_entity(model, s);
        else if (starts_with_word(s, "unique")) end = parse_index(model, s, 1);
        else if (starts_with_word(s, "index")) end = parse_index(model, s, 0);
        else if (is_relation_line(s)) end = parse_relation(model, s);
        if (end) {
            for (const char *c = line; c < end; c++) if (*c == '\n') model->line++;
            p = end;
            continue;
        }
        const char *newline = strchr(line, '\n');
        size_t length = newline ? (size_t)(newline - line) + 1 : strlen(line);
        emit(model, "%.*s", (int)length, line);
        model->line++;
        p = line + length;
    }

    if (!strstr(source, "core/option.mln")) emit(model, "\nimport { Option } from \"@std/core/option.mln\";\n");
    if (!strstr(source, "core/iter.mln")) emit(model, "import { Iterator } from \"@std/core/iter.mln\";\n\n");

    for (int i = 0; i < model->entity_count; i++)
        emit(model, "/** The id of a %s row. Zero names no row. */\nexport struct %s { i32 id; };\n\n",
             model->entities[i].name, model->entities[i].name);
    for (int i = 0; i < model->entity_count; i++) emit_row_struct(model, &model->entities[i]);
    for (int i = 0; i < model->entity_count; i++) emit_entity_core(model, &model->entities[i]);
    for (int i = 0; i < model->relation_count; i++) {
        const Relation *r = &model->relations[i];
        if (r->owns || r->many) emit_chain(model, r);
        else emit_reference(model, r);
    }
    for (int i = 0; i < model->index_count; i++) emit_index(model, &model->indexes[i]);
    for (int i = 0; i < model->entity_count; i++) emit_delete(model, &model->entities[i]);

    char *text = model->out.text ? model->out.text : strdup("");
    free(model);
    return text;
}
