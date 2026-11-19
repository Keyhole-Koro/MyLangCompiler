/* Modules kept from one unit to the next in a process that compiles several
 * (mlc --serve).
 *
 * Loading an imported module -- lexing it, parsing it, lowering its generics
 * -- is most of what compiling a unit costs, and a unit loads every module it
 * imports, transitively. A build compiles each source as a unit, so it used
 * to load the modules at the bottom of the graph once per unit. A serving
 * process keeps each module it loads and gives the same Module to the next
 * unit that imports it.
 *
 * A kept module has to be the module that unit would have loaded itself. Its
 * load depends on its source and its imports' (which do not change during a
 * build), on the loader's aliases (compared), and on what the session's graph
 * held while it loaded: the loads it started, and the lookups that search
 * every module in the graph (import_private_name, preserved_payload_enum).
 * So each load is recorded as the events it went through, in order. Giving
 * the module to a later unit replays them: the same imports are loaded at the
 * same points, and every lookup has to find the module it found the first
 * time. One that finds another is a conflict, which module_cache_take_conflict
 * reports so that the unit is compiled again by a process of its own.
 *
 * A module is not kept if its load failed, if it met a module still loading
 * (an import cycle), if an import or a lookup gave it a module that was not
 * kept, or if it searched the graph for a package (load_package_generic_
 * function), which is not recorded. */

#include "mylang/frontend/module.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
    EVENT_LOAD,
    EVENT_LOOKUP,
} EventKind;

typedef struct {
    EventKind kind;
    ModuleLookupKind lookup;
    char *key;       /* the canonical path loaded, or what was looked up */
    Module *result;  /* the kept module it came to; NULL for a lookup that found none */
} CacheEvent;

typedef struct {
    Module *module;
    char *aliases;
    CacheEvent *events;
    int event_count;
} CacheEntry;

/* A load in progress. A replay records nothing: its events are the entry's. */
typedef struct {
    int recording;
    int keepable;
    CacheEvent *events;
    int event_count;
    int event_capacity;
} LoadFrame;

static int g_enabled;
static int g_conflict;
static CacheEntry *g_entries;
static int g_entry_count;
static int g_entry_capacity;
static LoadFrame *g_frames;
static int g_frame_count;
static int g_frame_capacity;

void module_cache_enable(void) {
    g_enabled = 1;
}

int module_cache_take_conflict(void) {
    int conflict = g_conflict;
    g_conflict = 0;
    return conflict;
}

static LoadFrame *current_frame(void) {
    return g_frame_count > 0 ? &g_frames[g_frame_count - 1] : NULL;
}

static void push_frame(int recording) {
    if (g_frame_count == g_frame_capacity) {
        g_frame_capacity = g_frame_capacity ? g_frame_capacity * 2 : 16;
        g_frames = realloc(g_frames, sizeof(LoadFrame) * (size_t)g_frame_capacity);
    }
    g_frames[g_frame_count++] = (LoadFrame){ .recording = recording, .keepable = 1 };
}

static void free_events(CacheEvent *events, int count) {
    for (int i = 0; i < count; i++) free(events[i].key);
    free(events);
}

/* Every load in progress has now met something it cannot be kept with. */
static void spoil_all_frames(void) {
    for (int i = 0; i < g_frame_count; i++) g_frames[i].keepable = 0;
}

static CacheEvent *add_event(EventKind kind, ModuleLookupKind lookup, const char *key) {
    LoadFrame *frame = current_frame();
    if (!frame || !frame->recording) return NULL;
    if (frame->event_count == frame->event_capacity) {
        frame->event_capacity = frame->event_capacity ? frame->event_capacity * 2 : 16;
        frame->events = realloc(frame->events, sizeof(CacheEvent) * (size_t)frame->event_capacity);
    }
    CacheEvent *event = &frame->events[frame->event_count++];
    *event = (CacheEvent){ .kind = kind, .lookup = lookup, .key = strdup(key ? key : "") };
    return event;
}

static char *alias_fingerprint(const ModuleLoader *loader) {
    size_t size = 1;
    for (int i = 0; i < loader->alias_count; i++)
        size += strlen(loader->aliases[i].name) + strlen(loader->aliases[i].target) + 2;
    char *text = malloc(size);
    if (!text) return NULL;
    text[0] = '\0';
    for (int i = 0; i < loader->alias_count; i++) {
        strcat(text, loader->aliases[i].name);
        strcat(text, "=");
        strcat(text, loader->aliases[i].target);
        strcat(text, "\n");
    }
    return text;
}

static CacheEntry *find_entry(const char *canonical) {
    for (int i = 0; i < g_entry_count; i++) {
        if (strcmp(g_entries[i].module->canonical_path, canonical) == 0) return &g_entries[i];
    }
    return NULL;
}

/* An event's result: the module only when it is kept, as only a kept module
 * is the same object in every unit. */
static void note_result(CacheEvent *event, Module *module) {
    LoadFrame *frame = current_frame();
    if (module && !module->cached && frame) frame->keepable = 0;
    if (event) event->result = module;
}

/* What a lookup finds in the graph now, as the parser's lookup would. */
static Module *redo_lookup(const ModuleGraph *graph, ModuleLookupKind lookup, const char *key) {
    for (int m = 0; m < graph->module_count; m++) {
        Module *module = graph->modules[m];
        if (!module_is_published(module)) continue;
        if (lookup == MODULE_LOOKUP_LINK_NAME) {
            for (int s = 0; s < module->symbol_count; s++) {
                if (module->symbols[s].link_name && strcmp(module->symbols[s].link_name, key) == 0)
                    return module;
            }
        } else {
            for (int i = 0; i < module->exported_payload_enum_count; i++) {
                ASTNode *candidate = module->exported_payload_enums[i];
                if (candidate && candidate->type == AST_ENUM && candidate->enum_stmt.name &&
                    strcmp(candidate->enum_stmt.name, key) == 0)
                    return module;
            }
        }
    }
    return NULL;
}

Module *module_cache_load(ModuleLoader *loader, const char *canonical) {
    if (!g_enabled) return NULL;
    CacheEntry *entry = find_entry(canonical);
    if (!entry) return NULL;
    char *aliases = alias_fingerprint(loader);
    int same_aliases = aliases && strcmp(aliases, entry->aliases) == 0;
    free(aliases);
    if (!same_aliases) return NULL;

    Module *module = entry->module;
    if (!module_graph_add_existing(loader->graph, module)) return NULL;
    module->state = MODULE_LOADING;
    push_frame(0);
    for (int i = 0; i < entry->event_count; i++) {
        CacheEvent *event = &entry->events[i];
        Module *now = event->kind == EVENT_LOAD
            ? module_loader_load_canonical(loader, event->key)
            : redo_lookup(loader->graph, event->lookup, event->key);
        if (now != event->result) g_conflict = 1;
    }
    g_frame_count--;
    module->state = MODULE_LOADED;
    return module;
}

void module_cache_note_load(const char *canonical, Module *existing) {
    if (!g_enabled) return;
    /* A module still loading is an import cycle: what each of its modules
     * holds depends on which one was loaded first. */
    if (existing && existing->state == MODULE_LOADING) spoil_all_frames();
    add_event(EVENT_LOAD, MODULE_LOOKUP_LINK_NAME, canonical);
}

void module_cache_note_loaded(const char *canonical, Module *module) {
    if (!g_enabled) return;
    LoadFrame *frame = current_frame();
    if (!frame || !frame->recording) return;
    /* The load event this call recorded is the last one for canonical. */
    for (int i = frame->event_count - 1; i >= 0; i--) {
        CacheEvent *event = &frame->events[i];
        if (event->kind == EVENT_LOAD && strcmp(event->key, canonical) == 0) {
            note_result(event, module);
            return;
        }
    }
}

void module_cache_note_lookup(ModuleLookupKind lookup, const char *key, Module *found) {
    if (!g_enabled) return;
    note_result(add_event(EVENT_LOOKUP, lookup, key), found);
}

void module_cache_note_unrecorded_lookup(void) {
    if (!g_enabled) return;
    LoadFrame *frame = current_frame();
    if (frame) frame->keepable = 0;
}

void module_cache_begin_load(void) {
    if (!g_enabled) return;
    push_frame(1);
}

void module_cache_end_load(ModuleLoader *loader, Module *module) {
    if (!g_enabled || g_frame_count == 0) return;
    LoadFrame frame = g_frames[--g_frame_count];
    char *aliases = frame.keepable && module && module->state == MODULE_LOADED
        ? alias_fingerprint(loader) : NULL;
    if (!aliases) {
        free_events(frame.events, frame.event_count);
        /* A module set aside is not something its importer can be kept with. */
        LoadFrame *parent = current_frame();
        if (parent) parent->keepable = 0;
        return;
    }
    if (g_entry_count == g_entry_capacity) {
        g_entry_capacity = g_entry_capacity ? g_entry_capacity * 2 : 64;
        g_entries = realloc(g_entries, sizeof(CacheEntry) * (size_t)g_entry_capacity);
    }
    module->cached = 1;
    g_entries[g_entry_count++] = (CacheEntry){
        .module = module,
        .aliases = aliases,
        .events = frame.events,
        .event_count = frame.event_count,
    };
}
