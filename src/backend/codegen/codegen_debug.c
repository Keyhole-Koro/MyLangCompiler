#include "mylang/backend/codegen_internal.h"

/* `--line-info`: `.func`, `.loc` and `.cost` lines in the assembly, for tools
 * that turn an address back into a source position. None of them changes the
 * code, so an image is the same with or without the flag. */

/* Cost regions nest: the copy of a dropped field is inside the drop. Leaving
 * one returns to the region around it. */
#define COST_DEPTH 8

static int g_line_info = 0;
static const char *g_costs[COST_DEPTH];
static int g_cost_depth = 0;

void codegen_set_line_info(int enabled) {
    g_line_info = enabled;
}

void codegen_debug_func(StringBuilder *sb, const char *name, const char *file, int line) {
    g_cost_depth = 0;
    if (!g_line_info) return;
    sb_append(sb, "  .func \"%s\" \"%s\"\n", name, file ? file : "");
    codegen_debug_loc(sb, line);
}

void codegen_debug_loc(StringBuilder *sb, int line) {
    if (g_line_info && line > 0) sb_append(sb, "  .loc %d\n", line);
}

void codegen_cost_begin(StringBuilder *sb, const char *kind) {
    if (g_cost_depth < COST_DEPTH) g_costs[g_cost_depth] = kind;
    g_cost_depth++;
    if (g_line_info) sb_append(sb, "  .cost \"%s\"\n", kind);
}

void codegen_cost_end(StringBuilder *sb) {
    if (g_cost_depth > 0) g_cost_depth--;
    if (!g_line_info) return;
    int top = g_cost_depth < COST_DEPTH ? g_cost_depth : COST_DEPTH;
    sb_append(sb, "  .cost \"%s\"\n", top > 0 ? g_costs[top - 1] : "");
}
