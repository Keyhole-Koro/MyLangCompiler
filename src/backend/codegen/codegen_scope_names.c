#include "mylang/backend/codegen_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Codegen keys a function's locals by name (collect_locals, find_var_offset,
 * find_local_info). Two declarations of one name in different scopes --
 * sibling `if` blocks, or an inner block shadowing an outer local -- would
 * then share one slot, one type, and one size: the second `request` read
 * its fields at the first one's offsets. Before a function is emitted, every
 * declaration after the first of its name gets a function-unique spelling
 * (`request__s2`), and every reference resolved through the scopes follows.
 * Semantic analysis has already run, so diagnostics keep the written names.
 */

typedef struct {
    char *written;   // name as declared
    char *spelling;  // name codegen sees (== written for the first one)
} ScopeBinding;

typedef struct {
    ScopeBinding *bindings;
    int count, cap;
    int *marks;          // binding count at each open scope
    int mark_count, mark_cap;
    char **used;         // every spelling in the function
    int used_count, used_cap;
    char **replaced;     // written names of renamed declarations
    int replaced_count, replaced_cap;
} ScopeNames;

static void *grow(void *items, int *cap, int need, size_t size)
{
    if (need <= *cap) return items;
    int next = *cap ? *cap * 2 : 16;
    while (next < need) next *= 2;
    void *grown = realloc(items, (size_t)next * size);
    if (!grown) { fputs("out of memory renaming locals\n", stderr); exit(1); }
    *cap = next;
    return grown;
}

static char *dup_name(const char *s)
{
    size_t n = strlen(s) + 1;
    char *copy = malloc(n);
    if (!copy) { fputs("out of memory renaming locals\n", stderr); exit(1); }
    memcpy(copy, s, n);
    return copy;
}

static int is_used(ScopeNames *S, const char *name)
{
    for (int i = 0; i < S->used_count; i++)
        if (strcmp(S->used[i], name) == 0) return 1;
    return 0;
}

static void note_used(ScopeNames *S, const char *name)
{
    S->used = grow(S->used, &S->used_cap, S->used_count + 1, sizeof *S->used);
    S->used[S->used_count++] = (char *)name;
}

static void open_scope(ScopeNames *S)
{
    S->marks = grow(S->marks, &S->mark_cap, S->mark_count + 1, sizeof *S->marks);
    S->marks[S->mark_count++] = S->count;
}

static void close_scope(ScopeNames *S)
{
    S->count = S->marks[--S->mark_count];
}

static void bind(ScopeNames *S, char *written, char *spelling)
{
    S->bindings = grow(S->bindings, &S->cap, S->count + 1, sizeof *S->bindings);
    S->bindings[S->count++] = (ScopeBinding){ written, spelling };
}

static const char *lookup(ScopeNames *S, const char *name)
{
    for (int i = S->count - 1; i >= 0; i--)
        if (strcmp(S->bindings[i].written, name) == 0) return S->bindings[i].spelling;
    return NULL;
}

/* Compiler temporaries (`__mlg_ret_3`) are unique already, and some are
 * found again by their spelling. */
static int is_internal(const char *name)
{
    return name[0] == '_' && name[1] == '_';
}

/* Declares `*name` in the innermost scope, renaming it when the function
 * already has a local or parameter of that spelling. */
static void declare(ScopeNames *S, char **name)
{
    if (!*name || is_internal(*name)) return;
    char *written = *name;
    if (is_used(S, written)) {
        size_t len = strlen(written) + 16;
        char *fresh = malloc(len);
        if (!fresh) { fputs("out of memory renaming locals\n", stderr); exit(1); }
        int n = 2;
        do { snprintf(fresh, len, "%s__s%d", written, n++); } while (is_used(S, fresh));
        *name = fresh;
        bind(S, written, fresh);
        note_used(S, fresh);
        // Bindings still compare against the written name; free it last.
        S->replaced = grow(S->replaced, &S->replaced_cap, S->replaced_count + 1, sizeof *S->replaced);
        S->replaced[S->replaced_count++] = written;
        return;
    }
    bind(S, written, written);
    note_used(S, written);
}

static void respell(ScopeNames *S, char **name)
{
    if (!*name) return;
    const char *spelling = lookup(S, *name);
    if (spelling && strcmp(spelling, *name) != 0) {
        free(*name);
        *name = dup_name(spelling);
    }
}

static void walk(ScopeNames *S, ASTNode *node);

static void walk_child(ASTNode **child, void *ctx)
{
    walk(ctx, *child);
}

static void walk_scoped(ScopeNames *S, ASTNode *node)
{
    open_scope(S);
    walk(S, node);
    close_scope(S);
}

static void walk(ScopeNames *S, ASTNode *node)
{
    if (!node) return;
    switch (node->type) {
    case AST_IDENTIFIER:
        respell(S, &node->identifier.name);
        return;
    case AST_CALL:
        // A call through a local function pointer names the local.
        respell(S, &node->call.name);
        ast_visit_children(node, walk_child, S);
        return;
    case AST_VAR_DECL:
        // The initializer is outside the new name's scope.
        walk(S, node->var_decl.init);
        declare(S, &node->var_decl.name);
        return;
    case AST_BLOCK:
        open_scope(S);
        for (int i = 0; i < node->block.count; i++) walk(S, node->block.stmts[i]);
        close_scope(S);
        return;
    case AST_FOR:
        open_scope(S);
        walk(S, node->for_stmt.init);
        walk(S, node->for_stmt.cond);
        walk(S, node->for_stmt.inc);
        walk_scoped(S, node->for_stmt.body);
        close_scope(S);
        return;
    case AST_IF:
        walk(S, node->if_stmt.cond);
        walk_scoped(S, node->if_stmt.then_stmt);
        walk_scoped(S, node->if_stmt.else_stmt);
        return;
    case AST_WHILE:
        walk(S, node->while_stmt.cond);
        walk_scoped(S, node->while_stmt.body);
        return;
    case AST_DO_WHILE:
        walk_scoped(S, node->do_while_stmt.body);
        walk(S, node->do_while_stmt.cond);
        return;
    case AST_CASE:
        walk(S, node->case_expr.target);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            walk(S, node->case_expr.cases[i].key);
            walk_scoped(S, node->case_expr.cases[i].expr);
        }
        walk_scoped(S, node->case_expr.default_expr);
        return;
    case AST_FUN_LITERAL:
        open_scope(S);
        for (int i = 0; i < node->fun_literal.param_count; i++) {
            ASTNode *p = node->fun_literal.params[i];
            if (p && p->type == AST_PARAM) declare(S, &p->param.name);
        }
        walk(S, node->fun_literal.body);
        close_scope(S);
        return;
    case AST_TYPE: case AST_TYPE_GENERIC: case AST_TYPE_ARRAY: case AST_TYPE_FUNCTION:
        return;
    default:
        ast_visit_children(node, walk_child, S);
        return;
    }
}

void codegen_give_locals_unique_names(ASTNode *fn)
{
    if (!fn || fn->type != AST_FUNDEF || !fn->fundef.body) return;
    ScopeNames S = {0};
    open_scope(&S);
    for (int i = 0; i < fn->fundef.param_count; i++) {
        ASTNode *p = fn->fundef.params[i];
        if (p && p->type == AST_PARAM && p->param.name) {
            bind(&S, p->param.name, p->param.name);
            note_used(&S, p->param.name);
        }
    }
    walk(&S, fn->fundef.body);
    close_scope(&S);
    for (int i = 0; i < S.replaced_count; i++) free(S.replaced[i]);
    free(S.replaced);
    free(S.bindings);
    free(S.marks);
    free(S.used);
}
