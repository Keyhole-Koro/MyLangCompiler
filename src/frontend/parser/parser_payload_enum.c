#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

/* Lowers payload enum *uses* onto the struct layout parser_instantiate.c gives
 * their declarations.
 *
 * A specialized `enum Result<i32, char> { Ok(T), Err(E) }` becomes
 *
 *     struct Result_i32_char { i32 __tag; i32 Ok; char Err; }
 *
 * so a variant is a tag value plus one field named after it. That leaves two
 * surface forms to translate, and this file owns both:
 *
 *   Ok(5)           construction, only meaningful against a destination
 *   Ok(x) -> expr   a case arm, which binds the payload for the arm's body
 *
 * Construction has to be a statement rewrite rather than an expression one,
 * because the value being built is a struct and the backend cannot return one:
 * there is nowhere to put `Ok(5)` except directly into the variable it is
 * initialising. `T r = Ok(5);` therefore becomes `T r;` followed by the two
 * field stores, and a plain assignment expands the same way.
 *
 * A pattern binding is substituted rather than copied: `Ok(x) -> x + 1`
 * becomes `0 -> r.Ok + 1`, with every `x` in the arm replaced by the member
 * access. That avoids needing the payload's type here -- there is no inference
 * at this stage, and the variant name alone cannot say whether a `Result` came
 * from `<i32, char>` or `<char, i32>`. The binding aliases the field rather
 * than copying it, which is what a read-only match wants anyway; because the
 * access is re-evaluated per occurrence, a matched target has to be something
 * cheap and repeatable to name, which is checked below.
 */

/* Same shape as parser_instantiate.c's reporter: a node carries a position but
 * not a token, and parse_error wants one. */
static void payload_error(ParserContext *context, ASTNode *node, const char *message) {
    Token location = {0};
    location.line = node ? node->line : 0;
    location.col = node ? node->col : 0;
    parse_error(context, message, &location);
}

typedef struct {
    char *variant; /* variant name, and the payload field name when it has one */
    long tag;
    int has_payload;
    int ambiguous; /* the same name at different tags in different enums */
    const char *enum_name;
} VariantTag;

typedef struct {
    VariantTag *items;
    int count;
    ParserContext *context;
} VariantTable;

static VariantTag *find_variant(VariantTable *table, const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < table->count; i++)
        if (strcmp(table->items[i].variant, name) == 0) return &table->items[i];
    return NULL;
}

static void record_variant(VariantTable *table, const char *name, long tag,
                           int has_payload, const char *enum_name) {
    VariantTag *existing = find_variant(table, name);
    if (existing) {
        /* Two payload enums may name a variant the same way. That only matters
         * when their tags disagree, because then the name stops determining
         * what to compare against. Flag it and report at the use site, where
         * there is something to point at. */
        if (existing->tag != tag) existing->ambiguous = 1;
        return;
    }
    table->items = realloc(table->items, sizeof(VariantTag) * (table->count + 1));
    table->items[table->count].variant = strdup(name);
    table->items[table->count].tag = tag;
    table->items[table->count].has_payload = has_payload;
    table->items[table->count].ambiguous = 0;
    table->items[table->count].enum_name = enum_name;
    table->count++;
}

static void collect_variants(VariantTable *table, ASTNode *program) {
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->type != AST_ENUM || !node->enum_stmt.has_payloads) continue;
        for (int m = 0; m < node->enum_stmt.member_count; m++) {
            ASTNode *member = node->enum_stmt.members[m];
            if (!member) continue;
            record_variant(table, member->enum_member.name, member->enum_member.resolved_value,
                           member->enum_member.payload_type != NULL, node->enum_stmt.name);
        }
    }
}

/* A call whose callee names a payload variant, i.e. `Ok(expr)`. Nothing else in
 * the language spells a carrying construction that way, so the shape is the
 * test. */
static VariantTag *variant_call(VariantTable *table, ASTNode *node) {
    if (!node || node->type != AST_CALL || !node->call.name) return NULL;
    VariantTag *variant = find_variant(table, node->call.name);
    return variant && variant->has_payload ? variant : NULL;
}

/* A variant with nothing to carry is written bare, as `None` rather than
 * `None()`, both where it is built and where it is matched. */
static VariantTag *variant_bare(VariantTable *table, ASTNode *node) {
    if (!node || node->type != AST_IDENTIFIER || !node->identifier.name) return NULL;
    VariantTag *variant = find_variant(table, node->identifier.name);
    return variant && !variant->has_payload ? variant : NULL;
}

/* Either spelling. */
static VariantTag *variant_use(VariantTable *table, ASTNode *node) {
    VariantTag *variant = variant_call(table, node);
    return variant ? variant : variant_bare(table, node);
}

static void check_unambiguous(VariantTable *table, VariantTag *variant, ASTNode *at) {
    if (!variant->ambiguous) return;
    char message[256];
    snprintf(message, sizeof(message),
             "variant '%s' is declared by more than one payload enum with a different tag, "
             "so the name alone does not say which one is meant",
             variant->variant);
    payload_error(table->context, at, message);
}

static void check_single_payload(VariantTable *table, ASTNode *call) {
    if (call->call.arg_count == 1) return;
    char message[256];
    snprintf(message, sizeof(message), "variant '%s' carries one payload, but %d were given",
             call->call.name, call->call.arg_count);
    payload_error(table->context, call, message);
}

/* Specialization names an instance `__mlg_s_<len>_<template><args...>`
 * (parser_instantiate.c). A diagnostic should say `Result`, not that. The
 * length prefix makes the template name recoverable without guessing where the
 * arguments start. */
static const char *display_enum_name(const char *name) {
    static const char kPrefix[] = "__mlg_s_";
    if (!name || strncmp(name, kPrefix, sizeof(kPrefix) - 1) != 0) return name;

    const char *digits = name + sizeof(kPrefix) - 1;
    char *end = NULL;
    long length = strtol(digits, &end, 10);
    if (!end || *end != '_' || length <= 0) return name;
    return end + 1; /* the template name, followed by its encoded arguments */
}

/* Compares only the template name, so `Result<i32, char>` reads as `Result`
 * while two different specializations still stay distinct as full names. */
static void copy_display_name(char *out, size_t size, const char *name) {
    const char *display = display_enum_name(name);
    size_t length = 0;
    while (display[length] && display[length] != '_' && length + 1 < size) length++;
    memcpy(out, display, length);
    out[length] = '\0';
}

/* The declared type of the thing being built names its enum, so a variant from
 * a different one can be caught here rather than becoming a store to a field
 * the layout does not have. */
static void check_variant_belongs(VariantTable *table, ASTNode *type, VariantTag *variant,
                                  ASTNode *at) {
    if (!type || type->type != AST_TYPE || !type->type_node.base_type ||
        type->type_node.base_type->type != AST_IDENTIFIER)
        return;
    const char *declared = type->type_node.base_type->identifier.name;
    if (!variant->enum_name || !declared) return;
    if (strcmp(declared, variant->enum_name) == 0) return;

    /* Only complain when the declaration really is a payload enum; any other
     * type is somebody else's error to report. */
    int declared_is_payload_enum = 0;
    for (int i = 0; i < table->count; i++)
        if (table->items[i].enum_name && strcmp(table->items[i].enum_name, declared) == 0) {
            declared_is_payload_enum = 1;
            break;
        }
    if (!declared_is_payload_enum) return;

    char want[64], got[64];
    copy_display_name(want, sizeof(want), declared);
    copy_display_name(got, sizeof(got), variant->enum_name);
    char message[256];
    snprintf(message, sizeof(message), "'%s' is a variant of '%s', not of '%s'",
             variant->variant, got, want);
    payload_error(table->context, at, message);
}

static char *tag_text(long tag) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%ld", tag);
    return strdup(buf);
}

/* `dest.__tag = tag;` then `dest.<variant> = payload;` -- the two statements a
 * construction becomes. `dest` is cloned per statement because each owns its
 * copy. */
static void build_construction(VariantTable *table, ASTNode *dest, ASTNode *use,
                               ASTNode **out_tag, ASTNode **out_payload) {
    VariantTag *variant = variant_use(table, use);
    check_unambiguous(table, variant, use);

    char *text = tag_text(variant->tag);
    *out_tag = new_expr_stmt(new_assign(new_member_access(ast_clone(dest), "__tag"),
                                        new_number(text)));
    free(text);

    if (!variant->has_payload) {
        /* Nothing to store: the tag is the whole value. */
        *out_payload = NULL;
        return;
    }
    check_single_payload(table, use);
    *out_payload = new_expr_stmt(new_assign(new_member_access(ast_clone(dest), variant->variant),
                                            ast_clone(use->call.args[0])));
}

typedef struct {
    const char *name;
    ASTNode *replacement;
} Binding;

/* Replace every occurrence of `name` with a copy of `replacement`, binding a
 * pattern variable to the field it destructures. */
static void substitute_identifier(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    if (!node) return;
    Binding *binding = user_data;
    if (node->type == AST_IDENTIFIER && node->identifier.name &&
        strcmp(node->identifier.name, binding->name) == 0) {
        ASTNode *copy = ast_clone(binding->replacement);
        copy->line = node->line;
        copy->col = node->col;
        copy->end_line = node->end_line;
        copy->end_col = node->end_col;
        free_ast(node);
        *slot = copy;
        return;
    }
    ast_visit_children(node, substitute_identifier, user_data);
}

/* Naming the matched value again for each bound occurrence is only sound when
 * doing so is free of side effects and cheap. Identifiers and the accesses
 * built from them qualify; a call or an arithmetic expression does not. */
static int is_repeatable_target(ASTNode *node) {
    if (!node) return 0;
    switch (node->type) {
    case AST_IDENTIFIER:
        return 1;
    case AST_MEMBER_ACCESS:
        return is_repeatable_target(node->member_access.lhs);
    case AST_ARROW_ACCESS:
        return is_repeatable_target(node->arrow_access.lhs);
    case AST_UNARY:
        /* Dereferencing a name reads it again and nothing more. */
        return node->unary.op == ASTARISK && is_repeatable_target(node->unary.operand);
    default:
        return 0;
    }
}

static void rewrite_payload_node(ASTNode **slot, void *user_data);

/* `case r of { Ok(x) -> E; ... }` becomes `case r.__tag of { 0 -> E[x := r.Ok]; ... }`.
 * Arms that are not variant patterns are left alone, so a payload enum and a
 * plain integer case can be written the same way. */
/* Every variant of `enum_name` that no arm names, so a match can say what it
 * left out rather than silently falling through to zero. */
static void report_missing_arms(VariantTable *table, ASTNode *node, const char *enum_name,
                                const long *covered, int covered_count) {
    char missing[192];
    size_t used = 0;
    int count = 0;

    for (int i = 0; i < table->count; i++) {
        VariantTag *variant = &table->items[i];
        if (!variant->enum_name || strcmp(variant->enum_name, enum_name) != 0) continue;
        int seen = 0;
        for (int c = 0; c < covered_count; c++)
            if (covered[c] == variant->tag) { seen = 1; break; }
        if (seen) continue;
        int written = snprintf(missing + used, sizeof(missing) - used, "%s%s",
                               count ? ", " : "", variant->variant);
        if (written > 0 && used + (size_t)written < sizeof(missing)) used += (size_t)written;
        count++;
    }
    if (!count) return;

    char display[64];
    copy_display_name(display, sizeof(display), enum_name);
    char message[512];
    snprintf(message, sizeof(message),
             "this match does not cover %s of '%s': %s. Add %s, or a `_` arm",
             count == 1 ? "one variant" : "every variant", display, missing,
             count == 1 ? "an arm for it" : "arms for them");
    payload_error(table->context, node, message);
}

static void rewrite_payload_case(VariantTable *table, ASTNode *node) {
    int patterns = 0;
    for (int i = 0; i < node->case_expr.case_count; i++)
        if (variant_use(table, node->case_expr.cases[i].key)) patterns++;
    if (!patterns) return;

    ASTNode *target = node->case_expr.target;
    if (!is_repeatable_target(target))
        payload_error(table->context, target,
                      "a payload enum can only be matched on a variable or a field of one, "
                      "because each binding names the matched value again");

    const char *enum_name = NULL;
    long *covered = malloc(sizeof(long) * (size_t)node->case_expr.case_count);
    int covered_count = 0;

    for (int i = 0; i < node->case_expr.case_count; i++) {
        ASTNode *key = node->case_expr.cases[i].key;
        VariantTag *variant = variant_use(table, key);
        if (!variant) continue;
        check_unambiguous(table, variant, key);

        /* Arms of one match belong to one enum. Mixing them would make the tag
         * comparison meaningless, since tags only mean anything within the
         * enum that assigned them. */
        if (!enum_name) {
            enum_name = variant->enum_name;
        } else if (variant->enum_name && strcmp(enum_name, variant->enum_name) != 0) {
            char first[64], second[64];
            copy_display_name(first, sizeof(first), enum_name);
            copy_display_name(second, sizeof(second), variant->enum_name);
            char message[256];
            snprintf(message, sizeof(message),
                     "this match names variants of both '%s' and '%s'; a tag only means "
                     "something within its own enum",
                     first, second);
            payload_error(table->context, key, message);
        }

        for (int c = 0; c < covered_count; c++) {
            if (covered[c] != variant->tag) continue;
            char message[256];
            snprintf(message, sizeof(message), "'%s' is matched more than once",
                     variant->variant);
            payload_error(table->context, key, message);
        }
        covered[covered_count++] = variant->tag;

        if (variant->has_payload) {
            check_single_payload(table, key);
            ASTNode *bound = key->call.args[0];
            if (!bound || bound->type != AST_IDENTIFIER)
                payload_error(table->context, key,
                              "a variant pattern binds its payload to a name");

            ASTNode *field = new_member_access(ast_clone(target), variant->variant);
            Binding binding = {bound->identifier.name, field};
            substitute_identifier(&node->case_expr.cases[i].expr, &binding);
            free_ast(field);
        }

        char *text = tag_text(variant->tag);
        ASTNode *tag = new_number(text);
        free(text);
        tag->line = key->line;
        tag->col = key->col;
        tag->end_line = key->end_line;
        tag->end_col = key->end_col;
        free_ast(key);
        node->case_expr.cases[i].key = tag;
    }

    /* Without a `_` arm the case yields zero for an unmatched tag, which is a
     * silently wrong answer rather than a missing one. Require the arms to
     * account for every variant instead. */
    if (!node->case_expr.default_expr && enum_name)
        report_missing_arms(table, node, enum_name, covered, covered_count);

    free(covered);
    node->case_expr.target = new_member_access(target, "__tag");
}

/* Statements are rewritten as a list because a construction expands into two
 * of them, so a block's statement array is rebuilt rather than edited. */
static void rewrite_payload_block(VariantTable *table, ASTNode *block) {
    ASTNode **out = NULL;
    int count = 0;

    for (int i = 0; i < block->block.count; i++) {
        ASTNode *stmt = block->block.stmts[i];
        ASTNode *dest = NULL;
        ASTNode *call = NULL;

        if (stmt && stmt->type == AST_VAR_DECL && variant_use(table, stmt->var_decl.init)) {
            /* `T r = Ok(5);` -- keep the declaration, drop the initialiser, and
             * store into the variable the declaration just introduced. */
            call = stmt->var_decl.init;
            stmt->var_decl.init = NULL;
            dest = new_identifier(stmt->var_decl.name);
        } else if (stmt && stmt->type == AST_EXPR_STMT && stmt->expr_stmt.expr &&
                   stmt->expr_stmt.expr->type == AST_ASSIGN &&
                   variant_use(table, stmt->expr_stmt.expr->assign.right)) {
            call = stmt->expr_stmt.expr->assign.right;
            dest = ast_clone(stmt->expr_stmt.expr->assign.left);
        }

        if (!call) {
            rewrite_payload_node(&block->block.stmts[i], table);
            out = realloc(out, sizeof(ASTNode *) * (count + 1));
            out[count++] = block->block.stmts[i];
            continue;
        }

        if (!is_repeatable_target(dest))
            payload_error(table->context, dest,
                          "a variant can only be constructed into a variable or a field of one");

        /* A declaration says which enum is being built; an assignment does not,
         * so only the declaration form can be checked here. */
        if (stmt->type == AST_VAR_DECL)
            check_variant_belongs(table, stmt->var_decl.var_type, variant_use(table, call), call);

        if (call->type == AST_CALL && call->call.arg_count == 1)
            rewrite_payload_node(&call->call.args[0], table);

        ASTNode *tag_store = NULL;
        ASTNode *payload_store = NULL;
        build_construction(table, dest, call, &tag_store, &payload_store);

        /* Decide before anything is freed: the assignment form releases the
         * statement that would otherwise answer this. */
        int keeps_declaration = stmt->type == AST_VAR_DECL;

        out = realloc(out, sizeof(ASTNode *) * (count + 3));
        if (keeps_declaration) {
            out[count++] = stmt; /* the bare declaration */
            free_ast(call);      /* detached from it above */
        } else {
            free_ast(stmt);      /* the assignment, call included, is replaced */
        }
        out[count++] = tag_store;
        if (payload_store) out[count++] = payload_store;
        free_ast(dest);
    }

    free(block->block.stmts);
    block->block.stmts = out;
    block->block.count = count;
}

static void rewrite_payload_node(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    if (!node) return;
    VariantTable *table = user_data;

    if (node->type == AST_BLOCK) {
        rewrite_payload_block(table, node);
        return;
    }

    /* A case has to be rewritten before its children are visited: until the
     * patterns are consumed, its keys still look like constructions in a place
     * that cannot hold one, and the check below would reject them. */
    if (node->type == AST_CASE) {
        rewrite_payload_case(table, node);
        ast_visit_children(node, rewrite_payload_node, user_data);
        return;
    }

    ast_visit_children(node, rewrite_payload_node, user_data);

    /* A construction anywhere else has no destination to store into. Only the
     * carrying spelling is diagnosed: a bare variant is just an identifier, and
     * an unrelated variable may legitimately share its name. */
    if (variant_call(table, node)) {
        char message[256];
        snprintf(message, sizeof(message),
                 "'%s' constructs a payload enum, which can only appear as the whole "
                 "right-hand side of an assignment or an initialiser",
                 node->call.name);
        payload_error(table->context, node, message);
    }
}

/* Runs after specialization, so every payload enum in the program is concrete
 * and its variants carry final tags, and before the declarations themselves are
 * lowered to structs. */
void lower_payload_enum_uses(ParserContext *context, ASTNode *program) {
    VariantTable table = {NULL, 0, context};
    collect_variants(&table, program);
    if (table.count == 0) return;

    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->type == AST_ENUM) continue;
        rewrite_payload_node(&program->block.stmts[i], &table);
    }

    for (int i = 0; i < table.count; i++) free(table.items[i].variant);
    free(table.items);
}
