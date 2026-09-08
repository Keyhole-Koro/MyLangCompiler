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
    /* The declared return type of the function currently being walked, so a
     * bare `return Ok(v);` knows what to build into. NULL outside any
     * function, or inside one with no declared return type. */
    ASTNode *current_ret_type;
    /* Declarations a match target's hoist (see rewrite_payload_case) has
     * produced but that have not yet been spliced into the enclosing block;
     * rewrite_payload_block drains this right before it emits whatever
     * statement the hoist was found inside of, so the declaration lands
     * immediately before the first use of what it declares. */
    ASTNode **pending_hoists;
    int pending_hoist_count;
} VariantTable;

/* Specialization names an instance `__mlg_s_<len>_<template><args...>`
 * (parser_instantiate.c). A diagnostic -- and an `EnumName::Variant`
 * qualifier, which a user only ever writes against the template's own name --
 * should say `Result`, not that. The length prefix makes the template name
 * recoverable without guessing where the arguments start. */
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

/* `name` is either a bare variant ("OutOfMemory") or one qualified with its
 * enum's display name ("LoaderError::OutOfMemory", written that way at the
 * parser -- see the COLONCOLON handling in parser_expr_postfix.c). A
 * qualified name picks out one specific entry even when its bare form is
 * ambiguous (declared, with any tag, by more than one enum): the qualifier
 * says which enum was meant, so there is nothing left to be ambiguous about.
 * An unqualified name returns the first entry recorded for it, ambiguous or
 * not -- callers that care check `->ambiguous` (check_unambiguous) and
 * reject it themselves; this only looks the name up. */
static VariantTag *find_variant(VariantTable *table, const char *name) {
    if (!name) return NULL;
    const char *sep = strstr(name, "::");
    if (!sep) {
        for (int i = 0; i < table->count; i++)
            if (strcmp(table->items[i].variant, name) == 0) return &table->items[i];
        return NULL;
    }

    size_t qualifier_len = (size_t)(sep - name);
    const char *bare = sep + 2;
    for (int i = 0; i < table->count; i++) {
        if (strcmp(table->items[i].variant, bare) != 0) continue;
        char display[64];
        copy_display_name(display, sizeof(display), table->items[i].enum_name);
        if (strlen(display) == qualifier_len && strncmp(display, name, qualifier_len) == 0)
            return &table->items[i];
    }
    return NULL;
}

/* One entry per (enum, variant) pair, even when two enums happen to name a
 * variant the same way with the same tag: collapsing those into one entry
 * (as an earlier version of this did) meant a `LoaderError::NoError`
 * qualifier could resolve to the wrong enum's entry -- or to none at all --
 * whenever some other enum's same-named, same-tagged variant had been seen
 * first. Ambiguity is instead computed as a pass over the finished table,
 * once every entry, from every enum, is in it. */
static void record_variant(VariantTable *table, const char *name, long tag,
                           int has_payload, const char *enum_name) {
    table->items = realloc(table->items, sizeof(VariantTag) * (table->count + 1));
    table->items[table->count].variant = strdup(name);
    table->items[table->count].tag = tag;
    table->items[table->count].has_payload = has_payload;
    table->items[table->count].ambiguous = 0; /* corrected in collect_variants, once complete */
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

    /* A bare reference can't tell two enums' same-named variant apart even
     * when they happen to share a tag: flag every entry with a namesake in a
     * genuinely different enum, regardless. (A qualified reference
     * sidesteps this in find_variant, above, before ambiguity is ever a
     * question.) "Different" is by display name, not the raw one: distinct
     * specializations of one generic template (`Result<i32, MmuError>` and
     * `Result<i32, LoaderError>`, both `Result`) share every variant name by
     * construction, and are not what this is protecting against. */
    for (int i = 0; i < table->count; i++) {
        char display_i[64];
        copy_display_name(display_i, sizeof(display_i), table->items[i].enum_name);
        for (int j = 0; j < table->count; j++) {
            if (i == j || strcmp(table->items[i].variant, table->items[j].variant) != 0) continue;
            char display_j[64];
            copy_display_name(display_j, sizeof(display_j), table->items[j].enum_name);
            if (strcmp(display_i, display_j) != 0) {
                table->items[i].ambiguous = 1;
                break;
            }
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

/* `at`'s own spelling -- the exact text find_variant matched against, not
 * anything derived from the VariantTag it resolved to -- says whether this
 * particular reference was qualified (`EnumName::Variant`) or bare. */
static int reference_is_qualified(ASTNode *at) {
    const char *name = !at ? NULL
                      : at->type == AST_CALL ? at->call.name
                      : at->type == AST_IDENTIFIER ? at->identifier.name : NULL;
    return name && strstr(name, "::") != NULL;
}

static void check_unambiguous(VariantTable *table, VariantTag *variant, ASTNode *at) {
    /* A qualified reference already said which enum was meant -- find_variant
     * only ever resolves it to that one entry -- so there is nothing left
     * for the bare-name ambiguity below to complain about. */
    if (!variant->ambiguous || reference_is_qualified(at)) return;
    char message[256];
    snprintf(message, sizeof(message),
             "variant '%s' is declared by more than one payload enum; write '<EnumName>::%s' "
             "to say which one is meant",
             variant->variant, variant->variant);
    payload_error(table->context, at, message);
}

static void check_single_payload(VariantTable *table, ASTNode *call) {
    if (call->call.arg_count == 1) return;
    char message[256];
    snprintf(message, sizeof(message), "variant '%s' carries one payload, but %d were given",
             call->call.name, call->call.arg_count);
    payload_error(table->context, call, message);
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

    /* Compared by display name, not the raw (possibly specialized) one:
     * table->items now holds one entry per (enum, variant) pair -- see
     * record_variant -- rather than one merged entry per name across every
     * enum that declares it, so `variant` may be the entry for a *different*
     * specialization of the same generic template the destination names
     * (`Result<i32, MmuError>`'s `Err` vs. a `Result<i32, LoaderError>`
     * destination). Those still display the same ("Result"), and share
     * every tag by construction, so there is nothing to reject there. */
    char want[64], got[64];
    copy_display_name(want, sizeof(want), declared);
    copy_display_name(got, sizeof(got), variant->enum_name);
    if (strcmp(want, got) == 0) return;

    /* Only complain when the declaration really is a (display-)named payload
     * enum; any other type is somebody else's error to report. */
    int declared_is_payload_enum = 0;
    for (int i = 0; i < table->count; i++) {
        if (!table->items[i].enum_name) continue;
        char display[64];
        copy_display_name(display, sizeof(display), table->items[i].enum_name);
        if (strcmp(display, want) == 0) {
            declared_is_payload_enum = 1;
            break;
        }
    }
    if (!declared_is_payload_enum) return;

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

    ASTNode *payload_value = use->call.args[0];
    VariantTag *nested_bare = variant_bare(table, payload_value);
    if (nested_bare) {
        /* The payload is itself a bare variant construction, e.g.
         * `Err(LoaderError::OutOfMemory)`: `payload_value` names a tag, not
         * an expression, so there is no value to copy in the way there
         * would be from a real variable. The payload field -- itself a
         * struct -- gets its own __tag store instead, exactly the one a
         * top-level `LoaderError x = OutOfMemory;` would produce, just
         * targeting `dest.<field>` rather than `x`. (A *carrying* nested
         * construction, `Err(BadFd(fd))`, never reaches here: it is an
         * AST_CALL, which the recursive rewrite_payload_node pass already
         * rejects -- "constructs a payload enum, which can only appear as
         * the whole right-hand side..." -- before build_construction runs.
         * Only build_construction's own caller can catch the bare form,
         * because unlike a call, a bare identifier is legitimately just a
         * variable everywhere else, and only means a variant right here.) */
        ASTNode *field = new_member_access(ast_clone(dest), variant->variant);
        char *inner_text = tag_text(nested_bare->tag);
        *out_payload = new_expr_stmt(new_assign(new_member_access(field, "__tag"),
                                                new_number(inner_text)));
        free(inner_text);
        return;
    }

    *out_payload = new_expr_stmt(new_assign(new_member_access(ast_clone(dest), variant->variant),
                                            ast_clone(payload_value)));
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

/* The declared return type of a direct call `f(...)`, when `f` is a function
 * this module can already see -- enough to hoist a non-repeatable case
 * target (rewrite_payload_case) without needing real type inference, which
 * does not exist yet at this stage of the pipeline. NULL for anything else
 * (not a call, or a callee this lookup cannot resolve), which leaves the
 * caller to fall back to its own error. */
static ASTNode *call_result_type(VariantTable *table, ASTNode *node) {
    if (!node || node->type != AST_CALL || !node->call.name) return NULL;
    ASTNode *fn = find_function(table->context, node->call.name);
    if (!fn || fn->type != AST_FUNDEF) return NULL;
    return fn->fundef.ret_type;
}

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

static ASTNode *new_case_node(ASTNode *target) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_CASE;
    node->case_expr.target = target;
    return node;
}

static void append_case_item(ASTNode *case_node, ASTNode *key, ASTNode *expr) {
    int n = case_node->case_expr.case_count;
    case_node->case_expr.cases = realloc(case_node->case_expr.cases, sizeof(CaseItem) * (size_t)(n + 1));
    case_node->case_expr.cases[n].key = key;
    case_node->case_expr.cases[n].expr = expr;
    case_node->case_expr.case_count = n + 1;
}

/* Whether a case arm's payload position (`Err(<here>)`) is itself a payload
 * enum pattern -- bare (`AllocFailed`) or carrying (`WrongType(t)`) -- rather
 * than a name the whole payload binds to. */
static int is_nested_pattern(VariantTable *table, ASTNode *node) {
    return variant_use(table, node) != NULL;
}

/* `Err(AllocFailed) -> X; Err(NoFreeSlot) -> Y;` each name a specific inner
 * variant rather than binding the whole payload, the way `Err(e) -> ...`
 * does. Rather than teach every consumer of a case arm's shape about this,
 * fold arms like that into the ordinary one before anything else here looks
 * at them: the first nested-pattern arm seen for an outer tag becomes that
 * tag's sole surviving arm, its own payload position replaced by a fresh
 * placeholder name, and every nested pattern (including later arms for the
 * same tag) becomes one case of a synthesized `case <placeholder> of {...}`
 * that replaces its body:
 *
 *     Err(AllocFailed) -> X; Err(NoFreeSlot) -> Y;
 *  -> Err(__mlg_nestN) -> case __mlg_nestN of { AllocFailed -> X; NoFreeSlot -> Y; };
 *
 * The placeholder is then bound to the real payload by the ordinary path
 * below, exactly as any other `Err(e)` pattern would be -- substitution
 * rewrites every occurrence of its name, including the one now standing in
 * as the synthesized case's target, into the payload access. Recursing
 * through it is likewise ordinary: rewrite_payload_node's own AST_CASE
 * handling reaches the synthesized case as a normal child of this one's arm,
 * so it is lowered (and checked for exhaustiveness, and unfolded again if
 * its own arms nest further) the same way any other case is. */
static void merge_nested_patterns(VariantTable *table, ASTNode *node) {
    int n = node->case_expr.case_count;
    CaseItem *cases = node->case_expr.cases;

    CaseItem *out = NULL;
    ASTNode **group_case = NULL; /* parallel to out[]: its synthesized inner case, or NULL */
    int out_count = 0;

    for (int i = 0; i < n; i++) {
        ASTNode *key = cases[i].key;
        VariantTag *variant = variant_use(table, key);
        ASTNode *bound = (variant && variant->has_payload && key->type == AST_CALL &&
                          key->call.arg_count == 1) ? key->call.args[0] : NULL;
        int nested = bound && is_nested_pattern(table, bound);

        int existing = -1;
        if (variant && variant->has_payload) {
            for (int g = 0; g < out_count; g++) {
                if (variant_use(table, out[g].key) == variant) { existing = g; break; }
            }
        }

        if (existing >= 0 && (nested || group_case[existing])) {
            /* Either side of this pairing is a nested pattern: mixing one
             * with a plain binding for the same tag is ambiguous, since the
             * plain binding already covers every payload the nested pattern
             * could ever narrow down. Two plain bindings for the same tag
             * are the ordinary duplicate case the main loop below already
             * reports, so only complain when a nested pattern is involved. */
            if (!nested || !group_case[existing]) {
                char message[256];
                snprintf(message, sizeof(message),
                         "'%s' is matched both as a nested pattern and as a plain binding; "
                         "pick one form for this variant",
                         variant->variant);
                payload_error(table->context, key, message);
            }
            /* Fold into the existing group: `bound` and this arm's body move
             * into the synthesized case; the now-payload-less outer call
             * wrapper is discarded. */
            append_case_item(group_case[existing], bound, cases[i].expr);
            key->call.args[0] = NULL; /* detached above, so freeing key below cannot reach it */
            free_ast(key);
            continue;
        }

        if (!nested) {
            out = realloc(out, sizeof(CaseItem) * (size_t)(out_count + 1));
            group_case = realloc(group_case, sizeof(ASTNode *) * (size_t)(out_count + 1));
            out[out_count] = cases[i];
            group_case[out_count] = NULL;
            out_count++;
            continue;
        }

        /* First nested-pattern arm for this tag: becomes the representative. */
        char name[32];
        snprintf(name, sizeof(name), "__mlg_nest%d", table->context->lowering.payload_case_counter++);
        ASTNode *inner = new_case_node(new_identifier(name));
        inner->line = key->line; inner->col = key->col;
        inner->end_line = key->end_line; inner->end_col = key->end_col;
        append_case_item(inner, bound, cases[i].expr);
        key->call.args[0] = new_identifier(name); /* `bound`'s slot; `bound` itself now lives in `inner` */

        out = realloc(out, sizeof(CaseItem) * (size_t)(out_count + 1));
        group_case = realloc(group_case, sizeof(ASTNode *) * (size_t)(out_count + 1));
        out[out_count] = (CaseItem){key, inner};
        group_case[out_count] = inner;
        out_count++;
    }

    free(cases);
    free(group_case);
    node->case_expr.cases = out;
    node->case_expr.case_count = out_count;
}

static void rewrite_payload_case(VariantTable *table, ASTNode *node) {
    merge_nested_patterns(table, node);

    int patterns = 0;
    for (int i = 0; i < node->case_expr.case_count; i++)
        if (variant_use(table, node->case_expr.cases[i].key)) patterns++;
    if (!patterns) return;

    ASTNode *target = node->case_expr.target;
    if (!is_repeatable_target(target)) {
        /* Naming the target again per binding is unsound unless it is cheap
         * and side-effect-free (the comment on is_repeatable_target above).
         * A direct call to a known function is neither, but its result can
         * be made so: bind it to a temporary once, ahead of the statement
         * this match is part of, and match on that instead. */
        ASTNode *result_type = call_result_type(table, target);
        if (!result_type)
            payload_error(table->context, target,
                          "a payload enum can only be matched on a variable or a field of one, "
                          "because each binding names the matched value again");

        char name[32];
        snprintf(name, sizeof(name), "__mlg_case_target%d",
                 table->context->lowering.payload_case_counter++);
        ASTNode *decl = new_var_decl(ast_clone(result_type), name, target);
        table->pending_hoists = realloc(table->pending_hoists,
                                        sizeof(ASTNode *) * (table->pending_hoist_count + 1));
        table->pending_hoists[table->pending_hoist_count++] = decl;

        target = new_identifier(name);
        node->case_expr.target = target;
    }

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

/* Splices in whatever match-target hoists (rewrite_payload_case) turned up
 * while the statement now being emitted was being rewritten, ahead of it. */
static void flush_pending_hoists(VariantTable *table, ASTNode ***out, int *count) {
    if (!table->pending_hoist_count) return;
    *out = realloc(*out, sizeof(ASTNode *) * (size_t)(*count + table->pending_hoist_count));
    for (int i = 0; i < table->pending_hoist_count; i++)
        (*out)[(*count)++] = table->pending_hoists[i];
    free(table->pending_hoists);
    table->pending_hoists = NULL;
    table->pending_hoist_count = 0;
}

/* Statements are rewritten as a list because a construction expands into two
 * of them, so a block's statement array is rebuilt rather than edited. */
static void rewrite_payload_block(VariantTable *table, ASTNode *block) {
    ASTNode **out = NULL;
    int count = 0;

    /* A hoist queued while rewriting an ancestor statement -- a case target
     * belonging to whatever block encloses this one -- is not this block's
     * to flush. Park it for the call to restore on the way out, so a nested
     * block (an arm written as `({ ... })`, say) cannot claim it via its own
     * flush_pending_hoists calls below before the enclosing statement gets a
     * chance to. Each nested call does the same, so this nests correctly to
     * any depth without an explicit stack. */
    ASTNode **outer_hoists = table->pending_hoists;
    int outer_hoist_count = table->pending_hoist_count;
    table->pending_hoists = NULL;
    table->pending_hoist_count = 0;

    for (int i = 0; i < block->block.count; i++) {
        ASTNode *stmt = block->block.stmts[i];

        /* `return Ok(v);` -- there is no variable to build into, so one is
         * synthesized from the enclosing function's declared return type:
         * `T __mlg_retN; __mlg_retN.__tag = ...; __mlg_retN.Ok = v; return __mlg_retN;` */
        if (stmt && stmt->type == AST_RETURN && stmt->ret.expr &&
            variant_use(table, stmt->ret.expr)) {
            if (!table->current_ret_type)
                payload_error(table->context, stmt->ret.expr,
                              "'return' here has no declared return type to build this "
                              "payload enum's value into");

            ASTNode *ret_call = stmt->ret.expr;
            stmt->ret.expr = NULL; /* detached before `stmt` is freed below */

            if (ret_call->type == AST_CALL && ret_call->call.arg_count == 1)
                rewrite_payload_node(&ret_call->call.args[0], table);

            char name[32];
            snprintf(name, sizeof(name), "__mlg_ret%d",
                     table->context->lowering.payload_ret_counter++);
            ASTNode *decl = new_var_decl(ast_clone(table->current_ret_type), name, NULL);
            ASTNode *dest = new_identifier(name);

            check_variant_belongs(table, decl->var_decl.var_type, variant_use(table, ret_call),
                                  ret_call);

            ASTNode *tag_store = NULL;
            ASTNode *payload_store = NULL;
            build_construction(table, dest, ret_call, &tag_store, &payload_store);

            flush_pending_hoists(table, &out, &count);
            out = realloc(out, sizeof(ASTNode *) * (count + 4));
            out[count++] = decl;
            out[count++] = tag_store;
            if (payload_store) out[count++] = payload_store;
            out[count++] = new_return(dest); /* dest's ownership moves in here */

            free_ast(ret_call);
            free_ast(stmt);
            continue;
        }

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
            flush_pending_hoists(table, &out, &count);
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

        flush_pending_hoists(table, &out, &count);
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

    /* This block's own loop has already flushed everything it queued for
     * itself -- each branch above does so before it emits its statement(s).
     * What is left to restore is only ever what belonged to the caller. */
    table->pending_hoists = outer_hoists;
    table->pending_hoist_count = outer_hoist_count;
}

static void rewrite_payload_node(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    if (!node) return;
    VariantTable *table = user_data;

    if (node->type == AST_BLOCK) {
        rewrite_payload_block(table, node);
        return;
    }

    /* A bare `return Ok(v);` inside the body needs to know what to build,
     * which only the innermost enclosing function's declared type says --
     * track it across the walk and restore it on the way back out, so a
     * nested function literal doesn't leak its return type to whatever
     * encloses it, or vice versa. */
    if (node->type == AST_FUNDEF || node->type == AST_FUN_LITERAL) {
        ASTNode *saved = table->current_ret_type;
        table->current_ret_type =
            node->type == AST_FUNDEF ? node->fundef.ret_type : node->fun_literal.ret_type;
        ast_visit_children(node, rewrite_payload_node, user_data);
        table->current_ret_type = saved;
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
    VariantTable table = {NULL, 0, context, NULL, NULL, 0};
    collect_variants(&table, program);
    if (table.count == 0) return;

    /* Rebuilt the same way rewrite_payload_block rebuilds a function body:
     * a top-level statement can hoist a match target too (a global's
     * initializer, say), and that hoist's declaration needs a place to land
     * ahead of it. */
    ASTNode **out = NULL;
    int count = 0;
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (node && node->type != AST_ENUM) rewrite_payload_node(&program->block.stmts[i], &table);
        flush_pending_hoists(&table, &out, &count);
        out = realloc(out, sizeof(ASTNode *) * (count + 1));
        out[count++] = program->block.stmts[i];
    }
    free(program->block.stmts);
    program->block.stmts = out;
    program->block.count = count;

    for (int i = 0; i < table.count; i++) free(table.items[i].variant);
    free(table.items);
}
