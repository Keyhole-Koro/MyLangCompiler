#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/module.h"

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
    ASTNode *program;
    /* The enclosing function's declared return type, so `return Ok(5);` knows
     * what to build -- NULL outside a function body (or one whose return type
     * isn't itself a payload enum construction site). */
    ASTNode *current_return_type;
    /* Freshens the `__mlg_ret_N` stand-in used for `return Ok(5);` below; the
     * __mlg_ prefix is reserved for compiler-generated names (see
     * parser_instantiate.c), so these can't collide with user identifiers. */
    int temp_counter;
    /* Declarations synthesized while lowering `case f() of { ... }`.  The
     * enclosing block splices them directly before the statement containing
     * the case, so the call is evaluated exactly once. */
    ASTNode **pending_hoists;
    int pending_hoist_count;
} VariantTable;

static void copy_display_name(char *out, size_t size, const char *name);

static VariantTag *find_variant(VariantTable *table, const char *name) {
    if (!name) return NULL;

    const char *separator = strstr(name, "::");
    if (!separator) {
        for (int i = 0; i < table->count; i++)
            if (strcmp(table->items[i].variant, name) == 0) return &table->items[i];
        return NULL;
    }

    size_t enum_name_length = (size_t)(separator - name);
    const char *variant_name = separator + 2;
    for (int i = 0; i < table->count; i++) {
        if (strcmp(table->items[i].variant, variant_name) != 0) continue;
        char display_name[64];
        copy_display_name(display_name, sizeof(display_name), table->items[i].enum_name);
        if (strlen(display_name) == enum_name_length &&
            strncmp(display_name, name, enum_name_length) == 0)
            return &table->items[i];
    }
    return NULL;
}

static void record_variant(VariantTable *table, const char *name, long tag,
                           int has_payload, const char *enum_name) {
    /* Keep one entry per (enum, variant) pair: a qualified spelling must be
     * able to select the intended enum even if another enum has the same
     * member name and tag. */
    table->items = realloc(table->items, sizeof(VariantTag) * (table->count + 1));
    table->items[table->count].variant = strdup(name);
    table->items[table->count].tag = tag;
    table->items[table->count].has_payload = has_payload;
    table->items[table->count].ambiguous = 0;
    table->items[table->count].enum_name = enum_name;
    table->count++;
}

static void collect_enum_variants(VariantTable *table, ASTNode *node) {
    if (!node || node->type != AST_ENUM || !node->enum_stmt.has_payloads) return;
    for (int m = 0; m < node->enum_stmt.member_count; m++) {
        ASTNode *member = node->enum_stmt.members[m];
        if (!member) continue;
        record_variant(table, member->enum_member.name, member->enum_member.resolved_value,
                       member->enum_member.payload_type != NULL, node->enum_stmt.name);
    }
}

static void collect_variants(VariantTable *table, ASTNode *program) {
    for (int i = 0; i < program->block.count; i++) {
        collect_enum_variants(table, program->block.stmts[i]);
    }

    /* A case on a package function can be the only use of a generic payload
     * enum in this translation unit.  Its concrete return type lives in the
     * imported module, so there may be no local `Option<i32>` spelling to
     * instantiate before this pass.  The imported template still provides the
     * variant spelling, tag, and payload shape needed to lower the case. */
    for (int i = 0; i < generic_template_count(table->context); i++) {
        collect_enum_variants(table, generic_template_at(table->context, i));
    }

    /* An unqualified spelling is ambiguous whenever it occurs in different
     * payload enums.  Distinct specializations of the same generic template
     * intentionally share their display name and are therefore one family. */
    for (int i = 0; i < table->count; i++) {
        char first[64];
        copy_display_name(first, sizeof(first), table->items[i].enum_name);
        for (int j = 0; j < table->count; j++) {
            if (i == j || strcmp(table->items[i].variant, table->items[j].variant) != 0)
                continue;
            char second[64];
            copy_display_name(second, sizeof(second), table->items[j].enum_name);
            if (strcmp(first, second) != 0) {
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

static int is_qualified_variant_use(ASTNode *node) {
    const char *name = !node ? NULL
                      : node->type == AST_CALL ? node->call.name
                      : node->type == AST_IDENTIFIER ? node->identifier.name : NULL;
    return name && strstr(name, "::") != NULL;
}

static void check_unambiguous(VariantTable *table, VariantTag *variant, ASTNode *at) {
    if (!variant->ambiguous || is_qualified_variant_use(at)) return;
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

    /* Specializations of one generic payload enum have distinct internal
     * names but share a layout and variant tags.  Compare their user-visible
     * template names so `Result<i32, FsError>`'s `Err` is not mistaken for an
     * `Err` belonging to an earlier Result specialization. */
    char want[64], got[64];
    copy_display_name(want, sizeof(want), declared);
    copy_display_name(got, sizeof(got), variant->enum_name);
    if (strcmp(want, got) == 0) return;

    /* Only complain when the declaration really is a payload enum; any other
     * type is somebody else's error to report. */
    int declared_is_payload_enum = 0;
    for (int i = 0; i < table->count; i++) {
        if (!table->items[i].enum_name) continue;
        char candidate[64];
        copy_display_name(candidate, sizeof(candidate), table->items[i].enum_name);
        if (strcmp(candidate, want) == 0) {
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

/* Build `use` directly into an already-addressable aggregate slot.  This is
 * the recursive counterpart of build_construction: it gives a nested payload
 * expression such as `Err(LoaderError::Mmu(e))` a concrete destination,
 * namely the outer Result's `Err` field. */
static ASTNode *build_nested_construction(VariantTable *table, ASTNode *dest, ASTNode *use) {
    VariantTag *variant = variant_use(table, use);
    check_unambiguous(table, variant, use);

    char *text = tag_text(variant->tag);
    ASTNode *tag_store = new_expr_stmt(new_assign(new_member_access(ast_clone(dest), "__tag"),
                                                  new_number(text)));
    free(text);

    if (!variant->has_payload) return tag_store;
    check_single_payload(table, use);

    ASTNode *payload = use->call.args[0];
    ASTNode *field = new_member_access(ast_clone(dest), variant->variant);
    ASTNode *payload_store;
    if (variant_use(table, payload)) {
        payload_store = build_nested_construction(table, field, payload);
    } else {
        payload_store = new_expr_stmt(new_assign(ast_clone(field), ast_clone(payload)));
    }
    free_ast(field);

    ASTNode **statements = malloc(sizeof(ASTNode *) * 2);
    statements[0] = tag_store;
    statements[1] = payload_store;
    return new_block(statements, 2);
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

    ASTNode *payload = use->call.args[0];
    if (variant_use(table, payload)) {
        /* `Err(FsError::Disabled)` and `Err(LoaderError::Mmu(e))` construct
         * their inner value in the outer payload field instead of requiring
         * a source-level temporary. */
        ASTNode *field = new_member_access(ast_clone(dest), variant->variant);
        *out_payload = build_nested_construction(table, field, payload);
        free_ast(field);
        return;
    }

    *out_payload = new_expr_stmt(new_assign(new_member_access(ast_clone(dest), variant->variant),
                                            ast_clone(payload)));
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
    case AST_NUMBER:
        return 1;
    case AST_MEMBER_ACCESS:
        return is_repeatable_target(node->member_access.lhs);
    case AST_ARROW_ACCESS:
        return is_repeatable_target(node->arrow_access.lhs);
    case AST_UNARY:
        /* Dereferencing a name reads it again and nothing more. */
        return node->unary.op == ASTARISK && is_repeatable_target(node->unary.operand);
    case AST_BINARY:
        /* Array subscripting (which is syntactic sugar for *(a + i)) is repeatable 
         * if both the base pointer and the index are repeatable. */
        return (node->binary.op == ADD || node->binary.op == SUB) &&
               is_repeatable_target(node->binary.left) &&
               is_repeatable_target(node->binary.right);
    default:
        return 0;
    }
}

static void rewrite_payload_node(ASTNode **slot, void *user_data);

static const char *type_base_name(ASTNode *type) {
    if (!type || type->type != AST_TYPE || !type->type_node.base_type ||
        type->type_node.base_type->type != AST_IDENTIFIER)
        return NULL;
    return type->type_node.base_type->identifier.name;
}

static int program_has_type_layout(ASTNode *program, const char *name) {
    if (!program || program->type != AST_BLOCK || !name) return 0;
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node) continue;
        if (node->type == AST_STRUCT && node->struct_stmt.name &&
            strcmp(node->struct_stmt.name, name) == 0)
            return 1;
        if (node->type == AST_ENUM && node->enum_stmt.name &&
            strcmp(node->enum_stmt.name, name) == 0)
            return 1;
        if (node->type == AST_TYPEDEF && node->typedef_stmt.alias &&
            strcmp(node->typedef_stmt.alias, name) == 0)
            return 1;
    }
    return 0;
}

/* Bring in the backing struct for an imported aggregate return used only by a
 * direct payload-enum case.  Its declaration normally arrives through a
 * source-level `Option<i32>`/`Result<...>` use; this is the implicit
 * counterpart for `case package.function() of { ... }`. */
static void import_type_layout(VariantTable *table, Module *module, const char *name) {
    if (!table || !module || !module->program || !name ||
        program_has_type_layout(table->program, name))
        return;

    for (int i = 0; i < module->program->block.count; i++) {
        ASTNode *node = module->program->block.stmts[i];
        const char *candidate = NULL;
        if (node && node->type == AST_STRUCT) candidate = node->struct_stmt.name;
        else if (node && node->type == AST_ENUM) candidate = node->enum_stmt.name;
        else if (node && node->type == AST_TYPEDEF) candidate = node->typedef_stmt.alias;
        if (!candidate || strcmp(candidate, name) != 0) continue;

        /* Materialize layouts this layout contains first, so codegen can
         * compute a member's full size even when the payload is itself a
         * payload enum. */
        if (node->type == AST_STRUCT) {
            for (int m = 0; m < node->struct_stmt.member_count; m++) {
                ASTNode *member = node->struct_stmt.members[m];
                const char *dependency = member && member->type == AST_VAR_DECL
                    ? type_base_name(member->var_decl.var_type) : NULL;
                if (dependency && strcmp(dependency, name) != 0)
                    import_type_layout(table, module, dependency);
            }
        }

        table->program->block.stmts = realloc(
            table->program->block.stmts,
            sizeof(ASTNode *) * (size_t)(table->program->block.count + 1));
        table->program->block.stmts[table->program->block.count++] = ast_clone(node);
        return;
    }
}

static ASTNode *imported_call_result_type(VariantTable *table, ASTNode *node,
                                          Module **provider) {
    if (!table || !table->program || !node || !node->call.name) return NULL;
    FrontendSession *session = table->context->session;
    if (!session || !session->loader) return NULL;

    for (int i = 0; i < table->program->block.count; i++) {
        ASTNode *import_node = table->program->block.stmts[i];
        if (!import_node || import_node->type != AST_IMPORT || !import_node->import_stmt.path)
            continue;
        Module *module = module_loader_load(session->loader, table->context->module.filename,
                                            import_node->import_stmt.path);
        if (!module || module->state != MODULE_LOADED) continue;

        int package_import = import_node->import_stmt.symbol_count == 0 && module->package_name;
        for (int s = 0; s < module->symbol_count; s++) {
            ModuleSymbol *symbol = &module->symbols[s];
            if (!symbol->is_exported || symbol->kind != SYMBOL_FUNCTION ||
                !symbol->declaration || symbol->declaration->type != AST_FUNDEF)
                continue;

            int matches = package_import
                ? symbol->link_name && strcmp(node->call.name, symbol->link_name) == 0
                : symbol->source_name && strcmp(node->call.name, symbol->source_name) == 0;
            if (!matches) continue;
            if (provider) *provider = module;
            return symbol->declaration->fundef.ret_type;
        }
    }
    return NULL;
}

static ASTNode *call_result_type(VariantTable *table, ASTNode *node, Module **provider) {
    if (!node || node->type != AST_CALL || !node->call.name) return NULL;
    if (provider) *provider = NULL;
    ASTNode *function = find_function(table->context, node->call.name);
    /* Exported functions are renamed to `<package>_<name>` after their
     * original declaration has already populated the parser's function table.
     * During payload lowering a same-module call can still carry the source
     * spelling, so follow that export mapping before giving up. */
    if (!function) {
        const char *mangled = find_export_mangled(table->context, node->call.name);
        if (mangled) function = find_function(table->context, mangled);
    }
    if (function && function->type == AST_FUNDEF) return function->fundef.ret_type;
    return imported_call_result_type(table, node, provider);
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

static void append_case_item(ASTNode *case_node, ASTNode *key, ASTNode *expr,
                             int is_noop) {
    int count = case_node->case_expr.case_count;
    case_node->case_expr.cases = realloc(case_node->case_expr.cases,
                                         sizeof(CaseItem) * (size_t)(count + 1));
    case_node->case_expr.cases[count].key = key;
    case_node->case_expr.cases[count].expr = expr;
    case_node->case_expr.cases[count].is_noop = is_noop;
    case_node->case_expr.case_count = count + 1;
}

/* A payload pattern can itself narrow the payload to another payload enum
 * variant (`Err(MmuError::AllocFailed)`) or to a numeric enum value already
 * substituted by the parser (`Err(SyscallError::BadFd)`). */
static int is_nested_pattern(VariantTable *table, ASTNode *node) {
    return variant_use(table, node) != NULL || (node && node->type == AST_NUMBER);
}

/* Fold multiple narrow payload patterns for one outer tag into an ordinary
 * nested case.  For example:
 *
 *   Err(AllocFailed) -> a; Err(UnalignedAddress(x)) -> b;
 *
 * becomes one `Err(__mlg_nest_N)` arm whose body matches that temporary.
 * The regular payload binding path below then substitutes the temporary with
 * the outer payload field, and normal case lowering recursively handles the
 * synthesized inner case. */
static void merge_nested_patterns(VariantTable *table, ASTNode *node) {
    int original_count = node->case_expr.case_count;
    CaseItem *original = node->case_expr.cases;
    CaseItem *out = NULL;
    ASTNode **inner_cases = NULL;
    int out_count = 0;

    for (int i = 0; i < original_count; i++) {
        ASTNode *key = original[i].key;
        VariantTag *variant = variant_use(table, key);
        ASTNode *bound = variant && variant->has_payload && key->type == AST_CALL &&
                         key->call.arg_count == 1 ? key->call.args[0] : NULL;
        int nested = bound && is_nested_pattern(table, bound);

        int existing = -1;
        if (variant && variant->has_payload) {
            for (int j = 0; j < out_count; j++) {
                if (variant_use(table, out[j].key) == variant) {
                    existing = j;
                    break;
                }
            }
        }

        if (existing >= 0 && (nested || inner_cases[existing])) {
            if (!nested && inner_cases[existing]) {
                /* A plain binding after narrow inner patterns is their
                 * fallback: `Err(AllocFailed) -> A; Err(e) -> B;` becomes
                 * `case payload of { AllocFailed -> A; _ -> B; }`.  Rewrite
                 * the source binding to the generated inner-case target now;
                 * the outer binding pass will subsequently replace that
                 * target with the actual `Err` field access. */
                if (!bound || bound->type != AST_IDENTIFIER)
                    payload_error(table->context, key,
                                  "a variant pattern binds its payload to a name");
                if (inner_cases[existing]->case_expr.default_expr ||
                    inner_cases[existing]->case_expr.default_is_noop)
                    payload_error(table->context, key,
                                  "a variant is matched more than once by a fallback binding");
                Binding fallback = {bound->identifier.name,
                                    inner_cases[existing]->case_expr.target};
                if (!original[i].is_noop)
                    substitute_identifier(&original[i].expr, &fallback);
                inner_cases[existing]->case_expr.default_expr = original[i].expr;
                inner_cases[existing]->case_expr.default_is_noop = original[i].is_noop;
                free_ast(key);
                continue;
            }
            if (!inner_cases[existing]) {
                char message[256];
                snprintf(message, sizeof(message),
                         "'%s' is matched both as a plain binding and as a nested pattern; "
                         "write the nested patterns before its fallback binding", variant->variant);
                payload_error(table->context, key, message);
            }
            append_case_item(inner_cases[existing], bound, original[i].expr,
                             original[i].is_noop);
            key->call.args[0] = NULL;
            free_ast(key);
            continue;
        }

        if (!nested) {
            out = realloc(out, sizeof(CaseItem) * (size_t)(out_count + 1));
            inner_cases = realloc(inner_cases, sizeof(ASTNode *) * (size_t)(out_count + 1));
            out[out_count] = original[i];
            inner_cases[out_count++] = NULL;
            continue;
        }

        char name[32];
        snprintf(name, sizeof(name), "__mlg_nest_%d", table->temp_counter++);
        ASTNode *inner = new_case_node(new_identifier(name));
        inner->line = key->line;
        inner->col = key->col;
        inner->end_line = key->end_line;
        inner->end_col = key->end_col;
        append_case_item(inner, bound, original[i].expr, original[i].is_noop);
        key->call.args[0] = new_identifier(name);

        out = realloc(out, sizeof(CaseItem) * (size_t)(out_count + 1));
        inner_cases = realloc(inner_cases, sizeof(ASTNode *) * (size_t)(out_count + 1));
        out[out_count] = (CaseItem){key, inner, 0};
        inner_cases[out_count++] = inner;
    }

    free(original);
    free(inner_cases);
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
        Module *provider = NULL;
        ASTNode *result_type = call_result_type(table, target, &provider);
        if (!result_type)
            payload_error(table->context, target,
                          "a payload enum can only be matched on a variable or a field of one, "
                          "because each binding names the matched value again");

        if (provider) {
            const char *result_name = type_base_name(result_type);
            if (result_name) import_type_layout(table, provider, result_name);
        }

        char name[32];
        snprintf(name, sizeof(name), "__mlg_case_target_%d", table->temp_counter++);
        ASTNode *declaration = new_var_decl(ast_clone(result_type), name, target);
        table->pending_hoists = realloc(table->pending_hoists,
                                        sizeof(ASTNode *) * (size_t)(table->pending_hoist_count + 1));
        table->pending_hoists[table->pending_hoist_count++] = declaration;
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
    if (!node->case_expr.default_expr && !node->case_expr.default_is_noop && enum_name)
        report_missing_arms(table, node, enum_name, covered, covered_count);

    free(covered);
    node->case_expr.target = new_member_access(target, "__tag");
}

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

    /* A nested block must not consume hoists that belong immediately before
     * its caller's statement.  Keep the caller's queue aside until this block
     * has emitted every hoist created while walking its own statements. */
    ASTNode **outer_hoists = table->pending_hoists;
    int outer_hoist_count = table->pending_hoist_count;
    table->pending_hoists = NULL;
    table->pending_hoist_count = 0;

    for (int i = 0; i < block->block.count; i++) {
        ASTNode *stmt = block->block.stmts[i];
        ASTNode *dest = NULL;
        ASTNode *call = NULL;
        int is_return = 0;
        char temp_name[32];

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
        } else if (stmt && stmt->type == AST_RETURN && stmt->ret.expr &&
                   table->current_return_type && variant_use(table, stmt->ret.expr)) {
            /* `return Ok(5);` has no variable to build into, so one is
             * invented to stand in for the return slot: `T __mlg_ret_N;
             * __mlg_ret_N.__tag = ...; ...; return __mlg_ret_N;` -- the same
             * shape `T r = Ok(5);` gets, just with a name nothing else wrote. */
            is_return = 1;
            call = stmt->ret.expr;
            stmt->ret.expr = NULL;
            snprintf(temp_name, sizeof(temp_name), "__mlg_ret_%d", table->temp_counter++);
            dest = new_identifier(temp_name);
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

        /* A declaration or a return says which enum is being built; a plain
         * assignment does not, so only those two forms can be checked here. */
        if (stmt->type == AST_VAR_DECL)
            check_variant_belongs(table, stmt->var_decl.var_type, variant_use(table, call), call);
        else if (is_return)
            check_variant_belongs(table, table->current_return_type, variant_use(table, call), call);

        if (call->type == AST_CALL && call->call.arg_count == 1 &&
            !variant_use(table, call->call.args[0]))
            rewrite_payload_node(&call->call.args[0], table);

        ASTNode *tag_store = NULL;
        ASTNode *payload_store = NULL;
        build_construction(table, dest, call, &tag_store, &payload_store);

        /* Decide before anything is freed: the assignment form releases the
         * statement that would otherwise answer this. */
        int keeps_declaration = stmt->type == AST_VAR_DECL;

        flush_pending_hoists(table, &out, &count);
        out = realloc(out, sizeof(ASTNode *) * (count + 4));
        if (is_return) {
            /* Declare the stand-in; the original return is fully replaced
             * (its expr is already detached into `call`). */
            out[count++] = new_var_decl(ast_clone(table->current_return_type), temp_name, NULL);
            free_ast(stmt);
        } else if (keeps_declaration) {
            out[count++] = stmt; /* the bare declaration */
            free_ast(call);      /* detached from it above */
        } else {
            free_ast(stmt);      /* the assignment, call included, is replaced */
        }
        out[count++] = tag_store;
        if (payload_store) out[count++] = payload_store;
        if (is_return) out[count++] = new_return(ast_clone(dest));
        free_ast(dest);
    }

    free(block->block.stmts);
    block->block.stmts = out;
    block->block.count = count;
    table->pending_hoists = outer_hoists;
    table->pending_hoist_count = outer_hoist_count;
}

static void rewrite_payload_node(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    if (!node) return;
    VariantTable *table = user_data;

    /* Tracks the function whose body is being walked, so a `return Ok(5);`
     * inside it knows which payload enum to build (see rewrite_payload_block).
     * Saved and restored around the visit so nested function literals, if any,
     * see their own return type rather than the enclosing one's. */
    if (node->type == AST_FUNDEF) {
        ASTNode *saved_return_type = table->current_return_type;
        table->current_return_type = node->fundef.ret_type;
        ast_visit_children(node, rewrite_payload_node, user_data);
        table->current_return_type = saved_return_type;
        return;
    }

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
    VariantTable table = {NULL, 0, context, program, NULL, 0, NULL, 0};
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
