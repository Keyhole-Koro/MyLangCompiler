#include "mylang/frontend/parser_payload_internal.h"

/* `case` on a payload enum: variant patterns become tag comparisons whose
 * bindings name the payload field, and a case that produces a payload enum or
 * another aggregate stores each arm into its destination. */

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
    /* `_` binds nothing: in the arm it is still the unit value. */
    if (node->type == AST_IDENTIFIER && node->identifier.name &&
        strcmp(node->identifier.name, binding->name) == 0 &&
        strcmp(binding->name, "_") != 0) {
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

    /* A narrow pattern that does not match goes to the match's own `_` arm. */
    for (int i = 0; i < out_count; i++) {
        ASTNode *inner = inner_cases[i];
        if (!inner || inner->case_expr.default_expr || inner->case_expr.default_is_noop)
            continue;
        inner->case_expr.default_is_noop = node->case_expr.default_is_noop;
        if (node->case_expr.default_expr)
            inner->case_expr.default_expr = ast_clone(node->case_expr.default_expr);
    }

    free(original);
    free(inner_cases);
    node->case_expr.cases = out;
    node->case_expr.case_count = out_count;
}

void rewrite_payload_case(VariantTable *table, ASTNode *node) {
    check_try_error_type(table, node);
    merge_nested_patterns(table, node);

    int patterns = 0;
    for (int i = 0; i < node->case_expr.case_count; i++)
        if (variant_use(table, node->case_expr.cases[i].key)) patterns++;
    if (!patterns) return;

    ASTNode *target = node->case_expr.target;
    if (!is_repeatable_target(target)) {
        Module *provider = NULL;
        ASTNode *result_type = call_result_type(table, target, &provider);
        if (!result_type && target && target->type == AST_CALL && target->call.recv)
            result_type = try_source_type(table, target); /* `case r.ok() of` */
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
    if (!node->case_expr.default_expr && !node->case_expr.default_is_noop && enum_name) {
        report_missing_arms(table, node, enum_name, covered, covered_count);
        node->case_expr.is_exhaustive = 1;
    }

    free(covered);
    node->case_expr.target = new_member_access(target, "__tag");
}

/* Find a construction used as a value of a case arm.  Pattern keys are
 * deliberately ignored: `case value of { Some(x) -> x; ... }` matches a
 * payload enum, but it does not itself produce one. */
VariantTag *case_result_variant(VariantTable *table, ASTNode *node) {
    if (!node || node->type != AST_CASE) return NULL;
    for (int i = 0; i < node->case_expr.case_count; i++) {
        ASTNode *expr = node->case_expr.cases[i].expr;
        VariantTag *variant = variant_use(table, expr);
        if (variant) return variant;
        variant = case_result_variant(table, expr);
        if (variant) return variant;
    }
    VariantTag *variant = variant_use(table, node->case_expr.default_expr);
    if (variant) return variant;
    return case_result_variant(table, node->case_expr.default_expr);
}

/* A struct, or a payload enum (still an AST_ENUM until this pass finishes),
 * held by value: a case producing one must store into its destination, since
 * an arm's value is otherwise carried as a single word. */
int is_aggregate_type(VariantTable *table, ASTNode *type) {
    const char *name = type_base_name(type);
    if (!name || type->type_node.pointer_level || type->type_node.borrow_kind != REFKIND_NONE) return 0;
    for (int i = 0; i < table->program->block.count; i++) {
        ASTNode *node = table->program->block.stmts[i];
        if (!node) continue;
        if (node->type == AST_STRUCT && node->struct_stmt.name &&
            strcmp(node->struct_stmt.name, name) == 0)
            return 1;
        if (node->type == AST_TYPEDEF_STRUCT && node->typedef_struct.typedef_name &&
            strcmp(node->typedef_struct.typedef_name, name) == 0)
            return 1;
        if (node->type == AST_ENUM && node->enum_stmt.has_payloads && node->enum_stmt.name &&
            strcmp(node->enum_stmt.name, name) == 0)
            return 1;
    }
    return 0;
}

/* `({ ...; return x; })`, `({ break; })`: an arm that leaves instead of
 * producing a value has nothing to store. */
static int arm_diverges(ASTNode *expr) {
    if (!expr || expr->type != AST_STMT_EXPR || !expr->stmt_expr.block ||
        expr->stmt_expr.block->type != AST_BLOCK || expr->stmt_expr.block->block.count == 0)
        return 0;
    ASTNode *last = expr->stmt_expr.block->block.stmts[expr->stmt_expr.block->block.count - 1];
    return last && (last->type == AST_RETURN || last->type == AST_BREAK || last->type == AST_CONTINUE);
}

static ASTNode *case_result_store(ASTNode *dest, ASTNode *value) {
    ASTNode **statements = malloc(sizeof(ASTNode *) * 2);
    statements[0] = new_expr_stmt(new_assign(ast_clone(dest), value));
    /* The surrounding case is evaluated only for its stores.  Give every arm
     * the same harmless scalar result so ordinary case codegen can still be
     * used; the aggregate itself lives in `dest`. */
    statements[1] = new_yield(new_number("0"));
    return new_stmt_expr(new_block(statements, 2));
}

/* Turn an aggregate-valued case into destination-passing form.  For example,
 *
 *   Result r = case x of { 0 -> Ok(1); _ -> Err(2); };
 *
 * becomes a bare declaration followed by a scalar case whose arms assign
 * directly into r.  Nested cases use the same destination. */
void lower_case_result_into(VariantTable *table, ASTNode *node, ASTNode *dest,
                                   ASTNode *expected_type, const char *expected_enum) {
    if (!node || node->type != AST_CASE) return;

    for (int i = 0; i < node->case_expr.case_count; i++) {
        CaseItem *arm = &node->case_expr.cases[i];
        if (arm->is_noop || !arm->expr)
            payload_error(table->context, arm->key,
                          "an aggregate-valued case arm must produce a value");

        if (arm->expr->type == AST_CASE) {
            lower_case_result_into(table, arm->expr, dest, expected_type, expected_enum);
            continue;
        }
        if (arm_diverges(arm->expr)) continue;

        VariantTag *variant = variant_use(table, arm->expr);
        if (variant) {
            check_unambiguous(table, variant, arm->expr);
            if (expected_type) check_variant_belongs(table, expected_type, variant, arm->expr);
            if (expected_enum && variant->enum_name &&
                strcmp(expected_enum, variant->enum_name) != 0) {
                char first[64], second[64], message[256];
                copy_display_name(first, sizeof(first), expected_enum);
                copy_display_name(second, sizeof(second), variant->enum_name);
                snprintf(message, sizeof(message),
                         "this case produces variants of both '%s' and '%s'",
                         first, second);
                payload_error(table->context, arm->expr, message);
            }
        }
        arm->expr = case_result_store(dest, arm->expr);
    }

    if (node->case_expr.default_is_noop)
        payload_error(table->context, node,
                      "an aggregate-valued case default must produce a value");
    if (node->case_expr.default_expr) {
        ASTNode *expr = node->case_expr.default_expr;
        if (expr->type == AST_CASE) {
            lower_case_result_into(table, expr, dest, expected_type, expected_enum);
        } else if (!arm_diverges(expr)) {
            VariantTag *variant = variant_use(table, expr);
            if (variant) {
                check_unambiguous(table, variant, expr);
                if (expected_type) check_variant_belongs(table, expected_type, variant, expr);
                if (expected_enum && variant->enum_name &&
                    strcmp(expected_enum, variant->enum_name) != 0) {
                    char first[64], second[64], message[256];
                    copy_display_name(first, sizeof(first), expected_enum);
                    copy_display_name(second, sizeof(second), variant->enum_name);
                    snprintf(message, sizeof(message),
                             "this case produces variants of both '%s' and '%s'",
                             first, second);
                    payload_error(table->context, expr, message);
                }
            }
            node->case_expr.default_expr = case_result_store(dest, expr);
        }
    }
}

/* `x = case ...;` where x is a local or parameter of aggregate type. */
int assigned_aggregate(VariantTable *table, ASTNode *lhs) {
    if (!lhs || lhs->type != AST_IDENTIFIER || !table->current_function) return 0;
    ASTNode *fn = table->current_function;
    ASTNode *type = NULL;
    for (int i = 0; i < fn->fundef.param_count && !type; i++)
        type = find_local_type(fn->fundef.params[i], lhs->identifier.name);
    if (!type) type = find_local_type(fn->fundef.body, lhs->identifier.name);
    return type && is_aggregate_type(table, type);
}
