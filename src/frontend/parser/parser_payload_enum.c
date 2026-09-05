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
    char *variant; /* variant name, which is also the payload field name */
    long tag;
    int ambiguous; /* the same name at different tags in different enums */
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

static void record_variant(VariantTable *table, const char *name, long tag) {
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
    table->items[table->count].ambiguous = 0;
    table->count++;
}

static void collect_variants(VariantTable *table, ASTNode *program) {
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->type != AST_ENUM || !node->enum_stmt.has_payloads) continue;
        for (int m = 0; m < node->enum_stmt.member_count; m++) {
            ASTNode *member = node->enum_stmt.members[m];
            if (!member || !member->enum_member.payload_type) continue;
            record_variant(table, member->enum_member.name, member->enum_member.resolved_value);
        }
    }
}

/* A call whose callee names a payload variant, i.e. `Ok(expr)`. Nothing else in
 * the language spells a construction that way, so the shape is the test. */
static VariantTag *variant_call(VariantTable *table, ASTNode *node) {
    if (!node || node->type != AST_CALL || !node->call.name) return NULL;
    return find_variant(table, node->call.name);
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

static char *tag_text(long tag) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%ld", tag);
    return strdup(buf);
}

/* `dest.__tag = tag;` then `dest.<variant> = payload;` -- the two statements a
 * construction becomes. `dest` is cloned per statement because each owns its
 * copy. */
static void build_construction(VariantTable *table, ASTNode *dest, ASTNode *call,
                               ASTNode **out_tag, ASTNode **out_payload) {
    VariantTag *variant = find_variant(table, call->call.name);
    check_unambiguous(table, variant, call);
    check_single_payload(table, call);

    char *text = tag_text(variant->tag);
    *out_tag = new_expr_stmt(new_assign(new_member_access(ast_clone(dest), "__tag"),
                                        new_number(text)));
    free(text);
    *out_payload = new_expr_stmt(new_assign(new_member_access(ast_clone(dest), call->call.name),
                                            ast_clone(call->call.args[0])));
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
static void rewrite_payload_case(VariantTable *table, ASTNode *node) {
    int patterns = 0;
    for (int i = 0; i < node->case_expr.case_count; i++)
        if (variant_call(table, node->case_expr.cases[i].key)) patterns++;
    if (!patterns) return;

    ASTNode *target = node->case_expr.target;
    if (!is_repeatable_target(target))
        payload_error(table->context, target,
                      "a payload enum can only be matched on a variable or a field of one, "
                      "because each binding names the matched value again");

    for (int i = 0; i < node->case_expr.case_count; i++) {
        ASTNode *key = node->case_expr.cases[i].key;
        VariantTag *variant = variant_call(table, key);
        if (!variant) continue;
        check_unambiguous(table, variant, key);
        check_single_payload(table, key);

        ASTNode *bound = key->call.args[0];
        if (!bound || bound->type != AST_IDENTIFIER)
            payload_error(table->context, key,
                          "a variant pattern binds its payload to a name");

        ASTNode *field = new_member_access(ast_clone(target), key->call.name);
        Binding binding = {bound->identifier.name, field};
        substitute_identifier(&node->case_expr.cases[i].expr, &binding);
        free_ast(field);

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

        if (stmt && stmt->type == AST_VAR_DECL && variant_call(table, stmt->var_decl.init)) {
            /* `T r = Ok(5);` -- keep the declaration, drop the initialiser, and
             * store into the variable the declaration just introduced. */
            call = stmt->var_decl.init;
            stmt->var_decl.init = NULL;
            dest = new_identifier(stmt->var_decl.name);
        } else if (stmt && stmt->type == AST_EXPR_STMT && stmt->expr_stmt.expr &&
                   stmt->expr_stmt.expr->type == AST_ASSIGN &&
                   variant_call(table, stmt->expr_stmt.expr->assign.right)) {
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
        out[count++] = payload_store;
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

    /* A construction anywhere else has no destination to store into. */
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
