#include "mylang/frontend/parser_payload_internal.h"
#include "mylang/frontend/parser_annot_internal.h"

/* Lowers payload enum *uses* onto the struct layout parser_instantiate.c gives
 * their declarations.
 *
 * A specialized `enum Result<i32, char> { Ok(T), Err(E) }` becomes
 *
 *     struct Result_i32_char { i32 __tag; i32 Ok; char Err; }
 *
 * so a variant is a tag value plus one field named after it. That leaves two
 * surface forms to translate:
 *
 *   Ok(5)           construction, only meaningful against a destination
 *   Ok(x) -> expr   a case arm, which binds the payload for the arm's body
 *
 * This file keeps the variant table and the walk, and builds constructions;
 * parser_payload_case.c rewrites case arms, and parser_payload_try.c the case
 * a `?` expands to.
 *
 * Construction has to be a statement rewrite rather than an expression one,
 * because the value being built is a struct and the backend cannot return one:
 * there is nowhere to put `Ok(5)` except directly into the variable it is
 * initialising. `T r = Ok(5);` therefore becomes `T r;` followed by the two
 * field stores, and a plain assignment expands the same way.
 *
 * A call argument has no such variable, and its type is the parameter's, which
 * for a method is not known until resolve_method_calls() has run. So the first
 * pass leaves `f(Some(x))` alone, and lower_payload_call_arguments() walks the
 * same tree again after name rewriting and builds it into a temporary:
 * `T __mlg_arg_N;`, the field stores, `f(__mlg_arg_N);`.
 *
 * A pattern binding is substituted rather than copied: `Ok(x) -> x + 1`
 * becomes `0 -> r.Ok + 1`, with every `x` in the arm replaced by the member
 * access. That avoids needing the payload's type here -- there is no inference
 * at this stage, and the variant name alone cannot say whether a `Result` came
 * from `<i32, char>` or `<char, i32>`. The binding aliases the field rather
 * than copying it, which is what a read-only match wants anyway; because the
 * access is re-evaluated per occurrence, a matched target has to be something
 * cheap and repeatable to name, which rewrite_payload_case checks.
 */

/* Same shape as parser_instantiate.c's reporter: a node carries a position but
 * not a token, and parse_error wants one. */
void payload_error(ParserContext *context, ASTNode *node, const char *message) {
    Token location = {0};
    location.line = node ? node->line : 0;
    location.col = node ? node->col : 0;
    parse_error(context, message, &location);
}

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
VariantTag *variant_use(VariantTable *table, ASTNode *node) {
    VariantTag *variant = variant_call(table, node);
    return variant ? variant : variant_bare(table, node);
}

static int is_qualified_variant_use(ASTNode *node) {
    const char *name = !node ? NULL
                      : node->type == AST_CALL ? node->call.name
                      : node->type == AST_IDENTIFIER ? node->identifier.name : NULL;
    return name && strstr(name, "::") != NULL;
}

void check_unambiguous(VariantTable *table, VariantTag *variant, ASTNode *at) {
    if (!variant->ambiguous || is_qualified_variant_use(at)) return;
    char message[256];
    snprintf(message, sizeof(message),
             "variant '%s' is declared by more than one payload enum; write '<EnumName>::%s' "
             "to say which one is meant",
             variant->variant, variant->variant);
    payload_error(table->context, at, message);
}

void check_single_payload(VariantTable *table, ASTNode *call) {
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
void copy_display_name(char *out, size_t size, const char *name) {
    const char *display = display_enum_name(name);
    size_t length = 0;
    while (display[length] && display[length] != '_' && length + 1 < size) length++;
    memcpy(out, display, length);
    out[length] = '\0';
}

/* The declared type of the thing being built names its enum, so a variant from
 * a different one can be caught here rather than becoming a store to a field
 * the layout does not have. */
void check_variant_belongs(VariantTable *table, ASTNode *type, VariantTag *variant,
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

char *tag_text(long tag) {
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

static void mark_payload_stores(ASTNode *statement, int fills_new_value) {
    if (!statement) return;
    if (statement->type == AST_EXPR_STMT) {
        statement->expr_stmt.expr->assign.is_construction = 1;
        statement->expr_stmt.expr->assign.fills_new_value = fills_new_value;
    } else if (statement->type == AST_BLOCK) {
        for (int i = 0; i < statement->block.count; i++)
            mark_payload_stores(statement->block.stmts[i], fills_new_value);
    }
}

/* Naming the matched value again for each bound occurrence is only sound when
 * doing so is free of side effects and cheap. Identifiers and the accesses
 * built from them qualify; a call or an arithmetic expression does not. */
int is_repeatable_target(ASTNode *node) {
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
void import_type_layout(VariantTable *table, Module *module, const char *name) {
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
                ASTNode *type = member && member->type == AST_VAR_DECL
                    ? member->var_decl.var_type : NULL;
                while (type && type->type == AST_TYPE_ARRAY) type = type->type_array.element_type;
                const char *dependency = type_base_name(type);
                if (dependency && strcmp(dependency, name) != 0)
                    import_type_layout(table, module, dependency);
            }
        }

        ASTNode *block = table->program;
        block->block.stmts = realloc(block->block.stmts,
                                     sizeof(ASTNode *) * (size_t)(block->block.count + 1));
        memmove(block->block.stmts + table->layout_count + 1,
                block->block.stmts + table->layout_count,
                sizeof(ASTNode *) * (size_t)(block->block.count - table->layout_count));
        block->block.stmts[table->layout_count++] = ast_clone(node);
        block->block.count++;
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

ASTNode *call_result_type(VariantTable *table, ASTNode *node, Module **provider) {
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

ASTNode *find_local_type(ASTNode *node, const char *name) {
    if (!node || !name) return NULL;
    if (node->type == AST_VAR_DECL && node->var_decl.name &&
        strcmp(node->var_decl.name, name) == 0)
        return node->var_decl.var_type;
    if (node->type == AST_PARAM && node->param.name && strcmp(node->param.name, name) == 0)
        return node->param.type;
    if (node->type == AST_BLOCK) {
        for (int i = 0; i < node->block.count; i++) {
            ASTNode *found = find_local_type(node->block.stmts[i], name);
            if (found) return found;
        }
    } else if (node->type == AST_IF) {
        ASTNode *found = find_local_type(node->if_stmt.then_stmt, name);
        return found ? found : find_local_type(node->if_stmt.else_stmt, name);
    } else if (node->type == AST_WHILE) {
        return find_local_type(node->while_stmt.body, name);
    } else if (node->type == AST_DO_WHILE) {
        return find_local_type(node->do_while_stmt.body, name);
    } else if (node->type == AST_FOR) {
        ASTNode *found = find_local_type(node->for_stmt.init, name);
        return found ? found : find_local_type(node->for_stmt.body, name);
    } else if (node->type == AST_STMT_EXPR) {
        return find_local_type(node->stmt_expr.block, name);
    }
    return NULL;
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
        ASTNode *case_value = NULL;
        ASTNode *expected_type = NULL;
        int is_return = 0;
        char temp_name[32];
        int trace_kind = RET_TRACE_NONE, trace_line = 0, trace_col = 0;
        char *trace_note = NULL;

        /* A carrying constructor may be the direct result of a case arm.  The
         * case itself needs the same concrete destination as a direct
         * constructor, so recognize these sites before the ordinary
         * construction cases below. */
        if (stmt && stmt->type == AST_VAR_DECL &&
            stmt->var_decl.init && stmt->var_decl.init->type == AST_CASE &&
            (case_result_variant(table, stmt->var_decl.init) ||
             is_aggregate_type(table, stmt->var_decl.var_type))) {
            case_value = stmt->var_decl.init;
            stmt->var_decl.init = NULL;
            dest = new_identifier(stmt->var_decl.name);
            expected_type = stmt->var_decl.var_type;
        } else if (stmt && stmt->type == AST_EXPR_STMT && stmt->expr_stmt.expr &&
                   stmt->expr_stmt.expr->type == AST_ASSIGN &&
                   stmt->expr_stmt.expr->assign.right &&
                   stmt->expr_stmt.expr->assign.right->type == AST_CASE &&
                   (case_result_variant(table, stmt->expr_stmt.expr->assign.right) ||
                    assigned_aggregate(table, stmt->expr_stmt.expr->assign.left))) {
            case_value = stmt->expr_stmt.expr->assign.right;
            stmt->expr_stmt.expr->assign.right = NULL;
            dest = ast_clone(stmt->expr_stmt.expr->assign.left);
        } else if (stmt && stmt->type == AST_RETURN && stmt->ret.expr &&
                   stmt->ret.expr->type == AST_CASE && table->current_return_type &&
                   (case_result_variant(table, stmt->ret.expr) ||
                    is_aggregate_type(table, table->current_return_type))) {
            is_return = 1;
            case_value = stmt->ret.expr;
            stmt->ret.expr = NULL;
            expected_type = table->current_return_type;
            snprintf(temp_name, sizeof(temp_name), "__mlg_ret_%d", table->temp_counter++);
            dest = new_identifier(temp_name);
        }

        if (case_value) {
            VariantTag *produced = case_result_variant(table, case_value);
            lower_case_result_into(table, case_value, dest, expected_type,
                                   produced ? produced->enum_name : NULL);
            rewrite_payload_node(&case_value, table);

            flush_pending_hoists(table, &out, &count);
            out = realloc(out, sizeof(ASTNode *) * (size_t)(count + 3));
            if (is_return) {
                out[count++] = new_var_decl(ast_clone(table->current_return_type), temp_name, NULL);
                free_ast(stmt);
            } else if (stmt->type == AST_VAR_DECL) {
                out[count++] = stmt;
            } else {
                free_ast(stmt);
            }
            out[count++] = new_expr_stmt(case_value);
            if (is_return) out[count++] = new_return(ast_clone(dest));
            free_ast(dest);
            continue;
        }

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
            trace_kind = stmt->ret.trace_kind;
            trace_note = stmt->ret.trace_note;
            stmt->ret.trace_note = NULL;
            trace_line = stmt->line;
            trace_col = stmt->col;
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
        mark_payload_stores(payload_store, keeps_declaration || is_return);

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
        if (is_return) {
            ASTNode *ret = new_return(ast_clone(dest));
            ret->ret.trace_kind = trace_kind;
            ret->ret.trace_note = trace_note;
            ret->line = trace_line;
            ret->col = trace_col;
            out[count++] = ret;
        }
        free_ast(dest);
    }

    free(block->block.stmts);
    block->block.stmts = out;
    block->block.count = count;
    table->pending_hoists = outer_hoists;
    table->pending_hoist_count = outer_hoist_count;
}

/* What `variant` of the enum `name` carries, while enums are still enums. */
static ASTNode *enum_payload_type(VariantTable *table, const char *name, const char *variant) {
    for (int i = 0; i < table->program->block.count; i++) {
        ASTNode *node = table->program->block.stmts[i];
        if (!node || node->type != AST_ENUM || strcmp(node->enum_stmt.name, name) != 0) continue;
        for (int m = 0; m < node->enum_stmt.member_count; m++) {
            ASTNode *member = node->enum_stmt.members[m];
            if (member && strcmp(member->enum_member.name, variant) == 0)
                return member->enum_member.payload_type;
        }
    }
    return NULL;
}

/* The type a named struct literal gives field `index`. */
static ASTNode *literal_field_type(VariantTable *table, ASTNode *literal, int index) {
    const char *field = literal->init_list.field_names ? literal->init_list.field_names[index] : NULL;
    if (!field) return NULL;
    for (int i = 0; i < table->program->block.count; i++) {
        ASTNode *node = table->program->block.stmts[i];
        ASTNode **members = NULL;
        int count = 0;
        if (node && node->type == AST_STRUCT &&
            strcmp(node->struct_stmt.name, literal->init_list.struct_type_name) == 0) {
            members = node->struct_stmt.members;
            count = node->struct_stmt.member_count;
        } else if (node && node->type == AST_TYPEDEF_STRUCT &&
                   strcmp(node->typedef_struct.typedef_name, literal->init_list.struct_type_name) == 0) {
            members = node->typedef_struct.members;
            count = node->typedef_struct.member_count;
        }
        for (int m = 0; m < count; m++) {
            if (members[m] && members[m]->type == AST_VAR_DECL &&
                strcmp(members[m]->var_decl.name, field) == 0)
                return members[m]->var_decl.var_type;
        }
    }
    return NULL;
}

/* Materialize a payload enum construction as its lowered tagged struct.  A
 * struct-literal field is already a concrete aggregate destination, so unlike
 * ordinary construction this form needs no temporary or sequence of stores.
 * Recurse for payloads such as `Some(Other::None)`.
 *
 * `type` is the field's declared type. Every specialization of a generic enum
 * has its own entry in the table, so the variant alone would build whichever
 * specialization came first. */
static ASTNode *make_payload_struct_literal(VariantTable *table, ASTNode *use, ASTNode *type) {
    VariantTag *variant = variant_use(table, use);
    check_unambiguous(table, variant, use);
    if (variant->has_payload) check_single_payload(table, use);
    const char *enum_name = type_base_name(type) ? type_base_name(type) : variant->enum_name;

    int count = variant->has_payload ? 2 : 1;
    char **field_names = malloc(sizeof(char *) * (size_t)count);
    ASTNode **fields = malloc(sizeof(ASTNode *) * (size_t)count);
    char *tag = tag_text(variant->tag);
    field_names[0] = strdup("__tag");
    fields[0] = new_number(tag);
    free(tag);

    if (variant->has_payload) {
        field_names[1] = strdup(variant->variant);
        ASTNode *payload = use->call.args[0];
        fields[1] = variant_use(table, payload)
            ? make_payload_struct_literal(table, payload,
                                          enum_payload_type(table, enum_name, variant->variant))
            : ast_clone(payload);
    }
    return new_struct_init_list(enum_name, field_names, fields, count);
}

static void hoist_statement(VariantTable *table, ASTNode *statement) {
    table->pending_hoists = realloc(table->pending_hoists,
                                    sizeof(ASTNode *) * (size_t)(table->pending_hoist_count + 1));
    table->pending_hoists[table->pending_hoist_count++] = statement;
}

/* A generated store reports its errors where the construction was written. */
static ASTNode *located_store(ASTNode *place, ASTNode *value, ASTNode *at) {
    ASTNode *assign = new_assign(place, value);
    assign->line = place->line = at->line;
    assign->col = place->col = at->col;
    ASTNode *statement = new_expr_stmt(assign);
    statement->line = at->line;
    statement->col = at->col;
    return statement;
}

static ASTNode *program_struct(ASTNode *program, const char *name) {
    for (int i = 0; program && i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (node && node->type == AST_STRUCT && node->struct_stmt.name &&
            strcmp(node->struct_stmt.name, name) == 0)
            return node;
    }
    return NULL;
}

/* A file can pass None to `set_focus(Option<NodeId>)` without naming the type.
 * The instance's name is the same in every module that has one. */
static void import_type_layout_from_graph(VariantTable *table, const char *name) {
    FrontendSession *session = table->context->session;
    if (!session || !session->graph) return;
    for (int i = 0; i < session->graph->module_count; i++) {
        Module *module = session->graph->modules[i];
        if (module->state != MODULE_LOADED || !program_has_type_layout(module->program, name))
            continue;
        import_type_layout(table, module, name);
        return;
    }
}

/* The lowered layout behind `type`, when that is a payload enum. An alias is
 * followed, and a layout this unit has not seen yet is brought in. */
static ASTNode *payload_layout(VariantTable *table, ASTNode *type) {
    for (int steps = 0; steps < 16; steps++) {
        const char *name = type_base_name(type);
        if (!name) return NULL;
        ASTNode *found = program_struct(table->program, name);
        if (!found && !program_has_type_layout(table->program, name)) {
            import_type_layout_from_graph(table, name);
            found = program_struct(table->program, name);
        }
        if (found) return found->struct_stmt.payload_enum ? found : NULL;

        ASTNode *alias = NULL;
        for (int i = 0; i < table->program->block.count && !alias; i++) {
            ASTNode *node = table->program->block.stmts[i];
            if (node && node->type == AST_TYPEDEF && !node->typedef_stmt.is_newtype &&
                strcmp(node->typedef_stmt.alias, name) == 0)
                alias = node->typedef_stmt.src_type;
        }
        if (!alias) return NULL;
        type = alias;
    }
    return NULL;
}

static ASTNode *layout_member_type(ASTNode *layout, const char *name) {
    for (int i = 0; i < layout->struct_stmt.member_count; i++) {
        ASTNode *member = layout->struct_stmt.members[i];
        if (member && member->type == AST_VAR_DECL && strcmp(member->var_decl.name, name) == 0)
            return member->var_decl.var_type;
    }
    return NULL;
}

/* What `node` is written as, if it could name a variant at all. */
static const char *construction_name(ASTNode *node) {
    if (!node) return NULL;
    if (node->type == AST_CALL && !node->call.recv) return node->call.name;
    return node->type == AST_IDENTIFIER ? node->identifier.name : NULL;
}

/* The variant of `layout`'s enum that `use` spells, or NULL. `use` needs no
 * entry in a variant table: the type says which enum is meant. */
static ASTNode *layout_variant(ASTNode *layout, ASTNode *use) {
    const char *name = construction_name(use);
    if (!name) return NULL;
    ASTNode *payload_enum = layout->struct_stmt.payload_enum;
    const char *separator = strstr(name, "::");
    if (separator) {
        char want[64], got[64];
        snprintf(want, sizeof(want), "%.*s", (int)(separator - name), name);
        copy_display_name(got, sizeof(got), payload_enum->enum_stmt.name);
        if (strcmp(want, got) != 0) return NULL;
        name = separator + 2;
    }
    for (int i = 0; i < payload_enum->enum_stmt.member_count; i++) {
        ASTNode *member = payload_enum->enum_stmt.members[i];
        if (member && strcmp(member->enum_member.name, name) == 0 &&
            (member->enum_member.payload_type != NULL) == (use->type == AST_CALL))
            return member;
    }
    return NULL;
}

/* The tag and payload stores of `use`, into `dest` of the enum `layout` lays
 * out. A payload that is itself a construction goes into its own field. */
static void hoist_construction_stores(VariantTable *table, ASTNode *dest, ASTNode *layout,
                                      ASTNode *variant, ASTNode *use) {
    char *text = tag_text(variant->enum_member.resolved_value);
    hoist_statement(table, located_store(new_member_access(ast_clone(dest), "__tag"),
                                         new_number(text), use));
    free(text);
    if (!variant->enum_member.payload_type) return;
    check_single_payload(table, use);

    ASTNode *field = new_member_access(ast_clone(dest), variant->enum_member.name);
    ASTNode *payload = use->call.args[0];
    ASTNode *field_type = layout_member_type(layout, variant->enum_member.name);
    ASTNode *field_layout = payload_layout(table, field_type);
    ASTNode *nested = field_layout ? layout_variant(field_layout, payload) : NULL;
    if (nested) {
        hoist_construction_stores(table, field, field_layout, nested, payload);
        free_ast(field);
    } else {
        ASTNode *store = located_store(field, ast_clone(payload), payload);
        mark_payload_stores(store, 1);
        hoist_statement(table, store);
    }
}

/* `f(Some(x))`: hoists `T __mlg_arg_N;` and the stores, and leaves the name. */
static void hoist_construction(VariantTable *table, ASTNode **slot, ASTNode *type,
                               ASTNode *layout, ASTNode *variant) {
    ASTNode *use = *slot;
    char name[32];
    snprintf(name, sizeof(name), "__mlg_arg_%d", table->temp_counter++);
    ASTNode *temporary_type = ast_clone(type);
    temporary_type->type_node.type_modifiers &= ~TYPEMOD_CONST;
    ASTNode *declaration = new_var_decl(temporary_type, name, NULL);
    declaration->line = use->line;
    declaration->col = use->col;
    hoist_statement(table, declaration);

    ASTNode *dest = new_identifier(name);
    dest->line = use->line;
    dest->col = use->col;
    hoist_construction_stores(table, dest, layout, variant, use);
    free_ast(use);
    *slot = dest;
}

/* The type a name was declared with in the function being walked, or as a
 * global. */
static ASTNode *declared_value_type(VariantTable *table, const char *name) {
    ASTNode *fn = table->current_function;
    ASTNode *type = NULL;
    for (int i = 0; fn && i < fn->fundef.param_count && !type; i++)
        type = find_local_type(fn->fundef.params[i], name);
    if (!type && fn) type = find_local_type(fn->fundef.body, name);
    for (int i = 0; i < table->program->block.count && !type; i++) {
        ASTNode *node = table->program->block.stmts[i];
        if (node && node->type == AST_VAR_DECL && strcmp(node->var_decl.name, name) == 0)
            type = node->var_decl.var_type;
    }
    return type;
}

/* What a call's arguments go into: a function's parameters, or the parameter
 * types of the function value it calls through. Returns how many of them have
 * a type of their own (a variadic tail has none). */
static int callee_parameters(VariantTable *table, ASTNode *call, ASTNode ***params) {
    ASTNode *fn = callee_declaration(table->context, table->program, call->call.name);
    if (fn) {
        *params = fn->fundef.params;
        return fn->fundef.is_variadic ? fn->fundef.param_count - 1 : fn->fundef.param_count;
    }
    ASTNode *type = declared_value_type(table, call->call.name);
    for (int steps = 0; steps < 16 && type && type->type == AST_TYPE; steps++) {
        const char *name = type_base_name(type);
        ASTNode *alias = NULL;
        for (int i = 0; name && i < table->program->block.count && !alias; i++) {
            ASTNode *node = table->program->block.stmts[i];
            if (node && node->type == AST_TYPEDEF && strcmp(node->typedef_stmt.alias, name) == 0)
                alias = node->typedef_stmt.src_type;
        }
        type = alias;
    }
    if (!type || type->type != AST_TYPE_FUNCTION) return 0;
    *params = type->function_type.param_types;
    return type->function_type.is_variadic ? type->function_type.param_count - 1
                                           : type->function_type.param_count;
}

static ASTNode *parameter_type(ASTNode *param) {
    return param && param->type == AST_PARAM ? param->param.type : param;
}

static void find_side_effect(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    int *found = user_data;
    if (!node || *found) return;
    if ((node->type == AST_CALL && !node->call.is_construction) || node->type == AST_ASSIGN ||
        (node->type == AST_UNARY && (node->unary.op == INC || node->unary.op == DEC ||
                                     node->unary.op == POST_INC || node->unary.op == POST_DEC))) {
        *found = 1;
        return;
    }
    ast_visit_children(node, find_side_effect, user_data);
}

/* An argument ahead of a construction has to keep running first. */
static void hoist_earlier_argument(VariantTable *table, ASTNode **slot, ASTNode *type) {
    int found = 0;
    find_side_effect(slot, &found);
    if (!found || !type) return;
    char name[32];
    snprintf(name, sizeof(name), "__mlg_arg_%d", table->temp_counter++);
    ASTNode *declaration = new_var_decl(ast_clone(type), name, *slot);
    declaration->line = (*slot)->line;
    declaration->col = (*slot)->col;
    hoist_statement(table, declaration);
    ASTNode *reference = new_identifier(name);
    reference->line = declaration->line;
    reference->col = declaration->col;
    *slot = reference;
}

static void argument_error(VariantTable *table, ASTNode *call, int index, ASTNode *argument,
                           const char *problem) {
    char message[384];
    snprintf(message, sizeof(message), "'%s' as argument %d of '%s': %s",
             construction_name(argument), index + 1, call->call.name, problem);
    payload_error(table->context, argument, message);
}

/* The parameter's enum if `argument` names one of its variants, reporting a
 * construction that cannot go there. */
static ASTNode *argument_variant(VariantTable *table, ASTNode *call, int index, ASTNode *type,
                                 ASTNode **layout) {
    ASTNode *argument = call->call.args[index];
    int written_as_variant = argument->type == AST_CALL && argument->call.is_construction;
    *layout = type && type->type == AST_TYPE ? payload_layout(table, type) : NULL;
    ASTNode *variant = *layout ? layout_variant(*layout, argument) : NULL;
    if (variant && argument->type == AST_IDENTIFIER &&
        declared_value_type(table, argument->identifier.name))
        return NULL; /* a variable that shares the variant's name */

    if (written_as_variant && !type)
        argument_error(table, call, index, argument,
                       "the parameter has no type to build it as");
    if (written_as_variant && !*layout)
        argument_error(table, call, index, argument,
                       "the parameter does not take a payload enum");
    if (written_as_variant && !variant)
        argument_error(table, call, index, argument,
                       "it is not a variant of the parameter's enum");
    if (variant && (type->type_node.pointer_level || type->type_node.borrow_kind != REFKIND_NONE))
        argument_error(table, call, index, argument,
                       "a temporary has no place to lend; put it in a variable and pass &variable");
    return variant;
}

static void lower_call_constructions(VariantTable *table, ASTNode *call) {
    for (int i = 0; i < call->call.arg_count; i++)
        rewrite_payload_node(&call->call.args[i], table);
    if (call->call.is_construction) return; /* built by whatever holds it */

    ASTNode **params = NULL;
    int known = callee_parameters(table, call, &params);

    int last = -1;
    for (int i = 0; i < call->call.arg_count; i++) {
        ASTNode *layout = NULL;
        ASTNode *type = i < known ? parameter_type(params[i]) : NULL;
        if (argument_variant(table, call, i, type, &layout)) last = i;
    }
    for (int i = 0; i <= last; i++) {
        ASTNode *layout = NULL;
        ASTNode *type = i < known ? parameter_type(params[i]) : NULL;
        ASTNode *variant = argument_variant(table, call, i, type, &layout);
        if (variant) hoist_construction(table, &call->call.args[i], type, layout, variant);
        else hoist_earlier_argument(table, &call->call.args[i], type);
    }
}

/* The temporaries an expression hoists go ahead of its statement. Where the
 * expression runs only sometimes or more than once, ahead of the statement is
 * the wrong place: its own block keeps them with it. */
static void keep_hoists_here(VariantTable *table, ASTNode **slot) {
    if (!*slot) return;
    ASTNode **outer_hoists = table->pending_hoists;
    int outer_hoist_count = table->pending_hoist_count;
    table->pending_hoists = NULL;
    table->pending_hoist_count = 0;

    rewrite_payload_node(slot, table);

    if (table->pending_hoist_count) {
        int count = table->pending_hoist_count;
        ASTNode **statements = malloc(sizeof(ASTNode *) * (size_t)(count + 1));
        memcpy(statements, table->pending_hoists, sizeof(ASTNode *) * (size_t)count);
        statements[count] = new_yield(*slot);
        ASTNode *wrapped = new_stmt_expr(new_block(statements, count + 1));
        wrapped->line = (*slot)->line;
        wrapped->col = (*slot)->col;
        *slot = wrapped;
        free(table->pending_hoists);
    }
    table->pending_hoists = outer_hoists;
    table->pending_hoist_count = outer_hoist_count;
}

/* The body of an `if`, a loop or a `defer` may be one bare statement, and what
 * that statement hoists must stay inside it: `else if (f()?)`, `while (c)
 * g(None);`. A block is what can hold them. */
static void rewrite_body(VariantTable *table, ASTNode **slot) {
    if (!*slot) return;
    if ((*slot)->type != AST_BLOCK) {
        ASTNode *statement = *slot;
        ASTNode **statements = malloc(sizeof(ASTNode *));
        statements[0] = statement;
        *slot = new_block(statements, 1);
        (*slot)->line = statement->line;
        (*slot)->col = statement->col;
    }
    rewrite_payload_node(slot, table);
}

/* The first pass leaves a construction in an argument for
 * lower_payload_call_arguments(), and only looks inside it. */
static void keep_construction_argument(VariantTable *table, ASTNode **slot) {
    ASTNode *argument = *slot;
    if (variant_bare(table, argument)) return;
    if (!variant_call(table, argument)) {
        rewrite_payload_node(slot, table);
        return;
    }
    argument->call.is_construction = 1;
    for (int i = 0; i < argument->call.arg_count; i++)
        keep_construction_argument(table, &argument->call.args[i]);
}

static void rewrite_payload_node(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    if (!node) return;
    VariantTable *table = user_data;

    switch (node->type) {
    case AST_TERNARY:
        rewrite_payload_node(&node->ternary.cond, table);
        keep_hoists_here(table, &node->ternary.then_expr);
        keep_hoists_here(table, &node->ternary.else_expr);
        return;
    case AST_BINARY:
        if (node->binary.op != LAND && node->binary.op != LOR) break;
        rewrite_payload_node(&node->binary.left, table);
        keep_hoists_here(table, &node->binary.right);
        return;
    case AST_IF:
        rewrite_payload_node(&node->if_stmt.cond, table);
        rewrite_body(table, &node->if_stmt.then_stmt);
        rewrite_body(table, &node->if_stmt.else_stmt);
        return;
    case AST_WHILE:
        keep_hoists_here(table, &node->while_stmt.cond);
        rewrite_body(table, &node->while_stmt.body);
        return;
    case AST_DO_WHILE:
        rewrite_body(table, &node->do_while_stmt.body);
        keep_hoists_here(table, &node->do_while_stmt.cond);
        return;
    case AST_FOR:
        rewrite_payload_node(&node->for_stmt.init, table);
        keep_hoists_here(table, &node->for_stmt.cond);
        keep_hoists_here(table, &node->for_stmt.inc);
        rewrite_body(table, &node->for_stmt.body);
        return;
    case AST_DEFER:
        rewrite_body(table, &node->defer_stmt.body);
        return;
    default:
        break;
    }

    /* Tracks the function whose body is being walked, so a `return Ok(5);`
     * inside it knows which payload enum to build (see rewrite_payload_block).
     * Saved and restored around the visit so nested function literals, if any,
     * see their own return type rather than the enclosing one's. */
    if (node->type == AST_FUNDEF) {
        ASTNode *saved_return_type = table->current_return_type;
        ASTNode *saved_function = table->current_function;
        table->current_return_type = node->fundef.ret_type;
        table->current_function = node;
        ast_visit_children(node, rewrite_payload_node, user_data);
        table->current_return_type = saved_return_type;
        table->current_function = saved_function;
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
        rewrite_payload_node(&node->case_expr.target, table);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            rewrite_payload_node(&node->case_expr.cases[i].key, table);
            keep_hoists_here(table, &node->case_expr.cases[i].expr);
        }
        keep_hoists_here(table, &node->case_expr.default_expr);
        return;
    }

    /* A named struct literal supplies a concrete destination for each field,
     * just like `Option<i32> value = None` does.  Rewrite a variant used as a
     * field value to the enum's lowered struct literal, rather than requiring
     * a source-level temporary.  This is deliberately handled before the
     * ordinary child walk: bare unit variants such as `None` are identifiers
     * and otherwise reach semantic analysis as undefined names. */
    if (node->type == AST_INIT_LIST && node->init_list.struct_type_name) {
        for (int i = 0; i < node->init_list.count; i++) {
            ASTNode *value = node->init_list.elements[i];
            VariantTag *variant = variant_use(table, value);
            if (!variant) continue;
            ASTNode *replacement = make_payload_struct_literal(
                table, value, literal_field_type(table, node, i));
            free_ast(value);
            node->init_list.elements[i] = replacement;
        }
    }

    /* A construction anywhere else has no destination to store into. Only the
     * carrying spelling is diagnosed: a bare variant is just an identifier, and
     * an unrelated variable may legitimately share its name. */
    if (variant_call(table, node)) {
        char message[256];
        snprintf(message, sizeof(message),
                 "'%s' constructs a payload enum, which can only appear as the whole "
                 "right-hand side of an assignment or an initialiser, or as a call argument",
                 node->call.name);
        payload_error(table->context, node, message);
    }

    if (node->type == AST_CALL && table->lowering_arguments) {
        lower_call_constructions(table, node);
        return;
    }
    if (node->type == AST_CALL) {
        for (int i = 0; i < node->call.arg_count; i++)
            keep_construction_argument(table, &node->call.args[i]);
        rewrite_payload_node(&node->call.recv, table);
        return;
    }

    ast_visit_children(node, rewrite_payload_node, user_data);
}

/* Walks a copy of the list: a layout imported on the way lands in the program. */
static void rewrite_program(VariantTable *table) {
    int count = table->program->block.count;
    ASTNode **nodes = malloc(sizeof(ASTNode *) * (size_t)(count ? count : 1));
    memcpy(nodes, table->program->block.stmts, sizeof(ASTNode *) * (size_t)count);
    for (int i = 0; i < count; i++) {
        if (!nodes[i] || nodes[i]->type == AST_ENUM) continue;
        rewrite_payload_node(&nodes[i], table);
    }
    free(nodes);
}

/* Runs after specialization, so every payload enum in the program is concrete
 * and its variants carry final tags, and before the declarations themselves are
 * lowered to structs. */
void lower_payload_enum_uses(ParserContext *context, ASTNode *program) {
    VariantTable table = {.context = context, .program = program};
    collect_variants(&table, program);
    if (table.count == 0) return;

    rewrite_program(&table);

    for (int i = 0; i < table.count; i++) free(table.items[i].variant);
    free(table.items);
}

/* Runs once call names are final, so a callee can be looked up whatever it
 * was written as. The walk is the one above, to the same hoists; every other
 * construction is gone by now, which leaves it nothing else to do. */
void lower_payload_call_arguments(ParserContext *context, ASTNode *program) {
    VariantTable table = {.context = context, .program = program, .lowering_arguments = 1};
    rewrite_program(&table);
}
