#include "mylang/frontend/parser_trait_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/support/stringBuilder.h"
#include "mylang/type/type_info.h"

/* Traits and impls (docs/traits.md).
 *
 * A trait is only a contract, so parsing one registers a TraitDef and leaves
 * nothing in the program. An impl's items are parsed as the ordinary methods
 * and functions they implement and spliced into the program; what remains of
 * the impl is its ImplDef, which later passes consult to check bounds and to
 * lower `?`, `==`, `Type::name(...)`, and for-in. Semantic analysis and
 * codegen therefore never learn traits exist. */

static void trait_error_at(ParserContext *context, int line, int col, const char *message,
                           const char *note) {
    fprintf(stderr, "%s:%d:%d: error: %s\n",
            context->module.filename ? context->module.filename : "<input>", line, col, message);
    if (note) fprintf(stderr, "  note: %s\n", note);
    exit(1);
}

/* ---- records ---------------------------------------------------------- */

static void free_token_list(Token *tok) {
    while (tok) {
        Token *next = tok->next;
        free(tok->value);
        free(tok);
        tok = next;
    }
}

/* A copy of one token, positioned at `at` (the source position a
 * diagnostic should name). */
static Token *clone_token(const Token *src, const Token *at) {
    Token *tok = calloc(1, sizeof(Token));
    tok->kind = src->kind;
    if (src->value) {
        /* A string literal's value may hold NUL bytes; value_length counts
         * them. */
        size_t len = src->value_length > 0 ? (size_t)src->value_length : strlen(src->value);
        tok->value = malloc(len + 1);
        memcpy(tok->value, src->value, len);
        tok->value[len] = '\0';
    }
    tok->value_length = src->value_length;
    tok->line = at->line;
    tok->col = at->col;
    tok->length = src->length;
    return tok;
}

/* Copies [first, last] into an owned list ending in EOT. */
static Token *copy_token_range(const Token *first, const Token *last) {
    Token head = {0};
    Token *tail = &head;
    for (const Token *t = first; t; t = t->next) {
        tail->next = clone_token(t, t);
        tail = tail->next;
        if (t == last) break;
    }
    Token *eot = calloc(1, sizeof(Token));
    eot->kind = EOT;
    eot->line = tail->line;
    eot->col = tail->col;
    tail->next = eot;
    return head.next;
}

void trait_def_free(TraitDef *trait) {
    if (!trait) return;
    free(trait->name);
    for (int i = 0; i < trait->type_param_count; i++) free(trait->type_params[i]);
    free(trait->type_params);
    for (int i = 0; i < trait->item_count; i++) {
        free_ast(trait->items[i]);
        if (trait->defaults) free_token_list(trait->defaults[i]);
    }
    free(trait->items);
    free(trait->defaults);
    free(trait);
}

void impl_def_free(ImplDef *impl) {
    if (!impl) return;
    free(impl->trait_name);
    for (int i = 0; i < impl->trait_arg_count; i++) free_ast(impl->trait_args[i]);
    free(impl->trait_args);
    free_ast(impl->self_type);
    free(impl->self_name);
    for (int i = 0; i < impl->item_count; i++) {
        free(impl->item_names[i]);
        free(impl->item_mangled[i]);
    }
    free(impl->item_names);
    free(impl->item_mangled);
    for (int i = 0; i < impl->type_param_count; i++) {
        free(impl->type_params[i]);
        if (impl->type_param_bounds) free_ast(impl->type_param_bounds[i]);
    }
    free(impl->type_params);
    free(impl->type_param_bounds);
    free(impl->placeholder);
    if (impl->template_items) {
        for (int i = 0; i < impl->item_count; i++) free_ast(impl->template_items[i]);
        free(impl->template_items);
    }
    free(impl);
}

static char **clone_strings(char **src, int count) {
    if (!src || count == 0) return NULL;
    char **out = malloc(sizeof(char *) * (size_t)count);
    for (int i = 0; i < count; i++) out[i] = src[i] ? strdup(src[i]) : NULL;
    return out;
}

static ASTNode **clone_nodes(ASTNode **src, int count) {
    if (!src || count == 0) return NULL;
    ASTNode **out = malloc(sizeof(ASTNode *) * (size_t)count);
    for (int i = 0; i < count; i++) out[i] = ast_clone(src[i]);
    return out;
}

TraitDef *trait_def_clone(const TraitDef *trait) {
    TraitDef *out = calloc(1, sizeof(TraitDef));
    out->name = strdup(trait->name);
    out->type_params = clone_strings(trait->type_params, trait->type_param_count);
    out->type_param_count = trait->type_param_count;
    out->items = clone_nodes(trait->items, trait->item_count);
    if (trait->defaults) {
        out->defaults = calloc((size_t)trait->item_count, sizeof(Token *));
        for (int i = 0; i < trait->item_count; i++) {
            if (!trait->defaults[i]) continue;
            const Token *last = trait->defaults[i];
            while (last->next && last->next->kind != EOT) last = last->next;
            out->defaults[i] = copy_token_range(trait->defaults[i], last);
        }
    }
    out->item_count = trait->item_count;
    out->is_exported = trait->is_exported;
    return out;
}

ImplDef *impl_def_clone(const ImplDef *impl) {
    ImplDef *out = calloc(1, sizeof(ImplDef));
    out->trait_name = strdup(impl->trait_name);
    out->trait_args = clone_nodes(impl->trait_args, impl->trait_arg_count);
    out->trait_arg_count = impl->trait_arg_count;
    out->self_type = ast_clone(impl->self_type);
    out->self_name = strdup(impl->self_name);
    out->item_names = clone_strings(impl->item_names, impl->item_count);
    out->item_mangled = clone_strings(impl->item_mangled, impl->item_count);
    out->item_count = impl->item_count;
    out->is_exported = impl->is_exported;
    out->line = impl->line;
    out->col = impl->col;
    out->is_template = impl->is_template;
    out->type_params = clone_strings(impl->type_params, impl->type_param_count);
    out->type_param_bounds = clone_nodes(impl->type_param_bounds, impl->type_param_count);
    out->type_param_count = impl->type_param_count;
    out->placeholder = impl->placeholder ? strdup(impl->placeholder) : NULL;
    out->template_items = clone_nodes(impl->template_items, impl->item_count);
    return out;
}

static void add_trait(ParserContext *context, TraitDef *trait) {
    TraitTable *table = &context->symbols.traits;
    table->traits = realloc(table->traits, sizeof(TraitDef *) * (size_t)(table->count + 1));
    table->traits[table->count++] = trait;
}

static void add_impl(ParserContext *context, ImplDef *impl) {
    ImplTable *table = &context->symbols.impls;
    table->impls = realloc(table->impls, sizeof(ImplDef *) * (size_t)(table->count + 1));
    table->impls[table->count++] = impl;
}

void add_impl_instance(ParserContext *context, ImplDef *impl) {
    add_impl(context, impl);
}

TraitDef *find_trait(ParserContext *context, const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < context->symbols.traits.count; i++) {
        if (strcmp(context->symbols.traits.traits[i]->name, name) == 0)
            return context->symbols.traits.traits[i];
    }
    return NULL;
}

int impl_count(ParserContext *context) {
    return context->symbols.impls.count;
}

ImplDef *impl_at(ParserContext *context, int index) {
    if (index < 0 || index >= context->symbols.impls.count) return NULL;
    return context->symbols.impls.impls[index];
}

const char *impl_item_mangled(const ImplDef *impl, const char *item_name) {
    if (!impl || !item_name) return NULL;
    for (int i = 0; i < impl->item_count; i++) {
        if (strcmp(impl->item_names[i], item_name) == 0) return impl->item_mangled[i];
    }
    return NULL;
}

/* ---- type spelling ---------------------------------------------------- */

static void append_type_key(StringBuilder *sb, ASTNode *type) {
    if (!type) {
        sb_append(sb, "?");
        return;
    }
    switch (type->type) {
    case AST_TYPE: {
        if (type->type_node.ref_kind == REFKIND_SHARED) sb_append(sb, "ref ");
        else if (type->type_node.ref_kind == REFKIND_MUT) sb_append(sb, "ref mut ");
        if (type->type_node.type_modifiers) sb_append(sb, "m%d ", type->type_node.type_modifiers);
        append_type_key(sb, type->type_node.base_type);
        for (int i = 0; i < type->type_node.pointer_level; i++) sb_append(sb, "*");
        return;
    }
    case AST_IDENTIFIER:
        sb_append(sb, "%s", type->identifier.name);
        return;
    case AST_TYPE_GENERIC:
        sb_append(sb, "%s<", type->generic_type.name);
        for (int i = 0; i < type->generic_type.arg_count; i++) {
            if (i) sb_append(sb, ",");
            append_type_key(sb, type->generic_type.args[i]);
        }
        sb_append(sb, ">");
        return;
    case AST_TYPE_ARRAY:
        append_type_key(sb, type->type_array.element_type);
        sb_append(sb, "[%d]", type->type_array.array_size);
        return;
    case AST_TYPE_FUNCTION:
        sb_append(sb, "fn(");
        for (int i = 0; i < type->function_type.param_count; i++) {
            if (i) sb_append(sb, ",");
            append_type_key(sb, type->function_type.param_types[i]);
        }
        sb_append(sb, ")->");
        append_type_key(sb, type->function_type.return_type);
        return;
    case AST_NUMBER:
        sb_append(sb, "%s", type->number.value);
        return;
    default:
        sb_append(sb, "?");
        return;
    }
}

char *trait_type_key(ASTNode *type) {
    StringBuilder sb;
    sb_init(&sb);
    append_type_key(&sb, type);
    char *out = strdup(sb.buf ? sb.buf : "");
    sb_free(&sb);
    return out;
}

/* Reads one length-prefixed name (`3_Box`) at *p, demangling it when it is
 * itself an instance. */
static int demangle_name(const char **p, StringBuilder *out);

/* `__mlg_s_3_Box_p0_r0_m0_n5_Point` -> `Box<Point>` (parser_instantiate.c
 * builds the key). Returns 0, leaving *p, when *p is not an instance. */
static int demangle_instance(const char **p, StringBuilder *out) {
    const char *s = *p;
    if (strncmp(s, "__mlg_s_", 8) != 0 && strncmp(s, "__mlg_f_", 8) != 0) return 0;
    s += 8;
    if (!demangle_name(&s, out)) return 0;
    int first = 1;
    while (*s == '_' && (s[1] == 'p' || s[1] == 'c')) {
        sb_append(out, first ? "<" : ", ");
        first = 0;
        if (s[1] == 'c') {
            s += 2;
            char *end;
            long len = strtol(s, &end, 10);
            if (*end != '_') return 0;
            sb_append(out, "%.*s", (int)len, end + 1);
            s = end + 1 + len;
            continue;
        }
        int ptr = 0, ref = 0, mods = 0, used = 0;
        if (sscanf(s, "_p%d_r%d_m%d_n%n", &ptr, &ref, &mods, &used) < 3 || used == 0) return 0;
        s += used;
        if (ref == REFKIND_SHARED) sb_append(out, "ref ");
        else if (ref == REFKIND_MUT) sb_append(out, "ref mut ");
        if (!demangle_name(&s, out)) return 0;
        for (int i = 0; i < ptr; i++) sb_append(out, "*");
    }
    if (!first) sb_append(out, ">");
    *p = s;
    return 1;
}

static int demangle_name(const char **p, StringBuilder *out) {
    char *end;
    long len = strtol(*p, &end, 10);
    if (end == *p || *end != '_' || len <= 0) return 0;
    const char *name = end + 1;
    const char *inner = name;
    StringBuilder nested;
    sb_init(&nested);
    if (demangle_instance(&inner, &nested) && inner == name + len) sb_append(out, "%s", nested.buf);
    else sb_append(out, "%.*s", (int)len, name);
    sb_free(&nested);
    *p = name + len;
    return 1;
}

char *trait_type_display(ASTNode *type) {
    char *key = trait_type_key(type);
    StringBuilder out;
    sb_init(&out);
    for (const char *s = key; *s;) {
        StringBuilder piece;
        sb_init(&piece);
        const char *at = s;
        if (demangle_instance(&at, &piece)) {
            sb_append(&out, "%s", piece.buf);
            s = at;
        } else {
            sb_append(&out, "%c", *s);
            s++;
        }
        sb_free(&piece);
    }
    char *display = strdup(out.buf ? out.buf : "");
    sb_free(&out);
    free(key);
    return display;
}

static int same_type(ASTNode *left, ASTNode *right) {
    char *a = trait_type_key(left);
    char *b = trait_type_key(right);
    int same = strcmp(a, b) == 0;
    free(a);
    free(b);
    return same;
}

ImplDef *find_impl(ParserContext *context, const char *trait_name,
                   ASTNode **args, int arg_count, ASTNode *self_type) {
    for (int i = 0; i < context->symbols.impls.count; i++) {
        ImplDef *impl = context->symbols.impls.impls[i];
        if (impl->is_template) continue;
        if (strcmp(impl->trait_name, trait_name) != 0 || impl->trait_arg_count != arg_count)
            continue;
        if (!same_type(impl->self_type, self_type)) continue;
        int args_match = 1;
        for (int a = 0; a < arg_count && args_match; a++)
            args_match = same_type(impl->trait_args[a], args[a]);
        if (args_match) return impl;
    }
    return NULL;
}

ImplDef *find_impl_for_name(ParserContext *context, const char *trait_name,
                            const char *self_name) {
    for (int i = 0; i < context->symbols.impls.count; i++) {
        ImplDef *impl = context->symbols.impls.impls[i];
        if (impl->is_template) continue;
        if (strcmp(impl->trait_name, trait_name) == 0 && strcmp(impl->self_name, self_name) == 0)
            return impl;
    }
    return NULL;
}

/* Replace each named type by its stand-in, carrying the use site's pointer
 * level, reference kind, and modifiers -- `Self *` with Self = FsError reads
 * `FsError *`. */
typedef struct {
    char **names;
    ASTNode **types;
    int count;
} TypeSubst;

static void subst_type_slot(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    TypeSubst *sub = user_data;
    if (!node) return;
    if (node->type == AST_TYPE && node->type_node.base_type &&
        node->type_node.base_type->type == AST_IDENTIFIER) {
        for (int i = 0; i < sub->count; i++) {
            if (strcmp(node->type_node.base_type->identifier.name, sub->names[i]) != 0) continue;
            ASTNode *replacement = ast_clone(sub->types[i]);
            if (replacement->type == AST_TYPE) {
                replacement->type_node.pointer_level += node->type_node.pointer_level;
                replacement->type_node.type_modifiers |= node->type_node.type_modifiers;
                if (node->type_node.ref_kind != REFKIND_NONE)
                    replacement->type_node.ref_kind = node->type_node.ref_kind;
            }
            replacement->line = node->line;
            replacement->col = node->col;
            free_ast(node);
            *slot = replacement;
            return;
        }
    }
    ast_visit_children(node, subst_type_slot, user_data);
}

static ASTNode *subst_type(ASTNode *type, TypeSubst *sub) {
    ASTNode *out = ast_clone(type);
    subst_type_slot(&out, sub);
    return out;
}

/* ---- foreign names (orphan rule) -------------------------------------- */

void mark_foreign_name(ParserContext *context, const char *name) {
    if (!name) return;
    for (int i = 0; i < context->symbols.foreign_name_count; i++)
        if (strcmp(context->symbols.foreign_names[i], name) == 0) return;
    context->symbols.foreign_names = realloc(context->symbols.foreign_names,
        sizeof(char *) * (size_t)(context->symbols.foreign_name_count + 1));
    context->symbols.foreign_names[context->symbols.foreign_name_count++] = strdup(name);
}

static int is_foreign_name(ParserContext *context, const char *name) {
    if (!name) return 1;
    if (mylang_type_is_builtin(name)) return 1;
    for (int i = 0; i < context->symbols.foreign_name_count; i++)
        if (strcmp(context->symbols.foreign_names[i], name) == 0) return 1;
    return 0;
}

static const char *type_base_name(ASTNode *type) {
    if (!type || type->type != AST_TYPE || !type->type_node.base_type) return NULL;
    ASTNode *base = type->type_node.base_type;
    if (base->type == AST_IDENTIFIER) return base->identifier.name;
    if (base->type == AST_TYPE_GENERIC) return base->generic_type.name;
    return NULL;
}

/* ---- trait declarations ----------------------------------------------- */

/* `R (Self *self) name(params);` or `R name(params);`, or either with a
 * `{ body }` instead of `;`: a default, whose tokens go to `*out_default`. */
static ASTNode *parse_trait_item(ParserContext *context, Token **cur, Token **out_default) {
    Token *start = *cur;
    *out_default = NULL;
    ASTNode *ret_type = parse_type(context, cur);
    ASTNode *recv = NULL;
    if ((*cur)->kind == L_PARENTHESES) {
        *cur = (*cur)->next;
        recv = parse_param(context, cur);
        if (!expect(cur, R_PARENTHESES)) parse_error(context, "expected ')' after method receiver", *cur);
        const char *recv_name = recv->type == AST_PARAM ? type_base_name(recv->param.type) : NULL;
        if (!recv_name || strcmp(recv_name, "Self") != 0)
            parse_error(context, "a trait method's receiver must be Self", start);
    }
    if (!token_is_member_name(*cur)) parse_error(context, "expected trait item name", *cur);
    Token *name_tok = *cur;
    *cur = (*cur)->next;
    if ((*cur)->kind == LT) parse_error(context, "generic trait items are not supported yet", *cur);
    if (!expect(cur, L_PARENTHESES)) parse_error(context, "expected '(' after trait item name", *cur);
    int count = 0;
    bool is_variadic = false;
    ASTNode **rest = NULL;
    if ((*cur)->kind != R_PARENTHESES) rest = parse_param_list(context, cur, &count, &is_variadic);
    if (!expect(cur, R_PARENTHESES)) parse_error(context, "expected ')' after parameter list", *cur);
    if ((*cur)->kind == L_BRACE) {
        /* The body is parsed per impl, once `Self` is known; here it is only
         * kept. */
        int depth = 0;
        Token *last = *cur;
        for (Token *t = *cur; t && t->kind != EOT; t = t->next) {
            if (t->kind == L_BRACE) depth++;
            else if (t->kind == R_BRACE && --depth == 0) { last = t; break; }
        }
        if (depth != 0) parse_error(context, "unterminated default body", *cur);
        *out_default = copy_token_range(start, last);
        *cur = last->next;
    } else if (!expect(cur, SEMICOLON)) {
        parse_error(context, "expected ';' or a default body after trait item", *cur);
    }

    int total = count + (recv ? 1 : 0);
    ASTNode **params = total ? malloc(sizeof(ASTNode *) * (size_t)total) : NULL;
    int at = 0;
    if (recv) params[at++] = recv;
    for (int i = 0; i < count; i++) params[at++] = rest[i];
    free(rest);
    ASTNode *item = new_fundef(ret_type, name_tok->value, params, total, NULL, is_variadic);
    if (recv) item->fundef.recv_type_name = strdup("Self");
    set_node_loc_from_tokens(item, start, name_tok);
    return item;
}

ASTNode *parse_trait(ParserContext *context, Token **cur, int want_export) {
    Token *start = *cur;
    if (!expect(cur, TRAIT)) parse_error(context, "expected 'trait'", *cur);
    if ((*cur)->kind != IDENTIFIER) parse_error(context, "expected trait name", *cur);
    Token *name_tok = *cur;
    if (find_trait(context, name_tok->value)) parse_error(context, "duplicate trait", name_tok);
    if (is_user_typename(context, name_tok->value))
        parse_error(context, "a trait cannot share its name with a type", name_tok);
    *cur = (*cur)->next;

    int mark = typename_scope_mark(context);
    TraitDef *trait = calloc(1, sizeof(TraitDef));
    trait->name = strdup(name_tok->value);
    trait->is_exported = want_export;
    if ((*cur)->kind == LT) {
        Token *params_tok = *cur;
        ASTNode **bounds = NULL;
        trait->type_params = parse_type_params(context, cur, &trait->type_param_count, NULL, 1, &bounds);
        if (bounds) parse_error(context, "trait type parameters cannot have bounds yet", params_tok);
    }
    add_typename(context, "Self");

    if (!expect(cur, L_BRACE)) parse_error(context, "expected '{' after trait name", *cur);
    while ((*cur)->kind != R_BRACE) {
        if ((*cur)->kind == EOT) parse_error(context, "unterminated trait", start);
        Token *default_tokens = NULL;
        ASTNode *item = parse_trait_item(context, cur, &default_tokens);
        for (int i = 0; i < trait->item_count; i++) {
            if (strcmp(trait->items[i]->fundef.name, item->fundef.name) == 0)
                trait_error_at(context, item->line, item->col, "duplicate trait item", NULL);
        }
        trait->items = realloc(trait->items, sizeof(ASTNode *) * (size_t)(trait->item_count + 1));
        if (default_tokens && !trait->defaults)
            trait->defaults = calloc((size_t)trait->item_count + 1, sizeof(Token *));
        if (trait->defaults) {
            trait->defaults = realloc(trait->defaults, sizeof(Token *) * (size_t)(trait->item_count + 1));
            trait->defaults[trait->item_count] = default_tokens;
        }
        trait->items[trait->item_count++] = item;
    }
    *cur = (*cur)->next;
    if ((*cur)->kind == SEMICOLON) *cur = (*cur)->next;
    restore_typenames(context, mark);
    add_trait(context, trait);
    return NULL;
}

/* ---- impl declarations ------------------------------------------------ */

/* Spell `Self` inside an impl body as the impl's own type. The self type is a
 * single token (impls of generic instances are not supported yet), so this is
 * a plain rename of each `Self` identifier between the braces. */
static void substitute_self_tokens(Token *open_brace, const Token *self_tok) {
    int depth = 0;
    for (Token *t = open_brace; t; t = t->next) {
        if (t->kind == L_BRACE) depth++;
        else if (t->kind == R_BRACE && --depth == 0) return;
        else if (t->kind == IDENTIFIER && t->value && strcmp(t->value, "Self") == 0) {
            Token *copy = clone_token(self_tok, t);
            free(t->value);
            t->kind = copy->kind;
            t->value = copy->value;
            t->value_length = copy->value_length;
            free(copy);
        }
    }
}

static char *mangle_type_key(const char *key) {
    char *out = strdup(key);
    for (char *p = out; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')))
            *p = '_';
    }
    return out;
}

/* A receiver item is the method `Self__name`, as any method is. An
 * associated function has no receiver to tell impls apart, so a generic
 * trait's arguments become part of its label: one type may implement both
 * From<A> and From<B>. */
static char *assoc_function_label(TraitDef *trait, ImplDef *impl, const char *item_name) {
    StringBuilder sb;
    sb_init(&sb);
    sb_append(&sb, "%s__", impl->self_name);
    if (trait->type_param_count > 0) {
        sb_append(&sb, "%s", trait->name);
        for (int i = 0; i < impl->trait_arg_count; i++) {
            char *key = trait_type_key(impl->trait_args[i]);
            char *safe = mangle_type_key(key);
            sb_append(&sb, "_%s", safe);
            free(safe);
            free(key);
        }
        sb_append(&sb, "__");
    }
    sb_append(&sb, "%s", item_name);
    char *out = strdup(sb.buf);
    sb_free(&sb);
    return out;
}

char *impl_assoc_label(ParserContext *context, ImplDef *impl, const char *item_name) {
    TraitDef *trait = find_trait(context, impl->trait_name);
    return assoc_function_label(trait, impl, item_name);
}

static TypeSubst impl_subst(TraitDef *trait, ImplDef *impl) {
    TypeSubst sub = {0};
    sub.count = trait->type_param_count + 1;
    sub.names = malloc(sizeof(char *) * (size_t)sub.count);
    sub.types = malloc(sizeof(ASTNode *) * (size_t)sub.count);
    sub.names[0] = "Self";
    sub.types[0] = impl->self_type;
    for (int i = 0; i < trait->type_param_count; i++) {
        sub.names[i + 1] = trait->type_params[i];
        sub.types[i + 1] = impl->trait_args[i];
    }
    return sub;
}

static void signature_mismatch(ParserContext *context, ASTNode *fn, TraitDef *trait,
                               const char *item, ASTNode *expected, ASTNode *actual,
                               const char *what) {
    char *want = trait_type_key(expected);
    char *got = trait_type_key(actual);
    char message[512];
    snprintf(message, sizeof(message), "'%s' does not match trait %s: %s is '%s', expected '%s'",
             item, trait->name, what, got, want);
    free(want);
    free(got);
    trait_error_at(context, fn->line, fn->col, message, NULL);
}

static void check_item_signature(ParserContext *context, TraitDef *trait, TypeSubst *sub,
                                 ASTNode *item, ASTNode *fn) {
    const char *name = item->fundef.name;
    int item_is_method = item->fundef.recv_type_name != NULL;
    int fn_is_method = fn->fundef.recv_type_name != NULL;
    if (item_is_method != fn_is_method) {
        char message[256];
        snprintf(message, sizeof(message), "'%s' must be %s, as trait %s declares it", name,
                 item_is_method ? "a method with a receiver" : "an associated function without a receiver",
                 trait->name);
        trait_error_at(context, fn->line, fn->col, message, NULL);
    }
    ASTNode *ret = subst_type(item->fundef.ret_type, sub);
    if (!same_type(ret, fn->fundef.ret_type))
        signature_mismatch(context, fn, trait, name, ret, fn->fundef.ret_type, "the return type");
    free_ast(ret);
    if (item->fundef.param_count != fn->fundef.param_count) {
        char message[256];
        snprintf(message, sizeof(message), "'%s' takes %d parameter(s); trait %s declares %d", name,
                 fn->fundef.param_count, trait->name, item->fundef.param_count);
        trait_error_at(context, fn->line, fn->col, message, NULL);
    }
    for (int i = 0; i < item->fundef.param_count; i++) {
        ASTNode *want = subst_type(item->fundef.params[i]->param.type, sub);
        ASTNode *got = fn->fundef.params[i]->param.type;
        if (!same_type(want, got))
            signature_mismatch(context, fn, trait, name, want, got,
                               i == 0 && item_is_method ? "the receiver" : "a parameter");
        free_ast(want);
    }
}

/* `impl From<SsdError> for FsError = FsError::IoError;` -- the one associated
 * function of the trait, returning a fixed value regardless of its argument. */
static ASTNode *synthesize_short_impl(ParserContext *context, TraitDef *trait, TypeSubst *sub,
                                      ASTNode *value, Token *at) {
    if (trait->item_count != 1 || trait->items[0]->fundef.recv_type_name)
        parse_error(context, "'impl ... = value;' needs a trait with exactly one associated function", at);
    ASTNode *item = trait->items[0];
    ASTNode **params = item->fundef.param_count
        ? malloc(sizeof(ASTNode *) * (size_t)item->fundef.param_count) : NULL;
    for (int i = 0; i < item->fundef.param_count; i++) {
        ASTNode *param = item->fundef.params[i];
        params[i] = new_param(subst_type(param->param.type, sub), param->param.name);
    }
    ASTNode **stmts = malloc(sizeof(ASTNode *));
    stmts[0] = new_return(value);
    ASTNode *fn = new_fundef(subst_type(item->fundef.ret_type, sub), item->fundef.name, params,
                             item->fundef.param_count, new_block(stmts, 1), item->fundef.is_variadic);
    set_node_loc_from_tokens(fn, at, NULL);
    return fn;
}

/* An item the impl leaves out, built from the trait's default: its tokens
 * again, with `Self` spelled as the impl's type, parsed as if the impl had
 * written them. The trait's own type parameters are replaced afterwards in
 * the AST, so `Option<T>` reads `Option<i32>` for `impl Iterator<i32>`.
 *
 * The parser may keep pointers into a token's value, so the copy stays
 * allocated for the rest of the compilation. */
static ASTNode *parse_default_item(ParserContext *context, TraitDef *trait, ImplDef *impl,
                                   int item_index, const Token *self_tok, const Token *at) {
    const Token *source = trait->defaults[item_index];
    const Token *last = source;
    while (last->next && last->next->kind != EOT) last = last->next;
    Token *tokens = copy_token_range(source, last);
    for (Token *t = tokens; t; t = t->next) {
        /* Diagnostics in a default point at the impl that instantiated it. */
        t->line = at->line;
        t->col = at->col;
        if (t->kind == IDENTIFIER && t->value && strcmp(t->value, "Self") == 0) {
            free(t->value);
            t->kind = self_tok->kind;
            t->value = strdup(self_tok->value);
            t->value_length = self_tok->value_length;
        }
    }

    int mark = typename_scope_mark(context);
    for (int i = 0; i < trait->type_param_count; i++) add_typename(context, trait->type_params[i]);
    Token *cur = tokens;
    ASTNode *fn = trait->items[item_index]->fundef.recv_type_name ? parse_method(context, &cur)
                                                                  : parse_fundef(context, &cur);
    restore_typenames(context, mark);
    if (!fn || fn->type != AST_FUNDEF || !fn->fundef.body)
        trait_error_at(context, at->line, at->col, "a trait's default item did not parse as a function", NULL);

    if (trait->type_param_count > 0) {
        TypeSubst params = {0};
        params.count = trait->type_param_count;
        params.names = trait->type_params;
        params.types = impl->trait_args;
        subst_type_slot(&fn, &params);
    }
    return fn;
}

static void orphan_check(ParserContext *context, TraitDef *trait, ImplDef *impl, Token *at) {
    (void)trait;
    if (!is_foreign_name(context, impl->trait_name)) return;
    if (!is_foreign_name(context, impl->self_name)) return;
    for (int i = 0; i < impl->trait_arg_count; i++)
        if (!is_foreign_name(context, type_base_name(impl->trait_args[i]))) return;
    char message[256];
    snprintf(message, sizeof(message), "impl %s for %s is not allowed here", impl->trait_name,
             impl->self_name);
    trait_error_at(context, at->line, at->col, message,
                   "the trait, the type, or one of the trait's type arguments must be declared "
                   "in this source tree rather than imported through an '@' alias");
}

/* Copy is a compiler-recognised marker because it changes ownership checking.
 * The semantic pass validates its fields after every struct layout is known. */
static void validate_copy_impl(ParserContext *context, ImplDef *impl, Token *at) {
    if (strcmp(impl->trait_name, "Copy") != 0) return;
    if (find_impl_for_name(context, "Drop", impl->self_name))
        trait_error_at(context, at->line, at->col,
                       "a type with drop() cannot implement Copy", NULL);
}

/* Tokens [first, last] spell a type; does the sequence starting at `t`? */
static const Token *match_token_run(const Token *t, const Token *first, const Token *last) {
    for (const Token *p = first;; p = p->next, t = t->next) {
        if (!t || t->kind != p->kind) return NULL;
        if ((t->value || p->value) && (!t->value || !p->value || strcmp(t->value, p->value) != 0))
            return NULL;
        if (p == last) return t;
    }
}

/* In an impl template's body, `Self` and the impl's type spelled out
 * (`Box<T>`) both become the one placeholder token, so the items parse as
 * methods of a plain named type. The tokens a spelled-out type replaced are
 * unlinked and stay allocated: the parser may hold pointers into them. */
static void substitute_template_self(Token *open_brace, const Token *self_first,
                                     const Token *self_last, const char *placeholder) {
    int depth = 0;
    for (Token *t = open_brace; t; t = t->next) {
        if (t->kind == L_BRACE) depth++;
        else if (t->kind == R_BRACE && --depth == 0) return;
        const Token *run_end = NULL;
        if (t->kind == IDENTIFIER && t->value && strcmp(t->value, "Self") == 0) run_end = t;
        else run_end = match_token_run(t, self_first, self_last);
        if (!run_end) continue;
        free(t->value);
        t->kind = IDENTIFIER;
        t->value = strdup(placeholder);
        t->value_length = (int)strlen(placeholder);
        t->next = run_end->next;
    }
}

/* A template's items were registered as they parsed; they are not functions
 * of the program until an instance makes them concrete. */
static void forget_template_item(ParserContext *context, ASTNode *fn, const char *placeholder) {
    FunctionTable *functions = &context->symbols.functions;
    for (int i = 0; i < functions->count; i++) {
        if (functions->funcs[i] != fn) continue;
        memmove(&functions->funcs[i], &functions->funcs[i + 1],
                sizeof(ASTNode *) * (size_t)(functions->count - i - 1));
        functions->count--;
        break;
    }
    MethodTable *methods = &context->symbols.methods;
    for (int i = 0; i < methods->count; i++) {
        MethodDef *def = methods->methods[i];
        if (def->fundef != fn || strcmp(def->type_name, placeholder) != 0) continue;
        free(def->type_name);
        free(def->method_name);
        free(def->mangled);
        free(def);
        memmove(&methods->methods[i], &methods->methods[i + 1],
                sizeof(MethodDef *) * (size_t)(methods->count - i - 1));
        methods->count--;
        break;
    }
}

static int self_type_is_plain(ASTNode *type) {
    return type->type == AST_TYPE && type->type_node.base_type &&
           (type->type_node.base_type->type == AST_IDENTIFIER ||
            type->type_node.base_type->type == AST_TYPE_GENERIC) &&
           !type->type_node.pointer_level && type->type_node.ref_kind == REFKIND_NONE &&
           !type->type_node.type_modifiers;
}

ASTNode *parse_impl(ParserContext *context, Token **cur, int want_export) {
    Token *start = *cur;
    if (!expect(cur, IMPL)) parse_error(context, "expected 'impl'", *cur);
    int type_mark = typename_scope_mark(context);
    char **impl_params = NULL;
    ASTNode **impl_bounds = NULL;
    int impl_param_count = 0;
    if ((*cur)->kind == LT)
        impl_params = parse_type_params(context, cur, &impl_param_count, NULL, 1, &impl_bounds);
    if ((*cur)->kind != IDENTIFIER) parse_error(context, "expected trait name after 'impl'", *cur);
    Token *trait_tok = *cur;
    TraitDef *trait = find_trait(context, trait_tok->value);
    if (!trait) {
        char message[256];
        snprintf(message, sizeof(message), "unknown trait '%s'", trait_tok->value);
        parse_error(context, message, trait_tok);
    }
    *cur = (*cur)->next;

    ImplDef *impl = calloc(1, sizeof(ImplDef));
    impl->trait_name = strdup(trait->name);
    impl->is_exported = want_export;
    impl->line = start->line;
    impl->col = start->col;
    impl->type_params = impl_params;
    impl->type_param_bounds = impl_bounds;
    impl->type_param_count = impl_param_count;
    if ((*cur)->kind == LT)
        impl->trait_args = parse_type_args(context, cur, &impl->trait_arg_count);
    if (impl->trait_arg_count != trait->type_param_count) {
        char message[256];
        snprintf(message, sizeof(message), "trait %s takes %d type argument(s), but %d were given",
                 trait->name, trait->type_param_count, impl->trait_arg_count);
        parse_error(context, message, trait_tok);
    }

    if (!expect(cur, FOR)) parse_error(context, "expected 'for' after the trait in an impl", *cur);
    Token *self_tok = *cur;
    impl->self_type = parse_type(context, cur);
    Token *self_last = self_tok;
    while (self_last->next != *cur) self_last = self_last->next;
    if (!self_type_is_plain(impl->self_type))
        parse_error(context, "an impl's type must be a named type or a generic instance "
                             "(impls for pointers and references are not supported yet)", self_tok);
    ASTNode *self_base = impl->self_type->type_node.base_type;
    impl->is_template = self_base->type == AST_TYPE_GENERIC;
    impl->self_name = strdup(self_base->type == AST_TYPE_GENERIC ? self_base->generic_type.name
                                                                 : self_base->identifier.name);
    if (impl_param_count > 0 && !impl->is_template)
        parse_error(context, "an impl's type parameters must appear in its type", self_tok);
    /* Each parameter is bound by matching the type, so it must be one of
     * the type's arguments as written. */
    for (int p = 0; p < impl_param_count; p++) {
        int bound_by_type = 0;
        for (int a = 0; a < self_base->generic_type.arg_count && !bound_by_type; a++) {
            ASTNode *arg = self_base->generic_type.args[a];
            bound_by_type = arg && arg->type == AST_TYPE && arg->type_node.base_type &&
                            arg->type_node.base_type->type == AST_IDENTIFIER &&
                            !arg->type_node.pointer_level &&
                            strcmp(arg->type_node.base_type->identifier.name, impl_params[p]) == 0;
        }
        if (!bound_by_type)
            parse_error(context, "an impl's type parameter must be an argument of its type", self_tok);
    }

    orphan_check(context, trait, impl, start);
    ImplDef *existing = impl->is_template ? NULL
        : find_impl(context, impl->trait_name, impl->trait_args, impl->trait_arg_count, impl->self_type);
    if (existing) {
        char message[256], note[256];
        snprintf(message, sizeof(message), "conflicting impl %s for %s", impl->trait_name, impl->self_name);
        snprintf(note, sizeof(note), "an impl of the same trait and arguments is already visible (line %d)",
                 existing->line);
        trait_error_at(context, start->line, start->col, message, note);
    }

    validate_copy_impl(context, impl, start);
    if (strcmp(impl->trait_name, "Drop") == 0 &&
        find_impl_for_name(context, "Copy", impl->self_name))
        trait_error_at(context, start->line, start->col,
                       "a Copy type cannot implement Drop", NULL);

    /* A template's items are written against a placeholder type. */
    Token placeholder_tok = *self_tok;
    ASTNode *placeholder_type = NULL;
    if (impl->is_template) {
        char name[64];
        snprintf(name, sizeof(name), "__mlg_impl_self_%d", context->lowering.payload_case_counter++);
        impl->placeholder = strdup(name);
        add_typename(context, impl->placeholder);
        placeholder_tok.kind = IDENTIFIER;
        placeholder_tok.value = impl->placeholder;
        placeholder_tok.value_length = (int)strlen(impl->placeholder);
        placeholder_type = new_type_node(new_identifier(impl->placeholder), 0, TYPEMOD_NONE, REFKIND_NONE);
    }
    const char *item_self_name = impl->is_template ? impl->placeholder : impl->self_name;

    TypeSubst sub = impl_subst(trait, impl);
    if (placeholder_type) sub.types[0] = placeholder_type;
    ASTNode **fns = NULL;
    int fn_count = 0;

    if ((*cur)->kind == ASSIGN) {
        Token *assign = *cur;
        if (impl->is_template)
            parse_error(context, "'impl ... = value;' is not supported for generic types yet", assign);
        *cur = (*cur)->next;
        ASTNode *value = parse_expr(context, cur);
        if (!expect(cur, SEMICOLON)) parse_error(context, "expected ';' after impl value", *cur);
        fns = malloc(sizeof(ASTNode *));
        fns[fn_count++] = synthesize_short_impl(context, trait, &sub, value, assign);
        add_function(context, fns[0]);
    } else {
        if ((*cur)->kind != L_BRACE) parse_error(context, "expected '{' or '=' after the impl's type", *cur);
        if (impl->is_template) substitute_template_self(*cur, self_tok, self_last, impl->placeholder);
        else substitute_self_tokens(*cur, self_tok);
        *cur = (*cur)->next;
        while ((*cur)->kind != R_BRACE) {
            if ((*cur)->kind == EOT) parse_error(context, "unterminated impl", start);
            Token *item_tok = *cur;
            ASTNode *fn = looks_like_method(context, *cur) ? parse_method(context, cur)
                                                           : parse_fundef(context, cur);
            if (!fn || fn->type != AST_FUNDEF || fn->fundef.type_param_count > 0)
                parse_error(context, "impl items must be non-generic methods or functions", item_tok);
            if (!fn->fundef.body) parse_error(context, "an impl item needs a body", item_tok);
            if (fn->fundef.recv_type_name && strcmp(fn->fundef.recv_type_name, item_self_name) != 0)
                parse_error(context, "an impl method's receiver must be the impl's own type", item_tok);
            fns = realloc(fns, sizeof(ASTNode *) * (size_t)(fn_count + 1));
            fns[fn_count++] = fn;
        }
        *cur = (*cur)->next;
        if ((*cur)->kind == SEMICOLON) *cur = (*cur)->next;
    }

    /* Items left out take the trait's default, when it has one. */
    if (trait->defaults) {
        for (int i = 0; i < trait->item_count; i++) {
            if (!trait->defaults[i]) continue;
            const char *item_name = trait->items[i]->fundef.name;
            int written = 0;
            for (int f = 0; f < fn_count && !written; f++) {
                const char *name = fns[f]->fundef.recv_type_name
                    ? fns[f]->fundef.name + strlen(fns[f]->fundef.recv_type_name) + 2 : fns[f]->fundef.name;
                written = strcmp(name, item_name) == 0;
            }
            if (written) continue;
            fns = realloc(fns, sizeof(ASTNode *) * (size_t)(fn_count + 1));
            fns[fn_count++] = parse_default_item(context, trait, impl, i, &placeholder_tok, start);
        }
    }

    /* Each trait item exactly once, nothing else. */
    impl->item_count = trait->item_count;
    impl->item_names = calloc((size_t)trait->item_count, sizeof(char *));
    impl->item_mangled = calloc((size_t)trait->item_count, sizeof(char *));
    if (impl->is_template) impl->template_items = calloc((size_t)trait->item_count, sizeof(ASTNode *));
    for (int f = 0; f < fn_count; f++) {
        ASTNode *fn = fns[f];
        const char *written = fn->fundef.recv_type_name
            ? fn->fundef.name + strlen(fn->fundef.recv_type_name) + 2 : fn->fundef.name;
        int found = -1;
        for (int i = 0; i < trait->item_count; i++)
            if (strcmp(trait->items[i]->fundef.name, written) == 0) found = i;
        if (found < 0) {
            char message[256];
            snprintf(message, sizeof(message), "'%s' is not an item of trait %s", written, trait->name);
            trait_error_at(context, fn->line, fn->col, message, NULL);
        }
        if (impl->item_names[found])
            trait_error_at(context, fn->line, fn->col, "trait item implemented more than once", NULL);
        check_item_signature(context, trait, &sub, trait->items[found], fn);
        impl->item_names[found] = strdup(written);
        if (impl->is_template) {
            forget_template_item(context, fn, impl->placeholder);
            impl->template_items[found] = fn;
            continue;
        }
        if (fn->fundef.recv_type_name) {
            impl->item_mangled[found] = strdup(fn->fundef.name);
        } else {
            impl->item_mangled[found] = assoc_function_label(trait, impl, written);
            free(fn->fundef.name);
            fn->fundef.name = strdup(impl->item_mangled[found]);
        }
        if (want_export) {
            fn->fundef.is_exported = 1;
            free(fn->fundef.package);
            fn->fundef.package = strdup(context->module.current_package);
        }
    }
    for (int i = 0; i < trait->item_count; i++) {
        if (impl->item_names[i]) continue;
        char message[256];
        snprintf(message, sizeof(message), "impl %s for %s is missing '%s'", trait->name,
                 impl->self_name, trait->items[i]->fundef.name);
        trait_error_at(context, start->line, start->col, message, NULL);
    }
    free(sub.names);
    free(sub.types);
    free_ast(placeholder_type);
    restore_typenames(context, type_mark);

    add_impl(context, impl);
    if (impl->is_template) {
        free(fns);
        fns = NULL;
        fn_count = 0;
    }
    ASTNode *group = new_block(fns, fn_count);
    group->line = start->line;
    group->col = start->col;
    return group;
}

/* ---- bounds ------------------------------------------------------------ */

/* Equality for these scalar types is a language primitive, not an `impl`,
 * so a generic `T: Eq` must accept them without manufacturing an impl that
 * would make `==` recursively lower inside its own implementation. */
static int has_builtin_eq(ASTNode *self_type) {
    if (!self_type || self_type->type != AST_TYPE) return 0;
    if (self_type->type_node.pointer_level) return 1;
    ASTNode *base = self_type->type_node.base_type;
    if (!base || base->type != AST_IDENTIFIER) return 0;
    const char *name = base->identifier.name;
    return strcmp(name, "i32") == 0 || strcmp(name, "u32") == 0 ||
           strcmp(name, "u16") == 0 || strcmp(name, "u8") == 0 ||
           strcmp(name, "char") == 0 || strcmp(name, "bool") == 0 ||
           strcmp(name, "str") == 0;
}

static const char *bound_trait_name(ASTNode *bound) {
    ASTNode *base = bound->type_node.base_type;
    return base->type == AST_TYPE_GENERIC ? base->generic_type.name : base->identifier.name;
}

int bound_holds(ParserContext *context, ASTNode *self_type, ASTNode *bound) {
    ASTNode *base = bound->type_node.base_type;
    const char *trait_name = bound_trait_name(bound);
    ASTNode **args = base->type == AST_TYPE_GENERIC ? base->generic_type.args : NULL;
    int arg_count = base->type == AST_TYPE_GENERIC ? base->generic_type.arg_count : 0;
    if (find_impl(context, trait_name, args, arg_count, self_type)) return 1;
    return arg_count == 0 && strcmp(trait_name, "Eq") == 0 && has_builtin_eq(self_type);
}

void require_bound(ParserContext *context, ASTNode *use, const char *template_name,
                   ASTNode *self_type, ASTNode *bound) {
    const char *trait_name = bound_trait_name(bound);
    TraitDef *trait = find_trait(context, trait_name);
    if (!trait) {
        char message[256];
        snprintf(message, sizeof(message), "unknown trait '%s' in a bound of '%s'", trait_name,
                 template_name);
        trait_error_at(context, bound->line, bound->col, message, NULL);
    }
    if (bound_holds(context, self_type, bound)) return;
    char *self_key = trait_type_display(self_type);
    char *bound_key = trait_type_display(bound);
    char message[512], note[512];
    snprintf(message, sizeof(message), "%s does not implement %s (required by '%s')", self_key,
             bound_key, template_name);
    snprintf(note, sizeof(note), "add `impl %s for %s`", bound_key, self_key);
    free(self_key);
    free(bound_key);
    trait_error_at(context, use ? use->line : 0, use ? use->col : 0, message, note);
}

/* ---- modules ----------------------------------------------------------- */

static int import_requests(const ASTNode *node, const char *name) {
    for (int i = 0; i < node->import_stmt.symbol_count; i++)
        if (node->import_stmt.symbols[i] && strcmp(node->import_stmt.symbols[i], name) == 0) return 1;
    return 0;
}

static void drop_import_symbol(ASTNode *node, const char *name) {
    for (int i = 0; i < node->import_stmt.symbol_count; i++) {
        if (!node->import_stmt.symbols[i] || strcmp(node->import_stmt.symbols[i], name) != 0) continue;
        free(node->import_stmt.symbols[i]);
        for (int j = i + 1; j < node->import_stmt.symbol_count; j++)
            node->import_stmt.symbols[j - 1] = node->import_stmt.symbols[j];
        /* A trait is not a linker symbol. An import that listed only traits
         * is left with no names, which codegen reads as a package import of
         * the module's exported functions -- none, for a trait module. */
        node->import_stmt.symbol_count--;
        return;
    }
}

static ASTNode *find_module_fundef(Module *module, const char *name) {
    if (!module->program || module->program->type != AST_BLOCK) return NULL;
    for (int i = 0; i < module->program->block.count; i++) {
        ASTNode *node = module->program->block.stmts[i];
        if (node && node->type == AST_FUNDEF && node->fundef.name && strcmp(node->fundef.name, name) == 0)
            return node;
    }
    return NULL;
}

static void import_signature_type(ParserContext *context, Module *module, ASTNode *type) {
    const char *name = type_base_name(type);
    if (name) import_type_dependency(context, module, name);
}

/* The importer calls an imported impl's items by label; a prototype in its own
 * program gives codegen their signatures (aggregate returns included) and
 * makes the labels linker imports. The types those signatures name come
 * along, as an imported type's field types do. */
static void import_impl_items(ParserContext *context, Module *module, ImplDef *impl) {
    for (int i = 0; i < impl->item_count; i++) {
        ASTNode *fn = find_module_fundef(module, impl->item_mangled[i]);
        if (!fn) continue;
        if (fn->fundef.recv_type_name && find_method(context, impl->self_name, impl->item_names[i]))
            continue;
        if (!fn->fundef.recv_type_name && find_function(context, impl->item_mangled[i])) continue;
        import_signature_type(context, module, fn->fundef.ret_type);
        ASTNode **params = fn->fundef.param_count
            ? malloc(sizeof(ASTNode *) * (size_t)fn->fundef.param_count) : NULL;
        for (int p = 0; p < fn->fundef.param_count; p++) {
            import_signature_type(context, module, fn->fundef.params[p]->param.type);
            params[p] = ast_clone(fn->fundef.params[p]);
        }
        ASTNode *proto = new_fundef(ast_clone(fn->fundef.ret_type), fn->fundef.name, params,
                                    fn->fundef.param_count, NULL, fn->fundef.is_variadic);
        if (fn->fundef.recv_type_name) proto->fundef.recv_type_name = strdup(fn->fundef.recv_type_name);
        add_function(context, proto);
        if (fn->fundef.recv_type_name)
            add_method(context, impl->self_name, impl->item_names[i], proto->fundef.name, proto);
        add_imported_plain_type(context, proto);
    }
}

static int type_is_visible(ParserContext *context, const char *name) {
    return name && (mylang_type_is_builtin(name) || is_user_typename(context, name));
}

void resolve_imported_impls(ParserContext *context) {
    ParserSymbolState *symbols = &context->symbols;
    for (int i = 0; i < symbols->pending_impl_count; i++) {
        ImplDef *impl = symbols->pending_impls[i];
        /* A template applies only to instances, which may arrive as the
         * field type of an imported struct without the generic type itself
         * being named here; it is kept either way. */
        if (!impl->is_template && !type_is_visible(context, impl->self_name)) continue;
        if (impl->is_template) {
            /* Instantiated here, per instance; nothing to import but the
             * template, once. */
            int seen = 0;
            for (int k = 0; k < symbols->impls.count && !seen; k++) {
                ImplDef *other = symbols->impls.impls[k];
                seen = other->is_template && strcmp(other->placeholder, impl->placeholder) == 0 &&
                       strcmp(other->trait_name, impl->trait_name) == 0 &&
                       strcmp(other->self_name, impl->self_name) == 0;
            }
            if (!seen) {
                ImplDef *copy = impl_def_clone(impl);
                copy->is_exported = 0;
                add_impl(context, copy);
            }
            continue;
        }
        if (find_impl(context, impl->trait_name, impl->trait_args, impl->trait_arg_count, impl->self_type))
            continue;
        ImplDef *copy = impl_def_clone(impl);
        copy->is_exported = 0; /* travels only from its declaring module */
        add_impl(context, copy);
        import_impl_items(context, symbols->pending_impl_modules[i], impl);
    }
    free(symbols->pending_impl_modules);
    free(symbols->pending_impls);
    symbols->pending_impl_modules = NULL;
    symbols->pending_impls = NULL;
    symbols->pending_impl_count = 0;
}

void load_imported_traits(ParserContext *context, ASTNode *import_node,
                          const char *source_path, Module *module) {
    if (!import_node || !module) return;
    int foreign = source_path && source_path[0] == '@';
    if (foreign) {
        for (int i = 0; i < import_node->import_stmt.symbol_count; i++)
            mark_foreign_name(context, import_node->import_stmt.symbols[i]);
    }
    for (int i = 0; i < module->trait_count; i++) {
        TraitDef *trait = module->traits[i];
        if (!trait->is_exported || !import_requests(import_node, trait->name)) continue;
        drop_import_symbol(import_node, trait->name);
        if (find_trait(context, trait->name)) continue;
        TraitDef *copy = trait_def_clone(trait);
        copy->is_exported = 0; /* an importer does not re-export it */
        add_trait(context, copy);
    }
    /* An exported impl is visible to an importer of the module declaring it,
     * whichever names that import lists, once its type is visible there too.
     * The type may arrive through a later import, so this waits for the end
     * of parsing (resolve_imported_impls). */
    ParserSymbolState *symbols = &context->symbols;
    for (int i = 0; i < module->impl_count; i++) {
        symbols->pending_impl_modules = realloc(symbols->pending_impl_modules,
            sizeof(Module *) * (size_t)(symbols->pending_impl_count + 1));
        symbols->pending_impls = realloc(symbols->pending_impls,
            sizeof(ImplDef *) * (size_t)(symbols->pending_impl_count + 1));
        symbols->pending_impl_modules[symbols->pending_impl_count] = module;
        symbols->pending_impls[symbols->pending_impl_count++] = module->impls[i];
    }
}

void transfer_traits_to_module(ParserContext *context, Module *module) {
    module->traits = context->symbols.traits.traits;
    module->trait_count = context->symbols.traits.count;
    context->symbols.traits.traits = NULL;
    context->symbols.traits.count = 0;

    /* Only this module's own exported impls travel; the ones it imported
     * reach an importer through their declaring module. */
    for (int i = 0; i < context->symbols.impls.count; i++) {
        ImplDef *impl = context->symbols.impls.impls[i];
        if (!impl->is_exported) continue;
        module->impls = realloc(module->impls, sizeof(ImplDef *) * (size_t)(module->impl_count + 1));
        module->impls[module->impl_count++] = impl_def_clone(impl);
    }
}
