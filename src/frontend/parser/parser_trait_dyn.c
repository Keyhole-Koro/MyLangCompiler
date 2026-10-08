#include "mylang/frontend/parser_trait_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/support/stringBuilder.h"

/* `dyn Trait<Args>` -- dynamic dispatch (docs/traits.md).
 *
 * A trait object is an ordinary struct, declared here per spelling:
 *
 *     struct __dyn_5_Shape {
 *         u8 *data;                         // the object
 *         fn(u8 *) -> i32 __m_area;         // one entry per method
 *     };
 *     i32 (__dyn_5_Shape *self) area() {    // dispatch method
 *         fn(u8 *) -> i32 __f = self->__m_area;
 *         return __f(self->data);
 *     }
 *
 * so `s.area()` is a normal method call. Where a dyn value is expected and
 * a `Square *` is given, lowering calls a generated conversion that fills
 * the struct from Square's impl (coerce_to_dyn). Semantic analysis and
 * codegen see only structs, function pointers, and calls. */

static void dyn_error(ParserContext *context, int line, int col, const char *message, const char *note) {
    fprintf(stderr, "%s:%d:%d: error: %s\n",
            context->module.filename ? context->module.filename : "<input>", line, col, message);
    if (note) fprintf(stderr, "  note: %s\n", note);
    exit(1);
}

static void free_tokens_owned(Token *tok) {
    while (tok) {
        Token *next = tok->next;
        free(tok->value);
        free(tok);
        tok = next;
    }
}

void dyn_use_free(DynUse *use) {
    free(use->placeholder);
    free(use->trait_name);
    free_tokens_owned(use->trait_args);
    for (int i = 0; i < use->arg_count; i++) free_ast(use->args[i]);
    free(use->args);
}

static Token *copy_token(const Token *src) {
    Token *tok = calloc(1, sizeof(Token));
    tok->kind = src->kind;
    tok->value = src->value ? strdup(src->value) : NULL;
    tok->value_length = src->value_length;
    tok->line = src->line;
    tok->col = src->col;
    tok->length = src->length;
    return tok;
}

/* ---- tokens -------------------------------------------------------------- */

/* The `>` closing the `<` at `open`, splitting a `>>` that closes it and an
 * enclosing list (`Box<dyn Iterator<i32>>`). NULL when unbalanced. */
static Token *close_angle(Token *open) {
    int depth = 0;
    for (Token *t = open; t && t->kind != EOT; t = t->next) {
        if (t->kind == LT) depth++;
        else if (t->kind == GT) {
            if (--depth == 0) return t;
        } else if (t->kind == RSH) {
            if (depth == 1) {
                Token *second = copy_token(t);
                second->kind = GT;
                free(second->value);
                second->value = strdup(">");
                second->value_length = 1;
                second->col = t->col + 1;
                second->next = t->next;
                t->kind = GT;
                free(t->value);
                t->value = strdup(">");
                t->value_length = 1;
                t->next = second;
                return t;
            }
            depth -= 2;
            if (depth == 0) return t;
        }
    }
    return NULL;
}

static DynUse *find_dyn_use(ParserContext *context, const char *placeholder) {
    for (int i = 0; i < context->symbols.dyn_use_count; i++)
        if (strcmp(context->symbols.dyn_uses[i].placeholder, placeholder) == 0)
            return &context->symbols.dyn_uses[i];
    return NULL;
}

void rewrite_dyn_types(ParserContext *context, Token *head) {
    for (Token *t = head; t && t->kind != EOT; t = t->next) {
        if (t->kind != IDENTIFIER || !t->value || strcmp(t->value, "dyn") != 0) continue;
        Token *name = t->next;
        if (!name || name->kind != IDENTIFIER) continue;
        Token *last = name;
        if (name->next && name->next->kind == LT) {
            last = close_angle(name->next);
            if (!last) dyn_error(context, t->line, t->col, "unterminated type arguments after 'dyn'", NULL);
        }

        /* One placeholder per spelling; the same spelling in another module
         * names the same (identically laid out) struct. */
        StringBuilder spelling;
        sb_init(&spelling);
        for (Token *s = name;; s = s->next) {
            sb_append(&spelling, "%s", s->value ? s->value : "");
            if (s == last) break;
        }
        for (char *p = spelling.buf; *p; p++) {
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')))
                *p = '_';
        }
        char placeholder[300];
        snprintf(placeholder, sizeof(placeholder), "__dyn_%zu_%s", strlen(spelling.buf), spelling.buf);
        sb_free(&spelling);

        if (!find_dyn_use(context, placeholder)) {
            ParserSymbolState *symbols = &context->symbols;
            symbols->dyn_uses = realloc(symbols->dyn_uses,
                                        sizeof(DynUse) * (size_t)(symbols->dyn_use_count + 1));
            DynUse *use = &symbols->dyn_uses[symbols->dyn_use_count++];
            memset(use, 0, sizeof(*use));
            use->placeholder = strdup(placeholder);
            use->trait_name = strdup(name->value);
            use->line = t->line;
            use->col = t->col;
            if (last != name) {
                Token head_copy = {0};
                Token *tail = &head_copy;
                for (Token *s = name->next;; s = s->next) {
                    tail->next = copy_token(s);
                    tail = tail->next;
                    if (s == last) break;
                }
                Token *eot = calloc(1, sizeof(Token));
                eot->kind = EOT;
                tail->next = eot;
                use->trait_args = head_copy.next;
            }
            add_typename(context, placeholder);
        }

        /* `dyn` becomes the placeholder; the trait reference is unlinked
         * (and kept: the parser may point into token values). */
        free(t->value);
        t->value = strdup(placeholder);
        t->value_length = (int)strlen(placeholder);
        t->next = last->next;
    }
}

DynUse *dyn_use_for_type(ParserContext *context, ASTNode *type) {
    if (!type || type->type != AST_TYPE || type->type_node.pointer_level ||
        !type->type_node.base_type || type->type_node.base_type->type != AST_IDENTIFIER)
        return NULL;
    const char *name = type->type_node.base_type->identifier.name;
    if (strncmp(name, "__dyn_", 6) != 0) return NULL;
    return find_dyn_use(context, name);
}

/* ---- the struct and its dispatch methods --------------------------------- */

static int mentions_self(ASTNode *node);

static void mentions_self_child(ASTNode **slot, void *found) {
    if (*(int *)found) return;
    if (mentions_self(*slot)) *(int *)found = 1;
}

static int mentions_self(ASTNode *node) {
    if (!node) return 0;
    if (node->type == AST_IDENTIFIER && node->identifier.name && strcmp(node->identifier.name, "Self") == 0)
        return 1;
    int found = 0;
    ast_visit_children(node, mentions_self_child, &found);
    return found;
}

static ASTNode *u8_pointer(void) {
    return new_type_node(new_identifier("u8"), 1, TYPEMOD_NONE, REFKIND_NONE);
}

/* The trait's item types with its parameters replaced by the dyn's
 * arguments: `Option<T>` reads `Option<i32>` for `dyn Iterator<i32>`. */
typedef struct {
    char **names;
    ASTNode **types;
    int count;
} ParamSubst;

static void subst_params(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    ParamSubst *sub = user_data;
    if (!node) return;
    if (node->type == AST_TYPE && node->type_node.base_type &&
        node->type_node.base_type->type == AST_IDENTIFIER) {
        for (int i = 0; i < sub->count; i++) {
            if (strcmp(node->type_node.base_type->identifier.name, sub->names[i]) != 0) continue;
            ASTNode *replacement = ast_clone(sub->types[i]);
            if (replacement->type == AST_TYPE) {
                replacement->type_node.pointer_level += node->type_node.pointer_level;
                replacement->type_node.type_modifiers |= node->type_node.type_modifiers;
            }
            free_ast(node);
            *slot = replacement;
            return;
        }
    }
    ast_visit_children(node, subst_params, user_data);
}

static ASTNode *item_type(DynUse *use, TraitDef *trait, ASTNode *type) {
    ASTNode *out = ast_clone(type);
    ParamSubst sub = {trait->type_params, use->args, trait->type_param_count};
    subst_params(&out, &sub);
    return out;
}

/* `fn(u8 *, P...) -> R`: an entry of the object's table. */
static ASTNode *entry_type(DynUse *use, TraitDef *trait, ASTNode *item) {
    int count = item->fundef.param_count;
    ASTNode **params = malloc(sizeof(ASTNode *) * (size_t)count);
    params[0] = u8_pointer();
    for (int p = 1; p < count; p++) params[p] = item_type(use, trait, item->fundef.params[p]->param.type);
    return new_function_type(params, count, item_type(use, trait, item->fundef.ret_type), false);
}

static char *entry_name(const char *item_name) {
    size_t len = strlen(item_name) + 8;
    char *name = malloc(len);
    snprintf(name, len, "__m_%s", item_name);
    return name;
}

/* Only methods taking `Self *self` and not otherwise naming Self can be
 * called without knowing the type. */
static void require_object_safe(ParserContext *context, DynUse *use, TraitDef *trait) {
    for (int i = 0; i < trait->item_count; i++) {
        ASTNode *item = trait->items[i];
        char message[512];
        if (!item->fundef.recv_type_name) {
            snprintf(message, sizeof(message), "trait %s cannot be used as dyn: '%s' has no receiver",
                     trait->name, item->fundef.name);
            dyn_error(context, use->line, use->col, message,
                      "a dyn value can only call methods; call an associated function on a concrete type");
        }
        ASTNode *recv = item->fundef.params[0]->param.type;
        if (recv->type != AST_TYPE || recv->type_node.pointer_level != 1 ||
            recv->type_node.ref_kind != REFKIND_NONE) {
            snprintf(message, sizeof(message),
                     "trait %s cannot be used as dyn: '%s' must take its receiver as 'Self *self'",
                     trait->name, item->fundef.name);
            dyn_error(context, use->line, use->col, message, NULL);
        }
        int names_self = mentions_self(item->fundef.ret_type);
        for (int p = 1; p < item->fundef.param_count && !names_self; p++)
            names_self = mentions_self(item->fundef.params[p]->param.type);
        if (names_self) {
            snprintf(message, sizeof(message),
                     "trait %s cannot be used as dyn: '%s' names Self outside its receiver",
                     trait->name, item->fundef.name);
            dyn_error(context, use->line, use->col, message, NULL);
        }
    }
}

static int program_declares(ParserContext *context, ASTNode *program, const char *name) {
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (node && node->type == AST_STRUCT && strcmp(node->struct_stmt.name, name) == 0) return 1;
    }
    for (int i = 0; i < imported_plain_type_count(context); i++) {
        ASTNode *node = imported_plain_type_at(context, i);
        if (node && node->type == AST_STRUCT && strcmp(node->struct_stmt.name, name) == 0) return 1;
    }
    return 0;
}

static ASTNode *dispatch_method(DynUse *use, TraitDef *trait, ASTNode *item) {
    const char *name = item->fundef.name;
    int count = item->fundef.param_count;
    ASTNode **params = malloc(sizeof(ASTNode *) * (size_t)count);
    params[0] = new_param(new_type_node(new_identifier(use->placeholder), 1, TYPEMOD_NONE, REFKIND_NONE),
                          "self");
    ASTNode **call_args = malloc(sizeof(ASTNode *) * (size_t)count);
    call_args[0] = new_arrow_access(new_identifier("self"), "data");
    for (int p = 1; p < count; p++) {
        char arg_name[32];
        snprintf(arg_name, sizeof(arg_name), "__a%d", p);
        params[p] = new_param(item_type(use, trait, item->fundef.params[p]->param.type), arg_name);
        call_args[p] = new_identifier(arg_name);
    }
    char *field = entry_name(name);
    ASTNode **stmts = malloc(sizeof(ASTNode *) * 2);
    stmts[0] = new_var_decl(entry_type(use, trait, item), "__f",
                            new_arrow_access(new_identifier("self"), field));
    free(field);
    ASTNode *call = new_call("__f", call_args, count);
    ASTNode *ret_type = item_type(use, trait, item->fundef.ret_type);
    int returns_void = ret_type->type == AST_TYPE && ret_type->type_node.base_type &&
                       ret_type->type_node.base_type->type == AST_IDENTIFIER &&
                       strcmp(ret_type->type_node.base_type->identifier.name, "void") == 0 &&
                       !ret_type->type_node.pointer_level;
    stmts[1] = returns_void ? new_expr_stmt(call) : new_return(call);

    char mangled[512];
    snprintf(mangled, sizeof(mangled), "%s__%s", use->placeholder, name);
    ASTNode *fn = new_fundef(ret_type, mangled, params, count, new_block(stmts, 2), item->fundef.is_variadic);
    fn->fundef.recv_type_name = strdup(use->placeholder);
    fn->line = use->line;
    fn->col = use->col;
    return fn;
}

void synthesize_dyn_types(ParserContext *context, ASTNode *program) {
    for (int u = 0; u < context->symbols.dyn_use_count; u++) {
        DynUse *use = &context->symbols.dyn_uses[u];
        TraitDef *trait = find_trait(context, use->trait_name);
        if (!trait) {
            char message[256];
            snprintf(message, sizeof(message), "unknown trait '%s' after 'dyn'", use->trait_name);
            dyn_error(context, use->line, use->col, message, NULL);
        }
        if (use->trait_args) {
            Token *cur = use->trait_args;
            use->args = parse_type_args(context, &cur, &use->arg_count);
        }
        if (use->arg_count != trait->type_param_count) {
            char message[256];
            snprintf(message, sizeof(message), "dyn %s takes %d type argument(s), but %d were given",
                     trait->name, trait->type_param_count, use->arg_count);
            dyn_error(context, use->line, use->col, message, NULL);
        }
        require_object_safe(context, use, trait);

        if (!program_declares(context, program, use->placeholder)) {
            int count = trait->item_count + 1;
            ASTNode **members = malloc(sizeof(ASTNode *) * (size_t)count);
            members[0] = new_var_decl(u8_pointer(), "data", NULL);
            for (int i = 0; i < trait->item_count; i++) {
                char *field = entry_name(trait->items[i]->fundef.name);
                members[i + 1] = new_var_decl(entry_type(use, trait, trait->items[i]), field, NULL);
                free(field);
            }
            ASTNode *decl = new_struct(use->placeholder, members, count);
            /* Exported so a module importing a signature that names it gets
             * the declaration along with it. */
            decl->struct_stmt.is_exported = 1;
            decl->struct_stmt.package = context->module.current_package
                ? strdup(context->module.current_package) : NULL;
            decl->line = use->line;
            decl->col = use->col;
            program->block.stmts = realloc(program->block.stmts,
                                           sizeof(ASTNode *) * (size_t)(program->block.count + 1));
            memmove(program->block.stmts + 1, program->block.stmts,
                    sizeof(ASTNode *) * (size_t)program->block.count);
            program->block.stmts[0] = decl;
            program->block.count++;
        }

        /* A dyn value is two kinds of pointer: copying it shares the object,
         * as copying a `T *` does. */
        if (!find_impl_for_name(context, "Copy", use->placeholder)) {
            ImplDef *copy = calloc(1, sizeof(ImplDef));
            copy->trait_name = strdup("Copy");
            copy->self_type = new_type_node(new_identifier(use->placeholder), 0, TYPEMOD_NONE, REFKIND_NONE);
            copy->self_name = strdup(use->placeholder);
            copy->line = use->line;
            copy->col = use->col;
            add_impl_instance(context, copy);
        }

        for (int i = 0; i < trait->item_count; i++) {
            if (find_method(context, use->placeholder, trait->items[i]->fundef.name)) continue;
            ASTNode *fn = dispatch_method(use, trait, trait->items[i]);
            program->block.stmts = realloc(program->block.stmts,
                                           sizeof(ASTNode *) * (size_t)(program->block.count + 1));
            program->block.stmts[program->block.count++] = fn;
            add_function(context, fn);
            add_method(context, use->placeholder, trait->items[i]->fundef.name, fn->fundef.name, fn);
        }
    }
}

/* ---- conversions ----------------------------------------------------------- */

static const char *pointee_name(ASTNode *type) {
    if (!type || type->type != AST_TYPE || type->type_node.pointer_level != 1 ||
        type->type_node.ref_kind != REFKIND_NONE || !type->type_node.base_type ||
        type->type_node.base_type->type != AST_IDENTIFIER)
        return NULL;
    return type->type_node.base_type->identifier.name;
}

/* The struct's declared type of an entry: already concrete when this runs
 * (after instantiation), unlike the trait's item types. */
static ASTNode *declared_entry_type(ParserContext *context, ASTNode *program, DynUse *use,
                                    const char *field) {
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->type != AST_STRUCT || strcmp(node->struct_stmt.name, use->placeholder) != 0)
            continue;
        for (int m = 0; m < node->struct_stmt.member_count; m++) {
            ASTNode *member = node->struct_stmt.members[m];
            if (member && member->type == AST_VAR_DECL && strcmp(member->var_decl.name, field) == 0)
                return ast_clone(member->var_decl.var_type);
        }
    }
    dyn_error(context, use->line, use->col, "internal error: dyn struct entry not found", field);
    return NULL;
}

/* `__dyn_5_Shape __dyn_5_Shape__from_Square(Square *__obj)`: the object's
 * address and Square's impl of each method. */
static char *conversion(ParserContext *context, ASTNode *program, DynUse *use, TraitDef *trait,
                        ImplDef *impl, const char *type_name) {
    size_t len = strlen(use->placeholder) + strlen(type_name) + 8;
    char *label = malloc(len);
    snprintf(label, len, "%s__from_%s", use->placeholder, type_name);
    if (find_function(context, label)) return label;

    int count = trait->item_count + 1;
    char **fields = malloc(sizeof(char *) * (size_t)count);
    ASTNode **values = malloc(sizeof(ASTNode *) * (size_t)count);
    fields[0] = strdup("data");
    values[0] = new_cast(u8_pointer(), new_identifier("__obj"));
    for (int i = 0; i < trait->item_count; i++) {
        ASTNode *item = trait->items[i];
        fields[i + 1] = entry_name(item->fundef.name);
        values[i + 1] = new_cast(declared_entry_type(context, program, use, fields[i + 1]),
                                 new_identifier((char *)impl_item_mangled(impl, item->fundef.name)));
    }
    ASTNode **stmts = malloc(sizeof(ASTNode *));
    stmts[0] = new_return(new_struct_init_list(use->placeholder, fields, values, count));
    ASTNode **params = malloc(sizeof(ASTNode *));
    params[0] = new_param(new_type_node(new_identifier((char *)type_name), 1, TYPEMOD_NONE, REFKIND_NONE),
                          "__obj");
    ASTNode *fn = new_fundef(new_type_node(new_identifier(use->placeholder), 0, TYPEMOD_NONE, REFKIND_NONE),
                             label, params, 1, new_block(stmts, 1), false);
    program->block.stmts = realloc(program->block.stmts,
                                   sizeof(ASTNode *) * (size_t)(program->block.count + 1));
    program->block.stmts[program->block.count++] = fn;
    add_function(context, fn);
    return label;
}

void coerce_to_dyn(ParserContext *context, ASTNode *program, ASTNode **slot, ASTNode *source,
                   ASTNode *target) {
    DynUse *use = dyn_use_for_type(context, target);
    if (!use || !*slot) return;
    const char *type_name = pointee_name(source);
    if (!type_name || strncmp(type_name, "__dyn_", 6) == 0) return;
    TraitDef *trait = find_trait(context, use->trait_name);
    ASTNode *self_type = new_type_node(new_identifier((char *)type_name), 0, TYPEMOD_NONE, REFKIND_NONE);
    ImplDef *impl = find_impl(context, use->trait_name, use->args, use->arg_count, self_type);
    if (!impl) {
        char *self_display = trait_type_display(self_type);
        char message[512], note[512];
        snprintf(message, sizeof(message), "%s does not implement %s, so a %s * cannot be a dyn %s",
                 self_display, use->trait_name, self_display, use->trait_name);
        snprintf(note, sizeof(note), "add `impl %s for %s`", use->trait_name, self_display);
        free(self_display);
        dyn_error(context, (*slot)->line, (*slot)->col, message, note);
    }
    free_ast(self_type);
    char *label = conversion(context, program, use, trait, impl, type_name);
    ASTNode **args = malloc(sizeof(ASTNode *));
    args[0] = *slot;
    ASTNode *call = new_call(label, args, 1);
    call->line = args[0]->line;
    call->col = args[0]->col;
    free(label);
    *slot = call;
}
