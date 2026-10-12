#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/support/stringBuilder.h"
#include "mylang/frontend/parser_trait_internal.h"
#include "mylang/frontend/parser_annot_internal.h"

/* Templates remain parser-owned. Each concrete declaration is an independent
 * AST owned by the program, so the existing semantic and backend passes see
 * only ordinary types and calls. All caches live for one translation unit. */
typedef struct {
    char *name;
    ASTNode *declaration;
} Instance;

typedef struct {
    ParserContext *parser_context;
    ASTNode *program;
    Instance *instances;
    int count;
    int depth;
    ASTNode **imported;   /* is_imported_instance structs already in program */
    int imported_count;
    char **impls_done;    /* instances whose impl templates were applied */
    int impls_done_count;
    /* Method names any code in the unit may call (collect_called_methods);
     * a generic type's receiver methods are made concrete only for these. */
    char **called_methods;
    int called_method_count;
} Instantiation;

typedef struct {
    ParserContext *parser_context;
    char **params;
    ASTNode **args;
    int count;
} Substitution;

static void concrete_node(ASTNode **slot, void *user_data);
static const char *instantiate(Instantiation *ctx, ASTNode *use, const char *name,
                               ASTNode **args, int count, int is_function);
static void check_bounds(Instantiation *ctx, ASTNode *use, const char *name,
                         char **type_params, ASTNode **bounds, ASTNode **args, int count);

static void append_instance(Instantiation *ctx, char *name, ASTNode *declaration) {
    ctx->instances = realloc(ctx->instances, sizeof(Instance) * (ctx->count + 1));
    ctx->instances[ctx->count++] = (Instance){name, declaration};
}

static void generic_error(ParserContext *context, ASTNode *node, const char *message) {
    Token location = {0};
    location.line = node ? node->line : 0;
    location.col = node ? node->col : 0;
    parse_error(context, message, &location);
}

static void substitute(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    Substitution *sub = user_data;
    if (!node) return;
    if (node->type == AST_TYPE_ARRAY && node->type_array.array_size_param) {
        for (int i = 0; i < sub->count; i++) {
            if (strcmp(node->type_array.array_size_param, sub->params[i]) != 0) continue;
            ASTNode *arg = sub->args[i];
            if (!arg || arg->type != AST_NUMBER)
                generic_error(sub->parser_context, node,
                              "array capacity generic argument must be an integer constant");
            long size = strtol(arg->number.value, NULL, 10);
            if (size <= 0 || size > 1048576)
                generic_error(sub->parser_context, arg,
                              "array capacity generic argument is outside 1..1048576");
            node->type_array.array_size = (int)size;
            free(node->type_array.array_size_param);
            node->type_array.array_size_param = NULL;
            break;
        }
    }
    if (node->type == AST_TYPE && node->type_node.base_type &&
        node->type_node.base_type->type == AST_IDENTIFIER) {
        for (int i = 0; i < sub->count; i++) {
            if (strcmp(node->type_node.base_type->identifier.name, sub->params[i]) != 0) continue;
            ASTNode *arg = ast_clone(sub->args[i]);
            if (arg->type == AST_NUMBER) {
                if (node->type_node.pointer_level ||
                    node->type_node.ref_kind != REFKIND_NONE ||
                    node->type_node.type_modifiers != TYPEMOD_NONE)
                    generic_error(sub->parser_context, node,
                                  "integer generic argument cannot be used as a wrapped type");
                free_ast(node);
                *slot = arg;
                return;
            }
            if (arg->type == AST_TYPE_FUNCTION) {
                if (node->type_node.pointer_level ||
                    node->type_node.ref_kind != REFKIND_NONE ||
                    node->type_node.type_modifiers != TYPEMOD_NONE)
                    generic_error(sub->parser_context, node,
                                  "function type argument cannot be wrapped in a modifier, reference, or pointer");
                arg->line = node->line; arg->col = node->col;
                arg->end_line = node->end_line; arg->end_col = node->end_col;
                free_ast(node);
                *slot = arg;
                return;
            }
            if (arg->type != AST_TYPE)
                generic_error(sub->parser_context, node, "unsupported generic type argument");
            if (arg->type_node.ref_kind != REFKIND_NONE &&
                (node->type_node.ref_kind != REFKIND_NONE || node->type_node.pointer_level))
                generic_error(sub->parser_context, node,
                              "cannot wrap a reference type argument in another reference or pointer");
            arg->type_node.pointer_level += node->type_node.pointer_level;
            arg->type_node.type_modifiers |= node->type_node.type_modifiers;
            if (node->type_node.ref_kind != REFKIND_NONE)
                arg->type_node.ref_kind = node->type_node.ref_kind;
            arg->line = node->line; arg->col = node->col;
            arg->end_line = node->end_line; arg->end_col = node->end_col;
            free_ast(node);
            *slot = arg;
            return; /* A substituted argument must not itself be substituted. */
        }
    }
    /* `T::from(v)` in a bounded template names an associated function of
     * whatever T becomes. */
    if (node->type == AST_CALL && node->call.name && !node->call.recv) {
        const char *separator = strstr(node->call.name, "::");
        for (int i = 0; separator && i < sub->count; i++) {
            size_t length = (size_t)(separator - node->call.name);
            if (strlen(sub->params[i]) != length || strncmp(node->call.name, sub->params[i], length) != 0)
                continue;
            ASTNode *arg = sub->args[i];
            if (!arg || arg->type != AST_TYPE || !arg->type_node.base_type ||
                arg->type_node.base_type->type != AST_IDENTIFIER || arg->type_node.pointer_level ||
                arg->type_node.ref_kind != REFKIND_NONE)
                generic_error(sub->parser_context, node,
                              "'T::name(...)' needs T to be a plain named type");
            StringBuilder name;
            sb_init(&name);
            sb_append(&name, "%s%s", arg->type_node.base_type->identifier.name, separator);
            free(node->call.name);
            node->call.name = strdup(name.buf);
            sb_free(&name);
            break;
        }
    }
    ast_visit_children(node, substitute, user_data);
}

/* Length-prefixed names and every qualifier keep the key unambiguous. Nested
 * generic arguments have already become concrete type names at this point. */
static void append_type_key(ParserContext *context, StringBuilder *key, ASTNode *arg) {
    if (arg && arg->type == AST_NUMBER) {
        sb_append(key, "_c%zu_%s", strlen(arg->number.value), arg->number.value);
        return;
    }
    if (arg && arg->type == AST_TYPE_FUNCTION) {
        sb_append(key, "_f%d_v%d", arg->function_type.param_count,
                  arg->function_type.is_variadic ? 1 : 0);
        for (int i = 0; i < arg->function_type.param_count; i++)
            append_type_key(context, key, arg->function_type.param_types[i]);
        sb_append(key, "_ret");
        append_type_key(context, key, arg->function_type.return_type);
        return;
    }
    if (!arg || arg->type != AST_TYPE || !arg->type_node.base_type ||
        arg->type_node.base_type->type != AST_IDENTIFIER)
        generic_error(context, arg, "generic argument did not resolve to a concrete type");
    const char *name = arg->type_node.base_type->identifier.name;
    sb_append(key, "_p%d_r%d_m%d_n%zu_%s", arg->type_node.pointer_level,
              arg->type_node.ref_kind, arg->type_node.type_modifiers, strlen(name), name);
}

static int method_is_called(Instantiation *ctx, const char *name) {
    for (int i = 0; i < ctx->called_method_count; i++)
        if (strcmp(ctx->called_methods[i], name) == 0) return 1;
    return 0;
}

static void note_called_method(Instantiation *ctx, const char *name) {
    if (!name || method_is_called(ctx, name)) return;
    ctx->called_methods = realloc(ctx->called_methods,
                                  sizeof(char *) * (size_t)(ctx->called_method_count + 1));
    ctx->called_methods[ctx->called_method_count++] = strdup(name);
}

static void collect_called_in(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    if (!node) return;
    if (node->type == AST_CALL && node->call.recv) note_called_method(user_data, node->call.name);
    ast_visit_children(node, collect_called_in, user_data);
}

/* Every `x.name(...)` in the unit, in templates as well as concrete code,
 * plus what later passes call without a written call: trait items (`==`
 * calls eq, for-in calls next) and drop. A name being called somewhere is
 * enough; this only keeps unused methods of every instance from being
 * emitted (Option<T> has several, and there are many Options). */
static void collect_called_methods(Instantiation *ctx, ASTNode *program) {
    ParserContext *context = ctx->parser_context;
    collect_called_in(&program, ctx);
    for (int i = 0; i < generic_template_count(context); i++) {
        ASTNode *tpl = generic_template_at(context, i);
        collect_called_in(&tpl, ctx);
    }
    for (int i = 0; i < generic_method_count(context); i++) {
        ASTNode *fn = generic_method_at(context, i)->fundef;
        collect_called_in(&fn, ctx);
    }
    for (int i = 0; i < impl_count(context); i++) {
        ImplDef *impl = impl_at(context, i);
        for (int k = 0; impl->template_items && k < impl->item_count; k++) {
            ASTNode *fn = impl->template_items[k];
            collect_called_in(&fn, ctx);
        }
    }
    for (int i = 0; i < context->symbols.traits.count; i++) {
        TraitDef *trait = context->symbols.traits.traits[i];
        for (int k = 0; k < trait->item_count; k++) note_called_method(ctx, trait->items[k]->fundef.name);
    }
    note_called_method(ctx, "drop");
}

static void instantiate_receiver_methods(Instantiation *ctx, const char *template_name,
                                         const char *concrete_type_name,
                                         ASTNode **args, int count) {
    ParserContext *context = ctx->parser_context;
    for (int i = 0; i < generic_method_count(context); i++) {
        GenericMethodDef *entry = generic_method_at(context, i);
        if (strcmp(entry->receiver_template_name, template_name) != 0) continue;
        if (entry->fundef->fundef.type_param_count != count)
            generic_error(context, entry->fundef,
                          "generic method receiver type argument count mismatch");

        /* Receiver-bound parameters are method parameters too.  Validate
         * their bounds when the receiver is specialized -- whether or not
         * the method is called -- before lowering its body. */
        check_bounds(ctx, entry->fundef, entry->method_name, entry->fundef->fundef.type_params,
                     entry->fundef->fundef.type_param_bounds, args, count);
        if (!method_is_called(ctx, entry->method_name)) continue;
        if (find_method(context, concrete_type_name, entry->method_name)) continue;

        ASTNode *method = ast_clone(entry->fundef);
        Substitution sub = {
            /* The receiver binds the method's own formal names.  They need
             * not spell the struct template's names the same way: a valid
             * `T (ref Box<U> self) get()` is just as generic as `Box<T>`. */
            context, entry->fundef->fundef.type_params, args, count,
        };
        substitute(&method, &sub);
        for (int p = 0; p < method->fundef.type_param_count; p++)
            free(method->fundef.type_params[p]);
        free(method->fundef.type_params);
        method->fundef.type_params = NULL;
        free(method->fundef.type_param_is_const);
        method->fundef.type_param_is_const = NULL;
        if (method->fundef.type_param_bounds) {
            for (int p = 0; p < count; p++) free_ast(method->fundef.type_param_bounds[p]);
            free(method->fundef.type_param_bounds);
            method->fundef.type_param_bounds = NULL;
        }
        method->fundef.type_param_count = 0;

        StringBuilder mangled;
        sb_init(&mangled);
        sb_append(&mangled, "%s__%s", concrete_type_name, entry->method_name);
        free(method->fundef.name);
        method->fundef.name = strdup(mangled.buf);
        free(method->fundef.recv_type_name);
        method->fundef.recv_type_name = strdup(concrete_type_name);

        /* Publish before walking the body.  This mirrors ordinary generic
         * functions and lets recursive uses share one concrete declaration. */
        append_instance(ctx, mangled.buf, method);
        concrete_node(&method, ctx);
        add_function(context, method);
        add_method(context, concrete_type_name, entry->method_name,
                   method->fundef.name, method);
    }
}

/* `<T: Eq + From<S>, S>`: substitute the template's own parameters into each
 * bound, make the bound's type arguments concrete, and require an impl. The
 * template is a generic function, method, struct, or enum. */
static void check_bounds(Instantiation *ctx, ASTNode *use, const char *name,
                         char **type_params, ASTNode **bounds, ASTNode **args, int count) {
    if (!bounds) return;
    Substitution sub = {ctx->parser_context, type_params, args, count};
    for (int i = 0; i < count; i++) {
        ASTNode *list = bounds[i];
        if (!list) continue;
        for (int b = 0; b < list->block.count; b++) {
            ASTNode *bound = ast_clone(list->block.stmts[b]);
            ASTNode *base = bound->type_node.base_type;
            if (base->type == AST_TYPE_GENERIC) {
                for (int a = 0; a < base->generic_type.arg_count; a++) {
                    substitute(&base->generic_type.args[a], &sub);
                    concrete_node(&base->generic_type.args[a], ctx);
                }
            }
            require_bound(ctx->parser_context, use, name, args[i], bound);
            free_ast(bound);
        }
    }
}

/* A struct literal written as `Self { ... }` in an impl template names the
 * placeholder type. */
typedef struct {
    const char *from;
    const char *to;
} LiteralRename;

static void rename_literal_type(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    LiteralRename *rename = user_data;
    if (!node) return;
    if (node->type == AST_INIT_LIST && node->init_list.struct_type_name &&
        strcmp(node->init_list.struct_type_name, rename->from) == 0) {
        free(node->init_list.struct_type_name);
        node->init_list.struct_type_name = strdup(rename->to);
    }
    ast_visit_children(node, rename_literal_type, user_data);
}

static ASTNode *named_type(const char *name) {
    return new_type_node(new_identifier((char *)name), 0, TYPEMOD_NONE, REFKIND_NONE);
}

/* Binds an impl template's parameters by matching its type's arguments
 * against an instance's. Returns 0 when the template does not cover the
 * instance (`impl Eq for Box<i32>` against Box<u8>). */
static int match_impl_template(Instantiation *ctx, ImplDef *impl, ASTNode **args, int count,
                               ASTNode **bound) {
    ASTNode *base = impl->self_type->type_node.base_type;
    if (base->generic_type.arg_count != count) return 0;
    for (int a = 0; a < count; a++) {
        ASTNode *pattern = base->generic_type.args[a];
        int param = -1;
        if (pattern && pattern->type == AST_TYPE && pattern->type_node.base_type &&
            pattern->type_node.base_type->type == AST_IDENTIFIER && !pattern->type_node.pointer_level &&
            pattern->type_node.ref_kind == REFKIND_NONE) {
            for (int p = 0; p < impl->type_param_count; p++)
                if (strcmp(pattern->type_node.base_type->identifier.name, impl->type_params[p]) == 0) param = p;
        }
        char *want = trait_type_key(args[a]);
        int same;
        if (param >= 0 && !bound[param]) {
            bound[param] = ast_clone(args[a]);
            same = 1;
        } else {
            ASTNode *expected = param >= 0 ? ast_clone(bound[param]) : ast_clone(pattern);
            concrete_node(&expected, ctx);
            char *got = trait_type_key(expected);
            same = strcmp(got, want) == 0;
            free(got);
            free_ast(expected);
        }
        free(want);
        if (!same) return 0;
    }
    return 1;
}

/* Every impl template for `template_name` that covers this instance and
 * whose bounds hold gets concrete items and an ImplDef. An instance whose
 * bounds fail simply has no impl, so a use that needs one reports it. */
static void instantiate_impl_templates(Instantiation *ctx, const char *template_name,
                                       const char *concrete_name, ASTNode **args, int count) {
    ParserContext *context = ctx->parser_context;
    for (int i = 0; i < ctx->impls_done_count; i++)
        if (strcmp(ctx->impls_done[i], concrete_name) == 0) return;
    ctx->impls_done = realloc(ctx->impls_done, sizeof(char *) * (size_t)(ctx->impls_done_count + 1));
    ctx->impls_done[ctx->impls_done_count++] = strdup(concrete_name);
    int templates = impl_count(context);
    for (int t = 0; t < templates; t++) {
        ImplDef *tpl = impl_at(context, t);
        if (!tpl->is_template || strcmp(tpl->self_name, template_name) != 0) continue;
        ASTNode **bound = calloc((size_t)tpl->type_param_count + 1, sizeof(ASTNode *));
        int ok = match_impl_template(ctx, tpl, args, count, bound);
        for (int p = 0; ok && p < tpl->type_param_count; p++) {
            if (!bound[p]) ok = 0;
        }
        Substitution params = {context, tpl->type_params, bound, tpl->type_param_count};
        for (int p = 0; ok && tpl->type_param_bounds && p < tpl->type_param_count; p++) {
            ASTNode *list = tpl->type_param_bounds[p];
            for (int b = 0; ok && list && b < list->block.count; b++) {
                ASTNode *need = ast_clone(list->block.stmts[b]);
                ASTNode *need_base = need->type_node.base_type;
                if (need_base->type == AST_TYPE_GENERIC) {
                    for (int a = 0; a < need_base->generic_type.arg_count; a++) {
                        substitute(&need_base->generic_type.args[a], &params);
                        concrete_node(&need_base->generic_type.args[a], ctx);
                    }
                }
                ok = bound_holds(context, bound[p], need);
                free_ast(need);
            }
        }
        if (!ok) {
            for (int p = 0; p < tpl->type_param_count; p++) free_ast(bound[p]);
            free(bound);
            continue;
        }

        /* The placeholder is one more parameter, standing for the instance. */
        int sub_count = tpl->type_param_count + 1;
        char **names = malloc(sizeof(char *) * (size_t)sub_count);
        for (int p = 0; p < tpl->type_param_count; p++) names[p] = tpl->type_params[p];
        names[tpl->type_param_count] = tpl->placeholder;
        bound[tpl->type_param_count] = named_type(concrete_name);
        Substitution sub = {context, names, bound, sub_count};

        ImplDef *impl = calloc(1, sizeof(ImplDef));
        impl->trait_name = strdup(tpl->trait_name);
        impl->trait_arg_count = tpl->trait_arg_count;
        impl->trait_args = tpl->trait_arg_count
            ? malloc(sizeof(ASTNode *) * (size_t)tpl->trait_arg_count) : NULL;
        for (int a = 0; a < tpl->trait_arg_count; a++) {
            impl->trait_args[a] = ast_clone(tpl->trait_args[a]);
            substitute(&impl->trait_args[a], &sub);
            concrete_node(&impl->trait_args[a], ctx);
        }
        impl->self_type = named_type(concrete_name);
        impl->self_name = strdup(concrete_name);
        impl->item_count = tpl->item_count;
        impl->item_names = calloc((size_t)tpl->item_count, sizeof(char *));
        impl->item_mangled = calloc((size_t)tpl->item_count, sizeof(char *));
        impl->line = tpl->line;
        impl->col = tpl->col;
        /* Registered before the items are made concrete: an item may use the
         * impl itself (`==` on the type inside its own Eq is a recursion). */
        add_impl_instance(context, impl);

        LiteralRename rename = {tpl->placeholder, concrete_name};
        for (int i = 0; i < tpl->item_count; i++) {
            ASTNode *fn = ast_clone(tpl->template_items[i]);
            substitute(&fn, &sub);
            rename_literal_type(&fn, &rename);
            impl->item_names[i] = strdup(tpl->item_names[i]);
            int is_method = fn->fundef.recv_type_name != NULL;
            char *label;
            if (is_method) {
                StringBuilder mangled;
                sb_init(&mangled);
                sb_append(&mangled, "%s__%s", concrete_name, tpl->item_names[i]);
                label = strdup(mangled.buf);
                sb_free(&mangled);
                free(fn->fundef.recv_type_name);
                fn->fundef.recv_type_name = strdup(concrete_name);
            } else {
                label = impl_assoc_label(context, impl, tpl->item_names[i]);
            }
            free(fn->fundef.name);
            fn->fundef.name = strdup(label);
            fn->fundef.is_exported = 0;
            impl->item_mangled[i] = strdup(label);
            append_instance(ctx, label, fn);
            concrete_node(&fn, ctx);
            add_function(context, fn);
            if (is_method) add_method(context, concrete_name, tpl->item_names[i], fn->fundef.name, fn);
        }
        for (int p = 0; p < sub_count; p++) free_ast(bound[p]);
        free(bound);
        free(names);
    }
}

/* One argument of an instance key (append_type_key), advancing *p; NULL
 * when the key does not read back. */
static ASTNode *decode_key_arg(const char **p) {
    const char *s = *p;
    char *end;
    if (strncmp(s, "_c", 2) == 0) {
        long digits = strtol(s + 2, &end, 10);
        if (*end != '_') return NULL;
        char *value = strndup(end + 1, (size_t)digits);
        ASTNode *arg = new_number(value);
        free(value);
        *p = end + 1 + digits;
        return arg;
    }
    if (strncmp(s, "_f", 2) == 0) {
        int count = 0, variadic = 0, used = 0;
        if (sscanf(s, "_f%d_v%d%n", &count, &variadic, &used) < 2 || used == 0) return NULL;
        s += used;
        ASTNode **params = count ? malloc(sizeof(ASTNode *) * (size_t)count) : NULL;
        for (int i = 0; i < count; i++) {
            params[i] = decode_key_arg(&s);
            if (!params[i]) {
                for (int k = 0; k < i; k++) free_ast(params[k]);
                free(params);
                return NULL;
            }
        }
        if (strncmp(s, "_ret", 4) != 0) {
            for (int k = 0; k < count; k++) free_ast(params[k]);
            free(params);
            return NULL;
        }
        s += 4;
        ASTNode *ret = decode_key_arg(&s);
        if (!ret) {
            for (int k = 0; k < count; k++) free_ast(params[k]);
            free(params);
            return NULL;
        }
        *p = s;
        return new_function_type(params, count, ret, variadic != 0);
    }
    int ptr = 0, ref = 0, mods = 0, used = 0;
    if (sscanf(s, "_p%d_r%d_m%d_n%n", &ptr, &ref, &mods, &used) < 3 || used == 0) return NULL;
    s += used;
    long name_len = strtol(s, &end, 10);
    if (*end != '_' || name_len <= 0) return NULL;
    char *arg_name = strndup(end + 1, (size_t)name_len);
    ASTNode *arg = new_type_node(new_identifier(arg_name), ptr, mods, ref);
    free(arg_name);
    *p = end + 1 + name_len;
    return arg;
}

/* The template name and arguments an instance key spells:
 * `__mlg_s_3_Box_p0_r0_m0_n3_i32` is Box with `i32`. Returns 0 for a key
 * this cannot read back. */
static int decode_instance_key(const char *key, char **out_name, ASTNode ***out_args, int *out_count) {
    if (strncmp(key, "__mlg_s_", 8) != 0) return 0;
    const char *s = key + 8;
    char *end;
    long len = strtol(s, &end, 10);
    if (*end != '_' || len <= 0) return 0;
    char *name = strndup(end + 1, (size_t)len);
    s = end + 1 + len;
    ASTNode **args = NULL;
    int count = 0;
    while (*s) {
        ASTNode *arg = decode_key_arg(&s);
        if (!arg) break;
        args = realloc(args, sizeof(ASTNode *) * (size_t)(count + 1));
        args[count++] = arg;
    }
    if (*s) {
        for (int i = 0; i < count; i++) free_ast(args[i]);
        free(args);
        free(name);
        return 0;
    }
    *out_name = name;
    *out_args = args;
    *out_count = count;
    return 1;
}

/* Instances that came in with imported types get their called receiver
 * methods and their impls here too: this unit may call, compare, or drop
 * one without ever naming the generic type. */
static void instantiate_imported_instance_impls(Instantiation *ctx) {
    /* A payload enum instance arrives as the enum itself (its declaring
     * module kept it unlowered), so it is found by its instance name. */
    for (int i = 0; i < ctx->program->block.count; i++) {
        ASTNode *node = ctx->program->block.stmts[i];
        if (!node || node->type != AST_ENUM || strncmp(node->enum_stmt.name, "__mlg_s_", 8) != 0) continue;
        char *template_name = NULL;
        ASTNode **args = NULL;
        int count = 0;
        if (!decode_instance_key(node->enum_stmt.name, &template_name, &args, &count)) continue;
        instantiate_receiver_methods(ctx, template_name, node->enum_stmt.name, args, count);
        instantiate_impl_templates(ctx, template_name, node->enum_stmt.name, args, count);
        for (int a = 0; a < count; a++) free_ast(args[a]);
        free(args);
        free(template_name);
    }
    for (int i = 0; i < ctx->imported_count; i++) {
        const char *key = ctx->imported[i]->struct_stmt.name;
        char *template_name = NULL;
        ASTNode **args = NULL;
        int count = 0;
        if (!decode_instance_key(key, &template_name, &args, &count)) continue;
        instantiate_receiver_methods(ctx, template_name, key, args, count);
        instantiate_impl_templates(ctx, template_name, key, args, count);
        for (int a = 0; a < count; a++) free_ast(args[a]);
        free(args);
        free(template_name);
    }
}

/* `dom.key_filter().unwrap_or(0)`: a function of another module returns an
 * instance this unit never names, so nothing here would make its methods.
 * Instantiate the type of every call result used as a method receiver. */
static void instantiate_receiver_results(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    Instantiation *ctx = user_data;
    if (!node) return;
    ast_visit_children(node, instantiate_receiver_results, user_data);
    if (node->type != AST_CALL || !node->call.recv || node->call.recv->type != AST_CALL ||
        node->call.recv->call.recv || !node->call.recv->call.name)
        return;
    ASTNode *callee = callee_declaration(ctx->parser_context, ctx->program, node->call.recv->call.name);
    ASTNode *ret = callee && callee->type == AST_FUNDEF ? callee->fundef.ret_type : NULL;
    if (!ret || ret->type != AST_TYPE || ret->type_node.pointer_level || !ret->type_node.base_type ||
        ret->type_node.base_type->type != AST_IDENTIFIER)
        return;
    const char *key = ret->type_node.base_type->identifier.name;
    if (strncmp(key, "__mlg_s_", 8) != 0) return;
    char *template_name = NULL;
    ASTNode **args = NULL;
    int count = 0;
    if (!decode_instance_key(key, &template_name, &args, &count)) return;
    if (find_generic_type_template(ctx->parser_context, template_name))
        instantiate(ctx, node, template_name, args, count, 0);
    for (int a = 0; a < count; a++) free_ast(args[a]);
    free(args);
    free(template_name);
}

/* Impl records name their types the way the source did; make them concrete
 * too, so `Box<i32>` in an impl and in a use spell the same instance. */
static void concretize_impls(Instantiation *ctx) {
    ParserContext *context = ctx->parser_context;
    for (int i = 0; i < impl_count(context); i++) {
        ImplDef *impl = impl_at(context, i);
        if (impl->is_template) continue; /* made concrete per instance */
        concrete_node(&impl->self_type, ctx);
        for (int a = 0; a < impl->trait_arg_count; a++) concrete_node(&impl->trait_args[a], ctx);
    }
}

static const char *instantiate(Instantiation *ctx, ASTNode *use, const char *name,
                               ASTNode **args, int count, int is_function) {
    ParserContext *context = ctx->parser_context;
    ASTNode *tpl = is_function ? find_generic_function_template(context, name) : find_generic_type_template(context, name);
    if (!tpl) generic_error(context, use, "generic declaration is not available in this module");
    int is_enum = !is_function && tpl->type == AST_ENUM;
    int expected = is_function ? tpl->fundef.type_param_count :
                   is_enum ? tpl->enum_stmt.type_param_count : tpl->struct_stmt.type_param_count;
    if (count != expected) generic_error(context, use, "generic type argument count mismatch");
    if (is_function && !tpl->fundef.body)
        generic_error(context, use,
                      "generic function instantiation requires a definition in this module");

    unsigned char *param_is_const = is_function ? tpl->fundef.type_param_is_const :
                                    is_enum ? tpl->enum_stmt.type_param_is_const :
                                              tpl->struct_stmt.type_param_is_const;
    for (int i = 0; i < count; i++) {
        int numeric = args[i] && args[i]->type == AST_NUMBER;
        if (param_is_const && param_is_const[i] && !numeric)
            generic_error(context, args[i], "const generic argument must be an integer constant");
        if ((!param_is_const || !param_is_const[i]) && numeric)
            generic_error(context, args[i], "type generic argument must be a type");
        if (numeric) {
            long value = strtol(args[i]->number.value, NULL, 10);
            if (value <= 0 || value > 1048576)
                generic_error(context, args[i],
                              "const generic argument is outside 1..1048576");
        }
    }

    if (is_function)
        check_bounds(ctx, use, name, tpl->fundef.type_params, tpl->fundef.type_param_bounds, args, count);
    else if (is_enum)
        check_bounds(ctx, use, name, tpl->enum_stmt.type_params, tpl->enum_stmt.type_param_bounds, args, count);
    else
        check_bounds(ctx, use, name, tpl->struct_stmt.type_params, tpl->struct_stmt.type_param_bounds, args, count);

    StringBuilder key;
    sb_init(&key);
    sb_append(&key, "__mlg_%c_%zu_%s", is_function ? 'f' : 's', strlen(name), name);
    for (int i = 0; i < count; i++) append_type_key(context, &key, args[i]);
    for (int i = 0; i < ctx->count; i++) {
        if (strcmp(ctx->instances[i].name, key.buf) == 0) {
            sb_free(&key);
            return ctx->instances[i].name;
        }
    }
    /* The same instantiation may have arrived with an imported type whose
     * field it is; one layout, one declaration. */
    for (int i = 0; i < ctx->imported_count; i++) {
        if (strcmp(ctx->imported[i]->struct_stmt.name, key.buf) == 0) {
            sb_free(&key);
            /* Its called methods and impls are this unit's to instantiate,
             * as for its own. */
            if (!is_function) {
                instantiate_receiver_methods(ctx, name, ctx->imported[i]->struct_stmt.name, args, count);
                instantiate_impl_templates(ctx, name, ctx->imported[i]->struct_stmt.name, args, count);
            }
            return ctx->imported[i]->struct_stmt.name;
        }
    }
    if (ctx->depth >= 64 || ctx->count >= 256 || key.len > 240)
        generic_error(context, use,
                      "generic instantiation limit exceeded (possibly expanding recursion)");

    ASTNode *decl = ast_clone(tpl);
    Substitution sub = {
        context,
        is_function ? tpl->fundef.type_params :
        is_enum ? tpl->enum_stmt.type_params : tpl->struct_stmt.type_params,
        args,
        count,
    };
    substitute(&decl, &sub);
    char **params = is_function ? decl->fundef.type_params :
                    is_enum ? decl->enum_stmt.type_params : decl->struct_stmt.type_params;
    for (int i = 0; i < count; i++) free(params[i]);
    free(params);
    char *concrete_name = key.buf;
    if (is_function) {
        free(decl->fundef.name);
        decl->fundef.name = strdup(concrete_name);
        decl->fundef.type_params = NULL;
        free(decl->fundef.type_param_is_const);
        decl->fundef.type_param_is_const = NULL;
        if (decl->fundef.type_param_bounds) {
            for (int i = 0; i < count; i++) free_ast(decl->fundef.type_param_bounds[i]);
            free(decl->fundef.type_param_bounds);
            decl->fundef.type_param_bounds = NULL;
        }
        decl->fundef.type_param_count = 0;
        decl->fundef.is_exported = 0;
    } else if (is_enum) {
        free(decl->enum_stmt.name);
        decl->enum_stmt.name = strdup(concrete_name);
        decl->enum_stmt.type_params = NULL;
        free(decl->enum_stmt.type_param_is_const);
        decl->enum_stmt.type_param_is_const = NULL;
        if (decl->enum_stmt.type_param_bounds) {
            for (int i = 0; i < count; i++) free_ast(decl->enum_stmt.type_param_bounds[i]);
            free(decl->enum_stmt.type_param_bounds);
            decl->enum_stmt.type_param_bounds = NULL;
        }
        decl->enum_stmt.type_param_count = 0;
        decl->enum_stmt.is_exported = 0;
    } else {
        free(decl->struct_stmt.name);
        decl->struct_stmt.name = strdup(concrete_name);
        decl->struct_stmt.type_params = NULL;
        free(decl->struct_stmt.type_param_is_const);
        decl->struct_stmt.type_param_is_const = NULL;
        if (decl->struct_stmt.type_param_bounds) {
            for (int i = 0; i < count; i++) free_ast(decl->struct_stmt.type_param_bounds[i]);
            free(decl->struct_stmt.type_param_bounds);
            decl->struct_stmt.type_param_bounds = NULL;
        }
        decl->struct_stmt.type_param_count = 0;
        decl->struct_stmt.is_exported = 0;
    }
    /* Publish before visiting the body to close same-type recursion. */
    append_instance(ctx, concrete_name, decl);
    ctx->depth++;
    concrete_node(&decl, ctx);
    ctx->depth--;
    if (is_function) {
        add_function(context, decl);
    } else {
        instantiate_receiver_methods(ctx, name, concrete_name, args, count);
        instantiate_impl_templates(ctx, name, concrete_name, args, count);
    }
    return concrete_name;
}

/* The backend already has complete struct layout support. Until payload enum
 * constructors and aggregate return ABI arrive, represent every payload enum
 * as its explicit tag plus one storage field per variant. This keeps generic
 * specialization concrete and gives the later constructor/pattern lowering a
 * stable layout to target. */
static ASTNode *lower_payload_enum(ASTNode *node) {
    if (!node || node->type != AST_ENUM || !node->enum_stmt.has_payloads) return node;

    int member_count = node->enum_stmt.member_count;
    ASTNode **members = calloc((size_t)member_count + 1, sizeof(ASTNode *));
    members[0] = new_var_decl(new_type_node(new_identifier("i32"), 0,
                                             TYPEMOD_NONE, REFKIND_NONE),
                              "__tag", NULL);
    int field_count = 1;
    for (int i = 0; i < member_count; i++) {
        ASTNode *variant = node->enum_stmt.members[i];
        if (!variant) return node;
        /* A variant with nothing to carry contributes only its tag value, so
         * it gets no storage. `Opt<T> { Some(T), None }` is one field wide. */
        if (!variant->enum_member.payload_type) continue;
        members[field_count++] = new_var_decl(ast_clone(variant->enum_member.payload_type),
                                              variant->enum_member.name, NULL);
    }

    ASTNode *result = new_struct(node->enum_stmt.name, members, field_count);
    result->line = node->line;
    result->col = node->col;
    result->end_line = node->end_line;
    result->end_col = node->end_col;
    /* new_struct() defaults is_exported/package to "not exported" -- carry
     * the enum's own flags over instead, so an `export enum` with payloads
     * is still exported once lowered to its backing struct. Within a single
     * file this never showed: only cross-file lookups (an importer asking
     * whether this struct's declaration is exported) ever read it. Move
     * `package` rather than copy it; it's about to be freed with the rest
     * of `node`. */
    result->struct_stmt.is_exported = node->enum_stmt.is_exported;
    result->struct_stmt.package = node->enum_stmt.package;
    node->enum_stmt.package = NULL;
    free_ast(node);
    return result;
}

static void concrete_node(ASTNode **slot, void *user_data) {
    ASTNode *node = *slot;
    if (!node) return;
    Instantiation *ctx = user_data;
    ParserContext *context = ctx->parser_context;
    /* Typedefs are transparent in specialization keys as well as in the
     * signatures that consume specialized types. Resolve before visiting the
     * children so aliases of generic types are instantiated too. */
    if (generic_template_count(context) && node->type == AST_TYPE && node->type_node.base_type &&
        node->type_node.base_type->type == AST_IDENTIFIER) {
        const char *name = node->type_node.base_type->identifier.name;
        for (int i = 0; i < ctx->program->block.count; i++) {
            ASTNode *alias = ctx->program->block.stmts[i];
            if (alias->type != AST_TYPEDEF || alias->typedef_stmt.is_newtype ||
                strcmp(alias->typedef_stmt.alias, name) != 0) continue;
            if (ctx->depth >= 64)
                generic_error(context, node,
                              "generic instantiation limit exceeded while resolving aliases");
            char *params[] = {(char *)name};
            ASTNode *args[] = {alias->typedef_stmt.src_type};
            Substitution sub = {context, params, args, 1};
            substitute(slot, &sub);
            ctx->depth++;
            concrete_node(slot, ctx);
            ctx->depth--;
            return;
        }
    }
    ast_visit_children(node, concrete_node, ctx);
    if (node->type == AST_INIT_LIST && node->init_list.struct_type_arg_count > 0) {
        const char *name = instantiate(ctx, node, node->init_list.struct_type_name,
                                       node->init_list.struct_type_args,
                                       node->init_list.struct_type_arg_count, 0);
        free(node->init_list.struct_type_name);
        node->init_list.struct_type_name = strdup(name);
        for (int i = 0; i < node->init_list.struct_type_arg_count; i++)
            free_ast(node->init_list.struct_type_args[i]);
        free(node->init_list.struct_type_args);
        node->init_list.struct_type_args = NULL;
        node->init_list.struct_type_arg_count = 0;
    } else if (node->type == AST_TYPE_GENERIC) {
        const char *name = instantiate(ctx, node, node->generic_type.name,
                                       node->generic_type.args, node->generic_type.arg_count, 0);
        ASTNode *id = new_identifier((char *)name);
        id->line = node->line; id->col = node->col;
        id->end_line = node->end_line; id->end_col = node->end_col;
        free_ast(node);
        *slot = id;
    } else if (node->type == AST_CALL && node->call.type_arg_count && strstr(node->call.name, "::")) {
        /* `Box<i32>::make(...)` names the instance's associated function. */
        const char *separator = strstr(node->call.name, "::");
        char *type_name = strndup(node->call.name, (size_t)(separator - node->call.name));
        const char *name = instantiate(ctx, node, type_name, node->call.type_args,
                                       node->call.type_arg_count, 0);
        StringBuilder qualified;
        sb_init(&qualified);
        sb_append(&qualified, "%s%s", name, separator);
        free(type_name);
        free(node->call.name);
        node->call.name = strdup(qualified.buf);
        sb_free(&qualified);
        for (int i = 0; i < node->call.type_arg_count; i++) free_ast(node->call.type_args[i]);
        free(node->call.type_args);
        node->call.type_args = NULL;
        node->call.type_arg_count = 0;
    } else if (node->type == AST_CALL && node->call.type_arg_count) {
        const char *name = instantiate(ctx, node, node->call.name,
                                       node->call.type_args, node->call.type_arg_count, 1);
        free(node->call.name);
        node->call.name = strdup(name);
        for (int i = 0; i < node->call.type_arg_count; i++) free_ast(node->call.type_args[i]);
        free(node->call.type_args);
        node->call.type_args = NULL;
        node->call.type_arg_count = 0;
    }
}

static const char *struct_name(ASTNode *node) {
    if (node->type == AST_STRUCT) return node->struct_stmt.name;
    if (node->type == AST_TYPEDEF_STRUCT) return node->typedef_struct.typedef_name;
    return NULL;
}

/* Layout construction currently walks structs in source order. Specialization
 * can introduce forward dependencies, so order by by-value containment. */
static void order_struct(ParserContext *context, ASTNode *program, int index,
                         int *state, ASTNode **ordered, int *count) {
    if (state[index] == 2) return;
    ASTNode *node = program->block.stmts[index];
    if (state[index] == 1)
        generic_error(context, node, "recursive by-value struct has infinite size");
    state[index] = 1;
    ASTNode **members = node->type == AST_STRUCT ? node->struct_stmt.members : node->typedef_struct.members;
    int size = node->type == AST_STRUCT ? node->struct_stmt.member_count : node->typedef_struct.member_count;
    for (int i = 0; i < size; i++) {
        ASTNode *type = members[i]->var_decl.var_type;
        int alias_steps = 0;
        while (type) {
            if (type->type == AST_TYPE_ARRAY) { type = type->type_array.element_type; continue; }
            if (type->type != AST_TYPE || type->type_node.pointer_level ||
                type->type_node.ref_kind != REFKIND_NONE) break;
            ASTNode *base = type->type_node.base_type;
            if (!base || base->type != AST_IDENTIFIER) break;
            ASTNode *alias = NULL;
            for (int j = 0; j < program->block.count; j++) {
                ASTNode *candidate = program->block.stmts[j];
                const char *name = struct_name(candidate);
                if (name && strcmp(name, base->identifier.name) == 0)
                    order_struct(context, program, j, state, ordered, count);
                if (candidate->type == AST_TYPEDEF && !candidate->typedef_stmt.is_newtype &&
                    strcmp(candidate->typedef_stmt.alias, base->identifier.name) == 0)
                    alias = candidate->typedef_stmt.src_type;
            }
            if (++alias_steps > program->block.count)
                generic_error(context, node, "cyclic type alias in struct layout");
            type = alias;
        }
    }
    state[index] = 2;
    ordered[(*count)++] = node;
}

/* Splice every plain struct/enum staged by load_imported_plain_types() into
 * program->block.stmts, before anything below walks it: unlike a generic
 * template's concrete instantiation (spliced in further down, once a use is
 * found), a plain type has no per-use specialization to wait for -- it's
 * already the concrete declaration -- so it goes in unconditionally, early
 * enough that the generic-use walk, the payload-enum lowering, and (if
 * triggered) the struct reordering below all see it as if it had been
 * declared locally. */
static void splice_imported_plain_types(ParserContext *context, ASTNode *program) {
    int count = imported_plain_type_count(context);
    if (count == 0) return;
    int old_count = program->block.count;
    program->block.count += count;
    program->block.stmts = realloc(program->block.stmts, sizeof(ASTNode *) * program->block.count);
    /* Ahead of this file's own declarations: the semantic walk registers a
     * numeric enum when it reaches it, so an imported one has to come before
     * the functions whose signatures name it (when nothing is specialized,
     * nothing below reorders the program). */
    memmove(program->block.stmts + count, program->block.stmts, sizeof(ASTNode *) * (size_t)old_count);
    for (int i = 0; i < count; i++) {
        program->block.stmts[i] = imported_plain_type_at(context, i);
    }
    /* Ownership of each declaration just moved into program->block.stmts;
     * only the staging array itself is ours to free. */
    free(context->symbols.imported_plain_types.declarations);
    context->symbols.imported_plain_types.declarations = NULL;
    context->symbols.imported_plain_types.count = 0;
}

void instantiate_generics(ParserContext *context, ASTNode *program) {
    splice_imported_plain_types(context, program);
    Instantiation ctx = {.parser_context = context, .program = program};
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (node && node->type == AST_STRUCT && node->struct_stmt.is_imported_instance) {
            ctx.imported = realloc(ctx.imported, sizeof(ASTNode *) * (ctx.imported_count + 1));
            ctx.imported[ctx.imported_count++] = node;
        }
    }
    collect_called_methods(&ctx, program);
    concretize_impls(&ctx);
    instantiate_imported_instance_impls(&ctx);
    instantiate_receiver_results(&program, &ctx);
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        const char *name = struct_name(node);
        if (node->type == AST_FUNDEF) name = node->fundef.name;
        if (node->type == AST_VAR_DECL) name = node->var_decl.name;
        if (name && strncmp(name, "__mlg_", 6) == 0 &&
            !(node->type == AST_STRUCT && node->struct_stmt.is_imported_instance))
            generic_error(context, node,
                          "the __mlg_ prefix is reserved for generic instantiations");
        concrete_node(&program->block.stmts[i], &ctx);
    }
    if (ctx.count) {
        int old_count = program->block.count;
        program->block.count += ctx.count;
        program->block.stmts = realloc(program->block.stmts, sizeof(ASTNode *) * program->block.count);
        for (int i = 0; i < ctx.count; i++) program->block.stmts[old_count + i] = ctx.instances[i].declaration;
        lower_trait_uses(context, program);
        lower_payload_enum_uses(context, program);
        for (int i = 0; i < program->block.count; i++) {
            program->block.stmts[i] = lower_payload_enum(program->block.stmts[i]);
        }
        int *state = calloc(program->block.count, sizeof(int));
        ASTNode **ordered = malloc(sizeof(ASTNode *) * program->block.count);
        int count = 0;
        /* The semantic walk registers numeric enums on encounter. Keep those
         * definitions ahead of specialized structs that use them as fields. */
        for (int i = 0; i < program->block.count; i++)
            if (program->block.stmts[i]->type == AST_ENUM) ordered[count++] = program->block.stmts[i];
        for (int i = 0; i < program->block.count; i++)
            if (struct_name(program->block.stmts[i]))
                order_struct(context, program, i, state, ordered, &count);
        for (int i = 0; i < program->block.count; i++)
            if (!struct_name(program->block.stmts[i]) && program->block.stmts[i]->type != AST_ENUM)
                ordered[count++] = program->block.stmts[i];
        free(state);
        free(program->block.stmts);
        program->block.stmts = ordered;
    } else {
        lower_trait_uses(context, program);
        lower_payload_enum_uses(context, program);
        for (int i = 0; i < program->block.count; i++) {
            program->block.stmts[i] = lower_payload_enum(program->block.stmts[i]);
        }
    }
    for (int i = 0; i < ctx.count; i++) free(ctx.instances[i].name);
    free(ctx.instances);
    free(ctx.imported);
    for (int i = 0; i < ctx.impls_done_count; i++) free(ctx.impls_done[i]);
    free(ctx.impls_done);
    for (int i = 0; i < ctx.called_method_count; i++) free(ctx.called_methods[i]);
    free(ctx.called_methods);
}
