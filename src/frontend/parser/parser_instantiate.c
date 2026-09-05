#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/support/stringBuilder.h"

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
} Instantiation;

typedef struct {
    ParserContext *parser_context;
    char **params;
    ASTNode **args;
    int count;
} Substitution;

static void concrete_node(ASTNode **slot, void *user_data);

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
    if (node->type == AST_TYPE && node->type_node.base_type &&
        node->type_node.base_type->type == AST_IDENTIFIER) {
        for (int i = 0; i < sub->count; i++) {
            if (strcmp(node->type_node.base_type->identifier.name, sub->params[i]) != 0) continue;
            ASTNode *arg = ast_clone(sub->args[i]);
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
    ast_visit_children(node, substitute, user_data);
}

/* Length-prefixed names and every qualifier keep the key unambiguous. Nested
 * generic arguments have already become concrete type names at this point. */
static void append_type_key(ParserContext *context, StringBuilder *key, ASTNode *arg) {
    if (!arg || arg->type != AST_TYPE || !arg->type_node.base_type ||
        arg->type_node.base_type->type != AST_IDENTIFIER)
        generic_error(context, arg, "generic argument did not resolve to a concrete type");
    const char *name = arg->type_node.base_type->identifier.name;
    sb_append(key, "_p%d_r%d_m%d_n%zu_%s", arg->type_node.pointer_level,
              arg->type_node.ref_kind, arg->type_node.type_modifiers, strlen(name), name);
}

static const char *instantiate(Instantiation *ctx, ASTNode *use, const char *name,
                               ASTNode **args, int count, int is_function) {
    ParserContext *context = ctx->parser_context;
    ASTNode *tpl = is_function ? find_generic_function_template(context, name) : find_generic_type_template(context, name);
    if (!tpl) generic_error(context, use, "generic declaration is not available in this module");
    int expected = is_function ? tpl->fundef.type_param_count : tpl->struct_stmt.type_param_count;
    if (count != expected) generic_error(context, use, "generic type argument count mismatch");
    if (is_function && !tpl->fundef.body)
        generic_error(context, use,
                      "generic function instantiation requires a definition in this module");

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
    if (ctx->depth >= 64 || ctx->count >= 256 || key.len > 240)
        generic_error(context, use,
                      "generic instantiation limit exceeded (possibly expanding recursion)");

    ASTNode *decl = ast_clone(tpl);
    Substitution sub = {
        context,
        is_function ? tpl->fundef.type_params : tpl->struct_stmt.type_params,
        args,
        count,
    };
    substitute(&decl, &sub);
    char **params = is_function ? decl->fundef.type_params : decl->struct_stmt.type_params;
    for (int i = 0; i < count; i++) free(params[i]);
    free(params);
    char *concrete_name = key.buf;
    if (is_function) {
        free(decl->fundef.name);
        decl->fundef.name = strdup(concrete_name);
        decl->fundef.type_params = NULL;
        decl->fundef.type_param_count = 0;
        decl->fundef.is_exported = 0;
    } else {
        free(decl->struct_stmt.name);
        decl->struct_stmt.name = strdup(concrete_name);
        decl->struct_stmt.type_params = NULL;
        decl->struct_stmt.type_param_count = 0;
        decl->struct_stmt.is_exported = 0;
    }
    /* Publish before visiting the body to close same-type recursion. */
    ctx->instances = realloc(ctx->instances, sizeof(Instance) * (ctx->count + 1));
    ctx->instances[ctx->count++] = (Instance){concrete_name, decl};
    ctx->depth++;
    concrete_node(&decl, ctx);
    ctx->depth--;
    if (is_function) add_function(context, decl);
    return concrete_name;
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
            if (alias->type != AST_TYPEDEF || strcmp(alias->typedef_stmt.alias, name) != 0) continue;
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
    if (node->type == AST_TYPE_GENERIC) {
        const char *name = instantiate(ctx, node, node->generic_type.name,
                                       node->generic_type.args, node->generic_type.arg_count, 0);
        ASTNode *id = new_identifier((char *)name);
        id->line = node->line; id->col = node->col;
        id->end_line = node->end_line; id->end_col = node->end_col;
        free_ast(node);
        *slot = id;
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
                if (candidate->type == AST_TYPEDEF &&
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

void instantiate_generics(ParserContext *context, ASTNode *program) {
    Instantiation ctx = {.parser_context = context, .program = program};
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        const char *name = struct_name(node);
        if (node->type == AST_FUNDEF) name = node->fundef.name;
        if (node->type == AST_VAR_DECL) name = node->var_decl.name;
        if (name && strncmp(name, "__mlg_", 6) == 0)
            generic_error(context, node,
                          "the __mlg_ prefix is reserved for generic instantiations");
        concrete_node(&program->block.stmts[i], &ctx);
    }
    if (ctx.count) {
        int old_count = program->block.count;
        program->block.count += ctx.count;
        program->block.stmts = realloc(program->block.stmts, sizeof(ASTNode *) * program->block.count);
        for (int i = 0; i < ctx.count; i++) program->block.stmts[old_count + i] = ctx.instances[i].declaration;
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
    }
    for (int i = 0; i < ctx.count; i++) free(ctx.instances[i].name);
    free(ctx.instances);
}
