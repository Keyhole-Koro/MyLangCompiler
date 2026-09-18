#include "mylang/frontend/parser_annot_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/lexer.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/resolver.h"

#include <stdarg.h>
#include <ctype.h>

/* Annotations: user-declared attributes and their compile-time templates.
 *
 * The compiler carries no attribute vocabulary. `@app`, `@timer` and friends
 * are declared in MyLang and imported like anything else:
 *
 *     export annotation app(bool single = false, char *name = "")
 *         on struct T requires method view
 *     {
 *         i32 __app_@{T}_view(i32 self) { @T *p = (@T*)self; return p->view(); }
 *         ...
 *     }
 *     export annotation timer(i32 ms) on method of app;
 *
 *     import { app, timer } from "annotations.mln";
 *     @app struct Counter { ... };
 *
 * This pass resolves every attribute in the program to a declaration
 * (local first, then symbol-list imports), checks it -- target kind,
 * argument shapes against the declared parameters, `of` and `requires` --
 * and, for declarations with a body, expands the template into MyLang
 * source that goes through the ordinary top-level parser, so generated code
 * is method-resolved, semantically checked and compiled like anything the
 * author wrote.
 *
 * The template is the declaration's raw body text. Everything is copied
 * through except `@` directives, which read the annotated declaration:
 *
 *     @T, @{T}                 the annotated type's name (`T` is `on struct T`);
 *                              the braced form splices inside an identifier
 *     @name(T)                 the same as a string literal
 *     @arg(p)                  annotation argument `p` (or its default) as a literal
 *     @each(f in @fields(T) [where init]) { ... }   per field; @f, @f.type, @f.init
 *     @each(m in @methods(T, annot)) { ... }         per method carrying @annot;
 *                              @m, @m.mangled, @m.args[i] (that annotation's args)
 *     @count(@fields(T)) / @count(@methods(T, annot))
 *     @i                       0-based index inside the innermost @each
 *     @tramp(m)                a `void (i32 owner, i32 id, i32 arg)` function
 *                              calling method m (generated on first use)
 *     @@                       a literal '@'
 *
 * The one piece of meaning left in the compiler is @tramp: the calling
 * convention is the compiler's. Templates read declarations; they do not
 * compute. Names ending in `__tramp` are reserved for generated trampolines.
 */

static void annot_error(ParserContext *context, int line, int col, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "%s:%d:%d: error: ",
            context->module.filename ? context->module.filename : "<input>", line, col);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

// --- generated source -----------------------------------------------------------

typedef struct {
    char *text;
    size_t len;
    size_t cap;
} Src;

static void src_appendf(Src *s, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) { va_end(ap2); return; }
    if (s->len + (size_t)need + 1 > s->cap) {
        s->cap = (s->len + (size_t)need + 1) * 2;
        s->text = realloc(s->text, s->cap);
    }
    vsnprintf(s->text + s->len, s->cap - s->len, fmt, ap2);
    va_end(ap2);
    s->len += (size_t)need;
}

static void src_append_n(Src *s, const char *text, size_t n) {
    if (s->len + n + 1 > s->cap) {
        s->cap = (s->len + n + 1) * 2;
        s->text = realloc(s->text, s->cap);
    }
    memcpy(s->text + s->len, text, n);
    s->len += n;
    s->text[s->len] = 0;
}

// Appends `text` as a MyLang string literal, re-escaping what the lexer unescaped.
static void src_append_quoted(Src *s, const char *text) {
    src_appendf(s, "\"");
    for (const char *p = text; *p; p++) {
        switch (*p) {
        case '"': src_appendf(s, "\\\""); break;
        case '\\': src_appendf(s, "\\\\"); break;
        case '\n': src_appendf(s, "\\n"); break;
        case '\t': src_appendf(s, "\\t"); break;
        default: src_appendf(s, "%c", *p); break;
        }
    }
    src_appendf(s, "\"");
}

/* Parses generated top-level source into the program. The tokens are freed
 * afterwards: every AST constructor copies its strings. */
void parse_generated_toplevels(ParserContext *context, ASTNode *program, const char *source) {
    char *copy = strdup(source);
    Token *tokens = lexer(copy);
    Token *cur = tokens;
    while (cur && cur->kind != EOT) {
        ASTNode *node = parse_toplevel(context, &cur);
        if (!node) continue;
        program->block.stmts = realloc(program->block.stmts, sizeof(ASTNode *) * (program->block.count + 1));
        program->block.stmts[program->block.count++] = node;
    }
    while (tokens) {
        Token *next = tokens->next;
        free(tokens->value);
        free(tokens);
        tokens = next;
    }
    free(copy);
}

// --- trampolines ------------------------------------------------------------------

static const char *method_short_name(const ASTNode *fn) {
    // Methods are stored mangled as `<Type>__<name>`.
    const char *sep = strstr(fn->fundef.name, "__");
    return sep ? sep + 2 : fn->fundef.name;
}

/* The argument list a trampoline hands to a callee with `param_count`
 * parameters (after any receiver): (), (id) or (id, arg). */
static const char *tramp_args(ParserContext *context, const ASTNode *fn, int param_count, int line, int col) {
    switch (param_count) {
    case 0: return "";
    case 1: return "id";
    case 2: return "id, arg";
    default:
        annot_error(context, line, col,
                    "handler '%s' takes %d parameters; a handler takes at most (i32 id, i32 arg)",
                    method_short_name(fn), param_count);
        return NULL;
    }
}

/* A method reached through the handler ABI must take a pointer receiver
 * (`T *self`): the dispatcher identifies the instance by an i32, and a
 * `ref mut T` cannot be built from one. */
static void require_pointer_receiver(ParserContext *context, const ASTNode *fn, int line, int col) {
    ASTNode *recv = fn->fundef.param_count > 0 ? fn->fundef.params[0] : NULL;
    ASTNode *type = recv && recv->type == AST_PARAM ? recv->param.type : NULL;
    if (!type || type->type != AST_TYPE || type->type_node.pointer_level != 1 ||
        type->type_node.ref_kind != REFKIND_NONE) {
        annot_error(context, line, col,
                    "handler method '%s' must take a pointer receiver, `(%s *self)`",
                    method_short_name(fn), fn->fundef.recv_type_name ? fn->fundef.recv_type_name : "T");
    }
}

const char *ensure_method_trampoline(ParserContext *context, ASTNode *program,
                                     const char *type_name, const char *method_name,
                                     int line, int col) {
    const MethodDef *m = find_method(context, type_name, method_name);
    if (!m) {
        annot_error(context, line, col, "type '%s' has no method '%s'", type_name, method_name);
    }
    static char name[300];
    snprintf(name, sizeof(name), "%s__tramp", m->mangled);
    if (find_function(context, name)) return name;

    require_pointer_receiver(context, m->fundef, line, col);
    const char *args = tramp_args(context, m->fundef, m->fundef->fundef.param_count - 1, line, col);
    Src src = {0};
    src_appendf(&src, "void %s(i32 owner, i32 id, i32 arg) { %s *p = (%s*)owner; p->%s(%s); }\n",
                name, type_name, type_name, method_name, args);
    parse_generated_toplevels(context, program, src.text);
    free(src.text);
    return name;
}

const char *ensure_function_trampoline(ParserContext *context, ASTNode *program,
                                       const char *function_name, int line, int col) {
    ASTNode *fn = find_function(context, function_name);
    if (!fn || fn->type != AST_FUNDEF) return NULL;
    if (fn->fundef.recv_type_name) return NULL;
    if (fn->fundef.param_count >= 3 || fn->fundef.is_variadic) return function_name;

    static char name[300];
    snprintf(name, sizeof(name), "%s__tramp", function_name);
    if (find_function(context, name)) return name;

    const char *args = tramp_args(context, fn, fn->fundef.param_count, line, col);
    Src src = {0};
    src_appendf(&src, "void %s(i32 owner, i32 id, i32 arg) { %s(%s); }\n", name, function_name, args);
    parse_generated_toplevels(context, program, src.text);
    free(src.text);
    return name;
}

// --- resolving declarations ------------------------------------------------------

/* The declaration `@name` refers to: one in this file, else one exported by a
 * module named in a symbol-list import (`import { app } from "..."`). */
static ASTNode *resolve_annotation(ParserContext *context, ASTNode *program, const char *name) {
    ASTNode *local = find_local_annotation(context, name);
    if (local) return local;

    FrontendSession *session = context->session;
    if (!session || !session->loader) return NULL;
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->type != AST_IMPORT || !node->import_stmt.path) continue;
        if (node->import_stmt.symbol_count == 0) continue;
        if (!module_loader_is_mylang_source(node->import_stmt.path)) continue;
        Module *mod = module_loader_load(session->loader, context->module.filename, node->import_stmt.path);
        if (!mod || mod->state != MODULE_LOADED) continue;
        ModuleSymbol *sym = resolver_lookup_import_symbol(node, mod, name);
        if (sym && sym->kind == SYMBOL_ANNOTATION && sym->declaration &&
            sym->declaration->type == AST_ANNOTATION) {
            return sym->declaration;
        }
    }
    return NULL;
}

static const Attribute *find_attr(const ASTNode *node, const char *name) {
    for (int i = 0; i < node->attr_count; i++) {
        if (strcmp(node->attrs[i].name, name) == 0) return &node->attrs[i];
    }
    return NULL;
}

static ASTNode *find_struct_decl(ASTNode *program, const char *name) {
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (node && node->type == AST_STRUCT && node->struct_stmt.name &&
            strcmp(node->struct_stmt.name, name) == 0) return node;
    }
    return NULL;
}

// --- literals as text -------------------------------------------------------------

static const char *param_base_type(const ASTNode *param) {
    const ASTNode *type = param->param.type;
    if (!type || type->type != AST_TYPE || !type->type_node.base_type) return "";
    const ASTNode *base = type->type_node.base_type;
    return base->type == AST_IDENTIFIER ? base->identifier.name : "";
}

static int param_is_string(const ASTNode *param) {
    const ASTNode *type = param->param.type;
    return type && type->type == AST_TYPE && type->type_node.pointer_level == 1 &&
           strcmp(param_base_type(param), "char") == 0;
}

static int param_is_bool(const ASTNode *param) {
    return strcmp(param_base_type(param), "bool") == 0;
}

/* Writes a literal AST (number, negated number, string, char) as source. */
static void append_literal(ParserContext *context, Src *out, const ASTNode *value, int line, int col) {
    if (!value) { src_appendf(out, "0"); return; }
    switch (value->type) {
    case AST_NUMBER: src_appendf(out, "%s", value->number.value); return;
    case AST_STRING_LITERAL: src_append_quoted(out, value->string_literal.value); return;
    case AST_CHAR_LITERAL: src_appendf(out, "'%s'", value->char_literal.value); return;
    case AST_UNARY:
        if (value->unary.op == SUB && value->unary.operand && value->unary.operand->type == AST_NUMBER) {
            src_appendf(out, "-%s", value->unary.operand->number.value);
            return;
        }
        break;
    default: break;
    }
    annot_error(context, line, col, "only a literal can be used here");
}

static void append_type(ParserContext *context, Src *out, const ASTNode *type, int line, int col) {
    if (!type || type->type != AST_TYPE || !type->type_node.base_type) {
        annot_error(context, line, col, "@f.type: field type is not a plain type");
    }
    const ASTNode *base = type->type_node.base_type;
    if (base->type == AST_IDENTIFIER) src_appendf(out, "%s", base->identifier.name);
    else if (base->type == AST_TYPE_GENERIC) src_appendf(out, "%s", base->generic_type.name);
    else annot_error(context, line, col, "@f.type: unsupported field type");
    for (int i = 0; i < type->type_node.pointer_level; i++) src_appendf(out, "*");
}

// --- one use of an annotation ---------------------------------------------------------

typedef struct {
    ASTNode *decl;              // AST_ANNOTATION
    const Attribute *attr;      // the use
    ASTNode *target;            // the annotated declaration
    const char *type_name;      // struct name (struct target) or receiver type (method target)
    const ASTNode **arg_values; // per declared parameter: the supplied literal, or NULL for default
    int line;
    int col;
} AnnotUse;

/* Matches the attribute's arguments to the declaration's parameters: keyed
 * by name, positional in order, and a bare identifier naming a bool
 * parameter sets it (`@app(single)`). Literal kinds are checked against the
 * parameter types. */
static void bind_arguments(ParserContext *context, AnnotUse *use) {
    ASTNode *decl = use->decl;
    int n = decl->annotation.param_count;
    use->arg_values = calloc(n > 0 ? n : 1, sizeof(ASTNode *));
    static ASTNode one_literal;
    one_literal.type = AST_NUMBER;
    one_literal.number.value = "1";

    int positional = 0;
    for (int i = 0; i < use->attr->arg_count; i++) {
        const AttrArg *arg = &use->attr->args[i];
        int slot = -1;
        const ASTNode *value = arg->value;
        if (arg->name) {
            for (int p = 0; p < n; p++) {
                if (strcmp(decl->annotation.params[p]->param.name, arg->name) == 0) { slot = p; break; }
            }
            if (slot < 0) annot_error(context, arg->line, arg->col, "@%s has no parameter '%s'", decl->annotation.name, arg->name);
        } else if (value && value->type == AST_IDENTIFIER) {
            for (int p = 0; p < n; p++) {
                if (param_is_bool(decl->annotation.params[p]) &&
                    strcmp(decl->annotation.params[p]->param.name, value->identifier.name) == 0) { slot = p; break; }
            }
            if (slot < 0) annot_error(context, arg->line, arg->col, "@%s: unknown flag '%s'", decl->annotation.name, value->identifier.name);
            value = &one_literal;
        } else {
            while (positional < n && use->arg_values[positional]) positional++;
            if (positional >= n) annot_error(context, arg->line, arg->col, "@%s takes %d argument%s", decl->annotation.name, n, n == 1 ? "" : "s");
            slot = positional;
        }
        if (use->arg_values[slot]) annot_error(context, arg->line, arg->col, "@%s: '%s' given twice", decl->annotation.name, decl->annotation.params[slot]->param.name);

        const ASTNode *param = decl->annotation.params[slot];
        int ok;
        if (param_is_string(param)) ok = value && value->type == AST_STRING_LITERAL;
        else if (param_is_bool(param)) ok = value && value->type == AST_NUMBER;
        else ok = value && (value->type == AST_NUMBER || value->type == AST_CHAR_LITERAL ||
                            (value->type == AST_UNARY && value->unary.op == SUB));
        if (!ok) {
            annot_error(context, arg->line, arg->col, "@%s: argument '%s' must be a %s literal",
                        decl->annotation.name, param->param.name,
                        param_is_string(param) ? "string" : param_is_bool(param) ? "bool" : "number");
        }
        use->arg_values[slot] = value;
    }
    for (int p = 0; p < n; p++) {
        if (!use->arg_values[p] && !decl->annotation.params[p]->param.default_value) {
            annot_error(context, use->line, use->col, "@%s is missing argument '%s'",
                        decl->annotation.name, decl->annotation.params[p]->param.name);
        }
    }
}

static const ASTNode *arg_value(const AnnotUse *use, const char *param_name) {
    for (int p = 0; p < use->decl->annotation.param_count; p++) {
        const ASTNode *param = use->decl->annotation.params[p];
        if (strcmp(param->param.name, param_name) == 0) {
            return use->arg_values[p] ? use->arg_values[p] : param->param.default_value;
        }
    }
    return NULL;
}

// --- template expansion ---------------------------------------------------------------------

typedef struct {
    const char *var;          // loop variable name
    int kind;                 // 1 = field, 2 = method
    ASTNode *item;            // the field's var_decl or the method's fundef
    const char *annot;        // for methods: the annotation whose args @v.args[i] reads
    int index;
} LoopBinding;

typedef struct {
    ParserContext *context;
    ASTNode *program;
    AnnotUse *use;
    LoopBinding loops[8];
    int loop_depth;
    int line;                 // current template line, for diagnostics
} Expand;

static void expand_text(Expand *ex, const char *text, size_t len, Src *out);

static const LoopBinding *find_loop(const Expand *ex, const char *var) {
    for (int i = ex->loop_depth - 1; i >= 0; i--) {
        if (strcmp(ex->loops[i].var, var) == 0) return &ex->loops[i];
    }
    return NULL;
}

// Reads an identifier at *p into buf; returns its length (0 if none).
static size_t read_ident(const char *p, char *buf, size_t cap) {
    size_t n = 0;
    while ((isalnum((unsigned char)p[n]) || p[n] == '_') && n + 1 < cap) { buf[n] = p[n]; n++; }
    buf[n] = 0;
    return n;
}

static const char *skip_ws(const char *p) { while (*p && isspace((unsigned char)*p)) p++; return p; }

// Finds the '}' matching the '{' at p (p[0] == '{'); NULL if unbalanced.
static const char *match_brace(const char *p) {
    int depth = 0;
    for (; *p; p++) {
        if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; } if (!*p) return NULL; continue; }
        if (*p == '{') depth++;
        else if (*p == '}') { depth--; if (depth == 0) return p; }
    }
    return NULL;
}

// Finds the ')' matching the '(' at p.
static const char *match_paren(const char *p) {
    int depth = 0;
    for (; *p; p++) {
        if (*p == '(') depth++;
        else if (*p == ')') { depth--; if (depth == 0) return p; }
    }
    return NULL;
}

/* Collects the items of `@fields(T) [where init]` or `@methods(T, annot)`:
 * `spec` is the text inside @each's parentheses after `in`, or inside
 * @count's. Returns the count; fills `items` (borrowed) when non-NULL. */
static int collect_items(Expand *ex, const char *spec, size_t spec_len, int *out_kind,
                         const char **out_annot, ASTNode **items, int max_items) {
    char buf[256];
    size_t n = spec_len < sizeof(buf) - 1 ? spec_len : sizeof(buf) - 1;
    memcpy(buf, spec, n);
    buf[n] = 0;
    const char *p = skip_ws(buf);
    if (*p != '@') annot_error(ex->context, ex->line, 0, "@each/@count: expected @fields(T) or @methods(T, annot)");
    p++;
    char name[32];
    p += read_ident(p, name, sizeof(name));
    p = skip_ws(p);
    if (*p != '(') annot_error(ex->context, ex->line, 0, "@%s: expected '('", name);
    const char *close = match_paren(p);
    if (!close) annot_error(ex->context, ex->line, 0, "@%s: unbalanced parentheses", name);
    char inner[128];
    size_t ilen = (size_t)(close - p - 1) < sizeof(inner) - 1 ? (size_t)(close - p - 1) : sizeof(inner) - 1;
    memcpy(inner, p + 1, ilen);
    inner[ilen] = 0;
    const char *rest = skip_ws(close + 1);

    // First argument must be the target variable.
    char tvar[64];
    const char *q = skip_ws(inner);
    q += read_ident(q, tvar, sizeof(tvar));
    if (strcmp(tvar, ex->use->decl->annotation.target_var) != 0) {
        annot_error(ex->context, ex->line, 0, "@%s: expected the annotated type '%s', got '%s'", name,
                    ex->use->decl->annotation.target_var, tvar);
    }
    q = skip_ws(q);

    int count = 0;
    if (strcmp(name, "fields") == 0) {
        int where_init = 0;
        if (strncmp(rest, "where", 5) == 0) {
            const char *w = skip_ws(rest + 5);
            if (strncmp(w, "init", 4) != 0) annot_error(ex->context, ex->line, 0, "@fields: the only filter is `where init`");
            where_init = 1;
        }
        ASTNode *st = find_struct_decl(ex->program, ex->use->type_name);
        if (!st) annot_error(ex->context, ex->line, 0, "@fields: '%s' is not a struct declared in this file", ex->use->type_name);
        for (int i = 0; i < st->struct_stmt.member_count; i++) {
            ASTNode *m = st->struct_stmt.members[i];
            if (!m || m->type != AST_VAR_DECL) continue;
            if (where_init && !m->var_decl.init) continue;
            if (items && count < max_items) items[count] = m;
            count++;
        }
        *out_kind = 1;
        *out_annot = NULL;
        return count;
    }
    if (strcmp(name, "methods") == 0) {
        if (*q != ',') annot_error(ex->context, ex->line, 0, "@methods takes (T, annotation)");
        q = skip_ws(q + 1);
        static char annot[64];
        read_ident(q, annot, sizeof(annot));
        if (!annot[0]) annot_error(ex->context, ex->line, 0, "@methods: expected an annotation name");
        for (int i = 0; i < ex->program->block.count; i++) {
            ASTNode *fn = ex->program->block.stmts[i];
            if (!fn || fn->type != AST_FUNDEF || !fn->fundef.recv_type_name) continue;
            if (strcmp(fn->fundef.recv_type_name, ex->use->type_name) != 0) continue;
            if (!find_attr(fn, annot)) continue;
            if (items && count < max_items) items[count] = fn;
            count++;
        }
        *out_kind = 2;
        *out_annot = annot;
        return count;
    }
    annot_error(ex->context, ex->line, 0, "unknown directive '@%s'; expected @fields or @methods", name);
    return 0;
}

/* `@v` and `@v.x` for a loop variable. */
static int expand_loop_ref(Expand *ex, const LoopBinding *b, const char **pp, Src *out) {
    const char *p = *pp;
    if (*p != '.') {
        if (b->kind == 1) src_appendf(out, "%s", b->item->var_decl.name);
        else src_appendf(out, "%s", method_short_name(b->item));
        *pp = p;
        return 1;
    }
    p++;
    char member[32];
    p += read_ident(p, member, sizeof(member));
    if (b->kind == 1) {
        if (strcmp(member, "init") == 0) {
            if (!b->item->var_decl.init) annot_error(ex->context, ex->line, 0, "@%s.init: field '%s' has no initializer", b->var, b->item->var_decl.name);
            append_literal(ex->context, out, b->item->var_decl.init, ex->line, 0);
        } else if (strcmp(member, "type") == 0) {
            append_type(ex->context, out, b->item->var_decl.var_type, ex->line, 0);
        } else {
            annot_error(ex->context, ex->line, 0, "@%s.%s: a field has .init and .type", b->var, member);
        }
    } else {
        if (strcmp(member, "mangled") == 0) {
            src_appendf(out, "%s", b->item->fundef.name);
        } else if (strcmp(member, "args") == 0) {
            if (*p != '[') annot_error(ex->context, ex->line, 0, "@%s.args needs an index: @%s.args[0]", b->var, b->var);
            int idx = atoi(p + 1);
            while (*p && *p != ']') p++;
            if (*p == ']') p++;
            const Attribute *a = find_attr(b->item, b->annot);
            if (!a || idx < 0 || idx >= a->arg_count) {
                // Fall back to the declaration's default for that parameter.
                ASTNode *decl = resolve_annotation(ex->context, ex->program, b->annot);
                if (decl && idx >= 0 && idx < decl->annotation.param_count && decl->annotation.params[idx]->param.default_value) {
                    append_literal(ex->context, out, decl->annotation.params[idx]->param.default_value, ex->line, 0);
                } else {
                    annot_error(ex->context, ex->line, 0, "@%s.args[%d]: @%s on '%s' has no such argument", b->var, idx, b->annot, method_short_name(b->item));
                }
            } else {
                append_literal(ex->context, out, a->args[idx].value, ex->line, 0);
            }
        } else {
            annot_error(ex->context, ex->line, 0, "@%s.%s: a method has .mangled and .args[i]", b->var, member);
        }
    }
    *pp = p;
    return 1;
}

static void expand_text(Expand *ex, const char *text, size_t len, Src *out) {
    const char *p = text;
    const char *end = text + len;
    while (p < end) {
        if (*p == '\n') ex->line++;
        // Comments are copied verbatim: a `@` in one is prose, not a directive.
        if (*p == '/' && p + 1 < end && p[1] == '/') {
            const char *eol = p;
            while (eol < end && *eol != '\n') eol++;
            src_append_n(out, p, (size_t)(eol - p));
            p = eol;
            continue;
        }
        if (*p != '@') { src_append_n(out, p, 1); p++; continue; }
        p++;
        if (*p == '@') { src_append_n(out, "@", 1); p++; continue; }
        // `@{T}` splices inside an identifier: `__app_@{T}_init`. The braces
        // may also wrap a loop reference, `@{f.init}`.
        int braced = *p == '{';
        if (braced) p++;
        char name[64];
        size_t n = read_ident(p, name, sizeof(name));
        if (n == 0) { src_append_n(out, "@", 1); continue; }
        p += n;
        const char *brace_end = NULL;
        if (braced) {
            brace_end = strchr(p, '}');
            if (!brace_end) annot_error(ex->context, ex->line, 0, "@{: missing '}'");
        }

        // The target type.
        if (strcmp(name, ex->use->decl->annotation.target_var) == 0) {
            src_appendf(out, "%s", ex->use->type_name);
            if (braced) p = brace_end + 1;
            continue;
        }
        if (strcmp(name, "i") == 0) {
            if (ex->loop_depth == 0) annot_error(ex->context, ex->line, 0, "@i outside @each");
            src_appendf(out, "%d", ex->loops[ex->loop_depth - 1].index);
            if (braced) p = brace_end + 1;
            continue;
        }
        const LoopBinding *b = find_loop(ex, name);
        if (b) {
            expand_loop_ref(ex, b, &p, out);
            if (braced) p = brace_end + 1;
            continue;
        }
        if (braced) annot_error(ex->context, ex->line, 0, "@{%s}: only the type, @i or a loop variable can be braced", name);

        // Directives with parentheses.
        const char *open = skip_ws(p);
        if (*open != '(') annot_error(ex->context, ex->line, 0, "unknown directive '@%s'", name);
        const char *close = match_paren(open);
        if (!close) annot_error(ex->context, ex->line, 0, "@%s: unbalanced parentheses", name);
        const char *inner = open + 1;
        size_t ilen = (size_t)(close - inner);
        p = close + 1;

        if (strcmp(name, "name") == 0) {
            char tvar[64];
            read_ident(skip_ws(inner), tvar, sizeof(tvar));
            if (strcmp(tvar, ex->use->decl->annotation.target_var) != 0)
                annot_error(ex->context, ex->line, 0, "@name: expected '%s'", ex->use->decl->annotation.target_var);
            src_append_quoted(out, ex->use->type_name);
        } else if (strcmp(name, "arg") == 0) {
            char pname[64];
            read_ident(skip_ws(inner), pname, sizeof(pname));
            const ASTNode *value = arg_value(ex->use, pname);
            if (!value) annot_error(ex->context, ex->line, 0, "@arg(%s): @%s has no such parameter", pname, ex->use->decl->annotation.name);
            append_literal(ex->context, out, value, ex->line, 0);
        } else if (strcmp(name, "tramp") == 0) {
            char var[64];
            read_ident(skip_ws(inner), var, sizeof(var));
            const LoopBinding *m = find_loop(ex, var);
            if (!m || m->kind != 2) annot_error(ex->context, ex->line, 0, "@tramp(%s): expected a method loop variable", var);
            const char *tramp = ensure_method_trampoline(ex->context, ex->program, ex->use->type_name,
                                                         method_short_name(m->item), ex->use->line, ex->use->col);
            src_appendf(out, "%s", tramp);
        } else if (strcmp(name, "count") == 0) {
            int kind; const char *annot;
            int count = collect_items(ex, inner, ilen, &kind, &annot, NULL, 0);
            src_appendf(out, "%d", count);
        } else if (strcmp(name, "each") == 0) {
            // @each(v in <spec>) { body }
            char var[64];
            const char *q = skip_ws(inner);
            q += read_ident(q, var, sizeof(var));
            q = skip_ws(q);
            if (strncmp(q, "in", 2) != 0) annot_error(ex->context, ex->line, 0, "@each: expected `v in @fields(T)` or `v in @methods(T, annot)`");
            q = skip_ws(q + 2);
            ASTNode *items[128];
            int kind; const char *annot;
            int count = collect_items(ex, q, (size_t)(close - q), &kind, &annot, items, 128);
            const char *body_open = skip_ws(p);
            if (*body_open != '{') annot_error(ex->context, ex->line, 0, "@each: expected '{' after the loop header");
            const char *body_close = match_brace(body_open);
            if (!body_close) annot_error(ex->context, ex->line, 0, "@each: unbalanced braces in body");
            if (ex->loop_depth >= 8) annot_error(ex->context, ex->line, 0, "@each nested too deep");
            int saved_line = ex->line;
            for (int i = 0; i < count && i < 128; i++) {
                LoopBinding *lb = &ex->loops[ex->loop_depth++];
                lb->var = var;
                lb->kind = kind;
                lb->item = items[i];
                lb->annot = annot;
                lb->index = i;
                ex->line = saved_line;
                expand_text(ex, body_open + 1, (size_t)(body_close - body_open - 1), out);
                ex->loop_depth--;
            }
            // Account for the body's newlines once, whether or not it ran.
            for (const char *c = body_open; c < body_close; c++) if (*c == '\n') saved_line++;
            ex->line = saved_line;
            p = body_close + 1;
        } else {
            annot_error(ex->context, ex->line, 0, "unknown directive '@%s'", name);
        }
    }
}

static void expand_template(ParserContext *context, ASTNode *program, AnnotUse *use) {
    Expand ex = {0};
    ex.context = context;
    ex.program = program;
    ex.use = use;
    ex.line = use->decl->annotation.template_line;
    Src out = {0};
    expand_text(&ex, use->decl->annotation.template, strlen(use->decl->annotation.template), &out);
    if (out.text) parse_generated_toplevels(context, program, out.text);
    free(out.text);
}

// --- checking a use -------------------------------------------------------------------------

static void check_use(ParserContext *context, ASTNode *program, AnnotUse *use) {
    ASTNode *decl = use->decl;
    const char *aname = decl->annotation.name;
    ASTNode *target = use->target;

    int is_struct = target->type == AST_STRUCT;
    int is_method = target->type == AST_FUNDEF && target->fundef.recv_type_name != NULL;
    int is_function = target->type == AST_FUNDEF && !is_method;
    int allowed = (is_struct && (decl->annotation.target & ANNOT_ON_STRUCT)) ||
                  (is_method && (decl->annotation.target & ANNOT_ON_METHOD)) ||
                  (is_function && (decl->annotation.target & ANNOT_ON_FUNCTION));
    if (!allowed) {
        const char *want = decl->annotation.target == ANNOT_ON_STRUCT ? "a struct" :
                           decl->annotation.target == ANNOT_ON_METHOD ? "a method" : "a function";
        annot_error(context, use->line, use->col, "@%s applies to %s, not to this %s", aname, want,
                    is_struct ? "struct" : is_method ? "method" : "function");
    }
    if (is_struct) {
        if (!target->struct_stmt.name || !target->struct_stmt.name[0])
            annot_error(context, use->line, use->col, "@%s needs a named struct", aname);
        use->type_name = target->struct_stmt.name;
    } else if (is_method) {
        use->type_name = target->fundef.recv_type_name;
    } else {
        use->type_name = target->fundef.name;
    }

    if (decl->annotation.of_annotation) {
        ASTNode *owner = is_method ? find_struct_decl(program, use->type_name) : NULL;
        if (!owner || !find_attr(owner, decl->annotation.of_annotation)) {
            annot_error(context, use->line, use->col, "@%s goes on a method of a @%s struct; '%s' is not one",
                        aname, decl->annotation.of_annotation, use->type_name);
        }
    }
    if (is_method) require_pointer_receiver(context, target, use->line, use->col);

    for (int i = 0; i < decl->annotation.require_count; i++) {
        const char *m = decl->annotation.requires[i];
        const MethodDef *def = find_method(context, use->type_name, m);
        if (!def) {
            annot_error(context, use->line, use->col, "@%s struct '%s' needs a method '%s'", aname, use->type_name, m);
        }
        // A required method is one the template calls through the instance
        // pointer, so it takes the same receiver as a handler.
        require_pointer_receiver(context, def->fundef, use->line, use->col);
    }
    bind_arguments(context, use);
}

static void clear_attrs(ASTNode *node) {
    free_attributes(node->attrs, node->attr_count);
    node->attrs = NULL;
    node->attr_count = 0;
}

void lower_annotations(ParserContext *context, ASTNode *program) {
    if (!program || program->type != AST_BLOCK) return;

    // Resolve and check every use first: expansion reads other declarations'
    // attributes (@methods(T, timer)), so nothing is cleared until the end.
    int count = program->block.count;
    AnnotUse *uses = NULL;
    int use_count = 0;
    for (int i = 0; i < count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->attr_count == 0) continue;
        for (int k = 0; k < node->attr_count; k++) {
            const Attribute *a = &node->attrs[k];
            ASTNode *decl = resolve_annotation(context, program, a->name);
            if (!decl) {
                annot_error(context, a->line, a->col,
                            "unknown annotation '@%s'; declare it with `annotation %s ...` or import it",
                            a->name, a->name);
            }
            uses = realloc(uses, sizeof(AnnotUse) * (use_count + 1));
            AnnotUse *use = &uses[use_count++];
            memset(use, 0, sizeof(*use));
            use->decl = decl;
            use->attr = a;
            use->target = node;
            use->line = a->line;
            use->col = a->col;
            check_use(context, program, use);
        }
    }

    for (int i = 0; i < use_count; i++) {
        if (uses[i].decl->annotation.template) expand_template(context, program, &uses[i]);
    }

    for (int i = 0; i < count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (node && node->attr_count > 0) clear_attrs(node);
    }
    for (int i = 0; i < use_count; i++) free(uses[i].arg_values);
    free(uses);
}

// --- default arguments ------------------------------------------------------------

/* The declaration a call by (post-rewrite) name resolves to: a function in
 * this file, else an exported function of an imported module -- reached as
 * `pkg_name` through a package import or by bare name through a symbol-list
 * import. NULL when unknown (an indirect call through a variable, say). */
static ASTNode *callee_declaration(ParserContext *context, ASTNode *program, const char *name) {
    ASTNode *local = find_function(context, name);
    if (local && local->type == AST_FUNDEF) return local;

    FrontendSession *session = context->session;
    if (!session || !session->loader) return NULL;
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->type != AST_IMPORT || !node->import_stmt.path) continue;
        if (!module_loader_is_mylang_source(node->import_stmt.path)) continue;
        Module *mod = module_loader_load(session->loader, context->module.filename, node->import_stmt.path);
        if (!mod || mod->state != MODULE_LOADED) continue;

        const char *bare = name;
        if (node->import_stmt.symbol_count == 0 && mod->package_name) {
            size_t plen = strlen(mod->package_name);
            if (strncmp(name, mod->package_name, plen) != 0 || name[plen] != '_') continue;
            bare = name + plen + 1;
        }
        ModuleSymbol *sym = resolver_lookup_import_symbol(node, mod, bare);
        if (sym && sym->kind == SYMBOL_FUNCTION && sym->declaration &&
            sym->declaration->type == AST_FUNDEF) {
            return sym->declaration;
        }
    }
    return NULL;
}

static void fill_call_defaults(ParserContext *context, ASTNode *program, ASTNode *call) {
    if (call->call.recv || call->call.type_arg_count > 0 || !call->call.name) return;
    ASTNode *decl = callee_declaration(context, program, call->call.name);
    if (!decl || decl->fundef.is_variadic) return;
    int want = decl->fundef.param_count;
    int have = call->call.arg_count;
    if (have >= want) return;
    for (int i = have; i < want; i++) {
        ASTNode *p = decl->fundef.params[i];
        if (!p || p->type != AST_PARAM || !p->param.default_value) return; // semantic reports the count
    }
    call->call.args = realloc(call->call.args, sizeof(ASTNode *) * want);
    for (int i = have; i < want; i++) {
        ASTNode *value = ast_clone(decl->fundef.params[i]->param.default_value);
        value->line = call->line;
        value->col = call->col;
        call->call.args[i] = value;
    }
    call->call.arg_count = want;
}

typedef struct {
    ParserContext *context;
    ASTNode *program;
} DefaultsWalk;

static void fill_defaults_visit(ASTNode **slot, void *data) {
    ASTNode *node = slot ? *slot : NULL;
    if (!node) return;
    DefaultsWalk *walk = data;
    ast_visit_children(node, fill_defaults_visit, data);
    if (node->type == AST_CALL) fill_call_defaults(walk->context, walk->program, node);
}

/* Appends the `= literal` defaults a positional call left out, for every
 * callee whose declaration is in reach. Runs after name rewriting, so the
 * call names are final. */
void fill_default_arguments(ParserContext *context, ASTNode *program) {
    if (!program || program->type != AST_BLOCK) return;
    DefaultsWalk walk = { context, program };
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->type != AST_FUNDEF) continue;
        fill_defaults_visit(&program->block.stmts[i], &walk);
    }
}
