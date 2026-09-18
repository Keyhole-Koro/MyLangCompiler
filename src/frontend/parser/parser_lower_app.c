#include "mylang/frontend/parser_app_internal.h"
#include "mylang/frontend/parser_dom_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/lexer.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/resolver.h"

#include <stdarg.h>
#include <ctype.h>
#include <strings.h>

/* Lowers attributes into ordinary MyLang declarations.
 *
 * `@app struct Counter { ... };` marks a struct as an application the OS
 * framework can create, mount and dispatch events to. The framework never
 * sees the struct: it works through a descriptor table of i32 words that this
 * pass generates (`__app_Counter_desc()`), plus trampolines that turn the
 * uniform handler ABI `void (i32 owner, i32 id, i32 arg)` back into method
 * calls on the instance `owner` points at:
 *
 *     @app struct Counter { i32 clicks = 0; i32 label; };
 *     i32  (Counter *c) view()        { return <Window ...>...</Window>; }
 *     @timer(100)
 *     void (Counter *c) poll()        { ... }
 *
 *     void __app_Counter_init(i32 self)   { Counter *p = (Counter*)self; p->clicks = 0; }
 *     i32  __app_Counter_view(i32 self)   { Counter *p = (Counter*)self; return p->view(); }
 *     void Counter__poll__tramp(i32 owner, i32 id, i32 arg) { Counter *p = (Counter*)owner; p->poll(); }
 *     export i32* __app_Counter_desc()    { ...fills a static i32 table...; return &table[0]; }
 *
 * The generated code is written as MyLang source and parsed with the ordinary
 * top-level parser, so it goes through method resolution, semantic checking
 * and codegen like anything the author wrote. The descriptor layout is the
 * contract with the OS framework (system/MyOS/src/app/app.mln):
 *
 *     [0] name (char*)        [1] flags (1 = single instance)   [2] sizeof(T)
 *     [3] init  void(self)    [4] view  i32(self) -> window id
 *     [5] open  handler|0     [6] on_close handler|0            [7] task handler|0
 *     [8] timer count N       [9] key count M
 *     [10 ..] N x (interval, handler), then M x (mods, code, handler)
 *
 * where every handler is `void (i32 owner, i32 id, i32 arg)`. The same
 * trampolines back DOM markup handlers (`onClick={c.click}`), see
 * parser_lower_dom.c, which calls ensure_method_trampoline().
 */

#define APP_TABLE_WORDS 64
#define APP_TABLE_FIXED 10
#define APP_FLAG_SINGLE 1

static void app_error(ParserContext *context, int line, int col, const char *fmt, ...) {
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

/* Writes the argument list a trampoline hands to a method with `param_count`
 * parameters after its receiver: (), (id) or (id, arg). */
static const char *tramp_args(ParserContext *context, const ASTNode *fn, int param_count, int line, int col) {
    switch (param_count) {
    case 0: return "";
    case 1: return "id";
    case 2: return "id, arg";
    default:
        app_error(context, line, col,
                  "handler '%s' takes %d parameters; a handler takes at most (i32 id, i32 arg)",
                  method_short_name(fn), param_count);
        return NULL;
    }
}

/* The method's receiver must be a pointer (`T *self`): a `ref mut T` receiver
 * cannot be built from the i32 the dispatcher hands over, and the owner
 * pointer is what identifies the instance. */
static void require_pointer_receiver(ParserContext *context, const ASTNode *fn, int line, int col) {
    ASTNode *recv = fn->fundef.param_count > 0 ? fn->fundef.params[0] : NULL;
    ASTNode *type = recv && recv->type == AST_PARAM ? recv->param.type : NULL;
    if (!type || type->type != AST_TYPE || type->type_node.pointer_level != 1 ||
        type->type_node.ref_kind != REFKIND_NONE) {
        app_error(context, line, col,
                  "handler method '%s' must take a pointer receiver, `(%s *self)`",
                  method_short_name(fn), fn->fundef.recv_type_name ? fn->fundef.recv_type_name : "T");
    }
}

const char *ensure_method_trampoline(ParserContext *context, ASTNode *program,
                                     const char *type_name, const char *method_name,
                                     int line, int col) {
    const MethodDef *m = find_method(context, type_name, method_name);
    if (!m) {
        app_error(context, line, col, "type '%s' has no method '%s'", type_name, method_name);
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

// --- @app --------------------------------------------------------------------------

typedef struct {
    ASTNode *fn;
    int interval;
} AppTimer;

typedef struct {
    ASTNode *fn;
    int mods;
    int code;
} AppKey;

typedef struct {
    ASTNode *decl;          // the @app struct
    int line;               // of its @app attribute, for diagnostics
    int col;
    const char *type_name;
    const char *display_name;
    int flags;
    ASTNode *open_fn;
    ASTNode *close_fn;
    ASTNode *task_fn;
    AppTimer timers[16];
    int timer_count;
    AppKey keys[16];
    int key_count;
} AppInfo;

static const Attribute *find_attr(const ASTNode *node, const char *name) {
    for (int i = 0; i < node->attr_count; i++) {
        if (strcmp(node->attrs[i].name, name) == 0) return &node->attrs[i];
    }
    return NULL;
}

static void read_app_attr(ParserContext *context, const Attribute *a, AppInfo *info) {
    for (int i = 0; i < a->arg_count; i++) {
        const AttrArg *arg = &a->args[i];
        if (!arg->name) {
            const char *flag = arg->value && arg->value->type == AST_IDENTIFIER ? arg->value->identifier.name : NULL;
            if (flag && strcmp(flag, "single") == 0) { info->flags |= APP_FLAG_SINGLE; continue; }
            app_error(context, arg->line, arg->col, "@app: unknown flag; the only flag is `single`");
        }
        if (strcmp(arg->name, "name") == 0) {
            if (!arg->value || arg->value->type != AST_STRING_LITERAL)
                app_error(context, arg->line, arg->col, "@app: `name` takes a string literal");
            info->display_name = arg->value->string_literal.value;
            continue;
        }
        app_error(context, arg->line, arg->col, "@app: unknown argument '%s'; known: single, name = \"...\"", arg->name);
    }
}

/* "Ctrl+S", "Shift+Enter", "F5" -> (mods, code) in the kernel's keyboard.mln
 * encoding: letters are their lower-case ASCII code, named keys as below. */
static int named_key_code(const char *name) {
    static const struct { const char *name; int code; } keys[] = {
        {"backspace", 8}, {"tab", 9}, {"enter", 13}, {"return", 13}, {"esc", 27}, {"escape", 27},
        {"space", 32}, {"delete", 127}, {"del", 127},
        {"left", 0x101}, {"right", 0x102}, {"up", 0x103}, {"down", 0x104},
        {"home", 0x105}, {"end", 0x106}, {"pageup", 0x107}, {"pagedown", 0x108},
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (strcasecmp(keys[i].name, name) == 0) return keys[i].code;
    }
    if ((name[0] == 'F' || name[0] == 'f') && isdigit((unsigned char)name[1])) {
        int n = atoi(name + 1);
        if (n >= 1 && n <= 12) return 0x120 + n;
    }
    if (strlen(name) == 1 && isprint((unsigned char)name[0])) return tolower((unsigned char)name[0]);
    return -1;
}

static void parse_key_spec(ParserContext *context, const Attribute *a, int *out_mods, int *out_code) {
    if (a->arg_count != 1 || a->args[0].name || !a->args[0].value ||
        a->args[0].value->type != AST_STRING_LITERAL) {
        app_error(context, a->line, a->col, "@key takes one string, e.g. @key(\"Ctrl+S\")");
    }
    const char *spec = a->args[0].value->string_literal.value;
    int mods = 0;
    int code = -1;
    char part[32];
    const char *p = spec;
    while (*p) {
        const char *plus = strchr(p, '+');
        size_t n = plus ? (size_t)(plus - p) : strlen(p);
        // A trailing "+" names the plus key itself ("Ctrl++").
        if (n == 0 && plus && plus[1] == 0) { n = 1; plus = NULL; }
        if (n == 0 || n >= sizeof(part)) app_error(context, a->line, a->col, "@key: malformed key \"%s\"", spec);
        memcpy(part, p, n);
        part[n] = 0;
        p = plus ? plus + 1 : p + n;
        int is_last = *p == 0;
        if (!is_last) {
            if (strcasecmp(part, "ctrl") == 0) mods |= 2;
            else if (strcasecmp(part, "shift") == 0) mods |= 1;
            else if (strcasecmp(part, "alt") == 0) mods |= 4;
            else app_error(context, a->line, a->col, "@key: unknown modifier '%s' in \"%s\" (Ctrl, Shift, Alt)", part, spec);
        } else {
            code = named_key_code(part);
            if (code < 0) app_error(context, a->line, a->col, "@key: unknown key '%s' in \"%s\"", part, spec);
        }
    }
    if (code < 0) app_error(context, a->line, a->col, "@key: \"%s\" names no key", spec);
    *out_mods = mods;
    *out_code = code;
}

static int method_param_count(const ASTNode *fn) {
    return fn->fundef.param_count - 1;
}

static void check_arity(ParserContext *context, const ASTNode *fn, const Attribute *a, int max) {
    if (method_param_count(fn) > max) {
        app_error(context, a->line, a->col, "@%s: method '%s' may take at most %d parameter%s besides its receiver",
                  a->name, method_short_name(fn), max, max == 1 ? "" : "s");
    }
}

/* Collects the attributed methods of one @app type. */
static void collect_methods(ParserContext *context, ASTNode *program, AppInfo *info) {
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *fn = program->block.stmts[i];
        if (!fn || fn->type != AST_FUNDEF || fn->attr_count == 0) continue;
        if (!fn->fundef.recv_type_name || strcmp(fn->fundef.recv_type_name, info->type_name) != 0) continue;
        for (int k = 0; k < fn->attr_count; k++) {
            const Attribute *a = &fn->attrs[k];
            require_pointer_receiver(context, fn, a->line, a->col);
            if (strcmp(a->name, "timer") == 0) {
                if (a->arg_count != 1 || a->args[0].name || !a->args[0].value || a->args[0].value->type != AST_NUMBER)
                    app_error(context, a->line, a->col, "@timer takes one number: the period in milliseconds");
                check_arity(context, fn, a, 1);
                if (info->timer_count >= 16) app_error(context, a->line, a->col, "@timer: too many timers on '%s'", info->type_name);
                info->timers[info->timer_count].fn = fn;
                info->timers[info->timer_count].interval = atoi(a->args[0].value->number.value);
                info->timer_count++;
            } else if (strcmp(a->name, "key") == 0) {
                check_arity(context, fn, a, 2);
                if (info->key_count >= 16) app_error(context, a->line, a->col, "@key: too many keys on '%s'", info->type_name);
                AppKey *key = &info->keys[info->key_count++];
                key->fn = fn;
                parse_key_spec(context, a, &key->mods, &key->code);
            } else if (strcmp(a->name, "open") == 0) {
                if (info->open_fn) app_error(context, a->line, a->col, "@open: '%s' already has an @open method", info->type_name);
                if (method_param_count(fn) != 1)
                    app_error(context, a->line, a->col, "@open: method '%s' must take exactly one parameter, the path (char *)", method_short_name(fn));
                info->open_fn = fn;
            } else if (strcmp(a->name, "on_close") == 0) {
                if (info->close_fn) app_error(context, a->line, a->col, "@on_close: '%s' already has an @on_close method", info->type_name);
                check_arity(context, fn, a, 1);
                info->close_fn = fn;
            } else if (strcmp(a->name, "task") == 0) {
                if (info->task_fn) app_error(context, a->line, a->col, "@task: '%s' already has a @task method", info->type_name);
                check_arity(context, fn, a, 0);
                info->task_fn = fn;
            } else {
                app_error(context, a->line, a->col, "unknown attribute '@%s' on method '%s'", a->name, method_short_name(fn));
            }
        }
    }
}

static const char *tramp_for(ParserContext *context, ASTNode *program, const AppInfo *info, const ASTNode *fn) {
    return ensure_method_trampoline(context, program, info->type_name, method_short_name(fn), fn->line, fn->col);
}

/* `@open` hands the path over in `arg`, so its trampoline differs from the
 * generic (id, arg) shape. */
static const char *open_tramp_for(ParserContext *context, ASTNode *program, const AppInfo *info) {
    static char name[300];
    snprintf(name, sizeof(name), "%s__tramp", info->open_fn->fundef.name);
    if (find_function(context, name)) return name;
    Src src = {0};
    src_appendf(&src, "void %s(i32 owner, i32 id, i32 arg) { %s *p = (%s*)owner; p->%s((char*)arg); }\n",
                name, info->type_name, info->type_name, method_short_name(info->open_fn));
    parse_generated_toplevels(context, program, src.text);
    free(src.text);
    return name;
}

static void emit_field_init(ParserContext *context, Src *src, const ASTNode *member) {
    if (!member || member->type != AST_VAR_DECL || !member->var_decl.init) return;
    const ASTNode *init = member->var_decl.init;
    if (init->type == AST_UNARY && init->unary.op == SUB && init->unary.operand &&
        init->unary.operand->type == AST_NUMBER) {
        src_appendf(src, " p->%s = -%s;", member->var_decl.name, init->unary.operand->number.value);
        return;
    }
    if (init->type == AST_NUMBER) {
        src_appendf(src, " p->%s = %s;", member->var_decl.name, init->number.value);
        return;
    }
    if (init->type == AST_STRING_LITERAL) {
        src_appendf(src, " p->%s = ", member->var_decl.name);
        src_append_quoted(src, init->string_literal.value);
        src_appendf(src, ";");
        return;
    }
    if (init->type == AST_CHAR_LITERAL) {
        src_appendf(src, " p->%s = '%s';", member->var_decl.name, init->char_literal.value);
        return;
    }
    app_error(context, member->line, member->col,
              "@app: field '%s' of '%s' has a non-literal initializer; only literals are supported",
              member->var_decl.name, "struct");
}

static void lower_one_app(ParserContext *context, ASTNode *program, AppInfo *info) {
    const char *T = info->type_name;
    if (!find_method(context, T, "view")) {
        app_error(context, info->line, info->col,
                  "@app struct '%s' needs a view method: `i32 (%s *self) view()`", T, T);
    }
    const MethodDef *view = find_method(context, T, "view");
    require_pointer_receiver(context, view->fundef, info->line, info->col);
    if (method_param_count(view->fundef) != 0) {
        app_error(context, view->fundef->line, view->fundef->col, "@app: '%s.view' takes no parameters", T);
    }
    collect_methods(context, program, info);

    Src src = {0};

    src_appendf(&src, "void __app_%s_init(i32 self) { %s *p = (%s*)self;", T, T, T);
    for (int i = 0; i < info->decl->struct_stmt.member_count; i++) {
        emit_field_init(context, &src, info->decl->struct_stmt.members[i]);
    }
    src_appendf(&src, " }\n");
    src_appendf(&src, "i32 __app_%s_view(i32 self) { %s *p = (%s*)self; return p->view(); }\n", T, T, T);
    src_appendf(&src, "i32 __app_%s_table[%d];\n", T, APP_TABLE_WORDS);
    parse_generated_toplevels(context, program, src.text);
    src.len = 0;
    src.text[0] = 0;

    const char *open_t = info->open_fn ? open_tramp_for(context, program, info) : NULL;
    const char *close_t = info->close_fn ? tramp_for(context, program, info, info->close_fn) : NULL;
    const char *task_t = info->task_fn ? tramp_for(context, program, info, info->task_fn) : NULL;
    const char *timer_t[16];
    for (int i = 0; i < info->timer_count; i++) timer_t[i] = strdup(tramp_for(context, program, info, info->timers[i].fn));
    const char *key_t[16];
    for (int i = 0; i < info->key_count; i++) key_t[i] = strdup(tramp_for(context, program, info, info->keys[i].fn));

    int words = APP_TABLE_FIXED + info->timer_count * 2 + info->key_count * 3;
    if (words > APP_TABLE_WORDS) {
        app_error(context, info->line, info->col, "@app: '%s' declares too many timers and keys", T);
    }

    src_appendf(&src, "export i32* __app_%s_desc() {\n", T);
    src_appendf(&src, "  i32 *t = &__app_%s_table[0];\n", T);
    src_appendf(&src, "  %s probe;\n", T);
    src_appendf(&src, "  t[0] = (i32)");
    src_append_quoted(&src, info->display_name);
    src_appendf(&src, ";\n");
    src_appendf(&src, "  t[1] = %d;\n", info->flags);
    src_appendf(&src, "  t[2] = sizeof(probe);\n");
    src_appendf(&src, "  t[3] = __app_%s_init;\n", T);
    src_appendf(&src, "  t[4] = __app_%s_view;\n", T);
    if (open_t) src_appendf(&src, "  t[5] = %s;\n", open_t); else src_appendf(&src, "  t[5] = 0;\n");
    if (close_t) src_appendf(&src, "  t[6] = %s;\n", close_t); else src_appendf(&src, "  t[6] = 0;\n");
    if (task_t) src_appendf(&src, "  t[7] = %s;\n", task_t); else src_appendf(&src, "  t[7] = 0;\n");
    src_appendf(&src, "  t[8] = %d;\n", info->timer_count);
    src_appendf(&src, "  t[9] = %d;\n", info->key_count);
    int w = APP_TABLE_FIXED;
    for (int i = 0; i < info->timer_count; i++) {
        src_appendf(&src, "  t[%d] = %d;\n  t[%d] = %s;\n", w, info->timers[i].interval, w + 1, timer_t[i]);
        w += 2;
    }
    for (int i = 0; i < info->key_count; i++) {
        src_appendf(&src, "  t[%d] = %d;\n  t[%d] = %d;\n  t[%d] = %s;\n",
                    w, info->keys[i].mods, w + 1, info->keys[i].code, w + 2, key_t[i]);
        w += 3;
    }
    src_appendf(&src, "  return t;\n}\n");
    parse_generated_toplevels(context, program, src.text);
    free(src.text);
    for (int i = 0; i < info->timer_count; i++) free((char *)timer_t[i]);
    for (int i = 0; i < info->key_count; i++) free((char *)key_t[i]);
}

/* Every attribute the program carries must be consumed here; anything left
 * over is unknown or on the wrong kind of declaration. */
static void reject_unconsumed_attributes(ParserContext *context, ASTNode *program) {
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->attr_count == 0) continue;
        const Attribute *a = &node->attrs[0];
        if (node->type == AST_STRUCT) {
            app_error(context, a->line, a->col, "unknown attribute '@%s' on struct '%s'; only @app applies to a struct",
                      a->name, node->struct_stmt.name);
        }
        if (node->type == AST_FUNDEF && node->fundef.recv_type_name) {
            app_error(context, a->line, a->col,
                      "'@%s' on method '%s': its receiver type '%s' is not an @app struct",
                      a->name, method_short_name(node), node->fundef.recv_type_name);
        }
        app_error(context, a->line, a->col, "attribute '@%s' is not allowed here; attributes apply to @app structs and their methods", a->name);
    }
}

static void clear_attrs(ASTNode *node) {
    free_attributes(node->attrs, node->attr_count);
    node->attrs = NULL;
    node->attr_count = 0;
}

void lower_app_program(ParserContext *context, ASTNode *program) {
    if (!program || program->type != AST_BLOCK) return;

    // Snapshot the declarations: lowering appends generated ones.
    int count = program->block.count;
    for (int i = 0; i < count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->type != AST_STRUCT) continue;
        const Attribute *app = find_attr(node, "app");
        if (!app) continue;
        if (node->attr_count != 1) {
            app_error(context, node->attrs[0].line, node->attrs[0].col, "a struct takes only the @app attribute");
        }
        if (!node->struct_stmt.name || !node->struct_stmt.name[0]) {
            app_error(context, app->line, app->col, "@app needs a named struct");
        }
        AppInfo info = {0};
        info.decl = node;
        info.line = app->line;
        info.col = app->col;
        info.type_name = node->struct_stmt.name;
        info.display_name = node->struct_stmt.name;
        read_app_attr(context, app, &info);
        lower_one_app(context, program, &info);

        // Consumed: the struct's own attribute and its methods'.
        for (int j = 0; j < program->block.count; j++) {
            ASTNode *fn = program->block.stmts[j];
            if (fn && fn->type == AST_FUNDEF && fn->attr_count > 0 && fn->fundef.recv_type_name &&
                strcmp(fn->fundef.recv_type_name, info.type_name) == 0) {
                clear_attrs(fn);
            }
        }
        clear_attrs(node);
    }
    reject_unconsumed_attributes(context, program);
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
