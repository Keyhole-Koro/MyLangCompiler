#include "mylang/frontend/parser_annot_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/lexer.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/resolver.h"

#include <stdarg.h>
#include <ctype.h>

/* Annotations: `@a(args)` on a function or method is metadata.
 *
 * An annotation is declared as a function prototype whose first three
 * parameters are fixed -- the annotated function, its receiver type's name
 * and that type's size -- followed by the annotation's own arguments:
 *
 *     // annotations.mln
 *     export void timer(i32 fn, char *type, i32 size, i32 ms);
 *
 *     // terminal.dom.mln
 *     import { app, timer } from "annotations.mln";
 *     @timer(100)
 *     void (Terminal *t) poll() { ... }
 *
 * The compiler never calls `timer`. It checks the use against the
 * declaration (resolvable: local or a symbol-list import; first parameters
 * (i32, char*, i32); the written arguments matched to the rest by name,
 * position or a bare bool parameter's name as a flag, defaults filling the
 * gaps) and records one row per use in the module's generated table:
 *
 *     export i32* __annotations() -> [count, row0..., row1...]
 *     row: [name char*, fn, type char*, size, argc, arg0, arg1, arg2]
 *
 * Whoever reads the table decides what "timer" means and when -- for MyOS,
 * the application framework at boot (system/MyAppFramework/src/meta.mln).
 * A module that declares
 *
 *     extern i32* __annotations_table(i32 m);
 *
 * and reaches annotated modules through its imports receives its definition
 * here: it hands back the table of the m-th such module (0 past the end),
 * so the program's root collects every module's rows without a manifest.
 * A module that reaches none (a reader like the framework's meta.mln) keeps
 * the prototype and links against the root's definition.
 *
 * Because the calling convention ignores extra arguments, a method
 * `(T *self, i32 id)` can be called through the DOM's uniform handler shape
 * `(owner, id, arg)` directly -- a table entry is the real method, not a
 * wrapper. A method reached this way must take a pointer receiver.
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

/* A method reached through the handler ABI is called with the instance's
 * address as its first argument, so its receiver must be one that is an
 * address underneath: a pointer (`T *self`) or a reference (`ref T`,
 * `ref mut T`). A value receiver would be a move, which makes no sense for
 * a callback invoked on a persistent instance. */
static void require_pointer_receiver(ParserContext *context, const ASTNode *fn, int line, int col) {
    ASTNode *recv = fn->fundef.param_count > 0 ? fn->fundef.params[0] : NULL;
    ASTNode *type = recv && recv->type == AST_PARAM ? recv->param.type : NULL;
    int by_pointer = type && type->type == AST_TYPE && type->type_node.pointer_level == 1 &&
                     type->type_node.ref_kind == REFKIND_NONE;
    int by_ref = type && type->type == AST_TYPE && type->type_node.pointer_level == 0 &&
                 type->type_node.ref_kind != REFKIND_NONE;
    if (!by_pointer && !by_ref) {
        annot_error(context, line, col,
                    "handler method '%s' must take its receiver by pointer or reference, `(%s *self)` or `(ref mut %s self)`",
                    method_short_name(fn), fn->fundef.recv_type_name ? fn->fundef.recv_type_name : "T",
                    fn->fundef.recv_type_name ? fn->fundef.recv_type_name : "T");
    }
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

// --- annotation calls -------------------------------------------------------------

/* The function `@name` refers to: one in this file, else one exported by a
 * module named in a symbol-list import. `link_name` is what the generated
 * call spells (the exported, package-mangled name for an import). */
static ASTNode *resolve_annotation(ParserContext *context, ASTNode *program, const char *name,
                                   const char **link_name) {
    ASTNode *local = find_function(context, name);
    if (local && local->type == AST_FUNDEF) { *link_name = local->fundef.name; return local; }

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
        if (sym && sym->kind == SYMBOL_FUNCTION && sym->declaration &&
            sym->declaration->type == AST_FUNDEF) {
            *link_name = sym->link_name ? sym->link_name : sym->declaration->fundef.name;
            return sym->declaration;
        }
    }
    return NULL;
}

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

static int param_is_plain(const ASTNode *param, const char *base) {
    const ASTNode *type = param->param.type;
    return type && type->type == AST_TYPE && type->type_node.pointer_level == 0 &&
           strcmp(param_base_type(param), base) == 0;
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
    annot_error(context, line, col, "only a literal can be used as an annotation argument");
}

#define ANNOT_FIXED_PARAMS 3
#define ANNOT_MAX_ARGS 3
#define ANNOT_ROW_WORDS 8
#define ANNOT_TABLE_FN "__annotations"
#define ANNOT_AGGREGATE_FN "__annotations_table"

/* Appends the row for one attribute: `t[i] = ...;` for each of its words. */
static void emit_annotation_row(ParserContext *context, ASTNode *program, Src *out, int base,
                                ASTNode *target, const Attribute *attr) {
    const char *link_name = NULL;
    ASTNode *decl = resolve_annotation(context, program, attr->name, &link_name);
    if (!decl) {
        annot_error(context, attr->line, attr->col,
                    "unknown annotation '@%s'; an annotation is a function prototype, declared here or imported "
                    "with `import { %s } from \"...\"`", attr->name, attr->name);
    }
    if (target->type != AST_FUNDEF) {
        annot_error(context, attr->line, attr->col, "@%s: annotations go on functions and methods", attr->name);
    }
    int n = decl->fundef.param_count;
    if (n < ANNOT_FIXED_PARAMS ||
        !param_is_plain(decl->fundef.params[0], "i32") ||
        !param_is_string(decl->fundef.params[1]) ||
        !param_is_plain(decl->fundef.params[2], "i32")) {
        annot_error(context, attr->line, attr->col,
                    "'%s' cannot be used as an annotation: its first parameters must be "
                    "(i32 fn, char *type, i32 size)", attr->name);
    }
    if (decl->fundef.is_variadic || n > ANNOT_FIXED_PARAMS + ANNOT_MAX_ARGS) {
        annot_error(context, attr->line, attr->col,
                    "'%s' cannot be used as an annotation: at most %d arguments after (fn, type, size)",
                    attr->name, ANNOT_MAX_ARGS);
    }

    int is_method = target->fundef.recv_type_name != NULL;
    if (is_method) require_pointer_receiver(context, target, attr->line, attr->col);

    // Bind the written arguments to the parameters after the fixed three.
    const ASTNode **values = calloc((size_t)n, sizeof(ASTNode *));
    static ASTNode one_literal;
    one_literal.type = AST_NUMBER;
    one_literal.number.value = "1";
    int positional = ANNOT_FIXED_PARAMS;
    for (int i = 0; i < attr->arg_count; i++) {
        const AttrArg *arg = &attr->args[i];
        const ASTNode *value = arg->value;
        int slot = -1;
        if (arg->name) {
            for (int p = ANNOT_FIXED_PARAMS; p < n; p++) {
                if (strcmp(decl->fundef.params[p]->param.name, arg->name) == 0) { slot = p; break; }
            }
            if (slot < 0) annot_error(context, arg->line, arg->col, "@%s has no parameter '%s'", attr->name, arg->name);
        } else if (value && value->type == AST_IDENTIFIER) {
            for (int p = ANNOT_FIXED_PARAMS; p < n; p++) {
                if (param_is_bool(decl->fundef.params[p]) &&
                    strcmp(decl->fundef.params[p]->param.name, value->identifier.name) == 0) { slot = p; break; }
            }
            if (slot < 0) annot_error(context, arg->line, arg->col, "@%s: unknown flag '%s'", attr->name, value->identifier.name);
            value = &one_literal;
        } else {
            while (positional < n && values[positional]) positional++;
            if (positional >= n) {
                annot_error(context, arg->line, arg->col, "@%s takes %d argument%s", attr->name,
                            n - ANNOT_FIXED_PARAMS, n - ANNOT_FIXED_PARAMS == 1 ? "" : "s");
            }
            slot = positional;
        }
        if (values[slot]) annot_error(context, arg->line, arg->col, "@%s: '%s' given twice", attr->name, decl->fundef.params[slot]->param.name);
        const ASTNode *param = decl->fundef.params[slot];
        int ok;
        if (param_is_string(param)) ok = value && value->type == AST_STRING_LITERAL;
        else if (param_is_bool(param)) ok = value && value->type == AST_NUMBER;
        else ok = value && (value->type == AST_NUMBER || value->type == AST_CHAR_LITERAL ||
                            (value->type == AST_UNARY && value->unary.op == SUB));
        if (!ok) {
            annot_error(context, arg->line, arg->col, "@%s: argument '%s' must be a %s literal", attr->name,
                        param->param.name, param_is_string(param) ? "string" : param_is_bool(param) ? "bool" : "number");
        }
        values[slot] = value;
    }
    for (int p = ANNOT_FIXED_PARAMS; p < n; p++) {
        if (!values[p]) {
            values[p] = decl->fundef.params[p]->param.default_value;
            if (!values[p]) annot_error(context, attr->line, attr->col, "@%s is missing argument '%s'", attr->name, decl->fundef.params[p]->param.name);
        }
    }

    src_appendf(out, "    t[%d] = (i32)", base);
    src_append_quoted(out, attr->name);
    src_appendf(out, ";\n    t[%d] = %s;\n", base + 1, target->fundef.name);
    if (is_method) {
        src_appendf(out, "    t[%d] = (i32)", base + 2);
        src_append_quoted(out, target->fundef.recv_type_name);
        src_appendf(out, ";\n    t[%d] = sizeof(__annot_probe_%s);\n", base + 3, target->fundef.recv_type_name);
    } else {
        src_appendf(out, "    t[%d] = (i32)\"\";\n    t[%d] = 0;\n", base + 2, base + 3);
    }
    src_appendf(out, "    t[%d] = %d;\n", base + 4, n - ANNOT_FIXED_PARAMS);
    for (int k = 0; k < ANNOT_MAX_ARGS; k++) {
        int p = ANNOT_FIXED_PARAMS + k;
        src_appendf(out, "    t[%d] = ", base + 5 + k);
        if (p < n) {
            if (param_is_string(decl->fundef.params[p])) src_appendf(out, "(i32)");
            append_literal(context, out, values[p], attr->line, attr->col);
        } else {
            src_appendf(out, "0");
        }
        src_appendf(out, ";\n");
    }
    free(values);
}

static void clear_attrs(ASTNode *node) {
    free_attributes(node->attrs, node->attr_count);
    node->attrs = NULL;
    node->attr_count = 0;
}

/* Does a parsed (not lowered) module carry any attributed declaration? */
static int module_has_annotations(const Module *mod) {
    if (!mod || !mod->program || mod->program->type != AST_BLOCK) return 0;
    for (int i = 0; i < mod->program->block.count; i++) {
        ASTNode *node = mod->program->block.stmts[i];
        if (node && node->attr_count > 0) return 1;
    }
    return 0;
}

/* The aggregate: defined in a module that declared the extern prototype,
 * over every annotated module the loader reached from it. */
static void emit_aggregate(ParserContext *context, ASTNode *program, int proto_index) {
    FrontendSession *session = context->session;
    ModuleLoader *loader = session ? session->loader : NULL;
    ModuleGraph *graph = loader ? loader->graph : NULL;

    Src src = {0};
    int count = 0;
    Src body = {0};
    for (int i = 0; graph && i < graph->module_count; i++) {
        Module *mod = graph->modules[i];
        if (!module_has_annotations(mod)) continue;
        if (!mod->package_name) {
            annot_error(context, 0, 0, "%s: a module with annotations must declare a package (its table is named by it)",
                        mod->canonical_path ? mod->canonical_path : "<module>");
        }
        src_appendf(&src, "extern i32* %s_%s();\n", mod->package_name, ANNOT_TABLE_FN);
        src_appendf(&body, "    if (m == %d) { return %s_%s(); }\n", count, mod->package_name, ANNOT_TABLE_FN);
        count++;
    }
    // A module that reaches no annotated module -- a reader such as the
    // framework's meta.mln -- keeps its prototype: the definition belongs
    // to the program's root, which imports the apps.
    if (count == 0) { free(src.text); free(body.text); return; }

    // Not `export`: that would mangle the name with the package, and the
    // readers reach it by its bare name through their own extern prototype.
    src_appendf(&src, "i32* %s(i32 m) {\n%s    return (i32*)0;\n}\n", ANNOT_AGGREGATE_FN, body.text ? body.text : "");

    // The prototype gives way to the definition. The node stays registered
    // in the function table (there is no unregister), so it is only
    // unlinked from the program, not freed.
    for (int i = proto_index; i + 1 < program->block.count; i++) program->block.stmts[i] = program->block.stmts[i + 1];
    program->block.count--;

    parse_generated_toplevels(context, program, src.text);
    free(src.text);
    free(body.text);
}

void lower_annotations(ParserContext *context, ASTNode *program) {
    if (!program || program->type != AST_BLOCK) return;

    // A prototype of the aggregate marks the module that collects every
    // table; the real definition goes in its place (see emit_aggregate).
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (node && node->type == AST_FUNDEF && !node->fundef.body &&
            strcmp(node->fundef.name, ANNOT_AGGREGATE_FN) == 0) {
            emit_aggregate(context, program, i);
            break;
        }
    }

    Src rows = {0};
    Src probes = {0};
    int count = program->block.count;
    int row_count = 0;
    for (int i = 0; i < count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->attr_count == 0) continue;
        if (node->type == AST_FUNDEF && node->fundef.recv_type_name) {
            // One local per receiver type gives sizeof(T) an operand.
            char marker[300];
            snprintf(marker, sizeof(marker), "__annot_probe_%s;", node->fundef.recv_type_name);
            if (!probes.text || !strstr(probes.text, marker)) {
                src_appendf(&probes, "    %s __annot_probe_%s;\n", node->fundef.recv_type_name, node->fundef.recv_type_name);
            }
        }
        for (int k = 0; k < node->attr_count; k++) {
            emit_annotation_row(context, program, &rows, 1 + row_count * ANNOT_ROW_WORDS, node, &node->attrs[k]);
            row_count++;
        }
        clear_attrs(node);
    }
    if (row_count > 0) {
        const char *pkg = context->module.current_package;
        if (!pkg || !pkg[0] || strcmp(pkg, g_default_package) == 0) {
            annot_error(context, 0, 0, "a module with annotations must declare a package (its table is named by it)");
        }
        Src src = {0};
        src_appendf(&src, "i32 __annotations_data_%s[%d];\n", pkg, 1 + row_count * ANNOT_ROW_WORDS);
        src_appendf(&src, "export i32* %s() {\n    i32 *t = &__annotations_data_%s[0];\n%s    t[0] = %d;\n%s    return t;\n}\n",
                    ANNOT_TABLE_FN, pkg, probes.text ? probes.text : "", row_count, rows.text ? rows.text : "");
        parse_generated_toplevels(context, program, src.text);
        free(src.text);
    }
    free(rows.text);
    free(probes.text);
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
