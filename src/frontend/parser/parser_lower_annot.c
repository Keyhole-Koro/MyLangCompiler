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
 * gaps) and records one row per use. Codegen emits the rows as static data
 * in the `annotations` collected section (codegen_annotations.c):
 *
 *     .section annotations
 *     __annotations_rows:
 *       .word s_0, Terminal__poll, s_1, 24, 1, 100, 0, 0
 *
 * eight words per row: name, fn, type, size, argc, arg0..arg2. The linker
 * lays every object's chunk out contiguously as the `annotations` section
 * (MyLinker/inc/ObjectFormat.h, CollectEntry) and lists it in its section
 * directory, so whoever reads the rows -- MyStdLib's meta/annotations.mln,
 * for the application framework at boot -- finds them all without any
 * module listing them. What a row means is the reader's business.
 *
 * Because the calling convention ignores extra arguments, a method
 * `(T *self, i32 id)` can be called through the DOM's uniform handler shape
 * `(owner, id, arg)` directly -- a row holds the real method, not a
 * wrapper. A method reached this way must take its receiver by pointer or
 * reference.
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


#define ANNOT_FIXED_PARAMS 3
#define ANNOT_MAX_ARGS 3

static AnnotationRow *g_rows = NULL;
static int g_row_count = 0;

int annotation_row_count(void) { return g_row_count; }
const AnnotationRow *annotation_row(int index) {
    return index >= 0 && index < g_row_count ? &g_rows[index] : NULL;
}

void annotation_rows_reset(void) {
    for (int i = 0; i < g_row_count; i++) {
        free(g_rows[i].name);
        free(g_rows[i].fn);
        free(g_rows[i].type);
        for (int k = 0; k < ANNOTATION_MAX_ARGS; k++) free(g_rows[i].args[k].text);
    }
    free(g_rows);
    g_rows = NULL;
    g_row_count = 0;
}

static void record_arg(AnnotationArg *out, const ASTNode *value) {
    out->is_string = 0;
    out->text = NULL;
    out->value = 0;
    if (!value) return;
    switch (value->type) {
    case AST_NUMBER: out->value = strtol(value->number.value, NULL, 10); break;
    case AST_STRING_LITERAL: out->is_string = 1; out->text = strdup(value->string_literal.value); break;
    case AST_CHAR_LITERAL: out->value = (unsigned char)value->char_literal.value[0]; break;
    case AST_UNARY:
        if (value->unary.op == SUB && value->unary.operand && value->unary.operand->type == AST_NUMBER)
            out->value = -strtol(value->unary.operand->number.value, NULL, 10);
        break;
    default: break;
    }
}

/* Checks one attribute against its declaration and records its row. */
static void record_annotation(ParserContext *context, ASTNode *program, ASTNode *target, const Attribute *attr) {
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

    g_rows = realloc(g_rows, sizeof(AnnotationRow) * (g_row_count + 1));
    AnnotationRow *row = &g_rows[g_row_count++];
    memset(row, 0, sizeof(*row));
    row->name = strdup(attr->name);
    row->fn = strdup(target->fundef.name);
    row->type = is_method ? strdup(target->fundef.recv_type_name) : NULL;
    row->argc = n - ANNOT_FIXED_PARAMS;
    for (int k = 0; k < ANNOTATION_MAX_ARGS; k++) {
        int p = ANNOT_FIXED_PARAMS + k;
        record_arg(&row->args[k], p < n ? values[p] : NULL);
    }
    free(values);
}

static void clear_attrs(ASTNode *node) {
    free_attributes(node->attrs, node->attr_count);
    node->attrs = NULL;
    node->attr_count = 0;
}

void lower_annotations(ParserContext *context, ASTNode *program) {
    if (!program || program->type != AST_BLOCK) return;
    annotation_rows_reset();
    int count = program->block.count;
    for (int i = 0; i < count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->attr_count == 0) continue;
        for (int k = 0; k < node->attr_count; k++) {
            record_annotation(context, program, node, &node->attrs[k]);
        }
        clear_attrs(node);
    }
}

// --- default arguments ------------------------------------------------------------

/* The declaration a call by (post-rewrite) name resolves to: a function in
 * this file, else an exported function of an imported module -- reached as
 * `pkg_name` through a package import or by bare name through a symbol-list
 * import. NULL when unknown (an indirect call through a variable, say). */
ASTNode *callee_declaration(ParserContext *context, ASTNode *program, const char *name) {
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
