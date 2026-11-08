#include "mylang/frontend/parser_dom_internal.h"
#include "mylang/frontend/parser_annot_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/resolver.h"
#include "mylang/type/type_info.h"

#include <stdarg.h>
#include <ctype.h>

static void lower_nested_blocks(ParserContext *context, ASTNode *stmt);
static ASTNode *i32_type(void);

/* Lowers AST_DOM_ELEMENT nodes into ordinary MyLang calls.
 *
 * The compiler holds no element vocabulary. A tag names a function, its
 * properties name that function's parameters, and children are appended with
 * `append_child`; all three resolve like ordinary identifiers, so what elements
 * exist and what they do is entirely up to the imported package:
 *
 *     return <Window title="S" x={0} y={0} w={320} h={200}>
 *         <Button text="OK" onClick={h} />
 *     </Window>;
 *
 *     i32 __dom0 = dom.Window("S", 0, 0, 320, 200);
 *     i32 __dom1 = dom.Button("OK", 0, 0, 0, 0, h);
 *     dom.append_child(__dom0, __dom1);
 *     return __dom0;
 *
 * A generated local has the type the callee returns, so a package whose
 * elements return a nominal id type keeps it.
 *
 * Properties are ordered by the callee's parameter names, so source order does
 * not matter and a misspelled property is reported against the signature. A
 * property left out takes the parameter's `= literal` default, if it has one.
 * The generated statements are hoisted ahead of the statement that contained
 * the element, which is replaced by the id of the tree's root node.
 *
 * A handler property -- any parameter named `on` + a capital letter, such as
 * onClick -- whose value names a method (`onClick={c.click}`) or a local
 * function is passed as the parameter's declared function type, through a
 * trampoline when the function takes fewer arguments; see
 * parser_lower_annot.c. Any other value is passed through as written.
 *
 * `view` is the one method treated apart: a method of that name that reads its
 * receiver and holds markup. Writing to the receiver there is an error, and a
 * property whose value reads the receiver is bound: its node is recorded with
 * `bind(slot, node)`, and a generated method hands the value to the hook
 * `<Tag>_<property>(slot, value)` each time it runs:
 *
 *     View (Counter c) view() {
 *         return <Label text={"clicks: %d", c.clicks} />;
 *     }
 *
 *     View __dom0 = dom.Label(<the format>);
 *     dom.bind(0, __dom0);
 *     return __dom0;
 *     ...
 *     void (Counter c) __view_update() { dom.Label_text(0, <the format>); }
 *
 * The hook decides what a change means, so the compiler knows no property. A
 * format `{"%s: %d", a, b}` lowers to `format`, then `format_str` or
 * `format_int` per value, then `format_end`, which yields the text.
 */

#define DOM_APPEND_CHILD "append_child"
#define DOM_BIND "bind"
#define DOM_VIEW_METHOD "view"
#define DOM_VIEW_UPDATE "__view_update"

// Statements generated for one source statement, plus the id counter shared by
// every element lowered into it.
typedef struct {
    ASTNode **stmts;
    int count;
} DomEmit;

static void dom_error(ParserContext *context, const ASTNode *node,
                      int line, int col, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "%s:%d:%d: error: ",
            context->module.filename ? context->module.filename : "<input>",
            node ? (line ? line : node->line) : line,
            node ? (col ? col : node->col) : col);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

static int is_handler_param(const char *name) {
    return name && name[0] == 'o' && name[1] == 'n' && isupper((unsigned char)name[2]);
}

static const char *base_type_name(ASTNode *type) {
    if (!type || type->type != AST_TYPE || !type->type_node.base_type) return NULL;
    ASTNode *base = type->type_node.base_type;
    if (base->type == AST_IDENTIFIER) return base->identifier.name;
    if (base->type == AST_TYPE_GENERIC) return base->generic_type.name;
    return NULL;
}

typedef struct {
    const char *name;
    const char *type_name;
} DeclSearch;

static void find_decl(ASTNode **slot, void *data) {
    ASTNode *node = slot ? *slot : NULL;
    DeclSearch *search = data;
    if (!node || search->type_name) return;
    if (node->type == AST_VAR_DECL && node->var_decl.name && strcmp(node->var_decl.name, search->name) == 0) {
        search->type_name = base_type_name(node->var_decl.var_type);
        return;
    }
    ast_visit_children(node, find_decl, data);
}

/* The base type name of a local or parameter named `name` in the function
 * being lowered, or NULL. Parameters first, then the first declaration inside
 * the body, `case` arms and statement expressions included -- MyLang has no
 * shadowing across DOM-bearing statements worth modelling here. */
static const char *local_type_name(ParserContext *context, const char *name) {
    ASTNode *fn = context->lowering.dom_current_fn;
    if (!fn) return NULL;
    for (int i = 0; i < fn->fundef.param_count; i++) {
        ASTNode *p = fn->fundef.params[i];
        if (p && p->type == AST_PARAM && p->param.name && strcmp(p->param.name, name) == 0) {
            return base_type_name(p->param.type);
        }
    }
    DeclSearch search = { name, NULL };
    find_decl(&fn->fundef.body, &search);
    return search.type_name;
}

/* The function an element tag names, found as dom_signature_lookup finds it.
 * DomSignature keeps parameter names and defaults, not parameter types. */
static ASTNode *dom_callee(ParserContext *context, const char *tag) {
    ASTNode *local = find_function(context, tag);
    if (local && local->type == AST_FUNDEF) return local;

    ASTNode *program = context->lowering.dom_program;
    FrontendSession *session = context->session;
    if (!program || program->type != AST_BLOCK || !session || !session->loader) return NULL;
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node || node->type != AST_IMPORT || !node->import_stmt.path) continue;
        if (!module_loader_is_mylang_source(node->import_stmt.path)) continue;
        Module *mod = module_loader_load(session->loader, context->module.filename,
                                         node->import_stmt.path);
        if (!mod || mod->state != MODULE_LOADED) continue;
        ModuleSymbol *sym = resolver_lookup_import_symbol(node, mod, tag);
        if (sym && sym->kind == SYMBOL_FUNCTION && sym->declaration) return sym->declaration;
    }
    return NULL;
}

/* The type a handler value is passed as: the function type the callee declares
 * for the parameter, or the dispatcher's word ABI when it declares none. */
static ASTNode *handler_value_type(ParserContext *context, const char *tag, int param) {
    ASTNode *callee = dom_callee(context, tag);
    ASTNode *declared = callee && callee->type == AST_FUNDEF && param < callee->fundef.param_count
                            ? callee->fundef.params[param] : NULL;
    if (declared && declared->type == AST_PARAM && declared->param.type &&
        declared->param.type->type == AST_TYPE_FUNCTION) {
        return ast_clone(declared->param.type);
    }
    ASTNode **params = calloc(3, sizeof(ASTNode *));
    params[0] = i32_type();
    params[1] = i32_type();
    params[2] = i32_type();
    return new_function_type(
        params, 3,
        new_type_node(new_identifier("void"), 0, TYPEMOD_NONE, REFKIND_NONE),
        false);
}

static int same_value_type(const ASTNode *a, const ASTNode *b) {
    if (!a || !b || a->type != b->type) return 0;
    if (a->type != AST_TYPE) return 1;
    const char *left = base_type_name((ASTNode *)a);
    const char *right = base_type_name((ASTNode *)b);
    return left && right && strcmp(left, right) == 0 &&
           a->type_node.pointer_level == b->type_node.pointer_level &&
           a->type_node.borrow_kind == b->type_node.borrow_kind;
}

/* A handler takes the values its event carries, in order, or fewer of them:
 * what the function type declares after `owner`. */
static void check_handler_method(ParserContext *context, ASTNode *el, const DomProp *prop,
                                 const char *member, const ASTNode *method, const ASTNode *type) {
    if (!type || type->type != AST_TYPE_FUNCTION) {
        if (method->fundef.param_count > 3) {
            dom_error(context, el, prop->line, prop->col,
                      "handler method '%s' takes too many parameters; at most (i32 id, i32 arg) after the receiver", member);
        }
        return;
    }
    int carried = type->function_type.param_count - 1;
    int taken = method->fundef.param_count - 1;
    if (taken > carried) {
        dom_error(context, el, prop->line, prop->col,
                  "handler method '%s' takes %d value%s; %s on <%s> carries %d",
                  member, taken, taken == 1 ? "" : "s", prop->name, el->dom_element.tag, carried);
    }
    for (int i = 0; i < taken; i++) {
        const ASTNode *param = method->fundef.params[i + 1];
        if (!same_value_type(param->param.type, type->function_type.param_types[i + 1])) {
            dom_error(context, el, prop->line, prop->col,
                      "handler method '%s': parameter '%s' is not the type %s on <%s> carries",
                      member, param->param.name, prop->name, el->dom_element.tag);
        }
    }
}

/* `onClick={c.click}` names the method itself: the handler's function type
 * lands on the method directly, since the calling convention ignores trailing
 * arguments. A plain local function with fewer parameters is wrapped so `id`
 * arrives in the right slot. */
static ASTNode *lower_handler_value(ParserContext *context, ASTNode *el, const DomProp *prop,
                                    int param, ASTNode *value) {
    const char *tramp = NULL;
    if (value->type == AST_MEMBER_ACCESS || value->type == AST_ARROW_ACCESS) {
        ASTNode *lhs = value->type == AST_MEMBER_ACCESS ? value->member_access.lhs : value->arrow_access.lhs;
        const char *member = value->type == AST_MEMBER_ACCESS ? value->member_access.member : value->arrow_access.member;
        if (lhs && lhs->type == AST_IDENTIFIER) {
            const char *type_name = local_type_name(context, lhs->identifier.name);
            const MethodDef *m = type_name ? find_method(context, type_name, member) : NULL;
            if (m) {
                ASTNode *recv = m->fundef->fundef.params[0];
                ASTNode *rt = recv && recv->type == AST_PARAM ? recv->param.type : NULL;
                int by_pointer = rt && rt->type == AST_TYPE && rt->type_node.pointer_level == 1 && rt->type_node.borrow_kind == REFKIND_NONE;
                int by_ref = rt && rt->type == AST_TYPE && rt->type_node.pointer_level == 0 && rt->type_node.borrow_kind != REFKIND_NONE;
                if (!by_pointer && !by_ref) {
                    dom_error(context, el, prop->line, prop->col,
                              "handler method '%s' must take its receiver by pointer or reference, `(%s *self)` or `(borrow %s self)`",
                              member, type_name, type_name);
                }
                ASTNode *handler_type = handler_value_type(context, el->dom_element.tag, param);
                check_handler_method(context, el, prop, member, m->fundef, handler_type);
                free_ast(handler_type);
                tramp = m->mangled;
            }
        }
    } else if (value->type == AST_IDENTIFIER) {
        tramp = ensure_function_trampoline(context, context->lowering.dom_program,
                                           value->identifier.name, prop->line, prop->col);
    }
    if (!tramp) return value;
    (void)el;
    ASTNode *ref = new_identifier((char *)tramp);
    ref->line = value->line;
    ref->col = value->col;
    ASTNode *cast = new_cast(handler_value_type(context, el->dom_element.tag, param), ref);
    cast->line = value->line;
    cast->col = value->col;
    free_ast(value);
    return cast;
}

// --- values -------------------------------------------------------------------------

static ASTNode *dom_call(const char *name, ASTNode **args, int arg_count, const ASTNode *at);

/* A call of the function `name` in scope, as the source would resolve it. */
static ASTNode *hook_call(ParserContext *context, ASTNode *el, const DomProp *prop,
                          const char *name, ASTNode **args, int arg_count) {
    DomSignature sig;
    if (!dom_signature_lookup(context, context->lowering.dom_program, name, &sig)) {
        dom_error(context, el, prop->line, prop->col,
                  "'%s' on <%s> needs a function named '%s' in scope", prop->name, el->dom_element.tag, name);
    }
    ASTNode *call = dom_call(sig.call_name, args, arg_count, el);
    dom_signature_free(&sig);
    return call;
}

static ASTNode *hook_call1(ParserContext *context, ASTNode *el, const DomProp *prop,
                           const char *name, ASTNode *a) {
    ASTNode **args = malloc(sizeof(ASTNode *));
    args[0] = a;
    return hook_call(context, el, prop, name, args, 1);
}

static ASTNode *hook_call2(ParserContext *context, ASTNode *el, const DomProp *prop,
                           const char *name, ASTNode *a, ASTNode *b) {
    ASTNode **args = malloc(sizeof(ASTNode *) * 2);
    args[0] = a;
    args[1] = b;
    return hook_call(context, el, prop, name, args, 2);
}

static ASTNode *struct_field_type(ParserContext *context, const char *type_name, const char *field) {
    ASTNode *program = context->lowering.dom_program;
    if (!type_name || !program) return NULL;
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *decl = program->block.stmts[i];
        if (!decl || decl->type != AST_STRUCT || !decl->struct_stmt.name ||
            strcmp(decl->struct_stmt.name, type_name) != 0) continue;
        for (int m = 0; m < decl->struct_stmt.member_count; m++) {
            ASTNode *member = decl->struct_stmt.members[m];
            if (member && member->type == AST_VAR_DECL && member->var_decl.name &&
                strcmp(member->var_decl.name, field) == 0) {
                return member->var_decl.var_type;
            }
        }
    }
    return NULL;
}

/* `f.rows` where the field is a Text<N>. Instantiation has already named the
 * instance, so its name is what there is to read. */
static int value_is_fixed_text(ParserContext *context, ASTNode *value) {
    if (value->type != AST_MEMBER_ACCESS || !value->member_access.lhs ||
        value->member_access.lhs->type != AST_IDENTIFIER) return 0;
    const char *owner = local_type_name(context, value->member_access.lhs->identifier.name);
    const char *type = base_type_name(struct_field_type(context, owner, value->member_access.member));
    return type && strncmp(type, "__mlg_s_4_Text", 14) == 0;
}

/* A Text<N> field given where a `str` is read. */
static ASTNode *as_str_value(ParserContext *context, ASTNode *value) {
    if (!value_is_fixed_text(context, value)) return value;
    ASTNode *call = new_call("as_str", NULL, 0);
    call->line = value->line;
    call->col = value->col;
    call->call.recv = value;
    return call;
}

/* `{"a %d b %s", x, y}` as format("a %d b %s"), one call per value, format_end.
 * The literal says what each value is, so `x` goes to format_int(rest, x) and
 * its type is checked like any argument. Each call takes what is left of the
 * format and returns what follows its value. */
static ASTNode *lower_format_value(ParserContext *context, ASTNode *el, const DomProp *prop,
                                   ASTNode *value) {
    ASTNode *literal = value->call.args[0];
    if (literal->type != AST_STRING_LITERAL) {
        dom_error(context, el, prop->line, prop->col,
                  "'%s' on <%s>: a format starts with a string literal", prop->name, el->dom_element.tag);
    }
    const char *text = literal->string_literal.value;
    int given = value->call.arg_count - 1;
    int used = 0;
    ASTNode *call = hook_call1(context, el, prop, "format", literal);
    for (int i = 0; text[i]; i++) {
        if (text[i] != '%') continue;
        char spec = text[++i];
        if (spec == '%') continue;
        if (spec != 'd' && spec != 's') {
            dom_error(context, el, prop->line, prop->col,
                      "'%s' on <%s>: a format takes %%d, %%s and %%%%", prop->name, el->dom_element.tag);
        }
        if (used >= given) break;
        ASTNode *arg = value->call.args[++used];
        if (spec == 's') arg = as_str_value(context, arg);
        call = hook_call2(context, el, prop, spec == 'd' ? "format_int" : "format_str", call, arg);
    }
    int wanted = 0;
    for (int i = 0; text[i]; i++) {
        if (text[i] != '%') continue;
        if (text[++i] != '%') wanted++;
    }
    if (wanted != given) {
        dom_error(context, el, prop->line, prop->col,
                  "'%s' on <%s>: the format takes %d value%s, %d given",
                  prop->name, el->dom_element.tag, wanted, wanted == 1 ? "" : "s", given);
    }
    free(value->call.args);
    value->call.args = NULL;
    value->call.arg_count = 0;
    free_ast(value);
    return hook_call1(context, el, prop, "format_end", call);
}

static void emit_stmt(DomEmit *out, ASTNode *stmt);

static int parameter_is_str(ParserContext *context, const char *tag, int param) {
    ASTNode *callee = dom_callee(context, tag);
    ASTNode *declared = callee && callee->type == AST_FUNDEF && param < callee->fundef.param_count
                            ? callee->fundef.params[param] : NULL;
    const char *type = declared && declared->type == AST_PARAM ? base_type_name(declared->param.type) : NULL;
    return type && strcmp(type, "str") == 0;
}

// --- bound properties ----------------------------------------------------------------

typedef struct {
    const char *name;
    int found;
} NameSearch;

static void find_name(ASTNode **slot, void *data) {
    ASTNode *node = slot ? *slot : NULL;
    NameSearch *search = data;
    if (!node || search->found) return;
    if (node->type == AST_IDENTIFIER && strcmp(node->identifier.name, search->name) == 0) {
        search->found = 1;
        return;
    }
    ast_visit_children(node, find_name, data);
}

static int value_reads(ASTNode *value, const char *name) {
    NameSearch search = { name, 0 };
    find_name(&value, &search);
    return search.found;
}

static const char *view_receiver(ParserContext *context) {
    ASTNode *view = context->lowering.dom_view;
    return view ? view->fundef.params[0]->param.name : NULL;
}

typedef struct {
    ParserContext *context;
    ASTNode *el;
    const DomProp *prop;
} BoundValueCheck;

/* The update method has the receiver and nothing else of `view`. */
static void reject_view_local(ASTNode **slot, void *data) {
    ASTNode *node = slot ? *slot : NULL;
    BoundValueCheck *check = data;
    if (!node) return;
    if (node->type == AST_IDENTIFIER && strcmp(node->identifier.name, view_receiver(check->context)) != 0 &&
        local_type_name(check->context, node->identifier.name)) {
        dom_error(check->context, check->el, check->prop->line, check->prop->col,
                  "'%s' on <%s> reads the state and the local '%s'; a bound value can only read the state",
                  check->prop->name, check->el->dom_element.tag, node->identifier.name);
    }
    ast_visit_children(node, reject_view_local, data);
}

static int parameter_is_value(ParserContext *context, const char *tag, int param) {
    ASTNode *callee = dom_callee(context, tag);
    ASTNode *declared = callee && callee->type == AST_FUNDEF && param < callee->fundef.param_count
                            ? callee->fundef.params[param] : NULL;
    const char *type = declared && declared->type == AST_PARAM ? base_type_name(declared->param.type) : NULL;
    return type && (strcmp(type, "str") == 0 || mylang_type_is_builtin(type));
}

/* Records the update of a property whose value reads the state, and returns
 * its slot; -1 for a value that reads no state, and for a part: a handle the
 * element takes once, which is why the vocabulary has no hook for it. */
static int bind_property(ParserContext *context, ASTNode *el, const DomProp *prop, int param, ASTNode *value) {
    const char *receiver = view_receiver(context);
    if (!receiver || !value_reads(value, receiver)) return -1;
    BoundValueCheck check = { context, el, prop };
    reject_view_local(&value, &check);

    char hook[256];
    snprintf(hook, sizeof(hook), "%s_%s", el->dom_element.tag, prop->name);
    DomSignature sig;
    if (!dom_signature_lookup(context, context->lowering.dom_program, hook, &sig)) {
        if (!parameter_is_value(context, el->dom_element.tag, param)) return -1;
        dom_error(context, el, prop->line, prop->col,
                  "'%s' on <%s> reads the state, and no function '%s' can change it",
                  prop->name, el->dom_element.tag, hook);
    }
    int slot = context->lowering.dom_view_update_count;
    char number[32];
    snprintf(number, sizeof(number), "%d", slot);
    ASTNode **args = malloc(sizeof(ASTNode *) * 2);
    args[0] = new_number(number);
    args[1] = ast_clone(value);
    ASTNode *call = dom_call(sig.call_name, args, 2, el);
    dom_signature_free(&sig);
    context->lowering.dom_view_updates = realloc(context->lowering.dom_view_updates,
                                                 sizeof(ASTNode *) * (size_t)(slot + 1));
    context->lowering.dom_view_updates[slot] = new_expr_stmt(call);
    context->lowering.dom_view_update_count = slot + 1;
    return slot;
}

static ASTNode *take_prop(ASTNode *el, const char *name) {
    for (int i = 0; i < el->dom_element.prop_count; i++) {
        DomProp *p = &el->dom_element.props[i];
        if (p->value && strcmp(p->name, name) == 0) {
            ASTNode *value = p->value;
            p->value = NULL; // ownership moves to the generated call
            return value;
        }
    }
    return NULL;
}

static ASTNode *dom_call(const char *name, ASTNode **args, int arg_count, const ASTNode *at) {
    ASTNode *call = new_call((char *)name, args, arg_count);
    if (at) {
        call->line = at->line;
        call->col = at->col;
        call->end_line = at->end_line;
        call->end_col = at->end_col;
    }
    return call;
}

static ASTNode *i32_type(void) {
    return new_type_node(new_identifier("i32"), 0, TYPEMOD_NONE, REFKIND_NONE);
}

static int signature_returns_result(const DomSignature *sig) {
    ASTNode *type = sig ? sig->return_type : NULL;
    if (!type || type->type != AST_TYPE || !type->type_node.base_type) return 0;
    ASTNode *base = type->type_node.base_type;
    if (base->type == AST_IDENTIFIER) {
        const char *name = base->identifier.name;
        return strcmp(name, "Result") == 0 ||
               (strncmp(name, "__mlg_s_", 8) == 0 && strstr(name, "_Result_") != NULL);
    }
    if (base->type == AST_TYPE_GENERIC) {
        const char *name = base->generic_type.name;
        return strcmp(name, "Result") == 0 ||
               (strncmp(name, "__mlg_s_", 8) == 0 && strstr(name, "_Result_") != NULL);
    }
    return 0;
}

static void emit_stmt(DomEmit *out, ASTNode *stmt) {
    out->stmts = realloc(out->stmts, sizeof(ASTNode*) * (out->count + 1));
    out->stmts[out->count++] = stmt;
}

static void free_element_shell(ASTNode *el) {
    for (int i = 0; i < el->dom_element.prop_count; i++) {
        free(el->dom_element.props[i].name);
    }
    free(el->dom_element.props);
    free(el->dom_element.children);
    free(el->dom_element.tag);
    free(el);
}

// Lowers one element (and its subtree) into `out`, returning the name of the
// local that holds its node id.
static char *emit_element(ParserContext *context, ASTNode *el, DomEmit *out) {
    const char *tag = el->dom_element.tag;
    DomSignature sig;

    if (!dom_signature_lookup(context, context->lowering.dom_program, tag, &sig)) {
        dom_error(context, el, 0, 0,
                  "no function named '%s' is in scope for <%s>; a DOM element "
                  "calls the function of the same name", tag, tag);
    }

    for (int i = 0; i < el->dom_element.prop_count; i++) {
        DomProp *p = &el->dom_element.props[i];
        for (int j = 0; j < i; j++) {
            if (strcmp(el->dom_element.props[j].name, p->name) == 0) {
                dom_error(context, el, p->line, p->col, "<%s> sets '%s' twice", tag, p->name);
            }
        }
        int matched = 0;
        for (int j = 0; j < sig.param_count; j++) {
            if (strcmp(sig.param_names[j], p->name) == 0) { matched = 1; break; }
        }
        if (!matched) {
            dom_error(context, el, p->line, p->col, "<%s> has no property '%s'; '%s' has no such parameter",
                      tag, p->name, sig.call_name);
        }
    }

    // Properties are handed over in parameter order, so writing them in any
    // order produces the same call.
    ASTNode **args = sig.param_count > 0 ? malloc(sizeof(ASTNode*) * sig.param_count) : NULL;
    int *bound_slots = sig.param_count > 0 ? malloc(sizeof(int) * sig.param_count) : NULL;
    int bound_count = 0;
    int format_count = 0;
    for (int i = 0; i < sig.param_count; i++) {
        const DomProp *prop = NULL;
        for (int j = 0; j < el->dom_element.prop_count; j++) {
            if (strcmp(el->dom_element.props[j].name, sig.param_names[i]) == 0) { prop = &el->dom_element.props[j]; break; }
        }
        ASTNode *value = take_prop(el, sig.param_names[i]);
        if (!value && sig.param_defaults && sig.param_defaults[i]) {
            value = ast_clone(sig.param_defaults[i]);
        }
        if (!value) {
            dom_error(context, el, 0, 0, "<%s> is missing property '%s'; '%s' takes it as a parameter",
                      tag, sig.param_names[i], sig.call_name);
        }
        if (prop && is_handler_param(sig.param_names[i])) {
            value = lower_handler_value(context, el, prop, i, value);
        } else if (prop) {
            if (value->type == AST_CALL && strcmp(value->call.name, DOM_FORMAT_VALUE) == 0) {
                // The hooks build one text at a time.
                if (++format_count > 1) {
                    dom_error(context, el, prop->line, prop->col, "<%s> can format one property", tag);
                }
                value = lower_format_value(context, el, prop, value);
            } else if (parameter_is_str(context, tag, i)) {
                value = as_str_value(context, value);
            }
            int slot = bind_property(context, el, prop, i, value);
            if (slot >= 0) bound_slots[bound_count++] = slot;
            // A call's aggregate result cannot be an argument of a long call.
            if (value->type == AST_CALL && parameter_is_str(context, tag, i)) {
                char text_var[32];
                snprintf(text_var, sizeof(text_var), "__dom_text%d", context->lowering.dom_node_counter++);
                emit_stmt(out, new_var_decl(
                    new_type_node(new_identifier("str"), 0, TYPEMOD_NONE, REFKIND_NONE), text_var, value));
                value = new_identifier(text_var);
            }
        }
        args[i] = value;
    }

    int ordinal = context->lowering.dom_node_counter++;
    char var[32];
    snprintf(var, sizeof(var), "__dom%d", ordinal);
    ASTNode *create_call = NULL;
    ASTNode *node_type = NULL;
    if (signature_returns_result(&sig)) {
        char adapter_name[256];
        snprintf(adapter_name, sizeof(adapter_name), "dom_%s", tag);
        DomSignature adapter_sig;
        if (!dom_signature_lookup(context, context->lowering.dom_program,
                                  adapter_name, &adapter_sig)) {
            dom_error(context, el, 0, 0,
                      "Result-returning <%s> needs a function named '%s' in scope",
                      tag, adapter_name);
        }
        create_call = dom_call(adapter_sig.call_name, args, sig.param_count, el);
        node_type = ast_clone(adapter_sig.return_type);
        dom_signature_free(&adapter_sig);
    } else {
        create_call = dom_call(sig.call_name, args, sig.param_count, el);
        node_type = ast_clone(sig.return_type);
    }
    emit_stmt(out, new_var_decl(node_type ? node_type : i32_type(), var, create_call));

    for (int i = 0; i < bound_count; i++) {
        char number[32];
        snprintf(number, sizeof(number), "%d", bound_slots[i]);
        DomProp bound = { (char *)DOM_BIND, NULL, el->line, el->col };
        emit_stmt(out, new_expr_stmt(hook_call2(context, el, &bound, DOM_BIND,
                                                new_number(number), new_identifier(var))));
    }
    free(bound_slots);

    if (el->dom_element.child_count > 0) {
        DomSignature append_sig;
        if (!dom_signature_lookup(context, context->lowering.dom_program, DOM_APPEND_CHILD, &append_sig)) {
            dom_error(context, el, 0, 0,
                      "children need a function named '%s' in scope", DOM_APPEND_CHILD);
        }
        for (int i = 0; i < el->dom_element.child_count; i++) {
            char *child_var = emit_element(context, el->dom_element.children[i], out);
            ASTNode **child_args = malloc(sizeof(ASTNode*) * 2);
            child_args[0] = new_identifier(var);
            child_args[1] = new_identifier(child_var);
            ASTNode *append_call = dom_call(append_sig.call_name, child_args, 2, el);
            if (signature_returns_result(&append_sig)) {
                DomSignature adapter_sig;
                if (!dom_signature_lookup(context, context->lowering.dom_program,
                                          "dom_append_child", &adapter_sig)) {
                    dom_error(context, el, 0, 0,
                              "Result-returning append_child needs a function named 'dom_append_child' in scope");
                }
                free_ast(append_call);
                ASTNode **adapter_args = malloc(sizeof(ASTNode *) * 2);
                adapter_args[0] = new_identifier(var);
                adapter_args[1] = new_identifier(child_var);
                emit_stmt(out, new_expr_stmt(dom_call(adapter_sig.call_name, adapter_args, 2, el)));
                dom_signature_free(&adapter_sig);
            } else {
                emit_stmt(out, new_expr_stmt(append_call));
            }
            free(child_var);
        }
        dom_signature_free(&append_sig);
    }

    dom_signature_free(&sig);

    free_element_shell(el);
    return strdup(var);
}

static void lower_expr(ParserContext *context, ASTNode **slot, DomEmit *out) {
    ASTNode *node = slot ? *slot : NULL;
    if (!node) return;

    if (node->type == AST_DOM_ELEMENT) {
        int line = node->line, col = node->col;
        char *var = emit_element(context, node, out);
        ASTNode *ref = new_identifier(var);
        ref->line = line;
        ref->col = col;
        free(var);
        *slot = ref;
        return;
    }

    switch (node->type) {
    case AST_BINARY:
        lower_expr(context, &node->binary.left, out);
        lower_expr(context, &node->binary.right, out);
        break;
    case AST_ASSIGN:
        lower_expr(context, &node->assign.left, out);
        lower_expr(context, &node->assign.right, out);
        break;
    case AST_UNARY:
        lower_expr(context, &node->unary.operand, out);
        break;
    case AST_BORROW:
        lower_expr(context, &node->borrow.expr, out);
        break;
    case AST_CAST:
        lower_expr(context, &node->cast.expr, out);
        break;
    case AST_TERNARY:
        lower_expr(context, &node->ternary.cond, out);
        lower_expr(context, &node->ternary.then_expr, out);
        lower_expr(context, &node->ternary.else_expr, out);
        break;
    case AST_CALL:
        for (int i = 0; i < node->call.arg_count; i++) {
            lower_expr(context, &node->call.args[i], out);
        }
        break;
    case AST_MEMBER_ACCESS:
        lower_expr(context, &node->member_access.lhs, out);
        break;
    case AST_ARROW_ACCESS:
        lower_expr(context, &node->arrow_access.lhs, out);
        break;
    case AST_INIT_LIST:
        for (int i = 0; i < node->init_list.count; i++) {
            lower_expr(context, &node->init_list.elements[i], out);
        }
        break;
    case AST_SIZEOF:
        lower_expr(context, &node->sizeof_expr.expr, out);
        break;
    default:
        break;
    }
}

// Lowers the expressions a statement owns directly. Nested blocks are handled
// separately so their statements hoist into their own scope.
static void lower_stmt_exprs(ParserContext *context, ASTNode *stmt, DomEmit *out) {
    if (!stmt) return;
    switch (stmt->type) {
    case AST_RETURN:
        lower_expr(context, &stmt->ret.expr, out);
        break;
    case AST_DEFER:
        lower_nested_blocks(context, stmt->defer_stmt.body);
        break;
    case AST_YIELD:
        lower_expr(context, &stmt->yield_stmt.expr, out);
        break;
    case AST_EXPR_STMT:
        lower_expr(context, &stmt->expr_stmt.expr, out);
        break;
    case AST_VAR_DECL:
        lower_expr(context, &stmt->var_decl.init, out);
        break;
    case AST_ASSIGN:
        lower_expr(context, &stmt->assign.right, out);
        break;
    case AST_IF:
        lower_expr(context, &stmt->if_stmt.cond, out);
        break;
    case AST_WHILE:
        lower_expr(context, &stmt->while_stmt.cond, out);
        break;
    case AST_DO_WHILE:
        lower_expr(context, &stmt->do_while_stmt.cond, out);
        break;
    case AST_FOR:
        lower_stmt_exprs(context, stmt->for_stmt.init, out);
        lower_expr(context, &stmt->for_stmt.cond, out);
        lower_stmt_exprs(context, stmt->for_stmt.inc, out);
        break;
    default:
        break;
    }
}

static void find_element(ASTNode **slot, void *data) {
    ASTNode *node = slot ? *slot : NULL;
    int *found = data;
    if (!node || *found) return;
    if (node->type == AST_DOM_ELEMENT) { *found = 1; return; }
    ast_visit_children(node, find_element, data);
}

/* `View (T self) view()` with markup in it. */
static int is_view_method(ASTNode *fn) {
    if (!fn->fundef.recv_type_name || !fn->fundef.body || fn->fundef.param_count != 1) return 0;
    const char *sep = strstr(fn->fundef.name, "__");
    if (!sep || strcmp(sep + 2, DOM_VIEW_METHOD) != 0) return 0;
    ASTNode *receiver = fn->fundef.params[0];
    ASTNode *type = receiver && receiver->type == AST_PARAM ? receiver->param.type : NULL;
    if (!type || type->type != AST_TYPE || type->type_node.pointer_level ||
        type->type_node.borrow_kind != REFKIND_NONE) return 0;
    int found = 0;
    find_element(&fn->fundef.body, &found);
    return found;
}

static void read_only_receiver(ASTNode *fn) {
    fn->fundef.params[0]->param.type->type_node.type_modifiers |= TYPEMOD_CONST;
}

/* The method that runs the update hook of every bound property. */
static void generate_view_update(ParserContext *context, ASTNode *view) {
    ASTNode *program = context->lowering.dom_program;
    char source[512];
    snprintf(source, sizeof(source), "void (%s %s) %s() { }\n", view->fundef.recv_type_name,
             view->fundef.params[0]->param.name, DOM_VIEW_UPDATE);
    parse_generated_toplevels(context, program, source);
    ASTNode *update = program->block.stmts[program->block.count - 1];
    read_only_receiver(update);
    ASTNode *body = update->fundef.body;
    free(body->block.stmts);
    body->block.stmts = context->lowering.dom_view_updates;
    body->block.count = context->lowering.dom_view_update_count;
    context->lowering.dom_view_updates = NULL;
    context->lowering.dom_view_update_count = 0;
}

static void lower_nested_blocks(ParserContext *context, ASTNode *stmt) {
    if (!stmt) return;
    switch (stmt->type) {
    case AST_BLOCK:
        lower_dom_block(context, stmt);
        break;
    case AST_FUNDEF: {
        ASTNode *outer = context->lowering.dom_current_fn;
        int is_view = is_view_method(stmt);
        context->lowering.dom_current_fn = stmt;
        if (is_view) {
            read_only_receiver(stmt);
            context->lowering.dom_view = stmt;
        }
        lower_nested_blocks(context, stmt->fundef.body);
        if (is_view) {
            context->lowering.dom_view = NULL;
            generate_view_update(context, stmt);
        }
        context->lowering.dom_current_fn = outer;
        break;
    }
    case AST_FUN_LITERAL:
        lower_nested_blocks(context, stmt->fun_literal.body);
        break;
    case AST_IF:
        lower_nested_blocks(context, stmt->if_stmt.then_stmt);
        lower_nested_blocks(context, stmt->if_stmt.else_stmt);
        break;
    case AST_WHILE:
        lower_nested_blocks(context, stmt->while_stmt.body);
        break;
    case AST_DO_WHILE:
        lower_nested_blocks(context, stmt->do_while_stmt.body);
        break;
    case AST_FOR:
        lower_nested_blocks(context, stmt->for_stmt.body);
        break;
    case AST_DEFER:
        lower_nested_blocks(context, stmt->defer_stmt.body);
        break;
    case AST_STMT_EXPR:
        lower_nested_blocks(context, stmt->stmt_expr.block);
        break;
    case AST_VAR_DECL:
        if (stmt->var_decl.init) lower_nested_blocks(context, stmt->var_decl.init);
        break;
    default:
        break;
    }
}

static void lower_case_arm(ParserContext *context, ASTNode *arm) {
    if (arm && arm->type == AST_STMT_EXPR) lower_dom_block(context, arm->stmt_expr.block);
}

/* A `case` arm runs only when it is chosen, so markup in one cannot be hoisted
 * ahead of the whole statement. An arm written as a statement expression is a
 * block of its own and is lowered in place: in
 * `Err(e) -> ({ return <Alert text={e.describe()} />; })` the element is built
 * only when that arm runs. Markup that is itself an arm's value is left for
 * ensure_no_dom_elements to reject. Blocks, statement expressions and function
 * literals are lowered on their own, so the search stops at them. */
static void lower_case_arm_blocks(ASTNode **slot, void *data) {
    ParserContext *context = data;
    ASTNode *node = *slot;
    if (!node) return;
    switch (node->type) {
    case AST_BLOCK:
    case AST_STMT_EXPR:
    case AST_FUN_LITERAL:
        return;
    case AST_CASE:
        for (int i = 0; i < node->case_expr.case_count; i++) lower_case_arm(context, node->case_expr.cases[i].expr);
        lower_case_arm(context, node->case_expr.default_expr);
        break;
    default:
        break;
    }
    ast_visit_children(node, lower_case_arm_blocks, data);
}

void lower_dom_block(ParserContext *context, ASTNode *block) {
    if (!block || block->type != AST_BLOCK) return;

    ASTNode **stmts = NULL;
    int count = 0;

    for (int i = 0; i < block->block.count; i++) {
        ASTNode *stmt = block->block.stmts[i];
        if (!stmt) continue;

        DomEmit emit = { NULL, 0 };
        lower_stmt_exprs(context, stmt, &emit);
        for (int j = 0; j < emit.count; j++) {
            stmts = realloc(stmts, sizeof(ASTNode*) * (count + 1));
            stmts[count++] = emit.stmts[j];
        }
        free(emit.stmts);

        lower_nested_blocks(context, stmt);
        lower_case_arm_blocks(&stmt, context);

        stmts = realloc(stmts, sizeof(ASTNode*) * (count + 1));
        stmts[count++] = stmt;
    }

    free(block->block.stmts);
    block->block.stmts = stmts;
    block->block.count = count;
}

static void reject_dom_element(ASTNode **slot, void *data) {
    ASTNode *node = *slot;
    if (!node) return;
    if (node->type == AST_DOM_ELEMENT) {
        dom_error(data, node, 0, 0,
                  "a DOM element is only allowed as a value inside a statement, "
                  "such as `return <%s .../>;`", node->dom_element.tag);
    }
    ast_visit_children(node, reject_dom_element, data);
}

void ensure_no_dom_elements(ParserContext *context, ASTNode *node) {
    reject_dom_element(&node, context);
}

void dom_lowering_reset(ParserContext *context) {
    context->lowering.dom_node_counter = 0;
    context->lowering.dom_program = NULL;
    context->lowering.dom_current_fn = NULL;
    context->lowering.dom_view = NULL;
    context->lowering.dom_view_updates = NULL;
    context->lowering.dom_view_update_count = 0;
}

// The whole program is kept so element tags can be resolved against imports.
void dom_lowering_set_program(ParserContext *context, ASTNode *program) {
    context->lowering.dom_program = program;
}
