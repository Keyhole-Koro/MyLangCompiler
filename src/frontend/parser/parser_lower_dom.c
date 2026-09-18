#include "mylang/frontend/parser_dom_internal.h"
#include "mylang/frontend/parser_annot_internal.h"
#include "mylang/frontend/parser_ast_internal.h"

#include <stdarg.h>
#include <ctype.h>

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
 * Properties are ordered by the callee's parameter names, so source order does
 * not matter and a misspelled property is reported against the signature. A
 * property left out takes the parameter's `= literal` default, if it has one.
 * The generated statements are hoisted ahead of the statement that contained
 * the element, which is replaced by the id of the tree's root node.
 *
 * Two properties are handled by the compiler rather than the callee:
 *
 *   - `ref={lvalue}` stores the new node's id: `lvalue = __dom0;` follows the
 *     create call, so app code keeps ids without walking the tree afterwards.
 *   - A handler property -- any parameter named `on` + a capital letter, such
 *     as onClick -- whose value names a method (`onClick={c.click}`) or a
 *     local function is replaced by a trampoline with the dispatcher's
 *     uniform ABI, `void (i32 owner, i32 id, i32 arg)`; see
 *     parser_lower_app.c. Any other value is passed through as written.
 */

#define DOM_APPEND_CHILD "append_child"
#define DOM_REF_PROP "ref"

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

/* The base type name of a local or parameter named `name` in the function
 * being lowered, or NULL. Parameters first, then any declaration inside the
 * body -- MyLang has no shadowing across DOM-bearing statements worth
 * modelling here. */
static const char *base_type_name(ASTNode *type) {
    if (!type || type->type != AST_TYPE || !type->type_node.base_type) return NULL;
    ASTNode *base = type->type_node.base_type;
    if (base->type == AST_IDENTIFIER) return base->identifier.name;
    if (base->type == AST_TYPE_GENERIC) return base->generic_type.name;
    return NULL;
}

static const char *find_decl_type_in(ASTNode *node, const char *name) {
    if (!node) return NULL;
    if (node->type == AST_VAR_DECL && node->var_decl.name && strcmp(node->var_decl.name, name) == 0) {
        return base_type_name(node->var_decl.var_type);
    }
    const char *found = NULL;
    switch (node->type) {
    case AST_BLOCK:
        for (int i = 0; i < node->block.count && !found; i++) found = find_decl_type_in(node->block.stmts[i], name);
        break;
    case AST_IF:
        found = find_decl_type_in(node->if_stmt.then_stmt, name);
        if (!found) found = find_decl_type_in(node->if_stmt.else_stmt, name);
        break;
    case AST_WHILE: found = find_decl_type_in(node->while_stmt.body, name); break;
    case AST_DO_WHILE: found = find_decl_type_in(node->do_while_stmt.body, name); break;
    case AST_FOR:
        found = find_decl_type_in(node->for_stmt.init, name);
        if (!found) found = find_decl_type_in(node->for_stmt.body, name);
        break;
    case AST_UNCHECKED: found = find_decl_type_in(node->unchecked_block.body, name); break;
    case AST_STMT_EXPR: found = find_decl_type_in(node->stmt_expr.block, name); break;
    default: break;
    }
    return found;
}

static const char *local_type_name(ParserContext *context, const char *name) {
    ASTNode *fn = context->lowering.dom_current_fn;
    if (!fn) return NULL;
    for (int i = 0; i < fn->fundef.param_count; i++) {
        ASTNode *p = fn->fundef.params[i];
        if (p && p->type == AST_PARAM && p->param.name && strcmp(p->param.name, name) == 0) {
            return base_type_name(p->param.type);
        }
    }
    return find_decl_type_in(fn->fundef.body, name);
}

/* Replaces a handler property's value with a trampoline where one applies. */
static ASTNode *lower_handler_value(ParserContext *context, ASTNode *el, const DomProp *prop, ASTNode *value) {
    const char *tramp = NULL;
    if (value->type == AST_MEMBER_ACCESS || value->type == AST_ARROW_ACCESS) {
        ASTNode *lhs = value->type == AST_MEMBER_ACCESS ? value->member_access.lhs : value->arrow_access.lhs;
        const char *member = value->type == AST_MEMBER_ACCESS ? value->member_access.member : value->arrow_access.member;
        if (lhs && lhs->type == AST_IDENTIFIER) {
            const char *type_name = local_type_name(context, lhs->identifier.name);
            if (type_name && find_method(context, type_name, member)) {
                tramp = ensure_method_trampoline(context, context->lowering.dom_program,
                                                 type_name, member, prop->line, prop->col);
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
    free_ast(value);
    return ref;
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
        if (strcmp(p->name, DOM_REF_PROP) == 0) continue;
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
            value = lower_handler_value(context, el, prop, value);
        }
        args[i] = value;
    }

    char var[32];
    snprintf(var, sizeof(var), "__dom%d", context->lowering.dom_node_counter++);
    emit_stmt(out, new_var_decl(i32_type(), var,
                                dom_call(sig.call_name, args, sig.param_count, el)));

    ASTNode *ref_target = take_prop(el, DOM_REF_PROP);
    if (ref_target) {
        ASTNode *assign = new_assign(ref_target, new_identifier(var));
        assign->line = el->line;
        assign->col = el->col;
        emit_stmt(out, new_expr_stmt(assign));
    }

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
            emit_stmt(out, new_expr_stmt(dom_call(append_sig.call_name, child_args, 2, el)));
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
    case AST_BORROW_MUT:
        lower_expr(context, &node->borrow_mut.expr, out);
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

static void lower_nested_blocks(ParserContext *context, ASTNode *stmt) {
    if (!stmt) return;
    switch (stmt->type) {
    case AST_BLOCK:
        lower_dom_block(context, stmt);
        break;
    case AST_FUNDEF: {
        ASTNode *outer = context->lowering.dom_current_fn;
        context->lowering.dom_current_fn = stmt;
        lower_nested_blocks(context, stmt->fundef.body);
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
    case AST_UNCHECKED:
        lower_nested_blocks(context, stmt->unchecked_block.body);
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

        stmts = realloc(stmts, sizeof(ASTNode*) * (count + 1));
        stmts[count++] = stmt;
    }

    free(block->block.stmts);
    block->block.stmts = stmts;
    block->block.count = count;
}

void ensure_no_dom_elements(ParserContext *context, ASTNode *node) {
    if (!node) return;
    switch (node->type) {
    case AST_DOM_ELEMENT:
        dom_error(context, node, 0, 0,
                  "a DOM element is only allowed as a value inside a statement, "
                  "such as `return <%s .../>;`", node->dom_element.tag);
        break;
    case AST_VAR_DECL:
        ensure_no_dom_elements(context, node->var_decl.init);
        break;
    case AST_ASSIGN:
        ensure_no_dom_elements(context, node->assign.left);
        ensure_no_dom_elements(context, node->assign.right);
        break;
    case AST_BINARY:
        ensure_no_dom_elements(context, node->binary.left);
        ensure_no_dom_elements(context, node->binary.right);
        break;
    case AST_UNARY:
        ensure_no_dom_elements(context, node->unary.operand);
        break;
    case AST_BORROW:
        ensure_no_dom_elements(context, node->borrow.expr);
        break;
    case AST_BORROW_MUT:
        ensure_no_dom_elements(context, node->borrow_mut.expr);
        break;
    case AST_CAST:
        ensure_no_dom_elements(context, node->cast.expr);
        break;
    case AST_TERNARY:
        ensure_no_dom_elements(context, node->ternary.cond);
        ensure_no_dom_elements(context, node->ternary.then_expr);
        ensure_no_dom_elements(context, node->ternary.else_expr);
        break;
    case AST_IF:
        ensure_no_dom_elements(context, node->if_stmt.cond);
        ensure_no_dom_elements(context, node->if_stmt.then_stmt);
        ensure_no_dom_elements(context, node->if_stmt.else_stmt);
        break;
    case AST_WHILE:
        ensure_no_dom_elements(context, node->while_stmt.cond);
        ensure_no_dom_elements(context, node->while_stmt.body);
        break;
    case AST_DO_WHILE:
        ensure_no_dom_elements(context, node->do_while_stmt.cond);
        ensure_no_dom_elements(context, node->do_while_stmt.body);
        break;
    case AST_FOR:
        ensure_no_dom_elements(context, node->for_stmt.init);
        ensure_no_dom_elements(context, node->for_stmt.cond);
        ensure_no_dom_elements(context, node->for_stmt.inc);
        ensure_no_dom_elements(context, node->for_stmt.body);
        break;
    case AST_RETURN:
        ensure_no_dom_elements(context, node->ret.expr);
        break;
    case AST_YIELD:
        ensure_no_dom_elements(context, node->yield_stmt.expr);
        break;
    case AST_EXPR_STMT:
        ensure_no_dom_elements(context, node->expr_stmt.expr);
        break;
    case AST_CALL:
        for (int i = 0; i < node->call.arg_count; i++) {
            ensure_no_dom_elements(context, node->call.args[i]);
        }
        break;
    case AST_INIT_LIST:
        for (int i = 0; i < node->init_list.count; i++) {
            ensure_no_dom_elements(context, node->init_list.elements[i]);
        }
        break;
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++) {
            ensure_no_dom_elements(context, node->block.stmts[i]);
        }
        break;
    case AST_UNCHECKED:
        ensure_no_dom_elements(context, node->unchecked_block.body);
        break;
    case AST_STMT_EXPR:
        ensure_no_dom_elements(context, node->stmt_expr.block);
        break;
    case AST_FUNDEF:
        ensure_no_dom_elements(context, node->fundef.body);
        break;
    case AST_FUN_LITERAL:
        ensure_no_dom_elements(context, node->fun_literal.body);
        break;
    case AST_MEMBER_ACCESS:
        ensure_no_dom_elements(context, node->member_access.lhs);
        break;
    case AST_ARROW_ACCESS:
        ensure_no_dom_elements(context, node->arrow_access.lhs);
        break;
    case AST_SIZEOF:
        ensure_no_dom_elements(context, node->sizeof_expr.expr);
        break;
    default:
        break;
    }
}

void dom_lowering_reset(ParserContext *context) {
    context->lowering.dom_node_counter = 0;
    context->lowering.dom_program = NULL;
    context->lowering.dom_current_fn = NULL;
}

// The whole program is kept so element tags can be resolved against imports.
void dom_lowering_set_program(ParserContext *context, ASTNode *program) {
    context->lowering.dom_program = program;
}
