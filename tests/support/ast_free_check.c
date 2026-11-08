/* free_ast must release everything ast_clone allocates. check_ast_free.py
 * links this file with src/ast/AST.c and src/frontend/parser/parser_free.c
 * alone, wrapping malloc and free (-Wl,--wrap=...) to count live blocks, then
 * clones and frees a node of every kind that owns strings or arrays, with
 * every owned field set. A field the clone copies and free_ast forgets is a
 * block left behind. */
#include "mylang/ast/AST.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void free_ast(ASTNode *node);

static long live;

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *old, size_t size);
void __real_free(void *block);

void *__wrap_malloc(size_t size) {
    void *block = __real_malloc(size);
    if (block) live++;
    return block;
}

void *__wrap_calloc(size_t count, size_t size) {
    void *block = __real_calloc(count, size);
    if (block) live++;
    return block;
}

void *__wrap_realloc(void *old, size_t size) {
    void *block = __real_realloc(old, size);
    if (block && !old) live++;
    return block;
}

void __wrap_free(void *block) {
    if (block) live--;
    __real_free(block);
}

/* The templates below are never freed: only what the clone allocates is
 * counted against free_ast. */

static ASTNode *node(ASTNodeType type) {
    ASTNode *n = calloc(1, sizeof(ASTNode));
    n->type = type;
    return n;
}

static ASTNode **nodes(int count, ...) {
    ASTNode **list = calloc((size_t)count, sizeof(ASTNode *));
    va_list ap;
    va_start(ap, count);
    for (int i = 0; i < count; i++) list[i] = va_arg(ap, ASTNode *);
    va_end(ap);
    return list;
}

static char **names(int count, ...) {
    char **list = calloc((size_t)count, sizeof(char *));
    va_list ap;
    va_start(ap, count);
    for (int i = 0; i < count; i++) list[i] = va_arg(ap, char *);
    va_end(ap);
    return list;
}

static ASTNode *ident(char *name) {
    ASTNode *n = node(AST_IDENTIFIER);
    n->identifier.name = name;
    return n;
}

static ASTNode *number(char *value) {
    ASTNode *n = node(AST_NUMBER);
    n->number.value = value;
    n->number.enum_name = "Code";
    return n;
}

static ASTNode *named_type(char *name) {
    ASTNode *n = node(AST_TYPE);
    n->type_node.base_type = ident(name);
    return n;
}

static ASTNode *block(int count, ASTNode **stmts) {
    ASTNode *n = node(AST_BLOCK);
    n->block.stmts = stmts;
    n->block.count = count;
    return n;
}

static ASTNode *var_decl(char *name, ASTNode *init) {
    ASTNode *n = node(AST_VAR_DECL);
    n->var_decl.var_type = named_type("i32");
    n->var_decl.name = name;
    n->var_decl.init = init;
    n->var_decl.package = "pkg";
    n->var_decl.link_name = "__mlg_m_0123456789abcdef_global";
    return n;
}

static ASTNode *call(void) {
    ASTNode *n = node(AST_CALL);
    n->call.name = "make";
    n->call.type_args = nodes(1, named_type("i32"));
    n->call.type_arg_count = 1;
    n->call.args = nodes(2, number("1"), ident("x"));
    n->call.arg_count = 2;
    n->call.recv = ident("self");
    return n;
}

/* Two type parameters, `T: Eq` and `const N`. */
static void type_params(char ***params, unsigned char **is_const, ASTNode ***bounds, int *count) {
    *params = names(2, "T", "N");
    *is_const = calloc(2, 1);
    (*is_const)[1] = 1;
    *bounds = nodes(2, block(1, nodes(1, named_type("Eq"))), NULL);
    *count = 2;
}

static ASTNode *string_literal(void) {
    ASTNode *n = node(AST_STRING_LITERAL);
    n->string_literal.value = "a\0b";
    n->string_literal.length = 3;
    return n;
}

static ASTNode *expressions(void) {
    ASTNode *member = node(AST_MEMBER_ACCESS);
    member->member_access.lhs = ident("p");
    member->member_access.member = "x";
    ASTNode *arrow = node(AST_ARROW_ACCESS);
    arrow->arrow_access.lhs = member;
    arrow->arrow_access.member = "y";
    ASTNode *character = node(AST_CHAR_LITERAL);
    character->char_literal.value = "c";
    ASTNode *literal = node(AST_INIT_LIST);
    literal->init_list.elements = nodes(3, arrow, character, string_literal());
    literal->init_list.count = 3;
    literal->init_list.struct_type_name = "Box";
    literal->init_list.struct_type_args = nodes(1, named_type("i32"));
    literal->init_list.struct_type_arg_count = 1;
    literal->init_list.field_names = names(3, "a", "b", "c");
    return literal;
}

static ASTNode *case_expr(void) {
    ASTNode *n = node(AST_CASE);
    n->case_expr.target = call();
    n->case_expr.cases = calloc(1, sizeof(CaseItem));
    n->case_expr.cases[0].key = number("1");
    n->case_expr.cases[0].expr = expressions();
    n->case_expr.case_count = 1;
    n->case_expr.default_expr = number("0");
    return n;
}

static ASTNode *dom_element(void) {
    ASTNode *child = node(AST_DOM_ELEMENT);
    child->dom_element.tag = "Label";
    ASTNode *n = node(AST_DOM_ELEMENT);
    n->dom_element.tag = "Window";
    n->dom_element.props = calloc(1, sizeof(DomProp));
    n->dom_element.props[0].name = "title";
    n->dom_element.props[0].value = string_literal();
    n->dom_element.prop_count = 1;
    n->dom_element.children = nodes(1, child);
    n->dom_element.child_count = 1;
    return n;
}

static ASTNode *function(void) {
    ASTNode *param = node(AST_PARAM);
    param->param.type = named_type("i32");
    param->param.name = "x";
    param->param.default_value = number("0");
    ASTNode *ret = node(AST_RETURN);
    ret->ret.expr = case_expr();
    ret->ret.trace_note = "A -> B";
    ASTNode *fn = node(AST_FUNDEF);
    fn->fundef.ret_type = named_type("i32");
    fn->fundef.name = "f";
    fn->fundef.params = nodes(1, param);
    fn->fundef.param_count = 1;
    fn->fundef.body = block(2, nodes(2, var_decl("local", dom_element()), ret));
    fn->fundef.package = "pkg";
    fn->fundef.link_name = "__mlg_m_0123456789abcdef_f";
    fn->fundef.recv_type_name = "Box";
    fn->fundef.origin_path = "lib.mln";
    type_params(&fn->fundef.type_params, &fn->fundef.type_param_is_const,
                &fn->fundef.type_param_bounds, &fn->fundef.type_param_count);
    fn->attrs = calloc(1, sizeof(Attribute));
    fn->attrs[0].name = "app";
    fn->attrs[0].args = calloc(1, sizeof(AttrArg));
    fn->attrs[0].args[0].name = "name";
    fn->attrs[0].args[0].value = string_literal();
    fn->attrs[0].arg_count = 1;
    fn->attr_count = 1;
    return fn;
}

static ASTNode *enumeration(void) {
    ASTNode *member = node(AST_ENUM_MEMBER);
    member->enum_member.name = "Some";
    member->enum_member.value = number("1");
    member->enum_member.payload_type = named_type("T");
    ASTNode *n = node(AST_ENUM);
    n->enum_stmt.name = "Option";
    n->enum_stmt.members = nodes(1, member);
    n->enum_stmt.member_count = 1;
    n->enum_stmt.package = "pkg";
    type_params(&n->enum_stmt.type_params, &n->enum_stmt.type_param_is_const,
                &n->enum_stmt.type_param_bounds, &n->enum_stmt.type_param_count);
    return n;
}

static ASTNode *structure(void) {
    ASTNode *n = node(AST_STRUCT);
    n->struct_stmt.name = "Box";
    n->struct_stmt.members = nodes(1, var_decl("value", NULL));
    n->struct_stmt.member_count = 1;
    n->struct_stmt.package = "pkg";
    n->struct_stmt.payload_enum = enumeration();
    type_params(&n->struct_stmt.type_params, &n->struct_stmt.type_param_is_const,
                &n->struct_stmt.type_param_bounds, &n->struct_stmt.type_param_count);
    return n;
}

static ASTNode *types(void) {
    ASTNode *array = node(AST_TYPE_ARRAY);
    array->type_array.element_type = named_type("u8");
    array->type_array.array_size_param = "N";
    ASTNode *generic = node(AST_TYPE_GENERIC);
    generic->generic_type.name = "Box";
    generic->generic_type.args = nodes(1, array);
    generic->generic_type.arg_count = 1;
    ASTNode *function_type = node(AST_TYPE_FUNCTION);
    function_type->function_type.param_types = nodes(1, generic);
    function_type->function_type.param_count = 1;
    function_type->function_type.return_type = named_type("void");
    ASTNode *alias = node(AST_TYPEDEF);
    alias->typedef_stmt.src_type = function_type;
    alias->typedef_stmt.alias = "Handler";
    alias->typedef_stmt.package = "pkg";
    return alias;
}

static ASTNode *typedef_struct(void) {
    ASTNode *n = node(AST_TYPEDEF_STRUCT);
    n->typedef_struct.struct_name = "point";
    n->typedef_struct.members = nodes(1, var_decl("x", NULL));
    n->typedef_struct.member_count = 1;
    n->typedef_struct.typedef_name = "Point";
    n->typedef_struct.package = "pkg";
    return n;
}

static ASTNode *import(void) {
    ASTNode *n = node(AST_IMPORT);
    n->import_stmt.path = "lib.mln";
    n->import_stmt.symbols = names(2, "Box", "make");
    n->import_stmt.symbol_count = 2;
    return n;
}

static ASTNode *lambda(void) {
    ASTNode *param = node(AST_PARAM);
    param->param.type = named_type("i32");
    param->param.name = "id";
    ASTNode *n = node(AST_FUN_LITERAL);
    n->fun_literal.params = nodes(1, param);
    n->fun_literal.param_count = 1;
    n->fun_literal.body = block(0, NULL);
    return n;
}

int main(void) {
    struct { const char *label; ASTNode *template; } cases[] = {
        { "function", function() },
        { "global", var_decl("global", number("7")) },
        { "struct", structure() },
        { "enum", enumeration() },
        { "typedef", types() },
        { "typedef struct", typedef_struct() },
        { "import", import() },
        { "function literal", lambda() },
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        long before = live;
        free_ast(ast_clone(cases[i].template));
        if (live != before) {
            printf("free_ast leaves %ld block(s) of a cloned %s\n", live - before, cases[i].label);
            failed = 1;
        }
    }
    if (!failed) printf("free_ast releases every cloned node\n");
    return failed;
}
