#include "mylang/ast/AST.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *astType2str(ASTNodeType type) {
    switch (type) {
        case AST_NUMBER: return "AST_NUMBER";
        case AST_IDENTIFIER: return "AST_IDENTIFIER";
        case AST_BINARY: return "AST_BINARY";
        case AST_TYPE: return "AST_TYPE";
        case AST_TYPE_GENERIC: return "AST_TYPE_GENERIC";
        case AST_TYPE_ARRAY: return "AST_TYPE_ARRAY";
        case AST_VAR_DECL: return "AST_VAR_DECL";
        case AST_BORROW: return "AST_BORROW";
        case AST_BORROW_MUT: return "AST_BORROW_MUT";
        case AST_ASSIGN: return "AST_ASSIGN";
        case AST_UNARY: return "AST_UNARY";
        case AST_CAST: return "AST_CAST";
        case AST_EXPR_STMT: return "AST_EXPR_STMT";
        case AST_IF: return "AST_IF";
        case AST_RETURN: return "AST_RETURN";
        case AST_BLOCK: return "AST_BLOCK";
        case AST_FUN_LITERAL: return "AST_FUN_LITERAL";
        case AST_FUNDEF: return "AST_FUNDEF";
        case AST_PARAM: return "AST_PARAM";
        case AST_CALL: return "AST_CALL";
        case AST_WHILE: return "AST_WHILE";
        case AST_FOR: return "AST_FOR";
        case AST_TYPEDEF: return "AST_TYPEDEF";
        case AST_STRUCT: return "AST_STRUCT";
        case AST_STRUCT_MEMBER: return "AST_STRUCT_MEMBER";
        case AST_TYPEDEF_STRUCT: return "AST_TYPEDEF_STRUCT";
        case AST_ENUM: return "AST_ENUM";
        case AST_ENUM_MEMBER: return "AST_ENUM_MEMBER";
        case AST_STRING_LITERAL: return "AST_STRING_LITERAL";
        case AST_CHAR_LITERAL: return "AST_CHAR_LITERAL";
        case AST_MEMBER_ACCESS: return "AST_MEMBER_ACCESS";
        case AST_ARROW_ACCESS: return "AST_ARROW_ACCESS";
        case AST_BREAK: return "AST_BREAK";
        case AST_CONTINUE: return "AST_CONTINUE";
        case AST_DO_WHILE: return "AST_DO_WHILE";
        case AST_INIT_LIST: return "AST_INIT_LIST";
        case AST_SIZEOF: return "AST_SIZEOF";
        case AST_TERNARY: return "AST_TERNARY";
        case AST_IMPORT: return "AST_IMPORT";
        case AST_YIELD: return "AST_YIELD";
        case AST_STMT_EXPR: return "AST_STMT_EXPR";
        case AST_CASE: return "AST_CASE";
        case AST_UNCHECKED: return "AST_UNCHECKED";
        case AST_DOM_ELEMENT: return "AST_DOM_ELEMENT";
    }
    return "<unknown>";
}

void ast_visit_children(ASTNode *n, void (*visit)(ASTNode **, void *), void *ctx) {
    if (!n) return;
#define CHILD(field) visit(&n->field, ctx)
#define CHILDREN(field, count) for (int i = 0; i < n->count; i++) CHILD(field[i])
    switch (n->type) {
    case AST_BINARY: CHILD(binary.left); CHILD(binary.right); break;
    case AST_ASSIGN: CHILD(assign.left); CHILD(assign.right); break;
    case AST_TYPE: CHILD(type_node.base_type); break;
    case AST_TYPE_GENERIC: CHILDREN(generic_type.args, generic_type.arg_count); break;
    case AST_TYPE_ARRAY: CHILD(type_array.element_type); break;
    case AST_VAR_DECL: CHILD(var_decl.var_type); CHILD(var_decl.init); break;
    case AST_TYPEDEF: CHILD(typedef_stmt.src_type); break;
    case AST_CAST: CHILD(cast.type); CHILD(cast.expr); break;
    case AST_BORROW: CHILD(borrow.expr); break;
    case AST_BORROW_MUT: CHILD(borrow_mut.expr); break;
    case AST_UNARY: CHILD(unary.operand); break;
    case AST_EXPR_STMT: CHILD(expr_stmt.expr); break;
    case AST_IF: CHILD(if_stmt.cond); CHILD(if_stmt.then_stmt); CHILD(if_stmt.else_stmt); break;
    case AST_RETURN: CHILD(ret.expr); break;
    case AST_YIELD: CHILD(yield_stmt.expr); break;
    case AST_BLOCK: CHILDREN(block.stmts, block.count); break;
    case AST_UNCHECKED: CHILD(unchecked_block.body); break;
    case AST_STMT_EXPR: CHILD(stmt_expr.block); break;
    case AST_FUN_LITERAL:
        CHILDREN(fun_literal.params, fun_literal.param_count);
        CHILD(fun_literal.body); CHILD(fun_literal.ret_type); break;
    case AST_CASE:
        CHILD(case_expr.target);
        for (int i = 0; i < n->case_expr.case_count; i++) {
            CHILD(case_expr.cases[i].key); CHILD(case_expr.cases[i].expr);
        }
        CHILD(case_expr.default_expr); break;
    case AST_FUNDEF:
        CHILD(fundef.ret_type); CHILDREN(fundef.params, fundef.param_count);
        CHILD(fundef.body); break;
    case AST_PARAM: CHILD(param.type); break;
    case AST_CALL:
        CHILDREN(call.type_args, call.type_arg_count);
        CHILDREN(call.args, call.arg_count); break;
    case AST_DOM_ELEMENT:
        for (int i = 0; i < n->dom_element.prop_count; i++) CHILD(dom_element.props[i].value);
        CHILDREN(dom_element.children, dom_element.child_count); break;
    case AST_WHILE: CHILD(while_stmt.cond); CHILD(while_stmt.body); break;
    case AST_DO_WHILE: CHILD(do_while_stmt.cond); CHILD(do_while_stmt.body); break;
    case AST_FOR:
        CHILD(for_stmt.init); CHILD(for_stmt.cond); CHILD(for_stmt.inc); CHILD(for_stmt.body); break;
    case AST_STRUCT: CHILDREN(struct_stmt.members, struct_stmt.member_count); break;
    case AST_TYPEDEF_STRUCT: CHILDREN(typedef_struct.members, typedef_struct.member_count); break;
    case AST_ENUM: CHILDREN(enum_stmt.members, enum_stmt.member_count); break;
    case AST_ENUM_MEMBER: CHILD(enum_member.value); CHILD(enum_member.payload_type); break;
    case AST_MEMBER_ACCESS: CHILD(member_access.lhs); break;
    case AST_ARROW_ACCESS: CHILD(arrow_access.lhs); break;
    case AST_INIT_LIST: CHILDREN(init_list.elements, init_list.count); break;
    case AST_SIZEOF: CHILD(sizeof_expr.expr); break;
    case AST_TERNARY: CHILD(ternary.cond); CHILD(ternary.then_expr); CHILD(ternary.else_expr); break;
    case AST_NUMBER: case AST_IDENTIFIER: case AST_STRUCT_MEMBER:
    case AST_STRING_LITERAL: case AST_CHAR_LITERAL: case AST_BREAK: case AST_CONTINUE: case AST_IMPORT: break;
    }
#undef CHILD
#undef CHILDREN
}

static void *copy_array(const void *src, size_t bytes) {
    if (!src || !bytes) return NULL;
    void *copy = malloc(bytes);
    if (!copy) { fputs("out of memory copying AST\n", stderr); exit(1); }
    memcpy(copy, src, bytes);
    return copy;
}

static char *copy_string(const char *src) {
    return src ? copy_array(src, strlen(src) + 1) : NULL;
}

static void clone_child(ASTNode **slot, void *unused) {
    (void)unused;
    *slot = ast_clone(*slot);
}

ASTNode *ast_clone(const ASTNode *src) {
    if (!src) return NULL;
    ASTNode *n = copy_array(src, sizeof(*src));
#define STR(field) n->field = copy_string(src->field)
#define ARRAY(field, count) n->field = copy_array(src->field, sizeof(*src->field) * src->count)
#define STRINGS(field, count) do { ARRAY(field, count); for (int i = 0; i < src->count; i++) STR(field[i]); } while (0)
    switch (n->type) {
    case AST_NUMBER: STR(number.value); break;
    case AST_IDENTIFIER: STR(identifier.name); break;
    case AST_TYPE_GENERIC: STR(generic_type.name); ARRAY(generic_type.args, generic_type.arg_count); break;
    case AST_VAR_DECL: STR(var_decl.name); STR(var_decl.package); break;
    case AST_TYPEDEF: STR(typedef_stmt.alias); break;
    case AST_BLOCK: ARRAY(block.stmts, block.count); break;
    case AST_FUN_LITERAL: ARRAY(fun_literal.params, fun_literal.param_count); break;
    case AST_CASE: ARRAY(case_expr.cases, case_expr.case_count); break;
    case AST_FUNDEF:
        STR(fundef.name); STR(fundef.package); ARRAY(fundef.params, fundef.param_count);
        STRINGS(fundef.type_params, fundef.type_param_count); break;
    case AST_PARAM: STR(param.name); break;
    case AST_CALL:
        STR(call.name); ARRAY(call.args, call.arg_count); ARRAY(call.type_args, call.type_arg_count); break;
    case AST_DOM_ELEMENT:
        STR(dom_element.tag); ARRAY(dom_element.props, dom_element.prop_count);
        for (int i = 0; i < src->dom_element.prop_count; i++) STR(dom_element.props[i].name);
        ARRAY(dom_element.children, dom_element.child_count); break;
    case AST_STRUCT:
        STR(struct_stmt.name); STR(struct_stmt.package); ARRAY(struct_stmt.members, struct_stmt.member_count);
        STRINGS(struct_stmt.type_params, struct_stmt.type_param_count); break;
    case AST_STRUCT_MEMBER: STR(struct_member.type); STR(struct_member.name); break;
    case AST_TYPEDEF_STRUCT:
        STR(typedef_struct.struct_name); STR(typedef_struct.typedef_name);
        ARRAY(typedef_struct.members, typedef_struct.member_count); break;
    case AST_ENUM:
        STR(enum_stmt.name); STR(enum_stmt.package); ARRAY(enum_stmt.members, enum_stmt.member_count);
        STRINGS(enum_stmt.type_params, enum_stmt.type_param_count); break;
    case AST_ENUM_MEMBER: STR(enum_member.name); break;
    case AST_CHAR_LITERAL: STR(char_literal.value); break;
    case AST_STRING_LITERAL: STR(string_literal.value); break;
    case AST_MEMBER_ACCESS: STR(member_access.member); break;
    case AST_ARROW_ACCESS: STR(arrow_access.member); break;
    case AST_INIT_LIST:
        ARRAY(init_list.elements, init_list.count);
        STR(init_list.struct_type_name);
        if (src->init_list.field_names)
            STRINGS(init_list.field_names, init_list.count);
        break;
    case AST_IMPORT: STR(import_stmt.path); STRINGS(import_stmt.symbols, import_stmt.symbol_count); break;
    default: break;
    }
#undef STR
#undef ARRAY
#undef STRINGS
    ast_visit_children(n, clone_child, NULL);
    return n;
}
