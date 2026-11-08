#include "mylang/frontend/parser_internal.h"
#include "mylang/driver/source_spec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * A borrow is checked only while it lives in a local, a parameter or a
 * returned value: the borrow checker sees every use of those inside one
 * function. A borrow stored in a struct field, an enum payload, a global or
 * an array element would outlive that view -- the struct can be moved,
 * returned or kept while the borrowed value is moved away -- so those
 * positions are rejected as written, before generics are instantiated.
 *
 * Generic type arguments follow the same rule, except Option and Result:
 * `Option<borrow T>` is how a method returns "maybe a borrow of my
 * receiver", and the checker tracks such a local like a plain borrow. Any
 * other `Box<borrow T>` would put the borrow in a field. Long-lived links
 * are kept as ids or indices instead, or written with raw pointers in an
 * .unsafe.mln file.
 */

static const char *g_filename;
/* The file is checked, not `.unsafe.mln`: rules U5 and B2 apply. */
static int g_checked_source;
/* A contract describes a wire record, whose pointer fields are addresses
 * that only unsafe code ever follows. */
static int g_contract_source;

static void borrow_position_error(ASTNode *at, const char *what) {
    fprintf(stderr, "%s:%d:%d: error: %s cannot hold a borrow\n",
            g_filename ? g_filename : "<input>", at ? at->line : 0, at ? at->col : 0, what);
    fprintf(stderr, "  note: a borrow lives only in a local, a parameter or a return value; "
                    "keep an id or index instead, or use a raw pointer in an .unsafe.mln file\n");
    exit(1);
}

static int type_is_str(ASTNode *type) {
    return g_checked_source && type && type->type == AST_TYPE && type->type_node.base_type &&
           type->type_node.base_type->type == AST_IDENTIFIER &&
           strcmp(type->type_node.base_type->identifier.name, "str") == 0;
}

static int type_is_borrow(ASTNode *type) {
    return type && type->type == AST_TYPE &&
           (type->type_node.borrow_kind != BORROWKIND_NONE || type_is_str(type));
}

/* Rule U5: a checked file does not spell `T*`. */
static void check_raw_type(ASTNode *type, ASTNode *at) {
    if (!g_checked_source || !type) return;
    if (type->type == AST_TYPE && type->type_node.pointer_level > 0) {
        ASTNode *where = type->line ? type : at;
        fprintf(stderr, "%s:%d:%d: error[E0701]: a raw pointer type outside an .unsafe.mln file\n",
                g_filename ? g_filename : "<input>", where ? where->line : 0, where ? where->col : 0);
        exit(1);
    }
    if (type->type == AST_TYPE) check_raw_type(type->type_node.base_type, at);
    if (type->type == AST_TYPE_ARRAY) check_raw_type(type->type_array.element_type, at);
    if (type->type == AST_TYPE_GENERIC) {
        for (int i = 0; i < type->generic_type.arg_count; i++)
            check_raw_type(type->generic_type.args[i], at);
    }
}

static int generic_may_hold_borrow(const char *name) {
    return strcmp(name, "Option") == 0 || strcmp(name, "Result") == 0;
}

/* Rejects a borrow anywhere inside `type` when `what` is set (a field, a
 * global, ...); otherwise checks only the generic arguments within it. */
static void check_type(ASTNode *type, ASTNode *at, const char *what) {
    if (!type) return;
    switch (type->type) {
    case AST_TYPE:
        if (what && type_is_borrow(type))
            borrow_position_error(type->line ? type : at, what);
        check_type(type->type_node.base_type, at, what);
        return;
    case AST_TYPE_ARRAY:
        if (type_is_borrow(type->type_array.element_type))
            borrow_position_error(type->line ? type : at, "an array element");
        check_type(type->type_array.element_type, at, what);
        return;
    case AST_TYPE_GENERIC:
        for (int i = 0; i < type->generic_type.arg_count; i++) {
            ASTNode *arg = type->generic_type.args[i];
            if (what) {
                check_type(arg, at, what);
            } else if (type_is_borrow(arg) && !generic_may_hold_borrow(type->generic_type.name)) {
                char message[160];
                snprintf(message, sizeof message, "a type argument of '%s'", type->generic_type.name);
                borrow_position_error(arg->line ? arg : at, message);
            } else {
                check_type(arg, at, NULL);
            }
        }
        return;
    default:
        return;
    }
}

static int type_has_raw_pointer(ASTNode *type) {
    if (!type) return 0;
    if (type->type == AST_TYPE)
        return type->type_node.pointer_level > 0 || type_has_raw_pointer(type->type_node.base_type);
    if (type->type == AST_TYPE_ARRAY) return type_has_raw_pointer(type->type_array.element_type);
    if (type->type == AST_TYPE_GENERIC) {
        for (int i = 0; i < type->generic_type.arg_count; i++)
            if (type_has_raw_pointer(type->generic_type.args[i])) return 1;
    }
    return 0;
}

/* Rule U5: what vouches for its caller cannot hand it an address. */
static void check_safe_signature(ASTNode *fn) {
    if (!fn->fundef.is_safe) return;
    int raw = type_has_raw_pointer(fn->fundef.ret_type);
    for (int i = 0; !raw && i < fn->fundef.param_count; i++) {
        ASTNode *param = fn->fundef.params[i];
        raw = param && param->type == AST_PARAM && type_has_raw_pointer(param->param.type);
    }
    if (!raw) return;
    fprintf(stderr, "%s:%d:%d: error[E0702]: a @safe function cannot take or return a raw pointer\n",
            g_filename ? g_filename : "<input>", fn->line, fn->col);
    exit(1);
}

static void check_body(ASTNode **child, void *ctx);

static void check_node(ASTNode *node) {
    if (!node) return;
    switch (node->type) {
    case AST_VAR_DECL:
        check_type(node->var_decl.var_type, node, NULL);
        check_raw_type(node->var_decl.var_type, node);
        break;
    case AST_PARAM:
        check_type(node->param.type, node, NULL);
        check_raw_type(node->param.type, node);
        break;
    case AST_CAST:
        check_type(node->cast.type, node, NULL);
        break;
    case AST_FUNDEF:
        check_type(node->fundef.ret_type, node, NULL);
        check_raw_type(node->fundef.ret_type, node);
        check_safe_signature(node);
        break;
    case AST_TYPE: case AST_TYPE_GENERIC: case AST_TYPE_ARRAY: case AST_TYPE_FUNCTION:
        return;
    default:
        break;
    }
    ast_visit_children(node, check_body, NULL);
}

static void check_body(ASTNode **child, void *ctx) {
    (void)ctx;
    check_node(*child);
}

static void check_members(ASTNode **members, int count, const char *what) {
    for (int i = 0; i < count; i++) {
        ASTNode *m = members[i];
        if (m && m->type == AST_VAR_DECL) {
            check_type(m->var_decl.var_type, m, what);
            if (!g_contract_source) check_raw_type(m->var_decl.var_type, m);
        }
    }
}

void check_borrow_positions(ParserContext *context, ASTNode *program) {
    if (!program || program->type != AST_BLOCK) return;
    g_filename = context->module.filename;
    MyLangSourceSpecResult source = mylang_source_spec_parse(g_filename ? g_filename : "");
    g_checked_source = source.ok && source.spec.safety == MYLANG_SAFETY_CHECKED;
    g_contract_source = g_filename && strstr(g_filename, ".contract.mln") != NULL;
    for (int i = 0; i < program->block.count; i++) {
        ASTNode *node = program->block.stmts[i];
        if (!node) continue;
        switch (node->type) {
        case AST_STRUCT:
            check_members(node->struct_stmt.members, node->struct_stmt.member_count, "a struct field");
            break;
        case AST_TYPEDEF_STRUCT:
            check_members(node->typedef_struct.members, node->typedef_struct.member_count, "a struct field");
            break;
        case AST_ENUM:
            for (int k = 0; k < node->enum_stmt.member_count; k++) {
                ASTNode *m = node->enum_stmt.members[k];
                if (m) check_type(m->enum_member.payload_type, m, "an enum payload");
            }
            break;
        case AST_TYPEDEF:
            check_type(node->typedef_stmt.src_type, node,
                       node->typedef_stmt.is_newtype ? "a newtype" : "a typedef");
            break;
        case AST_VAR_DECL:
            check_type(node->var_decl.var_type, node, "a global");
            check_raw_type(node->var_decl.var_type, node);
            check_node(node->var_decl.init);
            break;
        default:
            check_node(node);
            break;
        }
    }
}
