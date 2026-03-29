#include "mylang/frontend/parser_ast_internal.h"

ASTNode *new_type_array(ASTNode *elem_type, int size) {
    ASTNode *node = malloc(sizeof(ASTNode));
    node->type = AST_TYPE_ARRAY;
    node->type_array.element_type = elem_type;
    node->type_array.array_size = size;
    return node;
}

ASTNode *new_var_decl(ASTNode *type, char *name, ASTNode *init) {
    ASTNode *node = malloc(sizeof(ASTNode));
    node->type = AST_VAR_DECL;
    node->var_decl.var_type = type;
    node->var_decl.name = strdup(name);
    node->var_decl.init = init;
    node->var_decl.is_exported = 0;
    node->var_decl.package = NULL;
    return node;
}

ASTNode* new_param(ASTNode *type, char *name) {
    ASTNode *node = malloc(sizeof(ASTNode));
    node->type = AST_PARAM;
    node->param.type = type;
    node->param.name = strdup(name);
    return node;
}

ASTNode* new_fundef(ASTNode *ret_type, char *name, ASTNode **params, int param_count, ASTNode *body) {
    ASTNode *node = malloc(sizeof(ASTNode));
    node->type = AST_FUNDEF;
    node->fundef.ret_type = ret_type;
    node->fundef.name = strdup(name);
    node->fundef.params = params;
    node->fundef.param_count = param_count;
    node->fundef.body = body;
    node->fundef.is_exported = 0;
    node->fundef.package = NULL;
    return node;
}

ASTNode *new_fun_literal(ASTNode **params, int param_count, ASTNode *body) {
    ASTNode *node = malloc(sizeof(ASTNode));
    node->type = AST_FUN_LITERAL;
    node->fun_literal.params = params;
    node->fun_literal.param_count = param_count;
    node->fun_literal.body = body;
    node->fun_literal.ret_type = NULL;
    return node;
}

ASTNode *new_type_node(ASTNode *base_type, int pointer_level, int modifiers) {
    ASTNode *node = malloc(sizeof(ASTNode));
    node->type = AST_TYPE;
    node->type_node.base_type = base_type;
    node->type_node.pointer_level = pointer_level;
    node->type_node.type_modifiers = modifiers;
    return node;
}

ASTNode *new_typedef(ASTNode *src_type, char *alias) {
    ASTNode *node = malloc(sizeof(ASTNode));
    node->type = AST_TYPEDEF;
    node->typedef_stmt.src_type = src_type;
    node->typedef_stmt.alias = strdup(alias);
    return node;
}

ASTNode *new_typedef_struct(char *struct_name, ASTNode **members, int member_count, char *typedef_name) {
    ASTNode *node = malloc(sizeof(ASTNode));
    node->type = AST_TYPEDEF_STRUCT;
    node->typedef_struct.struct_name = strdup(struct_name ? struct_name : "");
    node->typedef_struct.members = members;
    node->typedef_struct.member_count = member_count;
    node->typedef_struct.typedef_name = strdup(typedef_name);
    return node;
}

ASTNode *new_struct(char *name, ASTNode **members, int member_count) {
    ASTNode *node = malloc(sizeof(ASTNode));
    node->type = AST_STRUCT;
    node->struct_stmt.name = strdup(name);
    node->struct_stmt.members = members;
    node->struct_stmt.member_count = member_count;
    return node;
}

ASTNode *new_import_stmt(char *path, char **symbols, int count) {
    ASTNode *node = calloc(1, sizeof(ASTNode));
    node->type = AST_IMPORT;
    node->import_stmt.path = strdup(path);
    node->import_stmt.symbols = symbols;
    node->import_stmt.symbol_count = count;
    return node;
}

ASTNode *new_struct_member(char *type, char *name) {
    ASTNode *node = malloc(sizeof(ASTNode));
    node->type = AST_STRUCT_MEMBER;
    node->struct_member.type = strdup(type);
    node->struct_member.name = strdup(name);
    return node;
}
