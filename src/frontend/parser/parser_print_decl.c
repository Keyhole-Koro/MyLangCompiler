#include "mylang/frontend/parser_internal.h"

static void fprint_indent(FILE *out, int indent) {
    for (int i = 0; i < indent; i++) fprintf(out, "  ");
}

static void fprint_member_name(FILE *out, ASTNode *member, int indent) {
    const char *name = (member->type == AST_STRUCT_MEMBER) ? member->struct_member.name :
                       (member->type == AST_VAR_DECL) ? member->var_decl.name : "";
    fprint_indent(out, indent);
    fprintf(out, "Member:  %s\n", name);
}

static void fprint_type_modifiers(FILE *out, ASTNode *node, int indent) {
    fprint_indent(out, indent);
    fprintf(out, "modifiers:");
    if (node->type_node.type_modifiers & TYPEMOD_CONST) fprintf(out, " const");
    if (node->type_node.type_modifiers & TYPEMOD_UNSIGNED) fprintf(out, " unsigned");
    if (node->type_node.type_modifiers & TYPEMOD_SIGNED) fprintf(out, " signed");
    if (!(node->type_node.type_modifiers & (TYPEMOD_CONST | TYPEMOD_UNSIGNED | TYPEMOD_SIGNED))) fprintf(out, " none");
    fprintf(out, "\n");
}

int fprint_ast_decl_node(FILE *out, ASTNode *node, int indent) {
    switch (node->type) {
    case AST_TYPE:
        fprint_indent(out, indent); fprintf(out, "Type:\n");
        fprint_ast(out, node->type_node.base_type, indent + 1);
        fprint_indent(out, indent); fprintf(out, "pointers: %d\n", node->type_node.pointer_level);
        fprint_type_modifiers(out, node, indent);
        return 1;
    case AST_TYPE_ARRAY:
        fprint_indent(out, indent); fprintf(out, "TypeArray: size=%d\n", node->type_array.array_size);
        fprint_ast(out, node->type_array.element_type, indent + 1);
        return 1;
    case AST_VAR_DECL:
        fprint_indent(out, indent); fprintf(out, "VarDecl:\n");
        fprint_indent(out, indent); fprintf(out, "  Type:\n");
        fprint_ast(out, node->var_decl.var_type, indent + 2);
        fprint_indent(out, indent); fprintf(out, "  Name: %s\n", node->var_decl.name);
        if (node->var_decl.init) {
            fprint_indent(out, indent); fprintf(out, "  Init:\n");
            fprint_ast(out, node->var_decl.init, indent + 2);
        }
        return 1;
    case AST_PARAM:
        fprint_indent(out, indent); fprintf(out, "Param:  %s\n", node->param.name);
        return 1;
    case AST_STRUCT:
        fprint_indent(out, indent); fprintf(out, "Struct: %s\n", node->struct_stmt.name);
        for (int i = 0; i < node->struct_stmt.member_count; i++)
            fprint_member_name(out, node->struct_stmt.members[i], indent + 1);
        return 1;
    case AST_TYPEDEF:
        fprint_indent(out, indent); fprintf(out, "Typedef: %s\n", node->typedef_stmt.alias);
        fprint_indent(out, indent); fprintf(out, "  BaseType:\n");
        fprint_ast(out, node->typedef_stmt.src_type, indent + 2);
        return 1;
    case AST_STRUCT_MEMBER:
        fprint_indent(out, indent); fprintf(out, "StructMember: %s %s\n", node->struct_member.type, node->struct_member.name);
        return 1;
    case AST_TYPEDEF_STRUCT:
        fprint_indent(out, indent); fprintf(out, "TypedefStruct:  -> %s\n", node->typedef_struct.typedef_name);
        for (int i = 0; i < node->typedef_struct.member_count; i++)
            fprint_member_name(out, node->typedef_struct.members[i], indent + 1);
        return 1;
    case AST_IMPORT:
        fprint_indent(out, indent); fprintf(out, "Import: %s\n", node->import_stmt.path);
        for (int i = 0; i < node->import_stmt.symbol_count; i++) {
            fprint_indent(out, indent); fprintf(out, "  Symbol: %s\n", node->import_stmt.symbols[i]);
        }
        return 1;
    case AST_FUNDEF:
        fprint_indent(out, indent); fprintf(out, "Function:  %s\n", node->fundef.name);
        for (int i = 0; i < node->fundef.param_count; i++) {
            fprint_indent(out, indent); fprintf(out, "  Param:  %s\n", node->fundef.params[i]->param.name);
        }
        fprint_ast(out, node->fundef.body, indent + 1);
        return 1;
    default:
        return 0;
    }
}
