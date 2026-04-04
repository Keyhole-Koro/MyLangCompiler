#include "mylang/frontend/parser_internal.h"

static void fprint_indent(FILE *out, int indent) {
    for (int i = 0; i < indent; i++) fprintf(out, "  ");
}

int fprint_ast_expr_node(FILE *out, ASTNode *node, int indent) {
    switch (node->type) {
    case AST_NUMBER:
        fprint_indent(out, indent); fprintf(out, "Number: %s\n", node->number.value);
        return 1;
    case AST_IDENTIFIER:
        fprint_indent(out, indent); fprintf(out, "Identifier: %s\n", node->identifier.name);
        return 1;
    case AST_BINARY:
        fprint_indent(out, indent); fprintf(out, "Binary: %s\n", tokenkind2str(node->binary.op));
        fprint_ast(out, node->binary.left, indent + 1);
        fprint_ast(out, node->binary.right, indent + 1);
        return 1;
    case AST_ASSIGN:
        fprint_indent(out, indent); fprintf(out, "Assign\n");
        fprint_ast(out, node->assign.left, indent + 1);
        fprint_ast(out, node->assign.right, indent + 1);
        return 1;
    case AST_BORROW:
        fprint_indent(out, indent); fprintf(out, "Borrow\n");
        fprint_ast(out, node->borrow.expr, indent + 1);
        return 1;
    case AST_BORROW_MUT:
        fprint_indent(out, indent); fprintf(out, "BorrowMut\n");
        fprint_ast(out, node->borrow_mut.expr, indent + 1);
        return 1;
    case AST_UNARY:
        fprint_indent(out, indent);
        switch (node->unary.op) {
        case AMPERSAND: fprintf(out, "Unary: & (address)\n"); break;
        case SUB: fprintf(out, "Unary: - (negate)\n"); break;
        case INC: fprintf(out, "Unary: ++ (pre-increment)\n"); break;
        case DEC: fprintf(out, "Unary: -- (pre-decrement)\n"); break;
        case POST_INC: fprintf(out, "Unary: ++ (post-increment)\n"); break;
        case POST_DEC: fprintf(out, "Unary: -- (post-decrement)\n"); break;
        case ASTARISK: fprintf(out, "Unary: * (dereference)\n"); break;
        default: fprintf(out, "Unary: %d\n", node->unary.op); break;
        }
        fprint_ast(out, node->unary.operand, indent + 1);
        return 1;
    case AST_TERNARY:
        fprint_indent(out, indent); fprintf(out, "Ternary\n");
        fprint_ast(out, node->ternary.cond, indent + 1);
        fprint_ast(out, node->ternary.then_expr, indent + 1);
        fprint_ast(out, node->ternary.else_expr, indent + 1);
        return 1;
    case AST_SIZEOF:
        fprint_indent(out, indent); fprintf(out, "Sizeof\n");
        fprint_ast(out, node->sizeof_expr.expr, indent + 1);
        return 1;
    case AST_CAST:
        fprint_indent(out, indent); fprintf(out, "Cast\n");
        fprint_indent(out, indent); fprintf(out, "  Type:\n");
        fprint_ast(out, node->cast.type, indent + 2);
        fprint_indent(out, indent); fprintf(out, "  Expr:\n");
        fprint_ast(out, node->cast.expr, indent + 2);
        return 1;
    case AST_CASE:
        fprint_indent(out, indent); fprintf(out, "CaseExpr\n");
        fprint_indent(out, indent); fprintf(out, "  Target:\n");
        fprint_ast(out, node->case_expr.target, indent + 2);
        for (int i = 0; i < node->case_expr.case_count; i++) {
            fprint_indent(out, indent); fprintf(out, "  Case:\n");
            fprint_ast(out, node->case_expr.cases[i].key, indent + 3);
            fprint_indent(out, indent); fprintf(out, "  =>\n");
            fprint_ast(out, node->case_expr.cases[i].expr, indent + 3);
        }
        if (node->case_expr.default_expr) {
            fprint_indent(out, indent); fprintf(out, "  Default:\n");
            fprint_ast(out, node->case_expr.default_expr, indent + 2);
        }
        return 1;
    case AST_CALL:
        fprint_indent(out, indent); fprintf(out, "Call: %s\n", node->call.name);
        for (int i = 0; i < node->call.arg_count; i++) fprint_ast(out, node->call.args[i], indent + 1);
        return 1;
    case AST_STRING_LITERAL:
        fprint_indent(out, indent); fprintf(out, "StringLiteral: \"%s\"\n", node->string_literal.value);
        return 1;
    case AST_CHAR_LITERAL:
        fprint_indent(out, indent); fprintf(out, "CharLiteral: '%c'\n", node->char_literal.value ? node->char_literal.value[0] : '\0');
        return 1;
    case AST_MEMBER_ACCESS:
        fprint_indent(out, indent); fprintf(out, "MemberAccess: %s\n", node->member_access.member);
        fprint_ast(out, node->member_access.lhs, indent + 1);
        return 1;
    case AST_ARROW_ACCESS:
        fprint_indent(out, indent); fprintf(out, "ArrowAccess: %s\n", node->arrow_access.member);
        fprint_ast(out, node->arrow_access.lhs, indent + 1);
        return 1;
    case AST_INIT_LIST:
        fprint_indent(out, indent); fprintf(out, "InitList:\n");
        for (int i = 0; i < node->init_list.count; i++) fprint_ast(out, node->init_list.elements[i], indent + 1);
        return 1;
    default:
        return 0;
    }
}
