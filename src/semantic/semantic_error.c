#include "mylang/semantic/semantic_internal.h"

SemanticLocation semantic_location_unknown(void) {
    SemanticLocation loc;
    loc.line = 0;
    loc.col = 0;
    return loc;
}

SemanticLocation semantic_location_from_ast(ASTNode *node) {
    SemanticLocation loc = semantic_location_unknown();

    if (!node) return loc;
    if (node->line > 0 || node->col > 0) {
        loc.line = node->line;
        loc.col = node->col;
        return loc;
    }

    switch (node->type) {
    case AST_MEMBER_ACCESS:
        return semantic_location_from_ast(node->member_access.lhs);
    case AST_ARROW_ACCESS:
        return semantic_location_from_ast(node->arrow_access.lhs);
    case AST_UNARY:
        return semantic_location_from_ast(node->unary.operand);
    case AST_BORROW:
        return semantic_location_from_ast(node->borrow.expr);
    case AST_BORROW_MUT:
        return semantic_location_from_ast(node->borrow_mut.expr);
    case AST_ASSIGN:
        return semantic_location_from_ast(node->assign.left);
    case AST_EXPR_STMT:
        return semantic_location_from_ast(node->expr_stmt.expr);
    case AST_RETURN:
        return semantic_location_from_ast(node->ret.expr);
    default:
        return loc;
    }
}

static const char *severity_name(SemanticDiagnosticSeverity severity) {
    switch (severity) {
    case SEMANTIC_DIAG_ERROR: return "error";
    case SEMANTIC_DIAG_NOTE: return "note";
    default: return "diagnostic";
    }
}

static void semantic_diagnostic_at(SemanticContext *ctx, SemanticDiagnosticSeverity severity,
                                   SemanticLocation loc, const char *fmt, va_list ap) {
    if (!ctx) {
        fprintf(stderr, "<input>:%d:%d: %s: ", loc.line, loc.col, severity_name(severity));
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
        return;
    }

    if (ctx->diagnostic_count >= (int)(sizeof(ctx->diagnostics) / sizeof(ctx->diagnostics[0]))) {
        fprintf(stderr, "%s:%d:%d: error: semantic diagnostic buffer exhausted\n",
                ctx->filename ? ctx->filename : "<input>", loc.line, loc.col);
        ctx->error_count++;
        return;
    }

    SemanticDiagnostic *diag = &ctx->diagnostics[ctx->diagnostic_count++];
    diag->severity = severity;
    diag->loc = loc;
    vsnprintf(diag->message, sizeof(diag->message), fmt, ap);
    diag->message[sizeof(diag->message) - 1] = '\0';
    if (severity == SEMANTIC_DIAG_ERROR) ctx->error_count++;
}

void semantic_error_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    semantic_diagnostic_at(ctx, SEMANTIC_DIAG_ERROR, loc, fmt, ap);
    va_end(ap);
}

void semantic_note_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    semantic_diagnostic_at(ctx, SEMANTIC_DIAG_NOTE, loc, fmt, ap);
    va_end(ap);
}

void semantic_emit_diagnostics(SemanticContext *ctx) {
    if (!ctx) return;
    const char *filename = ctx->filename ? ctx->filename : "<input>";
    for (int i = 0; i < ctx->diagnostic_count; i++) {
        SemanticDiagnostic *diag = &ctx->diagnostics[i];
        fprintf(stderr, "%s:%d:%d: %s: %s\n",
                filename,
                diag->loc.line,
                diag->loc.col,
                severity_name(diag->severity),
                diag->message);
    }
}
