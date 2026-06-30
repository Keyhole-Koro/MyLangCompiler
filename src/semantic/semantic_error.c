#include "mylang/semantic/semantic_internal.h"

SemanticLocation semantic_location_unknown(void) {
    SemanticLocation loc;
    loc.line = 0;
    loc.col = 0;
    loc.end_line = 0;
    loc.end_col = 0;
    return loc;
}

SemanticLocation semantic_location_from_ast(ASTNode *node) {
    SemanticLocation loc = semantic_location_unknown();

    if (!node) return loc;
    if (node->line > 0 || node->col > 0) {
        loc.line = node->line;
        loc.col = node->col;
        loc.end_line = node->end_line > 0 ? node->end_line : node->line;
        loc.end_col = node->end_col > 0 ? node->end_col : node->col;
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

static int semantic_location_has_range(SemanticLocation loc) {
    if (loc.line <= 0 || loc.col <= 0 || loc.end_line <= 0 || loc.end_col <= 0) return 0;
    return loc.end_line != loc.line || loc.end_col != loc.col;
}

static const char *severity_name(SemanticDiagnosticSeverity severity) {
    switch (severity) {
    case SEMANTIC_DIAG_ERROR: return "error";
    case SEMANTIC_DIAG_WARNING: return "warning";
    case SEMANTIC_DIAG_NOTE: return "note";
    default: return "diagnostic";
    }
}

static void print_severity(FILE *out, SemanticDiagnosticSeverity severity, const char *code) {
    fprintf(out, "%s", severity_name(severity));
    if ((severity == SEMANTIC_DIAG_ERROR || severity == SEMANTIC_DIAG_WARNING) &&
        code && code[0] != '\0') {
        fprintf(out, "[%s]", code);
    }
}

static void semantic_diagnostic_at(SemanticContext *ctx, SemanticDiagnosticSeverity severity,
                                   SemanticLocation loc, const char *code,
                                   const char *fmt, va_list ap) {
    if (!ctx) {
        fprintf(stderr, "<input>:%d:%d: ", loc.line, loc.col);
        print_severity(stderr, severity, code);
        fprintf(stderr, ": ");
        vfprintf(stderr, fmt, ap);
        if (semantic_location_has_range(loc)) {
            fprintf(stderr, " [range %d:%d-%d:%d]",
                    loc.line, loc.col, loc.end_line, loc.end_col);
        }
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
    diag->code = code;
    vsnprintf(diag->message, sizeof(diag->message), fmt, ap);
    diag->message[sizeof(diag->message) - 1] = '\0';
    if (severity == SEMANTIC_DIAG_ERROR) ctx->error_count++;
    if (severity == SEMANTIC_DIAG_WARNING) ctx->warning_count++;
}

void semantic_error_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    semantic_diagnostic_at(ctx, SEMANTIC_DIAG_ERROR, loc, NULL, fmt, ap);
    va_end(ap);
}

void semantic_error_code_at(SemanticContext *ctx, SemanticLocation loc, const char *code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    semantic_diagnostic_at(ctx, SEMANTIC_DIAG_ERROR, loc, code, fmt, ap);
    va_end(ap);
}

void semantic_warning_code_at(SemanticContext *ctx, SemanticLocation loc, const char *code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    semantic_diagnostic_at(ctx, SEMANTIC_DIAG_WARNING, loc, code, fmt, ap);
    va_end(ap);
}

void semantic_note_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    semantic_diagnostic_at(ctx, SEMANTIC_DIAG_NOTE, loc, NULL, fmt, ap);
    va_end(ap);
}

void semantic_emit_diagnostics(SemanticContext *ctx) {
    if (!ctx) return;
    const char *filename = ctx->filename ? ctx->filename : "<input>";
    for (int i = 0; i < ctx->diagnostic_count; i++) {
        SemanticDiagnostic *diag = &ctx->diagnostics[i];
        fprintf(stderr, "%s:%d:%d: ",
                filename,
                diag->loc.line,
                diag->loc.col);
        print_severity(stderr, diag->severity, diag->code);
        fprintf(stderr, ": %s", diag->message);
        if (semantic_location_has_range(diag->loc)) {
            fprintf(stderr, " [range %d:%d-%d:%d]",
                    diag->loc.line, diag->loc.col, diag->loc.end_line, diag->loc.end_col);
        }
        fputc('\n', stderr);
    }
}
