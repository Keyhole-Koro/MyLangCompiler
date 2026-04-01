#include "mylang/semantic/semantic_internal.h"

SemanticLocation semantic_location_unknown(void) {
    SemanticLocation loc;
    loc.line = 0;
    loc.col = 0;
    return loc;
}

void semantic_error_at(SemanticContext *ctx, SemanticLocation loc, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "%s:%d:%d: error: ",
            (ctx && ctx->filename) ? ctx->filename : "<input>",
            loc.line,
            loc.col);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    if (ctx) ctx->error_count++;
}
