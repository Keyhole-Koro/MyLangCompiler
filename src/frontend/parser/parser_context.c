#include "mylang/frontend/parser_internal.h"

static ParserContext default_context = {
    .module.current_package = (char *)g_default_package,
};
static ParserContext *active_context = &default_context;

ParserContext *parser_context_current(void) {
    return active_context;
}

void parser_context_init(ParserContext *context) {
    if (!context) return;
    *context = (ParserContext){
        .module.current_package = (char *)g_default_package,
    };
}

ParserContext *parser_context_activate(ParserContext *context) {
    ParserContext *previous = active_context;
    if (context) active_context = context;
    return previous;
}
