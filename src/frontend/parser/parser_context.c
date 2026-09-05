#include "mylang/frontend/parser_internal.h"

static ParserContext default_context = {
    .module.current_package = (char *)g_default_package,
};

ParserContext *parser_context_current(void) {
    return &default_context;
}

void parser_context_init(ParserContext *context) {
    if (!context) return;
    *context = (ParserContext){
        .module.current_package = (char *)g_default_package,
    };
}
