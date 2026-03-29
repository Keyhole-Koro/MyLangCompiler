#include "mylang/backend/codegen_internal.h"

const char *intern_string_literal(CompilerContext *cc, const char *s)
{
    for (int i = 0; i < cg_string_count; i++) {
        if (strcmp(cg_strings[i].text, s) == 0) return cg_strings[i].label;
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "s_%d", cg_string_count);
    StrItem it = { strdup(s), strdup(buf) };
    if (!cg_data_sb_inited) {
        sb_init(&cg_data_sb);
        cg_data_sb_inited = 1;
    }

    sb_append(&cg_data_sb, "%s:\n", it.label);
    sb_append(&cg_data_sb, "  .byte ");
    const unsigned char *p = (const unsigned char*)s;
    int first = 1;
    while (*p) {
        sb_append(&cg_data_sb, "%s0x%02X", first ? "" : ", ", (unsigned)*p);
        first = 0;
        p++;
    }
    sb_append(&cg_data_sb, "%s0x00\n", first ? "" : ", ");

    cg_strings = (StrItem*)realloc(cg_strings, sizeof(StrItem) * (cg_string_count + 1));
    cg_strings[cg_string_count++] = it;
    return it.label;
}
