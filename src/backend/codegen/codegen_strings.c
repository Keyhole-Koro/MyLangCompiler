#include "mylang/backend/codegen_internal.h"

static StrItem *intern_string_item(CompilerContext *cc, const char *s, int length)
{
    if (length < 0) length = 0;
    for (int i = 0; i < cg_string_count; i++) {
        if (cg_strings[i].length == length &&
            (length == 0 || memcmp(cg_strings[i].text, s, (size_t)length) == 0))
            return &cg_strings[i];
    }

    char bytes_buf[32], view_buf[32];
    snprintf(bytes_buf, sizeof(bytes_buf), "s_%d", cg_string_count);
    snprintf(view_buf, sizeof(view_buf), "sv_%d", cg_string_count);
    char *text = malloc((size_t)length + 1);
    if (length > 0) memcpy(text, s, (size_t)length);
    text[length] = '\0';
    StrItem it = { text, length, strdup(bytes_buf), strdup(view_buf) };
    if (!cg_data_sb_inited) {
        sb_init(&cg_data_sb);
        cg_data_sb_inited = 1;
    }

    sb_append(&cg_data_sb, "%s:\n", it.view_label);
    sb_append(&cg_data_sb, "  .word %s, %d\n", it.label, length);
    sb_append(&cg_data_sb, "%s:\n", it.label);
    sb_append(&cg_data_sb, "  .byte ");
    const unsigned char *p = (const unsigned char*)s;
    int first = 1;
    for (int i = 0; i < length; i++) {
        sb_append(&cg_data_sb, "%s0x%02X", first ? "" : ", ", (unsigned)p[i]);
        first = 0;
    }
    sb_append(&cg_data_sb, "%s0x00\n", first ? "" : ", ");

    cg_strings = (StrItem*)realloc(cg_strings, sizeof(StrItem) * (cg_string_count + 1));
    cg_strings[cg_string_count++] = it;
    return &cg_strings[cg_string_count - 1];
}

const char *intern_string_literal_n(CompilerContext *cc, const char *s, int length)
{
    return intern_string_item(cc, s ? s : "", length)->label;
}

const char *intern_string_view_n(CompilerContext *cc, const char *s, int length)
{
    return intern_string_item(cc, s ? s : "", length)->view_label;
}

const char *intern_string_literal(CompilerContext *cc, const char *s)
{
    return intern_string_literal_n(cc, s ? s : "", s ? (int)strlen(s) : 0);
}

void emit_string_literal_into_addr(CompilerContext *cc, ASTNode *literal,
                                   StringBuilder *sb, const char *dest_addr_reg)
{
    if (!literal || literal->type != AST_STRING_LITERAL) return;
    const char *bytes = intern_string_literal_n(cc, literal->string_literal.value,
                                                literal->string_literal.length);
    sb_append(sb, "  movi r1, %s\n", bytes);
    emit_store_to_addr(sb, dest_addr_reg, "r1", 0);
    sb_append(sb, "  movi r1, %d\n", literal->string_literal.length);
    sb_append(sb, "  mov r2, %s\n", dest_addr_reg);
    sb_append(sb, "  addis r2, %d\n", SLOT_SIZE);
    emit_store_to_addr(sb, "r2", "r1", 0);
}

// `movi` carries a 21-bit zero-extended immediate and `movis` a 21-bit
// sign-extended one, so between them a register can be loaded directly with
// any value in [-2^20, 2^21). Anything outside that has no single-instruction
// form on this target: there is no load-upper, and `movis` is signed rather
// than shifted despite the name. Such constants are parked in the data section
// as a word and loaded from there.
//
// Emitted big-endian to match the emulator's u32::from_be_bytes, and via
// `.byte` because that is the only data directive the assembler has.
const char *intern_word_constant(CompilerContext *cc, long value)
{
    unsigned long bits = (unsigned long)value & 0xFFFFFFFFul;

    for (int i = 0; i < cg_const_count; i++) {
        if (((unsigned long)cg_consts[i].value & 0xFFFFFFFFul) == bits)
            return cg_consts[i].label;
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "k_%d", cg_const_count);

    if (!cg_data_sb_inited) {
        sb_init(&cg_data_sb);
        cg_data_sb_inited = 1;
    }

    sb_append(&cg_data_sb, "%s:\n", buf);
    sb_append(&cg_data_sb, "  .byte 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
              (unsigned)((bits >> 24) & 0xFF), (unsigned)((bits >> 16) & 0xFF),
              (unsigned)((bits >> 8) & 0xFF), (unsigned)(bits & 0xFF));

    cg_consts = (ConstItem*)realloc(cg_consts, sizeof(ConstItem) * (cg_const_count + 1));
    cg_consts[cg_const_count].value = value;
    cg_consts[cg_const_count].label = strdup(buf);
    return cg_consts[cg_const_count++].label;
}

// Load an integer constant into target_reg by whichever of the three forms the
// value fits: movi for a small non-negative value, movis for a small negative
// one, and a data-section word otherwise.
void emit_load_const(CompilerContext *cc, StringBuilder *sb, const char *target_reg, long value)
{
    if (value >= 0 && value <= 0x1FFFFF) {
        sb_append(sb, "  movi  %s, %ld\n", target_reg, value);
        return;
    }
    if (value < 0 && value >= -0x100000) {
        sb_append(sb, "  movis %s, %ld\n", target_reg, value);
        return;
    }

    const char *label = intern_word_constant(cc, value);
    sb_append(sb, "  movi  %s, %s\n", target_reg, label);
    sb_append(sb, "  load  %s, %s\n", target_reg, target_reg);
}
