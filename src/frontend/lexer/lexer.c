#include "mylang/frontend/lexer.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include "mylang/support/utils.h"

static void advance_pos(const char *start, size_t len, int *line, int *col) {
    for (size_t i = 0; i < len; i++) {
        char c = start[i];
        if (c == '\n') { (*line)++; *col = 1; }
        else (*col)++;
    }
}

static void unescape_string_literal_inplace(char *s) {
    char *src = s;
    char *dst = s;

    while (*src) {
        if (*src == '\\') {
            src++;
            switch (*src) {
                case 'n': *dst++ = '\n'; src++; break;
                case 't': *dst++ = '\t'; src++; break;
                case 'r': *dst++ = '\r'; src++; break;
                case '0': *dst++ = '\0'; src++; break;
                case '\\': *dst++ = '\\'; src++; break;
                case '"': *dst++ = '"'; src++; break;
                default:
                    if (*src) {
                        *dst++ = *src++;
                    } else {
                        *dst++ = '\\';
                    }
                    break;
            }
            continue;
        }

        *dst++ = *src++;
    }

    *dst = '\0';
}

StringTokenKindMap operators[] = {
    {"==", EQ}, {"!=", NEQ}, {"<=", LTE}, {">=", GTE}, {"&&", LAND}, {"||", LOR},
    {"<<", LSH}, {">>", RSH}, {"++", INC}, {"--", DEC}, {"*", ASTARISK}, {"->", ARROW},
    {"+", ADD}, {"-", SUB}, {"/", DIV}, {"%", MOD}, {"=", ASSIGN},
    {"(", L_PARENTHESES}, {")", R_PARENTHESES}, {";", SEMICOLON}, {",", COMMA},
    {"{", L_BRACE}, {"}", R_BRACE}, {"[", L_BRACKET}, {"]", R_BRACKET},
    {"<", LT}, {">", GT}, {".", DOT}, {"!", NOT}, {"?", QUESTION}, {":", COLON},
    {"|", BITOR}, {"^", BITXOR}, {"~", BITNOT}, {"#", HASH}, {"&", AMPERSAND}
};

StringTokenKindMap reservedWords[] = {
    {"sizeof", SIZEOF}, {"bool", BOOL}, {"u8", U8}, {"u16", U16}, {"i32", I32}, {"u32", U32}, {"char", CHAR}, {"float", FLOAT},
    {"double", DOUBLE}, {"void", VOID}, {"long", LONG}, {"short", SHORT},
    {"const", CONST}, {"static", STATIC}, {"mut", MUT}, {"ref", REF},
    {"extern", EXTERN}, {"auto", AUTO}, {"register", REGISTER},
    {"if", IF}, {"else", ELSE}, {"while", WHILE}, {"do", DO}, {"for", FOR},
    {"switch", SWITCH}, {"case", CASE}, {"default", DEFAULT},
    {"break", BREAK}, {"continue", CONTINUE}, {"return", RETURN},
    {"yield", YIELD}, {"unchecked", UNCHECKED},
    {"of", OF}, {"_", UNDERSCORE},
    {"typedef", TYPEDEF}, {"struct", STRUCT}, {"union", UNION}, {"enum", ENUM},
    {"import", IMPORT}, {"from", FROM}, {"export", EXPORT}, {"package", PACKAGE}, {"rest", REST}
};

char *tokenkind2str(TokenKind kind) {
    switch (kind) {
        case EQ: return "EQ";
        case NEQ: return "NEQ";
        case LTE: return "LTE";
        case GTE: return "GTE";
        case LAND: return "AND";
        case LOR: return "OR";
        case LSH: return "LSH";
        case RSH: return "RSH";
        case INC: return "INC";
        case DEC: return "DEC";
        case ASTARISK: return "ASTARISK";
        case ARROW: return "MEMBER";
        case ADD: return "ADD";
        case SUB: return "SUB";
        case DIV: return "DIV";
        case MOD: return "MOD";
        case ASSIGN: return "ASSIGN";
        case L_PARENTHESES: return "L_PARENTHESES";
        case R_PARENTHESES: return "R_PARENTHESES";
        case SEMICOLON: return "SEMICOLON";
        case COMMA: return "COMMA";
        case L_BRACE: return "L_BRACE";
        case R_BRACE: return "R_BRACE";
        case L_BRACKET: return "L_BRACKET";
        case R_BRACKET: return "R_BRACKET";
        case LT: return "LT";
        case GT: return "GT";
        case DOT: return "DOT";
        case NOT: return "NOT";
        case QUESTION: return "QUESTION";
        case COLON: return "COLON";
        case BITOR: return "BITOR";
        case BITXOR: return "BITXOR";
        case BITNOT: return "BITNOT";
        case HASH: return "HASH";
        case AMPERSAND: return "AMPERSAND";

        case SIZEOF: return "SIZEOF";
        case BOOL: return "BOOL";
        case U8: return "U8";
        case U16: return "U16";
        case I32: return "I32";
        case U32: return "U32";
        case CHAR: return "CHAR";
        case FLOAT: return "FLOAT";
        case DOUBLE: return "DOUBLE";
        case VOID: return "VOID";
        case LONG: return "LONG";
        case SHORT: return "SHORT";
        case CONST: return "CONST";
        case STATIC: return "STATIC";
        case MUT: return "MUT";
        case REF: return "REF";
        case EXTERN: return "EXTERN";
        case AUTO: return "AUTO";
        case REGISTER: return "REGISTER";
        case IF: return "IF";
        case ELSE: return "ELSE";
        case WHILE: return "WHILE";
        case DO: return "DO";
        case FOR: return "FOR";
        case SWITCH: return "SWITCH";
        case CASE: return "CASE";
        case DEFAULT: return "DEFAULT";
        case BREAK: return "BREAK";
        case CONTINUE: return "CONTINUE";
        case RETURN: return "RETURN";
        case YIELD: return "YIELD";
        case UNCHECKED: return "UNCHECKED";
        case OF: return "OF";
        case UNDERSCORE: return "UNDERSCORE";
        case TYPEDEF: return "TYPEDEF";
        case STRUCT: return "STRUCT";
        case UNION: return "UNION";
        case ENUM: return "ENUM";
        case IMPORT: return "IMPORT";
        case FROM: return "FROM";
        case REST: return "REST";
        case EXPORT: return "EXPORT";
        case PACKAGE: return "PACKAGE";

        case NUMBER: return "NUMBER";
        case STRING_LITERAL: return "STRING_LITERAL";
        case CHAR_LITERAL: return "CHAR_LITERAL";
        case IDENTIFIER: return "IDENTIFIER";
        case EOT: return "EOT";
        default: break;
    }
    return "UNKNOWN";
}

Token *createToken(Token *cur, int kind, char *value, int line, int col, int length) {
    Token *newTk = malloc(sizeof(Token));
    newTk->kind = kind;
    newTk->value = strdup(value);
    newTk->line = line;
    newTk->col = col;
    newTk->length = length;
    newTk->next = NULL;
    cur->next = newTk;
    return newTk;
}

bool isComment(char *ptr, char *buffer) {
    if (ptr[0] != '/' || ptr[1] != '/') return false;
    while (*ptr && *ptr != '\n') *buffer++ = *ptr++;
    *buffer = '\0';
    return true;
}

bool isCommentBlock(char *ptr, char *buffer) {
    if (ptr[0] != '/' || ptr[1] != '*') return false;
    ptr += 2;
    while (*ptr && !(ptr[0] == '*' && ptr[1] == '/')) *buffer++ = *ptr++;
    if (*ptr) ptr += 2;
    *buffer = '\0';
    return true;
}

bool isOperator(char *ptr, TokenKind *tk, char *buffer) {
    for (long unsigned int i = 0; i < sizeof(operators)/sizeof(operators[0]); i++) {
        size_t len = strlen(operators[i].str);
        if (strncmp(ptr, operators[i].str, len) == 0) {
            strcpy(buffer, operators[i].str);
            if (tk) *tk = operators[i].kind;
            return true;
        }
    }
    return false;
}

bool isReservedWord(char *ptr, TokenKind *tk, char *buffer) {
    for (long unsigned int i = 0; i < sizeof(reservedWords)/sizeof(reservedWords[0]); i++) {
        size_t len = strlen(reservedWords[i].str);
        if (strncmp(ptr, reservedWords[i].str, len) == 0 &&
            !isalnum(ptr[len]) && ptr[len] != '_') {
            strcpy(buffer, reservedWords[i].str);
            if (tk) *tk = reservedWords[i].kind;
            return true;
        }
    }
    return false;
}

static bool is_bin_digit(char c) { return c == '0' || c == '1'; }

// Recognizes decimal, hexadecimal (0x...), and binary (0b...) integer
// literals, plus decimal floats. Hex/binary literals are normalized to their
// decimal text in `buffer` so the rest of the pipeline (codegen -> assembler)
// only ever sees decimal. `*src_len` receives the number of source characters
// consumed (which differs from strlen(buffer) after normalization).
bool isNumber(char *ptr, char *buffer, size_t *src_len) {
    char *start = ptr;
    int negative = 0;
    if (*ptr == '+' || *ptr == '-') {
        negative = (*ptr == '-');
        ptr++;
    }

    // 0x / 0b prefixed integer literals.
    if (ptr[0] == '0' && (ptr[1] == 'x' || ptr[1] == 'X' || ptr[1] == 'b' || ptr[1] == 'B')) {
        int base = (ptr[1] == 'x' || ptr[1] == 'X') ? 16 : 2;
        char *digits = ptr + 2;
        char *d = digits;
        if (base == 16) {
            while (isxdigit((unsigned char)*d)) d++;
        } else {
            while (is_bin_digit(*d)) d++;
        }
        if (d == digits) return false; // no digits after prefix

        unsigned long value = strtoul(digits, NULL, base);
        long signed_value = negative ? -(long)value : (long)value;
        snprintf(buffer, 64, "%ld", signed_value);
        *src_len = (size_t)(d - start);
        return true;
    }

    char *numStart = ptr;
    while (isdigit(*ptr)) ptr++;
    if (*ptr == '.') {
        ptr++;
        while (isdigit(*ptr)) ptr++;
    }
    if (ptr == numStart) return false;
    size_t len = ptr - start;
    strncpy(buffer, start, len);
    buffer[len] = '\0';
    *src_len = len;
    return true;
}

bool isIdentifier(char *ptr, char *buffer) {
    if (!isalpha(*ptr) && *ptr != '_') return false;
    char *start = ptr;
    while (isalnum(*ptr) || *ptr == '_') ptr++;
    size_t len = ptr - start;
    strncpy(buffer, start, len);
    buffer[len] = '\0';
    return true;
}

bool isStringLiteral(char *ptr, char *buffer) {
    if (*ptr != '"') return false;
    char *start = ptr++;
    while (*ptr && (*ptr != '"' || *(ptr - 1) == '\\')) ptr++;
    if (*ptr != '"') return false;
    ptr++;
    size_t len = ptr - start;
    strncpy(buffer, start, len);
    buffer[len] = '\0';
    return true;
}

int isCharLiteral(char *ptr, char *buffer) {
    if (*ptr != '\'') return 0;
    ptr++;  // skip opening '

    char c;
    int consumed = 1;

    if (*ptr == '\\') {
        ptr++; consumed++;
        switch (*ptr) {
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case '\\': c = '\\'; break;
            case '\'': c = '\''; break;
            case '0': c = '\0'; break;
            default: c = *ptr; break;
        }
        ptr++; consumed++;
    } else {
        c = *ptr++; consumed++;
    }

    if (*ptr != '\'') return 0;
    consumed++;  // closing '
    buffer[0] = c;
    buffer[1] = '\0';

    return consumed;
}

Token *lexer(char *input) {
    Token head = {0};
    Token *cur = &head;
    char *ptr = input;
    /* Sized to the whole input: no single token can exceed it, so the is*()
       helpers that copy into it cannot overflow (even on pathological tokens). */
    char *buffer = malloc(strlen(input) + 1);
    if (!buffer) return NULL;
    size_t consumed_len = 0;
    TokenKind kind;
    int line = 1;
    int col = 1;

    while (*ptr) {
        buffer[0] = '\0';

        if (isspace(*ptr)) {
            advance_pos(ptr, 1, &line, &col);
            ptr++;
            continue;
        }

        if (isComment(ptr, buffer)) {
            size_t consumed = strlen(buffer);
            advance_pos(ptr, consumed, &line, &col);
            ptr += consumed;
            while (*ptr && *ptr != '\n') { advance_pos(ptr,1,&line,&col); ptr++; }
            if (*ptr == '\n') { advance_pos(ptr,1,&line,&col); ptr++; }
            continue;
        }

        if (isCommentBlock(ptr, buffer)) {
            // Consume up to and including '*/', or to end of input if unclosed
            // (an unterminated comment must not advance past the buffer).
            char *end = strstr(ptr, "*/");
            size_t consumed = end ? (size_t)(end + 2 - ptr) : strlen(ptr);
            advance_pos(ptr, consumed, &line, &col);
            ptr += consumed;
            continue;
        }

        if (isOperator(ptr, &kind, buffer)) {
            int tok_line = line, tok_col = col;
            size_t consumed = strlen(buffer);
            cur = createToken(cur, kind, buffer, tok_line, tok_col, (int)consumed);
            advance_pos(ptr, consumed, &line, &col);
            ptr += consumed;
            continue;
        }

        if (isReservedWord(ptr, &kind, buffer)) {
            int tok_line = line, tok_col = col;
            size_t consumed = strlen(buffer);
            cur = createToken(cur, kind, buffer, tok_line, tok_col, (int)consumed);
            advance_pos(ptr, consumed, &line, &col);
            ptr += consumed;
            continue;
        }

        if (isNumber(ptr, buffer, &consumed_len)) {
            int tok_line = line, tok_col = col;
            cur = createToken(cur, NUMBER, buffer, tok_line, tok_col, (int)consumed_len);
            advance_pos(ptr, consumed_len, &line, &col);
            ptr += consumed_len;
            continue;
        }

        if (isIdentifier(ptr, buffer)) {
            int tok_line = line, tok_col = col;
            size_t consumed = strlen(buffer);
            cur = createToken(cur, IDENTIFIER, buffer, tok_line, tok_col, (int)consumed);
            advance_pos(ptr, consumed, &line, &col);
            ptr += consumed;
            continue;
        }

        if (isStringLiteral(ptr, buffer)) {
            int tok_line = line, tok_col = col;
            size_t consumed = strlen(buffer);
            ptr += consumed;
            advance_pos(ptr - consumed, consumed, &line, &col);

            memmove(buffer, buffer + 1, strlen(buffer) - 2); // Remove quotes
            buffer[strlen(buffer) - 2] = '\0';
            unescape_string_literal_inplace(buffer);
            cur = createToken(cur, STRING_LITERAL, buffer, tok_line, tok_col, (int)consumed);
            continue;
        }

        int len;
        if ((len = isCharLiteral(ptr, buffer)) > 0) {
            int tok_line = line, tok_col = col;
            cur = createToken(cur, CHAR_LITERAL, buffer, tok_line, tok_col, len);
            advance_pos(ptr, (size_t)len, &line, &col);
            ptr += len;
            continue;
        }

        advance_pos(ptr, 1, &line, &col);
        ptr++;
    }

    createToken(cur, EOT, "", line, col, 0);
    free(buffer);
    return head.next;
}

Token *lexer_from_file(const char *file_path) {
    if (!file_path) return NULL;
    char *input = readSampleInput(file_path);
    if (!input) return NULL;
    Token *tokens = lexer(input);
    free(input);
    return tokens;
}
