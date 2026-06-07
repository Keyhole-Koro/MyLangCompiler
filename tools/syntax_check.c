#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "mylang/frontend/lexer.h"
#include "mylang_syntax_engine/syntax_engine.h"

#define TOKEN_KIND_COUNT ((int)EOT + 1)

static const char *default_grammar_path =
    "../MyLangSyntaxEngine/tests/fixtures/grammars/mylang_lsp.grammar";

static void free_tokens(Token *token) {
    while (token) {
        Token *next = token->next;
        free(token->value);
        free(token);
        token = next;
    }
}

static void print_json_string(const char *text) {
    putchar('"');
    for (const char *p = text; *p; p++) {
        switch (*p) {
            case '\\': printf("\\\\"); break;
            case '"': printf("\\\""); break;
            case '\n': printf("\\n"); break;
            case '\r': printf("\\r"); break;
            case '\t': printf("\\t"); break;
            default: putchar(*p); break;
        }
    }
    putchar('"');
}

static const char *expected_label(const char *token) {
    struct Label {
        const char *token;
        const char *label;
    };
    static const struct Label labels[] = {
        {"IDENTIFIER", "identifier"},
        {"NUMBER", "number"},
        {"STRING_LITERAL", "string literal"},
        {"CHAR_LITERAL", "char literal"},
        {"BOOL", "bool"},
        {"I32", "i32"},
        {"U32", "u32"},
        {"CHAR", "char"},
        {"FLOAT", "float"},
        {"DOUBLE", "double"},
        {"VOID", "void"},
        {"LONG", "long"},
        {"SHORT", "short"},
        {"CONST", "const"},
        {"STATIC", "static"},
        {"MUT", "mut"},
        {"REF", "ref"},
        {"EXTERN", "extern"},
        {"AUTO", "auto"},
        {"REGISTER", "register"},
        {"IF", "if"},
        {"ELSE", "else"},
        {"WHILE", "while"},
        {"DO", "do"},
        {"FOR", "for"},
        {"SWITCH", "switch"},
        {"CASE", "case"},
        {"DEFAULT", "default"},
        {"BREAK", "break"},
        {"CONTINUE", "continue"},
        {"RETURN", "return"},
        {"YIELD", "yield"},
        {"UNCHECKED", "unchecked"},
        {"OF", "of"},
        {"TYPEDEF", "typedef"},
        {"STRUCT", "struct"},
        {"UNION", "union"},
        {"ENUM", "enum"},
        {"SIZEOF", "sizeof"},
        {"IMPORT", "import"},
        {"EXPORT", "export"},
        {"PACKAGE", "package"},
        {"FROM", "from"},
        {"REST", "rest"},
        {"EQ", "=="},
        {"NEQ", "!="},
        {"LTE", "<="},
        {"GTE", ">="},
        {"AND", "&&"},
        {"OR", "||"},
        {"LSH", "<<"},
        {"RSH", ">>"},
        {"INC", "++"},
        {"DEC", "--"},
        {"ASTARISK", "*"},
        {"MEMBER", "->"},
        {"ADD", "+"},
        {"SUB", "-"},
        {"DIV", "/"},
        {"MOD", "%"},
        {"ASSIGN", "="},
        {"L_PARENTHESES", "("},
        {"R_PARENTHESES", ")"},
        {"SEMICOLON", ";"},
        {"COMMA", ","},
        {"L_BRACE", "{"},
        {"R_BRACE", "}"},
        {"L_BRACKET", "["},
        {"R_BRACKET", "]"},
        {"LT", "<"},
        {"GT", ">"},
        {"DOT", "."},
        {"NOT", "!"},
        {"QUESTION", "?"},
        {"COLON", ":"},
        {"BITOR", "|"},
        {"BITXOR", "^"},
        {"BITNOT", "~"},
        {"HASH", "#"},
        {"AMPERSAND", "&"},
    };
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        if (strcmp(token, labels[i].token) == 0) return labels[i].label;
    }
    return token;
}

static void append_text(char *buf, size_t cap, const char *text) {
    size_t len = strlen(buf);
    if (len + 1 >= cap) return;
    snprintf(buf + len, cap - len, "%s", text);
}

static void format_expected_message(const SyntaxResult *result, char *buf, size_t cap) {
    buf[0] = '\0';
    append_text(buf, cap, "Expected: ");
    size_t shown = 0;
    size_t limit = result->expected_count < 12 ? result->expected_count : 12;
    for (size_t i = 0; i < result->expected_count && shown < limit; i++) {
        if (shown > 0) append_text(buf, cap, ", ");
        append_text(buf, cap, expected_label(result->expected[i]));
        shown++;
    }
    if (result->expected_count > shown) {
        char suffix[64];
        snprintf(suffix, sizeof(suffix), ", ... and %zu more", result->expected_count - shown);
        append_text(buf, cap, suffix);
    }
}

static int build_token_map(const SyntaxGrammar *grammar, int *map) {
    for (int i = 0; i < TOKEN_KIND_COUNT; i++) {
        map[i] = syntax_terminal_id(grammar, tokenkind2str((TokenKind)i));
    }
    return 0;
}

static int check_tokens(SyntaxTable *table, const int *token_map, Token *tokens) {
    if (!tokens) {
        printf("{\"status\":\"error\",\"diagnostics\":[{\"line\":0,\"character\":0,\"endCharacter\":1,\"message\":\"Failed to read source file.\"}]}\n");
        return 0;
    }

    size_t token_count = 0;
    for (Token *t = tokens; t && t->kind != EOT; t = t->next) token_count++;

    int *token_ids = calloc(token_count ? token_count : 1, sizeof(int));
    Token **token_refs = calloc(token_count ? token_count : 1, sizeof(Token *));
    if (!token_ids || !token_refs) {
        free(token_ids);
        free(token_refs);
        free_tokens(tokens);
        return 1;
    }

    size_t index = 0;
    for (Token *t = tokens; t && t->kind != EOT; t = t->next) {
        token_ids[index] = token_map[t->kind];
        token_refs[index] = t;
        index++;
    }

    SyntaxResult result = syntax_parse_token_ids(table, token_ids, token_count);

    printf("{\"status\":");
    print_json_string(result.status == SYNTAX_OK ? "ok" : result.status == SYNTAX_INCOMPLETE ? "incomplete" : "error");
    printf(",\"diagnostics\":[");
    if (result.status != SYNTAX_OK) {
        int line = 1;
        int col = 1;
        int end_col = 2;
        if (result.token_index < token_count) {
            Token *tok = token_refs[result.token_index];
            line = tok->line;
            col = tok->col;
            end_col = col + (int)strlen(tok->value);
            if (end_col <= col) end_col = col + 1;
        }
        printf("{\"line\":%d,\"character\":%d,\"endCharacter\":%d,\"message\":", line - 1, col - 1, end_col - 1);
        char message[2048];
        if (result.expected_count > 0) format_expected_message(&result, message, sizeof(message));
        else snprintf(message, sizeof(message), "%s", result.status == SYNTAX_INCOMPLETE ? "Incomplete syntax." : "Syntax error.");
        print_json_string(message);
        printf("}");
    }
    printf("]}\n");

    syntax_result_free(&result);
    free(token_ids);
    free(token_refs);
    free_tokens(tokens);
    return 0;
}

static int check_file(SyntaxTable *table, const int *token_map, const char *source_path) {
    return check_tokens(table, token_map, lexer_from_file(source_path));
}

static int check_source(SyntaxTable *table, const int *token_map, char *source) {
    if (!source) {
        printf("{\"status\":\"error\",\"diagnostics\":[{\"line\":0,\"character\":0,\"endCharacter\":1,\"message\":\"Failed to read source text.\"}]}\n");
        return 0;
    }
    return check_tokens(table, token_map, lexer(source));
}

static int consume_record_separator(void) {
    int c = getchar();
    if (c == EOF || c == '\n') return 0;
    if (c == '\r') {
        c = getchar();
        return c == EOF || c == '\n' ? 0 : 1;
    }
    return 1;
}

static int run_stdio(SyntaxTable *table, const int *token_map) {
    printf("ready\n");
    fflush(stdout);

    char path[4096];
    while (fgets(path, sizeof(path), stdin)) {
        path[strcspn(path, "\r\n")] = '\0';
        if (path[0] == '\0') continue;

        if (strncmp(path, "content ", 8) == 0) {
            char *end = NULL;
            unsigned long length = strtoul(path + 8, &end, 10);
            if (end == path + 8) return 1;

            char *source = malloc(length + 1);
            if (!source) return 1;
            size_t got = fread(source, 1, length, stdin);
            source[got] = '\0';
            if (got != length || consume_record_separator() != 0) {
                free(source);
                return 1;
            }

            int status = check_source(table, token_map, source);
            free(source);
            if (status != 0) return status;
            fflush(stdout);
            continue;
        }

        if (check_file(table, token_map, path) != 0) return 1;
        fflush(stdout);
    }
    return 0;
}

int main(int argc, char **argv) {
    bool stdio = false;
    const char *source_path = NULL;
    const char *grammar_path = default_grammar_path;

    if (argc >= 2 && strcmp(argv[1], "--stdio") == 0) {
        stdio = true;
        if (argc > 2) grammar_path = argv[2];
    } else {
        if (argc < 2) {
            fprintf(stderr, "usage: %s <source.mln> [grammar]\n       %s --stdio [grammar]\n", argv[0], argv[0]);
            return 2;
        }
        source_path = argv[1];
        if (argc > 2) grammar_path = argv[2];
    }

    SyntaxGrammar *grammar = syntax_load_grammar(grammar_path);
    if (!grammar) return 1;
    SyntaxTable *table = syntax_build_lr1_table(grammar);
    if (!table) {
        syntax_free_grammar(grammar);
        return 1;
    }

    int token_map[TOKEN_KIND_COUNT];
    build_token_map(grammar, token_map);

    int status = stdio ? run_stdio(table, token_map) : check_file(table, token_map, source_path);
    syntax_free_table(table);
    syntax_free_grammar(grammar);
    return status;
}
