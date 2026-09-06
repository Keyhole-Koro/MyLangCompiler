#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "mylang/frontend/lexer.h"
#include "syntax_engine/syntax_engine.h"

#define TOKEN_KIND_COUNT ((int)EOT + 1)

typedef enum {
    ANGLE_NORMAL = 0,
    ANGLE_GENERIC_OPEN,
    ANGLE_GENERIC_CLOSE,
    ANGLE_GENERIC_DOUBLE_CLOSE,
} AngleKind;

static const char *default_grammar_path =
    "../MySyntaxEngine/tests/fixtures/grammars/mylang_lsp.grammar";
static const char *default_table_cache_path = "mylang-syntax-check.table";

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
        {"FAT_ARROW", "=>"},
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

static bool expected_contains(const SyntaxResult *result, const char *token) {
    for (size_t i = 0; i < result->expected_count; i++) {
        if (strcmp(result->expected[i], token) == 0) return true;
    }
    return false;
}

static size_t count_expected_tokens(const SyntaxResult *result, const char **tokens, size_t token_count) {
    size_t count = 0;
    for (size_t i = 0; i < token_count; i++) {
        if (expected_contains(result, tokens[i])) count++;
    }
    return count;
}

static void append_before_token(char *buf, size_t cap, const Token *unexpected) {
    if (!unexpected || !unexpected->value || unexpected->value[0] == '\0') return;
    append_text(buf, cap, " before ");
    if (unexpected->kind == IDENTIFIER || unexpected->kind == NUMBER ||
        unexpected->kind == STRING_LITERAL || unexpected->kind == CHAR_LITERAL) {
        append_text(buf, cap, expected_label(tokenkind2str(unexpected->kind)));
        append_text(buf, cap, " ");
    }
    append_text(buf, cap, "'");
    append_text(buf, cap, unexpected->value);
    append_text(buf, cap, "'");
}

static bool format_expected_category_message(const SyntaxResult *result, const Token *unexpected, char *buf, size_t cap) {
    static const char *expr_start[] = {
        "IDENTIFIER", "NUMBER", "STRING_LITERAL", "CHAR_LITERAL", "L_PARENTHESES",
        "NOT", "BITNOT", "SUB", "ADD", "ASTARISK", "AMPERSAND", "INC", "DEC", "SIZEOF"
    };
    static const char *type_start[] = {
        "IDENTIFIER", "BOOL", "I32", "U32", "CHAR", "FLOAT", "DOUBLE", "VOID",
        "LONG", "SHORT", "CONST", "REF"
    };
    static const char *stmt_start[] = {
        "L_BRACE", "IF", "WHILE", "DO", "FOR", "RETURN", "BREAK", "CONTINUE",
        "YIELD", "UNCHECKED", "SEMICOLON"
    };

    if (count_expected_tokens(result, expr_start, sizeof(expr_start) / sizeof(expr_start[0])) >= 5) {
        snprintf(buf, cap, "Expected expression");
        append_before_token(buf, cap, unexpected);
        append_text(buf, cap, ".");
        return true;
    }

    if (count_expected_tokens(result, type_start, sizeof(type_start) / sizeof(type_start[0])) >= 4) {
        snprintf(buf, cap, "Expected type");
        append_before_token(buf, cap, unexpected);
        append_text(buf, cap, ".");
        return true;
    }

    if (count_expected_tokens(result, stmt_start, sizeof(stmt_start) / sizeof(stmt_start[0])) >= 4) {
        snprintf(buf, cap, "Expected statement");
        append_before_token(buf, cap, unexpected);
        append_text(buf, cap, ".");
        return true;
    }

    return false;
}

static void add_expected_label(char labels[][64], size_t *count, size_t cap, const char *token) {
    const char *label = expected_label(token);
    for (size_t i = 0; i < *count; i++) {
        if (strcmp(labels[i], label) == 0) return;
    }
    if (*count >= cap) return;
    snprintf(labels[*count], 64, "%s", label);
    (*count)++;
}

static void collect_expected_labels(const SyntaxResult *result, char labels[][64], size_t *count, size_t cap) {
    static const char *preferred[] = {
        "SEMICOLON", "R_PARENTHESES", "R_BRACE", "R_BRACKET", "COMMA",
        "IDENTIFIER", "NUMBER", "STRING_LITERAL", "CHAR_LITERAL",
        "L_PARENTHESES", "L_BRACE", "ASSIGN"
    };

    *count = 0;
    for (size_t i = 0; i < sizeof(preferred) / sizeof(preferred[0]); i++) {
        if (expected_contains(result, preferred[i])) add_expected_label(labels, count, cap, preferred[i]);
    }
    for (size_t i = 0; i < result->expected_count; i++) {
        add_expected_label(labels, count, cap, result->expected[i]);
    }
}

static void format_expected_message(const SyntaxResult *result, const Token *unexpected, char *buf, size_t cap) {
    if (format_expected_category_message(result, unexpected, buf, cap)) return;

    buf[0] = '\0';
    append_text(buf, cap, "Expected: ");

    char labels[64][64];
    size_t label_count = 0;
    collect_expected_labels(result, labels, &label_count, sizeof(labels) / sizeof(labels[0]));

    size_t limit = label_count < 6 ? label_count : 6;
    for (size_t i = 0; i < limit; i++) {
        if (i > 0) append_text(buf, cap, ", ");
        append_text(buf, cap, labels[i]);
    }
    if (label_count > limit) {
        char suffix[64];
        snprintf(suffix, sizeof(suffix), ", ... and %zu more", label_count - limit);
        append_text(buf, cap, suffix);
    }
}

static int build_token_map(const SyntaxGrammar *grammar, int *map) {
    for (int i = 0; i < TOKEN_KIND_COUNT; i++) {
        map[i] = syntax_terminal_id(grammar, tokenkind2str((TokenKind)i));
    }
    return 0;
}

static int generic_name_contains(const char **names, size_t count, const char *name) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(names[i], name) == 0) return 1;
    }
    return 0;
}

static void generic_name_add(const char ***names, size_t *count, const char *name) {
    if (!name || generic_name_contains(*names, *count, name)) return;
    const char **resized = realloc((void *)*names, sizeof(char *) * (*count + 1));
    if (!resized) return;
    *names = resized;
    (*names)[(*count)++] = name;
}

static int find_angle_close(Token **tokens, size_t token_count, size_t open_index, size_t *out_close) {
    int depth = 1;
    for (size_t i = open_index + 1; i < token_count; i++) {
        if (tokens[i]->kind == LT) depth++;
        else if (tokens[i]->kind == GT) depth--;
        else if (tokens[i]->kind == RSH) depth -= 2;
        if (depth == 0) {
            *out_close = i;
            return 1;
        }
        if (depth < 0) return 0;
    }
    return 0;
}

static void mark_generic_span(
    Token **tokens,
    AngleKind *angles,
    size_t open_index,
    size_t close_index
) {
    for (size_t i = open_index; i <= close_index; i++) {
        if (tokens[i]->kind == LT) angles[i] = ANGLE_GENERIC_OPEN;
        else if (tokens[i]->kind == GT) angles[i] = ANGLE_GENERIC_CLOSE;
        else if (tokens[i]->kind == RSH) angles[i] = ANGLE_GENERIC_DOUBLE_CLOSE;
    }
}

/* The LR grammar intentionally cannot distinguish `(Name *)value` from a
 * parenthesized identifier expression without a resolver for user-defined
 * type names.  Treat this unambiguous pointer-cast prefix as transparent so
 * valid compiler input does not become an editor-only syntax error. */
static size_t named_pointer_cast_end(Token **tokens, size_t token_count, size_t start) {
    if (start + 3 >= token_count || tokens[start]->kind != L_PARENTHESES ||
        tokens[start + 1]->kind != IDENTIFIER || tokens[start + 2]->kind != ASTARISK)
        return token_count;
    size_t index = start + 2;
    while (index + 1 < token_count && tokens[index + 1]->kind == ASTARISK) index++;
    return index + 1 < token_count && tokens[index + 1]->kind == R_PARENTHESES
        ? index + 1 : token_count;
}

/* The editor grammar deliberately omits expression-level braces: adding a
 * recursive `IDENTIFIER { name: expr }` production makes its canonical LR(1)
 * table prohibitively large.  A named struct literal is nevertheless fully
 * self-delimiting, so collapse a well-formed token span to one expression
 * token for the lightweight checker.  The compiler remains the authority for
 * type/member validation and code generation. */
static size_t named_struct_literal_end(Token **tokens, size_t token_count, size_t start) {
    if (start + 2 >= token_count || tokens[start]->kind != IDENTIFIER ||
        tokens[start + 1]->kind != L_BRACE)
        return token_count;

    size_t i = start + 2;
    if (tokens[i]->kind == R_BRACE) return i;
    while (i < token_count) {
        if (tokens[i]->kind != IDENTIFIER || i + 1 >= token_count ||
            tokens[i + 1]->kind != COLON)
            return token_count;
        i += 2;
        size_t value_start = i;
        int paren_depth = 0, bracket_depth = 0, brace_depth = 0;
        for (; i < token_count; i++) {
            TokenKind kind = tokens[i]->kind;
            if (kind == L_PARENTHESES) paren_depth++;
            else if (kind == R_PARENTHESES) { if (paren_depth > 0) paren_depth--; }
            else if (kind == L_BRACKET) bracket_depth++;
            else if (kind == R_BRACKET) { if (bracket_depth > 0) bracket_depth--; }
            else if (kind == L_BRACE) brace_depth++;
            else if (kind == R_BRACE) {
                if (brace_depth > 0) { brace_depth--; continue; }
                if (paren_depth == 0 && bracket_depth == 0) break;
            }
            if (kind == COMMA && paren_depth == 0 && bracket_depth == 0 && brace_depth == 0)
                break;
        }
        if (i == value_start || i >= token_count) return token_count;
        if (tokens[i]->kind == R_BRACE) return i;
        if (tokens[i]->kind != COMMA || ++i >= token_count) return token_count;
        if (tokens[i]->kind == R_BRACE) return i; /* trailing comma */
    }
    return token_count;
}

static AngleKind *classify_generic_angles(Token **tokens, size_t token_count) {
    AngleKind *angles = calloc(token_count ? token_count : 1, sizeof(AngleKind));
    const char **generic_names = NULL;
    size_t generic_name_count = 0;
    int brace_depth = 0;

    /* Named imports have no type information in this lightweight syntax
     * checker.  They can nevertheless name a generic template, so record
     * them as candidates.  The following pass only changes '<...>' after one
     * of these names; ordinary relational expressions remain untouched. */
    for (size_t i = 0; i < token_count; i++) {
        if (tokens[i]->kind != IMPORT || i + 1 >= token_count ||
            tokens[i + 1]->kind != L_BRACE)
            continue;
        for (size_t j = i + 2; j < token_count && tokens[j]->kind != R_BRACE; j++) {
            if (tokens[j]->kind == IDENTIFIER)
                generic_name_add(&generic_names, &generic_name_count, tokens[j]->value);
        }
    }

    for (size_t i = 0; i < token_count; i++) {
        if (tokens[i]->kind == L_BRACE) brace_depth++;
        else if (tokens[i]->kind == R_BRACE && brace_depth > 0) brace_depth--;

        if (i + 2 >= token_count || tokens[i]->kind != IDENTIFIER || tokens[i + 1]->kind != LT)
            continue;

        size_t close_index = 0;
        if (!find_angle_close(tokens, token_count, i + 1, &close_index)) continue;
        TokenKind next_kind = close_index + 1 < token_count ? tokens[close_index + 1]->kind : EOT;
        int is_struct_declaration = i > 0 && tokens[i - 1]->kind == STRUCT && next_kind == L_BRACE;
        int is_function_declaration = brace_depth == 0 && next_kind == L_PARENTHESES;
        if (!is_struct_declaration && !is_function_declaration) continue;

        generic_name_add(&generic_names, &generic_name_count, tokens[i]->value);
        mark_generic_span(tokens, angles, i + 1, close_index);
    }

    for (size_t i = 0; i + 1 < token_count; i++) {
        if (tokens[i]->kind != IDENTIFIER || tokens[i + 1]->kind != LT ||
            !generic_name_contains(generic_names, generic_name_count, tokens[i]->value))
            continue;
        size_t close_index = 0;
        if (find_angle_close(tokens, token_count, i + 1, &close_index))
            mark_generic_span(tokens, angles, i + 1, close_index);
    }

    free(generic_names);
    return angles;
}

static SyntaxTable *load_or_build_table(SyntaxGrammar *grammar, const char *cache_path) {
    SyntaxTable *table = NULL;
    if (cache_path) {
        table = syntax_load_lr1_table(grammar, cache_path);
        if (table) return table;
    }

    table = syntax_build_lr1_table(grammar);
    if (table && cache_path) {
        syntax_save_lr1_table(table, cache_path);
    }
    return table;
}

static int check_tokens(
    const SyntaxGrammar *grammar,
    SyntaxTable *table,
    const int *token_map,
    Token *tokens
) {
    (void)grammar;
    if (!tokens) {
        printf("{\"status\":\"error\",\"diagnostics\":[{\"line\":0,\"character\":0,\"endCharacter\":1,\"message\":\"Failed to read source file.\"}]}\n");
        return 0;
    }

    size_t source_count = 0;
    for (Token *t = tokens; t && t->kind != EOT; t = t->next) source_count++;

    Token **source_tokens = calloc(source_count ? source_count : 1, sizeof(Token *));
    size_t source_index = 0;
    for (Token *t = tokens; t && t->kind != EOT; t = t->next)
        source_tokens[source_index++] = t;

    if (!source_tokens) {
        free_tokens(tokens);
        return 1;
    }
    AngleKind *angles = classify_generic_angles(source_tokens, source_count);
    size_t parse_capacity = source_count * 2 + 1;
    int *token_ids = calloc(parse_capacity, sizeof(int));
    Token **token_refs = calloc(parse_capacity, sizeof(Token *));
    size_t *token_source_indices = calloc(parse_capacity, sizeof(size_t));
    int *roles = calloc(parse_capacity, sizeof(int));
    int *source_roles = calloc(source_count ? source_count : 1, sizeof(int));
    SyntaxSymbol *symbols = calloc(parse_capacity, sizeof(SyntaxSymbol));
    size_t symbol_count = 0;
    if (!angles || !token_ids || !token_refs ||
        !token_source_indices || !roles || !source_roles || !symbols) {
        free(source_tokens);
        free(angles);
        free(token_ids);
        free(token_refs);
        free(token_source_indices);
        free(roles);
        free(source_roles);
        free(symbols);
        free_tokens(tokens);
        return 1;
    }

    size_t token_count = 0;
    int generic_depth = 0;
    for (size_t i = 0; i < source_count; i++) {
        Token *t = source_tokens[i];
        size_t struct_literal_end = named_struct_literal_end(source_tokens, source_count, i);
        if (struct_literal_end != source_count) {
            // A number is an unambiguous primary expression in the grammar.
            // Keep the first source token as the diagnostic anchor.
            token_ids[token_count] = token_map[NUMBER];
            token_refs[token_count] = t;
            token_source_indices[token_count++] = i;
            i = struct_literal_end;
            continue;
        }
        size_t cast_end = named_pointer_cast_end(source_tokens, source_count, i);
        if (cast_end != source_count) {
            i = cast_end;
            continue;
        }
        if (angles[i] == ANGLE_GENERIC_OPEN) {
            generic_depth++;
            continue;
        }
        if (generic_depth > 0) {
            if (angles[i] == ANGLE_GENERIC_CLOSE) generic_depth--;
            else if (angles[i] == ANGLE_GENERIC_DOUBLE_CLOSE) generic_depth -= 2;
            continue;
        }
        token_ids[token_count] = token_map[t->kind];
        token_refs[token_count] = t;
        token_source_indices[token_count++] = i;
    }

    SyntaxResult result = syntax_parse_token_ids_ex(
        table, token_ids, token_count, roles, symbols, parse_capacity, &symbol_count);

    for (size_t i = 0; i < token_count; i++) {
        if (roles[i] != 0) source_roles[token_source_indices[i]] = roles[i];
    }

    printf("{\"status\":");
    print_json_string(result.status == SYNTAX_OK ? "ok" : result.status == SYNTAX_INCOMPLETE ? "incomplete" : "error");
    printf(",\"diagnostics\":[");
    if (result.status != SYNTAX_OK) {
        int line = 1;
        int col = 1;
        int end_col = 2;
        Token *unexpected = NULL;
        if (result.token_index < token_count) {
            Token *tok = token_refs[result.token_index];
            unexpected = tok;
            line = tok->line;
            col = tok->col;
            end_col = col + (int)strlen(tok->value);
            if (end_col <= col) end_col = col + 1;
        }
        printf("{\"line\":%d,\"character\":%d,\"endCharacter\":%d,\"message\":", line - 1, col - 1, end_col - 1);
        char message[2048];
        if (result.expected_count > 0) format_expected_message(&result, unexpected, message, sizeof(message));
        else snprintf(message, sizeof(message), "%s", result.status == SYNTAX_INCOMPLETE ? "Incomplete syntax." : "Syntax error.");
        print_json_string(message);
        printf("}");
    }
    printf("],\"tokens\":[");
    {
        int first = 1;
        size_t ti = 0;
        for (Token *t = tokens; t && t->kind != EOT; t = t->next, ti++) {
            if (!first) printf(",");
            first = 0;
            const char *role = (ti < source_count) ? syntax_label_name(table, source_roles[ti]) : NULL;
            if (role)
                printf("[%d,%d,%d,\"%s\",\"%s\"]",
                       t->line - 1, t->col - 1, t->length, tokenkind2str(t->kind), role);
            else
                printf("[%d,%d,%d,\"%s\"]",
                       t->line - 1, t->col - 1, t->length, tokenkind2str(t->kind));
        }
    }
    printf("],\"symbols\":[");
    {
        int first = 1;
        for (size_t i = 0; i < symbol_count; i++) {
            int idx = symbols[i].token_index;
            const char *kind = syntax_label_name(table, symbols[i].kind);
            if (idx < 0 || (size_t)idx >= token_count || !kind) continue;
            Token *t = token_refs[idx];
            if (!first) printf(",");
            first = 0;
            printf("[%d,%d,%d,\"%s\"]", t->line - 1, t->col - 1, t->length, kind);
        }
    }
    printf("]}\n");

    syntax_result_free(&result);
    free(symbols);
    free(source_roles);
    free(token_ids);
    free(token_refs);
    free(token_source_indices);
    free(roles);
    free(angles);
    free(source_tokens);
    free_tokens(tokens);
    return 0;
}

static int check_file(
    const SyntaxGrammar *grammar,
    SyntaxTable *table,
    const int *token_map,
    const char *source_path
) {
    return check_tokens(grammar, table, token_map, lexer_from_file(source_path));
}

static int check_source(
    const SyntaxGrammar *grammar,
    SyntaxTable *table,
    const int *token_map,
    char *source
) {
    if (!source) {
        printf("{\"status\":\"error\",\"diagnostics\":[{\"line\":0,\"character\":0,\"endCharacter\":1,\"message\":\"Failed to read source text.\"}]}\n");
        return 0;
    }
    return check_tokens(grammar, table, token_map, lexer(source));
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

static int run_stdio(const SyntaxGrammar *grammar, SyntaxTable *table, const int *token_map) {
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

            int status = check_source(grammar, table, token_map, source);
            free(source);
            if (status != 0) return status;
            fflush(stdout);
            continue;
        }

        if (check_file(grammar, table, token_map, path) != 0) return 1;
        fflush(stdout);
    }
    return 0;
}

int main(int argc, char **argv) {
    bool stdio = false;
    const char *source_path = NULL;
    const char *grammar_path = default_grammar_path;
    const char *cache_path = default_table_cache_path;

    if (argc >= 2 && strcmp(argv[1], "--stdio") == 0) {
        stdio = true;
        if (argc > 2) grammar_path = argv[2];
        if (argc > 3) cache_path = argv[3];
    } else {
        if (argc < 2) {
            fprintf(stderr, "usage: %s <source.mln> [grammar] [cache]\n       %s --stdio [grammar] [cache]\n", argv[0], argv[0]);
            return 2;
        }
        source_path = argv[1];
        if (argc > 2) grammar_path = argv[2];
        if (argc > 3) cache_path = argv[3];
    }

    char *gpaths[16];
    int gcount = 0;
    char *path_copy = strdup(grammar_path);
    char *tok = strtok(path_copy, ",");
    while (tok && gcount < 16) {
        gpaths[gcount++] = tok;
        tok = strtok(NULL, ",");
    }
    SyntaxGrammar *grammar = syntax_load_grammar_multiple((const char **)gpaths, gcount);
    free(path_copy);
    if (!grammar) return 1;
    SyntaxTable *table = load_or_build_table(grammar, cache_path);
    if (!table) {
        syntax_free_grammar(grammar);
        return 1;
    }

    int token_map[TOKEN_KIND_COUNT];
    build_token_map(grammar, token_map);

    int status = stdio
        ? run_stdio(grammar, table, token_map)
        : check_file(grammar, table, token_map, source_path);
    syntax_free_table(table);
    syntax_free_grammar(grammar);
    return status;
}
