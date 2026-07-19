#ifndef TOKEN_H
#define TOKEN_H
#include <stdbool.h>

typedef int symbol;

typedef enum {
    ADD, SUB, DIV, MOD, ASSIGN, EQ, NEQ, LT, GT, LTE, GTE,
    LAND, LOR, NOT, AMPERSAND, BITOR, BITXOR, BITNOT, LSH, RSH,
    POST_INC, POST_DEC, INC, DEC,

    ASTARISK, ADDRESS, ARROW, FAT_ARROW,

    BOOL, U8, U16, I32, U32, CHAR, FLOAT, DOUBLE, VOID, LONG, SHORT,
    CONST, STATIC, MUT, REF, EXTERN, AUTO, REGISTER,

    IF, ELSE, WHILE, DO, FOR, SWITCH, CASE, DEFAULT, BREAK, CONTINUE,
    RETURN, YIELD, UNCHECKED, OF, UNDERSCORE, TYPEDEF, STRUCT, UNION,
    ENUM, SIZEOF, IMPORT, EXPORT, PACKAGE, FROM, REST,

    L_PARENTHESES, R_PARENTHESES, SEMICOLON, COMMA, L_BRACE, R_BRACE,
    L_BRACKET, R_BRACKET, DOT, QUESTION, COLON, VERTICAL_BAR, CARET, HASH,

    NUMBER, STRING_LITERAL, CHAR_LITERAL, IDENTIFIER, INLINE,

    /* Internal token names are retained temporarily while the DOM parser is
       migrated. They are emitted only when DOM syntax is explicitly enabled. */
    MLX_TAG_OPEN,
    MLX_TAG_CLOSE,
    MLX_TAG_SELF_CLOSE,
    MLX_CLOSE_TAG_OPEN,
    MLX_TEXT,

    EOT
} TokenKind;

typedef struct Token Token;

struct Token {
    TokenKind kind;
    char *value;
    int line;
    int col;
    int length;
    Token *next;
};

typedef enum {
    MODE_DEFAULT,
    MODE_MLX_TAG,
    MODE_MLX_TEXT
} LexerMode;

typedef struct {
    char *input;
    char *ptr;
    int line;
    int col;
    LexerMode mode_stack[16];
    int depth;
    int mlx_tag_depth;
    TokenKind last_token_kind;
    bool eot_returned;
    bool dom_syntax_enabled;
} LexerContext;

LexerContext *lexer_context_create(char *input);
LexerContext *lexer_context_create_with_dom(char *input, bool dom_syntax_enabled);
void lexer_context_destroy(LexerContext *ctx);
Token *lexer_next_token(LexerContext *ctx);

typedef struct {
    char *str;
    symbol kind;
} StringTokenKindMap;

/* lexer() keeps the historical lexer-test behavior and enables DOM syntax.
   Compiler entry points must use lexer_with_dom() with the resolved profile. */
Token *lexer(char *input);
Token *lexer_with_dom(char *input, bool dom_syntax_enabled);

char *tokenkind2str(TokenKind kind);

Token *lexer_from_file(const char *file_path);
Token *lexer_from_file_with_dom(const char *file_path, bool dom_syntax_enabled);

#endif
