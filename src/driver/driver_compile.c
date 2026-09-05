#include "mylang/driver/driver_internal.h"

static void dump_tokens(FILE *out, Token *tokens) {
    for (Token *t = tokens; t; t = t->next) {
        fprintf(out, "Token: kind=%s, value=%s\n",
                tokenkind2str(t->kind), t->value ? t->value : "(null)");
    }
}

static int is_dom_token(TokenKind kind) {
    return kind == MLX_TAG_OPEN ||
           kind == MLX_TAG_CLOSE ||
           kind == MLX_TAG_SELF_CLOSE ||
           kind == MLX_CLOSE_TAG_OPEN ||
           kind == MLX_TEXT;
}

static Token *first_dom_token(Token *tokens) {
    for (Token *t = tokens; t; t = t->next) {
        if (is_dom_token(t->kind)) return t;
    }
    return NULL;
}

static SemanticSafetyProfile semantic_profile_for_source(MyLangSafetyProfile profile) {
    return profile == MYLANG_SAFETY_STRICT
        ? SEMANTIC_SAFETY_STRICT
        : SEMANTIC_SAFETY_DEFAULT;
}

int compile_one(const char *input_path, const char *output_path) {
    MyLangSourceSpecResult source = mylang_source_spec_parse(input_path);
    if (!source.ok) {
        fprintf(stderr, "Invalid MyLang source filename: %s\n", source.error);
        return 1;
    }

    Token *tokens = lexer_from_file(input_path);
    if (!tokens) {
        fprintf(stderr, "Failed to read input file (or included files): %s\n", input_path);
        return 1;
    }

    Token *dom_token = first_dom_token(tokens);
    if (dom_token && source.spec.syntax != MYLANG_SYNTAX_DOM) {
        fprintf(stderr,
                "%s:%d:%d: DOM syntax requires a canonical .dom.mln filename\n",
                input_path,
                dom_token->line,
                dom_token->col);
        free_tokens(tokens);
        return 1;
    }

    printf("Source profile: syntax=%s, safety=%s\n",
           mylang_syntax_profile_name(source.spec.syntax),
           mylang_safety_profile_name(source.spec.safety));

    parser_reset();
    parser_set_filename(input_path);
    semantic_reset_imported_packages();
    semantic_set_filename(input_path);
    semantic_set_safety_profile(semantic_profile_for_source(source.spec.safety));

    dump_tokens(stdout, tokens);

    Token *cur = tokens;
    ASTNode *root = parse_program(&cur);

    print_ast(root, 0);
    printf("AST parsing completed.\n");

    int pkg_count = parser_get_imported_package_count();
    for (int i = 0; i < pkg_count; i++) {
        const char *pkg = parser_get_imported_package(i);
        if (pkg) semantic_add_imported_package(pkg);
    }

    int success = semantic_check(root);
    if (!success) {
        fprintf(stderr, "Semantic analysis failed.\n");
        free_ast(root);
        free_tokens(tokens);
        semantic_reset_imported_packages();
        parser_reset();
        return 1;
    }
    printf("Semantic analysis completed.\n");

    codegen_set_source_path(input_path);
    char *output = codegen(root);
    if (!output) {
        fprintf(stderr, "Code generation failed.\n");
        free_ast(root);
        free_tokens(tokens);
        semantic_reset_imported_packages();
        parser_reset();
        return 1;
    }

    saveOutput(output_path, output);
    printf("Code generation completed. Output saved to %s\n", output_path);

    char *tokens_txt = build_sidecar_path(output_path, "_tokens.txt");
    char *ast_txt = build_sidecar_path(output_path, "_ast.txt");

    if (tokens_txt) {
        FILE *tf = fopen(tokens_txt, "wb");
        if (tf) {
            dump_tokens(tf, tokens);
            fclose(tf);
            printf("Tokens saved to %s\n", tokens_txt);
        } else {
            perror("Failed to save tokens.txt");
        }
    }

    if (ast_txt) {
        FILE *af = fopen(ast_txt, "wb");
        if (af) {
            fprint_ast(af, root, 0);
            fclose(af);
            printf("AST saved to %s\n", ast_txt);
        } else {
            perror("Failed to save ast.txt");
        }
    }

    free(tokens_txt);
    free(ast_txt);
    free(output);
    free_ast(root);
    free_tokens(tokens);
    semantic_reset_imported_packages();
    parser_reset();
    return 0;
}
