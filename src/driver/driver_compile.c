#include "mylang/driver/driver_internal.h"

static void dump_tokens(FILE *out, Token *tokens) {
    for (Token *t = tokens; t; t = t->next) {
        fprintf(out, "Token: kind=%s, value=%s\n",
                tokenkind2str(t->kind), t->value ? t->value : "(null)");
    }
}

int compile_one(const char *input_path, const char *output_path) {
    Token *tokens = lexer_from_file(input_path);
    if (!tokens) {
        fprintf(stderr, "Failed to read input file (or included files): %s\n", input_path);
        return 1;
    }
    parser_reset();
    parser_set_filename(input_path);

    dump_tokens(stdout, tokens);

    Token *cur = tokens;
    ASTNode *root = parse_program(&cur);

    print_ast(root, 0);
    printf("AST parsing completed.\n");

    char *output = codegen(root);
    if (!output) {
        fprintf(stderr, "Code generation failed.\n");
        free_ast(root);
        free_tokens(tokens);
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
    parser_reset();
    return 0;
}
