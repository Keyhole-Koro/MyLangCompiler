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

static void destroy_compile_session(FrontendSession *session) {
    parser_reset();
    frontend_session_destroy(session);
}

static char *trim_ascii(char *text) {
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') text++;
    char *end = text + strlen(text);
    while (end > text && (end[-1] == ' ' || end[-1] == '\t' ||
                          end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }
    return text;
}

static int unquote_value(char *value) {
    size_t len = strlen(value);
    if (len == 0) return 1;
    if (len < 2 || value[0] != '"' || value[len - 1] != '"') return 0;
    value[len - 1] = '\0';
    memmove(value, value + 1, len - 1);
    return 1;
}

static int project_config_path(const char *input_path, char *out_path, size_t out_size) {
    char current[PATH_MAX];
    if (!realpath(input_path, current)) return 0;
    if (path_is_file(current)) {
        char *slash = strrchr(current, '/');
        if (!slash) return 0;
        *slash = '\0';
    }

    while (current[0]) {
        int written = snprintf(out_path, out_size, "%s/mylang.toml", current);
        if (written < 0 || (size_t)written >= out_size) return 0;
        if (path_is_file(out_path)) return 1;

        char *slash = strrchr(current, '/');
        if (!slash) break;
        if (slash == current) {
            current[1] = '\0';
            break;
        }
        *slash = '\0';
    }
    return 0;
}

static int add_project_aliases(FrontendSession *session, const char *input_path) {
    char config_path[PATH_MAX];
    if (!project_config_path(input_path, config_path, sizeof(config_path))) return 1;

    FILE *file = fopen(config_path, "rb");
    if (!file) {
        fprintf(stderr, "failed to open project config: %s\n", config_path);
        return 0;
    }

    char config_dir[PATH_MAX];
    snprintf(config_dir, sizeof(config_dir), "%s", config_path);
    char *slash = strrchr(config_dir, '/');
    if (!slash) {
        fclose(file);
        return 0;
    }
    *slash = '\0';

    int in_alias_section = 0;
    char line[PATH_MAX * 2];
    int line_number = 0;
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        char *text = trim_ascii(line);
        char *comment = strchr(text, '#');
        if (comment) {
            *comment = '\0';
            text = trim_ascii(text);
        }
        if (*text == '\0') continue;
        if (*text == '[') {
            in_alias_section = strcmp(text, "[alias]") == 0;
            continue;
        }
        if (!in_alias_section) continue;

        char *equals = strchr(text, '=');
        if (!equals) {
            fprintf(stderr, "%s:%d: expected alias assignment\n", config_path, line_number);
            fclose(file);
            return 0;
        }
        *equals = '\0';
        char *name = trim_ascii(text);
        char *target = trim_ascii(equals + 1);
        if (!unquote_value(name) || !unquote_value(target) || name[0] != '@' ||
            name[1] == '\0' || target[0] == '\0') {
            fprintf(stderr, "%s:%d: alias must be \"@name\" = \"path\"\n",
                    config_path, line_number);
            fclose(file);
            return 0;
        }

        char target_path[PATH_MAX];
        if (target[0] == '/') {
            snprintf(target_path, sizeof(target_path), "%s", target);
        } else {
            int written = snprintf(target_path, sizeof(target_path), "%s/%s",
                                   config_dir, target);
            if (written < 0 || (size_t)written >= sizeof(target_path)) {
                fprintf(stderr, "%s:%d: alias target path is too long\n",
                        config_path, line_number);
                fclose(file);
                return 0;
            }
        }
        char resolved[PATH_MAX];
        if (!realpath(target_path, resolved) || !path_is_dir(resolved)) {
            fprintf(stderr, "%s:%d: alias target directory does not exist: %s\n",
                    config_path, line_number, target_path);
            fclose(file);
            return 0;
        }
        if (!frontend_session_add_alias(session, name, resolved)) {
            fprintf(stderr, "%s:%d: duplicate or invalid alias: %s\n",
                    config_path, line_number, name);
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    return 1;
}

static int configure_aliases(FrontendSession *session, const char **aliases, int alias_count) {
    for (int i = 0; i < alias_count; i++) {
        const char *spec = aliases[i];
        const char *equals = strchr(spec, '=');
        if (!equals || equals == spec || equals[1] == '\0') {
            fprintf(stderr, "invalid alias specification: %s\n", spec ? spec : "(null)");
            return 0;
        }
        char name[PATH_MAX];
        size_t name_len = (size_t)(equals - spec);
        if (name_len >= sizeof(name)) {
            fprintf(stderr, "alias name is too long: %s\n", spec);
            return 0;
        }
        memcpy(name, spec, name_len);
        name[name_len] = '\0';
        char resolved[PATH_MAX];
        if (!realpath(equals + 1, resolved) || !path_is_dir(resolved)) {
            fprintf(stderr, "alias target directory does not exist: %s\n", equals + 1);
            return 0;
        }
        if (!frontend_session_add_alias(session, name, resolved)) {
            fprintf(stderr, "failed to register alias '%s'\n", name);
            return 0;
        }
    }
    return 1;
}

typedef struct SourceDependency {
    char *canonical_path;
    const char *kind;
} SourceDependency;

static void free_source_dependencies(SourceDependency *dependencies, int count) {
    for (int i = 0; i < count; i++) free(dependencies[i].canonical_path);
    free(dependencies);
}

static int write_dependency_file(const char *depfile_path,
                                 const char *input_path,
                                 ASTNode *root,
                                 FrontendSession *session) {
    if (!depfile_path) return 1;
    if (!root || root->type != AST_BLOCK || !session || !session->loader) return 0;

    SourceDependency *dependencies = NULL;
    int dependency_count = 0;
    for (int i = 0; i < root->block.count; i++) {
        ASTNode *node = root->block.stmts[i];
        if (!node || node->type != AST_IMPORT || !node->import_stmt.path) continue;

        char canonical[PATH_MAX];
        if (!module_loader_resolve_import_path(session->loader, input_path,
                                               node->import_stmt.path,
                                               canonical, sizeof(canonical))) {
            fprintf(stderr, "failed to resolve import dependency '%s' from '%s'\n",
                    node->import_stmt.path, input_path);
            free_source_dependencies(dependencies, dependency_count);
            return 0;
        }

        const char *kind = NULL;
        if (has_ext(canonical, ".mln")) kind = "mln";
        else if (has_ext(canonical, ".masm")) kind = "masm";
        else {
            fprintf(stderr, "unsupported import dependency type: %s\n", canonical);
            free_source_dependencies(dependencies, dependency_count);
            return 0;
        }
        if (strchr(canonical, '\n') || strchr(canonical, '\r') || strchr(canonical, '\t')) {
            fprintf(stderr, "dependency path contains unsupported control characters: %s\n",
                    canonical);
            free_source_dependencies(dependencies, dependency_count);
            return 0;
        }

        int duplicate = 0;
        for (int j = 0; j < dependency_count; j++) {
            if (strcmp(dependencies[j].canonical_path, canonical) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) continue;

        SourceDependency *grown = realloc(
            dependencies, sizeof(SourceDependency) * (dependency_count + 1));
        if (!grown) {
            fprintf(stderr, "out of memory while collecting dependencies\n");
            free_source_dependencies(dependencies, dependency_count);
            return 0;
        }
        dependencies = grown;
        dependencies[dependency_count].canonical_path = strdup(canonical);
        dependencies[dependency_count].kind = kind;
        if (!dependencies[dependency_count].canonical_path) {
            fprintf(stderr, "out of memory while collecting dependencies\n");
            free_source_dependencies(dependencies, dependency_count);
            return 0;
        }
        dependency_count++;
    }

    FILE *file = fopen(depfile_path, "wb");
    if (!file) {
        fprintf(stderr, "failed to open dependency file: %s\n", depfile_path);
        free_source_dependencies(dependencies, dependency_count);
        return 0;
    }
    fprintf(file, "MYDEPS 1\n");
    for (int i = 0; i < dependency_count; i++) {
        fprintf(file, "%s\t%s\n", dependencies[i].kind,
                dependencies[i].canonical_path);
    }
    int ok = fclose(file) == 0;
    if (!ok) fprintf(stderr, "failed to write dependency file: %s\n", depfile_path);
    free_source_dependencies(dependencies, dependency_count);
    return ok;
}

int compile_one(const char *input_path, const char *output_path,
                int dump_tokens_to_stdout, int dump_ast_to_stdout,
                const char **aliases, int alias_count,
                const char *depfile_path) {
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
    FrontendSession *session = frontend_session_create();
    if (!session) {
        fprintf(stderr, "Failed to create frontend session.\n");
        free_tokens(tokens);
        return 1;
    }
    frontend_session_set_current(session);
    if (!add_project_aliases(session, input_path)) {
        destroy_compile_session(session);
        free_tokens(tokens);
        return 1;
    }
    if (!configure_aliases(session, aliases, alias_count)) {
        destroy_compile_session(session);
        free_tokens(tokens);
        return 1;
    }
    parser_set_filename(input_path);
    semantic_set_filename(input_path);
    semantic_set_safety_profile(semantic_profile_for_source(source.spec.safety));

    if (dump_tokens_to_stdout) dump_tokens(stdout, tokens);
    /* Keep stdout progress/debug output ordered before parser diagnostics on
       stderr when both streams are captured by a build runner. */
    fflush(stdout);

    Token *cur = tokens;
    ASTNode *root = parse_program(&cur);

    if (dump_ast_to_stdout) print_ast(root, 0);
    printf("AST parsing completed.\n");

    int success = semantic_check_with_session(root, session);
    if (!success) {
        fprintf(stderr, "Semantic analysis failed.\n");
        free_ast(root);
        free_tokens(tokens);
        destroy_compile_session(session);
        return 1;
    }
    printf("Semantic analysis completed.\n");

    codegen_set_source_path(input_path);
    char *output = codegen_with_session(root, session);
    if (!output) {
        fprintf(stderr, "Code generation failed.\n");
        free_ast(root);
        free_tokens(tokens);
        destroy_compile_session(session);
        return 1;
    }

    if (!write_dependency_file(depfile_path, input_path, root, session)) {
        free(output);
        free_ast(root);
        free_tokens(tokens);
        destroy_compile_session(session);
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
    destroy_compile_session(session);
    return 0;
}
