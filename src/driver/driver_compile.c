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
    return profile == MYLANG_SAFETY_UNSAFE
        ? SEMANTIC_SAFETY_UNSAFE
        : SEMANTIC_SAFETY_CHECKED;
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

/* Resolves one import path from `input_path` and adds it to the list unless
 * it is already there. */
static int add_source_dependency(FrontendSession *session, const char *input_path,
                                 const char *import_path,
                                 SourceDependency **dependencies, int *dependency_count) {
    char canonical[PATH_MAX];
    if (!module_loader_resolve_import_path(session->loader, input_path,
                                           import_path, canonical, sizeof(canonical))) {
        fprintf(stderr, "failed to resolve import dependency '%s' from '%s'\n",
                import_path, input_path);
        return 0;
    }

    const char *kind = NULL;
    if (has_ext(canonical, ".mln")) kind = "mln";
    else if (has_ext(canonical, ".masm")) kind = "masm";
    else {
        fprintf(stderr, "unsupported import dependency type: %s\n", canonical);
        return 0;
    }
    if (strchr(canonical, '\n') || strchr(canonical, '\r') || strchr(canonical, '\t')) {
        fprintf(stderr, "dependency path contains unsupported control characters: %s\n",
                canonical);
        return 0;
    }

    for (int j = 0; j < *dependency_count; j++) {
        if (strcmp((*dependencies)[j].canonical_path, canonical) == 0) return 1;
    }

    SourceDependency *grown = realloc(
        *dependencies, sizeof(SourceDependency) * (*dependency_count + 1));
    if (!grown) {
        fprintf(stderr, "out of memory while collecting dependencies\n");
        return 0;
    }
    *dependencies = grown;
    grown[*dependency_count].canonical_path = strdup(canonical);
    grown[*dependency_count].kind = kind;
    if (!grown[*dependency_count].canonical_path) {
        fprintf(stderr, "out of memory while collecting dependencies\n");
        return 0;
    }
    (*dependency_count)++;
    return 1;
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
        if (!add_source_dependency(session, input_path, node->import_stmt.path,
                                   &dependencies, &dependency_count)) {
            free_source_dependencies(dependencies, dependency_count);
            return 0;
        }
    }
    /* `--error-trace` calls into the trace module, which this source may never
     * import; the build links it through this manifest. */
    if (codegen_error_trace_used() &&
        !add_source_dependency(session, input_path, "@std/debug/error_trace.mln",
                               &dependencies, &dependency_count)) {
        free_source_dependencies(dependencies, dependency_count);
        return 0;
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

/* What one compilation holds. compile_one frees all of it, however far the
 * steps below get. */
typedef struct {
    const DriverOptions *opts;
    const char *input_path;
    const char *output_path;
    MyLangSourceSpec spec;
    Token *tokens;
    FrontendSession *session;
    ASTNode *root;
    char *output;
} Compilation;

static int writes_output(const Compilation *c) {
    return c->opts->stage == COMPILE_TO_OUTPUT;
}

/* Reads the source profile from the filename and lexes the source. */
static int load_source(Compilation *c) {
    MyLangSourceSpecResult source = mylang_source_spec_parse(c->input_path);
    if (!source.ok) {
        fprintf(stderr, "Invalid MyLang source filename: %s\n", source.error);
        return 0;
    }
    c->spec = source.spec;

    c->tokens = lexer_from_file(c->input_path);
    if (!c->tokens) {
        fprintf(stderr, "Failed to read input file (or included files): %s\n", c->input_path);
        return 0;
    }

    Token *dom_token = first_dom_token(c->tokens);
    if (dom_token && c->spec.syntax != MYLANG_SYNTAX_DOM) {
        fprintf(stderr,
                "%s:%d:%d: DOM syntax requires a canonical .dom.mln filename\n",
                c->input_path,
                dom_token->line,
                dom_token->col);
        return 0;
    }

    if (writes_output(c)) {
        printf("Source profile: syntax=%s, safety=%s\n",
               mylang_syntax_profile_name(c->spec.syntax),
               mylang_safety_profile_name(c->spec.safety));
    }
    return 1;
}

/* Parses the source in a new frontend session and, unless only the parse
 * was asked for, checks it. */
static int run_frontend(Compilation *c) {
    parser_reset();
    c->session = frontend_session_create();
    if (!c->session) {
        fprintf(stderr, "Failed to create frontend session.\n");
        return 0;
    }
    frontend_session_set_current(c->session);
    if (!add_project_aliases(c->session, c->input_path) ||
        !configure_aliases(c->session, c->opts->aliases, c->opts->alias_count)) {
        return 0;
    }
    parser_set_filename(c->input_path);
    semantic_set_filename(c->input_path);
    semantic_set_safety_profile(semantic_profile_for_source(c->spec.safety));

    if (c->opts->dump_tokens) dump_tokens(stdout, c->tokens);
    /* Keep stdout progress/debug output ordered before parser diagnostics on
       stderr when both streams are captured by a build runner. */
    fflush(stdout);

    Token *cur = c->tokens;
    c->root = parse_program(&cur);

    if (c->opts->dump_ast) print_ast(c->root, 0);
    if (writes_output(c)) printf("AST parsing completed.\n");

    if (c->opts->stage == COMPILE_PARSE_ONLY) return 1;
    if (!semantic_check_with_session(c->root, c->session)) {
        if (writes_output(c)) fprintf(stderr, "Semantic analysis failed.\n");
        return 0;
    }
    if (writes_output(c)) printf("Semantic analysis completed.\n");
    return 1;
}

static void dump_tokens_sidecar(FILE *out, const Compilation *c) {
    dump_tokens(out, c->tokens);
}

static void dump_ast_sidecar(FILE *out, const Compilation *c) {
    fprint_ast(out, c->root, 0);
}

/* Writes `<output><suffix>` beside the assembly. A file that cannot be
 * written is reported but does not fail the compile. */
static void write_sidecar(const Compilation *c, const char *suffix, const char *what,
                          void (*dump)(FILE *out, const Compilation *c)) {
    char *path = build_sidecar_path(c->output_path, suffix);
    if (!path) return;
    FILE *file = fopen(path, "wb");
    if (file) {
        dump(file, c);
        fclose(file);
        printf("%s saved to %s\n", what, path);
    } else {
        /* perror()'s format, naming the file by its suffix. */
        fprintf(stderr, "Failed to save %s: %s\n", suffix + 1, strerror(errno));
    }
    free(path);
}

/* Generates the assembly and writes it with the files that go beside it. */
static int emit_output(Compilation *c) {
    codegen_set_source_path(c->input_path);
    c->output = codegen_with_session(c->root, c->session);
    if (!c->output) {
        fprintf(stderr, "Code generation failed.\n");
        return 0;
    }

    if (!write_dependency_file(c->opts->depfile_path, c->input_path, c->root, c->session) ||
        !write_symbol_file(c->opts->symbols_path, c->input_path, c->root, c->output)) {
        return 0;
    }

    saveOutput(c->output_path, c->output);
    printf("Code generation completed. Output saved to %s\n", c->output_path);

    write_sidecar(c, "_tokens.txt", "Tokens", dump_tokens_sidecar);
    write_sidecar(c, "_ast.txt", "AST", dump_ast_sidecar);
    return 1;
}

int compile_one(const DriverOptions *opts, const char *input_path, const char *output_path) {
    Compilation c = {
        .opts = opts,
        .input_path = input_path,
        .output_path = output_path,
    };
    int ok = load_source(&c) && run_frontend(&c) &&
             (!writes_output(&c) || emit_output(&c));

    free(c.output);
    free_ast(c.root);
    free_tokens(c.tokens);
    if (c.session) destroy_compile_session(c.session);
    return ok ? 0 : 1;
}
