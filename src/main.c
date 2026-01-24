#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>

#include "lexer.h"
#include "parser.h"
#include "codegen.h"
#include "AST.h"
#include "utils.h"

static char *build_sidecar_path(const char *out_path, const char *suffix) {
    if (!out_path || !suffix) return NULL;
    const char *last_slash = strrchr(out_path, '/');
    const char *last_back = strrchr(out_path, '\\');
    const char *sep = last_slash > last_back ? last_slash : last_back;
    const char *fname = sep ? sep + 1 : out_path;
    const char *dot = strrchr(fname, '.');
    size_t base_len = dot ? (size_t)(dot - out_path) : strlen(out_path);
    size_t suff_len = strlen(suffix);
    char *res = (char*)malloc(base_len + suff_len + 1);
    if (!res) return NULL;
    memcpy(res, out_path, base_len);
    memcpy(res + base_len, suffix, suff_len);
    res[base_len + suff_len] = '\0';
    return res;
}

static void free_tokens(Token *t) {
    while (t) {
        Token *next = t->next;
        free(t->value);
        free(t);
        t = next;
    }
}

static int path_is_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

static int path_is_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

static int has_ext(const char *path, const char *ext) {
    size_t plen = strlen(path);
    size_t elen = strlen(ext);
    return plen >= elen && strcmp(path + plen - elen, ext) == 0;
}

static void normalize_slashes(char *s) {
    for (; *s; s++) {
        if (*s == '\\') *s = '/';
    }
}

static int path_has_segment(const char *rel, const char *seg) {
    size_t seglen = strlen(seg);
    const char *p = rel;
    while (*p) {
        while (*p == '/') p++;
        const char *start = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - start);
        if (len == seglen && strncmp(start, seg, len) == 0) return 1;
    }
    return 0;
}

static int should_exclude(const char *rel, const char **excludes, int exclude_count) {
    for (int i = 0; i < exclude_count; i++) {
        const char *ex = excludes[i];
        if (!ex || !ex[0]) continue;
        char exbuf[PATH_MAX];
        snprintf(exbuf, sizeof(exbuf), "%s", ex);
        normalize_slashes(exbuf);
        size_t exlen_trim = strlen(exbuf);
        while (exlen_trim > 0 && exbuf[exlen_trim - 1] == '/') {
            exbuf[--exlen_trim] = '\0';
        }
        if (strchr(exbuf, '/')) {
            size_t exlen = strlen(exbuf);
            if (strncmp(rel, exbuf, exlen) == 0 &&
                (rel[exlen] == '\0' || rel[exlen] == '/')) {
                return 1;
            }
        } else {
            if (path_has_segment(rel, exbuf)) return 1;
        }
    }
    return 0;
}

static char *replace_ext(const char *path, const char *new_ext) {
    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '/');
    if (slash && dot && dot < slash) dot = NULL;
    size_t base_len = dot ? (size_t)(dot - path) : strlen(path);
    size_t ext_len = strlen(new_ext);
    char *out = (char*)malloc(base_len + ext_len + 1);
    if (!out) return NULL;
    memcpy(out, path, base_len);
    memcpy(out + base_len, new_ext, ext_len);
    out[base_len + ext_len] = '\0';
    return out;
}

static char *join_path(const char *a, const char *b) {
    size_t alen = strlen(a);
    size_t blen = strlen(b);
    int need_sep = alen > 0 && a[alen - 1] != '/' && a[alen - 1] != '\\';
    char *out = (char*)malloc(alen + (need_sep ? 1 : 0) + blen + 1);
    if (!out) return NULL;
    memcpy(out, a, alen);
    if (need_sep) out[alen++] = '/';
    memcpy(out + alen, b, blen);
    out[alen + blen] = '\0';
    return out;
}

static int mkdir_p(const char *path) {
    if (!path || !path[0]) return 0;
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    normalize_slashes(tmp);
    size_t len = strlen(tmp);
    if (len == 0) return 0;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0777) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0777) != 0 && errno != EEXIST) return -1;
    return 0;
}

static void ensure_parent_dir(const char *file_path) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", file_path);
    normalize_slashes(tmp);
    char *slash = strrchr(tmp, '/');
    if (!slash) return;
    *slash = '\0';
    mkdir_p(tmp);
}

static int copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) {
        perror("Failed to open input file");
        return 1;
    }
    ensure_parent_dir(dst);
    FILE *out = fopen(dst, "wb");
    if (!out) {
        perror("Failed to open output file");
        fclose(in);
        return 1;
    }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            perror("Failed to write output file");
            fclose(in);
            fclose(out);
            return 1;
        }
    }
    fclose(in);
    fclose(out);
    return 0;
}

static int compile_one(const char *input_path, const char *output_path) {
    Token *tokens = lexer_from_file(input_path);
    if (!tokens) {
        fprintf(stderr, "Failed to read input file (or included files): %s\n", input_path);
        return 1;
    }
    parser_reset();
    parser_set_filename(input_path);

    // Also print to console as before
    for (Token *t = tokens; t; t = t->next) {
        printf("Token: kind=%s, value=%s\n", tokenkind2str(t->kind), t->value ? t->value : "(null)");
    }

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

    // Save lexer tokens and AST to sidecar .txt files next to the output
    char *tokens_txt = build_sidecar_path(output_path, "_tokens.txt");
    char *ast_txt = build_sidecar_path(output_path, "_ast.txt");

    if (tokens_txt) {
        FILE *tf = fopen(tokens_txt, "wb");
        if (tf) {
            for (Token *t = tokens; t; t = t->next) {
                fprintf(tf, "Token: kind=%s, value=%s\n",
                        tokenkind2str(t->kind), t->value ? t->value : "(null)");
            }
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

typedef struct {
    const char *src_root;
    size_t src_root_len;
    const char *out_root;
    const char **excludes;
    int exclude_count;
    int include_masm;
    int compiled_count;
    int copied_count;
} WalkCtx;

static int walk_dir(WalkCtx *ctx, const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("Failed to open directory");
        return 1;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char *child_path = join_path(dir_path, entry->d_name);
        if (!child_path) {
            closedir(dir);
            return 1;
        }
        int is_dir = path_is_dir(child_path);
        int is_file = path_is_file(child_path);

        const char *rel = child_path + ctx->src_root_len;
        if (*rel == '/' || *rel == '\\') rel++;
        char relbuf[PATH_MAX];
        snprintf(relbuf, sizeof(relbuf), "%s", rel);
        normalize_slashes(relbuf);

        if (should_exclude(relbuf, ctx->excludes, ctx->exclude_count)) {
            free(child_path);
            continue;
        }

        if (is_dir) {
            int rc = walk_dir(ctx, child_path);
            free(child_path);
            if (rc != 0) {
                closedir(dir);
                return rc;
            }
            continue;
        }

        if (is_file && has_ext(child_path, ".ml")) {
            char *rel_out = replace_ext(relbuf, ".masm");
            char *out_path = join_path(ctx->out_root, rel_out ? rel_out : relbuf);
            if (!out_path) {
                free(rel_out);
                free(child_path);
                closedir(dir);
                return 1;
            }
            ensure_parent_dir(out_path);
            if (compile_one(child_path, out_path) != 0) {
                fprintf(stderr, "Failed to compile %s\n", child_path);
                free(rel_out);
                free(out_path);
                free(child_path);
                closedir(dir);
                return 1;
            }
            ctx->compiled_count++;
            free(rel_out);
            free(out_path);
        } else if (is_file && ctx->include_masm && has_ext(child_path, ".masm")) {
            char *out_path = join_path(ctx->out_root, relbuf);
            if (!out_path) {
                free(child_path);
                closedir(dir);
                return 1;
            }
            if (strcmp(child_path, out_path) != 0 && copy_file(child_path, out_path) != 0) {
                fprintf(stderr, "Failed to copy %s\n", child_path);
                free(out_path);
                free(child_path);
                closedir(dir);
                return 1;
            }
            ctx->copied_count++;
            free(out_path);
        }

        free(child_path);
    }
    closedir(dir);
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [options] <input.ml> <output.masm>\n"
            "  %s [options] <input_dir> <output_dir>\n"
            "\n"
            "Options:\n"
            "  -exclude <path>   Exclude relative path or directory name (repeatable)\n"
            "  -entry <name>     Entry function name mapped to __START__ (default: main)\n"
            "  -masm             When compiling a directory, also copy .masm files\n",
            prog, prog);
}

int main(int argc, char *argv[]) {
    const char *entry_name = NULL;
    const char *input_path = NULL;
    const char *output_path = NULL;
    const char **excludes = NULL;
    int exclude_count = 0;
    int include_masm = 0;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-exclude") == 0 || strcmp(argv[i], "--exclude") == 0) && i + 1 < argc) {
            excludes = (const char**)realloc(excludes, sizeof(char*) * (exclude_count + 1));
            excludes[exclude_count++] = argv[++i];
        } else if ((strcmp(argv[i], "-entry") == 0 || strcmp(argv[i], "--entry") == 0) && i + 1 < argc) {
            entry_name = argv[++i];
        } else if (strcmp(argv[i], "-masm") == 0 || strcmp(argv[i], "--masm") == 0) {
            include_masm = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            free(excludes);
            return 0;
        } else if (!input_path) {
            input_path = argv[i];
        } else if (!output_path) {
            output_path = argv[i];
        } else {
            fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
            print_usage(argv[0]);
            free(excludes);
            return 1;
        }
    }

    if (!input_path || !output_path) {
        print_usage(argv[0]);
        free(excludes);
        return 1;
    }

    if (entry_name) {
        codegen_set_entry(entry_name);
    }

    if (path_is_dir(input_path)) {
        if (!path_is_dir(output_path)) {
            if (mkdir_p(output_path) != 0) {
                fprintf(stderr, "Failed to create output directory: %s\n", output_path);
                free(excludes);
                return 1;
            }
        }
        WalkCtx ctx = {
            .src_root = input_path,
            .src_root_len = strlen(input_path),
            .out_root = output_path,
            .excludes = excludes,
            .exclude_count = exclude_count,
            .include_masm = include_masm,
            .compiled_count = 0,
            .copied_count = 0,
        };
        int rc = walk_dir(&ctx, input_path);
        if (rc == 0) {
            printf("Compiled %d .ml file(s)", ctx.compiled_count);
            if (include_masm) printf(", copied %d .masm file(s)", ctx.copied_count);
            printf(".\n");
        }
        free(excludes);
        return rc;
    }

    if (!path_is_file(input_path)) {
        fprintf(stderr, "Input path does not exist: %s\n", input_path);
        free(excludes);
        return 1;
    }

    if (compile_one(input_path, output_path) != 0) {
        free(excludes);
        return 1;
    }

    free(excludes);
    return 0;
}
