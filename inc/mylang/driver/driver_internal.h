#ifndef MYLANG_DRIVER_INTERNAL_H
#define MYLANG_DRIVER_INTERNAL_H

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "mylang/ast/AST.h"
#include "mylang/backend/codegen.h"
#include "mylang/driver/source_spec.h"
#include "mylang/frontend/lexer.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/parser.h"
#include "mylang/semantic/semantic.h"
#include "mylang/support/utils.h"

/* How far compile_one goes. The two checks stop early, write no file and print
   only diagnostics. */
typedef enum {
    COMPILE_TO_OUTPUT,
    COMPILE_CHECK,
    COMPILE_PARSE_ONLY,
} CompileStage;

typedef struct {
    const char *entry_name;
    const char *input_path;
    const char *output_path;
    const char **excludes;
    int exclude_count;
    const char **call_redirects;
    int call_redirect_count;
    const char **aliases;
    int alias_count;
    const char *depfile_path;
    const char *symbols_path;
    int include_masm;
    int warnings_as_errors;
    int error_trace;
    int line_info;
    int dump_tokens;
    int dump_ast;
    CompileStage stage;
} DriverOptions;

/* Directory mode: every .mln under opts->input_path compiles to the same
   relative path under opts->output_path. */
typedef struct {
    const DriverOptions *opts;
    size_t src_root_len;
    int compiled_count;
    int copied_count;
} WalkCtx;

char *build_sidecar_path(const char *out_path, const char *suffix);
void free_tokens(Token *t);
int path_is_dir(const char *path);
int path_is_file(const char *path);
int has_ext(const char *path, const char *ext);
void normalize_slashes(char *s);
int should_exclude(const char *rel, const char **excludes, int exclude_count);
char *replace_ext(const char *path, const char *new_ext);
char *join_path(const char *a, const char *b);
int mkdir_p(const char *path);
void ensure_parent_dir(const char *file_path);
int copy_file(const char *src, const char *dst);

/* Compiles one source as `opts` asks; returns 0 on success and 1 on error. */
int compile_one(const DriverOptions *opts, const char *input_path, const char *output_path);
int write_symbol_file(const char *symbols_path, const char *input_path, ASTNode *root,
                      const char *assembly);
int walk_dir(WalkCtx *ctx, const char *dir_path);
void driver_print_usage(const char *prog);
void driver_options_dispose(DriverOptions *opts);
int driver_parse_args(int argc, char *argv[], DriverOptions *opts);

#endif
