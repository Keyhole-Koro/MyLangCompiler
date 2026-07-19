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
#include "mylang/frontend/parser.h"
#include "mylang/semantic/semantic.h"
#include "mylang/support/utils.h"

typedef struct {
    const char *entry_name;
    const char *input_path;
    const char *output_path;
    const char **excludes;
    int exclude_count;
    int include_masm;
    int warnings_as_errors;
} DriverOptions;

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

int compile_one(const char *input_path, const char *output_path);
int walk_dir(WalkCtx *ctx, const char *dir_path);
void driver_print_usage(const char *prog);
void driver_options_dispose(DriverOptions *opts);
int driver_parse_args(int argc, char *argv[], DriverOptions *opts);

#endif
