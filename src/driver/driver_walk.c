#include "mylang/driver/driver_internal.h"

int walk_dir(WalkCtx *ctx, const char *dir_path) {
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
