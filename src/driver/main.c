#include "mylang/driver/driver_internal.h"

static int run_directory_mode(const DriverOptions *opts) {
    if (opts->stage != COMPILE_TO_OUTPUT) {
        fprintf(stderr, "--check and --parse-only take one source, not a directory\n");
        return 1;
    }
    if (opts->depfile_path) {
        fprintf(stderr, "--depfile is supported only for single-file compilation\n");
        return 1;
    }
    if (opts->symbols_path) {
        fprintf(stderr, "--emit-symbols is supported only for single-file compilation\n");
        return 1;
    }
    if (!path_is_dir(opts->output_path)) {
        if (mkdir_p(opts->output_path) != 0) {
            fprintf(stderr, "Failed to create output directory: %s\n", opts->output_path);
            return 1;
        }
    }

    /* walk_dir compiles each file with these options as they are: the checks
     * above have refused the check stages, --depfile and --emit-symbols,
     * which only make sense for a single source. */
    WalkCtx ctx = {
        .opts = opts,
        .src_root_len = strlen(opts->input_path),
        .compiled_count = 0,
        .copied_count = 0,
    };

    int rc = walk_dir(&ctx, opts->input_path);
    if (rc == 0) {
        printf("Compiled %d .mln file(s)", ctx.compiled_count);
        if (opts->include_masm) printf(", copied %d .masm file(s)", ctx.copied_count);
        printf(".\n");
    }
    return rc;
}

static int run_single_file_mode(const DriverOptions *opts) {
    if (!path_is_file(opts->input_path)) {
        fprintf(stderr, "Input path does not exist: %s\n", opts->input_path);
        return 1;
    }
    return compile_one(opts, opts->input_path, opts->output_path);
}

int main(int argc, char *argv[]) {
    DriverOptions opts;
    int parse_rc = driver_parse_args(argc, argv, &opts);
    if (parse_rc != 0) {
        driver_options_dispose(&opts);
        return parse_rc < 0 ? 1 : 0;
    }

    if (opts.entry_name) {
        codegen_set_entry(opts.entry_name);
    }
    codegen_set_call_redirects(opts.call_redirects, opts.call_redirect_count);
    semantic_set_warnings_as_errors(opts.warnings_as_errors);
    codegen_set_error_trace(opts.error_trace);
    codegen_set_line_info(opts.line_info);

    int rc = path_is_dir(opts.input_path)
        ? run_directory_mode(&opts)
        : run_single_file_mode(&opts);

    driver_options_dispose(&opts);
    return rc;
}
