#include "mylang/driver/driver_internal.h"

#include <unistd.h>

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

static void apply_options(const DriverOptions *opts) {
    codegen_set_entry(opts->entry_name);
    codegen_set_call_redirects(opts->call_redirects, opts->call_redirect_count);
    semantic_set_warnings_as_errors(opts->warnings_as_errors);
    codegen_set_error_trace(opts->error_trace);
    codegen_set_line_info(opts->line_info);
}

/* What a unit's line ends with: 0 compiled, 1 failed, 2 compile it again in a
 * fresh process (module_cache_take_conflict). */
static int serve_unit(char *line) {
    char *argv[256];
    int argc = 0;
    argv[argc++] = "mlc";
    for (char *field = strtok(line, "\t"); field && argc < 255; field = strtok(NULL, "\t"))
        argv[argc++] = field;
    argv[argc] = NULL;

    DriverOptions opts;
    int status = 1;
    if (driver_parse_args(argc, argv, &opts) == 0) {
        if (opts.stage != COMPILE_TO_OUTPUT || path_is_dir(opts.input_path)) {
            fprintf(stderr, "--serve compiles one source to its output per line\n");
        } else {
            apply_options(&opts);
            int rc = run_single_file_mode(&opts);
            status = module_cache_take_conflict() ? 2 : (rc == 0 ? 0 : 1);
        }
    }
    driver_options_dispose(&opts);
    return status;
}

/* --serve: compiles a unit for each line of stdin, which holds the arguments
 * a single-file compile takes, separated by tabs. A module one unit loads is
 * kept for the units after it (module_cache.c), which is why a build gives a
 * serving process many units. It starts with a line of "\x1e" and "serving";
 * what a compile prints, stderr included, goes to stdout, followed by a line
 * of "\x1e" and the unit's status. A compile error that ends the process
 * (most do) ends the server: whoever started it compiles that unit again in a
 * process of its own. */
static int run_serve_mode(void) {
    dup2(STDOUT_FILENO, STDERR_FILENO);
    setvbuf(stdout, NULL, _IOLBF, 0);
    module_cache_enable();
    printf("\x1eserving\n");
    fflush(stdout);
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    while ((length = getline(&line, &capacity, stdin)) > 0) {
        if (line[length - 1] == '\n') line[--length] = '\0';
        int status = serve_unit(line);
        fflush(stderr);
        printf("\x1e%d\n", status);
        fflush(stdout);
    }
    free(line);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "--serve") == 0) return run_serve_mode();

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
