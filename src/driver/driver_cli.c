#include "mylang/driver/driver_internal.h"

void driver_print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [options] <input.mln> <output.masm>\n"
            "  %s [options] <input_dir> <output_dir>\n"
            "\n"
            "Options:\n"
            "  -exclude <path>   Exclude relative path or directory name (repeatable)\n"
            "  -entry <name>     Entry function name mapped to __START__ (default: main)\n"
            "  -masm             When compiling a directory, also copy .masm files\n"
            "  --Werror          Treat semantic warnings as errors\n",
            prog, prog);
}

void driver_options_dispose(DriverOptions *opts) {
    free((void *)opts->excludes);
    opts->excludes = NULL;
    opts->exclude_count = 0;
}

int driver_parse_args(int argc, char *argv[], DriverOptions *opts) {
    memset(opts, 0, sizeof(*opts));

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-exclude") == 0 || strcmp(argv[i], "--exclude") == 0) && i + 1 < argc) {
            opts->excludes = (const char**)realloc((void *)opts->excludes, sizeof(char*) * (opts->exclude_count + 1));
            opts->excludes[opts->exclude_count++] = argv[++i];
        } else if ((strcmp(argv[i], "-entry") == 0 || strcmp(argv[i], "--entry") == 0) && i + 1 < argc) {
            opts->entry_name = argv[++i];
        } else if (strcmp(argv[i], "-masm") == 0 || strcmp(argv[i], "--masm") == 0) {
            opts->include_masm = 1;
        } else if (strcmp(argv[i], "--Werror") == 0 || strcmp(argv[i], "--warnings-as-errors") == 0) {
            opts->warnings_as_errors = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            driver_print_usage(argv[0]);
            return 1;
        } else if (!opts->input_path) {
            opts->input_path = argv[i];
        } else if (!opts->output_path) {
            opts->output_path = argv[i];
        } else {
            fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
            driver_print_usage(argv[0]);
            return -1;
        }
    }

    if (!opts->input_path || !opts->output_path) {
        driver_print_usage(argv[0]);
        return -1;
    }

    return 0;
}
