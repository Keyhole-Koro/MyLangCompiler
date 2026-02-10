#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

// Read a file verbatim into a newly allocated buffer (no include expansion).
char *readSampleInput(const char *filePath) {
    if (!filePath) return NULL;

    FILE *f = fopen(filePath, "rb");
    if (!f) {
        perror("Failed to open file");
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        perror("Failed to seek file");
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0) {
        perror("Failed to tell file size");
        fclose(f);
        return NULL;
    }
    rewind(f);

    char *buf = (char*)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t read = fread(buf, 1, (size_t)sz, f);
    buf[read] = '\0';
    fclose(f);

    return buf;
}

static void normalize_slashes(char *s) {
    for (; *s; s++) {
        if (*s == '\\') *s = '/';
    }
}

static int mkdir_one(const char *path) {
#ifdef _WIN32
    if (_mkdir(path) != 0 && errno != EEXIST) return -1;
#else
    if (mkdir(path, 0777) != 0 && errno != EEXIST) return -1;
#endif
    return 0;
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
            if (mkdir_one(tmp) != 0) return -1;
            *p = '/';
        }
    }
    if (mkdir_one(tmp) != 0) return -1;
    return 0;
}

static void ensure_parent_dir(const char *file_path) {
    if (!file_path || !file_path[0]) return;
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", file_path);
    normalize_slashes(tmp);
    char *slash = strrchr(tmp, '/');
    if (!slash) return;
    *slash = '\0';
    mkdir_p(tmp);
}

void saveOutput(const char *filePath, const char *content) {
    ensure_parent_dir(filePath);

    FILE *f = fopen(filePath, "wb");
    if (!f) {
        perror("Failed to open output file");
        return;
    }
    if (content) {
        fputs(content, f);
    }
    fclose(f);
}
