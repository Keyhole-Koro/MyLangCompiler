#include "mylang/driver/driver_internal.h"

char *build_sidecar_path(const char *out_path, const char *suffix) {
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

void free_tokens(Token *t) {
    while (t) {
        Token *next = t->next;
        free(t->value);
        free(t);
        t = next;
    }
}

int path_is_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

int path_is_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

int has_ext(const char *path, const char *ext) {
    size_t plen = strlen(path);
    size_t elen = strlen(ext);
    return plen >= elen && strcmp(path + plen - elen, ext) == 0;
}

void normalize_slashes(char *s) {
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

int should_exclude(const char *rel, const char **excludes, int exclude_count) {
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

char *replace_ext(const char *path, const char *new_ext) {
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

char *join_path(const char *a, const char *b) {
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

int mkdir_p(const char *path) {
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

void ensure_parent_dir(const char *file_path) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", file_path);
    normalize_slashes(tmp);
    char *slash = strrchr(tmp, '/');
    if (!slash) return;
    *slash = '\0';
    mkdir_p(tmp);
}

int copy_file(const char *src, const char *dst) {
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
