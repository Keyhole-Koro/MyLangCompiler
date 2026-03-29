#include "mylang/frontend/parser_internal.h"

static void print_line_snippet(const char *file, int line, int col) {
    if (!file || line <= 0) return;
    FILE *fp = fopen(file, "r");
    if (!fp) return;
    char buf[512];
    int cur_line = 1;
    while (fgets(buf, sizeof(buf), fp)) {
        if (cur_line == line) {
            size_t len = strlen(buf);
            while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[--len] = '\0';
            fprintf(stderr, "  %s\n", buf);
            if (col > 0) fprintf(stderr, "  %*s^\n", col, "");
            break;
        }
        cur_line++;
    }
    fclose(fp);
}

void parse_error(const char *msg, Token *head, Token *cur) {
    fprintf(stderr, "%s:%d:%d: error: %s\n",
            g_parse_filename ? g_parse_filename : "<input>",
            cur ? cur->line : 0,
            cur ? cur->col : 0,
            msg);
    if (cur) print_line_snippet(g_parse_filename, cur->line, cur->col);

    // Print a small window of surrounding tokens for context
    Token *prevs[2] = {NULL, NULL};
    Token *nexts[2] = {NULL, NULL};

    Token *p = head;
    while (p && p != cur) {
        prevs[1] = prevs[0];
        prevs[0] = p;
        p = p->next;
    }
    Token *q = cur;
    for (int i = 0; i < 2 && q; i++) {
        q = q->next;
        nexts[i] = q;
    }

    if (prevs[1])
        fprintf(stderr, "  prev-2: kind=%s, value=%s (l%d c%d)\n",
                tokenkind2str(prevs[1]->kind),
                prevs[1]->value ? prevs[1]->value : "(null)",
                prevs[1]->line, prevs[1]->col);
    if (prevs[0])
        fprintf(stderr, "  prev-1: kind=%s, value=%s (l%d c%d)\n",
                tokenkind2str(prevs[0]->kind),
                prevs[0]->value ? prevs[0]->value : "(null)",
                prevs[0]->line, prevs[0]->col);
    if (nexts[0])
        fprintf(stderr, "  next+1: kind=%s, value=%s (l%d c%d)\n",
                tokenkind2str(nexts[0]->kind),
                nexts[0]->value ? nexts[0]->value : "(null)",
                nexts[0]->line, nexts[0]->col);
    if (nexts[1])
        fprintf(stderr, "  next+2: kind=%s, value=%s (l%d c%d)\n",
                tokenkind2str(nexts[1]->kind),
                nexts[1]->value ? nexts[1]->value : "(null)",
                nexts[1]->line, nexts[1]->col);
    exit(1);
}
int expect(Token **cur, TokenKind kind) {
    if (*cur && (*cur)->kind == kind) {
        *cur = (*cur)->next;
        return 1;
    }
    return 0;
}
