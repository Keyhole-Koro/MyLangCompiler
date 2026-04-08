#include "mylang/backend/codegen_internal.h"

int param_offset(int n) { return -(4 + n * SLOT_SIZE); }
int local_offset(int param_count, int n) { return -SLOT_SIZE * (param_count + n + 1); }

int param_index(const char *name, char **params, int param_count)
{
    for (int i = 0; i < param_count; i++)
        if (strcmp(name, params[i]) == 0)
            return i;
    return -1;
}

int local_index_last(const char *name, char **locals, int local_count)
{
    int idx = -1;
    for (int i = 0; i < local_count; i++) {
        if (locals[i] && strcmp(name, locals[i]) == 0) idx = i;
    }
    return idx;
}

int slots_for_type(CompilerContext *cc, ASTNode *type_node)
{
    TypeInfo ti = {0};
    int total_bytes;

    if (!type_node) return 1;
    if (!typeinfo_from_type_ast(cc, type_node, &ti)) return 1;

    total_bytes = typeinfo_total_size_bytes(cc, &ti);
    if (total_bytes < 1) total_bytes = 1;
    return (total_bytes + SLOT_SIZE - 1) / SLOT_SIZE;
}
