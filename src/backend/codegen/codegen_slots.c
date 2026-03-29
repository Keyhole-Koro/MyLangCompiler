#include "mylang/backend/codegen_internal.h"

int param_offset(int n) { return -(4 + n * SLOT_SIZE); }
int local_offset(int n) { return -SLOT_SIZE * (n + 1); }

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
    if (!type_node) return 1;
    if (type_node->type == AST_TYPE_ARRAY) {
        int elem = slots_for_type(cc, type_node->type_array.element_type);
        int n = type_node->type_array.array_size;
        if (n <= 0) n = 1;
        return elem * n;
    }
    if (type_node->type == AST_TYPE) {
        if (type_node->type_node.pointer_level > 0) return 1;
        ASTNode *bt = type_node->type_node.base_type;
        if (bt && bt->type == AST_IDENTIFIER) {
            const StructInfo *si = find_struct(cc, bt->identifier.name);
            if (si) {
                if (si->size_bytes > 0)
                    return (si->size_bytes + SLOT_SIZE - 1) / SLOT_SIZE;
                return si->member_count > 0 ? si->member_count : 1;
            }
        }
        return 1;
    }
    return 1;
}
