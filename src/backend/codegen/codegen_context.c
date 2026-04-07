#include "mylang/backend/codegen_internal.h"

static const char *g_entry_name = "main";

void codegen_set_entry(const char *name) {
    if (name && name[0]) {
        g_entry_name = name;
    } else {
        g_entry_name = "main";
    }
}

int is_entry_name(const char *name) {
    return name && g_entry_name && strcmp(name, g_entry_name) == 0;
}

int next_label(CompilerContext *cc) {
    return cc->label_counter++;
}

const char *arg_regs[] = {"r5", "r6", "r7"};

int find_name(char **arr, int count, const char *name) {
    if (!name) return -1;
    for (int i = 0; i < count; i++) {
        if (arr[i] && strcmp(arr[i], name) == 0) return i;
    }
    return -1;
}

void note_defined_func(CompilerContext *cc, const char *name) {
    if (!cc || !name) return;
    if (find_name(cc->defined_funcs, cc->defined_func_count, name) >= 0) return;
    cc->defined_funcs = (char**)realloc(cc->defined_funcs, sizeof(char*) * (cc->defined_func_count + 1));
    cc->defined_funcs[cc->defined_func_count++] = (char*)name;
}

bool func_is_defined(CompilerContext *cc, const char *name) {
    return find_name(cc ? cc->defined_funcs : NULL, cc ? cc->defined_func_count : 0, name) >= 0;
}

int is_codegen_builtin(const char *name) {
    return name &&
           (strcmp(name, "__rest_len") == 0 ||
            strcmp(name, "__rest_get") == 0);
}

const FunctionSig *find_func_sig(CompilerContext *cc, const char *name) {
    if (!cc || !name) return NULL;
    for (int i = 0; i < cc->func_sig_count; i++) {
        if (cc->func_sigs[i].name && strcmp(cc->func_sigs[i].name, name) == 0) {
            return &cc->func_sigs[i];
        }
    }
    return NULL;
}

const EnumValueInfo *find_enum_value(CompilerContext *cc, const char *name) {
    if (!cc || !name) return NULL;
    for (int i = cc->enum_value_count - 1; i >= 0; i--) {
        if (cc->enum_values[i].name && strcmp(cc->enum_values[i].name, name) == 0) {
            return &cc->enum_values[i];
        }
    }
    return NULL;
}

void note_import_func(CompilerContext *cc, const char *name) {
    if (!cc || !name) return;
    if (is_codegen_builtin(name)) return;
    if (func_is_defined(cc, name)) return;
    if (find_name(cc->imports, cc->import_count, name) >= 0) return;
    cc->imports = (char**)realloc(cc->imports, sizeof(char*) * (cc->import_count + 1));
    cc->imports[cc->import_count++] = strdup(name);
}

void collect_imports_from_toplevel(CompilerContext *cc, ASTNode *root) {
    ASTNode *block = cg_as_block(root);
    if (!cc || !block) return;
    for (int i = 0; i < block->block.count; i++) {
        ASTNode *n = block->block.stmts[i];
        if (n->type == AST_IMPORT && n->import_stmt.symbol_count > 0) {
            for (int k = 0; k < n->import_stmt.symbol_count; k++) {
                note_import_func(cc, n->import_stmt.symbols[k]);
            }
        }
    }
}
