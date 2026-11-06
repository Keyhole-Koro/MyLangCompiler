#include <string.h>
#include "mylang/backend/codegen_internal.h"

// Aggregate (struct/array) by-value calling convention (MLC-015).
//
// Structs and arrays always use the same convention, including one-word
// aggregates. Every place they cross the ABI boundary -- a parameter, a return value --
// is compiled as a hidden pointer instead: the caller supplies the address of
// somewhere to put or find the value, and only that one address travels
// through the normal register/stack argument mechanism unchanged.
//
// This works without changing how a parameter's slot or a call's argument
// registers are populated, because those already move exactly one word
// regardless of type (scalar_var_width_bytes already returns SLOT_SIZE for a
// struct-typed name, since base_type_size_bytes only special-cases char/u8/
// u16). The one place that had to change is what gets computed as that word:
// gen_lvalue_addr's AST_IDENTIFIER case (via emit_addr_of_var) now recognises
// a by-value aggregate parameter and loads the pointer already held in its
// slot instead of taking the address of the slot itself. Every consumer built
// on gen_lvalue_addr -- member access, aggregate assignment, borrowing -- gets
// the fix for free by construction, without its own special case.
//
// No copy is made at the call. A plain parameter only reads, and a body that
// writes to one gets a copy on entry (copy_written_params, codegen_func.c).
// `move T x` takes the caller's memory over: the semantic layer rejects
// `consume(x); return x.a;` with "use of moved value 'x'".

int aggregate_type_size(CompilerContext *cc, ASTNode *type_ast) {
    if (!type_ast) return 0;
    LocalInfo info = {0};
    set_localinfo_from_type(cc, &info, type_ast);
    if (info.pointer_level != 0) return 0;
    if (!info.is_array && !find_struct(cc, info.base_type)) return 0;

    TypeInfo ti = {0};
    if (!typeinfo_from_type_ast(cc, type_ast, &ti)) return 0;
    int total = typeinfo_total_size_bytes(cc, &ti);
    return total > 0 ? total : 0;
}

int is_addressable_expr(ASTNode *node) {
    if (!node) return 0;
    switch (node->type) {
    case AST_IDENTIFIER:
    case AST_MEMBER_ACCESS:
    case AST_ARROW_ACCESS:
        return 1;
    case AST_UNARY:
        return node->unary.op == ASTARISK;
    default:
        return 0;
    }
}

int is_byval_aggregate_param(CompilerContext *cc, const char *name, char **params, int param_count) {
    if (param_index(name, params, param_count) < 0) return 0;
    const LocalInfo *li = find_local_info(cc, name);
    if (!li || li->pointer_level != 0) return 0;
    return li->is_array || find_struct(cc, li->base_type) != NULL;
}

int call_return_aggregate_size(CompilerContext *cc, ASTNode *node) {
    if (!node || node->type != AST_CALL) return 0;
    const FunctionSig *sig = find_func_sig(cc, node->call.name);
    if (sig) return sig->ret_is_aggregate ? sig->ret_size_bytes : 0;

    const LocalInfo *li = find_local_info(cc, node->call.name);
    if (!li) li = find_global_info(cc, node->call.name);
    if (!li || !li->is_function || !li->function_type ||
        li->function_type->type != AST_TYPE_FUNCTION) return 0;
    return aggregate_type_size(cc,
        (ASTNode *)li->function_type->function_type.return_type);
}

/* Past this size a copy is a loop: unrolled, a Text<128> costs a kilobyte of
 * code at every assignment and loading those bytes costs more than the loop. */
#define AGGREGATE_UNROLL_BYTES 32

int aggregate_loop_label(void) {
    static int next = 0;
    return next++;
}

/* A scratch register that holds neither address. */
static const char *loop_counter_reg(const char *a, const char *b) {
    return strcmp(a, "r7") != 0 && strcmp(b, "r7") != 0 ? "r7" : "r6";
}

void emit_aggregate_copy(StringBuilder *sb, const char *dest_addr_reg, const char *src_addr_reg, int total_bytes) {
    sb_append(sb, "  ; copy %d bytes (aggregate)\n", total_bytes);
    int off = 0;
    if (total_bytes > AGGREGATE_UNROLL_BYTES &&
        strcmp(dest_addr_reg, "sp") != 0 && strcmp(src_addr_reg, "sp") != 0) {
        const char *counter = loop_counter_reg(dest_addr_reg, src_addr_reg);
        int label = aggregate_loop_label();
        int words = total_bytes & ~3;
        sb_append(sb, "  push  %s\n", counter);
        sb_append(sb, "  movi  %s, 0\n", counter);
        sb_append(sb, "agg_copy_%d:\n", label);
        sb_append(sb, "  mov   r4, %s\n", src_addr_reg);
        sb_append(sb, "  add   r4, %s\n", counter);
        sb_append(sb, "  load  r1, r4\n");
        sb_append(sb, "  mov   r4, %s\n", dest_addr_reg);
        sb_append(sb, "  add   r4, %s\n", counter);
        sb_append(sb, "  store r4, r1\n");
        sb_append(sb, "  addis %s, 4\n", counter);
        sb_append(sb, "  movi  r4, %d\n", words);
        sb_append(sb, "  cmp   %s, r4\n", counter);
        sb_append(sb, "  jnz   agg_copy_%d\n", label);
        sb_append(sb, "  pop   %s\n", counter);
        off = words;
    }
    for (; off + 4 <= total_bytes; off += 4) {
        sb_append(sb, "  mov   r4, %s\n", src_addr_reg);
        if (off) sb_append(sb, "  addis r4, %d\n", off);
        sb_append(sb, "  load  r1, r4\n");
        sb_append(sb, "  mov   r4, %s\n", dest_addr_reg);
        if (off) sb_append(sb, "  addis r4, %d\n", off);
        sb_append(sb, "  store r4, r1\n");
    }
    for (; off < total_bytes; off++) {
        sb_append(sb, "  mov   r4, %s\n", src_addr_reg);
        if (off) sb_append(sb, "  addis r4, %d\n", off);
        sb_append(sb, "  loadb r1, r4\n");
        sb_append(sb, "  mov   r4, %s\n", dest_addr_reg);
        if (off) sb_append(sb, "  addis r4, %d\n", off);
        sb_append(sb, "  storeb r4, r1\n");
    }
}
