#include "mylang/backend/codegen_internal.h"

static long eval_const_expr(ASTNode *node);
int array_element_size_bytes(ASTNode *array_type);

void ensure_data_section(CompilerContext *cc) {
    if (!cg_data_sb_inited) { sb_init(&cg_data_sb); cg_data_sb_inited = 1; }
}

void emit_zero_bytes(StringBuilder *sb, int count) {
    if (count < 1) count = SLOT_SIZE;
    sb_append(sb, "  .byte ");
    for (int i = 0; i < count; i++) {
        sb_append(sb, "%s0", (i == 0) ? "" : ", ");
    }
    sb_append(sb, "\n");
}

static long eval_const_expr(ASTNode *node) {
    if (!node) return 0;
    if (node->type == AST_NUMBER) {
        return strtol(node->number.value, NULL, 10);
    }
    if (node->type == AST_CHAR_LITERAL) {
        return (unsigned char)(node->char_literal.value ? node->char_literal.value[0] : 0);
    }
    if (node->type == AST_UNARY && node->unary.op == SUB) {
        return -eval_const_expr(node->unary.operand);
    }
    return 0; 
}

// Emit a single scalar constant as `width` big-endian bytes.
static void emit_scalar_bytes(StringBuilder *sb, long val, int width) {
    if (width == 1) {
        sb_append(sb, "  .byte 0x%02X\n", (unsigned)(val & 0xFF));
    } else if (width == 2) {
        sb_append(sb, "  .byte 0x%02X, 0x%02X\n",
                  (unsigned)((val >> 8) & 0xFF),
                  (unsigned)(val & 0xFF));
    } else {
        sb_append(sb, "  .byte 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
                  (unsigned)((val >> 24) & 0xFF),
                  (unsigned)((val >> 16) & 0xFF),
                  (unsigned)((val >> 8) & 0xFF),
                  (unsigned)(val & 0xFF));
    }
}

void emit_global_init(StringBuilder *sb, ASTNode *init_expr, int expected_bytes, int elem_bytes) {
    if (!init_expr) {
        emit_zero_bytes(sb, expected_bytes);
        return;
    }

    // Aggregate initializer: emit each element at the array's element width,
    // then zero-pad any remaining bytes (e.g. `i32 a[8] = {1, 2};`).
    if (init_expr->type == AST_INIT_LIST) {
        int width = elem_bytes > 0 ? elem_bytes : SLOT_SIZE;
        int written = 0;
        for (int i = 0; i < init_expr->init_list.count; i++) {
            long ev = eval_const_expr(init_expr->init_list.elements[i]);
            emit_scalar_bytes(sb, ev, width);
            written += width;
        }
        if (written < expected_bytes) {
            emit_zero_bytes(sb, expected_bytes - written);
        }
        return;
    }

    // Evaluate constant expression
    long val = eval_const_expr(init_expr);

    if (expected_bytes == 1) {
        sb_append(sb, "  .byte 0x%02X\n", (unsigned)(val & 0xFF));
    } else if (expected_bytes == 2) {
        sb_append(sb, "  .byte 0x%02X, 0x%02X\n",
                  (unsigned)((val >> 8) & 0xFF),
                  (unsigned)(val & 0xFF));
    } else {
        // Word init (4 bytes) - Big Endian
        // If expected_bytes is 4, we write 4 bytes. 
        // If it is array or struct, this naive impl is insufficient (TODO),
        // but works for scalar i32.
        sb_append(sb, "  .byte 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
                  (unsigned)((val >> 24) & 0xFF),
                  (unsigned)((val >> 16) & 0xFF),
                  (unsigned)((val >> 8) & 0xFF),
                  (unsigned)(val & 0xFF));
        if (expected_bytes > 4) {
            emit_zero_bytes(sb, expected_bytes - 4);
        }
    }
}

void emit_global_decl(CompilerContext *cc, ASTNode *var_decl) {
    var_decl = cg_as_var_decl(var_decl);
    if (!var_decl) return;
    ensure_data_section(cc);

    int bytes = SLOT_SIZE;
    if (var_decl->var_decl.var_type) {
        TypeInfo ti = {0};
        if (typeinfo_from_type_ast(cc, var_decl->var_decl.var_type, &ti)) {
            bytes = typeinfo_total_size_bytes(cc, &ti);
        }
    }
    if (bytes < 1) bytes = SLOT_SIZE;

    // Element width for aggregate initializers (char/u8 -> 1, u16 -> 2,
    // otherwise a full slot). Scalar inits ignore this.
    int elem_bytes = SLOT_SIZE;
    if (var_decl->var_decl.var_type &&
        var_decl->var_decl.var_type->type == AST_TYPE_ARRAY) {
        elem_bytes = array_element_size_bytes(var_decl->var_decl.var_type);
    }

    sb_append(&cg_data_sb, "%s:\n", var_decl->var_decl.name ? var_decl->var_decl.name : "");
    if (var_decl->var_decl.init) {
        emit_global_init(&cg_data_sb, var_decl->var_decl.init, bytes, elem_bytes);
    } else {
        emit_zero_bytes(&cg_data_sb, bytes);
    }
}

int pointer_step_bytes(CompilerContext *cc, const TypeInfo *info) {
    if (!info) return 1;
    if (info->pointer_level <= 0) {
        if (info->dims_count > 0) {
            long sz = typeinfo_elem_size_bytes(cc, info);
            for (int i = 1; i < info->dims_count; i++) {
                int len = info->dims[i] > 0 ? info->dims[i] : 1;
                sz *= len;
            }
            if (sz <= 0) sz = SLOT_SIZE;
            return (int)sz;
        }
        return 1;
    }
    // pointer_level > 0
    if (info->dims_count > 0) {
        return typeinfo_total_size_bytes(cc, info);
    }
    if (info->pointer_level > 1) return SLOT_SIZE; // pointer to pointer etc.
    return typeinfo_elem_size_bytes(cc, info);
}

int array_element_size_bytes(ASTNode *array_type) {
    array_type = cg_as_type_array(array_type);
    if (!array_type) return SLOT_SIZE;
    ASTNode *elem = array_type->type_array.element_type;
    if (elem && elem->type == AST_TYPE) {
        ASTNode *bt = elem->type_node.base_type;
        if (elem->type_node.pointer_level == 0 && bt && bt->type == AST_IDENTIFIER) {
            if (strcmp(bt->identifier.name, "char") == 0 || strcmp(bt->identifier.name, "u8") == 0) return 1;
            if (strcmp(bt->identifier.name, "u16") == 0) return 2;
        }
    }
    return SLOT_SIZE;
}

int array_total_elements(ASTNode *array_type) {
    array_type = cg_as_type_array(array_type);
    if (!array_type) return 1;
    int n = array_type->type_array.array_size > 0 ? array_type->type_array.array_size : 1;
    return n * array_total_elements(array_type->type_array.element_type);
}

int lvalue_is_byte(CompilerContext *cc, ASTNode *node) {
    TypeInfo info = (TypeInfo){0};
    if (!infer_expr_type(cc, node, &info)) return 0;
    return typeinfo_is_byte(&info);
}

int lvalue_width_bytes(CompilerContext *cc, ASTNode *node) {
    TypeInfo info = (TypeInfo){0};
    if (!infer_expr_type(cc, node, &info)) return SLOT_SIZE;
    return typeinfo_scalar_width_bytes(&info);
}

int lvalue_is_const(CompilerContext *cc, ASTNode *node) {
    TypeInfo info = (TypeInfo){0};
    if (!infer_expr_type(cc, node, &info)) return 0;
    return (info.type_modifiers & TYPEMOD_CONST) != 0;
}

void emit_load_from_addr(StringBuilder *sb, const char *target_reg, const char *addr_reg, int is_byte) {
    emit_load_width_from_addr(sb, target_reg, addr_reg, is_byte ? 1 : SLOT_SIZE);
}

void emit_load_width_from_addr(StringBuilder *sb, const char *target_reg, const char *addr_reg, int width_bytes) {
    if (width_bytes == 1) {
        sb_append(sb, "  loadb %s, %s\n", target_reg, addr_reg);
    } else if (width_bytes == 2) {
        const char *scratch = (strcmp(target_reg, "r4") == 0) ? "r5" : "r4";
        sb_append(sb, "  ; load u16 from %s into %s\n", addr_reg, target_reg);
        sb_append(sb, "  loadb %s, %s\n", target_reg, addr_reg);
        for (int i = 0; i < 8; i++) sb_append(sb, "  shl %s\n", target_reg);
        sb_append(sb, "  addis %s, 1\n", addr_reg);
        sb_append(sb, "  loadb %s, %s\n", scratch, addr_reg);
        sb_append(sb, "  addis %s, -1\n", addr_reg);
        sb_append(sb, "  or %s, %s\n", target_reg, scratch);
    } else {
        sb_append(sb, "  load %s, %s\n", target_reg, addr_reg);
    }
}

void emit_store_to_addr(StringBuilder *sb, const char *addr_reg, const char *value_reg, int is_byte) {
    emit_store_width_to_addr(sb, addr_reg, value_reg, is_byte ? 1 : SLOT_SIZE);
}

void emit_store_width_to_addr(StringBuilder *sb, const char *addr_reg, const char *value_reg, int width_bytes) {
    if (width_bytes == 1) {
        sb_append(sb, "  storeb %s, %s\n", addr_reg, value_reg);
    } else if (width_bytes == 2) {
        const char *scratch = (strcmp(value_reg, "r4") == 0) ? "r5" : "r4";
        sb_append(sb, "  ; store u16 from %s to %s\n", value_reg, addr_reg);
        sb_append(sb, "  mov %s, %s\n", scratch, value_reg);
        for (int i = 0; i < 8; i++) sb_append(sb, "  shr %s\n", scratch);
        sb_append(sb, "  storeb %s, %s\n", addr_reg, scratch);
        sb_append(sb, "  addis %s, 1\n", addr_reg);
        sb_append(sb, "  storeb %s, %s\n", addr_reg, value_reg);
        sb_append(sb, "  addis %s, -1\n", addr_reg);
    } else {
        sb_append(sb, "  store %s, %s\n", addr_reg, value_reg);
    }
}

// If `n` is a power of two (> 0), return its exponent (log2), else -1.
static int power_of_two_shift(long n) {
    if (n <= 0) return -1;
    int shift = 0;
    while ((n & 1) == 0) {
        n >>= 1;
        shift++;
    }
    return (n == 1) ? shift : -1;
}

void emit_scale_reg_const(CompilerContext *cc, StringBuilder *sb, const char *reg, long factor) {
    if (factor == 1) return;
    if (factor <= 0) {
        sb_append(sb, "  ; unsupported scale factor %ld\n", factor);
        return;
    }

    // Fast path: multiplying by a power of two is a left shift. The target has
    // no multiply instruction, so the generic path below is a repeated-add
    // loop that runs `factor` times per scale — catastrophic for large factors
    // like a display row stride. `shl` shifts by one, so emit `shift` of them.
    int shift = power_of_two_shift(factor);
    if (shift >= 0) {
        sb_append(sb, "  ; scale %s by %ld (<< %d)\n", reg, factor, shift);
        for (int i = 0; i < shift; i++) {
            sb_append(sb, "  shl %s\n", reg);
        }
        return;
    }

    sb_append(sb, "  ; scale %s by %ld\n", reg, factor);
    sb_append(sb, "  mov r4, %s\n", reg);
    sb_append(sb, "  movi %s, 0\n", reg);
    sb_append(sb, "  movi r5, %ld\n", factor);
    int lbl = next_label(cc);
    sb_append(sb, "b_idx_mul_%d:\n", lbl);
    sb_append(sb, "  cmp r5, 0\n");
    sb_append(sb, "  jz b_idx_mul_end_%d\n", lbl);
    sb_append(sb, "  add %s, r4\n", reg);
    sb_append(sb, "  addis r5, -1\n");
    sb_append(sb, "  jmp b_idx_mul_%d\n", lbl);
    sb_append(sb, "b_idx_mul_end_%d:\n", lbl);
}

