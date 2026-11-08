#include "mylang/backend/codegen_internal.h"
#include <stdint.h>

static long eval_const_expr(CompilerContext *cc, ASTNode *node);
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

/* A `const` scalar global this file declares. A global initializer that names
 * one stores its value: `export const i32 CARET = ACCENT;` folds to ACCENT's
 * number. NULL for anything else -- a variable, an array, a pointer, or a
 * constant of another module -- so naming it stays an error. */
static ASTNode *constant_global(CompilerContext *cc, const char *name) {
    ASTNode *program = cg_as_block(cc->program);
    for (int i = 0; program && name && i < program->block.count; i++) {
        ASTNode *decl = cg_as_var_decl(program->block.stmts[i]);
        if (!decl || !decl->var_decl.name || strcmp(decl->var_decl.name, name) != 0) continue;
        ASTNode *type = decl->var_decl.var_type;
        TypeInfo info = {0};
        if (!decl->var_decl.init || decl->var_decl.is_extern || !type || type->type != AST_TYPE ||
            type->type_node.pointer_level != 0 || !(type->type_node.type_modifiers & TYPEMOD_CONST) ||
            aggregate_type_size(cc, type) > 0 || !typeinfo_from_type_ast(cc, type, &info) ||
            typeinfo_total_size_bytes(cc, &info) > SLOT_SIZE)
            return NULL;
        return decl;
    }
    return NULL;
}

/* A function this file defines, whose address a global stores. An exported
 * global is a defined symbol as well, but naming one means its value. */
static int is_function_name(CompilerContext *cc, ASTNode *expr) {
    return expr && expr->type == AST_IDENTIFIER && func_is_defined(cc, expr->identifier.name) &&
           !find_global_info(cc, expr->identifier.name);
}

static long eval_const_expr(CompilerContext *cc, ASTNode *node) {
    if (!node) return 0;
    if (node->type == AST_NUMBER) {
        return strtol(node->number.value, NULL, 10);
    }
    if (node->type == AST_IDENTIFIER) {
        /* Semantic analysis lets a global name only globals declared before
         * it, so a chain of constants always ends. */
        ASTNode *decl = constant_global(cc, node->identifier.name);
        if (decl) return eval_const_expr(cc, decl->var_decl.init);
    }
    if (node->type == AST_CHAR_LITERAL) {
        return (unsigned char)(node->char_literal.value ? node->char_literal.value[0] : 0);
    }
    if (node->type == AST_CAST) {
        return eval_const_expr(cc, node->cast.expr);
    }
    if (node->type == AST_CALL) {
        const TypedefInfo *newtype = find_typedef(cc, node->call.name);
        if (newtype && newtype->is_newtype && node->call.arg_count == 1) {
            return eval_const_expr(cc, node->call.args[0]);
        }
    }
    if (node->type == AST_UNARY) {
        uint32_t value = (uint32_t)eval_const_expr(cc, node->unary.operand);
        switch (node->unary.op) {
        case SUB: return (int32_t)(0u - value);
        case ADD: return (int32_t)value;
        case NOT: return !value;
        case BITNOT: return (int32_t)~value;
        default: break;
        }
    }
    if (node->type == AST_TERNARY) {
        return eval_const_expr(cc, eval_const_expr(cc, node->ternary.cond)
                               ? node->ternary.then_expr : node->ternary.else_expr);
    }
    if (node->type == AST_BINARY) {
        uint32_t left = (uint32_t)eval_const_expr(cc, node->binary.left);
        if (node->binary.op == LAND && !left) return 0;
        if (node->binary.op == LOR && left) return 1;
        uint32_t right = (uint32_t)eval_const_expr(cc, node->binary.right);
        switch (node->binary.op) {
        case ADD: return (int32_t)(left + right);
        case SUB: return (int32_t)(left - right);
        case ASTARISK: return (int32_t)(left * right);
        case DIV: if (right) return (int32_t)((int64_t)(int32_t)left / (int32_t)right); break;
        case MOD: if (right) return (int32_t)((int64_t)(int32_t)left % (int32_t)right); break;
        case LSH: if (right < 32) return (int32_t)(left << right); break;
        case RSH: if (right < 32) return left >> right; break;
        case AMPERSAND: return (int32_t)(left & right);
        case BITOR: return (int32_t)(left | right);
        case BITXOR: return (int32_t)(left ^ right);
        case EQ: return left == right;
        case NEQ: return left != right;
        case LT: return (int32_t)left < (int32_t)right;
        case LTE: return (int32_t)left <= (int32_t)right;
        case GT: return (int32_t)left > (int32_t)right;
        case GTE: return (int32_t)left >= (int32_t)right;
        case LAND: return left && right;
        case LOR: return left || right;
        default: break;
        }
    }
    fprintf(stderr, "Codegen error at %d:%d: invalid or non-constant global initializer (%s)\n",
            node ? node->line : 0, node ? node->col : 0,
            node ? astType2str(node->type) : "null");
    exit(1);
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

/* One `.word` for a 4-byte initializer: a string literal's label, a defined
 * function's name (both relocated by the linker) or a constant. */
static void emit_word_operand(CompilerContext *cc, StringBuilder *sb, ASTNode *expr) {
    if (expr && expr->type == AST_STRING_LITERAL) {
        sb_append(sb, "  .word %s\n", intern_string_literal_n(cc,
                  expr->string_literal.value, expr->string_literal.length));
    } else if (is_function_name(cc, expr)) {
        sb_append(sb, "  .word %s\n", expr->identifier.name);
    } else {
        sb_append(sb, "  .word %ld\n", eval_const_expr(cc, expr));
    }
}

void emit_global_init(CompilerContext *cc, StringBuilder *sb, ASTNode *init_expr,
                      int expected_bytes, int elem_bytes) {
    if (!init_expr) {
        emit_zero_bytes(sb, expected_bytes);
        return;
    }

    if (init_expr->type == AST_INIT_LIST && init_expr->init_list.struct_type_name) {
        const StructInfo *si = find_struct(cc, init_expr->init_list.struct_type_name);
        if (!si) {
            fprintf(stderr, "Codegen error: unknown struct '%s' in global literal\n",
                    init_expr->init_list.struct_type_name);
            exit(1);
        }
        // Data directives must be emitted in memory order, not source order.
        // Unspecified members receive the normal zero value.
        for (int m = 0; m < si->member_count; m++) {
            const MemberInfo *member = &si->members[m];
            if (member->total_size_bytes > SLOT_SIZE) {
                fprintf(stderr,
                        "Codegen error: aggregate field '%s' in a global struct literal is not supported\n",
                        member->name);
                exit(1);
            }
            ASTNode *value = NULL;
            for (int i = 0; i < init_expr->init_list.count; i++) {
                if (strcmp(init_expr->init_list.field_names[i], member->name) == 0) {
                    value = init_expr->init_list.elements[i];
                    break;
                }
            }
            if (member->total_size_bytes == SLOT_SIZE) {
                emit_word_operand(cc, sb, value);
            } else {
                emit_scalar_bytes(sb, eval_const_expr(cc, value), member->total_size_bytes);
            }
        }
        return;
    }

    // Aggregate initializer: emit each element at the array's element width,
    // then zero-pad any remaining bytes (e.g. `i32 a[8] = {1, 2};`). Word
    // elements go out as `.word`, so a string literal or function name is a
    // pointer the linker fills in (`char *names[] = {"a", "b"}`).
    if (init_expr->type == AST_INIT_LIST) {
        int width = elem_bytes > 0 ? elem_bytes : SLOT_SIZE;
        int written = 0;
        for (int i = 0; i < init_expr->init_list.count; i++) {
            ASTNode *elem = init_expr->init_list.elements[i];
            if (width == SLOT_SIZE) {
                emit_word_operand(cc, sb, elem);
            } else {
                emit_scalar_bytes(sb, eval_const_expr(cc, elem), width);
            }
            written += width;
        }
        if (written < expected_bytes) {
            emit_zero_bytes(sb, expected_bytes - written);
        }
        return;
    }

    if (expected_bytes == SLOT_SIZE * 2 && init_expr->type == AST_STRING_LITERAL) {
        sb_append(sb, "  .word %s, %d\n",
                  intern_string_literal_n(cc, init_expr->string_literal.value,
                                          init_expr->string_literal.length),
                  init_expr->string_literal.length);
        return;
    }

    // A pointer-sized scalar initialised with a string literal or a function
    // name holds that symbol's address: `char *s = "hi";`, `i32 f = handler;`.
    // Before .word existed this came out as a null pointer.
    if (expected_bytes == SLOT_SIZE &&
        (init_expr->type == AST_STRING_LITERAL || is_function_name(cc, init_expr))) {
        emit_word_operand(cc, sb, init_expr);
        return;
    }

    if (init_expr->type == AST_STRING_LITERAL) {
        fprintf(stderr,
                "Codegen error at %d:%d: a string literal cannot initialize this %d-byte global\n",
                init_expr->line, init_expr->col, expected_bytes);
        exit(1);
    }

    // Evaluate constant expression
    long val = eval_const_expr(cc, init_expr);

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

    // Build the global's block on the side: an initializer that interns a
    // string literal appends that string's own label and bytes to the data
    // section as it goes, and those must land before this block, not
    // inside it (the global's address would be the string's).
    StringBuilder block;
    sb_init(&block);
    if (var_decl->var_decl.link_name) sb_append(&block, "%s:\n", var_decl->var_decl.link_name);
    sb_append(&block, "%s:\n", var_decl->var_decl.name ? var_decl->var_decl.name : "");
    if (var_decl->var_decl.init) {
        emit_global_init(cc, &block, var_decl->var_decl.init, bytes, elem_bytes);
    } else {
        emit_zero_bytes(&block, bytes);
    }
    sb_append(&cg_data_sb, "%s", block.buf);
    sb_free(&block);
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

void emit_scale_reg_const(CompilerContext *cc, StringBuilder *sb, const char *reg, long factor) {
    (void)cc;
    if (factor == 1) return;
    if (factor <= 0) {
        sb_append(sb, "  ; unsupported scale factor %ld\n", factor);
        return;
    }

    // The target has no multiply instruction and `shl` shifts by one. The factor
    // is known here, so the product is shifts and adds: one `shl` per bit below
    // the top one and one `add` per further set bit. A row of a table is reached
    // through this on every access, so it must not loop.
    sb_append(sb, "  ; scale %s by %ld\n", reg, factor);
    long rest = factor;
    while ((rest & 1) == 0) {
        sb_append(sb, "  shl %s\n", reg);
        rest >>= 1;
    }
    rest >>= 1;
    if (rest == 0) return;
    sb_append(sb, "  mov r4, %s\n", reg);
    while (rest != 0) {
        sb_append(sb, "  shl r4\n");
        if (rest & 1) sb_append(sb, "  add %s, r4\n", reg);
        rest >>= 1;
    }
}
