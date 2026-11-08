#include "mylang/frontend/parser_payload_internal.h"
#include "mylang/frontend/parser_trait_internal.h"

/* `x?` reaches payload lowering as the case parser_expr_postfix.c expands it
 * to. A Result whose error type differs from the function's goes through
 * `impl From`, and an Option is re-keyed to Some and None. */

ASTNode *try_source_type(VariantTable *table, ASTNode *target) {
    if (target && target->type == AST_CALL && target->call.recv) {
        /* `r.ok()?`: the method of the receiver's type (methods are resolved
         * only after this pass). */
        ASTNode *recv_type = try_source_type(table, target->call.recv);
        const char *recv_name = type_base_name(recv_type);
        const MethodDef *method = recv_name ? find_method(table->context, recv_name, target->call.name) : NULL;
        return method ? method->fundef->fundef.ret_type : NULL;
    }
    ASTNode *type = call_result_type(table, target, NULL);
    if (type) return type;
    if (target && target->type == AST_IDENTIFIER && table->current_function) {
        ASTNode *fn = table->current_function;
        for (int i = 0; i < fn->fundef.param_count; i++) {
            type = find_local_type(fn->fundef.params[i], target->identifier.name);
            if (type) return type;
        }
        type = find_local_type(fn->fundef.body, target->identifier.name);
        for (int i = 0; i < table->program->block.count && !type; i++) {
            ASTNode *node = table->program->block.stmts[i];
            if (node && node->type == AST_VAR_DECL &&
                strcmp(node->var_decl.name, target->identifier.name) == 0)
                type = node->var_decl.var_type;
        }
        return type;
    }
    return NULL;
}

static const char *skip_encoded_type_key(const char *segment) {
    if (!segment || strncmp(segment, "_p", 2) != 0) return NULL;
    const char *length_marker = strstr(segment, "_n");
    if (!length_marker) return NULL;
    char *end = NULL;
    long length = strtol(length_marker + 2, &end, 10);
    if (!end || *end != '_' || length < 0) return NULL;
    const char *name = end + 1;
    if (strlen(name) < (size_t)length) return NULL;
    return name + length;
}

/* A concrete Result name ends in two length-prefixed type keys. Returning the
 * start of the second key lets `?` compare E without requiring enum E itself
 * to have a runtime-distinct representation. */
static const char *result_error_type_key(ASTNode *type) {
    const char *name = type_base_name(type);
    if (!name || strncmp(name, "__mlg_s_6_Result", 16) != 0) return NULL;
    const char *first = name + 16;
    return skip_encoded_type_key(first);
}

/* `_p0_r0_m0_n8_SsdError` (one key of an instance name) back to a type. */
static ASTNode *decode_type_key(const char *key) {
    int pointer_level = 0, borrow_kind = 0, modifiers = 0;
    size_t length = 0;
    int consumed = 0;
    if (sscanf(key, "_p%d_r%d_m%d_n%zu_%n", &pointer_level, &borrow_kind, &modifiers, &length,
               &consumed) != 4 || consumed == 0 || strlen(key + consumed) < length)
        return NULL;
    char name[256];
    if (length >= sizeof(name)) return NULL;
    memcpy(name, key + consumed, length);
    name[length] = '\0';
    return new_type_node(new_identifier(name), pointer_level, modifiers, borrow_kind);
}

static int is_generated_try_case(ASTNode *node) {
    if (!node || node->type != AST_CASE || node->case_expr.case_count != 2) return 0;
    ASTNode *key = node->case_expr.cases[0].key;
    if (!key || key->type != AST_CALL || key->call.arg_count != 1) return 0;
    ASTNode *binding = key->call.args[0];
    return binding && binding->type == AST_IDENTIFIER && binding->identifier.name &&
           strncmp(binding->identifier.name, "__mlg_try_value_", 16) == 0;
}

static int is_option_type(ASTNode *type) {
    const char *name = type_base_name(type);
    return name && strncmp(name, "__mlg_s_6_Option", 16) == 0;
}

/* `opt?` in a function returning an Option: `Some(v)` gives v, `None`
 * returns None. The expansion was written for Result; re-key its arms. */
static void lower_option_try(VariantTable *table, ASTNode *node) {
    if (!is_option_type(table->current_return_type)) {
        payload_error(table->context, node,
                      "'?' on an Option can only be used in a function returning Option "
                      "(match None explicitly, or turn it into a Result first)");
    }
    ASTNode *some = node->case_expr.cases[0].key;
    free(some->call.name);
    some->call.name = strdup("Some");
    free_ast(node->case_expr.cases[1].key);
    node->case_expr.cases[1].key = new_identifier("None");
    free_ast(node->case_expr.cases[1].expr);
    ASTNode **stmts = malloc(sizeof(ASTNode *));
    stmts[0] = new_return(new_identifier("None"));
    stmts[0]->line = node->line;
    stmts[0]->col = node->col;
    node->case_expr.cases[1].expr = new_stmt_expr(new_block(stmts, 1));
}

void check_try_error_type(VariantTable *table, ASTNode *node) {
    if (!is_generated_try_case(node) || !table->current_return_type) return;
    ASTNode *source_type = try_source_type(table, node->case_expr.target);
    if (is_option_type(source_type)) {
        lower_option_try(table, node);
        return;
    }
    const char *source_error = result_error_type_key(source_type);
    const char *target_error = result_error_type_key(table->current_return_type);
    if (!source_error)
        payload_error(table->context, node,
                      "'?' requires a Result value whose error can be propagated");
    if (!target_error)
        payload_error(table->context, node,
                      "'?' can only be used in a function returning Result");
    if (strcmp(source_error, target_error) == 0) return;

    /* A different error type propagates through `impl From<Source> for
     * Target`: the generated arm returns `Err(Target::from(error))`. */
    ASTNode *source = decode_type_key(source_error);
    ASTNode *target = decode_type_key(target_error);
    ImplDef *impl = source && target ? find_impl(table->context, "From", &source, 1, target) : NULL;
    if (!impl) {
        char *source_name = source ? trait_type_display(source) : strdup("the source error");
        char *target_name = target ? trait_type_display(target) : strdup("the function's error");
        fprintf(stderr, "%s:%d:%d: error: '?' cannot convert %s into %s\n",
                table->context->module.filename ? table->context->module.filename : "<input>",
                node->line, node->col, source_name, target_name);
        fprintf(stderr, "  note: add `impl From<%s> for %s`, or handle the error explicitly\n",
                source_name, target_name);
        exit(1);
    }
    /* The error return trace names the conversion on this hop. */
    char *source_name = trait_type_display(source);
    char *target_name = trait_type_display(target);
    size_t note_len = strlen(source_name) + strlen(target_name) + 8;
    char *note = malloc(note_len);
    snprintf(note, note_len, "%s -> %s", source_name, target_name);
    free(source_name);
    free(target_name);
    free_ast(source);
    free_ast(target);

    ASTNode *arm = node->case_expr.cases[1].expr;
    ASTNode *ret = arm && arm->type == AST_STMT_EXPR ? arm->stmt_expr.block->block.stmts[0] : NULL;
    ASTNode *err = ret && ret->type == AST_RETURN ? ret->ret.expr : NULL;
    if (!err || err->type != AST_CALL || err->call.arg_count != 1)
        payload_error(table->context, node, "internal error: unexpected '?' expansion");
    free(ret->ret.trace_note);
    ret->ret.trace_note = note;
    ASTNode **args = malloc(sizeof(ASTNode *));
    args[0] = err->call.args[0];
    ASTNode *convert = new_call((char *)impl_item_mangled(impl, "from"), args, 1);
    convert->line = node->line;
    convert->col = node->col;
    err->call.args[0] = convert;
}
