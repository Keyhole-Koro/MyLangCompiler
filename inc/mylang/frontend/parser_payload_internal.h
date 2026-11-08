#ifndef MYLANG_FRONTEND_PARSER_PAYLOAD_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_PAYLOAD_INTERNAL_H

/* Payload enum lowering, shared by its three files: parser_payload_enum.c
 * (the variant table, constructions and the walk), parser_payload_case.c
 * (`case` arms) and parser_payload_try.c (`?`). */

#include "mylang/frontend/parser_internal.h"
#include "mylang/frontend/parser_ast_internal.h"
#include "mylang/frontend/module.h"

typedef struct {
    char *variant; /* variant name, and the payload field name when it has one */
    long tag;
    int has_payload;
    int ambiguous; /* the same name at different tags in different enums */
    const char *enum_name;
} VariantTag;

typedef struct {
    VariantTag *items;
    int count;
    ParserContext *context;
    ASTNode *program;
    /* The enclosing function's declared return type, so `return Ok(5);` knows
     * what to build -- NULL outside a function body (or one whose return type
     * isn't itself a payload enum construction site). */
    ASTNode *current_return_type;
    ASTNode *current_function;
    /* Freshens the `__mlg_ret_N` stand-in used for `return Ok(5);` (see
     * rewrite_payload_block); the __mlg_ prefix is reserved for
     * compiler-generated names (see parser_instantiate.c), so these can't
     * collide with user identifiers. */
    int temp_counter;
    /* Declarations synthesized while lowering `case f() of { ... }`.  The
     * enclosing block splices them directly before the statement containing
     * the case, so the call is evaluated exactly once. */
    ASTNode **pending_hoists;
    int pending_hoist_count;
    /* Where import_type_layout() puts the next layout: ahead of everything
     * else, the way splice_imported_plain_types() does, and in order. */
    int layout_count;
    /* lower_payload_call_arguments() is walking: `items` is empty, and every
     * construction left is a call argument. */
    int lowering_arguments;
} VariantTable;

static inline const char *type_base_name(ASTNode *type) {
    if (!type || type->type != AST_TYPE || !type->type_node.base_type ||
        type->type_node.base_type->type != AST_IDENTIFIER)
        return NULL;
    return type->type_node.base_type->identifier.name;
}

/* parser_payload_enum.c */
void payload_error(ParserContext *context, ASTNode *node, const char *message);
VariantTag *variant_use(VariantTable *table, ASTNode *node);
void check_unambiguous(VariantTable *table, VariantTag *variant, ASTNode *at);
void check_single_payload(VariantTable *table, ASTNode *call);
void copy_display_name(char *out, size_t size, const char *name);
void check_variant_belongs(VariantTable *table, ASTNode *type, VariantTag *variant,
                           ASTNode *at);
char *tag_text(long tag);
int is_repeatable_target(ASTNode *node);
void import_type_layout(VariantTable *table, Module *module, const char *name);
ASTNode *call_result_type(VariantTable *table, ASTNode *node, Module **provider);
ASTNode *find_local_type(ASTNode *node, const char *name);

/* parser_payload_case.c */
void rewrite_payload_case(VariantTable *table, ASTNode *node);
VariantTag *case_result_variant(VariantTable *table, ASTNode *node);
int is_aggregate_type(VariantTable *table, ASTNode *type);
void lower_case_result_into(VariantTable *table, ASTNode *node, ASTNode *dest,
                            ASTNode *expected_type, const char *expected_enum);
int assigned_aggregate(VariantTable *table, ASTNode *lhs);

/* parser_payload_try.c */
ASTNode *try_source_type(VariantTable *table, ASTNode *target);
void check_try_error_type(VariantTable *table, ASTNode *node);

#endif
