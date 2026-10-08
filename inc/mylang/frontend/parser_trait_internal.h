#ifndef MYLANG_FRONTEND_PARSER_TRAIT_INTERNAL_H
#define MYLANG_FRONTEND_PARSER_TRAIT_INTERNAL_H

#include "mylang/frontend/parser_internal.h"

#include "mylang/frontend/module.h"

/* `trait Name<P...> { items }`. A trait has no code of its own: each item is
 * a body-less fundef written against the placeholder type `Self` and the
 * trait's own type parameters. A receiver item keeps its receiver in
 * params[0] and has recv_type_name "Self"; an associated function has none.
 *
 * An item written with a body is a default: `defaults[i]` holds a copy of
 * the item's tokens (signature and body, ending in EOT), which an impl that
 * leaves the item out parses again with `Self` spelled as its own type.
 * NULL for an item without one; `defaults` itself is NULL when no item has
 * a default.
 *
 * Ownership: every field is owned by the TraitDef. */
struct TraitDef {
    char *name;
    char **type_params;
    int type_param_count;
    ASTNode **items;
    Token **defaults;
    int item_count;
    int is_exported;
};

/* `impl Trait<Args> for Self { ... }`, after its items were spliced into the
 * program as ordinary methods and functions. The record is what bounds,
 * `?`, `==`, `Type::name(...)`, and for-in consult; the code itself is the
 * spliced fundefs. Types are plain AST_TYPE nodes. They are written as the
 * source spelled them and become concrete instance names once
 * instantiate_generics() reaches the record.
 *
 * An impl for a generic type -- `impl<T: Eq> Eq for Box<T>` or
 * `impl Eq for Box<i32>` -- is a template instead (is_template). Its items
 * are not in the program: they are kept here, written against `placeholder`
 * (the stand-in type both `Self` and the spelled-out `Box<T>` became), and
 * each instance of the generic type that matches self_type and meets the
 * bounds gets concrete items and a concrete ImplDef of its own
 * (parser_instantiate.c). self_name is the generic type's name; item_mangled
 * is unused. Lookups skip templates.
 *
 * Ownership: every field is owned by the ImplDef. */
struct ImplDef {
    char *trait_name;
    ASTNode **trait_args;
    int trait_arg_count;
    ASTNode *self_type;
    char *self_name;
    /* Parallel arrays, one entry per trait item: the item's own name and the
     * label of the function that implements it. */
    char **item_names;
    char **item_mangled;
    int item_count;
    int is_exported;
    int line;
    int col;
    int is_template;
    char **type_params;          /* the impl's own `<T, ...>` */
    ASTNode **type_param_bounds; /* parallel to type_params, or NULL */
    int type_param_count;
    char *placeholder;
    ASTNode **template_items;    /* parallel to item_names */
};

ASTNode *parse_trait(ParserContext *context, Token **cur, int want_export);
/* Returns an AST_BLOCK of the impl's spliced fundefs. */
ASTNode *parse_impl(ParserContext *context, Token **cur, int want_export);

TraitDef *find_trait(ParserContext *context, const char *name);
/* The impl of `trait_name<args>` for `self_type`, or NULL. Types are compared
 * by spelling, so callers pass types in the same (source or concrete) form
 * the registry currently holds. */
ImplDef *find_impl(ParserContext *context, const char *trait_name,
                   ASTNode **args, int arg_count, ASTNode *self_type);
/* Any impl of `trait_name` for the named type, whatever its arguments. */
ImplDef *find_impl_for_name(ParserContext *context, const char *trait_name,
                            const char *self_name);
/* Registers an impl the instantiation pass made from a template. */
void add_impl_instance(ParserContext *context, ImplDef *impl);
/* Whether `self_type` meets `bound` (a trait reference with concrete
 * arguments); require_bound() without the error. */
int bound_holds(ParserContext *context, ASTNode *self_type, ASTNode *bound);
/* The label of an associated function item `item_name` of `impl` (concrete
 * self type and trait arguments). Owned by the caller. */
char *impl_assoc_label(ParserContext *context, ImplDef *impl, const char *item_name);
int impl_count(ParserContext *context);
ImplDef *impl_at(ParserContext *context, int index);
const char *impl_item_mangled(const ImplDef *impl, const char *item_name);

/* A comparable spelling of a type: `SsdError`, `i32*`, `Box<i32>`. Owned by
 * the caller. */
char *trait_type_key(ASTNode *type);
/* trait_type_key() with generic instances spelled as written (`Box<Point>`
 * rather than the instance's internal name), for diagnostics. */
char *trait_type_display(ASTNode *type);

/* Records that `name` was imported through an `@alias/...` path, which is
 * what makes a declaration foreign to this source tree for the orphan rule. */
void mark_foreign_name(ParserContext *context, const char *name);

/* Imports the traits named by a symbol-list import and every exported impl
 * the module declares. */
void load_imported_traits(ParserContext *context, ASTNode *import_node,
                          const char *source_path, Module *module);

/* Makes the pending imported impls whose types are visible available; runs
 * once every import of the module has been parsed. */
void resolve_imported_impls(ParserContext *context);

/* Moves the context's traits and exported impls into a loaded module. */
void transfer_traits_to_module(ParserContext *context, Module *module);

/* Reports an error at `use` unless `self_type` implements `bound`, a trait
 * reference (`Eq`, `From<SsdError>`) whose arguments are already concrete. */
void require_bound(ParserContext *context, ASTNode *use, const char *template_name,
                   ASTNode *self_type, ASTNode *bound);

/* Resolves associated-function calls, trait-backed `==`, and for-in
 * iterator temporaries once every type in the program is concrete. Runs
 * inside instantiate_generics(), before payload enum uses are lowered. */
void lower_trait_uses(ParserContext *context, ASTNode *program);

/* `dyn Trait<Args>` (parser_trait_dyn.c). A trait object is a struct of
 * the object's address and one function pointer per method; `s.m()` calls
 * a generated dispatch method, and a `T *` becomes one through a generated
 * conversion where a dyn value is expected.
 *
 * Rewrites every `dyn Trait<Args>` in the token list to one placeholder type
 * name per spelling, before the module is parsed. */
void rewrite_dyn_types(ParserContext *context, Token *head);
/* Declares each placeholder's struct and dispatch methods once the module's
 * traits are known (end of parse_program_syntax()). */
void synthesize_dyn_types(ParserContext *context, ASTNode *program);
/* The dyn type `type` names, or NULL. */
DynUse *dyn_use_for_type(ParserContext *context, ASTNode *type);
/* Wraps `*slot`, a `T *`, in the conversion to dyn type `target` when T
 * implements the trait; leaves anything else alone. `source` is the
 * expression's inferred type (borrowed). */
void coerce_to_dyn(ParserContext *context, ASTNode *program, ASTNode **slot, ASTNode *source,
                   ASTNode *target);
void dyn_use_free(DynUse *use);

void trait_def_free(TraitDef *trait);
void impl_def_free(ImplDef *impl);
TraitDef *trait_def_clone(const TraitDef *trait);
ImplDef *impl_def_clone(const ImplDef *impl);

#endif
