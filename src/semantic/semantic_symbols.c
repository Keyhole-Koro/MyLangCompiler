#include "mylang/semantic/semantic_internal.h"
#include "mylang/frontend/module.h"
#include "mylang/frontend/resolver.h"

/* The names a module can see: its functions, enums, types and struct layouts,
 * its own and those its imports bring in. */

int semantic_enum_type_exists(SemanticContext *ctx, const char *name) {
    if (!ctx || !name) return 0;
    for (int i = 0; i < ctx->enum_type_count; i++) {
        if (ctx->enum_types[i] && strcmp(ctx->enum_types[i], name) == 0) return 1;
    }
    return 0;
}

int semantic_find_enum_value(SemanticContext *ctx, const char *name, long *out_value) {
    if (!ctx || !name) return 0;
    for (int i = ctx->enum_value_count - 1; i >= 0; i--) {
        if (ctx->enum_values[i].name && strcmp(ctx->enum_values[i].name, name) == 0) {
            if (out_value) *out_value = ctx->enum_values[i].value;
            return 1;
        }
    }
    return 0;
}

int semantic_is_builtin_call(const char *name) {
    return name &&
           (strcmp(name, "__rest_len") == 0 ||
            strcmp(name, "__rest_get") == 0);
}

SemanticFunctionSig *semantic_find_function_sig(SemanticContext *ctx, const char *name) {
    if (!ctx || !name) return NULL;
    for (int i = ctx->function_sig_count - 1; i >= 0; i--) {
        if (ctx->function_sigs[i].name && strcmp(ctx->function_sigs[i].name, name) == 0) {
            return &ctx->function_sigs[i];
        }
    }
    return NULL;
}

SemanticNewtype *semantic_find_newtype(SemanticContext *ctx, const char *name) {
    if (!ctx || !name) return NULL;
    for (int i = 0; i < ctx->newtype_count; i++)
        if (ctx->newtypes[i].name && strcmp(ctx->newtypes[i].name, name) == 0)
            return &ctx->newtypes[i];
    return NULL;
}

static void populate_function_sig_types(SemanticContext *ctx, SemanticFunctionSig *sig,
                                        ASTNode *return_type, ASTNode **params,
                                        int param_count, SemanticLocation loc) {
    int fixed_count;

    if (!ctx || !sig) return;
    sig->has_return_type = 0;
    sig->has_param_types = 0;
    semantic_typeinfo_clear(&sig->return_type);
    for (int i = 0; i < SEMANTIC_MAX_FUNCTION_PARAMS; i++) {
        semantic_typeinfo_clear(&sig->param_types[i]);
        sig->param_names[i] = NULL;
        sig->param_borrow_kinds[i] = REFKIND_NONE;
        sig->param_is_move[i] = 0;
    }

    if (return_type && semantic_typeinfo_from_type_ast(return_type, &sig->return_type)) {
        sig->has_return_type = 1;
    }

    fixed_count = sig->fixed_param_count;
    if (!params || fixed_count < 0) return;
    if (fixed_count > SEMANTIC_MAX_FUNCTION_PARAMS) {
        semantic_error_at(ctx, loc, "semantic function signature for '%s' has too many parameters", sig->name);
        return;
    }

    sig->has_param_types = 1;
    for (int i = 0; i < fixed_count; i++) {
        ASTNode *param = semantic_as_param(params[i]);
        if (!param || param->param.is_rest ||
            !semantic_typeinfo_from_type_ast(param->param.type, &sig->param_types[i])) {
            sig->has_param_types = 0;
            continue;
        }
        sig->param_names[i] = param->param.name;
        sig->param_borrow_kinds[i] = sig->param_types[i].borrow_kind;
        sig->param_is_move[i] = param->param.is_move;
    }
    (void)param_count;
}

static void register_function_sig(SemanticContext *ctx, const char *name, int param_count,
                                  int is_variadic, int is_imported, SemanticLocation loc,
                                  ASTNode *return_type, ASTNode **params,
                                  ASTNode *declaration) {
    SemanticFunctionSig *sig;

    if (!ctx || !name) return;
    sig = semantic_find_function_sig(ctx, name);
    if (sig && !sig->is_imported) return;
    if (sig && sig->is_imported && !is_imported) {
        sig->param_count = param_count;
        sig->fixed_param_count = is_variadic ? param_count - 1 : param_count;
        sig->is_variadic = is_variadic;
        sig->is_imported = 0;
        sig->decl_loc = loc;
        sig->declaration = declaration;
        populate_function_sig_types(ctx, sig, return_type, params, param_count, loc);
        return;
    }

    if (ctx->function_sig_count >= (int)(sizeof(ctx->function_sigs) / sizeof(ctx->function_sigs[0]))) {
        semantic_error_at(ctx, loc, "semantic function table exhausted while tracking '%s'", name);
        return;
    }

    sig = &ctx->function_sigs[ctx->function_sig_count++];
    sig->name = name;
    sig->param_count = param_count;
    sig->fixed_param_count = is_variadic ? param_count - 1 : param_count;
    sig->is_variadic = is_variadic;
    sig->is_imported = is_imported;
    sig->decl_loc = loc;
    sig->declaration = declaration;
    populate_function_sig_types(ctx, sig, return_type, params, param_count, loc);
}

void semantic_register_imported_package(SemanticContext *ctx, const char *name) {
    if (!ctx || !name || ctx->imported_package_count >= 64) return;
    for (int i = 0; i < ctx->imported_package_count; i++) {
        if (ctx->imported_packages[i] && strcmp(ctx->imported_packages[i], name) == 0) return;
    }
    ctx->imported_packages[ctx->imported_package_count++] = strdup(name);
}

int semantic_call_may_be_package_import(SemanticContext *ctx, const char *name) {
    if (!ctx || !name) return 0;
    for (int i = 0; i < ctx->imported_package_count; i++) {
        const char *package = ctx->imported_packages[i];
        size_t length = package ? strlen(package) : 0;
        if (length > 0 && strncmp(name, package, length) == 0 && name[length] == '_')
            return 1;
    }
    return 0;
}

void semantic_register_enum(SemanticContext *ctx, ASTNode *node) {
    if (!ctx || !node || node->type != AST_ENUM) return;
    if (node->enum_stmt.name && ctx->enum_type_count < (int)(sizeof(ctx->enum_types) / sizeof(ctx->enum_types[0]))) {
        ctx->enum_types[ctx->enum_type_count++] = node->enum_stmt.name;
    }
    for (int i = 0; i < node->enum_stmt.member_count; i++) {
        ASTNode *member = node->enum_stmt.members[i];
        if (!member || member->type != AST_ENUM_MEMBER) continue;
        if (ctx->enum_value_count >= (int)(sizeof(ctx->enum_values) / sizeof(ctx->enum_values[0]))) {
            semantic_error_at(ctx, semantic_location_from_ast(member),
                              "semantic enum table exhausted while tracking '%s'", member->enum_member.name);
            return;
        }
        ctx->enum_values[ctx->enum_value_count].name = member->enum_member.name;
        ctx->enum_values[ctx->enum_value_count].value = member->enum_member.resolved_value;
        ctx->enum_values[ctx->enum_value_count].enum_name = node->enum_stmt.name;
        ctx->enum_value_count++;
    }
}

void semantic_collect_function_sigs(SemanticContext *ctx, ASTNode *node) {
    if (!ctx || !node) return;

    switch (node->type) {
    case AST_BLOCK:
        for (int i = 0; i < node->block.count; i++) {
            semantic_collect_function_sigs(ctx, node->block.stmts[i]);
        }
        break;
    case AST_FUNDEF:
        register_function_sig(ctx,
                              node->fundef.name,
                              node->fundef.param_count,
                              node->fundef.is_variadic ? 1 : 0,
                              0,
                              semantic_location_from_ast(node),
                              node->fundef.ret_type,
                              node->fundef.params,
                              node);
        break;
    case AST_IMPORT:
        if (node->import_stmt.path && module_loader_is_mylang_source(node->import_stmt.path)) {
            FrontendSession *session = ctx->session;
            if (session && session->loader) {
                Module *mod = module_loader_load(session->loader, ctx->filename, node->import_stmt.path);
                if (mod) {
                    const char *pkg = resolver_import_package_name(node, mod);
                    if (pkg) {
                        semantic_register_imported_package(ctx, pkg);
                    }
                    /* Mock callback validation needs the concrete type of a
                     * package target, not merely its callable symbol name. */
                    for (int i = 0; i < mod->symbol_count; i++) {
                        ModuleSymbol *sym = &mod->symbols[i];
                        ASTNode *fn;
                        if (sym->kind != SYMBOL_FUNCTION || !sym->source_name ||
                            !sym->link_name ||
                            !resolver_lookup_import_symbol(node, mod, sym->source_name)) {
                            continue;
                        }
                        fn = sym->declaration;
                        if (!fn || fn->type != AST_FUNDEF) continue;
                        register_function_sig(ctx, sym->link_name,
                                              fn->fundef.param_count,
                                              fn->fundef.is_variadic ? 1 : 0,
                                              0,
                                              semantic_location_from_ast(node),
                                              fn->fundef.ret_type,
                                              fn->fundef.params,
                                              fn);
                        SemanticFunctionSig *imported = semantic_find_function_sig(ctx, sym->link_name);
                        if (imported) imported->from_unsafe_module = mod->is_unsafe;
                    }
                }
            }
        }
        for (int i = 0; i < node->import_stmt.symbol_count; i++) {
            register_function_sig(ctx,
                                  node->import_stmt.symbols[i],
                                  -1,
                                  0,
                                  1,
                                  semantic_location_from_ast(node),
                                  NULL,
                                  NULL,
                                  NULL);
            /* Assembly can do anything, so it is unsafe code by nature. */
            if (node->import_stmt.path && !module_loader_is_mylang_source(node->import_stmt.path)) {
                SemanticFunctionSig *imported = semantic_find_function_sig(ctx, node->import_stmt.symbols[i]);
                if (imported) imported->from_unsafe_module = 1;
            }
        }
        break;
    default:
        break;
    }
}

static void semantic_register_user_type(SemanticContext *ctx, const char *name) {
    if (!ctx || !name) return;
    if (ctx->user_type_count < (int)(sizeof(ctx->user_types) / sizeof(ctx->user_types[0]))) {
        ctx->user_types[ctx->user_type_count++] = name;
    }
}

/* Records one struct's members so a later member access can be typed. Anonymous
 * structs and members without a resolvable type are skipped rather than stored
 * half-formed: an unknown member type is somebody else's diagnostic. */
static void semantic_register_struct_layout(SemanticContext *ctx, const char *name,
                                            ASTNode **members, int member_count) {
    if (!ctx || !name || ctx->struct_layout_count >= 256) return;
    for (int i = 0; i < ctx->struct_layout_count; i++)
        if (strcmp(ctx->struct_layouts[i].name, name) == 0) return;

    SemanticStructLayout *layout = &ctx->struct_layouts[ctx->struct_layout_count];
    layout->name = name;
    layout->member_count = 0;
    for (int i = 0; i < member_count && layout->member_count < SEMANTIC_MAX_STRUCT_MEMBERS; i++) {
        ASTNode *member = members[i];
        if (!member || member->type != AST_VAR_DECL || !member->var_decl.name) continue;
        SemanticTypeInfo info;
        if (!semantic_typeinfo_from_type_ast(member->var_decl.var_type, &info)) continue;
        layout->members[layout->member_count].name = member->var_decl.name;
        layout->members[layout->member_count].type = info;
        layout->member_count++;
    }
    ctx->struct_layout_count++;
}

const SemanticStructMember *semantic_find_struct_member(SemanticContext *ctx,
                                                        const char *struct_name,
                                                        const char *member_name) {
    if (!ctx || !struct_name || !member_name) return NULL;
    if (strcmp(struct_name, "str") == 0) {
        static const SemanticStructMember data = {
            .name = "data",
            .type = { .base_type = "char", .pointer_level = 1 },
        };
        static const SemanticStructMember length = {
            .name = "length",
            .type = { .base_type = "i32" },
        };
        if (strcmp(member_name, "data") == 0) return &data;
        if (strcmp(member_name, "length") == 0) return &length;
        return NULL;
    }
    for (int i = 0; i < ctx->struct_layout_count; i++) {
        if (strcmp(ctx->struct_layouts[i].name, struct_name) != 0) continue;
        for (int m = 0; m < ctx->struct_layouts[i].member_count; m++)
            if (strcmp(ctx->struct_layouts[i].members[m].name, member_name) == 0)
                return &ctx->struct_layouts[i].members[m];
        return NULL; /* the struct is known, the member is not */
    }
    return NULL;
}

int semantic_struct_is_known(SemanticContext *ctx, const char *struct_name) {
    if (!ctx || !struct_name) return 0;
    if (strcmp(struct_name, "str") == 0) return 1;
    for (int i = 0; i < ctx->struct_layout_count; i++)
        if (strcmp(ctx->struct_layouts[i].name, struct_name) == 0) return 1;
    return 0;
}

/* An imported struct/typedef is registered under its link name (e.g.
 * "a_Thing" for `import a from "a.mln"` using `a.Thing`), matching how a
 * qualified type reference gets rewritten -- mirrors the AST_IMPORT handling
 * in semantic_collect_function_sigs() above, but for type declarations
 * instead of function signatures. Without this, `pkg.Type` was never a known
 * struct: semantic_infer_expr_type() silently declined to type a `->`/`.`
 * access through it (see semantic_struct_is_known()), instead of reporting
 * anything a caller could act on.
 */
static void semantic_collect_imported_user_types(SemanticContext *ctx, ASTNode *node) {
    if (!node->import_stmt.path || !module_loader_is_mylang_source(node->import_stmt.path)) return;
    FrontendSession *session = ctx->session;
    if (!session || !session->loader) return;
    Module *mod = module_loader_load(session->loader, ctx->filename, node->import_stmt.path);
    if (!mod) return;

    for (int i = 0; i < mod->symbol_count; i++) {
        ModuleSymbol *sym = &mod->symbols[i];
        if ((sym->kind != SYMBOL_STRUCT && sym->kind != SYMBOL_TYPEDEF) ||
            !sym->source_name || !sym->link_name ||
            !resolver_lookup_import_symbol(node, mod, sym->source_name)) {
            continue;
        }
        ASTNode *decl = sym->declaration;
        if (!decl) continue;
        if (decl->type == AST_STRUCT) {
            semantic_register_user_type(ctx, sym->link_name);
            semantic_register_struct_layout(ctx, sym->link_name, decl->struct_stmt.members,
                                            decl->struct_stmt.member_count);
        } else if (decl->type == AST_TYPEDEF_STRUCT) {
            semantic_register_user_type(ctx, sym->link_name);
            semantic_register_struct_layout(ctx, sym->link_name, decl->typedef_struct.members,
                                            decl->typedef_struct.member_count);
        } else if (decl->type == AST_TYPEDEF) {
            semantic_register_user_type(ctx, sym->link_name);
            if (decl->typedef_stmt.is_newtype && !semantic_find_newtype(ctx, sym->link_name) &&
                ctx->newtype_count < (int)(sizeof(ctx->newtypes) / sizeof(ctx->newtypes[0]))) {
                ctx->newtypes[ctx->newtype_count].name = sym->link_name;
                ctx->newtypes[ctx->newtype_count].base_type = decl->typedef_stmt.src_type;
                ctx->newtype_count++;
            }
        }
    }
}

void semantic_collect_imported_globals(SemanticContext *ctx, ASTNode *node) {
    if (!ctx || !node) return;
    if (node->type == AST_BLOCK) {
        for (int i = 0; i < node->block.count; i++) {
            semantic_collect_imported_globals(ctx, node->block.stmts[i]);
        }
        return;
    }
    if (node->type != AST_IMPORT || !node->import_stmt.path ||
        !module_loader_is_mylang_source(node->import_stmt.path)) {
        return;
    }

    FrontendSession *session = ctx->session;
    if (!session || !session->loader) return;
    Module *mod = module_loader_load(session->loader, ctx->filename,
                                     node->import_stmt.path);
    if (!mod || mod->state != MODULE_LOADED) return;

    for (int i = 0; i < mod->symbol_count; i++) {
        ModuleSymbol *sym = &mod->symbols[i];
        if (sym->kind != SYMBOL_GLOBAL || !sym->source_name ||
            !sym->link_name || !sym->declaration ||
            !resolver_lookup_import_symbol(node, mod, sym->source_name)) {
            continue;
        }
        const char *visible_name = node->import_stmt.symbol_count == 0
            ? sym->link_name : sym->source_name;
        ASTNode *decl = sym->declaration;
        int is_copy = semantic_type_is_copy(ctx, decl->var_decl.var_type);
        semantic_declare_binding(ctx, visible_name, decl->var_decl.var_type, is_copy, 0,
                        semantic_location_from_ast(node));
    }
}

void semantic_collect_user_types(SemanticContext *ctx, ASTNode *node) {
    if (!ctx || !node) return;
    if (node->type == AST_BLOCK) {
        for (int i = 0; i < node->block.count; i++) {
            semantic_collect_user_types(ctx, node->block.stmts[i]);
        }
    } else if (node->type == AST_STRUCT && node->struct_stmt.name) {
        semantic_register_user_type(ctx, node->struct_stmt.name);
        semantic_register_struct_layout(ctx, node->struct_stmt.name, node->struct_stmt.members,
                                        node->struct_stmt.member_count);
    } else if (node->type == AST_TYPEDEF_STRUCT && node->typedef_struct.typedef_name) {
        semantic_register_user_type(ctx, node->typedef_struct.typedef_name);
        semantic_register_struct_layout(ctx, node->typedef_struct.typedef_name,
                                        node->typedef_struct.members,
                                        node->typedef_struct.member_count);
    } else if (node->type == AST_TYPEDEF && node->typedef_stmt.alias) {
        semantic_register_user_type(ctx, node->typedef_stmt.alias);
        if (node->typedef_stmt.is_newtype && !semantic_find_newtype(ctx, node->typedef_stmt.alias) &&
            ctx->newtype_count < (int)(sizeof(ctx->newtypes) / sizeof(ctx->newtypes[0]))) {
            ctx->newtypes[ctx->newtype_count].name = node->typedef_stmt.alias;
            ctx->newtypes[ctx->newtype_count].base_type = node->typedef_stmt.src_type;
            ctx->newtype_count++;
        }
    } else if (node->type == AST_IMPORT) {
        semantic_collect_imported_user_types(ctx, node);
    }
}

void semantic_check_type_exists(SemanticContext *ctx, ASTNode *type_node) {
    if (!ctx || !type_node) return;
    if (type_node->type == AST_TYPE_FUNCTION) {
        for (int i = 0; i < type_node->function_type.param_count; i++)
            semantic_check_type_exists(ctx, type_node->function_type.param_types[i]);
        semantic_check_type_exists(ctx, type_node->function_type.return_type);
        return;
    }
    SemanticTypeInfo info;
    if (!semantic_typeinfo_from_type_ast(type_node, &info)) return;

    const char *base_type = info.base_type;
    if (!base_type || base_type[0] == '\0') return;

    if (semantic_enum_type_exists(ctx, base_type)) return;

    for (int i = 0; i < ctx->user_type_count; i++) {
        if (strcmp(ctx->user_types[i], base_type) == 0) return;
    }

    if (semantic_is_builtin_type(base_type)) {
        return;
    }

    if (strcmp(base_type, "rest") == 0) return; // For variadic params
    if (strcmp(base_type, "_") == 0) return; // Unit payload type

    semantic_error_at(ctx, semantic_location_from_ast(type_node), "unknown type '%s'", base_type);
}
