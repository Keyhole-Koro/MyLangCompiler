#include "mylang/frontend/parser_internal.h"

const char g_default_package[] = "main";

void add_function(ASTNode *fn) {
    ParserContext *context = parser_context_current();
    context->symbols.functions.funcs = realloc(context->symbols.functions.funcs, sizeof(ASTNode*) * (context->symbols.functions.count + 1));
    context->symbols.functions.funcs[context->symbols.functions.count++] = fn;
}

ASTNode *find_function(const char *name) {
    ParserContext *context = parser_context_current();
    for (int i = 0; i < context->symbols.functions.count; i++) {
        if (strcmp(context->symbols.functions.funcs[i]->fundef.name, name) == 0) {
            return context->symbols.functions.funcs[i];
        }
    }
    return NULL;
}

void add_typename(const char *name) {
    ParserContext *context = parser_context_current();
    context->symbols.types.typenames = realloc(context->symbols.types.typenames, sizeof(char*) * (context->symbols.types.count + 1));
    context->symbols.types.typenames[context->symbols.types.count++] = strdup(name);
}

int is_user_typename(const char *name) {
    ParserContext *context = parser_context_current();
    for (int i = 0; i < context->symbols.types.count; i++) {
        if (strcmp(context->symbols.types.typenames[i], name) == 0) return 1;
    }
    return 0;
}

int typename_scope_mark(void) {
    ParserContext *context = parser_context_current();
    return context->symbols.types.count;
}

void restore_typenames(int mark) {
    ParserContext *context = parser_context_current();
    if (mark < 0 || mark > context->symbols.types.count) return;
    for (int i = mark; i < context->symbols.types.count; i++) {
        free(context->symbols.types.typenames[i]);
    }
    context->symbols.types.count = mark;
    if (mark == 0) {
        free(context->symbols.types.typenames);
        context->symbols.types.typenames = NULL;
        return;
    }
    context->symbols.types.typenames = realloc(context->symbols.types.typenames, sizeof(char *) * mark);
}

static const char *generic_declaration_name(ASTNode *declaration) {
    if (!declaration) return NULL;
    if (declaration->type == AST_FUNDEF) return declaration->fundef.name;
    if (declaration->type == AST_STRUCT) return declaration->struct_stmt.name;
    return NULL;
}

void add_generic_template(ASTNode *declaration) {
    ParserContext *context = parser_context_current();
    const char *name = generic_declaration_name(declaration);
    if (!name) return;
    ASTNode *existing = declaration->type == AST_STRUCT
        ? find_generic_type_template(name)
        : find_generic_function_template(name);
    if (existing) {
        fprintf(stderr, "duplicate generic declaration '%s'\n", name);
        exit(1);
    }
    context->symbols.generic_templates.declarations = realloc(
        context->symbols.generic_templates.declarations,
        sizeof(ASTNode *) * (context->symbols.generic_templates.count + 1)
    );
    context->symbols.generic_templates.declarations[context->symbols.generic_templates.count++] = declaration;
}

static ASTNode *find_generic_template(const char *name, ASTNodeType declaration_type) {
    ParserContext *context = parser_context_current();
    if (!name) return NULL;
    for (int i = 0; i < context->symbols.generic_templates.count; i++) {
        ASTNode *declaration = context->symbols.generic_templates.declarations[i];
        const char *candidate = generic_declaration_name(declaration);
        if (declaration->type == declaration_type &&
            candidate && strcmp(candidate, name) == 0)
            return declaration;
    }
    return NULL;
}

ASTNode *find_generic_type_template(const char *name) {
    return find_generic_template(name, AST_STRUCT);
}

ASTNode *find_generic_function_template(const char *name) {
    return find_generic_template(name, AST_FUNDEF);
}

ASTNode *generic_template_at(int index) {
    ParserContext *context = parser_context_current();
    if (index < 0 || index >= context->symbols.generic_templates.count) return NULL;
    return context->symbols.generic_templates.declarations[index];
}

int generic_template_count(void) {
    ParserContext *context = parser_context_current();
    return context->symbols.generic_templates.count;
}

void add_structdef(char *name, ASTNode **members, int member_count) {
    ParserContext *context = parser_context_current();
    StructDef *def = malloc(sizeof(StructDef));
    def->name = strdup(name);
    def->members = members;
    def->member_count = member_count;
    context->symbols.structs.structs = realloc(context->symbols.structs.structs, sizeof(StructDef*) * (context->symbols.structs.count + 1));
    context->symbols.structs.structs[context->symbols.structs.count++] = def;
}

StructDef *find_structdef(const char *name) {
    ParserContext *context = parser_context_current();
    for (int i = 0; i < context->symbols.structs.count; i++) {
        if (strcmp(context->symbols.structs.structs[i]->name, name) == 0) return context->symbols.structs.structs[i];
    }
    return NULL;
}

void add_enum_constant(const char *name, long value) {
    ParserContext *context = parser_context_current();
    context->symbols.enum_constants = realloc(context->symbols.enum_constants, sizeof(EnumConstant) * (context->symbols.enum_constant_count + 1));
    context->symbols.enum_constants[context->symbols.enum_constant_count].name = strdup(name);
    context->symbols.enum_constants[context->symbols.enum_constant_count].value = value;
    context->symbols.enum_constant_count++;
}

int find_enum_constant(const char *name, long *out_value) {
    ParserContext *context = parser_context_current();
    if (!name) return 0;
    for (int i = context->symbols.enum_constant_count - 1; i >= 0; i--) {
        if (strcmp(context->symbols.enum_constants[i].name, name) == 0) {
            if (out_value) *out_value = context->symbols.enum_constants[i].value;
            return 1;
        }
    }
    return 0;
}
