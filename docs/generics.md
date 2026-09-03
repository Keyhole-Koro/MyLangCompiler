# MyLang Generics

**Status: design proposal. Not implemented.** This document defines the intended
shape of type parameters in MyLang so the work can be split into reviewable
steps. `docs/containers.md` builds `map` and `queue` on top of it.

## 1. Goals

1. Type-parameterized `struct`s and functions, checked at compile time.
2. No runtime cost and no runtime type information: every instantiation becomes
   ordinary monomorphic code.
3. No changes to semantic analysis or code generation. Generics are erased by a
   frontend pass, exactly as `AST_DOM_ELEMENT` is erased before the rest of the
   pipeline runs (`docs/source-modifiers.md`, `parser_lower_dom.c`).
4. Enough expressive power to write the standard containers as library code
   instead of compiler builtins.

### Non-goals for the first version

- Type-argument inference at call sites. Type arguments are written explicitly.
- Constraints, traits, or bounds. A type parameter is unconstrained.
- Generic lambdas, explicit specialization, and variance.
- Anything that needs a heap. See `docs/containers.md`.

## 2. Surface syntax

```mylang
struct Pair<T> {
    T first;
    T second;
}

T max<T>(T a, T b) {
    return (a > b) ? a : b;
}

i32 main() {
    mut Pair<i32> p = { first: 1, second: 2 };
    mut i32 m = max<i32>(p.first, p.second);
    return m;
}
```

### Grammar additions

Written against `docs/grammar.md`, which is updated in the same change that
implements this.

```text
type_params -> < IDENTIFIER ( , IDENTIFIER )* >
type_args   -> < type ( , type )* >

base_type   -> primitive_type | IDENTIFIER type_args?
struct_decl -> struct IDENTIFIER type_params? { var_decl* } (IDENTIFIER)? ;
fundef      -> type IDENTIFIER type_params? ( param_list ) ( block | ; )
call        -> IDENTIFIER type_args? ( arg_list )
```

### Why `<` is not ambiguous here

C++ needs backtracking because `a < b > (c)` is a valid expression. MyLang does
not, because `<` is consumed as a type-argument list **only when the preceding
identifier is already registered as a generic name**. The parser keeps those
tables today: `is_user_typename()` backs `is_type()`
(`src/frontend/parser/parser_lookahead.c:16`) and function names are tracked in
`parser_state_tables.c`. A generic name is registered when its template is
parsed, so an identifier that is not a template keeps parsing as a comparison
chain and no existing program changes meaning.

`looks_like_function()` (`parser_lookahead.c:31`) and `looks_like_fun_literal()`
must learn to skip a `<...>` group when they skip a base type; this is the only
lookahead change required.

### Type parameters inside a template

While a template is being parsed, its type parameters are pushed into the
typename table so `is_type()` accepts `T` in type position, and popped when the
template ends. A template body is therefore parsed but not type-checked until it
is instantiated. A template that is never instantiated is never checked. This
matches C++ two-phase behavior and is accepted for the first version.

## 3. Pipeline placement

```text
lexer -> parser -> [monomorphize] -> semantic -> codegen
                   ^ new frontend pass
```

The parser records templates in a side table and does not emit them into the
program tree. The monomorphization pass expands every instantiation into
ordinary declarations and rewrites the use sites. **After this pass no generic
node survives**, so `src/semantic/` and `src/backend/codegen/` need no changes
at all. This is the same contract the DOM extension already follows.

The pass lives in `src/frontend/parser/parser_mono.c`, next to the other
`parser_lower*.c` passes, and runs after parsing completes and before
`semantic_walk_ast()`.

## 4. AST additions

In `inc/mylang/ast/AST.h`:

```c
AST_TYPE_GENERIC,   // new node type

struct {
    char *base_name;      // "Pair"
    ASTNode **args;       // type nodes
    int arg_count;
} type_generic;
```

Existing members gain template information:

- `fundef`: `char **type_params; int type_param_count;`
- `struct_stmt` / `typedef_struct`: the same two fields.
- `call`: `ASTNode **type_args; int type_arg_count;`

A node with `type_param_count > 0` is a template and is never emitted. A node
carrying `AST_TYPE_GENERIC` or `type_args` is an instantiation site.

## 5. Monomorphization

1. **Collect.** Walk the top-level block. Move every declaration with type
   parameters into a template table and remove it from the tree.
2. **Seed.** Walk the remaining, non-generic code for instantiation sites: a
   `AST_TYPE_GENERIC` in any type position, and a call carrying type arguments.
   Push each `(template, type arguments)` pair onto a worklist.
3. **Expand.** For each pair not already instantiated: clone the template AST,
   substitute the type parameters, mangle the name, register the result as an
   ordinary typename or function, and append it to the top-level block. Scan the
   clone for further instantiation sites and push those too.
4. **Rewrite.** Replace each use site with the mangled name.
5. Repeat until the worklist is empty.

Substitution is a pure AST rewrite over type nodes. Pointer levels compose: `T*`
with `T = char*` becomes `char**`. Reference kinds and modifiers on the use site
are applied on top of the substituted type.

Recursive templates (`struct Node<T> { Node<Node<T>> next; }`) do not reach a
fixed point. The pass caps instantiation depth at 32 and reports `E0503`.

## 6. Name mangling

Instantiated names become assembly labels (`codegen_func.c` emits `%s:`), and
package qualification already joins names with `_`
(`parser_expr_postfix.c:21`), so mangled names stay within `[A-Za-z0-9_]`.

```text
mangled  := base ( "__" arg )*
arg      := ["c"] ["r" | "m"] base_name ("p" * pointer_level)
```

| Source | Mangled |
| --- | --- |
| `Pair<i32>` | `Pair__i32` |
| `map<char*, i32>` | `map__charp__i32` |
| `max<char**>` | `max__charpp` |
| `Box<ref mut Point>` | `Box__mPoint` |

`__` is reserved as the compiler's separator. A user symbol containing `__` is
rejected with `E0504`; the compiler already reserves this shape for generated
names such as `__dom0` and `__rest_len`.

## 7. Module boundaries

This is the one part of the design that is **not** settled, and the first
version deliberately avoids it.

Each `.mln` file compiles to its own `.masm` (`src/driver/driver_walk.c`), and
`import` resolves symbols by name only: the importer never builds the AST of the
imported file. A template body is therefore unavailable across a module
boundary, and a template cannot be instantiated where its body is unknown.

- **v1:** templates are module-local. `export` on a generic declaration is
  rejected with `E0505`.
- **Phase 2:** the importer parses imported sources for templates and
  instantiates them locally. The infrastructure exists — `parse_import()`
  already resolves a path relative to the importer and lexes the target file
  (`parser_toplevel.c:9`, `:31`). The open question is symbol duplication: two
  modules that both instantiate `map<i32,i32>` emit the same mangled label into
  two objects. Whether the MyComputer assembler and linker dedupe such symbols,
  or whether instantiations must be file-local, has to be decided with that
  toolchain before phase 2 lands.

## 8. Ownership

Generics are erased before semantic analysis, so `docs/ownership.md` applies to
the substituted code unchanged. A generic type is not Copy by declaration; each
instantiation is Copy exactly when its substituted members are. No new borrow or
move rules are introduced.

## 9. Diagnostics

New codes take the `E05xx` band, which `docs/diagnostic-codes.md` reserves as
unused. They are added to that table as "reserved" by this proposal and moved to
the live table when implemented.

| Code | Meaning |
| --- | --- |
| `E0501` | Type-argument count mismatch (`Pair<i32,i32>` for `Pair<T>`) |
| `E0502` | Generic name used without type arguments |
| `E0503` | Instantiation depth limit exceeded (recursive template) |
| `E0504` | User symbol uses the reserved `__` separator |
| `E0505` | Generic declaration cannot be exported (v1 restriction) |

## 10. Testing

- `tests/succeed/generic/`, `tests/fail/generic/` for surface behavior, picked
  up by `run_semantic_tests.py`.
- A whitebox case in `tests/` for the mangling function, so the scheme is
  pinned independently of the parser.
- A case asserting that a program using no generics produces byte-identical
  assembly before and after the pass, proving erasure is complete.
- All of it runs under `make test-component`; nothing here needs the e2e suite.

## 11. Milestones

| PR | Content |
| --- | --- |
| 1 | `AST_TYPE_GENERIC`, template fields, parsing and lookahead. Using a generic is a "not implemented" error. |
| 2 | Monomorphization of generic `struct`s, mangling, `E0501`–`E0505`. |
| 3 | Monomorphization of generic functions, including calls inside templates. |
| 4 | `std/queue.mln` and `std/map.mln` (`docs/containers.md`). |
| 5 | Cross-module templates, once the linker question in section 7 is answered. |
