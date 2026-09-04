# MyLang Generics

**Status: design proposal. Not implemented.** This document defines generic
types and functions as the foundation for ordinary MyLang library containers.
The first usable release includes cross-module templates and linker
deduplication; module-local generics alone are an implementation milestone, not
a supported endpoint.

## 1. Goals

1. Type-parameterized `struct`s and functions, checked at compile time.
2. No runtime type information and no dispatch cost: each used instantiation
   becomes ordinary monomorphic code.
3. Exported templates work across module boundaries, so generic types can live
   in `std` rather than beside every use site.
4. Identical public instantiations emitted by different compilation units are
   merged by the linker.
5. The design leaves a clean path to receiver methods (`docs/methods.md`).

### Non-goals for the first version

- Type-argument inference at free-function call sites.
- Constraints, traits, bounds, specialization, or variance.
- Generic lambdas or methods with type parameters independent of their
  receiver type.
- Anything requiring a heap. See `docs/containers.md`.

## 2. Surface syntax

Type parameters are attached to the declared type or function name. There is no
separate `generic` keyword.

```mylang
struct Pair<T> {
    T first;
    T second;
};

T max<T>(T a, T b) {
    return (a > b) ? a : b;
}

i32 main() {
    mut Pair<i32> p = { first: 1, second: 2 };
    mut i32 m = max<i32>(p.first, p.second);
    return m;
}
```

`export` keeps its existing position:

```mylang
export struct Queue<T> { /* ... */ };

export T max<T>(T a, T b) { /* ... */ }
```

### Grammar additions

Written against `docs/grammar.md`, which is updated with the parser change.

```text
type_params  -> < IDENTIFIER ( , IDENTIFIER )* >
type_args    -> < type ( , type )* >

base_type    -> primitive_type | IDENTIFIER type_args?
struct_decl  -> struct IDENTIFIER type_params? { var_decl* } ( IDENTIFIER )? ;
fundef       -> type IDENTIFIER type_params? ( param_list ) ( block | ; )
call         -> IDENTIFIER type_args? ( arg_list )
```

For a struct, the parser encounters `<T>` before its body and can push the
parameters into the scoped typename table directly. For a function, the type
parameters lexically follow the return type, so their scope is defined to cover
the complete declaration, including that return type:

```text
T max<T>(T a, T b)
^     +------------- T is in scope here too
```

At declaration position the parser performs non-consuming header lookahead. It
finds an identifier followed by a type-parameter list and `(`, records those
parameter names, then parses the declaration normally from its first token.
After the declaration it pops the temporary type names. This also handles a
generic return type such as `Pair<T> make_pair<T>(...)` without adding a new
function keyword or changing return-type placement.

### Parsing `<` in expressions

Type position is unambiguous. In expression position, `<...>` is parsed as type
arguments only when all of these conditions hold:

1. ordinary lexical name resolution finds a generic function (a local binding
   with the same spelling shadows it);
2. the contents parse as a comma-separated type list; and
3. the closing `>` is immediately followed by `(`.

Otherwise `<` remains a comparison operator. This preserves expressions such
as `a < b > (c)` and avoids relying on a global name table that ignores local
shadowing. The parser uses bounded lookahead for the complete `<...>(` shape;
it does not consume tokens until the shape is confirmed.

## 3. Template model and pipeline

The parser records generic declarations in a template table instead of emitting
them as ordinary declarations. An exported entry contains its complete AST,
source location, package identity, and ordered type-parameter list—not merely a
call signature.

```text
lexer -> parser/import templates -> monomorphize -> semantic -> codegen
```

Free functions and structs are monomorphized before semantic analysis. The
monomorphizer clones a template, substitutes concrete type arguments, and emits
ordinary AST nodes. No generic type node reaches the existing semantic or
backend paths.

Receiver method calls are the deliberate exception described in
`docs/methods.md`: the receiver expression needs semantic type resolution. A
generic struct instantiation eagerly emits its concrete methods before semantic
analysis; semantic analysis then resolves `value.method(...)` against those
ordinary concrete methods and a method-lowering pass rewrites the call before
code generation.

## 4. AST additions

In `inc/mylang/ast/AST.h`:

```c
AST_TYPE_GENERIC,

struct {
    char *base_name;
    ASTNode **args;
    int arg_count;
} type_generic;
```

Existing declaration nodes gain:

```c
char **type_params;
int type_param_count;
```

Calls gain explicit type arguments:

```c
ASTNode **type_args;
int type_arg_count;
```

Template records own their AST independently of the main program tree. Clone,
print, rewrite, validation, and free walkers must handle every added field.

## 5. Monomorphization

1. **Collect.** Record local generic declarations and imported exported
   templates under `(package, public name)`.
2. **Seed.** Walk ordinary code for `AST_TYPE_GENERIC` nodes and explicit
   generic calls.
3. **Canonicalize.** Resolve aliases and serialize each concrete type argument
   into its canonical form (section 6).
4. **Expand.** For each unseen `(template identity, canonical arguments)`, clone
   the template AST, substitute its parameters, assign the canonical generated
   name, and append an ordinary declaration.
5. **Discover.** Scan the clone for nested instantiations and add them to the
   worklist.
6. **Rewrite.** Replace generic type and call sites with generated ordinary
   names.
7. Repeat until the worklist is empty.

Pointer levels compose: `T*` with `T = char*` becomes `char**`. Reference kinds
and modifiers at the use site apply outside the substituted type.

Only used instantiations are emitted. Recursive expansion is capped at depth 32
and reports `E0503` with both the original use and expansion chain.

## 6. Canonical types and generated names

Generated names must be injective: distinct source types cannot share a symbol.
Appending letters such as `p` is insufficient because `Bar*` would collide with
a user type named `Barp`.

The canonical type encoding is recursive and self-delimiting:

```text
primitive   := I32 | U32 | U16 | U8 | CHAR | BOOL | ...
named       := N <decimal-byte-length> _ <qualified-name>
pointer     := P <type>
ref         := R <type>
ref-mut     := M <type>
const       := C <type>
array       := A <decimal-count> _ <type>
generic     := G <named> _ <arg-count> _ <type>...
```

Aliases are resolved before encoding. Nested generics, qualifiers, references,
pointers, and arrays therefore all contribute unambiguously.

Examples:

| Source type | Canonical encoding |
| --- | --- |
| `i32` | `I32` |
| `char*` | `PCHAR` |
| `Pair<i32>` | `GN4_Pair_1_I32` |
| `Pair<char*>` | `GN4_Pair_1_PCHAR` |

A public free-function instantiation is named from its package, public template
name, and canonical arguments. The consuming module is intentionally absent:

```text
std__queue_init__I32
```

Private generic instantiations include the defining compilation-unit identity
and are never eligible for cross-object deduplication. The compiler-reserved
`__` namespace remains unavailable to source declarations (`E0504`).

## 7. Cross-module templates

An ordinary import needs only an exported symbol signature. A generic import
also needs the template body. When parsing an import, the compiler loads the
target source's exported template records into an import cache. Cache keys use
canonical source identity plus package name, preventing repeated parsing and
detecting cycles.

Instantiation happens in each consuming compilation unit:

```text
main.mln   -> queue_push<i32> definition in main.masm
worker.mln -> queue_push<i32> definition in worker.masm
```

Both definitions deliberately use the same public generated name. This is the
same broad model used by C++ implicit template instantiation: consumers see the
definition, emit what they use, and the linker coalesces duplicates.

Conflicting exported templates with the same `(package, public name)` are an
error (`E0505`). Import cycles continue to use the package/import diagnostic
band.

## 8. Link-once definitions

The object/assembly pipeline gains a `linkonce`-equivalent marker for generated
public generic functions. Linker behavior is:

- duplicate strong definitions remain an error;
- duplicate `linkonce` definitions with the same symbol and identical content
  are coalesced to one definition;
- a strong definition colliding with `linkonce` is an error;
- same-name `linkonce` definitions with different bytes or relocations are an
  error, rather than silently selecting one.

Struct instantiations are compile-time layout information and emit no linker
symbol by themselves. Any generated functions using them follow the rules
above. Content comparison includes relocation targets, not only instruction
bytes.

Explicit-instantiation declarations and `extern template`-style suppression are
future optimizations, not part of v1.

## 9. Ownership

After substitution, `docs/ownership.md` applies to the concrete program. A
generic type is not implicitly Copy: each concrete instantiation is Copy only
when the corresponding ordinary struct would be Copy. No new borrow or move
rules are introduced.

## 10. Diagnostics

| Code | Meaning |
| --- | --- |
| `E0501` | Type-argument count mismatch |
| `E0502` | Generic name used without required type arguments |
| `E0503` | Instantiation depth limit exceeded |
| `E0504` | Source symbol uses the compiler-reserved `__` namespace |
| `E0505` | Conflicting exported template definitions |

## 11. Testing

- Parser cases for `struct Pair<T>` and `T max<T>(...)`, generic return types,
  and comparison expressions adjacent to generic names.
- Single-module struct/function instantiation and nested type substitution.
- Imports of an exported generic from two independent consumers.
- Two consumers linked together, proving identical generated definitions are
  coalesced.
- A negative linker test where equal generated names have different content.
- Mangling whitebox cases covering user names ending in `p`, nested generics,
  aliases, pointers, arrays, and reference modifiers.
- A non-generic program must produce byte-identical assembly after the pass is
  introduced.

## 12. Milestones

| PR | Content |
| --- | --- |
| 1 | Type-parameter grammar, declaration-header lookahead, AST fields, scoped type parameters, and diagnostics for unsupported use. |
| 2 | Canonical type encoding and single-module monomorphization of structs and free functions. |
| 3 | Export/import of complete template records and cross-module instantiation. |
| 4 | `linkonce` object/assembly marker and linker coalescing with mismatch diagnostics. |
| 5 | Receiver methods and type-aware method-call lowering (`docs/methods.md`). |
| 6 | `std/queue.mln` with its final method API. |
| 7 | Typed callbacks, then `std/map.mln`. |

The feature is advertised as usable only after milestone 4. Queue is published
only after receiver methods so its public API does not immediately change.
