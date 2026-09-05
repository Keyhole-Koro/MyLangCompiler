# Generic instantiation

Generic structs and functions are instantiated in the translation unit that
uses them. Type arguments are explicit:

```mylang
struct Box<T> { T value; };

T identity<T>(T value) { return value; }
T read<T>(Box<T> *box) { return box->value; }

i32 main() {
    Box<i32> box;
    box.value = identity<i32>(42);
    return read<i32>(&box);
}
```

The compiler substitutes concrete types for type parameters, checks each
instantiated body with the ordinary semantic checker, and emits ordinary
struct layouts and functions. Unused templates generate no code and their
bodies are not type-checked until instantiated.

The same declaration and type arguments share one instance in a translation
unit. Type aliases are expanded, while pointer depth, `const`, and reference
kind remain part of the instance identity. A type parameter is substituted
only in a type position, never into a variable or field name.

Nested types such as `Box<Box<i32>>` and calls from one generic function to
another are supported. Same-type function recursion reuses its instance.
Structs may contain pointers to themselves; direct or indirect by-value
containment cycles are rejected as infinitely sized. Generated structs are
ordered by their layout dependencies before the existing backend sees them.

## Boundaries

- Definitions must be available in the current translation unit or through a
  preceding named import of an exported template. A function can refer to
  itself.
- Instantiating a prototype without a definition is an error. The current
  template registry rejects duplicate generic declarations, including a
  separate prototype followed by a definition.
- A named import can expose an exported generic definition: for example,
  `import identity from "math.mln";` allows `identity<i32>(...)`. The
  specialization is emitted by the importing translation unit, not the library.
  Package-qualified generic imports and re-exporting imported templates are not
  supported yet. No implicit type-argument inference, constraints, or overloads
  are introduced here.
- Existing concrete-type semantics and calling conventions still apply.
  This pass does not add aggregate return/copy support, value-carrying enums,
  `Result`, destructors, or error propagation.
- A reference type argument cannot be wrapped in another reference or pointer;
  reference nesting/collapsing rules are not defined yet.
- Expansion is bounded to 64 active instantiations/alias resolutions and 256
  instances per translation unit. Internal names are limited to 240 bytes for
  the assembly toolchain. Expanding recursion fails with a diagnostic.
- Top-level names beginning with `__mlg_` are reserved for generated symbols.
  Their spelling is an implementation detail, not a public ABI.

## Implementation

`parser_instantiate.c` runs after top-level parsing and before DOM/lambda
lowering, export rewriting, semantic checking, and code generation. It owns
a temporary instance cache and clones template ASTs with `ast_clone`.
`ast_visit_children` supplies writable child slots for substitution and
concrete-type rewriting, including casts, arrays, initializers, and nested
expressions.

The program owns concrete declarations. The parser retains ownership of
templates until `parser_reset`. No AST nodes or owned strings are shared
between the two, and the instance cache does not survive compilation.

`make test-generics` tests the compiler CLI, diagnostics, instance reuse, and
deterministic assembly generation. Whitebox tests cover ownership and type
substitution; integration tests execute generic calls and struct layouts on
the emulator.
