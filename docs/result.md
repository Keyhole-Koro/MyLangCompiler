# `Result<T, E>` and Pattern `case` Design

`Result<T, E>` is MyLang's standard error-return type. It is a generic,
value-carrying `enum`:

```mylang
enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

This is the source-level type, AST type, and type-system model. The backend
may lower an enum to a tagged union for memory layout, but it must not model
`Result` as a special struct in earlier compiler phases.

## Surface API

```mylang
Result<i32, ParseError> parseNumber(string text) {
    if (text == "") {
        return Err(ParseError.Empty);
    }
    return Ok(42);
}
```

`Ok(value)` constructs the success case and `Err(error)` constructs the error
case.  Their `T` and `E` arguments are inferred from the expected
`Result<T, E>` type, initially from a return type or an explicitly typed
variable initializer.

The fields of `Result` are implementation details.  Programs must construct
and inspect it through `Ok`, `Err`, and `case`; direct initialization or
field access is not part of this API.

## Pattern `case ... of`

`case ... of` is an expression. It evaluates its target exactly once, matches
one arm, and produces that arm's value. Every arm must produce compatible
types. `Result` adds two typed patterns:

```mylang
i32 value = case parseNumber(input) of {
    Ok(value) -> value;
    Err(error) -> -1;
};
```

When the target has type `Result<T, E>`:

- `Ok(name)` binds `name` as `T`.
- `Err(name)` binds `name` as `E`.
- Each variant may appear at most once.
- Both variants are required unless a final `_` arm is present.
- Every arm must produce the same type.

`Ok(...)` and `Err(...)` are patterns only in this context.  Outside a
`case ... of` arm they retain their constructor meaning.

The first version deliberately keeps patterns small:

```mylang
pattern := _ | literal | Variant | Variant(identifier | _)
```

This supports `Ok(value)`, `Err(error)`, zero-payload variants such as `End`,
literal cases, and a final wildcard. Recursive patterns, multiple payloads,
and guards are deferred.

The compiler must reject duplicate variants, an arm after `_`, a payload on a
zero-payload variant, and a missing payload on a payload-carrying variant.
Bare identifiers in a case pattern resolve as zero-payload variants or enum
constants; they do not introduce bindings. Bindings only occur inside
`Variant(identifier)`.

## General enums and representation

`Result` is the first consumer of value-carrying enums. The same `case` rules
apply to all enums:

```mylang
enum Token {
    Number(i32),
    End,
}

i32 value = case token of {
    Number(value) -> value;
    End -> 0;
};
```

Each generic instantiation may be lowered to a concrete tagged union:

```c
struct Result_i32_ParseError {
    enum { RESULT_OK, RESULT_ERR } tag;
    union {
        int ok;
        struct ParseError err;
    } payload;
};
```

Only the active payload participates in copy, move, borrow, and destruction.
This avoids requiring a default value for both `T` and `E`, and preserves the
enum invariant that a result is exactly one of success or error.

## Implementation order

1. Extend `enum` declarations with generic parameters and optional
   single-value variants. Introduce enum-variant AST nodes and type metadata.
2. Replace expression keys in `case ... of` with `CasePattern` AST nodes;
   implement variant resolution, arm-local bindings, compatible arm result
   types, duplicate checking, and exhaustiveness checking.
3. Implement generic type instantiation and code generation. Generic
   declarations are parsed today, but generic type use deliberately reports
   "not implemented".
4. Add the standard `enum Result<T, E>` and concrete tagged-union lowering.
5. Type-check `Ok` / `Err` using the surrounding expected `Result<T, E>`
   type.
6. Add `?` as a separate feature. Its first version propagates the same `E`;
   error conversion is deferred until a conversion mechanism exists.

Methods and `?` are not prerequisites for the first `Result` implementation.
