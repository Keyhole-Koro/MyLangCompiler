# `Result<T, E>` Design

`Result<T, E>` is MyLang's standard error-return type.  It is specified as a
generic `struct`, rather than as an extension of MyLang's numeric `enum`
feature.  This lets it build on the existing struct and generic type model,
while leaving value-carrying enums as a future, general-purpose feature.

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

## `case ... of`

`case ... of` already exists as an expression form.  `Result` adds two typed
patterns to it:

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
- Both variants are required unless `_` is present.
- Every arm must produce the same type.

`Ok(...)` and `Err(...)` are patterns only in this context.  Outside a
`case ... of` arm they retain their constructor meaning.

Nested matches compose normally:

```mylang
case outer of {
    Ok(Ok(value)) -> value;
    Ok(Err(error)) -> -1;
    Err(error) -> -2;
};
```

## Representation and ownership

The source-level type remains a `struct`.  Each generic instantiation is
lowered to a concrete tagged struct with one active payload:

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
invariant that a result is exactly one of success or error.

## Implementation order

1. Implement generic type instantiation and code generation.  Generic
   declarations are parsed today, but generic type use deliberately reports
   "not implemented".
2. Add the standard, opaque `struct Result<T, E>` and concrete tagged-layout
   lowering.
3. Type-check `Ok` / `Err` using the surrounding expected `Result<T, E>`
   type.
4. Extend `case ... of` semantic analysis with `Ok` / `Err` patterns,
   bindings, arm-type checking, and exhaustiveness checking.
5. Add `?` as a separate feature.  Its first version propagates the same `E`;
   error conversion is deferred until a conversion mechanism exists.

The design deliberately does not add value-carrying `enum` declarations,
general pattern matching, methods, or `?` as prerequisites for the first
`Result` implementation.
