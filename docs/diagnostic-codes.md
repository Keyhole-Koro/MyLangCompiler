# MyLang Diagnostic Codes

This is the single source of truth for MyLangCompiler diagnostic codes. When you
add a new diagnostic, pick a code that fits its category band below, define it in
`inc/mylang/semantic/diagnostic_codes.h`, and add a row here in the same change.

Existing code values are stable and must not be reassigned.

## Numbering rules

A code is `<prefix><4 digits>`.

- **Prefix** selects severity: `E` = error, `W` = warning.
- **Leading two digits** select a category. The last two digits are the
  sequence within that category.

### Category bands

| Band | Category | Notes |
| --- | --- | --- |
| `E00xx` | Name resolution | undefined identifier / function |
| `E01xx` | Function call | argument count / type |
| `E02xx` | Return | return type |
| `E03xx` | Expression type | assignment / binary / condition |
| `E04xx` | Package / import | reserved for package symbol resolution (ISSUE-019) |
| `E05xx` | Generics | type parameters / type arguments |
| `E06xx` | Ownership and borrows | writes, moves, and borrows (`docs/design/mylang-values.md`) |
| `E07xx` | Unsafe code | raw pointers outside `.unsafe.mln`, `@safe` (`docs/design/mylang-values.md`) |
| `W00xx` | Warnings | unreachable statement, ... |

Bands `E08xx` and above are unused and reserved for future categories.

## Error codes

| Code | Category | Meaning | Example message |
| --- | --- | --- | --- |
| `E0001` | Name resolution | Undefined identifier | `undefined identifier 'foo'` |
| `E0002` | Name resolution | Undefined function | `undefined function 'foo'` |
| `E0101` | Function call | Argument count mismatch | `function 'add' expects 2 arguments but got 1` |
| `E0102` | Function call | Argument type mismatch | `function argument type mismatch: parameter 1 of 'add' expected i32, got char*` |
| `E0103` | Function call | Mock fake signature mismatch | `mock fake 'fake_read' parameter 2 does not match target 'device_read'` |
| `E0104` | Function call | Stored mock return used for an aggregate target | `mock .ret(...) cannot return aggregate target 'make_pair'; use .call(fake)` |
| `E0105` | Function call | TestKit mock ABI limit exceeded | `mock .when(...) supports at most six arguments` |
| `E0201` | Return | Return type mismatch | `function 'f' must return a value` / return type mismatch (expected / actual) |
| `E0202` | Return | A non-void function can reach its end | `'f' can reach its end without returning a value` |
| `E0203` | Return | A `@noreturn` function can return, or is not `void` | `@noreturn function 'f' can reach its end` |
| `E0301` | Expression type | Assignment / initializer type mismatch | assignment or initializer expected / actual mismatch |
| `E0302` | Expression type | Invalid binary operands | `invalid operands to '+': i32 and char*` |
| `E0303` | Expression type | Invalid condition type | `condition must be integer-like, pointer, or reference, got ...` |
| `E0304` | Expression type | Constant index outside a fixed-size array | `index 4 is out of range for an array of 4 elements` |
| `E0305` | Expression type | `*` on a value that is not a pointer or array, or on a borrow, whose name already reads the value | `cannot dereference a value of type 'i32'` |
| `E0501` | Generics | Type-argument count mismatch | `generic type 'Pair' expects 1 type argument but got 2` |
| `E0502` | Generics | Generic name used without required type arguments | `generic type 'Pair' requires type arguments` |
| `E0601` | Ownership and borrows | Change to, move of, or a temporary for a parameter that only reads an owned value (rule P1) | `cannot change 'p', which this function only reads` |
| `E0602` | Ownership and borrows | Change to a value while it is borrowed (rules B4, B5) | `cannot modify 'p' while it is borrowed` |
| `E0603` | Ownership and borrows | Use of a value while a local holds `&` of it (rule B4) | `cannot use 'q' while it is borrowed` |
| `E0604` | Ownership and borrows | Value from outside a loop moved inside it (rule V4) | `'q' is moved inside a loop, so the next iteration would use it after the move` |
| `E0605` | Ownership and borrows | Write to, or `&` of, a `const` value (rule W3) | `cannot modify const value 'c'` |
| `E0701` | Error | A raw-pointer operation, a raw pointer type, or a call of an `.unsafe.mln` function without `@safe`, in a checked source | `calling 'mem_write_word', which is not @safe, outside an .unsafe.mln file` |
| `E0702` | Error | A `@safe` function whose signature has a raw pointer | `a @safe function cannot take or return a raw pointer` |

## Warning codes

| Code | Category | Meaning | Example message |
| --- | --- | --- | --- |
| `W0001` | Warning | Statement after one that cannot complete | `unreachable statement` |
| `W0002` | Warning | `drop()` method without `impl Drop` | `T has drop() without `impl Drop`; ...` |

Warnings can be promoted to errors with warnings-as-errors mode.

## Reserved (not yet implemented)

These codes are reserved by proposed tickets so new work does not collide with
them. They are not emitted by the compiler yet.

| Code | Category | Meaning | Ticket |
| --- | --- | --- | --- |
| `E0401` | Package / import | Package does not export symbol | ISSUE-019 (package symbol resolution) |
| `E0402` | Package / import | Ambiguous imported symbol | ISSUE-019 |
| `E0403` | Package / import | Cyclic import detected | ISSUE-019 |

## Location and base convention

Every diagnostic carries a source range (`line` / `col` / `end_line` /
`end_col`). Human-readable CLI output and any index in a message body (for
example `parameter 1`) are 1-based. JSON / LSP output converts ranges to 0-based
in the integration layer (ISSUE-021); the semantic stage itself stays 1-based.
