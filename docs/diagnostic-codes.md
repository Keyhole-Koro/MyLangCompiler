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
| `W00xx` | Warnings | unreachable statement, ... |

Bands `E05xx` and above are unused and reserved for future categories.

## Error codes

| Code | Category | Meaning | Example message |
| --- | --- | --- | --- |
| `E0001` | Name resolution | Undefined identifier | `undefined identifier 'foo'` |
| `E0002` | Name resolution | Undefined function | `undefined function 'foo'` |
| `E0101` | Function call | Argument count mismatch | `function 'add' expects 2 arguments but got 1` |
| `E0102` | Function call | Argument type mismatch | `function argument type mismatch: parameter 1 of 'add' expected i32, got char*` |
| `E0201` | Return | Return type mismatch | `function 'f' must return a value` / return type mismatch (expected / actual) |
| `E0301` | Expression type | Assignment / initializer type mismatch | assignment or initializer expected / actual mismatch |
| `E0302` | Expression type | Invalid binary operands | `invalid operands to '+': i32 and char*` |
| `E0303` | Expression type | Invalid condition type | `condition must be integer-like, pointer, or reference, got ...` |

## Warning codes

| Code | Category | Meaning | Example message |
| --- | --- | --- | --- |
| `W0001` | Warning | Unreachable statement | `unreachable statement` |

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
