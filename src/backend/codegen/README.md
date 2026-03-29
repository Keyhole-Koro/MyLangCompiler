# Codegen Layout

This directory is split by emitted code shape and shared backend responsibilities.

## Main groups

- `codegen_driver.c`: top-level `codegen()` entry
- `codegen_context.c`: labels, imports, and backend context helpers
- `codegen_toplevel.c`: top-level collection and emission order
- `codegen_strings.c`: string literal interning and data labels
- `codegen_data.c`: global data emission
- `codegen_stmt.c`: statement dispatch
- `codegen_if.c`: `if` emission
- `codegen_loops.c`: loop emission
- `codegen_expr.c`: expression dispatch and shared expression handling
- `codegen_call.c`: call emission
- `codegen_assign.c`: assignment emission
- `codegen_unary.c`: unary special cases
- `codegen_lvalue.c`: address/load/store helpers
- `codegen_binop*.c`: binary operators split by logic, pointer, and math handling
- `codegen_slots.c`: stack-slot math
- `codegen_locals.c`: local collection and lookup
- `codegen_func.c`: function-level emission
- `codegen_type_*.c`: type lookup, inference, and collection

## Notes

- Shared backend declarations live in `inc/mylang/backend/codegen_internal.h`.
- When adding an operation, prefer putting it next to the emitted code pattern it matches.
- Keep statement dispatch thin and move specialized logic into dedicated files.
