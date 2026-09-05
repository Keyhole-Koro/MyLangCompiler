# MyLangCompiler Architecture

This compiler is organized so each stage has a small and obvious responsibility.
The goal is to keep feature work local and make parser/codegen changes easier to review.

## Overview

The main flow is:

1. `lexer` turns source text into tokens.
2. `parser` builds the AST and performs parser-local rewrites.
3. `semantic` walks the AST for compiler-level validation and future ownership checks.
4. `codegen` walks the AST and emits assembly text.
5. `driver` wires file IO, parsing, semantic analysis, code generation, and CLI behavior together.

## Directory Layout

```text
toolchain/MyLangCompiler/
├── inc/mylang/
│   ├── ast/                  # AST public types
│   ├── backend/              # codegen public/internal interfaces
│   ├── frontend/             # lexer/parser public/internal interfaces
│   ├── semantic/             # semantic analysis public/internal interfaces
│   └── support/              # reusable helpers
├── src/
│   ├── ast/                  # AST node utilities
│   ├── backend/codegen/      # assembly generation
│   ├── driver/               # CLI entrypoint
│   ├── frontend/lexer/       # tokenization
│   ├── frontend/parser/      # parsing + parser-local lowering/rewrites
│   ├── semantic/             # semantic analysis and validation
│   └── support/              # string builder and misc helpers
└── docs/                     # compiler-specific notes
```

## Frontend

### Lexer

`src/frontend/lexer/lexer.c` owns tokenization.
It is intentionally kept separate from parser state.

### Parser

The parser is split by responsibility instead of keeping one giant file.
The main groups are:

- `parser_token.c`: parser errors and token consumption helpers
- `parser_lookahead.c`: type checks and syntactic lookahead
- `parser_type.c`: type syntax, `struct`, and `typedef`
- `parser_decl.c`: function parameters and function declarations/definitions
- `parser_generic.c`: generic parameter and argument parsing
- `parser_instantiate.c`: module-local monomorphization before semantic checking
- `parser_stmt.c`: statement parsing
- `parser_toplevel.c`: package/import/export and whole-program parsing
- `parser_expr_*.c`: expression parsing split by precedence/shape
- `parser_ast_*.c`: AST node construction helpers
- `parser_rewrite*.c`: export name rewrite passes
- `parser_lower*.c`: function literal lowering
- `parser_check.c`: parser-side validation after lowering
- `parser_print*.c`: AST printing helpers
- `parser_free.c`: AST cleanup
- `parser_state_*.c`: parser-global tables and reset/package management

### Parser State

Parser state is still global, but it is now grouped more clearly:

- `parser_state_tables.c`: function/type/struct tables
- `parser_state_package.c`: package/export/import bookkeeping
- `parser_state_reset.c`: parser reset and filename lifecycle

The state declarations live in `inc/mylang/frontend/parser_state_internal.h`.
That keeps general parser declarations in `parser_internal.h` smaller.

Generic templates are kept separate from the executable program AST. The
[instantiation pass](generics.md) clones only used templates into concrete
declarations; `src/ast/ast_copy.c` owns deep copying and child-slot traversal.

## Semantic

The semantic stage sits between parsing and code generation.
It is the intended home for type-directed validation, ownership checks, borrow rules,
and lifetime analysis so those rules stay out of backend emission.

## Backend

The backend emits assembly directly from the AST.
It is grouped around the shape of the code being emitted.

- `codegen_driver.c`: top-level `codegen()` entry
- `codegen_context.c`: codegen context bookkeeping and label/import helpers
- `codegen_toplevel.c`: top-level AST collection and emission order
- `codegen_strings.c`: string literal interning/data emission
- `codegen_data.c`: global data initialization
- `codegen_stmt.c`: statement dispatch
- `codegen_if.c`: `if` emission
- `codegen_loops.c`: `for`/`while`/`do while` emission
- `codegen_expr.c`: expression entry and shared expression handling
- `codegen_call.c`: function calls
- `codegen_assign.c`: assignments
- `codegen_unary.c`: unary special cases like inc/dec
- `codegen_lvalue.c`: address/load/store helpers
- `codegen_binop*.c`: binary operator emission split by logic/pointer/math behavior
- `codegen_slots.c`: frame slot calculations
- `codegen_locals.c`: local collection and stack lookups
- `codegen_func.c`: function prologue/body/epilogue emission
- `codegen_type_*.c`: type inference, type collection, typedef/struct lookup

## Internal Headers

There are two important internal headers:

- `inc/mylang/frontend/parser_internal.h`
- `inc/mylang/backend/codegen_internal.h`

These are for implementation sharing inside a subsystem.
Public entrypoints stay in the smaller public headers.

## Design Rules

When adding new compiler features, try to keep these rules:

1. Put syntax changes near the syntax they affect.
2. Keep AST construction separate from parser control flow where practical.
3. Prefer small helpers over growing one central file.
4. Add internal declarations only to the subsystem that needs them.
5. Keep public headers smaller than internal headers.
6. Run the compiler test suite after every structural refactor.

## Reading Order

If you are onboarding to the compiler, this is a good order:

1. `src/driver/main.c`
2. `inc/mylang/frontend/parser.h`
3. `src/frontend/parser/parser_toplevel.c`
4. `src/frontend/parser/parser_stmt.c`
5. `src/frontend/parser/parser_expr_*.c`
6. `inc/mylang/semantic/semantic.h`
7. `src/semantic/semantic_driver.c`
8. `inc/mylang/backend/codegen.h`
9. `src/backend/codegen/codegen_driver.c`
10. `src/backend/codegen/codegen_stmt.c`
11. `src/backend/codegen/codegen_expr.c`

## Validation

Common validation commands:

```bash
make -C toolchain/MyLangCompiler clean all
python3 qa/mlc-test.py
```
