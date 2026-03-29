# Parser Layout

This directory is split by parser responsibility.

## Main groups

- `parser_token.c`: token consumption and error reporting
- `parser_lookahead.c`: syntactic lookahead helpers
- `parser_type.c`: type syntax, `struct`, and `typedef`
- `parser_decl.c`: parameters and function declarations
- `parser_stmt.c`: statements
- `parser_toplevel.c`: package/import/export and program parsing
- `parser_expr_primary.c`: literals, identifiers, grouped expressions
- `parser_expr_postfix.c`: calls, indexing, member access
- `parser_expr_unary.c`: unary operators
- `parser_expr_binop.c`: precedence climbing for binary/conditional/assignment expressions
- `parser_ast_*.c`: AST node constructors
- `parser_rewrite*.c`: export rewrite pass
- `parser_lower*.c`: function literal lowering
- `parser_check.c`: parser-side validation
- `parser_print*.c`: AST pretty printing
- `parser_free.c`: AST destruction
- `parser_state_*.c`: parser state tables and lifecycle

## Notes

- Shared parser implementation declarations live in `inc/mylang/frontend/parser_internal.h`.
- Parser-global state declarations live in `inc/mylang/frontend/parser_state_internal.h`.
- If a new feature only affects one syntax family, prefer extending the closest file rather than creating a broad catch-all.
