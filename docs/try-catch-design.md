# Try/Catch Exception Handling Design

## Status

Draft proposal for adding structured exception handling to MyLangCompiler.

The first implementation should intentionally stay small: one `catch` clause, no `finally`, no exception inheritance, and a runtime handler stack rather than zero-cost exceptions.

## Proposed syntax

```mylang
try {
    risky_operation();
} catch (Error err) {
    print(err.message);
}

throw Error("operation failed");
```

Initial restrictions:

- exactly one `catch` clause per `try`
- the caught value is bound to one local variable
- no `finally`
- no multi-catch syntax
- no inheritance-based matching
- uncaught exceptions terminate the program through the runtime

## Compiler pipeline changes

### Lexer

Add keyword token kinds for:

- `TRY`
- `CATCH`
- `THROW`

The keywords should be recognized in `src/frontend/lexer/lexer.c` and exposed through `inc/mylang/frontend/lexer.h`.

### AST

Add two node kinds:

```c
AST_TRY,
AST_THROW,
```

Suggested payloads:

```c
struct {
    ASTNode *try_body;
    ASTNode *catch_type;
    char *catch_name;
    ASTNode *catch_body;
} try_stmt;

struct {
    ASTNode *expr;
} throw_stmt;
```

Add constructors, printing, and cleanup support alongside the existing AST helpers.

### Parser

Extend statement parsing with:

```text
try-statement  := "try" block "catch" "(" type identifier ")" block
throw-statement := "throw" expression ";"
```

`parse_stmt()` should dispatch to dedicated helpers rather than growing the central statement parser.

Recommended helpers:

- `parse_try_stmt`
- `parse_throw_stmt`
- `new_try_stmt`
- `new_throw_stmt`

### Semantic analysis

The semantic pass should validate:

- the catch binding has a valid type and name
- `throw` has an expression
- the thrown expression is compatible with the initial exception representation
- catch variables are scoped only to the catch body
- unreachable statements after an unconditional `throw`

The first version does not need checked exceptions in function signatures.

## Runtime model

Use a linked stack of exception handler frames.

```c
typedef struct MyLangExceptionFrame {
    struct MyLangExceptionFrame *previous;
    void *catch_address;
    void *saved_stack_pointer;
} MyLangExceptionFrame;

typedef struct MyLangException {
    int type_id;
    void *value;
} MyLangException;
```

A runtime context stores:

- the active exception frame
- the currently thrown exception

Entering `try` pushes a frame. Normal exit pops it. `throw` stores the exception, restores the saved stack state, and jumps to the nearest handler. Throwing without an active handler terminates with a diagnostic.

## Code generation sketch

Conceptual output:

```asm
  ; enter try
  push_exception_handler .Lcatch_1

  ; try body
  call risky_operation

  pop_exception_handler
  jmp .Ltry_end_1

.Lcatch_1:
  pop_exception_handler
  ; bind current exception to the catch local
  ; emit catch body

.Ltry_end_1:
```

The code generator should keep the active exception context separate from loop `break` and `continue` labels.

A dedicated backend file such as `src/backend/codegen/codegen_exception.c` is preferable to embedding the implementation in `codegen_stmt.c`.

## Control-flow behavior

- `return` from a try or catch body must remove any active handler frames owned by the current scope.
- `break` and `continue` crossing a try scope must also clean up those frames.
- nested try blocks must select the nearest active handler.
- a new `throw` inside a catch body propagates to the next outer handler.

For the initial implementation, cleanup can be emitted explicitly for each structured control-flow exit. A later intermediate representation could make this more general.

## Ownership and cleanup

The first implementation should not promise destructor-style stack unwinding. When ownership and lifetime analysis become capable of generating cleanup actions, exception propagation must execute those actions before transferring control.

Until then, documentation should state that thrown exceptions do not automatically release owned resources.

## Implementation sequence

1. Add lexer tokens and parser-only AST support.
2. Add AST print/free coverage and parser tests.
3. Add semantic validation and catch-variable scoping.
4. Add runtime exception-frame helpers.
5. Add code generation for `try`, `catch`, and `throw`.
6. Add nested-handler and uncaught-exception integration tests.
7. Document resource-cleanup limitations.

## Test cases

Required success cases:

- a throw is caught by the nearest handler
- normal completion skips the catch body
- nested try blocks select the inner handler
- rethrowing from catch reaches an outer handler
- the catch binding can be referenced in the catch body

Required failure or runtime-error cases:

- malformed catch syntax
- missing throw expression
- incompatible thrown value
- uncaught exception
- catch variable used outside its scope

## Open questions

- Should the first exception value be an integer/status object or a built-in `Error` struct?
- Should catch type matching be implemented immediately or should version one catch every thrown value?
- Is the runtime context global, passed through generated functions, or reserved in a dedicated register?
- How should exception state interact with future threading support?
- Should `throw;` rethrow syntax be supported later?

## Acceptance criteria for the first implementation PR

- `try { ... } catch (T e) { ... }` parses and appears in the AST
- `throw expression;` parses and appears in the AST
- normal execution bypasses catch
- thrown execution reaches the nearest catch
- uncaught exceptions terminate with a useful message
- nested try/catch behavior is covered by integration tests
- existing compiler tests continue to pass
