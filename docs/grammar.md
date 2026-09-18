# MyLang Grammar Specification

This document defines the formal grammar for MyLang as implemented in `MyLangCompiler`.

## 1. Top-level Structure
A program consists of a sequence of top-level declarations and definitions.

- `program` -> `toplevel*`
- `toplevel` -> 
    - `attribute* ( struct_decl | fundef )` and `annotation_decl` (see "Attributes and annotations")
    - `package_decl`
    - `import_stmt`
    - `export_decl`
    - `extern_decl`
    - `typedef_stmt`
    - `struct_decl`
    - `enum_decl`
    - `fundef`
    - `var_decl`

## 2. Modules and Imports
MyLang uses a package-based module system.

- `package_decl` -> `package IDENTIFIER ;`
- `import_stmt` -> 
    - `import IDENTIFIER ;` (Import entire package)
    - `import IDENTIFIER from STRING_LITERAL ;` (Import specific symbol from a file)
    - `import { IDENTIFIER ( , IDENTIFIER )* } from STRING_LITERAL ;` (Import multiple symbols)
- `export_decl` -> `export ( fundef | var_decl | typedef_stmt | struct_decl | enum_decl )`
- `extern_decl` -> `extern ( fundef | var_decl )`

## 3. Declarations and Definitions

### Functions
- `fundef` -> `type receiver? IDENTIFIER type_params? ( param_list ) ( block | ; )`
- `receiver` -> `( param )`
- `type_params` -> `< IDENTIFIER ( , IDENTIFIER )* >`
- `param_list` -> `( param ( , param )* ( , rest_param )? )?`
- `param` -> `mut? type IDENTIFIER ( [ NUMBER? ] )*`
- `rest_param` -> `rest IDENTIFIER`

A `fundef` carrying a `receiver` is a **method** on the receiver's base type:

```mylang
void (ref User u)      display()          { ... }
void (ref mut User u)  rename(char* n)    { ... }
i32  (User* u)         raw_id()           { ... }
User (User u)          into_admin()       { ... }   // value receiver: a move
```

The receiver is one `param`, never a list, so its spelling is exactly a
parameter's: `mut`, `ref`, `ref mut`, pointer, and array suffixes all read the
same as they do in `param_list`. Lowering prepends it to the parameter list, so
a method is an ordinary function from the AST onward and the ownership rules
apply to the receiver unchanged -- notably, **a value receiver moves**, which is
why `ref` / `ref mut` are the usual forms.

Methods are called with `.` on any receiver expression, and `->` also works on a
pointer. The address-of / dereference needed to match the declared receiver is
inserted during resolution, so `u.display()` reads the same whether `display`
takes `User`, `ref User`, or `User*`.

A generic receiver binds the method's type parameters directly from its own
type arguments. The formal names need not match those used by the struct:

```mylang
struct Box<T> { T value; };

U (ref Box<U> box) get() { return box.value; }
```

When `Box<i32>` is used, the compiler specializes both the struct and this
method, then resolves `box.get()` to the concrete method. Receiver-bound type
arguments must currently be distinct identifiers; method-level type parameters
cannot be combined with a generic receiver yet.

### `test` is reserved

`test` is a keyword, which is what keeps a top-level test declaration
(`test("name", { ... }, () => { ... });`, see MLT-002) separable from a method
whose return type is itself a user type (`User (ref Config c) build()`). Both
would otherwise start `IDENTIFIER (`, and the LR(1) grammar the LSP builds from
this specification has only one token of lookahead.

It still reads as a plain name wherever a namespace is expected -- `package
test;`, `import test from "..."`, `test.pass()` -- so no existing source needed
to change. What it can no longer be is a variable, function, field, or type
name.

### Default parameters

- `param` -> `mut? type IDENTIFIER ( [ NUMBER? ] )* ( = literal )?`
- `literal` -> `-? NUMBER` | `STRING_LITERAL` | `CHAR_LITERAL` | `true` | `false`

```mylang
i32 Label(char *text, i32 x = 0, i32 y = 0, i32 color = 0, i32 bold = 0) { ... }

Label("hi");            // Label("hi", 0, 0, 0, 0)
Label("hi", 4, 8);      // Label("hi", 4, 8, 0, 0)
<Label text="hi" bold={1} />   // any defaulted property may be left out
```

A positional call may leave out trailing parameters that have defaults; a
DOM element may leave out any of them, since properties go by name. Only a
literal is allowed as a default because the compiler clones it into each
call site, which may be in another package where a name would not resolve.
The defaults of an imported function are read from its declaration, so
they work across packages (`lib.scale(5)`). Rest parameters and generic
calls take no defaults.

### Attributes and annotations

- `attribute` -> `@ IDENTIFIER ( ( attr_arg ( , attr_arg )* ) )?`
- `attr_arg` -> `IDENTIFIER` | `literal` | `IDENTIFIER = literal`
- `toplevel` -> `attribute* export? ( struct_decl | fundef )`
- `annotation_decl` -> `export? annotation IDENTIFIER ( param_list? )? on ( struct | method | function ) IDENTIFIER? ( of IDENTIFIER )? ( requires method IDENTIFIER ( , method IDENTIFIER )* )? ( ; | { template } )`

The compiler carries no attribute vocabulary. Every `@name` must resolve
to an `annotation` declaration -- in the same file, or exported by a module
named in a symbol-list import -- and is checked against it: what it may be
put on (`on struct` / `on method` / `on function`), its arguments against
the declared parameters (keyed, positional, or a bare bool parameter's
name as a flag: `@app(single)`), `of X` (a method annotation only on
methods of a type carrying `@X`) and `requires method m` (the annotated
type must have `m`, taking a pointer receiver). A misspelled or
unimported annotation is an error, never silently ignored.

```mylang
export annotation app(bool single = false, char *name = "")
    on struct T
    requires method view
{
    i32 __app_@{T}_view(i32 self) { @T *p = (@T*)self; return p->view(); }
    @each(m in @methods(T, timer)) { ... @m.args[0] ... @tramp(m) ... }
}
export annotation timer(i32 ms) on method of app;

import { app, timer } from "annotations.mln";
@app struct Counter { ... };
@timer(100) void (Counter *c) poll() { ... }
```

A declaration ending in `;` is a marker: it is checked and can be read by
other templates through `@methods(T, name)`. A declaration with a body is
a **template**: MyLang top-level source, copied through verbatim except for
`@` directives, which read the annotated declaration. The expansion is
parsed by the ordinary top-level parser, so generated code is
method-resolved, checked and compiled like anything the author wrote.

| directive | expands to |
| --- | --- |
| `@T`, `@{T}` | the annotated type's name (`T` as named by `on struct T`); braces splice inside an identifier, `__app_@{T}_init` |
| `@name(T)` | the same as a string literal |
| `@arg(p)` | annotation argument `p`, or its declared default, as a literal |
| `@each(f in @fields(T) [where init]) { ... }` | the body once per field; `@f`, `@f.type`, `@f.init` |
| `@each(m in @methods(T, annot)) { ... }` | once per method of `T` carrying `@annot`; `@m` (short name), `@m.mangled`, `@m.args[i]` (that annotation's i-th argument or its default) |
| `@count(@fields(T))`, `@count(@methods(T, annot))` | the number of items |
| `@i` | 0-based index inside the innermost `@each` |
| `@tramp(m)` | the name of `void (i32 owner, i32 id, i32 arg)`, generated on first use, that casts `owner` to `T*` and calls `m` with `()`, `(id)` or `(id, arg)` by its arity |
| `@@` | a literal `@` |

Templates read declarations; they do not compute (no arithmetic, no
conditionals -- emit runtime code for that, `i32 w = 10; ... w = w + 2;`).
`//` comments inside a template are copied as they are. `@tramp` is the one
piece of meaning the compiler keeps: the handler calling convention is
its business, so a method reached through it must take a pointer receiver
(`T *self`). Names ending in `__tramp` are reserved for those trampolines.

What `@app` and its companions mean -- the descriptor table, timers,
shortcuts, window close -- is declared by the application framework in
`system/MyAppFramework/src/annotations.mln`, not here.

### Variables
- `var_decl` -> `mut? type IDENTIFIER ( [ NUMBER? ] )* ( = ( expr | init_list ) )? ;`
- `init_list` -> `{ expr ( , expr )* ,? }`

### Types and Enumerations
- `struct_decl` -> `struct IDENTIFIER? { var_decl* } IDENTIFIER? ;` | `struct IDENTIFIER type_params { var_decl* } ;`
- `enum_decl` -> `enum IDENTIFIER { IDENTIFIER ( = NUMBER )? ( , IDENTIFIER ( = NUMBER )? )* ,? } ;`
- `typedef_stmt` -> `typedef type IDENTIFIER ;` | `typedef struct ... IDENTIFIER ;`

## 4. Type System
- `type` -> `const* ( ref mut? )? base_type ( * )*`
- `base_type` -> `primitive_type` | `IDENTIFIER type_args?`
- `type_args` -> `< type ( , type )* >`
- `primitive_type` -> `u8` | `u16` | `i32` | `u32` | `bool` | `char` | `float` | `double` | `void` | `long` | `short`

Generic uses are concretely instantiated before semantic analysis. See
[Generic instantiation](generics.md) for supported behavior and boundaries.

## 5. Statements
- `stmt` ->
    - `block` -> `{ stmt* }`
    - `if ( expr ) stmt ( else stmt )?`
    - `while ( expr ) stmt`
    - `do stmt while ( expr ) ;`
    - `for ( (var_decl | expr)? ; expr? ; expr? ) stmt`
    - `return expr? ;`
    - `break ;`
    - `continue ;`
    - `yield expr ;`
    - `unchecked block` (Disables safety checks)
    - `var_decl`
    - `expr ;`

## 6. Expressions
Expressions are listed in order of decreasing precedence.

| Precedence | Operator | Description |
|---|---|---|
| 1 | `lhs = rhs` | Assignment (Right-associative) |
| 2 | `cond ? then : else` | Ternary conditional |
| 3 | `||` | Logical OR |
| 4 | `&&` | Logical AND |
| 5 | `\|` | Bitwise OR |
| 6 | `^` | Bitwise XOR |
| 7 | `&` | Bitwise AND |
| 8 | `==`, `!=` | Equality |
| 9 | `<`, `>`, `<=`, `>=` | Relational |
| 10 | `<<`, `>>` | Bitwise Shift |
| 11 | `+`, `-` | Addition / Subtraction |
| 12 | `*`, `/`, `%` | Multiplication / Division / Modulo |
| 13 | `!`, `~`, `-`, `*`, `&`, `++`, `--`, `(type)`, `sizeof` | Unary operators |
| 14 | `++`, `--`, `.`, `->`, `(args)`, `type_args (args)` | Postfix operators / Function call |
| 15 | `( expr )`, literals, `IDENTIFIER`, `case`, lambdas | Primary expressions |

### Special Expressions
- **Case Expression**: `case expr of { ( (key | _) -> expr ; )* }`
  - A branch may use `-> _` as a no-op only when the whole `case` is used as
    a statement.  It cannot provide a value to an assignment, initializer, or
    `return`.
  - A statement-expression branch may calculate its value with `yield`, e.g.
    `Ok(v) -> ({ i32 adjusted = v + 1; yield adjusted; });`.
- **Function Literal (Lambda)**: `( param_list ) block` or `( param_list ) => block`
- **Statement Expression**: `( block )`
