# MyLang Grammar Specification

This document defines the formal grammar for MyLang as implemented in `MyLangCompiler`.

## 1. Top-level Structure
A program consists of a sequence of top-level declarations and definitions.

- `program` -> `toplevel*`
- `toplevel` -> 
    - `attribute* ( struct_decl | fundef )` (see "Attributes and applications")
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

### Attributes and applications

- `attribute` -> `@ IDENTIFIER ( ( attr_arg ( , attr_arg )* ) )?`
- `attr_arg` -> `IDENTIFIER` | `literal` | `IDENTIFIER = literal`
- `toplevel` -> `attribute* export? ( struct_decl | fundef )`

Attributes precede a top-level declaration. The parser only records them;
`parser_lower_app.c` gives them meaning and rejects any it does not know,
so a misspelled attribute is an error rather than silently ignored.

`@app` marks a struct as an application for the OS framework. Its fields
may carry literal initializers, its `view` method builds the window, and
its other attributed methods hook the framework:

```mylang
@app(single, name = "Editor")
struct Editor { i32 area; i32 dirty = 0; };

i32  (Editor *e) view()             { return <Window ...>...</Window>; }
@open     void (Editor *e) open(char *path)  { ... }   // ui.open(path) lands here
@on_close void (Editor *e) closing()         { ... }   // the window was closed
@timer(100) void (Editor *e) poll()          { ... }   // every 100 ms while mounted
@key("Ctrl+S") void (Editor *e) save()       { ... }   // window-level shortcut
@task     void (Editor *e) run()             { ... }   // a scheduler task per instance
```

| attribute | on | arguments | method shape (after the receiver) |
| --- | --- | --- | --- |
| `@app` | struct | `single`; `name = "..."` | -- |
| `@open` | method | -- | `(char *path)` |
| `@on_close` | method | -- | `()` or `(i32 id)` |
| `@timer` | method | period in ms | `()` or `(i32 id)` |
| `@key` | method | `"Ctrl+S"`, `"Shift+Enter"`, `"F5"` (Ctrl, Shift, Alt) | `()`, `(i32 id)` or `(i32 id, i32 arg)` |
| `@task` | method | -- | `()` |

Every such method, and every method used as a DOM handler, takes a
**pointer receiver** (`Editor *e`): the dispatcher identifies an instance by
the i32 it was mounted with, and a `ref mut` receiver cannot be built from
it. The compiler generates, per `@app` struct `T`:

- `void __app_T_init(i32 self)` -- writes the field initializers;
- `i32 __app_T_view(i32 self)` -- calls `view`;
- `void T__m__tramp(i32 owner, i32 id, i32 arg)` per handler method `m`,
  which casts `owner` back to `T*` and calls `m` with `()`, `(id)` or
  `(id, arg)` as its arity says (`@open` passes `(char*)arg`);
- `export i32* __app_T_desc()` -- a descriptor table of i32 words the
  framework reads: `[0]` name, `[1]` flags (1 = single), `[2]` size,
  `[3]` init, `[4]` view, `[5]` open, `[6]` on_close, `[7]` task,
  `[8]` timer count, `[9]` key count, then `(interval, handler)` pairs and
  `(mods, code, handler)` triples.

Names starting with `__app_` and ending in `__tramp` are reserved for this
generated code. The generated declarations are parsed from MyLang source and
go through method resolution, semantic checking and codegen like anything
the author wrote.

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
