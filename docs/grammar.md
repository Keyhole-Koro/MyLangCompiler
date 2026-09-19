# MyLang Grammar Specification

This document defines the formal grammar for MyLang as implemented in `MyLangCompiler`.

## 1. Top-level Structure
A program consists of a sequence of top-level declarations and definitions.

- `program` -> `toplevel*`
- `toplevel` -> 
    - `attribute* fundef` (see "Attributes and annotations")
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
- `toplevel` -> `attribute* export? fundef`

An annotation is metadata on a function or method. It is declared as a
function prototype -- never called -- whose first three parameters are
fixed (the annotated function, the name of its receiver type, that type's
size) and whose remaining parameters are the annotation's own arguments:

```mylang
// annotations.mln (a Java @interface, in effect)
export void app(i32 fn, char *type, i32 size, bool single = false, char *name = "");
export void timer(i32 fn, char *type, i32 size, i32 ms);

// terminal.dom.mln
import { app, timer } from "annotations.mln";

@app(name = "Terminal")
i32 (Terminal *t) view() { ... }

@timer(100)
void (Terminal *t) poll() { ... }
```

For every `@a(args)` the compiler records one row in the module's
generated table, `export i32* __annotations()`, laid out as
`[count, row0..., row1...]` with eight words per row:

| word | content |
| --- | --- |
| 0 | annotation name (`char*`) |
| 1 | the annotated function |
| 2 | receiver type name (`char*`; `""` for a plain function) |
| 3 | `sizeof` that type (0 for a plain function) |
| 4 | number of annotation arguments |
| 5..7 | the arguments: a number, a bool as 0/1, a string as `char*` |

Whoever reads the table decides what a row means and when (for MyOS, the
application framework at boot). The compiler checks that `a` resolves (a
function in this file, or one exported by a module named in a symbol-list
import), that its first parameters are `(i32, char*, i32)` and that it
takes at most three more, and matches the written arguments to those:
keyed by name, positional, or a bare bool parameter's name as a flag
(`@app(single)`); a parameter left out takes its `= literal` default; a
literal of the wrong kind, an unknown name or a surplus argument is an
error. A module with annotations must declare a `package`, which names
its table (`terminal___annotations`). Annotations cannot be put on a
struct or a generic declaration.

A module that declares

```mylang
extern i32* __annotations_table(i32 m);
```

and reaches annotated modules through its imports receives that
function's definition: the table of the m-th such module, 0 past the
end. The program's root (MyOS's `boot/main.mln`, which imports the apps)
declares it once, so every module's rows are collected without a
manifest; a reader that reaches no annotated module -- the framework's
`meta.mln` -- keeps its prototype and links against that definition.

An annotated method must take its receiver by pointer or reference
(`T *self`, `ref mut T self`): the recorded function is called later with
an instance's address as its first argument, and because the calling
convention ignores trailing arguments, the DOM's uniform handler shape
`(owner, id, arg)` reaches `(T *self, i32 id)` or `(T *self)` directly --
no wrapper is generated. A value receiver is a move and is rejected.

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
