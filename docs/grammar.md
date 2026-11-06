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
    - `trait_decl`, `impl_decl` (see [Traits](traits.md))

## 2. Modules and Imports
MyLang uses a package-based module system.

- `package_decl` -> `package IDENTIFIER ;`
- `import_stmt` -> 
    - `import IDENTIFIER ;` (Import entire package)
    - `import IDENTIFIER from STRING_LITERAL ;` (Import specific symbol from a file)
    - `import { IDENTIFIER ( , IDENTIFIER )* } from STRING_LITERAL ;` (Import multiple symbols)

`import X from "f.mln";` imports the package when `f.mln` declares
`package X;`, and otherwise the symbol `X` that `f.mln` declares. A package
cannot be imported under another name: a name that is neither the package nor
a declared symbol is an error that suggests the package's own name. Every name
in `import { ... }` must likewise be declared by the imported file.
- `export_decl` -> `export ( fundef | var_decl | typedef_stmt | struct_decl | enum_decl )`
- `extern_decl` -> `extern ( fundef | var_decl )`

Import paths may use a project alias configured in `mylang.toml`:

```toml
[alias]
"@std" = "toolchain/MyStdLib"
```

```mln
import { Option } from "@std/core/option.mln";
```

`./` and `../` paths remain relative to the importing file. Alias paths are
resolved from the project configuration file and are matched by complete path
segments. The compiler also accepts repeatable `--alias @name=path` options;
command-line aliases are applied after the project file, so a duplicate is
allowed only when it points to the same canonical directory.

`mlc --depfile <path>` writes the root source's direct `mln` and `masm`
dependencies after resolving relative paths and aliases. The build runner uses
this manifest instead of scanning MyLang source text independently.

## 3. Declarations and Definitions

### Functions
- `fundef` -> `type receiver? IDENTIFIER type_params? ( param_list ) ( block | ; )`
- `receiver` -> `( param )`
- `type_params` -> `< IDENTIFIER ( , IDENTIFIER )* >`
- `param_list` -> `( param ( , param )* ( , rest_param )? )?`
- `param` -> `move? type IDENTIFIER ( [ NUMBER? ] )*`
- `rest_param` -> `rest IDENTIFIER`

A `fundef` carrying a `receiver` is a **method** on the receiver's base type:

```mylang
void (User u)             display()          { ... }   // reads
void (borrow User u)      rename(char* n)    { ... }   // changes
i32  (User* u)            raw_id()           { ... }
User (move User u)        into_admin()       { ... }   // takes
```

The receiver is one `param`, never a list, so its spelling is exactly a
parameter's: `move`, `borrow`, pointer, and array suffixes all read the same as
they do in `param_list`. Lowering prepends it to the parameter list, so a method
is an ordinary function from the AST onward and the ownership rules apply to the
receiver unchanged: a plain receiver reads, `borrow` changes, and `move` takes.

Methods are called with `.` on any receiver expression, and `->` also works on a
pointer. The address-of / dereference needed to match the declared receiver is
inserted during resolution, so `u.display()` reads the same whether `display`
takes `User`, `borrow User`, or `User*`. The receiver may be a local, a parameter,
a global, a struct field (`it.rows.len()`, `t->hits.add(1)`), a call's result,
a cast, or `*p` / `&v` of one of those. This is the one place the `&` of a
`borrow` is not written: an argument to a `borrow` parameter always is, even when
it already is a borrow.

A generic receiver binds the method's type parameters directly from its own
type arguments. The formal names need not match those used by the struct:

```mylang
struct Box<T> { T value; };

U (borrow Box<U> box) get() { return box.value; }
```

When `Box<i32>` is used, the compiler specializes both the struct and this
method, then resolves `box.get()` to the concrete method. Receiver-bound type
arguments must be distinct identifiers. A list after the method name attaches
trait bounds to that same receiver-bound list; it must repeat every parameter
in the same order:

```mylang
bool (HashMap<K, V> *map) put<K: Hash + Eq, V>(K key, V value) { ... }
```

This is not a second, method-local set of type parameters. The bounds are
checked whenever `HashMap<K, V>` is specialized.

#### The built-in `str` type

`str` is a compiler-known, copyable two-word value type:

```mylang
str title = "hello";       // { char* data; i32 length; }
i32 n = title.len();
if (title == "hello") { ... } // content equality
```

String literals are length-aware views over interned, NUL-terminated bytes, so
embedded NULs are preserved. The standard library's `text/str.mln` module provides
`len`, `is_empty`, `compare`, `starts_with`, `ends_with`, `find`, `slice`,
`byte_at`, and `as_c_str`, plus the `char*` bridge `as_str()`.
Literals may still be passed to legacy `char*` or `char[]` parameters; a
non-literal `str` must use `as_c_str()` explicitly.

#### Methods across packages

An `export`ed method travels with its receiver type: importing the type is
enough, there is no per-method import.

```mylang
// annotations.mln
export struct Annotations { ... };
export bool (Annotations *it) next() { ... }

// app.mln
import annotations from "annotations.mln";
import { Annotations } from "annotations.mln";

Annotations it = annotations.named("app");
while (it.next()) { ... }                       // -> Annotations__next(&it)
```

`import { T }` registers a body-less prototype of every exported method of
`T` (parser_import_generics.c, `import_type_methods`), which is all method
resolution needs; the code stays in the defining module's object and links
by the `T__method` label, which is never package-mangled. Along with `T`
come the types its fields need -- other structs of the same module and the
generic instantiations (`__mlg_s_...`) it already lowered -- so the layouts
agree on both sides; an importer that instantiates the same generic reuses
the copy. A method that is not `export`ed is invisible to importers. The
receiver of a call whose result is a chained receiver (`pkg.make().next()`)
is typed from the imported declaration too.

### `test` is reserved

`test` is a keyword, which is what keeps a top-level test declaration
(`test("name", { ... }, () => { ... });`, see MLT-002) separable from a method
whose return type is itself a user type (`User (borrow Config c) build()`). Both
would otherwise start `IDENTIFIER (`, and the LR(1) grammar the LSP builds from
this specification has only one token of lookahead.

It still reads as a plain name wherever a namespace is expected -- `package
test;`, `import test from "..."`, `test.pass()` -- so no existing source needed
to change. What it can no longer be is a variable, function, field, or type
name.

### Default parameters

- `param` -> `move? type IDENTIFIER ( [ NUMBER? ] )* ( = literal )?`
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
import { CodeAddress } from "@std/core/address.mln";

export void app(CodeAddress fn, char *type, i32 size, bool single = false, char *name = "");
export void timer(CodeAddress fn, char *type, i32 size, i32 ms);

// terminal.dom.mln
import { app, timer } from "annotations.mln";

@app(name = "Terminal")
i32 (Terminal *t) view() { ... }

@timer(100)
void (Terminal *t) poll() { ... }
```

For every `@a(args)` the compiler emits one row of static data in the
module's chunk of the `annotations` collected section
(`codegen_annotations.c`; see `docs/design/toolchain-collected-sections.md`),
eight words per row:

| word | content |
| --- | --- |
| 0 | annotation name (`char*`) |
| 1 | the annotated function |
| 2 | receiver type name (`char*`; `""` for a plain function) |
| 3 | `sizeof` that type (0 for a plain function) |
| 4 | number of annotation arguments |
| 5..7 | the arguments: a number, a bool as 0/1, a string as `char*` |

The linker lays every object's chunk out contiguously as one section,
defines `__section_annotations` / `__section_annotations_size` and lists
the section in its directory (`__sections`), which is how MyStdLib's
`meta/annotations.mln` finds the table by name and hands it out as an
iterator (`annotations.named("app")`, `it.next()`, `it.fn()`, ...). No
module lists the others and nothing is generated into the program's root:
an object that carries a chunk is kept by the linker on that account
alone. Whoever reads a row decides what it means and when.

The compiler checks that `a` resolves (a function in this file, or one
exported by a module named in a symbol-list import), that its first
parameters are `(i32, char*, i32)` and that it takes at most three more,
and matches the written arguments to those: keyed by name, positional, or
a bare bool parameter's name as a flag (`@app(single)`); a parameter left
out takes its `= literal` default; a literal of the wrong kind, an unknown
name or a surplus argument is an error. Annotations cannot be put on a
struct or a generic declaration.

An annotated method must take its receiver by pointer or reference
(`T *self`, `borrow T self`): the recorded function is called later with
an instance's address as its first argument, and because the calling
convention ignores trailing arguments, the DOM's uniform handler shape
`(owner, id, arg)` reaches `(T *self, i32 id)` or `(T *self)` directly --
no wrapper is generated. A value receiver is a move and is rejected.

`@safe` and `@noreturn` belong to the language: they are not annotations and
emit no row.

### Functions that do not return

`@noreturn` declares that a call of a function does not come back. The
function must be `void`, must have no `return`, and must not be able to reach
its end (E0203). An assembly import has no declaration to mark, so a function
that ends in one says so itself:

```mylang
@noreturn
export void panic(char *msg) {
    print(msg);
    halt_cpu();
    while (1) {}
}
```

`@noreturn` cannot be put on a generic declaration.

### Reaching the end of a function

A function that returns a value must not be able to reach its end (E0202). A
statement after one that cannot complete is unreachable (W0001). A statement
cannot complete when it is:

- `return`, `break` or `continue`;
- a block with such a statement in it;
- an `if` with an `else`, neither branch of which can complete;
- `while` or `for` with a constant true condition, or a `for` with none, and no
  `break` of its own (a `break` in a case arm belongs to the enclosing loop);
- `do ... while` with no `break`, whose condition is constant true, or whose
  body cannot complete and has no `continue`;
- a `case` with a `_` arm or covering every member of its enum, none of whose
  arms can complete;
- a call of a `@noreturn` function.

Only a number literal counts as a constant condition.

### Variables
- `var_decl` -> `type IDENTIFIER ( [ ( NUMBER | const_parameter )? ] )* ( = ( expr | init_list ) )? ;`
- `init_list` -> `{ expr ( , expr )* ,? }`

### Types and Enumerations
- `struct_decl` -> `struct IDENTIFIER? { var_decl* } IDENTIFIER? ;` | `struct IDENTIFIER generic_params { var_decl* } ;`
- `enum_decl` -> `enum IDENTIFIER { IDENTIFIER ( = NUMBER )? ( , IDENTIFIER ( = NUMBER )? )* ,? } ;`
- `typedef_stmt` -> `typedef type IDENTIFIER ;` | `typedef struct ... IDENTIFIER ;`

### Variant constructions

`Some(x)`, `Ok(x)`, `Err(x)` and `None` are built where a place of their type is
known: an initialiser, an assignment, a `return`, a struct literal's field, the
payload of another construction, and a call argument. Anywhere else, such as an
operand, is an error.

```mylang
void set_focus(Option<NodeId> id);

set_focus(Some(id));
open_menu(x, y, items, on_menu, None);
nested(Some(Some(1)));
```

An argument is built as the parameter's type, for a function of this file or an
imported one, a method, an instance of a generic and a function value alike. The
caller does not have to name that type or import `Option`. A variadic tail has
no type to build as, and a `borrow` or pointer parameter needs a place, not a
temporary; both are errors. What a construction carries is checked like any
store into the parameter's payload field.

It runs where it is written: only in the `case` arm, branch or `&&`/`||` operand
it is in, and on every pass of a loop condition or increment. Within one
statement it runs ahead of the statement's other expressions, like `f()?`, apart
from the earlier arguments of its own call, which keep running first.

## 4. Type System

Function values carry their complete signature:

```mylang
fn(i32 owner, i32 id, i32 arg) -> void
fn(i32 owner, i32 code, i32 mods) -> bool
```

Parameter names in a function type are optional. Function values use one word
at runtime, and indirect calls use the same argument and return type checks as
direct calls. Struct and array parameters and return values also use the same
by-value aggregate ABI through a function value as through a named function.
The literal `0` is the null function value and cannot be called.
`fn` introduces a function type in type position and remains available as an
ordinary identifier in name and expression positions.

`CodeAddress` is the sole nominal type that accepts a function value directly.
It records the one-word code address for low-level registries such as TestKit;
ordinary integer types do not accept a function value implicitly.

Opaque scalar types use `newtype`:

```mylang
export newtype Pid = i32;
export newtype CodeAddress = i32;
Pid pid = Pid(raw_pid);
i32 raw_pid = (i32)pid;
```

Each newtype has nominal identity while keeping its base scalar's size,
alignment, and calling convention. Construction and extraction are explicit;
arithmetic requires extracting the base value first.
- `type` -> `const* borrow? base_type ( * )*`
- `base_type` -> `primitive_type` | `IDENTIFIER type_args?`
- `generic_params` -> `< generic_param ( , generic_param )* >`
- `generic_param` -> `IDENTIFIER ( : bound ( + bound )* )?` | `const IDENTIFIER`
- `bound` -> `IDENTIFIER type_args?` (a trait; see [Traits](traits.md))
- `type_args` -> `< generic_arg ( , generic_arg )* >`
- `generic_arg` -> `type` | `NUMBER`
- `primitive_type` -> `u8` | `u16` | `i32` | `u32` | `bool` | `char` | `float` | `double` | `void` | `long` | `short`

`const` applies to the declared value. Assignment through that binding is a
semantic error, including when the value was imported from another package.

A `borrow T` is an alias of a place, not a pointer: its name reads and writes the
`T`, `.f` and `[i]` reach into it, and `*` does not apply (E0305). `&x` makes one,
and on a borrow names the same place. `r = y` writes through `r`, and `r = &other`
is an error. See [Ownership](ownership.md).

Generic uses are concretely instantiated before semantic analysis. See
[Generic instantiation](generics.md) for supported behavior and boundaries.

## 5. Statements
- `stmt` ->
    - `block` -> `{ stmt* }`
    - `if ( expr ) stmt ( else stmt )?`
    - `while ( expr ) stmt`
    - `do stmt while ( expr ) ;`
    - `for ( (var_decl | expr)? ; expr? ; expr? ) stmt`
    - `for ( type IDENTIFIER in expr ) stmt` (over an `Iterator`; `in` is contextual)
    - `return expr? ;`
    - `break ;`
    - `continue ;`
    - `yield expr ;`
    - `defer expression ;`
    - `defer block`
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
| 14 | `++`, `--`, `.`, `->`, `(args)`, `type_args (args)`, `?` | Postfix operators / Function call / Result propagation |
| 15 | `( expr )`, literals, `IDENTIFIER`, `Type { fields }`, `Type<T...> { fields }`, `case`, lambdas | Primary expressions |

### Special Expressions
- **Result propagation**: `expr?` on a `Result<T, E>` yields the `Ok` value or
  returns `Err` from the enclosing function, converting the error through
  `impl From<E> for F` when the function returns `Result<_, F>`. A `?` is
  postfix only where it ends the expression (before `;`, `,`, `)`, `]`, `}`);
  elsewhere it is the ternary.
- **Associated function call**: `Type::name(args)` calls an associated
  function of a trait impl for `Type`, e.g. `FsError::from(e)`.
- **Equality through Eq**: `a == b` and `a != b` call `Eq::eq` when `a`'s type
  implements `Eq`. See [Traits](traits.md).
- **Named Struct Literal**: `Point { x: 1, y: 2 }` or `Box<i32> { value: 42 }`.
  Generic type arguments specialize the struct before member validation and
  code generation; omitted fields are zero-initialized.
- **Case Expression**: `case expr of { ( (key | _) -> expr ; )* }`
  - A branch may use `-> _` as a no-op only when the whole `case` is used as
    a statement.  It cannot provide a value to an assignment, initializer, or
    `return`.
  - A statement-expression branch may calculate its value with `yield`, e.g.
    `Ok(v) -> ({ i32 adjusted = v + 1; yield adjusted; });`.
- **Function Literal (Lambda)**: `( param_list ) block` or `( param_list ) => block`
- **Statement Expression**: `( block )`
- **`sizeof`**: `sizeof ( expr )` or `sizeof ( type )`. With a type -- a
  primitive, a struct, or a generic parameter, which is a concrete type by
  the time it is instantiated -- it is the size of the type itself
  (`size / sizeof(T)` in `section.as_slice<T>`), with no value at hand.
- **`array.length`**: on a fixed-size array (a local, global or struct field
  declared `T a[N]`) the member `length` is the declared element count `N`,
  folded to a constant at compile time. It neither reads nor moves the array,
  so `f(a, a.length)` is allowed even though passing `a` moves it. Pointers
  and slices have no `length`; a slice's count is `s.len()`.
