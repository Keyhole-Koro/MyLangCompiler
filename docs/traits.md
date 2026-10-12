# Traits

A trait names behaviour that several types share. MyLang has no classes:
data lives in `struct` and `enum`, a type's own behaviour in receiver methods,
and behaviour across types in traits. Dispatch is static -- a bounded generic
is specialized per type, so a trait costs nothing at run time.

```mylang
import { From } from "@std/core/convert.mln";

impl From<SsdError> for FsError = FsError::IoError;

Result<i32, FsError> write(...) {
    ssd.write_block(block, buf)?;   // Err(FsError::from(error))
    ...
}
```

## Declaring a trait

- `trait_decl` -> `export? trait IDENTIFIER generic_params? { trait_item* }`
- `trait_item` -> `type ( receiver )? IDENTIFIER ( params ) ( ; | block )`

```mylang
export trait From<S> {
    Self from(S source);                   // associated function
}

export trait Iterator<T> {
    Option<T> (Self *self) next();         // method
}
```

`Self` stands for the implementing type. An item with a receiver is a method;
its receiver must be `Self` (`Self *self` is the usual form). An item without
one is an associated function, called as `Type::name(...)`. A trait's own
type parameters take no bounds.

### Default items

An item written with a body is a default. An impl may leave it out and gets
the body, with `Self` and the trait's type parameters spelled as the impl's
types:

```mylang
trait Shape {
    i32 (Self *self) area();
    i32 (Self *self) double_area() { return self.area() * 2; }
}

impl Shape for Square {
    i32 (Square *self) area() { return self->side * self->side; }
}   // Square__double_area comes from the default
```

A default may call the trait's other items (`self.area()`, `Self::make(1)`).
It is parsed again for each impl that uses it, in the impl's module, so a
name in it resolves there; an impl may still write the item itself.

The standard traits live in MyStdLib's `core/`:

| trait | module | used by |
| --- | --- | --- |
| `From<S>` | `@std/core/convert.mln` | `?` across error types, `Type::from(v)` |
| `Eq` | `@std/core/cmp.mln` | `==` and `!=` |
| `Iterator<T>` | `@std/core/iter.mln` | `for (T x in it)` |
| `Drop` | `@std/core/drop.mln` | automatic cleanup |
| `Copy` | `@std/core/copy.mln` | explicit copy semantics for safe structs |
| `Describe` | `@std/core/describe.mln` | a short message for a value (errors), as `describe()` |

## Implementing a trait

- `impl_decl` -> `export? impl generic_params? IDENTIFIER type_args? for type { fundef* }`
- `impl_decl` -> `export? impl IDENTIFIER type_args? for type = expr ;`

```mylang
impl Eq for Point {
    bool (Point *self) eq(Point *other) {
        return self->x == other->x && self->y == other->y;
    }
}

impl From<SsdError> for FsError {
    FsError from(SsdError e) {
        return case e of { SsdError::DeviceError -> FsError::IoError; };
    }
}
```

`Self` may be written inside an impl body and means the impl's type. The impl
must provide every item of the trait that has no default, each at most once
and nothing else, with the trait's signature after `Self` and the trait's
parameters are replaced.

The `= expr` form implements a trait whose only item is an associated
function, returning `expr` whatever the argument: `impl From<SsdError> for
FsError = FsError::IoError;`.

Items the impl leaves out take the trait's defaults. The impl's items are
ordinary functions from the parser onward. A method is
the usual `Type__name`; an associated function is `Type__name`, or
`Type__Trait_Args__name` for a generic trait so one type can implement both
`From<A>` and `From<B>`.

### Where an impl may appear

- **Orphan rule.** The trait, the impl's type, or one of the trait's type
  arguments must belong to this source tree: declared in this file or
  imported through a relative path. A name imported through an `@alias/...`
  path belongs to another tree. `impl From<SsdError> for FsError` is allowed
  in MyOS's `fs.mln` because `SsdError` comes from `ssd.mln`, even though
  `From` comes from `@std` and `FsError` from `@contracts`.
- **One impl per trait, arguments, and type** among the impls a module can see.
- The impl's type is a named type or a generic type's instance (below).
  Impls for pointers and references are not supported yet.

### Impls for generic types

```mylang
impl<T: Eq> Eq for Box<T> {
    bool (Self *self) eq(Self *other) { return self->value == other->value; }
}

impl Make for Box<i32> {           // this instance only
    Self make(i32 n) { return Self { value: n }; }
}
```

An impl whose type has type arguments is a template. Each instance of the
generic type that the impl's type matches gets the impl, as concrete
methods and functions of that instance, when the instance's arguments meet
the impl's bounds; an instance that does not simply has no impl, and a use
that needs one reports it (`Box<Opaque> does not implement Eq`). Every
parameter of `impl<...>` must be one of the type's arguments. Inside the
body, `Self` and the type spelled out (`Box<T>`) are the same type, and
`Self { ... }` builds one.

`Box<i32>::make(5)` calls an associated function of an instance. An exported
template reaches every importer of its module and is instantiated there,
also for instances that arrive as the field type of an imported struct;
each object keeps its own copy of an instance's items. The `= expr` form is
not available for generic types yet, and overlapping templates are not
detected.

### Visibility

An impl is visible in its own module. An `export impl` is also visible to a
module that imports the declaring module, once the impl's type is visible
there too (imported or declared, by any import, in any order). Its items then
come along as prototypes, and the types their signatures name are imported
with them.

## Bounds

- `generic_param` -> `IDENTIFIER ( : bound ( + bound )* )?` | `const IDENTIFIER`
- `bound` -> `IDENTIFIER type_args?`

```mylang
bool contains<T: Eq>(T *items, i32 len, T *needle) {
    for (i32 i = 0; i < len; i++) {
        if (items[i] == *needle) { return true; }
    }
    return false;
}

T convert<T: From<S>, S>(S value) { return T::from(value); }
```

A bound may name a parameter declared later in the list. Each instantiation
requires an impl for every bound, after the template's parameters are
replaced:

```
app.mln:9:12: error: User does not implement Eq (required by 'contains')
  note: add `impl Eq for User`
```

Inside the template, the bound's methods are called as on any value and
`T::name(...)` calls an associated function of whatever `T` becomes.

Generic structs and enums take bounds the same way, checked wherever an
instance is first named; their receiver methods may rely on them:

```mylang
struct Pair<T: Eq> { T left; T right; };
bool (Pair<T> *self) same() { return self->left == self->right; }

Pair<Point> p;   // error unless `impl Eq for Point` is visible
```

A generic receiver method may also bound the receiver's parameters itself,
`HashMap<K, V>::put<K: Hash + Eq, V>`, checked when the receiver type is
instantiated.

## Language features backed by traits

### `?` and From

In a function returning `Result<_, Target>`, `expr?` on a
`Result<_, Source>` returns `Err(error)` when `Source` is `Target` and
`Err(Target::from(error))` when `impl From<Source> for Target` is visible.
Otherwise:

```
fs.mln:284:38: error: '?' cannot convert SsdError into FsError
  note: add `impl From<SsdError> for FsError`, or handle the error explicitly
```

`?` never converts in any other way, and conversions do not chain.

In a function returning an `Option`, `expr?` on an `Option` gives the value
or returns `None`. A Result joins in through `ok()`: `parse(s).ok()?`. `?`
on an Option in a function returning a Result is an error.

Built with `--error-trace`, each `?` hop is also recorded; see
[Error return trace](error-trace.md).

### `==` and Eq

For a value of a type with an `Eq` impl, `a == b` is `a.eq(&b)` and
`a != b` is `!a.eq(&b)`. An operand that is not a place (a call result, an
enum variant) is first bound to a temporary. Integers, pointers, plain enums,
and `str` keep their built-in equality. The rewrite is decided by the left
operand's declared type.

### for-in and Iterator

- `stmt` -> `for ( type IDENTIFIER in expr ) stmt`

```mylang
for (AnnotationRow *row in rows) { ... }
```

The loop calls `next()` until it returns `None`; `break` and `continue` work
as in any loop. The iterated value must implement `Iterator`. A local is
advanced in place; any other expression is evaluated once into a temporary.
`Option` must be visible (`import { Option } from "@std/core/option.mln";`).
`in` is contextual and stays an ordinary name elsewhere.

### Drop

A type implements `Drop` to have the compiler call `drop()` when an owner
goes out of scope (see `docs/design/mylang-owned-values-and-drop.md` in
MyComputer). A method named `drop` without the impl is still recognised for
compatibility, with warning W0002; new code writes `impl Drop`.

## Not supported yet

- dynamic dispatch (`dyn Trait`). It was implemented and removed again
  (2026-10-12): every use so far was served as well by passing what the
  trait computes (`e.describe()`) or by a function pointer. Its design is in
  MyComputer's `issues/completed/MLC-021_traits-and-try-conversion.md`.
- associated types
- `a[i]` for user types (an `Index` trait). Without a panic, an index out of
  range could only be ignored; checked lookups return an Option instead
  (`v.at(i)`, `map.get(&k)`), and iterators never go out of range.
- the `= expr` impl form for generic types; overlap checks between impl templates

## Implementation

| stage | file | work |
| --- | --- | --- |
| parse | `parser_trait.c` | `trait` registers a TraitDef (default bodies kept as tokens); `impl` parses its items as methods/functions, adds the defaults it leaves out, checks them against the trait and the orphan rule, splices them into the program, and records an ImplDef |
| parse | `parser_generic.c` | bounds in a type parameter list |
| parse | `parser_stmt.c` | for-in desugars to a `while` over `next()` |
| import | `parser_trait.c` | traits named by an import; exported impls whose type is visible, with item prototypes (`resolve_imported_impls`) |
| instantiate | `parser_instantiate.c` | bound checks (functions, methods, structs, enums), `T::name` in templates, concrete impl types, impl templates applied to each matching instance |
| lower | `parser_trait_lower.c` | `Type::name(...)`, `==` via Eq, for-in iterator types |
| lower | `parser_payload_enum.c` | `?` through From |

Semantic analysis and codegen see only ordinary functions and calls.
