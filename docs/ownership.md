# MyLang Ownership System

MyLang implements a resource management system based on ownership, moves, and borrows, similar to Rust, enforced during the semantic analysis phase.

## 1. Core Concepts

### Ownership
Every value has a variable that is its "owner". There can only be one owner at a time.

### Move Semantics
When a value is assigned to another variable or passed to a function, its ownership is **moved** by default, unless the type implements `Copy`. After a move, the original variable can no longer be used.

### Copy Types
Certain types are considered "Copy" and are duplicated instead of moved:
- Built-in numeric types (`i32`, `u32`, `float`, etc.)
- Booleans
- Enumerations
- Pointers and shared borrows (`borrow T`)
- Structs with an explicit `impl Copy`, when every field is Copy and the type
  does not implement `Drop`

## 2. Borrowing

Borrowing allows you to access a value without taking ownership.

A borrow's type is written `borrow T` (shared) or `borrow mut T` (mutable),
and its value is taken with `&x` / `&mut x`:

```mylang
borrow Node r = &n;
void (borrow mut Counter c) click(i32 id) { ... }
```

### Shared Borrows (`borrow T`)
- Created using the `&` operator.
- Multiple shared borrows can exist simultaneously.
- The underlying value cannot be modified through a shared borrow.
- The owner cannot move or mutably borrow the value while shared borrows are active.

### Mutable Borrows (`borrow mut T`)
- Created using the `&mut` operator (requires the variable to be declared as `mut`).
- Only **one** mutable borrow can exist at a time for a particular piece of data.
- No other borrows (shared or mutable) can exist while a mutable borrow is active.
- The owner cannot move or access the value while it is mutably borrowed.

## 3. Enforcement Rules

The semantic analyzer (`semantic_walk.c`) enforces these rules:

1. **Use After Move**: Attempting to use a variable after its value has been moved results in a compiler error.
2. **Borrow Conflicts**: 
   - Cannot mutably borrow a value if it is already borrowed (shared or mutably).
   - Cannot shared borrow a value if it is already mutably borrowed.
3. **Move while Borrowed**: Cannot move a variable if it currently has active borrows.
4. **Reference Escape**: Cannot return a reference to a local variable from a function.

### Where a borrow may live

A borrow is checked only while the analyzer can see every use of it, so it
may be held in exactly three places: a local, a parameter (including a method
receiver), and a return value. Writing one anywhere else is an error before
generics are instantiated (`parser_borrow_positions.c`):

- a struct field (`struct Holder { borrow Node node; }`)
- an enum payload, a typedef or a newtype
- a global
- an array element (`borrow i32 refs[2]`)
- a generic type argument (`Box<borrow i32>`), except `Option` and `Result`

Something that must refer to another value for longer is kept as an id or an
index (the DOM keeps node ids), or as a raw pointer in an `.unsafe.mln` file.

### Returning a borrow

A function that returns a borrow -- `borrow T`, or `Option<borrow T>` /
`Result` carrying one -- returns a borrow of its **first borrow parameter**:
the receiver for a method, otherwise the first parameter that is a borrow, a
pointer, or a value carrying a borrow. A borrow of a global is also allowed.

```mylang
Option<borrow T> (Vec<T> *v) at(i32 index);   // borrows from v
borrow i32 first(borrow i32 a, borrow i32 b) { return a; }  // ok
borrow i32 second(borrow i32 a, borrow i32 b) { return b; } // error
```

The caller then treats the result as borrowing whatever it passed in that
position, so the usual rules apply until the result's scope ends:

```mylang
Option<borrow i32> a = v.at(0);   // v is borrowed while a is in scope
v.push(4);                        // error: v is borrowed
```

`at_mut()` / `get_mut()` return `Option<borrow mut T>` and keep the
collection mutably borrowed. A borrow taken through a raw pointer
(`p->rows.at(i)`) has no owner to track. An instance of a generic written over
`T` (`unwrap_or` with `T = borrow i32`) is only checked for borrows of its own
locals.

## 4. Lifetimes and Scopes

MyLang uses lexical scopes to manage borrow lifetimes.
- When a scope ends, all borrows tied to bindings in that scope are released.
- This allows the owner to be used again (or moved) in the parent scope.

## 5. Raw pointers and `.unsafe.mln`

The borrow rules above follow references (`borrow` / `borrow mut`, and `&x` while
it is held as one). A raw pointer (`T *`) is not tracked: a pointer taken
from a value stays usable after the value is moved or dropped. Dereferencing
one, pointer arithmetic, and casts to or from pointers therefore belong in
`.unsafe.mln` sources; elsewhere they raise warning W0003 (see
[Source filename modifiers](source-modifiers.md)).

There is no block-level escape: an `unchecked { }` block existed and was
removed (2026-10-12) in favour of whole `.unsafe.mln` files.

## Run-time checks

Some mistakes cannot be seen before the program runs. Rather than corrupting
memory, the program stops where the check fails.

- **Array index.** `a[i]` on a fixed-size array (a local, global, or struct
  field declared `T a[N]`) checks `0 <= i < N`. A constant index outside the
  range is error E0304 at compile time; a computed one is compared when it
  runs. Only the first dimension of a multi-dimensional array is checked
  yet. Raw-pointer indexing `p[i]` has no length to check against and stays
  an unsafe operation (W0003).
- **Zero values.** A local declared without an initializer starts at zero,
  slot by slot (structs and arrays entirely), so reading it before the first
  assignment yields 0 rather than whatever an earlier frame left there.
- **Exhaustive matches.** A `case` on a plain enum must name every member or
  have a `_` arm, as payload enums already must; otherwise an unmatched value
  would silently yield zero.

A failed check *traps*: the program stops with r1 = `0x1BAD00 | kind`. In
kernel mode the machine halts with r1/r2 in the register dump; in a user
process the stop is a privilege violation, and the kernel ends the process.
No runtime library is linked for this (`codegen_trap.c`).

An index check is the single instruction `chk reg, N`, which traps unless
`reg < N` (unsigned, so a negative index fails too) and puts the address of
the `chk` in r2; the linker's `.map` names the function. Other traps are
`movi r1, code`, `movi r2, <line>`, `halt`.

| kind | r1 | r2 | meaning |
| --- | --- | --- | --- |
| `0x01` | `0x1BAD01` | address of the `chk` | index out of range |

## Scope cleanup with `defer`

`defer expression;` and `defer { ... }` register cleanup for the current
lexical scope. Registered bodies run in reverse order on normal scope exit and
before `return`, `break`, or `continue` transfers control out of that scope.
The cleanup runs before automatic drops registered in the same scope and reads
the current values from the variables' stack slots. A defer body cannot contain
`return`, `break`, `continue`, or another `defer`.

## 6. Automatic Drop

A non-Copy struct opts into deterministic cleanup by defining a one-argument
pointer/reference method named `drop` that returns `void`:

```mylang
void (Resource *self) drop() {
    release(self->handle);
}
```

The compiler tracks a runtime ownership flag for each droppable parameter and
local. It calls `drop()` once for the final owner at lexical scope exit,
including `break`, `continue`, and function return paths. Moving a value clears
the source flag; assigning a new value drops the destination's old value first.
Droppable fields are destroyed recursively in reverse declaration order after
their containing type's own `drop()` method.

Local arrays of droppable values are not owner-tracked yet. Use a container
type with its own `drop()` method when an owned collection is needed.
Moving or replacing a droppable field separately is likewise not supported;
move or replace its containing owner as one value.

`drop()` must accept its receiver through a pointer or reference. A value
receiver is not a destructor and is ignored by automatic cleanup.
