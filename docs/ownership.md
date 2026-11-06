# MyLang Ownership System

MyLang implements a resource management system based on ownership, moves, and borrows, similar to Rust, enforced during the semantic analysis phase.

The normative rules, with their numbers (V2, B4, ...), are in
`docs/design/mylang-values.md` at the repository root. This document
describes how the compiler implements them.

## 1. Core Concepts

### Ownership
Every value has a variable that is its "owner". There can only be one owner at a time.

### Move Semantics
When a value that cannot be copied is assigned to another variable, returned, or passed to a `move T x` parameter, its ownership is **moved**. After a move, the original variable can no longer be used.

### What is copied
A value's kind follows from its type (rule V2, `semantic_value_kind`): there is no declaration for it. A struct or array is the strongest of what it holds:

- **Owned**: the type has a `drop`, or a field or element holds one that does. It is moved, and dropped by its last owner.
- **Moved**: a struct with a raw pointer field, directly or in a field. It may own what the pointer points at: `Vec` has no `drop` yet, and copying its header would alias its buffer until shared values land (MLC-025).
- **Data**: everything else, which is copied: numbers, booleans, enums, newtypes, pointers and borrows held in a variable, function values, and the structs and arrays made of those. `Option<i32>`, `Text<N>` and `i32 a[4]` are data.

## 2. Parameters and Borrowing

A parameter is passed in one of three ways. Reading is the default:

| Form | Meaning |
| --- | --- |
| `T x` | Reads. The caller's value stays as it is. |
| `borrow T x` | Changes the caller's place. |
| `move T x` | Takes the value. The callee becomes its owner. |

### Reading (`T x`)
- A struct or array travels as an address, so no copy is made at the call.
- A body that writes to the parameter works on a copy taken on entry, so the
  caller sees no change (`copy_written_params`, `codegen_func.c`).
- A value with a `drop` cannot be copied. A parameter of such a type can only
  read: writing to it or moving it is E0601. The caller keeps it and drops it.
- An owned value straight from a call has no owner to drop it, so it cannot go
  to a reading parameter (E0601): give it a name first.
- A construction written as an argument (`read(Some(owned))`) is built into a
  temporary, which is its owner: the temporary drops it when its block ends.
- A `borrow T` variable passed to a `T` parameter is read through.

### Taking (`move T x`)
- The caller's variable is spent and the callee drops the value.
- Use it where a function keeps the value, such as `push(move T value)`.
- `take(Some(owned))` moves `owned` into the temporary and the temporary into
  the callee.

### Borrowing (`borrow T`)
A borrow is taken with `&x` and is an alias of the place: the name stands for
what is there, not for a reference to it.

```mylang
void add(borrow i32 n, i32 by) { n = n + by; }   // writes the caller's place
void (borrow Counter c) click(i32 id) { c.clicks = c.clicks + 1; }

borrow Node r = &n;
Node copy = r;     // reads the Node
r = other;         // writes n, for any T; an owned old value is dropped
r.next = 3;        // a field of n
```

This holds for parameters, locals, `case` bindings from `Option<borrow T>`, and
values returned as `borrow T`.

- `*b` on a borrow is E0305 in every source file. `*p` stays for a raw pointer.
- A borrow stays with its place: `r = &other` is an error.
- `&` is the mark at a call that an argument can change, so an argument to a
  `borrow` parameter is written `&x` even when `x` already is a borrow, and a
  bare `b` there is an error. `&b` names the place `b` already is. A receiver is
  the exception: its `&` is automatic.
- An instance of a generic written over `T` passes a borrow on without the mark,
  because its body could not spell it: `T` may or may not be a borrow.
- A borrow goes into a `borrow` local, return or `Option<borrow T>` payload as a
  place, with or without `&`: the destination says what is meant.
- Only **one** borrow can exist at a time for a particular piece of data.
- The owner cannot move, read or write the value while it is borrowed.
- A `const` value cannot be borrowed (E0605).
- Every variable can be written, as in C: there is no `mut` declaration.

## 3. Enforcement Rules

The semantic analyzer (`src/semantic/`) enforces these rules:

1. **Use After Move**: Attempting to use a variable after its value has been moved results in a compiler error.
   A branch that ends in `return`, `break` or `continue` does not carry its
   moves past the `if`.
2. **Borrow Conflicts**: a value cannot be borrowed while it is borrowed, and a
   call cannot both lend a place with `&` and read it through another argument.
3. **Move while Borrowed**: Cannot move a variable if it currently has active borrows.
4. **Reference Escape**: Cannot return a reference to a local variable from a function.
5. **Change to a reading parameter of an owned value** (E0601): `p.x = 1`,
   `p.x++`, `&p.x`, and moving `p` are errors when `p` is a plain parameter
   whose type has a `drop`.
6. **Change while borrowed** (E0602): the owner, or any field of it, cannot be
   assigned or stepped (`++` / `--`) while a borrow of it is in scope.
7. **Use while borrowed** (E0603): while a local holds `&x`, `x` itself cannot
   be read.
8. **Reborrows lock what they go through**: a borrow taken through a
   `borrow` parameter or a local holding one (`v.at(0)` on
   `borrow Vec<T> v`) keeps that parameter or local borrowed too, so
   `v.push(..)` cannot reallocate under it.
9. **Move inside a loop** (E0604): a variable declared outside a loop and
   moved inside it must be assigned again before the next iteration, or the
   loop must be left (`break`, `return`) after the move. The state at each
   `continue` counts as reaching the next iteration.
10. **Const** (E0605): fields of a `const` value cannot be written either.

Writes through a raw pointer (`p->x`, `p[i]` on `T *p`) are not checked here;
they are raw-pointer operations (W0003).

These checks and the backend see a borrow as a word holding the place's address.
`parser_borrow_places.c` writes a source's uses out in that form as the last
lowering step, once calls are ordinary calls and `case` bindings are payload
fields: a use of the value becomes `*b` and `&b` becomes `b`. Where a use stands
decides which it is. The base of a field or an index, the operand of `&` and
anything going into a `borrow` destination keep the place; everything else reads
or writes through.

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

A borrow taken through a raw pointer
(`p->rows.at(i)`) has no owner to track. An instance of a generic written over
`T` (`unwrap_or` with `T = borrow i32`) is only checked for borrows of its own
locals.

## 4. Lifetimes and Scopes

MyLang uses lexical scopes to manage borrow lifetimes.
- When a scope ends, all borrows tied to bindings in that scope are released.
- This allows the owner to be used again (or moved) in the parent scope.

## 5. Raw pointers and `.unsafe.mln`

The borrow rules above follow references (`borrow`, and `&x` while
it is held as one). A raw pointer (`T *`) is not tracked: a pointer taken
from a value stays usable after the value is moved or dropped. Dereferencing
one, pointer arithmetic, and casts to or from pointers therefore belong in
`.unsafe.mln` sources; elsewhere they are error E0701 (see
[Source filename modifiers](source-modifiers.md)).

Keeping a borrow as a raw pointer or an integer address -- initializing or
assigning a pointer or integer variable or field from one, putting one in a
struct literal, or returning one where a pointer is declared -- is reported
the same way (rule B9): from then on nothing tracks what it borrows. A borrow
of a global, and one taken through a raw pointer (`&p->x`), are not reported.
Passing a borrow to a pointer parameter is not reported yet; MLC-023 moves
those parameters to borrows first.

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

A struct opts into deterministic cleanup by defining a one-argument
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
