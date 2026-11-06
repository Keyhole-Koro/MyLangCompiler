# Semantic Walk Coverage

Covered by white-box tests:
- `AST_BORROW` / `AST_BORROW_MUT`
- `AST_PARAM` with `borrow mut`
- `AST_WHILE` with `AST_BREAK` / `AST_CONTINUE`
- `AST_CASE`

Covered by semantic smoke tests:
- `AST_DO_WHILE`
- `AST_FOR`
- `AST_STMT_EXPR`
- `AST_YIELD`
- `AST_TYPEDEF_STRUCT`
- `AST_MEMBER_ACCESS` / `AST_ARROW_ACCESS`

Covered by semantic failure tests:
- use-after-move on local move assignment
- use-after-move after call argument move
- use-after-move after branch-sensitive move merge from then / else branches
- independent branch move state before merge
- move while borrowed
- shared borrow then mutable borrow
- mutable borrow then shared borrow
- return reference to local
- return local reference binding
- borrow in a struct field, enum payload, global, array element or generic
  argument (`tests/fail/borrow/`)
- returned borrow not taken from the first borrow parameter
- `Option<borrow T>` returned from a local
- constant index outside a fixed-size array, including a negative one (E0304)
- match on a plain enum that leaves out a member without a `_` arm
- a non-void function or function literal that can reach its end: after an
  `if` without `else`, a `while (1)` with a `break` (also one inside a case
  arm), a `case` without `_` on an integer (E0202)
- a `@noreturn` function that has a `return`, can reach its end, or is not
  `void` (E0203)
- moving or mutating a receiver while a method's returned borrow is in scope
- writing through a shared borrow, `++` through one, and `&mut` of a field
  through one (E0601)
- assigning to a value, or to one of its fields, while it is borrowed (E0602)
- reading a value while a local holds `&mut` of it (E0603)
- a value moved inside a loop, at the end of the body or before `continue`
  (E0604)
- `&mut` of a `const` value, and writing a `const` struct's field (E0605)
- changing a `borrow mut` parameter or local while a borrow taken through it
  is in scope

Covered by semantic success tests:
- a move followed by `break` or `return`, and a value assigned again before
  the next iteration (`succeed/semantic/moveThenLeave.mln`)
- data-only structs copied without `impl Copy` (`succeed/semantic/dataStructsCopy.mln`)
- re-pointing a shared borrow variable (`succeed/semantic/rebindSharedBorrow.mln`)

Covered by warning tests:
- keeping a borrow as a raw pointer (W0003, `warn/semantic/borrowKeptAsPointer_warn.mln`)

Still thin / future work:
- field-sensitive move tracking
- borrow conflicts through function calls
- raw-pointer operations outside `.unsafe.mln` sources (E0701)
