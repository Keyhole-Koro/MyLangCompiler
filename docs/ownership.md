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
- Pointers and Shared References (`&T`)

## 2. Borrowing

Borrowing allows you to access a value without taking ownership.

### Shared Borrows (`&T`)
- Created using the `&` operator.
- Multiple shared borrows can exist simultaneously.
- The underlying value cannot be modified through a shared borrow.
- The owner cannot move or mutably borrow the value while shared borrows are active.

### Mutable Borrows (`&mut T`)
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

## 4. Lifetimes and Scopes

MyLang uses lexical scopes to manage borrow lifetimes.
- When a scope ends, all borrows tied to bindings in that scope are released.
- This allows the owner to be used again (or moved) in the parent scope.

## 5. Unchecked Blocks

The `unchecked` keyword can be used to bypass certain ownership checks:
```mylang
unchecked {
    // Ownership rules are relaxed here
    // Useful for low-level pointer manipulation
}
```
Inside an `unchecked` block, the compiler allows raw pointer operations and bypasses the borrow checker's strict exclusivity rules for references.
