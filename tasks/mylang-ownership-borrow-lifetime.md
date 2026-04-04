# MyLang ownership / borrow / lifetime tasks

## Goal
Add a Rust-like ownership system to `toolchain/MyLangCompiler` in small, safe steps.
The first milestone is not full Rust. The first milestone is:
- detect use-after-move
- support `&T` and `&mut T`
- reject conflicting borrows
- reject obvious dangling references
- limit the first implementation to local variables and lexical scopes

## Design direction
- Keep `parser -> semantic -> codegen` as the target pipeline.
- Do not mix borrow checking into backend code generation.
- Treat raw pointers and safe references as different concepts.
- Start with lexical lifetimes only.
- Postpone field-sensitive borrow checking, generics, traits, NLL, and drop glue.

## Safety model
- Keep both safe references and raw pointers; do not remove raw pointers from the language.
- Use a 3-layer model:
  - safe references for normal code
  - raw pointers for low-level and OS work
  - `unchecked` regions for operations that bypass borrow/lifetime guarantees
- Borrow checking should apply to safe references, not to raw pointers.
- Raw pointer dereference, pointer arithmetic, and pointer-to-reference conversion should eventually require `unchecked`.
- Prefer source-level syntax that makes the distinction obvious, for example:
  - `ref T`
  - `ref mut T`
  - `*const T`
  - `*mut T`
- Do not introduce a separate `ptr` keyword unless it is clearly needed; the distinction can be expressed with `ref` for safe references and `*...` forms for raw pointers.
- Existing C-style pointer syntax may remain temporarily for compatibility, but long-term syntax should make `ref` vs raw `*...` explicit.

## Draft semantics

### Overview
- MyLang distinguishes three categories of value access:
  - owned values
  - safe references
  - raw pointers
- Owned values participate in ownership transfer, move checking, and lifetime checking.
- Safe references participate in borrow checking and lifetime checking.
- Raw pointers are low-level escape hatches intended for OS and systems work; they are not protected by borrow checking.

### Ownership
- Every non-reference, non-raw-pointer value is an owned value.
- An owned value has exactly one current owner at a time.
- Ownership may be transferred by move.
- Ownership may be observed through safe references without transfer.

### Copy and move
- Assignment, argument passing, and `return` transfer values by default.
- If the source type is `Copy`, the operation performs a copy and the source remains usable.
- If the source type is not `Copy`, the operation performs a move and the source becomes unusable after the transfer.
- Literals and newly constructed values create fresh owned values rather than moving from an existing binding.

### Copy types
- The first implementation should treat primitive scalars as `Copy`.
- Raw pointers may also be treated as `Copy`.
- Safe references may be treated as `Copy` values, but still remain subject to borrow and lifetime constraints.
- User-defined `Copy` behavior is postponed until a later phase.

### Use after move
- Reading, writing, borrowing, or moving a binding after it has been moved is an error.
- Reinitializing a moved local may be allowed later, but the first implementation may reject all post-move uses for simplicity.

### Safe references
- A safe reference does not own the referent.
- A shared safe reference permits read-only access.
- A mutable safe reference permits mutable access and requires exclusive access to the referent for the duration of the borrow.
- Borrowing is explicit in the source language.

### Shared borrow rule
- Any number of shared safe references may coexist to the same referent.
- While shared borrows are live, mutable access through the owner is forbidden.
- While shared borrows are live, creation of a mutable safe reference to the same referent is forbidden.

### Mutable borrow rule
- At most one mutable safe reference may exist to a referent at a time.
- While a mutable borrow is live, reads and writes through the owner are forbidden except through that mutable reference.
- While a mutable borrow is live, no shared safe reference to the same referent may be created.

### Lifetime rule
- A safe reference may not outlive the referent it points to.
- Returning a reference to a local binding is an error.
- Storing a reference so that it escapes beyond the owner lifetime is an error.
- The first implementation uses lexical block lifetimes only.

### Function calls
- Passing an owned value to a parameter of owned type transfers that value by copy-or-move rules.
- Passing a value to a reference parameter performs a borrow instead of a move.
- Returning an owned value transfers ownership to the caller.
- Returning a safe reference is valid only if the referent outlives the call according to the lifetime rules.

### Raw pointers
- Raw pointers do not participate in borrow checking.
- Raw pointers may alias freely.
- Raw pointers may be null if the language chooses to allow null raw pointers.
- Raw pointers are intended for MMIO, low-level memory access, ABI boundaries, and kernel internals.

### Unchecked regions
- Operations that can violate memory safety must be confined to `unchecked { ... }` regions.
- The initial set of raw-only operations should include:
  - raw pointer dereference
  - raw pointer writes
  - pointer arithmetic
  - pointer-to-reference conversion
  - integer-to-pointer and pointer-to-integer casts
- `unchecked` regions do not disable the entire type system.
- Outside of the explicitly raw operations, normal parsing, name resolution, and ordinary type rules continue to apply.
- Inside `unchecked { ... }`, C-like pointer syntax and casts may be accepted even if safe code uses cleaner ownership-oriented syntax.

### Ref and ptr boundary
- Converting `ref` to a raw pointer may be permitted explicitly.
- Converting a raw pointer to `ref` must require an `unchecked` region because it reintroduces a value into the checked world.
- Dereferencing a raw pointer must require an `unchecked` region even if the pointed-to type matches.

### Initial simplifications
- The first implementation is local-variable-first.
- The first implementation may ignore field-sensitive borrow splitting.
- The first implementation may ignore partial moves.
- The first implementation may reject patterns that could be accepted by a more precise non-lexical analysis.

### Illustrative examples
- Move:
  ```mylang
  File a = open();
  File b = a;   // move
  use(a);       // error: use after move
  ```
- Borrow:
  ```mylang
  Buffer b = make();
  ref Buffer r = &b;   // shared borrow
  ```
- Mutable borrow:
  ```mylang
  Buffer b = make();
  ref mut Buffer w = &mut b;
  ```
- Raw access:
  ```mylang
  unchecked {
      u32* reg = (u32*)0xC000;
      *reg = 1;
  }
  ```

## Syntax direction
- Current preferred direction:
  - owned values use ordinary type syntax
  - safe references use `ref T` and `ref mut T`
  - raw pointers use `*const T` and `*mut T`
  - dangerous pointer operations are isolated inside `unchecked { ... }`
- Example:
  ```mylang
  Buffer b = make();
  ref Buffer r = &b;
  ref mut Buffer w = &mut b;

  unchecked {
      u32* reg = (u32*)0xC000;
      *reg = 1;
  }
  ```
- Rationale:
  - `ref` clearly marks checked references
  - raw pointers keep compact low-level syntax
  - no extra `ptr` keyword is needed
  - safe code and low-level code look visibly different
  - `unchecked` describes reduced guarantees without implying a full C sublanguage

## Phase 1: create a semantic analysis stage
- [x] Create `inc/mylang/semantic/` and `src/semantic/`.
- [x] Add a `semantic_check(ASTNode *root)` entrypoint.
- [x] Call semantic analysis after parser rewrites/checks and before codegen.
- [x] Move or duplicate minimal type inference utilities out of backend-only code.
- [x] Define a semantic error reporting path with source locations.

## Phase 2: extend syntax and AST for ownership
- [ ] Extend type syntax to represent shared references and mutable references.
- [ ] Decide the long-term source syntax for safe refs vs raw pointers.
- [ ] Decide whether existing C-style pointer syntax stays as legacy sugar or gets deprecated.
- [ ] Add AST representation for borrow expressions such as `&x` and `&mut x`.
- [ ] Add mutability information for variable declarations and parameters.
- [ ] Add `unchecked { ... }` syntax to the roadmap, even if the first implementation is parser-only.
- [ ] Add enough source-span/token metadata to produce good borrow-checker errors.

### Phase 2 target surface syntax
- Safe code:
  - `ref T`
  - `ref mut T`
  - borrow expressions `&x` and `&mut x`
- Low-level code:
  - existing C-style raw pointer syntax remains valid inside `unchecked { ... }`
  - examples:
    - `u32* reg = (u32*)0xC000;`
    - `*reg = 1;`
- Compatibility plan:
  - outside `unchecked`, raw-pointer-heavy C idioms should gradually become restricted
  - inside `unchecked`, C-like pointer syntax remains accepted for low-level work

### Phase 2 AST work
- [ ] Extend type AST so safe reference types can be represented distinctly from raw pointer types.
- [ ] Distinguish safe reference mutability from owner-variable mutability.
- [ ] Add AST nodes or flags for:
  - shared borrow expression
  - mutable borrow expression
  - `unchecked` block
- [ ] Decide whether raw pointer type syntax continues using the current pointer-level fields or gets split into an explicit raw-pointer kind.
- [ ] Ensure AST printing and freeing logic are updated for all new nodes.

### Phase 2 parser work
- [ ] Parse `ref T` types.
- [ ] Parse `ref mut T` types.
- [ ] Parse `&expr` as shared borrow in safe contexts.
- [ ] Parse `&mut expr` as mutable borrow in safe contexts.
- [ ] Parse `unchecked { ... }` as its own statement/block node.
- [ ] Decide how much C-style pointer syntax is accepted outside `unchecked` during the transition.
- [ ] Keep existing low-level pointer syntax working inside `unchecked`.

### Phase 2 semantic scaffolding
- [ ] Teach `semantic_walk_ast` about new reference and `unchecked` nodes.
- [ ] Add an `unchecked_depth` or equivalent flag to semantic context design.
- [ ] Prepare semantic helpers to tell apart:
  - owned values
  - safe references
  - raw pointers
- [ ] Do not enforce full borrow rules yet; Phase 2 only needs the syntax and AST to be representable and traversable.

### Phase 2 test goals
- [ ] Parse and walk a file containing `ref T` declarations.
- [ ] Parse and walk a file containing `ref mut T` declarations.
- [ ] Parse and walk borrow expressions `&x` and `&mut x`.
- [ ] Parse and walk an `unchecked { ... }` block with C-style pointer code.
- [ ] Confirm AST dump output includes the new node kinds.

## Phase 3: build symbol and scope tracking
- [ ] Assign a scope id to every block/function scope.
- [ ] Track variable declarations by scope.
- [ ] Record whether a variable is mutable.
- [ ] Record whether a variable is `Copy` or `Move` by default.
- [ ] Define rules for built-in `Copy` types in MyLang.

## Phase 4: implement ownership state tracking
- [ ] Create per-variable state:
  - owner available / moved
  - shared borrow count
  - mutable borrow active flag
  - declaration scope
  - last use or current live borrow info
- [ ] On assignment/init from an owned value, distinguish copy vs move.
- [ ] Reject reads of moved values.
- [ ] Reject reassignment of borrowed values.
- [ ] Reject moves while active borrows exist.

## Phase 5: implement borrow checking
- [ ] Allow multiple shared borrows.
- [ ] Allow only one mutable borrow.
- [ ] Reject shared borrow when mutable borrow is active.
- [ ] Reject mutable borrow when any borrow is active.
- [ ] Reject mutation through owner while shared borrow exists.
- [ ] Reject any owner use that violates mutable borrow exclusivity.

## Phase 6: implement lexical lifetime checks
- [ ] End borrows when their scope ends.
- [ ] Reject returning references to locals.
- [ ] Reject storing a reference that outlives its referent.
- [ ] Reject borrowing values from inner scopes into outer scopes.
- [ ] Keep the first version lexical; do not attempt non-lexical lifetimes yet.

## Phase 7: integrate with existing compiler behavior
- [ ] Review interactions with existing pointer/address-of logic.
- [ ] Review interactions with arrays, structs, and member access.
- [ ] Decide how function arguments are passed: move, copy, or borrow.
- [ ] Decide how return values behave for owned and borrowed types.
- [ ] Keep codegen simple by lowering checked references to addresses after semantic validation.
- [ ] Define explicit conversion boundaries between `ref` and raw pointers.
- [ ] Define which pointer operations are legal only inside `unchecked`.

## Phase 8: tests
### Success cases
- [ ] copyable scalar assignment stays usable
- [ ] single mutable borrow works
- [ ] multiple shared borrows work
- [ ] borrow ends after block scope
- [ ] borrowed function argument works

### Failure cases
- [ ] use after move
- [ ] mutable borrow while shared borrow exists
- [ ] shared borrow while mutable borrow exists
- [ ] assign to value while borrowed
- [ ] move value while borrowed
- [ ] return reference to local
- [ ] leak inner-scope reference to outer scope

## Suggested implementation order
1. semantic stage skeleton
2. scope table + symbol table
3. move/copy checking only
4. `&T` / `&mut T` syntax and AST
5. borrow conflict checking
6. lexical lifetime checks
7. function parameter/return rules
8. structs and member-level extensions

## Explicitly postponed
- [ ] named lifetimes like `'a`
- [ ] trait-style `Copy` derivation
- [ ] destructor / drop semantics
- [ ] partial move
- [ ] field-sensitive borrow splitting
- [ ] closure capture analysis
- [ ] non-lexical lifetimes
- [ ] generics-aware ownership

## Notes for this repository
- Current type inference helpers live under backend code such as `src/backend/codegen/codegen_type_infer.c`.
- Ownership checking should move earlier than codegen.
- Existing unary `&` and `*` behavior must be reviewed so safe references and raw pointers do not get conflated.
- `parser_rewrite_scope.c` already has scope-related helper ideas that may be reusable.
- Because this project targets OS and low-level work, raw pointers remain necessary even after ownership is added.
- The design goal is coexistence: safe-by-default references, explicit raw pointers, and explicit `unchecked` escape hatches.
