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

## Phase 1: create a semantic analysis stage
- [x] Create `inc/mylang/semantic/` and `src/semantic/`.
- [x] Add a `semantic_check(ASTNode *root)` entrypoint.
- [x] Call semantic analysis after parser rewrites/checks and before codegen.
- [x] Move or duplicate minimal type inference utilities out of backend-only code.
- [x] Define a semantic error reporting path with source locations.

## Phase 2: extend syntax and AST for ownership
- [ ] Extend type syntax to represent shared references and mutable references.
- [ ] Decide whether to keep raw pointer syntax as-is or gate it separately.
- [ ] Add AST representation for borrow expressions such as `&x` and `&mut x`.
- [ ] Add mutability information for variable declarations and parameters.
- [ ] Add enough source-span/token metadata to produce good borrow-checker errors.

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
