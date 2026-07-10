# Semantic Walk Coverage

Covered by white-box tests:
- `AST_BORROW` / `AST_BORROW_MUT`
- `AST_UNCHECKED`
- `AST_PARAM` with `ref mut`
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

Still thin / future work:
- field-sensitive move tracking
- borrow conflicts through function calls
- raw-pointer restrictions inside and outside `unchecked`
