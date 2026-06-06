# MyLang Compiler Context Specification

This document describes the internal state management of the `MyLangCompiler`. The compiler uses two primary context structures to track state across different phases: `SemanticContext` for analysis and `CompilerContext` for code generation.

---

## 1. SemanticContext (Analysis Phase)

Defined in `inc/mylang/semantic/semantic_internal.h`, this context tracks ownership, scopes, and types during the semantic walk.

### Key Fields
- **Scope Tracking**:
    - `scope_depth`: Current nesting level of blocks.
    - `function_depth`: Current nesting level of functions (lambdas).
- **Bindings**:
    - `bindings[256]`: Table of active variable/parameter bindings.
    - `binding_count`: Number of active bindings.
- **Type Information**:
    - `enum_types[128]`: List of defined enum type names.
    - `enum_values[512]`: Mapping of enum member names to their resolved numeric values.
    - `user_types[256]`: List of defined struct and typedef names.
- **Error Reporting**:
    - `filename`: Current source file being analyzed.
    - `error_count`: Total semantic errors encountered.

### Binding State (`SemanticBinding`)
Each variable tracked in `SemanticContext` maintains:
- `is_copy`: Whether the type has copy semantics.
- `moved`: Flag indicating if the value has been moved.
- `shared_borrow_count`: Number of active shared references (`&`).
- `mutable_borrow_active`: Flag indicating if a mutable reference (`&mut`) is active.
- `decl_loc` / `move_loc` / `borrow_loc`: Source locations for diagnostics.

---

## 2. CompilerContext (Code Generation Phase)

Defined in `inc/mylang/backend/codegen_internal.h`, this context manages assembly emission, symbol tables, and local variable offsets.

### Key Fields
- **Symbol Tables**:
    - `structs`: Information about struct layouts (offsets, sizes).
    - `typedefs`: Mapping of aliases to base types.
    - `func_sigs`: Function signatures (parameter counts, variadic status).
    - `globals_info` / `locals_info`: Metadata for global and local variables.
- **String Interning**:
    - `strings`: Table of string literals used in the program to be emitted in the data section.
- **Label Management**:
    - `label_counter`: Used to generate unique assembly labels for control flow (`.L1`, `.L2`, etc.).
    - `return_label`: Current function's exit point label.
- **Emission Buffers**:
    - `data_sb`: `StringBuilder` for collecting static data/globals.
- **Function/Import Tracking**:
    - `defined_funcs`: List of functions defined in the current module.
    - `imports`: List of functions imported from other packages.
    - `current_func`: Pointer to the AST node of the function currently being emitted.

---

## 3. Context Lifecycle

1.  **Parsing**: The parser uses global state (tables for types/structs) which is later synchronized with the contexts.
2.  **Semantic Analysis**: A `SemanticContext` is initialized. The `semantic_walk_ast` function traverses the AST, populating bindings and checking ownership/type rules.
3.  **Code Generation**: A `CompilerContext` is initialized.
    - **Toplevel Collection**: The compiler first walks the AST to collect struct definitions, global declarations, and function signatures.
    - **Emission**: The compiler walks the AST again to emit assembly for functions and data, using the collected metadata to calculate stack offsets and resolve types.
4.  **Cleanup**: `cleanup_codegen_context` is called to free allocated memory within the context.
