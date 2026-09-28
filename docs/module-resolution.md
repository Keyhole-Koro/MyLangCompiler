# Module Loading and Symbol Resolution

Status: implemented baseline. This document describes the technical design;
agent workflow belongs in `../AGENTS.md`.

## Scope

The compiler must load an imported `.mln` source once, retain its declarations
and export metadata, and let all frontend consumers query the same module
information. This removes independent source rescans from parser generic
imports, DOM signature discovery, semantic package checks, and codegen import
signatures.

This is infrastructure for later payload enums, `Result<T, E>`, pattern
matching, and a semantic `TypeMap`. It does not implement those language
features.

## Current problem

Historically, several phases resolved the same import independently:

- top-level parsing resolved paths and checked package declarations;
- generic import parsing re-lexed and parsed imported sources;
- DOM signature collection scanned tokens to infer function parameters;
- codegen scanned tokens to reconstruct exported function signatures;
- semantic analysis consulted parser default/global state for package prefixes;
- codegen separately re-inferred expression types.

These copies can disagree about package names, visibility, variadic metadata,
generic templates, or parameter names. Parser context lifetime also made it
possible for imported AST pointers to outlive the context that owned them.

## Ownership model

One frontend session owns the module graph for one compilation:

```text
FrontendSession
  ├── ModuleLoader
  │     └── ModuleGraph
  │           └── Module[]
  │                 ├── canonical_path
  │                 ├── package_name
  │                 ├── syntax AST
  │                 ├── declarations / exports
  │                 └── load state
  └── root ParserContext

Resolver
  └── reads ModuleGraph and applies import visibility
```

The conceptual data model is:

```c
typedef enum ModuleLoadState {
    MODULE_LOADING,
    MODULE_LOADED,
    MODULE_FAILED,
} ModuleLoadState;

typedef enum SymbolKind {
    SYMBOL_FUNCTION,
    SYMBOL_STRUCT,
    SYMBOL_TYPEDEF,
    SYMBOL_ENUM,
    SYMBOL_GLOBAL,
    SYMBOL_GENERIC_FUNCTION,
    SYMBOL_GENERIC_STRUCT,
} SymbolKind;

typedef struct ModuleSymbol {
    SymbolKind kind;
    const char *source_name;
    const char *link_name;
    ASTNode *declaration;
    int is_exported;
} ModuleSymbol;

typedef struct Module {
    char *canonical_path;
    char *package_name;
    ASTNode *program;
    ModuleSymbol *symbols;
    int symbol_count;
    ModuleLoadState state;
} Module;

typedef struct ModuleGraph {
    Module **modules;
    int module_count;
} ModuleGraph;
```

The exact C layout may evolve, but the ownership and visibility semantics are
part of the design.

## Required invariants

1. The cache key is the canonical source path, never the spelling of the
   import string.
2. A canonical `.mln` path is lexed and parsed at most once per frontend
   session.
3. `MODULE_LOADING` is detected before recursively loading an import cycle.
   Cycles must not recurse indefinitely; unresolved symbols are diagnosed at
   the point where they are required.
4. A present `.mln` file that fails to load or parse is a compiler diagnostic,
   not a silent fallback to a linker symbol.
5. `.masm` and other linker-visible imports are not parsed as MyLang modules.
6. `@name/...` imports use the project's `[alias]` entries from `mylang.toml`
   (or the compiler's repeatable `--alias @name=path` option); their targets are
   canonicalized before entering the module graph.
7. Module-owned AST and metadata remain valid until the session destroys the
   graph. Resetting a temporary parser context must not leave dangling module
   pointers.
8. AST cloning is limited to the boundaries that require a concrete generic
   specialization. The owner and freeing phase must be explicit.

## Import and visibility semantics

- `import { foo } from "x.mln";` exposes only the named exported symbol.
- `import foo from "x.mln";` is a package import when the target declares
  `package foo;`; otherwise it is a single-symbol import.
- A package import exposes exported symbols as `foo.bar()` and preserves the
  existing package-qualified link-name convention.
- `import foo;` remains the path-less linker/package import form.
- An exported method travels with its exported receiver type; importing the
  type provides the method prototype needed for resolution.
- Non-exported declarations and generic templates remain invisible to
  importers.

The resolver provides, at minimum:

- target package name;
- exported declaration for a source name;
- link name;
- function parameter names and types;
- parameter count and variadic metadata;
- exported generic function and struct templates;
- visibility under the selected import form.

## Phase responsibilities

### ModuleLoader / ModuleGraph

Own session initialization and destruction, path resolution, canonicalization,
cache lookup, `.mln` parsing, package metadata, export metadata, load failures,
and cycle state. The same import-path resolver is also used when emitting a
dependency manifest for non-MyLang imports such as `.masm`; those files are
recorded but are not parsed as modules.

### Resolver

Answer declaration and signature queries using the graph. It is not a complete
name-resolution or type-checking pass.

### Generic import lowering

Obtain exported templates from the cached module. Clone only when importing
translation-unit specialization requires an owned AST copy.

### DOM signature collection

Use parsed declarations and parameter metadata. Do not infer parameter names by
scanning tokens. Preserve local-function precedence over imported functions.

### Code generation

Register imported signatures and variadic metadata from resolver/module data.
Do not reconstruct them by lexing imported source again.

### Semantic analysis

Receive package-import and resolved-symbol information explicitly instead of
reading a parser singleton or default parser context.

## Session lifecycle

The intended pipeline is:

```text
frontend_session_init
  -> load/parse root module
  -> resolve imports
  -> specialize generics
  -> lower DOM and function literals
  -> rewrite names
  -> semantic analysis
  -> code generation
frontend_session_destroy
```

Existing public wrappers may remain while session-aware internal APIs are
introduced. The migration must not make semantic or codegen depend directly on
parser singleton state.

## Deferred work

The following are intentionally outside this design:

- payload enums and tagged unions;
- `Result<T, E>` implementation and case pattern binding;
- aggregate-return ABI redesign;
- type annotations on every AST node;
- complete removal of codegen `infer_expr_type()` in favor of `TypeMap`;
- parser-generator or CST replacement;
- Go-style struct methods.

The next type-analysis phase may introduce `TypedNode` and `TypeMap`, but it
must consume the same session/module ownership model.

## Verification

The module-resolution test set must cover:

- repeated imports and equivalent relative paths sharing one module;
- import cycles terminating without infinite recursion;
- package names, export visibility, and mangled link names;
- symbol-list imports hiding unspecified symbols;
- exported and non-exported generic templates;
- DOM signatures using AST parameter metadata;
- `.masm` imports bypassing the MyLang parser;
- session destruction without double-free or use-after-free;
- isolation between independent frontend sessions.

The existing compiler regression commands remain required:

```bash
make test-component
make test-e2e
```

Completion means every `.mln` import is loaded once per session, all relevant
phases use the same resolver/module metadata, import token scans are gone, and
existing `.masm` behavior and diagnostics remain compatible.
