# MyLangCompiler agent guidance

This file applies to work inside `toolchain/MyLangCompiler`. It contains
agent workflow and implementation guardrails; the compiler's language and
frontend specifications remain under `docs/`.

## Validation

Run the component fixtures after frontend, semantic, parser, or codegen work:

```bash
make test-component
```

Run the emulator-backed compiler cases for ABI and generated-code changes:

```bash
make test-e2e
```

The full compiler build is `make -j2`. Keep compiler warnings clean. Do not
change an expected value merely to hide a regression.

## Frontend and module-resolution guardrails

The module-resolution design is in
[`docs/module-resolution.md`](docs/module-resolution.md).

In particular:

- a compilation owns one frontend session and module graph;
- `.mln` sources are cached by canonical path and parsed once per session;
- `.masm` imports remain linker-visible imports and are not parsed as MyLang;
- symbol visibility follows the written import form;
- module-owned AST and metadata must outlive temporary parser contexts that
  produced them;
- parser, generic lowering, DOM signature collection, semantic analysis, and
  code generation must not reintroduce independent source rescans;
- ownership of borrowed versus owned AST data must be explicit in headers and
  cleanup code.

Prefer a small internal API or compatibility wrapper when migrating a public
compiler entry point. Do not begin an unrelated parser-generator, type-map, or
ABI redesign as part of a module-resolution change.

## C implementation notes

Follow the existing subsystem boundaries and naming conventions. Add internal
declarations to the header used by the subsystem that owns them. Preserve the
existing aggregate ABI, package mangling, import visibility, and diagnostic
behavior unless the task explicitly changes them.

Before finishing, inspect the generated diff, run `git diff --check`, and
report any behavior that remains intentionally deferred in the technical docs.
