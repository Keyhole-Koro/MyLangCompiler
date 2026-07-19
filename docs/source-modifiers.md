# Source filename modifiers

MyLang source files use `.mln` as the single base extension. Optional filename
segments before `.mln` select syntax features and semantic policies.

## Canonical forms

```text
main.mln
main.safe.mln
page.dom.mln
page.dom.safe.mln
```

The canonical order is:

```text
<name>.<syntax modifiers>.<semantic policy modifiers>.mln
```

`dom` enables DOM expression syntax. `safe` enables the strict memory-safety
profile. The two axes are independent, so DOM syntax can be compiled with or
without the strict policy.

## Rejected forms

```text
page.safe.dom.mln   # syntax modifiers must come first
page.dom.dom.mln    # duplicate modifier
page.web.mln        # unknown modifier
page.mlx            # legacy extension is not supported
```

There is intentionally no `.mlx` compatibility mode. DOM syntax is a native
MyLang frontend feature rather than a source-to-source preprocessing stage.

## Pipeline contract

The driver resolves the filename once and stores the result in the compilation
context:

```text
page.dom.safe.mln
        -> syntax = DOM
        -> safety = strict
```

The parser consumes the syntax profile. Semantic passes consume the safety
profile. Neither subsystem should inspect the source filename directly.

DOM nodes are lowered from extension AST nodes to core MyLang AST nodes. The
normal semantic and code-generation pipeline then processes the lowered tree;
no generated `.mln` intermediary is part of normal compilation.
