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

`dom` enables DOM expression syntax. `safe` selects the strict memory-safety
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

## Driver behavior

The driver resolves the filename before parsing and reports the selected source
profile. DOM tokens in a plain `.mln` or `.safe.mln` file are rejected with a
source-positioned diagnostic requiring `.dom.mln`.

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

## DOM lowering contract

The compiler carries no element vocabulary. Three rules define the lowering, and
everything they produce resolves like ordinary identifiers:

1. An element calls the function of the same name: `<Window .../>` calls `Window`.
2. A property is passed to the parameter of the same name, so source order is
   free: `<Button x={2} text="OK" .../>` fills `Button`'s `text` and `x`.
3. A child is attached with `append_child(parent, child)`.

```text
return <Window title="S" x={0} y={0} w={320} h={200}>
    <Button text="OK" x={20} y={40} w={100} h={30} onClick={h} />
</Window>;

i32 __dom0 = dom.Window("S", 0, 0, 320, 200);
i32 __dom1 = dom.Button("OK", 20, 40, 100, 30, h);
dom.append_child(__dom0, __dom1);
return __dom0;
```

Generated statements are hoisted ahead of the statement that held the element,
which is replaced by the root node's id. Node ids are `i32`.

Because tags are function names, adding an element means adding a function to
the imported package, and an event handler is simply a parameter (`onClick`
above). A tag with no matching function, a property with no matching parameter,
and a parameter with no matching property are all compile errors reported
against the callee's signature.
