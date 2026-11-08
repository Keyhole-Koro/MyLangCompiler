# Source filename modifiers

MyLang source files use `.mln` as the single base extension. Optional filename
segments before `.mln` select syntax features and semantic policies.

## Canonical forms

```text
main.mln
heap.unsafe.mln
page.dom.mln
page.dom.unsafe.mln
ui.model.mln
schema.contract.mln
serial_rx.test.mln
serial_rx.unsafe.test.mln
page.dom.test.mln
```

The canonical order is:

```text
<name>.<syntax modifiers>.<semantic policy modifiers>.<role marker>.mln
```

`dom` enables DOM expression syntax. `unsafe` allows raw-pointer operations;
every other source is checked. The two axes are independent, so DOM syntax
can be compiled checked or unsafe. `contract` and `test` are optional, mutually
exclusive final role markers; neither changes the compiler profile. `test` is
consumed by MyLangTester. Repository boundary checks enforce that contract
sources contain declarations rather than implementations.

`model` marks a declaration file: the lexer reads its expansion, which is
ordinary checked source (`docs/design/mylang-model.md` in MyComputer). It takes
no other modifier.

An import names `fs.mln` whether the file is `fs.mln`, `fs.unsafe.mln` or
`fs.model.mln`. Both a plain and an unsafe file of one name is an error.

A checked source may not spell a raw pointer type, and it may call a function
of an `.unsafe.mln` file only if that function is marked `@safe`. Assembly
imports are unsafe code. The only exception is a pointer field of a
`.contract.mln` record, which describes a wire format.

## Rejected forms

```text
page.unsafe.dom.mln # syntax modifiers must come first
page.safe.mln       # `safe` was removed: checked is the default
page.dom.dom.mln    # duplicate modifier
page.web.mln        # unknown modifier
page.mlx            # legacy extension is not supported
```

There is intentionally no `.mlx` compatibility mode. DOM syntax is a native
MyLang frontend feature rather than a source-to-source preprocessing stage.

## Driver behavior

The driver resolves the filename before parsing and reports the selected source
profile. DOM tokens in a plain `.mln` or `.unsafe.mln` file are rejected with a
source-positioned diagnostic requiring `.dom.mln`.

```text
page.dom.unsafe.mln
        -> syntax = DOM
        -> safety = unsafe
```

The parser consumes the syntax profile. Semantic passes consume the safety
profile. Neither subsystem should inspect the source filename directly.

DOM nodes are lowered from extension AST nodes to core MyLang AST nodes. The
normal semantic and code-generation pipeline then processes the lowered tree;
no generated `.mln` intermediary is part of normal compilation.

## Checked and unsafe sources

A checked source (no `unsafe` modifier) reports each raw-pointer operation
with warning W0003:

- dereferencing a raw pointer: `*p`, `p->x`, `p[i]`
- pointer arithmetic: `p + n`, `p - n`
- a cast to or from a raw pointer: `(u8 *)p`, `(i32)p`, `(T *)address`
- keeping a borrow as a raw pointer or an integer address: `T *p = &x;`,
  `Holder { p: r }`, `return r;` from a function declared to return `T *`

A `borrow` and an array are not raw pointers: `r.x` through a
reference and `arr[i]` on an array are checked code. Taking an address,
`&x`, is a borrow. A file reports its first eight operations where they are
and the rest as one count.

The operations belong in `name.unsafe.mln` files, kept small, which give the
rest of the program values, references, and Options rather than pointers to
dereference. W0003 is a warning while the existing sources move over; it
becomes an error once they have.

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
which is replaced by the root node's id. A generated local has the type the
called function returns: `i32` above, or a nominal id type (imported by the
source) when the package's elements return one.

A `case` arm runs only when it is chosen, so an element in one is lowered inside
the arm's own block: write the arm as a statement expression,
`Ok(v) -> ({ return <Label text={v} />; })` or `1 -> ({ yield (<A />); })`, and
the element is built only when that arm runs. An element that is itself an
arm's value would be hoisted ahead of the whole `case` and built whichever arm
runs, so it is an error.

Because tags are function names, adding an element means adding a function to
the imported package, and an event handler is simply a parameter (`onClick`
above). A tag with no matching function, a property with no matching parameter,
and a parameter with no matching property are all compile errors reported
against the callee's signature -- except that a parameter with a
`= literal` default (see grammar.md, "Default parameters") may be left out,
in which case the default is passed.

A *handler property* -- any parameter named `on` plus a capital letter
(`onClick`, `onChange`, `onTick`) -- is handled by the compiler rather than the
callee. `onClick={c.click}`, where `c` is a local or parameter of a type with
that method, passes the method itself as the function type the callee declares
for that parameter: the calling convention ignores trailing arguments, so the
method takes the values that type carries, in order, or fewer of them. The
method must take its receiver by pointer or reference. A plain local function
with fewer than three parameters is wrapped so the event's words land in the
right slots, and the wrapper converts them to the types the function declares.
A parameter taken by reference is an error. Any other value is passed through
unchanged. See grammar.md, "Attributes and annotations".

```text
i32 (Counter c) view() {
    return <Window title="Counter" w={400}>
        <Button text="Click me" onClick={c.click} />
    </Window>;
}

i32 __dom0 = dom.Window("Counter", 400, 200);   // h defaulted
i32 __dom1 = dom.Button("Click me", 0, 0, 90, 34, Counter__click);
dom.append_child(__dom0, __dom1);
return __dom0;
```
