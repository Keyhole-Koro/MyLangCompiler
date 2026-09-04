# MyLang Receiver Methods

**Status: design proposal. Not implemented.** MyLang methods follow Go's
composition-oriented model: methods are functions declared outside a struct,
with an explicit receiver and no inheritance. They are implemented as
type-checked calls to ordinary functions, not runtime dispatch.

## 1. Goals and non-goals

Goals:

- `value.method(args)` for struct values and generic struct instantiations;
- explicit shared or mutable receiver contracts;
- methods declared outside the struct definition;
- static resolution and zero runtime dispatch overhead;
- exported methods that follow their receiver type across module boundaries.

The first version has no inheritance, interfaces, virtual dispatch, overloads
by parameter list, associated functions, or method-specific type parameters.

## 2. Declaration and call syntax

The receiver appears between the return type and method name:

```mylang
i32 (ref Point self) x() {
    return self->x;
}

void (ref mut Point self) move(i32 dx, i32 dy) {
    self->x = self->x + dx;
    self->y = self->y + dy;
}
```

For a generic receiver, identifier arguments in the receiver type bind that
struct's type parameters for the whole method declaration:

```mylang
export bool (ref mut Queue<T> self) push(T value) { /* ... */ }
```

`Queue<T>` here is a receiver pattern, not a concrete instantiation. `Queue`
must name a generic struct and the number of identifiers must match its declared
parameters. Those identifiers are in scope in the return type as well:

```mylang
T (ref Queue<T> self) front() { /* ... */ }
```

As with a generic function return type, declaration-header lookahead discovers
the receiver parameters before parsing from the first token. A method does not
repeat type arguments on its name or at the call site; its concrete receiver
determines them.

Calls use ordinary postfix syntax:

```mylang
point.move(3, 4);
queue.push(42);
```

The compiler automatically forms the shared or mutable borrow required by the
declared receiver. A mutable receiver requires a mutable, uniquely borrowable
value. The explicit `self` name is scoped like the first parameter inside the
body.

## 3. Identity and lookup

A method is identified by:

```text
package + canonical receiver base type + method name
```

There is at most one method with a given name for a receiver type in v1; argument
types do not overload it. Methods may be declared only in the package that
defines the receiver type. This prevents unrelated packages from adding
conflicting methods to imported types.

Exported receiver types expose their exported methods. Importing the type makes
those method signatures available; generic methods also carry their complete
template AST under the rules in `docs/generics.md`.

## 4. AST and lowering

The parser must stop restricting postfix `(` to `AST_IDENTIFIER`. It preserves
a method call explicitly rather than guessing its target from syntax alone:

```c
AST_METHOD_CALL

struct {
    ASTNode *receiver;
    char *method_name;
    ASTNode **args;
    int arg_count;
} method_call;
```

Processing is:

```text
parse value.method(args)
        ↓
semantic resolves value's concrete type and checks receiver mutability
        ↓
method lowering inserts the receiver borrow and selects the generated function
        ↓
ordinary AST_CALL reaches codegen
```

For a generic receiver, instantiating `Queue<i32>` emits its concrete method
declarations before semantic analysis. The method call therefore resolves
against an ordinary `Queue<i32>` method signature; semantic analysis does not
need to reason about an unknown `T`.

## 5. Generated functions

Methods lower to ordinary functions whose generated name includes the canonical
receiver type. Conceptually:

```mylang
queue.push(42)
```

becomes:

```mylang
std__method__GN5_Queue_1_I32__N4_push(&mut queue, 42)
```

Public generic methods are marked `linkonce` and coalesced under the same rules
as other generic functions. Non-generic methods have one strong definition in
the receiver type's package.

## 6. Diagnostics

| Code | Meaning |
| --- | --- |
| `E0601` | Method receiver is not a struct type |
| `E0602` | Duplicate method name for the receiver type |
| `E0603` | Method is not defined for the receiver type |
| `E0604` | Mutable receiver requires a mutable, uniquely borrowable value |
| `E0605` | Method is declared outside the receiver type's package |

Normal argument-count and argument-type failures continue to use `E01xx` after
the implicit receiver is accounted for.

## 7. Testing

- shared and mutable receiver calls;
- rejection of a mutable method on immutable or already-borrowed storage;
- method lookup on two structs that use the same method name;
- chained postfix expressions where a method returns a struct;
- exported methods across an import boundary;
- generic receiver methods for two concrete types;
- a method declared in the wrong package;
- proof that method lowering leaves no `AST_METHOD_CALL` before codegen.
