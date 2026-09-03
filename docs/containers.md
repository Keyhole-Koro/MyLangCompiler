# MyLang Containers: map and queue

**Status: design proposal. Not implemented.** This document describes how `map`
and `queue` become available in MyLang. It depends on `docs/generics.md`.

## 1. Position

The compiler carries no container vocabulary, for the same reason it carries no
DOM element vocabulary (`docs/source-modifiers.md`): a tag is a function, a
property is a parameter, and everything resolves like an ordinary identifier.
Containers follow that rule one step further — **`map` and `queue` are library
types written in MyLang**, made possible by generics rather than by special
cases in the parser or in code generation.

Consequences:

- No new AST node, no new code-generation path, no builtin like `__rest_len`.
- The compiler is not the place to fix a container bug; `std/map.mln` is.
- Adding `set` or `list` later costs a source file, not a compiler change.

## 2. The heap constraint

There is no heap. The target is a custom ISA with no libc, and `malloc` appears
nowhere in the language, the tests, or the runtime. There is also no `drop`
mechanism: nothing in `src/semantic/` releases a value at the end of its scope,
so an owning, self-allocating container would leak by construction.

The first version therefore uses **caller-supplied storage**. The caller owns
the backing arrays, they live in an ordinary local or global, and their lifetime
is the enclosing scope. Nothing allocates and nothing needs to be freed.

```mylang
i32 main() {
    mut i32 storage[16];
    mut Queue<i32> q;
    queue_init<i32>(&mut q, storage, 16);
    queue_push<i32>(&mut q, 42);
    return queue_pop<i32>(&mut q);
}
```

When an allocator does arrive, only `*_init` gains a sibling constructor. The
container types, their operations, and every call site above stay as they are.

## 3. queue

A fixed-capacity ring buffer.

```mylang
package std;

export struct Queue<T> {
    T *buf;
    i32 cap;
    i32 head;
    i32 len;
}

export void queue_init<T>(ref mut Queue<T> q, T *storage, i32 cap) {
    q->buf = storage;
    q->cap = cap;
    q->head = 0;
    q->len = 0;
}

export i32 queue_len<T>(ref Queue<T> q) { return q->len; }

export bool queue_push<T>(ref mut Queue<T> q, T v) {
    if (q->len == q->cap) return false;
    mut i32 slot = q->head + q->len;
    if (slot >= q->cap) slot = slot - q->cap;
    q->buf[slot] = v;
    q->len = q->len + 1;
    return true;
}

export T queue_pop<T>(ref mut Queue<T> q) { /* ... */ }
```

`queue` is deliberately the first container to build: one type parameter, no
hashing, no probing. It exercises the whole generics pipeline end to end while
staying small enough to review.

## 4. map

Open addressing with linear probing, over three caller-supplied parallel arrays:
keys, values, and slot states (empty / used / tombstone).

```mylang
export struct Map<K, V> {
    K *keys;
    V *vals;
    u8 *state;
    i32 cap;
    i32 len;
    i32 hash;   // see section 5
    i32 eq;     // see section 5
}

export void map_init<K, V>(ref mut Map<K, V> m, K *keys, V *vals, u8 *state,
                           i32 cap, i32 hash, i32 eq);
export bool map_set<K, V>(ref mut Map<K, V> m, K key, V value);
export bool map_get<K, V>(ref Map<K, V> m, K key, ref mut V out);
export bool map_has<K, V>(ref Map<K, V> m, K key);
export bool map_del<K, V>(ref mut Map<K, V> m, K key);
export i32  map_len<K, V>(ref Map<K, V> m);
```

`map_get` reports absence through its return value and writes the found value
through `out`, rather than returning a `V` that has no meaningful "missing"
value. There are no option types in the language, and inventing one for this is
out of scope.

Parallel arrays rather than an array of entry structs: arrays of structs have no
test coverage today (`tests/succeed/array/` covers scalars only), and this
design should not depend on unverified behavior. An entry-struct layout is a
straightforward follow-up once arrays of structs are exercised.

## 5. Hashing and equality

A map over an arbitrary `K` needs a hash and an equality function for `K`, and
MyLang has no traits to carry them. Indirect calls do work — a call through a
variable holding a function value is emitted by `gen_indirect_call()`
(`src/backend/codegen/codegen_call.c:85`) — but there is no function-pointer
*type* syntax, so a callback cannot yet be declared as a struct member with its
signature.

The first version therefore stores the two callbacks as `i32` handles passed to
`map_init`, and `std` ships the usual ones (`std_hash_i32`, `std_eq_i32`,
`std_hash_str`, `std_eq_str`). This is the weakest point of the design and it
should be revisited when function-pointer types exist; the map's API does not
change when it is, only the declared type of those two fields.

## 6. Syntax sugar, deferred

`m[key]` and `q.push(v)` are **not** part of this proposal. Both are blocked on
frontend work that is worth its own change:

- **`m[key]`** — the parser desugars every `a[i]` into `*(a + i)` as it parses
  (`src/frontend/parser/parser_expr_primary.c:78`), before any type is known, so
  a map subscript cannot be told apart from a pointer subscript. Enabling it
  means introducing an `AST_INDEX` node and moving the pointer desugaring into a
  later, type-aware pass. That refactor is behavior-preserving and should land
  on its own, with the existing array tests as its proof.
- **`q.push(v)`** — `parse_postfix()` accepts `(` only directly after an
  identifier (`parser_expr_postfix.c:41`), so method-call syntax does not parse
  at all today.

Plain calls (`map_set<char*, i32>(&mut m, k, v)`) are verbose but complete, and
they keep the container work independent of the parser refactor. Sugar can be
added later without changing the library.

## 7. Testing

- `tests/succeed/container/` and `tests/fail/container/`, using a fixture
  package under `tests/support/std/` in the same way `tests/support/dom/dom.mln`
  backs the DOM cases. The compiler test suite then stays self-contained.
- Cases worth pinning: wraparound push/pop, push into a full queue, probe past a
  tombstone, overwrite of an existing key, and a capacity-1 map.
- Two instantiations of the same container in one program, to confirm the
  mangled symbols do not collide.

## 8. Open questions

1. **Cross-module use.** v1 generics are module-local (`docs/generics.md`
   section 7), so `std/map.mln` cannot be imported until phase 2 lands. Until
   then containers are usable only within the file that defines them, which is
   fine for tests but not for real programs. This is the gating item for the
   feature being useful, and it depends on the MyComputer linker's handling of
   duplicate symbols.
2. **Callback typing.** Section 5.
3. **Allocation and release.** Section 2. Both an allocator and a `drop`
   mechanism are prerequisites for a self-managing container, and neither
   exists.
4. **Element width.** Everything is a 4-byte slot today (`SLOT_SIZE`,
   `inc/mylang/backend/codegen_internal.h:11`). Monomorphization gives real
   sizes, but struct-valued `V` also needs struct assignment and struct copies
   through pointers to be verified before it is promised.
