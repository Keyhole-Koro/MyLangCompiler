# MyLang Containers: Queue and Map

**Status: design proposal. Not implemented.** Containers are ordinary MyLang
library types built on cross-module generics (`docs/generics.md`) and receiver
methods (`docs/methods.md`). They are not compiler builtins.

## 1. Position

The compiler carries no container vocabulary. Consequently:

- container bugs are fixed in `std/queue.mln` or `std/map.mln`;
- adding a later `Set<T>` does not add an AST node or backend path;
- the same generic and method mechanisms remain available to user libraries.

`std/queue.mln` is not published during the module-local implementation
milestone. A standard-library generic is useful only after imported template
bodies can be instantiated and duplicate generated functions can be coalesced
by the linker.

## 2. Storage and lifetime

MyLang currently has neither a heap allocator nor deterministic destruction.
The first containers therefore use caller-supplied storage. The caller owns the
arrays for at least as long as the container, and the container neither
allocates nor frees them.

```mylang
mut i32 storage[16];
mut Queue<i32> queue;
if (!queue_init<i32>(&mut queue, storage, 16)) return 1;

queue.push(42);
mut i32 value;
if (queue.pop(&mut value)) {
    // use value
}
```

`queue_init` remains a free function in v1 because MyLang has no established
rule for borrowing an uninitialized value as a method receiver. A later
associated-function or constructor feature can improve initialization without
changing the operational method API.

When an allocator arrives, an allocating constructor can be added alongside
the storage-taking initializer. Existing container operations need not change.

## 3. Queue<T>

`Queue<T>` is a fixed-capacity ring buffer and the first generic standard type.

```mylang
package std;

export generic<T>
struct Queue {
    T *buf;
    i32 cap;
    i32 head;
    i32 len;
};

export generic<T>
bool queue_init(ref mut Queue<T> queue, T *storage, i32 cap) {
    if (cap <= 0) return false;
    queue->buf = storage;
    queue->cap = cap;
    queue->head = 0;
    queue->len = 0;
    return true;
}

export generic<T>
i32 (ref Queue<T> self) len() {
    return self->len;
}

export generic<T>
bool (ref mut Queue<T> self) push(T value) {
    if (self->len == self->cap) return false;
    mut i32 slot = self->head + self->len;
    if (slot >= self->cap) slot = slot - self->cap;
    self->buf[slot] = value;
    self->len = self->len + 1;
    return true;
}

export generic<T>
bool (ref mut Queue<T> self) pop(ref mut T out) {
    if (self->len == 0) return false;
    *out = self->buf[self->head];
    self->head = self->head + 1;
    if (self->head == self->cap) self->head = 0;
    self->len = self->len - 1;
    return true;
}
```

`pop` cannot return `T` directly because an unconstrained `T` has no universal
empty value. It reports success as `bool` and writes the value through `out`.
Failed `push` and `pop` operations leave the queue unchanged.

`queue_init` returns false and leaves the destination untouched when `cap <= 0`.

## 4. Map<K, V>

Map follows Queue, after typed function values are designed. It uses open
addressing with linear probing over caller-supplied key, value, and slot-state
arrays.

```mylang
export generic<K, V>
struct Map {
    K *keys;
    V *values;
    u8 *states;
    i32 cap;
    i32 len;
    // Typed hash/equality callbacks; exact syntax belongs to the
    // function-value proposal and is intentionally not guessed here.
};
```

Required operations are:

```mylang
map_init<K, V>(...);
map.set(key, value);       // bool: false when no insertion slot exists
map.get(key, &mut value);  // bool: false when absent
map.has(key);              // bool
map.del(key);              // bool: false when absent
map.len();                 // i32
```

Hash and equality callbacks are not represented as raw `i32` handles. Although
indirect calls already exist in code generation, untyped handles would let a
wrong signature corrupt execution. `Map<K,V>` is gated on function-value type
syntax that can express at least `hash(K) -> u32` and `eq(K, K) -> bool`.

Parallel arrays avoid depending on currently unverified array-of-struct copy
behavior. An entry-struct representation can follow once aggregate array reads,
writes, and moves have dedicated tests.

## 5. Methods and indexing

Queue and Map use receiver methods described in `docs/methods.md`; methods are
not mere parser sugar because resolving `value.method` requires the receiver's
semantic type. They lower to ordinary generated functions before codegen.

Map subscripting remains deferred:

```mylang
map[key]
```

The parser currently lowers every index expression immediately to pointer
arithmetic (`parser_expr_primary.c`). Supporting type-directed indexing first
requires an `AST_INDEX` node and a later lowering pass. Plain `map.get` and
`map.set` cover the v1 API.

## 6. Testing

Queue tests cover:

- empty pop and full push, including unchanged state on failure;
- FIFO order and ring-buffer wraparound;
- capacity one;
- mutable-receiver rejection on an immutable queue;
- `Queue<i32>` and `Queue<char*>` imported from `std` in one program;
- the same instantiation used from two modules and linked once.

Map tests additionally cover probing over tombstones, overwrite without length
growth, absent lookup/deletion, callback signature errors, and full-table
termination.

## 7. Deferred questions

1. Allocating constructors and destruction, after allocator/drop semantics.
2. Aggregate-valued elements, after struct copy-through-pointer behavior is
   specified and tested.
3. `map[key]`, after type-directed `AST_INDEX` lowering.
4. Method type parameters independent of the receiver type.
