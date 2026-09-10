# Memory & ownership

SIC manages non-primitive values — `string`, and allocations made with `new` —
with deterministic reference counting and move/borrow semantics, so you get
memory safety without a garbage collector and without manual `free`. Primitive
values (`int`, `float`, pointers created the C way) keep plain C behavior.

## The model

For **non-primitives** (`string`, arrays/allocations, tuples, `bigint`/`fixed`):

- **Move on return.** Returning a value transfers ownership out of the function.
  Only the small wrapper descriptor is copied; the underlying buffer is *not*
  duplicated. If a local isn't returned, it's released at scope exit.
- **Borrow on pass.** Passing a value to a function borrows it — the callee reads
  it, the caller keeps ownership. No contents are copied.
- **Reference-counted sharing.** Copying an owned value shares one buffer and
  bumps its count; each holder releases at scope exit; the buffer frees when the
  count reaches zero.

For **primitives**, assignment and passing simply copy the value, exactly as in C.

```sic
string build(string base) {
    string t = base + "-built";   // owned local, refcount 1
    return t;                     // moved out — buffer not copied
}

int main() {
    string a = "Hello";
    string b = a + " world";      // owned, rc = 1
    string c = b;                 // copy → shared (rc = 2)
    string d = b[6:];             // slice keeps b's buffer alive (rc = 3)
    // b, c, d all valid; the buffer frees once, at scope exit.
    return 0;
}
```

You never *need* to call `free`/`del` on a `string`; releases are automatic and
safe against double-free and use-after-free.

### Early release with `del`

You *may* drop one reference early with `del`. It decrements the refcount
(freeing the buffer if this was the last reference) and invalidates that one
variable in place — other copies keep their own reference and stay valid until
their scope ends:

```sic
string a = base + "lo";   // owned, rc = 1
string b = a;             // shared copy, rc = 2
del a;                    // a's reference dropped (rc = 1); a is now empty
// b is still "…lo"; the buffer frees when b's scope ends.
```

After `del a`, `a` reads as an empty string. `del` is safe on a non-owning view
too (there is nothing to free; the instance is still invalidated).

## Copy-on-escape

A `string` built from a *local* buffer is a zero-copy view — until it would
escape the frame, at which point it is copied automatically so it can't dangle:

```sic
#include <stdio.h>
string label(int n) {
    char b[16];
    snprintf(b, 16, "%d", n);
    string s = b;      // a view of the local buffer `b` — no copy yet
    return s;          // `b` is about to die → an owned copy is made here
}
```

This is the default; you don't write `.dup`. The rules follow the buffer's
lifetime:

- View of a **local** stack buffer (or a `bigint`/`fixed` `.str`, which is freed
  at scope exit) → **copied on return**.
- Once the value becomes owned (e.g. after `s = s + "!"`), returning it just
  **moves** it — no second copy.
- A borrowed `string`/`char*` argument returned as-is is **not copied** (the
  caller's data outlives the call).

So `char b[10]; …; string s = b; return s;` returns a correct owned copy, while
`string fun(string p) { return p; }` copies nothing.

## `defer`

`defer <statement>;` runs the statement on **every** exit from the enclosing
scope (fall-through, `return`, `break`, `continue`), in last-in-first-out order —
handy for cleanup right next to the resource it pairs with:

```sic
int read_file(const char *path) {
    int *buf = new int(1024);
    defer del buf;               // runs however this function returns
    // … use buf …
    if (error) return -1;        // `del buf` runs here
    return 0;                    // and here
}
```

The deferred statement is evaluated at each exit site (a scope guard), not
captured at the `defer` point.

## `new` and `del`

`new` and `del` are the memory-safe replacements for `malloc`/`free`. `new T`
allocates one `T`; `new T(n)` allocates `n` of them. The returned pointer is
**fat** — the allocation carries its size and a reference count in a header — so
indexing is bounds-checked:

```sic
int *p = new int(4);   // room for 4 ints
p[0] = 10;
p[3] = 40;             // ok
p[10] = 0;             // bounds check fails → runtime exception (abort)
del p;                 // decrements refcount; frees at 0 (del NULL is a no-op)
```

A failed bounds check aborts the program (or is a compile error when provable).
`del` frees only when the last reference is dropped, so it's safe even if a
reference was handed to another owner (e.g. a thread) that outlives this scope.

## Managed structs — assignment shares

A struct with a destructor `~S()` (see
[constructors & destructors](iterators.md#constructors--destructors)) is a
*managed* value: assigning one to another (`v = other`) is not a blind byte copy.
It runs `v`'s destructor first (releasing `v`'s old resources), copies `other`,
then **retains the resources the destructor owns** — so `v` and `other` share
them and the shared block is freed exactly once, when the last of them is
destroyed:

```sic
struct Box {
    int *p;
    Box()  { p = new int(1); }
    ~Box() { del p; }             // owns `p`
};

Box a;
Box b;
a = b;            // a's old block freed; a shares b's (refcount 2)
// scope exit: ~a and ~b both run `del p`, freeing the shared block once
```

"The resources the destructor owns" is derived from the destructor itself — the
fields it `del`s. A **borrowed** pointer field (one `~S()` leaves alone — an
iterator's cursor, a parent back-pointer, a borrowed C string) is copied as-is
and never touched, so it isn't corrupted. A self-assign (`v = v`) is a no-op.

For a field you want *shared* this way, allocate it with `new`/`del` (a `free()`-d
malloc pointer has no reference count to share).

## `@` references

A reference, written `@T`, is a **scoped, reference-counted borrow** of a
`new`-allocated value. Taking one with `@expr` retains the referent for the
current scope and releases it at scope exit — so a reference can never point to
freed memory. At the machine level a reference is just the underlying pointer;
inside the callee you use it like an ordinary (immutable) pointer:

```sic
int slen(@char *s) {          // reference parameter
    int i = 0;
    while (s[i]) i++;
    return i;
}

char *name = new char(12);
memcpy(name, "hello world", 12);
int n = slen(@name);          // @name retains `name` across the call
```

- `@mut T` is a **mutable** reference and is **exclusive**: while a `@mut` borrow
  is live, no other borrow (read or write) of that variable is allowed. Prefer
  plain `@` (shared, read-only) — many readers are fine, but only one writer.
- Passing a reference onward forms a new reference and bumps the count.
- Returning a reference to a **local** is rejected; returning a reference
  parameter back to the caller is fine (its scope simply extends).

```sic
void upper0(@mut char *s) { s[0] = s[0] - 32; }   // exclusive mutable borrow
```

References are checked at compile time (readers-xor-writer, no `@NULL`, no
returning a reference to a local) and at run time (bounds checks on access).

Next: [enums & pattern matching](enums-and-matching.md).
