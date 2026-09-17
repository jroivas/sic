# Containers — `dict`, `list`, `set`

SIC has three built-in generic containers. Each is an opaque, heap-backed handle
that is created empty on declaration, grows on demand, and is **freed
automatically at scope exit** — you never `free` one. String and struct elements
they hold are owned (deep-copied and reclaimed with the container); reading one
out shares it safely.

The handle is **reference-counted**, so a container can be returned from a
function, shared through several bindings, stored inside another container, or
captured by a closure — it stays alive as long as any owner holds it and is freed
once, when the last one is dropped:

```sic
list<int> build() { list<int> xs; xs.add(1); xs.add(2); return xs; }   // safe to return
```

(Reference cycles — a container that transitively contains itself — are not
reclaimed; that's the usual refcounting trade-off. Break a cycle with a
[`weak<T>`](../sic.md#weak-references) reference, which points at a container
without keeping it alive.)

## `dict` — hash map

`dict<K, V>` maps keys to values; bare `dict` is `dict<any, any>`. Subscript to
read and write; a missing key reads back as a zero value; `del` removes an entry:

```sic
dict<string, int> ages;
ages["alice"] = 30;
ages["bob"]   = 25;
int a = ages["alice"];        // 30
int missing = ages["nobody"]; // 0 (absent → zero)
del ages["bob"];              // remove; ages["bob"] now reads 0
usize n = ages.size;          // entry count (also .length)
```

Keys may be integers or strings; string keys and string/struct values are copied
and owned by the dict. A `dict<K, any>` stores each value with its runtime type, so
one map can hold mixed value types:

```sic
dict<int, any> m;
m[1] = 42;  m[2] = "hi";  m[3] = 3.14;
```

The implementation is a CPython-style insertion-ordered table, so iteration order
is stable and deletions keep the surviving order intact.

## `list<T>` — growable array

```sic
list<int> xs;
xs.add(10);                   // also .push / .append
xs.add(20);
int a = xs[1];                // 20
xs[1] = 99;                   // update in place
usize n = xs.size;            // element count (also .length)
```

Elements are owned by the list — string and struct elements are copied and freed
with it (and reclaimed when overwritten via `l[i] = …`). `l[i].field` and `l[i][j]`
work for aggregate elements.

## `set<T>` — hash set

`set<T>` holds unique elements (a `dict<T, bool>` under the hood); bare `set` is
`set<any>`:

```sic
set<string> tags;
tags.add("red");
tags.add("red");              // already present — no effect
bool has = tags.contains("red");   // (also .has)
tags.remove("red");
usize n = tags.size;
```

The subscript form works too, since a set is a dict: `s[x] = true` adds, `s[x]`
tests membership, `del s[x]` removes.

## Iteration

Range-`for` walks each container (see [methods & iterators](iterators.md)):

- a **`dict`** yields `tuple(key, value)`,
- a **`set`** yields each element,
- a **`list`** yields `tuple(index, value)`.

```sic
for (tuple kv : ages)  { string k = kv[0]; int v = kv[1]; }
for (int x : primes)   { … }              // set of int
for (tuple iv : xs)    { usize i = iv[0]; int v = iv[1]; }
```

`.keys` / `.values` project one side into a `list` you can iterate (or keep):

```sic
for (string name : ages.keys)   { … }
for (int    age  : ages.values) { … }
list<string> names = ages.keys;           // a real, indexable snapshot
```

A `list`'s `.keys` are its indices `0 .. length-1`; its `.values` are the elements.

## `new` and pointers

A container may be heap-allocated with `new`. Because a container handle is
*already* a pointer, a pointer-to-handle is the same thing as the handle — `dict d`
and `dict *p` are interchangeable, and both are accessed directly (no deref) and
freed automatically:

```sic
dict<int,int> d;
dict<int,int> *p = new dict<int,int>;    // same handle type as `d`
d[5] = 10;
p[5] = 10;                                // no deref needed
```

`new list<T>` and `new set<T>` work the same way. Passing a container to a function
passes the handle by value, so the callee mutates the caller's container:

```sic
void fill(dict<int,int> d) { d[1] = 10; }
dict<int,int> m;
fill(m);                      // m now has {1: 10}
```

## `weak<T>` — non-owning references

A `weak<T>` (where `T` is a `list`/`dict`/`set`) refers to a container *without*
keeping it alive. Read it back with `.get`, which upgrades to a normal handle while
the container is still live, or reads as an empty/zero container once it is gone:

```sic
list<int> data; data.add(1); data.add(2);
weak<list<int>> w = data;      // observes `data`, does not own it
list<int> live = w.get;        // usable while `data` is alive
```

Its usual home is a **struct field** — the back-pointer that breaks an ownership
cycle, so the strong links form a tree and the weak links close the loops (an
observer that refers to its subject, a child that refers to its parent):

```sic
struct Observer { weak<list<int>> subject; };
struct Observer o;
o.subject = data;              // weak — `data`'s lifetime is unaffected
o.subject.get;                 // the live list, or empty once `data` is dropped
```

A closure captures a container weakly with `[weak x]`, for the same reason — so a
closure kept inside the container it observes does not keep that container alive.
Inside the body the captured name is a weak reference, upgraded with `.get`:

```sic
auto observe = [weak data]() -> int { return (int)(data.get).size; };
```

Reassigning a `weak` binding or field drops its old observation; when the observed
container is freed, every `weak` to it reads back dead.

Next: [modules](modules.md).
