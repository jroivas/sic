# Arrays & tuples

## Arrays

Arrays know their own extent. `.length` is the element count and `.size` the byte
size (element count × element size):

```sic
int v[5];
v.length;    // 5
v.size;      // 20   (5 × sizeof(int))
```

Use `.length` to iterate; use `.size` only when you actually mean bytes:

```sic
for (int i = 0; i < v.length; i++)
    v[i] = i;
```

### Concatenation

`+` concatenates two arrays. The result's `.length` is the combined count:

```sic
int a[5];
int b[5];
(a + b).length;             // 10

int c[10] = a + b;          // ok — declared size matches
// int c[7] = a + b;        // compile error: size mismatch
```

### Bounds checks

Indexing a fat pointer — one returned by `new` or bound to a `@` reference — is
bounds-checked at run time; an out-of-range access raises an exception:

```sic
int *p = new int(3);
p[10] = 1;                  // bounds check fails → abort
del p;
```

Plain C arrays follow C rules; see [memory & ownership](memory-and-ownership.md)
for `new`/`del` and references.

## Tuples

A tuple is a built-in, immutable, heterogeneous, fixed-size value — handy for
returning several values at once. The keyword `tuple` is used three ways:

```sic
tuple t = tuple(88, 66, 42);   // 1. pack (also the type: `tuple t;`)
t[0];                          //    index → 88
t[1];                          //    → 66

int a, b;
tuple(a, b) = get_two(42);     // 2. unpack into existing variables
```

A tuple-returning function infers its return type from the packed values:

```sic
tuple get_two(int x) {
    return tuple(x * 2, x * 3);
}
```

Elements may have different types; each element's type is fixed when the tuple is
created and checked on unpack:

```sic
tuple h = tuple(7, 3.5, 100);  // int, double, int
double d = h[1];               // 3.5
int    n = h[0];               // 7
```

Tuples are immutable after creation.

### Length

`.length` (alias `.size`) is a tuple's element count, read at run time:

```sic
tuple t = tuple(88, 66, 42);
t.length;                      // 3
```

A bare `tuple t;` is the **empty** tuple — `t.length` is `0` and it has no valid
element (any `t[i]` is an out-of-range error). It's a real binding you can assign
later; a reassignment adopts the new tuple (releasing the old one) and refines the
element types, so `t[i]` after `t = tuple(…)` is typed:

```sic
tuple t;                       // empty: t.length == 0
t = tuple("a", "b");           // now length 2; t[0] is a string
```

This is what lets a `string`'s [`split`](strings.md#search--split) report arity
`1` (separator absent) vs `2` (found) through `.length`.

### Static and dynamic tuples

A tuple's element types are **static** whenever the compiler can know them — a
`tuple(…)` value, a local initialized or assigned in straight-line code, a parameter
whose every call passes the same shape, a function whose every `return` agrees — and
then `t[i]` costs nothing extra. You can also spell the shape: `tuple<int, string>`.

Where the shape can't be known at compile time the tuple is **dynamically typed**:

- a struct field `tuple t;`,
- a parameter called with different shapes, or exported from a module,
- a local assigned different shapes inside a branch or loop,
- a `list<tuple>` / `dict<K, tuple>` holding several shapes,
- a function whose `return`s produce different shapes.

Every tuple records its shape at run time, so passing a static tuple where a dynamic
one is expected is free. Reading a dynamic tuple is checked:

```sic
struct S { tuple t; };
S s;
s.t = tuple(4, "pq");
int n = s.t[0];               // checked: element 0 must be an int
string w = s.t[1];            // checked: element 1 must be a string
int bad = s.t[1];             // run-time error: tuple element 1 is `string`, not `i32`
auto v = s.t[1];              // an `any` (no check until converted)
int a; string b;
tuple(a, b) = s.t;            // checks the arity, then each element
tuple<int, string> st = s.t;  // checks the whole shape once; `st[i]` is static after
```

The element must have exactly the target's type (no numeric conversion). A dynamic
index may be a run-time value. A static shape mismatch
(`tuple<int> x = tuple("a")`) is a compile error.

## Swap

The `<>` operator swaps two same-typed lvalues, including array elements — see
[language basics](language-basics.md#swap--):

```sic
int arr[3] = { 10, 20, 30 };
arr[0] <> arr[2];              // { 30, 20, 10 }
```

Next: [containers](containers.md).
