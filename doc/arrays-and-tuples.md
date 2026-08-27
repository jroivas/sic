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

Tuples are immutable after creation. A deferred declaration is allowed
(`tuple tmp;` then `tmp = tuple(…)`).

## Swap

The `<>` operator swaps two same-typed lvalues, including array elements — see
[language basics](language-basics.md#swap--):

```sic
int arr[3] = { 10, 20, 30 };
arr[0] <> arr[2];              // { 30, 20, 10 }
```

Next: [modules](modules.md).
