# Lambdas

SIC has C++-style lambda expressions — inline, anonymous functions, handy for
callbacks and small local helpers.

```sic
auto sq = [](int x) { return x * x; };
sq(10);                                  // 100
```

The form is `[captures](params) -> ret { body }`. The `-> ret` is optional — the
return type is inferred from the body — and there is a concise expression-body
sugar `=> expr`, equivalent to `{ return expr; }`:

```sic
auto add = [](int a, int b) => a + b;
add(20, 22);                             // 42
```

## Captureless lambdas are function pointers

A lambda with an empty capture list `[]` captures nothing, so it is *exactly* a
function: it lifts to an ordinary top-level function and the expression evaluates
to a plain function pointer. There is no runtime cost and no hidden allocation, so
it drops straight into a function-pointer variable or any C API that takes a
callback:

```sic
int (*dec)(int) = [](int x) { return x - 1; };
dec(43);                                 // 42

#include <stdlib.h>
int a[5] = { 5, 2, 8, 1, 3 };
qsort(a, 5, sizeof(int),
      [](const void *x, const void *y) { return *(const int*)x - *(const int*)y; });
// a is now { 1, 2, 3, 5, 8 }
```

Because the value is a function pointer, `auto fn = […]` gives `fn` the type
`ret(*)(params)`, and calling `fn(args)` works like any function pointer.

## Captures & currying (planned)

A non-empty capture list will bind names from the enclosing scope, reusing SIC's
[reference model](memory-and-ownership.md): `[x]` by value (a copy), `[@y]` by
shared borrow, `[@mut y]` by mutable borrow. A capturing lambda is a closure —
code plus a reference-counted environment — so it can be returned and stored,
which is what makes currying fall out naturally:

```sic
auto add = [](int a) { return [a](int b) { return a + b; }; };
add(2)(3);                               // 5   (planned)
```

Capturing closures are not implemented yet. Today only captureless `[]` lambdas
are accepted; a non-empty capture list is a compile error.

Next: [atomics](atomics.md).
