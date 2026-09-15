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

## Captures

A non-empty capture list binds names from the enclosing scope. `[x]` captures by
value — a copy taken when the closure is created:

```sic
int n = 100;
auto addn = [n](int x) { return x + n; };
addn(5);                                 // 105

int k = 1;
auto getk = [k]() { return k; };
k = 999;
getk();                                  // 1  (captured the value, not the variable)
```

A capturing lambda is a **closure**: code plus a reference-counted environment
holding the captured values, allocated on the heap and released automatically.
Because a closure can be returned and stored, **currying** works — a lambda that
returns a lambda capturing the outer parameter:

```sic
auto add   = [](int a) { return [a](int b) { return a + b; }; };
auto add10 = add(10);
add10(32);                               // 42
```

Current limits (planned to lift): captures are **by value** and limited to scalar
and pointer types; by-reference captures (`[@y]` shared, `[@mut y]` mutable),
capturing owned aggregates like `string`, and a nameable closure type
(`Fn<int(int)>`) are not implemented yet. Bind an intermediate closure to a
variable rather than chaining calls in one expression — `auto g = add(10); g(32)`,
not `add(10)(32)` — so its environment is released at scope exit.

Next: [atomics](atomics.md).
