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

A non-empty capture list binds names from the enclosing scope, reusing SIC's
[reference model](memory-and-ownership.md):

- `[x]` — captures `x`. A **scalar/pointer** is captured **by value** (a cheap
  copy); a larger value (**struct, `string`, `tuple`, container, …**) is captured
  **by reference**, avoiding a copy, so the closure sees its live value.
- `[@x]` — **shared borrow** (explicit): the closure reads `x`'s live value.
- `[@mut x]` — **mutable borrow**: the closure reads and writes the original `x`.

```sic
int n = 100;
auto addn = [n](int x) { return x + n; };   // by value
addn(5);                                     // 105

int k = 1;
auto getk = [k]() { return k; };             // by value — a snapshot
k = 999;
getk();                                      // 1

int sum = 0;
auto add = [@mut sum](int x) { sum += x; };  // mutable borrow — writes propagate
add(10); add(32);
sum;                                         // 42
```

A capturing lambda is a **closure**: code plus a reference-counted environment
holding the captured values (or, for a borrow, a pointer to the original),
allocated on the heap and released automatically. Because a closure can be
returned and stored, **currying** works — a lambda that returns a lambda
capturing the outer parameter:

```sic
auto add = [](int a) { return [a](int b) { return a + b; }; };
add(10)(32);                             // 42
```

## Naming a closure type — `Fn<ret(params)>`

A closure carries captured state, so it is not a plain function pointer. To name
one — as a parameter, a return type, or a variable — use `Fn<ret(params)>`:

```sic
int          apply(Fn<int(int)> f, int x) { return f(x); }
Fn<int(int)> adder(int n)                 { return [n](int x) { return x + n; }; }

apply([base](int x) { return x + base; }, 12);   // pass a closure with state
Fn<int(int)> a = adder(40);                       // store one
a(2);                                             // 42
```

A captureless lambda passed where an `Fn<…>` is expected is boxed into a closure
automatically, so an `Fn<int(int)>` parameter accepts both stateful closures and
plain `[](int x){…}` lambdas. (A plain `int(*)(int)` function-pointer type also
still works for captureless lambdas.)

## Across modules

Lambdas cross the [module](modules.md) boundary: a module can take a closure
parameter (`Fn<…>`), return a closure, and export a module-level lambda — a
captureless lambda bound to a function pointer at file scope:

```sic
module fx;
int (*dbl)(int)          = [](int x) { return x * 2; };   // module-level lambda
int apply(Fn<int(int)> f, int x) { return f(x); }         // closure parameter
Fn<int(int)> adder(int n) { return [n](int x) { return x + n; }; }  // closure return
```

A consumer calls `fx::dbl(x)`, passes closures to `fx::apply`, and stores what
`fx::adder` returns.

## Capture lifetimes

A captured **refcounted** value — a `string`, `tuple`, or another closure — is
retained for the closure's lifetime: kept alive as long as the closure lives, and
released when the closure is destroyed. So a closure that captures such a value
can be returned and outlive the scope that created it:

```sic
Fn<int()> make() {
    tuple t = tuple(40, 2);
    return [t]() { return (int)t[0] + (int)t[1]; };   // `t` stays alive
}
make()();                                // 42
```

The exceptions are borrows that alias non-refcounted storage — a plain (C) struct
`[x]`, a single-owner container (`list`/`dict`/`set`), or an explicit `@`/`@mut`
capture — which point at the original and so must not outlive it (like a C++
`[&]` capture). A closure that captures only scalars, strings, tuples, and
closures is always safe.

A capturing closure cannot initialize a module-level global (it needs a runtime
environment) — define it inside a function, or export a function.

Next: [atomics](atomics.md).
