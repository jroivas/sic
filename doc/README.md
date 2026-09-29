# SIC — Slightly Improved C

**SIC** is a systems language that starts from C and fixes its sharpest edges —
undefined behavior, unsafe strings, manual memory management, weak type
information — without abandoning C's model or its ecosystem. C source compiles
unchanged; the improvements are opt-in and live in `.sic` files.

> This guide documents the language **as implemented today**. The design
> specification (`sic.md` at the repo root) is the broader reference — most of it
> is implemented, but where it and the compiler differ this guide describes what
> the compiler actually does, and a few `sic.md` items are still marked *planned*.

## Contents

1. [Getting started](getting-started.md) — building the compiler, compiling a
   `.sic` file, the C/SIC split.
2. [Language basics & defined behavior](language-basics.md) — zero-initialization,
   integer overflow/wraparound, divide-by-zero, shifts and rotates, swap, and the
   syntactic tightenings (assignment in conditions, dangling `else`).
3. [Types](types.md) — fixed-width integers, `bigint`, `fixed` (exact rational),
   floats, `bool`.
4. [Strings](strings.md) — the native `string` type: slices, concatenation,
   comparison, `.dup`, and multi-line string literals.
5. [Memory & ownership](memory-and-ownership.md) — the move/borrow model,
   reference counting, copy-on-escape, `defer`, `new`/`del`, and `@` references.
6. [Enums & pattern matching](enums-and-matching.md) — tagged enums, generics,
   `Option`/`Result`, `match`, `bitfield` flag sets, the tightened `switch`, and
   `?:` / `?.` / `else` guards.
7. [RTTI & dynamic values](rtti-and-dynamic.md) — `type(x)`/`typeid`, the `any`
   box, `va_array` varargs, and `match (type(x))`.
8. [Arrays & tuples](arrays-and-tuples.md) — `.length`/`.size`, array/tuple
   concatenation, tuple packing/unpacking, the empty tuple.
9. [Containers](containers.md) — the built-in `dict`, `list`, and `set`: subscript,
   methods, iteration, `.keys`/`.values`, and `new`.
10. [Methods & iterators](iterators.md) — struct methods, constructors/destructors,
    `Iterator<T>`, and the range-`for`.
11. [Lambdas](lambdas.md) — C++-style `[](params){…}` / `=> expr`, captureless
    function-pointer decay, by-value and `@`/`@mut` captures, closures, currying,
    and the `Fn<ret(params)>` closure type.
12. [Atomics](atomics.md) — the `atomic` qualifier, lock-free RMW ops,
    `.swap`/`.cas`, and atomic pointers.
13. [Modules](modules.md) — `module`/`import` (namespaced, selective, `::*`),
    building a module, chain-loaded dependencies, and the `.smod` manifest.
14. [Standard library](standard-library.md) — `import std;` and
    `Fmt`/`Print`/`Println`.

## Design goals

- **No undefined behavior.** Every operation C leaves undefined has a defined
  result in SIC (see [defined behavior](language-basics.md)). You opt back into
  trapping behavior explicitly with `unsafe`.
- **Memory safety without a garbage collector.** Non-primitive values
  (`string`, and refcounted allocations) are owned, moved, and released
  deterministically; a view of a dying buffer is copied automatically before it
  can dangle. See [memory & ownership](memory-and-ownership.md).
- **Richer built-in types.** Native `string`, arbitrary-precision `bigint`, exact
  `fixed`-point, tuples, tagged enums with generics, and runtime type information.
- **Real modules.** `import` replaces header/`#include` fragility with a typed,
  portable module interface — while still generating a C header for interop.
- **C compatibility.** Existing C compiles as-is; SIC features are gated to `.sic`
  units, so you adopt them incrementally.

## A taste

```sic
import std;

enum Shape { Circle(fixed), Square(fixed) };

fixed area(Shape s) {
    match (s) {
        Circle(r): return r * r * 3.14159;   // exact-rational πr²
        Square(w): return w * w;
    }
}

int main() {
    Shape c = Shape::Circle(2.0);
    std::Println("area = {}", area(c).str);   // area = 12.566...
    return 0;
}
```
