# Modules

SIC has real modules — a typed, separately-compiled unit with an explicit
interface — replacing the `#include`/header pattern (which still works for C
interop). A module is built once into a library plus a portable manifest;
consumers `import` it.

## Declaring a module

A unit that begins with `module <name>;` is a module. Every top-level symbol is
exported unless marked `static`:

```sic
// math/math.sic
module math;

int meaning = 42;
static int helper(int x) { return x + 1; }   // static → private to the module
int sq(int x)  { return x * x; }
```

The implementation is not exported — only the interface (the non-`static`
symbols and their types).

## Building a module

`--emit-module <dir>` compiles every `.sic` file in `<dir>` that declares the
same `module` (one folder = one module; subfolders are separate) and produces:

```sh
sic --emit-module math
```

| output | purpose |
|--------|---------|
| `libmath.a`  | static archive |
| `libmath.so` | shared library (dynamic linking, the default) |
| `module_math.smod` | portable typed interface (the manifest) |
| `module_math.h`    | C header (mangled prototypes) for C consumers |
| `module_math.def`  | Windows export list |

A multi-file module just puts several `.sic` files with the same `module math;`
in the folder; they're compiled together, so they can call one another's
functions.

## Importing

A plain `import` makes a module's symbols reachable **only under its namespace**;
the other forms bring names into the global scope:

```sic
import math;                    // namespaced: use as math::sq(…), math::meaning
import math::sq;                // selective: brings `sq` into scope unqualified
import math::sq as square;      // renamed
import math::*;                 // bring ALL of math's symbols in unqualified

int main() {
    return math::sq(5) + square(2) + math::meaning;   // 25 + 4 + 42
}
```

- `import math;` — everything is reached qualified: functions `math::sq(5)`,
  globals `math::meaning`, types `math::Color`, enum variants
  `math::Status::Ok`. Using such a name **unqualified is a compile error** (with a
  fix-it telling you to qualify it or import it explicitly).
- `import math::sym;` — bring the single symbol `sym` into the global scope
  (`as name` renames it, for functions/globals).
- `import math::*;` — bring *all* of the module's symbols in unqualified.

Module members are reached with `::`, sic's scope-resolution operator — the same
operator used for enum variants (`Option::Some`) and namespaces (below). The older
dot form `math.sq(5)` still works as a tolerated alias for member access, but `::`
is canonical. This namespacing covers **every** kind of export — functions,
globals, types, enums, and generic functions — so `import`ing two modules that
each define a `Widget` or a `parse` never collides (symbols are module-qualified
internally).

## Namespaces

A `namespace` groups declarations into a compile-time scope *within* a unit (no
import needed), reached with the same `::` operator:

```sic
namespace geo {
    int width  = 4;
    int height = 3;
    int area() { return geo::width * geo::height; }
}

int main() {
    geo::width = 10;               // member variable (an lvalue)
    return geo::area();           // member function → 30
}
```

Functions and variables are supported; a `struct`/`enum` declared inside is visible
at file scope. `::` is the scope operator throughout sic — **namespaces, modules,
and enum variants all use it**; `.` is reserved for values (`obj.field`,
`obj.method()`).

## Exporting types

A module's `struct`/`union` types are **public by default**: they are written to
the manifest and a consumer can name them as `mod::Type` (and access their fields).

```sic
// module gfx:  struct Color { int r; int g; int b; };  Color *make(...);
import gfx;
gfx::Color *c = gfx::make(200, 50, 10);
int r = c->r;                                   // fields cross via the manifest
```

Mark a type `private` to keep it module-internal (withheld from the manifest, so
consumers cannot name it):

```sic
private struct Impl { … };     // not exported
```

> The qualified `mod::Type` form is required in a consumer — the bare `Type`
> spelling isn't available, because the parser resolves types before imports run.

A module's exported struct may carry a **constructor and destructor**, and they
run across the module boundary: a consumer's `new mod::S()` / `del`, and ordinary
scope exit for a `mod::S` value, call the module's `S()` / `~S()`. So a type like
`std::Buffer` cleans itself up in your code exactly as it does inside `std`.

## A module that imports modules

A module may `import` other modules and use them in its own implementation:

```sic
// extra/extra.sic
module extra;
import std;

namespace Extra {
    string greet(string name) { return std::Fmt("Hello, {}!", name); }
}
```

Dependencies are **chain-loaded**: a consumer that imports only `extra`
transitively pulls in `std`, so `extra`'s std-backed API works and `std::` is
even reachable — without importing `std` yourself:

```sic
import extra;                        // std comes along automatically
std::Println("{}", extra::Extra::greet("world"));
```

Each module's manifest lists only what *that* module defines, plus a `dep` line
naming each module it imports (it does not re-export its dependencies' symbols);
the consumer loads those dependencies and folds in their link flags.

## Finding modules — the search path

At compile time the compiler looks for `module_<name>.smod` in, in order:

1. every directory in the `$SIC_MODULE_PATH` environment variable (`:`-separated),
2. the compiler's relocatable **sysroot** relative to its own binary
   (`<exe>/../lib/sic`) — this is where `build.sh` installs `std`,
3. the `-I` include directories,
4. the current directory.

So `import std;` works with no flags (std lives in the sysroot); a local module is
found with `-I<dir>`.

## Static vs. dynamic linking

Both `libmath.a` and `libmath.so` are produced, and the manifest records the link
flags (including an rpath to the shared library). By default a consumer links
**dynamically**:

```sh
sic app.sic -Imath -o app
ldd app        # → libmath.so
```

Pass `-static` for a fully static binary that pulls the archive instead:

```sh
sic -static app.sic -Imath -o app
ldd app        # → not a dynamic executable
```

The manifest carries the linker flags a consumer needs (`-L`, `-l`, rpath, plus
any libraries the module itself depends on), so `-I<dir>` is usually all you pass.

## The manifest

`module_<name>.smod` is a small, human-readable, line-oriented text file — no
private compiler blob. It records the format version, module name, target triple,
link flags, and each export with its type and mangled linker symbol:

```text
sicmod 2
module math
triple x86_64-unknown-linux-gnu
link -L/path/to/math -Wl,-rpath,/path/to/math -lmath
dep std
fn sq (i32) -> i32 math_sq
var meaning i32 math_meaning
```

Besides `fn`/`var` exports it records: `dep` lines (modules to chain-load), `struct`/
`union`/`enum`/`tagenum` records for exported aggregate and enum types, `pubtype`
markers, `genericfn` templates (re-instantiated by the consumer), and `ctor`/`dtor`
lines pointing at a struct's constructor/destructor symbol. Describing aggregate
types is how `std` exports `Fmt(string, va_array) -> string`. A manifest built for a
different target triple, or a newer format version, is a hard error (no silent
source fallback).

## C interop

Non-SIC code can use a module through the generated header, calling the mangled
`<module>_<symbol>` names:

```c
#include "module_math.h"
int main(void) { return math_sq(6); }   // 36
```

```sh
cc user.c -Imath -Lmath -lmath -o user
```

Next: [the standard library](standard-library.md).
