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

```sic
import math;                    // namespaced: use as math.sq(…)
import math.sq;                 // selective: brings `sq` into scope unqualified
import math.sq as square;       // renamed

int main() {
    return math.sq(5) + square(2);   // 25 + 4
}
```

- `import math;` makes exports available under the module's namespace: `math.sq(5)`.
- `import math.sym;` imports just `sym` (unqualified); `as name` renames it.

> Namespaced access currently works for **function calls** (`math.sq(5)`).
> Accessing an exported *variable* as `math.meaning` is not yet wired up — import
> it selectively (`import math.meaning;`) as a workaround.

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
fn sq (i32) -> i32 math_sq
var meaning i32 math_meaning
```

It can describe aggregate types too (`string`, `va_array`, structs), which is how
`std` exports `Fmt(string, va_array) -> string`. A manifest built for a different
target triple, or a newer format version, is a hard error (no silent
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
