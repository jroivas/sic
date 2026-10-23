# Getting started

## Building the compiler

The compiler (`sic`) is a Rust workspace under `siccomp/`. Build it, and the
standard library, with the top-level script:

```sh
./build.sh                 # builds the compiler (debug) and installs std
```

`build.sh` runs `cargo build` in `siccomp/`, then compiles the SIC standard
library (`siccomp/lib/std/std.sic`) into the compiler's module sysroot so
`import std;` works with no extra flags. To build just the compiler:

```sh
cd siccomp && cargo build           # → siccomp/target/debug/sic
```

The same build produces `cargo-sic`, which adds Rust crates to a SIC project
(`cargo sic add <crate>`, see [Rust crates](rust-crates.md)). `build.sh` also builds
`sic-fmt/sic-fmt`, the code formatter: `sic-fmt file.sic` lays a file out in the
[default style](style.md), `sic-fmt --check src/` only reports (see
[sic-fmt](../sic-fmt/README.md)).

Add the binary to your `PATH`, or invoke it directly:

```sh
export SIC=siccomp/target/debug/sic
```

## Compiling and running a program

A `.sic` file is compiled to a native executable and linked with the system C
runtime:

```sh
$SIC hello.sic -o hello
./hello
```

```sic
// hello.sic
import std;
int main() {
    std::Println("Hello, {}!", "SIC");   // Hello, SIC!
    return 0;
}
```

The driver is a drop-in for a C compiler front end: `-c` (compile to object),
`-o`, `-I`, `-L`, `-l`, `-g`, `-O0`..`-O3`, `-shared`, `-static`, `-pie` /
`-no-pie` / `-static-pie`, `-D`, and the GCC/Clang version queries (`--version`,
`-dumpversion`, `-dumpmachine`) all work. Preprocessing uses sic's own `sic-cpp`
(`sic -print-prog-name=cpp`; `SIC_CPP=cpp` selects the system one), so `#include`
and `#define` behave as in C.

Warnings use the GCC flags: `-Wall`, `-Wextra`, `-W<name>` / `-Wno-<name>`,
`-Werror`, `-Werror=<name>` / `-Wno-error=<name>`, `-w`, `-pedantic`. sic reports
`-Wdiv-by-zero`, `-Wshift-count-overflow`/`-negative` (C only — SIC defines those
cases), `-Wunused-variable` (in `-Wall`), `-Wunsupported-asm` and `-Wlong-double` (opt-in);
other warning names are accepted and ignored, so existing build flags keep working.
As in GCC, nothing is reported from system headers.

`long double` is deprecated. It is ABI-compatible with C: values are kept in the
x87 80-bit format in memory (16-byte, 16-aligned slots), passed on the stack, read
by `va_arg` and returned in `st(0)` exactly as gcc does, so structs, pointers,
`printf("%Lf")`, `strtold` and the `*l` libm functions all interoperate. sic's own
arithmetic on it, however, has only `double` (64-bit) precision, so results can
differ from gcc in the last digits. To find uses, enable `-Wlong-double` (off by
default and not part of `-Wall`/`-Wextra`, since library headers such as glib's
declare `long double`).
Use `double`, or `fixed`/`bigint` for more precision.

## C and SIC in one project

The **file extension picks the language**:

- `*.sic` → SIC (Rust-style type aliases like `i32`/`u64` are reserved; the extra
  keywords `string`, `bigint`, `match`, `defer`, … are active).
- everything else → C. In C mode those SIC keywords are ordinary identifiers, so
  existing C code compiles unchanged.

Force the language with `-x sic` or `-x c` when the extension doesn't match:

```sh
$SIC -x sic mycode.c -o mycode      # compile a .c file as SIC
```

Because the split is per file, you adopt SIC incrementally: keep compiling your C
as C, write new units in `.sic`, and link them together.

C's GNU inline assembly is supported for the x86-64 templates real code uses
(`rdtsc`, `cpuid`, `xgetbv`, `pause`, fences, `divq`, `shld`/`shrd`,
`vmovdqa`/`vmovdqu`, compiler barriers, Valgrind client requests). Any other
template is reported (`-Wunsupported-asm`) and traps if it is ever executed — it
is never silently skipped.

## What "no flags" gets you

- `import std;` resolves against the sysroot populated by `build.sh` — no `-I`
  needed. See [modules](modules.md) for how the search path works.
- By default a program links **dynamically** against any imported module's shared
  library; pass `-static` for a fully static binary.

Next: [language basics & defined behavior](language-basics.md).
