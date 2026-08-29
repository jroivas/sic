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
`-o`, `-I`, `-L`, `-l`, `-g`, `-O0`..`-O3`, `-shared`, `-static`, `-D`, and the
GCC/Clang version queries (`--version`, `-dumpversion`, `-dumpmachine`) all work.
Preprocessing uses the system `cpp`, so `#include` and `#define` behave as in C.

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

## What "no flags" gets you

- `import std;` resolves against the sysroot populated by `build.sh` — no `-I`
  needed. See [modules](modules.md) for how the search path works.
- By default a program links **dynamically** against any imported module's shared
  library; pass `-static` for a fully static binary.

Next: [language basics & defined behavior](language-basics.md).
