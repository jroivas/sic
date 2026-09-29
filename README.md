# SIC — Slightly Improved C

Slightly Improved C is a programming language that borrows a lot from C, but is
not afraid to introduce breaking changes in order to improve it.

The compiler (`siccomp/`, a Rust workspace) has two front ends sharing one back
end:

  - a **C front end** — it compiles ordinary C, enough to build real codebases
    (SQLite, QEMU); and
  - a **SIC front end** — the memory-safe, undefined-behaviour-free language
    described in [sic.md](sic.md).

Both lower to a typed IR (`sic-ir`), are optimized by `sic-opt`, and are compiled
to native code by a **Cranelift** back end (`sic-cranelift`). There is no LLVM
dependency.

## Dependencies

  - A **Rust toolchain** (`cargo`, stable) to build the compiler.
  - A **C compiler / linker** (`cc`, gcc or clang) — `sic` links object files
    through it, and it is the bootstrapping compiler.
  - A system libc with headers, for compiling C and for some tests.

## Build

`build.sh` builds the compiler and then builds + installs the shipped standard
library (`import std;`) into the compiler's module sysroot:

    ./build.sh release        # or: ./build.sh debug (default)

That is just a wrapper around `cargo`; you can also build the compiler alone:

    cd siccomp && cargo build --release

The binary lands at `siccomp/target/release/sic` (or `.../debug/sic`).

## Usage

    sic hello.c   -o hello       # compile C and link a binary
    sic hello.sic -o hello       # compile SIC and link a binary
    ./hello

    sic -c foo.c -o foo.o        # compile to an object file, don't link
    sic -S foo.sic               # dump the textual IR instead of compiling
    sic -O2 foo.c -o foo         # optimize (0 | 1 | 2 | 3 | s | z)

`sic` accepts the usual `-o -c -O -D -I -l -L -W` flags for gcc/clang
compatibility; see `sic --help`.

## Tests

    ./compiletest_rust.sh        # the compile/run test suite (tests/)
    ./moduletest.sh              # the module-system tests
    ./check.sh                   # build both profiles + run every suite at every -O level

Benchmarks comparing sic against gcc and rustc live in `benchmarks/` (`./benchmarks/run.sh`).

## Status

The SIC language features in [sic.md](sic.md) are largely implemented; a few
advanced items remain partial or planned (noted inline there).
