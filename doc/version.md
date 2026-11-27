# Versions

What sic says about itself, and where each part of it comes from:

    $ sic --version
    sic version 0.3.0 (SIC Compiler, clang compatible, LLVM, Clpiobd)
    Target: x86_64-unknown-linux-gnu
    Thread model: posix

## The release number

`0.3.0` is the release, MAJOR.MINOR.PATCH, optionally with a SemVer pre-release
suffix (`0.4.0-dev`). The workspace `siccomp/Cargo.toml` is the source; sic's crates
take it from there. `./setversion.sh 0.3.1` writes it everywhere else it appears, and
`./setversion.sh --check` (run by smoketest.sh) fails when the places disagree:

- the producer string's documentation in `sic-ir`;
- `sic-fmt --version`;
- the `__SICC_MINOR__` and `__SICC_PATCH__` macros in sicpp.

Build systems ask for parts of it:

    sic -dumpversion     0.3.0
    sic -dumpmachine     x86_64-unknown-linux-gnu

## The `--version` line

`sic version 0.3.0 (SIC Compiler, clang compatible, LLVM, Clpiobd)` has these parts:

- **`clang compatible`:** build systems and Linux look for `clang` in this line;
  Linux shows it in `/proc/version`.
- **`LLVM` or `Cranelift`:** the back end a compile would use: `-fbackend=`, then
  `$SIC_BACKEND`, then the default (the first of `sic -print-backends`).
- **`Clpiobd`:** the compiler's identifier, below.

## The compiler's identifier

One letter per part of the compiler, in pipeline order. Uppercase means the part is
written in SIC, lowercase that it is written in Rust:

| letter | part |
|---|---|
| `c` | preprocessor (`-`: not sicpp but the system's, e.g. `SIC_CPP=cpp`) |
| `l` | lexer |
| `p` | parser |
| `i` | lowering to IR |
| `o` | optimizer |
| `b` | the back end in use: sic's code for it, not LLVM or Cranelift themselves |
| `d` | driver |

A part is uppercase only when all of it is SIC: the optimizer stays `o` until its
last pass is. Libraries sic uses (LLVM, Cranelift, wild) are not parts.

| compiler | identifier |
|---|---|
| 0.3.x (siccomp/), either back end | `Clpiobd`: sicpp is SIC, the rest Rust |
| 0.3.x preprocessing with the system cpp | `-lpiobd` |
| franken-SIC with the SIC lexer | `CLpiobd` |
| 0.4.0, the compiler in SIC | `CLPIOBD` |
| 0.4.x with Cranelift (its glue stays Rust) | `CLPIObD` |

The franken-SIC compiler (sic/target/release/sic, built by `sic/build.sh`) runs the
stages that `SIC_PARTS` picks in SIC, so its identifier follows `SIC_PARTS`:

    $ sic/target/release/sic -print-parts      # what is built, the default, active
    $ SIC_PARTS=lexer sic/target/release/sic --version | head -1
    sic version 0.3.0 (SIC Compiler, clang compatible, LLVM, CLpiobd)

Its release number is siccomp's: it is siccomp's driver, with stages replaced.

## Compiler macros

The preprocessor defines what code tests to detect the compiler:

| macro | value | why |
|---|---|---|
| `__SICC__` | `1` | sic itself; stays 1, since a major version of 0 would make `#if __SICC__` false |
| `__SICC_MINOR__`, `__SICC_PATCH__` | `3`, `0` | the release's numbers |
| `__clang__`, `__clang_major__` … | `17.0.6` | the Clang sic is compatible with |
| `__GNUC__`, `__GNUC_MINOR__` … | `4.2.1` | as Clang defines it |
| `__VERSION__` | `"Clang 17.0.6"` | |

## In objects

Every object records what made it in `.comment`, and in DWARF's
`DW_AT_producer` under `-g`:

    $ readelf -p .comment a.out
      sic 0.3.0 (preprocessor: sic-cpp, backend: llvm)

## Module manifests

A module's manifest (`module_<name>.smod`) starts with its format version,
`sicmod 3`. The number changes on any incompatible change to the format, and sic
refuses a manifest whose version it does not know: v2 added structs and unions,
and v3 calling conventions (`ms_abi`).

## Releases, tags and branches

- **Tags:** a release is tagged with its number, without a `v` (`0.3.0`), as an
  annotated tag. `release/release.sh` builds the packages of a tagged commit.
- **Dot releases:** `0.3.x` releases come from branch `release/0.3.x`. Fixes are
  made on main, in `siccomp/`, and cherry-picked there, so `siccomp/` on main is
  always the latest 0.3.x.
- **0.4:** the compiler written in SIC grows in `sic/`; `siccomp/` stays in the
  tree as the compiler that bootstraps it (sic/PLAN.md).
