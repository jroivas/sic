# sicsic: the sic compiler in SIC (target 0.4.0)

The compiler is rewritten part by part in SIC. During the work, a "franken-SIC"
compiler mixes Rust and SIC parts, so every intermediate state is a working
compiler. The Rust compiler stays the bootstrap and the reference.

This is a rewrite, not a translation. A SIC part should use what SIC does well
(tagged enums and `match`, refcounted structs, `defer`, strings as slices) and
fix what the Rust version got wrong or made slow. The extensive test set
(check.sh, c-testsuite, SQLite, QEMU, the kernel) decides what is correct, not
agreement with the Rust output.

## Ground rules

- **Two compilers in one tree.**
  - `siccomp/` is the 0.3 compiler, the bootstrap. On main it is always the
    same as the newest 0.3.x.
  - `sic/` is the new compiler, written in SIC.
  - At 0.4.0 `sic/` is the compiler, and `siccomp/` is still there, unchanged
    from the latest 0.3.x, so main can always bootstrap: build `siccomp/`, then
    compile `sic/` with it.
- **siccomp/ only gets fixes.**
  - They are made on main, in `siccomp/`, then cherry-picked to branch
    `release/0.3.x` (made from tag `0.3.0`); dot releases are tagged from it.
  - A bug or a missing language piece that blocks sicsic is fixed the same way.
  - `git diff release/0.3.x main -- siccomp` must stay empty, apart from
    fixes that haven't been picked yet.
- **sic/ builds with siccomp/.** It never uses a feature that siccomp/ lacks.
  When it needs one, that is a fix to siccomp/ as above.
- **One part at a time, behind a switch.** The franken compiler contains both
  the Rust and the SIC version of a part, and `SIC_PARTS` (below) picks one.
  A SIC part becomes the default once the tests pass with it. The Rust version
  is then no longer called in franken, but it stays in siccomp/ as part of the
  bootstrap.
- **Diffs are a tool, not the goal.** Each part gets a dump that diffs SIC
  against Rust (tokens, IR, LLVM IR). Where the SIC part differs on purpose
  (better code, better diagnostics, a different representation),
  `sic/DIFFERENCES.md` records the difference and the reason. The test set
  then has to pass.
- **Boundaries are flat data.**
  - Across the Rust/SIC line go scalars, strings, and lists of scalars or
    strings, which `--emit-crate` already supports.
  - Lists of structs are avoided: they box a copy per read (see the re
    module).
  - Where a big tree has to cross (AST, IR), it is serialized.

## Preparation in 0.3.x

**Move siccomp/lib to the top-level `lib/`** (std, art, re). Both compilers use
it, so it shouldn't belong to one of them.
- **Who uses the path:** build.sh, moduletest.sh, sic-fmt/test.sh,
  tests/re/re.sh, doc/ and release/. The compiler itself only reads the
  installed sysroot.
- **Branches:** the move happens on main and is cherry-picked to
  release/0.3.x, so siccomp/ stays the same on both.
- **Rule:** `lib/` must build with the siccomp/ compiler, like `sic/`.

Other 0.3.x preparation is listed under the first steps: the release/0.3.x
branch, the driver library, and the token dump.

## What exists already

| stage | Rust (siccomp/crates) | lines | SIC |
|---|---|---|---|
| preprocessor | sic-frontend/preprocess.rs (driver glue) | 540 | **sicpp, done** (sic-cpp/lib, 4.3k); sic/ imports it directly |
| lexer | sic-frontend/lexer | 960 | sic-fmt has a SIC tokenizer to borrow from |
| parser + macros | sic-frontend/parser, ast | 7.1k | |
| lowering to IR | sic-frontend/lower | 38k | |
| .smod manifests | sic-frontend/module_manifest.rs | 1.1k | |
| IR | sic-ir | 2.8k | |
| optimizer | sic-opt | 5.9k | |
| LLVM back end | sic-llvm (inkwell) | 2.4k | LLVM-C is a C API: SIC can include it directly |
| linker | sic-link (libwild) | 0.4k | stays Rust, as a Rust crate module (cargo-sic) |
| Cranelift back end | sic-cranelift | 3.8k | **last; optional for 0.4.0** (see below) |
| driver | sic | 5.1k | |

sicpp already shows the full path: `sic --emit-crate` builds `libsicpp.a` plus
Rust bindings, and `crates/sic/build.rs` links them in when they are there.

## How franken-SIC is wired without changing siccomp/

The stages are already separate library crates (`Lexer`, `Parser`,
`Lowerer`, `sic_opt::run_*_passes`, the back ends), but the pipeline that
connects them is inside the `sic` binary (`main.rs`, e.g. lexing at line
1227). The franken compiler is a Rust crate in `sic/franken/`. It depends on
the `siccomp/crates/*` by path, the same code the bootstrap uses, and links
the SIC parts.

To use the real driver, `crates/sic` gets one change with no change in
behaviour:
- a library target with the pipeline;
- a `Stages` table of function pointers (lex, parse, lower, IR passes, emit),
  filled with the Rust functions by default.

The `sic` binary is then a short `main` calling that library. Because it
changes nothing, it is cherry-picked to release/0.3.x like a fix, and
siccomp/ stays the same as release/0.3.x. `sic/franken` calls the same
library and replaces the stages that `SIC_PARTS` names with SIC ones.

A stage is the smallest thing that can be swapped:
- **Clean stages:** the lexer, each optimizer pass, and the back end.
- **Lowering is not one:** it is replaced whole, and diffed at the IR it
  produces.

## SIC_PARTS

The environment variable `SIC_PARTS` chooses which stages of the franken
compiler run in SIC. It is an environment variable rather than a flag so that it
reaches every compile inside a build system (QEMU's meson, the kernel's make,
SQLite) without touching CFLAGS.

- **Who reads it:** only `sic/franken`. The siccomp/ compiler ignores it, and
  it goes away with franken when the driver is SIC (step 6).
- **Names:** the stage names are `lexer`, `parser`, `lower`, `opt` (every
  pass), `opt.<pass>` (one pass, e.g. `opt.licm`) and `llvm`. `ir` is not a
  stage: it is the format the stages exchange.
- **Values:**
  - **Unset:** the default set, the stages already switched over (a list in
    `sic/franken/src/parts.rs`). At the start it is empty.
  - **`lexer,opt.licm`:** exactly these.
  - **`+parser` / `-lexer`:** the default set, plus or minus a stage. Items can
    be mixed: `-lexer,+parser`.
  - **`all` / `none`:** every built stage, or none (pure Rust; franken then
    behaves exactly like siccomp/'s sic).
- **No silent fallback:** a name that is unknown, or names a stage that wasn't
  built into this franken, is an error (exit 2). Otherwise a test run could
  quietly be testing Rust.
- **Visible:**
  - `sic -print-parts` lists each stage and whether it is built, in the
    default set and active.
  - check.sh and compiletest print the active set next to the compiler line.
- **Scope:** one compiler invocation, all files in it. There is no per-file
  mixing.

## Back ends, and Cranelift

The sic/ compiler keeps the current back-end design:
- **Options:** the `BackendOptions` contract (sic-ir/backend.rs).
- **Selection:** `--backend`, and `-print-backends` (the first one listed is
  the default).
- **Build order:** build.sh's `--backend a,b` order chooses which is first.

In sic/ that design is a table of back ends behind one entry point that takes
the IR module and the options and writes the object.

0.4.0 needs only LLVM. Cranelift comes last and may miss 0.4.0, and the design
keeps enabling it in 0.4.x a small step:
- **What's needed:** a Rust crate module (through cargo-sic) that reads the
  serialized IR with the Rust reader from step 2 and calls sic-cranelift
  unchanged.
- **What doesn't change:** sic-cranelift is not rewritten, and Cranelift itself
  is not changed.
- **Why a reader is enough:** the IR serialization, not a Rust in-memory
  structure, is the back-end boundary. Any back end, Rust or SIC, plugs in the
  same way.

## Order

1. **Lexer** (first; see below). It is a pure function, source text → tokens,
   called once per file (`main.rs:1227`). Its output is flat, so the boundary
   is trivial. It is hot, so it measures SIC's speed early. It is small enough
   to finish in days and proves the wiring every later part reuses.
2. **IR in SIC + an IR serialization.**
   - **Format:** a binary IR format, with a writer and reader in both Rust and
     SIC. It is also useful alone: `--emit-ir`, and reading a `.sir` file back.
   - **Test:** the round trip Rust → SIC → Rust must be identical.
   - **Why now:** every later part needs this boundary, and the IR (2.8k lines)
     is smaller and more stable than the AST.
   - **Cranelift:** the serialization is what keeps the door open for it.
3. **LLVM back end** over LLVM-C, diffed by the LLVM IR text it prints against
   sic-llvm's.
4. **Optimizer passes**, one at a time: IR in, IR out, diffed.
5. **Front end:** the parser and AST (serialized into the Rust lowerer while
   the lowerer is Rust), then lowering, area by area: types, statements,
   expressions, calls, builtins, asm, SIMD... Lowering is the bulk (38k
   lines). Since the IR already exists in SIC, the SIC lowering emits it
   directly.
6. **Driver.** wild comes in as a Rust crate module. `sic/franken` goes away;
   `sic/build.sh` produces the sic binary from SIC.
7. **Self-host check:** stage 0 (siccomp/) builds stage 1 (sicsic); stage 1
   builds stage 2; stage 2 builds stage 3; stage 2 and 3 must be
   byte-identical.
8. **Cranelift** back end, as described above: in 0.4.0 if it is ready, else
   0.4.x.

The bottom-up order after the lexer (IR, back end, optimizer, then front end)
puts the serialized IR boundary in early, and every later part is diffed
against it. The alternative, going front-to-back through the parser, would
need an AST serialization first, and the AST changes far more often.

## Layout

```
lib/               std, art, re (moved from siccomp/lib; both compilers)
sic/
  PLAN.md          this file
  DIFFERENCES.md   deliberate differences from the Rust compiler
  build.sh         builds every part with siccomp/'s sic, then sic/franken
  check.sh         check.sh's release suites with the franken compiler
  target/          franken's build: target/release/sic (+ cargo-sic)
  lexer/           module `lexer`: lexer.sic, tests/
  ir/              module `ir` (step 2)
  llvm/  opt/  parser/  lower/  driver/  ...
  franken/         Rust crate: siccomp crates by path + the SIC parts
    build.rs       links each built sic/<part> library, sets cfg(sic_<part>)
    src/main.rs    the driver library with SIC stages swapped in
    src/parts.rs   stage names, the default set, SIC_PARTS parsing
  tests/           differential scripts (diff-lexer.sh, ...)
```

The order is `./build.sh` (siccomp/, as today), then `sic/build.sh`. The parts
are compiled by `siccomp/target/release/sic`, which is the bootstrap compiler
on every commit of main. Franken builds into `sic/target`, so it never
touches siccomp's build; `sic/target` is as deep in the tree as
`siccomp/target`, which is where sic looks for the repository's `sic-cpp`
from its own location.

## First steps

1. **Branch release/0.3.x.** `git branch release/0.3.x 0.3.0`. siccomp/ fixes
   are made on main and cherry-picked there.
2. **Move siccomp/lib to lib/** and update the scripts and docs. Cherry-pick it
   to release/0.3.x.
3. **Driver library + `Stages`** in `crates/sic`, with no change in behaviour:
   check.sh must pass unchanged. Cherry-pick it to release/0.3.x.
4. **A token dump.**
   - **The option:** a hidden `sic -dump-tokens FILE`, which prints one line
     per token: kind, text, line:col, start..end, pack, hidden. It is a driver
     option in the shared library, so siccomp/ gets it too (cherry-picked).
   - **The diff:** `sic/tests/diff-lexer.sh` runs franken with
     `SIC_PARTS=none` and with `SIC_PARTS=lexer` over a corpus and diffs the
     dumps. The corpus:
     - tests/*.c and tests/*.sic
     - c-testsuite
     - lib/
     - sic-cpp, sic-fmt and tests/re
     - the SQLite amalgamation, preprocessed
5. **`sic/build.sh` and `sic/franken`** with no parts yet. The franken
   compiler is then the bootstrap with nothing swapped, and must pass check.sh
   as `SIC=sic/target/release/sic`. `-print-parts` and the
   `SIC_PARTS` errors are in from the start.
6. **The lexer in SIC** (`sic/lexer/lexer.sic`, `module lexer`). Done
   2026-11-27:
   - **Entry point:** `Tokens Lex(string src, i32 lang, bool c23, bool wchar16)`.
   - **`Tokens`:** structs with list fields don't cross `--emit-crate`, so the
     tokens are one `u32` array, 8 words a token: kind and flags, byte and char
     start and end, line, col, file. Literal texts, file names and system
     headers are byte buffers. Pointer fields needed a fix to `--emit-crate`,
     in 0.3.x.
   - **Errors:** a message with its file, line and col.
   - **Token kinds:** generated from `TokenKind`, in the same order; a Rust test
     compares the names through `KindName(i)`, so the lists cannot drift.
   - **Offsets:** the lexer reads the UTF-8 bytes in place, with no
     `Vec<char>`, and counts characters as it goes: the Rust parser gets char
     offsets, the SIC one will use bytes.
7. **Pass.**
   - **Diffs:** done. diff-lexer.sh is clean on all 1050 files, including
     `sic/tests/lexer`'s edge cases. The objects of every compile test and of
     SQLite are byte-identical whichever lexer runs. DIFFERENCES.md has the one
     deliberate difference, non-ASCII identifiers.
   - **Speed:** done. On the amalgamation the SIC stage costs as many
     instructions as the Rust lexer, and takes as long. Of that, the SIC
     lexing is about 210 M instructions, Rust's about 270 M, and the rest is
     building the Rust tokens.
   - **Tests:** sic/check.sh passes with `SIC_PARTS=lexer`. QEMU and kernel
     builds with it are still to run.
   - **Then:** the lexer joins the default set, and 0.4.0's CHANGELOG starts.

## Expected language gaps

Each gap is fixed in siccomp/ on main and cherry-picked to release/0.3.x
when it blocks a part. Some will show up soon:

- `list<Struct>` reads box a copy: tolerable at boundaries, too slow for
  compiler tables. The fix is in-place element access.
- `dict` holds only int/string keys and word values. Compiler symbol tables
  need struct values.
- The IR and AST want payload enums inside lists and recursive trees, which
  needs generic containers of refcounted structs.
- `--emit-crate` support for a struct with list fields still has to be checked
  (step 6).

## Done when (0.4.0)

- **Build:** the 0.4.0 `sic` is built from `sic/` by the siccomp/ compiler.
  siccomp/ is the same as the latest 0.3.x.
- **Rust:** `sic/` uses Rust only through wild, plus Cranelift if it made it.
- **Back ends:** LLVM is the back end.
- **Tests:** the self-host check (step 7) is byte-identical, and check.sh,
  SQLite, QEMU and the kernel pass as they do today. Cranelift-only tests are
  skipped when it isn't built.
