# Benchmarks

Small CPU-bound micro-benchmarks implemented three times with the **same algorithm**
— in C, Rust, and SIC — to compare the code the `sic` compiler produces against
mainstream LLVM-backed toolchains.

Each benchmark lives in its own directory with `main.c`, `main.rs`, and `main.sic`.
The `.sic` files are **idiomatic SIC**, not copies of the C: native fixed-width types
(`i32`/`i64`/`usize`/`bool`), heap arrays via `new T[count]` released with `defer del`
(freed on every scope exit, no explicit free at each return). These are numeric
kernels, so the large flat buffers are heap arrays — SIC's boxed containers
(`list`/`dict`/`set`) target dynamic or heterogeneous data and would be pathological
here (a `list<bool>` for a 100 M-entry sieve is ~2.4 GB, and boxed element access in
matmul's ~1e9-iteration inner loop would dwarf the arithmetic). Every program prints a
single integer **checksum**; the runner requires all three to agree before it trusts
any timing, so a miscompile shows up as a checksum mismatch rather than a wrong speed.

| benchmark | what it stresses                                   | checksum        |
|-----------|----------------------------------------------------|-----------------|
| `fib`     | recursion / function-call overhead (`fib(42)`)     | `267914296`     |
| `sieve`   | tight loops + memory bandwidth (sieve to 100 M)    | `5761455`       |
| `matmul`  | nested loops + array indexing (1024×1024 int matmul)| `2630909442048`|

`fib` reads its argument through a `volatile` / `black_box` so no compiler can fold
the recursion to a constant; `sieve` and `matmul` are data-dependent on heap arrays,
so the work cannot be optimized away.

## Running

```sh
./run.sh              # all benchmarks
./run.sh fib matmul   # selected
RUNS=10 ./run.sh      # more timing samples (default 5; reported time = the minimum)
```

Compiler flags (each toolchain's straightforward optimized setting):

- **C** — `cc -O2`
- **Rust** — `rustc -O` (opt-level 2)
- **SIC** — `sic -O2`, linked with `cc`

The runner builds into a temp dir (nothing is written into the repo), verifies the
checksums, then reports the minimum wall-clock time over `RUNS` runs and the ratio to
C. It uses the release `sic` (`../siccomp/target/release/sic`); override with `SIC=…`.

## A representative result

Measured with `RUNS=5` (gcc 15, rustc 1.93, release `sic`; one machine — treat the
ratios, not the absolute times, as the signal):

```
== fib ==     C 0.24s   Rust 0.45s (1.88x)   SIC 1.39s (5.79x C)
== matmul ==  C 0.13s   Rust 0.12s (0.92x)   SIC 1.17s (9.00x C)
== sieve ==   C 0.58s   Rust 0.58s (1.00x)   SIC 0.73s (1.26x C)
```

### Reading the numbers

`sic` produces **correct** code (every checksum matches C and Rust) and lands between
**1.3× and 9× slower** than the LLVM toolchains, depending on the workload:

- **`sieve` (1.26×)** — memory-bandwidth-bound, so back-end code quality barely
  matters; `sic` is nearly on par.
- **`fib` (5.8×)** — dominated by function-call overhead; `sic`/Cranelift does less
  aggressive inlining and call optimization than LLVM.
- **`matmul` (9×)** — the LLVM toolchains auto-vectorize the inner loop into SIMD;
  `sic`'s Cranelift back end emits scalar code, so it pays the full ~1 B scalar
  multiplies.

The gap is expected: `sic` uses [Cranelift](https://cranelift.dev/) (built for fast
compilation, not peak runtime) rather than LLVM, and does not auto-vectorize. These
benchmarks exist to track that gap over time and catch regressions, not to claim
parity.

## Frontend comparison: `sic` on C vs on SIC

`run.sh` also compiles each benchmark's `main.c` and `main.sic` with **the same `sic`
compiler** (`sic·C` and `sic·SIC`). Both go through the same Cranelift back end, so
the difference between them is down to the frontends and the memory model each source
uses. Representative result:

```
          gcc     sic·C    sic·SIC
fib      0.24s    5.75x     5.75x    (on par)
sieve    0.81s    1.20x     1.26x    (sic·SIC 1.05x sic·C)
matmul   0.13s    9.00x    15.15x    (sic·SIC 1.68x sic·C)
```

The frontends themselves emit **equivalent code**: an experiment compiling a `malloc`
-based `main.sic` (SIC frontend, unchecked pointers) matches `sic·C` exactly (matmul
1.18s vs 1.17s). The `sic·SIC` gap comes entirely from the **idiomatic SIC memory
model**: `new T[]` arrays are bounds-checked on every access (a safety feature the C
`malloc` versions don't have). So the check cost tracks how array-access-bound the
kernel is:

- **`fib`** — no arrays, so nothing to check: identical to `sic·C`.
- **`sieve`** — array-heavy but memory-bandwidth-bound, so the checks hide behind
  memory latency: only ~1.05×.
- **`matmul`** — compute-bound with ~1e9 array accesses in the inner loop, so the
  per-access bounds check dominates: ~1.68×.

In other words, sic's C and SIC frontends are on par for equivalent code; the visible
difference is the price of SIC's memory safety, paid in proportion to how tight the
array-indexing loop is.
