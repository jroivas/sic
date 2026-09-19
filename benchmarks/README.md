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

| benchmark    | what it stresses                                        | checksum          |
|--------------|---------------------------------------------------------|-------------------|
| `fib`        | recursion / function-call overhead (`fib(42)`)          | `267914296`       |
| `sieve`      | tight loops + memory bandwidth (sieve to 100 M)         | `5761455`         |
| `matmul`     | nested loops + array indexing (1024×1024 int matmul)    | `2630909442048`   |
| `quicksort`  | recursion + data-dependent swaps / irregular access (3 M ints) | `187506306455265` |
| `mandelbrot` | floating-point compute, no arrays (1000×1000, 256 iters)| `253815`          |

`fib` reads its argument through a `volatile` / `black_box` so no compiler can fold
the recursion to a constant; `sieve`, `matmul` and `quicksort` are data-dependent on
heap arrays, so the work cannot be optimized away; `mandelbrot` exercises pure `f64`
arithmetic (add/mul/compare) with no arrays.

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
== fib ==        C 0.25s   Rust 0.45s (1.80x)   SIC 1.39s (5.56x C)
== matmul ==     C 0.12s   Rust 0.12s (1.00x)   SIC 1.06s (8.83x C)
== sieve ==      C 0.55s   Rust 0.54s (0.98x)   SIC 0.75s (1.36x C)
== quicksort ==  C 0.14s   Rust 0.16s (1.14x)   SIC 0.21s (1.50x C)
== mandelbrot == C 0.13s   Rust 0.13s (1.00x)   SIC 0.38s (2.92x C)
```

(These `SIC` figures are `sic·SIC` — the safe, bounds-checked build. Its overhead
over unchecked code is tiny; see the frontend comparison below.)

### Reading the numbers

`sic` produces **correct** code (every checksum matches C and Rust) and lands between
~1.4× and ~9× slower than the LLVM toolchains, depending on the workload:

- **`sieve` (1.36×)** — memory-bandwidth-bound, so back-end code quality barely
  matters; `sic` is nearly on par.
- **`fib` (5.6×)** — dominated by function-call overhead; `sic`/Cranelift does less
  aggressive inlining and call optimization than LLVM.
- **`matmul` (~8.8×)** — the LLVM toolchains auto-vectorize the inner loop into SIMD;
  `sic`'s Cranelift back end emits scalar code, so it pays the full ~1 B scalar
  multiplies.

Almost all of that gap is the **back end (Cranelift vs LLVM)**, not memory safety:
the bounds-checked `sic·SIC` build runs within ~0–13% of `sic`'s own *unchecked* C
build (see the frontend comparison below).

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
             gcc     sic·C    sic·SIC   safety overhead (sic·SIC / sic·C)
fib         0.25s    5.56x     5.56x    1.00x
sieve       0.55s    1.33x     1.36x    1.03x
matmul      0.12s    7.83x     8.83x    1.13x
quicksort   0.14s    1.50x     1.50x    1.00x   (see note)
mandelbrot  0.13s    2.92x     2.92x    1.00x   (no arrays → no checks)
```

`mandelbrot` has no arrays, so there is nothing to bounds-check; it is a pure `f64`
test and `sic·SIC` == `sic·C` trivially. `quicksort` shows 1.00× for a subtler
reason: its hot partition loop indexes a pointer **parameter** (`int *a`), and SIC
currently bounds-checks only `new[]`/`@` **locals** — a fat pointer passed to a
function loses its size header, so the callee runs unchecked (like C). Only the
`new i32[N]` fill loop in `main` is checked (and loop-BCE hoists that). So quicksort's
hot path isn't actually protected today; propagating the fat header through pointer
parameters is future work. (`quicksort` is also only ~1.5× gcc because its branchy
partition can't be auto-vectorized, shrinking the Cranelift-vs-LLVM gap.)

The frontends emit **equivalent code** (an experiment compiling a `malloc`-based
`main.sic` matches `sic·C`), so the `sic·SIC` vs `sic·C` column isolates the cost of
the **idiomatic SIC memory model**: `new T[]` arrays are bounds-checked, which the C
`malloc` versions are not. That safety overhead is now **1.00×–1.13×** — a UB-free,
bounds-checked program runs within ~0–13% of the same code with raw unchecked
pointers, even on a compute-bound kernel that hammers array indices ~1e9 times.

Getting there took four back-end/front-end optimizations, each safe (a real
out-of-bounds access still aborts):

1. **`readonly` size load** — the immutable fat-pointer size header is read with a
   hoistable, CSE-able load.
2. **index-vs-count compare** — the check compares the index against the element
   count (derived from that hoistable load), off the per-access multiply path.
3. **register promotion (mem2reg)** of address-not-escaping pointer locals — the base
   pointer stays in a register instead of being reloaded each iteration (this also
   sped the *unchecked* `sic·C` matmul ~18%).
4. **loop bounds-check elimination** — a counting loop whose accesses are provably
   in-bounds gets one hoisted check on the index extremes, and the per-iteration
   checks vanish. This is what took matmul's safety overhead from 1.88× to 1.13×.

The remaining gap to gcc/rustc (matmul ~7.8×, fib ~5.6×) is **not** about safety — it
is the back end: `sic` uses Cranelift (fast compile, scalar output) rather than LLVM,
so it does not auto-vectorize matmul's inner loop or inline as aggressively. That is a
separate axis from memory safety, which these numbers show is nearly free.
