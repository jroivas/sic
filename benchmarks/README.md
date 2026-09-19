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
== fib ==        C 0.25s   Rust 0.45s (1.80x)   SIC 1.34s (5.36x C)
== matmul ==     C 0.13s   Rust 0.12s (0.92x)   SIC 0.89s (6.85x C)
== sieve ==      C 0.58s   Rust 0.58s (1.00x)   SIC 0.72s (1.24x C)
== quicksort ==  C 0.14s   Rust 0.15s (1.07x)   SIC 0.19s (1.36x C)
== mandelbrot == C 0.13s   Rust 0.13s (1.00x)   SIC 0.16s (1.23x C)
```

(These `SIC` figures are `sic·SIC` — the safe, bounds-checked build. Its overhead
over unchecked code is small; see the frontend comparison below.)

### Reading the numbers

`sic` produces **correct** code (every checksum matches C and Rust). On three of the
five it is within ~1.2–1.4× of the LLVM toolchains; the two large gaps are each a
single advanced LLVM transform that Cranelift does not do:

- **`mandelbrot` (1.23×)**, **`sieve` (1.24×)**, **`quicksort` (1.36×)** — scalar/
  memory-bound work with no vectorization opportunity; after register promotion
  (mem2reg) `sic` is close to gcc/rustc.
- **`fib` (5.4×)** — LLVM turns the recursion into an iteration (a recurrence
  transform); `sic` still makes the ~866 M real calls. This needs a
  recursion-elimination pass, not better register allocation.
- **`matmul` (~6.9×)** — LLVM auto-vectorizes the inner loop into SIMD; `sic`'s
  Cranelift back end emits scalar code, paying the full ~1 B scalar multiplies.

So the remaining distance to C/Rust is two specific missing optimizations
(recursion→iteration and auto-vectorization), not a broad codegen deficit.

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
fib         0.25s    5.36x     5.36x    1.00x
sieve       0.58s    1.09x     1.24x    1.14x
matmul      0.13s    5.08x     6.85x    1.35x
quicksort   0.14s    1.29x     1.36x    1.06x
mandelbrot  0.13s    1.23x     1.23x    1.00x   (no arrays → no checks)
```

`mandelbrot` has no arrays, so there is nothing to bounds-check; it is a pure `f64`
test and `sic·SIC` == `sic·C` trivially. `quicksort` is the one workload with a
larger safety overhead (1.29×): its partition does irregular, data-dependent accesses
(`a[i]`, `a[j]`, `a[hi]` where `i`/`hi` don't march in lockstep with a counting loop),
so most of its checks can't be hoisted by loop-BCE and are paid per access — the same
kind of cost Rust's bounds-checked slice indexing pays (rustc is ~1.07× gcc here).
Its array is a pointer **parameter** to a `static` helper, and SIC now propagates
fat-pointer-ness to static functions' parameters (`infer_fat_params`), so those
accesses are genuinely bounds-checked — earlier this benchmark ran that hot loop
*unchecked*. (`quicksort` is also only ~1.5–1.9× gcc because its branchy partition
can't be auto-vectorized, shrinking the Cranelift-vs-LLVM gap.)

The frontends emit **equivalent code** (an experiment compiling a `malloc`-based
`main.sic` matches `sic·C`), so the `sic·SIC` vs `sic·C` column isolates the cost of
the **idiomatic SIC memory model**: `new T[]` arrays are bounds-checked, which the C
`malloc` versions are not. That safety overhead is **1.00×–1.35×**: near-free where
the accesses are loop-regular (`fib`/`mandelbrot` 1.00×, `quicksort` 1.06×, `sieve`
1.14×) and a per-access cost on irregular indexing (`matmul` 1.35×) comparable to what
Rust's own bounds checks cost. A UB-free, bounds-checked program stays close to the
same code with raw unchecked pointers.

Getting there took five back-end/front-end optimizations, each safe (a real
out-of-bounds access still aborts):

1. **`readonly` size load** — the immutable fat-pointer size header is read with a
   hoistable, CSE-able load.
2. **index-vs-count compare** — the check compares the index against the element
   count (derived from that hoistable load), off the per-access multiply path.
3. **register promotion (mem2reg)** of address-not-escaping locals — pointers *and*
   scalars (int/float/bool) stay in registers instead of being reloaded each use, and
   two-branch store→load result merges become real SSA phis. This alone cut
   `mandelbrot` ~2.4× and `matmul` ~1.4× on the unchecked build.
4. **loop bounds-check elimination** — a counting loop whose accesses are provably
   in-bounds gets one hoisted check on the index extremes; the per-iteration checks
   vanish. Took matmul's safety overhead from 1.88× to ~1.35×.
5. **fat-pointer parameter propagation** — a `new[]` array passed to a `static`
   function stays bounds-checked in the callee (closing a real safety gap in
   quicksort), soundly (only where every call passes a fat base).

The remaining gap to gcc/rustc (matmul ~5–7×, fib ~5.4×) is **not** about safety — it
is the back end plus two missing high-level transforms: `sic` uses Cranelift (fast
compile, scalar output) rather than LLVM, so it does not auto-vectorize matmul's inner
loop, and it has no recursion→iteration pass to collapse fib's calls. Both are a
separate axis from memory safety, which these numbers show is nearly free.
