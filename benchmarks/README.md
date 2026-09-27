# Benchmarks

Small CPU-bound micro-benchmarks implemented three times with the **same algorithm**
— in C, Rust, and SIC — to compare the code the `sic` compiler produces against
mainstream LLVM-backed toolchains.

Each benchmark lives in its own directory with `main.c`, `main.rs`, and `main.sic`.
The `.sic` files are **idiomatic SIC**, not copies of the C: native fixed-width types
(`i32`/`i64`/`u8`/`u32`/`u64`/`bool`/`f64`), heap arrays via `new T[count]` released
with `defer del` (freed on every scope exit, no explicit free at each return). These
are numeric kernels, so the large flat buffers are heap arrays — SIC's boxed containers
(`list`/`dict`/`set`) target dynamic or heterogeneous data and would be pathological
here (a `list<bool>` for a 100 M-entry sieve is ~2.4 GB, and boxed element access in
matmul's ~1e9-iteration inner loop would dwarf the arithmetic). Every program prints a
single integer **checksum**; the runner requires all three to agree before it trusts
any timing, so a miscompile shows up as a checksum mismatch rather than a wrong speed.

## Benchmarks

| benchmark    | what it stresses                                        | checksum          |
|--------------|---------------------------------------------------------|-------------------|
| `fib`        | recursion / function-call overhead (`fib(42)`)          | `267914296`       |
| `sieve`      | tight loops + memory bandwidth (sieve to 100 M)         | `5761455`         |
| `matmul`     | nested loops + array indexing (1024×1024 int matmul)    | `2630909442048`   |
| `quicksort`  | recursion + data-dependent swaps / irregular access (3 M ints) | `187506306455265` |
| `mandelbrot` | floating-point compute, no arrays (1000×1000, 256 iters)| `253815`          |
| `divmix`     | compute-bound integer division by constants (200 M iters)| `4555444155444655`|
| `dotprod`    | vectorizable integer reduction, memory-bound (50 M pairs)| `13869450000000`  |
| `stencil`    | 1-D 3-point blur, multi-offset same-array reads (3000 passes)| `12442510`     |
| `bytecount`  | byte predicate count (`>= 128`), packed-compare reduction (20 passes)| `200000000` |
| `collatz`    | unpredictable branches + integer divide/modulo (3 M)    | `428343467`      |
| `ptrchase`   | memory latency: random pointer cycle through 64 MB      | `201066277`      |
| `hash`       | integer ALU: FNV-1a hashing (32 M bytes ×4)             | `1492286917`     |
| `bst`        | heap allocation + pointer chasing: 1M-node BST          | `1550171856`     |
| `rle`        | branchy byte processing: run-length encoding (40 M ×4)  | `1175180821`     |
| `base64`     | bit manipulation + table lookup (24 M ×4)               | `3021960101`     |
| `dispatch`   | indirect-branch prediction: 4 function pointers (4 M ×32)| `2148621765`    |
| `nbody`      | FP latency: all-pairs gravity, Newton sqrt (2048 ×8)    | `1738354361`     |
| `stream`     | memory write bandwidth: STREAM triad (16 M ×40)         | `473966592`      |
| `nqueens`    | backtracking recursion: 14-queens bitmask solver        | `365596`          |
| `life`       | 2D stencil: Conway's Game of Life (1024×1024, 300 gen)  | `2926690816`     |
| `hashmap`    | open-addressing hash map: 8M inserts + 16M lookups      | `731508049`      |
| `sha256`     | crypto mixing: full SHA-256 compression (4 MB ×16)      | `2967872896`     |
| `transpose`  | cache stride / TLB: naive matrix transpose (4096² ×6)   | `2575302656`     |
| `editdist`   | dynamic programming: Levenshtein distance (16K ×16K)    | `8296`            |
| `lz`         | branchy match search: LZ77 (4 MB, 512-byte window)      | `2977252358`     |
| `crc32`      | table-driven hashing: CRC32 (16 MB ×8)                  | `3210205936`     |
| `raster`     | software 3D renderer: Gouraud-shaded sphere (240 frames) | `2791669399382346646` |
| `inputlat`   | input latency simulation: event pipeline (20× 1M events)| `1524205649`     |

`fib` reads its argument through a `volatile` / `black_box` so no compiler can fold
the recursion to a constant; `sieve`, `matmul`, `quicksort`, `bst`, `hashmap`,
`transpose` and `editdist` are data-dependent on heap arrays, so the work cannot be
optimized away; `mandelbrot`, `nbody` and `nqueens` exercise pure compute (FP
arithmetic, recursion, bitmask operations) with minimal memory. `stencil` and
`bytecount` are **gap-finders**: they isolate two auto-vectorizations sic's front
end does NOT do. `stencil`'s `b[i] = (a[i-1] + 2·a[i] + a[i+1])·¼` reads the same
array at three offsets, which sic's auto-vectorizer bails on (it requires one affine
offset per array), so it runs scalar where LLVM emits shifted packed loads.
`bytecount` is a predicate reduction (`if (buf[i] >= 128) cnt++`) that LLVM turns
into `pcmpgtb`/`pmovmskb` + popcount 16 bytes at a time; sic branches per byte.

The newer benchmarks (`collatz` through `inputlat`) use only 32-bit wrapping integer
arithmetic (an LCG built from multiply + add) so all language builds stay bit-identical
without BigInt. `nbody` uses only `+ - * /` and a hand-rolled Newton-iteration `sqrt`
(no `libm`), so its doubles round identically across all backends — the same trick
`raster` uses for its polynomial sin/cos.

`raster` is a real (if tiny) software 3D renderer with no external dependencies — it
transforms and projects a UV-sphere mesh, rasterizes triangles with a z-buffer, and
Gouraud-shades them into an in-memory framebuffer, then folds the framebuffer into the
per-frame checksum. To stay bit-identical across all languages it uses **only**
`+ - * /` and comparisons: it ships its own polynomial `sin`/`cos` (each language's
`libm`/`Math.sin` differs in the last bits) and avoids `sqrt` entirely (the unit-sphere
vertex _is_ its own normal).

`inputlat` simulates an interactive UI event pipeline — 20M key/mouse events arrive on
a ring-buffer queue and drain through a fixed-timestep 250 Hz frame loop with a serial
per-event handler cost; each event's latency feeds the checksum. Every pointer event
hit-tests a 1024-widget tree through a 16×10 spatial grid and bubbles up the parent
chain. Hover enter/leave, double-click and drag state are tracked, and held keys fire
synthetic key-repeat events through a timer min-heap with their own latency accounting.

## Source

The 19 benchmarks added after `bytecount` (`collatz` through `inputlat`) are ported
from [MariuzM/bench](https://github.com/MariuzM/bench) (commit
`9f4eb7f1ae1f8407687588ac546b70274c896867`), a multi-language benchmark suite
comparing C, C++, Jai, JavaScript (Node.js), Odin, and Rust on 24 workloads. The
existing benchmarks (`fib`, `sieve`, `matmul`, `quicksort`, `mandelbrot`, `divmix`,
`dotprod`, `stencil`, `bytecount`) pre-date this import and use a different parameter
set. C and Rust implementations (`main.c` / `main.rs`) are extracted from the upstream
combined-source files; the SIC ports (`main.sic`) follow the idiomatic SIC patterns
established by the original suite.

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

Each run also appends one line per benchmark to `benchmarks/.<name>.times.log`
(git-ignored) for tracking speed regressions over time, and prints the `sic·SIC`
delta versus the previous run:

```
2026-09-19T20:30:48Z commit=10de755 gcc=0.24 rustc=0.45 sicc=1.34 sicsic=1.34
```

## A representative result

Measured with `RUNS=5` (gcc 15, rustc 1.93, release `sic`; one machine — treat the
ratios, not the absolute times, as the signal):

```
== fib ==        C 0.25s   Rust 0.45s (1.80x)   SIC 1.34s (5.36x C)
== matmul ==     C 0.13s   Rust 0.12s (0.92x)   SIC 0.89s (6.85x C)
== sieve ==      C 0.58s   Rust 0.58s (1.00x)   SIC 0.72s (1.24x C)
== quicksort ==  C 0.14s   Rust 0.15s (1.07x)   SIC 0.19s (1.36x C)
== mandelbrot == C 0.13s   Rust 0.13s (1.00x)   SIC 0.16s (1.23x C)
== divmix ==     C 0.29s   Rust 0.30s (1.03x)   SIC 0.32s (1.10x C)
== dotprod ==    C 0.24s   Rust 0.20s (0.83x)   SIC 0.26s (1.08x C)
```

(sic runs on Cranelift 0.132; the 0.113→0.132 upgrade added division-by-constant
strength reduction, which took `divmix` from 3.79× to 1.10×.)

(These `SIC` figures are `sic·SIC` — the safe, bounds-checked build. Its overhead
over unchecked code is small; see the frontend comparison below.)

### Reading the numbers

`sic` produces **correct** code (every checksum matches C and Rust). On five of the
seven it is within ~1.1–1.4× of the LLVM toolchains; the two remaining large gaps are
each a single advanced LLVM transform that Cranelift does not do:

- **`mandelbrot` (1.23×)**, **`sieve` (1.24×)**, **`quicksort` (1.36×)** — scalar/
  memory-bound work with no vectorization opportunity; after register promotion
  (mem2reg) `sic` is close to gcc/rustc.
- **`dotprod` (1.41×)** — vectorizable, but memory-bandwidth-bound (400 MB streamed),
  so gcc's SIMD can't pull far ahead; `sic` is close.
- **`fib` (5.4×)** — LLVM turns the recursion into an iteration (a recurrence
  transform); `sic` still makes the ~866 M real calls. Needs a recursion-elimination
  pass, not better register allocation.
- **`matmul` (~6.9×)** — LLVM auto-vectorizes the inner loop into SIMD; `sic`'s
  Cranelift back end emits scalar code, paying the full ~1 B scalar multiplies.
- **`divmix` (1.10×)** — was 3.79× on Cranelift 0.113 (a hardware `idiv` per element);
  the 0.132 upgrade brought division-by-constant strength reduction (magic multiply +
  shift), closing it. A good example of a gap that riding the back end forward fixed
  for free.

So the distance to C/Rust concentrates in just two specific missing optimizations —
recursion→iteration (`fib`) and auto-vectorization (`matmul`) — not a broad codegen
deficit. Everywhere else `sic` is now within ~1.1–1.4×.

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
divmix      0.29s    1.10x     1.10x    1.00x   (no arrays → no checks)
dotprod     0.24s    1.08x     1.08x    1.00x   (loop-BCE hoists the checks)
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
6. **Cranelift 0.113 → 0.132 upgrade** — brought division-by-constant strength
   reduction (fixing `divmix`, 3.79× → 1.10×) plus general codegen gains
   (`dotprod` 1.41× → 1.08×).

The remaining gap to gcc/rustc (matmul ~5–7×, fib ~5.4×) is **not** about safety — it
is the back end plus two missing high-level transforms: `sic` uses Cranelift (fast
compile, scalar output) rather than LLVM, so it does not auto-vectorize matmul's inner
loop, and it has no recursion→iteration pass to collapse fib's calls. Both are a
separate axis from memory safety, which these numbers show is nearly free.
