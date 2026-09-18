#!/usr/bin/env bash
#
# run.sh — build each benchmark with C (gcc), Rust (rustc) and SIC (sic), verify the
# three produce the SAME checksum, then time each and print a comparison table.
#
# Each benchmark lives in its own subdirectory with main.c / main.rs / main.sic that
# implement the identical algorithm and print one integer checksum. Wall-clock time
# is the minimum of several runs (min = least noise).
#
# Flags used (each compiler's straightforward "optimized" setting):
#   C    : cc -O2
#   Rust : rustc -O           (opt-level 2)
#   SIC  : sic -O2  (+ cc to link)   — sic's backend is Cranelift, not LLVM
#
# Usage: ./run.sh [benchmark ...]   (default: all subdirectories)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
SIC="${SIC:-$ROOT/../siccomp/target/release/sic}"
CC="${CC:-cc}"
RUSTC="${RUSTC:-rustc}"
RUNS="${RUNS:-5}"
BUILD="$(mktemp -d /tmp/sic_bench.XXXXXX)"
trap 'rm -rf "$BUILD"' EXIT

if [ ! -x "$SIC" ]; then
    echo "error: sic not found at $SIC (build it: ./build.sh release)" >&2
    exit 1
fi

benches=("$@")
if [ ${#benches[@]} -eq 0 ]; then
    for d in "$ROOT"/*/; do [ -f "$d/main.c" ] && benches+=("$(basename "$d")"); done
fi

# min_time <binary> — run it RUNS times, echo the smallest wall-clock time (seconds).
min_time() {
    local bin="$1" best="" t
    for _ in $(seq "$RUNS"); do
        t=$( { /usr/bin/time -f "%e" "$bin" >/dev/null; } 2>&1 )
        best=$(awk -v a="$best" -v b="$t" 'BEGIN{ if(a=="")print b; else print (b<a)?b:a }')
    done
    echo "$best"
}

printf "sic benchmarks — RUNS=%s, sic=%s\n\n" "$RUNS" "$SIC"

for name in "${benches[@]}"; do
    dir="$ROOT/$name"
    echo "== $name =="

    # --- build ---
    if ! "$CC" -O2 "$dir/main.c" -o "$BUILD/$name.c.bin" 2>"$BUILD/$name.c.err"; then
        echo "  C: BUILD FAILED"; sed 's/^/    /' "$BUILD/$name.c.err"; echo; continue
    fi
    if ! "$RUSTC" -O "$dir/main.rs" -o "$BUILD/$name.rs.bin" 2>"$BUILD/$name.rs.err"; then
        echo "  Rust: BUILD FAILED"; sed 's/^/    /' "$BUILD/$name.rs.err"; echo; continue
    fi
    if ! "$SIC" -c "$dir/main.sic" -o "$BUILD/$name.sic.o" -O2 2>"$BUILD/$name.sic.err" \
         || ! "$CC" "$BUILD/$name.sic.o" -o "$BUILD/$name.sic.bin" -lm 2>>"$BUILD/$name.sic.err"; then
        echo "  SIC: BUILD FAILED"; grep -iv note "$BUILD/$name.sic.err" | sed 's/^/    /'; echo; continue
    fi

    # --- correctness: all three checksums must match ---
    ck_c=$("$BUILD/$name.c.bin")
    ck_rs=$("$BUILD/$name.rs.bin")
    ck_sic=$("$BUILD/$name.sic.bin")
    if [ "$ck_c" != "$ck_rs" ] || [ "$ck_c" != "$ck_sic" ]; then
        echo "  CHECKSUM MISMATCH — C=$ck_c Rust=$ck_rs SIC=$ck_sic"; echo; continue
    fi

    # --- time ---
    t_c=$(min_time "$BUILD/$name.c.bin")
    t_rs=$(min_time "$BUILD/$name.rs.bin")
    t_sic=$(min_time "$BUILD/$name.sic.bin")

    printf "  checksum=%s  (all three agree)\n" "$ck_c"
    printf "  %-5s %8ss  %s\n" "C"    "$t_c"  "$(awk -v s="$t_sic" -v c="$t_c"  'BEGIN{printf "(baseline)"}')"
    printf "  %-5s %8ss  %s\n" "Rust" "$t_rs" "$(awk -v x="$t_rs"  -v c="$t_c"  'BEGIN{printf "(%.2fx C)", x/c}')"
    printf "  %-5s %8ss  %s\n" "SIC"  "$t_sic" "$(awk -v x="$t_sic" -v c="$t_c"  'BEGIN{printf "(%.2fx C)", x/c}')"
    echo
done
