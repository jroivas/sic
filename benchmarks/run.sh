#!/usr/bin/env bash
#
# run.sh — build each benchmark four ways, verify they all produce the SAME
# checksum, then time each and print a comparison table:
#
#   gcc      cc -O2       main.c      reference C toolchain (LLVM-class, gcc)
#   rustc    rustc -O     main.rs     reference Rust toolchain
#   sic·C    sic -O2      main.c      the sic compiler, C frontend
#   sic·SIC  sic -O2      main.sic    the sic compiler, SIC frontend
#
# The last two go through the same Cranelift back end, so comparing sic·C with
# sic·SIC isolates any difference between sic's C and SIC frontends for the same
# algorithm. Wall-clock time is the minimum of several runs (least noise).
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
# Per-benchmark timing history: one line per run appended to
# benchmarks/.<name>.times.log (git-ignored), for tracking speed regressions.
TSTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

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

# ratio <time> <baseline> — "<t>s  (N.NNx <label>)"
ratio() { awk -v t="$1" -v c="$2" -v l="$3" 'BEGIN{printf "%7ss  (%.2fx %s)", t, t/c, l}'; }

printf "sic benchmarks — RUNS=%s, sic=%s\n\n" "$RUNS" "$SIC"

for name in "${benches[@]}"; do
    dir="$ROOT/$name"
    echo "== $name =="

    # --- build all four ---
    fail=0
    "$CC" -O2 "$dir/main.c" -o "$BUILD/$name.gcc" 2>"$BUILD/e" \
        || { echo "  gcc: BUILD FAILED"; sed 's/^/    /' "$BUILD/e"; fail=1; }
    "$RUSTC" -O "$dir/main.rs" -o "$BUILD/$name.rustc" 2>"$BUILD/e" \
        || { echo "  rustc: BUILD FAILED"; sed 's/^/    /' "$BUILD/e"; fail=1; }
    { "$SIC" -c "$dir/main.c" -o "$BUILD/$name.sicc.o" -O2 2>"$BUILD/e" \
        && "$CC" "$BUILD/$name.sicc.o" -o "$BUILD/$name.sicc" -lm 2>>"$BUILD/e"; } \
        || { echo "  sic·C: BUILD FAILED"; grep -iv note "$BUILD/e" | sed 's/^/    /'; fail=1; }
    { "$SIC" -c "$dir/main.sic" -o "$BUILD/$name.sicsic.o" -O2 2>"$BUILD/e" \
        && "$CC" "$BUILD/$name.sicsic.o" -o "$BUILD/$name.sicsic" -lm 2>>"$BUILD/e"; } \
        || { echo "  sic·SIC: BUILD FAILED"; grep -iv note "$BUILD/e" | sed 's/^/    /'; fail=1; }
    [ "$fail" = 0 ] || { echo; continue; }

    # --- correctness: all four checksums must match ---
    ck_gcc=$("$BUILD/$name.gcc")
    ck_rs=$("$BUILD/$name.rustc")
    ck_sc=$("$BUILD/$name.sicc")
    ck_ss=$("$BUILD/$name.sicsic")
    if [ "$ck_gcc" != "$ck_rs" ] || [ "$ck_gcc" != "$ck_sc" ] || [ "$ck_gcc" != "$ck_ss" ]; then
        echo "  CHECKSUM MISMATCH — gcc=$ck_gcc rustc=$ck_rs sic·C=$ck_sc sic·SIC=$ck_ss"; echo; continue
    fi

    # --- time ---
    t_gcc=$(min_time "$BUILD/$name.gcc")
    t_rs=$(min_time "$BUILD/$name.rustc")
    t_sc=$(min_time "$BUILD/$name.sicc")
    t_ss=$(min_time "$BUILD/$name.sicsic")

    printf "  checksum=%s  (all four agree)\n" "$ck_gcc"
    printf "  %-8s %8ss  (baseline)\n" "gcc"     "$t_gcc"
    printf "  %-8s %s\n" "rustc"   "$(ratio "$t_rs" "$t_gcc" "gcc")"
    printf "  %-8s %s\n" "sic·C"   "$(ratio "$t_sc" "$t_gcc" "gcc")"
    printf "  %-8s %s\n" "sic·SIC" "$(ratio "$t_ss" "$t_gcc" "gcc")"
    # sic·SIC vs sic·C: same compiler, same back end, so this is the delta between
    # sic's C and SIC frontends *for the code each was given*. Note the SIC versions
    # use bounds-checked `new T[]` arrays while the C versions use raw malloc, so a
    # gap here reflects that safety feature, not frontend codegen quality (see README).
    printf "  sic·SIC vs sic·C: %s\n" \
        "$(awk -v s="$t_ss" -v c="$t_sc" 'BEGIN{ r=s/c; printf "%.2fx (%s)", r, (r>1.02)?"slower":((r<0.98)?"faster":"on par") }')"

    # Append this run's times to benchmarks/.<name>.times.log, and (if there is a
    # prior run) report the sic·SIC delta so a speed regression is visible run over run.
    local_log="$ROOT/.$name.times.log"
    prev_ss=""
    [ -f "$local_log" ] && prev_ss="$(grep -oE 'sicsic=[0-9.]+' "$local_log" | tail -1 | cut -d= -f2)"
    printf '%s commit=%s gcc=%s rustc=%s sicc=%s sicsic=%s\n' \
        "$TSTAMP" "$COMMIT" "$t_gcc" "$t_rs" "$t_sc" "$t_ss" >> "$local_log"
    if [ -n "$prev_ss" ]; then
        printf "  sic·SIC vs previous run: %s\n\n" \
            "$(awk -v n="$t_ss" -v p="$prev_ss" 'BEGIN{ d=n-p; r=(p>0)?d/p*100:0; printf "%+.2fs (%+.0f%%)%s", d, r, (r>=10)?"  ⚠ slower":"" }')"
    else
        printf "  (first recorded run for %s)\n\n" "$name"
    fi
done
