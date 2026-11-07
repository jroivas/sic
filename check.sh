#!/usr/bin/env bash
#
# check.sh — "check it all". Full verification of the sic compiler:
#   1. build the compiler in BOTH profiles (./build.sh release, ./build.sh debug)
#      with BOTH back ends (Cranelift and LLVM), each of which also rebuilds +
#      installs the std/art sysroot for that profile;
#   2. run the compile-test suite (compiletest_rust.sh) with BOTH profiles;
#   3. run that suite with the RELEASE compiler at every optimization level
#      (-O0 -O1 -O2 -O3 -Os -Oz);
#   4. run the module-test suite (moduletest_rust.sh) with BOTH profiles.
# Steps 2-4 run once per back end (SIC_BACKEND=cranelift, SIC_BACKEND=llvm).
# The compile tests run JOBS at a time (default: nproc); JOBS=1 runs them in turn.
# The LLVM back end needs LLVM 21; without it the build step fails.
#
# BAILS OUT on the first failure (build error, or any test not passing) and prints
# the tail of that step's log. The suites run with FAILFAST=1 so they stop and exit
# non-zero at the first failing test. Prints "ALL CHECKS PASSED" and exits 0 only if
# every step succeeded. Each profile's suites run right after that profile's build,
# so the per-profile std/art sysroot matches the compiler under test.
#
# Usage: ./check.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
cd "$ROOT"
LOGDIR="$(mktemp -d /tmp/sic_check.XXXXXX)"
DBG="$ROOT/siccomp/target/debug/sic"
REL="$ROOT/siccomp/target/release/sic"
# Every back end is checked: each suite runs once per back end.
BACKENDS=(cranelift llvm)
BUILD_BACKENDS="$(IFS=,; echo "${BACKENDS[*]}")"
# Compile tests run this many at once (results are reported in test order).
export JOBS="${JOBS:-$(nproc)}"
# Append one timing record per successful run here (git-ignored) — a history to
# watch for build/compile-time regressions.
TIMES_FILE="$ROOT/.check_times.log"
START=$(date +%s)
STEP=0
RECORD=""   # accumulates "key=seconds" pairs, one per step

fail() {   # fail <description> [logfile]
    echo ""
    echo "================================================================"
    echo "❌ CHECK FAILED: $1"
    if [ -n "${2:-}" ] && [ -f "$2" ]; then
        echo "---- last 40 lines of $2 ----"
        tail -40 "$2"
    fi
    echo "================================================================"
    echo "(full logs in $LOGDIR)"
    exit 1
}

# step <description> <command...> — run a command (timed), bail on non-zero exit.
step() {
    local desc="$1"; shift
    STEP=$((STEP + 1))
    local log="$LOGDIR/step$(printf '%02d' "$STEP").log"
    printf ">> [%02d] %s\n" "$STEP" "$desc"
    local t0 t1 dt
    t0=$(date +%s)
    if ! "$@" >"$log" 2>&1; then
        fail "$desc" "$log"
    fi
    t1=$(date +%s); dt=$((t1 - t0))
    # Record this step's duration under a sanitized key (spaces/punctuation → _).
    local key; key="$(printf '%s' "$desc" | tr -c 'A-Za-z0-9' '_' | sed -E 's/_+/_/g; s/^_|_$//g')"
    RECORD="$RECORD ${key}=${dt}"
    # For test suites, also sanity-check the "Passed N/N" summary (belt and
    # suspenders — the suites already exit non-zero under FAILFAST=1).
    local line
    line="$(grep -E '^Passed [0-9]+/[0-9]+' "$log" | tail -1)"
    if [ -n "$line" ]; then
        local nums="${line#Passed }"
        local passed="${nums%/*}" total="${nums#*/}"
        if [ "$passed" != "$total" ] || [ "$total" = "0" ]; then
            fail "$desc ($line)" "$log"
        fi
        printf "   %s\n" "$line"
    fi
}

echo "sic check-it-all — logs in $LOGDIR"
echo ""

# has_backends <sic> — the compiler has every back end in BACKENDS.
has_backends() {
    local have; have="$("$1" -print-backends)" || return 1
    local b
    for b in "${BACKENDS[@]}"; do
        grep -qx "$b" <<< "$have" || { echo "$1 has no back end '$b' (has: $have)"; return 1; }
    done
}

# ── Release profile ───────────────────────────────────────────────────────────
echo "== RELEASE =="
step "build compiler + sysroot (release)" ./build.sh release --backend "$BUILD_BACKENDS"
step "back ends (release)" has_backends "$REL"
for be in "${BACKENDS[@]}"; do
    step "moduletest (release, $be)" \
        env SIC="$REL" SIC_BACKEND="$be" FAILFAST=1 ./moduletest_rust.sh "$LOGDIR/mod_release_$be"
    # Compile-test suite at every optimization level with the release compiler —
    # covers both "compiletest with release" and the optimization-level sweep.
    for opt in -O0 -O1 -O2 -O3 -Os -Oz; do
        step "compiletest (release, $be, $opt)" \
            env SIC="$REL" SIC_BACKEND="$be" CFLAGS="$opt" FAILFAST=1 \
                ./compiletest_rust.sh "$LOGDIR/ct_release_$be$opt"
    done
done

# ── Debug profile ───────────────────────────────────────────────────────────
echo ""
echo "== DEBUG =="
step "build compiler + sysroot (debug)" ./build.sh debug --backend "$BUILD_BACKENDS"
step "back ends (debug)" has_backends "$DBG"
for be in "${BACKENDS[@]}"; do
    step "compiletest (debug, $be, -O0)" \
        env SIC="$DBG" SIC_BACKEND="$be" FAILFAST=1 ./compiletest_rust.sh "$LOGDIR/ct_debug_$be"
    step "moduletest (debug, $be)" \
        env SIC="$DBG" SIC_BACKEND="$be" FAILFAST=1 ./moduletest_rust.sh "$LOGDIR/mod_debug_$be"
done

# ── Done ─────────────────────────────────────────────────────────────────────
ELAPSED=$(( $(date +%s) - START ))

# Compare against the previous run's total (last record) before appending, so a
# creeping build/compile-time regression is visible run over run.
PREV=""
if [ -f "$TIMES_FILE" ]; then
    # Only runs over the same back ends compare.
    PREV="$(grep -F " backends=$BUILD_BACKENDS " "$TIMES_FILE" | grep -oE 'total=[0-9]+' | tail -1 | cut -d= -f2)"
fi

TSTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
printf '%s commit=%s backends=%s total=%d%s\n' "$TSTAMP" "$COMMIT" "$BUILD_BACKENDS" "$ELAPSED" "$RECORD" >> "$TIMES_FILE"

echo ""
echo "================================================================"
echo "✅ ALL CHECKS PASSED  (${STEP} steps, ${ELAPSED}s)"
if [ -n "$PREV" ]; then
    DELTA=$(( ELAPSED - PREV ))
    SIGN="+"; [ "$DELTA" -lt 0 ] && SIGN=""
    # Percent change (integer), guarding divide-by-zero.
    PCT=0; [ "$PREV" -gt 0 ] && PCT=$(( DELTA * 100 / PREV ))
    printf "   previous: %ss   now: %ss   delta: %s%ss (%s%d%%)\n" \
        "$PREV" "$ELAPSED" "$SIGN" "$DELTA" "$SIGN" "$PCT"
    if [ "$PCT" -ge 20 ]; then
        echo "   ⚠️  possible compile-time regression (>=20% slower than last run)"
    fi
else
    echo "   (first recorded run — baseline saved to .check_times.log)"
fi
echo "   timings appended to $TIMES_FILE"
echo "================================================================"
rm -rf "$LOGDIR"
