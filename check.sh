#!/usr/bin/env bash
#
# check.sh — "check it all". Full verification of the sic compiler:
#   1. build the compiler in BOTH profiles (./build.sh release, ./build.sh debug),
#      each of which also rebuilds + installs the std/art sysroot for that profile;
#   2. run the compile-test suite (compiletest_rust.sh) with BOTH profiles;
#   3. run that suite with the RELEASE compiler at every optimization level
#      (-O0 -O1 -O2 -O3 -Os -Oz);
#   4. run the module-test suite (moduletest_rust.sh) with BOTH profiles.
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
START=$(date +%s)
STEP=0

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

# step <description> <command...> — run a command, bail on non-zero exit.
step() {
    local desc="$1"; shift
    STEP=$((STEP + 1))
    local log="$LOGDIR/step$(printf '%02d' "$STEP").log"
    printf ">> [%02d] %s\n" "$STEP" "$desc"
    if ! "$@" >"$log" 2>&1; then
        fail "$desc" "$log"
    fi
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

# ── Release profile ───────────────────────────────────────────────────────────
echo "== RELEASE =="
step "build compiler + sysroot (release)" ./build.sh release
step "moduletest (release)" \
    env SIC="$REL" FAILFAST=1 ./moduletest_rust.sh "$LOGDIR/mod_release"
# Compile-test suite at every optimization level with the release compiler — covers
# both "compiletest with release" and the optimization-level sweep.
for opt in -O0 -O1 -O2 -O3 -Os -Oz; do
    step "compiletest (release, $opt)" \
        env SIC="$REL" CFLAGS="$opt" FAILFAST=1 ./compiletest_rust.sh "$LOGDIR/ct_release$opt"
done

# ── Debug profile ───────────────────────────────────────────────────────────
echo ""
echo "== DEBUG =="
step "build compiler + sysroot (debug)" ./build.sh debug
step "compiletest (debug, -O0)" \
    env SIC="$DBG" FAILFAST=1 ./compiletest_rust.sh "$LOGDIR/ct_debug"
step "moduletest (debug)" \
    env SIC="$DBG" FAILFAST=1 ./moduletest_rust.sh "$LOGDIR/mod_debug"

# ── Done ─────────────────────────────────────────────────────────────────────
ELAPSED=$(( $(date +%s) - START ))
echo ""
echo "================================================================"
echo "✅ ALL CHECKS PASSED  (${STEP} steps, ${ELAPSED}s)"
echo "================================================================"
rm -rf "$LOGDIR"
