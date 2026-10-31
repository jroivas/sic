#!/usr/bin/env bash
# Quick check after a change, in parallel: every compile test at one optimization
# level, the preprocessor tests and the c-testsuite. For the whole matrix (all
# levels, both profiles, modules) run check.sh.
#
#   ./smoketest.sh [release|debug]
#
# OPT=-O0 picks the level (default -O2), JOBS=N the parallelism (default: all CPUs).
set -u

MYDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROFILE="${1:-release}"
OPT="${OPT:--O2}"
export JOBS="${JOBS:-$(nproc)}"
export SIC="${SIC:-$MYDIR/siccomp/target/$PROFILE/sic}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/sic_smoke.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT
rc=0

step() { printf '%-16s' "$1"; }

step "compile $OPT"
CFLAGS="$OPT" "$MYDIR/compiletest_rust.sh" "$PROFILE" "$OUT/ct" > "$OUT/ct.log" 2>&1 || rc=1
grep -E '^WARNING' "$OUT/ct.log"
grep -E '^(Passed|FAIL )' "$OUT/ct.log" | tail -n 20
grep -q '^Failed:' "$OUT/ct.log" && rc=1

step "preprocessor"
"$MYDIR/preprocesstest.sh" > "$OUT/pp.log" 2>&1 || rc=1
tail -n 1 "$OUT/pp.log"

# The c-testsuite is a separate checkout: skipped when it is not there.
CT="$MYDIR/c-testsuite/tests/single-exec"
if [ -d "$CT" ]; then
    step "c-testsuite $OPT"
    ct_one() {
        local t="$1" b; b=$(basename "$t" .c)
        if "$SIC" $OPT -w "$t" -o "$OUT/$b" -lm 2>/dev/null \
            && { timeout 10 "$OUT/$b" > "$OUT/$b.out" 2>&1; cmp -s "$OUT/$b.out" "$t.expected"; }
        then echo "PASS $b"; else echo "FAIL $b"; fi
    }
    export -f ct_one; export OPT OUT SIC
    printf '%s\n' "$CT"/*.c | xargs -P "$JOBS" -I{} bash -c 'ct_one {}' > "$OUT/cts.log"
    echo "Passed $(grep -c '^PASS' "$OUT/cts.log")/$(wc -l < "$OUT/cts.log")"
    grep '^FAIL' "$OUT/cts.log" && rc=1
fi

[ $rc -eq 0 ] && echo "smoke test passed" || echo "smoke test FAILED"
exit $rc
