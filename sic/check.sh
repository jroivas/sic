#!/usr/bin/env bash
# Checks the franken compiler (sic/target/release/sic, built by
# sic/build.sh) with check.sh's release suites, once per back end it has: the ABI
# against GCC, the module tests, the re module, and the compile tests at every
# -O. With the SIC lexer built, the lexer comparison runs too. SIC_PARTS, when
# set, picks the stages under test (default: franken's default set).
#
# Usage: sic/check.sh          (bails out at the first failure; logs kept then)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SIC="$ROOT/sic/target/release/sic"
[ -x "$SIC" ] || { echo "no franken compiler at $SIC: run sic/build.sh"; exit 2; }
"$SIC" -print-parts > /dev/null || exit 2
export JOBS="${JOBS:-$(nproc)}"
LOGDIR="$(mktemp -d /tmp/sic_franken_check.XXXXXX)"
START=$(date +%s)
STEP=0

step() {   # step <description> <command...>
    local desc="$1"; shift
    STEP=$((STEP + 1))
    local log="$LOGDIR/step$(printf '%02d' "$STEP").log"
    printf ">> [%02d] %s\n" "$STEP" "$desc"
    if ! "$@" > "$log" 2>&1; then
        echo "❌ FAILED: $desc (logs in $LOGDIR)"
        tail -40 "$log"
        exit 1
    fi
    local line; line="$(grep -E '^Passed [0-9]+/[0-9]+' "$log" | tail -1)"
    [ -n "$line" ] && printf "   %s\n" "$line"
    return 0
}

echo "franken: $SIC"
echo "parts:   $("$SIC" -print-parts | awk 'NR > 1 && $4 == "yes" { printf "%s%s", s, $1; s = "," }')"
[ -n "${SIC_PARTS:-}" ] && echo "SIC_PARTS=$SIC_PARTS"

step "franken tests" sic/build.sh release --test
if "$SIC" -print-parts | awk '$1 == "lexer" && $2 == "yes" { f = 1 } END { exit !f }'; then
    step "lexer comparison" env FRANKEN="$SIC" sic/tests/diff-lexer.sh
fi
step "abi vs gcc" env SIC="$SIC" tests/abi/abi.sh
for be in $("$SIC" -print-backends); do
    step "moduletest ($be)" env SIC="$SIC" SIC_BACKEND="$be" FAILFAST=1 ./moduletest_rust.sh "$LOGDIR/mod_$be"
    step "moduletest C ($be)" env SIC="$SIC" SIC_BACKEND="$be" ./moduletest.sh
    step "re ($be)" env SIC="$SIC" SIC_BACKEND="$be" tests/re/re.sh
    for opt in -O0 -O1 -O2 -O3 -Os -Oz; do
        step "compiletest ($be, $opt)" env SIC="$SIC" SIC_BACKEND="$be" CFLAGS="$opt" FAILFAST=1 \
            ./compiletest_rust.sh "$LOGDIR/ct_$be$opt"
    done
done

rm -rf "$LOGDIR"
echo "✅ franken: ALL CHECKS PASSED ($STEP steps, $(( $(date +%s) - START ))s)"
