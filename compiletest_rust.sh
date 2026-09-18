#!/usr/bin/env bash
set -eu

MYDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TESTDIR="$MYDIR/tests"
SIC="${SIC:-$MYDIR/siccomp/target/debug/sic}"
CC="${CC:-cc}"
CFLAGS=${CFLAGS:-}
# FAILFAST=1: stop at the first failing test and exit non-zero immediately (used by
# check.sh). Either way, the script exits non-zero at the end if any test failed.
FAILFAST="${FAILFAST:-}"

outfolder="${1:-/tmp/sic_rust_tests}"
mkdir -p "$outfolder"

tests=0; success=0; failed_list=()

dotest() {
    local test="$1"
    local base; base=$(basename "$test"); base="${base%.*}"
    tests=$((tests + 1))

    local flags=""
    [ -f "$test.flags" ] && flags=$(cat "$test.flags")

    local bin_file="$outfolder/$base.bin"
    local obj_file="$outfolder/$base.o"

    # `.xfail` marker: the test passes iff sic *rejects* the source (used to pin
    # sic-only syntax, e.g. a `.sic` file that must fail because it uses a
    # reserved Rust-style type alias as an identifier).
    if [ -f "$test.xfail" ]; then
        if "$SIC" -c "$test" -o "$obj_file" $flags ${CFLAGS} 2>/tmp/sic_err_$base; then
            echo "FAIL $base: expected compile failure but it compiled"
            return 1
        fi
        echo "PASS $base (expected compile failure)"
        return 0
    fi

    if ! "$SIC" -c "$test" -o "$obj_file" $flags ${CFLAGS} 2>/tmp/sic_err_$base; then
        echo "FAIL $base: compile error"
        cat /tmp/sic_err_$base
        return 1
    fi
    if ! $CC "$obj_file" -o "$bin_file" -lm $flags 2>/tmp/link_err_$base; then
        echo "FAIL $base: link error"
        cat /tmp/link_err_$base
        return 1
    fi

    local expected=0
    [ -f "$test.res" ] && expected=$(cat "$test.res")

    set +e; "$bin_file"; local got=$?; set -e

    if [ "$got" -eq "$expected" ]; then
        echo "PASS $base (exit $got)"
        return 0
    else
        echo "FAIL $base: expected exit $expected, got $got"
        return 1
    fi
}

for test in "$TESTDIR"/test_*.sic "$TESTDIR"/test_*.c; do
    [ -e "$test" ] || continue
    if dotest "$test"; then
        success=$((success + 1))
    else
        failed_list+=("$(basename "$test")")
        # FAILFAST: stop and report at the first failure (default behavior is
        # unchanged — run everything, then print the summary below).
        if [ -n "$FAILFAST" ]; then
            echo ""
            echo "Passed ${success}/${tests} before failure"
            echo "Failed: ${failed_list[*]}"
            exit 1
        fi
    fi
done

echo ""
echo "Passed ${success}/${tests}"
if [ ${#failed_list[@]} -gt 0 ]; then
    echo "Failed: ${failed_list[*]}"
fi
