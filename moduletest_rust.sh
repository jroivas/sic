#!/usr/bin/env bash
# Folder-based module tests (sic.md §"Imports"), mirroring compiletest_rust.sh.
#
# Each case is a directory under module_test/. The runner:
#   1. builds every `mod-*/` subdir with `sic --emit-module` (in sorted order, so a
#      dependency named to sort first is built before the module that imports it),
#      accumulating a `-I` for each so a later module can import an earlier one;
#   2. compiles `main.sic` against those `-I`s (plus the std sysroot, auto-resolved)
#      and runs it;
#   3. checks the exit code (`main.res`, default 0) and, if present, exact stdout
#      (`main.out`);
#   4. runs it under valgrind and requires a clean report (unless a `no-valgrind`
#      marker file is present, or valgrind is unavailable).
#
# A case with no `mod-*/` dir is a pure-`std` test (std resolves via the sysroot).
set -u

MYDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TESTDIR="$MYDIR/module_test"
SIC="${SIC:-$MYDIR/siccomp/target/debug/sic}"
VALGRIND="${VALGRIND:-valgrind}"

outroot="${1:-/tmp/sic_module_tests}"
rm -rf "$outroot"; mkdir -p "$outroot"

tests=0; success=0; failed_list=()

run_case() {
    local dir="$1"
    local name; name=$(basename "$dir")
    tests=$((tests + 1))
    local work="$outroot/$name"
    mkdir -p "$work"
    cp -r "$dir"/. "$work/"

    # Build each module dir (mod-*), earliest-sorted first, so an earlier module is
    # importable by a later one. Each built module adds a `-I` for the rest.
    local incs=()
    local mod
    for mod in "$work"/mod-*/; do
        [ -d "$mod" ] || continue
        if ! "$SIC" --emit-module "$mod" "${incs[@]+"${incs[@]}"}" 2>"$work/build.err"; then
            echo "FAIL $name: building module $(basename "$mod") failed"
            sed 's/^/    /' "$work/build.err"
            return 1
        fi
        incs+=("-I$mod")
    done

    if [ ! -f "$work/main.sic" ]; then
        echo "FAIL $name: no main.sic"
        return 1
    fi
    # `main.xfail`: the consumer MUST fail to compile (a namespacing/typing rule).
    # Any non-empty content is required to appear in the error output.
    if [ -f "$dir/main.xfail" ]; then
        if "$SIC" "$work/main.sic" "${incs[@]+"${incs[@]}"}" -o "$work/main" 2>"$work/compile.err"; then
            echo "FAIL $name: expected a compile error but it compiled"
            return 1
        fi
        local need; need="$(cat "$dir/main.xfail")"
        if [ -n "$need" ] && ! grep -qF "$need" "$work/compile.err"; then
            echo "FAIL $name: compile error did not mention '$need'"
            sed 's/^/    /' "$work/compile.err"
            return 1
        fi
        echo "PASS $name (expected compile error)"
        return 0
    fi
    if ! "$SIC" "$work/main.sic" "${incs[@]+"${incs[@]}"}" -o "$work/main" 2>"$work/compile.err"; then
        echo "FAIL $name: consumer compile/link failed"
        sed 's/^/    /' "$work/compile.err"
        return 1
    fi

    local expected_exit=0
    [ -f "$dir/main.res" ] && expected_exit=$(cat "$dir/main.res")

    local got_out got_exit
    got_out="$("$work/main")"; got_exit=$?

    if [ "$got_exit" -ne "$expected_exit" ]; then
        echo "FAIL $name: expected exit $expected_exit, got $got_exit"
        return 1
    fi
    if [ -f "$dir/main.out" ]; then
        local want; want="$(cat "$dir/main.out")"
        if [ "$got_out" != "$want" ]; then
            echo "FAIL $name: stdout mismatch"
            printf 'want:\n%s\ngot:\n%s\n' "$want" "$got_out" | sed 's/^/    /'
            return 1
        fi
    fi
    if [ ! -f "$dir/no-valgrind" ] && command -v "$VALGRIND" >/dev/null 2>&1; then
        if ! "$VALGRIND" -q --error-exitcode=99 --leak-check=full "$work/main" >/dev/null 2>&1; then
            echo "FAIL $name: valgrind reported a leak/error"
            return 1
        fi
    fi

    echo "PASS $name (exit $got_exit)"
    return 0
}

for dir in "$TESTDIR"/*/; do
    [ -d "$dir" ] || continue
    if run_case "$dir"; then
        success=$((success + 1))
    else
        failed_list+=("$(basename "$dir")")
    fi
done

echo ""
echo "Passed ${success}/${tests}"
if [ ${#failed_list[@]} -gt 0 ]; then
    echo "Failed: ${failed_list[*]}"
    exit 1
fi
