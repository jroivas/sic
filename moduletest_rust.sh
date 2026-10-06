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
# Profile, as with ./build.sh: `./moduletest_rust.sh [release|debug] [...]` or
# PROFILE=release; default debug. An explicit SIC=/path/to/sic wins. SIC is
# exported so nested runs (CPP_MODE=both) test the same binary.
PROFILE="${PROFILE:-debug}"
case "${1:-}" in release|debug) PROFILE="$1"; shift ;; esac
case "$PROFILE" in release|debug) ;; *) echo "unknown profile '$PROFILE' (release, debug)"; exit 2 ;; esac
SIC="${SIC:-$MYDIR/siccomp/target/$PROFILE/sic}"
if [ ! -x "$SIC" ]; then echo "no compiler at $SIC — build it: ./build.sh $PROFILE"; exit 2; fi
export SIC
VALGRIND="${VALGRIND:-valgrind}"

# Guard against testing a stale compiler: warn when any compiler source is
# newer than the binary under test (e.g. only the release build was rebuilt).
if [ -x "$SIC" ] && [ -d "$MYDIR/siccomp/crates" ]; then
    newer="$(find "$MYDIR/siccomp/crates" -name '*.rs' -newer "$SIC" -print -quit 2>/dev/null)"
    [ -n "$newer" ] && echo "WARNING: $SIC is older than $newer — rebuild it (cargo build / ./build.sh)" >&2
fi
# CPP_MODE selects the preprocessor sic runs:
#   global  the system `cpp`
#   sic     this repository's sic-cpp (sic-cpp/sic-cpp; must be built)
#   both    run the whole suite once with each, and fail if either fails
#   unset   sic's own choice: $SIC_CPP, else sic-cpp on PATH, else the repo's
#           sic-cpp, else `cpp` (see `sic -print-prog-name=cpp`)
case "${CPP_MODE:-}" in
    global) export SIC_CPP="cpp" ;;
    sic)
        export SIC_CPP="$MYDIR/sic-cpp/sic-cpp"
        [ -x "$SIC_CPP" ] || { echo "CPP_MODE=sic: $SIC_CPP is not built (make -C sic-cpp)"; exit 2; }
        ;;
    both)
        both_rc=0
        for m in global sic; do
            echo "=== CPP_MODE=$m"
            CPP_MODE=$m "$0" "$@" || both_rc=1
        done
        exit $both_rc
        ;;
    "") ;;
    *) echo "unknown CPP_MODE '${CPP_MODE}' (global, sic, both)"; exit 2 ;;
esac
# (A sic older than -print-prog-name reports nothing useful; say so.)
pp_name="$("$SIC" -print-prog-name=cpp 2>/dev/null)" || pp_name=""
echo "preprocessor: ${pp_name:-unknown ($SIC predates -print-prog-name; rebuild it)}"

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
        # FAILFAST=1: stop and report at the first failure (default behavior is
        # unchanged — run everything, then the summary/exit below still apply).
        if [ -n "${FAILFAST:-}" ]; then
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
    exit 1
fi
