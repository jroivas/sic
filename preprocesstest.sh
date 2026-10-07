#!/usr/bin/env bash
# Preprocessor tests: tests/preprocess_NNNN.sic.
#
#   ./preprocesstest.sh [PREPROCESSOR [ARGS...]]
#
# PREPROCESSOR (or $CPP) is any `cpp`-compatible command; default: this
# repository's sic-cpp (sic-cpp/sic-cpp, must be built). Shorthands:
#   sic-cpp   the repository's sic-cpp
#   cpp       the system `cpp`            (also: global)
#   sic       `sic -E`  ($SIC, else siccomp/target/{release,debug}/sic)
#   both      run the suite with sic-cpp and with cpp; fail if either fails
#
# A test passes when:
#   * NAME.sic.res exists: the preprocessed output — minus linemarker/directive
#     lines (`#…`) and empty lines — equals NAME.sic.res (minus its empty lines);
#   * no NAME.sic.res: the preprocessor must FAIL (exit non-zero), e.g. `#if`
#     without an expression.
# NAME.sic.xfail marks a known failure: a failing result is reported as XFAIL
# (not counted as a failure), an unexpected pass as XPASS.
#
# VERBOSE=1 shows the diff of a failing test; FAILFAST=1 stops at the first one.
set -u

MYDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TESTDIR="$MYDIR/tests"
VERBOSE="${VERBOSE:-}"
FAILFAST="${FAILFAST:-}"
TIMEOUT="${TIMEOUT:-10}"

if [ $# -gt 0 ]; then CPPCMD=("$@"); else read -r -a CPPCMD <<< "${CPP:-sic-cpp}"; fi
case "${CPPCMD[0]}" in
    both)
        rc=0
        for p in sic-cpp cpp; do echo "=== $p"; "$0" "$p" || rc=1; done
        exit $rc
        ;;
    sic-cpp)
        CPPCMD=("$MYDIR/sic-cpp/sic-cpp" "${CPPCMD[@]:1}")
        if [ ! -x "${CPPCMD[0]}" ]; then echo "no sic-cpp at ${CPPCMD[0]} — build it: ./build.sh"; exit 2; fi
        newer="$(find "$MYDIR/sic-cpp/src" -newer "${CPPCMD[0]}" -print -quit 2>/dev/null)"
        [ -n "$newer" ] && echo "WARNING: ${CPPCMD[0]} is older than $newer — rebuild it (make -C sic-cpp)" >&2
        ;;
    global) CPPCMD=(cpp "${CPPCMD[@]:1}") ;;
    sic)
        SIC="${SIC:-}"
        if [ -z "$SIC" ]; then
            for p in release debug; do
                [ -x "$MYDIR/siccomp/target/$p/sic" ] && { SIC="$MYDIR/siccomp/target/$p/sic"; break; }
            done
        fi
        if [ -z "$SIC" ] || [ ! -x "$SIC" ]; then echo "no sic compiler found — build it: ./build.sh"; exit 2; fi
        CPPCMD=("$SIC" -E "${CPPCMD[@]:1}")
        ;;
esac
echo "preprocessor: ${CPPCMD[*]}"

WORK="$(mktemp -d /tmp/preprocesstest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

total=0; passed=0; failed=0; xfailed=0; xpassed=0
for test in "$TESTDIR"/preprocess*.sic; do
    [ -e "$test" ] || continue
    name="$(basename "$test")"
    total=$((total + 1))
    # Run from the test directory, so a test can #include its neighbours.
    ( cd "$TESTDIR" && timeout "$TIMEOUT" "${CPPCMD[@]}" "$name" ) > "$WORK/out" 2> "$WORK/err"
    rc=$?
    ok=0; why=""
    if [ -e "$test.res" ]; then
        if [ $rc -ne 0 ]; then
            why="preprocessor failed (exit $rc): $(head -c 200 "$WORK/err")"
        else
            grep -v '^#' "$WORK/out" | grep -v '^$' > "$WORK/got"
            grep -v '^$' "$test.res" > "$WORK/want"   # empty lines never count
            if cmp -s "$WORK/got" "$WORK/want"; then ok=1; else why="output differs"; fi
        fi
    else
        if [ $rc -ne 0 ]; then ok=1; else why="expected the preprocessor to fail, but it succeeded"; fi
    fi

    if [ -e "$test.xfail" ]; then
        if [ $ok -eq 1 ]; then echo "XPASS $name (marked .xfail)"; xpassed=$((xpassed + 1)); passed=$((passed + 1))
        else xfailed=$((xfailed + 1)); fi
        continue
    fi
    if [ $ok -eq 1 ]; then passed=$((passed + 1)); continue; fi
    failed=$((failed + 1))
    echo "FAIL $name: $why"
    if [ -n "$VERBOSE" ] && [ -e "$test.res" ] && [ $rc -eq 0 ]; then
        diff "$WORK/want" "$WORK/got" | sed 's/^/    /' | head -20
    fi
    if [ -n "$FAILFAST" ]; then break; fi
done

extra=""
[ $xfailed -gt 0 ] && extra="$extra, $xfailed xfail"
[ $xpassed -gt 0 ] && extra="$extra, $xpassed xpass"
echo "Passed $passed/$((total - xfailed))${extra}"
[ $failed -eq 0 ]
