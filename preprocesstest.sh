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

# Dependency output for standard input: only the included header is listed —
# not `<stdin>` (Linux's fixdep failed opening it, checksyscalls.sh). Targets
# differ between preprocessors (gcc `-`, clang the output), so only the
# prerequisites are compared.
total=$((total + 1))
printf 'int dep_h;\n' > "$WORK/dep_h.h"
printf '#include "dep_h.h"\nint x;\n' | ( cd "$WORK" && timeout "$TIMEOUT" "${CPPCMD[@]}" -MMD -MF "$WORK/dep.d" -x c - ) > /dev/null 2> "$WORK/err"
got="$(sed -e 's/^[^:]*://' -e 's/\\$//' "$WORK/dep.d" 2>/dev/null | tr -s ' \n' ' ' | sed 's/^ //; s/ $//')"
if [ "$got" = "dep_h.h" ]; then passed=$((passed + 1)); else
    failed=$((failed + 1)); echo "FAIL depfile-stdin: prerequisites '$got', want 'dep_h.h' $(head -c 200 "$WORK/err")"
fi

# A computed header name is spelled as is: no guard space between tokens that
# would lex as one (Linux's <trace/events/9p.h> became `9p .h`).
total=$((total + 1))
printf 'in_9p\n' > "$WORK/9p.h"
printf '#define SYS 9p\n#define H1(s) <s.h>\n#define H2(s) H1(s)\n#include H2(SYS)\n#if __has_include(H2(SYS))\nfound\n#endif\n' > "$WORK/hn.c"
got="$( (cd "$WORK" && timeout "$TIMEOUT" "${CPPCMD[@]}" -I. hn.c) 2> "$WORK/err" | grep -v '^#' | grep -v '^$' | tr '\n' '|')"
if [ "$got" = "in_9p|found|" ]; then passed=$((passed + 1)); else
    failed=$((failed + 1)); echo "FAIL header-name-spelling: got '$got' $(head -c 200 "$WORK/err")"
fi

# Assembler text allows a paste that is no single token, and adds no space after
# it (Linux's linker script: `.initcall##level##.init` became `.initcall1. init`).
total=$((total + 1))
printf '#define L(x) .foo##x##.init\nL(1)\n' > "$WORK/ap.S"
got="$( (cd "$WORK" && timeout "$TIMEOUT" "${CPPCMD[@]}" -x assembler-with-cpp -P ap.S) 2> "$WORK/err" | grep -v '^$' | tr '\n' '|')"
if [ "$got" = ".foo1.init|" ]; then passed=$((passed + 1)); else
    failed=$((failed + 1)); echo "FAIL asm-paste: got '$got' $(head -c 200 "$WORK/err")"
fi

# The sic driver's own preprocessing of an assembler source (`sic -E` on a
# `.S`, as Linux preprocesses its linker scripts with `-E -P -C -Ux86`): `-C`
# and `-U` are accepted and forwarded, and `__ASSEMBLER__` is defined as GCC
# does (the headers' C parts stayed in the script).
SICDRV=""
for p in release debug; do [ -x "$MYDIR/siccomp/target/$p/sic" ] && { SICDRV="$MYDIR/siccomp/target/$p/sic"; break; }; done
if [ -n "$SICDRV" ]; then
    total=$((total + 1))
    printf '/* kept */\n#ifdef __ASSEMBLER__\nasm_part foo\n#else\nc_part\n#endif\n' > "$WORK/drv.S"
    got="$( (cd "$WORK" && timeout "$TIMEOUT" "$SICDRV" -E -P -C -nostdinc -Dfoo=bar -Ufoo drv.S) 2> "$WORK/err" | grep -v '^$' | tr '\n' '|')"
    if [ "$got" = "/* kept */|asm_part foo|" ]; then passed=$((passed + 1)); else
        failed=$((failed + 1)); echo "FAIL driver-asm-cpp: got '$got' $(head -c 200 "$WORK/err")"
    fi
    # A strong definition in another object replaces a weak one, for callers next
    # to the weak one too: they must not have inlined it (Linux's __weak defaults).
    total=$((total + 1))
    printf 'int __attribute__((weak)) val(void) { return 1; }\nint call(void) { return val(); }\n' > "$WORK/w1.c"
    printf 'int call(void);\nint val(void) { return 42; }\nint main(void) { return call(); }\n' > "$WORK/w2.c"
    got="$( (cd "$WORK" && "$SICDRV" -O2 -c w1.c -o w1.o && "$SICDRV" -O2 -c w2.c -o w2.o && "$SICDRV" w1.o w2.o -o weak && { timeout "$TIMEOUT" ./weak; echo $?; }) 2> "$WORK/err")"
    if [ "$got" = "42" ]; then passed=$((passed + 1)); else
        failed=$((failed + 1)); echo "FAIL weak-override: got '$got' $(head -c 200 "$WORK/err")"
    fi
    # `inline` alone is an external definition with `gnu_inline` (Linux's `inline`)
    # or next to a declaration without it (C11 6.7.4p7, EXPORT_SYMBOL): another
    # object can call each one, and without either it stays out of the symbol table.
    total=$((total + 1))
    cat > "$WORK/il1.c" <<'ILEOF'
__attribute__((gnu_inline)) inline int g(void) { return 10; }
inline int d1(void) { return 20; }
int d1(void);
int d2(void);
inline int d2(void) { return 3; }
inline int d3(void) { return 7; }
extern typeof(d3) d3;
inline int plain(void) { return 1; }
static inline int st(void) { return 2; }
int use(void) { return plain() + st(); }
ILEOF
    printf 'int g(void), d1(void), d2(void), d3(void), use(void);\nint main(void) { return g() + d1() + d2() + d3() + use() - 3 + 2; }\n' > "$WORK/il2.c"
    got="$( (cd "$WORK" && "$SICDRV" -c il1.c -o il1.o && "$SICDRV" -c il2.c -o il2.o && "$SICDRV" il1.o il2.o -o il && { timeout "$TIMEOUT" ./il; echo $?; }; nm il1.o | grep -cE ' T (plain|st)$') 2> "$WORK/err" | tr '\n' ' ')"
    if [ "$got" = "42 0 " ]; then passed=$((passed + 1)); else
        failed=$((failed + 1)); echo "FAIL external-inline: got '$got' $(head -c 200 "$WORK/err")"
    fi
    # Dead code leaves no reference behind at -O2 (the test's stubs are for builds
    # without optimization; sic does not define __OPTIMIZE__ itself).
    total=$((total + 1))
    got="$( (cd "$WORK" && "$SICDRV" -O2 -D__OPTIMIZE__=1 -c "$TESTDIR/test_0692.c" -o dead.o && nm -u dead.o | grep -cE 'bug_|TOKEN|never_defined') 2> "$WORK/err")"
    if [ "$got" = "0" ]; then passed=$((passed + 1)); else
        failed=$((failed + 1)); echo "FAIL dead-references: got '$got' $(nm -u "$WORK/dead.o" 2>/dev/null | head -5 | tr '\n' ' ') $(head -c 200 "$WORK/err")"
    fi
    # One ELF section per section name (Linux's modpost reads one `.modinfo`), and
    # no undefined symbol that only dead code named (it counts them all). The kernel
    # code model, which writes the object without going through the assembler here.
    if command -v readelf >/dev/null; then
        total=$((total + 1))
        printf 'static const char a[] __attribute__((used,section(".modinfo"),aligned(1))) = "license=GPL";\nstatic const char b[] __attribute__((used,section(".modinfo"),aligned(1))) = "author=x";\nvoid gone(void);\nint f(int x) { if (0) gone(); return x; }\n' > "$WORK/mi.c"
        got="$( (cd "$WORK" && "$SICDRV" -O2 -fno-PIE -mcmodel=kernel -c mi.c -o mi.o && readelf -SW mi.o | grep -c ' \.modinfo ' && readelf -sW mi.o | grep -c ' UND gone') 2> "$WORK/err" | tr '\n' ' ')"
        if [ "$got" = "1 0 " ]; then passed=$((passed + 1)); else
            failed=$((failed + 1)); echo "FAIL section-merge: got '$got' $(head -c 200 "$WORK/err")"
        fi
    fi
    # `-m32` goes to the system compiler (Clang, else GCC; sic emits x86-64 only),
    # a flag only sic accepts is dropped, and a later `-m64` stays in sic.
    if command -v clang >/dev/null || command -v gcc >/dev/null; then
        total=$((total + 1))
        m32="$("$SICDRV" -m32 -ffoo-unknown-to-cc -E -dM -x c /dev/null 2> "$WORK/err" | grep -cE '^#define __i386__ ')"
        m64="$("$SICDRV" -m32 -m64 -E -dM -x c /dev/null 2>/dev/null | grep -cE '^#define __x86_64__ ')"
        if [ "$m32" = 1 ] && [ "$m64" = 1 ]; then passed=$((passed + 1)); else
            failed=$((failed + 1)); echo "FAIL driver-m32: i386=$m32 x86_64=$m64 $(head -c 200 "$WORK/err")"
        fi
    fi
fi

extra=""
[ $xfailed -gt 0 ] && extra="$extra, $xfailed xfail"
[ $xpassed -gt 0 ] && extra="$extra, $xpassed xpass"
echo "Passed $passed/$((total - xfailed))${extra}"
[ $failed -eq 0 ]
