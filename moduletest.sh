#!/usr/bin/env bash
# Module system round-trip tests (sic.md §"Imports"). The single-file
# compiletest harness cannot build a module and then import it, so this script
# exercises the compiled-manifest path end to end: build a `module`, emit its
# `module_<name>.smod`, then compile a consumer that `import`s it namespaced,
# selectively, and renamed — and run the result.
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
SIC="${SIC:-$ROOT/siccomp/target/debug/sic}"
CC="${CC:-cc}"
# CPP_MODE selects the preprocessor sic runs:
#   global  the system `cpp`
#   sic     this repository's sic-cpp (sic-cpp/sic-cpp; must be built)
#   both    run the whole suite once with each, and fail if either fails
#   unset   sic's own choice: $SIC_CPP, else sic-cpp on PATH, else the repo's
#           sic-cpp, else `cpp` (see `sic -print-prog-name=cpp`)
case "${CPP_MODE:-}" in
    global) export SIC_CPP="cpp" ;;
    sic)
        export SIC_CPP="$ROOT/sic-cpp/sic-cpp"
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
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()   { echo "PASS $1"; pass=$((pass+1)); }
bad()  { echo "FAIL $1: $2"; fail=$((fail+1)); }

cd "$WORK" || exit 1

# ── A module and a consumer ──────────────────────────────────────────────────
cat > math.sic <<'EOF'
module math;
int meaning = 42;
static int hidden = 7;          // static: not exported
int sq(int x){ return x * x; }
int addv(int a, int b){ return a + b; }
EOF

cat > app.sic <<'EOF'
import math;
import math.sq as square;
int main(){
    int a = math.sq(5);         // 25
    int b = square(4);          // 16 (renamed)
    return math.addv(a, b);     // 41
}
EOF

# 1. Building the module emits object + manifest.
if ! "$SIC" -c math.sic -o math.o 2>err; then
    bad "build-module" "compile failed: $(cat err)"
else
    [ -f module_math.smod ] && ok "manifest-emitted" || bad "manifest-emitted" "no module_math.smod"
fi

# 2. The manifest lists exports (mangled) but not the static symbol.
if grep -q "math_sq" module_math.smod && ! grep -q "hidden" module_math.smod; then
    ok "manifest-exports"
else
    bad "manifest-exports" "unexpected manifest:\n$(cat module_math.smod)"
fi

# 3. Consumer imports (namespaced + renamed) compile, link, and run.
if "$SIC" app.sic math.o -I. -o app 2>err; then
    ./app; got=$?
    [ "$got" -eq 41 ] && ok "import-run" || bad "import-run" "expected 41, got $got"
else
    bad "import-run" "compile/link failed: $(cat err)"
fi

# 4. A triple mismatch is a hard error (no source fallback).
sed 's/x86_64[^ ]*/some-other-triple/' module_math.smod > wrong.smod
mv module_math.smod good.smod && mv wrong.smod module_math.smod
if "$SIC" app.sic math.o -I. -o app2 2>err; then
    bad "triple-mismatch" "expected hard error, but it compiled"
else
    grep -q "built for target" err && ok "triple-mismatch" \
        || bad "triple-mismatch" "wrong error: $(cat err)"
fi
mv good.smod module_math.smod

# 5. Link flags recorded in a manifest are folded into a consumer's link.
cat > mlib.sic <<'EOF'
#include <math.h>
module mlib;
double droot(double x){ return sqrt(x); }
EOF
cat > useml.sic <<'EOF'
import mlib;
int main(){ return (int) mlib.droot(49.0); }   // 7
EOF
"$SIC" -c mlib.sic -o mlib.o -lm 2>err
if grep -q "^link -lm" module_mlib.smod; then
    # NOTE: no -lm on the consumer command line; it must come from the manifest.
    if "$SIC" useml.sic mlib.o -I. -o useml 2>err; then
        ./useml; got=$?
        [ "$got" -eq 7 ] && ok "link-fold" || bad "link-fold" "expected 7, got $got"
    else
        bad "link-fold" "link failed: $(cat err)"
    fi
else
    bad "link-fold" "manifest missing 'link -lm':\n$(cat module_mlib.smod)"
fi

# 6. Multi-file folder module: two files, one module, a cross-file call. The
#    consumer links only with `-I` (the archive is self-linking via the manifest).
mkdir -p geo
cat > geo/core.sic <<'EOF'
module geo;
int power(int x){ return x * x; }
EOF
cat > geo/support.sic <<'EOF'
module geo;
int double_power(int x){ return power(x) + power(x); }   /* cross-file */
EOF
if ! "$SIC" --emit-module geo 2>err; then
    bad "folder-module" "emit failed: $(cat err)"
else
    if [ -f geo/libgeo.a ] && [ -f geo/libgeo.so ] && [ -f geo/module_geo.h ] && [ -f geo/module_geo.def ]; then
        ok "folder-artifacts"
    else
        bad "folder-artifacts" "missing archive/shared-lib/header/def in geo/"
    fi
    cat > usegeo.sic <<'EOF'
import geo;
int main(){ return geo.double_power(5); }   /* 25+25 = 50 */
EOF
    if "$SIC" usegeo.sic -Igeo -o usegeo 2>err; then
        ./usegeo; got=$?
        [ "$got" -eq 50 ] && ok "folder-import-run" || bad "folder-import-run" "expected 50, got $got"
    else
        bad "folder-import-run" "compile/link failed: $(cat err)"
    fi
fi

# 7. A C translation unit consumes the module through the generated header.
cat > cuser.c <<'EOF'
#include "module_geo.h"
int main(void){ return geo_double_power(6); }   /* 36+36 = 72 */
EOF
if "$CC" cuser.c -Igeo -Lgeo -Wl,-rpath,"$WORK/geo" -lgeo -o cuser 2>err; then
    ./cuser; got=$?
    [ "$got" -eq 72 ] && ok "c-consumer" || bad "c-consumer" "expected 72, got $got"
else
    bad "c-consumer" "cc failed: $(cat err)"
fi

# 8. The `std` library (`import std;`): an ordinary SIC module, built with the
#    compiler (`--emit-module`) and resolved through its manifest via the module
#    search path (`$SIC_MODULE_PATH`) — no blessed special case. `std.Fmt`/`Print`/
#    `Println` are plain calls; formatting is done in SIC by dispatching on each
#    arg's runtime type. Verified by stdout + exit code, both dynamic and -static.
STD_SRC="$ROOT/siccomp/lib/std"
mkdir -p sysroot
cp "$STD_SRC"/*.sic sysroot/
if "$SIC" --emit-module sysroot 2>err && [ -f sysroot/module_std.smod ]; then
    ok "std-build"
else
    bad "std-build" "emit-module failed: $(cat err)"
fi
export SIC_MODULE_PATH="$WORK/sysroot"
cat > stduser.sic <<'EOF'
import std;
int main() {
    string who = "World";
    bigint meaning = 42;
    fixed half = 0.5;
    string f = std.Fmt("Hello {}! Meaning {}! Half {}!", who, meaning, half);
    std.Println("{}", f);
    std.Println("i={} s={} f={} b={} nb={}", 7, who, 3.5, true, false);
    std.Println("{{}} {}", 1);                      // literal {} then 1
    return (int) f.length;                          // "Hello World! Meaning 42! Half 0.500000000000000000!"
}
EOF
want=$'Hello World! Meaning 42! Half 0.500000000000000000!\ni=7 s=World f=3.5 b=true nb=false\n{} 1'
# Dynamic (default): links libstd.so, found at run time via the manifest rpath.
if "$SIC" -x sic stduser.sic -o stduser 2>err; then
    out="$(./stduser)"; got=$?
    if [ "$out" = "$want" ]; then ok "std-output"; else bad "std-output" "got:\n$out"; fi
    [ "$got" -eq 51 ] && ok "std-exit" || bad "std-exit" "expected 51, got $got"
    ldd stduser 2>/dev/null | grep -q "libstd.so" && ok "std-dynamic" \
        || bad "std-dynamic" "expected a dynamic libstd.so dependency"
else
    bad "std-run" "compile/link failed: $(cat err)"
fi
# Static: links libstd.a; the binary has no libstd.so dependency.
if "$SIC" -x sic -static stduser.sic -o stduser_s 2>err; then
    out="$(./stduser_s)"
    if [ "$out" = "$want" ]; then ok "std-static-output"; else bad "std-static-output" "got:\n$out"; fi
    ldd stduser_s 2>&1 | grep -q "libstd.so" \
        && bad "std-static" "unexpected libstd.so dependency in a -static build" \
        || ok "std-static"
else
    bad "std-static" "static compile/link failed: $(cat err)"
fi

# ── Default arguments across modules (sic.md §"Default parameters") ──────────
# A module exports functions with default parameters; the consumer fills omitted
# defaults from the manifest, including keyword-only defaults before a va sink.
mkdir -p defmod_dir
cat > defmod_dir/defmod.sic <<'EOF'
module defmod;
int addk(int a, int b = 5) { return a + b; }
int pick(int base = 7, va_array parts) { return base + (i32)parts.length; }
EOF
if "$SIC" --emit-module defmod_dir >/dev/null 2>derr && [ -f defmod_dir/module_defmod.smod ]; then
    ok "defmod-build"
else
    bad "defmod-build" "emit-module failed: $(cat derr 2>/dev/null)"
fi
grep -q "^default addk a:- b:5" defmod_dir/module_defmod.smod && ok "defmod-manifest" \
    || bad "defmod-manifest" "manifest missing default line:\n$(grep '^default' defmod_dir/module_defmod.smod 2>/dev/null)"
cat > defuser.sic <<'EOF'
import defmod;
int main() {
    if (defmod::addk(2, 4) != 6) return 1;          // explicit
    if (defmod::addk(2) != 7) return 2;             // b defaults to 5 (cross-module)
    if (defmod::pick() != 7) return 3;              // base default, no parts
    if (defmod::pick(base = 20) != 20) return 4;    // keyword-only base
    if (defmod::pick(1, 2, 3) != 10) return 5;      // base default (7) + 3 va parts
    if (defmod::pick(base = 20, 1, 2) != 22) return 6;
    return 42;
}
EOF
if "$SIC" -x sic -Idefmod_dir defuser.sic -o defuser 2>derr; then
    ./defuser; dg=$?
    [ "$dg" -eq 42 ] && ok "defmod-defaults" || bad "defmod-defaults" "expected 42, got $dg"
else
    bad "defmod-defaults" "compile/link failed: $(cat derr)"
fi

# ── Generic functions across modules (sic.md §"Generics") ────────────────────
# A module exports generic function templates; the consumer re-instantiates them
# locally (inference and turbofish), with no imported symbol.
cat > gmath.sic <<'EOF'
module gmath;
T gadd<T>(T a, T b) { return a + b; }
T gmax<T>(T a, T b) { return a > b ? a : b; }
EOF
cat > gapp.sic <<'EOF'
import gmath::*;                          // bring the module's generics in globally
int main() {
    int s = gadd(3, 4);                  // inferred T=int -> 7
    int m = gmax(9, 2);                  // -> 9
    int d = (int)gadd<double>(1, 2);     // turbofish across module -> 3
    return s + m + d - 19;               // 7+9+3-19 = 0
}
EOF
if "$SIC" -c gmath.sic -o gmath.o 2>err; then
    grep -q "genericfn" module_gmath.smod \
        && ok "generic-manifest" || bad "generic-manifest" "no genericfn record:\n$(cat module_gmath.smod)"
    if "$SIC" gapp.sic gmath.o -I. -o gapp 2>err; then
        ./gapp; got=$?
        [ "$got" -eq 0 ] && ok "generic-import-run" || bad "generic-import-run" "expected 0, got $got"
    else
        bad "generic-import-run" "consumer compile/link failed: $(cat err)"
    fi
else
    bad "generic-manifest" "module compile failed: $(cat err)"
fi

# ── std::Print with named arguments → `{name}` placeholders (va_dict) ─────────
cat > kwuser.sic <<'EOF'
import std;
int main() {
    std::Print("{name}={val}\n", val = 42, name = "answer");
    std::Println("mix {} and {k}", 7, k = "named");
    std::Println("{else}", else = "keyword-name");   // keyword as an arg name
    return 0;
}
EOF
if "$SIC" kwuser.sic -I. -o kwuser 2>err; then
    out="$(./kwuser)"
    want="answer=42
mix 7 and named
keyword-name"
    if [ "$out" = "$want" ]; then ok "std-named-args"; else bad "std-named-args" "got:\n$out"; fi
else
    bad "std-named-args" "compile/link failed: $(cat err)"
fi

# ── art (async runtime module): cooperative coroutines (sic.md §"Async") ────
# Build art into its own module dir, then a consumer spawns two coroutines that
# interleave via yield — proving the executor lives entirely in the module.
ART_SRC="$ROOT/siccomp/lib/art"
mkdir -p arun; cp "$ART_SRC"/*.sic arun/
if "$SIC" --emit-module arun 2>err && [ -f arun/module_art.smod ]; then
    ok "art-build"
else
    bad "art-build" "emit-module failed: $(cat err)"
fi
cat > coro.sic <<'EOF'
import art;
#include <stdio.h>
static int seq[16];
static int si = 0;
void ta(void *a) { for (int i = 0; i < 3; i++) { seq[si++] = 10 + i; art::yield_now(); } }
void tb(void *a) { for (int i = 0; i < 3; i++) { seq[si++] = 20 + i; art::yield_now(); } }
int main() {
    art::spawn(ta, 0);
    art::spawn(tb, 0);
    art::run();
    for (int i = 0; i < si; i++) printf("%d ", seq[i]);
    return 0;
}
EOF
if "$SIC" coro.sic arun/libart.a -Iarun -o coro 2>err; then
    out="$(./coro)"
    [ "$out" = "10 20 11 21 12 22 " ] && ok "art-coroutines" || bad "art-coroutines" "interleave wrong: [$out]"
else
    bad "art-coroutines" "compile/link failed: $(cat err)"
fi

# ── std::Buffer cross-module ctor/dtor (sic.md §"Memory safety") ─────────────
# A consumer's `del buf` must run the module's `~Buffer()` (freeing the data
# block), not just free the handle — the dtor symbol + association cross the
# module boundary via the manifest. Verified leak-free under valgrind if present.
cat > bufuser.sic <<'EOF'
import std;
int main() {
    auto buf = std::Buffer::Create(256);
    if (!buf) return 1;
    del buf;                 // runs ~Buffer() from libstd → frees buf.data
    return 0;
}
EOF
if "$SIC" bufuser.sic -I. -o bufuser 2>err; then
    ./bufuser; rc=$?
    if [ "$rc" -ne 0 ]; then
        bad "std-buffer-dtor" "exit $rc"
    elif command -v valgrind >/dev/null 2>&1; then
        if valgrind -q --error-exitcode=99 --leak-check=full ./bufuser >/dev/null 2>&1; then
            ok "std-buffer-dtor"
        else
            bad "std-buffer-dtor" "valgrind found a leak/error (cross-module ~Buffer not run?)"
        fi
    else
        ok "std-buffer-dtor"
    fi
else
    bad "std-buffer-dtor" "compile/link failed: $(cat err)"
fi

# ── same-named structs in two modules don't collide (module-qualified ctor/dtor) ─
# Two modules each export `struct Widget { ~Widget() }`; a consumer importing both
# must link (distinct `ma_Widget__dtor` / `mb_Widget__dtor`) and `del` each via the
# right module's destructor.
mkdir -p cma cmb
cat > cma/a.sic <<'EOF'
module cma;
namespace A { struct Widget { int *p; ~Widget() { del p; } };
    Widget *make() { Widget *w = new Widget(); w->p = new int(4); return w; } }
EOF
cat > cmb/b.sic <<'EOF'
module cmb;
namespace B { struct Widget { int *q; ~Widget() { del q; } };
    Widget *make() { Widget *w = new Widget(); w->q = new int(8); return w; } }
EOF
if "$SIC" --emit-module cma 2>err && "$SIC" --emit-module cmb 2>err2; then
    cat > cwuser.sic <<'EOF'
import cma;
import cmb;
int main() { auto a = cma::A::make(); auto b = cmb::B::make(); del a; del b; return 0; }
EOF
    if "$SIC" cwuser.sic -Icma -Icmb -o cwuser 2>err; then
        ./cwuser; rc=$?
        if [ "$rc" -ne 0 ]; then
            bad "module-struct-name-collision" "exit $rc"
        elif command -v valgrind >/dev/null 2>&1; then
            valgrind -q --error-exitcode=99 --leak-check=full ./cwuser >/dev/null 2>&1 \
                && ok "module-struct-name-collision" \
                || bad "module-struct-name-collision" "valgrind leak/error"
        else
            ok "module-struct-name-collision"
        fi
    else
        bad "module-struct-name-collision" "consumer compile/link failed: $(cat err)"
    fi
else
    bad "module-struct-name-collision" "module build failed: $(cat err err2)"
fi

# ── a module that imports another module (chain loading) ─────────────────────
# `module extra; import std;` — building extra pulls in std; the manifest records
# `dep std` (not std's symbols). A consumer importing ONLY extra chain-loads std,
# so extra's std-using API works and `std::` is reachable transitively.
mkdir -p emod
cat > emod/extra.sic <<'EOF'
module extra;
import std;
namespace Extra {
    string greet(string name) { return std::Fmt("Hello, {}!", name); }
    int answer() { return 42; }
}
EOF
if "$SIC" --emit-module emod 2>err; then
    # extra's manifest must NOT re-export std's symbols, but must record `dep std`.
    if grep -q '^dep std' emod/module_extra.smod \
       && ! grep -qE '^(dtor|enum|tagenum) ' emod/module_extra.smod; then
        cat > exuser.sic <<'EOF'
import extra;                 // std NOT imported directly
#include <stdio.h>
int main() {
    string g = extra::Extra::greet("world");
    printf("%s|%d\n", g.ptr, extra::Extra::answer());
    auto buf = std::Buffer::Create(64);   // std reachable via chain load
    del buf;
    return 0;
}
EOF
        if "$SIC" exuser.sic -Iemod -o exuser 2>err; then
            out="$(./exuser)"
            if [ "$out" = "Hello, world!|42" ]; then
                if command -v valgrind >/dev/null 2>&1; then
                    valgrind -q --error-exitcode=99 --leak-check=full ./exuser >/dev/null 2>&1 \
                        && ok "module-imports-module" \
                        || bad "module-imports-module" "valgrind leak/error"
                else
                    ok "module-imports-module"
                fi
            else
                bad "module-imports-module" "got: $out"
            fi
        else
            bad "module-imports-module" "consumer compile/link failed: $(cat err)"
        fi
    else
        bad "module-imports-module" "manifest not clean / missing 'dep std':\n$(cat emod/module_extra.smod)"
    fi
else
    bad "module-imports-module" "extra module build failed: $(cat err)"
fi

echo
echo "Passed $pass/$((pass+fail))"
[ "$fail" -eq 0 ]
