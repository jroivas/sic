#!/usr/bin/env bash
# Module system round-trip tests (sic.md §"Imports"). The single-file
# compiletest harness cannot build a module and then import it, so this script
# exercises the compiled-manifest path end to end: build a `module`, emit its
# `module_<name>.smod`, then compile a consumer that `import`s it namespaced,
# selectively, and renamed — and run the result.
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
# Profile, as with ./build.sh: `./moduletest.sh [release|debug] [...]` or
# PROFILE=release; default debug. An explicit SIC=/path/to/sic wins. SIC is
# exported so nested runs (CPP_MODE=both) test the same binary.
PROFILE="${PROFILE:-debug}"
case "${1:-}" in release|debug) PROFILE="$1"; shift ;; esac
case "$PROFILE" in release|debug) ;; *) echo "unknown profile '$PROFILE' (release, debug)"; exit 2 ;; esac
SIC="${SIC:-$ROOT/siccomp/target/$PROFILE/sic}"
if [ ! -x "$SIC" ]; then echo "no compiler at $SIC — build it: ./build.sh $PROFILE"; exit 2; fi
export SIC
echo "compiler: $SIC ($PROFILE, built $(date -r "$SIC" '+%Y-%m-%d %H:%M'), $("$SIC" --version 2>/dev/null | head -1 || echo 'version unknown'))"
CC="${CC:-cc}"
# Guard against testing a stale compiler: warn when any compiler source is
# newer than the binary under test (e.g. only the release build was rebuilt).
if [ -x "$SIC" ] && [ -d "$ROOT/siccomp/crates" ]; then
    newer="$(find "$ROOT/siccomp/crates" -name '*.rs' -newer "$SIC" -print -quit 2>/dev/null)"
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
[ -f "$STD_SRC/module.conf" ] && cp "$STD_SRC/module.conf" sysroot/
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

# std::Thread (lib/std/thread.sic): Spawn/Create/Join/Detach/Id/Sleep/Yield; eight
# threads add to one counter atomically, a detached thread frees itself. The
# closures cross threads, so their reference counts must be atomic.
cat > stdthread.sic <<'EOF'
// std::Thread: Spawn (closure), Create (closure + list arguments), Join,
// Detach, Id, Sleep, Yield. Several threads add to one counter atomically; a
// detached thread frees itself. Returns 42.
import std;

atomic int counter = 0;
atomic int detached_done = 0;

int join(std::thread::Status st)
{
    match (st) {
        std::thread::Status::Created(t): {
            match (std::thread::Join(t)) {
                std::thread::Status::Joined: return 1;
                _: return 0;
            }
        }
        _: return 0;
    }
}

int main()
{
    u64 main_id = std::thread::Id();
    int joined = 0;

    // Eight closures, each capturing its own increment.
    for (int i = 1; i <= 8; i++) {
        int add = i;
        joined += join(std::thread::Spawn([add]() {
            for (int k = 0; k < 1000; k++) counter += add;
            std::thread::Yield();
        }));
    }
    if (joined != 8 || counter != 36000) return 1;

    // Arguments through a list.
    list args;
    args.add(40);
    args.add(2);
    int sum = 0;
    int *psum = &sum;
    u64 *other = new u64();
    joined = join(std::thread::Create([psum, other](list a) {
        int x = a[0];
        int y = a[1];
        *psum = x + y;
        *other = std::thread::Id();
    }, args));
    if (joined != 1 || sum != 42 || *other == main_id) return 2;
    del other;

    // A detached thread runs to completion on its own and frees itself.
    match (std::thread::Spawn([]() { std::thread::Sleep(10); detached_done++; })) {
        std::thread::Status::Created(t): {
            match (std::thread::Detach(t)) {
                std::thread::Status::Detached: {}
                _: return 3;
            }
        }
        _: return 4;
    }
    for (int w = 0; w < 500 && detached_done == 0; w++) std::thread::Sleep(2);
    if (detached_done != 1) return 5;

    match (std::thread::Join(NULL)) {
        std::thread::Status::InvalidObject: {}
        _: return 6;
    }
    return 42;
}
EOF
for mode in "" "-static"; do
    if "$SIC" $mode stdthread.sic -o stdthread 2>err; then
        ./stdthread; got=$?
        [ "$got" -eq 42 ] && ok "std-thread$mode" || bad "std-thread$mode" "expected 42, got $got"
    else
        bad "std-thread$mode" "compile/link failed: $(cat err)"
    fi
done

# ── module.conf: cflags / ldflags / pkg-config packages for a folder module ──
# The module compiles with the conf's -D/-I (an include dir relative to the
# module), links libm into lib<name>.so and its manifest, and takes a package's
# --cflags/--libs from pkg-config (a local .pc via PKG_CONFIG_PATH). A consumer
# needs no flags; an unknown key and a missing package are reported.
mkdir -p confmod/inc pc
cat > confmod/inc/scale.h <<'EOF'
#define SCALE 2
EOF
cat > confmod/geo.sic <<'EOF'
module geo;
#include <math.h>
#include "scale.h"
double hyp(double a, double b) { return sqrt(a * a + b * b) * SCALE + BONUS + PKG_BONUS; }
EOF
cat > confmod/module.conf <<'EOF'
# geo build settings
cflags   = -DBONUS=10 -Iinc       # relative to the module dir
ldflags  = -lm
packages = sicfakepkg
EOF
cat > pc/sicfakepkg.pc <<'EOF'
Name: sicfakepkg
Description: test package for module.conf
Version: 1.0
Cflags: -DPKG_BONUS=22
Libs: -lm
EOF
cat > confuse.sic <<'EOF'
import geo;
int main() { return (int) geo::hyp(3.0, 4.0); }   // 5*2 + 10 + 22 = 42
EOF
if PKG_CONFIG_PATH="$WORK/pc" "$SIC" --emit-module confmod 2>err; then
    if grep -q "^link .* -lm" confmod/module_geo.smod && readelf -d confmod/libgeo.so 2>/dev/null | grep -q "libm.so"; then
        ok "module-conf-build"
    else
        bad "module-conf-build" "no -lm in manifest/libgeo.so:\n$(grep ^link confmod/module_geo.smod)"
    fi
    for mode in "" "-static"; do
        if "$SIC" $mode confuse.sic -Iconfmod -o confuse 2>err; then
            ./confuse; got=$?
            [ "$got" -eq 42 ] && ok "module-conf-run$mode" || bad "module-conf-run$mode" "expected 42, got $got"
        else
            bad "module-conf-run$mode" "compile/link failed: $(cat err)"
        fi
    done
else
    bad "module-conf-build" "emit-module failed: $(cat err)"
fi
mkdir -p confbad && cp confmod/geo.sic confbad/ && printf 'cflag = -DX\n' > confbad/module.conf
"$SIC" --emit-module confbad 2>err && bad "module-conf-badkey" "accepted an unknown key" \
    || { grep -q "unknown key 'cflag'" err && ok "module-conf-badkey" || bad "module-conf-badkey" "wrong error: $(cat err)"; }
printf 'packages = sic-no-such-package\n' > confbad/module.conf
"$SIC" --emit-module confbad 2>err && bad "module-conf-nopkg" "accepted a missing package" \
    || { grep -q "sic-no-such-package" err && ok "module-conf-nopkg" || bad "module-conf-nopkg" "wrong error: $(cat err)"; }

# ── Struct methods across a module boundary ─────────────────────────────────
# A module's struct methods are exported (`method S m symbol` in the manifest)
# so a consumer's `obj.m()` works — it used to fail with "no field 'm' in type"
# (std::random's `g.gen64()`). Value and pointer receivers, arguments, a method
# calling a method, and a struct (sret) return; dynamic and -static.
mkdir -p methmod
cat > methmod/counter.sic <<'EOF'
module ctr;
namespace counter {
    struct Pair { i64 a; i64 b; };
    struct Counter {
        i64 n;
        i64 step;
        i64 next(struct Counter *self) { self->n += self->step; return self->n; }
        i64 skip(struct Counter *self, i64 k) { for (i64 i = 0; i < k; i++) self->next(); return self->n; }
        Pair both(struct Counter *self) { Pair p; p.a = self->n; p.b = self->step; return p; }
    };
    Counter make(i64 step) { Counter c; c.n = 0; c.step = step; return c; }
}
EOF
cat > methuse.sic <<'EOF'
import ctr;
int main() {
    auto c = ctr::counter::make(3);
    c.next();                         // 3   (value receiver)
    c.skip(4);                        // 15
    ctr::counter::Counter *p = &c;
    p->next();                        // 18  (pointer receiver)
    ctr::counter::Pair q = c.both();  // {18, 3}  (struct return)
    return (int)(q.a + q.b * 8);      // 18 + 24 = 42
}
EOF
if "$SIC" --emit-module methmod 2>err && grep -q "^method Counter skip " methmod/module_ctr.smod; then
    for mode in "" "-static"; do
        if "$SIC" $mode methuse.sic -Imethmod -o methuse 2>err; then
            ./methuse; got=$?
            [ "$got" -eq 42 ] && ok "module-methods$mode" || bad "module-methods$mode" "expected 42, got $got"
        else
            bad "module-methods$mode" "compile/link failed: $(cat err)"
        fi
    done
else
    bad "module-methods" "module build / manifest failed: $(cat err) $(grep ^method methmod/module_ctr.smod)"
fi

# ── A module's type named without its module path ───────────────────────────
# `Counter *p = …` / `Counter c;` / `sizeof(Counter)` / a `Counter *` parameter
# in a consumer must say the type needs its module path (they reported "not an
# lvalue", "undefined name", a silent sizeof of 4, "expected RParen").
hint_ok=1
for body in 'auto c = ctr::counter::make(1); Counter *p = &c; return 0;' \
            'Counter c; return 0;' 'return (int)sizeof(Counter);'; do
    printf 'import ctr;\nint main() { %s }\n' "$body" > hint.sic
    "$SIC" hint.sic -Imethmod -o hint 2>err && { hint_ok=0; echo "  compiled: $body"; }
    grep -q "write 'ctr::Counter'" err || { hint_ok=0; echo "  no hint for: $body: $(cat err)"; }
done
printf 'import ctr;\nint f(Counter *p) { return 0; }\nint main() { return 0; }\n' > hint.sic
"$SIC" hint.sic -Imethmod -o hint 2>err && hint_ok=0
grep -q "unknown type name 'Counter'" err || { hint_ok=0; echo "  param: $(cat err)"; }
[ "$hint_ok" -eq 1 ] && ok "module-type-hint" || bad "module-type-hint" "see above"

# ── Generic-enum instances across a module boundary ─────────────────────────
# A module function returning `Option<Big>` / `Result<Big, i32>` exports the
# instance's record: it used to decode as an EMPTY struct in the consumer (wrong
# size for the by-value return) and could not be matched, guarded or named.
# A method call on the un-unwrapped Option says to unwrap it.
mkdir -p optmod
cat > optmod/opt.sic <<'EOF'
module opt;
namespace gen {
    struct Big { i64 a; i64 b; i64 c; i64 sum(struct Big *self) { return self->a + self->b + self->c; } };
    Option<Big> make(i64 x) { if (x < 0) return None; Big b; b.a = x; b.b = x * 2; b.c = x * 3; return Some(b); }
    Result<Big, i32> parse(i64 x) { if (x == 0) return Err(7); Big b; b.a = x; b.b = 0; b.c = 0; return Ok(b); }
}
EOF
cat > optuse.sic <<'EOF'
import opt;
int main() {
    i64 t = 0;
    match (opt::gen::make(5)) { Some(b): t += b.sum(); None: return 1; }       // 30
    auto b2 = opt::gen::make(1) else return 2;                                  // 6
    t += b2.sum();
    Option<opt::gen::Big> o = opt::gen::make(-1);
    match (o) { Some(b): return 3; None: t += 0; }
    match (opt::gen::parse(6)) { Ok(b): t += b.a; Err(e): return 4; }           // 6
    match (opt::gen::parse(0)) { Ok(b): return 5; Err(e): t += e - 7; }         // 0
    return (int)t;                                                              // 42
}
EOF
if "$SIC" --emit-module optmod 2>err && grep -q "^tagenum Option<s_Big> " optmod/module_opt.smod \
   && grep -q "^tagenum Result<s_Big,i32> " optmod/module_opt.smod; then
    for mode in "" "-static"; do
        if "$SIC" $mode optuse.sic -Ioptmod -o optuse 2>err; then
            ./optuse; got=$?
            [ "$got" -eq 42 ] && ok "module-generic-enums$mode" || bad "module-generic-enums$mode" "expected 42, got $got"
        else
            bad "module-generic-enums$mode" "compile/link failed: $(cat err)"
        fi
    done
    printf 'import opt;\nint main() { auto g = opt::gen::make(1); return (int)g.sum(); }\n' > optbad.sic
    "$SIC" optbad.sic -Ioptmod -o optbad 2>err && bad "module-generic-enum-hint" "compiled" \
        || { grep -q "'Option<Big>' has no field or method 'sum'; the value is an enum — unwrap it first" err \
             && ok "module-generic-enum-hint" || bad "module-generic-enum-hint" "wrong error: $(cat err)"; }
else
    bad "module-generic-enums" "module build / manifest failed: $(cat err)"
fi

# ── By-value module types must be fully described ───────────────────────────
# A struct with array fields (std::random::ChaCha12) had no manifest record: the
# consumer decoded it as empty and a by-value return overran its buffer. Arrays
# are now `[N]elem`; a type still not describable (an anonymous union member)
# makes its function omitted with a note instead of exported with a bad layout.
mkdir -p arrmod
cat > arrmod/arr.sic <<'EOF'
module arr;
namespace a {
    struct Blk { u32 key[8]; u64 n; u32 block[16]; };
    Option<Blk> make(u32 seed) {
        Blk b;
        for (int i = 0; i < 8; i++) b.key[i] = seed + i;
        for (int i = 0; i < 16; i++) b.block[i] = seed * 2 + i;
        b.n = 99;
        return Some(b);
    }
    struct Odd { int tag; union { int i; float f; } u; };
    Odd odd() { Odd o; o.tag = 1; o.u.i = 2; return o; }
}
EOF
cat > arruse.sic <<'EOF'
import arr;
int main() {
    auto b = arr::a::make(10) else return 1;
    u64 s = b.n;                                  // 99
    for (int i = 0; i < 8; i++) s += b.key[i];    // 10..17 = 108
    s += b.block[15];                             // 20 + 15 = 35
    return (int)(s - 200);                        // 42
}
EOF
if "$SIC" --emit-module arrmod 2>err && grep -q "^struct Blk key:\[8\]u32 " arrmod/module_arr.smod; then
    grep -q "export 'a__odd' passes or returns a type the manifest cannot describe" err \
        && ! grep -q "^fn a__odd " arrmod/module_arr.smod \
        && ok "module-undescribable-omitted" || bad "module-undescribable-omitted" "$(cat err)"
    for mode in "" "-static"; do
        if "$SIC" $mode arruse.sic -Iarrmod -o arruse 2>err; then
            ./arruse; got=$?
            [ "$got" -eq 42 ] && ok "module-array-fields$mode" || bad "module-array-fields$mode" "expected 42, got $got"
        else
            bad "module-array-fields$mode" "compile/link failed: $(cat err)"
        fi
    done
else
    bad "module-array-fields" "module build / manifest failed: $(cat err)"
fi

# ── Namespaced module variables (`mod::ns::var`) ────────────────────────────
# `std::math::pi` was "no exported symbol": only `mod::var` resolved, and its
# type was not inferred (a variadic/format argument saw an int).
mkdir -p nsvmod
cat > nsvmod/nsv.sic <<'EOF'
module nsv;
namespace k {
    const f64 half = 0.5;
    int count = 40;
}
EOF
cat > nsvuse.sic <<'EOF'
import nsv;
f64 twice(f64 x) { return x * 2.0; }
int main() {
    auto h = nsv::k::half;                  // inferred f64
    if (twice(h) != 1.0) return 1;
    return nsv::k::count + (int)(nsv::k::half * 4.0);   // 40 + 2
}
EOF
if "$SIC" --emit-module nsvmod 2>err && "$SIC" nsvuse.sic -Insvmod -o nsvuse 2>err; then
    ./nsvuse; got=$?
    [ "$got" -eq 42 ] && ok "module-namespaced-var" || bad "module-namespaced-var" "expected 42, got $got"
else
    bad "module-namespaced-var" "build failed: $(cat err)"
fi

# ── Containers are released in a module consumer ────────────────────────────
# A consumer whose container runtime lives in the module's library looked up
# __sic_list_free without declaring it; where nothing had declared it yet, the
# scope-exit release was silently dropped (a list unwrapped from a module's
# Option<list>, and the `.values` projection of a range-for, leaked).
mkdir -p lkmod
cat > lkmod/lk.sic <<'EOF'
module lk;
Option<list<int>> nums(int n) { list<int> l; for (int i = 0; i < n; i++) l.add(i); return Option::Some(l); }
EOF
cat > lkuse.sic <<'EOF'
import lk;
#include <malloc.h>
int sum(int n) {
    auto l = lk::nums(n) else return -1;
    int s = 0;
    for (int v : l.values) s += v;
    return s;
}
int main() {
    for (int i = 0; i < 10; i++) sum(8);
    usize before = mallinfo2().uordblks;
    int t = 0;
    for (int i = 0; i < 2000; i++) t += sum(8);
    usize after = mallinfo2().uordblks;
    if (t != 2000 * 28) return 2;
    return after - before < 4096 ? 42 : 1;
}
EOF
if "$SIC" --emit-module lkmod 2>err && "$SIC" lkuse.sic -Ilkmod -o lkuse 2>err; then
    ./lkuse; got=$?
    [ "$got" -eq 42 ] && ok "module-consumer-container-release" \
        || bad "module-consumer-container-release" "expected 42 (no leak), got $got"
else
    bad "module-consumer-container-release" "build failed: $(cat err)"
fi

# ── Producer identification (.comment) ──────────────────────────────────────
# Every object records which preprocessor built it; the linker keeps the
# strings (merged) in the executable — `readelf -p .comment`.
if command -v readelf >/dev/null 2>&1; then
    printf 'int pa(void){return 41;}\n' > pa.c
    printf 'int pa(void);\nint main(void){return pa()+1;}\n' > pb.c
    if SIC_CPP=cpp "$SIC" -c pa.c -o pa.o 2>err && "$SIC" -c pb.c -o pb.o 2>>err && "$CC" pa.o pb.o -o pab 2>>err; then
        want_pp="$(basename "$("$SIC" -print-prog-name=cpp)")"
        cmt="$(readelf -p .comment pab 2>/dev/null)"
        echo "$cmt" | grep -q "sic .* (preprocessor: cpp)" \
            && echo "$cmt" | grep -q "sic .* (preprocessor: $want_pp)" \
            && ok "comment-producer" || bad "comment-producer" "got:\n$cmt"
    else
        bad "comment-producer" "build failed: $(cat err)"
    fi
fi

# ── No sic <-> sic-cpp recursion ─────────────────────────────────────────────
# Builds often set CC=sic. sic-cpp must not pick sic as its host compiler, and
# even when forced to (SIC_HOST_CC=sic), the nested sic must not start sic-cpp
# again (that was an unbounded process fork). A counting `sic` wrapper on PATH.
mkdir -p recur_bin
printf '#!/bin/sh\necho x >> "%s/recur.log"\nexec "%s" "$@"\n' "$PWD" "$SIC" > recur_bin/sic
chmod +x recur_bin/sic
printf '#include <stdio.h>\nint main(void){puts("ok");return 0;}\n' > recur.c
: > recur.log
if PATH="$PWD/recur_bin:$PATH" CC=sic timeout 60 sic recur.c -o recur 2>err && [ "$(./recur)" = ok ]; then
    n=$(wc -l < recur.log)
    [ "$n" -eq 1 ] && ok "cc-sic-no-recursion" || bad "cc-sic-no-recursion" "sic ran $n times"
else
    bad "cc-sic-no-recursion" "build failed or timed out: $(cat err)"
fi
# sic-cpp run standalone asks sic for its info (`sic -print-cpp-info`), once,
# and queries no other compiler.
SICCPP="$("$SIC" -print-prog-name=cpp)"
if [ "$(basename "$SICCPP")" = sic-cpp ]; then
    : > recur.log
    PATH="$PWD/recur_bin:$PATH" timeout 60 "$SICCPP" -P recur.c > /dev/null 2>err
    n=$(wc -l < recur.log)
    [ "$n" -eq 1 ] && ok "standalone-sic-cpp-asks-sic-once" || bad "standalone-sic-cpp-asks-sic-once" "sic ran $n times: $(cat err)"
    # SIC_RECURSION without SIC_CPP_INFO: sic-cpp refuses to start sic.
    if SIC_RECURSION=1 timeout 60 "$SICCPP" -P recur.c > /dev/null 2>err; then
        bad "sic-cpp-recursion-bailout" "sic-cpp ran"
    else
        grep -q "SIC_RECURSION" err && ok "sic-cpp-recursion-bailout" || bad "sic-cpp-recursion-bailout" "$(cat err)"
    fi
fi
# `__has_*` answers come from sic: what it supports, `__x__` spellings included
# (glibc: `__has_extension(__attribute_deprecated_with_message__)`), and 0 for
# what it lacks (C23 `[[...]]`, `__builtin_trap`).
if [ "$(basename "$SICCPP")" = sic-cpp ]; then
    printf '%s\n' '#if __has_extension(__attribute_deprecated_with_message__) && __has_extension(c_generic_selections)' \
        'ok1' '#endif' '#if __has_attribute(__noreturn__) && __has_attribute(gnu::cold) && __has_builtin(__builtin_clzll)' \
        'ok2' '#endif' '#if !__has_c_attribute(nodiscard) && !__has_builtin(__builtin_trap) && !__has_attribute(destructor)' \
        'ok3' '#endif' > has.c
    [ "$("$SICCPP" -P has.c | tr -d '\n ')" = ok1ok2ok3 ] \
        && ok "has-answers-from-sic" || bad "has-answers-from-sic" "got: $("$SICCPP" -P has.c | tr '\n' ' ')"
fi
# SIC_RECURSION: sic refuses to start a preprocessor, but still answers the query.
if SIC_RECURSION=1 "$SIC" -c recur.c -o recur_x.o 2>err; then
    bad "sic-recursion-bailout" "sic preprocessed"
else
    grep -q "SIC_RECURSION" err && ok "sic-recursion-bailout" || bad "sic-recursion-bailout" "$(cat err)"
fi
SIC_RECURSION=1 "$SIC" -print-cpp-info | grep -q "^has builtin" \
    && ok "print-cpp-info" || bad "print-cpp-info" "no info"

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

# ── std::buffer::SetCapacity / SetSize: size <= capacity is kept ─────────────
# Grow = capacity then size; shrink = size then capacity. A size above the
# capacity or a capacity below the size fails and leaves the buffer unchanged.
cat > bufresize.sic <<'EOF'
import std;
int main()
{
    std::buffer::Buffer *b = std::buffer::Create(4);
    int r = 0;
    b->data[0] = 'a'; b->data[1] = 'b';
    if (!std::buffer::SetSize(b, 2)) r |= 1;
    if (std::buffer::SetSize(b, 5)) r |= 2;            // size > capacity
    if (!std::buffer::SetCapacity(b, 16)) r |= 4;      // grow
    if (b->capacity != 16 || b->size != 2) r |= 8;
    if (b->data[0] != 'a' || b->data[1] != 'b' || b->data[15] != 0) r |= 16;
    if (!std::buffer::SetSize(b, 10)) r |= 32;
    if (std::buffer::SetCapacity(b, 9)) r |= 64;       // capacity < size
    if (b->capacity != 16) r |= 128;
    if (!std::buffer::SetSize(b, 1)) r |= 256;
    if (!std::buffer::SetCapacity(b, 1)) r |= 512;     // shrink
    if (b->capacity != 1 || b->data[0] != 'a') r |= 1024;
    if (!std::buffer::SetSize(b, 0) || !std::buffer::SetCapacity(b, 0)) r |= 2048;
    if (!std::buffer::SetCapacity(b, 3) || b->data[2] != 0) r |= 4096;
    if (std::buffer::SetSize(NULL, 0) || std::buffer::SetCapacity(NULL, 0)) r |= 8192;
    std::Println("{}", r);
    del b;
    return r;
}
EOF
if "$SIC" bufresize.sic -I. -o bufresize 2>err; then
    out="$(./bufresize)"
    [ "$out" = "0" ] && ok "std-buffer-resize" || bad "std-buffer-resize" "failed checks mask: $out"
else
    bad "std-buffer-resize" "compile/link failed: $(cat err)"
fi

# ── std::Fmt format specs: {[arg][:[[fill]align][+][#][0][width][.prec][type]]} ─
cat > fmtspec.sic <<'EOF'
import std;
int main() {
    string who = "World";
    bigint big = 42;
    fixed half = 0.5;
    i8 m1 = -1;
    i32 neg = -42;
    u16 u = 255;
    f64 pi = 3.14159265;
    std::Println("Hello {}! {} {} {} {}", who, big, half, true, false);
    std::Println("{{}} {} }} {{x", 1);
    std::Println("[{:5}] [{:<5}] [{:>5}] [{:^5}] [{:*^6}]", 42, 42, 42, 42, 42);
    std::Println("[{:5}] [{:>5}] [{:^7}] [{:.2}] [{:-<8.3}]", "ab", "ab", "ab", "abcdef", "abcdef");
    std::Println("[{:x}] [{:X}] [{:#x}] [{:b}] [{:#o}] [{:#010x}]", 255, 255, 255, 5, 8, 255);
    std::Println("[{:x}] [{:x}] [{:b}] [{}] [{:+}] [{:+}]", m1, neg, m1, neg, 7, neg);
    std::Println("[{:05}] [{:+06}] [{:08.3}] [{:.3}] [{:e}] [{:.2e}] [{}]", neg, 42, pi, pi, pi, pi, pi);
    std::Println("[{1}] [{0}] [{}] [{1:>4}]", "a", "b");
    std::Println("[{name:>6}] [{n:#x}]", name = "nm", n = 255);
    std::Println("[{:→>5}] [{:5}] [{:.1}]", 1, "äö", "äö");
    std::Println("[{}] [{:x}] [{:08}]", u, u, big);
    std::Println("{ unmatched");
    std::Println("missing [{}] [{5}]", 1);
    std::Println("[{:.0}] [{:10.4}] [{:<10.4}|]", 2.5, -pi, pi);
    string s = std::Fmt("{:.300}", 1.0);
    std::Println("{}", s.size);
    return 0;
}
EOF
if "$SIC" fmtspec.sic -I. -o fmtspec 2>err; then
    out="$(./fmtspec)"
    want="$(cat <<'EOW'
Hello World! 42 0.500000000000000000 true false
{} 1 } {x
[   42] [42   ] [   42] [ 42  ] [**42**]
[ab   ] [   ab] [  ab   ] [ab] [abc-----]
[ff] [FF] [0xff] [101] [0o10] [0x000000ff]
[ff] [ffffffd6] [11111111] [-42] [+7] [-42]
[-0042] [+00042] [0003.142] [3.142] [3.141593e+00] [3.14e+00] [3.14159]
[b] [a] [a] [   b]
[    nm] [0xff]
[→→→→1] [äö   ] [ä]
[255] [ff] [00000042]
{ unmatched
missing [1] []
[2] [   -3.1416] [3.1416    |]
302
EOW
)"
    if [ "$out" = "$want" ]; then ok "std-fmt-spec"; else bad "std-fmt-spec" "got:\n$out"; fi
else
    bad "std-fmt-spec" "compile/link failed: $(cat err)"
fi

# ── std::Print/Println: all bytes written (short writes retried); -1 on error ─
cat > printbig.sic <<'EOF'
import std;
int main() {
    string big = "";
    for (int i = 0; i < 20000; i++) big = big + "0123456789";
    if (std::Println("{}", big) != 0) return 1;
    return 0;
}
EOF
cat > printclosed.sic <<'EOF'
import std;
int main() { return std::Println("x") == -1 ? 42 : 1; }
EOF
if "$SIC" printbig.sic -I. -o printbig 2>err && "$SIC" printclosed.sic -I. -o printclosed 2>>err; then
    ./printbig > big.out; rc=$?
    ./printclosed >&-; crc=$?
    sz=$(wc -c < big.out)
    if [ "$rc" -eq 0 ] && [ "$sz" -eq 200001 ] && [ "$crc" -eq 42 ]; then ok "std-print-write"
    else bad "std-print-write" "rc=$rc size=$sz closed-rc=$crc"; fi
else
    bad "std-print-write" "compile/link failed: $(cat err)"
fi

# ── A module's payload-less enum is usable as a type in a consumer ───────────
# (`mm::ns::Mode m`, `mm::Top t`): it was "unknown type" — only its variants
# were imported, not the type name.
mkdir -p enumty
cat > enumty/m.sic <<'EOF'
module enumty;
namespace ns { enum Mode { A, B, C }; int Val(Mode m) { return m == Mode::C ? 7 : 1; } }
enum Top { X, Y };
int TopVal(Top t) { return t == Top::Y ? 5 : 0; }
EOF
cat > enumtyuser.sic <<'EOF'
import enumty;
static int f(enumty::ns::Mode m) { return enumty::ns::Val(m); }
int main() {
    enumty::Top t = enumty::Top::Y;
    enumty::ns::Mode m = enumty::ns::Mode::C;
    return f(m) * 5 + enumty::TopVal(t);      // 7 * 5 + 5
}
EOF
if "$SIC" --emit-module enumty 2>err && "$SIC" enumtyuser.sic -Ienumty -o enumtyuser 2>err; then
    ./enumtyuser; got=$?
    [ "$got" -eq 40 ] && ok "enum-type-import" || bad "enum-type-import" "expected 40, got $got"
else
    bad "enum-type-import" "compile failed: $(cat err)"
fi

# ── std::file: Write creates/truncates, Append, Seek, ReadAll, Eof, errno ────
# statuses (NotFound / IsDirectory / PermissionDenied), std streams never closed.
mkdir -p fileio
cat > fileio/ftest.sic <<'EOF'
import std;
#include <sys/stat.h>
#include <unistd.h>

static std::file::File *open_or_die(string name, std::file::OpenMode m) {
    match (std::file::Open(name, m)) {
        std::file::Status::Opened(f): return f;
        _: return NULL;
    }
}

int main() {
    int r = 0;
    // Write creates + truncates
    std::file::File *w = open_or_die("t.txt", std::file::OpenMode::Write);
    if (!w) return 1;
    match (std::file::WriteString(w, "hello world\n")) {
        std::file::Status::Wrote(n): if (n != 12) r |= 2;
        _: r |= 2;
    }
    std::file::Close(w);
    // Append keeps content and writes at the end
    std::file::File *a = open_or_die("t.txt", std::file::OpenMode::Append);
    if (!a) return 3;
    std::file::WriteString(a, "more\n");
    std::file::Close(a);
    // Read: Size, partial read, Eof, Seek, ReadAll
    std::file::File *f = open_or_die("t.txt", std::file::OpenMode::Read);
    if (!f) return 4;
    match (std::file::Size(f)) {
        std::file::Status::Size(n): if (n != 17) r |= 8;
        _: r |= 8;
    }
    std::buffer::Buffer *buf = std::buffer::Create(5);
    match (std::file::Read(f, 100, buf)) {
        std::file::Status::Read(n): if (n != 5 || std::buffer::Value(buf) != "hello") r |= 16;
        _: r |= 16;
    }
    if (std::file::Eof(f)) r |= 32;
    if (std::file::Seek(f, 12) != std::file::Status::Success) r |= 64;
    std::file::Read(f, 5, buf);
    if (std::buffer::Value(buf) != "more\n") r |= 128;
    std::file::Read(f, 5, buf);
    if (!std::file::Eof(f) || buf->size != 0) r |= 256;
    std::file::Seek(f, 0);
    match (std::file::ReadAll(f, buf)) {
        std::file::Status::Read(n): if (n != 17 || std::buffer::Value(buf) != "hello world\nmore\n") r |= 512;
        _: r |= 512;
    }
    if (!std::file::Eof(f)) r |= 1024;
    // Writing a read-only file fails; reading it again works
    std::file::Status ws = std::file::Write(f, buf);
    if (ws == std::file::Status::Wrote) r |= 2048;
    std::file::Close(f);
    // Errors
    std::file::Status nf = std::file::Open("missing.txt", std::file::OpenMode::Read);
    if (nf != std::file::Status::NotFound) r |= 4096;
    std::file::Status d = std::file::Open(".", std::file::OpenMode::Write);
    if (d != std::file::Status::IsDirectory) r |= 8192;
    // No permission (skipped when running as root)
    std::file::File *ro = open_or_die("ro.txt", std::file::OpenMode::Write);
    if (!ro) return 5;
    std::file::Close(ro);
    chmod("ro.txt", 0);
    std::file::Status pd = std::file::Open("ro.txt", std::file::OpenMode::Read);
    if (geteuid() != 0 && pd != std::file::Status::PermissionDenied) r |= 65536;
    chmod("ro.txt", 0644);
    // Standard streams: Close leaves them open
    if (std::file::Close(std::file::Stdout()) != std::file::Status::Success) r |= 16384;
    std::file::WriteString(std::file::Stdout(), "still open\n");
    if (std::file::Seek(std::file::Stdin(), 3) != std::file::Status::InvalidOffset) r |= 32768;
    std::Println("status {}", nf.str);
    del buf;
    std::Println("r={}", r);
    return r;
}
EOF
if (cd fileio && "$SIC" ftest.sic -I.. -o ftest 2>../err); then
    out="$(cd fileio && ./ftest)"; rc=$?
    want="still open
status file::Status::NotFound
r=0"
    if [ "$rc" -eq 0 ] && [ "$out" = "$want" ]; then ok "std-file-io"
    else bad "std-file-io" "rc=$rc got:\n$out"; fi
else
    bad "std-file-io" "compile/link failed: $(cat err)"
fi

# ── An error raised without a location ("unknown type") gets the location of
# the statement / declaration being lowered (it printed a bare `error: …`).
printf 'int main() {\n    int a = 1;\n    nope::T x;\n    return a;\n}\n' > loc_stmt.sic
printf 'static int f(nope::T m) { return 1; }\nint main() { return 0; }\n' > loc_param.sic
printf 'int main() {\n    return 0;\n}\nnope::T g;\n' > loc_global.sic
printf 'struct S { int a;\n    nope::T b; };\nint main() { return 0; }\n' > loc_field.sic
printf 'import std;\nint main() {\n    if (1) {\n        std::file::Nope f;\n    }\n    return 0;\n}\n' > loc_module.sic
for c in "loc_stmt:3:5" "loc_param:1:1" "loc_global:4:1" "loc_field:1:1" "loc_module:4:9"; do
    f="${c%%:*}"; at="${c#*:}"
    if "$SIC" $f.sic -I. -o $f 2>err; then
        bad "error-location-$f" "expected an error, but it compiled"
    elif grep -q "^$f.sic:$at: error: unknown type" err; then
        ok "error-location-$f"
    else
        bad "error-location-$f" "wrong location (want $f.sic:$at): $(cat err)"
    fi
done

# ── std::file::ReadLine: lines of any length, last line without '\\n', Read(0)
# at the end; Read/ReadAll/Write after it continue from the logical position.
mkdir -p readline
cat > readline/rl.sic <<'EOF'
import std;

static std::file::File *open_or_die(string name, std::file::OpenMode m) {
    match (std::file::Open(name, m)) {
        std::file::Status::Opened(f): return f;
        _: return NULL;
    }
}

static u64 line(std::file::File *f, std::buffer::Buffer *b) {
    match (std::file::ReadLine(f, b)) {
        std::file::Status::Read(n): return n;
        _: return 999999;
    }
}

int main() {
    int r = 0;
    std::file::File *w = open_or_die("lines.txt", std::file::OpenMode::Write);
    if (!w) return 1;
    string longl = "";
    for (int i = 0; i < 1000; i++) longl = longl + "0123456789";   // 10000 bytes
    std::file::WriteString(w, "first\n\nthird line\n" + longl + "\nlast");
    std::file::Close(w);

    std::file::File *f = open_or_die("lines.txt", std::file::OpenMode::Read);
    if (!f) return 2;
    std::buffer::Buffer *b = std::buffer::Create(4);
    if (line(f, b) != 6 || std::buffer::Value(b) != "first\n") r |= 1;
    if (line(f, b) != 1 || std::buffer::Value(b) != "\n") r |= 2;
    if (line(f, b) != 11 || std::buffer::Value(b) != "third line\n") r |= 4;
    if (line(f, b) != 10001 || std::buffer::Value(b) != longl + "\n") r |= 8;
    if (std::file::Eof(f)) r |= 16;
    if (line(f, b) != 4 || std::buffer::Value(b) != "last") r |= 32;
    if (!std::file::Eof(f)) r |= 64;
    if (line(f, b) != 0 || b->size != 0) r |= 128;
    // Seek back; ReadLine then Read continue from the logical position
    std::file::Seek(f, 0);
    line(f, b);                                        // "first\n"
    std::buffer::Buffer *c = std::buffer::Create(3);
    std::file::Read(f, 3, c);
    if (std::buffer::Value(c) != "\nth") r |= 256;
    if (line(f, b) != 9 || std::buffer::Value(b) != "ird line\n") r |= 512;
    // ReadAll after ReadLine gets the rest
    match (std::file::ReadAll(f, c)) {
        std::file::Status::Read(n): if (n != 10005 || std::buffer::Value(c) != longl + "\nlast") r |= 1024;
        _: r |= 1024;
    }
    std::file::Close(f);
    // RW: a write after ReadLine lands at the logical position
    std::file::File *rw = open_or_die("lines.txt", std::file::OpenMode::RW);
    line(rw, b);                                       // "first\n"
    std::file::WriteString(rw, "X");
    std::file::Seek(rw, 0);
    line(rw, b); line(rw, b);
    if (std::buffer::Value(b) != "Xthird line\n") r |= 2048;   // "X" replaced the empty line's '\n'
    std::file::Close(rw);
    // stdin through a pipe
    u64 total = 0;
    int count = 0;
    while (true) {
        u64 n = line(std::file::Stdin(), b);
        if (n == 0 || n == 999999) break;
        total += n;
        count++;
    }
    std::Println("stdin {} lines {} bytes", count, total);
    del b;
    del c;
    std::Println("r={}", r);
    return r;
}
EOF
if (cd readline && "$SIC" rl.sic -I.. -o rl 2>../err); then
    out="$(cd readline && printf 'a\nbb\nccc' | ./rl)"; rc=$?
    want="stdin 3 lines 8 bytes
r=0"
    if [ "$rc" -eq 0 ] && [ "$out" = "$want" ]; then ok "std-file-readline"
    else bad "std-file-readline" "rc=$rc got:\n$out"; fi
else
    bad "std-file-readline" "compile/link failed: $(cat err)"
fi

# ── The sic driver links libm as needed: a program calling sin() links without
# -lm, as with gcc (which folds sin(2)); a program not using it gets no libm.
cat > usesm.c <<'EOF'
#include <math.h>
int main(int argc, char **argv) { return (int)(sin(argc * 1.5) * 10.0); }   /* sin(1.5)*10 = 9 */
EOF
printf 'int main(void) { return 0; }\n' > nolibm.c
if "$SIC" usesm.c -o usesm 2>err && "$SIC" nolibm.c -o nolibm 2>>err && "$SIC" -static usesm.c -o usesm_s 2>>err; then
    ./usesm; a=$?; ./usesm_s; b=$?
    if [ "$a" -eq 9 ] && [ "$b" -eq 9 ] && ! ldd nolibm 2>/dev/null | grep -q libm; then ok "driver-libm"
    else bad "driver-libm" "rc=$a static-rc=$b, or libm linked when unused"; fi
else
    bad "driver-libm" "compile/link failed: $(cat err)"
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
    auto buf = std::buffer::Create(256);
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
    auto buf = std::buffer::Create(64);   // std reachable via chain load
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

# ── A namespaced export named by its old, unqualified path ───────────────────
# Paths like `geo::Area` parse as enum variants, so a missing module member used
# to report "'geo' is not a tagged enum" (and, from type inference, with no
# location). It must name the module, the missing symbol, and the right path.
mkdir -p nsmod && cd nsmod
cat > geo.sic <<'EOF'
module geo;
namespace Shape { int Area(int w, int h) { return w * h; } }
EOF
cat > call.sic <<'EOF'
import geo;
int main() { return geo::Area(6, 7); }
EOF
cat > infer.sic <<'EOF'
import geo;
int main() { auto a = geo::Area(6, 7); return a; }
EOF
cat > guard.sic <<'EOF'
import geo;
int main() { auto a = geo::Area(6, 7) else return 1; return a; }
EOF
cat > good.sic <<'EOF'
import geo;
int main() { auto a = geo::Shape::Area(6, 7); return a; }
EOF
if "$SIC" -c geo.sic -o geo.o 2>err; then
    for c in call infer guard; do
        if "$SIC" $c.sic geo.o -I. -o $c 2>err; then
            bad "ns-missing-$c" "expected an error, but it compiled"
        elif grep -qF "module 'geo' has no exported symbol 'Area' (did you mean 'geo::Shape::Area'?)" err \
             && grep -q "^$c.sic:2:" err; then
            ok "ns-missing-$c"
        else
            bad "ns-missing-$c" "wrong error: $(cat err)"
        fi
    done
    if "$SIC" good.sic geo.o -I. -o good 2>err; then
        ./good; got=$?
        [ "$got" -eq 42 ] && ok "ns-qualified-call" || bad "ns-qualified-call" "expected 42, got $got"
    else
        bad "ns-qualified-call" "compile/link failed: $(cat err)"
    fi
else
    bad "ns-missing-call" "module build failed: $(cat err)"
fi
cd ..

# A module struct with managed fields (string, list) has an implicit member
# destructor, exported through the manifest: the consumer's scope exit, copy
# and reassignment release the fields (they leaked), with no double release.
mkdir -p mdtor && cd mdtor
cat > people.sic <<'EOF'
module people;
struct Person { string name; list<i32> scores; i32 age; };
Person make(string n, i32 age) { Person p; p.name = n + "!"; p.scores.add(age); p.age = age; return p; }
i32 total(Person *p) { i32 t = 0; for (i32 v : p->scores.values) t += v; return t; }
EOF
cat > app.sic <<'EOF'
import people;
#include <malloc.h>
i32 round() {
    people::Person a = people::make("ann", 30);
    people::Person b = a;
    b.name = "bob" + "?";
    people::Person c;
    c = people::make("cy", 5);
    return people::total(&a) + people::total(&c) + b.name.size + a.name.size;
}
int main() {
    if (round() != 43) return 1;
    usize before = mallinfo2().uordblks;
    for (i32 i = 0; i < 1000; i++) round();
    usize after = mallinfo2().uordblks;
    return after > before + 4096 ? 2 : 42;
}
EOF
if "$SIC" -c people.sic -o people.o 2>err && "$SIC" app.sic people.o -I. -o app 2>err; then
    ./app; got=$?
    [ "$got" -eq 42 ] && ok "module-member-dtor" || bad "module-member-dtor" "expected 42, got $got"
else
    bad "module-member-dtor" "compile/link failed: $(cat err)"
fi
cd ..

echo
echo "Passed $pass/$((pass+fail))"
[ "$fail" -eq 0 ]
