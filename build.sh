#!/usr/bin/env bash
# Build the sic compiler, then build the shipped standard library WITH it and
# install the library into the compiler's module sysroot.
#
# The compiler and each library build SEPARATELY: std is an ordinary sic module
# (`module std;` in lib/std/std.sic), compiled by `sic --emit-module` into
# `module_std.smod` + `libstd.{a,so}`, and installed into `<exe>/../lib/sic` — the
# relocatable sysroot the compiler searches by default. After this, `import std;`
# works with no flags (dynamic by default; `-static` links `libstd.a`).
#
# Finally it builds sic-cpp, the preprocessor sic uses by default.
#
# Usage: ./build.sh [debug|release]   (default: debug)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PROFILE="${1:-debug}"
CARGO_FLAGS=()
[ "$PROFILE" = "release" ] && CARGO_FLAGS=(--release)

echo ">> building the compiler ($PROFILE)"
( cd "$ROOT/siccomp" && cargo build "${CARGO_FLAGS[@]}" )

SIC="$ROOT/siccomp/target/$PROFILE/sic"
# The sysroot the compiler derives from its own path: <exe_dir>/../lib/sic.
SYSROOT="$ROOT/siccomp/target/lib/sic"

# Preprocess std and art (and bootstrap sic-cpp) with the system cpp when
# there is one: the existing sic-cpp links libstd, so once std is reinstalled a
# stale sic-cpp built against the previous libstd can fail to load (an API
# rename removed a symbol it uses) and break every later step.
BOOT_CPP=""
command -v cpp >/dev/null 2>&1 && BOOT_CPP="cpp"
[ -n "$BOOT_CPP" ] && export SIC_CPP="$BOOT_CPP"

build_modules() {
    echo ">> building + installing std into $SYSROOT"
    mkdir -p "$SYSROOT"
    # Emit the module directly into the sysroot: the manifest's baked -L then points
    # at the sysroot itself, and the .smod/.a/.so all land where the compiler looks.
    # Replace (not merge) the std sources: a file deleted from lib/std must not stay
    # behind in the sysroot and keep being compiled into libstd (it did: a removed
    # math.sic left `acos` unresolved in libstd.so, breaking sic-cpp).
    rm -f "$SYSROOT"/*.sic "$SYSROOT/module.conf"
    cp "$ROOT"/siccomp/lib/std/*.sic "$SYSROOT/"
    # The module's build settings (link flags, pkg-config packages, cflags).
    [ -f "$ROOT/siccomp/lib/std/module.conf" ] && cp "$ROOT/siccomp/lib/std/module.conf" "$SYSROOT/"
    "$SIC" --emit-module "$SYSROOT"

    echo ">> building + installing art (async runtime) into $SYSROOT"
    # art declares its own module, so it can't share std's emit dir (one module per
    # folder). Build it in a scratch dir, then install into the sysroot with the baked
    # -L/-rpath rewritten to point at the sysroot.
    ART_BUILD="$ROOT/siccomp/target/art_build"
    rm -rf "$ART_BUILD"; mkdir -p "$ART_BUILD"
    cp "$ROOT"/siccomp/lib/art/*.sic "$ART_BUILD/"
    "$SIC" --emit-module "$ART_BUILD"
    cp "$ART_BUILD"/libart.* "$SYSROOT/"
    sed "s|$ART_BUILD|$SYSROOT|g" "$ART_BUILD/module_art.smod" > "$SYSROOT/module_art.smod"
    [ -f "$ART_BUILD/module_art.h" ] && cp "$ART_BUILD/module_art.h" "$SYSROOT/"
}

build_modules

echo ">> building sic-cpp (sic's default preprocessor)"
# sic picks sic-cpp/sic-cpp next to the repo as its preprocessor (after $SIC_CPP
# and a sic-cpp on PATH), so build it here — it needs std, installed above.
# Bootstrapped with the system cpp (BOOT_CPP above), so a stale sic-cpp from an
# earlier build can never break building the new one.
SIC_CPP="${BOOT_CPP}" make -B -C "$ROOT/sic-cpp" SIC="$SIC"

if [ -n "$BOOT_CPP" ]; then
    # Stage 2: rebuild std and art with the fresh sic-cpp, the preprocessor
    # they are normally built with (the system cpp only bootstrapped them).
    unset SIC_CPP
    echo ">> rebuilding std + art with the new sic-cpp"
    build_modules
fi

echo ">> done. installed:"
ls -1 "$SYSROOT"/module_std.smod "$SYSROOT"/libstd.a "$SYSROOT"/libstd.so \
      "$SYSROOT"/module_art.smod "$SYSROOT"/libart.a "$SYSROOT"/libart.so \
      "$ROOT/sic-cpp/sic-cpp"
echo ">> preprocessor: $("$SIC" -print-prog-name=cpp)"
