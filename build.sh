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

echo ">> building + installing std into $SYSROOT"
mkdir -p "$SYSROOT"
# Emit the module directly into the sysroot: the manifest's baked -L then points
# at the sysroot itself, and the .smod/.a/.so all land where the compiler looks.
cp "$ROOT"/siccomp/lib/std/*.sic "$SYSROOT/"
"$SIC" --emit-module "$SYSROOT"

echo ">> building + installing asrun (async runtime) into $SYSROOT"
# asrun declares its own module, so it can't share std's emit dir (one module per
# folder). Build it in a scratch dir, then install into the sysroot with the baked
# -L/-rpath rewritten to point at the sysroot.
ASRUN_BUILD="$ROOT/siccomp/target/asrun_build"
rm -rf "$ASRUN_BUILD"; mkdir -p "$ASRUN_BUILD"
cp "$ROOT"/siccomp/lib/asrun/*.sic "$ASRUN_BUILD/"
"$SIC" --emit-module "$ASRUN_BUILD"
cp "$ASRUN_BUILD"/libasrun.* "$SYSROOT/"
sed "s|$ASRUN_BUILD|$SYSROOT|g" "$ASRUN_BUILD/module_asrun.smod" > "$SYSROOT/module_asrun.smod"
[ -f "$ASRUN_BUILD/module_asrun.h" ] && cp "$ASRUN_BUILD/module_asrun.h" "$SYSROOT/"

echo ">> done. installed:"
ls -1 "$SYSROOT"/module_std.smod "$SYSROOT"/libstd.a "$SYSROOT"/libstd.so \
      "$SYSROOT"/module_asrun.smod "$SYSROOT"/libasrun.a "$SYSROOT"/libasrun.so
