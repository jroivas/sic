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

echo ">> done. installed:"
ls -1 "$SYSROOT"/module_std.smod "$SYSROOT"/libstd.a "$SYSROOT"/libstd.so
