#!/usr/bin/env bash
# Builds the sic/ compiler: each part (a SIC folder module, sic/<part>/) with the
# bootstrap compiler, then sic/franken, which links them into siccomp's driver.
#
#   sic/build.sh [release|debug] [--backend llvm,cranelift]
#
# The bootstrap compiler is siccomp/'s ($SIC_BOOT overrides it): build it first
# with ./build.sh, which also installs the std sysroot both compilers use. The
# back ends default to the bootstrap's, in its order (the first is the default).
# Result: sic/target/<profile>/sic (and cargo-sic beside it, siccomp's).
# sic/target is as deep as siccomp/target: sic finds the repository's sic-cpp
# three levels up from itself.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE=release
BACKENDS=""
while [ $# -gt 0 ]; do
    case "$1" in
        release|debug) PROFILE="$1" ;;
        --backend=*) BACKENDS="${1#--backend=}" ;;
        --backend) [ $# -ge 2 ] || { echo "sic/build.sh: --backend needs a value" >&2; exit 2; }
            BACKENDS="$2"; shift ;;
        *) echo "usage: sic/build.sh [release|debug] [--backend llvm,cranelift]" >&2; exit 2 ;;
    esac
    shift
done

BOOT="${SIC_BOOT:-$ROOT/siccomp/target/$PROFILE/sic}"
[ -x "$BOOT" ] || { echo "sic/build.sh: no bootstrap compiler at $BOOT: build it with ./build.sh $PROFILE" >&2; exit 1; }
echo ">> bootstrap: $BOOT ($("$BOOT" --version | head -1))"
[ -n "$BACKENDS" ] || BACKENDS="$("$BOOT" -print-backends | paste -sd, -)"

# The parts, in sic/<part>/ (franken/build.rs and src/parts.rs list them too).
PARTS=()
for part in "${PARTS[@]}"; do
    echo ">> building part $part"
    "$BOOT" -O2 -g --emit-crate "$ROOT/sic/$part"
done

# The back ends as features, in order; LLVM needs LLVM 21, as for ./build.sh.
for b in ${BACKENDS//,/ }; do
    case "$b" in
        cranelift|llvm) ;;
        *) echo "sic/build.sh: unknown back end '$b' (cranelift, llvm)" >&2; exit 2 ;;
    esac
done
export SIC_BACKEND_ORDER="$BACKENDS"
if [[ ",$BACKENDS," == *,llvm,* ]]; then
    LLVM_CONFIG="$(command -v llvm-config-21 || command -v llvm-config || true)"
    [ -n "$LLVM_CONFIG" ] || { echo "sic/build.sh: the llvm back end needs LLVM 21: no llvm-config" >&2; exit 1; }
    export LLVM_SYS_211_PREFIX="$("$LLVM_CONFIG" --prefix)"
fi

F="$ROOT/sic/franken"
# The same dependency versions as the bootstrap (cargo drops what it doesn't use).
[ -f "$F/Cargo.lock" ] || { [ -f "$ROOT/siccomp/Cargo.lock" ] && cp "$ROOT/siccomp/Cargo.lock" "$F/Cargo.lock"; }
echo ">> building franken ($PROFILE, back ends: $BACKENDS)"
export CARGO_TARGET_DIR="$ROOT/sic/target"
CARGO_FLAGS=(--manifest-path "$F/Cargo.toml" --no-default-features --features "$BACKENDS")
[ "$PROFILE" = release ] && CARGO_FLAGS+=(--release)
cargo build "${CARGO_FLAGS[@]}"

T="$CARGO_TARGET_DIR/$PROFILE"
# The module sysroot sic finds at <exe>/../lib/sic: the one ./build.sh installed.
ln -sfn "$ROOT/siccomp/target/lib" "$CARGO_TARGET_DIR/lib"
# cargo-sic runs the sic beside it: a copy, so that is this one.
BOOT_CARGO_SIC="$(dirname "$BOOT")/cargo-sic"
[ -x "$BOOT_CARGO_SIC" ] && cp "$BOOT_CARGO_SIC" "$T/cargo-sic"
echo ">> $T/sic"
"$T/sic" -print-parts
