#!/usr/bin/env bash
# Set the release number everywhere it is written, or check that those agree.
#
#   ./setversion.sh 0.2.1     set it (then ./build.sh release, and commit)
#   ./setversion.sh 0.3.0-dev a pre-release: a SemVer suffix after `-`
#                             (letters, digits, `.`, `-`); the macros take the numbers
#   ./setversion.sh --check   exit 1 if the places disagree (smoketest.sh runs this)
#
# The workspace Cargo.toml is the source: sic and its crates take it from there.
# `__SICC__` stays 1: code tests `#if __SICC__` to detect the compiler, which a
# major version of 0 would turn false. `__SICC_MINOR__` and `__SICC_PATCH__` follow.
set -eu

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CARGO="$ROOT/siccomp/Cargo.toml"
MODULE="$ROOT/siccomp/crates/sic-ir/src/module.rs"
FMT="$ROOT/sic-fmt/src/main.sic"
CPP="$ROOT/sic-cpp/lib/sicpp.sic"

# A version: MAJOR.MINOR.PATCH, then an optional `-` pre-release suffix.
VCHARS='[0-9A-Za-z.-]*'

current() { sed -n "s/^version = \"\($VCHARS\)\"\$/\1/p" "$CARGO" | head -n 1; }

# The numbers of version $1 (its pre-release suffix dropped).
numbers() { IFS=. read -r major minor patch <<< "${1%%-*}"; }

check() {
    local v major minor patch bad=0
    v="$(current)"
    numbers "$v"
    grep -q "\`sic $v (preprocessor" "$MODULE" || { echo "setversion: $MODULE is not at $v"; bad=1; }
    grep -q "\"sic-fmt $v\"" "$FMT" || { echo "setversion: $FMT is not at $v"; bad=1; }
    grep -q "__SICC_MINOR__\"\] = \"O|$minor\"" "$CPP" || { echo "setversion: $CPP __SICC_MINOR__ is not $minor"; bad=1; }
    grep -q "__SICC_PATCH__\"\] = \"O|$patch\"" "$CPP" || { echo "setversion: $CPP __SICC_PATCH__ is not $patch"; bad=1; }
    return "$bad"
}

if [ "${1:-}" = "--check" ]; then
    check
    exit 0
fi

v="${1:-}"
if ! [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
    echo "usage: $0 MAJOR.MINOR.PATCH[-SUFFIX] | --check" >&2
    exit 2
fi
numbers "$v"

sed -i "s/^version = \"$VCHARS\"$/version = \"$v\"/" "$CARGO"
sed -i "s/\`sic $VCHARS (preprocessor/\`sic $v (preprocessor/" "$MODULE"
sed -i "s/\"sic-fmt $VCHARS\"/\"sic-fmt $v\"/" "$FMT"
sed -i "s/__SICC_MINOR__\"\] = \"O|[0-9]*\"/__SICC_MINOR__\"] = \"O|$minor\"/" "$CPP"
sed -i "s/__SICC_PATCH__\"\] = \"O|[0-9]*\"/__SICC_PATCH__\"] = \"O|$patch\"/" "$CPP"
check
echo "version $v"
