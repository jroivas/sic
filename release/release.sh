#!/usr/bin/env bash
# Build sic release packages in containers: a tarball and a .deb or .rpm per
# distro, from a tag or any commit. See release/README.md.
#
#   release/release.sh [REF] [options]
#
#   REF               a tag or commit (default HEAD); only committed files go in
#   --distros LIST    comma-separated (default: all of: ubuntu-24.04,ubuntu-26.04,fedora-43)
#   --engine NAME     podman or docker (default: podman if installed)
#   --out DIR         where packages go (default: release/out/sic-<version>)
#   --lockfile FILE   build with this Cargo.lock (Cargo.lock is not committed:
#                     without one, each build resolves the dependencies afresh
#                     and records the result in its output)
#   --test            also run the compile and module test suites in each container
#   --no-verify       skip installing each package into a clean container
#   --rebuild-images  rebuild the build images instead of using cached ones
#
# The version is the one in siccomp/Cargo.toml at REF. A pre-release suffix
# becomes `~` in package versions (0.3.0-dev → 0.3.0~dev, which sorts before
# 0.3.0); a REF that is not a tag adds +git<commit> (0.3.0~dev+git1a2b3c4d).
set -euo pipefail
# One group: bash reads all of it before running any, so editing this file
# while a release builds does not change the run.
{

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
RUST_VERSION=1.99.0
BACKENDS=cranelift,llvm
ALL_DISTROS=ubuntu-24.04,ubuntu-26.04,fedora-43

ref=HEAD distros=$ALL_DISTROS engine="" out="" lockfile="" run_tests=0 verify=1 rebuild=0
while [ $# -gt 0 ]; do
    case "$1" in
        --distros) distros="$2"; shift ;;
        --distros=*) distros="${1#*=}" ;;
        --engine) engine="$2"; shift ;;
        --engine=*) engine="${1#*=}" ;;
        --out) out="$2"; shift ;;
        --out=*) out="${1#*=}" ;;
        --lockfile) lockfile="$2"; shift ;;
        --lockfile=*) lockfile="${1#*=}" ;;
        --test) run_tests=1 ;;
        --no-verify) verify=0 ;;
        --rebuild-images) rebuild=1 ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        -*) echo "release.sh: unknown option $1" >&2; exit 2 ;;
        *) ref="$1" ;;
    esac
    shift
done

if [ -z "$engine" ]; then
    if command -v podman >/dev/null; then engine=podman
    elif command -v docker >/dev/null; then engine=docker
    else echo "release.sh: needs podman or docker" >&2; exit 1; fi
fi

# Per distro: package format, the base image (for the clean-install check), the
# dependencies a package declares, and what a clean system needs first.
distro_info() {
    case "$1" in
        ubuntu-24.04) FORMAT=deb; BASE=docker.io/library/ubuntu:24.04
            DEB_DEPENDS="gcc, libc6-dev, libllvm21"; RPM_REQUIRES=""; RPM_RECOMMENDS=""
            SETUP='apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates curl gnupg >/dev/null && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key -o /etc/apt/trusted.gpg.d/apt.llvm.org.asc && echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-21 main" > /etc/apt/sources.list.d/llvm-21.list'
            INSTALL='apt-get update -qq && apt-get install -y -qq /pkg/*.deb >/dev/null' ;;
        ubuntu-26.04) FORMAT=deb; BASE=docker.io/library/ubuntu:26.04
            DEB_DEPENDS="gcc, libc6-dev, libllvm21"; RPM_REQUIRES=""; RPM_RECOMMENDS=""
            SETUP=':'
            INSTALL='apt-get update -qq && apt-get install -y -qq /pkg/*.deb >/dev/null' ;;
        fedora-43) FORMAT=rpm; BASE=registry.fedoraproject.org/fedora:43
            DEB_DEPENDS=""; RPM_REQUIRES="gcc glibc-devel"; RPM_RECOMMENDS="glibc-static"
            SETUP=':'
            INSTALL='dnf -y -q install /pkg/*.rpm >/dev/null' ;;
        *) echo "release.sh: unknown distro '$1' (known: $ALL_DISTROS)" >&2; exit 2 ;;
    esac
}

cd "$ROOT"
commit="$(git rev-parse --verify "$ref^{commit}")" || { echo "release.sh: no such ref $ref" >&2; exit 1; }
short="$(git rev-parse --short=8 "$commit")"
version="$(git show "$commit:siccomp/Cargo.toml" | sed -n 's/^version = "\([0-9A-Za-z.-]*\)"$/\1/p' | head -1)"
[ -n "$version" ] || { echo "release.sh: no version in siccomp/Cargo.toml at $ref" >&2; exit 1; }
tag="$(git tag --points-at "$commit" | grep -E "^v?${version//./\\.}$" | head -1 || true)"
pkgver="$(echo "$version" | sed 's/-/~/')"
if [ -n "$tag" ]; then
    label="sic-$version"
else
    pkgver="$pkgver+git$short"
    label="sic-$version-g$short"
    other="$(git tag --points-at "$commit" | head -1 || true)"
    [ -n "$other" ] && echo "release.sh: note: tag '$other' is not version $version: building as a snapshot" >&2
fi
out="${out:-$HERE/out/$label}"
maintainer="$(git config user.name) <$(git config user.email)>"

echo "sic $version from $ref ($short)${tag:+, tag $tag} → package version $pkgver"
echo "engine $engine, distros $distros, output $out"

work="$(mktemp -d "${TMPDIR:-/tmp}/sic-release.XXXXXX")"
trap 'rm -rf "$work"' EXIT
git archive --format=tar -o "$work/src.tar" "$commit"
cp "$HERE/inside.sh" "$work/inside.sh"
if [ -n "$lockfile" ]; then cp "$lockfile" "$work/Cargo.lock"; fi
mkdir -p "$out"

# Under docker the container's root is the host's: give the output back. Under
# rootless podman it is already the user (a chown would map to a sub-UID).
owner=()
[ "$engine" = docker ] && owner=(-e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)")

IFS=, read -r -a list <<< "$distros"
failed=()
for d in "${list[@]}"; do
    distro_info "$d"
    image="sic-release-build:$d-rust$RUST_VERSION"
    if [ "$rebuild" = 1 ] || ! "$engine" image inspect "$image" >/dev/null 2>&1; then
        echo ">> [$d] build image $image"
        "$engine" build --build-arg RUST_VERSION="$RUST_VERSION" -t "$image" \
            -f "$HERE/containers/$d.Containerfile" "$HERE/containers"
    fi
    dout="$out/$d"
    rm -rf "$dout"; mkdir -p "$dout"
    echo ">> [$d] build"
    if ! "$engine" run --rm \
        -v "$work:/in:ro,Z" -v "$dout:/out:Z" -v sic-release-cargo:/root/.cargo/registry \
        -e VERSION="$version" -e PKGVER="$pkgver" -e DISTRO="$d" -e FORMAT="$FORMAT" \
        -e DEB_DEPENDS="$DEB_DEPENDS" -e RPM_REQUIRES="$RPM_REQUIRES" -e RPM_RECOMMENDS="$RPM_RECOMMENDS" \
        -e MAINTAINER="$maintainer" -e COMMIT="$commit" -e REF="$ref" -e BACKENDS="$BACKENDS" \
        -e RUN_TESTS="$run_tests" "${owner[@]}" \
        "$image" bash /in/inside.sh; then
        failed+=("$d (build)"); continue
    fi
    if [ "$verify" = 1 ]; then
        echo ">> [$d] install the package into a clean $BASE"
        if ! "$engine" run --rm -v "$dout:/pkg:ro,Z" "$BASE" bash -c "
            set -e
            $SETUP
            $INSTALL
            cd /tmp
            printf '#include <stdio.h>\nint main(void) { puts(\"ok\"); return 0; }\n' > c.c
            printf 'import std;\nint main() { std::Println(\"ok\"); return 0; }\n' > s.sic
            for b in \$(sic -print-backends); do
                sic -fbackend=\$b -O2 c.c -o c && ./c >/dev/null
                sic -fbackend=\$b -O2 s.sic -o s && ./s >/dev/null
                sic -fbackend=\$b -O2 -static s.sic -o ss && ./ss >/dev/null
            done
            for t in sic-fmt sic-cpp; do
                if ldd \$(command -v \$t) | grep -q 'not found'; then ldd \$(command -v \$t); exit 1; fi
            done
            sic --version | head -1
        "; then
            failed+=("$d (clean install)")
        fi
    fi
done

echo
if [ ${#failed[@]} -gt 0 ]; then
    echo "FAILED: ${failed[*]}"
    exit 1
fi
echo "packages in $out:"
(cd "$out" && find . -type f \( -name '*.tar.gz' -o -name '*.deb' -o -name '*.rpm' \) | sort)
exit
}
