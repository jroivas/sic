#!/usr/bin/env bash
# Runs inside a release build container (see release.sh): build sic from the
# source archive, check the installed tree works from where it lands, and pack
# it as a tarball and a .deb or .rpm.
#
# In:  /in/src.tar (git archive of the release commit), /in/Cargo.lock (optional)
# Out: /out/ (the packages, BUILDINFO, the Cargo.lock the build resolved)
# Env: VERSION (from the sources), PKGVER (package version), DISTRO, FORMAT
#      (deb|rpm), DEB_DEPENDS, RPM_REQUIRES, MAINTAINER, COMMIT, REF, BACKENDS,
#      RUN_TESTS (1: run the test suites too), HOST_UID/HOST_GID (owner of /out)
set -euo pipefail

say() { printf '>> [%s] %s\n' "$DISTRO" "$*"; }
die() { printf 'inside.sh [%s]: %s\n' "$DISTRO" "$*" >&2; exit 1; }

SRC=/build/src
STAGE=/build/stage
PREFIX=/usr
rm -rf "$SRC" "$STAGE"; mkdir -p "$SRC" "$STAGE"
tar -xf /in/src.tar -C "$SRC"
cd "$SRC"
if [ -f /in/Cargo.lock ]; then
    cp /in/Cargo.lock siccomp/Cargo.lock
    say "using the given Cargo.lock"
fi

say "building sic $VERSION ($COMMIT), back ends $BACKENDS"
./build.sh release --backend "$BACKENDS"
cp siccomp/Cargo.lock /out/Cargo.lock

if [ "${RUN_TESTS:-0}" = 1 ]; then
    IFS=, read -r -a backends <<< "$BACKENDS"
    for b in "${backends[@]}"; do
        say "test suites, $b"
        SIC_BACKEND=$b BACKEND=$b ./compiletest_rust.sh release
        SIC_BACKEND=$b ./moduletest.sh release
    done
fi

# ── The install tree, as the packages lay it out under /usr ──
say "staging under $PREFIX"
root="$STAGE$PREFIX"
install -Dm755 siccomp/target/release/sic "$root/bin/sic"
install -Dm755 siccomp/target/release/cargo-sic "$root/bin/cargo-sic"
install -Dm755 sic-fmt/sic-fmt "$root/bin/sic-fmt"
install -Dm755 sic-cpp/sic-cpp "$root/bin/sic-cpp"
# The module sysroot: sic finds it at <exe>/../lib/sic.
mkdir -p "$root/lib"
cp -a siccomp/target/lib/sic "$root/lib/sic"
# A manifest records the build's sysroot as -L and -rpath. sic adds both for the
# sysroot it is installed with, so these only point a program into this
# container: drop them.
built_sysroot="$SRC/siccomp/target/lib/sic"
sed -i -e "s| -L$built_sysroot||g" -e "s| -Wl,-rpath,$built_sysroot||g" "$root"/lib/sic/*.smod
# sic-fmt and sic-cpp, when linked dynamically, load libstd.so from the sysroot
# next to them.
for f in "$root/bin/sic-fmt" "$root/bin/sic-cpp"; do
    if readelf -d "$f" 2>/dev/null | grep -q 'libstd\.so'; then
        patchelf --set-rpath '$ORIGIN/../lib/sic' "$f"
    fi
done
doc="$root/share/doc/sic"
mkdir -p "$doc"
cp README.md LICENSE CHANGELOG.md sic.md "$doc/"
cp -a doc "$doc/doc"

# Nothing may still point into the build: a text file naming it, or a run path.
if grep -rIl -- "$SRC" "$STAGE" >/tmp/leaks 2>/dev/null; then
    cat /tmp/leaks >&2; die "files in the install tree name the build directory"
fi
for f in "$root"/bin/* "$root"/lib/sic/*.so; do
    rp="$(readelf -d "$f" 2>/dev/null | sed -n 's/.*R\(UN\)\{0,1\}PATH.*\[\(.*\)\]/\2/p')"
    case "$rp" in *"$SRC"*|*/build/*) die "$f has run path $rp" ;; esac
done

# ── Smoke test of the staged tree, from a directory the build never used ──
smoke() {
    local sic="$1" t
    t="$(mktemp -d)"
    cat > "$t/hello.c" <<'C'
#include <stdio.h>
int main(void) { printf("hello from C\n"); return 0; }
C
    cat > "$t/hello.sic" <<'S'
import std;
int main() { std::Println("hello from {}", "SIC"); return 0; }
S
    IFS=, read -r -a backends <<< "$BACKENDS"
    for b in "${backends[@]}"; do
        for opt in -O0 -O2; do
            (cd "$t" && "$sic" -fbackend="$b" $opt hello.c -o c && ./c >/dev/null) || die "C hello ($b $opt) failed"
            (cd "$t" && "$sic" -fbackend="$b" $opt hello.sic -o s && ./s >/dev/null) || die "SIC hello ($b $opt) failed"
            (cd "$t" && "$sic" -fbackend="$b" $opt -static hello.sic -o ss && ./ss >/dev/null) || die "static SIC hello ($b $opt) failed"
        done
    done
    # A program using std finds libstd.so through the run path sic gave it.
    readelf -d "$t/s" | grep -q 'lib/sic' || die "a std program has no run path to the sysroot"
    rm -rf "$t"
}
say "smoke test of the staged tree"
smoke "$root/bin/sic"

# ── Packages ──
out=/out
name="sic-$PKGVER-$DISTRO-x86_64"
say "tarball $name.tar.gz"
mkdir -p "/build/tar/$name"
cp -a "$root"/. "/build/tar/$name/"
tar -C /build/tar -czf "$out/$name.tar.gz" "$name"

# The tarball is relocatable: check it from somewhere else.
mkdir -p /tmp/reloc && tar -C /tmp/reloc -xzf "$out/$name.tar.gz"
say "smoke test of the unpacked tarball"
smoke "/tmp/reloc/$name/bin/sic"

summary="SIC compiler (C and SIC front ends, Cranelift and LLVM back ends)"
description="sic compiles C (GNU C, enough for SQLite, QEMU and Linux) and SIC,
 a memory-safe dialect of C, to x86-64 Linux code with the Cranelift or the
 LLVM back end, and links with its built-in linker."

case "$FORMAT" in
deb)
    say "deb"
    debroot=/build/deb
    mkdir -p "$debroot/DEBIAN"
    cp -a "$STAGE"/. "$debroot/"
    size="$(du -sk "$debroot/usr" | cut -f1)"
    cat > "$debroot/DEBIAN/control" <<CTRL
Package: sic
Version: $PKGVER
Architecture: amd64
Maintainer: $MAINTAINER
Installed-Size: $size
Depends: $DEB_DEPENDS
Section: devel
Priority: optional
Description: $summary
 $description
CTRL
    dpkg-deb --root-owner-group --build "$debroot" "$out/sic_${PKGVER}_${DISTRO}_amd64.deb" >/dev/null
    ;;
rpm)
    say "rpm"
    top=/build/rpm
    mkdir -p "$top"/{BUILD,RPMS,SPECS,SOURCES,BUILDROOT}
    # The RPM version has no `-`; a snapshot's commit goes in the release.
    rpmver="${PKGVER%%+*}"
    rel=1
    case "$PKGVER" in *+*) rel="1.${PKGVER#*+}" ;; esac
    cat > "$top/SPECS/sic.spec" <<SPEC
%global debug_package %{nil}
Name:           sic
Version:        $rpmver
Release:        $rel%{?dist}
Summary:        $summary
License:        MIT
Requires:       $RPM_REQUIRES
${RPM_RECOMMENDS:+Recommends:     $RPM_RECOMMENDS}
ExclusiveArch:  x86_64
Packager:       $MAINTAINER

%description
$description

%install
mkdir -p %{buildroot}
cp -a $STAGE/. %{buildroot}/

%files
%{_bindir}/sic
%{_bindir}/cargo-sic
%{_bindir}/sic-fmt
%{_bindir}/sic-cpp
/usr/lib/sic
%{_docdir}/sic
SPEC
    QA_RPATHS=$((0x0001|0x0010)) rpmbuild --define "_topdir $top" -bb "$top/SPECS/sic.spec" >/build/rpmbuild.log 2>&1 \
        || { tail -30 /build/rpmbuild.log >&2; die "rpmbuild failed"; }
    find "$top/RPMS" -name '*.rpm' -exec cp {} "$out/" \;
    ;;
*) die "unknown package format $FORMAT" ;;
esac

{
    echo "version=$VERSION"
    echo "package_version=$PKGVER"
    echo "ref=$REF"
    echo "commit=$COMMIT"
    echo "distro=$DISTRO"
    echo "backends=$BACKENDS"
    echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "rustc=$(rustc --version)"
    echo "llvm=$(llvm-config-21 --version 2>/dev/null || llvm-config --version 2>/dev/null || echo none)"
    echo "gcc=$(gcc -dumpfullversion)"
} > "$out/BUILDINFO"
(cd "$out" && sha256sum -- *.tar.gz *.deb *.rpm 2>/dev/null > SHA256SUMS || true)
[ -n "${HOST_UID:-}" ] && chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$out"
say "done: $(cd "$out" && ls | tr '\n' ' ')"
