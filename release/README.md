# Releases

`release.sh` builds sic's release packages in containers, so nothing is
installed on the host: a relocatable tarball and a `.deb` or `.rpm` per distro,
from a tag or any commit.

    release/release.sh 0.3.0                 # a tag
    release/release.sh                       # HEAD
    release/release.sh 1a2b3c4d --distros fedora-43
    release/release.sh --test                # also run the test suites in each container

Only committed files are built (`git archive`); a dirty working tree does not
matter. It needs podman or docker (`--engine`), and the network on the first
run, for the images and the crates.

| Distro       | Package  | LLVM 21 from        |
|--------------|----------|---------------------|
| Ubuntu 24.04 | `.deb`   | apt.llvm.org        |
| Ubuntu 26.04 | `.deb`   | the Ubuntu archive  |
| Fedora 43    | `.rpm`   | Fedora              |

Fedora 42 has only LLVM 20, so it is not built.

## Version

The version is `siccomp/Cargo.toml`'s at that commit (`./setversion.sh` sets it).
Packages write a pre-release suffix with `~`, so `0.3.0-dev` is `0.3.0~dev`
and sorts before `0.3.0`. A commit that is not a tag of that version is a
snapshot: `0.3.0~dev+git1a2b3c4d` (an RPM puts `git1a2b3c4d` in its release).
Tags are the bare version (`0.3.0`; `v0.3.0` works too).

## Output

`release/out/sic-<version>[-g<commit>]/<distro>/`:

- `sic-<version>-<distro>-x86_64.tar.gz`: `bin/`, `lib/sic/`, `share/doc/sic/`;
  unpack anywhere, sic finds its module sysroot at `<bin>/../lib/sic`
- `sic_<version>_<distro>_amd64.deb` or `sic-<version>-1.<dist>.x86_64.rpm`: the same
  under `/usr`
- `BUILDINFO` (commit, toolchain versions), `Cargo.lock` (what the build
  resolved), `SHA256SUMS`

Each build is checked before it is packed: hello world in C and SIC (`std`,
dynamic and `-static`) with each back end, from the install tree and from the
unpacked tarball; nothing in the tree may name the build directory. Then the
package is installed into a clean container of its distro, which must pull in
every dependency, and compiles and runs the same programs.

## What a package needs

`gcc` (the C runtime files and libgcc sic links with, and gcc's own headers)
and the libc headers (`libc6-dev`, `glibc-devel`; Fedora's static libc for
`-static`, `glibc-static`, is a recommended package), and `libLLVM` 21 for the
LLVM back end (`libllvm21`; on Fedora `llvm-libs`, found by the RPM's automatic
dependencies). On Ubuntu 24.04 add apt.llvm.org first:

    curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
    echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-21 main" | sudo tee /etc/apt/sources.list.d/llvm-21.list
    sudo apt update && sudo apt install ./sic_*.deb

## Reproducibility

`Cargo.lock` is not committed, so each build resolves the dependencies when it
runs (the exact pins in `siccomp/Cargo.toml` hold); the result is kept in the
output. To rebuild with the same dependencies, pass it back:
`--lockfile release/out/<label>/<distro>/Cargo.lock`. Rust is pinned in
`release.sh` (`RUST_VERSION`).

## Windows and macOS

Not for 0.3.0: sic generates x86-64 Linux code only, so on those systems it
would be a cross compiler that also needs a Linux sysroot.

## Files

- `release.sh`: the host side: source archive, version, one container per distro
- `inside.sh`: runs in a build container: build, check, stage, pack
- `containers/*.Containerfile`: the build images (cached as
  `sic-release-build:<distro>-rust<version>`; `--rebuild-images` remakes them)
