# Build environment for sic releases on Fedora 43 (LLVM 21 in the distro).
FROM registry.fedoraproject.org/fedora:43
ARG RUST_VERSION
RUN dnf -y install gcc gcc-c++ make git pkgconf-pkg-config patchelf file xz tar gzip \
      findutils which rpm-build llvm-devel libffi-devel glibc-static \
 && dnf clean all
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION"
ENV PATH=/root/.cargo/bin:$PATH
