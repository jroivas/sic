# Build environment for sic releases on Ubuntu 26.04 (LLVM 21 from the archive).
FROM docker.io/library/ubuntu:26.04
ARG RUST_VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gcc g++ make git \
      pkg-config patchelf file xz-utils dpkg-dev llvm-21-dev \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION"
ENV PATH=/root/.cargo/bin:$PATH
