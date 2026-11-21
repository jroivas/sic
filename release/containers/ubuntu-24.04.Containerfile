# Build environment for sic releases on Ubuntu 24.04. Its archive has no LLVM 21:
# that comes from apt.llvm.org, as it must on the systems the package goes to.
FROM docker.io/library/ubuntu:24.04
ARG RUST_VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key -o /etc/apt/trusted.gpg.d/apt.llvm.org.asc \
 && echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-21 main" > /etc/apt/sources.list.d/llvm-21.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends gcc g++ make git pkg-config patchelf file xz-utils \
      dpkg-dev llvm-21-dev \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION"
ENV PATH=/root/.cargo/bin:$PATH
