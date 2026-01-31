# Kryoptic Build Environment (Fedora-based)
# Supports building with jitterentropy feature for FIPS entropy sources
#
# Build:
#   podman build -t kryoptic-build -f Containerfile .
#
# Run (interactive):
#   podman run --rm -it -v $(pwd):/workspace:Z -w /workspace kryoptic-build
#
# Run (build with dynamic OpenSSL + system jitterentropy):
#   podman run --rm -v $(pwd):/workspace:Z -w /workspace/kryoptic kryoptic-build \
#     cargo build --release --features "dynamic,jitterentropy"
#   Note: Uses system libjitterentropy.so (from jitterentropy-devel package)
#
# Run (build FIPS provider with jitterentropy compiled from source):
#   podman run --rm -v $(pwd):/workspace:Z -w /workspace/kryoptic \
#     -e KRYOPTIC_OPENSSL_SOURCES=/workspace/openssl \
#     -e KRYOPTIC_JITTERENTROPY_SOURCES=/workspace/jitterentropy-library \
#     kryoptic-build \
#     cargo build --release --no-default-features --features "standard,fips,jitterentropy"
#   Note: Both environment variables required for FIPS builds with jitterentropy

FROM registry.fedoraproject.org/fedora:43

LABEL maintainer="Kryoptic Developers"
LABEL description="Build environment for Kryoptic PKCS#11 token with jitterentropy support"

# Install build dependencies
RUN dnf install -y \
    # Rust toolchain
    rust \
    cargo \
    rustfmt \
    clippy \
    # For OpenSSL bindings
    openssl-devel \
    pkg-config \
    # For bindgen (jitterentropy FFI)
    clang-devel \
    clang \
    llvm-devel \
    # For jitterentropy (dynamic builds link to system library)
    jitterentropy-devel \
    # For building C code (jitterentropy library, OpenSSL)
    gcc \
    g++ \
    make \
    perl \
    perl-FindBin \
    perl-IPC-Cmd \
    perl-File-Compare \
    perl-File-Copy \
    perl-Pod-Html \
    # For kryoptic database storage
    sqlite-devel \
    # Useful for development
    git \
    vim-enhanced \
    # For PKCS#11 testing
    opensc \
    softhsm \
    gnutls-utils \
    nss-tools \
    # Additional useful tools
    findutils \
    procps-ng \
    strace \
    && dnf clean all

# Set clang path for bindgen
ENV LIBCLANG_PATH=/usr/lib64

# Install rustup for toolchain management (Fedora's rust may not support edition2024)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
ENV PATH="/root/.cargo/bin:${PATH}"

# Verify Rust installation
RUN rustc --version && cargo --version

# Set working directory
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]
