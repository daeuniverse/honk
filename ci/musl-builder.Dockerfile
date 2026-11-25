# Native Alpine 3.24 builder image for static musl honk-core and honk-tool binaries.
# Keeps the same Alpine 3.24 baseline as the root Dockerfile so C/C++ dependencies
# (BoringSSL, jemalloc, SQLite) compile and link natively against upstream musl mallocng.
FROM docker.io/library/alpine:3.24

ARG RUST_TOOLCHAIN

RUN set -eux; \
    test -n "${RUST_TOOLCHAIN}"; \
    apk add --no-cache \
        binutils \
        build-base \
        ca-certificates \
        clang-dev \
        cmake \
        curl \
        git \
        llvm-dev \
        llvm-libunwind-static \
        perl; \
    case "$(uname -m)" in \
        x86_64) arch=x86_64 ;; \
        aarch64|arm64) arch=aarch64 ;; \
        *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    export RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo; \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 \
        "https://static.rust-lang.org/rustup/dist/${arch}-unknown-linux-musl/rustup-init" \
        -o /tmp/rustup-init; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"; \
    rm -f /tmp/rustup-init; \
    ln -s "/usr/local/rustup/toolchains/${RUST_TOOLCHAIN}-${arch}-unknown-linux-musl" /usr/local/rust; \
    chmod -R a+rX /usr/local/rustup /usr/local/cargo; \
    mkdir -p /cargo/registry /cargo/git; \
    chmod 1777 /cargo /cargo/registry /cargo/git

# Upstream rustup's musl toolchain defaults to crt-static=true, which breaks
# host build scripts that dlopen libclang.so (boring-sys via bindgen). Build
# host crates (invocations without --target) dynamically against Alpine musl
# while leaving explicit --target builds statically linked.
RUN printf '%s\n' \
        '#!/bin/sh' \
        'rustc=$1' \
        'shift' \
        'has_target=0' \
        'has_crate=0' \
        'for arg in "$@"; do' \
        '    case "$arg" in' \
        '        --target|--target=*) has_target=1 ;;' \
        '        --crate-name) has_crate=1 ;;' \
        '    esac' \
        'done' \
        'if [ "$has_crate" = 1 ] && [ "$has_target" = 0 ]; then' \
        '    exec "$rustc" "$@" -C target-feature=-crt-static' \
        'fi' \
        'exec "$rustc" "$@"' \
        > /usr/local/bin/musl-host-rustc && \
    chmod 0755 /usr/local/bin/musl-host-rustc

# Put the pinned toolchain's bin directory ahead of rustup shims so non-root
# runs execute cargo/rustc directly without attempting rust-toolchain.toml
# component downloads into read-only /usr/local/rustup.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/cargo \
    LIBCLANG_PATH=/usr/lib \
    RUSTC_WRAPPER=/usr/local/bin/musl-host-rustc \
    PATH=/usr/local/rust/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /src
