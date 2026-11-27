#!/bin/sh
# Build, verify or embed the selected host-independent BPF objects.
set -eu
mode=${1:?expected build, verify or embed}
profile=${2:?expected packet-ebpf or legacy-tc}
case "$mode" in build|verify|embed) ;; *) exit 2 ;; esac
case "$profile" in packet-ebpf|legacy-tc) ;; *) exit 2 ;; esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root"
ebpf=crates/honk-ebpf
raw="$root/$ebpf/target/bpfel-unknown-none/release"
bundle=${HONK_EBPF_PREBUILT_DIR:-"$raw/prebuilt"}
channel=$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ebpf/rust-toolchain.toml")
[ -n "$channel" ] || { echo 'missing eBPF compiler channel' >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM

# Each row selects both the producer's Cargo bin and the consumer's include_bytes! binding.
objects='honk-host:HONK_HOST_EBPF_OBJECT honk-tun:HONK_TUN_EBPF_OBJECT'
if [ "$profile" = legacy-tc ]; then objects="honk-ebpf:HONK_EBPF_OBJECT $objects"; fi
inputs="$ebpf/src $ebpf/.cargo/config.toml $ebpf/Cargo.toml $ebpf/Cargo.lock $ebpf/rust-toolchain.toml crates/honk-ebpf-common/src crates/honk-ebpf-common/Cargo.toml Cargo.toml crates/honk-core/build.rs ci/ebpf-objects.sh"
# Relative names and content survive artifact downloads, checkout paths and mtime changes.
find $inputs -type f -exec sha256sum '{}' + > "$work/input-files"
LC_ALL=C sort "$work/input-files" > "$work/input-hashes"
digest() { value=$(sha256sum < "$1") || return 1; printf '%s\n' "${value%% *}"; }
source_hash=$(digest "$work/input-hashes")
receipt() { checksum=$(digest "$2") || return 1; printf 'honk-ebpf-v1\n%s\n%s\n%s\n%s\n' "$1" "$channel" "$source_hash" "$checksum"; }
valid_elf() {
    readelf -SW "$2" > "$work/sections" && grep -Eq '[[:space:]]\.BTF[[:space:]]+PROGBITS' "$work/sections" &&
        { [ "$1" != honk-host ] || [ "$(wc -c < "$2")" -lt 32768 ]; }
}
object_path() {
    if [ "$1" = honk-ebpf ] && [ -z "${HONK_EBPF_PREBUILT_DIR:-}" ] && [ ! -f "$bundle/$1" ] && [ -f target/honk-core.o ]; then
        printf '%s\n' "$root/target/honk-core.o"
    else
        printf '%s\n' "$bundle/$1"
    fi
}
verify() {
    for entry in $objects; do
        name=${entry%:*}; path=$(object_path "$name")
        [ -f "$path" ] && [ -f "$path.receipt" ] && valid_elf "$name" "$path" &&
            receipt "$name" "$path" > "$work/expected" && cmp -s "$work/expected" "$path.receipt" || {
            echo "invalid or stale prebuilt $name at $path" >&2; return 1;
        }
    done
}
build() {
    [ -z "${HONK_EBPF_PREBUILT_DIR:-}" ] || { echo 'external prebuilt input is read-only' >&2; exit 1; }
    set --
    for entry in $objects; do set -- "$@" --bin "${entry%:*}"; done
    # Resolve from the tracked pin without letting optional host-only dependencies rewrite it.
    cp "$ebpf/Cargo.lock" "$work/Cargo.lock"
    (
        cd "$ebpf"
        unset RUSTC RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WORKSPACE_WRAPPER CLIPPY_ARGS
        for key in $(env | sed -n 's/^\(CARGO_PROFILE_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$key"; done
        export CARGO_TARGET_DIR="$root/$ebpf/target" CARGO_RESOLVER_LOCKFILE_PATH="$work/Cargo.lock"
        cargo "+$channel" build --release -Zbuild-std=core --target bpfel-unknown-none "$@"
    )
    mkdir -p "$bundle"
    staging=$(mktemp -d "$bundle/.build-XXXXXXXX")
    trap 'rm -rf "$work" "$staging"' EXIT
    for entry in $objects; do
        name=${entry%:*}; staged="$staging/$name"
        if [ "$name" = honk-host ] && [ "$(wc -c < "$raw/$name")" -ge 32768 ]; then
            sysroot=$(rustc "+$channel" --print sysroot)
            host=$(rustc "+$channel" --print host-tuple)
            "$sysroot/lib/rustlib/$host/bin/llvm-objcopy" --strip-debug "$raw/$name" "$staged"
        else
            cp "$raw/$name" "$staged"
        fi
        valid_elf "$name" "$staged" || { echo "invalid built $name" >&2; exit 1; }
        receipt "$name" "$staged" > "$staging/$name.receipt"
        mv "$staged" "$bundle/$name"
        mv "$staging/$name.receipt" "$bundle/$name.receipt"
    done
}
case "$mode" in
    build) build; verify ;;
    verify) verify ;;
    embed)
        out=${3:?expected OUT_DIR}
        if ! verify; then
            [ -z "${HONK_EBPF_PREBUILT_DIR:-}" ] || exit 1
            build
            verify
        fi
        for dep in $inputs; do printf 'cargo:rerun-if-changed=%s/%s\n' "$root" "$dep"; done
        for entry in $objects; do
            name=${entry%:*}; key=${entry#*:}; path=$(object_path "$name"); dest="$out/$name.o"
            cp "$path" "$dest"
            receipt "$name" "$dest" > "$work/expected"
            cmp "$work/expected" "$path.receipt"
            printf 'cargo:rerun-if-changed=%s\ncargo:rerun-if-changed=%s.receipt\ncargo:rustc-env=%s=%s\n' "$path" "$path" "$key" "$dest"
        done ;;
esac
