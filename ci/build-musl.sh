#!/usr/bin/env bash
# Build static musl release binaries natively inside the Alpine 3.24 builder image.
#
# Usage:
#   ci/build-musl.sh honk-core [--no-default-features] [--features ...] [cargo build args...]
#   ci/build-musl.sh honk-tool [cargo build args...]
#
# Environment overrides:
#   HONK_CONTAINER_ENGINE      Container CLI to use (default: docker, fallback: podman)
#   HONK_MUSL_BUILDER_IMAGE    Prebuilt builder image tag (default: auto-built from ci/musl-builder.Dockerfile)
#   HONK_DOONA_DIR             Absolute path to standard doona dir (required with native-ui; expects <dir>-lite sibling)
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: ci/build-musl.sh <honk-core|honk-tool> [cargo build args...]
EOF
  exit 2
}

(( $# >= 1 )) || usage
pkg=$1
shift

case "$pkg" in
  honk-core|honk-tool) ;;
  -h|--help) usage ;;
  *) echo "error: unsupported package '$pkg' (expected honk-core or honk-tool)" >&2; usage ;;
esac

repo_root=$(cd "$(dirname "$0")/.." && pwd -P)

case "$(uname -m)" in
  x86_64)
    target=x86_64-unknown-linux-musl
    docker_arch=amd64
    target_env_key=X86_64_UNKNOWN_LINUX_MUSL
    ;;
  aarch64|arm64)
    target=aarch64-unknown-linux-musl
    docker_arch=arm64
    target_env_key=AARCH64_UNKNOWN_LINUX_MUSL
    ;;
  *)
    echo "error: unsupported host architecture '$(uname -m)' (expected x86_64 or aarch64)" >&2
    exit 2
    ;;
esac

if [[ -n "${HONK_CONTAINER_ENGINE:-}" ]]; then
  engine=$HONK_CONTAINER_ENGINE
  if ! command -v "$engine" >/dev/null 2>&1; then
    echo "error: HONK_CONTAINER_ENGINE='$engine' not found in PATH" >&2
    exit 2
  fi
elif command -v docker >/dev/null 2>&1; then
  engine=docker
elif command -v podman >/dev/null 2>&1; then
  engine=podman
else
  echo "error: neither docker nor podman found in PATH (set HONK_CONTAINER_ENGINE to override)" >&2
  exit 2
fi

# Collect feature flags and reject conflicting --target overrides.
all_features=""
expect_features=0
expect_target=0
for arg in "$@"; do
  if (( expect_features )); then
    all_features="${all_features},${arg}"
    expect_features=0
    continue
  fi
  if (( expect_target )); then
    if [[ "$arg" != "$target" ]]; then
      echo "error: native Alpine builder only targets host arch '$target' (got '--target $arg')" >&2
      exit 2
    fi
    expect_target=0
    continue
  fi
  case "$arg" in
    --features|-F) expect_features=1 ;;
    --features=*) all_features="${all_features},${arg#--features=}" ;;
    -F*) all_features="${all_features},${arg#-F}" ;;
    --target) expect_target=1 ;;
    --target=*)
      if [[ "${arg#--target=}" != "$target" ]]; then
        echo "error: native Alpine builder only targets host arch '$target' (got '$arg')" >&2
        exit 2
      fi
      ;;
  esac
done
all_features=$(printf '%s' "$all_features" | tr ' ' ',')

has_feature() {
  [[ ",${all_features}," == *",$1,"* ]]
}

# Pre-flight: eBPF object freshness, BTF presence, and exact toolchain pin.
if [[ "$pkg" == "honk-core" ]] && has_feature ebpf; then
  ebpf_crate="$repo_root/crates/honk-ebpf"
  ebpf_obj="$ebpf_crate/target/bpfel-unknown-none/release/honk-ebpf"
  ebpf_tc="${ebpf_obj}.toolchain"
  ebpf_channel=$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ebpf_crate/rust-toolchain.toml")
  if [[ -z "$ebpf_channel" ]]; then
    echo "error: failed to parse channel from crates/honk-ebpf/rust-toolchain.toml" >&2
    exit 1
  fi
  if [[ ! -f "$ebpf_obj" ]]; then
    echo "error: missing eBPF object at $ebpf_obj (run 'just build-ebpf' first)" >&2
    exit 1
  fi
  if command -v readelf >/dev/null 2>&1; then
    if ! readelf -S "$ebpf_obj" | grep -q '\.BTF'; then
      echo "error: eBPF object at $ebpf_obj has no .BTF section (run 'just build-ebpf')" >&2
      exit 1
    fi
  fi
  if [[ ! -f "$ebpf_tc" ]] || ! cmp -s "$ebpf_tc" <(printf '%s' "$ebpf_channel"); then
    echo "error: $ebpf_tc is missing or does not exactly match '$ebpf_channel' (run 'just build-ebpf')" >&2
    exit 1
  fi
  stale_src=$(find "$ebpf_crate/src" "$repo_root/crates/honk-ebpf-common/src" "$ebpf_crate/rust-toolchain.toml" \
    -type f -newer "$ebpf_obj" -print -quit)
  if [[ -n "$stale_src" ]]; then
    echo "error: eBPF object $ebpf_obj is older than $stale_src (run 'just build-ebpf')" >&2
    exit 1
  fi
  if [[ "$repo_root/crates/honk-core/build.rs" -nt "$ebpf_tc" ]]; then
    echo "error: $ebpf_tc is older than crates/honk-core/build.rs (run 'just build-ebpf')" >&2
    exit 1
  fi
fi

# Pre-flight: doona standard + -lite sibling directories for native-ui.
doona_args=()
if [[ "$pkg" == "honk-core" ]] && has_feature native-ui; then
  if [[ -z "${HONK_DOONA_DIR:-}" ]]; then
    echo "error: native-ui requires HONK_DOONA_DIR (run 'export HONK_DOONA_DIR=\$(ci/fetch-doona.sh)')" >&2
    exit 1
  fi
  doona_dir=${HONK_DOONA_DIR%/}
  if [[ "$doona_dir" != /* ]]; then
    echo "error: HONK_DOONA_DIR must be an absolute path: $HONK_DOONA_DIR" >&2
    exit 1
  fi
  doona_lite="${doona_dir}-lite"
  if [[ ! -f "$doona_dir/index.html" ]]; then
    echo "error: missing $doona_dir/index.html" >&2
    exit 1
  fi
  if [[ ! -f "$doona_lite/index.html" ]]; then
    echo "error: missing sibling $doona_lite/index.html" >&2
    exit 1
  fi
  doona_parent=$(dirname "$doona_dir")
  doona_base=$(basename "$doona_dir")
  doona_args=(-v "$doona_parent:/doona:ro" -e "HONK_DOONA_DIR=/doona/$doona_base")
fi

# Resolve Git metadata and external worktree gitdir mounts before entering the container.
host_rev=""
expected_version=""
git_mounts=()
if git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  host_rev=$(git -C "$repo_root" rev-parse --short=12 HEAD)
  if [[ "${GITHUB_REF:-}" == refs/tags/* && -n "${GITHUB_REF#refs/tags/}" ]]; then
    expected_version="${GITHUB_REF#refs/tags/}"
  else
    expected_version=$(git -C "$repo_root" describe --tags --always --match 'v*')
  fi
  git_common_dir=$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)
  git_dir=$(git -C "$repo_root" rev-parse --path-format=absolute --git-dir)
  if [[ "$git_common_dir" != "$repo_root" && "$git_common_dir" != "$repo_root/"* ]]; then
    git_mounts+=(-v "$git_common_dir:$git_common_dir:ro")
  fi
  if [[ "$git_dir" != "$repo_root" && "$git_dir" != "$repo_root/"* \
     && "$git_dir" != "$git_common_dir" && "$git_dir" != "$git_common_dir/"* ]]; then
    git_mounts+=(-v "$git_dir:$git_dir:ro")
  fi
fi

# Build the Alpine 3.24 builder image on demand, keyed by Dockerfile + rust-toolchain.toml.
rust_toolchain=$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$repo_root/rust-toolchain.toml")
if [[ -z "$rust_toolchain" ]]; then
  echo "error: failed to parse channel from rust-toolchain.toml" >&2
  exit 1
fi
img_hash=$(sha256sum "$repo_root/ci/musl-builder.Dockerfile" "$repo_root/rust-toolchain.toml" | sha256sum | cut -c1-12)
image="${HONK_MUSL_BUILDER_IMAGE:-honk-musl-builder:${docker_arch}-${rust_toolchain}-${img_hash}}"

if ! "$engine" image inspect "$image" >/dev/null 2>&1; then
  echo "Building $image (Alpine 3.24, Rust $rust_toolchain, linux/$docker_arch)..." >&2
  "$engine" build \
    --platform "linux/$docker_arch" \
    --build-arg "RUST_TOOLCHAIN=$rust_toolchain" \
    -f "$repo_root/ci/musl-builder.Dockerfile" \
    -t "$image" \
    "$repo_root/ci"
fi

# Mount only Cargo's registry/git caches so host ~/.cargo/config.toml never leaks into Alpine.
host_cargo_home="${CARGO_HOME:-$HOME/.cargo}"
mkdir -p "$host_cargo_home/registry" "$host_cargo_home/git"

uid=$(id -u)
gid=$(id -g)
user_args=(-u "$uid:$gid")
if (( uid != 0 )) && "$engine" info --format '{{.Host.Security.Rootless}}' 2>/dev/null | grep -qx true; then
  user_args=(--userns=keep-id -u "$uid:$gid")
fi

extra_env=()
if [[ -n "${GITHUB_REF:-}" ]]; then
  extra_env+=(-e "GITHUB_REF=$GITHUB_REF")
fi
if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
  extra_env+=(-e "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS")
fi

# Use target-scoped RUSTFLAGS so host proc-macro dylibs stay unaffected while the
# musl target binary links statically against Alpine 3.24 libc.a, libstdc++.a, and libunwind.a.
"$engine" run --rm \
  --platform "linux/$docker_arch" \
  "${user_args[@]}" \
  -v "$repo_root:/src" \
  -w /src \
  -v "$host_cargo_home/registry:/cargo/registry" \
  -v "$host_cargo_home/git:/cargo/git" \
  "${git_mounts[@]}" \
  "${doona_args[@]}" \
  "${extra_env[@]}" \
  -e "HOME=/tmp" \
  -e "CARGO_TERM_COLOR=${CARGO_TERM_COLOR:-auto}" \
  -e "CARGO_TARGET_${target_env_key}_RUSTFLAGS=-C target-feature=+crt-static -C link-self-contained=no" \
  -e "GIT_CONFIG_COUNT=1" \
  -e "GIT_CONFIG_KEY_0=safe.directory" \
  -e "GIT_CONFIG_VALUE_0=*" \
  -e "HONK_HOST_REV=$host_rev" \
  -e "HONK_PKG=$pkg" \
  -e "HONK_TARGET=$target" \
  "$image" \
  sh -eu -c '
    if [ -n "$HONK_HOST_REV" ]; then
      ctr_rev=$(git rev-parse --short=12 HEAD)
      if [ "$ctr_rev" != "$HONK_HOST_REV" ]; then
        echo "error: container git revision ($ctr_rev) != host ($HONK_HOST_REV)" >&2
        exit 1
      fi
    fi
    cargo build --release -p "$HONK_PKG" --target "$HONK_TARGET" "$@"
    bin="target/$HONK_TARGET/release/$HONK_PKG"
    if readelf -l "$bin" | grep -q INTERP; then
      echo "error: $bin is dynamically linked (PT_INTERP present)" >&2
      readelf -l "$bin" | grep INTERP >&2
      exit 1
    fi
    if readelf -d "$bin" 2>/dev/null | grep -q NEEDED; then
      echo "error: $bin has shared library dependencies (DT_NEEDED present)" >&2
      readelf -d "$bin" | grep NEEDED >&2
      exit 1
    fi
  ' -- "$@"

bin="$repo_root/target/$target/release/$pkg"
actual_version=$("$bin" --version)
if [[ -n "$expected_version" && "$actual_version" != "$pkg $expected_version" ]]; then
  echo "error: unexpected --version output: got '$actual_version', expected '$pkg $expected_version'" >&2
  exit 1
fi
echo "Verified static musl binary: $bin ($actual_version)"
