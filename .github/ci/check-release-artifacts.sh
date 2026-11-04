#!/usr/bin/env bash
set -euo pipefail

# Usage: check-release-artifacts.sh <prefix>, where <prefix> is `debug` or the formal tag (e.g. v0.1.0-rc.1).
prefix=${1:?usage: check-release-artifacts.sh <debug|tag>}

check() {
  local artifact=$1
  if [[ ! -f "$artifact" || ! -s "$artifact" ]]; then
    printf '::error::Missing or empty release artifact: %s. Re-run all jobs to rebuild the complete set.\n' "$artifact" >&2
    exit 1
  fi
}

# Full: both APIs and the embedded UI, gnu and musl.
for target in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl; do
  for suffix in '' -stock; do
    check "dist/honk-core-$prefix-$target$suffix-full.tar.gz"
  done
done

# riscv64 ships the static full build only.
for suffix in '' -stock; do
  check "dist/honk-core-$prefix-riscv64gc-unknown-linux-musl$suffix-full.tar.gz"
done

# One VM image per architecture.
for arch in x86_64 aarch64 riscv64; do
  check "dist/honk-vm-$prefix-$arch.tar.gz"
done

# Lean variants ship for the static gateway targets only.
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  for suffix in '' -stock; do
    check "dist/honk-core-$prefix-$target$suffix-clash-api.tar.gz"
    check "dist/honk-core-$prefix-$target$suffix-native-api.tar.gz"
  done
done
