#!/usr/bin/env bash
set -euo pipefail

check() {
  local artifact=$1
  if [[ ! -f "$artifact" || ! -s "$artifact" ]]; then
    printf '::error::Missing or empty Debug artifact: %s. Re-run all jobs to rebuild the complete set.\n' "$artifact" >&2
    exit 1
  fi
}

# Full: both APIs and the embedded UI, gnu and musl.
for target in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl; do
  for suffix in '' -stock; do
    check "dist/honk-core-debug-$target$suffix-full.tar.gz"
  done
done

# Lean variants ship for the static gateway targets only.
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  for suffix in '' -stock; do
    check "dist/honk-core-debug-$target$suffix-clash-api.tar.gz"
    check "dist/honk-core-debug-$target$suffix-native-api.tar.gz"
  done
done
