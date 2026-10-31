#!/usr/bin/env bash
set -euo pipefail

# Usage: check-release-artifacts.sh <prefix> [--toolbox].
prefix=${1:?usage: check-release-artifacts.sh <debug|tag> [--toolbox]}
if (( $# > 2 )) || [[ -n ${2:-} && ${2:-} != --toolbox ]]; then
  printf 'usage: check-release-artifacts.sh <debug|tag> [--toolbox]\n' >&2
  exit 1
fi

check() {
  local artifact=$1
  if [[ ! -f "$artifact" || ! -s "$artifact" ]]; then
    printf '::error::Missing or empty release artifact: %s. Re-run all jobs to rebuild the complete set.\n' "$artifact" >&2
    exit 1
  fi
}

targets=(x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl)

# Full: both APIs and the embedded UI, gnu and musl.
for target in "${targets[@]}"; do
  for suffix in '' -stock; do
    check "dist/honk-core-$prefix-$target$suffix-full.tar.gz"
  done
done

# Lean variants ship for the static gateway targets only.
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  for suffix in '' -stock; do
    check "dist/honk-core-$prefix-$target$suffix-clash-api.tar.gz"
    check "dist/honk-core-$prefix-$target$suffix-native-api.tar.gz"
  done
done

if [[ ${2:-} == --toolbox ]]; then
  for target in "${targets[@]}"; do
    check "dist/honk-tool-$prefix-$target.tar.gz"
  done
fi
