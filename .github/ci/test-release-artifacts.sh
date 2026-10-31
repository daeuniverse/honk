#!/usr/bin/env bash
set -euo pipefail

ci_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

create_set() {
  local prefix=$1
  mkdir dist
  for target in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl; do
    for suffix in '' -stock; do
      printf 'artifact\n' > "dist/honk-core-$prefix-$target$suffix-full.tar.gz"
    done
  done
  for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    for suffix in '' -stock; do
      printf 'artifact\n' > "dist/honk-core-$prefix-$target$suffix-clash-api.tar.gz"
      printf 'artifact\n' > "dist/honk-core-$prefix-$target$suffix-native-api.tar.gz"
    done
  done
}

expect_rejection() {
  local prefix=$1 status=0
  bash "$ci_dir/check-release-artifacts.sh" "$@" > failure.log 2>&1 || status=$?
  if [[ "$status" != 1 ]]; then
    cat failure.log >&2
    printf 'Expected incomplete %s artifacts to be rejected, got exit %s\n' "$prefix" "$status" >&2
    exit 1
  fi
}

# Debug builds and formal tags share the sixteen-archive set; only the name prefix differs.
for prefix in debug v0.1.0-rc.1; do
  create_set "$prefix"
  bash "$ci_dir/check-release-artifacts.sh" "$prefix"

  artifact=dist/honk-core-$prefix-aarch64-unknown-linux-musl-stock-native-api.tar.gz
  mv "$artifact" saved.tar.gz
  expect_rejection "$prefix"
  mv saved.tar.gz "$artifact"
  bash "$ci_dir/check-release-artifacts.sh" "$prefix"

  artifact=dist/honk-core-$prefix-x86_64-unknown-linux-gnu-full.tar.gz
  mv "$artifact" saved.tar.gz
  expect_rejection "$prefix"
  mv saved.tar.gz "$artifact"
  bash "$ci_dir/check-release-artifacts.sh" "$prefix"

  : > "$artifact"
  expect_rejection "$prefix"
  rm "$artifact"
  mkdir "$artifact"
  expect_rejection "$prefix"
  rm -r dist
  expect_rejection "$prefix"
done

# A complete set under the other prefix does not satisfy the check.
create_set debug
expect_rejection v0.1.0-rc.1

expect_rejection debug --toolbox
for target in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl; do
  printf 'toolbox\n' > "dist/honk-tool-debug-$target.tar.gz"
done
bash "$ci_dir/check-release-artifacts.sh" debug --toolbox
for target in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl; do
  artifact=dist/honk-tool-debug-$target.tar.gz
  mv "$artifact" saved.tar.gz
  expect_rejection debug --toolbox
  : > "$artifact"
  expect_rejection debug --toolbox
  mv saved.tar.gz "$artifact"
done
bash "$ci_dir/check-release-artifacts.sh" debug --toolbox

printf 'Release artifact preflight regression passed\n'
