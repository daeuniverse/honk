#!/usr/bin/env bash
set -euo pipefail

ci_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
mkdir dist

for target in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl; do
  for suffix in '' -stock; do
    printf 'artifact\n' > "dist/honk-core-debug-$target$suffix.tar.gz"
  done
done
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  for suffix in '' -stock; do
    printf 'artifact\n' > "dist/honk-core-debug-$target$suffix-clash-api.tar.gz"
    printf 'artifact\n' > "dist/honk-core-debug-$target$suffix-native-api.tar.gz"
  done
done
bash "$ci_dir/check-debug-artifacts.sh"

expect_rejection() {
  local status=0
  bash "$ci_dir/check-debug-artifacts.sh" > failure.log 2>&1 || status=$?
  if [[ "$status" != 1 ]]; then
    cat failure.log >&2
    printf 'Expected incomplete Debug artifacts to be rejected, got exit %s\n' "$status" >&2
    exit 1
  fi
}

artifact=dist/honk-core-debug-aarch64-unknown-linux-musl-stock-native-api.tar.gz
mv "$artifact" saved.tar.gz
expect_rejection
mv saved.tar.gz "$artifact"
bash "$ci_dir/check-debug-artifacts.sh"

artifact=dist/honk-core-debug-x86_64-unknown-linux-gnu.tar.gz
mv "$artifact" saved.tar.gz
expect_rejection
mv saved.tar.gz "$artifact"
bash "$ci_dir/check-debug-artifacts.sh"

: > "$artifact"
expect_rejection
rm "$artifact"
mkdir "$artifact"
expect_rejection
rm -r dist
expect_rejection

printf 'Debug artifact preflight regression passed\n'
