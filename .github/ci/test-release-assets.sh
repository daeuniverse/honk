#!/usr/bin/env bash
# shellcheck disable=SC2016  # the expected lines contain literal Markdown backticks
set -euo pipefail

ci_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/dist"

touch "$work/dist/honk-core-v1.2.3-x86_64-unknown-linux-gnu-full.tar.gz" \
  "$work/dist/honk-core-v1.2.3-aarch64-unknown-linux-musl-stock-native-api.tar.gz" \
  "$work/dist/honk-core-debug-x86_64-unknown-linux-musl-clash-api.tar.gz" \
  "$work/dist/doona-source-0.1.0.tar.gz"
bash "$ci_dir/release-assets.sh" "$work/dist" > "$work/notes.md"

expect_line() {
  if ! grep -qxF -- "$1" "$work/notes.md"; then
    cat "$work/notes.md" >&2
    printf 'Missing line: %s\n' "$1" >&2
    exit 1
  fi
}
expect_line '| `honk-core-v1.2.3-x86_64-unknown-linux-gnu-full.tar.gz` | `mimalloc-fullapi-x86_64-gnu` |'
expect_line '| `honk-core-v1.2.3-aarch64-unknown-linux-musl-stock-native-api.tar.gz` | `stockalloc-nativeapi-aarch64-musl` |'
expect_line '| `honk-core-debug-x86_64-unknown-linux-musl-clash-api.tar.gz` | `mimalloc-clashapi-x86_64-musl` |'
expect_line '| `doona-source-0.1.0.tar.gz` | Corresponding source of the embedded doona UI (GPL-3.0 section 6) |'

# A name the table cannot classify fails the release instead of shipping an unexplained file.
touch "$work/dist/honk-core-v1.2.3-riscv64-unknown-linux-musl-full.tar.gz"
if bash "$ci_dir/release-assets.sh" "$work/dist" > /dev/null 2>&1; then
  printf 'Expected an unrecognised archive name to be rejected\n' >&2
  exit 1
fi

echo "release asset table: ok"
