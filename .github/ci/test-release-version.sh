#!/usr/bin/env bash
set -euo pipefail

ci_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "1.2.0-rc.3"\nedition = "2024"\n\n[package]\nversion = "9.9.9"\n' > "$work/Cargo.toml"

check() {
  bash "$ci_dir/check-release-version.sh" "$1" "$work/Cargo.toml" > /dev/null 2>&1
}

check v1.2.0-rc.3 || { echo 'Expected the matching tag to pass' >&2; exit 1; }
for tag in v1.2.0-rc.4 v1.2.0 v1.2.0.rc.3 v1.2.0-preview.1 v01.2.0-rc.3 1.2.0-rc.3 v9.9.9; do
  if check "$tag"; then
    printf 'Expected %s to be rejected\n' "$tag" >&2
    exit 1
  fi
done

echo "release version check: ok"
