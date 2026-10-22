#!/usr/bin/env bash
set -euo pipefail

ci_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git -C "$work" init -q
commit() { git -C "$work" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m "$1"; }
commit 'feat(core): old feature'
git -C "$work" tag v0.1.0-beta.1
commit 'feat(dns): add DoH3 upstreams'
commit 'fix(config): keep quoted names'
commit 'refactor(core): split the reload path'
commit 'bench(outbound): record QUIC throughput'
commit 'Update README'
git -C "$work" tag v0.1.0-beta.2

notes=$(cd "$work" && RELEASE_NOTES_OFFLINE=1 GITHUB_REPOSITORY=o/r bash "$ci_dir/release-notes.sh" v0.1.0-beta.2)
expect() {
  if ! grep -qF -- "$1" <<<"$notes"; then
    printf '%s\n' "$notes" >&2
    printf 'Missing: %s\n' "$1" >&2
    exit 1
  fi
}
expect '### New Features'
expect '- feat(dns): add DoH3 upstreams in '
expect '### Bug Fixes'
expect '- fix(config): keep quoted names in '
expect '### Documentation'
expect '- bench(outbound): record QUIC throughput in '
expect '2 refactoring, test and maintenance commits are not listed.'
expect '**Full Changelog**: https://github.com/o/r/compare/v0.1.0-beta.1...v0.1.0-beta.2'
if grep -qF 'old feature' <<<"$notes"; then
  echo 'Commits before the previous tag must not be listed' >&2
  exit 1
fi

echo "release notes: ok"
