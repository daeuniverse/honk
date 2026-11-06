#!/usr/bin/env bash
set -euo pipefail

ci_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
repo=$work/repo
git init -q "$repo"
commit() {
  git -C "$repo" add -A
  git -C "$repo" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m "$1"
}
commit 'old release'
git -C "$repo" tag v0.1.0-beta.1
mkdir -p "$repo/.github/ci"
printf 'DOONA_VERSION=0.1.0-rc.1\n' > "$repo/.github/ci/pins.env"
cat > "$repo/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

Entries live in [changes/](changes/) until release.

## [0.1.0-beta.2] - 2026-10-28

### Added

- Serve a local UI. (#12)

### Fixed

- Keep quoted node names. (#13)
- Preserve cached answers. (#14)

### Internal

- Collect release entries from fragments. (#15)

## [0.1.0-beta.1] - 2026-10-27

### Added

- Old release entry.

[Unreleased]: https://github.com/o/r/compare/v0.1.0-beta.2...HEAD
[0.1.0-beta.2]: https://github.com/o/r/compare/v0.1.0-beta.1...v0.1.0-beta.2
EOF
commit 'feat(core): this commit subject is not a release entry'
git -C "$repo" tag v0.1.0-beta.2
printf 'DOONA_VERSION=9.9.9\n' > "$repo/.github/ci/pins.env"
printf '# Unrelated working tree changelog\n' > "$repo/CHANGELOG.md"

printf '## Downloads\n\nAsset table.\n' > "$work/assets.md"
notes=$(cd "$repo" && GITHUB_REPOSITORY=o/r bash "$ci_dir/release-notes.sh" v0.1.0-beta.2 "$work/assets.md")
python3 - "$notes" <<'PY'
import sys
notes = sys.argv[1]
for value in ['<summary>Added (1)</summary>', '<summary>Fixed (2)</summary>',
              '<summary>Internal (1)</summary>', '- Serve a local UI. (#12)',
              '- Keep quoted node names. (#13)', '- Preserve cached answers. (#14)',
              '- Collect release entries from fragments. (#15)',
              'https://github.com/Zakkaus/doona/releases/tag/v0.1.0-rc.1',
              'https://github.com/o/r/compare/v0.1.0-beta.1...v0.1.0-beta.2',
              'honk 0.1.0-beta.2. This is a pre-release.', '## Downloads\n\nAsset table.',
              '[OpenWrt feed](https://openwrt.daeuniverse.org/)']:
    assert value in notes, value
assert notes.index('## Pairing with doona') < notes.index('## Downloads') < notes.index('[Full changelog]')
for value in ['Old release entry', 'Unrelated working tree', '9.9.9', 'this commit subject']:
    assert value not in notes, value
assert notes.count('<details>') == notes.count('</details>') == 3
PY

git -C "$repo" tag v0.1.0-beta.3
if (cd "$repo" && bash "$ci_dir/release-notes.sh" v0.1.0-beta.3) > "$work/notes" 2> "$work/error"; then
  echo 'Missing changelog version must fail' >&2
  exit 1
fi
test ! -s "$work/notes"
grep -qF 'CHANGELOG.md has no release section for v0.1.0-beta.3' "$work/error"
echo 'release notes: tagged entries, counts, pairing and missing-section checks ok'
