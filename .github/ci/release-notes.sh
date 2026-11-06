#!/usr/bin/env bash
# Run inside a full clone: release-notes.sh <tag> [assets.md].
set -euo pipefail

tag=${1:?usage: release-notes.sh <tag> [assets.md]}
assets=${2:-}
repo=${GITHUB_REPOSITORY:-daeuniverse/honk}
prev=$(git describe --tags --abbrev=0 --match 'v*' "$tag^" 2>/dev/null || true)
notes=$(python3 - "$tag" <<'PY'
import re
import subprocess
import sys

tag = sys.argv[1]
version = tag.removeprefix('v')
changelog = subprocess.check_output(['git', 'show', f'{tag}:CHANGELOG.md'], text=True)
section = re.search(rf'^## \[{re.escape(version)}\] - [^\n]+\n(.*?)(?=^## \[|^\[Unreleased\]:|\Z)', changelog, re.M | re.S)
if not section:
    sys.exit(f'CHANGELOG.md has no release section for {tag}')
pins = subprocess.check_output(['git', 'show', f'{tag}:.github/ci/pins.env'], text=True)
pin = re.search(r'^DOONA_VERSION=(\S+)$', pins, re.M)
if not pin:
    sys.exit(f'.github/ci/pins.env has no DOONA_VERSION at {tag}')
print('## Changes')
for group in re.finditer(r'^### ([^\n]+)\n(.*?)(?=^### |\Z)', section[1], re.M | re.S):
    body = group[2].strip()
    if not body:
        continue
    count = len(re.findall(r'^- ', body, re.M))
    print(f'\n<details>\n<summary>{group[1]} ({count})</summary>\n\n{body}\n\n</details>')
print(f'\n## Pairing with doona\n\nThe full builds embed [doona {pin[1]}](https://github.com/Zakkaus/doona/releases/tag/v{pin[1]}), pinned in `.github/ci/pins.env` at this tag.')
PY
)
stage=' This is a stable release.'
[[ $tag != *-* ]] || stage=' This is a pre-release.'
printf 'honk %s.%s\n\n## Highlights\n\n<!-- Maintainer: three to five bullets on what this release means to a gateway operator. -->\n\n%s\n' "${tag#v}" "$stage" "$notes"
if [[ -n $assets ]]; then
  downloads=$(<"$assets")
  printf '\n%s\n' "$downloads"
fi
links="[Documentation](https://github.com/$repo/blob/$tag/doc/README.md) | [doona](https://github.com/Zakkaus/doona) | [OpenWrt feed](https://openwrt.daeuniverse.org/)"
[[ -z $prev ]] || links="[Full changelog](https://github.com/$repo/compare/$prev...$tag) | $links"
printf '\n%s\n' "$links"
