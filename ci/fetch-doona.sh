#!/usr/bin/env bash
# Fetch the doona release pinned in .github/ci/pins.env for the native-ui feature.
#
#   ci/fetch-doona.sh [DIR]            extract the program files into DIR (default
#                                      target/doona-<version>) and print its absolute
#                                      path, for HONK_DOONA_DIR
#   ci/fetch-doona.sh --source OUTDIR  write OUTDIR/doona-source-<version>.tar.gz,
#                                      the corresponding source of that release
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
source "$root/.github/ci/pins.env"
repo=https://github.com/Zakkaus/doona
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [[ "${1:-}" == "--source" ]]; then
  out=${2:?usage: ci/fetch-doona.sh --source OUTDIR}
  git init --quiet --bare "$tmp/doona.git"
  git -C "$tmp/doona.git" fetch --quiet --depth 1 "$repo.git" \
    "refs/tags/v$DOONA_VERSION:refs/tags/v$DOONA_VERSION"
  revision=$(git -C "$tmp/doona.git" rev-parse "v$DOONA_VERSION^{commit}")
  if [[ "$revision" != "$DOONA_REVISION" ]]; then
    echo "doona tag v$DOONA_VERSION points at $revision, expected $DOONA_REVISION" >&2
    exit 1
  fi
  mkdir -p "$out"
  git -C "$tmp/doona.git" archive --format=tar --prefix=doona/ "v$DOONA_VERSION" |
    gzip -n > "$out/doona-source-$DOONA_VERSION.tar.gz"
  exit 0
fi

dir=${1:-$root/target/doona-$DOONA_VERSION}
curl -fsSL --retry 3 -o "$tmp/doona.tar.gz" \
  "$repo/releases/download/v$DOONA_VERSION/doona-$DOONA_VERSION.tar.gz"
echo "$DOONA_SHA256  $tmp/doona.tar.gz" | sha256sum -c --quiet -
mkdir "$tmp/doona"
tar -xzf "$tmp/doona.tar.gz" -C "$tmp/doona"
# Fonts ship in the separate doona-fonts package and are not embedded.
rm -rf "$tmp/doona/fonts"
# The embedded UI and each release tarball must carry every notice it needs.
missing=()
for file in LICENSE NOTICE THIRD-PARTY-NOTICES.txt \
  $(grep -o 'LICENSES/[A-Za-z0-9.+-]*\.txt' "$tmp/doona/NOTICE" 2>/dev/null | sort -u); do
  [[ -f "$tmp/doona/$file" ]] || missing+=("$file")
done
if (( ${#missing[@]} )); then
  echo "doona $DOONA_VERSION archive lacks required notices: ${missing[*]}" >&2
  exit 1
fi
rm -rf "$dir"
mkdir -p "$(dirname "$dir")"
mv "$tmp/doona" "$dir"
cd "$dir" && pwd
