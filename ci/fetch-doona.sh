#!/usr/bin/env bash
# Fetch the doona release pinned in .github/ci/pins.env for the native-ui feature.
#
#   ci/fetch-doona.sh [DIR]            extract standard into DIR (default
#                                      target/doona-<version>), lite into DIR-lite;
#                                      print only the absolute standard path for HONK_DOONA_DIR
#   ci/fetch-doona.sh --source OUTDIR  write OUTDIR/doona-source-<version>.tar.gz,
#                                      the corresponding source of both editions
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
dir=$(realpath -m "$dir")
for edition in doona doona-lite; do
  checksum=$DOONA_SHA256
  [[ "$edition" != doona-lite ]] || checksum=$DOONA_LITE_SHA256
  curl -fsSL --retry 3 -o "$tmp/$edition.tar.gz" \
    "$repo/releases/download/v$DOONA_VERSION/$edition-$DOONA_VERSION.tar.gz"
  echo "$checksum  $tmp/$edition.tar.gz" | sha256sum -c --quiet -
  mkdir "$tmp/$edition"
  tar -xzf "$tmp/$edition.tar.gz" -C "$tmp/$edition"
  # Fonts ship in the separate doona-fonts package and are not embedded.
  rm -rf "$tmp/$edition/fonts"
  # Each embedded edition and release tarball must carry every notice it needs.
  missing=()
  for file in LICENSE NOTICE THIRD-PARTY-NOTICES.txt \
    $(grep -o 'LICENSES/[A-Za-z0-9.+-]*\.txt' "$tmp/$edition/NOTICE" 2>/dev/null | sort -u); do
    [[ -f "$tmp/$edition/$file" ]] || missing+=("$file")
  done
  if (( ${#missing[@]} )); then
    echo "$edition $DOONA_VERSION archive lacks required notices: ${missing[*]}" >&2
    exit 1
  fi
done
mkdir -p "$(dirname "$dir")"
rm -rf "$dir" "$dir-lite"
mv "$tmp/doona" "$dir"
mv "$tmp/doona-lite" "$dir-lite"
printf '%s\n' "$dir"
