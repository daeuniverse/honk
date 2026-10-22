#!/usr/bin/env bash
# Print the Release notes section that explains each archive in a dist directory.
# Usage: release-assets.sh <dist-dir>
set -euo pipefail

dist=${1:?usage: release-assets.sh <dist-dir>}
rows=()
others=()

for path in "$dist"/*.tar.gz; do
  file=${path##*/}
  case $file in
    honk-core-*) ;;
    doona-source-*) others+=("| \`$file\` | Corresponding source of the embedded doona UI (GPL-3.0 section 6) |"); continue ;;
    *) printf '::error::Unknown release archive: %s\n' "$file" >&2; exit 1 ;;
  esac

  if [[ ! $file =~ -(x86_64|aarch64)-unknown-linux-(gnu|musl)(-stock)?-(full|clash-api|native-api)\.tar\.gz$ ]]; then
    printf '::error::Unrecognised honk-core archive name: %s\n' "$file" >&2
    exit 1
  fi
  arch=${BASH_REMATCH[1]}
  libc=${BASH_REMATCH[2]}
  alloc=mimalloc alloc_rank=1
  [[ -n ${BASH_REMATCH[3]} ]] && alloc=stockalloc alloc_rank=2
  case ${BASH_REMATCH[4]} in
    full) api=fullapi api_rank=1 ;;
    clash-api) api=clashapi api_rank=2 ;;
    native-api) api=nativeapi api_rank=3 ;;
  esac
  # Sort key first (arch, libc, API, allocator), stripped before printing.
  rows+=("$arch $libc $api_rank $alloc_rank"$'\t'"| \`$file\` | \`$alloc-$api-$arch-$libc\` |")
done

if (( ${#rows[@]} == 0 )); then
  printf '::error::No honk-core archives in %s\n' "$dist" >&2
  exit 1
fi

cat <<'EOF'
## Downloads

Each build is named `{allocator}-{API}-{arch}-{libc}`:

- `mimalloc` favours throughput; `stockalloc` uses the system allocator and keeps the memory peak lower on small devices.
- `fullapi` has the Clash API, the native API and the embedded doona UI; `clashapi` has the Clash API only; `nativeapi` has the native API only, without the UI.
- `musl` builds are static and suit gateways.

Check a download with `sha256sum -c --ignore-missing SHA256SUMS`, and its origin with `gh attestation verify <file> -R daeuniverse/honk`.

| File | Build |
|---|---|
EOF
printf '%s\n' "${rows[@]}" | sort | cut -f2-
if (( ${#others[@]} > 0 )); then
  printf '\n| File | Contents |\n|---|---|\n'
  printf '%s\n' "${others[@]}"
fi
