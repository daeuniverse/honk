#!/usr/bin/env bash
# Build .deb, .rpm and Arch packages from the static musl full builds in a dist directory.
# Usage: build-packages.sh <dist-dir> <tag>, run from the repository root.
set -euo pipefail

dist=$(cd -- "${1:?usage: build-packages.sh <dist-dir> <tag>}" && pwd -P)
tag=${2:?usage: build-packages.sh <dist-dir> <tag>}
repo=$(pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
version=${tag#v}
date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
summary='Transparent proxy engine built on eBPF'
details='Reads dae configuration and proxies the traffic of a Linux host or gateway
through eBPF programs attached to its interfaces. This build embeds the doona
web UI and serves both the Clash API and the native API.'

for arch in x86_64 aarch64; do
  name="honk-core-$tag-$arch-unknown-linux-musl-full"
  tar -xzf "$dist/$name.tar.gz" -C "$work"
  cp "$repo"/install/{honk-core.service,copyright,package-after-install.sh,package-before-remove.sh,package-after-remove.sh} "$repo/config.dae" "$work/$name/"
  config="$work/$name/nfpm.yaml"
  cp "$repo/install/nfpm.yaml" "$config"
  # rpm marks documentation per file, so list the notices one by one.
  (cd "$work/$name" && find doona doona-lite -type f | sort) | while read -r file; do
    printf '  - src: ./%s\n    dst: /usr/share/doc/honk-core/%s\n    type: doc\n' "$file" "$file" >> "$config"
  done
  # nfpm translates the architecture into each packager's own spelling.
  case $arch in
    x86_64) export PKG_ARCH=amd64 ;;
    aarch64) export PKG_ARCH=arm64 ;;
  esac
  for target in deb rpm pkg.tar.zst; do
    # A prerelease sorts below its release: `~` does that for dpkg and rpm, and
    # pacman, which forbids `-` and `~`, sorts a letter after the last number lower.
    packager=$target PKG_VERSION=${version//-/\~} PKG_DESCRIPTION="$summary"$'\n'"$details"
    [[ $target != pkg.tar.zst ]] || packager=archlinux PKG_VERSION=${version//-/} PKG_DESCRIPTION=$summary
    export PKG_VERSION PKG_DESCRIPTION
    # dpkg and rpm want a changelog entry for this exact version; it points at the release notes.
    cat > "$work/$name/changelog.yml" <<YAML
- semver: ${PKG_VERSION}-1
  date: ${date}
  packager: daeuniverse <dae@v2raya.org>
  deb:
    urgency: medium
    distributions: [stable]
  changes:
    - note: See https://github.com/daeuniverse/honk/releases/tag/${tag}
YAML
    (cd "$work/$name" && nfpm package --config "$config" --packager "$packager" --target "$dist/honk-core-$tag-$arch.$target")
  done
done
