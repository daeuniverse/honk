#!/usr/bin/env bash
# Install the public Linux x86-64 loopback peers into a private directory.
set -euo pipefail

[[ $# == 1 ]] || { echo "usage: $0 <peer-directory>" >&2; exit 2; }
source "$(dirname "${BASH_SOURCE[0]}")/../.github/ci/pins.env"
mkdir -p "$1"
cd "$1"

fetch() {
    local url=$1 digest=$2 archive=${1##*/}
    curl -fsSL --retry 3 --connect-timeout 10 --max-time 120 -o "$archive" "$url"
    echo "$digest  $archive" | sha256sum -c -
}

sing_box="sing-box-$SING_BOX_VERSION-linux-amd64-musl"
juicity=juicity-x86_64-unknown-linux-musl.zip
fetch "https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX_VERSION/$sing_box.tar.gz" "$SING_BOX_SHA256"
fetch "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VERSION/Xray-linux-64.zip" "$XRAY_SHA256"
fetch "https://github.com/juicity/juicity-rs/releases/download/v$JUICITY_VERSION/$juicity" "$JUICITY_SHA256"

tar -xzf "$sing_box.tar.gz" --strip-components=1 "$sing_box/sing-box"
unzip -oj Xray-linux-64.zip xray
unzip -oj "$juicity" juicity-server
chmod u+x juicity-server
test -x sing-box && test -x xray && test -x juicity-server
