#!/usr/bin/env bash
# Boot an unpacked honk VM image with run.sh and wait until the native API answers.
# Usage: vm-smoke.sh <vm-dir> [timeout-seconds]
set -euo pipefail
dir=$(realpath "${1:?usage: vm-smoke.sh <vm-dir> [timeout-seconds]}")
deadline=$(( SECONDS + ${2:-900} ))
work=$(mktemp -d)
port=$(( 20000 + RANDOM % 20000 ))
secret=smoke-test-secret-$RANDOM$RANDOM
cat > "$work/config.dae" <<CONFIG
global {
    wan_interface: eth0
    data_dir: '/var/lib/honk'
    log_level: info
    auto_config_kernel_parameter: true
}
node { }
routing { fallback: direct }
experimental {
    native_api {
        enabled: true
        listen: '0.0.0.0:9527'
        secret: '$secret'
        allowed_hosts: '127.0.0.1:$port'
    }
}
CONFIG
"$dir/run.sh" --config "$work/config.dae" --api-port "$port" < /dev/null > "$work/serial.log" 2>&1 &
vm=$!
trap 'kill "$vm" 2> /dev/null || true; wait "$vm" 2> /dev/null || true; rm -rf "$work"' EXIT

while (( SECONDS < deadline )); do
  if version=$(curl -fsS -m 2 -H "Authorization: Bearer $secret" "http://127.0.0.1:$port/api/v1/version" 2> /dev/null); then
    printf 'API ready after %ss: %s\n' "$SECONDS" "$version"
    cat "$work/serial.log"
    exit 0
  fi
  kill -0 "$vm" 2> /dev/null || break
  sleep 2
done
cat "$work/serial.log" >&2
printf '::error::honk VM API did not answer within the timeout\n' >&2
exit 1
