#!/usr/bin/env bash
# Disposable-virtme-guest gate; the matching daemon is supplied by run-vm-gate.sh.
set -euo pipefail

fail() { printf 'tun-daemon-smoke: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) == 0 && $(uname -s) == Linux ]] || fail 'requires Linux guest root'
read -r cmdline </proc/cmdline
[[ " $cmdline " == *' virtme.'* ]] || fail 'requires a disposable virtme guest'
[[ ${HONK_CI_VM_LANE:-} == floor || ${HONK_CI_VM_LANE:-} == recent ]] || fail 'requires floor/recent guest lane'
[[ $(uname -r) == "${HONK_CI_EXPECTED_KERNEL:?missing guest kernel identity}" ]] || fail 'guest kernel mismatch'
for tool in ip nft tc ethtool ss python3 unshare mount stat timeout; do
    command -v "$tool" >/dev/null || fail "missing provisioned prerequisite: $tool"
done
[[ -c /dev/net/tun ]] || fail 'requires provisioned /dev/net/tun'

if [[ ${1:-} != --isolated ]]; then
    [[ $# -le 1 ]] || fail 'expected one matching daemon executable'
    daemon=${1:-${HONK_XDP_DAEMON:-}}
    [[ $daemon == /* && -x $daemon ]] || fail 'supply the absolute matching honk-core executable'
    export HONK_TUN_PARENT_NETNS
    HONK_TUN_PARENT_NETNS=$(stat -Lc %i /proc/self/ns/net)
    exec unshare --mount --net -- bash "${BASH_SOURCE[0]}" --isolated "$daemon"
fi
[[ $# == 2 && $2 == /* && -x $2 ]] || fail 'invalid isolated invocation'
current_netns=$(stat -Lc %i /proc/self/ns/net)
[[ $current_netns != "${HONK_TUN_PARENT_NETNS:?missing outer guest guard}" &&
   $current_netns != "$(stat -Lc %i /proc/1/ns/net)" ]] || fail 'refusing initial network namespace'
mount --make-rprivate /
mount -t tmpfs -o mode=0755 tmpfs /run
mkdir -m 700 /run/honk-tun-state
mkdir /run/netns
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d "${HONK_TUN_ARTIFACT_ROOT:-/tmp}/honk-tun-daemon.XXXXXX")
printf 'TUN smoke artifacts: %s\n' "$work"
# The fixture owns operator forwarding/firewall/main-route prerequisites. The
# daemon must create its own TUN, addresses, table, five rules and crash guards.
exec timeout --signal=TERM --kill-after=20s 900s \
    python3 "$script_dir/tun-endpoint-peer.py" gate "$2" "$work"
