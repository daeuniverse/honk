#!/usr/bin/env bash
# Guest-only Host TCX/TUN gate. run-vm-gate.sh owns builds and boot identity.
set -euo pipefail
fail() { printf 'host-daemon-smoke: %s\n' "$*" >&2; exit 1; }
stage=guest
if [[ ${1:-} == --isolated ]]; then
    stage=isolated
    shift
fi
[[ $# == 2 && $1 == /* ]] || fail 'requires the launcher input manifest and SHA256'
[[ $(id -u) == 0 && $(uname -sm) == 'Linux x86_64' ]] || fail 'requires actual x86_64 guest root'
for tool in python3 ip tc ss sysctl nft mount umount stat unshare modprobe wg ethtool timeout; do
    command -v "$tool" >/dev/null || fail "missing provisioned guest prerequisite: $tool"
done
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
python3 -I -B - "$1" "$2" "$script_dir" "$stage" <<'PY'
import hashlib, json, os, pathlib, re, sys, time

path, expected, scripts, stage = sys.argv[1:]
path, scripts = pathlib.Path(path), pathlib.Path(scripts)
assert path == path.resolve(strict=True) and re.fullmatch('[0-9a-f]{64}', expected)
assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'boot manifest hash differs'
value = json.loads(path.read_text())
lane = os.environ['HONK_CI_VM_LANE']
assert value['schema'] == 'honk-host-ci-v1' and lane in ('floor', 'recent') and value['lane'] == lane
assert value['selection'] == os.environ['HONK_CI_HOST_SELECTION']
repo = scripts.parent.parent
assert pathlib.Path(value['repo']) == repo == pathlib.Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
assert path == repo / 'target/vm-tests' / lane / 'host-inputs.json'
read = lambda name: pathlib.Path(name).read_text().strip()
boot = read('/proc/sys/kernel/random/boot_id')
assert boot and boot != value['host_boot_id'], 'refusing the launcher host boot'
assert read('/sys/class/dmi/id/product_uuid').lower() == value['uuid'], 'guest UUID differs'
assert 'hypervisor' in read('/proc/cpuinfo').split(), 'actual hypervisor evidence missing'
assert 'virtme.exec=' in read('/proc/cmdline'), 'requires actual virtme guest'
assert os.uname().release == value['kernel_release'] == os.environ['HONK_CI_EXPECTED_KERNEL']
current = os.stat('/proc/self/ns/net').st_ino
initial = os.stat('/proc/1/ns/net').st_ino
if stage == 'guest':
    assert current == initial, 'guest entry must start in the launcher network namespace'
else:
    assert str(initial) == os.environ['HONK_HOST_PARENT_NETNS'] and current != initial
    assert os.stat('/proc/self/ns/mnt').st_ino != int(os.environ['HONK_HOST_PARENT_MNTNS'])
    assert time.monotonic_ns() < int(os.environ['HONK_HOST_DEADLINE_NS']), 'original guest deadline exhausted'

daemon = pathlib.Path(value['daemon'])
assert daemon == pathlib.Path(os.environ['HONK_XDP_DAEMON']).resolve(strict=True) and os.access(daemon, os.X_OK)
required = ('host-daemon-smoke.sh', 'host-daemon-peer.py', 'tun-endpoint-peer.py',
            'xdp-l3-lan.py', 'xdp-dns-shadow.py', 'xdp-ipv4-options.py', 'xdp_dns_tcp.py')
assert {str(scripts / name) for name in required} | {str(daemon)} == set(value['hashes'])
for name, digest in value['hashes'].items():
    with open(name, 'rb') as source:
        assert hashlib.file_digest(source, 'sha256').hexdigest() == digest, 'source input changed: ' + name
PY
if [[ $stage == guest ]]; then
    export HONK_HOST_PARENT_NETNS HONK_HOST_PARENT_MNTNS HONK_HOST_DEADLINE_NS
    HONK_HOST_PARENT_NETNS=$(stat -Lc %i /proc/self/ns/net)
    HONK_HOST_PARENT_MNTNS=$(stat -Lc %i /proc/self/ns/mnt)
    HONK_HOST_DEADLINE_NS=$(python3 -I -B -c 'import time; print(time.monotonic_ns() + 450_000_000_000)')
    exec unshare --mount --net --propagation private -- bash "$script_dir/host-daemon-smoke.sh" --isolated "$@"
fi
mount --make-rprivate /
mount -t tmpfs -o mode=0755 tmpfs /run
mkdir /run/netns
mkdir -m 700 /run/honk-host-state /run/honk-host-cgroup /run/honk-host-bpf
mount -t cgroup2 cgroup2 /run/honk-host-cgroup
[[ $(stat -f -c %T /run/honk-host-cgroup) == cgroup2fs ]] || fail 'actual guest cgroup2 unavailable'
mount -t bpf bpf /run/honk-host-bpf
[[ $(stat -f -c %T /run/honk-host-bpf) == bpf_fs ]] || fail 'actual private bpffs unavailable'
modprobe -a nf_conntrack wireguard
export HONK_XDP_PARENT_NETNS="$HONK_HOST_PARENT_NETNS"
exec timeout --signal=TERM --kill-after=20s 440s \
    python3 -I -B -u "$script_dir/host-daemon-peer.py" gate "$1" "$2"
