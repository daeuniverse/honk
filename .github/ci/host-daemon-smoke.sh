#!/usr/bin/env bash
# Guest-only production Host proof; launcher owns builds, identity and VM lifetime.
set -euo pipefail
fail() { printf 'host-daemon-smoke: %s\n' "$*" >&2; exit 1; }
[[ $# == 3 && $1 == --isolated && $2 == /* ]] || fail 'requires exact isolated manifest invocation'
[[ $(id -u) == 0 && $(uname -m) == x86_64 ]] || fail 'requires actual x86_64 guest root'
for tool in python3 ip tc ss sysctl nft mount stat; do
    command -v "$tool" >/dev/null || fail "missing provisioned guest prerequisite: $tool"
done
python3 - "$2" "$3" <<'PY'
import hashlib, json, os, pathlib, re, sys, time
if sys.flags.optimize:
    raise RuntimeError('optimization disables guest identity checks')
path = pathlib.Path(sys.argv[1]).resolve(strict=True)
expected = sys.argv[2]
assert re.fullmatch('[0-9a-f]{64}', expected)
assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'boot manifest hash differs'
value = json.loads(path.read_text())
assert value['schema'] == 'honk-host-daemon-vm-v1' and value['profile'] == 'host-daemon'
assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() != value['host_boot_id'], 'refusing the host boot'
assert pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == value['uuid'], 'guest UUID differs'
assert 'hypervisor' in pathlib.Path('/proc/cpuinfo').read_text().split(), 'actual hypervisor evidence missing'
assert 'virtme.exec=' in pathlib.Path('/proc/cmdline').read_text(), 'requires actual virtme guest'
assert os.uname().release == value['kernel_release'] == os.environ['HONK_CI_EXPECTED_KERNEL']
assert value['lane'] == os.environ['HONK_CI_VM_LANE']
current = os.stat('/proc/self/ns/net').st_ino
assert current == int(os.environ['HONK_HOST_COORDINATOR_INODE'])
assert current not in (os.stat(os.environ['HONK_HOST_PARENT_NETNS']).st_ino, os.stat('/proc/1/ns/net').st_ino)
assert time.monotonic_ns() < int(os.environ['HONK_HOST_DEADLINE_NS']), 'original guest deadline exhausted'
repo = pathlib.Path(value['repo'])
assert repo == path.parent.parent.parent / 'product-source'
for name in (str(repo / '.github/ci/host-daemon-smoke.sh'), str(path.parent.parent / 'peer.py'),
             str(repo / '.github/ci/tun-endpoint-peer.py')):
    assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() == value['hashes'][name], 'source input changed: ' + name
PY
mount --make-rprivate /
[[ $(stat -f -c %T /sys/kernel/security) == securityfs ]] || mount -t securityfs securityfs /sys/kernel/security
[[ $(stat -f -c %T /sys/kernel/security) == securityfs ]] || fail 'actual post-switch securityfs unavailable'
python3 - <<'PY'
from pathlib import Path
assert 'bpf' in Path('/sys/kernel/security/lsm').read_text().strip().split(','), 'BPF LSM is not active'
PY
mount -t tmpfs tmpfs /run
mkdir -p /run/netns
mkdir -m 700 /run/honk-host-state /run/honk-host-cgroup /run/honk-host-bpf
mount -t cgroup2 cgroup2 /run/honk-host-cgroup
[[ $(stat -f -c %T /run/honk-host-cgroup) == cgroup2fs ]] || fail 'actual guest cgroup2 unavailable'
mount -t bpf bpf /run/honk-host-bpf
[[ $(stat -f -c %T /run/honk-host-bpf) == bpf_fs ]] || fail 'actual private bpffs unavailable'
peer=$(dirname -- "$(dirname -- "$2")")/peer.py
exec python3 -B -u "$peer" gate "$2" "$3"
