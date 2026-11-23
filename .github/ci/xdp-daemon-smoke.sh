#!/usr/bin/env bash
# Disposable-virtme-guest gate. Never invoke on the host; no downloads/builds.
# Usage: bash .github/ci/xdp-daemon-smoke.sh /absolute/path/to/fresh/honk-core [all|runtime|daemon|dns-shadow]
set -euo pipefail

fail() { printf 'xdp-daemon-smoke: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) == 0 ]] || fail 'requires guest root'
[[ $(uname -s) == Linux ]] || fail 'requires Linux'
read -r cmdline </proc/cmdline
[[ " $cmdline " == *' virtme.'* ]] || fail 'requires a disposable virtme guest (kernel command line)'
for tool in ip tc nft ethtool python3 unshare mount mountpoint stat timeout; do
    command -v "$tool" >/dev/null || fail "missing provisioned prerequisite: $tool"
done
python3 - <<'PY'
import os, re
version = tuple(map(int, re.match(r'(\d+)\.(\d+)', os.uname().release).groups()))
assert version >= (6, 12), 'requires Linux >= 6.12'
assert os.path.exists('/proc/self/ns/net'), 'requires network namespaces'
PY

if [[ ${1:-} != --isolated ]]; then
    [[ $# -le 2 ]] || fail 'expected a fresh daemon executable and optional smoke scope'
    daemon=${1:-${HONK_XDP_DAEMON:-}}
    [[ $daemon == /* && -x $daemon ]] || fail 'supply an absolute fresh honk-core executable path'
    export HONK_XDP_PARENT_NETNS
    HONK_XDP_PARENT_NETNS=$(stat -Lc %i /proc/self/ns/net)
    exec unshare --mount --net -- bash "${BASH_SOURCE[0]}" --isolated "$daemon" "${2:-all}"
fi
[[ $# == 3 && -x $2 && $2 == /* ]] || fail 'invalid isolated invocation'
daemon=$2
smoke_scope=$3
case $smoke_scope in
    all) ;;
    runtime) [[ -n ${HONK_XDP_CORE_TEST_BIN:-} ]] || fail 'runtime scope requires the complete Core test executable' ;;
    daemon) [[ -z ${HONK_XDP_CORE_TEST_BIN:-} && -z ${HONK_XDP_XSK_TEST_BIN:-} ]] || fail 'daemon scope cannot ignore supplied test executables' ;;
    dns-shadow)
        [[ -n ${HONK_XDP_CORE_TEST_BIN:-} && -n ${HONK_XDP_XSK_TEST_BIN:-} ]] || fail 'dns-shadow requires the current Core and XSK test executables'
        ;;
    *) fail 'unknown smoke scope' ;;
esac
read -r smoke_started _ </proc/uptime
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
export HONK_XDP_PROBE="$script_dir/xdp-ipv4-options.py"
export HONK_XDP_DNS_PROBE="$script_dir/xdp-dns-shadow.py"
current_netns=$(stat -Lc %i /proc/self/ns/net)
[[ $current_netns != "${HONK_XDP_PARENT_NETNS:?missing outer guest guard}" &&
   $current_netns != "$(stat -Lc %i /proc/1/ns/net)" ]] || fail 'refusing initial network namespace'
# Every mutation below is inside both a private mount and network namespace.
mount --make-rprivate /
mount -t tmpfs tmpfs /run
mkdir -p /run/netns
mkdir -m 700 /run/honk-xdp-state /run/honk-tc-state /run/honk-cgroup
# ip netns exec remounts sysfs; keep the VM cgroup hierarchy outside that subtree.
mount -t cgroup2 cgroup2 /run/honk-cgroup
[[ $(stat -f -c %T /run/honk-cgroup) == cgroup2fs ]] || fail 'requires guest cgroup2'
work=$(mktemp -d "${HONK_XDP_ARTIFACT_ROOT:-/tmp}/honk-xdp-daemon.XXXXXX")
printf 'XDP smoke artifacts: %s\n' "$work"
printf 'monotonic_seconds\tprofile\tphase\n%s\tsetup\tbegin\n' "$smoke_started" >"$work/phases.tsv"
mark_phase() {
    local uptime idle
    read -r uptime idle </proc/uptime
    printf '%s\t%s\t%s\n' "$uptime" "$1" "$2" >>"$work/phases.tsv"
}
check_kernel_recovery() {
    python3 - <<'PY'
import select, subprocess, sys
server = r'''
import socket, sys
family, kind = map(int, sys.argv[1:3])
with socket.socket(family, kind) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(10)
    sock.bind((sys.argv[3], 18091))
    if kind == socket.SOCK_STREAM:
        sock.listen(1)
    print('READY', flush=True)
    if kind == socket.SOCK_STREAM:
        conn, _ = sock.accept()
        with conn:
            conn.settimeout(10)
            payload = b''
            while len(payload) < len(b'fresh-kernel-connection'):
                part = conn.recv(128)
                assert part, 'kernel recovery TCP request ended early'
                payload += part
            conn.sendall(payload)
    else:
        payload, peer = sock.recvfrom(128)
        sock.sendto(payload, peer)
'''
client = r'''
import socket, sys
family, kind = map(int, sys.argv[1:3])
with socket.socket(family, kind) as sock:
    sock.settimeout(10)
    sock.bind((sys.argv[3], 0))
    sock.connect((sys.argv[4], 18091))
    sock.sendall(b'fresh-kernel-connection')
    payload = b''
    while len(payload) < len(b'fresh-kernel-connection'):
        part = sock.recv(128)
        assert part, 'kernel recovery reply ended early'
        payload += part
    assert payload == b'fresh-kernel-connection'
'''
for family, source, destination in [(2, '192.0.2.2', '198.51.100.2'), (10, 'fd00:1::2', 'fd00:2::2')]:
    for kind in (1, 2):
        peer = subprocess.Popen(['ip', 'netns', 'exec', 'server', sys.executable, '-c', server, str(family), str(kind), destination], stdout=subprocess.PIPE, text=True)
        try:
            assert select.select([peer.stdout], [], [], 5)[0], 'kernel recovery server readiness deadline'
            assert peer.stdout.readline().strip() == 'READY'
            subprocess.run(['ip', 'netns', 'exec', 'client', sys.executable, '-c', client, str(family), str(kind), source, destination], check=True, timeout=15)
            assert peer.wait(timeout=5) == 0
            print('kernel new connection:', family, kind, 'PASS', flush=True)
        finally:
            if peer.poll() is None:
                peer.kill()
                peer.wait()
PY
}

mkdir "$work/bpf"
mount -t bpf bpf "$work/bpf"
[[ $(stat -f -c %T "$work/bpf") == bpf_fs ]] || fail 'requires bpffs'
export HONK_XDP_PIN_ROOT="$work/bpf"
server_pid= daemon_pid=
adaptive_active=false
namespaces=()
stop_sources() {
    if [[ -n $server_pid ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
        server_pid=
    fi
    # Quiesce producers before fixture namespace teardown.
    for ns in client server; do
        ip -n "$ns" link set lo down 2>/dev/null || true
    done
    ip -n client link set c0 down 2>/dev/null || true
    ip -n client link set ca down 2>/dev/null || true
    ip -n server link set s0 down 2>/dev/null || true
    ip -n server link set su down 2>/dev/null || true
}
retain_custody() {
    python3 - <<'PY'
import os, signal
held = [os.open('/proc/thread-self/ns/mnt', os.O_RDONLY)]
for name in os.listdir('/run/netns'):
    held.append(os.open('/run/netns/' + name, os.O_RDONLY))
print('unresolved fixture ownership retained until VM teardown', flush=True)
while True:
    signal.pause()
PY
}

cleanup() {
    status=$?
    trap - EXIT
    mark_phase cleanup "begin-status-$status"
    stop_sources
    if [[ $adaptive_active == true && ! -f $work/adaptive-runtime.joined ]]; then
        # Unresolved ownership cannot authorize namespace/pin teardown. This
        # guest-only custodian retains private mount/nsfs/bpffs until VM teardown.
        custody=adaptive
        retain_custody </dev/null >"$work/$custody-custodian.log" 2>&1 &
        printf '%s\n' "$!" >"$work/$custody-custodian.pid"
        printf 'Retaining unresolved %s ownership: %s (exit %s)\n' "$custody" "$work" "$status" >&2
        [[ $status != 0 ]] || status=1
        cp -a /run/honk-xdp-state "$work/state" 2>/dev/null || true
        cp -a /run/honk-tc-state "$work/tc-state" 2>/dev/null || true
        exit "$status"
    fi
    ip netns exec dut nft -j list ruleset >"$work/final.nft.json" 2>"$work/final.nft.stderr" || true
    ip -n dut -j -d link show >"$work/final.links.json" 2>"$work/final.links.stderr" || true
    if [[ -n $daemon_pid ]]; then
        kill -TERM "$daemon_pid" 2>/dev/null || true
        timeout 20s tail --pid="$daemon_pid" -f /dev/null 2>/dev/null || kill -KILL "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
    fi
    # Remove only this smoke's private pins, after ingress is down.
    find "$work/bpf" -type f -delete
    for ns in "${namespaces[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
    umount "$work/bpf" || true
    cp -a /run/honk-xdp-state "$work/state" || status=1
    cp -a /run/honk-tc-state "$work/tc-state" || status=1
    umount /run/honk-cgroup || true
    mark_phase cleanup "complete-status-$status"
    printf 'Artifacts retained: %s (exit %s)\n' "$work" "$status"
    exit "$status"
}
trap cleanup EXIT
for ns in dut client server; do
    ip netns add "$ns"
    namespaces+=("$ns")
    [[ $(ip netns exec "$ns" stat -Lc %i /proc/self/ns/net) != "$current_netns" ]] || fail 'netns isolation failed'
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.addr_gen_mode=1
    ip netns exec "$ns" sysctl -qw net.ipv6.auto_flowlabels=0
    ip -n "$ns" link set lo up
done
ip -n dut link add dut0 numrxqueues 2 numtxqueues 2 type veth peer name c0 numrxqueues 2 numtxqueues 2 netns client
ip -n dut link add dut1 numrxqueues 2 numtxqueues 2 type veth peer name s0 numrxqueues 2 numtxqueues 2 netns server
ip -n dut link add name up type veth peer name su netns server
for spec in 'dut dut0' 'dut dut1' 'dut up' 'client c0' 'server s0' 'server su'; do
    read -r ns dev <<<"$spec"
    ip -n "$ns" link set dev "$dev" mtu 1500 addrgenmode none
    ip netns exec "$ns" ethtool -K "$dev" rx off tx off tso off gso off gro off rxvlan off rx-vlan-stag-hw-parse off tx-vlan-offload off tx-vlan-stag-hw-insert off
    ip -n "$ns" link set dev "$dev" up
done
ip -n dut link set dut0 address 02:00:00:00:00:10
ip -n dut link set dut1 address 02:00:00:00:00:11
ip -n client link set c0 address 02:00:00:00:00:20
ip -n server link set s0 address 02:00:00:00:00:21
provision_routes() {
    local client_dev=$1 server_dev=$2 lan_dev=$3 wan_dev=$4 family client server gateway
    ip -n client addr replace 192.0.2.2/32 dev "$client_dev"
    ip -n client -6 addr replace fd00:1::2/128 dev "$client_dev" nodad
    ip -n server addr replace 198.51.100.2/32 dev "$server_dev"
    ip -n server -6 addr replace fd00:2::2/128 dev "$server_dev" nodad
    ip -n dut addr replace 10.77.0.1/24 brd + dev up
    ip -n dut -6 addr replace fd00:77::1/64 dev up nodad
    # Kernel NUD probes on the ordinary uplink need a link-local source after idle.
    ip -n dut -6 addr replace fe80::1/64 dev up nodad
    ip -n server addr replace 10.77.0.2/24 dev su
    ip -n server -6 addr replace fd00:77::2/64 dev su nodad
    ip -n server -6 addr replace fe80::2/64 dev su nodad
    ip -n dut addr replace 203.0.113.1/32 dev lo scope global
    ip -n client route replace 198.51.100.99/32 dev "$client_dev"
    ip -n client neigh replace 198.51.100.99 lladdr 02:00:00:00:00:10 nud permanent dev "$client_dev"
    ip -n server route replace 203.0.113.1/32 dev "$server_dev"
    ip -n server neigh replace 203.0.113.1 lladdr 02:00:00:00:00:11 nud permanent dev "$server_dev"
    for family in -4 -6; do
        if [[ $family == -4 ]]; then
            client=192.0.2.2 server=198.51.100.2 gateway=10.77.0.2
        else
            client=fd00:1::2 server=fd00:2::2 gateway=fd00:77::2
        fi
        ip -n client "$family" route replace "$server" dev "$client_dev"
        ip -n client "$family" neigh replace "$server" lladdr 02:00:00:00:00:10 nud permanent dev "$client_dev"
        ip -n server "$family" route replace "$client" dev "$server_dev"
        ip -n server "$family" neigh replace "$client" lladdr 02:00:00:00:00:11 nud permanent dev "$server_dev"
        ip -n dut "$family" route replace "$client" dev "$lan_dev"
        ip -n dut "$family" route replace "$server" dev "$wan_dev"
        ip -n dut "$family" neigh replace "$client" lladdr 02:00:00:00:00:20 nud permanent dev "$lan_dev"
        ip -n dut "$family" neigh replace "$server" lladdr 02:00:00:00:00:21 nud permanent dev "$wan_dev"
        ip -n dut "$family" route replace table 100 default via "$gateway" dev up
    done
    ip -n dut route replace 198.51.100.2/32 dev "$wan_dev" src 203.0.113.1
}
provision_routes c0 s0 dut0 dut1
for family in -4 -6; do
    ip -n dut "$family" rule add pref 100 fwmark 0x100/0xffffffff lookup 100
done
ip netns exec dut sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
ip netns exec dut sysctl -qw net.ipv4.ip_early_demux=0 net.ipv4.conf.all.accept_source_route=1 net.ipv4.conf.dut0.accept_source_route=1
ip -n dut -j -d link show >"$work/topology.links.json"
ip -n dut -j address show >"$work/topology.addresses.json"
for family in -4 -6; do
    ip -n dut "$family" -j rule show >"$work/topology.$family.rules.json"
    ip -n dut "$family" -j route show table all >"$work/topology.$family.routes.json"
done

mark_phase setup topology-ready
ip netns exec dut sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
mark_phase native-baseline begin
python3 "$HONK_XDP_PROBE" native-baseline | tee "$work/native-baseline.log"
mark_phase native-baseline complete
ip netns exec dut sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 net.ipv4.ip_early_demux=0 net.ipv4.conf.all.accept_source_route=1 net.ipv4.conf.dut0.accept_source_route=1
ip netns exec dut nft add table inet honk_smoke_native
ip netns exec dut nft 'add chain inet honk_smoke_native forward { type filter hook forward priority -300; policy accept; }'

cat >"$work/check.py" <<'PY'
import json, os, pathlib, subprocess, sys
mode = sys.argv[1]
def command(*args):
    return subprocess.check_output(args, text=True)
links = json.loads(command('ip', '-j', '-d', 'link', 'show'))
if mode == 'tc':
    assert any(link['ifname'] == 'dae0' for link in links), 'default TC did not create dae0'
    assert pathlib.Path('/run/netns/daens').exists(), 'default TC did not create daens'
    assert not any(link.get('xdp', {}).get('prog', {}).get('id', 0) or link.get('xdp', {}).get('prog_id', 0) for link in links), 'default TC installed XDP'
    print('kernel contract: omitted datapath uses real TC', flush=True)
    sys.exit(0)
assert not any(x['ifname'].startswith('dae0') or x.get('linkinfo', {}).get('info_kind') == 'tun' for x in links), links
assert not pathlib.Path('/run/netns/daens').exists(), 'legacy daens created'
assert 'queue' not in command('nft', 'list', 'ruleset'), 'NFQUEUE rules created'
queue = pathlib.Path('/proc/net/netfilter/nfnetlink_queue')
assert not queue.exists() or not queue.read_text().strip(), 'NFQUEUE bound'
captured = ('dut0',) if mode == 'tcp-2' else ('dut0', 'dut1')
for link in links:
    dev = link['ifname']
    if dev not in captured and mode != 'absent':
        subprocess.run([sys.executable, os.environ['HONK_XDP_PROBE'], 'xdp-absent', dev], check=True)
    if mode == 'absent':
        subprocess.run([sys.executable, os.environ['HONK_XDP_PROBE'], 'xdp-absent', dev], check=True)
    assert not any(q['kind'] in ('clsact', 'ingress') for q in json.loads(command('tc', '-j', 'qdisc', 'show', 'dev', dev))), dev
    for direction in ('ingress', 'egress'):
        assert not json.loads(command('tc', '-j', 'filter', 'show', 'dev', dev, direction)), dev
    if dev in ('dut0', 'dut1'):
        assert not json.loads(command('ip', '-j', 'addr', 'show', 'dev', dev))[0]['addr_info'], 'captured port is numbered'
        if mode == 'tcp-1' or (mode == 'absent' and sys.argv[2:] == ['1q']):
            assert len(list(pathlib.Path(f'/sys/class/net/{dev}/queues').glob('rx-*'))) == 1, link
        else:
            assert link['num_rx_queues'] == 2, link
        xdp = link.get('xdp', {})
        program_id = xdp.get('prog', {}).get('id', 0) or xdp.get('prog_id', 0)
        if mode != 'absent' and dev in captured:
            assert program_id, xdp
            role = 'data' if mode in ('tcp-1', 'tcp-2') else mode
            identity = [sys.executable, os.environ['HONK_XDP_PROBE'], 'identity', dev, role]
            subprocess.run(identity, check=True)
print('kernel contract:', mode, flush=True)
if mode == 'data':
    rules = json.loads(command('nft', '-j', 'list', 'chain', 'inet', 'honk_smoke_native', 'forward'))['nftables']
    expressions = [item['rule']['expr'] for item in rules if 'rule' in item]
    assert len(expressions) == 1 and expressions[0][-1] == {'drop': None}, expressions
    counter = next(item['counter'] for item in expressions[0] if 'counter' in item)
    expected = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    assert counter['packets'] == expected, ('unexpected native forwarding during consumer proof', expected, counter)
    print('independent native-forward fence:', counter, flush=True)
PY
run_dns_shadow_tests() {
    local binary=$1 suite=$2 test
    shift 2
    [[ $binary == /* && -x $binary ]] || fail "invalid DNS shadow $suite executable"
    for test in "$@"; do
        [[ $(ip netns exec dut "$binary" "$test" --exact --ignored --list --format terse) == "$test: test" ]] || fail "missing ignored DNS shadow regression: $test"
        local output="$work/dns-shadow-$suite/${test##*::}"
        mkdir -p "$output"
        timeout -k 5 180 ip netns exec dut env HONK_XDP_ARTIFACT_ROOT="$output" \
            "$binary" "$test" --exact --ignored --test-threads=1 --nocapture 2>&1 | tee "$output/result.log"
        [[ $(grep -c '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured;' "$output/result.log") == 1 ]] || fail "missing exact DNS shadow test result: $test"
    done
}

# The marked Endpoint sockets use table 100 and reach server/su. Original
# kernel-forwarded tuples use the main routes and reach shadow-wan/s0.
prepare_dns_tcp_wire() {
    local address
    for address in 198.51.100.2 198.51.100.4 198.51.100.6; do
        ip -n shadow-wan addr add "$address/32" dev s0
        ip -n dut neigh replace "$address" lladdr 02:00:00:00:00:21 nud permanent dev dut1
    done
    ip -n shadow-wan -6 addr add fd00:2::2/128 dev s0 nodad
    ip -n shadow-wan route add 192.0.2.2/32 dev s0
    ip -n shadow-wan neigh add 192.0.2.2 lladdr 02:00:00:00:00:11 nud permanent dev s0
    ip -n shadow-wan -6 route add fd00:1::2/128 dev s0
    ip -n shadow-wan -6 neigh add fd00:1::2 lladdr 02:00:00:00:00:11 nud permanent dev s0
    ip -n server addr add 198.51.100.99/32 dev lo
    ip netns exec dut nft -f - <<'NFT'
table inet honk_dns_tcp_wire {
    counter syn {}
    counter synack {}
    chain outbound {
        tcp sport 44000-44399 tcp dport { 53, 18154 } ct state new tcp flags & (syn | ack) == syn counter name syn
    }
    chain inbound {
        tcp dport 44000-44399 tcp sport { 53, 18154 } ct state established tcp flags & (syn | ack) == (syn | ack) counter name synack
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        iifname "dut0" oifname "dut1" ip saddr 192.0.2.2 ip daddr { 198.51.100.2, 198.51.100.4, 198.51.100.6 } jump outbound
        iifname "dut0" oifname "dut1" ip6 saddr fd00:1::2 ip6 daddr fd00:2::2 jump outbound
        iifname "dut1" oifname "dut0" ip daddr 192.0.2.2 ip saddr { 198.51.100.2, 198.51.100.4, 198.51.100.6 } jump inbound
        iifname "dut1" oifname "dut0" ip6 daddr fd00:1::2 ip6 saddr fd00:2::2 jump inbound
    }
}
NFT
}

dns_wire_channels() {
    local member ns dev
    for member in 'dut dut0' 'dut dut1' 'client c0' 'shadow-wan s0'; do
        read -r ns dev <<<"$member"
        ip netns exec "$ns" ethtool -L "$dev" rx "$1" tx "$1"
    done
}

run_dns_shadow_wire() {
    local old_namespace_count=${#namespaces[@]} ready profile dns_switch attempt address
    local workers wan cache_switch
    local proof="$work/dns-shadow-wire"
    mkdir "$proof"
    # Keep the real WAN ingress and put the independent echo peer behind the normal uplink.
    ip netns add shadow-wan
    namespaces+=(shadow-wan)
    ip -n server link set s0 netns shadow-wan
    ip -n shadow-wan link set lo up
    ip -n shadow-wan link set s0 addrgenmode none up
    ip -n shadow-wan -4 addr flush dev s0 scope global
    ip -n shadow-wan -6 addr flush dev s0 scope global
    ip -n shadow-wan addr add 198.51.100.3/32 dev s0
    ip -n dut route replace 198.51.100.3/32 dev dut1
    ip -n dut neigh replace 198.51.100.3 lladdr 02:00:00:00:00:21 nud permanent dev dut1
    for address in 198.51.100.2 198.51.100.99; do
        ip -n shadow-wan route replace "$address/32" dev s0
        ip -n shadow-wan neigh replace "$address" lladdr 02:00:00:00:00:11 nud permanent dev s0
    done
    for address in 198.51.100.4 198.51.100.6; do
        ip -n client route replace "$address/32" dev c0
        ip -n client neigh replace "$address" lladdr 02:00:00:00:00:10 nud permanent dev c0
        ip -n dut route replace "$address/32" dev dut1
    done
    ip -n dut route replace 198.51.100.99/32 dev dut1
    ip -n server addr add 198.51.100.2/32 dev lo
    ip -n server addr add 198.51.100.4/32 dev lo
    ip -n server addr add 198.51.100.6/32 dev lo
    ip -n server -6 addr add fd00:2::2/128 dev lo nodad

    for profile in static shadow tcp-static-1 tcp-dns-1 tcp-static-2 tcp-dns-2; do
        dns_switch= cache_switch= workers=1 wan='dut1: wan'
        case $profile in static|tcp-static-*) dns_switch='dns_projection: false';; esac
        if [[ $profile == tcp-* ]]; then
            workers=${profile##*-}
            cache_switch='optimistic_cache: false'
            if [[ $profile == tcp-static-1 ]]; then prepare_dns_tcp_wire; fi
            if [[ $workers == 1 ]]; then
                dns_wire_channels 1
            else
                wan=
                ip netns exec client tc qdisc add dev c0 root mqprio num_tc 2 map 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 queues 1@0 1@1 hw 0
            fi
        fi
        mkdir -m 700 "/run/honk-xdp-state/dns-$profile"
        cat >"$proof/$profile.dae" <<EOF
global {
    dial_mode: domain+
    nfqueue_enable: false
    so_mark_from_dae: 0x100
    data_dir: '/run/honk-xdp-state/dns-$profile'
    tcp_check_url: 'http://127.0.0.1:1/'
    udp_check_dns: '127.0.0.1:9'
}
dns {
    bind: ''
    optimistic_cache_ttl: 0
    $cache_switch
    upstream { default: 'udp://10.77.0.2:15353' }
}
datapath {
    backend: xdp
    direct: endpoint
    xsk_mode: copy
    workers: $workers
    $dns_switch
    interface {
        dut0: lan
        $wan
    }
}
routing {
    dip(198.51.100.6/32) && dport(53) -> direct(must)
    domain(suffix: pass-shadow.test) -> direct(must)
    fallback: direct
}
EOF
        if [[ $profile != tcp-* ]]; then
            ip netns exec dut nft add rule inet honk_smoke_native forward counter drop
        fi
        mark_phase "dns-$profile" readiness-begin
        ip netns exec dut "$daemon" -c "$proof/$profile.dae" --bpf-pin-root "$work/bpf" >"$proof/$profile.daemon.log" 2>&1 &
        daemon_pid=$!
        ready=false
        for ((attempt=0; attempt<200; attempt++)); do
            kill -0 "$daemon_pid" 2>/dev/null || fail "DNS shadow $profile daemon exited; see $proof/$profile.daemon.log"
            if grep -q 'XDP datapath ready' "$proof/$profile.daemon.log"; then ready=true; break; fi
            sleep 0.1
        done
        [[ $ready == true ]] || fail "DNS shadow $profile readiness deadline"
        if [[ $profile == tcp-* ]]; then
            ip netns exec dut python3 "$work/check.py" "tcp-$workers"
            timeout -k 5 120 python3 "$HONK_XDP_DNS_PROBE" tcp-wire "$profile" "$daemon_pid" "$proof/$profile.daemon.log" | tee "$proof/$profile.jsonl"
            ip netns exec dut python3 "$work/check.py" "tcp-$workers"
            ip netns exec dut nft -j list table inet honk_dns_tcp_wire >"$proof/$profile.native-forward.json"
        else
            ip netns exec dut python3 "$work/check.py" data
            timeout -k 5 120 python3 "$HONK_XDP_DNS_PROBE" wire "$profile" | tee "$proof/$profile.jsonl"
            ip netns exec dut python3 "$work/check.py" data 1
            ip netns exec dut nft -j list chain inet honk_smoke_native forward >"$proof/$profile.native-fence.json"
        fi
        kill -TERM "$daemon_pid"
        timeout 20s tail --pid="$daemon_pid" -f /dev/null || fail "DNS shadow $profile shutdown deadline"
        wait "$daemon_pid"
        daemon_pid=
        if [[ $profile == tcp-*-1 ]]; then
            ip netns exec dut python3 "$work/check.py" absent 1q
            dns_wire_channels 2
        else
            ip netns exec dut python3 "$work/check.py" absent
            if [[ $profile == tcp-*-2 ]]; then ip netns exec client tc qdisc del dev c0 root; fi
        fi
        [[ -z $(find "$work/bpf" -type f -print -quit) ]] || fail 'DNS shadow left persistent physical pins'
        ip netns exec dut nft flush chain inet honk_smoke_native forward
        mark_phase "dns-$profile" detached
    done
    python3 "$HONK_XDP_DNS_PROBE" compare "$proof/static.jsonl" "$proof/shadow.jsonl" | tee "$proof/result.json"
    for workers in 1 2; do
        python3 "$HONK_XDP_DNS_PROBE" tcp-compare "$proof/tcp-static-$workers.jsonl" "$proof/tcp-dns-$workers.jsonl" | tee "$proof/tcp-$workers.result.json"
    done

    ip netns exec dut nft delete table inet honk_dns_tcp_wire
    ip -n server addr del 198.51.100.99/32 dev lo
    for address in 198.51.100.4 198.51.100.6; do ip -n dut neigh del "$address" dev dut1; done
    ip -n shadow-wan -6 neigh del fd00:1::2 dev s0
    ip -n shadow-wan -6 route del fd00:1::2/128 dev s0
    ip -n shadow-wan -6 addr del fd00:2::2/128 dev s0
    ip -n shadow-wan neigh del 192.0.2.2 dev s0
    ip -n shadow-wan route del 192.0.2.2/32 dev s0
    ip -n shadow-wan -4 addr flush dev s0 scope global
    ip -n shadow-wan link set s0 netns server
    ip -n server link set s0 up
    ip netns del shadow-wan
    namespaces=("${namespaces[@]:0:old_namespace_count}")
    ip -n server addr del 198.51.100.2/32 dev lo
    ip -n server addr del 198.51.100.4/32 dev lo
    ip -n server addr del 198.51.100.6/32 dev lo
    ip -n server -6 addr del fd00:2::2/128 dev lo
    for address in 198.51.100.4 198.51.100.6; do
        ip -n client route del "$address/32" dev c0
        ip -n client neigh del "$address" dev c0
        ip -n dut route del "$address/32" dev dut1
    done
    ip -n dut neigh del 198.51.100.3 dev dut1
    ip -n dut route del 198.51.100.3/32 dev dut1
    ip -n dut route del 198.51.100.99/32 dev dut1
    provision_routes c0 s0 dut0 dut1
}

if [[ -n ${HONK_XDP_CORE_TEST_BIN:-} ]]; then
    modprobe nf_conntrack
    command -v objdump >/dev/null || fail 'native GNU objdump is required for the actual kernel JIT'
    generated_test=generated_dns_shadow_policy_verifies_and_jits
    run_dns_shadow_tests "$HONK_XDP_CORE_TEST_BIN" core \
        "xdp::tests::driven_kernel::gateway::dns::$generated_test" \
        dns::projection::tests::scoped::kernel_gateway_dns_canonical_publication \
        xdp::tests::driven_kernel::gateway::dns_reload::shadow_hosts_reload_keeps_kernel_bank_and_rebinds_generation \
        xdp::tests::driven_kernel::gateway::dns_reload::shadow_staged_rollback_retires_memory_and_reopens_fresh_epoch \
        xdp::tests::driven_kernel::gateway::dns_reload::native_pending_survives_static_downshift_until_idle_retirement \
        xdp::tests::driven_kernel::gateway::dns_reload::shadow_late_gateway_registration_waits_for_final_flags \
        xdp::tests::driven_kernel::gateway::dns_reload::shadow_optional_preparation_retains_complete_static_policy \
        xdp::tests::driven_kernel::gateway::dns_reload::shadow_committed_degraded_closes_kernel_bank
    proof_dir="$work/dns-shadow-core/$generated_test"
    python3 "$HONK_XDP_DNS_PROBE" budget "$proof_dir/result.log" | tee "$proof_dir/verifier.json"
fi
if [[ -n ${HONK_XDP_XSK_TEST_BIN:-} ]]; then
    run_dns_shadow_tests "$HONK_XDP_XSK_TEST_BIN" xsk \
        bpf::general::tests::gateway::kernel_gateway_dns_shadow_counts_only_authorized_data_and_keeps_xsk_fragment \
        bpf::general::tests::gateway::kernel_gateway_dns_shadow_concurrent_epoch_reuse \
        bpf::general::tests::gateway::ownership::kernel_gateway_tcp_dns_ownership \
        bpf::general::tests::gateway::ownership::kernel_gateway_tcp_dns_two_producers \
        bpf::gateway::tests::kernel_hold_sweep_native_reuse_guard_and_single_refund \
        bpf::gateway::tests::kernel_hold_sweep_rechecks_activity_and_releases_guard_on_refund_error \
        bpf::gateway::tests::kernel_hold_sweep_full_guard_reports_error_without_evicting_other_keys \
        bpf::gateway::tests::kernel_gateway_dns_maps_pressure_epoch_stride_and_reclaim_lookahead
fi
if [[ $smoke_scope != runtime ]]; then
    run_dns_shadow_wire
fi
if [[ $smoke_scope == dns-shadow ]]; then
    exit 0
fi

if [[ -n ${HONK_XDP_XSK_TEST_BIN:-} ]]; then
    [[ $HONK_XDP_XSK_TEST_BIN == /* && -x $HONK_XDP_XSK_TEST_BIN ]] || fail 'invalid XSK test executable'
    for test in \
        bpf::general::tests::kernel_group_unicast_cannot_borrow_connected_socket_exemption \
        bpf::general::tests::kernel_native_destinations_and_metadata_counter_are_distinct \
        bpf::general::tests::kernel_legacy_capture_keeps_rejection_counters_and_xsk_miss_closed \
        bpf::general::tests::gateway::kernel_gateway_g17_tcp_non_syn_miss_and_monotonic_hold_refresh \
        bpf::general::tests::gateway::kernel_gateway_local_then_hold_then_real_conntrack_and_reverse_quote \
        bpf::general::tests::gateway::kernel_gateway_g12_ihl_and_required_prefix_test_run_not_physical_sg \
        bpf::general::tests::gateway::kernel_gateway_fragment_verdict_ttl_and_post_hold_late_fragment \
        bpf::general::tests::gateway::kernel_gateway_g12_ipv6_fragment_then_destination_options_and_extension_bounds \
        bpf::general::tests::gateway::kernel_gateway_canonical_call_input_and_runtime_rule_permission \
        bpf::general::tests::gateway::kernel_gateway_reload_preserves_xsk_and_counter_map_identity \
        bpf::general::tests::gateway::kernel_gateway_vlan_realm_masks_pcp_dei_and_rejects_unknown_vid \
        bpf::general::tests::gateway::kernel_gateway_local_dns_exception_and_full_hold_drop \
        bpf::general::tests::gateway::kernel_gateway_g02_non_transport_quotes_pass \
        bpf::general::tests::gateway::kernel_gateway_g02_dnat_reverse_quote_ct_alias_miss_selects_xsk \
        bpf::general::tests::gateway::kernel_gateway_g17_production_capacity_hold_full_drops_before_xsk \
        bpf::gateway::tests::kernel_gateway_g17_sweep_strict_idle_boundary_and_retention_callback \
        bpf::gateway::tests::kernel_hold_sweep_retains_output_and_reread_changes \
        bpf::gateway::tests::kernel_gateway_lookup_errors_sum_possible_cpu_values \
        bpf::gateway::tests::kernel_hold_sweep_bounds_turn_and_preserves_cursor \
        bpf::attachment::tests::kernel_owned_links_replace_foreign_rejection_and_queue_failure_unwind \
        bpf::attachment::tests::kernel_owned_link_sigkill_detaches_without_pins; do
        [[ $(ip netns exec dut "$HONK_XDP_XSK_TEST_BIN" "$test" --exact --ignored --list --format terse) == "$test: test" ]] || fail "missing ignored XSK regression: $test"
    done
    ip netns exec dut "$HONK_XDP_XSK_TEST_BIN" bpf::general::tests::kernel_ --ignored --test-threads=1 --nocapture | tee "$work/xsk-kernel.log"
    for prefix in bpf::general::tests::gateway::kernel_ bpf::gateway::tests::kernel_ bpf::attachment::tests::kernel_owned_; do
        ip netns exec dut "$HONK_XDP_XSK_TEST_BIN" "$prefix" --skip kernel_gateway_dns_ --ignored --test-threads=1 --nocapture | tee "$work/${prefix//::/-}.log"
    done
    vlan_test=device::features::kernel_vlan_tests::kernel_vlan_no_upper_normal_failure_and_sigkill_boundaries
    [[ $(ip netns exec dut "$HONK_XDP_XSK_TEST_BIN" "$vlan_test" --exact --ignored --list --format terse) == "$vlan_test: test" ]] || fail "missing ignored XSK regression: $vlan_test"
    ip -n dut link add honkvlan0 type veth peer name honkvlan1
    vlan_features=$(ip netns exec dut ethtool -k honkvlan0)
    if printf '%s\n' "$vlan_features" | awk '
        /(rx-vlan-hw-parse|rx-vlan-offload):/ { ctag = ($2 == "on" && $0 !~ /\[fixed\]/) }
        /rx-vlan-stag-hw-parse:/ { stag = ($2 == "on" && $0 !~ /\[fixed\]/) }
        END { exit !(ctag && stag) }
    '; then
        ip netns exec dut env HONK_XDP_VLAN_TEST_DEVICE=honkvlan0 "$HONK_XDP_XSK_TEST_BIN" "$vlan_test" --exact --ignored --test-threads=1 --nocapture | tee "$work/vlan-offload.log"
    else
        printf '%s\n' 'NOT_RUN: vlan offload bits not writable on veth'
    fi
    ip -n dut link delete honkvlan0
fi
if [[ -n ${HONK_XDP_CORE_TEST_BIN:-} ]]; then
    [[ $HONK_XDP_CORE_TEST_BIN == /* && -x $HONK_XDP_CORE_TEST_BIN ]] || fail 'invalid Core test executable'
    modprobe nf_conntrack
    ip -n dut route replace 198.51.100.99/32 dev dut1 src 203.0.113.1
    ip -n dut -6 route replace fd00:2::99/128 dev dut1 src fd00:77::1
    ip -n dut route replace 192.0.2.2/32 dev dut0 src 203.0.113.1
    ip -n dut -6 route replace fd00:1::2/128 dev dut0 src fd00:77::1
    ip -n dut route replace 192.0.2.99/32 dev dut0 src 203.0.113.1
    ip -n dut -6 route replace fd00:1::99/128 dev dut0 src fd00:77::1
    ip -n dut route replace prohibit 198.51.100.98/32
    ip -n dut -6 route replace prohibit fd00:2::98/128
    driven_test=xdp::tests::driven_kernel::policy_publication_keeps_real_endpoint_app_timer_and_close_owned
    multiqueue_test=xdp::tests::driven_kernel::two_worker_publication_keeps_real_endpoint_app_timer_and_close_owned
    adaptive_test=xdp::tests::driven_kernel::adaptive::actual_owner_clock_budget_fairness_and_live_features
    detach_test=xdp::tests::driven_kernel::gateway::gateway_close_detaches_links_after_backend_unregister_timeout
    full_gateway_test=xdp::gateway::policy::tests::kernel_gateway_full_program_adaptive_endpoint_verifies_and_preserves_packets
    for test in \
        control::core_forward::tests::firewall_capacity_refusal_keeps_packet_owner_alive \
        control::core_forward::tests::unresolved_forward_neighbor_does_not_delay_transit_errors \
        control::core_forward::tests::generated_reassembly_error_keeps_scoped_nat_and_funding_through_completion \
        control::core_forward::tests::plain_output_history_survives_first_nat_enable_and_cq_owners \
        control::core_forward::tests::unbound_native_quote_cannot_authorize_a_reused_nat_identity \
        "$full_gateway_test" "$detach_test" "$driven_test" "$multiqueue_test" "$adaptive_test"; do
        [[ $(ip netns exec dut "$HONK_XDP_CORE_TEST_BIN" "$test" --exact --ignored --list --format terse) == "$test: test" ]] || fail "missing ignored Core regression: $test"
    done
    ip netns exec dut "$HONK_XDP_CORE_TEST_BIN" "$full_gateway_test" --exact --ignored --test-threads=1 --nocapture | tee "$work/gateway-full-program.log"
    mkdir "$work/detach-timeout"
    ip netns exec dut env HONK_XDP_ARTIFACT_ROOT="$work/detach-timeout" "$HONK_XDP_CORE_TEST_BIN" "$detach_test" --exact --ignored --test-threads=1 --nocapture | tee "$work/detach-timeout/result.log"
    for name in quiet_gateway_detects_revoked_link quiet_core_detects_revoked_link_with_a_blocked_reader; do
        test="xdp::tests::driven_kernel::gateway::$name"
        [[ $(ip netns exec dut "$HONK_XDP_CORE_TEST_BIN" "$test" --exact --ignored --list --format terse) == "$test: test" ]] || fail "missing ignored Core regression: $test"
        mkdir "$work/$name"
        timeout -k 5 40 ip netns exec dut env HONK_XDP_ARTIFACT_ROOT="$work/$name" "$HONK_XDP_CORE_TEST_BIN" "$test" --exact --ignored --test-threads=1 --nocapture | tee "$work/$name/result.log"
    done
    retention_test=xdp::tests::retention::gateway_hold_retains_real_queued_exported_and_cq_output
    [[ $(ip netns exec dut "$HONK_XDP_CORE_TEST_BIN" "$retention_test" --exact --list --format terse) == "$retention_test: test" ]] || fail "missing Core retention regression: $retention_test"
    ip netns exec dut "$HONK_XDP_CORE_TEST_BIN" "$retention_test" --exact --test-threads=1 --nocapture | tee "$work/gateway-retention.log"
    zone_test=xdp::gateway::zones::tests::kernel_gateway_zone_startup_refuses_nft_and_legacy
    [[ $(ip netns exec dut "$HONK_XDP_CORE_TEST_BIN" "$zone_test" --exact --ignored --list --format terse) == "$zone_test: test" ]] || fail "missing ignored Core regression: $zone_test"
    ip netns exec dut "$HONK_XDP_CORE_TEST_BIN" "$zone_test" --exact --ignored --test-threads=1 --nocapture | tee "$work/gateway-zone.log"
    ip netns exec dut "$HONK_XDP_CORE_TEST_BIN" control::core_forward::tests:: --ignored --test-threads=1 --nocapture | tee "$work/core-forward.log"
    ip netns exec dut nft add rule inet honk_smoke_native forward counter drop
    ip netns exec client nft add table inet honk_smoke_driven
    ip netns exec client nft 'add chain inet honk_smoke_driven prerouting { type filter hook prerouting priority -300; policy accept; }'
    ip netns exec client nft add rule inet honk_smoke_driven prerouting ip daddr 192.0.2.99 drop
    for test in "$driven_test" "$multiqueue_test"; do
        driven_work=$work
        if [[ $test == "$multiqueue_test" ]]; then
            driven_work="$work/multiqueue"
            mkdir "$driven_work"
            ip netns exec client tc qdisc add dev c0 root mqprio num_tc 2 map 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 queues 1@0 1@1 hw 0
        fi
    ip netns exec dut env HONK_XDP_ARTIFACT_ROOT="$driven_work" "$HONK_XDP_CORE_TEST_BIN" "$test" --exact --ignored --test-threads=1 --nocapture | tee "$driven_work/driven-runtime.log"
    ip netns exec dut nft -j list chain inet honk_smoke_native forward >"$driven_work/driven-runtime.native-fence.json"
    python3 - "$driven_work/driven-runtime.native-fence.json" <<'PY'
import json, pathlib, sys
items = json.loads(pathlib.Path(sys.argv[1]).read_text())['nftables']
rules = [item['rule']['expr'] for item in items if 'rule' in item]
assert len(rules) == 1 and rules[0][-1] == {'drop': None}, rules
counter = next(item['counter'] for item in rules[0] if 'counter' in item)
assert counter['packets'] == 0, ('native forwarding masked real Runtime evidence', counter)
PY
    for dev in dut0 dut1; do
        ip netns exec dut python3 "$HONK_XDP_PROBE" xdp-absent "$dev"
    done
    [[ -z $(find "$work/bpf" -type f -print -quit) ]] || fail 'driven runtime left physical program pins'
        if [[ $test == "$multiqueue_test" ]]; then
            ip netns exec client tc qdisc del dev c0 root
        fi
    done
    ip netns exec client nft delete table inet honk_smoke_driven
    ip netns exec dut nft flush chain inet honk_smoke_native forward
    ip netns exec dut python3 "$work/check.py" absent
    ip -n dut route del 198.51.100.99/32
    ip -n dut -6 route del fd00:2::99/128
    ip -n dut route del 192.0.2.99/32
    ip -n dut -6 route del fd00:1::99/128
    ip -n dut route del prohibit 198.51.100.98/32
    ip -n dut -6 route del prohibit fd00:2::98/128
    provision_routes c0 s0 dut0 dut1

    # A separate 180-second combined-consumer window; the original Event/E32
    # selection and every later daemon profile keep their original bounds.
    ip -n client -j -d link show dev c0 >"$work/adaptive-original-c0.json"
    ip -n server -j -d link show dev s0 >"$work/adaptive-original-s0.json"
    read -r original_c0_rx original_c0_tx original_s0_rx original_s0_tx < <(
        python3 -c 'import json,sys; links=[json.load(open(path))[0] for path in sys.argv[1:]]; print(*(link[key] for link in links for key in ("num_rx_queues", "num_tx_queues")))' \
            "$work/adaptive-original-c0.json" "$work/adaptive-original-s0.json"
    )
    recreate_adaptive_peers() {
        local c0_rx=$1 c0_tx=$2 s0_rx=$3 s0_tx=$4
        ip netns exec dut python3 "$work/check.py" absent
        # These exact pairs were created by this private window. No active
        # program/owner survives the preceding real join and identity checks.
        ip -n dut link del dut0
        ip -n dut link del dut1
        ip -n dut link add dut0 numrxqueues 2 numtxqueues 2 type veth peer name c0 numrxqueues "$c0_rx" numtxqueues "$c0_tx" netns client
        ip -n dut link add dut1 numrxqueues 2 numtxqueues 2 type veth peer name s0 numrxqueues "$s0_rx" numtxqueues "$s0_tx" netns server
        for spec in 'dut dut0' 'dut dut1' 'client c0' 'server s0'; do
            read -r ns dev <<<"$spec"
            ip -n "$ns" link set dev "$dev" mtu 1500 addrgenmode none
            ip netns exec "$ns" ethtool -K "$dev" rx off tx off tso off gso off gro off rxvlan off rx-vlan-stag-hw-parse off tx-vlan-offload off tx-vlan-stag-hw-insert off
            ip -n "$ns" link set dev "$dev" up
        done
        ip -n dut link set dut0 address 02:00:00:00:00:10
        ip -n dut link set dut1 address 02:00:00:00:00:11
        ip -n client link set c0 address 02:00:00:00:00:20
        ip -n server link set s0 address 02:00:00:00:00:21
        provision_routes c0 s0 dut0 dut1
    }
    recreate_adaptive_peers 2 2 2 2
    for spec in 'client c0' 'server s0'; do
        read -r ns dev <<<"$spec"
        ip netns exec "$ns" tc qdisc add dev "$dev" root mqprio num_tc 2 map 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 queues 1@0 1@1 hw 0
    done
    suffix="$BASHPID-$RANDOM"
    export HONK_XDP_ADAPTIVE_B_NS="hv7-b-$suffix"
    export HONK_XDP_ADAPTIVE_CLIENT_NS="hv7-c-$suffix"
    ip netns add "$HONK_XDP_ADAPTIVE_B_NS"
    adaptive_namespace_base=${#namespaces[@]}
    namespaces+=("$HONK_XDP_ADAPTIVE_B_NS")
    ip netns add "$HONK_XDP_ADAPTIVE_CLIENT_NS"
    namespaces+=("$HONK_XDP_ADAPTIVE_CLIENT_NS")
    export HONK_XDP_ADAPTIVE_B_INODE HONK_XDP_ADAPTIVE_CLIENT_INODE
    HONK_XDP_ADAPTIVE_B_INODE=$(stat -Lc %i "/run/netns/$HONK_XDP_ADAPTIVE_B_NS")
    HONK_XDP_ADAPTIVE_CLIENT_INODE=$(stat -Lc %i "/run/netns/$HONK_XDP_ADAPTIVE_CLIENT_NS")
    [[ $HONK_XDP_ADAPTIVE_B_INODE != "$current_netns" &&
       $HONK_XDP_ADAPTIVE_B_INODE != "$(stat -Lc %i /run/netns/dut)" &&
       $HONK_XDP_ADAPTIVE_CLIENT_INODE != "$HONK_XDP_ADAPTIVE_B_INODE" ]] || fail 'adaptive namespace identity collision'
    for ns in "$HONK_XDP_ADAPTIVE_B_NS" "$HONK_XDP_ADAPTIVE_CLIENT_NS"; do
        ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.addr_gen_mode=1
        ip -n "$ns" link set lo up
    done
    ip -n "$HONK_XDP_ADAPTIVE_B_NS" link add dut2 numrxqueues 2 numtxqueues 2 type veth peer name c1 numrxqueues 2 numtxqueues 2 netns "$HONK_XDP_ADAPTIVE_CLIENT_NS"
    ip -n "$HONK_XDP_ADAPTIVE_B_NS" link add upb type veth peer name sub netns server
    for spec in "$HONK_XDP_ADAPTIVE_B_NS dut2" "$HONK_XDP_ADAPTIVE_B_NS upb" "$HONK_XDP_ADAPTIVE_CLIENT_NS c1" 'server sub'; do
        read -r ns dev <<<"$spec"
        ip -n "$ns" link set dev "$dev" mtu 1500 addrgenmode none
        ip netns exec "$ns" ethtool -K "$dev" rx off tx off tso off gso off gro off rxvlan off rx-vlan-stag-hw-parse off tx-vlan-offload off tx-vlan-stag-hw-insert off
        ip -n "$ns" link set dev "$dev" up
    done
    ip -n "$HONK_XDP_ADAPTIVE_B_NS" link set dut2 address 02:00:00:00:00:12
    ip -n "$HONK_XDP_ADAPTIVE_CLIENT_NS" link set c1 address 02:00:00:00:00:22
    ip -n "$HONK_XDP_ADAPTIVE_CLIENT_NS" addr add 192.0.3.2/24 dev c1
    ip -n "$HONK_XDP_ADAPTIVE_CLIENT_NS" route add 198.51.100.2/32 dev c1
    ip -n "$HONK_XDP_ADAPTIVE_CLIENT_NS" neigh add 198.51.100.2 lladdr 02:00:00:00:00:12 nud permanent dev c1
    # Two actual traffic classes/queues, selected by the two real packet sockets'
    # SO_PRIORITY. The test must still observe both actual RX queue counters.
    ip netns exec "$HONK_XDP_ADAPTIVE_CLIENT_NS" tc qdisc add dev c1 root mqprio num_tc 2 map 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 queues 1@0 1@1 hw 0
    ip -n "$HONK_XDP_ADAPTIVE_B_NS" addr add 10.78.0.1/30 dev upb
    ip -n server addr add 10.78.0.2/30 dev sub
    ip -n "$HONK_XDP_ADAPTIVE_B_NS" rule add pref 100 fwmark 0x100/0xffffffff lookup 100
    ip -n "$HONK_XDP_ADAPTIVE_B_NS" route add table 100 default via 10.78.0.2 dev upb
    ip -n "$HONK_XDP_ADAPTIVE_B_NS" route add 198.51.100.2/32 via 10.78.0.2 dev upb
    ip netns exec "$HONK_XDP_ADAPTIVE_B_NS" sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
    ip -n dut route replace 192.0.2.99/32 dev dut0 src 203.0.113.1
    ip -n dut route replace 198.51.100.99/32 dev dut1 src 203.0.113.1
    ip netns exec dut nft add rule inet honk_smoke_native forward counter drop
    ip netns exec client nft add table inet honk_smoke_driven
    ip netns exec client nft 'add chain inet honk_smoke_driven prerouting { type filter hook prerouting priority -300; policy accept; }'
    ip netns exec client nft add rule inet honk_smoke_driven prerouting ip daddr 192.0.2.99 drop
    ip netns exec "$HONK_XDP_ADAPTIVE_B_NS" nft add table inet honk_smoke_native
    ip netns exec "$HONK_XDP_ADAPTIVE_B_NS" nft 'add chain inet honk_smoke_native forward { type filter hook forward priority -300; policy accept; }'
    ip netns exec "$HONK_XDP_ADAPTIVE_B_NS" nft add rule inet honk_smoke_native forward counter drop
    mkdir "$work/adaptive-bpf"
    mount -t bpf bpf "$work/adaptive-bpf"
    adaptive_active=true
    ip netns exec dut env HONK_XDP_PIN_ROOT="$work/adaptive-bpf" HONK_XDP_ARTIFACT_ROOT="$work" \
        "$HONK_XDP_CORE_TEST_BIN" "$adaptive_test" --exact --ignored --test-threads=1 --nocapture | tee "$work/adaptive-runtime.log"
    [[ -f $work/adaptive-runtime.joined ]] || fail 'adaptive owners did not all genuinely join'
    for ns in dut "$HONK_XDP_ADAPTIVE_B_NS"; do
        ip netns exec "$ns" nft -j list chain inet honk_smoke_native forward >"$work/adaptive-native-$ns.json"
    done
    python3 - "$work/adaptive-native-dut.json" "$work/adaptive-native-$HONK_XDP_ADAPTIVE_B_NS.json" <<'PY'
import json, pathlib, sys
for path in sys.argv[1:]:
    items = json.loads(pathlib.Path(path).read_text())['nftables']
    rules = [item['rule']['expr'] for item in items if 'rule' in item]
    assert len(rules) == 1 and rules[0][-1] == {'drop': None}, rules
    counter = next(item['counter'] for item in rules[0] if 'counter' in item)
    assert counter['packets'] == 0, ('native forwarding masked adaptive Runtime evidence', path, counter)
PY
    [[ -z $(find "$work/adaptive-bpf" -type f -print -quit) ]] || fail 'adaptive exact-owned pin cleanup incomplete'
    adaptive_active=false
    umount "$work/adaptive-bpf"
    rmdir "$work/adaptive-bpf"
    [[ $(stat -Lc %i "/run/netns/$HONK_XDP_ADAPTIVE_B_NS") == "$HONK_XDP_ADAPTIVE_B_INODE" &&
       $(stat -Lc %i "/run/netns/$HONK_XDP_ADAPTIVE_CLIENT_NS") == "$HONK_XDP_ADAPTIVE_CLIENT_INODE" ]] || fail 'adaptive namespace identity changed before cleanup'
    ip netns del "$HONK_XDP_ADAPTIVE_CLIENT_NS"
    ip netns del "$HONK_XDP_ADAPTIVE_B_NS"
    namespaces=("${namespaces[@]:0:adaptive_namespace_base}")
    ip netns exec client nft delete table inet honk_smoke_driven
    ip netns exec dut nft flush chain inet honk_smoke_native forward
    # The fixture's A frontier left dut0/dut1 administratively down, which flushed
    # their 192.0.2.99/198.51.100.99 routes; recreation below deletes both links.
    ip netns exec dut python3 "$work/check.py" absent
    recreate_adaptive_peers "$original_c0_rx" "$original_c0_tx" "$original_s0_rx" "$original_s0_tx"
fi
if [[ $smoke_scope == runtime ]]; then
    printf 'PASS: complete real driven Runtime tests and joined ownership cleanup.\n'
    exit 0
fi
cat >"$work/echo.py" <<'PY'
import pathlib, selectors, socket, sys
mode, ready = sys.argv[1:]
nat = mode in ('snat', 'masquerade')
selector = selectors.DefaultSelector()
for family, address in ((socket.AF_INET, '198.51.100.2'), (socket.AF_INET6, 'fd00:2::2')):
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        sock = socket.socket(family, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, 18081 if nat and family == socket.AF_INET else 18080))
        if kind == socket.SOCK_STREAM:
            sock.listen()
        selector.register(sock, selectors.EVENT_READ, (family, kind))
pathlib.Path(ready).touch()
completed = set()
while len(completed) < 4:
    for key, _ in selector.select(20):
        family, kind = key.data
        expected = ('10.77.0.1' if family == socket.AF_INET else 'fd00:77::1') if mode.startswith('endpoint') else ('192.0.2.2' if family == socket.AF_INET else 'fd00:1::2')
        if nat and family == socket.AF_INET:
            expected = '203.0.113.1'
        payload = (f'{mode}/{family}/{kind}:'.encode() + bytes(range(256)) * (32 if 'jumbo' in mode else 4))
        if kind == socket.SOCK_DGRAM:
            data, peer = key.fileobj.recvfrom(65535)
            assert peer[0] == expected, (peer, expected)
            assert data == payload, (len(data), len(payload))
            key.fileobj.sendto(data, peer)
        else:
            conn, peer = key.fileobj.accept()
            with conn:
                conn.settimeout(10)
                assert peer[0] == expected, (peer, expected)
                data = b''
                while len(data) < len(payload):
                    chunk = conn.recv(len(payload) - len(data))
                    assert chunk, 'early TCP EOF'
                    data += chunk
                assert data == payload
                conn.sendall(data)
        if nat and family == socket.AF_INET:
            first_port = 40000 if mode == 'snat' else 40004
            assert first_port <= peer[1] <= first_port + 3, peer
        completed.add((family, kind))
        print(mode, family, kind, peer, 'payload verified', flush=True)
PY
cat >"$work/client.py" <<'PY'
import contextlib, hashlib, json, os, pathlib, re, signal, socket, struct, subprocess, sys, time
mode = sys.argv[1]
def captures():
    started = time.monotonic()
    # Keep the original five-second allowance per device while batching startup.
    result = json.loads(subprocess.check_output(['ip', 'netns', 'exec', 'dut', sys.executable, os.environ['HONK_XDP_PROBE'], 'count', 'dut0', 'dut1'], text=True, timeout=10))
    print(json.dumps({'counter_readback_seconds': time.monotonic() - started, 'devices': list(result)}), flush=True)
    return result
def reload_config(text, expected):
    config, log = pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
    offset = len(log.read_text())
    config.write_text(text)
    os.kill(int(sys.argv[4]), signal.SIGHUP)
    deadline = time.monotonic() + 10
    while True:
        result = re.search(r'SIGHUP reload request \d+ (applied|rejected)', log.read_text()[offset:])
        if result:
            assert result[1] == expected, (result[0], expected)
            return
        assert time.monotonic() < deadline, 'policy reload did not acknowledge publication'
        time.sleep(0.02)
def polling_identity(log, offset=0, reason=None):
    deadline = time.monotonic() + 10
    while True:
        text = re.sub(r'\x1b\[[0-9;]*m', '', log.read_text()[offset:])
        lines = [line for line in text.splitlines() if 'XDP polling calibration identity' in line and (reason is None or reason in line)]
        if lines:
            line = lines[-1]
            values = {name: re.search(r'\b' + name + r'="([0-9a-f]{64})"', line) for name in ('executable_sha256', 'context_sha256', 'parameter_sha256')}
            if all(values.values()):
                return line, {name: match[1] for name, match in values.items()}
        assert time.monotonic() < deadline, 'missing actual Event calibration identities'
        time.sleep(0.01)

def polling_traffic(sock, payload, seconds=0.5):
    deadline = time.monotonic() + seconds
    count = 0
    while time.monotonic() < deadline:
        sock.sendall(payload)
        assert sock.recv(4096) == payload, 'adaptive probe lost real Endpoint reply progress'
        count += 1
    assert count > 2, 'no actual qualifying traffic was offered'
    return count

def polling_case(sock, payload, original, flagged):
    config, log = pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
    line, identity = polling_identity(log)
    actual = hashlib.sha256(pathlib.Path(f'/proc/{int(sys.argv[4])}/exe').read_bytes()).hexdigest()
    assert identity['executable_sha256'] == actual, 'calibration did not identify running executable'
    if flagged:
        assert 'explicit_event' in line, 'baseline did not actually remain Event'
        manifest = config.with_name('polling-preregistration.json')
        declaration = {'schema': 'honk-xdp-poll-smoke-preregistration-v1', 'identities': identity,
                       'parameters': {'pps_enter': 1, 'pps_exit': 0, 'observation_window_us': 20000,
                                      'enter_windows': 2, 'exit_windows': 1, 'max_busy_us': 1000,
                                      'empty_rounds': 2, 'budget_window_us': 10000, 'budget_us': 2000},
                       'purpose': 'real consumer correctness; not performance or energy qualification'}
        manifest.write_text(json.dumps(declaration, sort_keys=True) + '\n')
        evidence = hashlib.sha256(manifest.read_bytes()).hexdigest()
        calibration = '\ncalibration {\n schema: 1\n counting_revision: 1\n' + ''.join(f' {name}: "{value}"\n' for name, value in identity.items()) + f' status: candidate\n evidence_manifest_sha256: "{evidence}"\n}}\n'
        candidate = original.replace('poll_mode: event', 'poll_mode: adaptive', 1).replace('budget_us: 2000', 'budget_us: 2000' + calibration, 1)
        mismatch = '0' * 64 if identity['context_sha256'] != '0' * 64 else '1' * 64
        offset = len(log.read_text())
        reload_config(candidate.replace(identity['context_sha256'], mismatch), 'applied')
        reason, _ = polling_identity(log, offset, 'calibration_context_mismatch')
        assert 'calibration_context_mismatch' in reason, 'mismatched context was not actual Event'
        offset = len(log.read_text())
        reload_config(candidate, 'applied')
        polling_traffic(sock, payload)
        reload_config(candidate.replace('poll_mode: adaptive', 'poll_mode: event', 1), 'applied')
        settled, _ = polling_identity(log, offset, 'explicit_event')
        entries = re.search(r'\bbusy_entries=(\d+)', settled)
        rounds = re.search(r'\bbusy_probe_rounds=(\d+)', settled)
        assert entries and int(entries[1]) > 0, 'fully bound real candidate never entered Busy'
        assert rounds and int(rounds[1]) > 0, 'candidate had no complete actual Busy probe round'
        assert 'explicit_event' in settled, 'Event override did not reach real consumer'
        config.with_name('polling-candidate.dae').write_text(candidate)
        reload_config(original, 'applied')
        print('real Event identities, preregistered candidate, context mismatch, Busy rounds and Event reload verified', flush=True)
    else:
        assert 'calibration_candidate_not_enabled' in line, 'candidate without process opt-in was not refused'
        polling_traffic(sock, payload)
        offset = len(log.read_text())
        reload_config(original.replace('poll_mode: adaptive', 'poll_mode: event', 1), 'applied')
        settled, _ = polling_identity(log, offset, 'explicit_event')
        assert re.search(r'\bbusy_entries=0\b', settled), 'unflagged candidate entered Busy'
        print('real matching candidate remains Event without the laboratory process flag', flush=True)

two_queue = mode == 'endpoint-2q'
if two_queue:
    assert os.sched_getaffinity(0) == {0, 1}, 'expected both disposable guest CPUs'
    daemon = pathlib.Path(f'/proc/{int(sys.argv[4])}')
    worker_threads = {}
    for task in (daemon / 'task').iterdir():
        try:
            name = (task / 'comm').read_text().strip()
        except FileNotFoundError:
            continue
        if name in ('honk-xdp-0', 'honk-xdp-1'):
            assert name not in worker_threads, name
            worker_threads[name] = int(task.name)
    assert set(worker_threads) == {'honk-xdp-0', 'honk-xdp-1'}, worker_threads
    queues = [pathlib.Path(f'/sys/class/net/c0/queues/tx-{i}/xps_cpus') for i in (0, 1)]
    saved_masks = [path.read_text() for path in queues]
    for i, path in enumerate(queues):
        path.write_text(f'{1 << i:x}\n')
    masks = [int(path.read_text().replace(',', ''), 16) for path in queues]
    assert masks == [1, 2], masks
    running_sha = hashlib.sha256((daemon / 'exe').read_bytes()).hexdigest()
    pathlib.Path(sys.argv[2]).with_suffix('.workers.json').write_text(json.dumps({
        'worker_threads': worker_threads, 'daemon_sha256': running_sha, 'xps_cpu_masks': masks,
    }) + '\n')
for family, address in ((socket.AF_INET, '198.51.100.2'), (socket.AF_INET6, 'fd00:2::2')):
    if two_queue:
        rx_queue = int(family == socket.AF_INET6)
        os.sched_setaffinity(0, {rx_queue})
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        payload = f'{mode}/{family}/{kind}:'.encode() + bytes(range(256)) * (32 if 'jumbo' in mode else 4)
        before = captures() if mode != 'tc' else None
        with socket.socket(family, kind) as sock, contextlib.ExitStack() as resources:
            sock.settimeout(10)
            jumbo_trace = None
            if 'jumbo' in mode and kind == socket.SOCK_DGRAM:
                jumbo_trace = resources.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)))
                jumbo_trace.bind(('c0', 0))
                jumbo_trace.settimeout(3)
            if 'vlan' in mode:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'clis\0' if 'single' in mode else b'clic\0')
            target = '198.51.100.99' if mode in ('snat', 'masquerade') and family == socket.AF_INET else address
            sock.connect((target, 18080))
            if 'vlan' in mode and family == socket.AF_INET and kind == socket.SOCK_DGRAM:
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as trace:
                    trace.bind(('c0', 0))
                    trace.setsockopt(263, 8, 1)  # SOL_PACKET, PACKET_AUXDATA
                    trace.settimeout(5)
                    sock.sendall(payload)
                    while True:
                        packet, ancillary, _, peer = trace.recvmsg(4096, 128)
                        if peer[2] == 4 and payload in packet:
                            break
                    hidden = mode.endswith('offload')
                    tags = b'' if 'single' in mode else bytes.fromhex('8100002d')
                    expected = (b'' if hidden else bytes.fromhex('88a8007b')) + tags + bytes.fromhex('0800')
                    assert packet[12:12 + len(expected)] == expected, 'unexpected VLAN wire shape'
                    aux = next(data for level, kind, data in ancillary if (level, kind) == (263, 8))
                    status, _, _, _, _, tci, tpid = struct.unpack('=IIIHHHH', aux)
                    assert bool(status & 16) == hidden, 'hidden tag metadata disagrees with TX mode'
                    if hidden:
                        assert status & 64 and (tci, tpid) == (123, 0x88a8), 'wrong hidden outer VLAN'
            else:
                sock.sendall(payload)
            if kind == socket.SOCK_DGRAM:
                data = sock.recv(65535)
            else:
                data = b''
                while len(data) < len(payload):
                    chunk = sock.recv(4096)
                    assert chunk, 'early EOF'
                    data += chunk
            assert data == payload
            if jumbo_trace is not None:
                observed = {}
                deadline = time.monotonic() + 3
                while len(observed) < 2:
                    assert time.monotonic() < deadline, 'missing complete jumbo wire packet'
                    frame, peer = jumbo_trace.recvfrom(65535)
                    if payload not in frame or peer[2] not in (0, 4):
                        continue
                    ip = frame[14:]
                    if family == socket.AF_INET:
                        assert frame[12:14] == bytes.fromhex('0800') and ip[9] == 17
                        assert struct.unpack('!H', ip[6:8])[0] & 0x3fff == 0, 'jumbo UDP was fragmented'
                        length = struct.unpack('!H', ip[2:4])[0]
                        assert length == (ip[0] & 15) * 4 + 8 + len(payload)
                    else:
                        assert frame[12:14] == bytes.fromhex('86dd') and ip[6] == 17, 'jumbo IPv6 gained a fragment header'
                        length = 40 + struct.unpack('!H', ip[4:6])[0]
                        assert length == 40 + 8 + len(payload)
                    assert 4096 < length <= 9000, ('not a whole SG-sized packet', length)
                    observed['tx' if peer[2] == 4 else 'rx'] = length
                print(mode, family, 'complete UDP wire packets', observed, flush=True)
            if before is not None:
                after = captures()
                devices = ('dut0',) if mode.startswith('endpoint') else ('dut0', 'dut1')
                delta = {dev: sum(after[dev]) - sum(before[dev]) for dev in devices}
                assert all(value > 0 for value in delta.values()), ('flow lacks actual capture witness', mode, family, kind, delta)
                print(mode, family, kind, 'actual capture and consumer payload verified', delta, flush=True)
                if two_queue and kind == socket.SOCK_STREAM:
                    assert len(before['dut0']) == len(after['dut0']) == 2
                    captured = after['dut0'][rx_queue] - before['dut0'][rx_queue]
                    assert captured > 0, (rx_queue, before, after)
                    print(json.dumps({'two_queue_tcp': {
                        'family': 6 if family == socket.AF_INET6 else 4, 'rx_queue': rx_queue,
                        'capture_delta': captured, 'payload_sha256': hashlib.sha256(data).hexdigest(),
                        'before': before['dut0'], 'after': after['dut0'],
                    }}), flush=True)
            if mode == 'tc' and family == socket.AF_INET and kind == socket.SOCK_DGRAM:
                original = pathlib.Path(sys.argv[2]).read_text()
                for outbound in ('block', 'direct'):
                    reload_config(original.replace('fallback: direct', f'fallback: {outbound}'), 'applied')
                    with socket.socket(family, kind) as fresh:
                        fresh.settimeout(1 if outbound == 'block' else 10)
                        fresh.bind(('192.0.2.2', 41080 if outbound == 'block' else 41081))
                        fresh.connect((address, 18080))
                        fresh.sendall(payload)
                        try:
                            reply = fresh.recv(4096)
                        except socket.timeout:
                            assert outbound == 'block', 'default TC Direct did not recover after reload'
                        else:
                            assert outbound == 'direct' and reply == payload, 'default TC Block reload did not reject a new flow'
                print('omitted datapath default TC startup/traffic/Block/Direct reload verified', flush=True)
            if mode == 'endpoint' and family == socket.AF_INET and kind == socket.SOCK_DGRAM:
                original = pathlib.Path(sys.argv[2]).read_text()
                for binding, expected in [('copy', 'applied'), ('zerocopy', 'rejected'), ('', 'rejected')]:
                    candidate = original.replace('xsk_mode: copy', f'xsk_mode: {binding}' if binding else '')
                    reload_config(candidate, expected)
                    sock.sendall(payload)
                    assert sock.recv(4096) == payload, 'binding-mode reload disturbed the existing flow'
                print('explicit copy reload preserves flows; omitted and explicit zerocopy require restart', flush=True)
                polling_case(sock, payload, original, True)
            if mode == 'endpoint-candidate-unflagged' and family == socket.AF_INET and kind == socket.SOCK_DGRAM:
                polling_case(sock, payload, pathlib.Path(sys.argv[2]).read_text(), False)
            if mode == 'snat' and family == socket.AF_INET and kind == socket.SOCK_DGRAM:
                original = pathlib.Path(sys.argv[2]).read_text()
                for outbound in ('block', 'direct'):
                    reload_config(original.replace('fallback: direct', f'fallback: {outbound}'), 'applied')
                    sock.sendall(payload)
                    sock.settimeout(1 if outbound == 'block' else 10)
                    try:
                        reply = sock.recv(4096)
                    except socket.timeout:
                        assert outbound == 'block', 'restored Direct lost the retained NAT flow'
                    else:
                        assert outbound == 'direct' and reply == payload, 'retained NAT binding bypassed current Block'
                print('retained SNAT flow honors Block and restored Direct', flush=True)
        print(mode, family, kind, 'echo verified', flush=True)
if two_queue:
    for path, mask in zip(queues, saved_masks, strict=True):
        path.write_text(mask)
PY
write_config() {
    local file=$1 backend=$2 direct=$3 security= action= binding= packet_policy= polling= extra= log_level=info dns="dns { bind: '' }"
    if [[ ${4:-} == endpoint-2q ]]; then backend+=$'\n    workers: 2'; fi
    if [[ -n ${5:-} ]]; then binding="xsk_mode: $5"; fi
    if [[ ${4:-} == snat || ${4:-} == masquerade ]]; then
        # Separate daemon profiles must not reuse the peer's retained TIME_WAIT tuple.
        if [[ $4 == snat ]]; then action='snat(203.0.113.1,40000-40003)'; else action='masquerade(40004-40007)'; fi
        security="firewall {
        original { default: allow }
        forward { default: allow }
    }
    nat {
        prerouting { dip(198.51.100.99) && dport(18080) -> dnat(198.51.100.2:18081) }
        postrouting { sip(192.0.2.2) -> $action }
    }"
    fi
    if [[ ${4:-} == endpoint || ${4:-} == core ]]; then
        dns="dns {
    bind: ''
    optimistic_cache_ttl: 0
    upstream { default: 'udp://10.77.0.2:15353' }
}"
        packet_policy="dport(18083) -> direct(must)
    domain(packet-path.test) -> block"
    fi
    if [[ $direct == 'direct: endpoint' && -z $packet_policy ]]; then
        # endpoint-candidate-unflagged needs a barrier because D1 passes static Direct to the kernel.
        # endpoint-crash needs a barrier to establish Endpoint traffic before SIGKILL.
        # endpoint-vlan needs a barrier to test the Endpoint VLAN consumer rather than D1 PASS.
        # endpoint-vlan-offload needs a barrier to test recovered tags in Endpoint.
        # endpoint-vlan-single-offload needs a barrier to keep its tagged traffic in Endpoint.
        # endpoint-jumbo needs a barrier to test real Endpoint SG consumption rather than D1 PASS.
        packet_policy='domain(endpoint-consumer.invalid) -> block'
    fi
    if [[ ${4:-} == endpoint ]]; then
        log_level=debug
        polling="poll_mode: event
    busy_poll {
        pps_enter: 1
        pps_exit: 0
        observation_window_us: 20000
        enter_windows: 2
        exit_windows: 1
        max_busy_us: 1000
        empty_rounds: 2
        budget_window_us: 10000
        budget_us: 2000
    }"
    fi
    cat >"$file" <<EOF
global {
    dial_mode: ip
    nfqueue_enable: false
    so_mark_from_dae: 0x100
    data_dir: '/run/honk-xdp-state'
    tcp_check_url: 'http://127.0.0.1:1/'
    udp_check_dns: '127.0.0.1:9'
    log_level: $log_level
}
$dns
datapath {
    $backend
    $direct
    $binding
    $polling
    interface {
        dut0: lan
        dut1: wan
    }
    $security
}
routing {
    $packet_policy
    fallback: direct
}
$extra
EOF
}
write_config "$work/asymmetric.dae" 'backend: xdp' 'direct: endpoint' '' 'copy'
mark_phase admission begin
python3 - "$work/asymmetric.dae" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_text(path.read_text().replace('dut0: lan', 'asym: lan'))
PY
for rx in 2 1; do
    tx=$((3 - rx))
    ip -n dut link add asym numrxqueues "$rx" numtxqueues "$tx" type veth peer name ca numrxqueues "$tx" numtxqueues "$rx" netns client
    ip -n dut link set dev asym addrgenmode none up
    ip -n client link set dev ca addrgenmode none up
    ip -n dut -j -d link show dev asym >"$work/queues-rx$rx-tx$tx.json"
    python3 - "$work/queues-rx$rx-tx$tx.json" "$rx" "$tx" <<'PY'
import json, pathlib, sys
link = json.loads(pathlib.Path(sys.argv[1]).read_text())[0]
assert (link['num_rx_queues'], link['num_tx_queues']) == tuple(map(int, sys.argv[2:])), link
PY
    if [[ $rx == 2 ]]; then
        set +e
        ip netns exec dut timeout 15s "$daemon" -c "$work/asymmetric.dae" --bpf-pin-root "$work/bpf" >"$work/queues-rx2-tx1.daemon.log" 2>&1
        status=$?
        set -e
        [[ $status != 0 && $status != 124 && $status != 137 ]] || fail 'RX2/TX1 did not reject startup'
        ip netns exec dut python3 "$work/check.py" absent
        [[ -z $(find "$work/bpf" -type f -print -quit) ]] || fail 'RX2/TX1 rejection happened after persistent attachment'
    else
        ip netns exec dut "$daemon" -c "$work/asymmetric.dae" --bpf-pin-root "$work/bpf" >"$work/queues-rx1-tx2.daemon.log" 2>&1 &
        daemon_pid=$!
        ready=false
        for ((attempt=0; attempt<200; attempt++)); do
            kill -0 "$daemon_pid" 2>/dev/null || fail 'RX1/TX2 daemon exited'
            if grep -q 'XDP datapath ready' "$work/queues-rx1-tx2.daemon.log"; then ready=true; break; fi
            sleep 0.1
        done
        [[ $ready == true ]] || fail 'RX1/TX2 readiness deadline'
        for dev in asym dut1; do ip netns exec dut python3 "$HONK_XDP_PROBE" identity "$dev" data; done
        kill -TERM "$daemon_pid"
        timeout 20s tail --pid="$daemon_pid" -f /dev/null || fail 'RX1/TX2 shutdown deadline'
        wait "$daemon_pid"
        daemon_pid=
        stop_sources
        for dev in asym dut1; do
            ip netns exec dut python3 "$HONK_XDP_PROBE" xdp-absent "$dev"
        done
        [[ -z $(find "$work/bpf" -type f -print -quit) ]] || fail 'asymmetric capture left physical program pins'
        ip netns exec dut python3 "$work/check.py" absent
    fi
    ip -n dut link del asym
done
for spec in 'client c0' 'server s0' 'server su'; do
    read -r ns dev <<<"$spec"
    ip -n "$ns" link set lo up
    ip -n "$ns" link set "$dev" up
done
for missing in backend direct; do
    backend='backend: xdp' direct='direct: endpoint'
    if [[ $missing == backend ]]; then backend=; else direct=; fi
    write_config "$work/missing-$missing.dae" "$backend" "$direct"
    set +e
    ip netns exec dut timeout 15s "$daemon" -c "$work/missing-$missing.dae" --bpf-pin-root "$work/bpf" >"$work/missing-$missing.log" 2>&1
    status=$?
    set -e
    [[ $status != 0 && $status != 124 && $status != 137 ]] || fail "missing $missing did not reject startup"
    if grep -q 'XDP datapath ready\|XDP queue bound' "$work/missing-$missing.log"; then fail 'invalid config reached device startup'; fi
    ip netns exec dut python3 "$work/check.py" absent
    [[ -z $(find "$work/bpf" -type f -print -quit) ]] || fail 'invalid config left pinned kernel objects'
done
for binding in omitted zerocopy; do
    mode=$binding
    if [[ $binding == omitted ]]; then mode=; fi
    write_config "$work/$binding-refused.dae" 'backend: xdp' 'direct: endpoint' '' "$mode"
    set +e
    ip netns exec dut timeout 15s "$daemon" -c "$work/$binding-refused.dae" --bpf-pin-root "$work/bpf" >"$work/$binding-refused.log" 2>&1
    status=$?
    set -e
    [[ $status != 0 && $status != 124 && $status != 137 ]] || fail "unsupported $binding zero-copy did not reject startup"
    grep -q 'zero-copy segment capability unavailable' "$work/$binding-refused.log" || fail "$binding zero-copy request missed capability admission"
    if grep -q 'XDP queue bound' "$work/$binding-refused.log"; then fail 'unsupported zero-copy reached queue binding'; fi
    ip netns exec dut python3 "$work/check.py" absent
    [[ -z $(find "$work/bpf" -type f -print -quit) ]] || fail 'unsupported zero-copy left pinned objects'
done
ip -n dut link add link dut1 name lowmtu type vlan id 321
ip -n dut link set lowmtu mtu 1200 up
for profile in endpoint core; do
    write_config "$work/low-mtu-$profile.dae" 'backend: xdp' "direct: $profile" '' 'copy'
    set +e
    ip netns exec dut timeout 15s "$daemon" -c "$work/low-mtu-$profile.dae" --bpf-pin-root "$work/bpf" >"$work/low-mtu-$profile.log" 2>&1
    status=$?
    set -e
    [[ $status != 0 && $status != 124 && $status != 137 ]] || fail 'low logical MTU did not reject startup'
    # The gateway's capture_layout admission now refuses MTU <1280 before the logical-MTU check runs.
    grep -qE 'capture realm requires unicast MAC and MTU >=1280|XDP logical MTU must be at least 1280' "$work/low-mtu-$profile.log" || fail 'low-MTU rejection missed its contract'
    if grep -q 'XDP queue bound' "$work/low-mtu-$profile.log"; then fail 'low MTU reached device startup'; fi
    ip netns exec dut python3 "$work/check.py" absent
    [[ -z $(find "$work/bpf" -type f -print -quit) ]] || fail 'low MTU left pinned kernel objects'
done
ip -n dut link del lowmtu
mark_phase admission complete
profiles=(endpoint endpoint-candidate-unflagged endpoint-crash endpoint-2q core snat masquerade endpoint-vlan core-vlan endpoint-vlan-offload core-vlan-offload endpoint-vlan-single-offload core-vlan-single-offload endpoint-jumbo core-jumbo)
for profile in "${profiles[@]}"; do
    mark_phase "$profile" setup-begin
    for spec in 'client c0' 'server s0' 'server su'; do
        read -r ns dev <<<"$spec"
        ip -n "$ns" link set lo up
        ip -n "$ns" link set "$dev" up
    done
    if [[ $profile == *-jumbo ]]; then
        for spec in 'dut dut0' 'dut dut1' 'dut up' 'client c0' 'server s0' 'server su'; do
            read -r ns dev <<<"$spec"
            ip -n "$ns" link set dev "$dev" mtu 9000
        done
    fi
    if [[ $profile == endpoint-vlan ]]; then
        ip netns exec dut sysctl -qw net.ipv4.conf.default.forwarding=1 net.ipv6.conf.default.forwarding=1
        for spec in 'dut dut0 lan' 'dut dut1 wan' 'client c0 cli' 'server s0 srv'; do
            read -r ns parent stem <<<"$spec"
            ip -n "$ns" link add link "$parent" name "${stem}s" type vlan protocol 802.1ad id 123
            ip -n "$ns" link add link "${stem}s" name "${stem}c" type vlan protocol 802.1Q id 45
            ip -n "$ns" link set dev "${stem}s" addrgenmode none up
            ip -n "$ns" link set dev "${stem}c" addrgenmode none up
        done
    fi
    if [[ $profile == *-offload ]]; then
        ip netns exec client ethtool -K c0 tx-vlan-offload on tx-vlan-stag-hw-insert on
        ip netns exec server ethtool -K s0 tx-vlan-offload on tx-vlan-stag-hw-insert on
    fi
    if [[ $profile == *-single-* ]]; then
        client_dev=clis server_dev=srvs
        provision_routes clis srvs lans wans
    elif [[ $profile == *-vlan* ]]; then
        client_dev=clic server_dev=srvc
        provision_routes clic srvc lanc wanc
    else
        client_dev=c0 server_dev=s0
        provision_routes c0 s0 dut0 dut1
    fi
    ip netns exec dut nft flush chain inet honk_smoke_native forward
    mark_phase "$profile" kernel-baseline-begin
    python3 "$HONK_XDP_PROBE" guard delivered "$client_dev" "$server_dev" | tee "$work/$profile.kernel-baseline.log"
    if [[ $profile == endpoint-vlan ]]; then
        ip netns exec dut sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
        HONK_XDP_INLINE_QINQ=1 python3 "$HONK_XDP_PROBE" native-baseline | tee "$work/native-qinq-baseline.log"
        ip netns exec dut sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
    fi
    mark_phase "$profile" kernel-baseline-complete
    ip netns exec dut nft add rule inet honk_smoke_native forward counter drop
    direct=core
    if [[ $profile == endpoint* ]]; then direct=endpoint; fi
    check_mode=data
    native_fence_expected=0
    write_config "$work/$profile.dae" 'backend: xdp' "direct: $direct" "$profile" 'copy'
    polling_args=()
    if [[ $profile == endpoint ]]; then
        polling_args=(--busy-poll-calibration-experiment)
    elif [[ $profile == endpoint-candidate-unflagged ]]; then
        cp "$work/polling-candidate.dae" "$work/$profile.dae"
    fi
    ip -n dut -j address show >"$work/$profile.addresses.json"
    mark_phase "$profile" readiness-begin
    ip netns exec server python3 "$work/echo.py" "$profile" "$work/$profile.server-ready" >"$work/$profile.server.log" 2>&1 &
    server_pid=$!
    ip netns exec dut "$daemon" -c "$work/$profile.dae" --bpf-pin-root "$work/bpf" "${polling_args[@]}" >"$work/$profile.daemon.log" 2>&1 &
    daemon_pid=$!
    ready=false
    for ((attempt=0; attempt<200; attempt++)); do
        kill -0 "$daemon_pid" 2>/dev/null || fail "$profile daemon exited; see $work/$profile.daemon.log"
        if [[ -n $server_pid ]]; then kill -0 "$server_pid" 2>/dev/null || fail "$profile server exited"; fi
        if [[ -f $work/$profile.server-ready ]] && grep -q 'XDP datapath ready' "$work/$profile.daemon.log"; then ready=true; break; fi
        sleep 0.1
    done
    [[ $ready == true ]] || fail "$profile readiness deadline"
    mark_phase "$profile" ready
    python3 - "$work/$profile.daemon.log" <<'PY'
import pathlib, re, sys
log = re.sub(r'\x1b\[[0-9;]*m', '', pathlib.Path(sys.argv[1]).read_text())
before_ready = log.split('XDP datapath ready', 1)[0]
for interface in ('dut0', 'dut1'):
    for queue in (0, 1):
        assert any('XDP queue bound' in line
                   and re.search(r'\binterface="?' + interface + r'"?(?:\s|$)', line)
                   and re.search(r'\bqueue=' + str(queue) + r'(?:\s|$)', line)
                   for line in before_ready.splitlines()), (interface, queue, 'queue not bound before readiness')
print('all selected RX queues bound before readiness')
PY
    mark_phase "$profile" pre-client-check-begin
    ip netns exec dut python3 "$work/check.py" "$check_mode"
    for dev in dut0 dut1; do ip netns exec dut python3 "$HONK_XDP_PROBE" foreign-xdp-rejected "$dev"; done
    ip -n dut -j -d link show >"$work/$profile.links.json"
    mark_phase "$profile" client-begin
    ip netns exec client python3 "$work/client.py" "$profile" "$work/$profile.dae" "$work/$profile.daemon.log" "$daemon_pid" | tee "$work/$profile.client.log"
    mark_phase "$profile" client-complete
    ip netns exec dut python3 "$work/check.py" "$check_mode"
    if [[ -n $server_pid ]]; then
        wait "$server_pid"
        server_pid=
    fi
    mark_phase "$profile" server-joined
    for ns in client server; do ip netns exec "$ns" python3 "$HONK_XDP_PROBE" settled; done
    mark_phase "$profile" producers-settled
    if [[ $profile == endpoint || $profile == core ]]; then
        python3 "$HONK_XDP_PROBE" domain "$profile" | tee "$work/$profile.domain-routing.log"
        if [[ $profile == endpoint ]]; then native_fence_expected=2; fi
    fi
    if [[ $profile == snat || $profile == masquerade ]]; then
        ip netns exec server cat /proc/net/tcp >"$work/$profile.server-tcp.txt"
    fi
    if [[ $profile == core || $profile == core-vlan ]]; then
        if [[ $profile == core-vlan ]]; then export HONK_XDP_INLINE_QINQ=1; fi
        python3 "$HONK_XDP_PROBE" check | tee "$work/$profile.native-boundary.log"
        unset HONK_XDP_INLINE_QINQ
        if [[ $profile == core-vlan ]]; then HONK_XDP_INLINE_QINQ=1 python3 "$HONK_XDP_PROBE" padding | tee "$work/$profile.padded-vlan.log"; fi
    fi
    if [[ $profile == core-vlan-single-offload ]]; then
        HONK_XDP_SINGLE_VLAN=1 python3 "$HONK_XDP_PROBE" padding | tee "$work/$profile.padded-vlan.log"
    fi
    mark_phase "$profile" probes-complete
    ip netns exec dut python3 "$work/check.py" "$check_mode" "$native_fence_expected"
    if [[ $profile == endpoint-2q ]]; then
        ip netns exec dut nft -j list chain inet honk_smoke_native forward >"$work/$profile.native-fence.json"
    fi
    mark_phase "$profile" shutdown-begin
    if [[ $profile == endpoint-crash ]]; then kill -KILL "$daemon_pid"; else kill -TERM "$daemon_pid"; fi
    timeout 20s tail --pid="$daemon_pid" -f /dev/null || fail 'daemon shutdown deadline'
    daemon_status=0
    wait "$daemon_pid" || daemon_status=$?
    daemon_pid=
    if [[ $profile == endpoint-crash ]]; then
        [[ $daemon_status == 137 ]] || fail "$profile did not terminate through SIGKILL: $daemon_status"
    else
        [[ $daemon_status == 0 ]] || fail "$profile daemon exited with status $daemon_status"
    fi
    mark_phase "$profile" daemon-joined
    ip netns exec dut nft flush chain inet honk_smoke_native forward
    if [[ $profile != endpoint-crash ]]; then
        grep -q 'XDP admission closed; UMEM retained until process exit' "$work/$profile.daemon.log" || fail 'missing shutdown admission fence'
    fi
    mark_phase "$profile" kernel-recovery-begin
    ip netns exec dut python3 "$work/check.py" absent
    [[ -z $(find "$work/bpf" -type f -print -quit) ]] || fail 'FD capture left persistent physical pins'
    python3 "$HONK_XDP_PROBE" guard delivered "$client_dev" "$server_dev" | tee "$work/$profile.kernel-wire.log"
    check_kernel_recovery | tee "$work/$profile.kernel-connections.log"
    mark_phase "$profile" kernel-recovery-complete
    stop_sources
    mark_phase "$profile" detached
    if [[ $profile == *-jumbo ]]; then
        for spec in 'dut dut0' 'dut dut1' 'dut up' 'client c0' 'server s0' 'server su'; do
            read -r ns dev <<<"$spec"
            ip -n "$ns" link set dev "$dev" mtu 1500
        done
    fi
done
mark_phase tc setup-begin
for spec in 'dut lans' 'dut wans' 'client clis' 'server srvs'; do
    read -r ns dev <<<"$spec"
    ip -n "$ns" link del "$dev"
done
for spec in 'dut dut0' 'dut dut1' 'dut up' 'client c0' 'server s0' 'server su'; do
    read -r ns dev <<<"$spec"
    ip -n "$ns" link set dev "$dev" mtu 1500 up
    ip -n "$ns" link set lo up
done
provision_routes c0 s0 dut0 dut1
[[ $(ip netns exec dut stat -f -c %T /run/honk-cgroup) == cgroup2fs ]] || fail 'TC namespace lost guest cgroup2'
mkdir "$work/bpf/tc"
cat >"$work/tc.dae" <<EOF
global {
    lan_interface: dut0
    wan_interface: dut1
    dial_mode: ip
    nfqueue_enable: false
    so_mark_from_dae: 0x100
    data_dir: '/run/honk-tc-state'
    tcp_check_url: 'http://127.0.0.1:1/'
    udp_check_dns: '127.0.0.1:9'
}
dns { bind: '' }
routing { fallback: direct }
EOF
mark_phase tc readiness-begin
ip netns exec server python3 "$work/echo.py" tc "$work/tc.server-ready" >"$work/tc.server.log" 2>&1 &
server_pid=$!
ip netns exec dut "$daemon" -c "$work/tc.dae" --bpf-pin-root "$work/bpf/tc" >"$work/tc.daemon.log" 2>&1 &
daemon_pid=$!
ready=false
for ((attempt=0; attempt<300; attempt++)); do
    kill -0 "$daemon_pid" 2>/dev/null || fail "default TC daemon exited; see $work/tc.daemon.log"
    kill -0 "$server_pid" 2>/dev/null || fail 'default TC server exited'
    if [[ -f $work/tc.server-ready ]] && grep -q 'Control plane listening for TPROXY UDPv6' "$work/tc.daemon.log"; then ready=true; break; fi
    sleep 0.1
done
[[ $ready == true ]] || fail 'default TC readiness deadline'
mark_phase tc ready
ip netns exec dut python3 "$work/check.py" tc
mark_phase tc client-begin
ip netns exec client python3 "$work/client.py" tc "$work/tc.dae" "$work/tc.daemon.log" "$daemon_pid" | tee "$work/tc.client.log"
mark_phase tc client-complete
wait "$server_pid"
server_pid=
mark_phase tc server-joined
for ns in client server; do ip netns exec "$ns" python3 "$HONK_XDP_PROBE" settled; done
mark_phase tc shutdown-begin
kill -TERM "$daemon_pid"
timeout 30s tail --pid="$daemon_pid" -f /dev/null || fail 'default TC shutdown deadline'
wait "$daemon_pid"
daemon_pid=
mark_phase tc daemon-joined
stop_sources
ip netns exec dut python3 "$work/check.py" absent
mark_phase tc complete
printf 'PASS: omitted-datapath real TC startup, IPv4/IPv6 TCP/UDP and new-flow Block/Direct SIGHUP reload.\n'
printf 'PASS: real capture and Endpoint/Core consumption for IPv4/IPv6 TCP/UDP, QinQ, IPv4 NAT, binding-mode admission/reload, FD close kernel recovery, foreign-XDP rejection, and veth MTU 1500/9000.\n'
printf 'IPv6 Core uses flow-label zero; veth copy/SG results do not establish physical zero-copy, jumbo performance or DMA release.\n'
