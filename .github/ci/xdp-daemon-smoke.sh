#!/usr/bin/env bash
# Disposable-virtme-guest gate. Never invoke on the host; no downloads/builds.
# Usage: bash .github/ci/xdp-daemon-smoke.sh /absolute/path/to/fresh/honk-core [all|runtime|daemon]
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
    *) fail 'unknown smoke scope' ;;
esac
read -r smoke_started _ </proc/uptime
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
export HONK_XDP_PROBE="$script_dir/xdp-ipv4-options.py"
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
    # Quiesce ingress before stopping the daemon or removing its fail-closed guards.
    for ns in client server; do
        ip -n "$ns" link set lo down 2>/dev/null || true
    done
    ip -n client link set c0 down 2>/dev/null || true
    ip -n client link set ca down 2>/dev/null || true
    ip -n server link set s0 down 2>/dev/null || true
    ip -n server link set su down 2>/dev/null || true
}
retain_adaptive_custody() {
    python3 - <<'PY'
import os, signal
held = [os.open('/proc/thread-self/ns/mnt', os.O_RDONLY)]
for name in os.listdir('/run/netns'):
    held.append(os.open('/run/netns/' + name, os.O_RDONLY))
print('unresolved adaptive owner custody retained until VM teardown', flush=True)
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
        # A failed join cannot authorize namespace/pin teardown. This guest-only
        # custodian retains the private mount/nsfs/bpffs until the VM is destroyed.
        retain_adaptive_custody </dev/null >"$work/adaptive-custodian.log" 2>&1 &
        printf '%s\n' "$!" >"$work/adaptive-custodian.pid"
        printf 'Retaining unresolved adaptive ownership: %s (exit %s)\n' "$work" "$status" >&2
        [[ $status != 0 ]] || status=1
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
ip -n dut link add dut0 numrxqueues 2 numtxqueues 2 type veth peer name c0 netns client
ip -n dut link add dut1 numrxqueues 2 numtxqueues 2 type veth peer name s0 netns server
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
    ip -n server addr replace 10.77.0.2/24 dev su
    ip -n server -6 addr replace fd00:77::2/64 dev su nodad
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
for link in links:
    if mode == 'absent':
        assert not link.get('xdp', {}).get('prog', {}).get('id', 0) and not link.get('xdp', {}).get('prog_id', 0), link
    dev = link['ifname']
    assert not any(q['kind'] in ('clsact', 'ingress') for q in json.loads(command('tc', '-j', 'qdisc', 'show', 'dev', dev))), dev
    for direction in ('ingress', 'egress'):
        assert not json.loads(command('tc', '-j', 'filter', 'show', 'dev', dev, direction)), dev
    if dev in ('dut0', 'dut1'):
        assert not json.loads(command('ip', '-j', 'addr', 'show', 'dev', dev))[0]['addr_info'], 'captured port is numbered'
        assert link['num_rx_queues'] == 2, link
        xdp = link.get('xdp', {})
        program_id = xdp.get('prog', {}).get('id', 0) or xdp.get('prog_id', 0)
        if mode == 'absent':
            assert not program_id and xdp.get('attached') in (None, 'off'), xdp
        else:
            assert program_id, xdp
            identity = [sys.executable, os.environ['HONK_XDP_PROBE'], 'identity', dev, mode]
            if mode == 'guard':
                identity.append(pathlib.Path(f'{sys.argv[2]}.{dev}.guard-id').read_text().strip())
            subprocess.run(identity, check=True)
print('kernel contract:', mode, flush=True)
if mode == 'data':
    rules = json.loads(command('nft', '-j', 'list', 'chain', 'inet', 'honk_smoke_native', 'forward'))['nftables']
    expressions = [item['rule']['expr'] for item in rules if 'rule' in item]
    assert len(expressions) == 1 and expressions[0][-1] == {'drop': None}, expressions
    counter = next(item['counter'] for item in expressions[0] if 'counter' in item)
    assert counter['packets'] == 0, ('native forwarding attempted during consumer proof', counter)
    print('independent native-forward fence:', counter, flush=True)
PY
if [[ -n ${HONK_XDP_XSK_TEST_BIN:-} ]]; then
    [[ $HONK_XDP_XSK_TEST_BIN == /* && -x $HONK_XDP_XSK_TEST_BIN ]] || fail 'invalid XSK test executable'
    for test in \
        bpf::general::tests::kernel_group_unicast_cannot_borrow_connected_socket_exemption \
        bpf::general::tests::kernel_native_destinations_and_metadata_counter_are_distinct \
        bpf::general::tests::kernel_legacy_capture_keeps_rejection_counters_and_xsk_miss_closed; do
        [[ $(ip netns exec dut "$HONK_XDP_XSK_TEST_BIN" "$test" --exact --ignored --list --format terse) == "$test: test" ]] || fail "missing ignored XSK regression: $test"
    done
    ip netns exec dut "$HONK_XDP_XSK_TEST_BIN" bpf::general::tests::kernel_ --ignored --test-threads=1 --nocapture | tee "$work/xsk-kernel.log"
fi
if [[ -n ${HONK_XDP_CORE_TEST_BIN:-} ]]; then
    [[ $HONK_XDP_CORE_TEST_BIN == /* && -x $HONK_XDP_CORE_TEST_BIN ]] || fail 'invalid Core test executable'
    ip -n dut route replace 198.51.100.99/32 dev dut1 src 203.0.113.1
    ip -n dut -6 route replace fd00:2::99/128 dev dut1 src fd00:77::1
    ip -n dut route replace 192.0.2.2/32 dev dut0 src 203.0.113.1
    ip -n dut -6 route replace fd00:1::2/128 dev dut0 src fd00:77::1
    ip -n dut route replace 192.0.2.99/32 dev dut0 src 203.0.113.1
    ip -n dut -6 route replace fd00:1::99/128 dev dut0 src fd00:77::1
    ip -n dut route replace prohibit 198.51.100.98/32
    ip -n dut -6 route replace prohibit fd00:2::98/128
    driven_test=xdp::tests::driven_kernel::policy_publication_keeps_real_endpoint_app_timer_and_close_owned
    adaptive_test=xdp::tests::driven_kernel::adaptive::actual_owner_clock_budget_fairness_and_live_features
    for test in \
        control::core_forward::tests::firewall_capacity_refusal_keeps_packet_owner_alive \
        control::core_forward::tests::unresolved_forward_neighbor_does_not_delay_transit_errors \
        control::core_forward::tests::generated_reassembly_error_keeps_scoped_nat_and_funding_through_completion \
        control::core_forward::tests::plain_output_history_survives_first_nat_enable_and_cq_owners \
        control::core_forward::tests::unbound_native_quote_cannot_authorize_a_reused_nat_identity \
        "$driven_test" "$adaptive_test"; do
        [[ $(ip netns exec dut "$HONK_XDP_CORE_TEST_BIN" "$test" --exact --ignored --list --format terse) == "$test: test" ]] || fail "missing ignored Core regression: $test"
    done
    ip netns exec dut "$HONK_XDP_CORE_TEST_BIN" control::core_forward::tests:: --ignored --test-threads=1 --nocapture | tee "$work/core-forward.log"
    ip netns exec dut nft add rule inet honk_smoke_native forward counter drop
    ip netns exec client nft add table inet honk_smoke_driven
    ip netns exec client nft 'add chain inet honk_smoke_driven prerouting { type filter hook prerouting priority -300; policy accept; }'
    ip netns exec client nft add rule inet honk_smoke_driven prerouting ip daddr 192.0.2.99 drop
    ip netns exec dut env HONK_XDP_ARTIFACT_ROOT="$work" "$HONK_XDP_CORE_TEST_BIN" "$driven_test" --exact --ignored --test-threads=1 --nocapture | tee "$work/driven-runtime.log"
    ip netns exec dut nft -j list chain inet honk_smoke_native forward >"$work/driven-runtime.native-fence.json"
    python3 - "$work/driven-runtime.native-fence.json" <<'PY'
import json, pathlib, sys
items = json.loads(pathlib.Path(sys.argv[1]).read_text())['nftables']
rules = [item['rule']['expr'] for item in items if 'rule' in item]
assert len(rules) == 1 and rules[0][-1] == {'drop': None}, rules
counter = next(item['counter'] for item in rules[0] if 'counter' in item)
assert counter['packets'] == 0, ('native forwarding masked real Runtime evidence', counter)
PY
    for dev in dut0 dut1; do
        ifindex=$(ip netns exec dut cat "/sys/class/net/$dev/ifindex")
        guard_id=$(<"$work/driven-runtime.$dev.guard-id")
        ip netns exec dut env HONK_XDP_PIN_ROOT="$work/bpf/driven-runtime" python3 "$HONK_XDP_PROBE" identity "$dev" guard "$guard_id"
        ip -n dut link set "$dev" xdp off
        rm "$work/bpf/driven-runtime/xdp-$ifindex/guard" "$work/bpf/driven-runtime/xdp-$ifindex/data"
        rmdir "$work/bpf/driven-runtime/xdp-$ifindex"
    done
    rmdir "$work/bpf/driven-runtime"
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

    # A separate 45-second combined-consumer window; the original Event/E32
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

for family, address in ((socket.AF_INET, '198.51.100.2'), (socket.AF_INET6, 'fd00:2::2')):
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
PY
write_config() {
    local file=$1 backend=$2 direct=$3 security= action= binding= packet_policy= polling= log_level=info dns="dns { bind: '' }"
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
        for dev in asym dut1; do ip netns exec dut python3 "$HONK_XDP_PROBE" pin-id "$dev" guard >"$work/asymmetric.$dev.guard-id"; done
        kill -TERM "$daemon_pid"
        timeout 20s tail --pid="$daemon_pid" -f /dev/null || fail 'RX1/TX2 shutdown deadline'
        wait "$daemon_pid"
        daemon_pid=
        stop_sources
        for dev in asym dut1; do
            ip netns exec dut python3 "$HONK_XDP_PROBE" identity "$dev" guard "$(<"$work/asymmetric.$dev.guard-id")"
            ifindex=$(ip netns exec dut cat "/sys/class/net/$dev/ifindex")
            ip -n dut link set "$dev" xdp off
            rm "$work/bpf/xdp-$ifindex/guard" "$work/bpf/xdp-$ifindex/data"
            rmdir "$work/bpf/xdp-$ifindex"
        done
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
    grep -q 'XDP logical MTU must be at least 1280' "$work/low-mtu-$profile.log" || fail 'low-MTU rejection missed its contract'
    if grep -q 'XDP queue bound' "$work/low-mtu-$profile.log"; then fail 'low MTU reached device startup'; fi
    ip netns exec dut python3 "$work/check.py" absent
    [[ -z $(find "$work/bpf" -type f -print -quit) ]] || fail 'low MTU left pinned kernel objects'
done
ip -n dut link del lowmtu
mark_phase admission complete
for profile in endpoint endpoint-candidate-unflagged core snat masquerade endpoint-vlan core-vlan endpoint-vlan-offload core-vlan-offload endpoint-vlan-single-offload core-vlan-single-offload endpoint-jumbo core-jumbo; do
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
    mark_phase "$profile" guard-positive-begin
    python3 "$HONK_XDP_PROBE" guard delivered "$client_dev" "$server_dev" | tee "$work/$profile.guard-positive.log"
    if [[ $profile == endpoint-vlan ]]; then
        ip netns exec dut sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
        HONK_XDP_INLINE_QINQ=1 python3 "$HONK_XDP_PROBE" native-baseline | tee "$work/native-qinq-baseline.log"
        ip netns exec dut sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
    fi
    mark_phase "$profile" guard-positive-complete
    ip netns exec dut nft add rule inet honk_smoke_native forward counter drop
    direct=core
    if [[ $profile == endpoint* ]]; then direct=endpoint; fi
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
        kill -0 "$server_pid" 2>/dev/null || fail "$profile server exited"
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
    ip netns exec dut python3 "$work/check.py" data
    for dev in dut0 dut1; do ip netns exec dut python3 "$HONK_XDP_PROBE" pin-id "$dev" guard >"$work/$profile.$dev.guard-id"; done
    ip -n dut -j -d link show >"$work/$profile.links.json"
    mark_phase "$profile" client-begin
    ip netns exec client python3 "$work/client.py" "$profile" "$work/$profile.dae" "$work/$profile.daemon.log" "$daemon_pid" | tee "$work/$profile.client.log"
    mark_phase "$profile" client-complete
    ip netns exec dut python3 "$work/check.py" data
    wait "$server_pid"
    server_pid=
    mark_phase "$profile" server-joined
    for ns in client server; do ip netns exec "$ns" python3 "$HONK_XDP_PROBE" settled; done
    mark_phase "$profile" producers-settled
    if [[ $profile == endpoint || $profile == core ]]; then
        python3 "$HONK_XDP_PROBE" domain "$profile" | tee "$work/$profile.domain-routing.log"
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
    ip netns exec dut python3 "$work/check.py" data
    mark_phase "$profile" shutdown-begin
    kill -TERM "$daemon_pid"
    timeout 20s tail --pid="$daemon_pid" -f /dev/null || fail 'daemon shutdown deadline (guard custody retained)'
    wait "$daemon_pid"
    daemon_pid=
    mark_phase "$profile" daemon-joined
    ip netns exec dut nft flush chain inet honk_smoke_native forward
    grep -q 'XDP admission closed; UMEM retained until process exit' "$work/$profile.daemon.log" || fail 'missing shutdown admission fence'
    mark_phase "$profile" guard-negative-begin
    ip netns exec dut python3 "$work/check.py" guard "$work/$profile"
    python3 "$HONK_XDP_PROBE" guard refused "$client_dev" "$server_dev" | tee "$work/$profile.guard-negative.log"
    mark_phase "$profile" guard-negative-complete
    stop_sources
    # Deliberate operator removal with traffic already stopped; never automatic hot reopen.
    for dev in dut0 dut1; do
        ifindex=$(ip netns exec dut cat "/sys/class/net/$dev/ifindex")
        [[ -f $work/bpf/xdp-$ifindex/guard && -f $work/bpf/xdp-$ifindex/data ]] || fail 'missing persistent program pins'
        ip -n dut link set "$dev" xdp off
        rm "$work/bpf/xdp-$ifindex/guard" "$work/bpf/xdp-$ifindex/data"
        rmdir "$work/bpf/xdp-$ifindex"
    done
    ip netns exec dut python3 "$work/check.py" absent
    mark_phase "$profile" detached
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
printf 'PASS: real capture and Endpoint/Core consumption for IPv4/IPv6 TCP/UDP, QinQ, IPv4 NAT, binding-mode admission/reload, selected guard wire refusal, and veth MTU 1500/9000.\n'
printf 'IPv6 Core uses flow-label zero; veth copy/SG results do not establish physical zero-copy, jumbo performance or DMA release.\n'
