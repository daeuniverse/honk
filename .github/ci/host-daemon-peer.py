#!/usr/bin/env python3
"""Wire oracles for the Host TCX/TUN suite in the pinned CI guest."""
import contextlib
import errno
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import traceback

SCRIPTS = Path(__file__).resolve().parent
INPUTS = ('host-daemon-smoke.sh', 'host-daemon-peer.py', 'tun-endpoint-peer.py',
          'xdp-l3-lan.py', 'xdp-dns-shadow.py', 'xdp-ipv4-options.py', 'xdp_dns_tcp.py')
SELECTIONS = {
    'all': None,
    'host-ct-reply': ('ct-reply', 'ct-original-snat-rpf'),
    'host-pname': ('process-identity',),
}
STATE, CGROUP, PINS = map(Path, ('/run/honk-host-state', '/run/honk-host-cgroup', '/run/honk-host-bpf'))
TCX_EGRESS = 47
HOOKS = {2: 'host_create', 10: 'host_connect4', 11: 'host_connect6', 14: 'host_sendmsg4', 15: 'host_sendmsg6'}
HOST_DNS_REALM = 4096
HOSTS = ('up', 'hvlan.100', 'wwan0')
LOCAL = ('10.77.0.3',)
UPLINK = ('10.77.0.1', 'fd00:77::1')
SERVER = '10.77.0.2'
TARGET = ('198.51.100.2', 'fd00:2::2')
PROXY_SOURCE = ('198.51.100.250', 'fd00:2::250')
VLAN = ('10.86.0.1', 'fd00:86::1')
VLAN_PEER = ('10.86.0.2', 'fd00:86::2')
WG = ('10.87.0.1', 'fd00:87::1')
WG_PEER = ('10.87.0.2', 'fd00:87::2')
FILL_META = '198.51.100.30'
FILL_HOLD = ('198.51.100.31', '198.51.100.32', '198.51.100.33')
PROXY, DIRECT, PNAME, SERVICE, BLOCK, NEGATED = range(18081, 18087)
REASONS = {
    'non_transport': 0, 'endpoint_hold': 2, 'ct_original': 3, 'ct_reply': 4,
    'pass_fragment': 5, 'endpoint_fragment': 6, 'non_syn': 7, 'direct': 8,
    'endpoint': 9, 'hold_full': 12, 'fragment_miss': 14, 'dns_direct': 19,
    'meta_full': 27, 'direct_unrecorded': 28, 'late_packet': 29,
    'tcp_direct_full': 30,
    'queue_capacity': 31,
}


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def source_stamp(repo):
    repo = Path(repo).resolve(strict=True)
    assert repo == SCRIPTS.parent.parent
    revision = subprocess.check_output(['git', '-C', repo, 'rev-parse', 'HEAD'], text=True).strip()
    inventory = subprocess.check_output(['git', '-C', repo, 'ls-files', '-z', '--cached', '--others', '--exclude-standard'])
    paths = sorted(set(inventory.split(b'\0')) - {b''})
    assert {os.fsencode('.github/ci/' + name) for name in INPUTS} <= set(paths)
    source = hashlib.sha256()
    for name in paths:
        path = repo / os.fsdecode(name)
        source.update(name + b'\0')
        if path.is_symlink():
            identity = b'L' + os.fsencode(os.readlink(path))
        elif path.exists():
            identity = b'F' + bytes.fromhex(digest(path))
        else:
            identity = b'D'  # A tracked deletion is part of the frozen source inventory.
        source.update(len(identity).to_bytes(4, 'little') + identity)
    return revision + ':' + source.hexdigest()


def manifest(repo, lane, kernel, identity, daemon, frozen, selection):
    assert source_stamp(repo) == frozen, 'source inventory changed around the build'
    repo, daemon = Path(repo).resolve(strict=True), Path(daemon).resolve(strict=True)
    assert daemon.is_relative_to(repo / 'target') and os.access(daemon, os.X_OK)
    assert lane in ('floor', 'recent') and selection in SELECTIONS
    paths = [daemon, *(SCRIPTS / name for name in INPUTS)]
    print(json.dumps(dict(schema='honk-host-ci-v1', repo=str(repo), lane=lane, kernel_release=kernel,
                          uuid=identity, daemon=str(daemon), source=frozen, selection=selection,
                          host_boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                          hashes={str(path): digest(path) for path in paths}), sort_keys=True))


def read_inputs(path, expected, *, verify_files=True):
    assert __debug__ and os.geteuid() == 0 and os.uname().machine == 'x86_64'
    assert digest(path) == expected, 'launcher manifest changed'
    value = json.loads(path.read_text())
    assert value['schema'] == 'honk-host-ci-v1' and Path(value['repo']) == SCRIPTS.parent.parent
    assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() != value['host_boot_id']
    assert Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == value['uuid']
    assert 'hypervisor' in Path('/proc/cpuinfo').read_text().split()
    assert 'virtme.exec=' in Path('/proc/cmdline').read_text()
    assert os.uname().release == value['kernel_release'] == os.environ['HONK_CI_EXPECTED_KERNEL']
    assert value['lane'] == os.environ['HONK_CI_VM_LANE'] in ('floor', 'recent')
    assert value['selection'] == os.environ['HONK_CI_HOST_SELECTION'] in SELECTIONS
    assert os.stat('/proc/1/ns/net').st_ino == int(os.environ['HONK_HOST_PARENT_NETNS'])
    assert os.stat('/proc/self/ns/net').st_ino != int(os.environ['HONK_HOST_PARENT_NETNS'])
    assert os.stat('/proc/self/ns/mnt').st_ino != int(os.environ['HONK_HOST_PARENT_MNTNS'])
    deadline()
    assert {str(SCRIPTS / name) for name in INPUTS} | {value['daemon']} == set(value['hashes'])
    if verify_files:
        for name, expected in value['hashes'].items():
            assert digest(name) == expected, ('guest input changed', name)
    return value


def deadline():
    if time.monotonic_ns() >= int(os.environ['HONK_HOST_DEADLINE_NS']):
        raise TimeoutError('original Host guest deadline exhausted')


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local(sock):
    return sock.getsockname()[:2]


def send(sock, data, address):
    assert sock.sendto(data, address) == len(data)


def record(case, **data):
    print(json.dumps(dict(case=case, **data), sort_keys=True), flush=True)


def canonical(address):
    wire = wg.dns.address_bytes(address)
    return b'\0' * 10 + b'\xff\xff' + wire if len(wire) == 4 else wire


def flow_key(binding, source, target, protocol):
    return (struct.pack('=II', binding['realm'], 6 if ':' in source[0] else 4)
            + canonical(source[0]) + canonical(target[0]) + struct.pack('!HHB3x', source[1], target[1], protocol))


def map_read(details, key):
    if details[1] == 6:
        size = ((details[3] + 7) & ~7) * wg.dns.possible_cpus()
    else:
        size = details[3]
    return wg.dns.map_value(details, key, size)


def occupancy(details):
    identity, kind, key_size, value_size, capacity, _ = details
    assert kind == 1 and capacity > 0
    c = wg.dns.C
    keys, values, cursor = (c.create_string_buffer(size) for size in (key_size * 512, value_size * 512, key_size))
    probe = wg.dns.probe
    fd = probe.bpf(14, probe.Id(id=identity))
    total, previous = 0, 0
    try:
        while True:
            raw = struct.pack('=QQQQIIQQ', previous, c.addressof(cursor), c.addressof(keys), c.addressof(values), 512, fd, 0, 0)
            attr = c.create_string_buffer(raw, len(raw))
            complete = False
            try:
                probe.bpf(24, attr)  # BPF_MAP_LOOKUP_BATCH
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise
                complete = True
            count, = struct.unpack_from('=I', attr, 32)
            assert count <= 512 and (count or complete), (details, count)
            total += count
            assert total <= capacity, (details, total)
            if complete:
                return total
            previous = c.addressof(cursor)
    finally:
        os.close(fd)


def program_name(identity):
    probe = wg.dns.probe
    fd = probe.bpf(13, probe.Id(id=identity))
    try:
        info = wg.dns.info(fd, 80)
        assert struct.unpack_from('=I', info, 4)[0] == identity
        return info.raw[64:80].rstrip(b'\0').decode()
    finally:
        os.close(fd)


def cgroup_programs():
    c = wg.dns.C
    fd = os.open(CGROUP, os.O_DIRECTORY | os.O_RDONLY)
    try:
        result = {}
        for hook in HOOKS:
            ids = (c.c_uint32 * 32)()
            raw = struct.pack('=4IQII4Q', fd, hook, 0, 0, c.addressof(ids), len(ids), 0, 0, 0, 0, 0)
            attr = c.create_string_buffer(raw, len(raw))
            wg.dns.probe.bpf(16, attr)
            count, = struct.unpack_from('=I', attr, 24)
            assert count <= len(ids) and all(ids[:count]), (hook, count)
            result[hook] = [(identity, program_name(identity)) for identity in ids[:count]]
        return result
    finally:
        os.close(fd)


def daemon_cgroup_links(pid, active):
    probe = wg.dns.probe
    links = {}
    for path in Path(f'/proc/{pid}/fdinfo').iterdir():
        try:
            text = path.read_text()
        except FileNotFoundError:
            continue
        match = re.search(r'^link_id:\s+(\d+)$', text, re.M)
        if not match:
            continue
        identity = int(match[1])
        fd = probe.bpf(30, probe.Id(id=identity))
        try:
            kind, link_id, program, cgroup, hook = struct.unpack_from('=III4xQI', wg.dns.info(fd, 32))
        finally:
            os.close(fd)
        if kind == 3:
            assert link_id == identity and cgroup == CGROUP.stat().st_ino
            assert (program, HOOKS[hook]) in active[hook] and hook not in links
            links[hook] = identity
    assert set(links) == set(HOOKS), links
    return links


def foreign_cgroup(owned):
    c = wg.dns.C
    code = c.create_string_buffer(struct.pack('<BBhiBBhi', 0xb7, 0, 0, 1, 0x95, 0, 0, 0))
    license_text = c.create_string_buffer(b'GPL')
    program = wg.raw_bpf(5, '=IIQQIIQII16sII', 9, 2, c.addressof(code), c.addressof(license_text),
                         0, 0, 0, 0, 0, b'host_ci_allow', 0, 2)
    try:
        cgroup = os.open(CGROUP, os.O_DIRECTORY | os.O_RDONLY)
        try:
            fd = wg.raw_bpf(28, '=4I', program, cgroup, 2, 0)
        finally:
            os.close(cgroup)
    finally:
        os.close(program)
    owned.callback(os.close, fd)
    assert any(name == 'host_ci_allow' for _, name in cgroup_programs()[2])


def nft_count(name, ns='dut'):
    if name in ('snat', 'masquerade'):
        name = 'ci_' + name
    data = json.loads(wg.inside(ns, 'nft', '-j', 'list', 'counter', 'inet', 'host_ci', name))['nftables']
    counters = [entry['counter'] for entry in data if 'counter' in entry]
    [counter] = counters
    assert counter['name'] == name
    return counter['packets']


def auxiliary_wg(keys, peer):
    wg.wg_peer(keys, peer)
    wg.wg_outer(keys, peer)


def wan_wg(keys, peer, rebuild=False):
    if not rebuild:
        wg.ip('wgpeer', 'link', 'add', 'wwpeer0', 'type', 'wireguard')
        for number, address in enumerate(WG_PEER):
            wg.add_address('wgpeer', 'wwpeer0', f'{address}/{64 if number else 24}')
        wg.wg_set('wgpeer', 'wwpeer0', peer, 52821, keys, ','.join((WG[0] + '/32', WG[1] + '/128')), '10.78.0.1:52820')
    wg.ip('dut', 'link', 'add', 'wwan0', 'type', 'wireguard')
    for number, address in enumerate(WG):
        wg.add_address('dut', 'wwan0', f'{address}/{64 if number else 24}')
    wg.wg_set('dut', 'wwan0', keys, 52820, peer, ','.join((WG_PEER[0] + '/32', WG_PEER[1] + '/128')), '10.78.0.2:52821')


def vlan():
    wg.ip('dut', 'link', 'add', 'hvlan', 'type', 'veth', 'peer', 'name', 'hvpeer', 'netns', 'server')
    for ns, parent, addresses in [('dut', 'hvlan', VLAN), ('server', 'hvpeer', VLAN_PEER)]:
        device = parent + '.100'
        wg.ip(ns, 'link', 'set', parent, 'up')
        wg.ip(ns, 'link', 'add', 'link', parent, 'name', device, 'type', 'vlan', 'id', 100)
        wg.ip(ns, 'link', 'set', device, 'up')
        for lane, address in enumerate(addresses):
            wg.add_address(ns, device, f'{address}/{64 if lane else 24}')
    for index in (40, 41, 42, 43, 44):
        address = f'198.51.100.{index}/32'
        wg.add_address('server', 'lo', address)
        wg.ip('dut', 'route', 'add', address, 'via', VLAN_PEER[0], 'dev', HOSTS[1])


def firewall():
    wg.inside('dut', 'sysctl', '-qw', 'net.ipv4.conf.all.rp_filter=1', 'net.ipv4.conf.default.rp_filter=1',
              'net.ipv4.conf.up.rp_filter=1')
    wg.inside('server', 'sysctl', '-qw', 'net.ipv4.conf.all.rp_filter=1', 'net.ipv4.conf.su.rp_filter=1')
    wg.inside('dut', 'nft', '-f', '-', input=f'''table inet host_ci {{
        counter original {{}}
        counter reply {{}}
        counter ci_snat {{}}
        counter ci_masquerade {{}}
        counter returned {{}}
        counter related {{}}
        counter wg_underlay {{}}
        chain output {{
            type filter hook output priority filter; policy accept;
            oifname "up" ip saddr {LOCAL[0]} udp dport {PROXY} ct direction original ct state new ct zone 0 counter name original
            oifname "up" udp sport 51820 ct direction reply ct state established ct zone 0 counter name reply
        }}
        chain postrouting {{
            type nat hook postrouting priority srcnat; policy accept;
            oifname "up" ip saddr {LOCAL[0]} counter name ci_snat snat ip to {UPLINK[0]}
            oifname "up" ip saddr {wg.LAN[0]} counter name ci_masquerade masquerade
        }}
        chain input {{
            type filter hook input priority filter; policy drop;
            iifname "lo" accept
            iifname "up" ip daddr {LOCAL[0]} ct state established counter name returned accept
            iifname "up" ip daddr {LOCAL[0]} ct state related counter name related accept
            ct state {{ established, related }} accept
            iifname "up" tcp dport {SERVICE} accept
            iifname "up" udp dport 51820 accept
            iifname "under0" udp dport 52820 counter name wg_underlay accept
            iifname "under0" udp dport 51820 accept
            iifname "hvlan.100" udp dport 53 accept
            iifname "hvlan.100" tcp dport 53 accept
            meta l4proto ipv6-icmp accept
        }}
    }}''')
    wg.inside('server', 'nft', '-f', '-', input=f'''table inet host_ci {{
        counter strict_peer {{}}
        counter native_syn {{}}
        counter proxy_syn {{}}
        chain input {{
            type filter hook input priority filter; policy accept;
            iifname "su" ip saddr {UPLINK[0]} udp dport {DIRECT} counter name strict_peer
            iifname "su" tcp dport 18107 tcp flags & (syn | ack) == syn counter name native_syn
            iifname "su" tcp dport 18111 tcp flags & (syn | ack) == syn counter name proxy_syn
            ip daddr {{ {', '.join((FILL_META, *FILL_HOLD))} }} udp dport 20000-59999 drop
        }}
    }}''')


class Router:
    def __init__(self, owned, binary, work, mixed):
        self.owned, self.binary, self.work, self.mixed = owned, binary, work, mixed
        work.mkdir()
        self.config, self.log = work / 'honk.dae', work / 'daemon.log'
        self.state = Path(owned.enter_context(tempfile.TemporaryDirectory(dir=STATE)))
        self.pins = PINS / work.name
        self.pins.mkdir()
        owned.callback(self.pins.rmdir)
        self.hosts = HOSTS if mixed else HOSTS[:1]
        self.generation = 0
        self.manifest, self.manifest_sha = INPUT_PATH, INPUT_SHA
        self.process = None
        foreign_cgroup(owned)
        self.foreign = cgroup_programs()
        self.namespace_inodes = wg.topology(owned, 2)
        wg.add_address('dut', 'up', f'{LOCAL[0]}/24')
        addresses = {address for targets in tun.TARGETS.values() for address in targets} | set(PROXY_SOURCE) | {FILL_META, *FILL_HOLD}
        existing = {item['local'] for link in json.loads(wg.ip('server', '-j', 'addr', 'show')) for item in link['addr_info']}
        for address in sorted(addresses - existing):
            wg.add_address('server', 'lo', f"{address}/{128 if ':' in address else 32}")
        if mixed:
            auxiliary_wg(wg.keypair(), wg.keypair())
            vlan()
            self.wan_keys = wg.keypair(), wg.keypair()
        firewall()
        (work / 'peer-control.json').write_text('{"subscription": 0}\n')
        self.config.write_text(self.text())
        with (work / 'peer.log').open('x') as log:
            peer = subprocess.Popen(['ip', 'netns', 'exec', 'server', sys.executable, '-I', '-B', SCRIPTS / 'tun-endpoint-peer.py',
                                     'serve', work], env=dict(os.environ, HONK_TUN_PARENT_NETNS=os.environ['HONK_HOST_PARENT_NETNS']),
                                    stdout=log, stderr=subprocess.STDOUT)
        owned.callback(tun.stop, peer)
        def ready():
            assert peer.poll() is None, ('independent socket peer exited', work)
            return (work / 'peer-ready').is_file()
        wg.until(ready, 'independent socket peer readiness')

    def text(self, rules='', hosts=None):
        devices = '\n '.join(self.hosts if hosts is None else hosts)
        physical = 'xsk_mode: copy\n workers: 2\n interface {\n dut0: lan\n wg0: l3_lan\n }' if self.mixed else ''
        return f'''global {{
 nfqueue_enable: false
 log_level: debug
 dial_mode: {'domain+' if self.mixed else 'ip'}
 data_dir: '{self.state}'
 tcp_check_url: 'http://{SERVER}:18090/health'
 udp_check_dns: '{SERVER}:15353'
 udp_warm_node_count: 0
 check_interval: 3600s
}}
node {{ fixture: 'socks5://{SERVER}:1080' }}
group {{ proxy {{
 filter: name(fixture)
 policy: select
}} }}
datapath {{
 backend: xdp
 direct: endpoint
 dns_projection: true
 {physical}
 host {{ interface {{\n {devices}\n }} }}
}}
dns {{
 bind: 'tcp+udp://0.0.0.0:53'
 optimistic_cache: false
 upstream {{ default: 'udp://{SERVER}:25353' }}
}}
experimental {{
 clash_api {{ external_controller: '127.0.0.1:19090' }}
 cache_file {{ enabled: false }}
}}
routing {{
 {rules}
 pname(hostnamed) && dport({PNAME}) -> proxy
 dport({PNAME}) -> direct(must)
 pname(hostnamed) && dport({NEGATED}) -> direct(must)
 !pname(hostnamed) && dport({NEGATED}) -> proxy
 dport({NEGATED}) -> block(must)
 dip(198.51.100.6/32) -> direct(must)
 dport({PROXY}, 18111) -> proxy
 dport({DIRECT}, 18101, 18107, 18110) -> direct(must)
 dport({SERVICE}) -> direct
 dport({BLOCK}, 67, 547) -> block(must)
 dport(18106) -> direct
 sport(51820) -> block(must)
 dip({FILL_META}/32) -> block(must)
 dip({', '.join(address + '/32' for address in FILL_HOLD)}) -> direct(must)
 dport(18102) && domain(suffix: host-ci.test) -> direct(must)
 fallback: direct
}}
'''

    def start(self):
        self.process = wg.start_daemon(self.owned, self.binary, self.config, self.pins, self.log)
        wg.wait_log(self.process, self.log, 'XDP datapath ready')
        assert os.path.samefile(self.binary, f'/proc/{self.process.pid}/exe')
        assert os.stat(f'/proc/{self.process.pid}/ns/net').st_ino == Path('/run/netns/dut').stat().st_ino
        active = cgroup_programs()
        for hook, name in HOOKS.items():
            assert [entry[1] for entry in active[hook] if entry not in self.foreign[hook]] == [name], active
            assert [entry for entry in active[hook] if entry[1] != name] == self.foreign[hook], active
        record('host-cgroup-active', programs=active, links=daemon_cgroup_links(self.process.pid, active))
        self.primary = self.binding(0)
        program = self.primary['outer_link'][1]
        self.maps = {name: wg.named_map(program, name) for name in (
            'HOST_HOLD', 'honk_gw_stats', 'HOST_FLOW_META', 'HOST_DIRECT_TCP',
            'HOST_SK_IDENTIT', 'HOST_SK_DECISIO', 'dns_epochs', 'dns_facts')}
        assert self.maps['honk_gw_stats'][1:5] == (6, 4, 8, max(REASONS.values()) + 1)
        assert self.maps['HOST_FLOW_META'][1:5] == (1, 48, 88, 8192)
        assert self.maps['HOST_DIRECT_TCP'][1:5] == (1, 48, 32, 8192)
        assert self.maps['HOST_HOLD'][1:5] == (1, 48, 32, 65536)
        for name in ('HOST_SK_IDENTIT', 'HOST_SK_DECISIO'):
            _, kind, key_size, _, limit, flags = self.maps[name]
            assert (kind, key_size, limit, flags) == (24, 4, 0, 1), (name, self.maps[name])
        return self

    def binding(self, index, *, after=0, bounded=False):
        device, tun_name = self.hosts[index], f'honk-host-{index}'
        field = re.compile(r'\b(interface|realm|binding_id|ifindex|mtu|private_mtu)=([^\s]+)')
        def observe():
            assert self.process.poll() is None, ('daemon exited waiting for egress', device, self.log)
            rows = [dict(field.findall(line)) for line in self.log.read_text()[after:].splitlines()
                    if 'Host egress active' in line]
            matches = [row for row in rows if row.get('interface') == device]
            if not matches or device not in (links := wg.links()) or tun_name not in links:
                return None
            outer = wg.tcx('dut', device, attach_type=TCX_EGRESS)
            inner = wg.tcx('dut', tun_name)
            return (matches[-1], links, outer, inner) if outer and len(inner) == 2 else None
        row, links, outer, inner = wg.until(observe, f'active Host egress {device}')
        realm, incarnation, index, mtu, private_mtu = (int(row[field]) for field in ('realm', 'binding_id', 'ifindex', 'mtu', 'private_mtu'))
        [entry] = outer
        returned, guard = inner
        assert entry[0] and entry[2] == 'honk_host_gw'
        assert returned[0] and returned[2] == 'honk_aux_return' and guard[0] == 0 and guard[2] == 'honk_aux_stop'
        assert realm and incarnation and index == links[device]['ifindex']
        if bounded:
            actual_mtu = int(wg.inside('dut', 'cat', f'/sys/class/net/{tun_name}/mtu'))
            assert actual_mtu == private_mtu
        tun_link = links[tun_name]
        assert links[device]['mtu'] == mtu and tun_link['mtu'] == private_mtu and tun_link['linkinfo']['info_kind'] == 'tun'
        assert private_mtu >= 1280 and (private_mtu < mtu if bounded else private_mtu == mtu), (device, mtu, private_mtu)
        tun_fds = []
        for path in Path(f'/proc/{self.process.pid}/fdinfo').iterdir():
            try:
                info = path.read_text()
            except FileNotFoundError:
                continue
            if re.search(r'^iff:\s+' + re.escape(tun_name) + '$', info, re.M):
                tun_fds.append(int(path.name))
        assert len(tun_fds) == 1, (tun_name, tun_fds)
        assert not json.loads(wg.ip('dut', '-j', 'addr', 'show', 'dev', tun_name))[0]['addr_info']
        for family in ('-4', '-6'):
            assert not json.loads(wg.ip('dut', '-j', family, 'route', 'show', 'table', 'all', 'dev', tun_name))
        pair = wg.named_map(entry[1], 'honk_aux_devs')
        assert pair == wg.named_map(returned[1], 'honk_aux_devs')
        assert (wg.slot(pair, 0), wg.slot(pair, 1)) == (index, tun_link['ifindex'])
        state = dict(device=device, tun=tun_name, ifindex=index, tun_index=tun_link['ifindex'], mtu=mtu, private_mtu=private_mtu, realm=realm,
                     incarnation=incarnation, outer_link=entry, return_link=returned, devmap=pair)
        record('host-binding', **state)
        return state

    def counters(self, *reasons):
        return dict(zip(reasons, wg.counters(self.maps, 'honk_gw_stats', [REASONS[name] for name in reasons]), strict=True))

    def delta(self, before):
        return {key: value - before[key] for key, value in self.counters(*before).items()}

    def packets(self, binding=None):
        binding = binding or self.primary
        [link] = json.loads(wg.ip('dut', '-j', '-s', 'link', 'show', 'dev', binding['tun']))
        stats = link.get('stats64', link.get('stats'))
        return tuple(stats[direction]['packets'] for direction in ('tx', 'rx'))

    def events(self):
        events = (self.work / 'peer-events.jsonl').read_text().split('\n')[:-1]
        return [json.loads(line) for line in events]

    def echo(self, payload, target, action, original):
        rows = [row for row in self.events() if row['kind'] == 'echo' and row['target'] == list(target)
                and row['payload'] == payload.hex()]
        assert len(rows) == 1, ('expected exactly one independent peer delivery', target, action, rows)
        [row] = rows
        lane = int(':' in target[0])
        address = UPLINK[0] if original[0] == LOCAL[0] else original[0]
        if action == 'native':
            assert row['remote'] == [address, original[1]], ('original tuple did not go native', row, original)
        elif action == 'endpoint':
            assert row['remote'][0] == UPLINK[lane] and row['remote'] != [address, original[1]], row
        else:
            assert action == 'proxy' and row['remote'][0] == PROXY_SOURCE[lane], ('missing SOCKS relay delivery', row)
        return row['remote']

    def hold(self, binding, source, target, protocol):
        return self.flow_owner('HOST_HOLD', binding, source, target, protocol)

    def meta(self, binding, source, target, protocol):
        wire = map_read(self.maps['HOST_FLOW_META'], flow_key(binding, source, target, protocol))
        if wire is not None:
            stamp, incarnation, pid, length, name, cookie, born_ns = struct.unpack('=QQIB3x48sQQ', wire)
            assert incarnation == binding['incarnation'] and 0 <= length <= len(name), (binding, wire.hex())
            held = self.hold(binding, source, target, protocol)
            assert held and held['stamp'] == stamp and held['cookie'] == cookie and 0 < born_ns <= held['last_seen']
            return dict(stamp=stamp, binding=incarnation, pid=pid, pname=name[:length].decode(), cookie=cookie, born_ns=born_ns)

    def direct_tcp(self, binding, source, target):
        owner = self.flow_owner('HOST_DIRECT_TCP', binding, source, target, socket.IPPROTO_TCP)
        if owner is not None:
            assert owner['stamp'] >> 62 == 1 and owner['cookie']
        return owner

    def flow_owner(self, table, binding, source, target, protocol):
        wire = map_read(self.maps[table], flow_key(binding, source, target, protocol))
        if wire is not None:
            stamp, last_seen, cookie, incarnation = struct.unpack('=4Q', wire)
            assert stamp >> 62 in (1, 2) and stamp & ((1 << 62) - 1)
            assert last_seen and incarnation == binding['incarnation']
            return dict(stamp=stamp, last_seen=last_seen, cookie=cookie, binding=incarnation)

    def reload(self, rules):
        pending = self.config.with_suffix('.pending')
        pending.write_text(self.text(rules))
        pending.replace(self.config)
        self.generation += 1
        offset = self.log.stat().st_size
        self.process.send_signal(signal.SIGHUP)
        text = wg.wait_log(self.process, self.log, f'SIGHUP reload request {self.generation} applied', offset=offset)
        assert 'degraded' not in text.lower(), text

    def mode(self, value):
        with wg.dns.namespace('dut'):
            conn = http.client.HTTPConnection('127.0.0.1', 19090, timeout=8)
            try:
                conn.request('PATCH', '/configs', json.dumps(dict(mode=value)), {'Content-Type': 'application/json'})
                response = conn.getresponse()
                assert response.status == 204, (value, response.status, response.read())
                response.read()
                conn.request('GET', '/configs')
                response = conn.getresponse()
                assert response.status == 200 and json.load(response)['mode'] == value
            finally:
                conn.close()

    def stopped(self, *, crash=False):
        if crash:
            self.process.kill()
        else:
            self.process.terminate()
        assert self.process.wait(timeout=20) == (-9 if crash else 0), self.log
        wg.until(lambda: cgroup_programs() == self.foreign, 'daemon cgroup links survive daemon exit')
        links = wg.links()
        assert not any(name.startswith(('honk-host-', 'honk-l3-')) for name in links), links
        assert all(not wg.tcx('dut', name, attach_type=TCX_EGRESS) for name in self.hosts if name in links)
        assert not self.mixed or not wg.tcx('dut', 'wg0')
        with wg.dns.namespace('dut'):
            wg.dns.probe.require_xdp_absent(wg.dns.probe.kernel_xdp_state('dut0'))
        assert not any(self.pins.iterdir()), 'daemon left bpffs entries'
        assert not list(self.state.rglob('*receipt*')), 'daemon left a Host receipt'
        record('host-process-exit', crash=crash, cgroup_programs=cgroup_programs(), links=list(links))


def tcp_at(owned, ns, source, target):
    client = wg.socket_at(owned, ns, source, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512 * 1024)
    client.connect(target)
    return client


def no_udp_reply(sock, target, payload):
    previous = sock.gettimeout()
    sock.settimeout(0.65)
    try:
        send(sock, payload, target)
        reply = sock.recvfrom(65535)
    except (TimeoutError, ConnectionRefusedError):
        pass
    else:
        raise AssertionError(('blocked datagram received a reply', target, reply))
    finally:
        sock.settimeout(previous)


def udp_peer_exchange(client, target, payload):
    send(client, payload, target)
    data, source = client.recvfrom(65535)
    assert data == payload and source[:2] == target, ('original UDP socket received wrong bytes or tuple', source, target)


def udp_trial(fixture, source, target, action, *, sock=None, mark=0, fragment=False):
    before = fixture.packets()
    payload = os.urandom(2000 if fragment else 53)
    with contextlib.ExitStack() as owned:
        if sock is None:
            sock = wg.socket_at(owned, 'dut', (source, 0), socket.SOCK_DGRAM)
        if mark:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == mark
        if fragment:
            sock.setsockopt(socket.IPPROTO_IP, 10, 0)  # IP_MTU_DISCOVER, DONT
        original = local(sock)
        udp_peer_exchange(sock, target, payload)
        assert local(sock) == original
    observed = fixture.echo(payload, target, action, original)
    after = fixture.packets()
    if action == 'native':
        assert after == before, ('native datagram used internal TUN', original, target, before, after)
    else:
        assert all(new > old for old, new in zip(before, after, strict=True)), (original, target, before, after)
    return dict(origin=original, target=target, far_source=observed, tun_before=before, tun_after=after)


def tcp_trial(fixture, source, target, action, *, size=53):
    before = fixture.packets()
    payload = os.urandom(size)
    with contextlib.ExitStack() as owned:
        client = tcp_at(owned, 'dut', (source, 0), target)
        assert tun.exact(client, len(tun.BANNER)) == tun.BANNER
        original = local(client)
        tun.tcp_exchange(client, payload)
        closed = tun.tcp_close(client)
    observed = fixture.echo(payload, target, action, original)
    after = fixture.packets()
    if action == 'native':
        assert after == before, ('native TCP used internal TUN', original, target, before, after)
    else:
        assert all(new > old for old, new in zip(before, after, strict=True)), (original, target, before, after)
    return dict(origin=original, target=target, far_source=observed, tun_before=before, tun_after=after,
                bytes_each_direction=size, sha256=hashlib.sha256(payload).hexdigest(), close=closed)


def ct_reply(fixture):
    before = fixture.counters('ct_reply', 'endpoint')
    zone0 = nft_count('reply')
    tun_before = fixture.packets()
    with contextlib.ExitStack() as owned:
        client = wg.socket_at(owned, 'server', (TARGET[0], 0), socket.SOCK_DGRAM)
        client.settimeout(2)
        remote = wg.socket_at(owned, 'dut', (UPLINK[0], 51820), socket.SOCK_DGRAM)
        payload = os.urandom(53)
        send(client, payload, local(remote))
        data, source = remote.recvfrom(65535)
        assert data == payload and source == local(client)
        send(remote, payload[::-1], source)
        assert nft_count('reply') == zone0 + 1, 'the actual local skb was not a zone-0 REPLY in OUTPUT'
        try:
            response = client.recvfrom(65535)
        except TimeoutError as error:
            raise AssertionError(('zone-0 attached REPLY did not reach the original UDP client', fixture.delta(before))) from error
        assert response == (payload[::-1], local(remote)), response
        assert fixture.delta(before)['ct_reply'] == 1
        assert fixture.packets() == tun_before
        server = wg.socket_at(owned, 'dut', (UPLINK[0], SERVICE), socket.SOCK_STREAM)
        server.listen(1)
        client_tcp = tcp_at(owned, 'server', (TARGET[0], 0), local(server))
        accepted, source = server.accept()
        with accepted:
            assert source == local(client_tcp)
            client_tcp.sendall(b'service request')
            assert tun.exact(accepted, 15) == b'service request'
            accepted.sendall(b'service reply')
            assert tun.exact(client_tcp, 13) == b'service reply'
    assert fixture.delta(before)['ct_reply'] > 1 and fixture.delta(before)['endpoint'] == 0
    return dict(gateway=fixture.delta(before), zone0=nft_count('reply') - zone0)


def ct_original(fixture):
    before = fixture.counters('ct_reply', 'ct_original', 'endpoint', 'direct')
    fields = ('original', 'snat', 'returned', 'related')
    nft_before = {name: nft_count(name) for name in fields}
    strict_before = nft_count('strict_peer', 'server')
    for ns, device in [('dut', 'up'), ('server', 'su')]:
        for interface in ('all', device):
            assert wg.inside(ns, 'sysctl', '-n', f'net.ipv4.conf.{interface}.rp_filter').strip() == '1'
    try:
        proxied = udp_trial(fixture, LOCAL[0], (TARGET[0], PROXY), 'proxy')
    except (AssertionError, OSError) as error:
        assert nft_count('original') == nft_before['original'] + 1, 'the actual local skb was not a zone-0 ORIGINAL in OUTPUT'
        raise AssertionError(('zone-0 ORIGINAL missed Endpoint policy', fixture.delta(before))) from error
    native = udp_trial(fixture, LOCAL[0], (TARGET[0], DIRECT), 'native')
    with contextlib.ExitStack() as owned:
        client = wg.socket_at(owned, 'dut', (LOCAL[0], 0), socket.SOCK_DGRAM)
        client.connect((TARGET[0], 18101))
        client.send(b'ordinary closed service')
        try:
            client.recv(1)
        except ConnectionRefusedError:
            pass
        else:
            raise AssertionError('missing ct-related ICMP port unreachable')
    observed = {name: nft_count(name) - nft_before[name] for name in fields}
    assert observed['original'] == 1 and observed['snat'] >= 3, observed
    assert observed['returned'] >= 2 and observed['related'] >= 1, observed
    assert nft_count('strict_peer', 'server') == strict_before + 1
    delta = fixture.delta(before)
    assert delta['ct_original'] == delta['ct_reply'] == 0 and delta['endpoint'] == 1 and delta['direct'] >= 2, delta
    return dict(proxied=proxied, native=native, nft=observed, gateway=delta)


def named_client(transport, comm, source, target, port, payload, sport='0', receive='true'):
    assert Path('/run/netns/dut').stat().st_ino == os.stat('/proc/self/ns/net').st_ino
    assert wg.dns.probe.libc.prctl(15, comm.encode(), 0, 0, 0) == 0
    af = wg.dns.family(source)
    kind = socket.SOCK_STREAM if transport == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(af, kind) as client:
        client.settimeout(8)
        client.bind((source, int(sport)))
        target, payload = (target, int(port)), bytes.fromhex(payload)
        if kind == socket.SOCK_STREAM:
            client.connect(target)
            assert tun.exact(client, len(tun.BANNER)) == tun.BANNER
            tun.tcp_exchange(client, payload)
            tun.tcp_close(client)
        else:
            if transport == 'connected-udp':
                client.connect(target)
                assert client.send(payload) == len(payload)
                data, source = client.recvfrom(65535)
                assert data == payload and source[:2] == target
            else:
                if receive == 'true':
                    udp_peer_exchange(client, target, payload)
                else:
                    assert receive == 'false'
                    send(client, payload, target)
        cookie = socket_cookie(client)
        print(json.dumps(dict(pid=os.getpid(), source=local(client), cookie=cookie)), flush=True)


def named_probe(fixture, argv0, comm, transport, source, destination, payload, *args):
    return json.loads(tun.run('bash', '-c', 'exec -a "$0" "$@"', argv0, sys.executable, '-I', '-B',
                             SCRIPTS / 'host-daemon-peer.py', 'named', fixture.manifest, fixture.manifest_sha,
                             transport, comm, source, *destination, payload.hex(), *args, namespace='dut').stdout)


def process_identity(fixture):
    outcomes = []
    log = fixture.log.read_text()
    comm_only = 'trying thread names' in log
    for lane in (0, 1):
        for transport in ('tcp', 'connected-udp', 'unconnected-udp'):
            for process, port, action in [('hostnamed', PNAME, 'proxy'), ('hostother', PNAME, 'native'),
                                          ('hostnamed', NEGATED, 'native'), ('hostother', NEGATED, 'proxy')]:
                # Opposite names distinguish the active argv source from the comm fallback.
                other = 'hostnamed' if process == 'hostother' else 'hostother'
                argv0, comm = (other, process) if comm_only else (process, other)
                payload = os.urandom(53)
                destination = (TARGET[lane], port)
                child = named_probe(fixture, argv0, comm, transport, UPLINK[lane], destination, payload)
                source = tuple(child['source'])
                remote = fixture.echo(payload, destination, action, source)
                protocol = socket.IPPROTO_TCP if transport == 'tcp' else socket.IPPROTO_UDP
                meta = fixture.meta(fixture.primary, source, destination, protocol)
                if action == 'proxy':
                    assert meta and (meta['pid'], meta['pname'], meta['cookie']) == (child['pid'], process, child['cookie']), (transport, process, meta, child)
                else:
                    assert meta is None, (transport, destination, meta)
                outcomes.append(dict(transport=transport, process=process, source=source, far_source=remote, target=destination, action=action, meta=meta))
    for client in fixture.precreated:
        source = local(client)
        destination = client.getpeername()[:2]
        identity = fixture.maps['HOST_SK_IDENTIT']
        assert wg.dns.map_value(identity, struct.pack('=I', client.fileno()), identity[3]) is None
        payload = os.urandom(53)
        assert client.send(payload) == len(payload)
        data, peer = client.recvfrom(65535)
        assert data == payload and peer[:2] == destination
        assert wg.dns.map_value(identity, struct.pack('=I', client.fileno()), identity[3]) is None
        remote = fixture.echo(payload, destination, 'native', source)
        outcomes.append(dict(process='missing', source=source, target=destination, far_source=remote))
    return dict(capture='comm' if comm_only else 'argv0', exchanges=outcomes)


def modes_and_protocols(fixture):
    policy = []
    for mode, port, action in [('Rule', SERVICE, 'native'), ('Global', SERVICE, 'proxy'),
                               ('Global', DIRECT, 'native'), ('Direct', PROXY, 'endpoint')]:
        fixture.mode(mode)
        for lane in (0, 1):
            policy.append(dict(mode=mode, action=action, **udp_trial(fixture, UPLINK[lane], (TARGET[lane], port), action)))
    fixture.mode('Rule')
    exact = udp_trial(fixture, UPLINK[0], (TARGET[0], PROXY), 'native', mark=0x100)
    partial = udp_trial(fixture, UPLINK[0], (TARGET[0], PROXY), 'proxy', mark=0x101)
    before, tun_before = fixture.counters('non_transport'), fixture.packets()
    with contextlib.ExitStack() as owned:
        for lane, port in enumerate((67, 547)):
            server = wg.socket_at(owned, 'server', (TARGET[lane], port), socket.SOCK_DGRAM)
            client = wg.socket_at(owned, 'dut', (UPLINK[lane], 0), socket.SOCK_DGRAM)
            payload = os.urandom(53)
            send(client, payload, local(server))
            assert server.recvfrom(65535)[0] == payload, 'DHCP port failed native exemption'
    assert fixture.packets() == tun_before and fixture.delta(before)['non_transport'] >= 2
    return dict(policy=policy, marks={'exact': exact, 'other': partial}, gateway=fixture.delta(before))


def mixed_udp(fixture):
    before = fixture.counters('direct', 'endpoint', 'endpoint_hold')
    evidence = []
    for lane in (0, 1):
        with contextlib.ExitStack() as owned:
            client = wg.socket_at(owned, 'dut', (UPLINK[lane], 0), socket.SOCK_DGRAM)
            origin = local(client)
            direct, proxy = (TARGET[lane], DIRECT), (TARGET[lane], PROXY)
            for destination, action in ((direct, 'native'), (proxy, 'proxy'), (direct, 'native'), (proxy, 'proxy')):
                evidence.append(udp_trial(fixture, UPLINK[lane], destination, action, sock=client))
            assert local(client) == origin
            for destination, tag in ((direct, 1), (proxy, 2)):
                owner = fixture.hold(fixture.primary, origin, destination, socket.IPPROTO_UDP)
                assert owner and owner['stamp'] >> 62 == tag and owner['cookie'] == socket_cookie(client)
            decision = fixture.maps['HOST_SK_DECISIO']
            assert wg.dns.map_value(decision, struct.pack('=I', client.fileno()), decision[3]) is None
    delta = fixture.delta(before)
    assert delta['endpoint'] == 2 and delta['endpoint_hold'] >= 2 and delta['direct'] >= 2, delta
    return dict(gateway=delta, exchanges=evidence)


def fragments(fixture):
    before = fixture.counters('pass_fragment', 'endpoint_fragment', 'fragment_miss')
    native = udp_trial(fixture, LOCAL[0], (TARGET[0], DIRECT), 'native', fragment=True)
    relay = udp_trial(fixture, LOCAL[0], (TARGET[0], PROXY), 'proxy', fragment=True)
    delta = fixture.delta(before)
    assert delta['pass_fragment'] >= 1 and delta['endpoint_fragment'] >= 1 and delta['fragment_miss'] == 0, delta
    return dict(payload_bytes=2000, native=native, endpoint=relay, gateway=delta)


def ipv4_udp_frames(capture, source, targets):
    source = socket.inet_aton(source)
    destinations = {socket.inet_aton(address): address for address in targets}
    while select.select([capture], [], [], 0)[0]:
        frame, _, flags, address = capture.recvmsg(65586)
        assert not flags & socket.MSG_TRUNC, 'truncated UDP wire observation'
        if address[2] != 0 or frame[22:24] != b'\x08\x00':
            continue
        packet = frame[24:]
        if (len(packet) < 20 or packet[9] != socket.IPPROTO_UDP or packet[12:16] != source
                or packet[16:20] not in destinations):
            continue
        size, identity, fragment = struct.unpack_from('!HHH', packet, 2)
        header = (packet[0] & 15) * 4
        assert packet[0] >> 4 == 4 and 20 <= header < size <= len(packet)
        assert tun.checksum(packet[:header]) == 0
        yield (destinations[packet[16:20]], (identity, (fragment & 0x1fff) * 8, bool(fragment & 0x2000),
                                            size, struct.unpack_from('<BB4H', frame), packet[header:size]))


def large_udp_reply(fixture):
    assert os.sysconf('SC_PAGE_SIZE') == 4096
    fixture.mode('Direct')
    previous = fixture.primary
    external_mtu = 32000
    start = len(fixture.log.read_text())
    wg.ip('server', 'link', 'set', 'su', 'mtu', external_mtu)
    wg.ip('dut', 'link', 'set', 'dev', previous['device'], 'mtu', external_mtu)
    try:
        fixture.primary = fixture.binding(0, after=start, bounded=True)
        binding = fixture.primary
        assert binding['incarnation'] != previous['incarnation'] and binding['ifindex'] == previous['ifindex']
        assert binding['mtu'] == external_mtu and wg.links('server')['su']['mtu'] == external_mtu
        request, reply = os.urandom(53), os.urandom(24 * 1024)
        assert 4 * os.sysconf('SC_PAGE_SIZE') < len(reply) + 28 <= external_mtu
        assert binding['private_mtu'] < len(reply) + 28
        before = fixture.packets()
        with contextlib.ExitStack() as owned:
            with wg.dns.namespace('dut'):
                capture = owned.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)))
                capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512 * 1024)
                capture.setsockopt(263, 15, 1)  # SOL_PACKET, PACKET_VNET_HDR
                capture.bind((binding['device'], 0))
            client = wg.socket_at(owned, 'dut', (LOCAL[0], 0), socket.SOCK_DGRAM)
            peer = wg.socket_at(owned, 'server', (TARGET[0], 18106), socket.SOCK_DGRAM)
            peer.setsockopt(socket.IPPROTO_IP, 10, 2)  # IP_MTU_DISCOVER, IP_PMTUDISC_DO
            target = local(peer)
            send(client, request, target)
            payload, outbound = peer.recvfrom(65535)
            assert payload == request and outbound[0] == UPLINK[0]
            send(peer, reply, outbound)
            delivered, source = client.recvfrom(65535)
            assert delivered == reply and source == target, ('original socket missed exact UDP reassembly', source, len(delivered))

            wire = list(ipv4_udp_frames(capture, target[0], (UPLINK[0], LOCAL[0])))
            [carrier] = [row for address, row in wire if address == UPLINK[0]]
            _, offset, more, size, vnet, datagram = carrier
            assert (offset, more, size, vnet[1], vnet[3]) == (0, False, len(reply) + 28, 0, 0), carrier[:-1]
            assert struct.unpack_from('!HHH', datagram) == (target[1], outbound[1], len(reply) + 8)
            assert datagram[8:] == reply

            fragments = sorted((row for address, row in wire if address == LOCAL[0]), key=lambda item: item[1])
            assert len(fragments) >= 2 and len({row[0] for row in fragments}) == 1
            reassembled = bytearray()
            for index, (_, offset, more, size, vnet, data) in enumerate(fragments):
                assert offset == len(reassembled) and size <= binding['private_mtu'], (offset, size, binding)
                assert more == (index < len(fragments) - 1) and vnet[1] == vnet[3] == 0
                reassembled.extend(data)
            assert struct.unpack_from('!HHH', reassembled) == (target[1], local(client)[1], len(reply) + 8)
            assert reassembled[8:] == reply
            _, dropped = struct.unpack('=II', capture.getsockopt(263, 6, 8))  # PACKET_STATISTICS
            assert dropped == 0
        after = fixture.packets()
        assert after[0] > before[0] and after[1] >= before[1] + len(fragments)
        return dict(outer_mtu=external_mtu, private_mtu=binding['private_mtu'], carrier_bytes=carrier[3],
                    fragment_bytes=[fragment[3] for fragment in fragments], original_response_source=source,
                    response_bytes=len(reply), response_sha256=hashlib.sha256(reply).hexdigest())
    finally:
        start = len(fixture.log.read_text())
        wg.ip('dut', 'link', 'set', 'dev', previous['device'], 'mtu', previous['mtu'])
        wg.ip('server', 'link', 'set', 'su', 'mtu', previous['mtu'])
        fixture.primary = fixture.binding(0, after=start)
        fixture.mode('Rule')


def exchange_tcp(client, server):
    payload = os.urandom(53)
    client.sendall(payload)
    assert tun.exact(server, len(payload)) == payload
    server.sendall(payload[::-1])
    assert tun.exact(client, len(payload)) == payload[::-1]


def close_tcp(client, server):
    client.shutdown(socket.SHUT_WR)
    assert server.recv(1) == b''
    tail = os.urandom(32768)
    server.sendall(tail)
    server.shutdown(socket.SHUT_WR)
    assert tun.exact(client, len(tail)) == tail and client.recv(1) == b''
    assert client.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
    return hashlib.sha256(tail).hexdigest()


def tcp_lifetime(fixture):
    orig, old_peer, original_source = fixture.old_tcp
    before = fixture.counters('non_syn', 'endpoint', 'endpoint_hold', 'direct')
    tun_before = fixture.packets()
    exchange_tcp(orig, old_peer)
    assert local(orig) == original_source and fixture.packets() == tun_before
    assert fixture.delta(before)['non_syn'] > 0, 'preexisting TCP missed non-SYN continuation'
    fixture.mode('Direct')
    with contextlib.ExitStack() as owned:
        clients = []
        for port in (18106, 18107):
            client, server, arrived = wg.stream(owned, 'dut', (UPLINK[0], 0), (TARGET[0], port), b'')
            source, target = local(client), client.getpeername()[:2]
            assert (arrived == source) == (port == 18107), (port, source, arrived)
            exchange_tcp(client, server)
            row = tcp_owner(fixture, client, target, native=port == 18107)
            stamp = row['stamp']
            clients.append((client, server, source, target, stamp))
        latest = time.monotonic()
        fixture.reload('dport(18106, 18107) -> block(must)')
        time.sleep(max(0, latest + 36 - time.monotonic()))
        evidence = []
        for client, server, source, target, stamp in clients:
            packets = fixture.packets()
            exchange_tcp(client, server)
            live = tcp_owner(fixture, client, target, native=target[1] == 18107)
            tail = close_tcp(client, server)
            if target[1] == 18106:
                assert live['stamp'] == stamp, ('live Endpoint TCP changed ownership after idle', live, stamp)
                assert tcp_owner(fixture, client, target, native=False)['stamp'] == stamp, 'Endpoint FIN/TIME_WAIT lost the hold'
                assert all(new > old for old, new in zip(packets, fixture.packets(), strict=True))
            else:
                assert live['stamp'] >= stamp, (source, target, stamp, live)
                assert fixture.packets() == packets
            expr = f'( sport = :{source[1]} and dport = :{target[1]} )'
            time_wait = wg.until(lambda: wg.inside('dut', 'ss', '-Htn', 'state', 'time-wait', expr).strip(),
                                 f'original application TCP tuple TIME_WAIT {source} {target}', timeout=3)
            evidence.append(dict(source=source, target=target, hold=live, tail_sha256=tail, time_wait=time_wait))
        with contextlib.ExitStack() as fresh:
            udp = wg.socket_at(fresh, 'dut', (UPLINK[0], 0), socket.SOCK_DGRAM)
            server = wg.socket_at(fresh, 'server', (TARGET[0], 18106), socket.SOCK_DGRAM)
            no_udp_reply(udp, local(server), b'new flow after hold-policy reload')
            assert not select.select([server], [], [], 0)[0], 'new flow bypassed reloaded Block'
    fixture.reload('')
    reconnect = tcp_reconnect(fixture)
    fixture.mode('Rule')
    return dict(preexisting=original_source, idle_seconds=time.monotonic() - latest,
                exchanges=evidence, reconnect=reconnect, gateway=fixture.delta(before))


def tcp_reconnect(fixture):
    with contextlib.ExitStack() as owned:
        with contextlib.ExitStack() as reservation:
            temporary = wg.socket_at(reservation, 'dut', (UPLINK[0], 0), socket.SOCK_STREAM)
            source = local(temporary)
        client = wg.socket_at(owned, 'dut', source, socket.SOCK_STREAM)
        native = wg.socket_at(owned, 'server', (TARGET[0], 18107), socket.SOCK_STREAM)
        endpoint = wg.socket_at(owned, 'server', (TARGET[0], 18106), socket.SOCK_STREAM)
        for listener in (native, endpoint):
            listener.listen(1)
        client.connect(local(native))
        accepted, peer = native.accept()
        with accepted:
            accepted.settimeout(wg.SOCKET_TIMEOUT)
            assert peer == source
            exchange_tcp(client, accepted)
            original = client.getsockopt(socket.SOL_SOCKET, 57, 8)
            tcp_disconnect(client, accepted)
        before = fixture.packets()
        client.connect(local(endpoint))
        accepted, peer = endpoint.accept()
        with accepted:
            accepted.settimeout(wg.SOCKET_TIMEOUT)
            assert local(client) == source and client.getsockopt(socket.SOL_SOCKET, 57, 8) == original
            assert peer != source and peer[0] == UPLINK[0]
            exchange_tcp(client, accepted)
            close_tcp(client, accepted)
        assert all(new > old for old, new in zip(before, fixture.packets(), strict=True))
        return dict(original_socket_cookie=int.from_bytes(original, sys.byteorder), source=source,
                    first_destination=local(native), second_destination=local(endpoint), second_peer=peer)


def tcp_disconnect(client, peer):
    addr = wg.dns.C.create_string_buffer(struct.pack('=H14x', socket.AF_UNSPEC), 16)
    assert wg.dns.probe.libc.connect(client.fileno(), addr, len(addr)) == 0, wg.dns.C.get_errno()
    try:
        assert peer.recv(1) == b''
    except ConnectionResetError:
        pass


def tcp_same_tuple_reconnect(fixture):
    with contextlib.ExitStack() as owned:
        with contextlib.ExitStack() as reservation:
            temporary = wg.socket_at(reservation, 'dut', (UPLINK[0], 0), socket.SOCK_STREAM)
            source = local(temporary)
        client = wg.socket_at(owned, 'dut', source, socket.SOCK_STREAM)
        listener = wg.socket_at(owned, 'server', (TARGET[0], 0), socket.SOCK_STREAM)
        listener.listen(2)
        target = local(listener)
        fixture.reload(f'dport({target[1]}) -> direct(must)')
        try:
            initial = fixture.packets()
            client.connect(target)
            native, peer = listener.accept()
            with native:
                native.settimeout(wg.SOCKET_TIMEOUT)
                assert local(client) == peer == source and client.getpeername()[:2] == target
                exchange_tcp(client, native)
                assert fixture.packets() == initial
                original = socket_cookie(client)
                direct = tcp_owner(fixture, client, target, native=True)
                tcp_disconnect(client, native)
            fixture.reload(f'dport({target[1]}) -> proxy')
            still_held = fixture.direct_tcp(fixture.primary, source, target)
            assert still_held and still_held['stamp'] == direct['stamp'], ('old Direct ownership must survive until reconnect', direct, still_held)
            before = fixture.packets()
            counters = fixture.counters('endpoint', 'direct')
            client.connect(target)
            replacement, peer = listener.accept()
            with replacement:
                replacement.settimeout(wg.SOCKET_TIMEOUT)
                assert local(client) == source and client.getpeername()[:2] == target
                assert socket_cookie(client) == original
                assert peer[0] == PROXY_SOURCE[0], ('identical reconnect still used the old Direct route', source, target, peer)
                exchange_tcp(client, replacement)
                close_tcp(client, replacement)
            successor = tcp_owner(fixture, client, target, native=False)
            assert successor['stamp'] != direct['stamp']
            assert all(new > old for old, new in zip(before, fixture.packets(), strict=True))
            delta = fixture.delta(counters)
            assert delta == {'endpoint': 1, 'direct': 0}, delta
            return dict(source=source, target=target, original_socket_cookie=original, direct_stamp=direct['stamp'],
                        endpoint=successor, peer=peer, gateway=delta)
        finally:
            fixture.reload('')


def socket_cookie(sock):
    cookie, = struct.unpack('=Q', sock.getsockopt(socket.SOL_SOCKET, 57, 8))  # SO_COOKIE
    assert cookie
    return cookie


def tcp_owner(fixture, client, target, *, native):
    binding, source = fixture.primary, local(client)
    direct = fixture.direct_tcp(binding, source, target)
    hold = fixture.hold(binding, source, target, socket.IPPROTO_TCP)
    if native:
        assert direct and hold is None, (source, target, direct, hold)
        assert fixture.meta(binding, source, target, socket.IPPROTO_TCP) is None
        owner = direct
    else:
        assert direct is None and hold and hold['stamp'] >> 62 == 2, (source, target, direct, hold)
        owner = fixture.meta(binding, source, target, socket.IPPROTO_TCP)
    assert owner and owner['cookie'] == socket_cookie(client), (source, target, owner)
    return owner


def capacity_tcp_listeners(owned):
    direct = wg.socket_at(owned, 'server', (TARGET[0], 18107), socket.SOCK_STREAM)
    proxy = wg.socket_at(owned, 'server', (TARGET[0], 18111), socket.SOCK_STREAM)
    for listener in (direct, proxy):
        listener.listen(8)
    return direct, proxy


def capacity_tcp_pair(owned, listener):
    # The caller enters the DUT once for the entire batch. Peer FDs keep their own namespace.
    client = owned.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    client.settimeout(wg.SOCKET_TIMEOUT)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 8)
    client.bind((UPLINK[0], 0))
    client.connect(local(listener))
    peer, _ = listener.accept()
    owned.enter_context(peer)
    peer.settimeout(wg.SOCKET_TIMEOUT)
    return client, peer


def require_tcp_capacity_refusal(fixture, listener, reason):
    target = local(listener)
    counter = {18107: 'native_syn', 18111: 'proxy_syn'}[target[1]]
    ingress_before = nft_count(counter, 'server')
    before = fixture.counters('hold_full', 'tcp_direct_full', 'direct_unrecorded')
    packets = fixture.packets()
    with contextlib.ExitStack() as owned:
        client = wg.socket_at(owned, 'dut', (UPLINK[0], 0), socket.SOCK_STREAM)
        client.settimeout(0.8)
        source = local(client)
        try:
            client.connect(target)
        except TimeoutError:
            pass
        else:
            raise AssertionError(('TCP capacity refusal reached its real listener', source, target, reason))
    assert not select.select([listener], [], [], 0)[0], (source, target, reason)
    assert nft_count(counter, 'server') == ingress_before, ('refused TCP SYN reached peer ingress', source, target)
    assert fixture.packets() == packets
    assert fixture.direct_tcp(fixture.primary, source, target) is None
    assert fixture.hold(fixture.primary, source, target, socket.IPPROTO_TCP) is None
    delta = fixture.delta(before)
    assert delta[reason] > 0 and all(count == 0 for name, count in delta.items() if name != reason), delta
    return dict(source=source, target=target, gateway=delta)


def dedicated_tcp_capacity(fixture):
    direct, hold = (fixture.maps[name] for name in ('HOST_DIRECT_TCP', 'HOST_HOLD'))
    assert occupancy(direct) == 0
    hold_before = occupancy(hold)
    with contextlib.ExitStack() as owned:
        inherited = resource.getrlimit(resource.RLIMIT_NOFILE)
        minimum = 2 * direct[4] + 256
        if 0 <= inherited[0] < minimum:
            hard = inherited[1] if inherited[1] == resource.RLIM_INFINITY else max(inherited[1], minimum)
            resource.setrlimit(resource.RLIMIT_NOFILE, (minimum, hard))
            owned.callback(resource.setrlimit, resource.RLIMIT_NOFILE, inherited)
        listener, proxy = capacity_tcp_listeners(owned)
        target = local(listener)
        before = fixture.counters('tcp_direct_full', 'hold_full', 'direct_unrecorded', 'endpoint', 'direct')
        packets = fixture.packets()
        with wg.dns.namespace('dut'):
            for index in range(direct[4]):
                if index % 128 == 0:
                    deadline()
                client, peer = capacity_tcp_pair(owned, listener)
                assert peer.getpeername()[:2] == local(client)
                if index == 0:
                    first = client, peer
        assert occupancy(direct) == direct[4] and occupancy(hold) == hold_before
        assert fixture.packets() == packets
        first_owner = tcp_owner(fixture, first[0], target, native=True)
        last_owner = tcp_owner(fixture, client, target, native=True)
        assert first_owner['stamp'] != last_owner['stamp']
        refused = require_tcp_capacity_refusal(fixture, listener, 'tcp_direct_full')
        exchange_tcp(*first)
        exchange_tcp(client, peer)
        assert tcp_owner(fixture, first[0], target, native=True)['stamp'] == first_owner['stamp']
        assert tcp_owner(fixture, client, target, native=True)['stamp'] == last_owner['stamp']
        assert fixture.packets() == packets

        with wg.dns.namespace('dut'):
            proxied, far = capacity_tcp_pair(owned, proxy)
        assert far.getpeername()[0] == PROXY_SOURCE[0]
        exchange_tcp(proxied, far)
        proxy_owner = tcp_owner(fixture, proxied, local(proxy), native=False)
        hold_after = occupancy(hold)
        assert occupancy(direct) == direct[4] and hold_after == hold_before + 1
        assert all(new > old for old, new in zip(packets, fixture.packets(), strict=True))
        delta = fixture.delta(before)
        assert delta['direct'] >= direct[4] and delta['tcp_direct_full'] > 0 and delta['endpoint'] == 1, delta
        assert delta['hold_full'] == delta['direct_unrecorded'] == 0
        return dict(recorded_tcp_entries=direct[4], host_hold_before=hold_before, host_hold_after=hold_after,
                    retained_first=first_owner, retained_last=last_owner, endpoint_proxy=proxy_owner, refused=refused,
                    gateway=delta)


def send_fill(sock, addresses, length):
    destinations = ((address, port) for address in addresses for port in range(20000, 60000))
    for number, destination in zip(range(length), destinations):
        if number % 2048 == 0:
            deadline()
        send(sock, b'ordinary capacity datagram', destination)


def capacity(fixture):
    meta, hold = fixture.maps['HOST_FLOW_META'], fixture.maps['HOST_HOLD']
    program, interfaces, index = wg.physical()
    lan_hold = wg.named_map(program, 'honk_gw_hold')
    lan_realm = wg.realm(interfaces, index)
    assert lan_hold[0] != hold[0] and lan_hold[1:5] == (1, 48, 16, 65536)
    before = fixture.counters('meta_full', 'hold_full', 'direct_unrecorded', 'tcp_direct_full')
    # Capacity datagrams have their own limits. Keep this workload below the unrelated kernel CT limit.
    fill_addresses = ', '.join((FILL_META, *FILL_HOLD))
    wg.inside('dut', 'nft', '-f', '-', input=f'''add chain inet host_ci fill_output {{
        type filter hook output priority raw; policy accept;
    }}
    add rule inet host_ci fill_output ip daddr {{ {fill_addresses} }} udp dport 20000-59999 notrack
    ''')
    with contextlib.ExitStack() as owned:
        lan, far, peer = wg.stream(owned, 'client', (wg.LAN[0], 0), (TARGET[0], 0), b'')
        assert peer[0] == UPLINK[0] and peer != local(lan)
        exchange_tcp(lan, far)
        lan_source, lan_target = local(lan), lan.getpeername()[:2]
        lan_stamp = wg.hold_value(lan_hold, lan_realm, lan_source, lan_target, socket.IPPROTO_TCP)
        assert lan_stamp
        lan_before = occupancy(lan_hold)
        fill = wg.socket_at(owned, 'dut', (UPLINK[0], 0), socket.SOCK_DGRAM)
        original = wg.socket_at(owned, 'dut', (UPLINK[0], 0), socket.SOCK_DGRAM)
        cached_direct, cached_proxy = (TARGET[0], DIRECT), (TARGET[0], PROXY)
        udp_trial(fixture, UPLINK[0], cached_direct, 'native', sock=original)
        udp_trial(fixture, UPLINK[0], cached_proxy, 'proxy', sock=original)
        held = fixture.hold(fixture.primary, local(original), cached_proxy, socket.IPPROTO_UDP)['stamp']
        send_fill(fill, (FILL_META,), meta[4] + 8)
        assert occupancy(meta) == meta[4], 'live Host metadata map did not saturate'
        assert fixture.delta(before)['meta_full'] > 0
        new_client = wg.socket_at(owned, 'dut', (UPLINK[0], 0), socket.SOCK_DGRAM)
        denied = os.urandom(37)
        denied_at = fixture.counters('meta_full')
        no_udp_reply(new_client, cached_proxy, denied)
        assert fixture.delta(denied_at)['meta_full'] == 1
        assert not any(row.get('payload') == denied.hex() for row in fixture.events())
        assert fixture.hold(fixture.primary, local(new_client), cached_proxy, socket.IPPROTO_UDP) is None
        meta_control = udp_trial(fixture, UPLINK[0], cached_direct, 'native', sock=new_client)
        udp_trial(fixture, UPLINK[0], cached_proxy, 'proxy', sock=original)
        direct_tcp, proxy_tcp = capacity_tcp_listeners(owned)
        tcp_target = local(direct_tcp)
        with wg.dns.namespace('dut'):
            existing_tcp, existing_peer = capacity_tcp_pair(owned, direct_tcp)
        assert existing_peer.getpeername()[:2] == local(existing_tcp)
        existing_owner = tcp_owner(fixture, existing_tcp, tcp_target, native=True)

        started = time.monotonic()
        send_fill(fill, FILL_HOLD, hold[4] + 16)
        assert occupancy(hold) == hold[4], 'live HOST_HOLD did not saturate'
        lan_after_host_fill = occupancy(lan_hold)
        assert 0 < lan_after_host_fill <= lan_before
        assert time.monotonic() - started < 25, 'capacity workload exceeded the hold lifetime margin'
        new_target = (tun.TARGETS[4][1], DIRECT)
        unrecorded_at = fixture.counters('direct_unrecorded', 'hold_full')
        unrecorded = udp_trial(fixture, UPLINK[0], new_target, 'native', sock=new_client)
        assert fixture.delta(unrecorded_at)['direct_unrecorded'] == 1
        assert fixture.hold(fixture.primary, local(new_client), new_target, socket.IPPROTO_UDP) is None
        denied = os.urandom(37)
        no_udp_reply(new_client, cached_proxy, denied)
        assert fixture.delta(unrecorded_at)['hold_full'] == 1
        assert not any(row.get('payload') == denied.hex() for row in fixture.events())
        udp_trial(fixture, UPLINK[0], cached_direct, 'native', sock=original)
        udp_trial(fixture, UPLINK[0], cached_proxy, 'proxy', sock=original)
        assert fixture.hold(fixture.primary, local(original), cached_proxy, socket.IPPROTO_UDP)['stamp'] == held

        fixture.reload(f'dip({new_target[0]}/32) && dport({DIRECT}) -> block(must)')
        assert occupancy(hold) == hold[4], 'hold pressure changed before reclassification'
        reclassified_at = fixture.counters('direct_unrecorded', 'hold_full')
        denied = os.urandom(37)
        no_udp_reply(new_client, new_target, denied)
        assert not any(row.get('payload') == denied.hex() for row in fixture.events())
        assert fixture.delta(reclassified_at) == {'direct_unrecorded': 0, 'hold_full': 1}
        assert fixture.hold(fixture.primary, local(new_client), new_target, socket.IPPROTO_UDP) is None

        assert occupancy(hold) == hold[4], 'HOST_HOLD is not full at TCP admission'
        packets = fixture.packets()
        tcp_before = fixture.counters('direct', 'direct_unrecorded', 'hold_full', 'tcp_direct_full')
        with wg.dns.namespace('dut'):
            admitted_tcp, admitted_peer = capacity_tcp_pair(owned, direct_tcp)
        assert admitted_peer.getpeername()[:2] == local(admitted_tcp)
        admitted_owner = tcp_owner(fixture, admitted_tcp, tcp_target, native=True)
        exchange_tcp(existing_tcp, existing_peer)
        exchange_tcp(admitted_tcp, admitted_peer)
        assert tcp_owner(fixture, existing_tcp, tcp_target, native=True)['stamp'] == existing_owner['stamp']
        assert admitted_owner['stamp'] != existing_owner['stamp'] and fixture.packets() == packets
        tcp_delta = fixture.delta(tcp_before)
        assert tcp_delta['direct'] > 0 and tcp_delta['direct_unrecorded'] == tcp_delta['hold_full'] == tcp_delta['tcp_direct_full'] == 0
        refused_tcp = require_tcp_capacity_refusal(fixture, proxy_tcp, 'hold_full')
        exchange_tcp(lan, far)
        assert wg.hold_value(lan_hold, lan_realm, lan_source, lan_target, socket.IPPROTO_TCP) == lan_stamp
        fresh_source, fresh_target = wg.trial('lan-endpoint-while-host-hold-full', 'client', TARGET[0],
                                              socket.SOCK_STREAM, 'endpoint')
        fresh_stamp = wg.hold_value(lan_hold, lan_realm, fresh_source, fresh_target, socket.IPPROTO_TCP)
        assert fresh_stamp and fresh_stamp != lan_stamp
        assert occupancy(hold) == hold[4]
    return dict(host_meta_entries=meta[4], host_hold_entries=hold[4], gateway=fixture.delta(before),
                metadata_pressure_direct=meta_control, hold_pressure_unrecorded=unrecorded,
                tcp_under_host_hold_pressure=dict(existing=existing_owner, admitted=admitted_owner,
                                                   refused_proxy=refused_tcp, gateway=tcp_delta),
                lan_under_host_hold_pressure=dict(map_id=lan_hold[0], entries_before=lan_before,
                                                   entries_after_host_fill=lan_after_host_fill,
                                                   retained_stamp=lan_stamp, fresh_stamp=fresh_stamp))


def wire_udp(client, server, payload, *, reply=True):
    target = local(server)
    send(client, payload, target)
    received, source = server.recvfrom(65535)
    assert received == payload
    if reply:
        send(server, payload[::-1], source)
        response, remote = client.recvfrom(65535)
        assert response == payload[::-1] and remote[:2] == target, (remote, target)
    return source[:2]


def binding_udp(fixture, binding, address, target, action):
    server_ns = 'wgpeer' if binding['device'] == HOSTS[2] else 'server'
    before = fixture.packets(binding)
    with contextlib.ExitStack() as owned:
        server = wg.socket_at(owned, server_ns, target, socket.SOCK_DGRAM)
        client = wg.socket_at(owned, 'dut', (address, 0), socket.SOCK_DGRAM)
        peer = wire_udp(client, server, os.urandom(53))
        origin = local(client)
    after = fixture.packets(binding)
    if action == 'native':
        assert peer == origin and after == before, (origin, peer, before, after)
    else:
        assert action == 'endpoint' and peer[0] == address and peer != origin, (origin, peer)
        assert all(new > old for old, new in zip(before, after, strict=True)), (before, after)
    return dict(device=binding['device'], origin=origin, target=target, remote=peer, tun_before=before, tun_after=after)


def coexistence(fixture):
    wg.wait_log(fixture.process, fixture.log, 'Host egress waiting_link')
    assert HOSTS[2] not in wg.links(), 'unexpected Host WAN before fixture link creation'
    start = len(fixture.log.read_text())
    wan_wg(*fixture.wan_keys)
    physical, maps, index = wg.physical()
    assert wg.links()['dut0']['num_rx_queues'] == maps['honk_xdp_count'][4] - 4 == 2
    assert wg.tcx('dut', 'wg0')[0][2] == 'honk_aux_gw'
    nat = nft_count('masquerade')
    with contextlib.ExitStack() as owned:
        server = wg.socket_at(owned, 'server', (wg.STATIC, 0), socket.SOCK_DGRAM)
        client = wg.socket_at(owned, 'client', (wg.LAN[0], 0), socket.SOCK_DGRAM)
        peer = wire_udp(client, server, b'XDP-LAN forwarding and masquerade')
        assert peer == (UPLINK[0], local(client)[1])
    assert nft_count('masquerade') == nat + 1
    wg.trial('auxiliary-wireguard-coexists', 'wgpeer', TARGET[0], socket.SOCK_DGRAM, 'endpoint')
    fixture.secondary = fixture.binding(1)
    assert len(fixture.namespace_inodes) == 5
    fixture.wan = fixture.binding(2, after=start)
    assert wg.inside('dut', 'cat', '/sys/class/net/wwan0/type').strip() == '65534'
    assert wg.links()[HOSTS[1]]['linkinfo']['info_kind'] == 'vlan'
    v4 = udp_trial(fixture, UPLINK[0], (TARGET[0], DIRECT), 'native')
    vlan_wires, wg_wires = [], []
    for lane in (0, 1):
        vlan_wires.append(binding_udp(fixture, fixture.secondary, VLAN[lane], (VLAN_PEER[lane], 18106), 'endpoint'))
        wg_wires.append(binding_udp(fixture, fixture.wan, WG[lane], (WG_PEER[lane], 18106), 'endpoint'))
    hold, realm = wg.named_map(physical, 'honk_gw_hold'), wg.realm(maps, index)
    assert realm not in [state['realm'] for state in (fixture.primary, fixture.secondary, fixture.wan)]
    fixture.physical_session = fixture.owned.enter_context(contextlib.ExitStack())
    fixture.progress = fixture.physical_session.enter_context(wg.physical_progress(hold, realm))
    fixture.progress('physical-flow-with-three-host-egresses')
    return dict(physical_program=physical, physical_realm=realm, lan_masquerade=peer, primary_direct=v4,
                vlan=vlan_wires, wireguard=wg_wires)


def offload(fixture, lane):
    inner = fixture.primary['tun']
    output = fixture.work / f'tcp{6 if lane else 4}-offload.trace'
    features = wg.inside('dut', 'ethtool', '-k', inner)
    for name in ('tx-checksum-ip-generic', 'tx-tcp-segmentation', 'tx-tcp6-segmentation'):
        assert re.search(rf'^\s*{name}: on\b', features, re.M), (name, features)
    events = [('net_dev_start_xmit', (inner,)), ('netif_rx_entry', (inner,)),
              ('netif_receive_skb_entry', (inner,))]
    with wg.trace_guest(fixture.state, events) as trace:
        try:
            wire = tcp_trial(fixture, UPLINK[lane], (TARGET[lane], PROXY), 'proxy', size=256 * 1024)
        finally:
            observed = wg.read_trace(trace, output)
    protocol = 0x86dd if lane else 0x0800
    gso_type = 1 << (4 if lane else 0)
    phases = {'application_to_tun': [], 'tun_to_application': []}
    for event, device, info in observed:
        assert device == inner
        if info.get('protocol') != protocol or info.get('len', 0) <= fixture.primary['mtu']:
            continue
        assert info['ip_summed'] == 3 and info['gso_size'] > 0 and info['gso_type'] & gso_type, info
        phase = 'application_to_tun' if event == 'net_dev_start_xmit' else 'tun_to_application'
        phases[phase].append(info)
    assert all(phases.values()), ('missing live checksum-partial TCP GSO in one direction', output)
    return dict(wire=wire, offloads={direction: max(rows, key=lambda item: item['len']) for direction, rows in phases.items()})


def epoch(fixture):
    return wg.epoch(fixture.maps, HOST_DNS_REALM)


def fact(fixture, address, realm=HOST_DNS_REALM):
    generation = wg.epoch(fixture.maps, realm)
    if generation:
        return map_read(fixture.maps['dns_facts'], struct.pack('=QII', generation, realm, 0) + canonical(address))


def pending_dns(owned, upstream, ns, source, target, name, address, *, tcp=False):
    nonce, = struct.unpack('!H', os.urandom(2))
    query = tun.dns_question(name, 1, nonce)
    if tcp:
        client = tcp_at(owned, ns, (source, 0), target)
        client.sendall(struct.pack('!H', len(query)) + query)
    else:
        client = wg.socket_at(owned, ns, (source, 0), socket.SOCK_DGRAM)
        send(client, query, target)
    forwarded, peer = upstream.recvfrom(65535)
    alias, kind, end = tun.dns_parse(forwarded)
    assert (alias, kind) == (name, (1, 1)), (name, alias, kind)
    response = (forwarded[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + forwarded[12:end]
                + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 120, 4) + socket.inet_aton(address))
    return client, peer, response, query


def dns_exchange(owned, upstream, ns, source, target, name, address, *, tcp=False):
    client, peer, response, query = pending_dns(owned, upstream, ns, source, target, name, address, tcp=tcp)
    send(upstream, response, peer)
    if tcp:
        count, = struct.unpack('!H', tun.exact(client, 2))
        reply = tun.exact(client, count)
    else:
        reply, origin = client.recvfrom(65535)
        assert origin[:2] == target, (origin, target)
    tun.verify_dns(reply, query, address)
    return local(client)


def offline(binding):
    def check():
        links = wg.links()
        return binding['tun'] not in links and (binding['device'] not in links or not wg.tcx('dut', binding['device'], attach_type=TCX_EGRESS))
    wg.until(check, f'retirement of Host link {binding["device"]} and {binding["tun"]}')


def dns_scopes(fixture):
    active = epoch(fixture)
    assert active > 0
    target = '198.51.100.40'
    before = fixture.counters('dns_direct')
    with contextlib.ExitStack() as owned:
        upstream = wg.socket_at(owned, 'server', (SERVER, 25353), socket.SOCK_DGRAM)
        transparent_at = fixture.packets()
        dns_exchange(owned, upstream, 'dut', UPLINK[0], (TARGET[0], 53), 'transparent.host-ci.test', target)
        assert all(new > old for old, new in zip(transparent_at, fixture.packets(), strict=True))
        wg.until(lambda: fact(fixture, target), 'transparent Host DNS projection')
        cross_link = binding_udp(fixture, fixture.secondary, VLAN[0], (target, 18102), 'native')
        assert fixture.delta(before)['dns_direct'] >= 1
        for transport, address in [('udp', TARGET[0]), ('tcp', '198.51.100.41')]:
            dns_exchange(owned, upstream, 'dut', '127.0.0.1', ('127.0.0.1', 53),
                         transport + '-loopback.host-ci.test', address, tcp=transport == 'tcp')
            wg.until(lambda: fact(fixture, address), f'loopback {transport} Host DNS projection')
        foreign = '198.51.100.42'
        for kind in ('udp', 'tcp'):
            dns_exchange(owned, upstream, 'server', VLAN_PEER[0], (VLAN[0], 53), kind + '-remote.host-ci.test', foreign,
                         tcp=kind == 'tcp')
        assert fact(fixture, foreign) is None, 'nonloopback bound peer published a Host fact'
        physical, maps, index = wg.physical()
        assert physical and maps['dns_facts'] == fixture.maps['dns_facts']
        assert fact(fixture, target, wg.realm(maps, index)) is None
        delayed = '198.51.100.43'
        pending, remote, response, _ = pending_dns(owned, upstream, 'dut', VLAN[0], ('198.51.100.44', 53),
                                                  'withheld.host-ci.test', delayed)
        old_policy = binding_udp(fixture, fixture.secondary, VLAN[0], (VLAN_PEER[0], 18110), 'native')
        mtu = fixture.secondary['mtu']
        wg.ip('dut', 'link', 'set', HOSTS[1], 'down')
        offline(fixture.secondary)
        assert epoch(fixture) == active and fact(fixture, TARGET[0]), 'single binding loss withdrew shared active facts'
        wg.late_reply(upstream, remote, local(upstream), payload=response)
        pending.settimeout(0.8)
        try:
            data = pending.recv(65535)
        except TimeoutError:
            pass
        else:
            raise AssertionError(('retired binding received a delayed DNS response', data))
        assert fact(fixture, delayed) is None, 'retired binding published a delayed DNS response'
        fixture.progress('physical-flow-while-host-vlan-down')
        fixture.reload('dport(18110) -> block(must)')
        assert epoch(fixture) > 0 and fixture.binding(0)['incarnation'] == fixture.primary['incarnation']
        dns_exchange(owned, upstream, 'dut', UPLINK[0], (TARGET[0], 53), 'fresh.host-ci.test', delayed)
        wg.until(lambda: fact(fixture, delayed), 'fresh surviving Host binding DNS projection')
        start = len(fixture.log.read_text())
        wg.ip('dut', 'link', 'set', HOSTS[1], 'up')
        returned = fixture.binding(1, after=start)
        assert returned['incarnation'] != fixture.secondary['incarnation'] and returned['mtu'] == mtu
        fixture.secondary = returned
        listener = wg.socket_at(owned, 'server', (VLAN_PEER[0], 18110), socket.SOCK_DGRAM)
        client = wg.socket_at(owned, 'dut', (VLAN[0], 0), socket.SOCK_DGRAM)
        tun_before = fixture.packets(returned)
        no_udp_reply(client, local(listener), b'policy committed while this Host egress was down')
        assert fixture.packets(returned)[0] > tun_before[0]
        assert not select.select([listener], [], [], 0)[0], 'rebound egress used the old native policy'
    return dict(active_epoch=active, cross_link=cross_link, retired_query_ip=delayed, foreign_ip=foreign,
                old_vlan_policy=old_policy, surviving_epoch=epoch(fixture), gateway=fixture.delta(before))


def broadcast_member(root, address):
    identity = wg.slot(root, 0)
    assert identity
    probe = wg.dns.probe
    fd = probe.bpf(14, probe.Id(id=identity))
    try:
        info = wg.dns.info(fd, 40)
        kind, observed, key, value, limit, flags = struct.unpack_from('=6I', info)
        assert (kind, observed, key, value, limit) == (1, identity, 4, 4, 64)
        assert info.raw[24:40].rstrip(b'\0') == b'honk_host_bcast'
        member = map_read((identity, kind, key, value, limit, flags), socket.inet_aton(address))
        assert member in (None, struct.pack('=I', 1))
        return identity, member is not None
    finally:
        os.close(fd)


def sibling_broadcast_refresh(fixture):
    bindings = [fixture.binding(index) for index in range(len(HOSTS))]
    roots = [wg.named_map(state['outer_link'][1], 'honk_bcast_root') for state in bindings]
    assert all(root[1:5] == (12, 4, 4, 1) for root in roots)
    assert len({root[0] for root in roots}) == len(bindings)
    address, broadcast = '10.88.15.1/24', '10.88.15.255'
    initial = [broadcast_member(root, broadcast) for root in roots]
    assert not any(present for _, present in initial)

    def changed(previous, expected):
        current = [broadcast_member(root, broadcast) for root in roots]
        if all(present == expected and identity != old[0] for (identity, present), old in zip(current, previous, strict=True)):
            return current

    with contextlib.ExitStack() as owned:
        client, server, peer = wg.stream(owned, 'dut', (UPLINK[0], 0), (TARGET[0], 18106), b'')
        target = client.getpeername()[:2]
        assert peer[0] == UPLINK[0] and peer != local(client)
        exchange_tcp(client, server)
        owner = tcp_owner(fixture, client, target, native=False)
        wg.ip('dut', 'addr', 'add', address, 'brd', broadcast, 'dev', HOSTS[1])
        added = wg.until(lambda: changed(initial, True), 'Host broadcast map did not publish the sibling address')
        assert [fixture.binding(index) for index in range(len(HOSTS))] == bindings
        exchange_tcp(client, server)
        assert tcp_owner(fixture, client, target, native=False) == owner
        wg.ip('dut', 'addr', 'del', address, 'dev', HOSTS[1])
        removed = wg.until(lambda: changed(added, False), 'Host broadcast map retained a removed sibling address')
        assert [fixture.binding(index) for index in range(len(HOSTS))] == bindings
        exchange_tcp(client, server)
        assert tcp_owner(fixture, client, target, native=False) == owner
        close_tcp(client, server)
    return dict(broadcast=broadcast, roots=[root[0] for root in roots],
                snapshots=[[identity for identity, _ in rows] for rows in (initial, added, removed)],
                retained_binding=bindings[0]['incarnation'], tcp_stamp=owner['stamp'])


def topology_rebind(fixture):
    progress = fixture.progress
    progress('physical-flow-before-host-ifindex-churn')
    previous = fixture.binding(2)
    with contextlib.ExitStack() as owned:
        probe = wg.dns.probe
        map_fd = probe.bpf(14, probe.Id(id=previous['devmap'][0]))
        owned.callback(os.close, map_fd)
        server = wg.socket_at(owned, 'wgpeer', (WG_PEER[0], 18106), socket.SOCK_DGRAM)
        client = wg.socket_at(owned, 'dut', (WG[0], 0), socket.SOCK_DGRAM)
        original = local(client)
        remote = wire_udp(client, server, b'old link retains one datagram', reply=False)
        assert remote != original
        stamp = fixture.hold(previous, original, local(server), socket.IPPROTO_UDP)
        assert stamp is not None
        reused = 'wreused'
        events = [('net_dev_queue', (reused,)), ('net_dev_start_xmit', (reused,)), ('netif_rx', (reused,))]
        with wg.trace_guest(fixture.state, events) as trace:
            try:
                wg.ip('dut', 'link', 'del', HOSTS[2])
                wg.ip('dut', 'link', 'add', 'name', reused, 'index', previous['ifindex'], 'type', 'wireguard')
                wg.ip('dut', 'link', 'set', reused, 'up')
                assert wg.links()[reused]['ifindex'] == previous['ifindex']
                assert not wg.tcx('dut', reused, attach_type=TCX_EGRESS)
                offline(previous)
                assert [wg.slot(previous['devmap'], key) for key in (0, 1)] == [None, None]
                wg.until(lambda: fixture.hold(previous, original, local(server), socket.IPPROTO_UDP) is None,
                         'retired execution tuple removed')
                incoming = nft_count('wg_underlay')
                send(server, b'delayed response for old binding', remote)
                wg.until(lambda: nft_count('wg_underlay') > incoming, 'delayed encrypted peer packet arrival')
                progress('physical-flow-during-unrelated-ifindex-reuse')
                start = len(fixture.log.read_text())
                wan_wg(*fixture.wan_keys, rebuild=True)
                fixture.wan = fixture.binding(2, after=start)
                assert fixture.wan['ifindex'] != previous['ifindex'] and fixture.wan['incarnation'] != previous['incarnation']
                peer = wire_udp(client, server, b'new binding never receives the old response')
                assert peer != original
                new = fixture.hold(fixture.wan, original, local(server), socket.IPPROTO_UDP)
                assert new and new['stamp'] != stamp['stamp']
                assert not select.select([client, server], [], [], 0.2)[0], 'unexpected duplicate or replay on fresh binding'
            finally:
                rows = wg.read_trace(trace, fixture.work / 'reused-ifindex.trace')
        assert not rows and not wg.tcx('dut', reused, attach_type=TCX_EGRESS), rows
        wg.ip('dut', 'link', 'del', reused)

    broadcast = sibling_broadcast_refresh(fixture)
    progress('physical-flow-after-sibling-broadcast-updates')
    previous = fixture.primary = fixture.binding(0)
    new_mac = '02:15:16:17:18:19'
    wg.ip('dut', 'link', 'set', 'dev', 'up', 'address', new_mac)
    wg.ip('server', 'neigh', 'replace', UPLINK[0], 'lladdr', new_mac, 'nud', 'permanent', 'dev', 'su')
    mac = wg.named_map(previous['return_link'][1], 'honk_host_mac')
    expected_mac = bytes.fromhex(new_mac.replace(':', '')) + b'\x02\x68'
    wg.until(lambda: map_read(mac, struct.pack('=I', 0)) == expected_mac, 'atomic return MAC update')
    assert fixture.binding(0) == previous, 'MAC-only change replaced its active binding'
    after_mac = udp_trial(fixture, UPLINK[0], (TARGET[0], PROXY), 'proxy')
    progress('physical-flow-after-host-mac-change')
    start = len(fixture.log.read_text())
    wg.ip('dut', 'link', 'set', 'dev', 'up', 'mtu', 1400)
    fixture.primary = fixture.binding(0, after=start)
    assert fixture.primary['incarnation'] != previous['incarnation'] and fixture.primary['mtu'] == 1400
    assert fixture.primary['tun_index'] != previous['tun_index'] and fixture.primary['ifindex'] == previous['ifindex']
    after_mtu = udp_trial(fixture, UPLINK[0], (TARGET[0], PROXY), 'proxy')
    progress('physical-flow-after-host-mtu-change')
    fixture.physical_session.close()
    return dict(previous_ifindex=previous['ifindex'], wan_ifindex=fixture.wan['ifindex'],
                broadcast=broadcast, mac=after_mac, mtu=after_mtu)


def private_delay(fixture):
    wg.command('modprobe', 'sch_netem')
    binding = fixture.primary
    device = binding['tun']

    def tc(*args):
        return wg.inside('dut', 'tc', *args)

    def scheduler(kind):
        rows = json.loads(tc('-s', '-j', 'qdisc', 'show', 'dev', device))
        [row] = rows
        assert row['kind'] == kind and row['root'] is True, row
        return row

    fifo_limit = scheduler('pfifo')['options']['limit']
    assert fifo_limit == int(wg.inside('dut', 'cat', f'/sys/class/net/{device}/tx_queue_len')) and fifo_limit >= 2

    def netem():
        row = scheduler('netem')
        assert row['handle'] == '20:' and row['options']['limit'] == fifo_limit
        return row

    with contextlib.ExitStack() as owned:
        tc('qdisc', 'replace', 'dev', device, 'root', 'handle', '20:', 'netem', 'delay', '100s', 'limit', str(fifo_limit))
        owned.callback(tc, 'qdisc', 'replace', 'dev', device, 'root', 'pfifo', 'limit', str(fifo_limit))
        with contextlib.ExitStack() as reservation:
            sock = wg.socket_at(reservation, 'dut', (UPLINK[0], 0), socket.SOCK_DGRAM)
            source = local(sock)
        destination = (TARGET[0], PROXY)
        before = fixture.counters('late_packet', 'endpoint', 'queue_capacity')
        stale, fresh = os.urandom(53), os.urandom(53)
        sent_at = time.monotonic_ns()
        first = named_probe(fixture, 'hostold', 'hostold', 'unconnected-udp', source[0], destination, stale, source[1], 'false')
        first_hold = fixture.hold(binding, source, destination, socket.IPPROTO_UDP)
        first_meta = fixture.meta(binding, source, destination, socket.IPPROTO_UDP)
        assert first_hold and first_meta
        assert (first_meta['pid'], first_meta['cookie'], first_meta['pname']) == (first['pid'], first['cookie'], 'hostold')
        queued = wg.until(lambda: (row if (row := netem())['qlen'] == 1 else None), 'private netem never queued the original skb')
        assert queued['backlog'] > 0 and fixture.delta(before)['late_packet'] == 0
        direct = udp_trial(fixture, source[0], (TARGET[0], DIRECT), 'native')
        key = flow_key(binding, source, destination, socket.IPPROTO_UDP)
        wg.until(lambda: fixture.hold(binding, source, destination, socket.IPPROTO_UDP) is None
                 and map_read(fixture.maps['HOST_FLOW_META'], key) is None,
                 'inactive tuple did not retire while its original skb remained in private netem', timeout=90)
        retired_at = time.monotonic_ns()
        assert retired_at - first_hold['last_seen'] > 61_000_000_000 and netem()['qlen'] == 1
        # Change new enqueue timing while the original skb retains its scheduled dequeue time.
        tc('qdisc', 'change', 'dev', device, 'root', 'handle', '20:', 'netem', 'delay', '0ms', 'limit', str(fifo_limit))
        unchanged = netem()
        assert (unchanged['qlen'], unchanged['backlog'], unchanged['drops']) == (1, queued['backlog'], queued['drops'])
        second = named_probe(fixture, 'hostnext', 'hostnext', 'unconnected-udp', source[0], destination, fresh, source[1])
        assert tuple(first['source']) == tuple(second['source']) == source and first['cookie'] != second['cookie']
        assert netem()['qlen'] == 1 and fixture.delta(before)['late_packet'] == 0
        second_meta = fixture.meta(binding, source, destination, socket.IPPROTO_UDP)
        assert second_meta and second_meta['stamp'] != first_meta['stamp']
        assert (second_meta['cookie'], second_meta['pid'], second_meta['pname']) == (second['cookie'], second['pid'], 'hostnext')
        fixture.echo(fresh, destination, 'proxy', source)
        wg.until(lambda: fixture.delta(before)['late_packet'] == 1 and netem()['qlen'] == 0,
                 'queued ordinary skb did not reach the late-packet filter', timeout=50)
        delivered_ns = time.monotonic_ns() - sent_at
        assert delivered_ns > 30_000_000_000
        assert fixture.meta(binding, source, destination, socket.IPPROTO_UDP) == second_meta
        assert not any(row.get('payload') == stale.hex() for row in fixture.events()), 'the late nonce reached a wire peer'
        drained = netem()
        assert fixture.delta(before)['queue_capacity'] == 0
    assert scheduler('pfifo')['options']['limit'] == fifo_limit
    restored = udp_trial(fixture, source[0], destination, 'proxy')
    return dict(elapsed_ns=delivered_ns, queued=queued, drained=drained, original=first_meta, successor=second_meta,
                direct=direct, restored=restored, gateway=fixture.delta(before))


def unsupported_devices(fixture):
    assert not fixture.mixed and fixture.process.returncode == 0
    wg.command('modprobe', '-a', 'ip_gre', 'ppp_generic')
    wg.ip('dut', 'link', 'add', 'hgre', 'type', 'gre', 'local', UPLINK[0], 'remote', SERVER)
    with contextlib.ExitStack() as owned:
        device = fixture.state / 'ppp'
        os.mknod(device, stat.S_IFCHR | 0o600, os.makedev(108, 0))
        owned.callback(device.unlink)
        with wg.dns.namespace('dut'):
            ppp = os.open(device, os.O_RDWR | os.O_CLOEXEC)
            owned.callback(os.close, ppp)
            unit, = struct.unpack('=i', fcntl.ioctl(ppp, 0xc004743e, struct.pack('=i', -1)))  # PPPIOCNEWUNIT
        names = (('hgre', 778), (f'ppp{unit}', 512))  # ARPHRD_IPGRE, ARPHRD_PPP
        outcomes = []
        for name, arphrd in names:
            wg.ip('dut', 'link', 'set', name, 'up')
            assert int(wg.inside('dut', 'cat', f'/sys/class/net/{name}/type').strip()) == arphrd
            fixture.config.write_text(fixture.text(hosts=(name,)))
            log = fixture.work / f'{name}-refused.log'
            process = wg.start_daemon(owned, fixture.binary, fixture.config, fixture.pins, log)

            def resolved():
                text = log.read_text()
                if process.poll() is not None or ('waiting_link' in text and name in text):
                    return text

            text = wg.until(resolved, f'specific Host framing refusal for {name}')
            assert 'Host egress cannot use loopback, PPP or GRE' in text and name in text, text
            assert not wg.tcx('dut', name, attach_type=TCX_EGRESS)
            assert 'Host egress active' not in text
            outcome = process.poll()
            if outcome is None:
                process.terminate()
                assert process.wait(timeout=10) == 0
            else:
                assert outcome > 0
            outcomes.append(dict(name=name, arphrd=arphrd, exit_code=process.returncode))
        assert cgroup_programs() == fixture.foreign
    return dict(devices=outcomes)


def last_link(fixture):
    active = epoch(fixture)
    assert active > 0
    for binding in (fixture.secondary, fixture.primary, fixture.wan):
        wg.ip('dut', 'link', 'set', 'dev', binding['device'], 'down')
        offline(binding)
        if binding != fixture.wan:
            assert epoch(fixture) == active
    wg.until(lambda: epoch(fixture) == 0, 'last Host egress did not withdraw shared DNS epoch')
    start = len(fixture.log.read_text())
    for device in HOSTS:
        wg.ip('dut', 'link', 'set', 'dev', device, 'up')
    fixture.primary, fixture.secondary, fixture.wan = (fixture.binding(index, after=start) for index in range(len(HOSTS)))
    rebound = wg.until(lambda: epoch(fixture), 'new Host authority was not published')
    assert rebound != active and fact(fixture, TARGET[0]) is None
    return dict(previous_epoch=active, active_epoch=rebound)


def udp_trial_without_daemon(fixture):
    with contextlib.ExitStack() as owned:
        client = wg.socket_at(owned, 'dut', (UPLINK[0], 0), socket.SOCK_DGRAM)
        destination = (TARGET[0], PROXY)
        payload = os.urandom(53)
        udp_peer_exchange(client, destination, payload)
        return fixture.echo(payload, destination, 'native', local(client))


def crash_cleanup(fixture):
    wg.trial('physical-flow-before-daemon-crash', 'client', TARGET[0], socket.SOCK_STREAM, 'endpoint')
    fixture.stopped(crash=True)
    with contextlib.ExitStack() as owned:
        client, peer, far = wg.stream(owned, 'client', (wg.LAN[0], 0), (TARGET[0], 0), b'')
        exchange_tcp(client, peer)
        assert far == (UPLINK[0], local(client)[1])
    recovered = udp_trial_without_daemon(fixture)
    return dict(native_after_crash=far, host_native_after_crash=recovered, cgroup=cgroup_programs())


def graceful(fixture):
    fixture.stopped()
    return dict(native_peer=udp_trial_without_daemon(fixture), cgroup=cgroup_programs())


STANDALONE = {
    'ct-reply': ct_reply,
    'ct-original-snat-rpf': ct_original,
    'process-identity': process_identity,
    'policy-modes-protocols': modes_and_protocols,
    'unconnected-udp': mixed_udp,
    'postrouting-fragments': fragments,
    'large-udp-return': large_udp_reply,
    'tcp-lifetime': tcp_lifetime,
    'tcp-same-tuple-reconnect': tcp_same_tuple_reconnect,
    'private-tun-delay': private_delay,
    'graceful-fd-cleanup': graceful,
    'unsupported-devices': unsupported_devices,
}
PRESSURE = {'tcp-direct-capacity': dedicated_tcp_capacity}
MIXED = {
    'coexistence': coexistence,
    'offload-tcp4': lambda fixture: offload(fixture, 0),
    'offload-tcp6': lambda fixture: offload(fixture, 1),
    'binding-shared-dns': dns_scopes,
    'binding-recreation': topology_rebind,
    'last-binding': last_link,
    'real-map-capacity': capacity,
    'crash-fd-cleanup': crash_cleanup,
}


def gate(value, path):
    def timed_out(signum, _):
        raise TimeoutError(f'Host guest deadline: {signal.Signals(signum).name}')

    signal.signal(signal.SIGTERM, timed_out)
    assert not any(Path('/run/netns').iterdir())
    work = Path(tempfile.mkdtemp(dir=path.parent, prefix='host-daemon.'))
    record('host-guest', output=str(work), lane=value['lane'], source=value['source'],
           sha256=value['hashes'][value['daemon']], selection=value['selection'])
    selected = SELECTIONS[value['selection']]
    cases = [case for case in (*STANDALONE, *PRESSURE, *MIXED) if selected is None or case in selected]
    assert cases and (selected is None or tuple(cases) == selected), (selected, cases)
    results = {case: {'status': 'NOT_RUN'} for case in cases}
    result_path = work / 'results.json'

    def save():
        result_path.write_text(json.dumps(results, indent=2) + '\n')

    save()
    failures = []
    try:
        for profile, matrix in (('standalone', STANDALONE), ('capacity', PRESSURE), ('mixed', MIXED)):
            current = tuple(case for case in cases if case in matrix)
            if not current:
                continue
            cgroup_before = cgroup_programs()
            with contextlib.ExitStack() as owned:
                fixture = Router(owned, value['daemon'], work / profile, matrix is MIXED)
                if 'process-identity' in current:
                    fixture.precreated = [wg.socket_at(owned, 'dut', (source, 0), socket.SOCK_DGRAM) for source in UPLINK]
                    for client, address in zip(fixture.precreated, TARGET, strict=True):
                        client.connect((address, PNAME))
                if 'tcp-lifetime' in current:
                    fixture.old_tcp = wg.stream(owned, 'dut', (UPLINK[0], 0), (TARGET[0], 18109), b'')
                    exchange_tcp(*fixture.old_tcp[:2])
                fixture.start()
                for case in current:
                    try:
                        deadline()
                        details = matrix[case](fixture)
                    except Exception as error:
                        results[case] = dict(status='FAIL', error=repr(error))
                        if selected != SELECTIONS['host-ct-reply']:
                            raise
                        failures.append(error)
                        record(case, status='FAIL', error=repr(error))
                    else:
                        results[case] = dict(status='PASS', **details)
                        record(case, status='PASS', **details)
                    finally:
                        save()
                if fixture.process.poll() is None:
                    fixture.stopped()
            assert cgroup_programs() == cgroup_before, 'fixture cgroup hook leaked'
            assert not any(Path('/run/netns').iterdir()), 'fixture namespaces leaked'
        read_inputs(path, INPUT_SHA)
        if failures:
            raise ExceptionGroup('Host conntrack wire failures', failures)
    except Exception:
        (work / 'failure.txt').write_text(traceback.format_exc())
        raise
    assert all(row['status'] == 'PASS' for row in results.values()), results
    record('host-daemon-complete', output=str(work), cases=len(cases))


def main():
    global wg, tun, INPUT_PATH, INPUT_SHA
    operation, *args = sys.argv[1:]
    if operation == 'source':
        [repo] = args
        print(source_stamp(repo))
        return
    if operation == 'manifest':
        manifest(*args)
        return
    if operation not in ('gate', 'named'):
        raise ValueError(operation)
    path, INPUT_SHA, *args = args
    INPUT_PATH = Path(path)
    value = read_inputs(INPUT_PATH, INPUT_SHA, verify_files=operation == 'gate')
    sys.path.insert(0, str(SCRIPTS))
    wg = load('host_wireguard_helpers', 'xdp-l3-lan.py')
    tun = load('host_socket_helpers', 'tun-endpoint-peer.py')
    if operation == 'gate':
        assert not args
        gate(value, INPUT_PATH)
    else:
        named_client(*args)


if __name__ == '__main__':
    main()
