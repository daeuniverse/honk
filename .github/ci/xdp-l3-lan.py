#!/usr/bin/env python3
"""Real WireGuard and physical XDP peers in the disposable smoke guest."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('dns_fixture', Path(__file__).with_name('xdp-dns-shadow.py'))
dns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dns)
from xdp_dns_tcp import owners, read_exact

OUTER, INNER, REUSED = 'wg0', 'honk-l3-0', 'wg-unrelated'
WG, LAN, UPLINK = ('10.79.0.2', 'fd00:79::2'), (dns.LAN4, dns.LAN6), (dns.UP4, dns.UP6)
WG_PEER_ALLOWED_IPS = '10.79.0.1/32,fd00:79::1/128,198.51.100.0/24,fd00:2::/64'
WG_PEER_ENDPOINT = '10.78.0.1:51820'
TARGETS = ((dns.TARGET4, dns.TARGET6), (dns.EXPIRING, 'fd00:2::4'))
STATIC, NEXT_STATIC = dns.STATIC, '198.51.100.8'
ROLLBACK = 'xdp::tests::driven_kernel::gateway::kernel_gateway_auxiliary_mixed_rollback'
SOCKET_TIMEOUT = 8
UDP_SEGMENT, UDP_SEGMENT_SIZE, UDP_SEGMENTS = 103, 1181, 24
TCX_INGRESS, TCX_LINK, SCHED_CLS = 46, 11, 3
OBSERVER_NAME = 'smoke_wg_rx'
OBSERVATIONS = 1024
INGRESS_RECORD = struct.Struct('=4I44si')


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=5, **kwargs).stdout


def ip(ns, *args):
    return command('ip', '-n', ns, *map(str, args))


def inside(ns, *args, **kwargs):
    return command('ip', 'netns', 'exec', ns, *args, **kwargs)


def record(case, **data):
    print(json.dumps({'case': case, **data}), flush=True)


def until(probe, description, timeout=20):
    deadline = time.monotonic() + timeout
    while True:
        result = probe()
        if result:
            return result
        if time.monotonic() >= deadline:
            raise TimeoutError(description)
        time.sleep(0.05)


def links(ns='dut'):
    return {link['ifname']: link for link in json.loads(ip(ns, '-j', '-d', 'link', 'show'))}


def remove_namespace(name, inode):
    assert Path('/run/netns', name).stat().st_ino == inode, ('namespace identity changed', name)
    assert not command('ip', 'netns', 'pids', name).strip(), ('unjoined namespace children', name)
    command('ip', 'netns', 'del', name)


def topology(owned, workers):
    inodes = set()
    for ns in ('dut', 'client', 'server', 'wgpeer', 'wgmoved'):
        command('ip', 'netns', 'add', ns)
        inode = Path('/run/netns', ns).stat().st_ino
        owned.callback(remove_namespace, ns, inode)
        assert inode not in inodes and inode != os.stat('/proc/self/ns/net').st_ino
        inodes.add(inode)
        inside(ns, 'sysctl', '-qw', 'net.ipv6.conf.default.addr_gen_mode=1', 'net.ipv6.auto_flowlabels=0')
        ip(ns, 'link', 'set', 'lo', 'up')

    for local, remote, ns, queues in [('dut0', 'c0', 'client', workers), ('dut1', 's0', 'server', 1),
                                       ('up', 'su', 'server', 1), ('under0', 'under1', 'wgpeer', 1)]:
        channels = ('numrxqueues', queues, 'numtxqueues', queues)
        ip('dut', 'link', 'add', 'name', local, *channels, 'type', 'veth', 'peer', 'name', remote, *channels, 'netns', ns)
        for realm, device in [('dut', local), (ns, remote)]:
            ip(realm, 'link', 'set', 'dev', device, 'addrgenmode', 'none')
            if local == 'under0':
                inside(realm, 'ethtool', '-K', device, 'gro', 'on')
            elif local == 'dut0':
                inside(realm, 'ethtool', '-K', device, 'rx', 'off', 'tx', 'off', 'tso', 'off', 'gso', 'off',
                       'gro', 'off', 'rxvlan', 'off', 'rx-vlan-stag-hw-parse', 'off',
                       'tx-vlan-offload', 'off', 'tx-vlan-stag-hw-insert', 'off')
    for ns, dev, mac in [('dut', 'dut0', '10'), ('dut', 'dut1', '11'), ('client', 'c0', '20')]:
        ip(ns, 'link', 'set', dev, 'address', '02:00:00:00:00:' + mac)
    for ns, dev in [('dut', 'dut0'), ('dut', 'dut1'), ('dut', 'up'), ('dut', 'under0'),
                    ('client', 'c0'), ('server', 's0'), ('server', 'su'), ('wgpeer', 'under1')]:
        ip(ns, 'link', 'set', 'dev', dev, 'up')
    if workers == 2:
        inside('client', 'tc', 'qdisc', 'add', 'dev', 'c0', 'root', 'mqprio', 'num_tc', '2',
               'map', '0', '1', *(['0'] * 14), 'queues', '1@0', '1@1', 'hw', '0')

    inside('dut', 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1',
           'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0', 'net.ipv4.ip_early_demux=0')
    for ns, dev, address in [('dut', 'up', UPLINK[0] + '/24'), ('server', 'su', '10.77.0.2/24'),
                             ('dut', 'up', UPLINK[1] + '/64'), ('server', 'su', 'fd00:77::2/64'),
                             ('dut', 'up', 'fe80::1/64'), ('server', 'su', 'fe80::2/64'),
                             ('dut', 'under0', '10.78.0.1/24'), ('wgpeer', 'under1', '10.78.0.2/24')]:
        add_address(ns, dev, address)
    for lane, plen, gateway in [(0, 32, '10.77.0.2'), (1, 128, 'fd00:77::2')]:
        family = '-4' if lane == 0 else '-6'
        add_address('client', 'c0', f'{LAN[lane]}/{plen}')
        ip('dut', family, 'route', 'add', 'default', 'via', gateway, 'dev', 'up')
        ip('dut', 'route', 'add', f'{LAN[lane]}/{plen}', 'dev', 'dut0')
        ip('dut', 'neigh', 'add', LAN[lane], 'lladdr', '02:00:00:00:00:20', 'nud', 'permanent', 'dev', 'dut0')
        for address in (LAN[lane], WG[lane]):
            ip('server', 'route', 'add', f'{address}/{plen}', 'via', UPLINK[lane], 'dev', 'su')
        targets = [pair[lane] for pair in TARGETS]
        if lane == 0:
            targets.extend((STATIC, NEXT_STATIC, dns.DNS[0]))
        for address in targets:
            ip('client', 'route', 'add', f'{address}/{plen}', 'dev', 'c0')
            ip('client', 'neigh', 'add', address, 'lladdr', '02:00:00:00:00:10', 'nud', 'permanent', 'dev', 'c0')
            if address != dns.DNS[0]:
                add_address('server', 'lo', f'{address}/{plen}')
    # A real zone-0 conntrack consumer installs the stateful hooks in this namespace.
    inside('dut', 'nft', '-f', '-', input='''table inet honk_l3_wire {
        chain forward {
            type filter hook forward priority filter; policy accept;
            ct state { new, established } counter
        }
    }''')
    return inodes


def add_address(ns, dev, address):
    ip(ns, 'addr', 'add', address, 'dev', dev, *(['nodad'] if ':' in address else []))


def keypair():
    private = command('wg', 'genkey')
    return private, command('wg', 'pubkey', input=private).strip()


def wg_set(ns, device, keys, port, peer, allowed, endpoint):
    inside(ns, 'wg', 'set', device, 'private-key', '/dev/stdin', 'listen-port', str(port),
           'peer', peer[1], 'allowed-ips', allowed, 'endpoint', endpoint, input=keys[0])
    ip(ns, 'link', 'set', device, 'mtu', 1420, 'up')


def wg_outer(keys, peer):
    ip('dut', 'link', 'add', OUTER, 'type', 'wireguard')
    # WireGuard encrypts individual datagrams. The DUT can aggregate them after decryption.
    inside('dut', 'ethtool', '-K', OUTER, 'gro', 'on', 'rx-gro-list', 'off', 'rx-udp-gro-forwarding', 'on')
    add_address('dut', OUTER, '10.79.0.1/24')
    add_address('dut', OUTER, 'fd00:79::1/64')
    wg_set('dut', OUTER, keys, 51820, peer, '10.79.0.2/32,fd00:79::2/128', '10.78.0.2:51821')


def wg_peer(keys, peer):
    ip('wgpeer', 'link', 'add', 'wpeer0', 'type', 'wireguard')
    add_address('wgpeer', 'wpeer0', WG[0] + '/24')
    add_address('wgpeer', 'wpeer0', WG[1] + '/64')
    wg_set('wgpeer', 'wpeer0', peer, 51821, keys, WG_PEER_ALLOWED_IPS, WG_PEER_ENDPOINT)
    for subnet in ('198.51.100.0/24', 'fd00:2::/64'):
        ip('wgpeer', 'route', 'add', subnet, 'dev', 'wpeer0')


def wg_reset_peer(keys):
    # A recreated DUT has no session for packets encrypted by the surviving peer.
    inside('wgpeer', 'wg', 'set', 'wpeer0', 'peer', keys[1], 'remove')
    inside('wgpeer', 'wg', 'set', 'wpeer0', 'peer', keys[1],
           'allowed-ips', WG_PEER_ALLOWED_IPS, 'endpoint', WG_PEER_ENDPOINT)


def wg_stats():
    transfers = inside('dut', 'wg', 'show', OUTER, 'transfer').split()
    handshake = inside('dut', 'wg', 'show', OUTER, 'latest-handshakes').split()
    assert len(transfers) == 3 and len(handshake) == 2 and transfers[0] == handshake[0]
    return dict(rx=int(transfers[1]), tx=int(transfers[2]), handshake=int(handshake[1]))


def tcx(ns, device, *, with_revision=False, attach_type=TCX_INGRESS):
    c = dns.C
    with dns.namespace(ns):
        programs, link_ids = (c.c_uint32 * 4)(), (c.c_uint32 * 4)()
        # BPF_PROG_QUERY includes link IDs in chain order.
        wire = struct.pack('=4IQII4Q', socket.if_nametoindex(device), attach_type, 0, 0, c.addressof(programs),
                           len(programs), 0, 0, c.addressof(link_ids), 0, 0)
        query = c.create_string_buffer(wire, len(wire))
        dns.probe.bpf(16, query)
        count, = struct.unpack_from('=I', query, 24)
        assert count <= len(programs) and all(programs[:count]), (device, count, list(programs))
        chain = []
        for identity, link_id in zip(programs[:count], link_ids[:count], strict=True):
            fd = dns.probe.bpf(13, dns.probe.Id(id=identity))
            try:
                info = dns.info(fd, 80)
                assert struct.unpack_from('=II', info) == (3, identity), (device, identity)
                chain.append((link_id, identity, info.raw[64:80].rstrip(b'\0').decode()))
            finally:
                os.close(fd)
        if with_revision:
            revision, = struct.unpack_from('=Q', query, 56)
            assert revision > 0, (device, revision)
            return chain, revision
        return chain


def raw_bpf(operation, layout, *fields):
    raw = struct.pack(layout, *fields)
    return dns.probe.bpf(operation, dns.C.create_string_buffer(raw, len(raw)))


def observer_program(map_fd, family, verifier_log):
    # SCHED_CLS reads these stable __sk_buff offsets before any packet access.
    length, protocol, data, data_end, gso_segs, gso_size = 0, 16, 76, 80, 164, 176
    ethertype, header_size = (0x86dd, 44) if family == socket.AF_INET6 else (0x0800, 24)
    body = [
        (0xbf, 6, 1, 0, 0),                           # Save ctx.
        (0x61, 0, 6, protocol, 0),
        (0x55, 0, 0, None, socket.htons(ethertype)),  # Other families go to NEXT.
        (0x62, 10, 0, -4, 0),                         # Lookup array element zero.
        (0x18, 1, 1, 0, map_fd), (0, 0, 0, 0, 0),
        (0xbf, 2, 10, 0, 0), (0x07, 2, 0, 0, -4),
        (0x85, 0, 0, 0, 1),
        (0x15, 0, 0, None, 0),
        (0xb7, 2, 0, 0, 1), (0xdb, 0, 2, 0, 1),      # Atomic fetch-add of the u64 count.
        (0x35, 2, 0, None, OBSERVATIONS),
        (0x67, 2, 0, 0, 6), (0x0f, 0, 2, 0, 0),      # Each packet record occupies 64 bytes.
        (0xbf, 7, 0, 0, 0), (0x07, 7, 0, 0, 8),      # Skip the count.
        (0x61, 0, 6, length, 0), (0x63, 7, 0, 0, 0),
        (0x61, 0, 6, data_end, 0), (0x61, 1, 6, data, 0),
        (0x1f, 0, 1, 0, 0), (0x63, 7, 0, 4, 0),      # Store only the linear length, no pointers.
        (0x61, 0, 6, gso_size, 0), (0x63, 7, 0, 8, 0),
        (0x61, 0, 6, gso_segs, 0), (0x63, 7, 0, 12, 0),
        (0xbf, 1, 6, 0, 0), (0xb7, 2, 0, 0, 0),
        (0xbf, 3, 7, 0, 0), (0x07, 3, 0, 0, 16), (0xb7, 4, 0, 0, header_size),
        (0x85, 0, 0, 0, 26), (0x63, 7, 0, 60, 0),    # skb_load_bytes copies the tuple prefix.
    ]
    next_at = len(body)
    body.extend([(0xb7, 0, 0, 0, -1), (0x95, 0, 0, 0, 0)])  # TCX_NEXT.
    image = b''.join(struct.pack('<BBhi', op, dst | src << 4, next_at - i - 1 if off is None else off, imm)
                     for i, (op, dst, src, off, imm) in enumerate(body))
    c = dns.C
    assert sys.byteorder == 'little' and INGRESS_RECORD.size == 64
    instructions, license_text = c.create_string_buffer(image), c.create_string_buffer(b'GPL')
    log = c.create_string_buffer(65536)
    try:
        return raw_bpf(5, '=IIQQIIQII16sII', SCHED_CLS, len(body), c.addressof(instructions), c.addressof(license_text),
                       1, len(log), c.addressof(log), 0, 0, OBSERVER_NAME.encode(), 0, TCX_INGRESS)
    except OSError:
        verifier_log.write_text(log.value.decode(errors='replace'))
        raise


@contextlib.contextmanager
def observe_ingress(address, output):
    # WireGuard's internal NAPI receive-list delivery reaches TCX after GRO.
    with contextlib.ExitStack() as owned:
        with dns.namespace('dut'):
            original, revision = tcx('dut', OUTER, with_revision=True)
            [(anchor, _, name)] = original
            assert anchor > 0 and name == 'honk_aux_gw', original
            index = socket.if_nametoindex(OUTER)
            size = 8 + OBSERVATIONS * INGRESS_RECORD.size
            # BPF_MAP_TYPE_ARRAY with BPF_F_RDONLY for userspace.
            map_fd = raw_bpf(0, '=7I16s', 2, 4, size, 1, 1 << 3, 0, 0, b'smoke_wg_rows')
            owned.callback(os.close, map_fd)
            program = observer_program(map_fd, dns.family(address), output.with_suffix('.verifier.log'))
            owned.callback(os.close, program)
            kind, program_id = struct.unpack_from('=II', dns.info(program, 80))
            assert kind == SCHED_CLS and program_id > 0
            # BPF_F_BEFORE | BPF_F_ID | BPF_F_LINK names the exact daemon link at this revision.
            link = raw_bpf(28, '=6IQ', program, index, TCX_INGRESS, (1 << 3) | (1 << 5) | (1 << 13), anchor, 0, revision)
            owned.callback(os.close, link)
        rows = []
        attached = None
        try:
            with dns.namespace('dut'):
                kind, identity, attached_program, target, hook = struct.unpack('=III4xII', dns.info(link, 24))
            assert identity > 0 and (kind, attached_program, target, hook) == (TCX_LINK, program_id, index, TCX_INGRESS)
            attached = [(identity, program_id, OBSERVER_NAME), *original]
            assert tcx('dut', OUTER) == attached
            yield rows
        finally:
            with dns.namespace('dut'):
                try:
                    before_detach = tcx('dut', OUTER)
                finally:
                    # Detach synchronizes with in-flight readers before the map snapshot.
                    raw_bpf(34, '=I', link)
            after_detach = tcx('dut', OUTER)
            key, value = dns.C.c_uint32(0), dns.C.create_string_buffer(size)
            dns.probe.bpf(1, dns.probe.Element(map_fd, 0, dns.C.addressof(key), dns.C.addressof(value), 0))
            count, = struct.unpack_from('=Q', value)
            for length, linear, gso_size, gso_segs, header, error in INGRESS_RECORD.iter_unpack(
                    value.raw[8:8 + min(count, OBSERVATIONS) * INGRESS_RECORD.size]):
                rows.append(dict(len=length, linear_len=linear, gso_size=gso_size, gso_segs=gso_segs,
                                 header=header.hex(), read_error=error))
            output.write_text(json.dumps(dict(ifindex=index, observed_count=count, chain=before_detach,
                                              restored_chain=after_detach, rows=rows), indent=2))
            assert count <= OBSERVATIONS, ('ingress observer overflow', count, output)
            assert after_detach == original, (after_detach, original)
            assert attached is None or before_detach == attached, (before_detach, attached)


def flow_observations(rows, address, transport, flow):
    family = dns.family(address)
    proto_at, source_at, target_at, ports_at = (6, 8, 24, 40) if family == socket.AF_INET6 else (9, 12, 16, 20)
    origin, target = flow
    source_bytes, target_bytes = dns.address_bytes(origin[0]), dns.address_bytes(target[0])
    expected_ports = struct.pack('!HH', origin[1], target[1])
    selected = []
    for row in rows:
        header = bytes.fromhex(row['header'])
        assert row['read_error'] == 0 or row['len'] < ports_at + 4, row
        normal_header = header[0] >> 4 == 6 if family == socket.AF_INET6 else header[0] == 0x45
        if row['read_error'] or not normal_header or header[proto_at] != transport or header[ports_at:ports_at + 4] != expected_ports:
            continue
        if header[source_at:target_at] == source_bytes and header[target_at:ports_at] == target_bytes:
            assert 0 <= row['linear_len'] <= row['len'], row
            selected.append({**row, 'data_len': row['len'] - row['linear_len']})
    assert selected, ('no ingress evidence for socket flow', flow, transport)
    return selected


def named_map(program, name):
    ids = (dns.C.c_uint32 * 32)()

    def request(info):
        struct.pack_into('=IQ', info, 52, len(ids), dns.C.addressof(ids))

    fd = dns.probe.bpf(13, dns.probe.Id(id=program))
    try:
        count, = struct.unpack_from('=I', dns.info(fd, 80, request), 52)
    finally:
        os.close(fd)
    assert 0 < count <= len(ids), (program, count)
    for identity in ids[:count]:
        fd = dns.probe.bpf(14, dns.probe.Id(id=identity))
        try:
            info = dns.info(fd, 40)
            if info.raw[24:40].rstrip(b'\0').decode() == name:
                kind, observed, key, value, entries, flags = struct.unpack_from('=6I', info)
                assert observed == identity, (name, identity, observed)
                return identity, kind, key, value, entries, flags
        finally:
            os.close(fd)
    raise AssertionError(('missing program map', program, name))


def physical():
    with dns.namespace('dut'):
        state = dns.probe.kernel_xdp_state('dut0')
        fd = dns.probe.bpf(13, dns.probe.Id(id=state['prog_id']))
        try:
            program = dns.probe.program_identity(fd, 'dut0', 'data')
            dns.probe.require_xdp_identity(state, program)
            maps = dns.program_maps(fd)
            index = socket.if_nametoindex('dut0')
        finally:
            os.close(fd)
    return program, maps, index


def realm(maps, index):
    value = dns.map_value(maps['honk_gw_realms'], struct.pack('=I12x', index), 4)
    return struct.unpack('=I', value)[0] if value is not None else None


def epoch(maps, realm_id):
    value = dns.map_value(maps['dns_epochs'], struct.pack('=I', realm_id), 64)
    assert value is not None, ('missing DNS epoch', realm_id)
    return struct.unpack_from('=Q', value)[0]


def counters(maps, name, reasons):
    details = maps[name]
    length = 8 * (dns.possible_cpus() if name == 'honk_gw_stats' else 1)
    assert details[2:4] == (4, 8), details
    return [sum(n for n, in struct.iter_unpack('=Q', dns.map_value(details, struct.pack('=I', key), length)))
            for key in reasons]


def slot(pair, index):
    value = dns.map_value(pair, struct.pack('=I', index), pair[3])
    return struct.unpack_from('=I', value)[0] if value is not None else None


def hold_value(hold, realm_id, source, target, protocol):
    def canonical(address):
        wire = dns.address_bytes(address)
        return b'\0' * 10 + b'\xff\xff' + wire if len(wire) == 4 else wire

    key = (struct.pack('=II', realm_id, 4 if ':' not in source[0] else 6)
           + canonical(source[0]) + canonical(target[0]) + struct.pack('!HHB3x', source[1], target[1], protocol))
    value = dns.map_value(hold, key, 16)
    return struct.unpack_from('=Q', value)[0] if value is not None else None


def check_inner(inner, active):
    assert inner['linkinfo']['info_kind'] == 'tun', inner
    assert inside('dut', 'cat', f'/proc/sys/net/ipv6/conf/{INNER}/disable_ipv6').strip() == '1'
    (address,) = json.loads(ip('dut', '-j', 'address', 'show', 'dev', INNER))
    assert not address['addr_info'], address
    for family in ('-4', '-6'):
        assert not json.loads(ip('dut', family, '-j', 'route', 'show', 'table', 'all', 'dev', INNER))
    chain = tcx('dut', INNER)
    assert len(chain) == (2 if active else 1) and chain[-1][0] == 0 and chain[-1][2] == 'honk_aux_stop', chain
    if active:
        assert chain[0][0] > 0 and chain[0][2] == 'honk_aux_return', chain
    return chain


def socket_at(owned, ns, address, kind, priority=0):
    with dns.namespace(ns):
        sock = owned.enter_context(socket.socket(dns.family(address[0]), kind))
    sock.settimeout(SOCKET_TIMEOUT)
    if priority:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, priority)
    sock.bind(address)
    return sock


def stream(owned, ns, source, destination, request, priority=0):
    listener = socket_at(owned, 'server', destination, socket.SOCK_STREAM)
    listener.listen(1)
    client = socket_at(owned, ns, source, socket.SOCK_STREAM, priority)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512 * 1024)
    client.connect(listener.getsockname()[:2])
    client.sendall(request)
    conn, peer = listener.accept()
    owned.enter_context(conn)
    conn.settimeout(SOCKET_TIMEOUT)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512 * 1024)
    return client, conn, peer[:2]


@contextlib.contextmanager
def physical_progress(hold, realm_id):
    with contextlib.ExitStack() as owned:
        preface = b'physical ready'
        client, server, peer = stream(owned, 'client', (LAN[0], 0), (dns.TARGET4, 0), preface)
        assert peer[0] == UPLINK[0], peer
        assert read_exact(server, len(preface)) == preface
        origin, dest = client.getsockname()[:2], client.getpeername()[:2]
        stamp = hold_value(hold, realm_id, origin, dest, socket.IPPROTO_TCP)
        assert stamp, (origin, dest)
        for sock in (client, server):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        stop, progress = threading.Event(), threading.Condition()
        errors, turns = [], 0

        def exchange():
            nonlocal turns
            try:
                while not stop.is_set():
                    request = struct.pack('!Q', turns) + os.urandom(16)
                    client.sendall(request)
                    assert read_exact(server, len(request)) == request
                    reply = request[::-1]
                    server.sendall(reply)
                    assert read_exact(client, len(reply)) == reply
                    with progress:
                        turns += 1
                        progress.notify_all()
                    stop.wait(0.02)
            except BaseException as error:
                with progress:
                    errors.append(error)
                    progress.notify_all()

        thread = threading.Thread(target=exchange)
        thread.start()

        def advanced(stage):
            with progress:
                previous = turns
                assert progress.wait_for(lambda: turns > previous or errors, SOCKET_TIMEOUT), stage
                if errors:
                    raise errors[0]
                complete = turns
            assert hold_value(hold, realm_id, origin, dest, socket.IPPROTO_TCP) == stamp, stage
            record(stage, physical={'origin': origin, 'destination': dest, 'peer': peer, 'turns': complete,
                                    'bytes_each_direction': complete * 24, 'hold_stamp': stamp, 'realm': realm_id})

        try:
            yield advanced
        finally:
            stop.set()
            thread.join(SOCKET_TIMEOUT * 2 + 1)
            assert not thread.is_alive(), 'physical peer thread did not join'
            if errors:
                raise errors[0]


def udp_exchange(client, server, request, reply, segmented):
    if segmented:
        for sock in (client, server):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
        uploads = [request[i:i + UDP_SEGMENT_SIZE] for i in range(0, len(request), UDP_SEGMENT_SIZE)]
        downloads = [reply[i:i + UDP_SEGMENT_SIZE] for i in range(0, len(reply), UDP_SEGMENT_SIZE)]
        option = [(socket.IPPROTO_UDP, UDP_SEGMENT, struct.pack('=H', UDP_SEGMENT_SIZE))]
        assert client.sendmsg(uploads, option) == len(request)
    else:
        uploads, downloads = [request], [reply]
        assert client.send(request) == len(request)

    expected = dict(zip(uploads, downloads, strict=True))
    peers = set()
    for _ in uploads:
        payload, peer = server.recvfrom(65535)
        assert payload in expected, ('unexpected upload datagram', len(payload), peer)
        response = expected.pop(payload)
        assert server.sendto(response, peer) == len(response)
        peers.add(peer[:2])
    [peer] = peers
    expected = set(downloads)
    for _ in downloads:
        payload, source = client.recvfrom(65535)
        assert payload in expected and source == client.getpeername(), ('unexpected download datagram', len(payload), source)
        expected.remove(payload)
    return peer


def trial(case, ns, address, kind, route, *, bulk=False, empty=False, priority=0, segmented=False):
    lane = int(':' in address)
    is_wg = ns == 'wgpeer'
    source = ((WG if is_wg else LAN)[lane], 0)
    native = route != 'endpoint'
    _, maps, _ = physical()
    reasons = (8, 9, 10, 19)  # Static D1, Endpoint new, UnclassifiableHeader, DNS D1.
    before = counters(maps, 'honk_gw_stats', reasons)
    tunnel_before = wg_stats() if is_wg else None
    with contextlib.ExitStack() as owned:
        if segmented:
            request = b''.join(struct.pack('!I', i) + os.urandom(UDP_SEGMENT_SIZE - 4) for i in range(UDP_SEGMENTS))
            reply = os.urandom(len(request))
        else:
            request = b'' if empty else os.urandom(262144 if bulk else 37)
            reply = b'' if empty else os.urandom(262144 if bulk else 47)
        if kind == socket.SOCK_STREAM:
            client, server, peer = stream(owned, ns, source, (address, 0), request, priority)
            assert read_exact(server, len(request)) == request, case
            server.sendall(reply)
            assert read_exact(client, len(reply)) == reply, case
        else:
            server = socket_at(owned, 'server', (address, 0), kind)
            client = socket_at(owned, ns, source, kind, priority)
            client.connect(server.getsockname()[:2])
            peer = udp_exchange(client, server, request, reply, segmented)
        origin, target = client.getsockname()[:2], server.getsockname()[:2]
        assert client.getpeername()[:2] == target and target[0] == address, (case, target)
        assert peer[0] == (origin[0] if native else UPLINK[lane]), (case, origin, peer)
        assert not native or peer == origin, (case, origin, peer)
        after = counters(maps, 'honk_gw_stats', reasons)
        deltas = [b - a for a, b in zip(before, after, strict=True)]
        static, endpoint, bad_header, learned = deltas
        assert ((static > 0), (endpoint > 0), bad_header, (learned > 0)) == (
            route == 'static', route == 'endpoint', 0, route == 'dns'), (case, deltas)
        tunnel_after = None
        if is_wg:
            def transferred():
                observed = wg_stats()
                if observed['handshake'] > 0 and all(
                        observed[direction] - tunnel_before[direction] >= max(1, len(payload))
                        for direction, payload in [('rx', request), ('tx', reply)]):
                    return observed

            tunnel_after = until(transferred, f'WireGuard transfer counters for {case}', timeout=SOCKET_TIMEOUT)
        record(case, transport='tcp' if kind == socket.SOCK_STREAM else 'udp', origin=origin, destination=target,
               datagrams_each_direction=(UDP_SEGMENTS if segmented else 1) if kind == socket.SOCK_DGRAM else None,
               server_saw=peer, client_saw=client.getpeername()[:2], stats_delta=dict(zip(reasons, deltas)),
               wireguard_before=tunnel_before, wireguard_after=tunnel_after,
               upload={'bytes': len(request), 'sha256': hashlib.sha256(request).hexdigest()},
               download={'bytes': len(reply), 'sha256': hashlib.sha256(reply).hexdigest()})
        return origin, target


def learn(ns, expected):
    name = 'learn.pass-shadow.test' if ns == 'wgpeer' else 'wan.pass-shadow.test'
    qtype = 28 if ':' in expected else 1
    txid, = struct.unpack('!H', os.urandom(2))
    source = (WG if ns == 'wgpeer' else LAN)[0]
    question = dns.name_wire(name) + struct.pack('!HH', qtype, 1)
    packet = struct.pack('!6H', txid, 0x0100, 1, 0, 0, 0) + question

    def answer(received, kind):
        assert (received, kind) == (name, qtype)
        return expected, 60

    with contextlib.ExitStack() as owned:
        events = dns.endpoint_peer(owned, answer, record_peer_identity=True)
        result = dns.client_exchange(ns, (source, 0), dns.DNS, packet)
        dns.verify_answer(result, question, txid, qtype, expected, 60)
    record('dns-answer', source=source, query=name, qtype=qtype, address=expected, upstream=events)
    return events


@contextlib.contextmanager
def trace_guest(owned_dir, events):
    # A private trace instance in the authenticated VM leaves global settings alone.
    with contextlib.ExitStack() as owned:
        directory = Path(owned.enter_context(tempfile.TemporaryDirectory(dir=owned_dir, prefix='trace.')))
        command('mount', '-t', 'tracefs', 'tracefs', directory)
        owned.callback(command, 'umount', directory)
        instance = directory / 'instances' / directory.name
        instance.mkdir()
        owned.callback(instance.rmdir)
        (instance / 'tracing_on').write_text('0')
        (instance / 'buffer_size_kb').write_text('1024')
        for name, devices in events:
            event = instance / 'events' / 'net' / name
            (event / 'filter').write_text(' || '.join(f'name == "{dev}"' for dev in devices))
            (event / 'enable').write_text('1')
        (instance / 'tracing_on').write_text('1')
        try:
            yield instance
        finally:
            (instance / 'tracing_on').write_text('0')


def read_trace(instance, path):
    (instance / 'tracing_on').write_text('0')
    raw = (instance / 'trace').read_text()
    path.write_text(raw)
    extent = re.search(r'entries-in-buffer/entries-written:\s*(\d+)/(\d+)', raw)
    assert extent and extent[1] == extent[2], ('trace overflow or missing readback', path)
    rows = []
    for line in raw.splitlines():
        match = re.search(r'\b(net\w+): dev=(\S+) (.*)', line)
        if match:
            fields = {name: int(value, 16 if value.startswith('0x') else 10)
                      for name, value in re.findall(r'\b(protocol|ip_summed|len|data_len|gso_size|gso_segs|gso_type)=(0x[0-9a-fA-F]+|\d+)\b', match[3])}
            rows.append((match[1], match[2], fields))
    assert len(rows) == int(extent[1]), ('unparsed trace events', len(rows), extent[1], path)
    return rows


def offload(artifacts, state):
    features = {dev: inside(ns, 'ethtool', '-k', dev) for ns, dev in [('dut', OUTER), ('dut', INNER), ('wgpeer', 'wpeer0')]}
    (artifacts / 'offload-features.json').write_text(json.dumps(features, indent=2))
    for address in TARGETS[0]:
        version = 6 if ':' in address else 4
        protocol = 0x86dd if version == 6 else 0x0800
        with observe_ingress(address, artifacts / f'tcp-ingress-{version}.json') as ingress:
            with trace_guest(state, [('net_dev_start_xmit', (OUTER, INNER))]) as trace:
                try:
                    flow = trial('bulk-wireguard-endpoint', 'wgpeer', address, socket.SOCK_STREAM, 'endpoint', bulk=True)
                finally:
                    rows = read_trace(trace, artifacts / f'offload-{version}.trace')
        received = flow_observations(ingress, address, socket.IPPROTO_TCP, flow)
        selected = [(event, dev, fields) for event, dev, fields in rows if fields.get('protocol') == protocol]
        into_tun = [fields for event, dev, fields in selected if event == 'net_dev_start_xmit' and dev == INNER]
        returned = [fields for event, dev, fields in selected if event == 'net_dev_start_xmit' and dev == OUTER]
        gro = next((row for row in received if row['data_len'] > 0 and row['gso_size'] > 0 and row['len'] > 1420), None)
        tun_tx = next((row for row in into_tun if row['data_len'] > 0 and row['gso_size'] > 0 and row['len'] > 1420), None)
        wg_tx = next((row for row in returned if row['gso_size'] > 0 and row['len'] > 1420 and row['ip_summed'] == 3), None)
        assert gro and tun_tx and wg_tx, ('missing live GRO/nonlinear/TUN/TSO/checksum evidence', protocol, artifacts)
        record('observed-skb', protocol=protocol, wireguard_ingress=gro, internal_tun_xmit=tun_tx, wireguard_xmit=wg_tx)


def udp_offload(artifacts, state, address, route):
    version = 6 if ':' in address else 4
    protocol = 0x86dd if version == 6 else 0x0800
    headers = (40 if version == 6 else 20) + 8
    with observe_ingress(address, artifacts / f'udp-ingress-{version}-{route}.json') as ingress:
        with trace_guest(state, [('net_dev_start_xmit', (INNER,))]) as trace:
            try:
                flow = trial(f'wireguard-udp-segment-{route}', 'wgpeer', address, socket.SOCK_DGRAM, route, segmented=True)
            finally:
                rows = read_trace(trace, artifacts / f'udp-offload-{version}-{route}.trace')

    aggregates = []
    ordinary_ingress = tun_segments = 0
    for packet in flow_observations(ingress, address, socket.IPPROTO_UDP, flow):
        size = packet['len'] - headers
        if packet['gso_size'] == UDP_SEGMENT_SIZE:
            segments, remainder = divmod(size, UDP_SEGMENT_SIZE)
            assert 2 <= segments <= UDP_SEGMENTS and remainder == 0 and packet['data_len'] > 0, packet
            assert packet['gso_segs'] == segments, packet
            aggregates.append(segments)
        else:
            assert packet['gso_size'] == 0 and size == UDP_SEGMENT_SIZE, packet
            ordinary_ingress += 1
    for _, device, packet in rows:
        if packet['protocol'] != protocol:
            continue
        size = packet['len'] - headers
        if device == INNER and size == UDP_SEGMENT_SIZE:
            assert packet['gso_size'] == 0, packet
            tun_segments += 1
    assert aggregates, ('no decrypted UDP aggregate reached TCX ingress', version, route)
    assert ordinary_ingress + sum(aggregates) == UDP_SEGMENTS, (version, route, ordinary_ingress, aggregates)
    assert tun_segments == (UDP_SEGMENTS if route == 'endpoint' else 0), (version, route, tun_segments)
    record('observed-udp-offload', version=version, route=route, segment_bytes=UDP_SEGMENT_SIZE,
           wireguard_aggregate_segments=aggregates, wireguard_ordinary_packets=ordinary_ingress,
           internal_tun_ordinary_packets=tun_segments)


def config_file(state, workers, static=STATIC, project=True, *, dns_projection=True):
    rule = 'domain(suffix: pass-shadow.test) -> direct(must)' if project else ''
    return f'''global {{
    dial_mode: domain+
    nfqueue_enable: false
    so_mark_from_dae: 0x100
    data_dir: '{state}'
    tcp_check_url: 'http://127.0.0.1:1/'
    udp_check_dns: '127.0.0.1:9'
}}
dns {{
    bind: ''
    optimistic_cache: false
    upstream {{ default: 'udp://10.77.0.2:15353' -> direct }}
}}
datapath {{
    backend: xdp
    direct: endpoint
    dns_projection: {str(dns_projection).lower()}
    xsk_mode: copy
    workers: {workers}
    interface {{
        dut0: lan
        {OUTER}: l3_lan
    }}
}}
group {{ endpoint_relay {{
    filter: name('direct')
    policy: select
    final: direct
}} }}
routing {{
    dip({static}/32) -> direct(must)
    {rule}
    fallback: endpoint_relay
}}
'''


def reap(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=10)


def start_daemon(owned, daemon, config, pins, log):
    with log.open('x') as output:
        process = subprocess.Popen(['ip', 'netns', 'exec', 'dut', daemon, '-c', config, '--bpf-pin-root', pins],
                                   stdout=output, stderr=subprocess.STDOUT)
    owned.callback(reap, process)
    return process


def wait_log(process, log, marker, *, offset=0):
    def check():
        assert process.poll() is None, ('daemon exited', process.returncode, log)
        text = log.read_text()[offset:]
        return text if marker in text else None

    return until(check, f'{marker}: {log}')


def reload_policy(process, log, config, source, request, *, rejected=False):
    offset = len(log.read_text())
    pending = config.with_suffix('.candidate')
    pending.write_text(source)
    pending.replace(config)
    process.send_signal(signal.SIGHUP)
    outcome = 'rejected' if rejected else 'applied'
    text = wait_log(process, log, f'SIGHUP reload request {request} {outcome}', offset=offset)
    assert 'degraded' not in text.lower(), text
    if rejected:
        assert 'datapath backend, Direct profile and device setup require restart' in text, text
    record('config-reload', request=request, outcome=outcome, physical_program=physical()[0])


def binding(process, log, offset, mtu, *, previous=None):
    wait_log(process, log, 'L3 LAN active', offset=offset)
    current = links()
    outer, inner = current[OUTER], current[INNER]
    assert outer['linkinfo']['info_kind'] == 'wireguard' and outer['mtu'] == inner['mtu'] == mtu, (outer, inner)
    assert inside('dut', 'cat', f'/sys/class/net/{OUTER}/type').strip() == '65534'
    if previous:
        assert inner['ifindex'] != previous['inner'], (previous, inner)
    (entry,) = tcx('dut', OUTER)
    assert entry[0] > 0, entry
    inner_chain = check_inner(inner, True)
    pair = named_map(entry[1], 'honk_aux_devs')
    assert pair == named_map(inner_chain[0][1], 'honk_aux_devs'), (entry, inner_chain)
    assert (slot(pair, 0), slot(pair, 1)) == (outer['ifindex'], inner['ifindex']), pair
    _, maps, physical_index = physical()
    realm_id = realm(maps, outer['ifindex'])
    assert realm_id and realm_id != realm(maps, physical_index), (outer, realm_id)
    assert not previous or realm_id == previous['realm'], (realm_id, previous)
    state = dict(index=outer['ifindex'], inner=inner['ifindex'], realm=realm_id, pair=pair,
                 outer_chain=entry, inner_chain=inner_chain, mtu=mtu)
    record('binding', **state)
    return state


def require_offline(old, *, check_existing=False):
    def detached():
        devices = links()
        if INNER in devices or (check_existing and tcx('dut', OUTER)):
            return False
        return realm(physical()[1], old['index']) is None

    until(detached, 'old TCX, TUN and realm retirement')
    record('offline', former_outer_index=old['index'], retired_tun_index=old['inner'], realm=old['realm'])


def no_live_links():
    with dns.namespace('dut'):
        dns.probe.require_xdp_absent(dns.probe.kernel_xdp_state('dut0'))
    devices = links()
    assert 'dae0' not in devices and all(not name.startswith('honk-l3-') for name in devices), devices
    if OUTER in devices:
        assert tcx('dut', OUTER) == [], 'external TCX chain was not released'


def exact_kernel_case(binary, test, output, pins):
    output.mkdir()
    env = dict(os.environ, HONK_XDP_ARTIFACT_ROOT=str(output), HONK_XDP_PIN_ROOT=str(pins))
    assert inside('dut', binary, test, '--exact', '--ignored', '--list', '--format', 'terse', env=env).strip() == test + ': test'
    with (output / 'result.log').open('x') as log:
        subprocess.run(['ip', 'netns', 'exec', 'dut', binary, test, '--exact', '--ignored', '--test-threads=1', '--nocapture'],
                       env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=90)
    result = (output / 'result.log').read_text()
    assert len(re.findall(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured;', result, re.M)) == 1, (test, output)
    record('kernel-regression', test=test, result_log=str(output / 'result.log'))


def classifier_control(daemon, config, pins, artifacts, state):
    def tc(*args):
        return inside('dut', 'tc', *args)

    with contextlib.ExitStack() as owned:
        tc('qdisc', 'add', 'dev', OUTER, 'clsact')
        owned.callback(tc, 'qdisc', 'del', 'dev', OUTER, 'clsact')
        tc('filter', 'add', 'dev', OUTER, 'ingress', 'protocol', 'ip', 'pref', '7', 'matchall', 'action', 'pass')
        before = json.loads(tc('-j', 'filter', 'show', 'dev', OUTER, 'ingress'))
        assert any(row.get('kind') == 'matchall' and row.get('pref') == 7 for row in before), before
        log = artifacts / 'classifier-rejected.log'
        process = start_daemon(owned, daemon, config, pins, log)
        assert process.wait(timeout=20) > 0 and 'l3_lan has a conflicting legacy ingress filter' in log.read_text(), log
        assert json.loads(tc('-j', 'filter', 'show', 'dev', OUTER, 'ingress')) == before
        no_live_links()
        record('classic-classifier-refused', filter=before)
        tc('filter', 'del', 'dev', OUTER, 'ingress', 'protocol', 'ip', 'pref', '7')
        bare = json.loads(tc('-j', 'qdisc', 'show', 'dev', OUTER))
        assert any(row['kind'] == 'clsact' for row in bare), bare
        static = artifacts / 'static.dae'
        static.write_text(config_file(state, 1, project=False, dns_projection=False))
        log = artifacts / 'static.log'
        process = start_daemon(owned, daemon, static, pins, log)
        wait_log(process, log, 'XDP datapath ready')
        binding(process, log, 0, 1420)
        assert not dns.SHADOW_MAPS.intersection(physical()[1])
        trial('static-only-native', 'wgpeer', STATIC, socket.SOCK_STREAM, 'static')
        trial('static-only-fallback-relay', 'wgpeer', TARGETS[0][0], socket.SOCK_STREAM, 'endpoint')
        process.terminate()
        assert process.wait(timeout=20) == 0, log
        no_live_links()
        assert json.loads(tc('-j', 'qdisc', 'show', 'dev', OUTER)) == bare


def late_reply(server, peer, target, *, payload=None):
    if payload is None:
        payload = os.urandom(29)
    with dns.namespace('dut'):
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    with capture:
        # AF_PACKET bind resolves the name in the socket namespace via the caller.
        with dns.namespace('dut'):
            capture.bind(('up', 0x0800))
        assert server.sendto(payload, peer) == len(payload)
        ports = struct.pack('!HH', target[1], peer[1])
        addresses = socket.inet_aton(target[0]) + socket.inet_aton(peer[0])
        deadline = time.monotonic() + SOCKET_TIMEOUT
        while time.monotonic() < deadline:
            capture.settimeout(max(0.001, deadline - time.monotonic()))
            frame = capture.recv(2048)
            if len(frame) >= 42 and frame[12:14] == b'\x08\x00' and frame[23] == socket.IPPROTO_UDP and frame[26:34] == addresses:
                l4 = 14 + 4 * (frame[14] & 0x0f)
                if frame[l4:l4 + 4] == ports and frame[l4 + 8:] == payload:
                    record('late-peer-reply-arrived', peer=target, destination=peer, payload=payload.hex())
                    return
        raise TimeoutError('missing late reply on DUT uplink')


def held_udp(owned, hold, current):
    server = socket_at(owned, 'server', (TARGETS[0][0], 0), socket.SOCK_DGRAM)
    client = socket_at(owned, 'wgpeer', (WG[0], 0), socket.SOCK_DGRAM)
    origin, target = client.getsockname(), server.getsockname()
    client.connect(target)
    payload = os.urandom(43)
    assert client.send(payload) == len(payload)
    received, peer = server.recvfrom(2048)
    assert received == payload and peer[0] == UPLINK[0], (received, peer)
    stamp = hold_value(hold, current['realm'], origin, target, socket.IPPROTO_UDP)
    assert stamp, (origin, target)
    return server, client, peer, origin, target, stamp


def delete_reload_reuse(artifacts, state, process, log, config, workers, keys, peer_keys, current, hold, progress):
    with contextlib.ExitStack() as owned:
        server, client, peer, origin, target, stamp = held_udp(owned, hold, current)
        devices = current['pair']
        owned.callback(os.close, dns.probe.bpf(14, dns.probe.Id(id=devices[0])))
        committed = config_file(state, workers, NEXT_STATIC, project=False)
        with trace_guest(state, [('net_dev_queue', (REUSED,)), ('net_dev_start_xmit', (REUSED,))]) as trace:
            try:
                progress('before-delete')
                ip('dut', 'link', 'del', OUTER)
                ip('dut', 'link', 'add', 'name', REUSED, 'index', current['index'], 'type', 'wireguard')
                ip('dut', 'link', 'set', REUSED, 'up')
                reused = links()[REUSED]
                assert reused['ifindex'] == current['index'] and tcx('dut', REUSED) == [], reused
                assert slot(devices, 0) is None, ('former device slot still resolves after ifindex reuse', devices, reused)
                late_reply(server, peer, target)
                require_offline(current)
                assert slot(devices, 1) is None and hold_value(hold, current['realm'], origin, target, socket.IPPROTO_UDP) is None
                progress('delete-offline-first-progress')
                reload_policy(process, log, config, committed, 1)
                trial('physical-offline-new-policy', 'client', NEXT_STATIC, socket.SOCK_STREAM, 'static')
                physical_committed = physical()[0]
                reload_policy(process, log, config, config_file(state, 3 - workers), 2, rejected=True)
                assert physical()[0] == physical_committed and OUTER not in links()
                config.write_text(committed)
                progress('delete-offline-second-progress')
                offset = len(log.read_text())
                wg_outer(keys, peer_keys)
                wg_reset_peer(keys)
                rebound = binding(process, log, offset, 1420, previous=current)
                assert rebound['index'] != reused['ifindex']
                payload = os.urandom(53)
                assert client.send(payload) == len(payload)
                received, new_peer = server.recvfrom(2048)
                assert received == payload and new_peer[0] == UPLINK[0]
                new_stamp = hold_value(hold, rebound['realm'], origin, target, socket.IPPROTO_UDP)
                assert new_stamp and new_stamp != stamp, (stamp, new_stamp)
                assert server.sendto(payload[::-1], new_peer) == len(payload)
                assert client.recv(2048) == payload[::-1]
                trial('wg-last-committed-static', 'wgpeer', NEXT_STATIC, socket.SOCK_STREAM, 'static')
                trial('wg-rejected-static-stays-endpoint', 'wgpeer', STATIC, socket.SOCK_STREAM, 'endpoint')
                learn('wgpeer', TARGETS[0][0])
                trial('wg-disabled-domain-policy', 'wgpeer', TARGETS[0][0], socket.SOCK_STREAM, 'endpoint')
                progress('rebound-physical-same-flow')
            finally:
                rows = read_trace(trace, artifacts / 'reused-ifindex.trace')
        assert not rows and tcx('dut', REUSED) == [], ('unrelated device saw output or attachment', rows, reused)
        record('explicit-ifindex-reuse', removed=current, unrelated=reused['ifindex'], rebound=rebound,
               previous_hold=stamp, new_hold=new_stamp, late_reply='arrived', unrelated_egress_events=len(rows))
        ip('dut', 'link', 'del', REUSED)
        return rebound


def native_after_crash(ns, source):
    with contextlib.ExitStack() as owned:
        nonce = os.urandom(32)
        client, server, peer = stream(owned, ns, (source, 0), (TARGETS[0][0], 0), nonce)
        assert peer == client.getsockname()[:2], (ns, peer)
        assert read_exact(server, len(nonce)) == nonce
        server.sendall(nonce[::-1])
        assert read_exact(client, len(nonce)) == nonce[::-1]
        record('kernel-recovery-after-sigkill', ns=ns, origin=peer, destination=client.getpeername(), bytes_each_direction=len(nonce))


def matrix(daemon, core, xsk, workers, artifacts, pins):
    artifacts.mkdir()
    pins.mkdir(mode=0o700)
    with contextlib.ExitStack() as owned:
        state = Path(owned.enter_context(tempfile.TemporaryDirectory(prefix=f'l3-lan-{workers}q.', dir='/run/honk-xdp-state')))
        namespaces = topology(owned, workers)
        (artifacts / 'topology.json').write_text(json.dumps(links(), indent=2))
        config, log = artifacts / 'honk.dae', artifacts / 'daemon.log'
        initial = config_file(state, workers)
        config.write_text(initial)
        keys, peer_keys = keypair(), keypair()
        wg_peer(keys, peer_keys)
        if workers == 1:
            wg_outer(keys, peer_keys)
            classifier_control(daemon, config, pins, artifacts, state)
            exact_kernel_case(core, ROLLBACK, artifacts / 'rollback', pins)
            dns_case = 'control::dns_control::tests::packet::kernel_gateway_host_dns_fences_queued_fills'
            exact_kernel_case(core, dns_case, artifacts / dns_case.rsplit('::', 1)[1], pins)
            for test in ('gateway::tests::kernel_aux_registry_and_retirement_preserve_other_realms',
                         'gateway::tests::kernel_aux_tun_guard_requires_its_fd_and_outlives_return_link',
                         'gateway::tests::kernel_aux_hash_batch_survives_deleted_successor',
                         'tcx_aux::tests::kernel_aux_outer_anchor_cannot_activate_on_reused_ifindex',
                         'tcx_aux::tests::kernel_host_return_header_uses_verified_mac_and_preserves_protocol',
                         'tcx_aux::tests::kernel_host_broadcast_swap_keeps_incumbent_through_invalid_snapshot',
                         'tcx_aux::tests::kernel_host_delay_filter_checks_full_timestamp_and_counts_before_the_ring',
                         'gateway::host::tests::kernel_host_flow_capacity_charge',
                         'gateway::host::tests::kernel_host_batch_reclaims_short_endpoint_flows',
                         'gateway::host::tests::kernel_host_flow_owner_and_drain'):
                exact_kernel_case(xsk, 'bpf::' + test, artifacts / test.rsplit('::', 1)[1], pins)
            no_live_links()
            ip('dut', 'link', 'del', OUTER)
        rules = [ip('dut', family, '-j', 'rule', 'show') for family in ('-4', '-6')]
        process = start_daemon(owned, daemon, config, pins, log)
        wait_log(process, log, 'XDP datapath ready')
        wait_log(process, log, 'L3 LAN waiting_link')
        assert os.path.samefile(daemon, Path('/proc', str(process.pid), 'exe'))
        program, maps, physical_index = physical()
        physical_realm = realm(maps, physical_index)
        devices = links()
        assert physical_realm and OUTER not in devices and INNER in devices, devices
        queues = maps['honk_xdp_count'][4] - 4
        assert queues == workers == links()['dut0']['num_rx_queues']
        hold = named_map(program, 'honk_gw_hold')
        assert hold[2:4] == (48, 16), hold
        record('startup-waiting-link', workers=workers, namespace_inodes=sorted(namespaces),
               inner_chain=check_inner(devices[INNER], False), **owners(process.pid, log, ['dut0'], workers))

        with physical_progress(hold, physical_realm) as progress:
            progress('physical-up-with-wg-missing')
            offset = len(log.read_text())
            wg_outer(keys, peer_keys)
            if workers == 1:
                wg_reset_peer(keys)
            current = binding(process, log, offset, 1420)
            assert [ip('dut', family, '-j', 'rule', 'show') for family in ('-4', '-6')] == rules
            trial('wg-static-control', 'wgpeer', STATIC, socket.SOCK_STREAM, 'static')
            offload(artifacts, state)
            queue_before = counters(maps, 'honk_xdp_count', range(workers))
            for wg_target, physical_target in zip(*TARGETS, strict=True):
                trial('wg-ordinary-empty-udp', 'wgpeer', wg_target, socket.SOCK_DGRAM, 'endpoint', empty=True)
                udp_offload(artifacts, state, wg_target, 'endpoint')
                assert len(learn('wgpeer', wg_target)) == 1
                assert len(learn('client', physical_target)) == 1
                for authorized, other, address in [(current['realm'], physical_realm, wg_target),
                                                    (physical_realm, current['realm'], physical_target)]:
                    own = dict(maps=maps, realm=authorized, epoch=epoch(maps, authorized))
                    foreign = dict(maps=maps, realm=other, epoch=epoch(maps, other))
                    assert own['epoch'] > 0 and foreign['epoch'] > 0
                    witness = dns.live_dns_fact(own, address, True)
                    assert dns.dns_fact(foreign, address) is None, (address, other)
                    record('dns-fact-isolation', address=address, authorized_realm=authorized,
                           other_realm=other, **witness)
                udp_offload(artifacts, state, wg_target, 'dns')
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    trial('wg-learned-native', 'wgpeer', wg_target, kind, 'dns')
                    trial('physical-does-not-inherit-wg-fact', 'client', wg_target, kind, 'endpoint', priority=workers - 1)
                    trial('physical-learned-native', 'client', physical_target, kind, 'dns')
                    trial('wg-does-not-inherit-physical-fact', 'wgpeer', physical_target, kind, 'endpoint')
            queue_after = counters(maps, 'honk_xdp_count', range(workers))
            assert all(b > a for a, b in zip(queue_before, queue_after, strict=True)), (queue_before, queue_after)
            record('observed-physical-queues', before=queue_before, after=queue_after)

            old_epoch, physical_epoch = epoch(maps, current['realm']), epoch(maps, physical_realm)
            assert old_epoch and physical_epoch
            progress('physical-before-wg-down')
            dns.live_dns_fact(dict(maps=maps, realm=physical_realm, epoch=physical_epoch), TARGETS[1][1], True)
            ip('dut', 'link', 'set', OUTER, 'down')
            require_offline(current, check_existing=True)
            assert epoch(maps, current['realm']) == 0 and epoch(maps, physical_realm) == physical_epoch
            progress('physical-while-wg-down')
            trial('physical-fact-survives-aux-down', 'client', TARGETS[1][1], socket.SOCK_STREAM, 'dns')
            offset = len(log.read_text())
            ip('dut', 'link', 'set', OUTER, 'up')
            current = binding(process, log, offset, 1420, previous=current)
            assert epoch(maps, current['realm']) > old_epoch
            trial('wg-old-fact-cleared-on-down-up', 'wgpeer', TARGETS[0][0], socket.SOCK_STREAM, 'endpoint')
            current = delete_reload_reuse(artifacts, state, process, log, config, workers, keys, peer_keys, current, hold, progress)

            with contextlib.ExitStack() as move:
                devices = current['pair']
                move.callback(os.close, dns.probe.bpf(14, dns.probe.Id(id=devices[0])))
                progress('physical-before-wg-move')
                ip('dut', 'link', 'set', OUTER, 'netns', 'wgmoved')
                require_offline(current)
                assert OUTER not in links() and links('wgmoved')[OUTER]['linkinfo']['info_kind'] == 'wireguard'
                assert tcx('wgmoved', OUTER) == [] and (slot(devices, 0), slot(devices, 1)) == (None, None)
                progress('physical-while-wg-moved')
                reload_policy(process, log, config, initial, 3)
                offset = len(log.read_text())
                wg_outer(keys, peer_keys)
                wg_reset_peer(keys)
                current = binding(process, log, offset, 1420, previous=current)
                record('wireguard-moved', other_netns=Path('/run/netns/wgmoved').stat().st_ino,
                       moved_index=links('wgmoved')[OUTER]['ifindex'], current_index=current['index'])
                trial('wg-domain-fact-needs-fresh-query', 'wgpeer', TARGETS[0][0], socket.SOCK_STREAM, 'endpoint')
                learn('wgpeer', TARGETS[0][0])
                trial('wg-restored-domain-policy', 'wgpeer', TARGETS[0][0], socket.SOCK_STREAM, 'dns')

            old = current
            progress('physical-before-mtu-change')
            offset = len(log.read_text())
            ip('wgpeer', 'link', 'set', 'wpeer0', 'mtu', 1280)
            ip('dut', 'link', 'set', OUTER, 'mtu', 1280)
            current = binding(process, log, offset, 1280, previous=old)
            assert current['index'] == old['index'], (old, current)
            trial('wg-after-mtu-change', 'wgpeer', TARGETS[0][1], socket.SOCK_STREAM, 'endpoint', bulk=True)
            progress('physical-after-mtu-change')

        process.kill()
        assert process.wait(timeout=10) == -signal.SIGKILL
        no_live_links()
        assert current['index'] == links()[OUTER]['ifindex']
        assert not any(path.is_file() for path in pins.rglob('*')), 'daemon left BPF pins'
        assert [ip('dut', family, '-j', 'rule', 'show') for family in ('-4', '-6')] == rules
        record('sigkill-releases-kernel-links', wireguard=links()[OUTER]['ifindex'], outer_chain=tcx('dut', OUTER),
               retired_inner=current['inner'])
        native_after_crash('client', LAN[0])
        native_after_crash('wgpeer', WG[0])


def main():
    dns.probe.require_live_namespace()
    assert __debug__ and os.environ['HONK_CI_VM_LANE'] in ('floor', 'recent')
    assert os.uname().release == os.environ['HONK_CI_EXPECTED_KERNEL']
    assert not os.path.samefile('/proc/self/ns/mnt', '/proc/1/ns/mnt')
    assert command('stat', '-f', '-c', '%T', '/run').strip() == 'tmpfs'
    assert not any(Path('/run/netns').iterdir()), 'L3 lane requires clean smoke-owned namespace names'
    daemon, core, xsk, output = map(Path, sys.argv[1:])
    for binary in (daemon, core, xsk):
        assert binary.is_absolute() and os.access(binary, os.X_OK), binary
    pins = Path(os.environ['HONK_XDP_PIN_ROOT']).resolve(strict=True)
    assert output.resolve(strict=True).parent == pins.parent
    assert command('stat', '-f', '-c', '%T', pins).strip() == 'bpf_fs'

    def deadline(signo, _frame):
        raise TimeoutError(f'L3 LAN guest deadline ({signal.Signals(signo).name})')

    signal.signal(signal.SIGALRM, deadline)
    signal.signal(signal.SIGTERM, deadline)
    for workers in (1, 2):
        signal.alarm(200)
        try:
            matrix(daemon, core, xsk, workers, output / f'{workers}q', pins / f'l3-lan-{workers}q')
        finally:
            signal.alarm(0)
        record('profile-complete', workers=workers)


if __name__ == '__main__':
    main()
