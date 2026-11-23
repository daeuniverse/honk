"""Ordinary UDP gateway wire cases driven by the guarded guest entry."""
import contextlib
import json
import os
import select
import socket
import struct
import subprocess
import time

from xdp_dns_tcp import owners


PROFILES = ('udp-static-1', 'udp-dns-1', 'udp-static-2', 'udp-dns-2')
OTHER_LAN = '192.0.2.3'
WAN_TARGET = '198.51.100.7'
EARLIER_PORT = 18155
LEGACY_CASES = (
    'lan-missing', 'learn-a', 'lan-a', 'dns-dependent-port-53', 'learn-aaaa', 'lan-aaaa',
    'learn-wan', 'wan', 'static-port-53', 'learn-conflict', 'lan-conflict', 'learn-zero',
    'lan-known-zero', 'learn-expiry', 'lan-before-expiry', 'lan-expired',
)
LEGACY_NATIVE = ('lan-a', 'lan-aaaa', 'lan-before-expiry')
TABLE = 'inet honk_dns_udp_wire'


def set_forward_tuple(ingress, origin, target):
    family = 'ip6' if ':' in origin[0] else 'ip'
    rules = f'''flush chain {TABLE} forward
add rule {TABLE} forward iifname "{ingress}" {family} saddr {origin[0]} {family} daddr {target[0]} udp sport {origin[1]} udp dport {target[1]} counter name outbound
add rule {TABLE} forward oifname "{ingress}" {family} saddr {target[0]} {family} daddr {origin[0]} udp sport {target[1]} udp dport {origin[1]} counter name inbound
'''
    subprocess.run(['ip', 'netns', 'exec', 'dut', 'nft', '-f', '-'],
                   input=rules, text=True, timeout=5, check=True)


def forward_counts():
    output = subprocess.check_output(['ip', 'netns', 'exec', 'dut', 'nft', '-j', 'list', 'table', *TABLE.split()],
                                     text=True, timeout=5)
    counts = {row['name']: row['packets'] for item in json.loads(output)['nftables']
              if (row := item.get('counter')) and row['table'] == 'honk_dns_udp_wire'}
    assert set(counts) == {'outbound', 'inbound'}, counts
    return counts


def udp_frames(f, shape, origin, target, payload):
    source, destination = f.address_bytes(origin[0]), f.address_bytes(target[0])
    length = 8 + len(payload)
    udp = struct.pack('!HHHH', origin[1], target[1], length, 0) + payload
    # A fragment header does not contribute to the UDP pseudo-header length.
    if shape == 'ipv6-atomic':
        pseudo = source + destination + struct.pack('!I3xB', length, 17)
    else:
        pseudo = source + destination + struct.pack('!BBH', 0, 17, length)
    udp = udp[:6] + struct.pack('!H', f.probe.checksum(pseudo + udp) or 0xffff) + udp[8:]
    macs = bytes.fromhex('020000000010020000000020')
    if shape == 'ipv6-atomic':
        ip = struct.pack('!IHBB16s16s', 6 << 28, 8 + length, 44, 64, source, destination)
        return [macs + b'\x86\xdd' + ip + struct.pack('!BBHI', 17, 0, 0, origin[1]) + udp]
    assert shape == 'ipv4-fragmented' and length > 32
    frames = []
    for bits, fragment in [(0x2000, udp[:32]), (32 // 8, udp[32:])]:
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(fragment), origin[1], bits,
                         64, 17, 0, source, destination)
        ip = ip[:10] + struct.pack('!H', f.probe.checksum(ip)) + ip[12:]
        frames.append(macs + b'\x08\x00' + ip + fragment)
    return frames


def peer_sockets(f, owned, target, client_namespace):
    peers = {}
    for realm, device in [('server', 'su'), ('shadow-wan', 's0')]:
        if realm == client_namespace:
            continue  # The WAN client's target is local only on the marked path.
        with f.namespace(realm):
            server = owned.enter_context(socket.socket(f.family(target[0]), socket.SOCK_DGRAM))
            server.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device.encode() + b'\0')
            server.bind(target)
            server.settimeout(5)
            peers[server] = {'namespace': realm, 'inode': os.stat('/proc/thread-self/ns/net').st_ino,
                             'interface': device}
    assert len({peer['inode'] for peer in peers.values()}) == len(peers), peers
    return peers


def echo(f, peers, origin, target, payload, native):
    readable, _, _ = select.select(list(peers), [], [], 5)
    assert len(readable) == 1, ('expected exactly one UDP peer', origin, target, readable)
    [server] = readable
    peer = peers[server]
    received, source = server.recvfrom(4096)
    source = source[:2]
    destination = server.getsockname()[:2]
    assert peer['namespace'] == ('shadow-wan' if native else 'server'), (origin, target, peer)
    assert destination == target and received == payload, (origin, target, destination, received)
    if native:
        assert source == origin, (origin, source, target)
    else:
        assert source[0] == (f.UP6 if ':' in target[0] else f.UP4) and source != origin, (origin, source)
    response = b'honk/udp-reply/' + os.urandom(24) if payload else b''
    assert server.sendto(response, source) == len(response)
    return response, dict(peer, source=source, destination=destination)


def wire(f, profile, pid, log):
    f.probe.require_live_namespace()
    base = 43100 + 25 * PROFILES.index(profile)  # Avoid reuse of a kernel conntrack tuple across profiles.
    enabled = profile.startswith('udp-dns-')
    workers = int(profile[-1])
    members = ('dut0', 'dut1', 'dut2') if workers == 1 else ('dut0',)
    affinity = os.sched_getaffinity(0)
    sender_cpus = sorted(affinity)[:workers]
    assert len(sender_cpus) == workers, (workers, affinity)
    identities, cases = {}, []
    observed_queues, observed_dns_cpus = set(), set()
    aaa = f.TARGET6

    def answer(name, qtype):
        if name == 'wan.pass-shadow.test':
            return WAN_TARGET, 60
        if qtype == 28:
            return aaa, 60
        return f.answer_ip(name, qtype)

    def snapshot(device):
        state = f.snapshot(device, enabled)
        identity = (state['program'], state['maps'], state['realm'])
        assert identities.setdefault(device, identity) == identity, (device, state)
        return state

    devices = {device: snapshot(device) for device in members}
    stats_ids = {state['maps']['honk_gw_stats'][0] for state in devices.values()}
    [stats_id] = stats_ids
    assert len({state['realm'] for state in devices.values()}) == len(members), devices
    print(json.dumps({'profile': profile, **owners(pid, log, members, workers), 'stats_map_id': stats_id,
                      'program_ids': {device: state['program'] for device, state in devices.items()}}), flush=True)

    def assert_reasons(case, before, after, *, dns, static, fragments):
        delta = {key: value - before['counters'][key] for key, value in after['counters'].items()}
        native = dns or static
        assert delta == dict.fromkeys(delta, 0) | {
            'pass_d1': int(static), 'pass_dns_d1': int(dns), 'xsk_new': int(not native),
            'ct_reply': int(native and workers == 1),
            'capture': int(not native) + fragments, 'xsk_fragment': fragments,
        }, (case, delta, before, after)
        return delta

    def lease(state, ip, expected):
        if not enabled or expected is None:
            return None
        if expected in ('live', 'zero'):
            return f.live_dns_fact(state, ip, expected == 'live')
        value = f.dns_fact(state, ip)
        now = time.monotonic_ns()
        if value is not None:
            assert expected == 'expired' and struct.unpack_from('=Q', value)[0] <= now, (ip, expected, value)
        return {'observed_mono_ns': now, 'raw': value.hex() if value is not None else None}

    with contextlib.ExitStack() as owned:
        upstream = f.endpoint_peer(owned, answer, record_peer_identity=True)

        def trial(case, target, payload, *, realm='client', eligible=False, static=False,
                  fact=None, shape='datagram', question=None, other_lease=False):
            device = {'client': 'dut0', 'shadow-wan': 'dut1', 'shadow-lan': 'dut2'}[realm]
            ip = {'shadow-wan': f.WAN4, 'shadow-lan': OTHER_LAN}.get(realm, f.LAN6 if ':' in target[0] else f.LAN4)
            assert len(cases) < 25, cases
            origin = (ip, base + len(cases))
            priority = len(cases) % workers
            dns = enabled and eligible
            native = static or dns
            fragmented = shape == 'ipv4-fragmented'
            before = snapshot(device)
            local_lease = lease(before, target[0], fact)
            lan_lease = lease(snapshot('dut0'), target[0], 'live') if other_lease else None
            set_forward_tuple(device, origin, target)
            forward_before = forward_counts()
            upstream_count = len(upstream)
            first_fragment = None
            with contextlib.ExitStack() as sockets:
                peers = peer_sockets(f, sockets, target, realm) if question is None else {}
                with f.namespace(realm):
                    client = sockets.enter_context(socket.socket(f.family(ip), socket.SOCK_DGRAM))
                    if shape == 'datagram':
                        sender = client
                        frames = [payload]
                    else:
                        assert realm == 'client'
                        sender = sockets.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)))
                        sender.bind(('c0', 0))
                        frames = udp_frames(f, shape, origin, target, payload)
                client.settimeout(5)
                client.bind(origin)
                client.connect(target)
                sender.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, priority)
                for index, frame in enumerate(frames):
                    os.sched_setaffinity(0, {sender_cpus[priority]})
                    try:
                        assert sender.send(frame) == len(frame)
                    finally:
                        os.sched_setaffinity(0, affinity)
                    if fragmented and index == 0:
                        deadline = time.monotonic() + 2
                        while True:
                            first = snapshot(device)
                            if first['counters']['capture'] > before['counters']['capture']:
                                break
                            assert time.monotonic() < deadline, ('first fragment never captured', case, first)
                            time.sleep(0.005)
                        first_fragment = assert_reasons(case, before, first, dns=False, static=False, fragments=0)
                        assert forward_counts() == forward_before and not select.select(list(peers), [], [], 0)[0], case
                if question is None:
                    response, peer = echo(f, peers, origin, target, payload, native)
                    assert client.recv(4096) == response, ('wrong UDP reply', case)
                else:
                    response = client.recv(4096)
                    name, qtype = question
                    address, ttl = answer(name, qtype)
                    f.verify_answer(response, payload[12:], struct.unpack_from('!H', payload)[0], qtype, address, ttl)
                    [peer] = upstream[upstream_count:]
                    assert (peer['name'], peer['qtype']) == question, peer
                assert not select.select([client, *peers], [], [], 0.1)[0], ('duplicate UDP delivery', case)
                assert len(upstream) - upstream_count == int(question is not None), ('unexpected DNS upstream traffic', case)

            after = snapshot(device)
            expired_lease = None
            if fact == 'expired':
                if enabled:
                    assert 0 < before['epoch'] <= after['epoch'], (case, before, after)
                    expired_lease = lease(after, target[0], 'expired')
                else:
                    assert before['epoch'] == after['epoch'] == 0, (case, before, after)
            elif question is None:
                assert after['epoch'] == before['epoch'], (case, before, after)
            delta = assert_reasons(case, before, after, dns=dns, static=static, fragments=int(fragmented))
            forward_after = forward_counts()
            forward = {key: value - forward_before[key] for key, value in forward_after.items()}
            assert forward == dict.fromkeys(forward_before, int(native)), (case, forward)
            queue_delta = [y - x for x, y in zip(before['queues'], after['queues'], strict=True)]
            assert len(queue_delta) == workers, (device, queue_delta, workers)
            assert all(count >= 0 for count in queue_delta) and sum(queue_delta) == delta['capture'], (case, queue_delta)
            observed_queues.update((device, queue) for queue, count in enumerate(queue_delta) if count)
            dns_cpus = [i for i, (x, y) in enumerate(zip(before['dns_by_cpu'], after['dns_by_cpu'], strict=True)) if y > x]
            assert len(dns_cpus) == int(dns), (case, dns_cpus)
            observed_dns_cpus.update(dns_cpus)
            row = {'profile': profile, 'case': case, 'origin': origin, 'target': target, 'ingress': device, 'shape': shape,
                   'realm': before['realm'], 'program_id': before['program'],
                   'dns_epoch_before': before['epoch'], 'dns_epoch': after['epoch'],
                   'dns_fact': local_lease, 'other_lan_fact': lan_lease, 'peer': peer,
                   'request_hex': payload.hex(), 'reply_hex': response.hex(),
                   'delta': delta, 'forward_before': forward_before, 'forward_after': forward_after,
                   'capture_by_queue_before': before['queues'], 'capture_by_queue_after': after['queues'],
                   'dns_pass_cpus': dns_cpus, 'send_priority': priority, 'sender_affinity_cpu': sender_cpus[priority]}
            if first_fragment is not None:
                row['first_fragment'] = {'delta': first_fragment, 'capture_by_queue': first['queues']}
            if question:
                row['answer'] = address
            if fact == 'expired':
                row['dns_fact_after'] = expired_lease
            print(json.dumps(row), flush=True)
            cases.append(case)
            return local_lease

        def packet(case, ip, *, port=f.PORT, empty=False, **expected):
            data = b'' if empty else b'honk/udp-wire/' + case.encode() + b'/' + os.urandom(32)
            return trial(case, (ip, port), data, **expected)

        def learn(case, name, qtype, *, realm='client'):
            question = f.name_wire(name) + struct.pack('!HH', qtype, 1)
            query = struct.pack('!HHHHHH', 0xa000 + len(cases), 0x0100, 1, 0, 0, 0) + question
            trial(case, f.DNS, query, realm=realm, question=(name, qtype))
            return time.monotonic_ns() + answer(name, qtype)[1] * 1_000_000_000

        packet('lan-missing', f.TARGET4, fact='absent')
        learn('learn-a', 'learn.pass-shadow.test', 1)
        ipv4 = packet('lan-a', f.TARGET4, fact='live', eligible=True)
        port53 = packet('dns-dependent-port-53', f.TARGET4, port=53, fact='live')
        assert not enabled or ipv4['value'] == port53['value'], (ipv4, port53)
        packet('lan-earlier-rule', f.TARGET4, port=EARLIER_PORT, fact='live')
        packet('lan-empty', f.TARGET4, empty=True, fact='live', eligible=True)
        packet('lan-fragmented', f.TARGET4, fact='live', shape='ipv4-fragmented')
        if workers == 1:
            packet('other-lan', f.TARGET4, realm='shadow-lan', fact='absent', other_lease=True)
        learn('learn-aaaa', 'learn.pass-shadow.test', 28)
        ipv6 = packet('lan-aaaa', f.TARGET6, fact='live', eligible=True)
        packet('lan-ipv6-atomic', f.TARGET6, fact='live', eligible=True, shape='ipv6-atomic')
        aaa = 'fd00:2::7'
        learn('learn-aaaa-replacement', 'learn.pass-shadow.test', 28)
        if enabled:
            lease(snapshot('dut0'), aaa, 'live')
            assert time.monotonic_ns() < ipv6['value']['valid_before_mono_ns'], ipv6
        packet('lan-withdrawn', f.TARGET6, fact='absent')
        if workers == 1:
            learn('learn-lan-wan-target', 'wan.pass-shadow.test', 1)
            learn('learn-wan', 'wan.pass-shadow.test', 1, realm='shadow-wan')
            packet('wan', WAN_TARGET, realm='shadow-wan', fact='absent', other_lease=True)
        packet('static-port-53', f.STATIC, port=53, static=True)
        learn('learn-a-again', 'learn.pass-shadow.test', 1)
        a = lease(snapshot('dut0'), f.TARGET4, 'live')
        learn('learn-conflict', 'conflict.test', 1)
        if enabled:
            assert time.monotonic_ns() < a['value']['valid_before_mono_ns'], a
        packet('lan-conflict', f.TARGET4, fact='absent')
        learn('learn-zero', 'zero.test', 1)
        packet('lan-known-zero', f.STATIC, fact='zero')
        deadline = learn('learn-expiry', 'expire.pass-shadow.test', 1)
        expiring = packet('lan-before-expiry', f.EXPIRING, fact='live', eligible=True)
        if enabled:
            deadline = expiring['value']['valid_before_mono_ns']
        time.sleep(max(0, (deadline - time.monotonic_ns()) / 1e9) + 0.05)
        packet('lan-expired', f.EXPIRING, fact='expired')
    assert observed_queues == {(member, queue) for member in members for queue in range(workers)}, observed_queues
    assert not enabled or len(observed_dns_cpus) >= workers, observed_dns_cpus
    print(json.dumps({'profile': profile, 'cases': cases, 'captured_queues_observed': sorted(observed_queues),
                      'dns_pass_cpus_observed': sorted(observed_dns_cpus)}), flush=True)


def compare(baseline, enabled):
    left, right = ([json.loads(line) for line in path.read_text().splitlines()] for path in (baseline, enabled))
    assert left[0]['executable_sha256'] == right[0]['executable_sha256']
    assert left[0]['bound_queues'] == right[0]['bound_queues']
    has_wan = 'dut1' in left[0]['bound_queues']
    legacy = tuple(case for case in LEGACY_CASES if has_wan or case not in ('learn-wan', 'wan'))
    extra = {'lan-earlier-rule', 'lan-empty', 'lan-fragmented', 'lan-ipv6-atomic',
             'learn-aaaa-replacement', 'lan-withdrawn', 'learn-a-again'}
    if has_wan:
        extra.update(('other-lan', 'learn-lan-wan-target'))
    off, on = left[1:-1], right[1:-1]
    cases = [row['case'] for row in off]
    assert cases == [row['case'] for row in on] == left[-1]['cases'] == right[-1]['cases']
    assert len(cases) == len(set(cases)) and tuple(case for case in cases if case in legacy) == legacy, cases
    assert set(cases) == set(legacy) | extra, cases
    changed = []
    for a, b in zip(off, on, strict=True):
        assert a['program_id'] != b['program_id'] and a['origin'][0] == b['origin'][0] and a['origin'][1] != b['origin'][1]
        assert all(a[key] == b[key] for key in ('target', 'ingress', 'realm', 'shape')), (a, b)
        if 'answer' in a:
            assert a['answer'] == b['answer'] and a['delta'] == b['delta'], (a, b)
            assert {key: value for key, value in a['peer'].items() if key != 'source_port'} == {
                key: value for key, value in b['peer'].items() if key != 'source_port'}, (a, b)
            continue
        if a['peer']['inode'] != b['peer']['inode']:
            assert a['peer']['namespace'] == 'server' and b['peer']['namespace'] == 'shadow-wan', (a, b)
            assert b['peer']['source'] == b['origin'] and b['delta']['pass_dns_d1'] == 1, b
            changed.append(b['case'])
        else:
            assert (a['peer']['namespace'], a['peer']['interface'], a['peer']['source'][0], a['delta']) == (
                b['peer']['namespace'], b['peer']['interface'], b['peer']['source'][0], b['delta']), (a, b)
    assert tuple(case for case in changed if case in legacy) == LEGACY_NATIVE, changed
    assert set(changed) - set(legacy) == {'lan-empty', 'lan-ipv6-atomic'}, changed
    print(json.dumps({'gateway_dns_udp_wire': {'cases': cases, 'legacy_cases': legacy, 'legacy_changed_peer': LEGACY_NATIVE,
                                              'changed_peer': changed, 'bound_queues': left[0]['bound_queues'],
                                              'enabled_capture_queues_observed': right[-1]['captured_queues_observed'],
                                              'enabled_dns_pass_cpus_observed': right[-1]['dns_pass_cpus_observed']}}), flush=True)
