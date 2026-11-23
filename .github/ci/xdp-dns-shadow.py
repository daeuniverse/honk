#!/usr/bin/env python3
"""Read actual kernel gateway counters/JIT and drive the transparent DNS wire fixture."""
import contextlib
import errno
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
loader = SourceFileLoader('xdp_probe', str(Path(__file__).with_name('xdp-ipv4-options.py')))
probe = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(probe)
C = probe.C

LAN4, LAN6 = '192.0.2.2', 'fd00:1::2'
WAN4 = '198.51.100.3'
TARGET4, TARGET6, EXPIRING, STATIC = '198.51.100.2', 'fd00:2::2', '198.51.100.4', '198.51.100.6'
UP4, UP6 = '10.77.0.1', 'fd00:77::1'
DNS = ('198.51.100.99', 53)
PORT = 18154
SHADOW_MAPS = {'dns_facts', 'dns_epochs'}
JIT_BUDGET = 800_000


@contextlib.contextmanager
def namespace(name):
    home = os.open('/proc/self/ns/net', os.O_RDONLY)
    directory = os.open('/run/netns/' + name, os.O_RDONLY)
    try:
        os.setns(directory, 0)
        yield
    finally:
        os.setns(home, 0)
        os.close(directory)
        os.close(home)


def info(fd, size, setup=lambda _: None):
    data = C.create_string_buffer(size)
    setup(data)
    attr = probe.Info(fd, size, C.addressof(data))
    probe.bpf(15, attr)
    assert attr.length == size, ('truncated BPF object info', size, attr.length)
    return data


def program_maps(program):
    ids = (C.c_uint32 * 32)()

    def setup(header):
        struct.pack_into('=I', header, 52, len(ids))
        struct.pack_into('=Q', header, 56, C.addressof(ids))

    header = info(program, 80, setup)
    count = struct.unpack_from('=I', header, 52)[0]
    assert 0 < count <= len(ids)
    result = {}
    for identity in ids[:count]:
        fd = probe.bpf(14, probe.Id(id=identity))
        try:
            header = info(fd, 40)
            kind, observed, key, value, entries, flags = struct.unpack_from('=IIIIII', header)
            name = header.raw[24:40].rstrip(b'\0').decode()
            assert observed == identity and identity > 0
            if name in SHADOW_MAPS or name in {'honk_gw_stats', 'honk_gw_realms', 'honk_xdp_count'}:
                assert name not in result, (name, result)
                result[name] = (identity, kind, key, value, entries, flags)
        finally:
            os.close(fd)
    return result


def map_value(details, key, length):
    identity, _, key_size, value_size, _, _ = details
    assert key_size == len(key) and length >= value_size, (details, key, length)
    fd = probe.bpf(14, probe.Id(id=identity))
    try:
        source, target = C.create_string_buffer(key), C.create_string_buffer(length)
        try:
            probe.bpf(1, probe.Element(fd, 0, C.addressof(source), C.addressof(target), 0))
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise
            return None
        return target.raw
    finally:
        os.close(fd)


def saved_jit(program, role, identity, out, mode):
    # struct bpf_prog_info through verified_insns and attach_btf_obj_id.
    header = info(program, 224)
    kind, observed = struct.unpack_from('=II', header)
    jited_len, xlated_len = struct.unpack_from('=II', header, 16)
    func_count = struct.unpack_from('=I', header, 108)[0]
    processed = struct.unpack_from('=I', header, 216)[0]
    name = header.raw[64:80].rstrip(b'\0').decode()
    assert (kind, observed, name) == (6, identity, 'honk_gw_' + role)
    assert 0 < processed <= JIT_BUDGET, ('verifier instruction budget', mode, role, identity, processed)
    assert 0 < jited_len < 1_000_000 and 0 < xlated_len < 1_000_000 and xlated_len % 8 == 0
    assert func_count == 2, ('generated wrapper + routing subprogram', func_count)
    jited = C.create_string_buffer(jited_len)
    xlated = C.create_string_buffer(xlated_len)
    funcs = (C.c_uint32 * func_count)()

    def setup(data):
        struct.pack_into('=IIQQ', data, 16, jited_len, xlated_len, C.addressof(jited), C.addressof(xlated))
        struct.pack_into('=I', data, 108, func_count)
        struct.pack_into('=Q', data, 120, C.addressof(funcs))

    second = info(program, 224, setup)
    assert second.raw[:24] == header.raw[:24] and struct.unpack_from('=I', second, 108)[0] == func_count
    assert all(funcs) and sum(funcs) == jited_len and any(jited.raw) and any(xlated.raw), (list(funcs), jited_len)
    maps = program_maps(program)
    assert SHADOW_MAPS.intersection(maps) == (SHADOW_MAPS if mode == 'shadow' else set()), maps
    stem = out / f'{mode}-{role}'
    stem.with_suffix('.jited').write_bytes(jited.raw)
    stem.with_suffix('.xlated').write_bytes(xlated.raw)
    wrapper = stem.with_suffix('.wrapper')
    wrapper.write_bytes(jited.raw[:funcs[0]])
    arch = os.uname().machine
    disasm = subprocess.check_output([
        'objdump', '-D', '-b', 'binary', '-m', {'x86_64': 'i386:x86-64', 'aarch64': 'aarch64'}[arch],
        '--no-show-raw-insn', str(wrapper),
    ], text=True, timeout=15)
    stem.with_suffix('.asm').write_text(disasm)
    kind = check_exchange(arch, xlated.raw, disasm, mode == 'shadow')
    return {'arch': arch, 'program_id': identity, 'mode': mode, 'role': role,
            'verified_insns': processed, 'jited_bytes': jited_len, 'jited_func_lens': list(funcs),
            'atomic': kind, 'map_ids': {name: row[0] for name, row in maps.items()}}


def check_exchange(arch, xlated, disassembly, enabled):
    instructions = list(struct.iter_unpack('=BBhi', xlated))
    exchanges = [i for i, (op, _, _, imm) in enumerate(instructions) if (op, imm) == (0xdb, 0xe1)]
    rows = [(int(offset, 16), re.sub(r'\s+', ' ', text.partition('//')[0].strip()))
            for offset, text in re.findall(r'^\s*([0-9a-f]+):\s+(.+)$', disassembly, re.M)]
    assert rows and rows[0][0] == 0
    if arch == 'x86_64':
        positions = [i for i, (_, text) in enumerate(rows) if re.match(r'(?:lock )?xchgq? ', text) and '(' in text]
        if not enabled:
            assert not exchanges and not positions
            return 'none'
        [i], [j] = exchanges, positions
        assert instructions[i - 3] == (0xb7, 3, 0, 8) and instructions[i - 2][0] == 0x85
        assert instructions[i - 1:i + 1] == [(0xb7, 1, 0, 0), (0xdb, 0x18, 0, 0xe1)]
        assert re.fullmatch(r'(?:lock )?xchgq? %rdi,\s*(?:0x0)?\(%r14\)', rows[j][1]), rows[j - 2:j + 2]
        assert re.fullmatch(r'(?:xor[lq]? %(edi|rdi),\s*%\1|mov[ql]? \$0x0,\s*%(?:edi|rdi))', rows[j - 1][1]), rows[j - 2:j + 2]
        return 'x86-64 memory xchg'

    # ARM64 Linux 6.12 uses SWPAL with LSE and a release-exclusive retry loop
    # followed by DMB ISH otherwise. Both swaps must address the same busy word.
    def at_busy(text):
        return re.fullmatch(r'(?:swpal x[01], x[01]|ld(?:a)?xr x[01]), \[x21\]', text) is not None

    positions = [i for i, (_, text) in enumerate(rows) if at_busy(text)]
    if not enabled:
        assert not exchanges and not positions
        return 'none'
    [i, k], [j, l] = exchanges, positions
    assert instructions[i - 4] == (0xb7, 3, 0, 8) and instructions[i - 3][0] == 0x85
    assert k == i + 1 and instructions[i - 2:k + 1] == [
        (0xb7, 1, 0, 0), (0xb7, 2, 0, 1), (0xdb, 0x28, 0, 0xe1), (0xdb, 0x18, 0, 0xe1),
    ]
    lse = rows[j][1] == 'swpal x1, x1, [x21]'
    start = j if lse else j - 1
    assert re.fullmatch(r'mov [wx]0, (?:#0x0|[wx]zr)', rows[start - 2][1]), rows[start - 2:start + 1]
    assert re.fullmatch(r'mov [wx]1, #0x1', rows[start - 1][1]), rows[start - 2:start + 1]
    if lse:
        assert l == j + 1 and rows[l][1] == 'swpal x0, x0, [x21]', rows[j:l + 1]
        return 'arm64 LSE SWPAL pair'
    assert l == j + 5, rows[j - 1:l + 4]
    for index, source in [(j, 'x1'), (l, 'x0')]:
        offset, load = rows[index]
        assert load in (f'ldxr {source}, [x21]', f'ldaxr {source}, [x21]'), rows[index - 1:index + 4]
        copy = re.fullmatch(rf'mov (x\d+), {source}', rows[index - 1][1])
        store = re.fullmatch(r'stlxr (w\d+), (x\d+), \[x21\]', rows[index + 1][1])
        retry = re.fullmatch(r'cbnz (w\d+), (?:0x)?([0-9a-f]+)', rows[index + 2][1])
        assert copy and store and retry and copy[1] == store[2] and store[1] == retry[1]
        assert int(retry[2], 16) == offset and rows[index + 3][1] == 'dmb ish', rows[index - 1:index + 4]
    return 'arm64 LL/SC and DMB ISH pair'


def dump_jit(mode, role, identity, directory):
    assert mode in ('static', 'shadow') and role in ('boot', 'data') and identity > 0
    fd = probe.bpf(13, probe.Id(id=identity))
    try:
        result = saved_jit(fd, role, identity, directory, mode)
    finally:
        os.close(fd)
    print(json.dumps({'gateway_dns_jit': result}), flush=True)


def verifier_budget(path):
    text = path.read_text()
    cases = [json.loads(record)['gateway_dns_jit']
             for record in re.findall(r'(\{"gateway_dns_jit": [^\n]+)$', text, re.M)]
    assert [(row['mode'], row['role']) for row in cases] == [
        ('static', 'boot'), ('static', 'data'), ('shadow', 'boot'), ('shadow', 'data'),
    ]
    assert len({row['program_id'] for row in cases}) == 4
    for row in cases[2:]:
        identity = row['program_id']
        logs = [line for line in text.splitlines() if 'gateway DNS shadow verifier' in line
                and re.search(rf'\bprogram_id={identity}\b', line)]
        [line] = logs
        assert f'data={str(row["role"] == "data").lower()}' in line, line
        match = re.search(r'processed (\d+) insns \(limit (\d+)\) max_states_per_insn (\d+) total_states (\d+) peak_states (\d+)', line)
        assert match, line
        processed, limit, max_states, total, peak = map(int, match.groups())
        assert 0 < processed == row['verified_insns'] <= JIT_BUDGET < limit == 1_000_000
        assert max_states > 0 and 0 < peak <= total, line
        row.update(limit=limit, max_states_per_insn=max_states, total_states=total, peak_states=peak)
    print(json.dumps({'gateway_dns_verifier': cases}), flush=True)


def possible_cpus():
    count = 0
    for item in Path('/sys/devices/system/cpu/possible').read_text().strip().split(','):
        first, _, last = item.partition('-')
        count += int(last or first) - int(first) + 1
    return count


def snapshot(device, enabled):
    with namespace('dut'):
        program = probe.program_fd(device, 'data')
        try:
            identity = probe.program_identity(program, device, 'data')
            maps = program_maps(program)
            assert SHADOW_MAPS.intersection(maps) == (SHADOW_MAPS if enabled else set()), maps
            stats = maps['honk_gw_stats']
            assert stats[1:5] == (6, 4, 8, 19), stats
            counter = maps['honk_xdp_count']
            length = 8 * possible_cpus()
            counters = {label: sum(x[0] for x in struct.iter_unpack('=Q', map_value(stats, struct.pack('=I', key), length)))
                        for label, key in [('pass_d1', 8), ('xsk_new', 9), ('would_pass_dns', 18)]}
            assert counter[1:4] == (2, 4, 8) and 5 <= counter[4] <= 260, counter
            counters['capture'] = sum(struct.unpack('=Q', map_value(counter, struct.pack('=I', queue), 8))[0]
                                      for queue in range(counter[4] - 4))
            realm = struct.unpack('=I', map_value(maps['honk_gw_realms'],
                                                 struct.pack('=I12x', socket.if_nametoindex(device)), 4))[0]
            assert 0 < realm <= 64, (device, realm)
            epoch = 0
            if enabled:
                assert maps['dns_facts'][1:] == (1, 32, 40, 4096, 0), maps
                epochs = maps['dns_epochs']
                assert epochs[1:] == (2, 4, 64, maps['honk_gw_realms'][4] + 1, 1024), epochs
                value = map_value(epochs, struct.pack('=I', realm), 64)
                assert value is not None, ('missing captured realm slot', device, realm)
                epoch = struct.unpack_from('=Q', value)[0]
                assert (epoch > 0) == (device == 'dut0'), (device, realm, epoch)
            return {'program': identity, 'maps': maps, 'realm': realm, 'epoch': epoch, 'counters': counters,
                    'forward': probe.forward_fence_packets()}
        finally:
            os.close(program)


def answer_ip(name, qtype):
    return {
        ('learn.pass-shadow.test', 1): (TARGET4, 60),
        ('learn.pass-shadow.test', 28): (TARGET6, 60),
        ('wan.pass-shadow.test', 1): (TARGET4, 60),
        ('conflict.test', 1): (TARGET4, 60),
        ('zero.test', 1): (STATIC, 60),
        ('expire.pass-shadow.test', 1): (EXPIRING, 3),
    }[(name, qtype)]


def family(address):
    return socket.AF_INET6 if ':' in address else socket.AF_INET


def address_bytes(address):
    return socket.inet_pton(family(address), address)


def live_dns_fact(state, ip, nonzero):
    canonical = address_bytes(ip)
    if family(ip) == socket.AF_INET:
        canonical = b'\0' * 10 + b'\xff\xff' + canonical
    key = struct.pack('=QII', state['epoch'], state['realm'], 0) + canonical
    with namespace('dut'):
        fact = map_value(state['maps']['dns_facts'], key, 40)
    assert fact is not None, ('missing current DNS fact', ip, state)
    deadline, bitmap = struct.unpack('=Q32s', fact)
    now = time.monotonic_ns()
    assert now < deadline and any(bitmap) == nonzero, (ip, state, now, deadline, bitmap.hex())
    return {'observed_mono_ns': now, 'value': {'valid_before_mono_ns': deadline, 'bitmap': bitmap.hex()}}


def name_wire(name):
    return b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\0'


def endpoint_peer(owned):
    sockets = {}
    with namespace('server'):
        uplink = socket.if_nametoindex('su')
        for ip, port in [('10.77.0.2', 15353), (TARGET4, PORT), (TARGET6, PORT), (EXPIRING, PORT),
                         (STATIC, PORT), (TARGET4, 53)]:
            sock = owned.enter_context(socket.socket(family(ip), socket.SOCK_DGRAM))
            if family(ip) == socket.AF_INET:
                sock.setsockopt(socket.IPPROTO_IP, 8, 1)  # IP_PKTINFO
            else:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
            sock.bind((ip, port))
            sockets[sock] = (ip, port)
    stop_read, stop_write = socket.socketpair()
    owned.enter_context(stop_read)
    owned.enter_context(stop_write)
    events, errors = [], []

    def run():
        try:
            while True:
                read, _, _ = select.select([stop_read, *sockets], [], [], 30)
                assert read, 'independent peer idle deadline'
                if stop_read in read:
                    return
                for sock in read:
                    data, ancillary, flags, source = sock.recvmsg(4096, socket.CMSG_SPACE(20))
                    ip, port = sockets[sock]
                    assert flags == 0 and len(ancillary) == 1
                    [(level, kind, wire)] = ancillary
                    if family(ip) == socket.AF_INET:
                        assert (level, kind) == (socket.IPPROTO_IP, 8), ancillary
                        ifindex, _, destination = struct.unpack('=I4s4s', wire)
                    else:
                        assert (level, kind) == (socket.IPPROTO_IPV6, socket.IPV6_PKTINFO), ancillary
                        destination, ifindex = struct.unpack('=16sI', wire)
                    assert destination == address_bytes(ip) and ifindex == uplink, (destination, ifindex, ip)
                    assert source[0] == (UP4 if family(ip) == socket.AF_INET else UP6), source
                    if port == 15353:
                        end = probe.dns_name_end(data, 12)
                        qtype, qclass = struct.unpack_from('!HH', data, end)
                        question = data[12:end + 4]
                        name = next(label for label in ('learn.pass-shadow.test', 'wan.pass-shadow.test', 'conflict.test',
                                                         'zero.test', 'expire.pass-shadow.test')
                                    if question == name_wire(label) + struct.pack('!HH', qtype, 1))
                        assert qclass == 1
                        address, ttl = answer_ip(name, qtype)
                        body = address_bytes(address)
                        response = (data[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + question
                                    + b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, ttl, len(body)) + body)
                        events.append({'kind': 'dns', 'name': name, 'qtype': qtype, 'source': source[0], 'destination': ip,
                                       'port': port, 'ingress': 'su'})
                    else:
                        response = data
                        events.append({'kind': 'echo', 'payload': data.decode(), 'source': source[0], 'destination': ip,
                                       'port': port, 'ingress': 'su'})
                    sock.sendto(response, source)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=run)
    thread.start()

    def finish():
        stop_write.send(b'\0')
        thread.join(5)
        assert not thread.is_alive(), 'independent peer failed to stop'
        if errors:
            raise errors[0]

    owned.callback(finish)
    return events


def client_exchange(realm, source, destination, payload, expect_reply=True):
    with namespace(realm):
        sock = socket.socket(family(source[0]), socket.SOCK_DGRAM)
    with sock:
        sock.settimeout(5 if expect_reply else 0.4)
        sock.bind(source)
        sock.connect(destination)
        assert sock.send(payload) == len(payload)
        if expect_reply:
            return sock.recv(4096)
        try:
            data = sock.recv(4096)
        except TimeoutError:
            return None
        raise AssertionError(('static D1 leaked through the independent native-forward fence', data))


def wire(enabled):
    expected_rows = []
    with contextlib.ExitStack() as owned:
        events = endpoint_peer(owned)
        first = {}

        def trial(label, destination, payload, *, realm='client', source=LAN4, hit=False, static=False,
                  live_bitmap=None, same_fact_as=None):
            device = 'dut0' if realm == 'client' else 'dut1'
            before, event_count = snapshot(device, enabled), len(events)
            if device in first:
                assert (before['program'], before['maps']) == first[device], ('live program/map changed', device)
            else:
                first[device] = before['program'], before['maps']
            fact = None
            expected_bitmap = True if hit else live_bitmap
            if enabled and expected_bitmap is not None:
                fact = live_dns_fact(before, destination[0], expected_bitmap)
                if same_fact_as is not None:
                    assert (device, before['realm'], before['epoch'], fact['value']) == (
                        same_fact_as['interface'], same_fact_as['realm'], same_fact_as['dns_epoch'],
                        same_fact_as['dns_fact']['value']), (label, fact, same_fact_as)
            origin = (source, 43100 + len(expected_rows))
            result = client_exchange(realm, origin, destination, payload, not static)
            after = snapshot(device, enabled)
            assert (after['program'], after['maps']) == first[device], ('live program/map changed', device)
            if fact is not None:
                assert (after['realm'], after['epoch']) == (before['realm'], before['epoch']), (label, before, after)
            delta = {key: value - before['counters'][key] for key, value in after['counters'].items()}
            assert delta == {'pass_d1': int(static), 'xsk_new': int(not static), 'capture': int(not static),
                             'would_pass_dns': int(enabled and hit)}, (label, delta, before, after)
            forward = after['forward'] - before['forward']
            assert forward == int(static), (label, before, after)
            branches = events[event_count:]
            assert len(branches) == int(not static), (label, branches, events)
            expected_rows.append({'case': label, 'origin': list(origin), 'target': list(destination), 'interface': device,
                                  'realm': before['realm'], 'program_id': before['program'], 'dns_epoch': after['epoch'],
                                  'dns_fact': fact, 'delta': delta, 'native_forward': forward,
                                  'peer': branches[0] if branches else None})
            print(json.dumps(expected_rows[-1]), flush=True)
            return result

        def echo(label, ip, *, port=PORT, **checks):
            data = ('shadow-wire/' + label).encode()
            result = trial(label, (ip, port), data, **checks)
            assert result == data, (label, result)
            assert expected_rows[-1]['peer']['payload'] == data.decode()
            return expected_rows[-1]

        def learn(label, name, qtype, *, realm='client', source=LAN4):
            question = name_wire(name) + struct.pack('!HH', qtype, 1)
            serial = 0xa000 + len(expected_rows)
            request = struct.pack('!HHHHHH', serial, 0x0100, 1, 0, 0, 0) + question
            result = trial(label, DNS, request, realm=realm, source=source)
            identifier, flags, questions, answers, _, _ = struct.unpack_from('!HHHHHH', result)
            assert identifier == serial and flags & 0x800f == 0x8000 and questions == answers == 1
            assert result[12:12 + len(question)] == question
            start = probe.dns_name_end(result, 12 + len(question))
            rtype, rclass, ttl, size = struct.unpack_from('!HHIH', result, start)
            ip, maximum_ttl = answer_ip(name, qtype)
            assert (rtype, rclass) == (qtype, 1) and 0 < ttl <= maximum_ttl
            assert result[start + 10:start + 10 + size] == address_bytes(ip)
            assert expected_rows[-1]['peer']['name'] == name and expected_rows[-1]['peer']['qtype'] == qtype
            return time.monotonic_ns() + maximum_ttl * 1_000_000_000

        echo('lan-missing', TARGET4)
        learn('learn-a', 'learn.pass-shadow.test', 1)
        ipv4 = echo('lan-a', TARGET4, hit=True)
        # The AAAA observation can rotate this realm; use the same IPv4 lease for the port-53 check.
        echo('dns-dependent-port-53', TARGET4, port=53, live_bitmap=True, same_fact_as=ipv4)
        learn('learn-aaaa', 'learn.pass-shadow.test', 28)
        echo('lan-aaaa', TARGET6, source=LAN6, hit=True)
        learn('learn-wan', 'wan.pass-shadow.test', 1, realm='shadow-wan', source=WAN4)
        echo('wan', TARGET4, realm='shadow-wan', source=WAN4)
        trial('static-port-53', (STATIC, 53), b'shadow-static-53', static=True)
        learn('learn-conflict', 'conflict.test', 1)
        echo('lan-conflict', TARGET4)
        learn('learn-zero', 'zero.test', 1)
        echo('lan-known-zero', STATIC, live_bitmap=False)
        deadline = learn('learn-expiry', 'expire.pass-shadow.test', 1)
        expiring = echo('lan-before-expiry', EXPIRING, hit=True)
        if enabled:
            deadline = expiring['dns_fact']['value']['valid_before_mono_ns']
        time.sleep(max(0, (deadline - time.monotonic_ns()) / 1e9) + 0.05)
        echo('lan-expired', EXPIRING)
        assert len(events) == len(expected_rows) - 1
        realms = {row['interface']: row['realm'] for row in expected_rows}
        assert realms['dut0'] != realms['dut1'], 'fixture lacks distinct LAN and WAN realms'


def compare(baseline, shadow):
    expected = ['lan-missing', 'learn-a', 'lan-a', 'dns-dependent-port-53', 'learn-aaaa', 'lan-aaaa',
                'learn-wan', 'wan', 'static-port-53', 'learn-conflict', 'lan-conflict', 'learn-zero',
                'lan-known-zero', 'learn-expiry', 'lan-before-expiry', 'lan-expired']
    left, right = ([json.loads(line) for line in path.read_text().splitlines()] for path in (baseline, shadow))
    assert [row['case'] for row in left] == [row['case'] for row in right] == expected
    expected_hits = {'lan-a', 'lan-aaaa', 'lan-before-expiry'}
    for before, after in zip(left, right, strict=True):
        assert before['program_id'] != after['program_id']
        assert before['delta']['would_pass_dns'] == 0
        assert after['delta']['would_pass_dns'] == int(after['case'] in expected_hits)
        for key in ('origin', 'target', 'interface', 'realm', 'peer', 'native_forward'):
            assert before[key] == after[key], (key, before, after)
        for key in ('pass_d1', 'capture', 'xsk_new'):
            assert before['delta'][key] == after['delta'][key], (key, before, after)
    print(json.dumps({'gateway_dns_wire': {'cases': expected, 'would_pass_dns': sorted(expected_hits),
                                         'shadow_native_forward': sum(row['native_forward'] for row in right if row['case'] != 'static-port-53'),
                                         'static_native_forward': right[expected.index('static-port-53')]['native_forward']}}), flush=True)


def main(args):
    probe.require_live_namespace()
    mode, *values = args
    if mode == 'jit':
        kind, role, identity, out = values
        dump_jit(kind, role, int(identity), Path(out))
    elif mode == 'budget':
        verifier_budget(Path(values[0]))
    elif mode == 'wire':
        [profile] = values
        assert profile in ('static', 'shadow')
        wire(profile == 'shadow')
    elif mode == 'compare':
        compare(*map(Path, values))
    else:
        raise ValueError(mode)


if __name__ == '__main__':
    main(sys.argv[1:])
