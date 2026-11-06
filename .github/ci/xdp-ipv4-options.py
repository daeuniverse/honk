#!/usr/bin/env python3
"""Disposable-guest actual-ingress, producer identity and shutdown wire probes."""
import ctypes as C
import contextlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time

cmdline = Path('/proc/cmdline').read_text()
parent = os.environ.get('HONK_XDP_PARENT_NETNS')
current = str(os.stat('/proc/self/ns/net').st_ino)
if os.geteuid() != 0 or 'virtme.' not in cmdline or not parent or current == parent or current == str(os.stat('/proc/1/ns/net').st_ino):
    raise RuntimeError('requires the smoke-owned private disposable-guest namespace')

marker = b'HONK-IPV4-NATIVE-BOUNDARY'
path = str(Path(__file__).resolve())
domain_probe_name = b'\x0bpacket-path\x04test\0'


def command(namespace, *args):
    return ['ip', 'netns', 'exec', namespace, sys.executable, path, *args]


def ready_line(child):
    if not select.select([child.stdout], [], [], 5)[0]:
        raise TimeoutError('probe readiness deadline')
    line = child.stdout.readline().strip()
    assert line, ('probe exited before readiness', child.poll(), child.stderr.read())
    return line


def stop(child):
    if child is not None:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def frame(port, case, payload=marker):
    destinations = {
        'broadcast': ('0.0.0.0', '255.255.255.255', 'ffffffffffff'),
        'mdns4': ('192.0.2.2', '224.0.0.251', '01005e0000fb'),
        'ssdp4': ('192.0.2.2', '239.255.255.250', '01005e7ffffa'),
        'directed-broadcast': ('192.0.2.2', '10.77.0.255', 'ffffffffffff'),
        'mdns6': ('fd00:1::2', 'ff02::fb', '3333000000fb'),
        'padding': ('192.0.2.2', '198.51.100.2', '020000000010'),
    }
    source, initial, mac = destinations.get(case, ('192.0.2.2', '10.77.0.1', '020000000010'))
    if 'unicast6' in case:
        source, initial = 'fd00:1::2', 'fd00:77::1'
    if case.startswith('broadcast-unicast'):
        mac = 'ffffffffffff'
    elif case.startswith('multicast-unicast'):
        mac = '3333000000fb' if 'unicast6' in case else '01005e0000fb'
    ipv6 = ':' in source
    source = socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET, source)
    initial = socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET, initial)
    final = socket.inet_aton('198.51.100.2') if case == 'options' else initial
    source_port = 6868 if case == 'broadcast' else 41000
    length = 8 + len(payload)
    udp = struct.pack('!HHHH', source_port, port, length, 0) + payload
    pseudo = source + final + (struct.pack('!I3xB', length, 17) if ipv6 else struct.pack('!BBH', 0, 17, length))
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 65535) + udp[8:]
    if ipv6:
        ip = struct.pack('!IHBB16s16s', 6 << 28, len(udp), 17, 255, source, initial)
    else:
        options = bytes([131, 7, 4]) + final + b'\0' if case == 'options' else b''
        header_length = 20 + len(options)
        ip = struct.pack('!BBHHHBBH4s4s', 0x40 | (header_length // 4), 0, header_length + len(udp), 0x1234, 0, 64, 17, 0, source, initial) + options
        ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    tags = bytes.fromhex('88a8007b8100002d') if os.environ.get('HONK_XDP_INLINE_QINQ') == '1' else b''
    if os.environ.get('HONK_XDP_SINGLE_VLAN') == '1':
        tags = bytes.fromhex('88a8007b')
    return bytes.fromhex(mac + '020000000020') + tags + struct.pack('!H', 0x86dd if ipv6 else 0x0800) + ip + udp


class ObjectGet(C.Structure):
    _fields_ = [('pathname', C.c_uint64), ('bpf_fd', C.c_uint32), ('file_flags', C.c_uint32), ('path_fd', C.c_uint32), ('padding', C.c_uint32)]


class Info(C.Structure):
    _fields_ = [('fd', C.c_uint32), ('length', C.c_uint32), ('data', C.c_uint64)]


class Id(C.Structure):
    _fields_ = [('id', C.c_uint32), ('next', C.c_uint32), ('flags', C.c_uint32)]


class Element(C.Structure):
    _fields_ = [('fd', C.c_uint32), ('padding', C.c_uint32), ('key', C.c_uint64), ('value', C.c_uint64), ('flags', C.c_uint64)]


libc = C.CDLL(None, use_errno=True)
libc.syscall.restype = C.c_long


def bpf(operation, attr):
    assert os.uname().machine == 'x86_64', 'this BPF syscall fixture is x86_64 only'
    result = libc.syscall(321, operation, C.byref(attr), C.sizeof(attr))
    if result < 0:
        raise OSError(C.get_errno(), os.strerror(C.get_errno()))
    return result


def program_fd(device, role):
    assert role in ('data', 'guard')
    index = socket.if_nametoindex(device)
    name = C.create_string_buffer(str(Path(os.environ['HONK_XDP_PIN_ROOT']) / f'xdp-{index}' / role).encode())
    return bpf(7, ObjectGet(pathname=C.addressof(name)))


def counts(device='dut0'):
    program = program_fd(device, 'data')
    try:
        ids = (C.c_uint32 * 16)()
        info = C.create_string_buffer(80)
        struct.pack_into('=I', info, 52, len(ids))
        struct.pack_into('=Q', info, 56, C.addressof(ids))
        bpf(15, Info(program, len(info), C.addressof(info)))
        count = struct.unpack_from('=I', info, 52)[0]
        assert count <= len(ids)
        for identity in ids[:count]:
            fd = bpf(14, Id(id=identity))
            try:
                details = C.create_string_buffer(40)
                bpf(15, Info(fd, len(details), C.addressof(details)))
                if details.raw[24:40].rstrip(b'\0') != b'honk_xdp_count':
                    continue
                kind, _, key_size, value_size, entries = struct.unpack_from('=IIIII', details)
                assert (kind, key_size, value_size) == (2, 4, 8) and 5 <= entries <= 260
                values = []
                for queue in range(entries - 4):
                    key, value = C.c_uint32(queue), C.c_uint64()
                    bpf(1, Element(fd=fd, key=C.addressof(key), value=C.addressof(value)))
                    values.append(value.value)
                return values
            finally:
                os.close(fd)
        raise AssertionError('actual producer counter map unavailable')
    finally:
        os.close(program)


def native_check(baseline):
    broadcasts = json.loads(subprocess.check_output(['ip', '-n', 'dut', '-4', '-j', 'route', 'show', 'table', 'local', 'type', 'broadcast'], text=True))
    assert any(route.get('dst') in ('10.77.0.255', '10.77.0.255/32') for route in broadcasts), ('directed-broadcast control lacks a real local route', broadcasts)
    failures = []
    for case in (
        'options', 'broadcast-unicast', 'multicast-unicast',
        'broadcast-unicast-wildcard', 'multicast-unicast-wildcard',
        'broadcast-unicast6', 'multicast-unicast6',
        'broadcast-unicast6-wildcard', 'multicast-unicast6-wildcard',
        'broadcast', 'directed-broadcast', 'mdns4', 'ssdp4', 'mdns6',
    ):
        if baseline and case == 'options':
            continue
        holder = receiver = None
        try:
            selected = case == 'options' or '-unicast' in case
            port = 6767
            if selected and 'wildcard' not in case:
                holder = subprocess.Popen(command('dut', 'hold', '1', '6' if 'unicast6' in case else '4'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                port = int(ready_line(holder))
                if case == 'options':
                    subprocess.run(command('client', 'send', str(port), 'control'), check=True, timeout=5)
                    assert json.loads(ready_line(holder)) == marker.hex(), 'marked socket did not receive native control'
                    receiver = subprocess.Popen(command('server', 'receive', str(port), 'options'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    assert ready_line(receiver) == 'READY'
            else:
                receiver = subprocess.Popen(command('dut', 'receive', str(port), case), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                assert ready_line(receiver) == 'READY'
            before = None if baseline else json.loads(subprocess.check_output(command('dut', 'count'), text=True, timeout=5))
            subprocess.run(command('client', 'send', str(port), case), check=True, timeout=5)
            child = receiver if receiver is not None else holder
            result = json.loads(ready_line(child))
            if selected and not baseline:
                after = json.loads(subprocess.check_output(command('dut', 'count'), text=True, timeout=5))
                assert sum(after) - sum(before) == 1, ('selected packet escaped actual capture', case, before, after, result)
                assert result is None, ('native unicast delivery escaped capture', case, result)
            else:
                if selected and 'wildcard' not in case:
                    assert result == marker.hex(), ('native unicast baseline', case, result)
                else:
                    source = 'fd00:1::2' if case == 'mdns6' or 'unicast6' in case else '0.0.0.0' if case == 'broadcast' else '192.0.2.2'
                    port = 6868 if case == 'broadcast' else 41000
                    assert result is not None and result['data'] == marker.hex() and result['peer'][:2] == [source, port], ('native health control lost or relayed', case, result)
                if not baseline:
                    after = json.loads(subprocess.check_output(command('dut', 'count'), text=True, timeout=5))
                    assert after == before, ('native health control captured', case, before, after)
            print(json.dumps({'native_boundary': case, 'baseline': baseline, 'status': 'PASS'}), flush=True)
        except Exception as error:
            failures.append(case)
            print(json.dumps({'native_boundary': case, 'baseline': baseline, 'status': 'FAIL', 'error': str(error)}), flush=True)
        finally:
            stop(receiver)
            stop(holder)
    return bool(failures)


def guard_probe(expected, client_device, server_device):
    assert expected in ('delivered', 'refused')
    for family, client, server in (('4', '192.0.2.2', '198.51.100.2'), ('6', 'fd00:1::2', 'fd00:2::2')):
        for source, destination, device, wire, address in (
            ('client', 'server', client_device, 's0', server),
            ('server', 'client', server_device, 'c0', client),
        ):
            receiver = None
            payload = f'HONK-GUARD-WIRE/{family}/{source}'.encode().hex()
            ingress = 'dut0' if source == 'client' else 'dut1'
            before = json.loads(subprocess.check_output(command('dut', 'count', ingress), text=True, timeout=5)) if expected == 'refused' else None
            try:
                receiver = subprocess.Popen(command(destination, 'wire-receive', wire, payload), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                assert ready_line(receiver) == 'READY'
                subprocess.run(command(source, 'wire-send', family, device, address, payload), check=True, timeout=5)
                result = json.loads(ready_line(receiver))
                assert result == (expected == 'delivered'), ('guard wire oracle', family, source, expected, result)
                if before is not None:
                    after = json.loads(subprocess.check_output(command('dut', 'count', ingress), text=True, timeout=5))
                    assert sum(after) - sum(before) == 1, ('negative probe did not reach selected guard ingress', ingress, before, after)
                print(json.dumps({'guard_wire': source, 'family': family, 'expected': expected, 'status': 'PASS'}), flush=True)
            finally:
                stop(receiver)


def dns_name_end(message, offset):
    while True:
        length = message[offset]
        offset += 1
        if not length:
            return offset
        if length & 0xc0 == 0xc0:
            assert offset < len(message)
            return offset + 1
        assert length < 64 and offset + length <= len(message)
        offset += length


def domain_peer():
    with contextlib.ExitStack() as owned:
        dns = owned.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        dns.bind(('10.77.0.2', 15353))
        data_sockets = {}
        for family, address in ((socket.AF_INET, '198.51.100.2'), (socket.AF_INET6, 'fd00:2::2')):
            for port in (18082, 18083):
                sock = owned.enter_context(socket.socket(family, socket.SOCK_DGRAM))
                sock.bind((address, port))
                data_sockets[sock] = family
        received, queries = [], 0
        deadline = time.monotonic() + 30
        print('READY', flush=True)
        while time.monotonic() < deadline:
            readable, _, _ = select.select([dns, *data_sockets, sys.stdin], [], [], 1)
            for sock in readable:
                if sock is sys.stdin:
                    assert sys.stdin.readline().strip() == 'done'
                    print(json.dumps({'received': received, 'queries': queries}), flush=True)
                    return
                data, peer = sock.recvfrom(4096)
                if sock is dns:
                    end = dns_name_end(data, 12)
                    qtype, qclass = struct.unpack_from('!HH', data, end)
                    accepted = data[12:end].lower() == domain_probe_name and qclass == 1 and qtype in (1, 28)
                    answer = b''
                    if accepted:
                        queries += 1
                        address = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6, '198.51.100.2' if qtype == 1 else 'fd00:2::2')
                        answer = b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 60, len(address)) + address
                    response = data[:2] + struct.pack('!HHHHH', 0x8180 if accepted else 0x8183, 1, int(accepted), 0, 0) + data[12:end + 4] + answer
                    sock.sendto(response, peer)
                else:
                    expected = '10.77.0.1' if data_sockets[sock] == socket.AF_INET else 'fd00:77::1'
                    assert peer[0] == expected, ('packet Endpoint reply source', peer, expected)
                    received.append(data.decode('ascii'))
                    assert len(received) <= 16, received
                    sock.sendto(data, peer)
        raise TimeoutError('domain peer did not receive its completion barrier')


def domain_client():
    for family, address, qtype, label in ((socket.AF_INET, '198.51.100.2', 1, '4'), (socket.AF_INET6, 'fd00:2::2', 28, '6')):
        with socket.socket(family, socket.SOCK_DGRAM) as original, socket.socket(family, socket.SOCK_DGRAM) as fresh:
            original.settimeout(5)
            original.connect((address, 18082))
            before = ('before-' + label).encode()
            original.send(before)
            assert original.recv(4096) == before
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as query:
                query.settimeout(5)
                query.connect(('198.51.100.99', 53))
                identifier = 0xd000 + qtype
                question = domain_probe_name + struct.pack('!HH', qtype, 1)
                query.send(struct.pack('!HHHHHH', identifier, 0x100, 1, 0, 0, 0) + question)
                response = query.recv(4096)
                ident, flags, questions, answers, _, _ = struct.unpack_from('!HHHHHH', response)
                assert ident == identifier and flags & 0xf == 0 and questions == answers == 1
                start = dns_name_end(response, dns_name_end(response, 12) + 4)
                rtype, rclass, _, size = struct.unpack_from('!HHIH', response, start)
                assert (rtype, rclass) == (qtype, 1)
                assert response[start + 10:start + 10 + size] == socket.inet_pton(family, address)
            fresh.settimeout(1)
            fresh.connect((address, 18082))
            assert fresh.getsockname()[1] != original.getsockname()[1]
            fresh.send(('blocked-' + label).encode())
            try:
                leaked = fresh.recv(4096)
            except socket.timeout:
                pass
            else:
                raise AssertionError(('learned domain bypassed Block', leaked))
            with socket.socket(family, socket.SOCK_DGRAM) as must:
                must.settimeout(5)
                must.connect((address, 18083))
                payload = ('must-' + label).encode()
                must.send(payload)
                assert must.recv(4096) == payload
        print(json.dumps({'packet_domain_family': label, 'before': 'direct', 'after': 'blocked', 'earlier_must': 'direct'}), flush=True)


def domain_check():
    peer = None
    try:
        before = json.loads(subprocess.check_output(command('dut', 'count', 'dut0'), text=True, timeout=5))
        peer = subprocess.Popen(command('server', 'domain-peer'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert ready_line(peer) == 'READY'
        client = subprocess.run(command('client', 'domain-client'), capture_output=True, text=True, timeout=20)
        peer.stdin.write('done\n')
        peer.stdin.flush()
        observed = json.loads(ready_line(peer))
        peer.wait(timeout=5)
        assert peer.returncode == 0, peer.stderr.read()
        print(client.stdout, end='', flush=True)
        assert client.returncode == 0, (client.stdout, client.stderr, observed)
        assert sorted(observed['received']) == ['before-4', 'before-6', 'must-4', 'must-6'], observed
        assert observed['queries'] == 2, observed
        after = json.loads(subprocess.check_output(command('dut', 'count', 'dut0'), text=True, timeout=5))
        assert sum(after) - sum(before) >= 8, ('domain probe lacked actual capture', before, after)
        print(json.dumps({'packet_dns_domain_routing': 'PASS', 'peer': observed, 'capture_delta': sum(after) - sum(before)}), flush=True)
    finally:
        stop(peer)


mode = sys.argv[1] if len(sys.argv) > 1 else 'check'
if mode == 'hold':
    ipv6 = sys.argv[3] == '6'
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x100)
        sock.bind(('fd00:77::1' if ipv6 else '10.77.0.1', 0))
        sock.connect(('fd00:1::2' if ipv6 else '192.0.2.2', 41000))
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) == 0x100
        print(sock.getsockname()[1], flush=True)
        sock.settimeout(float(sys.argv[2]))
        try:
            result = sock.recv(4096).hex()
        except socket.timeout:
            result = None
        print(json.dumps(result), flush=True)
        sys.stdin.read()
elif mode == 'receive':
    case = sys.argv[3]
    ipv6 = case == 'mdns6' or 'unicast6' in case
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('::' if ipv6 else '198.51.100.2' if case == 'options' else '0.0.0.0', int(sys.argv[2])))
        device = 'lanc' if os.environ.get('HONK_XDP_INLINE_QINQ') == '1' else 'dut0'
        if case in ('mdns4', 'ssdp4'):
            group = socket.inet_aton('224.0.0.251' if case == 'mdns4' else '239.255.255.250')
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group + struct.pack('=4sI', b'\0' * 4, socket.if_nametoindex(device)))
        elif case == 'mdns6':
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, socket.inet_pton(socket.AF_INET6, 'ff02::fb') + struct.pack('=I', socket.if_nametoindex(device)))
        sock.settimeout(1)
        print('READY', flush=True)
        try:
            packet, source = sock.recvfrom(4096)
            result = {'data': packet.hex(), 'peer': source}
        except socket.timeout:
            result = None
        print(json.dumps(result), flush=True)
elif mode == 'send':
    packet = frame(int(sys.argv[2]), sys.argv[3])
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind(('c0', 0))
        assert sock.send(packet) == len(packet)
elif mode == 'count':
    print(json.dumps(counts(sys.argv[2] if len(sys.argv) > 2 else 'dut0')), flush=True)
elif mode in ('identity', 'pin-id'):
    device, role = sys.argv[2:4]
    fd = program_fd(device, role)
    try:
        info = C.create_string_buffer(80)
        bpf(15, Info(fd, len(info), C.addressof(info)))
        expected = struct.unpack_from('=I', info, 4)[0]
        assert info.raw[64:80].rstrip(b'\0') == f'honk_xdp_{role}'.encode(), (device, role, info.raw[64:80])
        assert expected != 0, (device, role, expected)
        if mode == 'pin-id':
            print(expected, flush=True)
        else:
            if role == 'guard':
                assert len(sys.argv) == 5 and expected == int(sys.argv[4]), ('guard pin changed since readiness', device, expected, sys.argv[4:])
            link = json.loads(subprocess.check_output(['ip', '-j', '-d', 'link', 'show', 'dev', device], text=True))[0]
            xdp = link.get('xdp', {})
            actual = xdp.get('prog', {}).get('id', 0) or xdp.get('prog_id', 0)
            assert actual == expected, (device, role, actual, expected)
            print(json.dumps({'device': device, 'role': role, 'program_id': actual}), flush=True)
    finally:
        os.close(fd)
elif mode == 'wire-receive':
    payload = bytes.fromhex(sys.argv[3])
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind((sys.argv[2], 0))
        print('READY', flush=True)
        deadline = time.monotonic() + 1
        result = False
        while time.monotonic() < deadline:
            sock.settimeout(deadline - time.monotonic())
            try:
                packet, peer = sock.recvfrom(65535)
            except socket.timeout:
                break
            if peer[2] != 4 and payload in packet:
                result = True
                break
        print(json.dumps(result), flush=True)
elif mode == 'wire-send':
    family, device, address, payload = sys.argv[2:]
    with socket.socket(socket.AF_INET if family == '4' else socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device.encode() + b'\0')
        sock.bind(('0.0.0.0' if family == '4' else '::', 41090))
        assert sock.sendto(bytes.fromhex(payload), (address, 19090)) == len(bytes.fromhex(payload))
elif mode == 'padding-send':
    packet = frame(19092, 'padding', b'pad')
    minimum = 64 if os.environ.get('HONK_XDP_SINGLE_VLAN') == '1' else 68
    assert len(packet) < minimum
    packet = packet.ljust(minimum, b'\0')
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind(('c0', 0))
        assert sock.send(packet) == minimum
    print(json.dumps({'padded_vlan_wire_bytes': minimum}), flush=True)
elif mode == 'padding-receive':
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('198.51.100.2', 19092))
        sock.settimeout(3)
        print('READY', flush=True)
        data, peer = sock.recvfrom(4096)
        assert (data, peer) == (b'pad', ('192.0.2.2', 41000)), (data, peer)
        print('DELIVERED', flush=True)
elif mode == 'padding':
    receiver = None
    try:
        before = json.loads(subprocess.check_output(command('dut', 'count'), text=True, timeout=5))
        receiver = subprocess.Popen(command('server', 'padding-receive'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert ready_line(receiver) == 'READY'
        subprocess.run(command('client', 'padding-send'), check=True, timeout=5)
        assert ready_line(receiver) == 'DELIVERED'
        after = json.loads(subprocess.check_output(command('dut', 'count'), text=True, timeout=5))
        assert sum(after) - sum(before) == 1, ('padded VLAN lacks actual capture', before, after)
        print(json.dumps({'padded_vlan_core_delivery': 'PASS'}), flush=True)
    finally:
        stop(receiver)
elif mode == 'settled':
    deadline = time.monotonic() + 5
    while True:
        states = [line.split()[3] for name in ('tcp', 'tcp6') for line in Path('/proc/net', name).read_text().splitlines()[1:]]
        if all(state in ('06', '0A') for state in states):
            break
        assert time.monotonic() < deadline, ('test producers still own unfinished TCP wire work', states)
        time.sleep(0.02)
elif mode == 'domain-peer':
    domain_peer()
elif mode == 'domain-client':
    domain_client()
elif mode == 'domain':
    domain_check()
elif mode == 'guard':
    guard_probe(*sys.argv[2:])
elif mode in ('check', 'native-baseline'):
    sys.exit(native_check(mode == 'native-baseline'))
else:
    raise RuntimeError('unknown smoke role')
