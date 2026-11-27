#!/usr/bin/env python3
"""Disposable-guest actual-ingress, producer identity and shutdown wire probes."""
import ctypes as C
import contextlib
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import re

def require_live_namespace():
    cmdline = Path('/proc/cmdline').read_text()
    parent = os.environ.get('HONK_XDP_PARENT_NETNS')
    current = str(os.stat('/proc/self/ns/net').st_ino)
    if os.geteuid() != 0 or 'virtme.' not in cmdline or not parent or current == parent or current == str(os.stat('/proc/1/ns/net').st_ino):
        raise RuntimeError('requires the smoke-owned private disposable-guest namespace')

def decode_xdp_identity(xdp, kernel=None):
    """Project ip JSON, filling omitted fields only from an RTM_GETLINK result."""
    modes = {'off': 0, 'none': 0, 'drv': 1, 'native': 1, 'driver': 1,
             'skb': 2, 'generic': 2, 'hw': 3, 'offload': 3, 'multi': 4}
    state = {}
    for key in ('attached', 'mode'):
        if key in xdp:
            value = xdp[key]
            # iproute2 7.x prints "attached": [{"mode": N, "prog": {...}}] where older prints a string.
            if isinstance(value, list):
                assert len(value) == 1, ('invalid XDP attachment list', xdp)
                value = value[0]
                if isinstance(value, dict):
                    assert value.get('prog', {}).get('id') == xdp.get('prog', {}).get('id'), ('conflicting XDP attachment ID', xdp)
                    value = value['mode']
            value = modes.get(value, value)
            assert type(value) is int and 0 <= value <= 4, ('invalid XDP mode', xdp)
            assert 'attached' not in state or state['attached'] == value, ('conflicting XDP modes', xdp)
            state['attached'] = value
    ids = [value for value in (xdp.get('prog', {}).get('id'), xdp.get('prog_id')) if value is not None]
    if ids:
        assert all(type(value) is int and 0 <= value <= 0xffffffff for value in ids), ('invalid XDP ID', xdp)
        assert len(set(ids)) == 1, ('conflicting aggregate XDP IDs', xdp)
        state['prog_id'] = ids[0]
    for key in ('drv_prog_id', 'skb_prog_id', 'hw_prog_id'):
        if key in xdp:
            value = xdp[key]
            assert type(value) is int and 0 <= value <= 0xffffffff, ('invalid XDP ID', xdp)
            state[key] = value
    for key in ('attached', 'prog_id', 'drv_prog_id', 'skb_prog_id', 'hw_prog_id'):
        if kernel is not None:
            assert key not in state or state[key] == kernel[key], ('ip/kernel XDP identity mismatch', state, kernel)
            state[key] = kernel[key]
        elif key not in state:
            raise ValueError('incomplete ip XDP identity: ' + key)
    return state


def require_xdp_identity(state, expected):
    wanted = dict(attached=1, prog_id=expected, drv_prog_id=expected, skb_prog_id=0, hw_prog_id=0)
    assert expected > 0 and state == wanted, ('not the exact owned DRV attachment', state, wanted)


def require_xdp_absent(state):
    assert state == dict(attached=0, prog_id=0, drv_prog_id=0, skb_prog_id=0, hw_prog_id=0), ('XDP remains attached', state)


def netlink_attributes(data):
    while data:
        assert len(data) >= 4, 'truncated netlink attribute header'
        length, kind = struct.unpack_from('=HH', data)
        assert 4 <= length <= len(data), 'invalid netlink attribute extent'
        extent = (length + 3) & ~3
        assert extent <= len(data) or length == len(data), 'truncated netlink attribute padding'
        yield kind & 0x3fff, data[4:length]
        data = data[extent:]


def decode_xdp_attributes(data):
    state = dict(attached=0, prog_id=0, drv_prog_id=0, skb_prog_id=0, hw_prog_id=0)
    fields = {2: ('attached', 1), 4: ('prog_id', 4), 5: ('drv_prog_id', 4),
              6: ('skb_prog_id', 4), 7: ('hw_prog_id', 4)}
    seen = set()
    for kind, value in netlink_attributes(data):
        if kind in fields:
            key, size = fields[kind]
            assert kind not in seen and len(value) == size, ('invalid XDP attribute', kind, value)
            seen.add(kind)
            state[key] = value[0] if size == 1 else struct.unpack('=I', value)[0]
    return state


def netlink_messages(data):
    while data:
        assert len(data) >= 16, 'truncated netlink message header'
        length, kind, flags, sequence, pid = struct.unpack_from('=IHHII', data)
        assert 16 <= length <= len(data), 'invalid netlink message extent'
        extent = (length + 3) & ~3
        assert extent <= len(data) or length == len(data), 'truncated netlink message padding'
        yield kind, flags, sequence, pid, data[16:length]
        data = data[extent:]


def decode_setlink_ack(data, request):
    matched = False
    sequence = struct.unpack_from('=I', request, 8)[0]
    for kind, flags, seq, pid, payload in netlink_messages(data):
        if seq != sequence:
            continue
        assert kind == 2 and not flags & 0x10, ('unexpected SETLINK reply', kind, flags)
        assert not matched and len(payload) >= 20, 'missing complete matching netlink ACK'
        assert payload[4:20] == request[:16], 'ACK does not match SETLINK request'
        error = struct.unpack_from('=i', payload)[0]
        assert error <= 0, ('invalid netlink errno', error)
        if error:
            raise OSError(-error, os.strerror(-error))
        matched = True
    return matched


def netlink_reply(sock, deadline):
    sock.settimeout(max(0.001, deadline - time.monotonic()))
    data, ancillary, flags, source = sock.recvmsg(65536)
    assert data and not flags & socket.MSG_TRUNC and source[0] == 0, 'truncated or nonkernel netlink reply'
    return data


def kernel_xdp_state(device):
    require_live_namespace()
    ifindex = socket.if_nametoindex(device)
    request = struct.pack('=IHHII', 32, 18, 1, 1, 0) + struct.pack('=BBHiII', 0, 0, 0, ifindex, 0, 0)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
        sock.bind((0, 0))
        sock.settimeout(2)
        deadline = time.monotonic() + 2
        assert sock.sendto(request, (0, 0)) == len(request), 'short GETLINK send'
        while True:
            assert time.monotonic() < deadline, 'GETLINK deadline expired'
            result = None
            for kind, flags, sequence, pid, payload in netlink_messages(netlink_reply(sock, deadline)):
                if sequence != 1:
                    continue
                if kind == 2:
                    assert len(payload) >= 20, 'truncated GETLINK error'
                    error = struct.unpack_from('=i', payload)[0]
                    assert error < 0, ('unexpected GETLINK ACK', error)
                    raise OSError(-error, os.strerror(-error))
                assert kind == 16 and not flags & 0x10 and len(payload) >= 16, 'invalid GETLINK reply'
                assert struct.unpack_from('=i', payload, 4)[0] == ifindex and result is None, 'wrong or duplicate GETLINK device'
                result = dict(attached=0, prog_id=0, drv_prog_id=0, skb_prog_id=0, hw_prog_id=0)
                seen = False
                for attribute, value in netlink_attributes(payload[16:]):
                    if attribute == 43:
                        assert not seen, 'duplicate IFLA_XDP'
                        seen = True
                        result = decode_xdp_attributes(value)
            if result is not None:
                return result


def xdp_state(device):
    require_live_namespace()
    link = json.loads(subprocess.check_output(['ip', '-j', '-d', 'link', 'show', 'dev', device], text=True))[0]
    xdp = link.get('xdp', {})
    try:
        return decode_xdp_identity(xdp)
    except ValueError:
        return decode_xdp_identity(xdp, kernel_xdp_state(device))


def xdp_detach_request(ifindex, expected_fd):
    assert ifindex > 0 and expected_fd >= 0
    nested = struct.pack('=HHi', 8, 1, -1) + struct.pack('=HHI', 8, 3, (1 << 2) | (1 << 4))
    nested += struct.pack('=HHi', 8, 8, expected_fd)
    return (struct.pack('=IHHII', 60, 19, 5, 1, 0)
            + struct.pack('=BBHiII', 0, 0, 0, ifindex, 0, 0)
            + struct.pack('=HH', 28, 43 | 0x8000) + nested)


def detach_guard(device, fd, expected):
    require_live_namespace()
    require_xdp_identity(kernel_xdp_state(device), expected)
    request = xdp_detach_request(socket.if_nametoindex(device), fd)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
        sock.bind((0, 0))
        sock.settimeout(2)
        deadline = time.monotonic() + 2
        assert sock.sendto(request, (0, 0)) == len(request), 'short expected-FD detach send'
        while not decode_setlink_ack(netlink_reply(sock, deadline), request):
            assert time.monotonic() < deadline, 'expected-FD detach ACK deadline expired'
    require_xdp_absent(kernel_xdp_state(device))


def decoder_selftest():
    good = dict(attached='drv', prog={'id': 71}, drv_prog_id=71, skb_prog_id=0, hw_prog_id=0)
    require_xdp_identity(decode_xdp_identity(good), 71)
    require_xdp_identity(decode_xdp_identity(dict(good, attached=['drv'])), 71)
    require_xdp_identity(decode_xdp_identity(dict(good, attached=[{'mode': 1, 'prog': {'id': 71}}])), 71)
    for changes in (dict(attached='generic'), dict(skb_prog_id=9), dict(hw_prog_id=9),
                    dict(attached='multi'), dict(drv_prog_id=72), dict(prog={'id': 72}),
                    dict(attached='off', prog={'id': 0}, drv_prog_id=0)):
        try:
            require_xdp_identity(decode_xdp_identity(dict(good, **changes)), 71)
        except AssertionError:
            pass
        else:
            raise AssertionError(('decoder admitted wrong mode/identity', changes))
    try:
        decode_xdp_identity(dict(attached='drv', prog_id=71))
    except ValueError:
        pass
    else:
        raise AssertionError('missing per-mode fields became proof of absence')
    attrs = struct.pack('=HHB3x', 5, 2, 1) + struct.pack('=HHI', 8, 4, 71) + struct.pack('=HHI', 8, 5, 71)
    kernel = decode_xdp_attributes(attrs)
    require_xdp_identity(decode_xdp_identity(dict(attached='native', prog_id=71), kernel), 71)
    try:
        decode_xdp_identity(dict(attached='generic', prog_id=71), kernel)
    except AssertionError:
        pass
    else:
        raise AssertionError('kernel fallback hid conflicting ip mode')
    require_xdp_absent(decode_xdp_attributes(b''))
    request = xdp_detach_request(17, 29)
    assert len(request) == 60 and struct.unpack_from('=i', request, 40)[0] == -1
    assert struct.unpack_from('=I', request, 48)[0] == 20 and struct.unpack_from('=i', request, 56)[0] == 29
    ack = struct.pack('=IHHIIi', 36, 2, 0, 1, 0, 0) + request[:16]
    assert decode_setlink_ack(ack, request)
    for malformed in (ack[:20], ack[:8] + struct.pack('=I', 2) + ack[12:], ack[:24] + b'\0\0' + ack[26:]):
        try:
            accepted = decode_setlink_ack(malformed, request)
        except AssertionError:
            continue
        assert not accepted, 'accepted incomplete or mismatched ACK'
    negative = ack[:16] + struct.pack('=i', -17) + ack[20:]
    try:
        decode_setlink_ack(negative, request)
    except OSError as error:
        assert error.errno == 17
    else:
        raise AssertionError('negative SETLINK ACK accepted')


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


def frame(port, case, payload=marker, source_port=None):
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
    source_port = source_port if source_port is not None else (6868 if case == 'broadcast' else 41000)
    length = 8 + len(payload)
    udp = struct.pack('!HHHH', source_port, port, length, 0) + payload
    pseudo = source + final + (struct.pack('!I3xB', length, 17) if ipv6 else struct.pack('!BBH', 0, 17, length))
    # IPv6 UDP's pseudo-header length excludes all extension headers.
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
    require_live_namespace()
    number = {'x86_64': 321, 'aarch64': 280}[os.uname().machine]
    result = libc.syscall(number, operation, C.byref(attr), C.sizeof(attr))
    if result < 0:
        raise OSError(C.get_errno(), os.strerror(C.get_errno()))
    return result


def program_fd(device, role):
    assert role in ('data', 'guard')
    if role == 'data' and not os.environ.get('HONK_XDP_EXPECT_NAME'):
        state = xdp_state(device)
        require_xdp_identity(state, state['prog_id'])
        return bpf(13, Id(id=state['prog_id']))
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


def domain_peer(profile):
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
                    if profile == 'core':
                        expected = '192.0.2.2' if data_sockets[sock] == socket.AF_INET else 'fd00:1::2'
                    else:
                        expected = '10.77.0.1' if data_sockets[sock] == socket.AF_INET else 'fd00:77::1'
                    assert peer[0] == expected, ('packet domain reply source', profile, peer, expected)
                    received.append(data.decode('ascii'))
                    assert len(received) <= 16, received
                    sock.sendto(data, peer)
        raise TimeoutError('domain peer did not receive its completion barrier')


def forward_fence_packets():
    items = json.loads(subprocess.check_output(['ip', 'netns', 'exec', 'dut', 'nft', '-j', 'list', 'chain', 'inet', 'honk_smoke_native', 'forward'], text=True))['nftables']
    rules = [item['rule']['expr'] for item in items if 'rule' in item]
    assert len(rules) == 1 and rules[0][-1] == {'drop': None}, rules
    return next(item['counter']['packets'] for item in rules[0] if 'counter' in item)


def dut_reply_evidence():
    def read(*args):
        return subprocess.check_output(['ip', 'netns', 'exec', 'dut', *args], text=True, timeout=5)
    wanted = {'Ip6InReceives', 'Ip6InDiscards', 'Ip6InNoRoutes', 'Ip6InAddrErrors', 'Ip6InDelivers',
              'Udp6InDatagrams', 'Udp6NoPorts', 'Udp6InErrors', 'Udp6RcvbufErrors'}
    snmp6 = dict(line.split() for line in read('cat', '/proc/net/snmp6').splitlines() if line.strip())
    sockets = [fields for fields in (line.split() for line in read('cat', '/proc/net/udp6').splitlines()[1:])]
    xdp = [line.strip() for line in read('ethtool', '-S', 'dut1').splitlines() if 'xdp' in line or 'drop' in line]
    return {'snmp6': {name: int(value) for name, value in snmp6.items() if name in wanted},
            'udp6': [(fields[1], fields[4], fields[-1]) for fields in sockets], 'dut1': xdp}


def domain_client(profile='endpoint'):
    for family, address, qtype, label in ((socket.AF_INET, '198.51.100.2', 1, '4'), (socket.AF_INET6, 'fd00:2::2', 28, '6')):
        with socket.socket(family, socket.SOCK_DGRAM) as original, socket.socket(family, socket.SOCK_DGRAM) as fresh:
            original.settimeout(5)
            original.connect((address, 18082))
            before = ('before-' + label).encode()
            evidence = dut_reply_evidence()
            original.send(before)
            try:
                assert original.recv(4096) == before
            except TimeoutError as error:
                raise AssertionError(('original reply missing', label, original.getsockname(), evidence, dut_reply_evidence())) from error
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
                if profile == 'endpoint':
                    captured = json.loads(subprocess.check_output(command('dut', 'count', 'dut0'), text=True, timeout=5))
                    forwarded = forward_fence_packets()
                    must.send(payload)
                    try:
                        reply = must.recv(4096)
                    except socket.timeout:
                        pass
                    else:
                        raise AssertionError(('D1 direct-must bypassed the kernel forwarding fence', reply))
                    assert forward_fence_packets() == forwarded + 1, 'direct-must never reached kernel forwarding'
                    assert json.loads(subprocess.check_output(command('dut', 'count', 'dut0'), text=True, timeout=5)) == captured, 'direct-must entered Endpoint'
                else:
                    must.send(payload)
                    assert must.recv(4096) == payload
        print(json.dumps({'packet_domain_family': label, 'before': 'direct', 'after': 'blocked', 'earlier_must': 'kernel-fence' if profile == 'endpoint' else 'direct'}), flush=True)


def domain_check(profile):
    assert profile in ('endpoint', 'core'), profile
    peer = None
    try:
        before = json.loads(subprocess.check_output(command('dut', 'count', 'dut0'), text=True, timeout=5))
        peer = subprocess.Popen(command('server', 'domain-peer', profile), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert ready_line(peer) == 'READY'
        client = subprocess.run(command('client', 'domain-client', profile), capture_output=True, text=True, timeout=20)
        peer.stdin.write('done\n')
        peer.stdin.flush()
        observed = json.loads(ready_line(peer))
        peer.wait(timeout=5)
        assert peer.returncode == 0, peer.stderr.read()
        print(client.stdout, end='', flush=True)
        assert client.returncode == 0, (client.stdout, client.stderr, observed)
        expected = ['before-4', 'before-6'] if profile == 'endpoint' else ['before-4', 'before-6', 'must-4', 'must-6']
        assert sorted(observed['received']) == sorted(expected), observed
        assert observed['queries'] == 2, observed
        after = json.loads(subprocess.check_output(command('dut', 'count', 'dut0'), text=True, timeout=5))
        minimum_captured = 6 if profile == 'endpoint' else 8
        assert sum(after) - sum(before) >= minimum_captured, ('domain probe lacked actual capture', before, after)
        if profile == 'endpoint':
            assert forward_fence_packets() == 2, 'direct-must did not produce two kernel forwarding attempts'
        print(json.dumps({'packet_dns_domain_routing': 'PASS', 'profile': profile, 'peer': observed, 'capture_delta': sum(after) - sum(before)}), flush=True)
    finally:
        stop(peer)


def tcp_quiescence_probe(rows):
    result = dict(netns=None, rows=[], owners=[], partial=False, reasons=[],
                  rows_truncated=False, owners_omitted=0, pids_scanned=0,
                  fd_links_scanned=0, owner_scan_complete=False,
                  owner_scope='visible process leader FD tables; non-atomic snapshot and scan',
                  limits=dict(rows=32, owners=64, pids=256, fd_links=4096,
                              scan_seconds=1, encoded_bytes=16384))

    def partial(reason):
        result['partial'] = True
        if reason not in result['reasons']:
            result['reasons'].append(reason)

    def deadline(signum, frame):
        raise TimeoutError('TCP diagnostic scan deadline')

    def starttime(process):
        return int(Path(process, 'stat').read_text().rsplit(')', 1)[1].split()[19])

    def endpoint(value, family):
        address, port = value.split(':')
        packed = b''.join(struct.pack('=I', int(address[index:index + 8], 16))
                          for index in range(0, len(address), 8))
        return [socket.inet_ntop(family, packed), int(port, 16)]

    previous_handler = signal.getsignal(signal.SIGALRM)
    try:
        signal.signal(signal.SIGALRM, deadline)
        signal.setitimer(signal.ITIMER_REAL, 1)
        namespace = os.stat('/proc/self/ns/net')
        result['netns'] = dict(link=os.readlink('/proc/self/ns/net'),
                               device=namespace.st_dev, inode=namespace.st_ino)
        for table, raw in rows:
            fields = raw.split()
            if fields[3] in ('06', '0A'):
                continue
            if len(result['rows']) == 32:
                result['rows_truncated'] = True
                partial('row_limit')
                break
            row = dict(table=table, raw=raw, ownership='unresolved')
            result['rows'].append(row)
            family = socket.AF_INET if table == 'tcp' else socket.AF_INET6
            row.update(local=endpoint(fields[1], family), remote=endpoint(fields[2], family),
                       state=fields[3], inode=int(fields[9]))
        targets = {f'socket:[{row["inode"]}]': row['inode']
                   for row in result['rows'] if row.get('inode', 0) > 0}
        stopped = False
        if targets:
            with os.scandir('/proc') as processes:
                for process in processes:
                    if not process.name.isdecimal():
                        continue
                    if result['pids_scanned'] == 256:
                        partial('pid_limit')
                        stopped = True
                        break
                    result['pids_scanned'] += 1
                    try:
                        started = starttime(process.path)
                        with os.scandir(process.path + '/fd') as descriptors:
                            for entry in descriptors:
                                if result['fd_links_scanned'] == 4096:
                                    partial('fd_link_limit')
                                    stopped = True
                                    break
                                result['fd_links_scanned'] += 1
                                try:
                                    link = os.readlink(entry.path)
                                    if link not in targets:
                                        continue
                                    if len(result['owners']) == 64:
                                        partial('owner_limit')
                                        stopped = True
                                        break
                                    netns = os.readlink(process.path + '/ns/net')
                                    if (os.readlink(entry.path) != link
                                            or os.readlink(process.path + '/ns/net') != netns
                                            or starttime(process.path) != started):
                                        partial('owner_changed_during_scan')
                                        continue
                                    result['owners'].append(dict(inode=targets[link], pid=int(process.name),
                                                                 starttime=started, fd=int(entry.name),
                                                                 process_netns=netns))
                                except TimeoutError:
                                    raise
                                except (OSError, ValueError, IndexError):
                                    partial('fd_owner_unreadable')
                    except TimeoutError:
                        raise
                    except (OSError, ValueError, IndexError):
                        partial('process_unreadable')
                    if stopped:
                        break
            result['owner_scan_complete'] = not stopped and not any(
                reason in result['reasons'] for reason in
                ('fd_owner_unreadable', 'process_unreadable', 'owner_changed_during_scan'))
        else:
            result['owner_scan_complete'] = True
    except BaseException as error:
        partial('scan_deadline' if isinstance(error, TimeoutError) else 'diagnostic_error')
        result['error_type'] = type(error).__name__
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
    for row in result['rows']:
        row['owner_matches'] = sum(owner['inode'] == row.get('inode') for owner in result['owners'])
        if row.get('inode') == 0:
            row.update(ownership='orphan', owner_basis='kernel row has no FD inode')
        elif row['owner_matches']:
            row['ownership'] = 'matched'
        else:
            partial('owner_unresolved')
    line = json.dumps(dict(tcp_quiescence_failure=result), separators=(',', ':'))
    while len(line.encode('utf-8')) + 1 > 16 * 1024:
        partial('encoded_line_limit')
        if result['owners']:
            result['owners'].pop()
            result['owners_omitted'] += 1
        else:
            result['rows'].pop()
            result['rows_truncated'] = True
        line = json.dumps(dict(tcp_quiescence_failure=result), separators=(',', ':'))
    print(line, flush=True)


def program_identity(fd, device, role, saved_guard=None):
    info = C.create_string_buffer(80)
    bpf(15, Info(fd, len(info), C.addressof(info)))
    kind, identity = struct.unpack_from('=II', info)
    # A configured gateway loads honk_gw_{data,boot}; without one the general honk_xdp_{data,guard} load.
    names = {os.environ['HONK_XDP_EXPECT_NAME']} if os.environ.get('HONK_XDP_EXPECT_NAME') else {
        'data': {'honk_xdp_data', 'honk_gw_data'}, 'guard': {'honk_xdp_guard', 'honk_gw_boot'}}[role]
    actual = info.raw[64:80].rstrip(b'\0').decode(errors='replace')
    assert kind == 6 and identity != 0 and actual in names, ('unexpected pinned XDP program', device, role, kind, identity, actual)
    if saved_guard is not None:
        assert role == 'guard' and identity == int(saved_guard), ('guard pin changed since readiness', device, identity, saved_guard)
    return identity


mode = (sys.argv[1] if len(sys.argv) > 1 else 'check') if __name__ == '__main__' else None
if mode is not None and mode != 'decoder-selftest':
    require_live_namespace()
if mode == 'decoder-selftest':
    decoder_selftest()
elif mode == 'xdp-absent':
    require_xdp_absent(xdp_state(sys.argv[2]))
elif mode == 'foreign-xdp-rejected':
    device = sys.argv[2]
    before = kernel_xdp_state(device)
    fd = program_fd(device, 'data')
    try:
        request = bytearray(xdp_detach_request(socket.if_nametoindex(device), fd))
        struct.pack_into('=i', request, 40, fd)
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
            sock.bind((0, 0))
            assert sock.sendto(request, (0, 0)) == len(request)
            try:
                decode_setlink_ack(netlink_reply(sock, time.monotonic() + 2), request)
            except OSError as error:
                assert error.errno == 16, ('foreign XDP replacement failed for an unexpected reason', error)
            else:
                raise AssertionError('foreign XDP replacement changed an FD-owned link')
        assert kernel_xdp_state(device) == before, 'foreign XDP attempt changed capture'
    finally:
        os.close(fd)
elif mode == 'hold':
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
    devices = sys.argv[2:] or ['dut0']
    def count_deadline(signum, frame):
        raise TimeoutError('actual producer counter read exceeded its five-second deadline')
    signal.signal(signal.SIGALRM, count_deadline)
    values = {}
    for device in devices:
        signal.setitimer(signal.ITIMER_REAL, 5)
        try:
            values[device] = counts(device)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(values[devices[0]] if len(devices) == 1 else values), flush=True)
elif mode in ('identity', 'pin-id'):
    device, role = sys.argv[2:4]
    fd = program_fd(device, role)
    try:
        saved = sys.argv[4] if role == 'guard' and mode == 'identity' and len(sys.argv) == 5 else None
        if role == 'guard' and mode == 'identity':
            assert saved is not None, 'guard identity requires saved readiness ID'
        expected = program_identity(fd, device, role, saved)
        if mode == 'pin-id':
            print(expected, flush=True)
        else:
            require_xdp_identity(xdp_state(device), expected)
            print(json.dumps({'device': device, 'role': role, 'program_id': expected}), flush=True)
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
        rows = [(name, line) for name in ('tcp', 'tcp6') for line in Path('/proc/net', name).read_text().splitlines()[1:]]
        states = [line.split()[3] for _, line in rows]
        if all(state in ('06', '0A') for state in states):
            break
        try:
            assert time.monotonic() < deadline, ('test producers still own unfinished TCP wire work', states)
        except AssertionError:
            try:
                tcp_quiescence_probe(rows)
            except BaseException:
                pass
            raise
        time.sleep(0.02)
elif mode == 'domain-peer':
    domain_peer(sys.argv[2])
elif mode == 'domain-client':
    domain_client(sys.argv[2] if len(sys.argv) > 2 else 'endpoint')
elif mode == 'domain':
    domain_check(sys.argv[2])
elif mode == 'guard':
    guard_probe(*sys.argv[2:])
elif mode in ('check', 'native-baseline'):
    sys.exit(native_check(mode == 'native-baseline'))
elif mode is not None:
    raise RuntimeError('unknown smoke role')
