#!/usr/bin/env python3
"""Disposable-guest actual-ingress, producer identity and shutdown wire probes."""
import ctypes as C
import contextlib
import errno
import faulthandler
import fcntl
import copy
import hashlib
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
import runpy
import threading
import http.client
import traceback

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
    applied = 'SIGHUP reload request 1 applied\n'
    require_native_owner_log(applied)
    for failure in ('XDP owner failed closed', 'XDP topology authority changed'):
        history = 'ready\n' + applied + failure + '\n' + applied
        first_offset, later_offset = len('ready\n'), history.rfind(applied)
        assert failure in history[first_offset:later_offset]
        for text, offset in ((applied + failure, 0), (failure + '\n' + applied, 0), (history, first_offset)):
            try:
                require_native_owner_log(text, offset)
            except AssertionError as error:
                assert failure in str(error), error
            else:
                raise AssertionError(('applied reload hid owner failure', text))
    layout = dict(map_id=17, map_type=1, key_size=56, value_size=72, map_flags=0, max_entries=128)
    assert require_native_claim_layout([layout]) == layout
    for layouts in ([], None, [{}], [None], [layout, layout],
                    [dict(layout, key_size=40)], [dict(layout, value_size=40)],
                    [dict(layout, value_size=32)], [dict(layout, value_size=48)],
                    [dict(layout, value_size=4096)], [dict(layout, max_entries=0)], [dict(layout, map_flags=1)]):
        try:
            require_native_claim_layout(layouts)
        except ValueError:
            pass
        else:
            raise AssertionError(('accepted incompatible claims layout', layouts))
    claim = struct.pack('=QQQIIQQQQII', 7, 7, 13, 2, 4, 1234567890123, 0, 0, 0, 0, 0)
    assert decode_native_claim(claim) == dict(epoch=7, incarnation=7, scope=13, executor=2,
                                            state=4, phase=4, outstanding=0, last_seen_ns=1234567890123,
                                            owner_cookie=0, owner_incarnation=0, attachment_generation=0,
                                            mark_kind=0, mark_value=0)
    for malformed in (b'', claim[:31], claim[:32], claim[:40], claim[:71], claim + b'\0', claim + bytes(8), bytes(4096)):
        try:
            decode_native_claim(malformed)
        except struct.error:
            pass
        else:
            raise AssertionError(('accepted malformed claims value', len(malformed)))
    key = bytes(36) + bytes([17, 4]) + struct.pack('=BBQHB5s', 0, 0, 5, 0, 2, bytes(5))
    decoded_key = decode_native_key(key)
    assert decoded_key['namespace_cookie'] == 5 and decoded_key['zone_state'] == 2
    producer = struct.pack('=QQQII', 7, 11, 19, 1, 0)
    assert decode_native_import(producer) == dict(epoch=7, incarnation=11, expires_boottime_ns=19, flags=1, reserved=0)
    invalid_keys = [key[:40], key[:55], key + b'\0']
    for offset, replacement in ((38, 3), (39, 2), (40, 0), (50, 3), (51, 1), (52, 1), (53, 1), (54, 1), (55, 1)):
        malformed = bytearray(key)
        malformed[offset] = replacement
        invalid_keys.append(malformed)
    for malformed in invalid_keys:
        try:
            decode_native_key(malformed)
        except (ValueError, struct.error):
            pass
        else:
            raise AssertionError(('accepted malformed key', bytes(malformed).hex()))
    for malformed in (producer[:16], producer[:31], producer + b'\0',
                      struct.pack('=QQQII', 7, 11, 19, 2, 0), struct.pack('=QQQII', 7, 11, 19, 1, 1)):
        try:
            decode_native_import(malformed)
        except (ValueError, struct.error):
            pass
        else:
            raise AssertionError(('accepted malformed producer import', malformed.hex()))


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


def frame(port, case, payload=marker, source_port=None, extension_count=1):
    destinations = {
        'broadcast': ('0.0.0.0', '255.255.255.255', 'ffffffffffff'),
        'mdns4': ('192.0.2.2', '224.0.0.251', '01005e0000fb'),
        'ssdp4': ('192.0.2.2', '239.255.255.250', '01005e7ffffa'),
        'directed-broadcast': ('192.0.2.2', '10.77.0.255', 'ffffffffffff'),
        'mdns6': ('fd00:1::2', 'ff02::fb', '3333000000fb'),
        'padding': ('192.0.2.2', '198.51.100.2', '020000000010'),
        'native-hbh-padding': ('fd00:1::2', 'fd00:2::2', '020000000010'),
        'native-hbh-parameter': ('fd00:1::2', 'fd00:2::2', '020000000010'),
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
        extension = b''
        if case.startswith('native-hbh-'):
            assert 1 <= extension_count <= 9
            options = bytes.fromhex('800001020000' if case == 'native-hbh-parameter' else '010400000000')
            extension = b''.join(bytes([17 if index == extension_count - 1 else 60, 0]) + options
                                 for index in range(extension_count))
        ip = struct.pack('!IHBB16s16s', 6 << 28, len(extension) + len(udp),
                         0 if extension else 17, 37 if extension else 255, source, initial) + extension
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
    assert os.uname().machine == 'x86_64', 'this BPF syscall fixture is x86_64 only'
    result = libc.syscall(321, operation, C.byref(attr), C.sizeof(attr))
    if result < 0:
        raise OSError(C.get_errno(), os.strerror(C.get_errno()))
    return result


def program_fd(device, role):
    assert role in ('data', 'guard', 'native-gate-prog', 'native-return-restorer-prog', 'native-return-restorer-link')
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


def require_native_claim_layout(layouts):
    if not isinstance(layouts, list) or len(layouts) != 1 or not isinstance(layouts[0], dict):
        raise ValueError(f'expected one claims map, found {layouts!r}')
    layout = layouts[0]
    if ((layout.get('map_type'), layout.get('key_size'), layout.get('value_size'), layout.get('map_flags')) != (1, 56, 72, 0)
            or type(layout.get('max_entries')) is not int or layout['max_entries'] <= 0):
        raise ValueError(f'incompatible claims map layout: {layout}')
    return layout


def decode_native_key(value):
    src_ip, dst_ip, src_port, dst_port, protocol, version, domain, direction, namespace, zone, zone_state, reserved = struct.unpack('=16s16sHHBBBBQHB5s', value)
    if domain not in (0, 1, 2) or direction not in (0, 1) or zone_state not in (0, 1, 2) or namespace == 0 or any(reserved) or version not in (4, 6) or protocol not in (6, 17):
        raise ValueError('invalid native key projection')
    if (domain == 0 and (zone_state not in (1, 2) or zone_state == 2 and zone != 0)
            or domain == 1 and (direction != 0 or zone_state != 1)
            or domain == 2 and (direction != 0 or zone_state != 0 or zone != 0)):
        raise ValueError('invalid native key domain/direction/zone combination')
    return dict(src_ip=src_ip.hex(), dst_ip=dst_ip.hex(), src_port=socket.ntohs(src_port),
                dst_port=socket.ntohs(dst_port), l4proto=protocol, ip_version=version,
                domain=domain, direction=direction, namespace_cookie=namespace, zone=zone,
                zone_state=zone_state, reserved=reserved.hex())


def decode_native_import(value):
    epoch, incarnation, expires, flags, reserved = struct.unpack('=QQQII', value)
    if flags & ~1 or reserved:
        raise ValueError('invalid native import flags/reserved')
    return dict(epoch=epoch, incarnation=incarnation, expires_boottime_ns=expires, flags=flags, reserved=reserved)


def decode_native_claim(value):
    epoch, incarnation, scope, executor, state, last_seen_ns, owner_cookie, owner_incarnation, attachment_generation, mark_kind, mark_value = struct.unpack('=QQQIIQQQQII', value)
    phase, outstanding = state & 15, state >> 4
    if epoch == 0 or not epoch & 1 or incarnation != epoch or scope == 0:
        raise ValueError('invalid native claim identity')
    if (executor, phase) not in ((3, 0), (1, 1), (2, 2), (2, 3), (2, 4), (1, 5), (2, 5), (3, 5), (3, 6)):
        raise ValueError('invalid native executor/phase')
    if phase == 4 and outstanding or mark_kind not in (0, 1) or mark_kind == 0 and mark_value:
        raise ValueError('invalid native selection/mark')
    return dict(epoch=epoch, incarnation=incarnation, scope=scope, executor=executor,
                state=state, phase=phase, outstanding=outstanding, last_seen_ns=last_seen_ns,
                owner_cookie=owner_cookie, owner_incarnation=owner_incarnation,
                attachment_generation=attachment_generation, mark_kind=mark_kind, mark_value=mark_value)


def decode_native_projection(key, value):
    projection, claim = decode_native_key(key), decode_native_claim(value)
    domain, phase = projection['domain'], claim['phase']
    if phase == 0 and domain != 0 or phase == 6 and domain != 2 or domain == 2 and phase not in (5, 6):
        raise ValueError('invalid native claim domain/phase')
    if (domain, projection['direction'], projection['zone_state']) == (0, 0, 2):
        if any(claim[field] for field in ('owner_cookie', 'owner_incarnation', 'attachment_generation', 'mark_kind', 'mark_value')) or phase == 6:
            raise ValueError('Transit claim carries Host authority')
    return projection, claim


def native_claims():
    result = dict(program_name=None, map_count=0, match_count=0, steps=0,
                  claims_read=0, partial=False, truncated=False, error_code=None,
                  expected_layout_label=3, expected_key_size=56, expected_value_size=72,
                  last_seen_clock='CLOCK_MONOTONIC', observed_layouts=[])
    try:
        program = program_fd('dut0', 'data')
        claim_fd = None
        try:
            ids = (C.c_uint32 * 64)()
            info = C.create_string_buffer(80)
            struct.pack_into('=I', info, 52, len(ids))
            struct.pack_into('=Q', info, 56, C.addressof(ids))
            bpf(15, Info(program, len(info), C.addressof(info)))
            result['program_name'] = info.raw[64:80].split(b'\0', 1)[0].decode('ascii', errors='replace')
            result['program_id'] = struct.unpack_from('=I', info, 4)[0]
            result['map_count'] = struct.unpack_from('=I', info, 52)[0]
            if result['map_count'] > len(ids):
                result['truncated'] = True
                raise RuntimeError('program map ID count exceeds 64')
            matches = result['observed_layouts']
            for identity in ids[:result['map_count']]:
                fd = bpf(14, Id(id=identity))
                try:
                    details = C.create_string_buffer(24)
                    bpf(15, Info(fd, len(details), C.addressof(details)))
                    kind, map_id, key_size, value_size, entries, map_flags = struct.unpack_from('=IIIIII', details)
                    if kind == 1 and key_size in (40, 56):
                        matches.append(dict(map_id=map_id, map_type=kind, key_size=key_size,
                                            value_size=value_size, max_entries=entries, map_flags=map_flags))
                        result['match_count'] = len(matches)
                        if claim_fd is None:
                            claim_fd, fd = fd, None
                finally:
                    if fd is not None:
                        os.close(fd)
            try:
                layout = require_native_claim_layout(matches)
            except ValueError:
                result['error_code'] = 'native_claim_layout_incompatible'
                raise
            result.update(layout, claims=[])
            fd, entries = claim_fd, layout['max_entries']
            key = None
            for _ in range(min(1024, entries * 2)):
                next_key = C.create_string_buffer(56)
                result['steps'] += 1
                try:
                    bpf(4, Element(fd=fd, key=C.addressof(key) if key is not None else 0,
                                   value=C.addressof(next_key)))
                except OSError as error:
                    if error.errno == errno.ENOENT:
                        break
                    raise
                key = next_key
                value = C.create_string_buffer(72)
                try:
                    bpf(1, Element(fd=fd, key=C.addressof(key), value=C.addressof(value)))
                    projection, claim = decode_native_projection(key.raw, value.raw)
                except Exception as error:
                    result.update(partial=True, error_code='native_claim_read_incomplete', error=repr(error)[:200])
                    continue
                result['claims'].append(dict(key=key.raw.hex(), projection=projection, **claim))
                result['claims_read'] += 1
                if result['claims_read'] == 64:
                    result['truncated'] = True
                    break
            else:
                result['truncated'] = True
        finally:
            if claim_fd is not None:
                os.close(claim_fd)
            os.close(program)
    except Exception as error:
        result.update(partial=True, error_code=result.get('error_code') or 'native_claim_probe_failed', error=repr(error)[:200])
    line = json.dumps(result)
    if len(line.encode()) + 1 > 16 * 1024:
        result.pop('claims', None)
        result['truncated'] = True
        line = json.dumps(result)
    print(line, flush=True)


def native_claims_probe(label):
    result = dict(phase=label)
    try:
        result['boottime_start_ns'] = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        result['monotonic_start_ns'] = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        result['realtime_start_ns'] = time.clock_gettime_ns(time.CLOCK_REALTIME)
        child = subprocess.run(command('dut', 'native-claims'), capture_output=True, text=True, timeout=5)
        child.check_returncode()
        value = json.loads(child.stdout)
        if not isinstance(value, dict):
            raise ValueError('native-claims output is not a JSON object')
        result['result'] = value
        try:
            if (value.get('expected_layout_label') != 3 or value.get('expected_key_size') != 56
                    or value.get('expected_value_size') != 72 or value.get('last_seen_clock') != 'CLOCK_MONOTONIC'
                    or value.get('match_count') != 1 or type(value.get('partial')) is not bool
                    or type(value.get('truncated')) is not bool):
                raise ValueError('missing or incompatible native-claims diagnostic schema')
            require_native_claim_layout(value.get('observed_layouts', []))
        except (TypeError, ValueError) as error:
            value.update(partial=True, error_code='native_claim_layout_incompatible', error=repr(error)[:200])
    except BaseException as error:
        result['error'] = repr(error)[:200]
    try:
        result['boottime_end_ns'] = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        result['monotonic_end_ns'] = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        result['realtime_end_ns'] = time.clock_gettime_ns(time.CLOCK_REALTIME)
        if 'boottime_start_ns' in result:
            result['elapsed_ns'] = result['boottime_end_ns'] - result['boottime_start_ns']
        line = json.dumps(dict(native_claims_probe=result))
        if len(line.encode()) + 1 > 16 * 1024:
            result.get('result', {}).pop('claims', None)
            result.setdefault('result', {})['truncated'] = True
            line = json.dumps(dict(native_claims_probe=result))
        print(line, flush=True)
    except BaseException as error:
        result['error'] = repr(error)[:200]
        try:
            line = json.dumps(dict(native_claims_probe=result))
            if len(line.encode()) + 1 > 16 * 1024:
                result.get('result', {}).pop('claims', None)
                result.setdefault('result', {})['truncated'] = True
                line = json.dumps(dict(native_claims_probe=result))
            if len(line.encode()) + 1 > 16 * 1024:
                result.pop('result', None)
                result['truncated'] = True
                line = json.dumps(dict(native_claims_probe=result))
            print(line, flush=True)
        except BaseException as error:
            result['error'] = repr(error)[:200]


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
        deadline = time.monotonic() + (45 if profile == 'native' else 30)
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
                        answer = b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 8 if profile == 'native' else 60, len(address)) + address
                    response = data[:2] + struct.pack('!HHHHH', 0x8180 if accepted else 0x8183, 1, int(accepted), 0, 0) + data[12:end + 4] + answer
                    sock.sendto(response, peer)
                else:
                    if profile in ('core', 'native'):
                        expected = '192.0.2.2' if data_sockets[sock] == socket.AF_INET else 'fd00:1::2'
                    else:
                        expected = '10.77.0.1' if data_sockets[sock] == socket.AF_INET else 'fd00:77::1'
                    assert peer[0] == expected, ('packet domain reply source', profile, peer, expected)
                    received.append(data.decode('ascii'))
                    assert len(received) <= 16, received
                    sock.sendto(data, peer)
        raise TimeoutError('domain peer did not receive its completion barrier')


def domain_client(profile='endpoint'):
    for family, address, qtype, label in ((socket.AF_INET, '198.51.100.2', 1, '4'), (socket.AF_INET6, 'fd00:2::2', 28, '6')):
        if profile == 'native':
            resource = '/dns/query?name=packet-path.test&type=' + ('A' if qtype == 1 else 'AAAA')
            result = json.loads(subprocess.check_output(command('dut', 'native-api', 'GET', resource, ''), text=True, timeout=10))
            assert result['Status'] == 0 and any(answer.get('data') == address for answer in result.get('Answer', [])), ('independent API DNS lookup failed', result)
        with socket.socket(family, socket.SOCK_DGRAM) as original, socket.socket(family, socket.SOCK_DGRAM) as fresh:
            if profile == 'native':
                original.bind((native_addresses[4 if family == socket.AF_INET else 6][0], 49000 + int(label)))
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
                expires_after = time.monotonic() + struct.unpack_from('!I', response, start + 4)[0] + 1.1
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
            if profile == 'native':
                original.settimeout(1)
                payload = ('retained-blocked-' + label).encode()
                original.send(payload)
                assert original.recv(4096) == payload, ('scoped DNS changed retained Native Direct', payload)
            with socket.socket(family, socket.SOCK_DGRAM) as must:
                must.settimeout(5)
                must.connect((address, 18083))
                payload = ('must-' + label).encode()
                must.send(payload)
                assert must.recv(4096) == payload
            if profile == 'native':
                time.sleep(max(0, expires_after - time.monotonic()))
                with socket.socket(family, socket.SOCK_DGRAM) as expired:
                    expired.connect((address, 18082))
                    assert expired.getsockname()[1] not in (original.getsockname()[1], fresh.getsockname()[1])
                    for sock, prefix in ((original, 'expired-original-'), (expired, 'expired-fresh-')):
                        sock.settimeout(5)
                        payload = (prefix + label).encode()
                        sock.send(payload)
                        assert sock.recv(4096) == payload, ('expired scoped DNS authority still blocks Direct', payload)
        print(json.dumps({'packet_domain_family': label, 'before': 'direct', 'after': 'blocked', 'earlier_must': 'direct'}), flush=True)


def domain_check(profile):
    assert profile in ('endpoint', 'core', 'native'), profile
    peer = None
    try:
        before = json.loads(subprocess.check_output(command('dut', 'count', 'dut0'), text=True, timeout=5))
        peer = subprocess.Popen(command('server', 'domain-peer', profile), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert ready_line(peer) == 'READY'
        client = subprocess.run(command('client', 'domain-client', profile), capture_output=True, text=True, timeout=35 if profile == 'native' else 20)
        peer.stdin.write('done\n')
        peer.stdin.flush()
        observed = json.loads(ready_line(peer))
        peer.wait(timeout=5)
        assert peer.returncode == 0, peer.stderr.read()
        print(client.stdout, end='', flush=True)
        assert client.returncode == 0, (client.stdout, client.stderr, observed)
        expected = ['before-4', 'before-6', 'must-4', 'must-6']
        if profile == 'native':
            expected += ['retained-blocked-4', 'retained-blocked-6']
            expected += ['expired-original-4', 'expired-original-6', 'expired-fresh-4', 'expired-fresh-6']
        assert sorted(observed['received']) == sorted(expected), observed
        assert (2 <= observed['queries'] <= 4) if profile == 'native' else observed['queries'] == 2, observed
        after = json.loads(subprocess.check_output(command('dut', 'count', 'dut0'), text=True, timeout=5))
        if profile != 'native':
            assert sum(after) - sum(before) >= 8, ('domain probe lacked actual capture', before, after)
        print(json.dumps({'packet_dns_domain_routing': 'PASS', 'profile': profile, 'peer': observed, 'capture_delta': sum(after) - sum(before)}), flush=True)
    finally:
        stop(peer)


def native_coverage():
    stems = '''plain-tcp plain-udp udp-empty rpdb-none rpdb-some snat dnat both-nat
helper-early helper-seqadj helper-expectation confirm-clash ct-zone-reuse
asymmetric-reverse local-tcp local-udp router-alert generated-errors
direct-socket-errors fragment-order fragment-expiry gso-retained
gso-segment-list jumbo revoke-reload revoke-mode revoke-dns-aba
revoke-dns-shorten revoke-expiry shutdown ack-ambiguity worker-death'''.split()
    rows = [f'F-v{number}-native-{stem}' for number in (4, 6) for stem in stems] + ['F-v6-native-hbh']
    assert len(rows) == len(set(rows)) == 65
    print(json.dumps(dict(
        acceptance=[dict(id=row, status='NOT_RUN', reason='selected daemon subcases do not discharge the complete functional oracle') for row in rows],
        consumers=[dict(id=name, status='NOT_RUN', reason=reason) for name, reason in (
            ('captured-first-original-return', 'production retained-original/entry/fresh-Grace consumer requires a joined per-sample production receipt and complete independent oracle'),
            ('captured-first-follower-order', 'production held-follower/count-zero consumer requires per-generation ordering receipts and complete independent oracle'),
            ('native-host-original-operation', 'Native Host original-operation consumer is outside this Transit cut'),
            ('captured-reverse-translated-import', 'M25: Transit import cannot authenticate CT-ORIGINAL-keyed reverse/translated input; seam extension pending user decision'),
            ('negative-writev-after-admission', 'no deterministic stock injection of a negative writev after admission; no fabricated result'))]
    )), flush=True)


class NativeGateQuery(C.Structure):
    _fields_ = [('target', C.c_uint32), ('attach_type', C.c_uint32), ('query_flags', C.c_uint32),
                ('attach_flags', C.c_uint32), ('programs', C.c_uint64), ('count', C.c_uint32),
                ('padding', C.c_uint32), ('program_flags', C.c_uint64), ('links', C.c_uint64),
                ('link_flags', C.c_uint64), ('revision', C.c_uint64)]


class NativeGateAttach(C.Structure):
    _fields_ = [('target', C.c_uint32), ('program', C.c_uint32), ('attach_type', C.c_uint32),
                ('attach_flags', C.c_uint32), ('replace_program', C.c_uint32),
                ('relative', C.c_uint32), ('revision', C.c_uint64)]


def decode_native_gate_query(query, programs, links, program_flags, link_flags):
    assert 0 <= query.count <= 64 and query.revision > 0, ('invalid TCX count/revision', query.count, query.revision)
    assert query.attach_flags == 0, ('unexpected TCX attach flags', query.attach_flags)
    assert all(len(values) >= query.count for values in (programs, links, program_flags, link_flags)), 'incomplete TCX query'
    entries = []
    for index in range(query.count):
        assert programs[index] > 0 and program_flags[index] == link_flags[index] == 0, 'invalid TCX program/flags'
        entries.append([programs[index], links[index]])
    return dict(entries=entries, revision=query.revision)


def query_native_gate(ifindex, invoke):
    queried = {}
    for direction, attach_type in (('ingress', 46), ('egress', 47)):
        programs, links, program_flags, link_flags = ((C.c_uint32 * 64)() for _ in range(4))
        query = NativeGateQuery(target=ifindex, attach_type=attach_type, programs=C.addressof(programs),
                                count=64, links=C.addressof(links), program_flags=C.addressof(program_flags),
                                link_flags=C.addressof(link_flags))
        invoke(16, query)
        queried[direction] = decode_native_gate_query(query, programs, links, program_flags, link_flags)
    return queried


def native_gate_query(ifindex):
    require_live_namespace()
    return query_native_gate(ifindex, bpf)


def require_native_gate_query(queried, program_id, restorer_program_id, restorer_link_id):
    assert restorer_program_id > 0 and restorer_link_id > 0 and restorer_program_id != program_id, 'invalid owned restorer identity'
    assert queried['ingress']['entries'] == [[restorer_program_id, restorer_link_id], [program_id, 0]] and not queried['egress']['entries'], ('extra, missing, reordered or wrong Native TCX attachment', queried)


def require_native_gate_absent(queried):
    assert not any(value['entries'] for value in queried.values()), ('unowned or remaining TCX attachment', queried)


def decode_native_gate_program(data):
    assert len(data) >= 80, 'incomplete Native program info'
    kind, program_id = struct.unpack_from('=II', data)
    name = data[64:80].split(b'\0', 1)[0].decode()
    assert kind == 3 and program_id > 0 and name == 'honk_nat_gate', ('not the owned SCHED_CLS Native gate program', kind, program_id, name)
    return dict(program_type=kind, program_id=program_id, program_name=name)


def native_gate_program(fd):
    info = C.create_string_buffer(80)
    attr = Info(fd=fd, length=C.sizeof(info), data=C.addressof(info))
    bpf(15, attr)
    return decode_native_gate_program(info.raw[:attr.length])


def native_device_identity(device):
    require_live_namespace()
    ifindex = socket.if_nametoindex(device)
    namespace = os.stat('/proc/self/ns/net')
    sysfs = Path('/sys/class/net') / device
    netdev = sysfs.stat()
    directory = Path(os.environ['HONK_XDP_PIN_ROOT']) / f'xdp-{ifindex}'
    capture = directory.stat()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        cookie, = struct.unpack('=Q', sock.getsockopt(socket.SOL_SOCKET, 71, 8))
    assert cookie > 0 and int((sysfs / 'ifindex').read_text()) == ifindex, 'namespace/device changed during inventory'
    return dict(device=device, ifindex=ifindex, boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                netns_device=namespace.st_dev, netns_inode=namespace.st_ino, netns_cookie=cookie,
                device_inode=netdev.st_ino, iflink=int((sysfs / 'iflink').read_text()),
                device_type=int((sysfs / 'type').read_text()), address=(sysfs / 'address').read_text().strip(),
                capture_device=capture.st_dev, capture_inode=capture.st_ino)


def require_native_gate_identity(result, saved):
    # A TCX bundle can be rebuilt with revision 1; revisions only fence a current mutation.
    revisions = {'ingress_revision', 'egress_revision', 'owner_pid', 'owner_starttime'}
    assert {key: value for key, value in result.items() if key not in revisions} == {
        key: value for key, value in saved.items() if key not in revisions
    }, ('Native gate or namespace/device/capture changed', result, saved)


NATIVE_RETURN_PINS = {'operation-map', 'realm-dispatch-map', 'tap-xdp-guard', 'tap-xdp-dispatch',
    'tap-tcx-redirect-prog', 'tap-tcx-guard-prog', 'target-entry-prog', 'target-entry-link'}


def pinned_object(path):
    assert not Path(path).is_symlink(), ('symlink in Native pin inventory', path)
    name = C.create_string_buffer(os.fsencode(path))
    return bpf(7, ObjectGet(pathname=C.addressof(name)))


def require_native_return_receipt(receipt, namespace, attachment=None):
    assert type(receipt) is dict and receipt['format'] == 2 and receipt['namespace'] == namespace, 'Native return receipt namespace/format'
    for field in ('namespace', 'pid', 'starttime', 'return_attachment'):
        assert type(receipt[field]) is int and 0 < receipt[field] < 1 << 64, ('invalid Native return receipt identity', field)
    assert receipt['operation_bytes'] == 264 and isinstance(receipt['source_sha'], str) and receipt['source_sha'], 'Native return source/operation ABI differs'
    if attachment is not None:
        assert receipt['return_attachment'] == attachment and receipt['phase'] == 'joined', 'Native return joined attachment differs'
    expected = Path(os.environ['HONK_XDP_PIN_ROOT']) / f"native-return-{receipt['return_attachment']}"
    assert Path(receipt['pin_root']) == expected, 'Native return receipt pin root differs'
    resources = receipt['resources']
    assert type(resources) is list and len(resources) == 4 and all(item['state'] == 'installed' for item in resources), 'unacknowledged Native return mutation'
    by_role = {item['role']: item for item in resources}
    assert set(by_role) == {'private-tap', 'private-tap-configuration', 'terminal-netdev-drop', 'private-installation'}, 'unexpected Native return resource roles'
    tap, installation = by_role['private-tap'], by_role['private-installation']
    assert tap['identity']['namespace'] == namespace and tap['identity']['persistent'] is False, 'foreign/persistent private TAP'
    assert tap['identity']['name'] == f"nr{receipt['return_attachment']:x}" and tap['identity']['flags'] == 0x9002, 'private TAP name/flags differ'
    physical = tap['identity']['max_physical_ip_mtu']
    assert type(physical) is int and 68 <= physical <= 65535, 'physical original MTU differs'
    assert type(tap['identity']['mtu']) is int and tap['identity']['mtu'] == min(physical, 65521), 'private administrative MTU differs'
    assert type(tap['identity']['max_original_frame_bytes']) is int and tap['identity']['max_original_frame_bytes'] == physical + 22, 'original frame capacity differs'
    assert type(tap['observed']['ifindex']) is int and tap['observed']['ifindex'] > 0, 'private TAP ifindex differs'
    for field in ('fd', 'fd_device', 'fd_inode'):
        assert type(tap['observed'][field]) is int and tap['observed'][field] >= 0, ('invalid TAP FD identity', field)
    configuration = by_role['private-tap-configuration']
    assert configuration['identity'] == dict(ifindex=tap['observed']['ifindex'], mtu=tap['identity']['mtu'], offloads=0,
        rx_batched=0, rps_cpus='0', rps_flow_cnt=0, disable_ipv6=1, accept_ra=0, autoconf=0), 'private TAP configuration differs'
    assert configuration['observed'] == dict(readback='matched', mtu=tap['identity']['mtu'], max_mtu=65521, arphrd=1), 'private TAP configuration not acknowledged'
    assert installation['identity']['root'] == str(expected) and installation['identity']['operation_map_bytes'] == 264 and installation['identity']['static_programs'] == 6, 'private operation/program ABI differs'
    assert set(installation['identity']['pins']) == NATIVE_RETURN_PINS and len(installation['identity']['pins']) == len(NATIVE_RETURN_PINS), 'private declared pin set differs'
    assert installation['identity']['target_pins'] == ['native-return-restorer-prog', 'native-return-restorer-link'], 'physical declared pin set differs'
    targets = installation['identity']['targets']
    assert type(targets) is list and 0 < len(targets) <= 64 and len({t['realm_index'] for t in targets}) == len(targets), 'private realm inventory differs'
    assert {t['realm_index'] for t in targets} == set(range(len(targets))), 'realm dispatch indices are not dense'
    for target in targets:
        assert target['namespace_cookie'] == namespace, 'foreign target namespace'
        assert all(type(target[field]) is int and target[field] > 0 for field in ('ifindex', 'logical_ifindex', 'attachment_generation', 'scope')), 'incomplete target capture authority'
        assert type(target['config_generation']) is int and 0 <= target['config_generation'] <= 0xffffffffffffffff, 'invalid target configuration generation'
    guard = by_role['terminal-netdev-drop']
    assert guard['identity'] == dict(table=f"honk_native_return_{receipt['return_attachment']}", chain='ingress', ifindex=tap['observed']['ifindex']), 'foreign terminal containment'
    assert guard['observed']['policy'] == 'drop' and all(type(guard['observed'][field]) is int and guard['observed'][field] > 0 for field in ('table_handle', 'chain_handle')), 'missing terminal DROP receipt'
    assert type(guard['observed']['rule_handle']) is int and guard['observed']['rule_handle'] > 0, 'invalid terminal rule handle'
    return by_role


def require_native_return_geometry(resources, links):
    tap = resources['private-tap']
    targets = resources['private-installation']['identity']['targets']
    indices = {tap['observed']['ifindex']} | {target['ifindex'] for target in targets}
    selected = {index: [link for link in links if link['ifindex'] == index] for index in indices}
    assert all(len(items) == 1 for items in selected.values()), 'missing/duplicate live return link'
    private = selected[tap['observed']['ifindex']][0]
    assert private['ifname'] == tap['identity']['name'] and private['link_type'] == 'ether', 'private TAP live identity/type differs'
    assert re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', private['address']), 'private TAP Ethernet address absent'
    assert private['linkinfo']['info_kind'] == 'tun' and private['linkinfo']['info_data']['type'] == 'tap', 'private link is not an Ethernet TAP'
    observed = resources['private-tap-configuration']['observed']
    assert private['mtu'] == observed['mtu'] and private['max_mtu'] == observed['max_mtu'], 'live private TAP geometry differs from receipt'
    mtus = [selected[target['ifindex']][0]['mtu'] for target in targets]
    assert all(type(mtu) is int and 68 <= mtu <= 65535 for mtu in mtus), 'invalid live physical MTU'
    assert max(mtus) == tap['identity']['max_physical_ip_mtu'], 'live physical original extent differs from receipt'


def require_native_return_objects(receipt, inventory):
    resources = require_native_return_receipt(receipt, receipt['namespace'])
    installation, tap = resources['private-installation'], resources['private-tap']['observed']['ifindex']
    directory, pin_root = Path(receipt['pin_root']), Path(os.environ['HONK_XDP_PIN_ROOT'])
    expected = {}
    kinds = {'operation-map': 2, 'realm-dispatch-map': 3, 'tap-xdp-guard': 6, 'tap-xdp-dispatch': 6,
        'tap-tcx-redirect-prog': 3, 'tap-tcx-guard-prog': 3, 'target-entry-prog': 26, 'target-entry-link': 2}
    physical = {target['ifindex'] for target in installation['identity']['targets']}
    objects = installation['observed']['objects']
    assert type(objects) is list and 0 < len(objects) <= 512, 'private object inventory bound'
    for item in objects:
        assert item['state'] == 'Installed' and type(item['id']) is int and item['id'] > 0, 'incomplete private object installation'
        role, path = item['role'], Path(item['pin_path'])
        if role == 'realm-gate-prog':
            continue
        if role in kinds:
            assert path == directory / role and item['kind'] == kinds[role] and item['ifindex'] == (0 if role.startswith('target-entry-') else tap), ('foreign private object role/path/kind/target', item)
        else:
            assert role in ('native-return-restorer-prog', 'native-return-restorer-link') and item['ifindex'] in physical, ('unknown private object role/target', item)
            assert path == pin_root / f"xdp-{item['ifindex']}" / role and item['kind'] == (3 if role.endswith('-prog') else 11), 'foreign physical restorer receipt'
        assert path not in expected, ('duplicate installed resource', str(path))
        expected[path] = item
    root = installation['observed']['root_map_id']
    assert type(root) is int and root > 0, 'missing actual publication root ID receipt'
    assert installation['observed']['operation_map_id'] == expected[directory / 'operation-map']['id'], 'operation map scalar/object identity differs'
    assert {path.name for path in expected if path.parent == directory} == NATIVE_RETURN_PINS, 'missing/extra private static pin'
    for ifindex in physical:
        assert all(pin_root / f'xdp-{ifindex}' / role in expected for role in ('native-return-restorer-prog', 'native-return-restorer-link')), 'missing physical restorer receipt'
    assert inventory is not None and inventory['return_attachment'] == receipt['return_attachment'], 'missing/foreign canonical candidate inventory'
    assert inventory['status'] in ('Committed', 'Failed', 'Partial'), 'unknown canonical publication status'
    realms, selected = {target['realm_index'] for target in installation['identity']['targets']}, {}
    for candidate in inventory['candidates']:
        path = Path(candidate['pin_path'])
        assert candidate['realm_index'] in realms and path.parent == directory, 'foreign canonical candidate realm/root'
        assert path not in expected, 'duplicate canonical candidate path'
        expected[path] = dict(role='realm-gate-prog', pin_path=str(path), kind=6, id=candidate['program_id'], ifindex=tap, state='Installed')
        if inventory['status'] == 'Committed' and candidate['state'] == 'Installed':
            assert candidate['realm_index'] not in selected, 'duplicate selected canonical realm'
            selected[candidate['realm_index']] = candidate['program_id']
    if inventory['status'] == 'Committed':
        assert set(selected) == realms, 'committed canonical inventory omits a selected realm'
    return expected, root, selected


def require_native_private_pins(directory, names, expected):
    assert names == {path.name for path in expected if path.parent == directory}, 'missing/extra/staging private pin'


def require_native_dispatch_selection(actual, selected):
    assert actual == selected, ('canonical dispatch selection differs', actual, selected)


def require_native_object_info(item, data, target_count):
    assert len(data) >= 24, 'incomplete private object info'
    kind, object_id = struct.unpack_from('=II', data)
    assert (kind, object_id) == (item['kind'], item['id']), ('replaced private object', item, kind, object_id)
    if item['role'] == 'operation-map':
        assert struct.unpack_from('=IIII', data, 8) == (4, 264, 1, 1 << 10), 'operation map ABI differs'
    elif item['role'] == 'realm-dispatch-map':
        assert struct.unpack_from('=IIII', data, 8) == (4, 4, target_count, 0), 'realm dispatch map ABI differs'


def require_native_link_info(item, data, program_id):
    assert len(data) >= 24 and struct.unpack_from('=I', data, 8)[0] == program_id, 'private link program differs'
    if item['role'] == 'native-return-restorer-link':
        assert struct.unpack_from('=II', data, 16) == (item['ifindex'], 46), 'private link target/attach differs'
    else:
        assert item['role'] == 'target-entry-link' and struct.unpack_from('=I', data, 16)[0] == 24, 'entry link is not the recorded fentry attachment'


def native_root_snapshot(map_id):
    fd = bpf(14, Id(id=map_id))
    try:
        info = C.create_string_buffer(24)
        bpf(15, Info(fd, len(info), C.addressof(info)))
        assert struct.unpack_from('=IIIIII', info) == (2, map_id, 4, 16, 1, 1 << 10), 'publication root map ABI differs'
        key, value = C.c_uint32(), C.create_string_buffer(16)
        bpf(1, Element(fd=fd, key=C.addressof(key), value=C.addressof(value)))
        epoch, flags, reserved = struct.unpack('=QII', value.raw)
        assert epoch > 0 and epoch & 1 and reserved == 0, 'Native publication root is not open'
        return dict(map_id=map_id, epoch=str(epoch), flags=flags, sampled_boottime_ns=str(time.clock_gettime_ns(time.CLOCK_BOOTTIME)))
    finally:
        os.close(fd)


def native_publication_document(prefix, pid, startup_binding=None):
    helpers = runpy.run_path(str(Path(__file__).with_name('native-publication.py')))
    direct = os.environ.get('HONK_XDP_NATIVE_PUBLICATION_ARTIFACT')
    if direct:
        raw = helpers['artifact'](direct)
        document = helpers['decode'](raw)
        binding = dict(helpers['identity'](document), path=direct,
            executable_sha256=hashlib.sha256(Path(f'/proc/{pid}/exe').read_bytes()).hexdigest(),
            build_version=document['build_version'], source_sha=document['source_sha'])
    else:
        binding = helpers['decode'](Path(prefix + '.binding.json').read_bytes())
        raw = helpers['artifact'](binding['path'])
        document = helpers['decode'](raw)
        log = prefix.removesuffix('.publication') + '.daemon.log'
        results = [helpers['result'](line) for line in helpers['results'](log)]
        helpers['same_owner'](results, binding)
        matching = [result for result in results if helpers['matches'](result, binding) and result['sha256'] == hashlib.sha256(raw).hexdigest()]
        assert matching, 'current Native artifact has no durable publication result'
        helpers['published'](matching[-1], raw, document, binding, False)
    assert helpers['identity'](document) == {name: binding[name] for name in helpers['IDENTITY']}, 'Native publication binding identity differs'
    assert int(pid) == binding['pid'] and binding['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'Native publication process/boot differs'
    assert binding['starttime_ticks'] == int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]), 'Native publication owner incarnation differs'
    assert binding['executable_sha256'] == hashlib.sha256(Path(f'/proc/{pid}/exe').read_bytes()).hexdigest(), 'Native daemon executable changed'
    assert all(document[name] == binding[name] for name in ('build_version', 'source_sha')), 'Native source/build identity differs'
    assert document['schema'] == 'native-publication/v1' and document['clock_id'] == 'CLOCK_BOOTTIME' and document['unit'] == 'ns', 'Native publication schema/clock differs'
    helpers['limits'](document)
    if not direct or startup_binding is not None:
        initial_binding = binding if not direct else helpers['decode'](helpers['artifact'](startup_binding))
        assert helpers['matches'](initial_binding, dict(binding, path=initial_binding['path'])), 'startup checkpoint owner differs'
        initial_raw = helpers['artifact'](initial_binding['checkpoint_path'])
        initial = helpers['initial_checkpoint'](initial_binding, initial_raw)
        assert all(document[name] == initial[name] for name in ('build_version', 'source_sha', 'collection_start_ns',
            'initial_epoch', 'initial_flags', 'ring_capacity', 'hook_capacity')), 'current artifact contradicts startup checkpoint'
        assert document['events'][0] == initial['events'][0], 'current history lost initial event'
        if not direct:
            assert Path(prefix + '.initial.json').read_bytes() == initial_raw, 'retained startup bytes changed'
    return document, binding, helpers['captured_inventory'](document)


def native_return_receipt(namespace, attachment=None):
    root = Path(os.environ.get('HONK_XDP_NATIVE_STATE_DIR', '/run/honk-xdp-state/state'))
    path = root / (f'native-return-{namespace}.json' if attachment is None else f'native-return-{namespace}-{attachment}.joined.json')
    assert not path.is_symlink() and path.is_file() and path.stat().st_size <= 1 << 20, ('missing/bad Native return receipt', str(path))
    helpers = runpy.run_path(str(Path(__file__).with_name('native-publication.py')))
    receipt = helpers['decode'](helpers['artifact'](str(path)))
    require_native_return_receipt(receipt, namespace, attachment)
    return receipt


def native_return_inventory(pid, prefix, startup_binding=None):
    pid = int(pid)
    identity = native_device_identity('dut0')
    receipt = native_return_receipt(identity['netns_cookie'])
    assert receipt['phase'] == 'ready' and receipt['pid'] == pid, 'Native return owner is not ready'
    document, binding, dynamic = native_publication_document(prefix, pid, startup_binding)
    assert receipt['starttime'] == binding['starttime_ticks'] and receipt['source_sha'] == binding['source_sha'], 'Native return process/source incarnation differs'
    resources = require_native_return_receipt(receipt, identity['netns_cookie'])
    tap = resources['private-tap']
    name, ifindex, descriptor = tap['identity']['name'], tap['observed']['ifindex'], tap['observed']['fd']
    assert socket.if_nametoindex(name) == ifindex, 'private TAP identity changed'
    descriptor_path = Path(f'/proc/{pid}/fd/{descriptor}')
    descriptor_stat = descriptor_path.stat()
    assert (descriptor_stat.st_dev, descriptor_stat.st_ino) == (tap['observed']['fd_device'], tap['observed']['fd_inode']), 'private TAP FD replaced'
    assert re.search(r'^iff:\s*' + re.escape(name) + r'\s*$', Path(f'/proc/{pid}/fdinfo/{descriptor}').read_text(), re.M), 'daemon does not own the recorded TAP FD'
    links = json.loads(subprocess.check_output(['ip', '-j', '-d', 'link', 'show'], text=True))
    require_native_return_geometry(resources, links)
    expected, root, selected = require_native_return_objects(receipt, dynamic)
    directory = Path(receipt['pin_root'])
    assert not os.path.lexists(directory / 'publication-root'), 'publication root must remain unpinned'
    assert root == binding['root_map_id'], 'private root differs from publication owner'
    root_snapshot = native_root_snapshot(root)
    require_native_private_pins(directory, {entry.name for entry in directory.iterdir()}, expected)
    observed = []
    for path, item in expected.items():
        fd = pinned_object(path)
        try:
            info = C.create_string_buffer(128)
            bpf(15, Info(fd, len(info), C.addressof(info)))
            require_native_object_info(item, info.raw, len(resources['private-installation']['identity']['targets']))
            role = item['role']
            if role == 'realm-dispatch-map' and dynamic['status'] == 'Committed':
                actual = {}
                for realm in selected:
                    key, value = C.c_uint32(realm), C.c_uint32()
                    bpf(1, Element(fd=fd, key=C.addressof(key), value=C.addressof(value)))
                    actual[realm] = value.value
                require_native_dispatch_selection(actual, selected)
            if role.endswith('link'):
                program_role = 'target-entry-prog' if role == 'target-entry-link' else 'native-return-restorer-prog'
                require_native_link_info(item, info.raw, expected[path.with_name(program_role)]['id'])
            observed.append(dict(item))
        finally:
            os.close(fd)
    assert dynamic['status'] == 'Committed', ('canonical publication is not committed', dynamic)
    for physical in {target['ifindex'] for target in resources['private-installation']['identity']['targets']}:
        device = socket.if_indextoname(physical)
        require_native_pins({entry.name for entry in (Path(os.environ['HONK_XDP_PIN_ROOT']) / f'xdp-{physical}').iterdir()})
        gate = native_gate_snapshot(device)
        assert gate['restorer_program_id'] == expected[Path(os.environ['HONK_XDP_PIN_ROOT']) / f'xdp-{physical}' / 'native-return-restorer-prog']['id'], 'restorer program differs from owner receipt'
        assert gate['restorer_link_id'] == expected[Path(os.environ['HONK_XDP_PIN_ROOT']) / f'xdp-{physical}' / 'native-return-restorer-link']['id'], 'restorer link differs from owner receipt'
    queried = native_gate_query(ifindex)
    assert queried['ingress']['entries'] == [[expected[directory / 'tap-tcx-redirect-prog']['id'], 0]] and not queried['egress']['entries'], 'private TAP TCX chain differs'
    xdp = kernel_xdp_state(name)
    require_xdp_identity(xdp, expected[directory / 'tap-xdp-dispatch']['id'])
    guard = resources['terminal-netdev-drop']
    nft = json.loads(subprocess.check_output(['nft', '-j', '-a', 'list', 'table', 'netdev', guard['identity']['table']], text=True))['nftables']
    tables = [entry['table'] for entry in nft if 'table' in entry]
    chains = [entry['chain'] for entry in nft if 'chain' in entry]
    rules = [entry['rule'] for entry in nft if 'rule' in entry]
    assert len(tables) == len(chains) == 1 and tables[0]['handle'] == guard['observed']['table_handle'], 'private NETDEV table changed'
    chain = chains[0]
    assert chain['handle'] == guard['observed']['chain_handle'] and chain['name'] == 'ingress' and chain['hook'] == 'ingress' and chain['policy'] == 'drop' and chain.get('dev') == name, 'private NETDEV DROP containment changed'
    assert len(rules) == 1 and rules[0]['handle'] == guard['observed']['rule_handle'] and rules[0]['expr'] == [dict(drop=None)], 'private NETDEV rules differ'
    return dict(receipt=receipt, tap_ifindex=ifindex, target_identity=identity, objects=observed,
                links=links, root=root_snapshot, captured_realm_inventory=dynamic,
                publication_identity={key: binding[key] for key in ('pid', 'starttime_ticks', 'root_map_id', 'source_sha', 'executable_sha256')})


def native_restorer(device):
    ifindex = socket.if_nametoindex(device)
    result = {}
    for role in ('native-return-restorer-prog', 'native-return-restorer-link'):
        fd = program_fd(device, role)
        try:
            data = C.create_string_buffer(80)
            bpf(15, Info(fd, len(data), C.addressof(data)))
            kind, identity = struct.unpack_from('=II', data)
            assert identity > 0, ('zero owned restorer object ID', role)
            if role.endswith('-prog'):
                assert kind == 3, ('restorer is not SCHED_CLS', kind)
                result['restorer_program_id'] = identity
            else:
                linked_program, _, target, attach_type = struct.unpack_from('=IIII', data, 8)
                assert kind == 11 and linked_program == result['restorer_program_id'] and target == ifindex and attach_type == 46, ('foreign restorer link', kind, linked_program, target, attach_type)
                result['restorer_link_id'] = identity
        finally:
            os.close(fd)
    return result


def native_gate_snapshot(device):
    identity = native_device_identity(device)
    fd = program_fd(device, 'native-gate-prog')
    try:
        program = native_gate_program(fd)
        restorer = native_restorer(device)
        queried = native_gate_query(identity['ifindex'])
        assert native_device_identity(device) == identity, 'namespace/device/capture changed during gate query'
        require_native_gate_query(queried, program['program_id'], **restorer)
        return dict(identity, **program, **restorer, link_id=0, ingress_revision=queried['ingress']['revision'],
                    egress_revision=queried['egress']['revision'])
    finally:
        os.close(fd)


def native_gate(device, pid, expected=''):
    require_live_namespace()
    if expected == 'none':
        require_native_gate_absent(native_gate_query(socket.if_nametoindex(device)))
        return
    if expected:
        saved = json.loads(Path(expected).read_text())
        assert int(pid) == saved['owner_pid'], 'saved gate owner PID differs'
        suffix = f'.{device}.native-gate-program.json'
        assert str(expected).endswith(suffix), 'saved gate inventory filename differs'
        result = native_joined_gate_snapshot(device, saved, str(expected)[:-len(suffix)])
    else:
        result = native_gate_snapshot(device)
        owned = []
        for entry in Path(f'/proc/{int(pid)}/fdinfo').iterdir():
            try:
                text = entry.read_text()
                target = os.readlink(Path(f'/proc/{int(pid)}/fd') / entry.name)
            except FileNotFoundError:
                continue
            if (target == 'anon_inode:bpf-prog' and not re.search(r'^link_id:', text, re.M)
                    and re.search(r'^prog_id:\s*' + str(result['program_id']) + r'\s*$', text, re.M)):
                owned.append(entry.name)
        assert owned, ('Native gate program FD is not retained by the daemon', result, pid)
        result['owner_pid'] = int(pid)
        result['owner_starttime'] = int(Path(f'/proc/{int(pid)}/stat').read_text().rsplit(')', 1)[1].split()[19])
    print(json.dumps(result), flush=True)


native_addresses = {4: ('192.0.2.2', '198.51.100.2'), 6: ('fd00:1::2', 'fd00:2::2')}
native_cases = ('tcp', 'udp-connected', 'udp-unconnected', 'udp-empty-connected', 'udp-empty-unconnected',
                'udp-jumbo', 'udp-unconnected-two-targets')


def native_wire(packet):
    if len(packet) < 14:
        return None
    protocol, offset = struct.unpack_from('!H', packet, 12)[0], 14
    if protocol == 0x0800 and len(packet) >= offset + 20:
        size = (packet[offset] & 15) * 4
        end = offset + struct.unpack_from('!H', packet, offset + 2)[0]
        family, transport, ttl = 4, packet[offset + 9], packet[offset + 8]
        source, target = (socket.inet_ntop(socket.AF_INET, packet[offset + n:offset + n + 4]) for n in (12, 16))
    elif protocol == 0x86dd and len(packet) >= offset + 40:
        size = 40
        end = offset + 40 + struct.unpack_from('!H', packet, offset + 4)[0]
        family, transport, ttl = 6, packet[offset + 6], packet[offset + 7]
        source, target = (socket.inet_ntop(socket.AF_INET6, packet[offset + n:offset + n + 16]) for n in (8, 24))
    else:
        return None
    offset += size
    # Observation only: admission and option actions belong to the daemon/kernel.
    if family == 6:
        for _ in range(8):
            if transport not in (0, 43, 60):
                break
            if end > len(packet) or offset + 8 > end:
                return None
            size = (packet[offset + 1] + 1) * 8
            if offset + size > end:
                return None
            transport, offset = packet[offset], offset + size
    if transport not in (6, 17) or end > len(packet) or end < offset + (20 if transport == 6 else 8):
        return None
    sport, dport = struct.unpack_from('!HH', packet, offset)
    if not 18100 <= dport <= 18107:
        return None
    header = (packet[offset + 12] >> 4) * 4 if transport == 6 else 8
    return dict(family=family, transport=transport, source=source, target=target, sport=sport,
                dport=dport, ttl=ttl, payload=packet[offset + header:end].hex(),
                syn=bool(transport == 6 and packet[offset + 13] & 2))


def native_hbh_client(case):
    cases = ('padding', 'parameter', 'proxy', 'block', 'eight', 'nine')
    assert case in cases, case
    source, target = native_addresses[6]
    port = 49600 + cases.index(case)
    payload = ('native/ipv6-hbh-' + case).encode()
    extension_count = {'eight': 8, 'nine': 9}.get(case, 1)
    parameter = case in ('parameter', 'block')
    packet = frame(18101, 'native-hbh-parameter' if parameter else 'native-hbh-padding', payload, port, extension_count)
    original = packet[14:]
    assert original[6:8] == b'\x00\x25' and original[42:44] == (b'\x80\x00' if parameter else b'\x01\x04'), 'HBH input position/action/hop limit'
    assert len(original) == 40 + 8 * extension_count + 8 + len(payload)
    assert struct.unpack_from('!H', original, 4)[0] == len(original) - 40, 'IPv6 payload extent'
    for index in range(extension_count):
        assert original[40 + 8 * index:48 + 8 * index] == bytes([17 if index == extension_count - 1 else 60, 0]) + (bytes.fromhex('800001020000') if parameter else bytes.fromhex('010400000000')), 'extension chain input'
    udp = original[40 + 8 * extension_count:]
    assert checksum(original[8:40] + struct.pack('!I3xB', len(udp), 17) + udp) == 0, 'UDP checksum after full extension extent'
    error = None
    delivered = False
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp, socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as trace:
        udp.bind((source, port))
        trace.bind(('c0', 0))
        trace.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        assert trace.send(packet) == len(packet)
        deadline = time.monotonic() + (1 if case == 'block' else 5)
        while time.monotonic() < deadline:
            readable, _, _ = select.select([udp, trace], [], [], max(0, deadline - time.monotonic()))
            for sock in readable:
                if sock is udp:
                    data, peer = udp.recvfrom(65535)
                    assert case in ('padding', 'eight', 'proxy'), ('HBH action delivered ordinary UDP', case, data, peer)
                    assert data == payload and peer[:2] == (target, 18101), ('HBH reply bytes/source', case, data, peer)
                    delivered = True
                else:
                    reply, peer = trace.recvfrom(65535)
                    if peer[2] != 0 or len(reply) < 62 or reply[12:14] != b'\x86\xdd' or reply[20] != 58:
                        continue
                    end = 54 + struct.unpack_from('!H', reply, 18)[0]
                    assert end <= len(reply) and end >= 62, 'truncated ICMPv6 observation'
                    message = reply[54:end]
                    if message[0] != 4:
                        continue
                    assert case == 'parameter', ('refused/padded HBH reached Linux option action', case, message.hex())
                    error = dict(type=message[0], code=message[1], pointer=struct.unpack_from('!I', message, 4)[0],
                                 recipient=socket.inet_ntop(socket.AF_INET6, reply[38:54]), quote=message[8:].hex())
                    # These values are stated independently of the unhooked result.
                    assert (error['type'], error['code'], error['pointer'], error['recipient']) == (4, 2, 42, 'fd00:1::2'), error
                    assert message[8:] == original and message[15] == 37, ('ICMPv6 quote changed original operation/hop limit', error, original.hex())
                    pseudo = reply[22:54] + struct.pack('!I3xB', len(message), 58)
                    assert checksum(pseudo + message) == 0, ('invalid ICMPv6 checksum', error)
            if delivered or error is not None:
                break
        _, dropped = struct.unpack('II', trace.getsockopt(263, 6, 8))
        assert dropped == 0, ('HBH sender wire oracle dropped packets', dropped)
    assert delivered == (case in ('padding', 'eight', 'proxy')), ('HBH UDP completion', case, delivered)
    assert (error is not None) == (case == 'parameter'), ('missing/unexpected ICMPv6 Parameter Problem', case, error)
    print(json.dumps(dict(family=6, case=case, payload=payload.hex(), source=[source, port],
                          target=[target, 18101], original=original.hex(), error=error)), flush=True)


def native_hbh_check(peer, case, hooked=True):
    peer.stdin.write('snapshot\n')
    peer.stdin.flush()
    previous = json.loads(ready_line(peer))
    before = json.loads(subprocess.check_output(command('dut', 'count', 'dut0', 'dut1'), text=True, timeout=10)) if hooked else None
    client = subprocess.run(command('client', 'native-hbh-client', case), capture_output=True, text=True, timeout=15)
    assert client.returncode == 0, (client.stdout, client.stderr)
    result = json.loads(client.stdout)
    after = json.loads(subprocess.check_output(command('dut', 'count', 'dut0', 'dut1'), text=True, timeout=10)) if hooked else None
    delta = sum(map(sum, after.values())) - sum(map(sum, before.values())) if hooked else None
    if hooked:
        if case == 'proxy':
            assert delta > 0, ('padded proxy control did not enter XSK/Endpoint', before, after)
        else:
            assert before == after, ('Native HBH operation entered XSK/Endpoint', case, before, after)
    peer.stdin.write('snapshot\n')
    peer.stdin.flush()
    observed = json.loads(ready_line(peer))
    events = observed['events'][len(previous['events']):]
    wire = observed['wire'][len(previous['wire']):]
    raw_wire = observed['hbh_wire'][len(previous['hbh_wire']):]
    raw_frames = [packet for packet in raw_wire if result['payload'] in packet]
    records = [event for event in events if event.get('kind') == 'received' and event.get('payload') == result['payload']]
    proxy = [event for event in events if event.get('kind', '').startswith('proxy-')
             and (event.get('payload') == result['payload'] or (event.get('target'), event.get('port')) == tuple(result['target']))]
    frames = [packet for packet in wire if packet['family'] == 6 and packet['sport'] == result['source'][1] and packet['dport'] == 18101]
    if case in ('parameter', 'block', 'nine'):
        assert not records and not proxy and not frames and not raw_frames, ('HBH negative reached peer/proxy/wire', case, records, proxy, frames, raw_frames)
        assert not any(event.get('kind') == 'received' and event.get('family') == 6 and event.get('case') == 'udp-connected' for event in events), ('HBH negative delivered ordinary UDP', case, events)
    else:
        expected_source = 'fd00:2::250' if case == 'proxy' else 'fd00:1::2'
        assert len(records) == 1 and records[0]['peer'][0] == expected_source, ('HBH consumer/source', case, records)
        if case in ('padding', 'eight'):
            assert records[0]['peer'] == result['source'] and not proxy, ('Native HBH original source/proxy', records, proxy)
            assert len(frames) == 1 and frames[0]['source'] == 'fd00:1::2' and frames[0]['target'] == 'fd00:2::2' and frames[0]['ttl'] == 36 and frames[0]['payload'] == result['payload'], ('Native HBH payload/once-only hop decrement', frames)
            original = bytes.fromhex(result['original'])
            assert raw_frames == [(original[:7] + b'\x24' + original[8:]).hex()], ('original extension chain changed/duplicated on far wire', case, raw_frames)
        else:
            assert len([event for event in proxy if event.get('kind') == 'proxy-udp' and event.get('payload') == result['payload']]) == 1, ('missing actual padded-extension proxy transport', proxy)
    return dict(native_hbh=result, xsk_delta=delta,
                events=events, wire=wire, hbh_wire=raw_wire)


def native_hbh_baseline():
    peer = None
    try:
        for device in ('dut0', 'dut1'):
            subprocess.run(command('dut', 'xdp-absent', device), check=True, timeout=5)
            subprocess.run(command('dut', 'native-gate', device, '0', 'none'), check=True, timeout=5)
        peer = subprocess.Popen(command('server', 'native-peer'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert ready_line(peer) == 'READY'
        result = native_hbh_check(peer, 'parameter', hooked=False)
        peer.stdin.write('done\n')
        peer.stdin.flush()
        ready_line(peer)
        peer.wait(timeout=15)
        assert peer.returncode == 0, peer.stderr.read()
        print(json.dumps(dict(unhooked_kernel=result)), flush=True)
    finally:
        stop(peer)


def native_hbh_cases(peer, config, log, pid, baseline):
    original = Path(config).read_text()
    print(json.dumps(native_hbh_check(peer, 'padding')), flush=True)
    parameter = native_hbh_check(peer, 'parameter')
    expected = json.loads(Path(baseline).read_text())['unhooked_kernel']['native_hbh']
    assert parameter['native_hbh'] == expected, ('Native HBH differs from same-guest unhooked kernel', parameter, expected)
    print(json.dumps(parameter), flush=True)
    print(json.dumps(native_hbh_check(peer, 'eight')), flush=True)
    print(json.dumps(native_hbh_check(peer, 'nine')), flush=True)
    try:
        native_reload(config, log, pid, original.replace('fallback: direct', 'fallback: proxy'))
        print(json.dumps(dict(native_hbh_check(peer, 'proxy'), transport_consumption_only=True)), flush=True)
        native_reload(config, log, pid, original.replace('fallback: direct', 'fallback: block'))
        print(json.dumps(native_hbh_check(peer, 'block')), flush=True)
    finally:
        native_reload(config, log, pid, original)


def native_exact(sock, size, received=None):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if chunk and received is not None:
            received[0] += len(chunk)
        assert chunk, 'early fixture stream EOF'
        data += chunk
    return data


def native_socks_connection(conn, events, failures, idle, shutdown):
    stage = 'greeting'
    started = time.monotonic()
    received = [0]
    try:
        with conn, contextlib.ExitStack() as owned:
            conn.settimeout(10)
            version, methods = native_exact(conn, 2, received)
            assert version == 5 and 0 in native_exact(conn, methods, received)
            conn.sendall(b'\x05\0')
            stage = 'request'
            version, operation, reserved, kind = native_exact(conn, 4)
            assert version == 5 and reserved == 0 and kind in (1, 4)
            family = socket.AF_INET if kind == 1 else socket.AF_INET6
            target = socket.inet_ntop(family, native_exact(conn, 4 if kind == 1 else 16))
            port = struct.unpack('!H', native_exact(conn, 2))[0]
            if operation == 1:
                upstream = owned.enter_context(socket.socket(family, socket.SOCK_STREAM))
                upstream.settimeout(10)
                upstream.bind(('198.51.100.250' if kind == 1 else 'fd00:2::250', 0))
                try:
                    upstream.connect((target, port))
                except ConnectionRefusedError as error:
                    conn.sendall(b'\x05\x05\0\x01' + b'\0' * 6)
                    events.append(dict(kind='proxy-connect-refused', target=target, port=port,
                                       errno=error.errno))
                    return
                conn.sendall(b'\x05\0\0\x01' + socket.inet_aton('10.77.0.2') + b'\0\0')
                events.append(dict(kind='proxy-connect', target=target, port=port))
                active = [conn, upstream]
                stage = 'relay'
                while active and not shutdown.is_set():
                    readable, _, _ = select.select(active, [], [], 0.2)
                    for source in readable:
                        destination = upstream if source is conn else conn
                        data = source.recv(65535)
                        if not data:
                            active.remove(source)
                            destination.shutdown(socket.SHUT_WR)
                        else:
                            destination.sendall(data)
            else:
                assert operation == 3, operation
                relay = owned.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                relay.bind(('10.77.0.2', 0))
                conn.sendall(b'\x05\0\0\x01' + socket.inet_aton('10.77.0.2') + struct.pack('!H', relay.getsockname()[1]))
                outputs = {}
                stage = 'relay'
                while not shutdown.is_set():
                    readable, _, _ = select.select([conn, relay, *outputs], [], [], 0.2)
                    for source in readable:
                        if source is conn:
                            assert not conn.recv(1), 'unexpected UDP association control bytes'
                            return
                        data, peer = source.recvfrom(65535)
                        if source is relay:
                            assert data[:3] == b'\0\0\0' and data[3] in (1, 4), data[:4]
                            kind = data[3]
                            family = socket.AF_INET if kind == 1 else socket.AF_INET6
                            size = 4 if kind == 1 else 16
                            target = socket.inet_ntop(family, data[4:4 + size])
                            port = struct.unpack_from('!H', data, 4 + size)[0]
                            out = next((sock for sock, value in outputs.items() if value[0] == family), None)
                            if out is None:
                                out = owned.enter_context(socket.socket(family, socket.SOCK_DGRAM))
                                out.bind(('198.51.100.250' if kind == 1 else 'fd00:2::250', 0))
                            outputs[out] = (family, peer)
                            events.append(dict(kind='proxy-udp', target=target, port=port, payload=data[6 + size:].hex()))
                            out.sendto(data[6 + size:], (target, port))
                        else:
                            family, destination = outputs[source]
                            kind = 1 if family == socket.AF_INET else 4
                            relay.sendto(b'\0\0\0' + bytes([kind]) + socket.inet_pton(family, peer[0]) + struct.pack('!H', peer[1]) + data, destination)
    except Exception as error:
        if not shutdown.is_set():
            if stage == 'greeting' and received[0] == 0 and (
                isinstance(error, TimeoutError) or
                (isinstance(error, AssertionError) and 'early fixture stream EOF' in str(error))
            ):
                idle.append(f'{error!r}; elapsed={time.monotonic() - started:.1f}s')
            else:
                failures.append(f'{error!r}; stage={stage}; elapsed={time.monotonic() - started:.1f}s\n{traceback.format_exc()}')


def native_peer():
    with contextlib.ExitStack() as owned:
        trace = owned.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)))
        trace.bind(('s0', 0))
        trace.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        listeners = {}
        for number, (_, address) in native_addresses.items():
            family = socket.AF_INET if number == 4 else socket.AF_INET6
            for index, case in enumerate((*native_cases, 'udp-unconnected-two-targets')):
                kind = socket.SOCK_STREAM if case == 'tcp' else socket.SOCK_DGRAM
                sock = owned.enter_context(socket.socket(family, kind))
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((address, 18100 + index))
                if kind == socket.SOCK_STREAM:
                    sock.listen()
                listeners[sock] = (number, case)
        socks = owned.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socks.bind(('10.77.0.2', 11080))
        socks.listen()
        events, wire, hbh_wire, failures, idle, workers = [], [], [], [], [], []
        shutdown = threading.Event()

        def observe(packet, peer):
            if peer[2] != 0:
                return
            record = native_wire(packet)
            if record is not None:
                wire.append(record)
            # Opaque bytes keep the ninth-header refusal independent of native_wire's bound.
            if packet[12:14] == b'\x86\xdd' and b'native/ipv6-hbh-' in packet[54:]:
                hbh_wire.append(packet[14:].hex())
                assert len(hbh_wire) <= 4096, 'Native HBH raw wire observations exceeded bound'

        try:
            faulthandler.register(signal.SIGUSR1, file=sys.stderr, all_threads=True)
        except Exception:
            pass
        print('READY', flush=True)
        deadline = time.monotonic() + 180
        try:
            while time.monotonic() < deadline:
                readable, _, _ = select.select([trace, socks, *listeners, sys.stdin], [], [], 0.2)
                for source in readable:
                    if source is sys.stdin:
                        request = sys.stdin.readline().strip()
                        assert request in ('snapshot', 'done', 'diagnose'), request
                        # Drain frames already queued before publishing the socket observations.
                        while select.select([trace], [], [], 0)[0]:
                            packet, peer = trace.recvfrom(65535)
                            observe(packet, peer)
                        if request == 'diagnose':
                            print(json.dumps(dict(events=list(events)[:256],
                                                  wire=[dict(record, payload=record['payload'][:96]) for record in list(wire)[:4096]],
                                                  hbh_wire=list(hbh_wire)[:4096],
                                                  failures=list(failures)[:16], idle=list(idle)[:16])), flush=True)
                        else:
                            _, dropped = struct.unpack('II', trace.getsockopt(263, 6, 8))
                            assert dropped == 0, ('Native wire oracle dropped packets', dropped)
                            assert not failures, failures
                            print(json.dumps(dict(events=events, wire=wire, hbh_wire=hbh_wire)), flush=True)
                            if request == 'done':
                                return
                    elif source is trace:
                        packet, peer = trace.recvfrom(65535)
                        observe(packet, peer)
                    elif source is socks:
                        conn, _ = socks.accept()
                        worker = threading.Thread(target=native_socks_connection, args=(conn, events, failures, idle, shutdown))
                        worker.start()
                        workers.append(worker)
                    else:
                        number, case = listeners[source]
                        if case == 'tcp':
                            conn, peer = source.accept()
                            with conn:
                                conn.settimeout(5)
                                data = b''
                                while True:
                                    chunk = conn.recv(65535)
                                    if not chunk:
                                        break
                                    data += chunk
                                    assert len(data) <= 65535, 'unbounded fixture TCP input'
                                conn.sendall(data)
                        else:
                            data, peer = source.recvfrom(65535)
                            source.sendto(data, peer)
                        events.append(dict(kind='received', family=number, case=case, peer=list(peer[:2]), payload=data.hex(), target_port=source.getsockname()[1]))
                    assert len(events) <= 256 and len(wire) <= 4096, 'Native fixture exceeded bounded observations'
            raise TimeoutError('Native peer completion deadline')
        except BaseException:
            try:
                sys.stderr.write(traceback.format_exc()[:4096])
                sys.stderr.flush()
            except BaseException:
                pass
            raise
        finally:
            shutdown.set()
            for worker in workers:
                worker.join(timeout=11)
                assert not worker.is_alive(), 'proxy fixture worker did not join'
            assert not failures, failures


def native_payload(case, label, target_index=0):
    if 'empty' in case:
        return b''
    prefix = ('native/' + label + (f'/target-{target_index}' if case == 'udp-unconnected-two-targets' else '')).encode()
    return (prefix + bytes(range(256)) * (32 if case == 'udp-jumbo' else 1))[:8192]


def native_client(number, case, profile, label, blocked='false', source_port='0', synchronized='false'):
    number = int(number)
    blocked = blocked == 'true'
    family = socket.AF_INET if number == 4 else socket.AF_INET6
    index = native_cases.index(case)
    source, address = native_addresses[number]
    if profile == 'native-nat':
        address = '198.51.100.99' if number == 4 else 'fd00:2::99'
    with socket.socket(family, socket.SOCK_STREAM if case == 'tcp' else socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1 if blocked else 5)
        sock.setsockopt(socket.IPPROTO_IP if number == 4 else socket.IPPROTO_IPV6,
                        socket.IP_TTL if number == 4 else socket.IPV6_UNICAST_HOPS, 37)
        sock.bind((source, int(source_port) or 43000 + number * 100 + index + (2000 if profile == 'native-nat' else 0)))
        if synchronized == 'true':
            print('READY', flush=True)
            assert sys.stdin.readline() == 'go\n', 'missing finite fixture release'
        operations = []
        for target_index, port in enumerate((18106, 18107) if case == 'udp-unconnected-two-targets' else (18100 + index,)):
            payload, target = native_payload(case, label, target_index), (address, port)
            started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            try:
                if 'unconnected' not in case:
                    sock.connect(target)
                    assert sock.send(payload) == len(payload)
                else:
                    assert sock.sendto(payload, target) == len(payload)
                if case == 'tcp':
                    sock.shutdown(socket.SHUT_WR)
                    reply = native_exact(sock, len(payload))
                    assert sock.recv(1) == b'', 'missing real server TCP half-close'
                    peer = target
                else:
                    reply, peer = sock.recvfrom(65535)
                assert not blocked, ('blocked original reached a peer', label, reply)
                assert reply == payload and peer[:2] == target, ('Native reply bytes/source', label, reply, peer)
            except (TimeoutError, ConnectionRefusedError, ConnectionResetError, OSError) as error:
                assert blocked and isinstance(error, (TimeoutError, ConnectionRefusedError, ConnectionResetError)), (label, repr(error))
            operations.append(dict(family=number, case=case, label=label, payload=payload.hex(),
                source=list(sock.getsockname()[:2]), target=list(target), blocked=blocked,
                target_index=target_index, send_started_boottime_ns=str(started),
                completed_boottime_ns=str(time.clock_gettime_ns(time.CLOCK_BOOTTIME))))
        result = operations[0] if len(operations) == 1 else dict(operations[0], operations=operations)
        print(json.dumps(result), flush=True)


def require_native_owner_log(text, offset=0):
    text = text[offset:]
    assert 'XDP owner failed closed' not in text, 'Native reload: XDP owner failed closed'
    assert 'XDP topology authority changed' not in text, 'Native reload: XDP topology authority changed'


def require_native_owner(log, pid, offset):
    try:
        os.kill(int(pid), 0)
        state = Path(f'/proc/{int(pid)}/stat').read_text().rsplit(')', 1)[1].split()[0]
    except (ProcessLookupError, FileNotFoundError) as error:
        raise AssertionError('Native reload: daemon process exited') from error
    assert state not in ('Z', 'X'), 'Native reload: daemon process exited'
    require_native_owner_log(Path(log).read_text(), offset)


def native_reload(config, log, pid, text):
    config, log = Path(config), Path(log)
    offset = len(log.read_text())
    config.write_text(text)
    os.kill(int(pid), signal.SIGHUP)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        result = re.search(r'SIGHUP reload request \d+ (applied|rejected)', log.read_text()[offset:])
        if result:
            assert result[1] == 'applied', ('Native reload: owner could not process subsequent policy operation', result[0])
            require_native_owner(log, pid, offset)
            return offset
        time.sleep(0.02)
    raise TimeoutError('Native reload: owner could not process subsequent policy operation: publication deadline')


def native_live(number):
    number = int(number)
    family = socket.AF_INET if number == 4 else socket.AF_INET6
    source, address = native_addresses[number]
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind((source, 45000 + number))
        sock.connect((address, 18101))
        sock.setsockopt(socket.IPPROTO_IP if number == 4 else socket.IPPROTO_IPV6,
                        socket.IP_TTL if number == 4 else socket.IPV6_UNICAST_HOPS, 37)
        print('READY', flush=True)
        for line in sys.stdin:
            request = json.loads(line)
            if request.get('done'):
                return
            payload = request['label'].encode()
            sock.settimeout(1 if request['blocked'] else 5)
            sock.send(payload)
            try:
                reply = sock.recv(4096)
            except socket.timeout:
                assert request['blocked'], ('retained Native owner lost permitted operation', request)
            else:
                assert not request['blocked'] and reply == payload, ('retained Native policy/executor', request, reply)
            print(json.dumps(dict(request, source=list(sock.getsockname()), payload=payload.hex())), flush=True)


def native_api(method, resource, body):
    connection = http.client.HTTPConnection('127.0.0.1', 19090, timeout=5)
    try:
        connection.request(method, resource, body or None, {'Content-Type': 'application/json'})
        response = connection.getresponse()
        data = response.read()
        assert response.status in (200, 204), (response.status, data)
        print(data.decode() if data else '{}', flush=True)
    finally:
        connection.close()


def native_policy(peer, config, log, pid):
    original = Path(config).read_text()
    live = []
    expected = []
    blocked_payloads = []
    owner_offset = len(Path(log).read_text())

    @contextlib.contextmanager
    def reloaded(text):
        try:
            native_reload(config, log, pid, text)
        except Exception:
            require_native_owner(log, pid, owner_offset)
            raise
        require_native_owner(log, pid, owner_offset)
        try:
            yield
        except Exception:
            require_native_owner(log, pid, owner_offset)
            raise
        require_native_owner(log, pid, owner_offset)

    def set_mode(mode):
        require_native_owner(log, pid, owner_offset)
        try:
            subprocess.run(command('dut', 'native-api', 'PATCH', '/configs', json.dumps(dict(mode=mode))), check=True, timeout=10)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            require_native_owner(log, pid, owner_offset)
            raise AssertionError('Native reload: owner could not process subsequent policy operation') from error
        require_native_owner(log, pid, owner_offset)

    def snapshot():
        peer.stdin.write('snapshot\n')
        peer.stdin.flush()
        return json.loads(ready_line(peer))

    def send_live(label, blocked):
        for number, child in live:
            request = dict(label=f'{label}-{number}', blocked=blocked)
            child.stdin.write(json.dumps(request) + '\n')
            child.stdin.flush()
            result = json.loads(ready_line(child))
            (blocked_payloads if blocked else expected).append(result['payload'])

    def fresh(label, blocked=False, proxy=False):
        for number in (4, 6):
            for index, case in enumerate(('tcp', 'udp-connected') if proxy else ('udp-connected',)):
                port = 48000 + number * 10 + index if proxy else (46000 if blocked else 47000) + number
                result = subprocess.run(command('client', 'native-client', str(number), case, 'native',
                                                f'{label}-{number}-{case}', str(blocked).lower(), str(port)), capture_output=True, text=True, timeout=15)
                assert result.returncode == 0, (result.stdout, result.stderr)
                value = json.loads(result.stdout)
                if blocked:
                    blocked_payloads.append(value['payload'])
                else:
                    expected.append(value['payload'])
                    far = [event for event in snapshot()['events'] if event.get('kind') == 'received' and event['payload'] == value['payload']]
                    address = ('198.51.100.250' if number == 4 else 'fd00:2::250') if proxy else native_addresses[number][0]
                    assert len(far) == 1 and far[0]['peer'][0] == address, ('fresh proxy/Native selection', value, far)
                    if not proxy:
                        assert far[0]['peer'][1] == port, ('fresh Native source port changed', value, far)

    try:
        for number in (4, 6):
            child = subprocess.Popen(command('client', 'native-live', str(number)), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            live.append((number, child))
            assert ready_line(child) == 'READY'
        send_live('retained-before', False)
        with reloaded(original.replace('fallback: direct', 'fallback: block')):
            send_live('retained-block-reload', False)
            fresh('fresh-block-reload', True)
        with reloaded(original):
            send_live('retained-direct-restore', False)
            native_claims_probe('retained-direct-restore-after')
            fresh('fresh-direct-restore')
        with reloaded(original.replace('fallback: direct', 'fallback: proxy')):
            native_claims_probe('retained-refuse-proxy-migration-before')
            try:
                send_live('retained-refuse-proxy-migration', False)
            finally:
                native_claims_probe('retained-refuse-proxy-migration-after')
            fresh('fresh-proxy', proxy=True)
        set_mode('Direct')
        send_live('retained-mode-direct', False)
        set_mode('Rule')
        send_live('retained-mode-rule-proxy', False)
        with reloaded(original):
            send_live('retained-rule-direct-restored', False)
        observed = snapshot()
        for payload in blocked_payloads:
            assert not any(event.get('payload') == payload for event in observed['events']), ('revoked operation reached actual socket/proxy', payload, observed)
            assert not any(packet['payload'] == payload for packet in observed['wire']), ('revoked operation reached far wire', payload, observed)
        for payload in expected:
            records = [event for event in observed['events'] if event.get('kind') == 'received' and event.get('payload') == payload]
            assert len(records) == 1, ('missing/duplicated permitted operation', payload, records)
            number = records[0]['family']
            if records[0]['peer'][0] == native_addresses[number][0]:
                frames = [packet for packet in observed['wire'] if packet['payload'] == payload and packet['family'] == number]
                assert len(frames) == 1 and frames[0]['source'] == native_addresses[number][0] and frames[0]['sport'] == records[0]['peer'][1] and frames[0]['ttl'] == 36, ('original policy wire operation', frames)
            if bytes.fromhex(payload).startswith(b'retained-'):
                assert records[0]['peer'] == [native_addresses[number][0], 45000 + number], ('retained owner migrated/redialed', records)
                assert not any(event.get('kind') == 'proxy-udp' and event.get('payload') == payload for event in observed['events']), ('retained owner reached proxy transport', payload, observed)
        assert any(event['kind'] == 'proxy-connect' for event in observed['events']) and any(event['kind'] == 'proxy-udp' for event in observed['events']), ('no actual independent proxy transport', observed)
        print(json.dumps(dict(native_policy='PASS', observations=observed)), flush=True)
    except Exception:
        diagnosis = {}

        def diagnose():
            try:
                peer.stdin.write('diagnose\n')
                peer.stdin.flush()
                diagnosis['result'] = ready_line(peer)
            except Exception as error:
                diagnosis['error'] = repr(error)

        worker = threading.Thread(target=diagnose, daemon=True)
        worker.start()
        worker.join(timeout=5)
        if worker.is_alive():
            print(json.dumps({'native_policy_failure_peer_unavailable': 'diagnose deadline'}), flush=True)
        elif 'result' in diagnosis:
            result = diagnosis['result']
            try:
                result = json.loads(result)
            except json.JSONDecodeError:
                pass
            print(json.dumps({'native_policy_failure_peer': result}), flush=True)
        else:
            print(json.dumps({'native_policy_failure_peer_unavailable': diagnosis['error']}), flush=True)
        raise
    finally:
        for _, child in live:
            if child.poll() is None:
                child.stdin.write('{"done":true}\n')
                child.stdin.flush()
            child.wait(timeout=5)
            assert child.returncode == 0, child.stderr.read()


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


def native_peer_stderr_probe(peer):
    try:
        result = dict(poll_before=None, poll_after=None, signal_error=None,
                      bytes=0, eof=False, truncated=False, text='')
        chunks = []
        try:
            result['poll_before'] = peer.poll()
            if result['poll_before'] is None:
                try:
                    os.kill(peer.pid, signal.SIGUSR1)
                except BaseException as error:
                    result['signal_error'] = repr(error)[:200]
                time.sleep(0.3)
            fd = peer.stderr.fileno()
            while result['bytes'] < 8192:
                if not select.select([fd], [], [], 0)[0]:
                    break
                chunk = os.read(fd, min(4096, 8192 - result['bytes']))
                if not chunk:
                    result['eof'] = True
                    break
                chunks.append(chunk)
                result['bytes'] += len(chunk)
            if result['bytes'] == 8192:
                result['truncated'] = True
        except BaseException as error:
            result['error'] = repr(error)[:200]
        try:
            result['poll_after'] = peer.poll()
        except BaseException as error:
            result['error'] = repr(error)[:200]
        result['text'] = b''.join(chunks).decode('utf-8', errors='replace')
        line = json.dumps(dict(native_peer_stderr=result))
        while len(line.encode('utf-8')) + 1 > 16 * 1024:
            result['truncated'] = True
            result['text'] = result['text'][:len(result['text']) // 2]
            line = json.dumps(dict(native_peer_stderr=result))
        print(line, flush=True)
    except BaseException:
        pass


def native_captured_schedule(peer, profile, config, log, pid):
    original = Path(config).read_text()
    assert original.count('routing {') == 1 and 'fallback: direct' in original, 'finite capture schedule requires the original final-Direct profile'
    temporary = original.replace('routing {', 'routing {\n    dport(18100-18107) -> proxy', 1)
    prefix = str(Path(config).with_suffix('.publication'))
    output = Path(config).with_suffix('.captured-schedule.json')
    schedule = dict(schema='native-captured-schedule/v1', clock_id='CLOCK_BOOTTIME', unit='ns', profile=profile,
        config=str(config), publication_prefix=prefix, daemon_pid=int(pid), kernel_release=os.uname().release,
        bounds=dict(children=14, targets=16, child_seconds=15, peer_events=256, peer_frames=4096, peer_seconds=180, artifact_bytes=2 << 20),
        classification=dict(status='NOT_RUN', reason='production per-sample receipt join required; counters, tuple and early PASS grant no captured credit'),
        negative_writev=dict(status='NOT_RUN', reason='no deterministic stock injection of a negative writev after admission; no fabricated result'), attempts=[])
    children, failures = [], []

    def now():
        return str(time.clock_gettime_ns(time.CLOCK_BOOTTIME))

    def snapshot():
        peer.stdin.write('snapshot\n')
        peer.stdin.flush()
        return json.loads(ready_line(peer))

    try:
        prior = snapshot()
        schedule['temporary_reload_started_boottime_ns'] = now()
        native_reload(config, log, pid, temporary)
        schedule['temporary_reload_ack_boottime_ns'] = now()
        readiness = json.loads(subprocess.check_output(command('dut', 'native-return', str(pid), prefix), text=True, timeout=10))
        schedule['old_root'] = readiness['root']
        schedule['return_attachment'] = str(readiness['receipt']['return_attachment'])
        schedule['publication_identity'] = readiness['publication_identity']
        schedule['copy_or_physical_zc'] = 'Copy' if re.search(r'\bmode:\s*copy\b', original) else 'NOT_RUN: no fixture-confirmed lane'
        schedule['xsk_before'] = json.loads(subprocess.check_output(command('dut', 'count', 'dut0', 'dut1'), text=True, timeout=10))
        for number in (4, 6):
            for index, case in enumerate(native_cases):
                label, source_port = f'{profile}-captured-{number}-{case}', 51000 + number * 100 + index
                source, target = native_addresses[number]
                if profile == 'native-nat':
                    target = '198.51.100.99' if number == 4 else 'fd00:2::99'
                attempt = dict(label=label, family=number, case=case, source=[source, source_port], targets=[], child_status='NOT_RUN')
                for target_index, port in enumerate((18106, 18107) if case == 'udp-unconnected-two-targets' else (18100 + index,)):
                    payload = native_payload(case, label, target_index)
                    attempt['targets'].append(dict(target_index=target_index, target=[target, port], payload=payload.hex(),
                        payload_length=len(payload), payload_sha256=hashlib.sha256(payload).hexdigest(),
                        input_frame_length=None, input_full_extent_sha256=None,
                        input_extent_status='NOT_RUN: socket send does not expose the complete captured original frame'))
                schedule['attempts'].append(attempt)
                child = subprocess.Popen(command('client', 'native-client', str(number), case, profile, label, 'false', str(source_port), 'true'),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                children.append((attempt, child))
        ready_deadline = time.monotonic() + 5
        for _, child in children:
            assert select.select([child.stdout], [], [], max(0, ready_deadline - time.monotonic()))[0], 'finite Native client readiness deadline'
            assert child.stdout.readline().strip() == 'READY', 'finite Native client was not ready'
        schedule['release_boottime_ns'] = now()
        deadline = time.monotonic() + 15
        for _, child in children:
            child.stdin.write('go\n')
            child.stdin.flush()
        schedule['final_reload_started_boottime_ns'] = now()
        native_reload(config, log, pid, original)
        schedule['final_reload_ack_boottime_ns'] = now()
        for attempt, child in children:
            try:
                stdout, stderr = child.communicate(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                child.kill()
                stdout, stderr = child.communicate()
                attempt['deadline_expired'] = True
            assert len(stdout.encode()) <= 128 << 10, 'finite Native client exceeded output bound'
            attempt.update(returncode=child.returncode, stderr=stderr[:4096], child_status='PASS' if child.returncode == 0 else 'FAIL')
            if child.returncode == 0:
                attempt['socket_result'] = json.loads(stdout)
            else:
                attempt['stdout'] = stdout[:4096]
                failures.append(attempt['label'])
        observed = snapshot()
        schedule['peer_events'] = observed['events'][len(prior['events']):]
        schedule['peer_wire'] = observed['wire'][len(prior['wire']):]
        schedule['xsk_after'] = json.loads(subprocess.check_output(command('dut', 'count', 'dut0', 'dut1'), text=True, timeout=10))
        schedule['completed_boottime_ns'] = now()
        assert not failures, ('finite captured schedule socket failures', failures)
    except BaseException as error:
        schedule['failure'] = repr(error)[:4096]
        raise
    finally:
        for attempt, child in children:
            stop(child)
            if 'returncode' not in attempt:
                stdout, stderr = child.communicate(timeout=5)
                attempt.update(returncode=child.returncode, stderr=stderr[:4096], stdout=stdout[:4096], child_status='FAIL')
                if child.returncode == 0:
                    attempt['socket_result'] = json.loads(stdout)
                    attempt['child_status'] = 'PASS'
        if Path(config).read_text() != original:
            try:
                schedule['restore_started_boottime_ns'] = now()
                native_reload(config, log, pid, original)
                schedule['restore_ack_boottime_ns'] = now()
            except BaseException as error:
                schedule['restore_failure'] = repr(error)[:4096]
        raw = (json.dumps(schedule, sort_keys=True) + '\n').encode()
        assert len(raw) <= 2 << 20, 'finite Native schedule artifact exceeded bound'
        with output.open('wb') as saved:
            saved.write(raw)
            saved.flush()
            os.fsync(saved.fileno())
        print(json.dumps(dict(captured_schedule=str(output), status=schedule['classification']['status'], reason=schedule['classification']['reason'])), flush=True)


def native_daemon_check(profile, config, log, pid, selection, baseline=''):
    assert profile in ('native', 'native-nat')
    assert selection in ('matrix', 'plain-udp4', 'ipv6-extensions'), selection
    assert selection != 'ipv6-extensions' or profile == 'native', 'extension controls are not NAT evidence; select profile native'
    peer = None
    failed = False
    try:
        peer = subprocess.Popen(command('server', 'native-peer'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert ready_line(peer) == 'READY'
        expected = []
        for number in (4, 6):
            for case in native_cases:
                if selection == 'ipv6-extensions':
                    continue
                if selection == 'plain-udp4' and (number, case) != (4, 'udp-connected'):
                    continue
                label = f'{profile}-{number}-{case}'
                before = json.loads(subprocess.check_output(command('dut', 'count', 'dut0', 'dut1'), text=True, timeout=10))
                client = subprocess.run(command('client', 'native-client', str(number), case, profile, label), capture_output=True, text=True, timeout=15)
                assert client.returncode == 0, (client.stdout, client.stderr)
                result = json.loads(client.stdout)
                expected.extend(result.get('operations', [result]))
                after = json.loads(subprocess.check_output(command('dut', 'count', 'dut0', 'dut1'), text=True, timeout=10))
                assert before == after, ('Native operation entered XSK/relay', label, before, after)
                print(json.dumps(dict(native_socket=result, xsk_delta=0)), flush=True)
        peer.stdin.write('snapshot\n')
        peer.stdin.flush()
        observed = json.loads(ready_line(peer))
        for result in expected:
            number, case = result['family'], result['case']
            source = ('203.0.113.1' if number == 4 else 'fd00:99::1') if profile == 'native-nat' else native_addresses[number][0]
            records = [event for event in observed['events'] if event.get('kind') == 'received' and event['family'] == number and event['case'] == case
                       and (case != 'udp-unconnected-two-targets' or event['target_port'] == result['target'][1])]
            assert len(records) == 1 and records[0]['peer'] == [source, result['source'][1]] and records[0]['payload'] == result['payload'], ('original socket/source or exactly-once receive', result, records)
            frames = [packet for packet in observed['wire'] if packet['family'] == number and packet['sport'] == result['source'][1] and packet['dport'] == result['target'][1]]
            assert frames and all(packet['source'] == source and packet['target'] == native_addresses[number][1] and packet['ttl'] == 36 for packet in frames), ('original NAT/TTL operation', result, frames)
            if case != 'tcp':
                assert len(frames) == 1 and frames[0]['payload'] == result['payload'], ('duplicated/modified UDP wire operation', result, frames)
            else:
                assert sum(packet['syn'] for packet in frames) == 1, ('TCP original was redialed', frames)
                assert bytes.fromhex(result['payload']) == b''.join(bytes.fromhex(packet['payload']) for packet in frames), ('TCP original bytes replayed', frames)
        if selection != 'ipv6-extensions':
            print(json.dumps(dict(native_wire=profile, status='PASS', selected=selection, observations=observed)), flush=True)
        if selection == 'matrix':
            native_captured_schedule(peer, profile, config, log, pid)
        if profile == 'native' and selection == 'matrix':
            native_policy(peer, config, log, pid)
        if profile == 'native' and selection in ('matrix', 'ipv6-extensions'):
            native_hbh_cases(peer, config, log, pid, baseline)
        if selection == 'ipv6-extensions':
            print(json.dumps(dict(native_wire=profile, status='PASS', selected=selection)), flush=True)
        peer.stdin.write('done\n')
        peer.stdin.flush()
        ready_line(peer)
        peer.wait(timeout=15)
        assert peer.returncode == 0, peer.stderr.read()
    except BaseException:
        failed = True
        raise
    finally:
        if failed and peer is not None:
            native_peer_stderr_probe(peer)
        stop(peer)


def program_identity(fd, device, role, saved_guard=None, native=False):
    info = C.create_string_buffer(80)
    bpf(15, Info(fd, len(info), C.addressof(info)))
    kind, identity = struct.unpack_from('=II', info)
    name = 'honk_nat_xdp' if native and role == 'data' else os.environ.get('HONK_XDP_EXPECT_NAME') or f'honk_xdp_{role}'
    assert kind == 6 and identity != 0 and info.raw[64:80].rstrip(b'\0') == name.encode(), ('unexpected pinned XDP program', device, role, kind, identity, info.raw[64:80])
    if saved_guard is not None:
        assert role == 'guard' and identity == int(saved_guard), ('guard pin changed since readiness', device, identity, saved_guard)
    if native:
        directory = Path(os.environ['HONK_XDP_PIN_ROOT']) / f'xdp-{socket.if_nametoindex(device)}'
        assert not os.path.lexists(directory / 'native-xdp-link'), ('stale Native XDP link pin', device)
    return identity


def require_native_pins(names):
    assert not names & {'native-gate-link', 'native-xdp-link'}, ('legacy or mixed Native pin format requires separate recovery', names)
    assert names == {'guard', 'data', 'native-gate-prog', 'native-return-restorer-prog', 'native-return-restorer-link'}, ('prepared-only, unknown or staging Native pins require explicit recovery', names)


def native_gate_detach_request(ifindex, fd, revision):
    assert ifindex > 0 and fd > 0 and revision > 0, 'exact TCX detach requires a nonzero program FD and current revision'
    return NativeGateAttach(target=ifindex, program=fd, attach_type=46, revision=revision)


def native_gate_detach(fd, ifindex, revision, invoke, readback,
                       duplicate=lambda fd: fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 1), close=os.close):
    assert fd >= 0
    exact_fd = duplicate(fd) if fd == 0 else fd
    assert exact_fd > 0, 'could not retain a nonzero exact gate program FD'
    try:
        assert invoke(9, native_gate_detach_request(ifindex, exact_fd, revision)) == 0, 'unexpected PROG_DETACH result'
        readback()
    finally:
        if exact_fd != fd:
            close(exact_fd)


def require_native_joined_inventory(receipt, saved, identity):
    resources = require_native_return_receipt(receipt, identity['netns_cookie'], receipt['return_attachment'])
    assert receipt['pid'] == saved['owner_pid'] and receipt['starttime'] == saved['owner_starttime'], 'joined receipt owner incarnation differs'
    expected, _, _ = require_native_return_objects(receipt, dict(return_attachment=receipt['return_attachment'], status='Partial', candidates=[]))
    entries, directory = receipt['terminal_inventory'], Path(receipt['pin_root'])
    assert type(entries) is list and 0 < len(entries) <= 1024, 'joined terminal inventory bound'
    seen, realms = {}, {}
    helpers = runpy.run_path(str(Path(__file__).with_name('native-publication.py')))
    candidates, programs = set(), set()
    targets = {target['realm_index'] for target in resources['private-installation']['identity']['targets']}
    for item in entries:
        path, role = Path(item['pin_path']), item['role']
        assert item['state'] in ('Detached', 'Unpinned') and type(item['id']) is int and item['id'] > 0, 'unresolved joined terminal object'
        if path in expected:
            assert all(item[field] == expected[path][field] for field in ('role', 'kind', 'id', 'ifindex')), 'joined terminal object identity differs'
        else:
            assert role == 'realm-gate-prog' and path.parent == directory and len(str(path).encode()) <= 4096, 'foreign joined terminal object path'
            key = helpers['captured_candidate_name'](path.name)
            realm = key[0]
            assert realm in targets and item['kind'] == 6 and item['ifindex'] == resources['private-tap']['observed']['ifindex'], 'foreign joined canonical identity'
            helpers['unsigned'](item['id'])
            assert key not in candidates and item['id'] not in programs, 'duplicate joined canonical identity/path/program'
            candidates.add(key)
            programs.add(item['id'])
            realms.setdefault(realm, set()).add(path)
            assert len(realms[realm]) <= 2, 'joined canonical old/new bound'
        states = seen.setdefault(path, [])
        assert item['state'] not in states, 'duplicate joined terminal transition'
        states.append(item['state'])
    assert set(expected) <= set(seen) and set(realms) == targets, 'joined terminal inventory omits installed objects/realms'
    for path, states in seen.items():
        assert set(states) == ({'Detached', 'Unpinned'} if path.name.endswith('link') else {'Unpinned'}), 'joined object lacks exact detach/unpin transitions'
    physical = Path(os.environ['HONK_XDP_PIN_ROOT']) / f"xdp-{identity['ifindex']}"
    assert expected[physical / 'native-return-restorer-link']['id'] == saved['restorer_link_id'], 'joined receipt restorer link differs'
    assert expected[physical / 'native-return-restorer-prog']['id'] == saved['restorer_program_id'], 'joined receipt restorer program differs'
    return expected


def native_joined_ack(path, receipt, saved, prefix):
    helpers = runpy.run_path(str(Path(__file__).with_name('native-publication.py')))
    raw = helpers['artifact'](str(path))
    assert helpers['decode'](raw) == receipt, 'joined receipt changed during acknowledgement validation'
    artifact = os.environ.get('HONK_XDP_NATIVE_PUBLICATION_ARTIFACT')
    if artifact is None:
        assert prefix, 'joined cleanup requires a bound publication prefix or actual fixture artifact'
        artifact = prefix + '.publication.artifact.json'
    document = helpers['decode'](helpers['artifact'](artifact))
    owner = helpers['identity'](document)
    assert owner['pid'] == saved['owner_pid'] == receipt['pid'] and owner['starttime_ticks'] == saved['owner_starttime'] == receipt['starttime'], 'joined ACK owner incarnation differs'
    assert owner['boot_id'] == saved['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and document['source_sha'] == receipt['source_sha'], 'joined ACK boot/source differs'
    assert owner['root_map_id'] == next(item for item in receipt['resources'] if item['role'] == 'private-installation')['observed']['root_map_id'], 'joined ACK publication root differs'
    assert document['schema'] == 'native-publication/v1' and document['clock_id'] == 'CLOCK_BOOTTIME' and document['unit'] == 'ns', 'joined ACK artifact schema differs'
    assert all(document[field] is True for field in ('final', 'complete', 'terminal', 'hooks_joined', 'all_counters_sealed')), 'joined ACK artifact lacks complete joined owner'
    return helpers['captured_joined_ack'](document, path.name, receipt['return_attachment'], hashlib.sha256(raw).hexdigest())


def native_joined_maps(receipt, expected):
    for role, layout in (('operation-map', (2, 4, 264, 1, 1 << 10)),
                         ('realm-dispatch-map', (3, 4, 4, len(next(item for item in receipt['resources'] if item['role'] == 'private-installation')['identity']['targets']), 0))):
        path = Path(receipt['pin_root']) / role
        if not os.path.lexists(path):
            continue
        fd = pinned_object(path)
        try:
            info = C.create_string_buffer(24)
            bpf(15, Info(fd, len(info), C.addressof(info)))
            kind, identity, key, value, entries, flags = struct.unpack_from('=IIIIII', info)
            assert identity == expected[path]['id'] and (kind, key, value, entries, flags) == layout, f'replaced Native {role}'
        finally:
            os.close(fd)


def native_joined_gate_snapshot(device, saved, prefix=None):
    identity = native_device_identity(device)
    assert identity == {key: saved[key] for key in identity}, 'joined recovery namespace/device/capture changed'
    root = Path(os.environ.get('HONK_XDP_NATIVE_STATE_DIR', '/run/honk-xdp-state/state'))
    paths = list(root.glob(f"native-return-{identity['netns_cookie']}-*.joined.json"))
    assert len(paths) <= 64, 'joined receipt fixture bound exceeded'
    matched = []
    link_path = Path(os.environ['HONK_XDP_PIN_ROOT']) / f"xdp-{identity['ifindex']}" / 'native-return-restorer-link'
    program_path = link_path.with_name('native-return-restorer-prog')
    for path in paths:
        match = re.fullmatch(r'native-return-' + str(identity['netns_cookie']) + r'-([1-9][0-9]*)\.joined\.json', path.name)
        assert match, 'malformed joined receipt name'
        receipt = native_return_receipt(identity['netns_cookie'], int(match[1]))
        entries = receipt['terminal_inventory']
        links = [item for item in entries if item['role'] == 'native-return-restorer-link'
                 and item['pin_path'] == str(link_path) and item['id'] == saved['restorer_link_id'] and item['ifindex'] == identity['ifindex']]
        if not links:
            continue
        assert receipt['pid'] == saved['owner_pid'] and receipt['starttime'] == saved['owner_starttime'], 'joined receipt owner incarnation differs'
        expected = require_native_joined_inventory(receipt, saved, identity)
        native_joined_maps(receipt, expected)
        native_joined_ack(path, receipt, saved, prefix)
        active = root / f"native-return-{identity['netns_cookie']}.json"
        assert not os.path.lexists(active), 'live Native return owner prevents joined singleton recovery'
        assert {item['state'] for item in links} == {'Detached', 'Unpinned'} and len(links) == 2, 'restorer link lacks exact detach/unpin receipt'
        programs = [item for item in entries if item['role'] == 'native-return-restorer-prog'
                    and item['pin_path'] == str(program_path) and item['id'] == saved['restorer_program_id'] and item['ifindex'] == identity['ifindex']]
        assert len(programs) == 1 and programs[0]['state'] == 'Unpinned', 'restorer program lacks exact unpin receipt'
        assert all(not os.path.lexists(item['pin_path']) for item in entries if item['state'] == 'Unpinned'), 'joined object pin still exists'
        private = Path(receipt['pin_root'])
        assert not private.exists() or not list(private.iterdir()), 'private operation/program pins survive joined close'
        assert not os.path.lexists(link_path) and not os.path.lexists(program_path), 'restorer survives joined close'
        resources = require_native_return_receipt(receipt, identity['netns_cookie'], receipt['return_attachment'])
        assert resources['private-tap']['identity']['name'] not in dict(socket.if_nameindex()).values(), 'private TAP survives joined close'
        tables = json.loads(subprocess.check_output(['nft', '-j', 'list', 'tables', 'netdev'], text=True, timeout=5))['nftables']
        assert not any(entry.get('table', {}).get('name') == resources['terminal-netdev-drop']['identity']['table'] for entry in tables), 'private NETDEV containment survives joined close'
        matched.append(receipt)
    assert len(matched) == 1, 'missing, foreign or ambiguous joined captured-return receipt'
    directory = link_path.parent
    assert {item.name for item in directory.iterdir()} == {'guard', 'data', 'native-gate-prog'}, 'joined physical pin set differs'
    fd = program_fd(device, 'native-gate-prog')
    try:
        program = native_gate_program(fd)
    finally:
        os.close(fd)
    queried = native_gate_query(identity['ifindex'])
    assert queried['ingress']['entries'] == [[saved['program_id'], 0]] and not queried['egress']['entries'], 'joined gate is not the exact saved singleton'
    result = dict(identity, **program, restorer_program_id=saved['restorer_program_id'],
                  restorer_link_id=saved['restorer_link_id'], link_id=0,
                  ingress_revision=queried['ingress']['revision'], egress_revision=queried['egress']['revision'])
    require_native_gate_identity(result, saved)
    return result


def detach_native_gate(device, fd, saved, prefix):
    require_live_namespace()
    current = native_joined_gate_snapshot(device, saved, prefix)
    require_native_gate_identity(current, saved)
    assert native_gate_program(fd)['program_id'] == current['program_id'], 'opened gate program differs from pin/query'

    def readback():
        identity = native_device_identity(device)
        assert identity == {key: saved[key] for key in identity}, 'namespace/device/capture changed during detach'
        require_native_gate_absent(native_gate_query(current['ifindex']))
        assert native_device_identity(device) == identity, 'namespace/device/capture changed during absence query'

    native_gate_detach(fd, current['ifindex'], current['ingress_revision'], bpf, readback)


def native_cleanup(prefix, *devices):
    require_live_namespace()
    assert devices and len(devices) == len(set(devices)), 'expected distinct owned devices'
    inventory = []
    with contextlib.ExitStack() as owned:
        for device in devices:
            identity = native_device_identity(device)
            directory = Path(os.environ['HONK_XDP_PIN_ROOT']) / f"xdp-{identity['ifindex']}"
            guard_file, gate_file = Path(f'{prefix}.{device}.guard-id'), Path(f'{prefix}.{device}.native-gate-program.json')
            assert guard_file.is_file() and gate_file.is_file(), 'prepared-only Native pins lack joined-daemon inventory; explicit recovery required'
            saved_guard, saved_gate = guard_file.read_text().strip(), json.loads(gate_file.read_text())
            names = {entry.name for entry in directory.iterdir()}
            if names != {'guard', 'data', 'native-gate-prog'}:
                require_native_pins(names)
                require_native_gate_identity(native_gate_snapshot(device), saved_gate)
            programs = {}
            for role in ('guard', 'data', 'native-gate-prog'):
                fd = program_fd(device, role)
                owned.callback(os.close, fd)
                program_id = (native_gate_program(fd)['program_id'] if role == 'native-gate-prog' else
                              program_identity(fd, device, role, saved_guard if role == 'guard' else None, native=True))
                programs[role] = (fd, program_id)
            if names == {'guard', 'data', 'native-gate-prog'}:
                queried = native_gate_query(identity['ifindex'])
                assert queried['ingress']['entries'] == [[saved_gate['program_id'], 0]] and not queried['egress']['entries'], 'joined candidate chain differs from saved gate'
            else:
                require_native_gate_identity(native_gate_snapshot(device), saved_gate)
            assert programs['native-gate-prog'][1] == saved_gate['program_id'], 'gate pin changed during inventory'
            assert native_device_identity(device) == identity, 'namespace/device/capture changed during inventory'
            require_xdp_identity(kernel_xdp_state(device), programs['guard'][1])
            inventory.append((device, directory, programs, saved_gate, identity))
        for device, directory, programs, gate, identity in inventory:
            native_joined_gate_snapshot(device, gate, prefix)
        archives = {}
        state_root = Path(os.environ.get('HONK_XDP_NATIVE_STATE_DIR', '/run/honk-xdp-state/state'))
        for _, _, _, gate, identity in inventory:
            for path in state_root.glob(f"native-return-{identity['netns_cookie']}-*.joined.json"):
                receipt = native_return_receipt(identity['netns_cookie'], int(re.fullmatch(r'native-return-[0-9]+-([1-9][0-9]*)\.joined\.json', path.name)[1]))
                if (receipt['pid'] == gate['owner_pid'] and receipt['starttime'] == gate['owner_starttime']
                        and any(item['role'] == 'native-return-restorer-link' and item['ifindex'] == identity['ifindex']
                                and item['id'] == gate['restorer_link_id'] for item in receipt['terminal_inventory'])):
                    require_native_joined_inventory(receipt, gate, identity)
                    native_joined_ack(path, receipt, gate, prefix)
                    targets = next(item for item in receipt['resources'] if item['role'] == 'private-installation')['identity']['targets']
                    assert {target['ifindex'] for target in targets} <= {row[4]['ifindex'] for row in inventory}, 'cleanup omits a receipt-named physical gate'
                    archives[path] = hashlib.sha256(path.read_bytes()).hexdigest()
        for device, directory, programs, gate, identity in inventory:
            assert native_device_identity(device) == identity, 'namespace/device/capture changed before XDP detach'
            native_joined_gate_snapshot(device, gate, prefix)
            detach_guard(device, *programs['guard'])
        for device, directory, programs, gate, identity in inventory:
            require_xdp_absent(kernel_xdp_state(device))
            detach_native_gate(device, programs['native-gate-prog'][0], gate, prefix)
        for device, directory, programs, gate, identity in inventory:
            assert native_device_identity(device) == identity, 'namespace/device/capture changed before pin removal'
            require_xdp_absent(kernel_xdp_state(device))
            require_native_gate_absent(native_gate_query(identity['ifindex']))
            assert {entry.name for entry in directory.iterdir()} == {'guard', 'data', 'native-gate-prog'}, 'joined physical pin set changed before unlink'
            for role, (_, expected_id) in programs.items():
                fd = program_fd(device, role)
                try:
                    actual_id = (native_gate_program(fd)['program_id'] if role == 'native-gate-prog' else
                                 program_identity(fd, device, role, native=True))
                    assert actual_id == expected_id, ('pin changed before removal', device, role)
                finally:
                    os.close(fd)
        for device, directory, programs, gate, identity in inventory:
            for role in ('native-gate-prog', 'guard', 'data'):
                (directory / role).unlink()
            directory.rmdir()
        for path, digest in archives.items():
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'joined archive changed before final removal'
        for path in archives:
            path.unlink()
        for parent in {path.parent for path in archives}:
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    print(json.dumps(dict(native_cleanup=list(devices), status='removed')), flush=True)


def native_gate_selftest():
    checked = []

    def rejects(name, action, exception=AssertionError, errno=None):
        try:
            action()
        except exception as error:
            if errno is not None:
                assert error.errno == errno, (name, error)
        else:
            raise AssertionError(('accepted invalid Native custody input', name))
        checked.append(name)

    def program(kind=3, program_id=71, name=b'honk_nat_gate'):
        return struct.pack('=II', kind, program_id) + bytes(56) + name.ljust(16, b'\0')

    def decoded(count=1, revision=8, programs=(71,), links=(0,), program_flags=(0,), link_flags=(0,), attach_flags=0):
        return decode_native_gate_query(NativeGateQuery(count=count, revision=revision, attach_flags=attach_flags),
                                        programs, links, program_flags, link_flags)

    empty = dict(entries=[], revision=1)
    queried = dict(ingress=dict(entries=[[73, 9], [71, 0]], revision=8), egress=empty)
    assert decode_native_gate_program(program()) == dict(program_type=3, program_id=71, program_name='honk_nat_gate')
    require_native_gate_query(queried, 71, 73, 9)
    require_native_gate_absent(dict(ingress=empty, egress=empty))
    require_native_pins({'guard', 'data', 'native-gate-prog', 'native-return-restorer-prog', 'native-return-restorer-link'})
    checked.append('owned-restorer-before-nonlink-gate')
    for name, data in (
            ('xdp-object', program(kind=6)), ('link-object', struct.pack('=III', 11, 71, 72) + bytes(68)),
            ('wrong-program-name', program(name=b'foreign')), ('zero-program-id', program(program_id=0)),
            ('incomplete-program-info', program()[:79])):
        rejects(name, lambda data=data: decode_native_gate_program(data))
    rejects('same-name-wrong-id', lambda: require_native_gate_query(queried, 72, 73, 9))
    for name, ingress, egress in (
            ('extra-ingress', dict(entries=[[73, 9], [71, 0], [72, 0]], revision=8), empty),
            ('wrong-restorer-id', dict(entries=[[74, 9], [71, 0]], revision=8), empty),
            ('wrong-restorer-link', dict(entries=[[73, 10], [71, 0]], revision=8), empty),
            ('missing-restorer-link', dict(entries=[[73, 0], [71, 0]], revision=8), empty),
            ('wrong-order', dict(entries=[[71, 0], [73, 9]], revision=8), empty),
            ('singleton-is-not-production', decoded(), empty),
            ('nonzero-gate-link-id', dict(entries=[[73, 9], [71, 8]], revision=8), empty),
            ('nonempty-egress', queried['ingress'], dict(entries=[[72, 0]], revision=8)),
            ('prepared-only-gate', empty, empty)):
        rejects(name, lambda ingress=ingress, egress=egress: require_native_gate_query(dict(ingress=ingress, egress=egress), 71, 73, 9))
    rejects('absence-required', lambda: require_native_gate_absent(queried))
    for name, arguments in (
            ('count-overflow', dict(count=65)), ('zero-revision', dict(revision=0)),
            ('incomplete-query', dict(links=())), ('unfilled-query', dict(programs=(0,))),
            ('program-flags', dict(program_flags=(1,))), ('link-flags', dict(link_flags=(1,))),
            ('attach-flags', dict(attach_flags=1))):
        rejects(name, lambda arguments=arguments: decoded(**arguments))

    calls = []

    def query(operation, attr):
        assert operation == 16 and attr.target == 17 and attr.count == 64
        assert attr.programs and attr.links and attr.program_flags and attr.link_flags
        calls.append(attr.attach_type)
        attr.count, attr.revision = (1, 8) if attr.attach_type == 46 else (0, 1)
        if attr.count:
            C.cast(attr.programs, C.POINTER(C.c_uint32))[0] = 71
        return 0

    assert query_native_gate(17, query) == dict(ingress=decoded(), egress=empty) and calls == [46, 47]
    checked.append('complete-query-buffers')

    def fails(errno):
        raise OSError(errno, os.strerror(errno))

    rejects('query-enospc', lambda: query_native_gate(17, lambda *_: fails(28)), OSError, 28)
    saved = dict(device='dut0', ifindex=17, boot_id='boot', netns_device=4, netns_inode=5, netns_cookie=6,
                 device_inode=7, iflink=18, device_type=1, address='02:00:00:00:00:10',
                 capture_device=8, capture_inode=9, program_type=3, program_id=71,
                 program_name='honk_nat_gate', link_id=0, ingress_revision=8, egress_revision=1)
    require_native_gate_identity(dict(saved, ingress_revision=1, egress_revision=9), saved)
    checked.append('revision-is-not-owner')
    for name, change in (
            ('namespace-mismatch', dict(netns_cookie=16)), ('device-mismatch', dict(ifindex=19)),
            ('device-generation-mismatch', dict(device_inode=17)), ('capture-mismatch', dict(capture_inode=19)),
            ('saved-program-mismatch', dict(program_id=72))):
        rejects(name, lambda change=change: require_native_gate_identity(dict(saved, **change), saved))
    for name, pins in (
            ('legacy-pin-format', {'guard', 'data', 'native-gate-link'}),
            ('mixed-pin-format', {'guard', 'data', 'native-gate-prog', 'native-gate-link'}),
            ('prepared-pin-format', {'guard', 'data'}),
            ('staging-pin-format', {'guard', 'data', 'native-gate-prog', 'data-next'})):
        rejects(name, lambda pins=pins: require_native_pins(pins))

    assert C.sizeof(NativeGateAttach) == 32 and NativeGateAttach.revision.offset == 24
    rejects('zero-sentinel-request', lambda: native_gate_detach_request(17, 0, 8))
    rejects('unfenced-detach-request', lambda: native_gate_detach_request(17, 7, 0))
    events, objects = [], {0: object()}

    def duplicate(fd):
        assert fd == 0
        objects[7] = objects[fd]
        events.append('duplicate')
        return 7

    def close(fd):
        assert fd == 7 and objects.pop(fd) is objects[0]
        events.append('close')

    def detach(operation, attr):
        assert objects[attr.program] is objects[0]
        assert operation == 9 and bytes(attr) == struct.pack('=IIIIIIQ', 17, 7, 46, 0, 0, 0, 8)
        events.append('detach')
        return 0

    def readback():
        assert objects[7] is objects[0] and events == ['duplicate', 'detach']
        events.append('absence')

    native_gate_detach(0, 17, 8, detach, readback, duplicate, close)
    assert events == ['duplicate', 'detach', 'absence', 'close'] and set(objects) == {0}
    checked.append('fd-zero-exact-copy-held-through-readback')
    events.clear()
    rejects('fd-zero-copy-failure', lambda: native_gate_detach(0, 17, 8, detach, readback,
                                                            lambda _: fails(24), close), OSError, 24)
    assert not events and set(objects) == {0}

    def stale(operation, attr):
        assert operation == 9 and attr.revision == 8 and attr.program == 7
        assert objects[7] is objects[0] and calls == [46, 47]
        return fails(116)

    rejects('stale-detach-retains', lambda: native_gate_detach(0, 17, 8, stale, readback,
                                                            duplicate, close), OSError, 116)
    assert events == ['duplicate', 'close'] and set(objects) == {0}
    events.clear()
    rejects('unknown-absence-retains', lambda: native_gate_detach(0, 17, 8, detach, lambda: fails(5),
                                                               duplicate, close), OSError, 5)
    assert events == ['duplicate', 'detach', 'close'] and set(objects) == {0}
    events.clear()
    objects[7] = objects[0]
    native_gate_detach(7, 17, 8, detach, lambda: events.append('absence'), lambda _: fails(5), close)
    assert events == ['detach', 'absence'] and objects[7] is objects[0]
    checked.append('nonzero-fd-retained-by-caller')
    print(json.dumps(dict(native_gate_selftest=checked, status='passed')), flush=True)


def native_return_selftest():
    checked = []

    def rejects(name, action):
        try:
            action()
        except (AssertionError, ValueError, KeyError, struct.error):
            checked.append(name)
        else:
            raise AssertionError(('accepted malformed Native return evidence', name))

    key = bytes(36) + bytes([17, 4]) + struct.pack('=BBQHB5s', 0, 0, 11, 0, 2, bytes(5))
    claim = struct.pack('=QQQIIQQQQII', 7, 7, 13, 3, 16, 23, 0, 0, 0, 0, 0)
    assert decode_native_projection(key, claim)[1]['outstanding'] == 1
    for name, offset, encoding, value in (
            ('unknown-phase', 28, 'I', 7), ('unknown-executor', 24, 'I', 9),
            ('capture-pending', 24, 'I', 1), ('even-epoch', 0, 'Q', 8),
            ('stale-incarnation', 8, 'Q', 9), ('zero-scope', 16, 'Q', 0),
            ('unknown-mark', 64, 'I', 2), ('keep-nonzero-mark', 68, 'I', 1),
            ('transit-owner-cookie', 40, 'Q', 1), ('transit-owner-incarnation', 48, 'Q', 1),
            ('transit-owner-attachment', 56, 'Q', 1), ('transit-set-zero', 64, 'I', 1),
            ('flow-source-pending', 28, 'I', 6)):
        malformed = bytearray(claim)
        struct.pack_into('=' + encoding, malformed, offset, value)
        rejects(name, lambda malformed=malformed: decode_native_projection(key, malformed))
    marked = bytearray(claim)
    struct.pack_into('=II', marked, 64, 1, 0xffffffff)
    rejects('transit-set-full-mark', lambda: decode_native_projection(key, marked))
    active = bytearray(claim)
    struct.pack_into('=II', active, 24, 2, 20)
    rejects('active-outstanding', lambda: decode_native_projection(key, active))
    for domain, direction, zone, state in ((0, 0, 0, 0), (0, 0, 1, 2), (1, 1, 0, 1), (1, 0, 0, 2), (2, 1, 0, 0), (2, 0, 0, 1), (2, 0, 1, 0)):
        malformed = key[:38] + struct.pack('=BBQHB5s', domain, direction, 11, zone, state, bytes(5))
        rejects(f'key-combination-{domain}-{direction}-{zone}-{state}', lambda malformed=malformed: decode_native_key(malformed))
    source_key = key[:38] + struct.pack('=BBQHB5s', 2, 0, 11, 0, 0, bytes(5))
    rejects('unbound-source-flow-pending', lambda: decode_native_projection(source_key, claim))
    for length in (0, 16, 31, 33, 48, 64):
        rejects(f'import-extent-{length}', lambda length=length: decode_native_import(bytes(length)))
    checked.append('ABI56-72-import32')
    helpers = runpy.run_path(str(Path(__file__).with_name('native-publication.py')))
    previous_root = os.environ.get('HONK_XDP_PIN_ROOT')
    os.environ['HONK_XDP_PIN_ROOT'] = '/native-selftest'
    try:
        directory = Path('/native-selftest/native-return-3')
        kinds = {'operation-map': 2, 'realm-dispatch-map': 3, 'tap-xdp-guard': 6, 'tap-xdp-dispatch': 6,
            'tap-tcx-redirect-prog': 3, 'tap-tcx-guard-prog': 3, 'target-entry-prog': 26, 'target-entry-link': 2}
        objects = [dict(role=role, pin_path=str(directory / role), kind=kind, id=100 + index,
            ifindex=0 if role.startswith('target-entry-') else 19, state='Installed') for index, (role, kind) in enumerate(kinds.items())]
        for role, kind, object_id in (('native-return-restorer-prog', 3, 201), ('native-return-restorer-link', 11, 202)):
            objects.append(dict(role=role, pin_path=f'/native-selftest/xdp-17/{role}', kind=kind, id=object_id, ifindex=17, state='Installed'))
        target = dict(realm_index=0, logical_ifindex=17, ifindex=17, namespace_cookie=11, attachment_generation=5, scope=7, config_generation=0)
        tap = dict(role='private-tap', state='installed', identity=dict(name='nr3', namespace=11, mtu=65521,
            max_physical_ip_mtu=65535, max_original_frame_bytes=65557, flags=0x9002, persistent=False),
            observed=dict(ifindex=19, fd=4, fd_device=1, fd_inode=2))
        configuration = dict(role='private-tap-configuration', state='installed',
            identity=dict(ifindex=19, mtu=65521, offloads=0, rx_batched=0, rps_cpus='0', rps_flow_cnt=0, disable_ipv6=1, accept_ra=0, autoconf=0),
            observed=dict(readback='matched', mtu=65521, max_mtu=65521, arphrd=1))
        guard = dict(role='terminal-netdev-drop', state='installed', identity=dict(table='honk_native_return_3', chain='ingress', ifindex=19),
            observed=dict(table_handle=1, chain_handle=2, rule_handle=3, policy='drop'))
        installation = dict(role='private-installation', state='installed', identity=dict(root=str(directory), operation_map_bytes=264, static_programs=6,
            targets=[target], pins=sorted(NATIVE_RETURN_PINS), target_pins=['native-return-restorer-prog', 'native-return-restorer-link']),
            observed=dict(objects=objects, root_map_id=1, operation_map_id=100))
        receipt = dict(format=2, namespace=11, pid=7, starttime=9, return_attachment=3, pin_root=str(directory), operation_bytes=264,
            source_sha='source', phase='ready', resources=[tap, configuration, guard, installation])
        candidate = dict(role='canonical_tap_gate', pin_path=str(directory / 'realm-0-gate-2-1-prog'), program_id=301, realm_index=0, closed_epoch='2', state='Installed')
        document = dict(captured_realm_inventory=dict(return_attachment='3', inventory_seq='1', boottime_ns='1', status='Committed', candidates=[candidate]))

        def inventory(document=document):
            return helpers['captured_inventory'](document)

        expected, root, selected = require_native_return_objects(receipt, inventory())
        assert root == 1 and selected == {0: 301}
        names = {path.name for path in expected if path.parent == directory}
        require_native_private_pins(directory, names, expected)
        require_native_dispatch_selection({0: 301}, selected)
        links = [dict(ifindex=19, ifname='nr3', link_type='ether', address='02:00:00:00:00:01', mtu=65521, max_mtu=65521,
                      linkinfo=dict(info_kind='tun', info_data=dict(type='tap'))), dict(ifindex=17, mtu=65535)]
        require_native_return_geometry(require_native_return_receipt(receipt, 11), links)
        advanced = copy.deepcopy(receipt)
        advanced['resources'][3]['identity']['targets'][0]['config_generation'] = 0xffffffffffffffff
        require_native_return_receipt(advanced, 11)
        for name, field, value in (
                ('negative-config-generation', 'config_generation', -1),
                ('overflow-config-generation', 'config_generation', 1 << 64),
                ('bool-config-generation', 'config_generation', True),
                ('string-config-generation', 'config_generation', '0'),
                ('zero-target-ifindex', 'ifindex', 0), ('zero-logical-ifindex', 'logical_ifindex', 0),
                ('zero-target-attachment', 'attachment_generation', 0), ('zero-target-scope', 'scope', 0)):
            bad = copy.deepcopy(receipt)
            bad['resources'][3]['identity']['targets'][0][field] = value
            rejects(name, lambda bad=bad: require_native_return_receipt(bad, 11))
        for name, mutate in (
                ('admin-uses-physical', lambda r: r['resources'][0]['identity'].update(mtu=65535)),
                ('physical-truncated', lambda r: r['resources'][0]['identity'].update(max_physical_ip_mtu=65521)),
                ('physical-too-large', lambda r: r['resources'][0]['identity'].update(max_physical_ip_mtu=65536)),
                ('physical-wrong-type', lambda r: r['resources'][0]['identity'].update(max_physical_ip_mtu=True)),
                ('frame-capacity-truncated', lambda r: r['resources'][0]['identity'].update(max_original_frame_bytes=65549)),
                ('configuration-physical-mtu', lambda r: r['resources'][1]['identity'].update(mtu=65535)),
                ('observed-wrong-mtu', lambda r: r['resources'][1]['observed'].update(mtu=65535)),
                ('observed-wrong-maximum', lambda r: r['resources'][1]['observed'].update(max_mtu=65535)),
                ('observed-wrong-type', lambda r: r['resources'][1]['observed'].update(arphrd=0))):
            bad = copy.deepcopy(receipt)
            mutate(bad)
            rejects(name, lambda bad=bad: require_native_return_receipt(bad, 11))
        for name, index, change in (('live-admin', 0, dict(mtu=65535)), ('live-maximum', 0, dict(max_mtu=65535)),
                ('live-ifindex', 0, dict(ifindex=20)), ('live-name', 0, dict(ifname='foreign')),
                ('live-type', 0, dict(link_type='none')), ('live-address', 0, dict(address='')),
                ('live-physical-extent', 1, dict(mtu=65521)), ('live-not-tap', 0, dict(linkinfo=dict(info_kind='veth')))):
            bad = copy.deepcopy(links)
            bad[index].update(change)
            rejects(name, lambda bad=bad: require_native_return_geometry(require_native_return_receipt(receipt, 11), bad))
        for bad in (links[:1], links + [links[0]]):
            rejects('live-missing-or-duplicate-link', lambda bad=bad: require_native_return_geometry(require_native_return_receipt(receipt, 11), bad))
        ordinary = copy.deepcopy(receipt)
        ordinary['resources'][0]['identity'].update(mtu=9000, max_physical_ip_mtu=9000, max_original_frame_bytes=9022)
        ordinary['resources'][1]['identity']['mtu'] = 9000
        ordinary['resources'][1]['observed']['mtu'] = 9000
        require_native_return_receipt(ordinary, 11)
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            root_path = Path(folder)
            owner = os.getpid()
            ticks = int(Path(f'/proc/{owner}/stat').read_text().rsplit(')', 1)[1].split()[19])
            mutable = root_path / 'state' / 'native-publication' / f'{owner}-{ticks}-1.json'
            checkpoint = mutable.parent.with_name('native-publication-initial') / mutable.name
            checkpoint.parent.mkdir(parents=True)
            direct = root_path / 'current.json'
            producer_binding = root_path / 'initial-binding.json'
            marker = dict(kind=1, seq='1', epoch_before='0', epoch_after='0')
            original = dict(schema='native-publication/v1', clock_id='CLOCK_BOOTTIME', unit='ns',
                boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(), pid=owner,
                starttime_ticks=str(ticks), publication_serial='1', root_map_id=1,
                build_version='synthetic', source_sha='synthetic', max_hooks=32, max_targets=16,
                data_dir_path_max_bytes=1024, hook_capacity=32, ring_capacity=4096,
                collection_start_ns='1', initial_epoch='0', initial_flags=0,
                final=False, complete=False, terminal=False, ready=False, capture_ready=False,
                final_epoch='0', final_flags=0, last_seq='1', hooks=[], events=[marker])
            original_raw = (json.dumps(original, indent=1) + '\n').encode()
            checkpoint.write_bytes(original_raw)
            latest = dict(original, final_epoch='3', ready=True, capture_ready=True, last_seq='2',
                hooks=[{'synthetic': 'current inventory'}], events=[marker, dict(kind=2)])
            direct.write_text(json.dumps(latest))
            initial_binding = dict(helpers['identity'](original), path=str(mutable), checkpoint_path=str(checkpoint),
                sha256=hashlib.sha256(original_raw).hexdigest(), bytes=len(original_raw))
            producer_binding.write_text(json.dumps(initial_binding))
            # Parser input only; no production custody or kernel admission is claimed.
            with patch.dict(os.environ, HONK_XDP_NATIVE_PUBLICATION_ARTIFACT=str(direct)), patch('runpy.run_path',
                    return_value=dict(helpers, artifact=lambda path: Path(path).read_bytes())):
                assert native_publication_document('unused', owner)[0] == latest
                assert native_publication_document('unused', owner, str(producer_binding))[0] == latest
                checkpoint.write_bytes(original_raw + b' ')
                rejects('explicit-startup-checkpoint-changed', lambda: native_publication_document('unused', owner, str(producer_binding)))
                assert native_publication_document('unused', owner)[0] == latest
                checkpoint.write_bytes(original_raw)
                initial_binding['sha256'] = '0' * 64
                producer_binding.write_text(json.dumps(initial_binding))
                rejects('explicit-startup-producer-digest', lambda: native_publication_document('unused', owner, str(producer_binding)))
            checked.extend(('direct-current-artifact-unchanged', 'explicit-startup-checkpoint-required'))
        for name, changed in (('missing-static-pin', names - {'operation-map'}), ('unreceipted-root-pin', names | {'publication-root'}),
                              ('wildcard-realm-pin', names | {'realm-0-gate-2-2-prog'}), ('staging-private-pin', names | {'tap-xdp-dispatch-next'})):
            rejects(name, lambda changed=changed: require_native_private_pins(directory, changed, expected))
        for actual in ({}, {0: 302}, {0: 301, 1: 302}):
            rejects('wrong-dispatch-selection-' + repr(actual), lambda actual=actual: require_native_dispatch_selection(actual, selected))
        for role, program_id, target, attach_type in (('native-return-restorer-link', 201, 17, 46), ('target-entry-link', 106, 24, 0)):
            item = next(item for item in objects if item['role'] == role)
            info = struct.pack('=IIIIII', item['kind'], item['id'], program_id, 0, target, attach_type)
            require_native_link_info(item, info, program_id)
            for field in (2, 4, 5) if role == 'native-return-restorer-link' else (2, 4):
                malformed = bytearray(info)
                struct.pack_into('=I', malformed, field * 4, 999)
                rejects(f'{role}-field-{field}', lambda malformed=malformed, item=item, program_id=program_id: require_native_link_info(item, malformed, program_id))
        for role, layout in (('operation-map', (2, 100, 4, 264, 1, 1 << 10)), ('realm-dispatch-map', (3, 101, 4, 4, 1, 0))):
            item = expected[directory / role]
            require_native_object_info(item, struct.pack('=IIIIII', *layout), 1)
            for field, replacement in ((0, 1), (1, 999), (2, 8), (3, 48), (4, 2), (5, 1)):
                malformed = list(layout)
                malformed[field] = replacement
                rejects(f'{role}-info-field-{field}', lambda malformed=malformed, item=item: require_native_object_info(item, struct.pack('=IIIIII', *malformed), 1))
        for field, value in (('pin_path', '/foreign/realm-0-gate-2-1-prog'), ('realm_index', 1), ('closed_epoch', '3'), ('state', 'Unknown'), ('program_id', 0)):
            malformed = copy.deepcopy(document)
            malformed['captured_realm_inventory']['candidates'][0][field] = value
            rejects('canonical-' + field, lambda malformed=malformed: require_native_return_objects(receipt, helpers['captured_inventory'](malformed)))
        for name, mutate in (
                ('missing-committed-realm', lambda value: value['captured_realm_inventory'].update(candidates=[])),
                ('unknown-publication-status', lambda value: value['captured_realm_inventory'].update(status='Unknown')),
                ('duplicate-canonical-candidate', lambda value: value['captured_realm_inventory']['candidates'].append(dict(candidate)))):
            changed = copy.deepcopy(document)
            mutate(changed)
            rejects(name, lambda changed=changed: require_native_return_objects(receipt, helpers['captured_inventory'](changed)))
        for name, mutate in (
                ('omitted-object-receipt', lambda value: value['resources'][-1]['observed']['objects'].pop(2)),
                ('foreign-object-receipt', lambda value: value['resources'][-1]['observed']['objects'][2].update(pin_path='/foreign/tap-xdp-guard')),
                ('wrong-object-kind', lambda value: value['resources'][-1]['observed']['objects'][2].update(kind=3)),
                ('unreceipted-root-object', lambda value: value['resources'][-1]['observed']['objects'].append(dict(role='publication-root', pin_path=str(directory / 'publication-root'), kind=2, id=1, ifindex=0, state='Installed')))):
            changed = copy.deepcopy(receipt)
            mutate(changed)
            rejects(name, lambda changed=changed: require_native_return_objects(changed, inventory()))
        for status in ('Failed', 'Partial'):
            changed = copy.deepcopy(document)
            changed['captured_realm_inventory']['status'] = status
            assert require_native_return_objects(receipt, helpers['captured_inventory'](changed))[2] == {}, 'failed attempt selected a canonical program'
        next_candidate = dict(candidate, program_id=302, pin_path=str(directory / 'realm-0-gate-2-2-prog'))
        overlap = copy.deepcopy(document)
        overlap['captured_realm_inventory'].update(status='Partial', candidates=[candidate, next_candidate])
        partial_expected, _, partial_selected = require_native_return_objects(receipt, inventory(overlap))
        assert partial_selected == {} and all(Path(item['pin_path']) in partial_expected for item in (candidate, next_candidate))
        committed = copy.deepcopy(overlap)
        committed['captured_realm_inventory']['status'] = 'Committed'
        rejects('same-epoch-two-selected', lambda: require_native_return_objects(receipt, inventory(committed)))
        committed['captured_realm_inventory']['candidates'][0]['state'] = 'retired-pending'
        assert require_native_return_objects(receipt, inventory(committed))[2] == {0: 302}
        checked.extend(('same-epoch-partial-two-candidates', 'same-epoch-committed-selected-and-retired'))
        for name, extra in (
                ('third-candidate', dict(candidate, program_id=303, pin_path=str(directory / 'realm-0-gate-2-3-prog'))),
                ('duplicate-path', dict(candidate, program_id=303)),
                ('duplicate-identity', dict(candidate, program_id=303, pin_path='/foreign/realm-0-gate-2-1-prog')),
                ('duplicate-program', dict(next_candidate, program_id=301))):
            changed = copy.deepcopy(overlap if name == 'third-candidate' else document)
            changed['captured_realm_inventory']['status'] = 'Partial'
            changed['captured_realm_inventory']['candidates'].append(extra)
            rejects('live-' + name, lambda changed=changed: require_native_return_objects(receipt, inventory(changed)))
        bad_names = (
            'realm-0-gate-2-prog', 'realm-1-gate-2-1-prog', 'realm-00-gate-2-1-prog', 'realm-4294967296-gate-2-1-prog',
            'realm-0-gate-0-1-prog', 'realm-0-gate-3-1-prog', 'realm-0-gate-02-1-prog', 'realm-0-gate-18446744073709551616-1-prog',
            'realm-0-gate-2-0-prog', 'realm-0-gate-2-01-prog', 'realm-0-gate-2-18446744073709551616-prog')
        for name in bad_names:
            changed = copy.deepcopy(document)
            changed['captured_realm_inventory']['candidates'][0]['pin_path'] = str(directory / name)
            rejects('live-' + name, lambda changed=changed: require_native_return_objects(receipt, inventory(changed)))
        boundary = copy.deepcopy(document)
        boundary['captured_realm_inventory']['candidates'][0].update(closed_epoch=str((1 << 64) - 2),
            pin_path=str(directory / 'realm-0-gate-18446744073709551614-18446744073709551615-prog'))
        assert require_native_return_objects(receipt, inventory(boundary))[2] == {0: 301}
        rejects('canonical-inventory-foreign-attachment', lambda: require_native_return_objects(receipt, dict(inventory(), return_attachment=4)))
        for name, change in (('foreign-return-attachment', dict(return_attachment=4)), ('wrong-operation-extent', dict(operation_bytes=256))):
            rejects(name, lambda change=change: require_native_return_objects(dict(receipt, **change), inventory()))
        for field, value in (('state', 'intent'), ('role', 'foreign-installation')):
            changed = copy.deepcopy(receipt)
            changed['resources'][-1][field] = value
            rejects('installation-' + field, lambda changed=changed: require_native_return_objects(changed, inventory()))
        joined = copy.deepcopy(receipt)
        joined['phase'] = 'joined'
        joined['terminal_inventory'] = []
        for path, item in expected.items():
            joined['terminal_inventory'].append(dict(item, state='Unpinned'))
            if path.name.endswith('link'):
                joined['terminal_inventory'].append(dict(item, state='Detached'))
        saved = dict(owner_pid=7, owner_starttime=9, restorer_program_id=201, restorer_link_id=202)
        identity = dict(netns_cookie=11, ifindex=17)
        require_native_joined_inventory(joined, saved, identity)
        terminal = next(item for item in joined['terminal_inventory'] if item['role'] == 'realm-gate-prog')
        overlap_joined = copy.deepcopy(joined)
        overlap_joined['terminal_inventory'].append(dict(terminal, id=302, pin_path=next_candidate['pin_path']))
        require_native_joined_inventory(overlap_joined, saved, identity)
        checked.append('joined-same-epoch-two-candidates')
        for name, extra in (
                ('third-candidate', dict(terminal, id=303, pin_path=str(directory / 'realm-0-gate-2-3-prog'))),
                ('duplicate-path', dict(terminal, id=303)),
                ('duplicate-identity', dict(terminal)),
                ('duplicate-program', dict(terminal, pin_path=next_candidate['pin_path']))):
            changed = copy.deepcopy(overlap_joined if name == 'third-candidate' else joined)
            changed['terminal_inventory'].append(extra)
            rejects('joined-' + name, lambda changed=changed: require_native_joined_inventory(changed, saved, identity))
        for name in bad_names:
            changed = copy.deepcopy(joined)
            next(item for item in changed['terminal_inventory'] if item['role'] == 'realm-gate-prog')['pin_path'] = str(directory / name)
            rejects('joined-' + name, lambda changed=changed: require_native_joined_inventory(changed, saved, identity))
        changed = copy.deepcopy(joined)
        next(item for item in changed['terminal_inventory'] if item['role'] == 'realm-gate-prog')['pin_path'] = boundary['captured_realm_inventory']['candidates'][0]['pin_path']
        require_native_joined_inventory(changed, saved, identity)
        rejects('joined-saved-restorer-program', lambda: require_native_joined_inventory(joined, dict(saved, restorer_program_id=999), identity))
        rejects('joined-saved-restorer-link', lambda: require_native_joined_inventory(joined, dict(saved, restorer_link_id=999), identity))
        for name, field, value in (('stale-owner-incarnation', 'starttime', 10), ('unresolved-operation', 'phase', 'failed-retained'), ('foreign-owner', 'pid', 8)):
            rejects(name, lambda field=field, value=value: require_native_joined_inventory(dict(joined, **{field: value}), saved, identity))
        for name, index, field, value in (('missing-unpin', 0, 'state', 'Installed'), ('replaced-operation-map-receipt', 0, 'id', 999),
                ('foreign-terminal-path', 0, 'pin_path', '/foreign/operation-map'), ('wrong-restorer-link', 10, 'id', 999)):
            changed = copy.deepcopy(joined)
            changed['terminal_inventory'][index][field] = value
            rejects(name, lambda changed=changed: require_native_joined_inventory(changed, saved, identity))
        changed = copy.deepcopy(joined)
        changed['terminal_inventory'] = [item for item in changed['terminal_inventory'] if item['state'] != 'Detached']
        rejects('joined-without-link-detach', lambda: require_native_joined_inventory(changed, saved, identity))
        changed = copy.deepcopy(joined)
        changed['terminal_inventory'].append(changed['terminal_inventory'][0])
        rejects('duplicate-terminal-transition', lambda: require_native_joined_inventory(changed, saved, identity))
        assert len(native_payload('udp-jumbo', 'selftest')) == 8192
        assert native_payload('udp-unconnected-two-targets', 'selftest', 0) != native_payload('udp-unconnected-two-targets', 'selftest', 1)
    finally:
        if previous_root is None:
            os.environ.pop('HONK_XDP_PIN_ROOT')
        else:
            os.environ['HONK_XDP_PIN_ROOT'] = previous_root
    print(json.dumps(dict(native_return_selftest=checked, status='passed')), flush=True)


mode = (sys.argv[1] if len(sys.argv) > 1 else 'check') if __name__ == '__main__' else None
if mode is not None and mode != 'decoder-selftest':
    require_live_namespace()
if mode == 'decoder-selftest':
    decoder_selftest()
    native_gate_selftest()
    native_return_selftest()
elif mode == 'native-cleanup':
    native_cleanup(*sys.argv[2:])
elif mode == 'xdp-absent':
    require_xdp_absent(xdp_state(sys.argv[2]))
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
        expected = program_identity(fd, device, role, saved, native=os.environ.get('HONK_XDP_NATIVE_RUN') == '1')
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
elif mode == 'native-peer':
    native_peer()
elif mode == 'native-hbh-baseline':
    native_hbh_baseline()
elif mode == 'native-hbh-client':
    native_hbh_client(*sys.argv[2:])
elif mode == 'native-client':
    native_client(*sys.argv[2:])
elif mode == 'native-daemon':
    native_daemon_check(*sys.argv[2:])
elif mode == 'native-live':
    native_live(*sys.argv[2:])
elif mode == 'native-api':
    native_api(*sys.argv[2:])
elif mode == 'native-coverage':
    native_coverage()
elif mode == 'native-gate':
    native_gate(*sys.argv[2:])
elif mode == 'native-return':
    print(json.dumps(native_return_inventory(*sys.argv[2:])), flush=True)
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
elif mode == 'native-claims':
    native_claims()
elif mode is not None:
    raise RuntimeError('unknown smoke role')
