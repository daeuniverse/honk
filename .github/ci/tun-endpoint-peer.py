#!/usr/bin/env python3
"""Independent socket/wire oracles for the disposable-guest TUN daemon gate."""
import contextlib
import ctypes
import errno
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback

if sys.flags.optimize:
    raise RuntimeError('optimized Python disables required fixture checks')

SCRIPT = str(Path(__file__).resolve())
ROWS = [f'A-{origin}{family}-{transport}' for origin in 'HT' for family in '46'
        for transport in ('T', 'Uc', 'Uu')]
PORTS = (18080, 18081, 18082, 18083, 18084, 18085, 18086)
SECRET = 'private-tun-smoke-credential'
BANNER = b'TUN independent peer\n'
TAIL = b'TUN retained close tail:' + bytes(range(256)) * 257
TARGETS = {4: ['198.51.100.' + str(i) for i in (2, 3, 10, 11, 12, 13, 14, 15, 16, 17)],
           6: ['fd00:2::' + str(i) for i in (2, 3, 10, 11, 12, 13, 14, 15, 16, 17)]}
DOMAINS = {'bound-udp.test': 2, 'bound-tcp.test': 3, 'transparent-udp.test': 4,
           'transparent-tcp.test': 5, 'asis.test': 6, 'must.test': 7,
           'after-reload.test': 8, 'cross-scope.test': 9}


class CleanupIncomplete(RuntimeError):
    """Do not start another scenario after unconfirmed resource teardown."""


def guard():
    current = str(os.stat('/proc/self/ns/net').st_ino)
    assert os.geteuid() == 0 and 'virtme.' in Path('/proc/cmdline').read_text()
    assert os.environ.get('HONK_CI_VM_LANE') in ('floor', 'recent')
    assert os.uname().release == os.environ['HONK_CI_EXPECTED_KERNEL']
    assert current not in (os.environ['HONK_TUN_PARENT_NETNS'],
                           str(os.stat('/proc/1/ns/net').st_ino))


def run(*args, namespace=None, check=True, timeout=20, **kwargs):
    argv = (['ip', 'netns', 'exec', namespace] if namespace else []) + list(map(str, args))
    return subprocess.run(argv, check=check, timeout=timeout, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def ip(namespace, *args, **kwargs):
    return run('ip', '-n', namespace, *args, **kwargs)


def json_ip(namespace, *args):
    return json.loads(ip(namespace, '-j', *args).stdout)


def child(owner, namespace, *args, **kwargs):
    return owner.track(subprocess.Popen(
        ['ip', 'netns', 'exec', namespace, sys.executable, SCRIPT, *map(str, args)],
        text=True, **kwargs))


def eventually(predicate, description, seconds=10):
    deadline = time.monotonic() + seconds
    while True:
        result = predicate()
        if result:
            return result
        assert time.monotonic() < deadline, description
        time.sleep(0.02)


def stop(process):
    try:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    except BaseException as error:
        raise CleanupIncomplete(f'child {process.pid} did not join: {error!r}') from error
    errors = []
    if process is not None:
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe is not None:
                try:
                    pipe.close()
                except Exception as error:
                    errors.append(repr(error))
    if errors:
        raise CleanupIncomplete(f'child {process.pid} pipe cleanup: {errors}')


def line(process):
    assert select.select([process.stdout], [], [], 15)[0], 'child readiness deadline'
    text = process.stdout.readline()
    assert text, ('child exited before reply', process.poll())
    return json.loads(text)


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        data = sock.recv(count - len(result))
        if not data:
            if not result:
                raise EOFError()
            raise AssertionError(('short stream record', len(result), count))
        result.extend(data)
    return bytes(result)


def family(number):
    return socket.AF_INET if int(number) == 4 else socket.AF_INET6


def endpoint(value):
    return [str(ipaddress.ip_address(value[0])), value[1]]


def packed_address(address, port):
    address = ipaddress.ip_address(address)
    return bytes([1 if address.version == 4 else 4]) + address.packed + struct.pack('!H', port)


def unpack_address(data, offset=0):
    kind = data[offset]
    offset += 1
    if kind == 1:
        size, af = 4, socket.AF_INET
    elif kind == 4:
        size, af = 16, socket.AF_INET6
    else:
        raise AssertionError(('expected literal SOCKS5 address', kind))
    assert len(data) >= offset + size + 2
    return socket.inet_ntop(af, data[offset:offset + size]), struct.unpack_from('!H', data, offset + size)[0], offset + size + 2


def stream_address(sock, kind):
    size = {1: 4, 4: 16}.get(kind)
    assert size is not None, ('expected numeric SOCKS5 target', kind)
    data = bytes([kind]) + exact(sock, size + 2)
    address, port, _ = unpack_address(data)
    return address, port


def dns_question(name, qtype, identifier):
    labels = b''.join(bytes([len(part)]) + part.encode() for part in name.split('.')) + b'\0'
    question = labels + struct.pack('!HH', qtype, 1)
    # Real clients advertise EDNS; the fixture answer deliberately omits OPT.
    return struct.pack('!6H', identifier, 0x100, 1, 0, 0, 1) + question + b'\0' + struct.pack('!HHIH', 41, 1232, 0, 0)


def dns_name_end(data, offset):
    while True:
        size = data[offset]
        offset += 1
        if size == 0:
            return offset
        if size & 0xc0 == 0xc0:
            assert offset < len(data)
            return offset + 1
        assert size < 64 and offset + size <= len(data)
        offset += size


def dns_parse(data):
    assert len(data) >= 12
    end = dns_name_end(data, 12)
    labels, offset = [], 12
    while data[offset]:
        size = data[offset]
        labels.append(data[offset + 1:offset + 1 + size].decode('ascii'))
        offset += size + 1
    return '.'.join(labels).lower(), struct.unpack_from('!HH', data, end), end + 4


def dns_answer(query):
    name, (qtype, qclass), end = dns_parse(query)
    assert qclass == 1 and qtype in (1, 28), (name, qtype, qclass)
    number = 4 if qtype == 1 else 6
    address = TARGETS[number][DOMAINS.get(name, 0)]
    packed = ipaddress.ip_address(address).packed
    return (query[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + query[12:end]
            + b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 60, len(packed)) + packed)


def verify_dns(response, query, expected=None, empty=False):
    ident, flags, questions, answers, _, _ = struct.unpack_from('!6H', response)
    assert ident == struct.unpack_from('!H', query)[0] and flags & 0x8000 and flags & 15 == 0
    assert questions == 1 and answers == (0 if empty else 1), (ident, flags, questions, answers)
    if not empty:
        offset = dns_name_end(response, dns_name_end(response, 12) + 4)
        qtype, qclass, _, length = struct.unpack_from('!HHIH', response, offset)
        assert qclass == 1 and qtype in (1, 28)
        answer = str(ipaddress.ip_address(response[offset + 10:offset + 10 + length]))
        assert answer == str(ipaddress.ip_address(expected)), (answer, expected)


class Peer:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.lock = threading.Lock()
        self.events = (self.directory / 'peer-events.jsonl').open('a', buffering=1)
        self.serial = 0
        self.sockets = []

    def event(self, kind, **values):
        with self.lock:
            self.serial += 1
            self.events.write(json.dumps(dict(serial=self.serial, kind=kind, **values), sort_keys=True) + '\n')

    def socket(self, af, kind, address, port):
        sock = socket.socket(af, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if af == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, port))
        self.sockets.append(sock)
        return sock

    def serve(self):
        roles = {}
        for number, addresses in TARGETS.items():
            for address in addresses:
                for port in (*PORTS, 53):
                    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                        sock = self.socket(family(number), kind, address, port)
                        role = 'dns' if port == 53 else 'echo'
                        if kind == socket.SOCK_STREAM:
                            sock.listen(32)
                        roles[sock] = (role, kind)
        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            sock = self.socket(socket.AF_INET, kind, '10.77.0.2', 15353)
            if kind == socket.SOCK_STREAM:
                sock.listen(32)
            roles[sock] = ('upstream', kind)
        for port in (1080, 1081, 1082, 18090):
            sock = self.socket(socket.AF_INET, socket.SOCK_STREAM, '10.77.0.2', port)
            sock.listen(64)
            roles[sock] = ('http' if port == 18090 else 'socks', socket.SOCK_STREAM)
        (self.directory / 'peer-ready').touch()
        while True:
            for sock in select.select(list(roles), [], [], 1)[0]:
                role, kind = roles[sock]
                if kind == socket.SOCK_STREAM:
                    conn, remote = sock.accept()
                    threading.Thread(target=self.connection, args=(conn, remote, role), daemon=True).start()
                else:
                    payload, remote = sock.recvfrom(65535)
                    local = endpoint(sock.getsockname())
                    values = dict(remote=endpoint(remote), target=local, payload=payload.hex())
                    if role in ('dns', 'upstream'):
                        name, (qtype, _), _ = dns_parse(payload)
                        self.event(role, transport='udp', name=name, qtype=qtype, **values)
                        sock.sendto(dns_answer(payload), remote)
                    else:
                        self.event('echo', transport='udp', **values)
                        sent = sock.sendto(payload, remote)
                        assert sent == len(payload)
                        self.event('echo-sent', transport='udp', length=sent, **values)

    def connection(self, conn, remote, role):
        with conn:
            conn.settimeout(20)
            try:
                if role == 'socks':
                    self.socks(conn)
                elif role == 'http':
                    request = bytearray()
                    while b'\r\n\r\n' not in request:
                        request.extend(exact(conn, 1))
                        assert len(request) < 16384
                    target = request.split(b' ')[1].decode()
                    control = json.loads((self.directory / 'peer-control.json').read_text())
                    version = control['subscription']
                    body = f'socks5://10.77.0.2:{1080 + version}#downloaded-v{version}\n'.encode() if target == '/sub' else b''
                    self.event('http', target=target, version=version, remote=endpoint(remote))
                    conn.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
                elif role in ('dns', 'upstream'):
                    while True:
                        count = struct.unpack('!H', exact(conn, 2))[0]
                        query = exact(conn, count)
                        name, (qtype, _), _ = dns_parse(query)
                        self.event(role, transport='tcp', name=name, qtype=qtype,
                                   remote=endpoint(remote), target=endpoint(conn.getsockname()))
                        response = dns_answer(query)
                        conn.sendall(struct.pack('!H', len(response)) + response)
                else:
                    conn.sendall(BANNER)
                    while True:
                        try:
                            count = struct.unpack('!I', exact(conn, 4))[0]
                        except EOFError:
                            break
                        assert count <= 1 << 20
                        payload = exact(conn, count)
                        self.event('echo', transport='tcp', remote=endpoint(remote),
                                   target=endpoint(conn.getsockname()), payload=payload.hex())
                        conn.sendall(struct.pack('!I', count) + payload)
                    time.sleep(0.05)
                    try:
                        conn.sendall(TAIL)
                        conn.shutdown(socket.SHUT_WR)
                    except OSError as error:
                        if error.errno != errno.ENOTCONN:
                            raise
                    else:
                        self.event('close-tail', remote=endpoint(remote), target=endpoint(conn.getsockname()), length=len(TAIL))
            except (EOFError, ConnectionResetError, BrokenPipeError):
                pass  # Selector warm sockets can close before any SOCKS request.
            except Exception as error:
                self.event('peer-error', role=role, error=repr(error))
            finally:
                if role == 'echo':
                    self.event('echo-closed', remote=endpoint(remote), target=endpoint(conn.getsockname()))

    def socks(self, conn):
        version, count = exact(conn, 2)
        assert version == 5 and 0 in exact(conn, count)
        conn.sendall(b'\x05\x00')
        version, command, reserved, kind = exact(conn, 4)
        assert version == 5 and reserved == 0
        address, port = stream_address(conn, kind)
        if command == 1:
            with socket.socket(family(ipaddress.ip_address(address).version), socket.SOCK_STREAM) as outbound:
                outbound.settimeout(20)
                outbound.bind(('198.51.100.250' if outbound.family == socket.AF_INET else 'fd00:2::250', 0))
                outbound.connect((address, port))
                self.event('socks-connect', target=[address, port], remote=endpoint(conn.getpeername()),
                           source=endpoint(outbound.getsockname()), listener=conn.getsockname()[1])
                conn.sendall(b'\x05\x00\x00' + packed_address(*endpoint(outbound.getsockname())))
                def copy(source, destination):
                    try:
                        while True:
                            data = source.recv(65536)
                            if not data:
                                destination.shutdown(socket.SHUT_WR)
                                return
                            destination.sendall(data)
                    except (OSError, TimeoutError):
                        return
                upload = threading.Thread(target=copy, args=(conn, outbound))
                upload.start()
                copy(outbound, conn)
                upload.join(timeout=20)
                assert not upload.is_alive(), 'SOCKS upload did not join'
        else:
            assert command == 3, command
            with contextlib.ExitStack() as owned:
                relay = owned.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                relay.bind(('10.77.0.2', 0))
                outbound = {}
                for number, source in ((4, '198.51.100.250'), (6, 'fd00:2::250')):
                    sock = owned.enter_context(socket.socket(family(number), socket.SOCK_DGRAM))
                    sock.bind((source, 0))
                    outbound[sock] = number
                association = relay.getsockname()[1]
                conn.sendall(b'\x05\x00\x00' + packed_address(*relay.getsockname()))
                client = None
                while True:
                    for sock in select.select([conn, relay, *outbound], [], [], 10)[0]:
                        if sock is conn:
                            assert not conn.recv(1), 'unexpected UDP association control data'
                            return
                        payload, remote = sock.recvfrom(65535)
                        if sock is relay:
                            assert payload[:3] == b'\0\0\0', 'fragmented SOCKS5 UDP record'
                            address, port, offset = unpack_address(payload, 3)
                            client = remote
                            number = ipaddress.ip_address(address).version
                            target_socket = next(s for s, n in outbound.items() if n == number)
                            self.event('socks-udp', association=association, target=[address, port],
                                       source=endpoint(target_socket.getsockname()), payload=payload[offset:].hex(),
                                       listener=conn.getsockname()[1])
                            assert target_socket.sendto(payload[offset:], (address, port)) == len(payload) - offset
                        else:
                            assert client is not None
                            record = b'\0\0\0' + packed_address(*endpoint(remote)) + payload
                            assert relay.sendto(record, client) == len(record)


def tcp_open(number, source, target, port):
    sock = socket.socket(family(number), socket.SOCK_STREAM)
    sock.settimeout(12)
    sock.bind((source, 0))
    sock.connect((target, port))
    assert endpoint(sock.getpeername()) == [target, port]
    assert exact(sock, len(BANNER)) == BANNER
    return sock


def tcp_exchange(sock, payload):
    sock.sendall(struct.pack('!I', len(payload)) + payload)
    assert struct.unpack('!I', exact(sock, 4))[0] == len(payload)
    assert exact(sock, len(payload)) == payload


def tcp_close(sock):
    sock.shutdown(socket.SHUT_WR)
    time.sleep(0.1)
    assert exact(sock, len(TAIL)) == TAIL, 'lost peer payload after request half-close'
    assert sock.recv(1) == b'', 'unexpected bytes after retained close tail'


def tcp_policy(number, source, target, port, label, blocked):
    with socket.socket(family(number), socket.SOCK_STREAM) as sock:
        sock.settimeout(1 if blocked == 'true' else 8)
        sock.bind((source, 0))
        try:
            sock.connect((target, int(port)))
            banner = exact(sock, len(BANNER))
        except (EOFError, OSError) as error:
            assert blocked == 'true', error
        else:
            assert blocked == 'false' and banner == BANNER, 'blocked TCP reached the real listener'
            tcp_exchange(sock, label.encode())
            tcp_close(sock)
    print(json.dumps(dict(blocked=blocked == 'true')), flush=True)


def traffic(number, source, transport, port, label):
    number, port = int(number), int(port)
    replies = []
    if transport == 'T':
        for target in TARGETS[number][:2]:
            with tcp_open(number, source, target, port) as sock:
                local = endpoint(sock.getsockname())
                for index, size in enumerate((8192, 131072)):
                    payload = f'{label}/{target}/{index}/'.encode() + bytes(range(256)) * (size // 256)
                    tcp_exchange(sock, payload)
                    replies.append(dict(payload=payload.hex(), local=local, target=[target, port]))
                tcp_close(sock)
                listing = run('ss', '-Htn', 'state', 'time-wait', f'( sport = :{local[1]} and dport = :{port} )').stdout
                assert local[0] in listing and target in listing, ('no original close tail/TIME_WAIT witness', local, listing)
    else:
        connected = transport == 'Uc'
        assert connected or transport == 'Uu'
        with socket.socket(family(number), socket.SOCK_DGRAM) as sock:
            sock.settimeout(8)
            sock.bind((source, 22000))
            local = endpoint(sock.getsockname())
            for target in TARGETS[number][:2]:
                if connected:
                    sock.connect((target, port))
                for payload in (f'{label}/{target}/datagram'.encode(), b''):
                    if connected:
                        assert sock.send(payload) == len(payload)
                    else:
                        assert sock.sendto(payload, (target, port)) == len(payload)
                    data, remote = sock.recvfrom(65535)
                    assert data == payload and endpoint(remote) == [target, port], (data, remote, target)
                    assert endpoint(sock.getsockname()) == local, 'source changed while reusing one socket'
                    replies.append(dict(payload=payload.hex(), local=local, target=[target, port]))
        with contextlib.ExitStack() as owned:
            sources = []
            for index, target in enumerate(TARGETS[number][:2]):
                sock = owned.enter_context(socket.socket(family(number), socket.SOCK_DGRAM))
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                sock.bind((source, 22001))
                if connected:
                    sock.connect((target, port))
                sources.append(sock)
                assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT) == 1
            offered = {}
            for index, (sock, target) in enumerate(zip(sources, TARGETS[number][:2])):
                payload = f'{label}/live-reuseport-{index}'.encode()
                offered[payload] = [target, port]
                if connected:
                    sock.send(payload)
                else:
                    sock.sendto(payload, (target, port))
            while offered:
                ready = select.select(sources, [], [], 8)[0]
                assert ready, ('two live SO_REUSEPORT sources lost a reply', offered)
                for sock in ready:
                    data, remote = sock.recvfrom(65535)
                    assert data in offered and endpoint(remote) == offered.pop(data)
                    replies.append(dict(payload=data.hex(), local=endpoint(sock.getsockname()),
                                        target=endpoint(remote), reuseport_receiver=sources.index(sock)))
    print(json.dumps(dict(replies=replies, same_tuple_reuseport=(transport != 'T'))), flush=True)


def api_hold(number, source, address, method, path, body):
    connection = http.client.HTTPConnection(address, 19090, timeout=10,
                                             source_address=(source, 0))
    connection.connect()
    print(json.dumps(dict(connected=True, local=endpoint(connection.sock.getsockname()))), flush=True)
    assert sys.stdin.readline().strip() == 'request'
    connection.request(method, path, body=body or None,
                       headers={'Authorization': 'Bearer ' + SECRET, 'Connection': 'close',
                                'Content-Type': 'application/json'})
    response = connection.getresponse()
    data = response.read()
    print(json.dumps(dict(status=response.status, body=data.decode())), flush=True)
    connection.close()


def dns_client(number, source, target, port, transport, name, empty='false', persistent='false'):
    number, port = int(number), int(port)
    query = dns_question(name, 1 if number == 4 else 28, 0xa000 + DOMAINS[name])
    kind = socket.SOCK_STREAM if transport == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(family(number), kind) as sock:
        sock.settimeout(8)
        sock.bind((source, 0))
        sock.connect((target, port))
        def exchange(question, expected_empty):
            if transport == 'tcp':
                sock.sendall(struct.pack('!H', len(question)) + question)
                response = exact(sock, struct.unpack('!H', exact(sock, 2))[0])
            else:
                sock.send(question)
                response, remote = sock.recvfrom(65535)
                assert endpoint(remote) == [target, port]
            expected = TARGETS[number][DOMAINS[dns_parse(question)[0]]]
            verify_dns(response, question, expected, expected_empty)
        exchange(query, empty == 'true')
        print(json.dumps(dict(answer=True, local=endpoint(sock.getsockname()), target=[target, port])), flush=True)
        if persistent == 'true':
            assert transport == 'tcp'
            assert sys.stdin.readline().strip() == 'after-reload'
            later = dns_question('after-reload.test', 1 if number == 4 else 28, 0xb001)
            exchange(later, True)
            print(json.dumps(dict(persistent=True, per_frame_reload=True)), flush=True)


def one_exchange(number, source, target, port, payload, blocked='false', source_port='0'):
    number, port = int(number), int(port)
    with socket.socket(family(number), socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.6 if blocked == 'true' else 8)
        sock.bind((source, int(source_port)))
        try:
            sock.sendto(payload.encode(), (target, port))
            data, remote = sock.recvfrom(65535)
        except (socket.timeout, ConnectionRefusedError, OSError) as error:
            if isinstance(error, OSError) and not isinstance(error, socket.timeout):
                assert error.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES, errno.EINVAL), error
            assert blocked == 'true', error
        else:
            assert blocked == 'false' and data == payload.encode() and endpoint(remote) == [target, port]
    print(json.dumps(dict(blocked=blocked == 'true', payload=payload)), flush=True)


def live_client(number, source):
    number = int(number)
    target = TARGETS[number][0]
    with tcp_open(number, source, target, 18081) as tcp, socket.socket(family(number), socket.SOCK_DGRAM) as udp:
        udp.settimeout(8)
        udp.bind((source, 22002))
        udp.connect((target, 18081))
        for phase in ('before', 'after'):
            payload = ('live-' + phase).encode()
            tcp_exchange(tcp, payload)
            udp.send(payload)
            assert udp.recv(4096) == payload
            print(json.dumps(dict(phase=phase, tcp=endpoint(tcp.getsockname()), udp=endpoint(udp.getsockname()))), flush=True)
            if phase == 'before':
                assert sys.stdin.readline().strip() == 'after-reload'
        tcp_close(tcp)


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def inject(number, source, target, device, case):
    number = int(number)
    af = family(number)
    packed_source, packed_target = socket.inet_pton(af, source), socket.inet_pton(af, target)
    payload = ('malformed-' + case).encode() + b'x' * 32
    udp = struct.pack('!4H', 23000, 18081, len(payload) + 8, 0) + payload
    pseudo = packed_source + packed_target + (struct.pack('!BBH', 0, 17, len(udp)) if number == 4 else struct.pack('!I3xB', len(udp), 17))
    value = checksum(pseudo + udp) or 65535
    udp = udp[:6] + struct.pack('!H', value ^ 1 or 2) + udp[8:]
    fragmented = case in ('incomplete-fragment', 'bad-fragment-checksum')
    pieces = [(udp, 0, False)]
    if fragmented:
        pieces = [(udp[:16], 0, True)]
        if case == 'bad-fragment-checksum':
            pieces.append((udp[16:], 16, False))
    packets = []
    identifier = 0x1235 if case == 'incomplete-fragment' else 0x1236
    for piece, offset, more in pieces:
        if number == 4:
            flags = (0x2000 if more else 0) | (offset // 8)
            header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(piece), identifier,
                                 flags, 64, 17, 0, packed_source, packed_target)
            packet = header[:10] + struct.pack('!H', checksum(header)) + header[12:] + piece
        else:
            fragment = struct.pack('!BBHI', 17, 0, offset | int(more), identifier) if fragmented else b''
            packet = struct.pack('!IHBB16s16s', 6 << 28, len(fragment) + len(piece), 44 if fragment else 17,
                                 64, packed_source, packed_target) + fragment + piece
        packets.append(packet)
    with socket.socket(socket.AF_PACKET if device != 'host' else af, socket.SOCK_RAW,
                       0 if device != 'host' else socket.IPPROTO_RAW) as wire:
        if device != 'host':
            wire.bind((device, 0))
        elif number == 4:
            wire.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        else:
            wire.setsockopt(socket.IPPROTO_IPV6, 36, 1)  # IPV6_HDRINCL
        for packet in packets:
            if device != 'host':
                frame = bytes.fromhex('020000000010020000000020') + struct.pack('!H', 0x0800 if number == 4 else 0x86dd) + packet
                assert wire.send(frame) == len(frame)
            else:
                assert wire.sendto(packet, (target, 0)) == len(packet)
    print(json.dumps(dict(case=case, lengths=list(map(len, packets)), payload=payload.hex())), flush=True)


class Fixture:
    def __init__(self, daemon, root, label, number=4):
        self.daemon_path, self.root, self.label, self.number = daemon, Path(root), label, number
        self.directory = self.root / label
        self.directory.mkdir(mode=0o700)
        self.state = Path('/run/honk-tun-state') / label
        self.state.mkdir(mode=0o700)
        self.names = {role: 'ht-' + label.lower() + '-' + role for role in ('dut', 'source', 'server')}
        self.created, self.daemon, self.peer = [], None, None
        self.children = []
        self.handles = []
        self.notify = None
        self.config = self.directory / 'config.dae'
        self.log = self.directory / 'daemon.log'
        self.source = '192.0.2.2' if number == 4 else 'fd00:1::2'
        self.host_source = '192.0.2.1' if number == 4 else 'fd00:1::1'
        self.api_address = self.host_source
        self.bind_address = '198.18.0.1' if number == 4 else 'fd00:686f:6e6b:100::1'

    def __enter__(self):
        try:
            self.setup()
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def setup(self):
        for ns in self.names.values():
            run('ip', 'netns', 'add', ns)
            self.created.append(ns)
            run('sysctl', '-qw', 'net.ipv6.conf.default.addr_gen_mode=1', namespace=ns)
            ip(ns, 'link', 'set', 'lo', 'up')
        dut, source, server = (self.names[role] for role in ('dut', 'source', 'server'))
        ip(dut, 'link', 'add', 'dlan', 'type', 'veth', 'peer', 'name', 'src0', 'netns', source)
        ip(dut, 'link', 'add', 'dup', 'type', 'veth', 'peer', 'name', 'srv0', 'netns', server)
        for ns, dev, mac in ((dut, 'dlan', '02:00:00:00:00:10'), (source, 'src0', '02:00:00:00:00:20'),
                             (dut, 'dup', '02:00:00:00:00:11'), (server, 'srv0', '02:00:00:00:00:21')):
            ip(ns, 'link', 'set', dev, 'mtu', '1500', 'addrgenmode', 'none', 'address', mac, 'up')
            run('ethtool', '-K', dev, 'rx', 'off', 'tx', 'off', 'tso', 'off', 'gso', 'off', 'gro', 'off', namespace=ns)
        for ns, dev, address4, address6 in ((dut, 'dlan', '192.0.2.1/24', 'fd00:1::1/64'),
                                           (source, 'src0', '192.0.2.2/24', 'fd00:1::2/64'),
                                           (dut, 'dup', '10.77.0.1/24', 'fd00:77::1/64'),
                                           (server, 'srv0', '10.77.0.2/24', 'fd00:77::2/64')):
            ip(ns, '-4', 'addr', 'add', address4, 'dev', dev)
            ip(ns, '-6', 'addr', 'add', address6, 'dev', dev, 'nodad')
        for number, gateway, server_gateway, subnet in ((4, '192.0.2.1', '10.77.0.1', '192.0.2.0/24'),
                                                        (6, 'fd00:1::1', 'fd00:77::1', 'fd00:1::/64')):
            option = '-' + str(number)
            ip(source, option, 'route', 'add', 'default', 'via', gateway, 'dev', 'src0')
            ip(dut, option, 'route', 'add', 'default', 'via', '10.77.0.2' if number == 4 else 'fd00:77::2', 'dev', 'dup')
            ip(server, option, 'route', 'add', subnet, 'via', server_gateway, 'dev', 'srv0')
            for address in [*TARGETS[number], '198.51.100.250' if number == 4 else 'fd00:2::250']:
                ip(server, option, 'addr', 'add', address + ('/32' if number == 4 else '/128'), 'dev', 'lo', *([] if number == 4 else ['nodad']))
        # These are explicit operator prerequisites, never daemon-owned setup.
        run('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1',
            'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0', namespace=dut)
        assert run('sysctl', '-n', 'net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding', namespace=dut).stdout.splitlines() == ['1', '1']
        operator = '''table inet honk_tun_operator {
 chain forward { type filter hook forward priority 0; policy drop;
  iifname "dlan" oifname "honk0" counter accept
  iifname "honk0" oifname "dlan" counter accept
  counter drop comment "native-forward-refused"
 }
 chain output { type filter hook output priority 0; policy accept;
  oifname "dup" meta l4proto { tcp, udp } meta mark != 0x100 counter drop comment "unmarked-uplink-refused"
 }
 chain input { type filter hook input priority 0; policy accept; }
}'''
        run('nft', '-f', '-', namespace=dut, input=operator)
        self.snapshot('operator-prerequisites')
        self.before = self.resources()
        (self.directory / 'peer-control.json').write_text(json.dumps({'subscription': 1}))
        self.peer = child(self, server, 'serve', self.directory, stdout=self.open('peer.log'), stderr=subprocess.STDOUT)
        eventually(lambda: (self.directory / 'peer-ready').exists() or self.peer.poll() is not None, 'real peer did not bind both transports')
        assert self.peer.poll() is None, 'real peer exited before readiness'
        self.text = self.config_text()
        self.config.write_text(self.text)

    def open(self, name):
        handle = (self.directory / name).open('a')
        self.handles.append(handle)
        return handle

    def config_text(self):
        api = self.api_address if self.number == 4 else '[' + self.api_address + ']'
        bind = self.bind_address if self.number == 4 else '[' + self.bind_address + ']'
        return f'''global {{
 nfqueue_enable: false
 so_mark_from_dae: 0x100
 dial_mode: ip
 data_dir: '{self.state}'
 log_level: debug
 tcp_check_url: 'http://10.77.0.2:18090/health'
 udp_check_dns: '10.77.0.2:15353'
 udp_warm_node_count: 0
 check_interval: 3600s
}}
datapath {{
 backend: tun
 direct: endpoint
 tun {{
  name: honk0
  mtu: 1500
  address4: 198.18.0.1/32
  address6: fd00:686f:6e6b:100::1/128
  table: 202
  rule_priority: 10000
  capture {{
   0.0.0.0/0
   ::/0
  }}
 }}
}}
node {{
 fixture: 'socks5://10.77.0.2:1080'
}}
subscription {{
 supplier: 'http://10.77.0.2:18090/sub' {{
  interval: 0
  cache: false
  route: direct
 }}
}}
group {{
 proxy {{
  filter: name(fixture)
  policy: select
 }}
 downloaded {{
  filter: subtag(supplier)
  policy: select
 }}
}}
dns {{
 bind: 'tcp+udp://{bind}:1053'
 optimistic_cache: false
 optimistic_cache_ttl: 0
 upstream {{
  default: 'udp://10.77.0.2:15353'
  tcpup: 'tcp://10.77.0.2:15353'
 }}
 routing {{
  request {{
   qname(full: asis.test) -> asis
   qname(full: bound-tcp.test, full: transparent-tcp.test) -> tcpup
   fallback: default
  }}
 }}
}}
routing {{
 dport(18082) -> direct(must)
 dport(18085) -> block(must)
 sport(26000) && dport(53) -> proxy(must)
 sport(26001) && dport(53) -> direct(must)
 domain(bound-udp.test, bound-tcp.test, transparent-udp.test, transparent-tcp.test, asis.test, must.test, after-reload.test, cross-scope.test) && dport(18083) -> block
 dport(18080) -> proxy
 dport(18084) -> downloaded
 dport(18086) -> direct
 fallback: direct
}}
experimental {{
 clash_api {{
  external_controller: '{api}:19090'
  secret: '{SECRET}'
 }}
 cache_file {{ enabled: false }}
}}
'''

    def track(self, process):
        try:
            self.children.append(process)
        except BaseException:
            stop(process)
            raise
        return process

    def launch(self, special=None, log=None):
        namespace = self.names['dut']
        environment = dict(os.environ, NOTIFY_SOCKET=str(self.state / 'notify.sock'), NO_COLOR='1')
        argv = ['ip', 'netns', 'exec', namespace]
        if special:
            argv += [sys.executable, SCRIPT, special]
        argv += [self.daemon_path, '-c', str(self.config)]
        return self.track(subprocess.Popen(
            argv, env=environment, stdout=self.open(log or 'daemon.log'), stderr=subprocess.STDOUT))

    def start(self):
        self.notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.notify.bind(str(self.state / 'notify.sock'))
        self.notify.settimeout(10)
        self.daemon = self.launch()
        self.starttime = int(Path(f'/proc/{self.daemon.pid}/stat').read_text().rsplit(')', 1)[1].split()[19])
        def ready():
            assert self.daemon.poll() is None, ('daemon exited before capture readiness', self.log.read_text())
            return 'TUN datapath ready' in self.log.read_text()
        eventually(ready, 'missing actual TUN capture-ready log', seconds=20)
        states = []
        while not any('READY=1' in state.splitlines() for state in states):
            states.append(self.notify.recv(4096).decode())
        (self.directory / 'sd-notify.json').write_text(json.dumps(states))
        self.check_active()
        self.identity = self.device_identity()
        self.snapshot('ready')

    def resources(self):
        dut = self.names['dut']
        return {option: dict(rules=json_ip(dut, option, 'rule', 'show'),
                             routes=json_ip(dut, option, 'route', 'show', 'table', 'all'))
                for option in ('-4', '-6')}

    def counters(self):
        link = json_ip(self.names['dut'], '-s', 'link', 'show', 'dev', 'honk0')[0]
        stats = link.get('stats64', link.get('stats'))
        assert stats is not None, 'missing real TUN interface counters'
        return {direction: stats[direction]['packets'] for direction in ('tx', 'rx')}

    def device_identity(self):
        dut = self.names['dut']
        link = json_ip(dut, '-d', 'link', 'show', 'dev', 'honk0')[0]
        info = []
        for path in Path(f'/proc/{self.daemon.pid}/fdinfo').iterdir():
            text = path.read_text()
            if re.search(r'^iff:\s+honk0$', text, re.M):
                flags = int(re.search(r'^flags:\s+(\d+)', text, re.M)[1], 8)
                required = os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC
                assert flags & (os.O_ACCMODE | os.O_NONBLOCK | os.O_CLOEXEC) == required
                info.append([path.name, text])
        assert len(info) == 1, ('expected one actual daemon TUN FD', info)
        return dict(ifindex=link['ifindex'], fd=info[0][0], namespace=os.stat('/run/netns/' + dut).st_ino)

    def check_active(self):
        dut = self.names['dut']
        link = json_ip(dut, '-d', 'link', 'show', 'dev', 'honk0')[0]
        assert link['mtu'] == 1500 and 'UP' in link['flags'] and link['linkinfo']['info_kind'] == 'tun'
        tun_flags = int(run('cat', '/sys/class/net/honk0/tun_flags', namespace=dut).stdout.strip(), 16)
        assert tun_flags & 0x1003 == 0x1001 and tun_flags & (0x100 | 0x30 | 0x4000) == 0, hex(tun_flags)
        addresses = json_ip(dut, 'address', 'show', 'dev', 'honk0')[0]['addr_info']
        assert {(item['local'], item['prefixlen']) for item in addresses} == {('198.18.0.1', 32), ('fd00:686f:6e6b:100::1', 128)}, addresses
        assert run('cat', '/proc/sys/net/ipv4/conf/honk0/rp_filter', namespace=dut).stdout.strip() == '0'
        for number in (4, 6):
            rules = json_ip(dut, '-' + str(number), 'rule', 'show')
            own = [rule for rule in rules if 10000 <= rule.get('priority', -1) <= 10004]
            assert [rule['priority'] for rule in own] == list(range(10000, 10005)), own
            assert len([rule for rule in rules if rule.get('priority') == 0 and rule.get('table') == 'local']) == 1
            for index, rule in enumerate(own):
                if index < 2:
                    assert int(str(rule['fwmark']), 0) == 0x100 and int(str(rule.get('fwmask', '0xffffffff')), 0) == 0xffffffff, rule
                if index in (2, 3):
                    assert rule['iif'] == 'honk0', rule
                if index in (1, 3):
                    assert rule.get('action') == 'prohibit' or rule.get('type') == 'prohibit', rule
                else:
                    assert str(rule['table']) == ('main' if index in (0, 2) else '202'), rule
            routes = json_ip(dut, '-' + str(number), 'route', 'show', 'table', '202')
            assert len(routes) == 2, routes
            active = [route for route in routes if route.get('type', 'unicast') == 'unicast']
            guards = [route for route in routes if route.get('type') == 'blackhole']
            assert len(active) == len(guards) == 1
            assert active[0]['dev'] == 'honk0' and active[0].get('metric') == 1024 and active[0].get('protocol') == 'static', active
            assert guards[0].get('metric') == 32760 and guards[0].get('protocol') == 'static', guards
            for route in routes:
                assert route.get('dst', 'default') in ('default', '0.0.0.0/0', '::/0'), route
            for mark, device in ((None, 'honk0'), ('0x100', 'dup')):
                args = ['-' + str(number), 'route', 'get', TARGETS[number][0]]
                if mark:
                    args += ['mark', mark]
                found = json_ip(dut, *args)[0]
                assert found['dev'] == device, found
        self.check_receipt()
        assert not any(item['ifname'] == 'dae0' or item.get('xdp', {}).get('prog_id') or item.get('xdp', {}).get('prog', {}).get('id') for item in json_ip(dut, '-d', 'link', 'show'))
        assert not Path('/run/netns/daens').exists()
        assert 'queue' not in run('nft', 'list', 'ruleset', namespace=dut).stdout
        for item in json_ip(dut, 'link', 'show'):
            assert not any(qdisc['kind'] in ('clsact', 'ingress') for qdisc in json.loads(run('tc', '-j', 'qdisc', 'show', 'dev', item['ifname'], namespace=dut).stdout))
            for direction in ('ingress', 'egress'):
                assert not json.loads(run('tc', '-j', 'filter', 'show', 'dev', item['ifname'], direction, namespace=dut).stdout)

    def check_receipt(self):
        receipts = list((self.state / 'state').glob('tun-*.json'))
        assert len(receipts) == 1, ('missing exclusive setup receipt', receipts)
        path = receipts[0]
        assert not path.is_symlink() and path.stat().st_mode & 0o777 == 0o600
        data = json.loads(path.read_text())
        assert set(data) == {'format', 'source_sha', 'pid', 'starttime', 'netns_cookie', 'nonce',
                             'incarnation', 'name', 'ifindex', 'ambiguous', 'resources'}, data
        assert data['format'] == 1 and re.fullmatch('[0-9a-f]{40}', data['source_sha'])
        assert data['pid'] == self.daemon.pid and data['starttime'] > 0
        if hasattr(self, 'starttime'):
            assert data['starttime'] == self.starttime
        cookie = self.probe('netns-cookie', origin='H')['cookie']
        assert data['netns_cookie'] == cookie and data['name'] == 'honk0'
        assert re.fullmatch('[0-9a-f]{32}', data['nonce']) and data['incarnation'] >= 1
        assert path.name == f"tun-{cookie}-{data['nonce']}.json" and data['ambiguous'] is False
        assert isinstance(data['ifindex'], int) and data['ifindex'] > 0
        if hasattr(self, 'identity'):
            assert data['ifindex'] == self.identity['ifindex']
        resources = data['resources']
        assert resources and all(item['state'] in ('intent', 'acknowledged', 'refused', 'removing', 'removed') for item in resources)
        active = self.daemon.poll() is None
        if active:
            assert all(item['state'] == 'acknowledged' for item in resources), resources
        index = data['ifindex']
        link = [item for item in resources if item['kind'] == 'link']
        assert len(link) == 1 and link[0]['name'] == 'honk0' and link[0]['ifindex'] == index
        assert {item['address'] for item in resources if item['kind'] == 'address'} == {'198.18.0.1/32', 'fd00:686f:6e6b:100::1/128'}
        assert [item['mtu'] for item in resources if item['kind'] == 'mtu'] == [1500]
        assert len([item for item in resources if item['kind'] == 'link_up']) == 1
        assert {(item['key'], item['value']) for item in resources if item['kind'] == 'sysctl'} == {
            ('net/ipv6/conf/honk0/addr_gen_mode', '1'), ('net/ipv6/conf/honk0/accept_ra', '0'),
            ('net/ipv6/conf/honk0/autoconf', '0'), ('net/ipv4/conf/honk0/rp_filter', '0')}
        for number, wire_family, destination in ((4, 'inet', '0.0.0.0/0'), (6, 'inet6', '::/0')):
            rules = [item for item in resources if item['kind'] == 'rule' and item['family'] == wire_family]
            assert len(rules) == 5
            for offset in range(5):
                matches = [item for item in rules if item['priority'] == 10000 + offset]
                assert len(matches) == 1
                rule = matches[0]
                assert rule == dict(kind='rule', family=wire_family, priority=10000 + offset,
                                    fwmark=256 if offset < 2 else None,
                                    fwmask=0xffffffff if offset < 2 else None,
                                    iif='honk0' if offset in (2, 3) else None,
                                    action='prohibit' if offset in (1, 3) else 'lookup',
                                    table=None if offset in (1, 3) else (202 if offset == 4 else 254),
                                    state='acknowledged'), rule
            routes = [item for item in resources if item['kind'] == 'route' and item['family'] == wire_family]
            assert len(routes) in ((2,) if active or hasattr(self, 'identity') else (1, 2))
            for route in routes:
                unicast = route['type'] == 'unicast'
                assert route['type'] in ('unicast', 'blackhole') and route['table'] == 202
                assert route['destination'] == destination and route['protocol'] == 'static'
                assert route['oif'] == (index if unicast else None) and route['metric'] == (1024 if unicast else 32760)
                assert route['state'] in (('acknowledged',) if not unicast or active else ('acknowledged', 'removed'))
        shutil.copy2(path, self.directory / 'active-receipt.json')
        return data

    def snapshot(self, label):
        dut = self.names['dut']
        values = self.resources()
        values['links'] = json_ip(dut, '-s', '-d', 'link', 'show')
        values['addresses'] = json_ip(dut, 'address', 'show')
        values['firewall'] = json.loads(run('nft', '-j', 'list', 'ruleset', namespace=dut).stdout)
        values['forwarding'] = run('sysctl', 'net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding', namespace=dut).stdout
        (self.directory / (label + '.json')).write_text(json.dumps(values, indent=2) + '\n')
        return values

    def peer_events(self):
        events = [json.loads(text) for text in (self.directory / 'peer-events.jsonl').read_text().split('\n')[:-1]]
        assert not [event for event in events if event['kind'] == 'peer-error'], events[-5:]
        return events

    def probe(self, *args, origin='T', timeout=40):
        ns = self.names['dut' if origin == 'H' else 'source']
        return json.loads(run(sys.executable, SCRIPT, *args, namespace=ns, timeout=timeout).stdout)

    def exchange(self, marker, target=None, port=18081, blocked=False, origin='T', source_port=0):
        target = target or TARGETS[self.number][0]
        source = self.host_source if origin == 'H' else self.source
        before = len(self.peer_events())
        result = self.probe('one', self.number, source, target, port, marker, str(blocked).lower(), source_port, origin=origin)
        events = self.peer_events()[before:]
        matches = [event for event in events if event['kind'] == 'echo' and event.get('payload') == marker.encode().hex()]
        assert bool(matches) != blocked, ('remote delivery disagrees with policy', marker, blocked, events)
        if not blocked:
            assert len(matches) == 1
        return result, matches

    def api(self, path='/configs', method='GET', body=None, prove_marks=False):
        before = self.counters()
        process = child(self, self.names['source'], 'api', self.number, self.source, self.api_address,
                        method, path, json.dumps(body) if body is not None else '', stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=self.open('api.stderr'))
        try:
            assert line(process)['connected']
            if prove_marks:
                for args in (('-lntpe',), ('-ntpe', 'state', 'established')):
                    def marked():
                        listing = run('ss', *args, '( sport = :19090 )', namespace=self.names['dut']).stdout
                        return listing if re.search(r'fwmark:(?:0x100|256)\b', listing) else False
                    listing = eventually(marked, 'actual API listener/accepted socket lacks bypass mark')
                    self.open('api-socket-marks.log').write(listing)
            process.stdin.write('request\n')
            process.stdin.flush()
            result = line(process)
            process.wait(timeout=10)
            assert process.returncode == 0 and 200 <= result['status'] < 300, result
            assert self.counters() == before, ('remote API handshake/reply entered TUN', before, self.counters())
            return json.loads(result['body']) if result['body'] else None
        finally:
            stop(process)

    def reload(self, text, expected='applied'):
        offset = len(self.log.read_text())
        self.config.write_text(text)
        self.daemon.send_signal(signal.SIGHUP)
        def outcome():
            assert self.daemon.poll() is None, 'daemon exited during policy reload'
            match = re.search(r'SIGHUP reload request \d+ (applied|rejected)', self.log.read_text()[offset:])
            return match[1] if match else None
        assert eventually(outcome, 'missing actual reload publication acknowledgement', 20) == expected
        assert self.device_identity() == self.identity, 'policy reload replaced the live TUN attachment'

    def fence_counters(self):
        items = json.loads(run('nft', '-j', 'list', 'ruleset', namespace=self.names['dut']).stdout)['nftables']
        found = set()
        for item in items:
            rule = item.get('rule', {})
            if rule.get('comment') in ('native-forward-refused', 'unmarked-uplink-refused'):
                found.add(rule['comment'])
                counters = [expr['counter']['packets'] for expr in rule['expr'] if 'counter' in expr]
                assert counters == [0], ('native/unmarked path attempted', rule)
        assert found == {'native-forward-refused', 'unmarked-uplink-refused'}, 'operator containment rules disappeared'

    def normal_stop(self, expected_rp_filter=0):
        self.daemon.terminate()
        status = self.daemon.wait(timeout=20)
        assert status == 0 and 'TUN datapath stopped' in self.log.read_text(), ('unconfirmed joined normal stop', status)
        assert not [link for link in json_ip(self.names['dut'], 'link', 'show') if link['ifname'] == 'honk0']
        assert self.resources() == self.before, 'normal stop did not remove exactly the owned RPDB/routes'
        assert not list((self.state / 'state').glob('tun-*.json')), 'successful cleanup retained setup receipt'
        assert run('sysctl', '-n', 'net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding',
                   'net.ipv4.conf.all.rp_filter', namespace=self.names['dut']).stdout.splitlines() == ['1', '1', str(expected_rp_filter)]
        self.snapshot('normal-stopped')

    def __exit__(self, _kind, body_error, _traceback):
        errors = ['unconfirmed child before teardown'] if isinstance(body_error, CleanupIncomplete) else []
        if self.names['source'] in self.created:
            try:
                ip(self.names['source'], 'link', 'set', 'src0', 'down')
            except Exception as error:
                errors.append(f'quiesce: {error!r}')
        can_remove = not errors
        for process in reversed(self.children):
            try:
                stop(process)
            except Exception as error:
                errors.append(f'join: {error!r}')
                can_remove = False
        if self.names['dut'] in self.created:
            try:
                self.snapshot('final')
            except Exception as error:
                errors.append(f'snapshot: {error!r}')
        if self.state.exists():
            try:
                shutil.copytree(self.state, self.directory / 'state', dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns('notify.sock'))
            except Exception as error:
                errors.append(f'state retention: {error!r}')
        retained = list(self.created)
        if can_remove:
            for ns in reversed(self.created):
                try:
                    run('ip', 'netns', 'del', ns)
                    retained.remove(ns)
                except Exception as error:
                    errors.append(f'namespace {ns}: {error!r}')
        for handle in [self.notify, *self.handles]:
            if handle is not None:
                try:
                    handle.close()
                except Exception as error:
                    errors.append(f'handle close: {error!r}')
        try:
            (self.directory / 'cleanup.json').write_text(json.dumps({
                'complete': not errors, 'errors': errors, 'retained_namespaces': retained,
                'children': [{'pid': process.pid, 'returncode': process.returncode}
                             for process in self.children],
            }, indent=2) + '\n')
        except Exception as error:
            errors.append(f'cleanup receipt: {error!r}')
        if errors:
            raise CleanupIncomplete('; '.join(errors))


def assert_outbound(events, replies, action, number):
    expected_source = ('10.77.0.1' if number == 4 else 'fd00:77::1') if action == 'direct' else ('198.51.100.250' if number == 4 else 'fd00:2::250')
    primary = []
    for reply in replies:
        matches = [event for event in events if event['kind'] == 'echo' and event.get('payload') == reply['payload'] and event['target'] == reply['target']]
        assert len(matches) == 1, ('independent far socket did not receive exactly once', reply, matches)
        event = matches[0]
        assert event['remote'][0] == expected_source and event['remote'] != reply['local'], ('Endpoint must create a new socket', event, reply)
        if 'reuseport_receiver' not in reply:
            primary.append(event)
        socks = [event for event in events if event['kind'] in ('socks-connect', 'socks-udp') and event['target'] == reply['target']
                 and (event['kind'] == 'socks-connect' or event.get('payload') == reply['payload'])]
        assert bool(socks) == (action == 'proxy'), ('actual SOCKS5 action witness', action, reply, socks)
    if primary and primary[0]['transport'] == 'udp':
        if action == 'proxy':
            assert len({tuple(event['remote']) for event in primary}) == 1, ('one source socket to two destinations lost outbound source ownership', primary)
            actual = [event for event in events if event['kind'] == 'socks-udp' and event.get('payload') in {reply['payload'] for reply in replies if 'reuseport_receiver' not in reply}]
            assert len({event['association'] for event in actual}) == 1, 'two targets did not share the actual SOCKS5 UDP association'
        else:
            for target in {tuple(event['target']) for event in primary}:
                assert len({tuple(event['remote']) for event in primary if tuple(event['target']) == target}) == 1, ('one Direct destination changed outbound source tuple', target, primary)


def matrix_row(daemon, root, row):
    origin, number, transport = row[2], int(row[3]), row[5:]
    with Fixture(daemon, root, row, number) as fixture:
        fixture.start()
        if transport == 'T':
            namespace = fixture.names['dut' if origin == 'H' else 'source']
            if origin == 'T':
                run('nft', '-f', '-', namespace=namespace, input='table inet honk_tun_loss {\n chain input { type filter hook input priority -10; policy accept; }\n}\n')
            table = 'honk_tun_operator' if origin == 'H' else 'honk_tun_loss'
            for port in (18080, 18081):
                source_address = fixture.host_source if origin == 'H' else fixture.source
                address_match = ('ip' if number == 4 else 'ip6') + ' daddr ' + source_address
                run('nft', '-f', '-', namespace=namespace, input=f'add rule inet {table} input {address_match} tcp sport {port} tcp flags & (syn | ack) == (syn | ack) numgen inc mod 1024 == 0 counter drop comment "one-synack-loss-{port}"')
        for action, port in (('proxy', 18080), ('direct', 18081)):
            before = fixture.counters()
            start = len(fixture.peer_events())
            result = fixture.probe('traffic', number, fixture.host_source if origin == 'H' else fixture.source,
                                   transport, port, row + '/' + action, origin=origin, timeout=80)
            events = fixture.peer_events()[start:]
            assert_outbound(events, result['replies'], action, number)
            after = fixture.counters()
            assert after['tx'] > before['tx'] and after['rx'] > before['rx'], ('missing real TUN FD read/write witness', before, after)
            assert after['tx'] - before['tx'] < 20000 and after['rx'] - before['rx'] < 20000, 'possible capture loop'
            time.sleep(0.15)
            quiet = fixture.counters()
            assert quiet['tx'] - after['tx'] <= 8 and quiet['rx'] - after['rx'] <= 8, ('TUN continued importing after sources completed', after, quiet)
            (fixture.directory / (action + '-wire.json')).write_text(json.dumps(dict(client=result, peer=events, counters=[before, after, quiet]), indent=2))
        if transport == 'T':
            items = json.loads(run('nft', '-j', 'list', 'ruleset', namespace=namespace).stdout)['nftables']
            losses = [item['rule'] for item in items if item.get('rule', {}).get('comment', '').startswith('one-synack-loss-')]
            assert len(losses) == 2
            assert all(next(expr['counter']['packets'] for expr in rule['expr'] if 'counter' in expr) == 1 for rule in losses), 'missing real retransmission after one dropped SYN-ACK'
        fixture.fence_counters()
        fixture.snapshot('traffic')
        fixture.normal_stop()


def dns_extensions(fixture):
    number = fixture.number
    for transport, name in (('udp', 'bound-udp.test'), ('tcp', 'bound-tcp.test')):
        target = TARGETS[number][DOMAINS[name]]
        fixture.exchange('before-' + name, target=target, port=18083)
        before = fixture.counters()
        fixture.probe('dns', number, fixture.source, fixture.bind_address, 1053, transport, name)
        assert fixture.counters() == before, 'marked standalone DNS response entered TUN'
        fixture.exchange('blocked-' + name, target=target, port=18083, blocked=True)
    for origin in ('H', 'T'):
        for transport, name in (('udp', 'transparent-udp.test'), ('tcp', 'transparent-tcp.test')):
            before = fixture.counters()
            fixture.probe('dns', number, fixture.host_source if origin == 'H' else fixture.source,
                          TARGETS[number][0], 53, transport, name, origin=origin)
            after = fixture.counters()
            assert after['tx'] > before['tx'] and after['rx'] > before['rx'], 'transparent DNS lacked actual TUN import/reply'
            fixture.exchange('blocked-' + origin + '-' + name, target=TARGETS[number][DOMAINS[name]], port=18083, blocked=True, origin=origin)
    name = 'cross-scope.test'
    result = fixture.api('/dns/query?name=' + name + '&type=' + ('A' if number == 4 else 'AAAA'))
    expected = ipaddress.ip_address(TARGETS[number][DOMAINS[name]])
    qtype = 1 if number == 4 else 28
    assert result['Status'] == 0 and any(
        answer.get('type') == qtype and answer.get('name', '').rstrip('.').lower() == name
        and ipaddress.ip_address(answer['data']) == expected
        for answer in result.get('Answer', [])), ('API DNS did not resolve the expected address', result)
    fixture.exchange('api-dns-cache-does-not-contaminate-packet-scope', target=str(expected), port=18083)
    for transport in ('udp', 'tcp'):
        fixture.probe('dns', number, fixture.source, TARGETS[number][0], 53, transport, 'asis.test')
    for port, action in ((26000, 'proxy'), (26001, 'direct')):
        for transport in ('udp', 'tcp'):
            query = dns_question('must.test', 1 if number == 4 else 28, port)
            result = fixture.probe('raw-dns', number, fixture.source, TARGETS[number][0], port, query.hex(), transport)
            assert result['reply'] and result['transport'] == transport
            fixture.exchange('raw-must-did-not-learn-' + action + '-' + transport,
                             target=TARGETS[number][DOMAINS['must.test']], port=18083)
    events = fixture.peer_events()
    for name, transport in (('bound-udp.test', 'udp'), ('bound-tcp.test', 'tcp'),
                            ('transparent-udp.test', 'udp'), ('transparent-tcp.test', 'tcp')):
        assert any(event['kind'] == 'upstream' and event.get('name') == name and event['transport'] == transport for event in events), (name, transport)
    assert all(any(event['kind'] == 'dns' and event.get('name') == 'asis.test' and event['transport'] == transport for event in events) for transport in ('udp', 'tcp'))
    assert any(event['kind'] == 'socks-udp' and event.get('payload') == dns_question('must.test', 1 if number == 4 else 28, 26000).hex() for event in events), 'raw/must DNS did not use the real proxy'
    fixture.fence_counters()


def control_extensions(fixture):
    number = fixture.number
    config = fixture.api(prove_marks=True)
    assert config['tun'] == dict(enable=True, device='honk0', mtu=1500, stack='honk') and config['ipv6'] is True, config
    live = child(fixture, fixture.names['source'], 'live', number, fixture.source, stdin=subprocess.PIPE,
                 stdout=subprocess.PIPE, stderr=fixture.open('live.stderr'))
    dns = child(fixture, fixture.names['source'], 'dns', number, fixture.source, fixture.bind_address,
                1053, 'tcp', 'bound-tcp.test', 'false', 'true', stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=fixture.open('persistent-dns.stderr'))
    try:
        assert line(live)['phase'] == 'before'
        assert line(dns)['answer']
        candidate = fixture.text.replace('qname(full: asis.test) -> asis', 'qname(full: after-reload.test) -> reject\n   qname(full: asis.test) -> asis')
        fixture.reload(candidate)
        fixture.reload(candidate.replace('mtu: 1500', 'mtu: 1501'), 'rejected')
        fixture.reload(candidate.replace('dport(18086) -> direct', 'dport(18086) -> block'))
        fixture.exchange('reloaded-block', port=18086, blocked=True)
        live.stdin.write('after-reload\n')
        live.stdin.flush()
        assert line(live)['phase'] == 'after'
        dns.stdin.write('after-reload\n')
        dns.stdin.flush()
        assert line(dns)['per_frame_reload']
        for process in (live, dns):
            process.wait(timeout=15)
            assert process.returncode == 0
        fixture.probe('dns', number, fixture.source, fixture.bind_address, 1053, 'udp', 'after-reload.test', 'true')
        fixture.reload(fixture.text)
    finally:
        try:
            stop(live)
        finally:
            stop(dns)
    for origin in ('H', 'T'):
        fixture.exchange('block-must-' + origin, port=18085, blocked=True, origin=origin)
        fixture.exchange('direct-must-' + origin, port=18082, origin=origin)
        for port, blocked in ((18085, True), (18082, False)):
            marker = 'tcp-must-' + origin + '-' + str(port)
            before = len(fixture.peer_events())
            fixture.probe('tcp-policy', number, fixture.host_source if origin == 'H' else fixture.source,
                          TARGETS[number][0], port, marker, str(blocked).lower(), origin=origin)
            events = fixture.peer_events()[before:]
            assert bool([event for event in events if event['kind'] == 'echo' and event.get('payload') == marker.encode().hex()]) != blocked
    fixture.api('/configs', 'PATCH', {'mode': 'Direct'})
    _, matches = fixture.exchange('mode-direct', port=18080)
    assert matches[0]['remote'][0] == ('10.77.0.1' if number == 4 else 'fd00:77::1')
    fixture.exchange('mode-direct-block-must', port=18085, blocked=True)
    fixture.api('/proxies/GLOBAL', 'PUT', {'name': 'proxy'})
    fixture.api('/configs', 'PATCH', {'mode': 'Global'})
    _, matches = fixture.exchange('mode-global', port=18081)
    assert matches[0]['remote'][0] == ('198.51.100.250' if number == 4 else 'fd00:2::250')
    fixture.api('/configs', 'PATCH', {'mode': 'Rule'})
    assert fixture.api('/configs')['mode'].lower() == 'rule'
    assert 'downloaded-v1' in fixture.api('/proxies/downloaded')['all']
    fixture.exchange('subscription-v1', port=18084)
    (fixture.directory / 'peer-control.json').write_text(json.dumps({'subscription': 2}))
    fixture.reload(fixture.text + '\n# Refresh the same authorized subscription.\n')
    eventually(lambda: 'downloaded-v2' in fixture.api('/proxies/downloaded')['all'], 'configured TUN subscription refresh was not published', 20)
    fixture.exchange('subscription-v2', port=18084)
    events = fixture.peer_events()
    for marker, listener in (('subscription-v1', 1081), ('subscription-v2', 1082)):
        assert any(event['kind'] == 'socks-udp' and event.get('payload') == marker.encode().hex() and event['listener'] == listener for event in events), (marker, listener)
    assert fixture.device_identity() == fixture.identity
    fixture.fence_counters()


def packet_extensions(fixture):
    number = fixture.number
    for origin in ('H', 'T'):
        for case in ('bad-udp-checksum', 'incomplete-fragment', 'bad-fragment-checksum'):
            before = fixture.counters()
            first = len(fixture.peer_events())
            source = fixture.host_source if origin == 'H' else fixture.source
            result = fixture.probe('inject', number, source, TARGETS[number][0], 'host' if origin == 'H' else 'src0', case, origin=origin)
            eventually(lambda: fixture.counters()['tx'] - before['tx'] >= len(result['lengths']), 'malformed wire records did not reach the actual TUN')
            time.sleep(0.2)
            assert not [event for event in fixture.peer_events()[first:] if event['kind'] == 'echo'], ('malformed/partial fragment escaped rejection', result)
            fixture.exchange('after-reject-' + origin + '-' + case, origin=origin)
    for action, port in (('proxy', 18080), ('direct', 18081)):
        before = fixture.counters()
        result = fixture.probe('mtu', number, fixture.source, TARGETS[number][0], port)
        assert result['fragmented_roundtrip'] and result['oversize_refused'] and result['mtu_df_refused']
        after = fixture.counters()
        assert after['tx'] - before['tx'] >= 2 and after['rx'] - before['rx'] >= 2
        (fixture.directory / ('mtu-' + action + '-wire.json')).write_text(json.dumps(dict(client=result, counters=[before, after]), indent=2))
    fixture.fence_counters()


def crash_fault(daemon, root, number, topology=False):
    label = f'A-{number}-' + ('topology-fault' if topology else 'crash-guard')
    with Fixture(daemon, root, label, number) as fixture:
        fixture.start()
        fixture.exchange('before-fatal')
        if topology:
            ip(fixture.names['dut'], '-' + str(number), 'route', 'del', 'default')
            assert fixture.daemon.wait(timeout=20) != 0, 'topology failure returned success'
            assert 'TUN owner failed closed' in fixture.log.read_text(), 'missing fatal owner outcome'
        else:
            fixture.daemon.kill()
            fixture.daemon.wait(timeout=10)
        dut = fixture.names['dut']
        eventually(lambda: not any(item['ifname'] == 'honk0' for item in json_ip(dut, 'link', 'show')), 'unique nonpersistent TUN FD survived daemon death')
        fixture.check_receipt()
        for current in (4, 6):
            rules = json_ip(dut, '-' + str(current), 'rule', 'show')
            assert len([rule for rule in rules if 10000 <= rule.get('priority', -1) <= 10004]) == 5
            routes = json_ip(dut, '-' + str(current), 'route', 'show', 'table', '202')
            assert len(routes) == 1 and routes[0].get('type') == 'blackhole' and routes[0].get('metric') == 32760, routes
            assert ip(dut, '-' + str(current), 'route', 'get', TARGETS[current][0], check=False).returncode != 0, 'capture fell through to native main route'
        if topology:
            assert ip(dut, '-' + str(number), 'route', 'get', TARGETS[number][0], 'mark', '0x100', check=False).returncode != 0, 'missing main route bypassed the exact marked prohibit rule'
        for origin in ('H', 'T'):
            fixture.exchange('after-fatal-must-not-dial-' + origin, blocked=True, origin=origin)
        before = fixture.resources()
        receipts = {path.name: path.read_bytes() for path in (fixture.state / 'state').glob('tun-*.json')}
        second = fixture.launch(log='restart-rejected.log')
        assert second.wait(timeout=15) != 0, 'crash guards were silently adopted'
        assert fixture.resources() == before
        assert {path.name: path.read_bytes() for path in (fixture.state / 'state').glob('tun-*.json')} == receipts
        assert 'TUN datapath ready' not in (fixture.directory / 'restart-rejected.log').read_text()
        fixture.snapshot('retained-guards')
        fixture.fence_counters()


def setup_fault(daemon, root, number, fault):
    with Fixture(daemon, root, f'A-{number}-setup-{fault}', number) as fixture:
        dut, option = fixture.names['dut'], '-' + str(number)
        if fault == 'name':
            ip(dut, 'link', 'add', 'honk0', 'type', 'dummy')
        elif fault == 'table':
            ip(dut, option, 'route', 'add', 'blackhole', 'default', 'table', '202', 'metric', '111')
        elif fault == 'priority':
            ip(dut, option, 'rule', 'add', 'pref', '10002', 'prohibit')
        elif fault == 'address':
            ip(dut, option, 'addr', 'add', fixture.bind_address + ('/32' if number == 4 else '/128'), 'dev', 'lo', *([] if number == 4 else ['nodad']))
        elif fault == 'main-route':
            ip(dut, option, 'route', 'del', 'default')
        elif fault == 'rpdb':
            ip(dut, option, 'rule', 'add', 'pref', '500', 'lookup', 'main')
        elif fault == 'dns-bind':
            fixture.config.write_text(fixture.text.replace('tcp+udp://' + ('[' + fixture.bind_address + ']' if number == 6 else fixture.bind_address) + ':1053', 'tcp+udp://' + ('[fd00:bad::1]' if number == 6 else '203.0.113.254') + ':1053'))
        elif fault not in ('no-cap', 'no-tun'):
            raise AssertionError(fault)
        before = fixture.snapshot('conflict-before')
        special = {'no-cap': 'uncap', 'no-tun': 'without-tun'}.get(fault)
        fixture.daemon = fixture.launch(special)
        assert fixture.daemon.wait(timeout=15) != 0, ('setup conflict did not refuse', fault)
        assert 'TUN datapath ready' not in fixture.log.read_text(), ('setup failed after false readiness', fault)
        after = fixture.snapshot('conflict-after')
        if fault != 'dns-bind':
            assert not list((fixture.state / 'state').glob('tun-*.json')), 'pre-capture rejection retained an unneeded setup receipt'
            for key in ('-4', '-6', 'links', 'addresses'):
                # Link statistics can change while neighbors resolve; identity cannot.
                if key == 'links':
                    simplify = lambda links: [{key: value for key, value in link.items() if key not in ('stats64', 'stats', 'operstate')} for link in links]
                    assert simplify(after[key]) == simplify(before[key]), (fault, key)
                else:
                    assert after[key] == before[key], ('setup rejection changed preexisting resources', fault, key)
        else:
            # Bind fails after guards exist: either exact normal rollback or retained containment.
            rules = after[option]['rules']
            if any(rule.get('priority') == 10004 for rule in rules):
                assert any(route.get('type') == 'blackhole' and str(route.get('table')) == '202' for route in after[option]['routes'])
                fixture.check_receipt()
            else:
                assert after[option] == before[option]
                assert not list((fixture.state / 'state').glob('tun-*.json'))


def duplicate_lock(daemon, root, number):
    with Fixture(daemon, root, f'A-{number}-instance-lock', number) as fixture:
        fixture.start()
        before = fixture.resources()
        identity = fixture.device_identity()
        lock_stat = Path('/run/honk-core.lock').stat()
        lock_key = (lock_stat.st_dev, lock_stat.st_ino)

        def lock_fds(process):
            assert process.poll() is None, 'instance exited before lock observation'
            found = []
            for fd in Path(f'/proc/{process.pid}/fd').iterdir():
                try:
                    info = fd.stat()
                    if (info.st_dev, info.st_ino) == lock_key:
                        found.append(Path(f'/proc/{process.pid}/fdinfo/{fd.name}').read_text())
                except FileNotFoundError:
                    continue
            return found

        def holds_lock(records):
            return any(line.startswith('lock:') and 'FLOCK' in line
                       for text in records for line in text.splitlines())

        first_lock = lock_fds(fixture.daemon)
        assert holds_lock(first_lock), 'first daemon does not hold the actual instance lock'
        second = fixture.launch(log='second-instance.log')
        try:
            eventually(lambda: lock_fds(second), 'second instance did not reach the lock file', seconds=10)
            observations = []
            for _ in range(2):
                waiting = lock_fds(second)
                held = lock_fds(fixture.daemon)
                assert waiting and not holds_lock(waiting) and holds_lock(held)
                assert fixture.resources() == before and fixture.device_identity() == identity
                fixture.exchange('first-owner-progresses-while-second-waits')
                observations.append({'first_fdinfo': held, 'second_fdinfo': waiting,
                                     'monotonic_ns': time.monotonic_ns()})
                time.sleep(0.5)
            (fixture.directory / 'lock-wait.json').write_text(json.dumps({
                'first_pid': fixture.daemon.pid, 'second_pid': second.pid,
                'lock_device_inode': lock_key, 'observations': observations,
            }, indent=2) + '\n')
        finally:
            stop(second)
        assert fixture.resources() == before and fixture.device_identity() == identity
        fixture.exchange('first-owner-survives-lock-conflict')
        fixture.normal_stop()


def close_active(daemon, root, number):
    with Fixture(daemon, root, f'A-{number}-close-active', number) as fixture:
        fixture.start()
        process = child(fixture, fixture.names['source'], 'live', number, fixture.source, stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=fixture.open('held-close.stderr'))
        try:
            assert line(process)['phase'] == 'before'
            fixture.normal_stop()
            eventually(lambda: any(event['kind'] == 'echo-closed' and event['target'] == [TARGETS[number][0], 18081]
                                   for event in fixture.peer_events()), 'normal stop did not close the real retained outbound TCP', 10)
        finally:
            stop(process)


def strict_rpf(daemon, root, number):
    row = f'A-{number}-strict-rpf'
    with Fixture(daemon, root, row, number) as fixture:
        run('sysctl', '-qw', 'net.ipv4.conf.all.rp_filter=1', namespace=fixture.names['dut'])
        fixture.daemon = fixture.launch()
        assert fixture.daemon.wait(timeout=15) != 0, 'strict global IPv4 rp_filter did not refuse startup'
        text = fixture.log.read_text()
        assert 'net.ipv4.conf.all.rp_filter' in text, ('missing strict-rpf startup diagnostic', text)
        assert 'TUN datapath ready' not in text, 'strict-rpf rejection followed false readiness'
        assert run('sysctl', '-n', 'net.ipv4.conf.all.rp_filter', namespace=fixture.names['dut']).stdout.strip() == '1'
        after = fixture.snapshot('strict-rpf-rejected')
        assert not any(link['ifname'] == 'honk0' for link in after['links']), 'strict-rpf rejection retained a TUN link'
        assert fixture.resources() == fixture.before, 'strict-rpf rejection changed preexisting RPDB/routes'
        assert not list((fixture.state / 'state').glob('tun-*.json')), 'strict-rpf rejection retained a setup receipt'
        fixture.fence_counters()


def gate(daemon, root):
    root = Path(root)
    fault_names = ('name', 'table', 'priority', 'address', 'main-route', 'rpdb', 'dns-bind', 'no-cap', 'no-tun')
    cases = ROWS + [f'A-{number}-{name}' for number in (4, 6)
                    for name in ('DNS', 'control', 'packets', 'instance-lock', 'close-active', 'strict-rpf',
                                 'crash-guard', 'topology-fault', *('setup-' + fault for fault in fault_names))]
    results = {row: {'status': 'NOT_RUN'} for row in cases}
    failures = []
    def record(row, operation):
        terminal_cleanup = None
        try:
            operation()
        except Exception as error:
            status = dict(status='FAIL', error=repr(error))
            failures.append(row)
            if isinstance(error, CleanupIncomplete):
                terminal_cleanup = error
            detail = traceback.format_exc()
            if isinstance(error, subprocess.CalledProcessError):
                detail += '\nstdout:\n' + (error.stdout or '') + '\nstderr:\n' + (error.stderr or '')
            (root / (row + '.failure.txt')).write_text(detail)
        else:
            status = dict(status='PASS')
        results[row] = status
        result = dict(row=row, **status)
        print(json.dumps(result, sort_keys=True), flush=True)
        with (root / 'rows.jsonl').open('a') as output:
            output.write(json.dumps(result, sort_keys=True) + '\n')
        (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        if terminal_cleanup is not None:
            raise terminal_cleanup
    (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    (root / 'executable.json').write_text(json.dumps(dict(path=daemon, sha256=hashlib.sha256(Path(daemon).read_bytes()).hexdigest(),
                                                          kernel=os.uname().release, lane=os.environ['HONK_CI_VM_LANE']), indent=2))
    (root / 'evidence-limits.json').write_text(json.dumps({
        'forced_real_tun_write_eagain': {
            'status': 'NOT_RUN',
            'reason': 'No deterministic external TUN write(EAGAIN) forcing seam; interface counters prove FD traffic only.',
            'separate_regression': 'tun::tests::writable_readiness_retries_the_same_lease_without_new_input uses a real saturated datagram socketpair and the production flush function.'
        },
        'oversize_datagram_boundary': 'The ordinary UDP length ceiling is rejected by the source kernel; this is not a claim of TUN FD jumbogram rejection.'
    }, indent=2) + '\n')
    for row in ROWS:
        record(row, lambda row=row: matrix_row(daemon, root, row))
    for number in (4, 6):
        for name, operation in (('DNS', dns_extensions), ('control', control_extensions), ('packets', packet_extensions)):
            row = f'A-{number}-{name}'
            def extension(number=number, row=row, operation=operation):
                with Fixture(daemon, root, row, number) as fixture:
                    fixture.start()
                    operation(fixture)
                    fixture.snapshot('extension-complete')
                    fixture.normal_stop()
            record(row, extension)
        record(f'A-{number}-instance-lock', lambda number=number: duplicate_lock(daemon, root, number))
        record(f'A-{number}-close-active', lambda number=number: close_active(daemon, root, number))
        record(f'A-{number}-strict-rpf', lambda number=number: strict_rpf(daemon, root, number))
        for fault in fault_names:
            record(f'A-{number}-setup-{fault}', lambda number=number, fault=fault: setup_fault(daemon, root, number, fault))
        for topology in (False, True):
            record(f'A-{number}-' + ('topology-fault' if topology else 'crash-guard'),
                   lambda number=number, topology=topology: crash_fault(daemon, root, number, topology))
    assert all(result['status'] != 'NOT_RUN' for result in results.values())
    assert not failures, ('TUN scenarios failed; inspect independent row artifacts', failures)


def raw_dns(number, source, target, source_port, data, transport):
    query = bytes.fromhex(data)
    kind = socket.SOCK_STREAM if transport == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(family(number), kind) as sock:
        sock.settimeout(8)
        sock.bind((source, int(source_port)))
        sock.connect((target, 53))
        for identifier in (int(source_port), int(source_port) + 1):
            current = struct.pack('!H', identifier) + query[2:]
            if transport == 'tcp':
                sock.sendall(struct.pack('!H', len(current)) + current)
                response = exact(sock, struct.unpack('!H', exact(sock, 2))[0])
            else:
                sock.send(current)
                response, remote = sock.recvfrom(65535)
                assert endpoint(remote) == [target, 53]
            verify_dns(response, current, TARGETS[int(number)][DOMAINS['must.test']])
    print(json.dumps(dict(reply=True, transport=transport)), flush=True)


def mtu_client(number, source, target, port):
    number, port = int(number), int(port)
    fragments = {'tx': [], 'rx': []}
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as trace, socket.socket(family(number), socket.SOCK_DGRAM) as sock:
        trace.bind(('src0', 0))
        trace.settimeout(2)
        sock.bind((source, 0))
        sock.connect((target, port))
        sock.settimeout(8)
        if number == 4:
            sock.setsockopt(socket.IPPROTO_IP, 10, 0)  # IP_MTU_DISCOVER, DONT
        else:
            sock.setsockopt(socket.IPPROTO_IPV6, 23, 0)  # IPV6_MTU_DISCOVER, DONT
            sock.setsockopt(socket.IPPROTO_IPV6, 62, 0)  # IPV6_DONTFRAG
        payload = b'valid-fragmented-datagram:' + bytes(range(256)) * 16
        assert sock.send(payload) == len(payload)
        assert sock.recv(65535) == payload, 'valid MTU-sized fragments lost reassembly/reply'
        deadline = time.monotonic() + 3
        while not all(len(pieces) >= 2 and any(piece['offset'] > 0 and not piece['more'] for piece in pieces) for pieces in fragments.values()):
            assert time.monotonic() < deadline, ('missing actual fragment wire records', fragments)
            frame, metadata = trace.recvfrom(65535)
            if metadata[2] not in (0, 4) or len(frame) < 54:
                continue
            packet = frame[14:]
            direction = 'tx' if metadata[2] == 4 else 'rx'
            if number == 4:
                if frame[12:14] != b'\x08\x00' or packet[9] != 17:
                    continue
                actual_source, actual_target = socket.inet_ntop(socket.AF_INET, packet[12:16]), socket.inet_ntop(socket.AF_INET, packet[16:20])
                field = struct.unpack_from('!H', packet, 6)[0]
                offset, more = (field & 0x1fff) * 8, bool(field & 0x2000)
                length = struct.unpack_from('!H', packet, 2)[0]
                identity = struct.unpack_from('!H', packet, 4)[0]
            else:
                if frame[12:14] != b'\x86\xdd' or packet[6] != 44:
                    continue
                actual_source, actual_target = socket.inet_ntop(socket.AF_INET6, packet[8:24]), socket.inet_ntop(socket.AF_INET6, packet[24:40])
                field = struct.unpack_from('!H', packet, 42)[0]
                offset, more = field & 0xfff8, bool(field & 1)
                length = 40 + struct.unpack_from('!H', packet, 4)[0]
                identity = struct.unpack_from('!I', packet, 44)[0]
            if [actual_source, actual_target] != ([source, target] if direction == 'tx' else [target, source]):
                continue
            assert (offset or more) and length <= 1500 and len(packet) >= length
            fragments[direction].append(dict(offset=offset, more=more, length=length, identity=identity))
        assert all(len({piece['identity'] for piece in pieces}) == 1 for pieces in fragments.values()), fragments
        if number == 4:
            sock.setsockopt(socket.IPPROTO_IP, 10, 2)  # IP_PMTUDISC_DO
        else:
            sock.setsockopt(socket.IPPROTO_IPV6, 62, 1)
        for rejected in (payload, b'x' * 65536):
            try:
                sock.send(rejected)
            except OSError as error:
                assert error.errno == errno.EMSGSIZE, error
            else:
                raise AssertionError('source kernel admitted a DF/ordinary UDP length violation')
    print(json.dumps(dict(fragmented_roundtrip=True, oversize_refused=True, mtu_df_refused=True, fragments=fragments)), flush=True)


def exec_uncap(argv):
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
    libc = ctypes.CDLL(None, use_errno=True)
    for capability in (12, 13):
        assert libc.prctl(24, capability, 0, 0, 0) == 0  # PR_CAPBSET_DROP
    header, data = Header(0x20080522, 0), (Data * 2)()
    assert libc.capget(ctypes.byref(header), data) == 0
    mask = ~((1 << 12) | (1 << 13)) & 0xffffffff
    data[0].effective &= mask
    data[0].permitted &= mask
    data[0].inheritable &= mask
    assert libc.capset(ctypes.byref(header), data) == 0
    assert libc.prctl(38, 1, 0, 0, 0) == 0  # PR_SET_NO_NEW_PRIVS
    os.execv(argv[0], argv)


def main():
    guard()
    mode, *args = sys.argv[1:]
    if mode == 'gate':
        def terminate(signum, _):
            raise SystemExit(128 + signum)
        signal.signal(signal.SIGTERM, terminate)
        gate(*args)
    elif mode == 'serve':
        Peer(*args).serve()
    elif mode == 'traffic':
        traffic(*args)
    elif mode == 'tcp-policy':
        tcp_policy(*args)
    elif mode == 'api':
        api_hold(*args)
    elif mode == 'dns':
        dns_client(*args)
    elif mode == 'raw-dns':
        raw_dns(*args)
    elif mode == 'one':
        one_exchange(*args)
    elif mode == 'live':
        live_client(*args)
    elif mode == 'inject':
        inject(*args)
    elif mode == 'mtu':
        mtu_client(*args)
    elif mode == 'netns-cookie':
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            cookie = struct.unpack('=Q', sock.getsockopt(socket.SOL_SOCKET, 71, 8))[0]
        print(json.dumps(dict(cookie=cookie)), flush=True)
    elif mode == 'uncap':
        exec_uncap(args)
    elif mode == 'without-tun':
        os.execvp('unshare', ['unshare', '--mount', '--', sys.executable, SCRIPT, 'hide-tun', *args])
    elif mode == 'hide-tun':
        run('mount', '--make-rprivate', '/')
        run('mount', '-t', 'tmpfs', 'tmpfs', '/dev/net')
        os.execv(args[0], args)
    else:
        raise AssertionError(('unknown concrete fixture operation', mode))


if __name__ == '__main__':
    main()
