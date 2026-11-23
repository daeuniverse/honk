"""Joined, disposable-guest peer for the attached-gateway UDP batch/quota test."""
import contextlib
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

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('dns_fixture', Path(__file__).with_name('xdp-dns-shadow.py'))
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
NSEG = 8
SEGMENT = 512


def exchange(sport, port, nonce, batch):
    count = NSEG if batch else 1
    origin = (f.LAN4, sport)
    target = (f.TARGET4, port)
    with contextlib.ExitStack() as owned:
        def endpoint(ns, address):
            with f.namespace(ns):
                sock = owned.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                sock.setsockopt(socket.IPPROTO_IP, 8, 1)  # IP_PKTINFO
                sock.settimeout(3)
                sock.bind(address)
                return sock

        def receive(sock, expected, interface, destination):
            data, ancillary, flags, source = sock.recvmsg(SEGMENT, socket.CMSG_SPACE(12))
            [(level, kind, raw)] = ancillary
            index, _, dst = struct.unpack('=I4s4s', raw)
            assert (flags, level, kind, index, socket.inet_ntoa(dst)) == (
                0, socket.IPPROTO_IP, 8, interface, destination), (ancillary, flags, destination)
            assert source[0] == expected[0] and (expected[1] is None or source[1] == expected[1]), source
            return data, source

        client = endpoint('client', origin)
        server = endpoint('server', target)
        with f.namespace('server'):
            incoming = socket.if_nametoindex('s0' if batch else 'su')
        with f.namespace('client'):
            c0 = socket.if_nametoindex('c0')
        client.connect(target)
        parts = [(nonce + struct.pack('!I', seq)).ljust(SEGMENT, b'X') for seq in range(count)]
        if batch:
            # Real UDP_SEGMENT, two back-to-back sends on the same connected socket.
            # The trace must see individual XDP arrivals, even when sendmsg succeeds.
            option = [(socket.IPPROTO_UDP, 103, struct.pack('=H', SEGMENT))]
            for i in (0, count // 2):
                chunk = parts[i:i + count // 2]
                assert client.sendmsg(chunk, option) == len(chunk) * SEGMENT
        else:
            assert client.send(parts[0]) == SEGMENT
        seen, echoed = set(), set()
        expected_source = origin if batch else (f.UP4, None)
        for _ in parts:
            data, source = receive(server, expected_source, incoming, target[0])
            assert data in parts and data not in seen, (data.hex(), seen)
            seen.add(data)
            assert server.sendto(data, source) == len(data)
        for _ in parts:
            data, _ = receive(client, target, c0, origin[0])
            assert data in seen and data not in echoed, (data.hex(), echoed)
            echoed.add(data)
        assert seen == echoed == set(parts)
        return dict(client=origin, destination=target, server_saw=source,
                    server_ingress='s0' if batch else 'su', echoed_sequences=list(range(count)),
                    nonce=nonce.hex())


def qualify(text, group, ifindex, cpu, nonce, sport, port):
    active = []
    qualified = []
    header = re.search(r'entries-in-buffer/entries-written:\s*(\d+)/(\d+)', text)
    assert header and header[1] == header[2], 'private trace ring overflowed or was unreadable'
    event_name = re.compile(r'\[(\d+)\].*?\s' + re.escape(group) + r'_(enter|leave|arrival|gro):\s')
    for line in text.splitlines():
        event = event_name.search(line)
        if not event:
            continue
        assert int(event[1]) == cpu, line
        fields = {name: int(value, 0) for name, value in re.findall(r'\b(\w+)=(-?0x[0-9a-fA-F]+|-?\d+)\b', line)}
        kind = event[2]
        if kind == 'enter':
            active.append((fields, {'arrival': set(), 'gro': set()}))
        elif kind == 'leave':
            if not active:  # trace can start in an already running poll
                continue
            poll, seen = active.pop()
            both = sorted(seen['arrival'] & seen['gro'])
            if len(both) >= 2:
                assert poll['ifindex'] == ifindex and poll['nid'] > 0 and poll['napi'] != 0
                assert len(seen['arrival']) <= fields['work'] <= poll['budget'], (poll, seen, fields)
                qualified.append(dict(napi_id=poll['nid'], napi=hex(poll['napi']), cpu=cpu, queue=0,
                                      ifindex=ifindex, work=fields['work'], budget=poll['budget'],
                                      xdp_sequences=sorted(seen['arrival']), gro_sequences=sorted(seen['gro'])))
        else:
            assert active, ('selected packet outside veth_poll', line)
            poll, seen = active[-1]
            assert fields['dev'] == poll['dev'] and poll['ifindex'] == ifindex, (poll, fields)
            if kind == 'arrival':
                assert fields['queue'] == 0 and fields['end'] - fields['data'] >= 54, fields
            else:
                assert fields['length'] - fields['nonlinear'] >= 40, fields
            assert fields['nonce'].to_bytes(8, sys.byteorder) == nonce
            assert fields['ihl'] == 0x45 and fields['proto'] == socket.IPPROTO_UDP
            assert fields['src'].to_bytes(4, sys.byteorder) == socket.inet_aton(f.LAN4)
            assert fields['dst'].to_bytes(4, sys.byteorder) == socket.inet_aton(f.TARGET4)
            assert fields['ports'].to_bytes(4, sys.byteorder) == struct.pack('!HH', sport, port)
            seq, = struct.unpack('!I', fields['seq'].to_bytes(4, sys.byteorder))
            assert seq < NSEG
            # First-time ownership may perform more than one CT lookup on the same packet.
            seen[kind].add(seq)
    assert qualified, 'no complete DUT veth_poll had two distinct numbered XDP arrivals and their GRO callbacks'
    return qualified


def trace(offsets, cpu, nonce, sport, port, ifindex):
    def field(name, base):
        return f'+{offsets[name]}({base})'

    def packet(data, l3):
        fields = [('ihl', 0, 8), ('total', 2, 16), ('proto', 9, 8), ('src', 12, 32), ('dst', 16, 32),
                  ('ports', 20, 32), ('ulen', 24, 16), ('nonce', 28, 64), ('seq', 36, 32)]
        return ' '.join(f'{name}=+{l3 + pos}({data}):x{bits}' for name, pos, bits in fields)

    ndev = field('napi_struct.dev', '$arg1')
    rxq = field('xdp_buff.rxq', '$arg1')

    def device(dev):
        return f'dev={dev}:x64 ifname={field("net_device.name", dev)}:string'

    selected = dict(ihl=0x45, proto=socket.IPPROTO_UDP,
                    total=socket.htons(28 + SEGMENT), ulen=socket.htons(8 + SEGMENT),
                    src=int.from_bytes(socket.inet_aton(f.LAN4), sys.byteorder),
                    dst=int.from_bytes(socket.inet_aton(f.TARGET4), sys.byteorder),
                    ports=int.from_bytes(struct.pack('!HH', sport, port), sys.byteorder),
                    nonce=int.from_bytes(nonce, sys.byteorder))
    packet_filter = ' && '.join(['ifname == "dut0"', *(f'{key} == {value:#x}' for key, value in selected.items())])
    definitions = [
        ('p', 'enter', 'veth_poll', f'napi=$arg1:x64 dev={ndev}:x64 '
         f'ifindex={field("net_device.ifindex", ndev)}:u32 nid={field("napi_struct.napi_id", "$arg1")}:u32 budget=$arg2:s32'),
        ('r', 'leave', 'veth_poll', 'work=$retval:s32'),
        ('p', 'arrival', 'bpf_xdp_ct_lookup', device(field('xdp_rxq_info.dev', rxq)) + ' '
         f'data={field("xdp_buff.data", "$arg1")}:x64 end={field("xdp_buff.data_end", "$arg1")}:x64 '
         f'queue={field("xdp_rxq_info.queue_index", rxq)}:u32 ' + packet(field('xdp_buff.data', '$arg1'), 14)),
        ('p', 'gro', 'inet_gro_receive', device(field('sk_buff.dev', '$arg2')) + ' '
         f'length={field("sk_buff.len", "$arg2")}:u32 nonlinear={field("sk_buff.data_len", "$arg2")}:u32 '
         + packet(field('sk_buff.data', '$arg2'), 0)),
    ]
    with contextlib.ExitStack() as owned:
        directory = Path(owned.enter_context(tempfile.TemporaryDirectory(prefix='honkudp_')))
        root = directory / 'tracefs'
        root.mkdir()
        subprocess.run(['mount', '-t', 'tracefs', 'tracefs', root], check=True, timeout=3)
        owned.callback(subprocess.run, ['umount', root], check=True, timeout=3)
        # Unique private ring and probe definitions. Never clear the global trace
        # buffer or change another instance's tracer, clock, filters, or enables.
        group = directory.name
        instance = root / 'instances' / group
        instance.mkdir()
        owned.callback(instance.rmdir)
        (instance / 'tracing_on').write_text('0')
        (instance / 'tracing_cpumask').write_text(format(1 << (cpu % 32), 'x') + ',00000000' * (cpu // 32))
        (instance / 'buffer_size_kb').write_text('64')

        def register(text):
            with (root / 'kprobe_events').open('a') as events:
                events.write(text + '\n')

        for kind, name, symbol, args in definitions:
            event_name = f'{group}_{name}'
            register(f'{kind}:{group}/{event_name} {symbol} {args}')
            owned.callback(register, f'-:{group}/{event_name}')
            event = instance / 'events' / group / event_name
            if name in ('arrival', 'gro'):
                (event / 'filter').write_text(packet_filter)
            (event / 'enable').write_text('1')
            owned.callback((event / 'enable').write_text, '0')
        (instance / 'tracing_on').write_text('1')
        try:
            delivery = exchange(sport, port, nonce, True)
        finally:
            (instance / 'tracing_on').write_text('0')
            raw = (instance / 'trace').read_text()
            (Path(os.environ['HONK_XDP_ARTIFACT_ROOT']) / 'udp-batch.trace').write_text(raw)
        profile = (root / 'kprobe_profile').read_text().splitlines()
        for _, name, _, _ in definitions:
            event_name = f'{group}_{name}'
            matches = [line.split() for line in profile if line.split() and line.split()[0].split('/')[-1] == event_name]
            assert len(matches) == 1 and int(matches[0][-1]) == 0, ('kprobe missed events', name, matches)
        polls = qualify(raw, group, ifindex, cpu, nonce, sport, port)
        return dict(delivery=delivery, polls=polls)


def batch_features():
    observed = {}
    for ns, interface, required in [
            ('dut', 'dut0', {'generic-receive-offload': 'on'}),
            ('client', 'c0', {'tx-checksum-ip-generic': 'on', 'generic-segmentation-offload': 'off'})]:
        output = subprocess.check_output(['ip', 'netns', 'exec', ns, 'ethtool', '-k', interface],
                                         text=True, timeout=3)
        values = dict(re.findall(r'^\s*([\w-]+):\s+(on|off)\b', output, re.M))
        observed[interface] = {name: values.get(name) for name in required}
        assert observed[interface] == required, ('attached device offload mismatch', ns, interface, observed, required)
    return observed


def main():
    if not __debug__:
        raise RuntimeError('the guest witness requires Python assertions')
    f.probe.require_live_namespace()
    assert os.path.samefile('/proc/self/ns/net', '/run/netns/dut')
    assert os.uname().release == os.environ['HONK_CI_EXPECTED_KERNEL']
    assert os.environ['HONK_CI_VM_LANE'] in ('floor', 'recent')
    mode, program, sport, port = sys.argv[1:5]
    assert mode in ('batch', 'quota')
    program, sport, port = int(program), int(sport), int(port)
    assert (sport, port) == (42063 if mode == 'batch' else 42064, 18275)
    f.probe.require_xdp_identity(f.probe.xdp_state('dut0'), program)
    nonce = os.urandom(8)
    ifindex = socket.if_nametoindex('dut0')
    if mode == 'batch':
        for ns, interface in [('dut', 'dut0'), ('dut', 'dut1'), ('client', 'c0'), ('server', 's0')]:
            settings = subprocess.check_output(['ip', 'netns', 'exec', ns, 'ethtool', '-l', interface],
                                                text=True, timeout=3).split('Current hardware settings:')[-1]
            assert all(re.search(rf'^{name}:\s+1\s*$', settings, re.M) for name in ('RX', 'TX')), (ns, interface, settings)
        cpu = min(os.sched_getaffinity(0))
        os.sched_setaffinity(0, {cpu})
        before = batch_features()
        result = trace(json.loads(sys.argv[5]), cpu, nonce, sport, port, ifindex)
        after = batch_features()
        result['offloads'] = {'before': before, 'after': after}
    else:
        result = dict(delivery=exchange(sport, port, nonce, False))
    f.probe.require_xdp_identity(f.probe.xdp_state('dut0'), program)
    print(json.dumps(dict(observation=mode, program=program, netns=os.stat('/proc/self/ns/net').st_ino,
                          ifindex=ifindex, **result)), flush=True)


if __name__ == '__main__':
    def deadline(signum, frame):
        raise TimeoutError('guest UDP observation deadline')
    signal.signal(signal.SIGALRM, deadline)
    signal.signal(signal.SIGTERM, deadline)
    signal.alarm(25)
    main()
