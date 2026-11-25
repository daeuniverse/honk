"""TCP gateway wire cases driven by the guarded xdp-dns-shadow.py guest entry."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import time


def read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        assert chunk, ('early TCP EOF', len(data), length)
        data.extend(chunk)
    return bytes(data)


def forward_counts():
    result = subprocess.check_output(['ip', 'netns', 'exec', 'dut', 'nft', '-j', 'list', 'table', 'inet', 'honk_dns_tcp_wire'],
                                     text=True, timeout=5)
    counts = {row['name']: row['packets'] for item in json.loads(result)['nftables']
              if (row := item.get('counter')) and row['table'] == 'honk_dns_tcp_wire'}
    assert set(counts) == {'syn', 'synack'}, counts
    return counts


def owners(pid, log, members, workers):
    proc = Path('/proc') / str(pid)
    threads = {}
    for task in (proc / 'task').iterdir():
        try:
            name = (task / 'comm').read_text().strip()
        except FileNotFoundError:
            continue
        if name.startswith('honk-xdp-') and name[9:].isdigit():
            assert name not in threads, name
            threads[name] = int(task.name)
    assert set(threads) == {f'honk-xdp-{i}' for i in range(workers)}, threads
    lines = re.sub(r'\x1b\[[0-9;]*m', '', log.read_text()).split('XDP datapath ready', 1)
    assert len(lines) == 2
    bound = {}
    for member in members:
        queues = {int(match[1]) for line in lines[0].splitlines() if 'XDP queue bound' in line
                  and re.search(r'\binterface="?' + member + r'"?(?:\s|$)', line)
                  and (match := re.search(r'\bqueue=(\d+)(?:\s|$)', line))}
        assert queues == set(range(workers)), (member, queues, workers)
        bound[member] = sorted(queues)
    with (proc / 'exe').open('rb') as exe:
        digest = hashlib.file_digest(exe, 'sha256').hexdigest()
    return {'pid': pid, 'executable_sha256': digest, 'worker_threads': threads, 'bound_queues': bound}


def wire(f, profile, pid, log):
    f.probe.require_live_namespace()
    profiles = ('tcp-static-1', 'tcp-dns-1', 'tcp-static-2', 'tcp-dns-2')
    base = 44000 + 100 * profiles.index(profile)  # disjoint from conntrack and TIME_WAIT in the preceding profile
    workers = int(profile[-1])
    enabled = profile.startswith('tcp-dns-')
    members = ['dut0', 'dut1'] if workers == 1 else ['dut0']
    affinity = os.sched_getaffinity(0)
    sender_cpus = sorted(affinity)[:workers]
    assert len(sender_cpus) == workers, (workers, affinity)
    print(json.dumps({'profile': profile, **owners(pid, log, members, workers)}), flush=True)
    identities = {}
    observed_queues = set()
    observed_dns_cpus = set()
    aaa = f.TARGET6

    def answer(name, qtype):
        if qtype == 28:
            return aaa, 60
        if name == 'wan.pass-shadow.test':
            return f.DNS[0], 60
        if name == 'expire.pass-shadow.test':
            return f.EXPIRING, 10
        return f.answer_ip(name, qtype)

    def snapshot(device):
        state = f.snapshot(device, enabled, tcp=True)
        identity = (state['program'], state['maps'], state['realm'])
        assert identities.setdefault(device, identity) == identity, (device, state)
        return state

    with contextlib.ExitStack() as owned:
        events = f.endpoint_peer(owned, answer)
        serial = 0xb100
        cases = []

        def learn(name, qtype, expected, *, wan=False):
            nonlocal serial
            serial += 1
            question = f.name_wire(name) + struct.pack('!HH', qtype, 1)
            request = struct.pack('!HHHHHH', serial, 0x0100, 1, 0, 0, 0) + question
            index = len(events)
            origin = (f.WAN4 if wan else f.LAN4, base + 50 + index)
            result = f.client_exchange('shadow-wan' if wan else 'client', origin, f.DNS, request)
            f.verify_answer(result, question, serial, qtype, expected, answer(name, qtype)[1])
            [peer] = events[index:]
            assert (peer['name'], peer['qtype']) == (name, qtype), peer
            print(json.dumps({'profile': profile, 'question': name, 'qtype': qtype, 'answer': expected,
                              'txid': serial, 'origin': origin, 'upstream': peer}), flush=True)

        def trial(case, ip, *, port=f.PORT, fact='absent', dns=False, static=False, wan=False):
            device = 'dut1' if wan else 'dut0'
            before = snapshot(device)
            lease = None
            if enabled and (fact == 'live' or wan):
                lease = f.live_dns_fact(snapshot('dut0') if wan else before, ip, True)
            elif enabled:
                value = f.dns_fact(before, ip)
                now = time.monotonic_ns()
                if value is not None:
                    assert fact == 'expired' and struct.unpack_from('=Q', value)[0] <= now, (case, value)
                lease = {'observed_mono_ns': now, 'raw': value.hex() if value is not None else None}
            original = (f.WAN4 if wan else (f.LAN6 if ':' in ip else f.LAN4), base + len(cases))
            native = static or (enabled and dns)
            forward_before = forward_counts()
            listeners = {}
            # Keep connected sockets open until the last snapshot so a preceding flow's FIN cannot count in the next case.
            with contextlib.ExitStack() as listening:
                for realm, iface in [('server', 'su'), ('shadow-wan', 's0')]:
                    if wan and realm == 'shadow-wan':
                        continue  # WAN client routes this address out of s0; it is local only on server/lo.
                    with f.namespace(realm):
                        sock = listening.enter_context(socket.socket(f.family(ip), socket.SOCK_STREAM))
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b'\0')
                        sock.bind((ip, port))
                        sock.listen(2)
                        listeners[sock] = (realm, iface, os.stat('/proc/thread-self/ns/net').st_ino)
                with f.namespace('shadow-wan' if wan else 'client'):
                    client = owned.enter_context(socket.socket(f.family(ip), socket.SOCK_STREAM))
                client.settimeout(8)
                client.bind(original)
                if workers == 2:
                    queue = len(cases) % 2
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, queue)
                    os.sched_setaffinity(0, {sender_cpus[queue]})
                    try:
                        client.connect((ip, port))
                    finally:
                        os.sched_setaffinity(0, affinity)
                else:
                    client.connect((ip, port))
                payload = b'honk/tcp-wire/' + case.encode() + b'/' + os.urandom(24)
                client.sendall(payload)
                readable, _, _ = select.select(list(listeners), [], [], 8)
                assert len(readable) == 1, (case, readable)
                [listener] = readable
                realm, iface, nsid = listeners[listener]
                conn, source = listener.accept()
                owned.enter_context(conn)
                conn.settimeout(8)
                destination = conn.getsockname()[:2]
                assert realm == ('shadow-wan' if native else 'server') and destination == (ip, port), (case, realm, destination)
                if native:
                    assert source[:2] == original, (case, source, original)
                else:
                    assert source[0] == (f.UP6 if ':' in ip else f.UP4), (case, source)
                assert read_exact(conn, len(payload)) == payload
                reply = realm.encode() + b'/' + os.urandom(32)
                conn.sendall(reply)
                assert read_exact(client, len(reply)) == reply
                # The final write carries the ACK for the reply before we sample capture counters.
                client.sendall(reply)
                assert read_exact(conn, len(reply)) == reply
                assert not select.select(list(listeners), [], [], 0)[0], (case, 'additional TCP accept')
            forward_after = forward_counts()
            after = snapshot(device)
            assert before['epoch'] == after['epoch'], (case, before, after)
            delta = {k: v - before['counters'][k] for k, v in after['counters'].items()}
            assert delta['pass_d1'] == int(static) and delta['pass_dns_d1'] == int(enabled and dns), (case, delta)
            assert delta['xsk_new'] == int(not native) and (delta['capture'] > 0) == (not native), (case, delta)
            assert all(delta[k] == 0 for k in ('would_pass_dns', 'dns_retry', 'pending_conflict', 'pending_capped',
                                               'hold_contention', 'hold_unavailable', 'release_failed', 'retire_failed')), (case, delta)
            assert all(forward_after[k] - forward_before[k] == int(native) for k in forward_before), (case, forward_before, forward_after)
            queue_delta = [y - x for x, y in zip(before['queues'], after['queues'], strict=True)]
            assert all(x >= 0 for x in queue_delta) and sum(queue_delta) == delta['capture'], (case, queue_delta)
            observed_queues.update((device, i) for i, count in enumerate(queue_delta) if count)
            dns_cpus = [i for i, (x, y) in enumerate(zip(before['dns_by_cpu'], after['dns_by_cpu'], strict=True)) if y > x]
            observed_dns_cpus.update(dns_cpus)
            print(json.dumps({'profile': profile, 'case': case, 'origin': original, 'ingress': device,
                              'program_id': after['program'], 'realm': after['realm'], 'epoch': after['epoch'], 'lan_lease': lease,
                              'peer': {'namespace': realm, 'inode': nsid, 'interface': iface, 'source': source[:2], 'destination': destination,
                                       'request_hex': payload.hex(), 'reply_hex': reply.hex()},
                              'before': before['counters'], 'after': after['counters'], 'delta': delta,
                              'capture_by_queue_before': before['queues'], 'capture_by_queue_after': after['queues'],
                              'dns_pass_cpus': dns_cpus, 'forward_before': forward_before, 'forward_after': forward_after}), flush=True)
            cases.append(case)
            return lease

        trial('missing', f.TARGET4)
        learn('learn.pass-shadow.test', 1, f.TARGET4)
        a = trial('a', f.TARGET4, fact='live', dns=True)
        port53 = trial('dns-dependent-port-53', f.TARGET4, port=53, fact='live')
        assert not enabled or a['value'] == port53['value']
        trial('static-port-53', f.STATIC, port=53, static=True)
        learn('learn.pass-shadow.test', 28, f.TARGET6)
        granted = trial('aaaa', f.TARGET6, fact='live', dns=True)
        aaa = 'fd00:2::7'
        learn('learn.pass-shadow.test', 28, aaa)
        if enabled:
            f.live_dns_fact(snapshot('dut0'), aaa, True)
            assert time.monotonic_ns() < granted['value']['valid_before_mono_ns']
        trial('withdrawn', f.TARGET6)
        learn('learn.pass-shadow.test', 1, f.TARGET4)
        if enabled:
            a = f.live_dns_fact(snapshot('dut0'), f.TARGET4, True)
        learn('conflict.test', 1, f.TARGET4)
        if enabled:
            assert time.monotonic_ns() < a['value']['valid_before_mono_ns']
        trial('conflict', f.TARGET4)
        learn('expire.pass-shadow.test', 1, f.EXPIRING)
        until = time.monotonic_ns() + 10_000_000_000
        expiring = trial('before-expiry', f.EXPIRING, fact='live', dns=True)
        if enabled:
            until = expiring['value']['valid_before_mono_ns']
        time.sleep(max(0, (until - time.monotonic_ns()) / 1e9) + 0.05)
        trial('expired', f.EXPIRING, fact='expired')
        if 'dut1' in members:
            learn('wan.pass-shadow.test', 1, f.DNS[0])
            learn('wan.pass-shadow.test', 1, f.DNS[0], wan=True)
            trial('wan', f.DNS[0], wan=True)
        assert observed_queues == {(member, i) for member in members for i in range(workers)}, observed_queues
        if enabled:
            assert len(observed_dns_cpus) >= workers, ('native decisions not observed on enough CPUs', observed_dns_cpus)
        print(json.dumps({'profile': profile, 'cases': cases, 'captured_queues_observed': sorted(observed_queues),
                          'sender_cpus': sender_cpus, 'dns_pass_cpus_observed': sorted(observed_dns_cpus)}), flush=True)


def compare(baseline, enabled):
    left, right = ([json.loads(line) for line in path.read_text().splitlines()] for path in (baseline, enabled))
    assert left[0]['executable_sha256'] == right[0]['executable_sha256']
    assert left[0]['bound_queues'] == right[0]['bound_queues']
    expected = ['missing', 'a', 'dns-dependent-port-53', 'static-port-53', 'aaaa', 'withdrawn',
                'conflict', 'before-expiry', 'expired']
    if 'dut1' in left[0]['bound_queues']:
        expected.append('wan')
    assert left[-1]['cases'] == right[-1]['cases'] == expected
    off = [row for row in left if 'case' in row]
    on = [row for row in right if 'case' in row]
    assert [row['case'] for row in off] == [row['case'] for row in on] == expected
    changed = []
    for a, b in zip(off, on, strict=True):
        assert a['program_id'] != b['program_id'] and a['origin'][0] == b['origin'][0]
        assert a['ingress'] == b['ingress'] and a['peer']['destination'] == b['peer']['destination']
        if a['peer']['inode'] != b['peer']['inode']:
            assert a['peer']['namespace'] == 'server' and b['peer']['namespace'] == 'shadow-wan'
            changed.append(b['case'])
    assert changed == ['a', 'aaaa', 'before-expiry'], changed
    print(json.dumps({'bound_queues': left[0]['bound_queues'], 'cases': expected, 'changed_peer': changed,
                      'enabled_capture_queues_observed': right[-1]['captured_queues_observed'],
                      'enabled_dns_pass_cpus_observed': right[-1]['dns_pass_cpus_observed']}), flush=True)
