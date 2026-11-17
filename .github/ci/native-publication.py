#!/usr/bin/env python3
"""Stop-file consumer for xdp-daemon-smoke; --self-test is host runnable (no BPF)."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import stat
import sys
import time

LIMIT = 8 << 20
IDENTITY = ('boot_id', 'pid', 'starttime_ticks', 'publication_serial', 'root_map_id')
DECIMALS = ('seq', 'operation_id', 'writer_id', 'epoch_before', 'epoch_after',
            'boottime_before_ns', 'boottime_after_ns', 'related_seq', 'counter_epoch',
            'counter_value', 'hook_id')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decimal(value):
    require(isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,19}', value)
            and int(value) < 1 << 64, 'invalid decimal u64: ' + repr(value))
    return int(value)


def unsigned(value, bits=32):
    require(type(value) is int and 0 <= value < 1 << bits, 'invalid unsigned integer')
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def boottime():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def durable(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value):
    durable(path, (json.dumps(value, sort_keys=True) + '\n').encode())


def artifact(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and info.st_size <= LIMIT, 'unsafe or oversized Native artifact')
        raw = source.read(LIMIT + 1)
        require(len(raw) <= LIMIT, 'oversized Native artifact')
    return raw


def results(log):
    text = re.sub(r'\x1b\[[0-9;]*m', '', Path(log).read_text())
    return [line for line in text.splitlines() if 'Native publication artifact result' in line]


def result(line):
    def field(name, pattern):
        match = re.search(r'(?<![\w])' + name + '=' + pattern + r'(?=\s|$)', line)
        require(match is not None, 'missing result field: ' + name)
        return match[1]
    value = {'export_publication_result': field('export_publication_result', r'"?([A-Z_]+)"?')}
    for name in ('path', 'sha256'):
        encoded = field(name, r'(None|Some\("(?:[^"\\]|\\.)*"\))')
        value[name] = None if encoded == 'None' else json.loads(encoded[5:-1])
    value['boot_id'] = field('boot_id', r'"?([0-9a-fA-F-]{36})"?')
    for name in ('pid', 'root_map_id', 'bytes', 'starttime_ticks', 'publication_serial', 'last_seq'):
        value[name] = int(field(name, r'([0-9]+)'))
    for name in ('final_export', 'complete'):
        value[name] = field(name, r'(true|false)') == 'true'
    # Error text is deliberately retained verbatim, including nested debug formatting.
    value['export_error'] = field('export_error', r'(.*?)(?= Native publication artifact result|$)')
    value['raw'] = line
    return value


def identity(document):
    value = {name: decimal(document[name]) if name in ('starttime_ticks', 'publication_serial')
             else document[name] for name in IDENTITY}
    require(isinstance(value['boot_id'], str)
            and re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', value['boot_id']), 'invalid boot identity')
    require(unsigned(value['pid']) > 0 and unsigned(value['root_map_id']) > 0
            and value['starttime_ticks'] > 0 and value['publication_serial'] > 0, 'missing publication identity')
    return value


def matches(value, binding):
    return all(value[name] == binding[name] for name in IDENTITY) and value['path'] == binding['path']


def published(value, raw, document, binding, final):
    require(matches(value, binding), 'publication result identity/path differs')
    require(value['export_publication_result'] == 'PUBLISHED_DURABLE'
            and value['export_error'] == 'None', 'export durability/error is incomplete')
    require(value['sha256'] == hashlib.sha256(raw).hexdigest()
            and value['bytes'] == len(raw), 'export digest/length differs')
    require(value['final_export'] is final and document['final'] is final
            and value['complete'] is document['complete']
            and value['last_seq'] == decimal(document['last_seq']), 'export result contradicts artifact')
    require(identity(document) == {name: binding[name] for name in IDENTITY}, 'artifact identity differs')


def limits(document):
    for name, expected in (('max_hooks', 32), ('max_targets', 16), ('data_dir_path_max_bytes', 1024)):
        require(unsigned(document[name]) == expected, 'unsupported manifest limit: ' + name)
    require(unsigned(document['hook_capacity']) == document['max_hooks'], 'contradictory hook capacity')


def captured_candidate_name(name):
    match = re.fullmatch(r'realm-(0|[1-9][0-9]{0,9})-gate-([1-9][0-9]{0,19})-([1-9][0-9]{0,19})-prog', name)
    require(match is not None, 'invalid canonical candidate basename')
    realm, epoch, candidate = (decimal(value) for value in match.groups())
    unsigned(realm)
    require(epoch & 1 == 0, 'canonical candidate epoch is not closed')
    return realm, epoch, candidate


def captured_inventory(document):
    raw = document.get('captured_realm_inventory')
    if raw is None:
        return None
    require(type(raw) is dict, 'invalid captured realm inventory')
    result = dict(raw)
    require(raw['status'] in ('Committed', 'Failed', 'Partial'), 'unknown captured publication attempt status')
    for name in ('return_attachment', 'inventory_seq', 'boottime_ns'):
        result[name] = decimal(raw[name])
        require(result[name] > 0, 'zero captured inventory identity/time')
    entries = raw['candidates']
    require(type(entries) is list and len(entries) <= 128, 'captured candidate inventory bound')
    result['candidates'] = []
    seen, paths, programs, per_realm = set(), set(), set(), {}
    for candidate in entries:
        entry = dict(candidate)
        entry['closed_epoch'] = decimal(candidate['closed_epoch'])
        realm, program = unsigned(entry['realm_index']), unsigned(entry['program_id'])
        path = entry['pin_path']
        require(entry['role'] == 'canonical_tap_gate' and program > 0
                and entry['state'] in ('Installed', 'retired-pending')
                and type(path) is str and len(path.encode()) <= 4096 and Path(path).is_absolute(), 'invalid captured realm candidate')
        key = captured_candidate_name(Path(path).name)
        require(key[:2] == (realm, entry['closed_epoch']), 'candidate generation/path differs')
        require(key not in seen and path not in paths and program not in programs, 'duplicate captured candidate identity/path/program')
        seen.add(key)
        paths.add(path)
        programs.add(program)
        states = per_realm.setdefault(realm, [])
        states.append(entry['state'])
        require(len(states) <= 2 and (raw['status'] != 'Committed' or states.count('Installed') <= 1), 'captured old/new candidate bound')
        result['candidates'].append(entry)
    return result


def require_finished_phase(event):
    fields = ('inventory_held', 'inventory_pending', 'inventory_flight', 'count_before', 'count_after')
    terminal, phase, outcome = event.get('terminal'), event.get('phase_after'), event['outcome']
    if outcome == 'Ambiguous':
        require(terminal is None and phase is None and all(event[name] is None for name in fields),
                'ambiguous operation carries settlement evidence')
        return
    require(type(terminal) is bool and type(phase) is int
            and all(event[name] is not None for name in fields), 'settled completion lacks factual state')
    allowed = {
        False: {'Transferred': {3, 4}, 'TakenOver': {1}, 'RefusedBeforeTransfer': {0, 2, 3, 4}, 'Disposed': {0, 1, 2, 3, 4}},
        True: {'Transferred': {2, 3}, 'TakenOver': {1}, 'RefusedBeforeTransfer': {0, 2, 3}, 'Disposed': {0, 1, 2, 3}},
    }
    require(phase in allowed[terminal][outcome], 'completion phase contradicts factual terminal state/outcome')
    if outcome == 'Transferred':
        require(event['entry_seq'] is not None and event['entry_seq'] > 0 and event['fresh_grace'] is True,
                'Transferred completion lacks entry and fresh Grace')
    elif outcome == 'RefusedBeforeTransfer':
        require(event['entry_seq'] is None and event['fresh_grace'] is True,
                'refused completion has entry or lacks joined fresh Grace')
    else:
        require(event['entry_seq'] is None and event['fresh_grace'] is None and event['related_seq'] is None,
                'local completion carries private transfer evidence')


def require_private_completion_proof(records, finished, evicted):
    by_seq = {event['seq']: event for event in records}
    done = by_seq.get(finished['related_seq'])
    started = by_seq.get(done['related_seq']) if done is not None else None
    entry = by_seq.get(started['related_seq']) if started is not None else None
    transferred = finished['outcome'] == 'Transferred'
    if done is None or started is None or transferred and entry is None:
        require(evicted > 0, 'private completion lacks recorded entry/fresh-Grace chain')
        return False
    require(done['kind'] == 'FRESH_GRACE_DONE' and done['fresh_grace'] is True
            and started['kind'] == 'FRESH_GRACE_STARTED', 'private completion references a different Grace')
    identity = ('key', 'claim_epoch', 'claim_incarnation', 'claim_scope', 'return_attachment', 'slot', 'op_incarnation',
                'producer_epoch', 'producer_incarnation', 'producer_flags', 'producer_expires_boottime_ns')
    require(all(finished[name] is not None for name in identity) and finished['slot'] == 0,
            'private completion operation identity is incomplete')
    chain = (entry, started, done, finished) if transferred else (started, done, finished)
    require(all(all(event[name] == finished[name] for name in identity) for event in chain),
            'private completion proof belongs to another operation/producer')
    require(all(left['seq'] < right['seq'] for left, right in zip(chain, chain[1:])), 'private completion proof sequence is reversed')
    require(all(event['boottime_ns'] is not None for event in chain)
            and all(left['boottime_ns'] <= right['boottime_ns'] for left, right in zip(chain, chain[1:])),
            'private completion proof lacks ordered BOOTTIME observations')
    if transferred:
        require(entry['kind'] == 'ENTRY_ACQUIRED' and entry['entry_seq'] == finished['entry_seq'],
                'Transferred completion references a different target entry')
    else:
        require(started['related_seq'] in (None, 0) and not any(event['kind'] == 'ENTRY_ACQUIRED'
                and all(event[name] == finished[name] for name in identity) for event in records),
                'refused operation has a target entry')
    return True


CAPTURED_DECIMALS = ('seq', 'claim_epoch', 'claim_incarnation', 'claim_scope',
    'producer_epoch', 'producer_incarnation', 'producer_expires_boottime_ns',
    'basis_epoch', 'routing_generation', 'mode_revision', 'fact_scope', 'fact_revision',
    'fact_horizon', 'return_attachment', 'slot', 'op_incarnation', 'entry_seq',
    'boottime_ns', 'related_seq', 'inventory_held', 'inventory_pending', 'inventory_flight',
    'count_before', 'count_after')
CAPTURED_KINDS = {'IMPORTED', 'CAPTURE_SELECTED', 'OPERATION_PREPARED', 'ENTRY_ACQUIRED',
    'FRESH_GRACE_STARTED', 'FRESH_GRACE_DONE', 'ORIGINAL_FINISHED', 'CAPTURED_JOINED_ACK'}


def captured_receipts(document):
    raw = document.get('captured_receipts')
    if raw is None:
        return {'status': 'NOT_RUN', 'reason': 'production captured receipt array absent', 'samples': []}
    require(type(raw) is list and len(raw) <= 256, 'invalid captured receipt bound')
    evicted = decimal(document['captured_receipts_evicted'])
    records = []
    last = 0
    for value in raw:
        require(type(value) is dict, 'captured receipt is not an object')
        event = dict(value)
        require(event['kind'] in CAPTURED_KINDS, 'unknown captured receipt kind')
        for name in CAPTURED_DECIMALS:
            event[name] = None if value[name] is None else decimal(value[name])
        require(event['seq'] is not None and event['seq'] > last, 'captured receipt sequence regressed')
        last = event['seq']
        for name in ('producer_flags', 'basis_flags'):
            if event[name] is not None:
                unsigned(event[name])
        require(event['producer_flags'] is None or event['producer_flags'] & ~1 == 0, 'unknown captured producer flags')
        require(event['fresh_grace'] is None or type(event['fresh_grace']) is bool, 'invalid fresh Grace outcome')
        allowed_outcomes = {'CAPTURE_SELECTED': {'CaptureCommitted', 'AlreadyCommitted'},
                            'ORIGINAL_FINISHED': {'Transferred', 'RefusedBeforeTransfer', 'Ambiguous', 'Disposed', 'TakenOver'}}
        if event['kind'] in allowed_outcomes:
            require(event.get('outcome') in allowed_outcomes[event['kind']], 'invalid outcome for captured record kind')
        else:
            require('outcome' not in event, 'milestone carries an outcome')
            event['outcome'] = None
        handle = event['completion_handle']
        if handle is not None:
            require(type(handle) is list and len(handle) == 4, 'invalid retained Port identity')
            event['completion_handle'] = [decimal(part) for part in handle]
            require(event['completion_handle'][0] > 0 and event['completion_handle'][1] > 0 and event['completion_handle'][3] > 0, 'zero retained Port generation')
        phase = event.get('phase_after')
        require(phase is None or type(phase) is int and 0 <= phase <= 5, 'invalid completion phase')
        inventory_fields = ('inventory_held', 'inventory_pending', 'inventory_flight', 'count_before', 'count_after')
        if event['kind'] != 'ORIGINAL_FINISHED':
            require(phase is None and event.get('terminal') is None and all(event[name] is None for name in inventory_fields), 'unrelated receipt carries completion inventory')
        else:
            require_finished_phase(event)
            require(event['inventory_flight'] in (None, 0, 1), 'invalid completion private-flight inventory')
            if all(event[name] is not None for name in inventory_fields):
                require(0 <= event['count_after'] <= event['count_before'] < 1 << 28, 'invalid completion credit transition')
                if event['producer_flags'] is not None:
                    require(event['count_before'] - event['count_after'] == event['producer_flags'] & 1, 'completion spent a different producer credit')
                if phase == 4:
                    require(event['count_after'] == event['inventory_held'] == event['inventory_pending'] == event['inventory_flight'] == 0, 'Active completion retains an original or flight')
        fingerprint = event['routing_fingerprint']
        require(fingerprint is None or type(fingerprint) is list and len(fingerprint) == 32
                and all(type(n) is int and 0 <= n <= 255 for n in fingerprint), 'invalid captured policy fingerprint')
        if event['kind'] == 'CAPTURED_JOINED_ACK':
            filename, digest = event.get('joined_receipt_file'), event.get('terminal_inventory_sha256')
            require(type(filename) is str and 1 <= len(filename.encode()) <= 255
                    and Path(filename).name == filename and '/' not in filename, 'invalid joined receipt filename')
            require(event['return_attachment'] is not None and event['return_attachment'] > 0
                    and type(digest) is list and len(digest) == 32
                    and all(type(n) is int and 0 <= n <= 255 for n in digest), 'invalid joined receipt acknowledgement')
        else:
            require(event.get('joined_receipt_file') is None and event.get('terminal_inventory_sha256') is None, 'unrelated receipt carries joined acknowledgement')
        key = event['key']
        if key is not None:
            require(type(key) is dict, 'invalid captured key')
            for name in ('src_ip', 'dst_ip'):
                require(type(key[name]) is list and len(key[name]) == 4, 'incomplete captured address')
                for word in key[name]:
                    unsigned(word)
            for name in ('src_port', 'dst_port', 'zone'):
                unsigned(key[name], 16)
            require(key['l4proto'] in (6, 17) and key['ip_version'] in (4, 6)
                    and key['domain'] == key['direction'] == key['zone'] == 0
                    and key['zone_state'] == 2 and decimal(key['namespace_cookie']) > 0
                    and key['reserved'] == [0] * 5, 'invalid Transit receipt key')
        records.append(event)
    unproven_private = []
    for finished in records:
        if finished['kind'] == 'ORIGINAL_FINISHED' and finished['outcome'] in ('Transferred', 'RefusedBeforeTransfer'):
            if not require_private_completion_proof(records, finished, evicted):
                unproven_private.append(str(finished['seq']))
    samples = []
    for prepared in (event for event in records if event['kind'] == 'OPERATION_PREPARED'):
        fields = ('key', 'claim_epoch', 'claim_incarnation', 'claim_scope')
        missing = [name for name in fields if prepared[name] is None]
        operation = ('return_attachment', 'op_incarnation', 'slot')
        missing += [name for name in operation if prepared[name] is None]
        report = {'prepare_seq': str(prepared['seq']), 'status': 'NOT_RUN', 'missing': missing,
                  'entry_and_fresh_grace': 'NOT_RUN', 'records': []}
        samples.append(report)
        if missing:
            continue
        require(prepared['slot'] == 0 and prepared['op_incarnation'] > 0 and prepared['return_attachment'] > 0, 'invalid operation identity')
        def same_claim(event):
            return all(event[name] == prepared[name] for name in fields)
        selected = [event for event in records if same_claim(event) and
                    all(event[name] == prepared[name] for name in operation) and event['kind'] != 'IMPORTED']
        report['records'] = [str(event['seq']) for event in selected]
        required = ('OPERATION_PREPARED', 'ENTRY_ACQUIRED', 'FRESH_GRACE_STARTED', 'FRESH_GRACE_DONE', 'ORIGINAL_FINISHED')
        by_kind = {kind: [event for event in selected if event['kind'] == kind] for kind in required}
        absent = [kind for kind, events in by_kind.items() if len(events) != 1]
        if absent:
            report['missing'] += absent
            continue
        prepared, entry, started, done, finished = (by_kind[kind][0] for kind in required)
        producer = ('producer_epoch', 'producer_incarnation', 'producer_flags', 'producer_expires_boottime_ns')
        if finished['completion_handle'] is None or any(finished[name] is None for name in producer):
            report['missing'].append('actual imported Port generation/producer identity')
            continue
        imports = [event for event in records if event['kind'] == 'IMPORTED' and same_claim(event)
                   and event['completion_handle'] == finished['completion_handle']
                   and all(event[name] == finished[name] for name in producer)]
        if len(imports) != 1:
            report['missing'].append('unique IMPORTED with the completed Port generation and producer identity')
            continue
        imported = imports[0]
        report['records'].insert(0, str(imported['seq']))
        require(all(prepared[name] == finished[name] for name in producer), 'producer identity changed at operation preparation')
        require(imported['seq'] < prepared['seq'] < entry['seq'] < started['seq'] < done['seq'] < finished['seq'], 'captured completion preceded actual entry/fresh Grace')
        require(started['related_seq'] == entry['seq'] and done['related_seq'] == started['seq'], 'fresh Grace is not associated with this entry')
        if any(event['boottime_ns'] is None for event in (entry, started, done)):
            report['missing'].append('entry/fresh-Grace BOOTTIME observations')
            continue
        require(entry['boottime_ns'] <= started['boottime_ns'] <= done['boottime_ns'], 'fresh Grace time preceded observed entry')
        require(entry['entry_seq'] is not None and entry['entry_seq'] > 0
                and finished['entry_seq'] == entry['entry_seq'], 'entry receipt changed across completion')
        require(finished['related_seq'] == done['seq'], 'completion is not associated with this fresh Grace')
        if finished['completion_handle'] is None:
            report['missing'].append('actual completion Port generation')
            continue
        report['completion_handle'] = [str(part) for part in finished['completion_handle']]
        inventory_fields = ('inventory_held', 'inventory_pending', 'inventory_flight', 'count_before', 'count_after')
        report['completion_inventory'] = {name: None if finished[name] is None else str(finished[name]) for name in inventory_fields}
        report['phase_after'] = finished.get('phase_after')
        report['terminal'] = finished.get('terminal')
        if finished['outcome'] != 'Transferred' or done['fresh_grace'] is not True or finished['fresh_grace'] is not True:
            report['missing'].append('successful transfer and newly completed Grace')
            continue
        report['entry_and_fresh_grace'] = 'PASS'
        # These observations require the fixture's independent packet/wire evidence.
        report['missing'] += ['source/daemon/object hashes and Copy/physical-ZC lane',
            'sample/frame digest and complete RX descriptor extent', 'zero pre-selection consumer mutation deltas',
            'loaded operation/program/link inventory', 'peer bytes/source/TTL/NAT/CT oracle',
            'full-chain release and count/Draining/Active/physical-PASS observations']
    return {'status': 'NOT_RUN', 'reason': 'full independent packet oracle required',
            'evicted': str(evicted), 'record_count': len(records), 'samples': samples,
            'unproven_private_completions': unproven_private,
            'entry_and_fresh_grace': 'PASS' if evicted == 0 and not unproven_private and any(sample['entry_and_fresh_grace'] == 'PASS' for sample in samples) else 'NOT_RUN'}


def captured_schedule(document, schedule):
    require(schedule['schema'] == 'native-captured-schedule/v1' and schedule['clock_id'] == 'CLOCK_BOOTTIME'
            and schedule['unit'] == 'ns', 'unsupported captured schedule schema/clock')
    require(schedule['profile'] in ('native', 'native-nat'), 'unsupported captured schedule profile')
    publication = schedule['publication_identity']
    require(publication['pid'] == document['pid']
            and str(publication['starttime_ticks']) == document['starttime_ticks']
            and publication['root_map_id'] == document['root_map_id']
            and publication['source_sha'] == document['source_sha'], 'captured schedule publication identity differs')
    old_epoch = decimal(schedule['old_root']['epoch'])
    acknowledged = decimal(schedule['final_reload_ack_boottime_ns'])
    require(old_epoch > 0 and old_epoch & 1 and decimal(schedule['final_reload_started_boottime_ns']) <= acknowledged,
            'invalid captured schedule publication bracket')
    attempts = schedule['attempts']
    cases = ('tcp', 'udp-connected', 'udp-unconnected', 'udp-empty-connected',
             'udp-empty-unconnected', 'udp-jumbo', 'udp-unconnected-two-targets')
    require(type(attempts) is list and len(attempts) == 14
            and {(attempt['family'], attempt['case']) for attempt in attempts} == {(family, case) for family in (4, 6) for case in cases}
            and len({(attempt['family'], tuple(attempt['source'])) for attempt in attempts}) == 14, 'captured finite matrix differs')
    causality = captured_receipts(document)
    raw = {event['seq']: event for event in document.get('captured_receipts', [])}
    samples = []
    for attempt in attempts:
        family = attempt['family']
        require(family in (4, 6) and type(attempt['targets']) is list
                and len(attempt['targets']) == (2 if attempt['case'] == 'udp-unconnected-two-targets' else 1),
                'invalid captured input family/target bound')
        source = attempt['source']
        require(type(source) is list and len(source) == 2, 'missing actual scheduled socket identity')
        for target in attempt['targets']:
            destination = target['target']
            payload = bytes.fromhex(target['payload'])
            require(len(payload) == target['payload_length'] and hashlib.sha256(payload).hexdigest() == target['payload_sha256'],
                    'scheduled input payload identity differs')
            require(('empty' not in attempt['case'] or len(payload) == 0)
                    and (attempt['case'] != 'udp-jumbo' or len(payload) == 8192), 'empty/jumbo matrix extent differs')
            matches = []
            for proof in causality['samples']:
                if proof['entry_and_fresh_grace'] != 'PASS':
                    continue
                prepared = raw[proof['prepare_seq']]
                imported = raw[proof['records'][0]]
                key = prepared['key']
                address_family = socket.AF_INET if family == 4 else socket.AF_INET6
                def address(words):
                    value = b''.join(struct.pack('=I', word) for word in words)
                    return value[12:] if family == 4 else value
                if (key['ip_version'] != family or key['l4proto'] != (6 if attempt['case'] == 'tcp' else 17)
                        or address(key['src_ip']) != socket.inet_pton(address_family, source[0])
                        or address(key['dst_ip']) != socket.inet_pton(address_family, destination[0])
                        or socket.ntohs(key['src_port']) != source[1] or socket.ntohs(key['dst_port']) != destination[1]):
                    continue
                if (decimal(imported['producer_epoch']) != old_epoch or decimal(imported['claim_epoch']) != old_epoch
                        or imported['producer_flags'] != 1 or imported['boottime_ns'] is None
                        or decimal(imported['boottime_ns']) < acknowledged
                        or decimal(prepared['basis_epoch']) <= old_epoch):
                    continue
                matches.append(proof)
            sample = {'label': attempt['label'], 'family': family, 'case': attempt['case'],
                      'target_index': target['target_index'], 'fixture_input': dict(source=source, **target),
                      'status': 'NOT_RUN', 'capture_status': 'NOT_EXERCISED', 'proofs': matches,
                      'source_sha': document['source_sha'], 'executable_sha256': publication['executable_sha256'],
                      'copy_or_physical_zc': schedule['copy_or_physical_zc'], 'kernel_release': schedule['kernel_release'],
                      'missing': ['complete captured frame/descriptor digest', 'zero pre-selection initializer/dial/Core counter deltas']}
            samples.append(sample)
            if len(matches) != 1:
                sample['reason'] = 'no unique capture-before/change/import-after operation with matching Port generation and fresh Grace'
                continue
            proof = matches[0]
            sample['production_receipts'] = [raw[seq] for seq in proof['records']]
            sample['capture_status'] = 'EXERCISED'
            number = family
            peer_source = ('203.0.113.1' if number == 4 else 'fd00:99::1') if schedule['profile'] == 'native-nat' else source[0]
            events = [event for event in schedule['peer_events'] if event.get('kind') == 'received'
                      and event['family'] == family and event['peer'] == [peer_source, source[1]]
                      and event['target_port'] == destination[1] and event['payload'] == target['payload']]
            destination_wire = '198.51.100.2' if family == 4 else 'fd00:2::2'
            frames = [frame for frame in schedule['peer_wire'] if frame['family'] == family
                      and frame['sport'] == source[1] and frame['dport'] == destination[1]]
            wire_ok = bool(frames) and all(frame['source'] == peer_source and frame['target'] == destination_wire and frame['ttl'] == 36 for frame in frames)
            if attempt['case'] == 'tcp':
                wire_ok = wire_ok and sum(frame['syn'] for frame in frames) == 1 and b''.join(bytes.fromhex(frame['payload']) for frame in frames) == payload
            else:
                wire_ok = wire_ok and len(frames) == 1 and frames[0]['payload'] == target['payload']
            sample['peer_events'], sample['peer_wire'] = events, frames
            sample['child_status'], sample['returncode'] = attempt['child_status'], attempt['returncode']
            sample['captured_entry_fresh_grace_peer'] = 'PASS' if attempt['returncode'] == 0 and len(events) == 1 and wire_ok else 'FAIL'
    exercised = all(sample['capture_status'] == 'EXERCISED' and sample.get('captured_entry_fresh_grace_peer') == 'PASS' for sample in samples)
    return {'status': 'NOT_RUN', 'capture_matrix': 'EXERCISED' if exercised else 'NOT_EXERCISED',
            'samples': samples, 'all65': 'NOT_RUN', 'negative_writev_after_admission': schedule['negative_writev'],
            'captured_reverse_and_nat_reply': {'status': 'NOT_RUN',
                'reason': 'M25: Transit import cannot authenticate CT-ORIGINAL-keyed reverse/translated input; seam extension pending user decision',
                'oracle': 'actual captured reverse ingress; original/reply CT and aliases; source/bytes/TTL/NAT/ICMP/fragment semantics; ordered followers and exact custody'},
            'reason': 'full independent original extent and pre-selection consumer observations remain required'}


def captured_joined_ack(document, filename, attachment, digest_hex):
    captured_receipts(document)
    require(type(attachment) is int and attachment > 0, 'invalid joined attachment')
    require(type(digest_hex) is str and re.fullmatch('[0-9a-f]{64}', digest_hex), 'invalid joined receipt digest')
    expected = list(bytes.fromhex(digest_hex))
    acknowledgements = [event for event in document.get('captured_receipts', [])
                        if event['kind'] == 'CAPTURED_JOINED_ACK'
                        and decimal(event['return_attachment']) == attachment
                        and event['joined_receipt_file'] == filename]
    require(len(acknowledgements) == 1, 'missing or ambiguous captured joined acknowledgement')
    ack = acknowledgements[0]
    require(ack['terminal_inventory_sha256'] == expected, 'captured joined acknowledgement digest differs')
    return {'seq': ack['seq'], 'return_attachment': str(attachment),
            'joined_receipt_file': filename, 'sha256': digest_hex}


def validate(document, binding, shutdown_ns, collected_ns, reasons=()):
    limits(document)
    require(document['schema'] == 'native-publication/v1'
            and document['clock_id'] == 'CLOCK_BOOTTIME' and document['unit'] == 'ns', 'unsupported schema/clock')
    require(identity(document) == {name: binding[name] for name in IDENTITY}, 'artifact identity differs')
    require(document['durability_evidence'] == 'REQUIRES_MATCHING_EXTERNAL_PUBLISHED_DURABLE_RESULT', 'unsupported durability contract')
    for name in ('final', 'complete', 'terminal', 'hooks_joined', 'all_counters_sealed'):
        require(document[name] is True, 'incomplete header: ' + name)
    for name in ('failed', 'recording_error', 'clock_error', 'accounting_error', 'counter_overflow', 'export_error'):
        require(document[name] is False, 'faulted header: ' + name)
    for name in ('ready', 'capture_ready'):
        require(type(document[name]) is bool, 'invalid state boolean')
    require(document['incomplete_reasons'] == [], 'incomplete reason codes')
    require(decimal(document['initial_epoch']) == 0 and unsigned(document['initial_flags']) == 0, 'invalid initial state')
    unsigned(document['final_flags'])
    start, end = decimal(document['collection_start_ns']), decimal(document['collection_end_ns'])
    require(start <= binding['attempts_after_ns'] <= shutdown_ns <= end <= collected_ns, 'collection does not cover attempts and joined stop')
    events, hooks = document['events'], document['hooks']
    require(type(events) is list and 0 < len(events) <= unsigned(document['ring_capacity']) <= 4096, 'invalid event capacity')
    require(type(hooks) is list and 0 < len(hooks) <= unsigned(document['hook_capacity']) <= 32, 'missing hook identities')
    last = decimal(document['last_seq'])
    require(decimal(document['first_retained_seq']) == 1 and last == len(events)
            and decimal(document['total_appended']) == last and decimal(document['overwritten_events']) == 0, 'whole history was lost')
    parsed = []
    frontier = start
    for index, raw in enumerate(events, 1):
        event = dict(raw)
        for name in DECIMALS:
            event[name] = decimal(raw[name])
        for name in ('kind', 'reason', 'outcome', 'flags', 'version'):
            unsigned(event[name])
        require(event['seq'] == index and 1 <= event['kind'] <= 13 and event['version'] == 1,
                'invalid sequence/kind/version')
        require(event['flags'] & ~511 == 0 and event['reserved'] == [0] * 24
                and all(type(n) is int for n in event['reserved']), 'unsupported flags/reserved bytes')
        require(event['outcome'] <= 2 and event['reason'] <= 14, 'unknown outcome/reason')
        if event['kind'] in (5, 6, 7, 9, 10, 11, 12):
            require(event['outcome'] in (1, 2), 'settled event has pending outcome')
        require(event['kind'] not in (3, 7) or event['reason'] != 0, 'missing writer reason')
        require(not event['flags'] & 1 or event['boottime_before_ns'] <= event['boottime_after_ns'], 'reversed timestamp bracket')
        if event['flags'] & 1:
            require(start <= event['boottime_after_ns'] <= end, 'timestamp outside collection')
            require(event['boottime_after_ns'] >= frontier, 'BOOTTIME frontiers moved backwards')
            if event['kind'] in (5, 9):
                require(event['boottime_before_ns'] >= frontier, 'store bracket precedes previous frontier')
            frontier = event['boottime_after_ns']
        if event['kind'] == 13:
            require(decimal(raw['old_program_id']) == event['counter_value']
                    and decimal(raw['new_program_id']) == event['counter_epoch'], 'replacement aliases differ')
        else:
            require(raw['old_program_id'] is None and raw['new_program_id'] is None, 'unexpected program aliases')
        applicable = {
            1: {'boottime_before_ns', 'boottime_after_ns'},
            2: {'hook_id', 'counter_epoch'},
            3: {'operation_id', 'writer_id'},
            4: {'operation_id', 'writer_id', 'epoch_before', 'epoch_after'},
            5: {'operation_id', 'writer_id', 'epoch_before', 'epoch_after', 'related_seq', 'boottime_before_ns', 'boottime_after_ns'},
            6: {'operation_id', 'writer_id', 'epoch_before', 'epoch_after', 'related_seq', 'boottime_after_ns'},
            7: {'operation_id', 'writer_id', 'epoch_after', 'counter_value'},
            8: {'operation_id', 'writer_id', 'epoch_before', 'epoch_after'},
            9: {'operation_id', 'writer_id', 'epoch_before', 'epoch_after', 'related_seq', 'boottime_before_ns', 'boottime_after_ns'},
            10: {'operation_id', 'related_seq', 'counter_epoch', 'counter_value', 'hook_id'},
            11: {'operation_id', 'writer_id', 'epoch_before', 'epoch_after', 'related_seq', 'boottime_after_ns'},
            12: {'epoch_before', 'epoch_after', 'boottime_after_ns'},
            13: {'operation_id', 'writer_id', 'hook_id', 'counter_epoch', 'counter_value'},
        }
        require(all(event[n] == 0 for n in DECIMALS if n != 'seq' and n not in applicable[event['kind']]),
                'nonzero event-inapplicable field')
        if event['kind'] in (1, 2, 3, 4, 8):
            require(event['outcome'] == 0, 'unexpected milestone outcome')
        if event['kind'] in (2, 3, 4, 8, 11, 13):
            require(event['flags'] == 0, 'unexpected milestone flags')
        parsed.append(event)
    by_seq = {e['seq']: e for e in parsed}
    registered, targets, programs, pending = {}, {}, {}, {}
    begins, outcomes, roots, intents, stores, drains, counters = {}, {}, {}, {}, {}, [], {}
    boundaries = {0: parsed[0]}
    epoch, failed = 0, False
    for e in parsed:
        kind, op, writer, seq = (e[n] for n in ('kind', 'operation_id', 'writer_id', 'seq'))
        if e['hook_id']:
            require(kind == 2 or e['hook_id'] in registered, 'event references unregistered hook')
        if kind == 1:
            require(seq == 1 and e['epoch_before'] == e['epoch_after'] == 0
                    and e['flags'] == 1 and e['boottime_after_ns'] == start, 'invalid initial marker')
        elif kind == 2:
            require(epoch % 2 == 0 and e['hook_id'] and e['hook_id'] not in registered, 'duplicate/open/missing hook registration')
            registered[e['hook_id']] = e
        elif kind == 3:
            require(op and writer and op not in begins, 'duplicate/missing writer identity')
            root = roots.get(writer)
            require(root is None or root not in outcomes, 'participant references settled root writer')
            roots.setdefault(writer, op)
            begins[op] = e
        elif kind in (4, 8):
            require(op and (op, kind) not in intents and e['epoch_before'] == epoch, 'unmatched intent')
            intents[op, kind] = e
        elif kind in (5, 9):
            intent = intents.get((op, 4 if kind == 5 else 8))
            require(intent is not None and e['related_seq'] == intent['seq']
                    and all(e[n] == intent[n] for n in ('writer_id', 'reason', 'epoch_before', 'epoch_after'))
                    and e['epoch_before'] == epoch and e['flags'] == 1 and e['outcome'] == 1
                    and (op, kind) not in stores, 'store differs from intent/current epoch')
            if kind == 5:
                require(e['epoch_after'] == epoch + (1 if epoch % 2 else 2), 'invalid close epoch')
                boundaries[e['epoch_after']] = e
            else:
                outcome = outcomes.get(op)
                require(not failed and not pending and epoch % 2 == 0 and e['epoch_after'] == epoch + 1
                        and outcome is not None and outcome['writer_id'] == writer
                        and outcome['outcome'] == 1 and outcome['flags'] == 0
                        and begins.keys() == outcomes.keys(), 'invented reopen after failed/pending writer')
                require(any(d['related_seq'] == boundaries[epoch]['seq'] for d in drains), 'reopen lacks successful grace')
            stores[op, kind] = e
            epoch = e['epoch_after']
        elif kind == 6:
            boundary = by_seq.get(e['related_seq'])
            require(boundary is not None and boundary['kind'] in (1, 5)
                    and boundary['seq'] < seq and boundary['epoch_after'] == e['epoch_after'] == epoch
                    and e['flags'] == 1 and e['outcome'] == 1
                    and e['boottime_after_ns'] >= boundary['boottime_after_ns'], 'invalid grace completion')
            require((e['operation_id'] == boundary['operation_id']
                     and e['writer_id'] == boundary['writer_id'] and e['reason'] == boundary['reason'])
                    or (e['operation_id'] != boundary['operation_id'] and e['writer_id'] == 0),
                    'grace identity differs from close or independent drain')
            drains.append(e)
        elif kind == 7:
            begin = begins.get(op)
            require(begin is not None and op not in outcomes and e['writer_id'] == begin['writer_id']
                    and (roots.get(writer) == op or roots.get(writer) not in outcomes)
                    and e['reason'] == begin['reason'] and e['outcome'] in (1, 2), 'unmatched/non-live writer outcome')
            outcomes[op] = e
            failed |= e['outcome'] == 2
        elif kind == 10:
            tag, hook = e['counter_epoch'], e['hook_id']
            boundary = boundaries.get(tag)
            require(hook in registered and boundary is not None and e['related_seq'] == boundary['seq']
                    and e['operation_id'] == boundary['operation_id'] and tag % 2 == 0
                    and e['flags'] == 2 and e['outcome'] == 1 and (hook, tag) not in counters,
                    'invalid/duplicate closed counter finalization')
            require(any(d['seq'] > boundary['seq'] and d['seq'] < seq
                        and (d['epoch_after'] != tag or (d['reason'] == 10 and d['writer_id'] == 0
                             and d['seq'] > max((t['seq'] for t in parsed if t['kind'] == 11 and t['seq'] < seq), default=seq)))
                        for d in drains), 'counter finalized before sealing grace/join')
            counters[hook, tag] = e
        elif kind == 11:
            require(e['outcome'] == 1 and e['epoch_after'] == epoch and epoch % 2 == 0
                    and any(d['operation_id'] == op and d['epoch_after'] == epoch for d in drains), 'terminal lacks successful close/grace')
        elif kind == 12:
            require(seq == last and e['outcome'] == 1 and e['flags'] == 1
                    and e['epoch_after'] == epoch and e['boottime_after_ns'] == end
                    and any(t['kind'] == 11 and t['seq'] < seq and t['epoch_after'] == epoch for t in parsed), 'missing actual terminal collection end')
        elif kind == 13:
            hook = e['hook_id']
            require(epoch % 2 == 0 and op in begins and begins[op]['writer_id'] == writer
                    and roots.get(writer) not in outcomes and op not in outcomes
                    and e['reason'] == begins[op]['reason'], 'replacement outside live closed writer')
            old = programs.get(hook, registered[hook]['counter_epoch'])
            require(e['counter_value'] == old and 0 < e['counter_epoch'] < 1 << 32
                    and old != e['counter_epoch'], 'broken old/new program chain')
            if e['outcome'] == 0:
                require(hook not in pending, 'overlapping replacement')
                pending[hook] = e
            else:
                intent = pending.pop(hook, None)
                require(intent is not None and e['outcome'] == 1
                        and all(e[n] == intent[n] for n in ('operation_id', 'writer_id', 'reason', 'counter_value', 'counter_epoch')),
                        'failed/unmatched replacement cannot be complete')
                programs[hook] = e['counter_epoch']
    require(parsed[-1]['kind'] == 12 and epoch == decimal(document['final_epoch'])
            and epoch % 2 == 0 and not pending and not failed, 'contradictory final epoch/end/failure')
    require(begins and begins.keys() == outcomes.keys(), 'unsettled/missing writers')
    require(stores and any(k == 5 for _, k in stores) and any(k == 9 for _, k in stores), 'empty actual close/reopen selection')
    for (op, kind), intent in intents.items():
        require((op, 5 if kind == 4 else 9) in stores, 'intent missing store')
    for (op, kind), store in stores.items():
        if kind == 5:
            require(any(d['operation_id'] == op and d['related_seq'] == store['seq'] for d in drains), 'store missing grace')
    seen, map_targets = set(), {}
    for raw in hooks:
        h = dict(raw)
        for name in ('hook_id', 'target_serial', 'scope', 'namespace_cookie', 'attachment_generation',
                     'registered_seq', 'publication_serial', 'current_attachment_generation'):
            h[name] = decimal(h[name])
        for name in ('kind', 'ifindex', 'counter_map_id', 'initial_program_id', 'current_program_id'):
            unsigned(h[name])
        hid, target = h['hook_id'], h['target_serial']
        require(hid and hid not in seen and hid in registered and h['kind'] in (0, 1)
                and all(h[n] for n in ('target_serial', 'namespace_cookie', 'ifindex', 'attachment_generation', 'counter_map_id'))
                and h['publication_serial'] == binding['publication_serial'], 'invalid/duplicate hook identity')
        seen.add(hid)
        registration = registered[hid]
        require(registration['seq'] == h['registered_seq'] and registration['counter_epoch'] == h['initial_program_id'], 'registration identity differs')
        replacements = [e for e in parsed if e['kind'] == 13 and e['hook_id'] == hid and e['outcome'] == 1]
        require(h['current_program_id'] == programs.get(hid, h['initial_program_id']) != 0
                and h['current_attachment_generation'] == h['attachment_generation'] + len(replacements), 'final program/generation differs')
        require(map_targets.setdefault(h['counter_map_id'], target) == target,
                'counter map aliases distinct targets')
        siblings = targets.setdefault(target, [])
        require(not any(s['kind'] == h['kind'] for s in siblings), 'duplicate target hook kind')
        if siblings:
            require(all(h[n] == siblings[0][n] for n in ('scope', 'namespace_cookie', 'ifindex', 'counter_map_id')), 'target identity differs across hooks')
        siblings.append(h)
        at_registration = max(tag for tag, b in boundaries.items() if b['seq'] < registration['seq'])
        expected = {tag for tag in boundaries if tag >= at_registration}
        actual = {tag for hook, tag in counters if hook == hid}
        require(actual == expected, 'missing/extra counter generations for registered hook')
    require(seen == registered.keys() and all({h['kind'] for h in group} == {0, 1} for group in targets.values()), 'incomplete XDP/TCX identity coverage')
    require(len(targets) <= document['max_targets'], 'target table exceeds declared limit')
    for reason in reasons:
        selected = [e for e in outcomes.values() if e['reason'] == reason and e['outcome'] == 1]
        require(selected, 'empty expected successful writer reason: ' + str(reason))
        require(any((e['operation_id'], 5) in stores or any(s['writer_id'] == e['writer_id'] for s in stores.values()) for e in selected), 'writer reason lacks actual store linkage')
    return {'events': last, 'hooks': len(hooks), 'closed_counter_finalizations': len(counters),
            'closed_hook_executions': str(sum(e['counter_value'] for e in counters.values())),
            'successful_writer_reasons': sorted({e['reason'] for e in outcomes.values() if e['outcome'] == 1}),
            'packet_causality': captured_receipts(document),
            'captured_realm_inventory': captured_inventory(document)}


def checkpoint_path(binding):
    path = Path(binding['path'])
    expected = f"{binding['pid']}-{binding['starttime_ticks']}-{binding['publication_serial']}.json"
    require(path.is_absolute() and path.name == expected and path.parent.name == 'native-publication',
            'unexpected artifact path')
    return str(path.parent.with_name('native-publication-initial') / path.name)


def initial_checkpoint(binding, raw):
    require(binding['checkpoint_path'] == checkpoint_path(binding), 'checkpoint path differs from owner')
    require(binding['sha256'] == hashlib.sha256(raw).hexdigest() and binding['bytes'] == len(raw),
            'initial checkpoint digest/length differs')
    document = decode(raw)
    require(identity(document) == {name: binding[name] for name in IDENTITY}, 'checkpoint identity differs')
    limits(document)
    path = Path(binding['path'])
    require(path.parent.parent.name == 'state'
            and len(os.fsencode(str(path.parents[2]))) <= document['data_dir_path_max_bytes'],
            'artifact path exceeds or contradicts declared data-directory contract')
    require(document['schema'] == 'native-publication/v1' and document['clock_id'] == 'CLOCK_BOOTTIME'
            and document['unit'] == 'ns' and document['final'] is False and document['complete'] is False
            and document['hooks'] == [] and len(document['events']) == 1
            and document['events'][0]['kind'] == 1 and decimal(document['events'][0]['seq']) == 1
            and decimal(document['events'][0]['epoch_before']) == 0
            and decimal(document['events'][0]['epoch_after']) == 0
            and decimal(document['initial_epoch']) == 0 and unsigned(document['initial_flags']) == 0
            and decimal(document['final_epoch']) == 0 and unsigned(document['final_flags']) == 0
            and document['terminal'] is False and document['ready'] is False
            and document['capture_ready'] is False and decimal(document['last_seq']) == 1,
            'initial manifest was not before attachment')
    return document


def same_owner(candidates, binding):
    require(all(matches(value, binding) for value in candidates if value['pid'] == binding['pid']),
            'conflicting same-PID publication identity/path')


def startup_result(candidates, pid):
    matching = [value for value in candidates if value['pid'] == pid and not value['final_export']]
    require(matching, 'startup publication result is absent')
    binding = matching[0].copy()
    same_owner(candidates, binding)
    binding['checkpoint_path'] = checkpoint_path(binding)
    require(binding['export_publication_result'] == 'PUBLISHED_DURABLE'
            and binding['export_error'] == 'None', 'initial publication failed')
    return binding


def bind(log, pid, prefix):
    pid = int(pid)
    lines = results(log)
    binding = startup_result([result(line) for line in lines], pid)
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == binding['boot_id'], 'boot identity differs')
    process = Path(f'/proc/{pid}')
    require(int((process / 'stat').read_text().rsplit(')', 1)[1].split()[19]) == binding['starttime_ticks'], 'process starttime differs')
    binding['executable_sha256'] = hashlib.sha256((process / 'exe').read_bytes()).hexdigest()
    owned = {'map_id': set(), 'prog_id': set()}
    for entry in (process / 'fdinfo').iterdir():
        try:
            text = entry.read_text()
        except FileNotFoundError:
            continue
        for name in owned:
            owned[name].update(int(value) for value in re.findall(r'^' + name + r':\s*([0-9]+)\s*$', text, re.M))
    require(binding['root_map_id'] in owned['map_id'], 'root map not held by bound daemon')
    binding['owned_map_ids'] = sorted(owned['map_id'])
    binding['owned_program_ids'] = sorted(owned['prog_id'])
    binding['ifindices'] = [socket.if_nametoindex(name) for name in ('dut0', 'dut1')]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        binding['namespace_cookie'] = struct.unpack('=Q', probe.getsockopt(socket.SOL_SOCKET, 71, 8))[0]
    raw = artifact(binding['checkpoint_path'])
    document = initial_checkpoint(binding, raw)
    published(binding, raw, document, binding, False)
    durable(prefix + '.initial.json', raw)
    binding['build_version'] = document['build_version']
    binding['source_sha'] = document['source_sha']
    binding['attempts_after_ns'] = boottime()
    binding['startup_result_count'] = len(lines)
    save(prefix + '.binding.json', binding)


def collect(log, prefix, daemon_status, reasons):
    """Retain available inputs independently; only bound durable final evidence can validate."""
    collected = boottime()
    failures = []

    def retain(step, action):
        try:
            return action()
        except (ValueError, KeyError, OSError, TypeError, IndexError) as error:
            failures.append({'step': step, 'error': str(error)})
            return None

    lines = retain('read_results', lambda: results(log))
    retain('save_results', lambda: durable(prefix + '.shutdown-results.log',
                                         ('\n'.join(lines or []) + '\n').encode()))
    candidates = []
    for index, line in enumerate(lines or []):
        candidate = retain('parse_result_' + str(index), lambda: result(line))
        if candidate is not None:
            candidates.append((index, candidate))
    retain('save_candidates', lambda: save(prefix + '.shutdown-result.json', [r for _, r in candidates]))
    binding = retain('read_binding', lambda: decode(Path(prefix + '.binding.json').read_bytes()))

    def status():
        require((type(daemon_status) is int and daemon_status >= 0) or (isinstance(daemon_status, str)
                and re.fullmatch(r'[0-9]+', daemon_status)), 'invalid nonnegative integer daemon exit status')
        return int(daemon_status)

    exit_status = retain('daemon_exit_status', status)
    if exit_status is not None:
        retain('save_daemon_status', lambda: save(prefix + '.daemon-status.json',
                                                {'daemon_exit_status': exit_status}))
    raw = retain('read_artifact', lambda: artifact(binding['path']))
    digest = hashlib.sha256(raw).hexdigest() if raw is not None else None
    if raw is not None:
        retain('save_artifact', lambda: durable(prefix + '.artifact.json', raw))
    checkpoint_raw = retain('read_checkpoint', lambda: artifact(binding['checkpoint_path']))
    checkpoints = {}
    retained_checkpoint = None
    if checkpoint_raw is not None:
        retained_checkpoint = retain('save_checkpoint', lambda:
            (durable(prefix + '.checkpoint.json', checkpoint_raw), prefix + '.checkpoint.json')[1])
    if isinstance(binding, dict) and isinstance(binding.get('checkpoint_path'), str):
        checkpoints[binding['checkpoint_path']] = (binding, {
            'path': binding['checkpoint_path'], 'retained_path': retained_checkpoint,
            'sha256': hashlib.sha256(checkpoint_raw).hexdigest() if checkpoint_raw is not None else None,
            'bytes': len(checkpoint_raw) if checkpoint_raw is not None else None,
            'binding_status': 'EXPLICITLY_UNBOUND'})
    initial_raw = retain('read_initial', lambda: Path(prefix + '.initial.json').read_bytes())
    candidate_artifacts = []
    for index, candidate in candidates:
        path = candidate['path']
        copied = prefix + '.candidate-' + str(index) + '.artifact.json'
        candidate_raw = retain('read_candidate_artifact_' + str(index), lambda: artifact(path))
        receipt = {'result_index': index, 'path': path, 'binding_status': 'EXPLICITLY_UNBOUND',
                   'retained_path': None, 'sha256': None, 'bytes': None}
        if candidate_raw is not None:
            receipt.update(sha256=hashlib.sha256(candidate_raw).hexdigest(), bytes=len(candidate_raw))
            saved = retain('save_candidate_artifact_' + str(index),
                           lambda: (durable(copied, candidate_raw), True)[1])
            if saved:
                receipt['retained_path'] = copied
        candidate_checkpoint = retain('derive_candidate_checkpoint_' + str(index), lambda: checkpoint_path(candidate))
        receipt['checkpoint'] = {'path': candidate_checkpoint, 'retained_path': None,
                                 'sha256': None, 'bytes': None, 'binding_status': 'EXPLICITLY_UNBOUND'}
        if candidate_checkpoint is not None:
            if candidate_checkpoint not in checkpoints:
                prefix_raw = retain('read_candidate_checkpoint_' + str(index), lambda: artifact(candidate_checkpoint))
                checkpoint_receipt = receipt['checkpoint']
                if prefix_raw is not None:
                    copied_checkpoint = prefix + '.candidate-' + str(index) + '.checkpoint.json'
                    checkpoint_receipt.update(sha256=hashlib.sha256(prefix_raw).hexdigest(), bytes=len(prefix_raw))
                    checkpoint_receipt['retained_path'] = retain('save_candidate_checkpoint_' + str(index), lambda:
                        (durable(copied_checkpoint, prefix_raw), copied_checkpoint)[1])
                checkpoints[candidate_checkpoint] = (candidate, checkpoint_receipt)
            source_owner, checkpoint_receipt = checkpoints[candidate_checkpoint]
            retain('candidate_checkpoint_owner_' + str(index), lambda:
                require(matches(candidate, source_owner), 'conflicting checkpoint source owner identity/path'))
            receipt['checkpoint'] = checkpoint_receipt
        candidate_artifacts.append(receipt)
    custody = {'path': binding.get('path') if isinstance(binding, dict) else None,
               'identity': {n: binding.get(n) for n in IDENTITY} if isinstance(binding, dict) else None,
               'sha256': digest, 'bytes': len(raw) if raw is not None else None,
               'candidate_artifacts': candidate_artifacts,
               'binding_status': 'STARTUP_BOUND' if isinstance(binding, dict) else 'EXPLICITLY_UNBOUND',
               'daemon_exit_status': exit_status, 'daemon_exit_status_input': daemon_status,
               'collected_boottime_ns': str(collected), 'failures': failures}
    validation_ready = not failures
    retain('save_custody', lambda: save(prefix + '.custody.json', custody))

    def validate_collected():
        count = unsigned(binding['startup_result_count'])
        same_owner([r for _, r in candidates], binding)
        terminal_candidates = [r for index, r in candidates
                               if index >= count and r['final_export'] is True and matches(r, binding)]
        require(len(terminal_candidates) == 1, 'shutdown result is absent/ambiguous/unbound')
        terminal = terminal_candidates[0]
        document = decode(raw)
        published(terminal, raw, document, binding, True)
        require(all(document[name] == binding[name] for name in ('build_version', 'source_sha')),
                'build/source identity changed after startup binding')
        initial = initial_checkpoint(binding, checkpoint_raw)
        require(initial_raw == checkpoint_raw, 'retained initial bytes differ from checkpoint')
        require(document['events'][0] == initial['events'][0]
                and all(document[name] == initial[name] for name in ('collection_start_ns', 'initial_epoch', 'initial_flags', 'ring_capacity', 'hook_capacity')),
                'final history contradicts retained initial manifest')
        for hook in document['hooks']:
            require(hook['counter_map_id'] in binding['owned_map_ids']
                    and hook['ifindex'] in binding['ifindices']
                    and decimal(hook['namespace_cookie']) == binding['namespace_cookie'],
                    'hook map/target identity differs from startup daemon custody')
            chain = {hook['initial_program_id']} | {decimal(e['new_program_id']) for e in document['events']
                                                  if e['kind'] == 13 and e['hook_id'] == hook['hook_id'] and e['outcome'] == 1}
            require(chain.intersection(binding['owned_program_ids']), 'no recorded program was held by startup daemon')
        require({hook['ifindex'] for hook in document['hooks']} == set(binding['ifindices']),
                'artifact omits an expected Native target')
        shutdown = decimal(decode(Path(prefix + '.shutdown.json').read_bytes())['boottime_ns'])
        report = validate(document, binding, shutdown, collected, reasons)
        report['failed_writer_real_row'] = 'NOT_RUN: existing Native smoke has no failed-writer injection'
        schedule_path = os.environ.get('HONK_XDP_CAPTURE_SCHEDULE')
        if schedule_path:
            schedule = decode(artifact(schedule_path))
            captured = captured_schedule(document, schedule)
            save(prefix + '.captured-return.json', captured)
            report['captured_return'] = captured
        save(prefix + '.validation.json', report)
        if schedule_path:
            require(report['captured_return']['capture_matrix'] == 'EXERCISED',
                    'NOT_EXERCISED: finite daemon schedule lacked the required captured-before/change/import-after matrix')

    if validation_ready:
        retain('validate', validate_collected)
    retain('save_final_custody', lambda: save(prefix + '.custody.json', custody))
    require(not failures, 'evidence collection/validation failed: ' + ', '.join(f['step'] for f in failures))


def captured_receipt_self_test():
    key = dict(src_ip=[0, 0, 0xffff0000, 1], dst_ip=[0, 0, 0xffff0000, 2],
               src_port=1, dst_port=2, l4proto=17, ip_version=4, domain=0,
               direction=0, namespace_cookie='1', zone=0, zone_state=2, reserved=[0] * 5)
    kinds = ('IMPORTED', 'OPERATION_PREPARED', 'ENTRY_ACQUIRED', 'FRESH_GRACE_STARTED',
             'FRESH_GRACE_DONE', 'ORIGINAL_FINISHED')
    events = []
    for seq, kind in enumerate(kinds, 1):
        event = {name: None for name in CAPTURED_DECIMALS}
        event.update(seq=str(seq), kind=kind, key=key, claim_epoch='3', claim_incarnation='3',
                     claim_scope='1', producer_flags=1, producer_epoch='3', producer_incarnation='3',
                     producer_expires_boottime_ns='100', basis_flags=0, completion_handle=['1', '2', '3', '4'],
                     routing_fingerprint=[0] * 32, fresh_grace=None,
                     return_attachment='1', op_incarnation='2', slot='0', entry_seq='1', boottime_ns=str(seq))
        events.append(event)
    events[3]['related_seq'], events[4]['related_seq'] = '3', '4'
    events[5]['related_seq'], events[5]['fresh_grace'] = '5', True
    events[1]['completion_handle'] = None
    events[4]['fresh_grace'], events[5]['outcome'] = True, 'Transferred'
    events[5].update(terminal=False, phase_after=4, inventory_held='0', inventory_pending='0',
                     inventory_flight='0', count_before='1', count_after='0')
    document = dict(captured_receipts=events, captured_receipts_evicted='0')
    observed = captured_receipts(document)
    require(observed['status'] == 'NOT_RUN' and observed['entry_and_fresh_grace'] == 'PASS', 'synthetic partial receipt was promoted or lost')
    for label, index, field, value in (
            ('earlier-publication-grace', 3, 'related_seq', '1'),
            ('wrong-operation-grace', 4, 'related_seq', '2'),
            ('time-before-entry', 3, 'boottime_ns', '1'),
            ('late-entry-reuse', 5, 'entry_seq', '2')):
        changed = copy.deepcopy(document)
        changed['captured_receipts'][index][field] = value
        try:
            captured_receipts(changed)
        except ValueError:
            pass
        else:
            raise ValueError('accepted synthetic causal mismatch: ' + label)
    for field, value in (('key', None), ('claim_incarnation', None)):
        changed = copy.deepcopy(document)
        changed['captured_receipts'][1][field] = value
        require(captured_receipts(changed)['entry_and_fresh_grace'] == 'NOT_RUN', 'missing association became evidence')
    changed = copy.deepcopy(document)
    changed['captured_receipts'][4]['fresh_grace'] = False
    try:
        captured_receipts(changed)
    except ValueError:
        pass
    else:
        raise ValueError('failed Grace became transfer')
    changed = copy.deepcopy(document)
    changed['captured_receipts'][5]['completion_handle'][3] = '5'
    require(captured_receipts(changed)['entry_and_fresh_grace'] == 'NOT_RUN', 'completed foreign packet generation became evidence')
    changed = copy.deepcopy(document)
    for event in changed['captured_receipts'][1:]:
        event['producer_flags'] = 0
    changed['captured_receipts'][5].update(count_before='0', count_after='0')
    require(captured_receipts(changed)['entry_and_fresh_grace'] == 'NOT_RUN', 'uncounted completion spent counted import evidence')
    inventory = copy.deepcopy(document)
    inventory['captured_receipts'][5].update(inventory_held='0', inventory_pending='0', inventory_flight='0',
                                             count_before='1', count_after='0', phase_after=4)
    proof = captured_receipts(inventory)['samples'][0]
    require(proof['completion_inventory']['count_after'] == '0' and proof['phase_after'] == 4,
            'actual completion inventory fields were lost')
    for field, value in (('inventory_held', '1'), ('inventory_pending', '1'), ('inventory_flight', '1'),
                         ('count_after', '1'), ('phase_after', 6)):
        changed = copy.deepcopy(inventory)
        changed['captured_receipts'][5][field] = value
        try:
            captured_receipts(changed)
        except ValueError:
            pass
        else:
            raise ValueError('accepted inconsistent completion inventory: ' + field)
    return document


def captured_schedule_self_test(receipts):
    document = copy.deepcopy(receipts)
    document.update(pid=1, starttime_ticks='1', root_map_id=1, source_sha='synthetic-source')
    for event in document['captured_receipts']:
        event['key']['src_ip'][3], = struct.unpack('=I', socket.inet_aton('192.0.2.2'))
        event['key']['dst_ip'][3], = struct.unpack('=I', socket.inet_aton('198.51.100.2'))
        event['basis_epoch'] = '5'
    cases = ('tcp', 'udp-connected', 'udp-unconnected', 'udp-empty-connected',
             'udp-empty-unconnected', 'udp-jumbo', 'udp-unconnected-two-targets')
    schedule = dict(schema='native-captured-schedule/v1', clock_id='CLOCK_BOOTTIME', unit='ns',
        profile='native', publication_identity=dict(pid=1, starttime_ticks='1', root_map_id=1,
            source_sha='synthetic-source', executable_sha256='synthetic-executable'),
        old_root=dict(epoch='3'), final_reload_started_boottime_ns='1', final_reload_ack_boottime_ns='1',
        attempts=[], peer_events=[], peer_wire=[], copy_or_physical_zc='Copy', kernel_release='synthetic',
        negative_writev=dict(status='NOT_RUN'))
    for family in (4, 6):
        for index, case in enumerate(cases):
            source = ['192.0.2.2' if family == 4 else 'fd00:1::2', 256 if (family, case) == (4, 'udp-connected') else 20000 + family * 100 + index]
            address = '198.51.100.2' if family == 4 else 'fd00:2::2'
            payload = b'' if 'empty' in case else b'x' * 8192 if case == 'udp-jumbo' else b'synthetic-captured'
            targets = [dict(target_index=target, target=[address, 512 if (family, case) == (4, 'udp-connected') else 18100 + index + target],
                            payload=payload.hex(), payload_length=len(payload), payload_sha256=hashlib.sha256(payload).hexdigest())
                       for target in range(2 if case == 'udp-unconnected-two-targets' else 1)]
            schedule['attempts'].append(dict(label=f'{family}-{case}', family=family, case=case, source=source, targets=targets, returncode=0, child_status='completed'))
    payload = b'synthetic-captured'.hex()
    schedule['peer_events'] = [dict(kind='received', family=4, peer=['192.0.2.2', 256], target_port=512, payload=payload)]
    schedule['peer_wire'] = [dict(family=4, source='192.0.2.2', target='198.51.100.2', sport=256, dport=512, ttl=36, payload=payload, syn=False)]
    def selected(report):
        return next(sample for sample in report['samples'] if (sample['family'], sample['case']) == (4, 'udp-connected'))
    positive = selected(captured_schedule(document, schedule))
    require(positive['status'] == 'NOT_RUN' and positive['capture_status'] == 'EXERCISED'
            and positive['captured_entry_fresh_grace_peer'] == 'PASS', 'synthetic captured sample association lost/promoted')
    changed = copy.deepcopy(document)
    for event in changed['captured_receipts']:
        event['producer_epoch'] = '7'
    require(selected(captured_schedule(changed, schedule))['capture_status'] == 'NOT_EXERCISED', 'post-change capture credited as captured-before publication')
    changed = copy.deepcopy(schedule)
    changed['peer_wire'][0]['ttl'] = 37
    require(selected(captured_schedule(document, changed))['captured_entry_fresh_grace_peer'] == 'FAIL', 'missing Linux TTL decrement credited')


def captured_inventory_self_test():
    candidate = dict(role='canonical_tap_gate', pin_path='/pins/native-return-1/realm-0-gate-2-1-prog',
                     program_id=5, realm_index=0, closed_epoch='2', state='Installed')
    document = dict(captured_realm_inventory=dict(return_attachment='1', inventory_seq='1', boottime_ns='1', status='Committed', candidates=[candidate]))
    require(captured_inventory(document)['candidates'][0]['closed_epoch'] == 2, 'canonical inventory decode failed')

    def rejects(name, changed):
        try:
            captured_inventory(changed)
        except ValueError:
            return
        raise ValueError('accepted incompatible canonical candidate: ' + name)

    next_candidate = dict(candidate, program_id=6, pin_path='/pins/native-return-1/realm-0-gate-2-2-prog')
    partial = copy.deepcopy(document)
    partial['captured_realm_inventory'].update(status='Partial', candidates=[candidate, next_candidate])
    require(len(captured_inventory(partial)['candidates']) == 2, 'same-epoch partial candidates were discarded')
    committed = copy.deepcopy(partial)
    committed['captured_realm_inventory']['status'] = 'Committed'
    rejects('two installed committed candidates', committed)
    committed['captured_realm_inventory']['candidates'][0]['state'] = 'retired-pending'
    require(len(captured_inventory(committed)['candidates']) == 2, 'same-epoch committed retirement was discarded')
    for name, extra in (
            ('third candidate', dict(candidate, program_id=7, pin_path='/pins/native-return-1/realm-0-gate-2-3-prog')),
            ('duplicate path', dict(candidate, program_id=7)),
            ('duplicate identity', dict(candidate, program_id=7, pin_path='/other/realm-0-gate-2-1-prog')),
            ('duplicate program', dict(next_candidate, program_id=5))):
        changed = copy.deepcopy(partial if name == 'third candidate' else document)
        changed['captured_realm_inventory']['status'] = 'Partial'
        changed['captured_realm_inventory']['candidates'].append(extra)
        rejects(name, changed)
    for field, value in (
            ('closed_epoch', '3'), ('closed_epoch', '0'), ('closed_epoch', '02'), ('closed_epoch', str(1 << 64)),
            ('realm_index', 1 << 32), ('program_id', 0), ('state', 'Unknown'),
            *(('pin_path', '/pins/native-return-1/' + name) for name in (
                'realm-0-gate-2-prog', 'realm-1-gate-2-1-prog', 'realm-0-gate-4-1-prog',
                'realm-00-gate-2-1-prog', 'realm-4294967296-gate-2-1-prog',
                'realm-0-gate-0-1-prog', 'realm-0-gate-02-1-prog', 'realm-0-gate-18446744073709551616-1-prog',
                'realm-0-gate-2-0-prog', 'realm-0-gate-2-01-prog', 'realm-0-gate-2-18446744073709551616-prog'))):
        changed = copy.deepcopy(document)
        changed['captured_realm_inventory']['candidates'][0][field] = value
        rejects(field + '=' + repr(value), changed)
    boundary = copy.deepcopy(document)
    boundary['captured_realm_inventory']['candidates'][0].update(realm_index=(1 << 32) - 1,
        closed_epoch=str((1 << 64) - 2), pin_path='/pins/native-return-1/realm-4294967295-gate-18446744073709551614-18446744073709551615-prog')
    captured_inventory(boundary)


def captured_joined_self_test():
    event = {name: None for name in CAPTURED_DECIMALS}
    filename = 'native-return-1-2.joined.json'
    digest = hashlib.sha256(b'joined fixture bytes').hexdigest()
    event.update(seq='1', kind='CAPTURED_JOINED_ACK', return_attachment='2',
                 key=None, completion_handle=None, producer_flags=None, basis_flags=None,
                 routing_fingerprint=None, fresh_grace=None, joined_receipt_file=filename,
                 terminal_inventory_sha256=list(bytes.fromhex(digest)))
    document = dict(captured_receipts=[event], captured_receipts_evicted='0')
    require(captured_joined_ack(document, filename, 2, digest)['seq'] == '1', 'matching joined acknowledgement lost')
    for attachment, name, sha in ((3, filename, digest), (2, 'other.joined.json', digest), (2, filename, '00' * 32)):
        try:
            captured_joined_ack(document, name, attachment, sha)
        except ValueError:
            pass
        else:
            raise ValueError('accepted unacknowledged joined receipt')


def finished_phase_self_test():
    table = {
        False: {'Transferred': {3, 4}, 'TakenOver': {1}, 'RefusedBeforeTransfer': {0, 2, 3, 4}, 'Disposed': {0, 1, 2, 3, 4}},
        True: {'Transferred': {2, 3}, 'TakenOver': {1}, 'RefusedBeforeTransfer': {0, 2, 3}, 'Disposed': {0, 1, 2, 3}},
    }
    for terminal, outcomes in table.items():
        for outcome, phases in outcomes.items():
            for phase in range(6):
                event = dict(terminal=terminal, outcome=outcome, phase_after=phase,
                             inventory_held=0, inventory_pending=0, inventory_flight=0,
                             count_before=1, count_after=0, entry_seq=1 if outcome == 'Transferred' else None,
                             fresh_grace=True if outcome in ('Transferred', 'RefusedBeforeTransfer') else None,
                             related_seq=5 if outcome in ('Transferred', 'RefusedBeforeTransfer') else None)
                try:
                    require_finished_phase(event)
                except ValueError:
                    require(phase not in phases, 'valid factual terminal phase was rejected')
                else:
                    require(phase in phases, 'invalid terminal/outcome phase was accepted')
    ambiguous = dict(terminal=None, outcome='Ambiguous', phase_after=None,
                     inventory_held=None, inventory_pending=None, inventory_flight=None,
                     count_before=None, count_after=None)
    require_finished_phase(ambiguous)
    for change in (dict(terminal=False), dict(terminal=True), dict(phase_after=2), dict(count_after=0)):
        try:
            require_finished_phase(dict(ambiguous, **change))
        except ValueError:
            pass
        else:
            raise ValueError('Ambiguous operation claimed settlement')


def self_test():
    # Synthetic parser checks only; not evidence of production recording or real hooks.
    captured = captured_receipt_self_test()
    captured_schedule_self_test(captured)
    captured_inventory_self_test()
    captured_joined_self_test()
    finished_phase_self_test()
    events = []
    def event(kind, **fields):
        e = dict.fromkeys(DECIMALS, '0')
        e.update(seq=str(len(events) + 1), kind=kind, reason=0, outcome=0, flags=0,
                 reserved=[0] * 24, old_program_id=None, new_program_id=None, version=1)
        e.update(fields)
        events.append(e)
        return str(len(events))
    event(1, flags=1, boottime_before_ns='10', boottime_after_ns='10')
    hooks = []
    for hook in (1, 2, 3, 4):
        registered = event(2, hook_id=str(hook), counter_epoch=str(hook))
        target = (hook + 1) // 2
        hooks.append(dict(hook_id=str(hook), target_serial=str(target), kind=(hook-1) % 2, scope='0', namespace_cookie='1',
                          ifindex=target, attachment_generation='1', counter_map_id=target, initial_program_id=hook,
                          current_program_id=hook, registered_seq=registered, publication_serial='1', current_attachment_generation='1'))
    event(3, operation_id='1', writer_id='1', reason=9)
    def close(before, after, op, writer, reason):
        timestamp = '20' if op == '1' else '26'
        intent = event(4, operation_id=op, writer_id=writer, epoch_before=before, epoch_after=after, reason=reason)
        stored = event(5, operation_id=op, writer_id=writer, epoch_before=before, epoch_after=after,
                       reason=reason, related_seq=intent, flags=1, outcome=1, boottime_before_ns=timestamp, boottime_after_ns=timestamp)
        event(6, operation_id=op, writer_id=writer, epoch_after=after, related_seq=stored,
              reason=reason, flags=1, outcome=1, boottime_after_ns=str(int(timestamp) + 1))
        return stored
    second = close('0', '2', '1', '1', 9)
    def counts(tag, boundary, op):
        for hook in (1, 2, 3, 4):
            event(10, operation_id=op, counter_epoch=tag, related_seq=boundary, hook_id=str(hook), flags=2, outcome=1)
    counts('0', '1', '0')
    for outcome in (0, 1):
        event(13, operation_id='1', writer_id='1', hook_id='1', reason=9, outcome=outcome,
              counter_value='1', counter_epoch='3', old_program_id='1', new_program_id='3')
    hooks[0].update(current_program_id=3, current_attachment_generation='2')
    event(7, operation_id='1', writer_id='1', reason=9, outcome=1)
    intent = event(8, operation_id='1', writer_id='1', reason=9, epoch_before='2', epoch_after='3')
    event(9, operation_id='1', writer_id='1', reason=9, epoch_before='2', epoch_after='3', related_seq=intent,
          flags=1, outcome=1, boottime_before_ns='22', boottime_after_ns='23')
    final = close('3', '4', '2', '0', 10)
    counts('2', second, '1')
    event(11, operation_id='2', epoch_after='4', reason=10, related_seq=final, outcome=1)
    event(6, operation_id='3', epoch_after='4', reason=10, related_seq=final, flags=1, outcome=1, boottime_after_ns='28')
    counts('4', final, '2')
    event(12, epoch_after='4', reason=10, flags=1, outcome=1, boottime_after_ns='30')
    binding = dict(boot_id='00000000-0000-0000-0000-000000000000', pid=1, starttime_ticks=1,
                   publication_serial=1, root_map_id=1, attempts_after_ns=11, path='/test/1-1-1.json')
    document = dict(schema='native-publication/v1', clock_id='CLOCK_BOOTTIME', unit='ns',
                    durability_evidence='REQUIRES_MATCHING_EXTERNAL_PUBLISHED_DURABLE_RESULT',
                    final=True, complete=True, terminal=True, hooks_joined=True, all_counters_sealed=True,
                    failed=False, recording_error=False, clock_error=False, accounting_error=False,
                    counter_overflow=False, export_error=False, ready=False, capture_ready=False,
                    incomplete_reasons=[], initial_epoch='0', initial_flags=0, final_epoch='4', final_flags=0,
                    collection_start_ns='10', collection_end_ns='30', ring_capacity=4096, hook_capacity=32,
                    max_hooks=32, max_targets=16, data_dir_path_max_bytes=1024,
                    first_retained_seq='1', last_seq=str(len(events)), total_appended=str(len(events)),
                    overwritten_events='0', events=events, hooks=hooks)
    document.update({n: str(binding[n]) if n in ('starttime_ticks', 'publication_serial') else binding[n] for n in IDENTITY})
    require(validate(document, binding, 24, 31, [9])['hooks'] == 4, 'valid fixture rejected')

    def splice(d, before, inserted):
        for e in d['events']:
            if int(e['seq']) >= before:
                e['seq'] = str(int(e['seq']) + len(inserted))
            if int(e['related_seq']) >= before:
                e['related_seq'] = str(int(e['related_seq']) + len(inserted))
        for h in d['hooks']:
            if int(h['registered_seq']) >= before:
                h['registered_seq'] = str(int(h['registered_seq']) + len(inserted))
        for index, e in enumerate(inserted, before):
            e['seq'] = str(index)
        d['events'][before-1:before-1] = inserted
        d.update(last_seq=str(len(d['events'])), total_appended=str(len(d['events'])))

    def participant(d, after_root=False, replacement=False):
        root = next(e for e in d['events'] if e['kind'] == 3)
        settled = next(e for e in d['events'] if e['kind'] == 7)
        begin = dict(root, operation_id='99')
        outcome = dict(settled, operation_id='99')
        if replacement:
            splice(d, int(root['seq']) + 1, [begin])
            for e in d['events']:
                if e['kind'] == 13:
                    e['operation_id'] = '99'
            # Root is settled, but its participant is still pending at replacement.
            d['events'].remove(settled)
            before = next(i for i, e in enumerate(d['events']) if e['kind'] == 13)
            d['events'].insert(before, settled)
            for index, e in enumerate(d['events'], 1):
                e['seq'] = str(index)
            splice(d, int(next(e for e in d['events'] if e['kind'] == 8)['seq']), [outcome])
        else:
            before = int(settled['seq']) + 1 if after_root else int(root['seq']) + 1
            splice(d, before, [begin, outcome])

    def late_participant_outcome(d):
        root = next(e for e in d['events'] if e['kind'] == 3)
        settled = next(e for e in d['events'] if e['kind'] == 7)
        splice(d, int(root['seq']) + 1, [dict(root, operation_id='99')])
        splice(d, int(settled['seq']) + 1, [dict(settled, operation_id='99')])

    def mismatched_replacement_operation(d):
        root = next(e for e in d['events'] if e['kind'] == 3)
        settled = next(e for e in d['events'] if e['kind'] == 7)
        splice(d, int(root['seq']) + 1, [dict(root, operation_id='99')])
        splice(d, int(settled['seq']), [dict(settled, operation_id='99')])
        next(e for e in d['events'] if e['kind'] == 13 and e['outcome'] == 1)['operation_id'] = '99'

    def extra_zero_hook_counter(d):
        counter = next(e for e in d['events'] if e['kind'] == 10)
        splice(d, int(counter['seq']) + 1, [dict(counter, hook_id='0', counter_value='999')])

    good = copy.deepcopy(document)
    participant(good)
    validate(good, binding, 24, 31, [9])

    def zero_hook(d):
        for h in d['hooks']:
            if h['hook_id'] == '2':
                h['hook_id'] = '0'
        for e in d['events']:
            if e['hook_id'] == '2':
                e['hook_id'] = '0'

    def alias_map(d):
        for h in d['hooks']:
            h['counter_map_id'] = 1
    mutations = [lambda d: d.update(overwritten_events='1'), lambda d: d.update(hooks_joined=False),
                 lambda d: d.update(max_hooks=64), lambda d: d.update(max_targets=32),
                 lambda d: d.update(data_dir_path_max_bytes=2048), lambda d: d.pop('max_hooks'),
                 lambda d: d['events'][4].update(seq='1'), lambda d: d['events'][4].update(kind=14),
                 lambda d: d['events'][4].update(reserved=[1] * 24), lambda d: d['events'][4].update(flags=512),
                 lambda d: d['events'][4].update(related_seq='1'), lambda d: d['events'][-2].update(counter_epoch='2'),
                 lambda d: next(e for e in d['events'] if e['kind'] == 7).update(outcome=2),
                 lambda d: next(e for e in d['events'] if e['kind'] == 10).update(outcome=0),
                 lambda d: next(e for e in d['events'] if e['kind'] == 11).update(outcome=0),
                 lambda d: next(e for e in d['events'] if e['kind'] == 13).update(counter_value='7', old_program_id='7'),
                 lambda d: next(e for e in d['events'] if e['kind'] == 13 and e['outcome'] == 1).update(outcome=2),
                 lambda d: d['hooks'][0].update(current_program_id=99), lambda d: d.update(complete=False)]
    mutations.extend([zero_hook, alias_map, lambda d: participant(d, after_root=True),
                      lambda d: participant(d, replacement=True), late_participant_outcome,
                      mismatched_replacement_operation, extra_zero_hook_counter])
    for mutate in mutations:
        bad = copy.deepcopy(document)
        mutate(bad)
        try:
            validate(bad, binding, 24, 31, [9])
        except (ValueError, KeyError):
            pass
        else:
            raise AssertionError('corrupt history accepted')
    raw = json.dumps(document).encode()
    terminal = dict(binding, export_publication_result='PUBLISHED_DURABLE', export_error='None',
                    sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), final_export=True, complete=True, last_seq=len(events))
    published(terminal, raw, document, binding, True)
    for patch in ({'export_publication_result': 'PUBLISHED_DURABILITY_UNKNOWN'}, {'sha256': '0' * 64}, {'path': '/wrong'}):
        try:
            published(dict(terminal, **patch), raw, document, binding, True)
        except ValueError:
            pass
        else:
            raise AssertionError('unbound/non-durable artifact accepted')
    line = ('export_publication_result="PUBLISHED_DURABLE" path=Some("/test/1-1-1.json") '
            'sha256=Some("' + terminal['sha256'] + '") bytes=' + str(len(raw)) + ' boot_id=' + binding['boot_id'] +
            ' pid=1 starttime_ticks=1 publication_serial=1 root_map_id=1 final_export=true complete=true last_seq=' +
            str(len(events)) + ' export_error=None Native publication artifact result')
    require(result(line)['path'] == binding['path'], 'structured tracing result parse failed')
    initial = dict(document, final=False, complete=False, terminal=False, ready=False, capture_ready=False,
                   final_epoch='0', final_flags=0, hooks=[], events=events[:1], last_seq='1')
    initial_raw = (json.dumps(initial, indent=1) + '\n').encode()
    initial_result = dict(terminal, path='/test/state/native-publication/1-1-1.json', final_export=False,
                          complete=False, last_seq=1, bytes=len(initial_raw), sha256=hashlib.sha256(initial_raw).hexdigest())
    repeated = [initial_result]
    for seq in (81, 112):
        snapshot_raw = json.dumps(dict(initial, last_seq=str(seq), events=[dict(events[0], seq=str(n))
                                  for n in range(1, seq + 1)])).encode()
        repeated.append(dict(initial_result, last_seq=seq, sha256=hashlib.sha256(snapshot_raw).hexdigest(), bytes=len(snapshot_raw)))
    first = startup_result(repeated, 1)
    require(first['last_seq'] == 1, 'later snapshot substituted for initial result')
    require(initial_checkpoint(first, initial_raw) == initial, 'initial checkpoint bytes decoded differently')

    def rejects_initial(action):
        try:
            action()
        except (ValueError, KeyError):
            pass
        else:
            raise AssertionError('invalid initial checkpoint/result accepted')

    for status in ('NOT_PUBLISHED', 'PUBLISHED_DURABILITY_UNKNOWN'):
        rejects_initial(lambda status=status: startup_result([dict(initial_result,
            export_publication_result=status, export_error='Some("initial failure")'), *repeated], 1))
    for field, value in (('boot_id', '11111111-1111-1111-1111-111111111111'), ('starttime_ticks', 2),
                         ('publication_serial', 2), ('root_map_id', 2), ('path', '/wrong')):
        rejects_initial(lambda field=field, value=value: startup_result([initial_result, dict(initial_result, **{field: value})], 1))
    for change in ({'sha256': '0' * 64}, {'bytes': len(initial_raw) + 1},
                   {'checkpoint_path': '/test/state/native-publication-initial/1-1-2.json'}):
        rejects_initial(lambda change=change: initial_checkpoint(dict(first, **change), initial_raw))
    rejects_initial(lambda: initial_checkpoint(first, initial_raw.replace(b'"kind": 1', b'"kind": 2')))
    for mutate in (lambda d: d.update(hooks=hooks), lambda d: d.update(events=events[:2]),
                   lambda d: d.update(initial_epoch='2'), lambda d: d['events'][0].update(epoch_after='2'),
                   lambda d: d.update(final_epoch='2'), lambda d: d.update(final_flags=1),
                   lambda d: d.update(terminal=True), lambda d: d.update(ready=True),
                   lambda d: d.update(capture_ready=True), lambda d: d.update(last_seq='2')):
        bad = copy.deepcopy(initial)
        mutate(bad)
        bad_raw = json.dumps(bad).encode()
        rejects_initial(lambda: initial_checkpoint(dict(first, sha256=hashlib.sha256(bad_raw).hexdigest(), bytes=len(bad_raw)), bad_raw))
    import tempfile
    from unittest.mock import patch
    invalid_statuses = {'invalid_status': 'not-a-status', 'plus_status': '+23', 'minus_status': '-23',
                        'negative_int_status': -23, 'bool_status': True, 'float_status': 23.0,
                        'decimal_status': '23.0', 'space_status': ' 23', 'empty_status': ''}

    with tempfile.TemporaryDirectory() as directory:
        for case in ('complete', 'partial', 'missing_binding', 'missing_binding_partial', 'missing_path',
                     'missing_artifact', 'missing_result', 'missing_log', 'malformed_result',
                     'missing_all', 'unbound', 'non_durable', 'multiple_exports', 'duplicate_terminal',
                     'prestartup_terminal', 'changed_checkpoint', 'missing_checkpoint', 'changed_initial',
                     'conflicting_checkpoint_owner', *invalid_statuses):
            folder = Path(directory) / case
            folder.mkdir()
            prefix, log = str(folder / 'publication'), str(folder / 'daemon.log')
            mutable = folder / 'state' / 'native-publication'
            immutable = folder / 'state' / 'native-publication-initial'
            mutable.mkdir(parents=True)
            immutable.mkdir()
            path = str(mutable / '1-1-1.json')
            no_binding = case.startswith('missing_binding')
            multiple = no_binding or case in ('missing_artifact', 'missing_path')
            alternate = str(mutable / '1-1-2.json')
            bound = dict(binding, path=path, startup_result_count=0, build_version='self-test', source_sha='self-test',
                         owned_map_ids=[1, 2], owned_program_ids=[1, 2, 3, 4], ifindices=[1, 2], namespace_cookie=1)
            captured = dict(document, build_version='self-test', source_sha='self-test')
            startup_raw = (json.dumps(dict(initial, build_version='self-test', source_sha='self-test'), indent=1) + '\n').encode()
            bound.update(checkpoint_path=checkpoint_path(bound), sha256=hashlib.sha256(startup_raw).hexdigest(), bytes=len(startup_raw))
            if case != 'missing_checkpoint':
                durable(bound['checkpoint_path'], startup_raw + (b' ' if case == 'changed_checkpoint' else b''))
            if case == 'prestartup_terminal':
                bound['startup_result_count'] = 1
            if case == 'partial':
                captured['complete'] = False
            captured_raw = json.dumps(captured).encode()
            captured_line = line.replace('Some("/test/1-1-1.json")', 'Some(' + json.dumps(path) + ')')
            captured_line = captured_line.replace(terminal['sha256'], hashlib.sha256(captured_raw).hexdigest())
            captured_line = captured_line.replace('bytes=' + str(len(raw)), 'bytes=' + str(len(captured_raw)))
            if case == 'partial':
                captured_line = captured_line.replace('complete=true', 'complete=false')
            if case == 'unbound':
                captured_line = captured_line.replace('pid=1 ', 'pid=2 ')
            if case == 'non_durable':
                captured_line = captured_line.replace('PUBLISHED_DURABLE', 'PUBLISHED_DURABILITY_UNKNOWN')
            if case == 'conflicting_checkpoint_owner':
                captured_line = captured_line.replace('root_map_id=1 ', 'root_map_id=2 ')
            alternate_raw = captured_raw + b'\n'
            alternate_line = captured_line.replace('Some(' + json.dumps(path) + ')',
                                                   'Some(' + json.dumps(alternate) + ')')
            alternate_line = alternate_line.replace(hashlib.sha256(captured_raw).hexdigest(),
                                                    hashlib.sha256(alternate_raw).hexdigest())
            alternate_line = alternate_line.replace('bytes=' + str(len(captured_raw)), 'bytes=' + str(len(alternate_raw)))
            alternate_line = alternate_line.replace('publication_serial=1 ', 'publication_serial=2 ')
            if case == 'missing_path':
                captured_line = captured_line.replace('Some(' + json.dumps(path) + ')', 'None')
            if not no_binding and case != 'missing_all':
                save(prefix + '.binding.json', bound)
            if case not in ('missing_artifact', 'missing_binding_partial', 'missing_all'):
                durable(path, captured_raw)
            if multiple:
                durable(alternate, alternate_raw)
                durable(str(immutable / '1-1-2.json'), b'synthetic failed checkpoint prefix\n')
            if case not in ('missing_log', 'missing_all'):
                text = '' if case == 'missing_result' else captured_line + '\n'
                if case == 'multiple_exports':
                    nonfinal = captured_line.replace('final_export=true', 'final_export=false').replace('complete=true', 'complete=false')
                    prefix_lines = []
                    for seq in (1, len(events) // 3, len(events) // 2, len(events) - 1):
                        snapshot_raw = startup_raw if seq == 1 else json.dumps(dict(captured,
                            final=False, complete=False, last_seq=str(seq), events=events[:seq])).encode()
                        snapshot_line = nonfinal.replace(hashlib.sha256(captured_raw).hexdigest(), hashlib.sha256(snapshot_raw).hexdigest())
                        snapshot_line = snapshot_line.replace('bytes=' + str(len(captured_raw)), 'bytes=' + str(len(snapshot_raw)))
                        prefix_lines.append(snapshot_line.replace('last_seq=' + str(len(events)), 'last_seq=' + str(seq)))
                    text = '\n'.join(prefix_lines) + '\n' + text
                    bound['startup_result_count'] = 3
                    save(prefix + '.binding.json', bound)
                if case == 'duplicate_terminal':
                    text += captured_line + '\n'
                if multiple:
                    text += alternate_line + '\n'
                if case == 'malformed_result':
                    text = 'Native publication artifact result malformed\n' + text
                durable(log, text.encode())
            durable(prefix + '.initial.json', startup_raw + (b' ' if case == 'changed_initial' else b''))
            save(prefix + '.shutdown.json', {'boottime_ns': '24'})
            # Synthetic input custody only: production root-owned artifact admission is not exercised here.
            checkpoint_reads = {}
            def read_captured(p):
                if p is not None and Path(p).parent.name == 'native-publication-initial':
                    checkpoint_reads[p] = checkpoint_reads.get(p, 0) + 1
                status_file = Path(prefix + '.daemon-status.json')
                if case in invalid_statuses:
                    require(not status_file.exists(), 'invalid status persisted as validated status')
                else:
                    require(decode(status_file.read_bytes()) == {'daemon_exit_status': 23},
                            'validated status was not durable before artifact read')
                return Path(p).read_bytes()

            with patch(__name__ + '.artifact', side_effect=read_captured):
                try:
                    collect(log, prefix, invalid_statuses.get(case, '23'), [9])
                except ValueError:
                    require(case not in ('complete', 'multiple_exports'), 'complete collector fixture rejected')
                else:
                    require(case in ('complete', 'multiple_exports'), 'partial/unbound collector fixture accepted: ' + case)
            require(all(count == 1 for count in checkpoint_reads.values()), 'immutable checkpoint reread per export')
            custody = decode(Path(prefix + '.custody.json').read_bytes())
            steps = {f['step'] for f in custody['failures']}
            require(custody['daemon_exit_status'] == (None if case in invalid_statuses else 23),
                    'available integer exit status not retained')
            success = case in ('complete', 'multiple_exports')
            require(bool(steps) != success, 'custody omitted failures')
            require(Path(prefix + '.validation.json').exists() == success, 'partial validation accepted')
            retained = decode(Path(prefix + '.shutdown-result.json').read_bytes())
            expected_results = 0 if case in ('missing_result', 'missing_log', 'missing_all') else 1
            if multiple:
                expected_results = 2
            if case == 'multiple_exports':
                expected_results = 5
            if case == 'duplicate_terminal':
                expected_results = 2
            require(len(retained) == expected_results, 'available parsed candidates lost')
            expected_lines = Path(log).read_text() if Path(log).exists() else '\n'
            require(Path(prefix + '.shutdown-results.log').read_text() == (expected_lines or '\n'),
                    'available raw result lines lost')
            if not no_binding and case not in ('missing_artifact', 'missing_all'):
                require(Path(prefix + '.artifact.json').read_bytes() == captured_raw
                        and custody['sha256'] == hashlib.sha256(captured_raw).hexdigest(), 'available artifact/hash lost')
            receipts = custody['candidate_artifacts']
            require(len(receipts) == expected_results, 'candidate artifact receipts lost')
            if case == 'multiple_exports':
                require(checkpoint_reads == {bound['checkpoint_path']: 1}
                        and {receipt['checkpoint']['retained_path'] for receipt in receipts} == {prefix + '.checkpoint.json'},
                        'repeated exports duplicated immutable checkpoint custody')
                require(not list(folder.glob('publication.candidate-*.checkpoint.json')), 'duplicate immutable checkpoint files retained')
            if multiple:
                prefix_receipt = receipts[-1]['checkpoint']
                require(prefix_receipt['retained_path'] is not None
                        and Path(prefix_receipt['retained_path']).read_bytes() == b'synthetic failed checkpoint prefix\n',
                        'distinct failed checkpoint prefix evidence lost')
            if case == 'conflicting_checkpoint_owner':
                require('candidate_checkpoint_owner_0' in steps, 'checkpoint source ownership conflict ignored')
            for receipt, candidate in zip(receipts, retained):
                require(receipt['path'] == candidate['path']
                        and receipt['binding_status'] == 'EXPLICITLY_UNBOUND', 'candidate receipt invented binding')
                available = candidate['path'] is not None and Path(candidate['path']).exists()
                require((receipt['retained_path'] is not None) == available, 'candidate artifact availability lost')
                if available:
                    expected_raw = alternate_raw if candidate['path'] == alternate else captured_raw
                    require(Path(receipt['retained_path']).read_bytes() == expected_raw
                            and receipt['sha256'] == hashlib.sha256(expected_raw).hexdigest()
                            and receipt['bytes'] == len(expected_raw), 'available candidate artifact/hash lost')
            if no_binding:
                require(custody['binding_status'] == 'EXPLICITLY_UNBOUND' and 'read_binding' in steps,
                        'missing binding was not retained explicitly')
            if case in invalid_statuses:
                require('daemon_exit_status' in steps and receipts[0]['retained_path'] is not None,
                        'invalid status discarded independent artifact evidence')
            for failed_case, step in (('missing_binding', 'read_binding'), ('missing_artifact', 'read_artifact'),
                                      ('missing_log', 'read_results'), ('malformed_result', 'parse_result_0'),
                                      ('invalid_status', 'daemon_exit_status')):
                require(case != failed_case or step in steps, 'custody omitted failed step: ' + step)
            if case == 'missing_all':
                require({'read_results', 'read_binding', 'read_artifact'} <= steps, 'missing-all collection aborted early')
    print('PASS: synthetic Native stop consumer checks; real hooks/producer/export fault rows NOT_RUN')


def main():
    if sys.argv[1:] == ['--self-test']:
        self_test()
    elif sys.argv[1] == 'bind':
        bind(*sys.argv[2:])
    elif sys.argv[1] == 'shutdown':
        save(sys.argv[2] + '.shutdown.json', {'boottime_ns': str(boottime())})
    elif sys.argv[1] == 'collect':
        collect(*sys.argv[2:5], [int(n) for n in sys.argv[5:]])
    else:
        raise ValueError('expected bind, shutdown, collect or --self-test')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError) as error:
        print('native-publication: ' + str(error), file=sys.stderr)
        sys.exit(1)
