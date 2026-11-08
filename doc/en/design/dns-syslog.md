# Client DNS audit over TCP syslog

Compile the optional `dns-syslog` feature, combining it with your usual eBPF/API
build features as needed:

```sh
cargo build --release -p honk-core --features dns-syslog
```

The feature is off by default and is not implied by `native-api` or `native-ui`.
A build without it rejects enabled DNS auditing at startup; its audit hooks are
zero-sized and do not create a queue or sender. Existing release capability sets
are unchanged, so use a build explicitly enabling this feature.

Configure a TCP syslog receiver in `global`:

```dae
global {
    syslog_addr: '192.0.2.10:514'
    syslog_dns_enabled: true
    syslog_cee_enabled: true
    syslog_hostname: 'router01'
    syslog_app_name: 'honk'
}
```

IPv6 uses `[2001:db8::10]:514`. Audit defaults off; the destination defaults empty
and must be a numeric unicast IP with nonzero port when enabled. Address, enabled
state, CEE mode, hostname and app-name require restart. This implementation does not include an IP access recorder or its switch.

`syslog_hostname` defaults empty: read `/proc/sys/kernel/hostname` once at startup,
remove one trailing LF and validate; unavailable/invalid values fall back to `-`.
It identifies the device running honk, not the DNS client. Explicit hostnames use
1–255 printable ASCII bytes without spaces. `syslog_app_name` defaults to `honk`
and requires 1–48 of the same bytes. Explicit whitespace, control bytes and Unicode
are rejected, not trimmed. Sender identity appears only in the RFC 5424 header;
the JSON body omits `hostname` and `app_name` to avoid duplicate receiver fields.

## Capture and event format

The DNS controller and standalone `dns.bind` UDP/TCP adapters capture the actual
client peer, frontend handling start time and final rendered response. Each accepted
query/frame produces one logical event, including cache hits, negative responses,
parseable refusals and failures. Upstream retries add no client events; client
retransmissions are separate requests. Cancellation before a response exists yields
`result: "cancelled"` and null `rcode`. Unprojectable questions are counted and
omitted. Start time is the audit hook time, not kernel packet arrival time.

Audit is independent of `native-api`, UI attachment, `record_dns_log`, its 512-entry
history and log level. Diagnostic calls, background refresh and engine-generated
resolution are excluded. Port-53 traffic left as raw direct/group TCP/UDP relay,
rather than handled by the DNS controller, is outside coverage. Routing is unchanged.

Output has a fixed RFC 5424 header (PRI 134 local0/info, UTC time, configured identity,
MSGID `dns.query`) followed by the complete compact JSON event.
`syslog_cee_enabled` defaults false for ordinary JSON receivers. Set it true, as
in the example above, to prefix `@cee: ` for a CEE-aware receiver:

```text
<134>1 2026-11-02T12:00:00.010000Z router01 honk - dns.query - @cee: {JSON body}
```

```json
{
  "schema_version": 1,
  "event": "dns.query",
  "message": "DNS 192.168.1.100 example.com. A IN: NOERROR answers=1",
  "event_id": "process-uuid:1",
  "query_time": "2026-11-02T12:00:00.000000Z",
  "completed_at": "2026-11-02T12:00:00.010000Z",
  "duration_ms": 10.0,
  "upstream": "default",
  "client_ip": "192.168.1.100",
  "client_port": 53120,
  "transport": "udp",
  "domain": "example.com.",
  "qtype": "A",
  "qclass": "IN",
  "result": "response",
  "rcode": "NOERROR",
  "response_truncated": false,
  "answers": [
    {"name":"example.com.","type":"A","class":"IN","ttl":60,"data":"203.0.113.20"}
  ],
  "answers_omitted": null,
  "answer_ips": ["203.0.113.20"],
  "answer_cnames": [],
  "answer_types": ["A"]
}
```

`transport` describes the client's DNS transport; audit output always uses TCP.
`duration_ms` is numeric processing time in milliseconds, truncated to microsecond
precision. A monotonic clock measures from audit admission until the final response
is ready (or cancellation), before response copying, reply I/O and background queuing.
UTC timestamps remain wall-clock values and are not subtracted to compute duration.
`upstream` is the final result's configured upstream name. Normal and stale cache
responses use `"cache"`; local answers, refusals, cancellations and other results
without upstream metadata use null. No initial upstream or requery history is emitted.
Complete answers retain owner, type, class, TTL and data, including unknown types
as RFC 3597 text. Honk derives three arrays, deduplicated in first-occurrence order:
`answer_ips` takes A/AAAA data, `answer_cnames` takes CNAME target data and
`answer_types` takes all types. Missing matches produce empty arrays. Original
answers are not removed or rewritten. Response validation checks record boundaries,
not every record's data, so a delivered response can still be unrenderable; its
event keeps the other fields with `answers: null`, empty arrays and
`answers_omitted: "invalid"` (`"budget"` if the projection would exceed the event
limit). Otherwise `answers_omitted` is null. TC describes the actual client response,
possibly limited by its UDP advertisement. Capture precedes reply I/O and does not
prove client receipt. Process UUID changes on restart; sequence identifies generated
events, not requests dropped before admission or proof of losslessness.

## Framing and batching

TCP uses [RFC 6587 octet counting](https://www.rfc-editor.org/rfc/rfc6587): decimal
byte length of the complete RFC 5424 message, one ASCII space, then that message.
The length includes header, CEE marker and JSON, excludes its own prefix, and counts UTF-8
bytes rather than characters. No newline or NUL is appended. Batches concatenate
independently framed events:

```text
<length1> <header and JSON1><length2> <header and JSON2>
```

The receiver must support octet counting. An HTTP JSON Lines endpoint cannot
consume this protocol directly. There is no UDP output or application-level fragmentation. An event above 8192 bytes remains one whole frame: a test with 100 compressed
AAAA answers yields a 2831-byte DNS response and about 10.3 kB of audit JSON. Repeated
keys, expanded names/search arrays, long TXT and binary/unknown data grow the JSON.

One asynchronous task lazily creates and reuses one TCP connection. Batches target
128 KiB or flush one second after their first prepared frame; arrivals never reset
that deadline. A single event above the batch target is sent whole in its own batch.
Complete RFC 5424 messages are limited to 4 MiB, with a finite projection budget before
answer allocation and capped serialization. Answers over the projection budget are
omitted as described above; a message still above the limit is rejected whole and
counted. Answers are never silently clipped. These are initial parameters, not a
throughput claim.

## Admission and failures

DNS submits immutable wire data without awaiting network I/O. At most 1024 captured/
pending records and 8 MiB of raw query/response, copied upstream names and entry accounting are admitted.
Response-byte admission never waits: failure drops the whole event, not a false
cancellation. Full queues drop new events and count them without delaying DNS.
Disabled audit copies no packets and starts no task.

The 8 MiB limit is raw admission, not total audit memory. The worker additionally
holds bounded projection/JSON data and framing copies, a normal <=128 KiB batch or
one <=4 MiB event, and at most one prepared next frame while flushing. Large batch
capacity is released after use.

Each TCP socket receives the effective `global.so_mark_from_dae` before connect and
uses TCP_NODELAY. There is no destination DNS lookup or proxy routing, and mark
failure permits no unmarked fallback. Connect and batch-write deadlines are 3 s.
Connection failure retains the bounded batch and stops dequeuing, retrying with
250 ms..30 s exponential backoff. A 1 s flush target cannot hold while disconnected.
Backoff resets after a successful batch write, not merely a successful connect.

Write errors/timeouts may have transmitted part of the batch: discard that ambiguous
batch, close the connection and never replay it. Later queued events can use the
next connection. There is no exactly-once guarantee, application acknowledgment or
receiver persistence proof. Successful writes count as submitted, not confirmed ingested.

Shutdown immediately cancels connect/write/backoff, closes admission and discards
pending work; the 1 s bound is a join/abort deadline, not a final-flush grace. Drop
aborts the task; reload does not duplicate it. Shutdown reports dropped/invalid/
submitted events and connect/write failures. A collector outage logs one WARN with
the error when it begins and INFO when a later batch write succeeds; retries in
between log at DEBUG. Queue-ceiling drops log a WARN at most every 10 s, and
unencodable events log at DEBUG.
No audit data is persisted locally. The receiver owns retention, rotation and search.

## Display message

The complete JSON event includes a nonempty `message` summary of
the canonical client IP, question, response status (or `cancelled`) and answer
count. Existing structured fields and complete answers remain available for
audit queries. The summary counts toward the whole-message byte limit.

With `syslog_cee_enabled: true`, VictoriaLogs syslog ingestion maps `message`
to `_msg` after expanding CEE JSON.
This supplies the text shown in log lists; older events lacking the field may
show its default missing-message placeholder while their other fields are stored.
See [VictoriaLogs syslog](https://docs.victoriametrics.com/victorialogs/data-ingestion/syslog/#cee)
and [message fields](https://docs.victoriametrics.com/victorialogs/keyconcepts/#message-field).

## Fixed format and configuration changes

The RFC 5424 header layout and JSON field schema are fixed. CEE changes only the
optional `@cee: ` prefix; the JSON fields and their types are identical in both
modes. Leave `syslog_cee_enabled` false when the receiver does not support CEE,
and configure its JSON parser as needed. There are no message templates, JSON
templates, tags, format versions or CEF mode. Serialization runs in the background
sender. Ordinary configuration reload does not change the event format or restart
its TCP sender. Changing `syslog_addr`, `syslog_dns_enabled`, `syslog_cee_enabled`,
`syslog_hostname` or `syslog_app_name` requires restart, even if audit is currently
disabled.

### Migration from earlier fork builds

Receivers that previously read `hostname` or `app_name` from the JSON body must
use the corresponding parsed RFC 5424 header fields instead. Existing stored
events are unchanged.

Remove `syslog_dns_template` and `syslog_dns_json`. Both removed keys are rejected
by presence in dae and structured configuration, including empty strings, false
and null. To retain the previous fixed CEE output, explicitly set
`syslog_cee_enabled: true`; otherwise the default body is ordinary JSON. Also
ensure the binary was built with the `dns-syslog` feature before enabling audit.
