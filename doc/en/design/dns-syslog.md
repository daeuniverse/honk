# Client DNS audit over TCP syslog

The optional `dns-syslog` feature sends one audit event per accepted client DNS
query to a TCP syslog receiver. Build honk with your usual eBPF and API
features:

```sh
cargo build --release -p honk-core --features dns-syslog
```

The feature is off by default and is not implied by `native-api` or `native-ui`.
A build without the feature rejects a configuration that enables DNS audit at
startup. In that build the audit hooks are zero-sized and create no queue or
sender. Release capability sets are unchanged, so build with this feature
explicitly.

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

For IPv6, write `[2001:db8::10]:514`. Audit is off by default, and the
destination address starts empty. Enabling audit requires a numeric unicast IP
and a nonzero port. Changing the address, the enabled state, the CEE mode, the
hostname or the app name requires a restart.

`syslog_hostname` defaults to empty. In that case honk reads
`/proc/sys/kernel/hostname` once at startup, removes one trailing LF and
validates the result. An unavailable or invalid value falls back to `-`. The
hostname identifies the device running honk, not the DNS client. An explicit
hostname must be 1–255 printable ASCII bytes with no spaces. `syslog_app_name`
defaults to `honk` and requires 1–48 of the same bytes. honk rejects explicit
whitespace, control bytes and Unicode instead of trimming them. Sender identity
appears only in the RFC 5424 header; the JSON body omits `hostname` and
`app_name` to avoid duplicate receiver fields.

## Capture and event format

The DNS controller and the standalone `dns.bind` UDP/TCP adapters capture the
actual client peer, the time the frontend starts handling the query, and the
final response as rendered. Each accepted query or frame produces one logical
event, including cache hits, negative responses, parseable refusals and
failures. Upstream retries add no client events; client retransmissions are
separate requests. Cancellation before a response exists yields
`result: "cancelled"` and null `rcode`. A question that cannot be projected is
counted and omitted. Start time is the audit hook time, not kernel packet
arrival time.

Audit does not depend on `native-api`, UI attachment, `record_dns_log` and its
512-entry history, or the log level. Diagnostic calls, background refresh and
engine-generated resolution are excluded. Port-53 traffic that a raw
direct/group TCP/UDP relay carries instead of the DNS controller is outside
coverage. Routing is unchanged.

Output starts with a fixed RFC 5424 header, then the complete compact JSON
event. The header carries PRI 134 local0/info, UTC time, the configured identity
and MSGID `dns.query`. `syslog_cee_enabled` defaults to false for ordinary JSON
receivers. For a CEE-aware receiver, set it true, as the example above does, to
prefix `@cee: `:

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
`duration_ms` is numeric processing time in milliseconds, truncated to
microsecond precision. A monotonic clock measures from audit admission to the
moment the final response is ready, or to the cancellation, before response
copying, reply I/O and background queuing. Duration never comes from the UTC
timestamps, which stay wall-clock values.

`upstream` is the configured name of the upstream that produced the final
result. Normal and stale cache responses use `"cache"`; local answers, refusals,
cancellations and other results without upstream metadata use null. honk emits
no initial upstream and no requery history.

Complete answers retain owner, type, class, TTL and data, including unknown
types as RFC 3597 text. honk derives three arrays, deduplicated in
first-occurrence order: `answer_ips` takes A/AAAA data, `answer_cnames` takes
CNAME target data and `answer_types` takes all types. Missing matches produce
empty arrays, and honk does not remove or rewrite the original answers.

Response validation checks record boundaries, not the data of every record, so a
delivered response can still fail to render. That event keeps the other fields,
with `answers: null`, empty arrays and `answers_omitted: "invalid"`, or
`"budget"` if the projection would exceed the event limit. Otherwise
`answers_omitted` is null. TC describes the actual client response, possibly
limited by its UDP advertisement. Capture precedes reply I/O and does not prove
client receipt. The process UUID changes on restart. Sequence numbers identify
generated events; they do not count requests dropped before admission, and they
do not prove lossless delivery.

## Framing and batching

TCP uses [RFC 6587 octet counting](https://www.rfc-editor.org/rfc/rfc6587): decimal
byte length of the complete RFC 5424 message, one ASCII space, then that message.
The length includes header, CEE marker and JSON, excludes its own prefix, and counts UTF-8
bytes rather than characters. No newline or NUL is appended. Batches concatenate
independently framed events:

```text
<length1> <header and JSON1><length2> <header and JSON2>
```

The receiver must support octet counting; an HTTP JSON Lines endpoint cannot
consume this protocol directly. There is no UDP output and no application-level
fragmentation. An event above 8192 bytes still goes out as one whole frame, up
to the 4 MiB limit. Repeated keys, expanded name/search arrays, long TXT records
and binary or unknown data all grow the JSON.

One asynchronous task creates one TCP connection when it needs it, then reuses
it. A batch targets 128 KiB, or flushes one second after its first prepared
frame; later arrivals never reset that deadline. A single event above the batch
target goes out whole in its own batch. A complete RFC 5424 message is limited
to 4 MiB, with a finite projection budget before answer allocation and a capped
serialization. Answers over the projection budget are omitted as described
above. A message still above the limit is rejected whole and counted, and
answers are never silently clipped. These are initial parameters, not a
throughput claim.

## Admission and failures

DNS submits immutable wire data without awaiting network I/O. The audit admits
at most 1024 captured or pending records, and 8 MiB in total. That total covers
raw query/response data, copied upstream names and entry accounting.
Response-byte admission never waits; on failure it drops the whole event instead
of recording a false cancellation. Full queues drop new events and count them,
without delaying DNS. A disabled audit copies no packets and starts no task.

The 8 MiB limit caps raw admission, not total audit memory. The worker also
holds bounded projection and JSON data, framing copies, a normal <=128 KiB batch
or one <=4 MiB event, and at most one prepared next frame while it flushes.
Large batch capacity is released after use.

Each TCP socket receives the effective `global.so_mark_from_dae` before connect
and uses TCP_NODELAY. honk does not resolve the destination name and does not
route the connection through a proxy. A mark failure allows no unmarked
fallback. Connect and batch-write deadlines are 3 s. A connection failure keeps
the bounded batch, stops dequeuing, and retries with 250 ms..30 s exponential
backoff. The 1 s flush target cannot hold while the connection is down. Backoff
resets after a successful batch write, not merely after a successful connect.

A write error or timeout may have transmitted part of the batch. Discard that
ambiguous batch, close the connection and never replay it. Later queued events
can use the next connection. There is no exactly-once guarantee, no application
acknowledgment and no proof that the receiver persisted the data. A successful
write counts as submitted, not as confirmed ingested.

Shutdown immediately cancels connect, write and backoff, closes admission and
discards pending work. The 1 s bound is a join/abort deadline, not a final-flush
grace. Drop aborts the task, and reload does not duplicate it. Shutdown reports
dropped, invalid and submitted events, and connect/write failures. A collector
outage logs one WARN with the error when it begins, and INFO when a later batch
write succeeds; retries in between log at DEBUG. Queue-ceiling drops log a WARN
at most every 10 s, and unencodable events log at DEBUG. honk persists no audit
data locally; the receiver owns retention, rotation and search.

## Display message

The complete JSON event includes a nonempty `message` that summarizes the
canonical client IP, the question, the response status or `cancelled`, and the
answer count. The structured fields and complete answers remain available for
audit queries. The summary counts toward the whole-message byte limit.

With `syslog_cee_enabled: true`, VictoriaLogs syslog ingestion maps `message` to
`_msg` after expanding the CEE JSON. That value supplies the text shown in log
lists. An older event without the field can show the default missing-message
placeholder while its other fields are still stored. See [VictoriaLogs
syslog](https://docs.victoriametrics.com/victorialogs/data-ingestion/syslog/#cee)
and [message
fields](https://docs.victoriametrics.com/victorialogs/keyconcepts/#message-field).

## Fixed format and configuration changes

The header layout and JSON schema are fixed; see above. There are no message
templates, JSON templates, tags, format versions or CEF mode. Serialization runs
in the background sender. An ordinary configuration reload neither changes the
event format nor restarts the TCP sender. The five settings require a restart
even while audit is disabled.

### Migration from earlier fork builds

Receivers that previously read `hostname` or `app_name` from the JSON body must
use the corresponding parsed RFC 5424 header fields instead. Existing stored
events are unchanged.

Remove `syslog_dns_template` and `syslog_dns_json`. honk rejects both keys by
presence, in dae and in structured configuration alike, even with an empty
string, false or null. To keep the previous fixed CEE output, set
`syslog_cee_enabled: true` explicitly; otherwise the default body is ordinary
JSON. Enable audit only after you build the binary with the `dns-syslog`
feature.
