# Client DNS audit over TCP syslog

Configure a TCP syslog receiver in `global`:

```dae
global {
    syslog_addr: '192.0.2.10:514'
    syslog_dns_enabled: true
    syslog_hostname: 'router01'
    syslog_app_name: 'honk'
}
```

IPv6 uses `[2001:db8::10]:514`. Audit defaults off; the destination defaults empty
and must be a numeric unicast IP with nonzero port when enabled. Address, enabled
state, hostname and app-name defaults require restart. Message and JSON templates
support hot reload; reload and native pre-write validation compile them before
acceptance. This
implementation does not include an IP access recorder or its switch.

`syslog_hostname` defaults empty: read `/proc/sys/kernel/hostname` once at startup,
remove one trailing LF and validate; unavailable/invalid values fall back to `-`.
It identifies the device running honk, not the DNS client. Explicit hostnames use
1–255 printable ASCII bytes without spaces. `syslog_app_name` defaults to `honk`
and requires 1–48 of the same bytes. Explicit whitespace, control bytes and Unicode
are rejected, not trimmed. The default header and JSON use the same identity;
custom templates may use literal header fields or map their own JSON keys.

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

The default output has an RFC 5424 header (PRI 134 local0/info, UTC time, configured identity,
MSGID `dns.query`) and a compact JSON body:

```text
<134>1 2026-11-02T12:00:00.010000Z router01 honk - dns.query - {JSON body}
```

```json
{
  "schema_version": 1,
  "event": "dns.query",
  "message": "DNS 192.168.1.100 example.com. A IN: NOERROR answers=1",
  "hostname": "router01",
  "app_name": "honk",
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
answers are not removed or rewritten. TC describes the actual client response,
possibly limited by its UDP advertisement. Capture precedes reply I/O and does not
prove client receipt. Process UUID changes on restart; sequence identifies generated
events, not requests dropped before admission or proof of losslessness.

## Framing and batching

TCP uses [RFC 6587 octet counting](https://www.rfc-editor.org/rfc/rfc6587): decimal
byte length of the complete RFC 5424 message, one ASCII space, then that message.
The length includes header and JSON, excludes its own prefix, and counts UTF-8
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
answer allocation and capped serialization. Oversized events are rejected whole and
counted, never silently clipped. These are initial parameters, not a throughput claim.

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
submitted events and connect/write failures; operational warnings are throttled.
No audit data is persisted locally. The receiver owns retention, rotation and search.

## Display message

The complete default event, with or without CEE, includes a nonempty `message` summary of
the canonical client IP, question, response status (or `cancelled`) and answer
count. Existing structured fields and complete answers remain available for
audit queries. The summary counts toward the whole-message byte limit.

VictoriaLogs syslog ingestion maps `message` to `_msg` after expanding CEE JSON.
Custom JSON templates should include their own `message` field for this display.
This supplies the text shown in log lists; older events lacking the field may
show its default missing-message placeholder while their other fields are stored.
See [VictoriaLogs syslog](https://docs.victoriametrics.com/victorialogs/data-ingestion/syslog/#cee)
and [message fields](https://docs.victoriametrics.com/victorialogs/keyconcepts/#message-field).

## Templates and hot reload

`syslog_dns_template` controls the complete RFC 5424 message, including PRI,
timestamp, hostname, app-name, PROCID, MSGID, structured data and body. RFC 6587's
decimal byte count and space are generated after rendering. Do not put them in
the template. The default is:

```dae
global {
    syslog_dns_template: '<134>1 ${completed_at} ${hostname} ${app_name} - dns.query - ${json}'
    syslog_dns_json: ''
}
```

`${json}` serializes the configured JSON object. Empty `syslog_dns_json` uses
the complete original event above, with the same fields and types. For example,
CEE with a custom nested object is:

```dae
global {
    syslog_dns_template: '<134>1 ${completed_at} ${hostname} ${app_name} - dns.query - @cee: ${json}'
    syslog_dns_json: '{"message":"${message}","time":"${query_time}","client":{"ip":"${client_ip}","port":"${client_port}"},"dns":{"name":"${domain}","answers":"${answers}","ips":"${answer_ips}"},"format":"${template_version}"}'
}
```

All original event keys, including `${duration_ms}` and `${upstream}`, are available
as tags, plus `${version}` (binary version),
`${template_version}` (64 hexadecimal SHA256 characters) and `${json}` (message
body only). Tags read canonical event fields, never other custom output keys.
JSON keys are literal; duplicate keys at any nesting level are rejected. The root
must be an object. An entire unfiltered tag, such as `"${client_port}"`, preserves
its number/boolean/null/array/object type. Tags embedded in text or using filters
produce strings. `$$` emits a literal dollar, so `$${domain}` emits `${domain}`.
Unknown tags, filters and unclosed tags reject the candidate even if audit is off.

Filters use `${field|filter}`:

- `text`: plain string, or compact JSON text for other value types.
- `json`: JSON encoding, including quotes around strings. Useful for manually
  composing text bodies; the structured JSON template already escapes its strings.
- `cef_header`: escape backslash, pipe, CR and LF in CEF header values.
- `cef_ext`: escape backslash, equals, CR and LF in CEF extension values.
- `sd`: escape backslash, quote and closing bracket in RFC 5424 structured-data
  values; control bytes are rejected. Use this filter inside quoted SD values.

There is no CEE/CEF mode switch. Both are literal body layouts. A CEF example:

```dae
global {
    syslog_dns_template: '<134>1 ${completed_at} ${hostname} ${app_name} - dns.query - CEF:0|GhostStar|honk|${version|cef_header}|dns.query|DNS query|1|src=${client_ip|cef_ext} dhost=${domain|cef_ext} msg=${message|cef_ext}'
}
```

RFC 5424 version 1 headers are checked at compilation and after rendering. Header
tokens cannot inject spaces or controls, and must fit the corresponding RFC byte
limits. Timestamps use `-` or RFC3339 with at most six fractional digits. SD IDs
and parameter names must be unique in their respective scopes. Structured data
is bounded to an 8 KiB header prefix. Invalid dynamic values drop the entire
event and increment `invalid`; JSON is never clipped. The message limit remains
4 MiB, including headers and literal markers. Combined template source is at
most 64 KiB, nesting depth 16, compiled nodes 1024 and placeholders 2048.

Templates compile before activation and publish at the existing successful
configuration/DNS commit point. A committed-degraded activation uses its new
template too. Rejected reloads retain the old configuration and template. Each
client request pins its template when auditing begins; transparent UDP does so
before work dispatch. In-flight and queued events keep the old template, including
cancellation, while later requests use the new one. Already framed batches stay
unchanged. One TCP connection can briefly carry both versions. `${template_version}`
is SHA256 of the two raw source strings, each prefixed by its big-endian u64 byte
length; it does not change for unrelated reloads and is absent from default output.

At most eight live compiled profiles, including the current one and candidates,
are retained. If queued or in-flight requests retain all slots, another template
change is rejected until references drain. Unchanged templates need no new slot.
No historical template cache or local spool is kept. Serialization, interpolation
and escaping run in the background sender, never in the DNS frontend.

### Migration from earlier fork builds

Remove `syslog_cee_enabled`, including explicit `false` or `null` in structured
configuration. The removed key is rejected with a migration message. For earlier
`true`, use the CEE message template above; for `false`, use the default template.
Address, enable flag and identity defaults continue to require restart. Template
changes alone use ordinary configuration reload without restarting the sender.
