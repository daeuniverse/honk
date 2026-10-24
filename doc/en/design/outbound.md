# Outbound and proxy stack

The outbound stack connects a selected leaf node to the proxy server or target and handles its protocol bytes.

## Scope

The outbound stack begins after routing and group selection have produced one leaf
`Node`. It owns capability dispatch, reusable protocol state, transport setup,
TLS and REALITY, proxy framing, and the TCP or UDP-facing object returned to the
control plane.

It does not define the node configuration surface; see
[Node reference](../reference/nodes.md). It also does not choose a group
member or define health policy; see [Group design](./groups.md).

An ordinary caller receives one of:

- `ProxyStream`, an established target-bound TCP byte stream; or
- `Arc<dyn PacketTransport>`, an established framed packet path for one UDP target.

Speculative UDP dialing first returns `PreparedUdpTransport<T>`. Commit is fallible and returns the selected `Arc<T>`; dropping an unselected preparation rolls it back. Source-shared protocols (concrete VLESS XUDP/Mux.Cool, Hysteria2 and TUIC, and every `MultiTargetTransport`) commit their transports into core-owned source attachments so several five-tuple endpoints can share one receiver.

`direct` reaches the target without a proxy protocol. `block` terminates the
request. Every other handler turns the selected node into bytes understood by
its proxy server.

Outbound dialing, groups, and health checking. Re-exported by `honk-core` as `honk_core::{proxy, group, outbound}`.

## Implementation ownership

Public `proxy::*`, `quic::*`, and `quic_boring::*` imports remain supported.
Implementations are split into ordinary Rust modules:

| Area | Implementation owners |
| --- | --- |
| Proxy contracts | `proxy/{error,packet,outbound,registry}.rs` |
| Protocol families | `proxy/shadowsocks/{mod,aead2022,stream}.rs`; `proxy/vless/{mod,handler,mux,cool,encryption}.rs` |
| QUIC | `quic/{path_health,flow_control,metrics,endpoint,client,stream,boring}.rs` |
| AnyTLS | `proxy/anytls/{padding,writer,overflow}.rs` |
| Score and health | `group/score/{evidence,ranking,feedback}.rs`; `alive/{health,urltest}.rs` |
| Session pool | `session/{maintenance,speculative}.rs` |
| Stream transports | `proxy/transport/{grpc,h2_io}.rs`; `proxy/transport/xhttp/{browser,preparation,request,response,runtime,session,stream,upload}.rs` |
| Pooled runtime lifecycle | `runtime/pooled.rs` |

Common state remains at the shared ancestor; child implementations do not make
its fields public. REALITY, TLS, stream transport and UoT remain shared rather
than VLESS-owned. Existing test-topic names stay intact within their owning
family. Physical file/line and defining-module metadata change with ownership:
public reexports do not preserve `type_name` or default tracing targets. Log
filters for the former `quic_boring`, `vless_mux` and `shadowsocks_2022` targets
must use `quic::boring`, `proxy::vless::mux` and `proxy::shadowsocks::aead2022`
under the `honk_outbound::` prefix.

## Registry and capability model

```mermaid
flowchart LR
    G[Selected leaf Node] --> R[OutboundRuntimeRegistry]
    G --> P[ProxyRegistry / ProtocolEntry]
    R --> N[NodeRuntime / ProtocolRuntime]
    P --> T[TcpOutbound]
    P --> U[PacketOutbound]
    P --> W[WarmableOutbound]
    P --> Q[ProbeableOutbound]
    T --> S[Shared transport and protocol codec]
    U --> K[PacketTransport]
    S --> B[Proxy server bytes]
    K --> B
```

`ProxyRegistry` is a protocol dispatcher, not a session owner. Each
`ProtocolEntry` contains a `ProtocolDescriptor`, the mandatory TCP handler, and
optional packet, warm, and probe capability slots. A `None` slot means that the
protocol does not implement that capability; dispatch is refused rather than
silently substituted.

- `src/proxy/mod.rs`: `ProxyStream::into_tcp_stream` preserves the zero-copy splice downcast invariant; `proxy/vless/handler/stream.rs`'s `ProxyStream::into_vision_splice` follows the same vtable-dispatch rule for the unwrapped Vision TLS/REALITY carrier type, so any new wrapper around that carrier disables its splice handover. `PreparedUdpTransport<T>` keeps speculative publication behind one consuming commit and returns the exact selected `Arc<T>`. `WarmAttempt` holds the retention lock across establishment; failure or cancellation rolls back only its inserted bit.

### Capability traits

`WarmRequirement::Session|Udp` selects the reusable state to establish. VLESS
resolves the two requirements independently from its TCP and UDP paths; a
UDP-only Xray pool therefore does not make Selector warming open that pool.

| Trait | Operations | Contract |
| --- | --- | --- |
| `TcpOutbound` | `dial`, `dial_with_tcp`, `dial_runtime`, `dial_runtime_marked` | Opens a target-bound `ProxyStream`. `dial_with_tcp` may consume an already connected bare server socket. `dial_runtime` pins session-owning work to the captured generation. `dial_runtime_marked` carries a routed direct flow's `DirectMark`; only Direct applies it, and every other handler refuses it. `ProxyRegistry` runs marked and unmarked dials through the same generation fences. |
| `PacketOutbound` | `dial_udp_transport`, `dial_udp_transport_runtime`, `dial_udp_transport_runtime_marked`, `dial_udp_transport_speculative_runtime` | Opens or prepares the ordinary `PacketTransport` contract. Runtime and speculative variants prevent reload or cold-race work from consulting mutable current state. The marked variant follows `dial_runtime_marked`. |
| `WarmableOutbound` | `warm(runtime, timeout, WarmRequirement)` | Establishes only the reusable state named by the requirement. Hysteria2 uses `Udp` to verify server admission; VLESS may map `Session` and `Udp` to different pools. |
| `ProbeableOutbound` | `test_connectivity` | Tests raw proxy-server reachability. Protocols may override the default marked TCP connect. |

`PacketTransport` exposes the relay target, `send_packet`,
`send_packet_confirmed`, and `recv_packet`. `send_packet_confirmed` is the
stronger first-packet admission point for queue-backed tunnels. Full-cone
protocols can additionally declare that server metadata authoritatively names
the reply source. For source-shared protocols, core serializes
sends from endpoint views and owns the transport's single receive loop.

No production UDP handler returns a raw socket or a loopback bridge. Direct and
SOCKS5 wrap native sockets behind `PacketTransport`; tunnel protocols implement
framing on their actual transport.

### Protocol descriptors

`src/descriptor.rs` owns `ProtocolDescriptor`, the single per-protocol facts table.
Predicates accept the concrete node because VLESS `network` and TCP path, and
Trojan transport, affect capability or pooling. Trojan and AnyTLS share
`network_allows_udp`; VLESS uses canonical `VlessConfig::udp_enabled()`.

| Protocol | `supports_udp` | `pool_ready_streams` | `pool_bare_tcp` | Generation runtime | Share-link schemes |
| --- | --- | --- | --- | --- | --- |
| Shadowsocks, including 2022 | yes | no | yes | `None` | `ss` |
| Trojan | when `network` is absent or contains `udp` | only `tcp`/empty transport | except XHTTP | `None` | `trojan` |
| VMess | no | no | except XHTTP | `None` | `vmess` |
| VLESS | when `network` allows UDP | no | direct TCP path except XHTTP | `Vless` | `vless` |
| SOCKS5 | yes | yes | yes | `None` | `socks5`, `socks4`, `socks4a` |
| Hysteria2 | yes | no | no | `Quic` | `hysteria2`, `hysteria` |
| TUIC | yes | no | no | `Quic` | `tuic` |
| Juicity | yes | no | no | `Quic` | `juicity` |
| AnyTLS | when `network` is absent or contains `udp` | no | no | `AnyTls` | `anytls` |
| Direct | yes | no | no | `None` | none |
| Block | no | no | yes | `None` | none |

Ready-stream pooling stores a completed target-bound handshake. Bare-TCP
pooling stores only a connected proxy-server socket and lets `dial_with_tcp`
perform the per-target protocol handshake. TCP-multiplexed and QUIC protocols
exclude both because their generation runtime owns reuse. Direct excludes both
because each flow's socket carries its own rule or global mark. VLESS with direct
TCP remains bare-poolable even when an independent UDP-only Xray pool exists.
XHTTP excludes both preconnect pools because its transport runtime owns physical H2 reuse.

Ready streams are keyed by runtime generation, node identity, and target; only
flows using the generation that dialed them may acquire them. After a reload
publishes its successor, retiring the old generation removes its ready streams,
target counts, warm claims, and hotness under the pool lock and refuses late
ready deposits, hotness updates, and warm claims for it. The successor starts
with an empty ready namespace. A rejected reload keeps the active pool state.
Bare-TCP keys remain proxy-server addresses; health purges remove that address's
bare entries and only the current generation's matching identity's ready entries.

A bare entry has completed only the proxy-server TCP connect. Before reuse,
the pool rejects any queued inbound byte, including a fatal TLS alert, because
protocol/TLS setup has not started and no server byte can be valid yet. There is
no SNI/alert special case and no handshake retry on that socket. A Ready entry
has completed its target-bound protocol handshake, so already buffered target
data remains valid and does not make it stale.

Registry assembly checks that descriptor capabilities, populated slots, and runtime kinds agree.
Node-dependent entries may carry a packet slot even when the default node lacks
UDP. `block` is the explicit exception: its descriptor says no UDP capability,
but its packet slot is allowed through dispatch so the selected block decision
can reject the flow terminally.
UDP-disabled nodes produce an ordinary capability refusal, allowing configured
cold-candidate fallback. Explicit target policy remains a terminal, health-neutral
refusal; it is not interchangeable with missing UDP support.

### Protocol and UDP inventory

| Handler | TCP behavior | `dial_udp_transport` |
| --- | --- | --- |
| `direct` | Native marked target connect | Native marked UDP behind `PacketTransport` |
| `block` | Rejects | Explicit reject-path exemption; carries no UDP |
| `socks5` | SOCKS CONNECT | RFC 1928 UDP association, one control stream and one relay-connected socket per client source for all its destinations; each request header names its destination, each reply returns the real wire source (IPv4-mapped IPv6 as IPv4). A domain source is accepted only as the dialed name on its port and projects to the captured target; any other name is dropped without DNS. On send, only the dialed name is written; any other name goes out as the numeric target. A truncated, nonzero-RSV, fragmented (`FRAG != 0`) or non-UTF-8-domain relay datagram is dropped on its own at DEBUG; an unknown ATYP or control EOF ends the association. Greeting/authentication and the ASSOCIATE request/reply (including relay DNS resolution) each have a five-second timeout |
| `ss` / Shadowsocks 2022 | Shadowsocks stream | Shadowsocks packet framing; one connected server socket and crypto state per client source, usable for every destination (see below) |
| `trojan` | Trojan stream over shared transport | Trojan UDP framing when `network` allows UDP; one associate stream per client source, each frame names its peer |
| `vmess` | VMess stream | Unimplemented |
| `vless` | Direct, H2, or Mux.Cool from the independent multiplex policy | Available when `network` allows UDP; encoding and optional UDP multiplexing select the path |
| `hysteria2` | QUIC stream | Hysteria2 QUIC datagrams |
| `anytls` | AnyTLS logical stream | UoT v2 logical stream |
| `tuic` | TUIC v5 QUIC stream | QUIC datagrams or uni-stream fallback |
| `juicity` | Juicity QUIC stream | One length-framed QUIC bi stream per client source, carrying every destination |

Shadowsocks (legacy AEAD and 2022) serves every destination of a client source
from one `MultiTargetTransport`: one marked socket connected to the server, one
set of crypto state, and, for 2022, one client session ID, one monotonically
increasing packet counter and one pair of server-session replay windows that
never reset per destination. The default target's address header is
pre-encoded; other destinations are encoded into a stack buffer. `recv_packet`
returns the authenticated inner address as the peer, so a reply from a
never-contacted host reaches the core as that host (IPv4-mapped IPv6 is
normalized to IPv4). A domain source is accepted only as the dialed domain and
port (ASCII case-insensitive) and is projected to the dialed target; any other
domain is dropped without DNS. On send only the dialed name is written per
datagram; any other name goes out as the numeric target. Short, wrong-key, replayed, bad-address or
unprojectable datagrams drop only themselves; 2022 replay state is committed
only after the address decodes. The outer socket stays connected to the
server, so whether an unsolicited peer can reach the client depends on the
server's own NAT behavior.

VMess and VLESS entries are compiled only with the `rprx` feature. The default
`honk-core` and `honk-tool` feature sets enable it. Without `rprx`, these node
forms still parse, but the registry contains no entry and dials fail with the
ordinary `No handler for protocol` refusal. Normal feature-off builds allocate
no VLESS runtime pools or carrier semaphores. Unit builds retain backend-only
coverage through `cfg(test)`; the feature-boundary integration test links the
normal library to verify that distinction.

Unknown transports, invalid pins/REALITY keys, and reserved built-in names/protocols fail closed.

## Runtime ownership and reload

`src/runtime.rs` defines `OutboundRuntimeRegistry`, the control plane's single owner of reusable
outbound state for one immutable configuration generation. It maps `Node.id` to
`NodeRuntime`:

- immutable `Arc<Node>` configuration;
- the node-aware `udp_capable` result;
- one `ProtocolRuntime` selected by the descriptor; and
- optional transport-owned XHTTP state beside, not instead of, the protocol runtime.

`ProtocolRuntime` is `None`, AnyTLS state, `VlessRuntime`, or one type-erased
QUIC client slot. Every VLESS node owns a `VlessRuntime`; it contains only the
H2/shared-Cool/separate-Cool pools selected by configuration plus the lazy
private source-ID key. Handlers remain stateless with respect to these
generation-owned resources.

- Structured/imported raw TCP TLS ALPN lives in `TlsOptions.alpn` (flat serde `tls_alpn`, omitted when empty). `Node::validate_protocol` requires enabled ordinary TLS on AnyTLS or TCP Trojan/VMess/VLESS, rejects REALITY/WS/gRPC/QUIC overrides, and bounds names to 1–255 bytes plus the encoded list to 65,533 bytes. Nonempty ALPN derives a child UUID v5 using the base ID as namespace and the JSON tuple `["tls-alpn", <ordered list>]` as name, separating it from arbitrary credential text; empty lists retain that base ID, including VLESS's re-derived identity. URI/v2rayN ALPN compatibility and TUIC's separate `tuic_alpn` remain unchanged.

XHTTP is a separate H2-only profile. Canonical nodes carry `["h2"]`; ordinary TLS and REALITY configure that offer without changing raw-TCP, WS or gRPC profiles. Ordinary TLS rejects a peer that does not negotiate H2 before sending proxy bytes. Authenticated REALITY selects H2 by transport contract: official Xray deliberately omits server ALPN. Explicit cleartext XHTTP requires H2 support at the peer. Its canonical request and TLS/plaintext shape participates in node identity and reload reuse.

Admission-scoped TCP feedback starts once at the first admitted physical attempt or before logical open on a reused session/QUIC connection; cold admission waiting remains unstarted, while completed paths without either boundary retain the completion fallback.

### Generation lifecycle

Startup builds and validates the full runtime registry before publication.
Reload builds a replacement registry against the previous one. A runtime is
eligible for transfer only when the full node configuration is equal, ignoring
parse-time `created_at` and `updated_at` metadata.

Transfer occurs at the reload commit point. The old generation records moved
`Node.id` values only after the replacement is published, then skips those
runtimes during drain and shutdown. Unchanged nodes keep:

- TUIC, Juicity, and Hysteria2 QUIC clients and connections;
- AnyTLS physical sessions; and
- the complete VLESS runtime, including H2/Mux.Cool carriers and its source-ID key.

A retiring generation first becomes terminal to new work. Non-transferred
AnyTLS and VLESS pools enter draining: no new logical streams are admitted, but
existing streams retain their carriers until completion. QUIC flows own
connection clones, so terminal generation checks reject new work while current
flows finish naturally. Process shutdown force-closes remaining pools and QUIC
clients only after the process-level flow drain.

Generation-free callers such as standalone probes use
`EphemeralRuntimeGuard`. AnyTLS or VLESS streams and packet transports retain
the guard for their whole lifetime. Normal completion can await `close`; drop
also starts deterministic teardown, so a throwaway pool cannot survive an
aborted caller. Single XUDP also uses its VLESS runtime for the per-source key,
even though its private carrier is not in a reusable session pool.

### Dial admission

Physical outbound connects (including direct TCP and proxy TCP/QUIC attempts) and their protocol handshakes acquire two permits:

1. the captured generation's configured dial gate; then
2. the immutable process-wide startup ceiling shared by overlapping reload
   generations.

Acquiring the generation gate first prevents a low-limit generation from
hoarding process capacity. A replacement can apply a new generation-local
limit immediately, while old in-flight work continues to occupy the shared
process gate. Logical streams on already warm sessions do not perform another
physical dial.

Session pools bind autonomous replacement dials only to the published owner's
admission. Reload publication atomically rebinds transferred pools before
predecessor retirement; a late speculative commit cannot restore its predecessor's
gate. Retirement clears the stored admission immediately, and an uncommitted
`PreparedUdpTransport` retains neither generation nor process dial-admission permit.

Pool waiters register for capacity changes before checking availability. Every
pool-owned stream permit, including the first detached permit, notifies waiters
when released. Carrier publication wakes all eligible waiters; a non-reserving
warm offer must not consume the only notification and strand a stream checkout.
The initiating caller subscribes before its dial task starts and consumes that
attempt's result directly. A completed local refusal remains terminal even when
a warm session could serve an ordinary failed spread attempt.
Pool-owned tasks recheck terminal state before polling the dial. An in-flight
normal dial reserves a reusable slot. Detached winner commits, including
multi-carrier batches, publish excess private carriers drain-only when ordinary
offers or in-flight dials fill the cap, preserving their already-admitted streams.
A batch validates every member before publishing any; dropping a loser or
committing into a retired pool still closes only its private carriers.
Releasing warm retention also wakes capacity waiters as excess live carriers
enter Draining, without waiting for their existing children to finish.
Maintenance likewise publishes capacity released by max-age drains or closed
session pruning, even when no idle carrier is closed and no prewarm runs.
Backend close and Active-to-Draining transitions notify that same owning pool,
including H2 driver termination while child permits remain held. Sessions bind
the pool notification before publication or detached attachment; manual pruning
also broadcasts when it removes an already-closed carrier.

VLESS physical carriers additionally hold one permit from the immutable
process-wide VLESS-carrier gate. The startup resource budget computes
`min(after_dials / 8, 8192)` before sizing UDP endpoints; zero remains zero.
Reloaded traffic and DNS runtime forks share the same gate. A permit stays with
actual carrier I/O through provisional, active, draining, and idle task
teardown. This gate, not a sum of node-local pool caps, is the authoritative descriptor bound.

## Shared stream, socket, and bootstrap layers

### Stream transport

`src/proxy/transport.rs` is shared by Trojan, VMess, and VLESS, driven by `StreamTransportOptions` fields `transport`/`ws_path`/`ws_host`/`grpc_service`/`xhttp` through `node.transport()`. The order is fixed:

```text
TCP -> optional TLS or REALITY -> optional WebSocket, gRPC or XHTTP -> protocol header
```

`maybe_tls_wrap_concrete` preserves the concrete TCP/TLS type needed by VLESS Vision direct-copy.
When REALITY parameters are present, its [bounded authenticated setup](#server-authentication-and-fingerprint-constraints)
replaces ordinary TLS. The same shared path therefore gives Trojan, VMess, and VLESS
consistent TLS, REALITY, WS, gRPC and XHTTP setup.

Cold and pooled-bare Trojan streams use that same complete transport stack.
TLS batching returns bytes already read before surfacing a later I/O error on
the next non-empty read; it never converts that error into EOF.

Trojan UDP carries every destination of a client source on one UDP-associate
stream: the request header names the first destination, and each frame
(`address | u16 length | CRLF | payload`) then names its own peer, in both
directions. `recv_packet` returns the frame's real peer (IPv4-mapped IPv6
canonicalized), so the core can admit a first reply from a never-contacted
peer. A domain-named frame is accepted only when it equals the captured dial
domain and port, then projects to the captured target; any other domain frame is
consumed whole (length, CRLF, payload) and dropped without DNS. On send only the
dialed name is written per frame; any other name goes out as the numeric target.
An unknown ATYP has no derivable length and ends the stream. Frames share the stream's writer:
a stalled partial frame is terminal for the whole source, never congestion, and
destinations share head-of-line blocking and failure fate. Domain-target scopes
stay per original destination.


`transport_quality` owns advisory per-runtime carrier pressure. Common TCP/TLS/REALITY and AnyTLS use a physical-I/O adapter; Shadowsocks borrows its existing socket half. Linux `TCP_INFO` is read at most once per active second, checking each field against the returned ABI length; missing fields/errors remain unknown and never alter I/O. Vision Direct and ready-pool descriptor probing retain the socket path. Hy2/TUIC/Juicity reuse their existing one-second physical QUIC monitor, excluding pre-confirmation/pre-publication history and reseeding on peer changes. Logical mux children do not each report the same carrier event. No extra descriptor or per-TCP sampling task is retained; quiescent TCP has no new event-driven observation. See [Score pressure semantics](./groups.md#score-scoring-and-lifecycle).

`proxy/transport/grpc.rs` implements gRPC gun framing over the existing `h2`
client. HTTP/2 framing, HPACK/Huffman, continuation assembly and dynamic-table
state belong to `h2`, with a 64 KiB response-header limit and the default 4 KiB
dynamic table. The stream owns its connection driver and socket directly;
dropping it closes the transport without a detached task.

The opening request does not set `END_STREAM`; TLS requests use `:scheme: https`
and negotiate `h2` independently of the fingerprint profile. DATA preserves the
gRPC length prefix and protobuf single-bytes-field envelope used by gun peers.
One owned application message of at most 16 KiB may wait for transmission;
cancellation never attributes its bytes to a later caller buffer. `h2` fragments
it across positive send windows, including windows smaller than the envelope.
Flush waits for queued DATA and the physical transport flush, not merely a
control-frame flush. Request shutdown sends `END_STREAM` without discarding the
response direction; split readers and writers both receive driver wakeups.

Non-200 responses, trailers-only refusals, nonzero gRPC status, stream resets and
error/excluding GOAWAY are stream errors rather than clean EOF. Already buffered
payload precedes terminal read errors, which remain errors on later reads;
successful receive completion remains EOF even if the write direction later
fails. An admitted stream can finish after graceful GOAWAY; no application
bytes are retried.

VMess records errors returned by its relay before closing the duplex half, so
response-header and body-decoding failures reach the stream owner instead of EOF.

#### XHTTP carrier and logical-flow ownership

`proxy/transport/xhttp.rs` adapts raw H2 bodies to the existing stream contract. It owns a node-local `SessionPool`, not a second proxy protocol or loopback relay. Download settings add a second peer with its own pool and dial node, which carries only GETs; a caller-supplied socket always belongs to the upload peer, and winner commit validates both peers' private carriers under one lifecycle lock and both pool locks before publishing either, so a dead carrier on either side publishes neither. Each pool keeps at most two reusable physical carriers; draining carriers may overlap replacements under the existing process descriptor and VLESS-carrier gates. Physical drivers retain their socket, observation and carrier permit; HTTP requests and logical proxy flows hold separate reservations. The peer's advertised concurrent-stream limit remains authoritative, including zero, one and later reductions.

Each carrier retains up to 2048 locally reset requests (16 admission windows) for h2's default one-second in-flight-frame grace period and keeps its bounded default lifetime budget of 1024 protocol-error resets; steady short-flow churn can cancel several admission windows before old reset state expires, so retention must exceed the active-request bound.

Stream-one uses one POST; stream-up uses a GET and streaming POST; packet-up uses a GET and ordered finite POSTs. Establishment returns a writable stream without waiting for response headers. Upload-response padding is drained and discarded, never reported as application RX. Packet-up sends the first data after idle immediately, with no additional batch delay. Consecutive POSTs respect `scMinPostsIntervalMs`; bytes accepted while a POST is paced or its body is in flight coalesce into the next POST. The per-flow byte buffer and eight unanswered POSTs bound backpressure; subsequent POSTs may progress after the previous body was physically written, without waiting for that response.

Legacy upload padding uses a Referer built from the configured base path with its query replaced by the generated `x_padding` value; the request itself retains the configured query.

Stream-one and stream-up flush wait for byte ownership release and physical I/O flush under current H2 flow control. Packet-up flushes for protocol setup and the first application write wait for their entire accepted byte prefix to be physically flushed, including across multiple POSTs; VLESS Encryption reserves an extra setup barrier, retained on resumed 0-RTT connections even when the handshake shares the header flush. Flushes without new bytes do not consume these barriers. Later packet-up flushes only check retained errors and do not wait for a POST, so a write/flush datagram loop batches across the pacing interval. Dropping a packet-up stream without shutdown discards accepted bytes not yet uploaded; shutdown is its only upload-completion barrier. Buffered download bytes precede terminal errors. Upload shutdown retains the response direction; stream-up completes once its request END_STREAM is physically flushed and continues draining its POST response, retaining late upload refusals. Packet-up shutdown waits until every accepted byte's POST response has completed and checks its status, with no fabricated EOF marker. Graceful GOAWAY stops new requests on that carrier while retaining admitted streams; only future new POSTs move to a replacement, with no ambiguous application replay. New logical-flow admission closes on retirement, while already-admitted packet flows retain the request capacity needed to finish.

If a peer stream-limit reduction makes a reserved packet-up upload lane unusable, its carrier begins draining before replacement admission. Existing GETs remain alive while the replacement acquires upload capacity; the old reservation cannot pin the reusable-carrier cap.

A ready stream-up upload-response failure takes precedence over simultaneous request END_STREAM completion, so shutdown reports that refusal rather than successful half-close.

Ephemeral establishment is guarded through cancellation, pool-owned handshakes have a deadline, and speculative UDP carriers stay unpublished until the winner's fallible commit. Closing or losing a preparation rolls back its reservations. Existing runtime shutdown, retirement and idle maintenance own cleanup; no protocol-specific janitor or production per-packet telemetry is added.

### Marked sockets and name resolution

`util.rs` centralizes outbound socket creation:

- `connect_marked` resolves then connects TCP with timeout, nodelay,
  keepalive, and optional `SO_MARK`;
- `connect_outbound` applies the bypass mark for proxy-server TCP; and
- `udp_marked_bind` and `marked_udp_socket` create bypass-marked UDP sockets.

Control-plane sockets use the process-scoped `global.so_mark_from_dae`; zero
selects `DAE_BYPASS_MARK` (`0x100`). Nonzero direct rule marks instead use
`rule_mark | CLASSIFIED_MARK`, without leaking the override into bootstrap or
proxy carriers. WAN egress recognizes both forms. Mark application remains
best-effort only for unprivileged `EPERM` environments without the production
datapath; other errors propagate.

Subscription and direct UI downloads use the same marked TCP dialer before
Hyper HTTP/1 framing and the existing rustls/platform-verifier TLS policy. This
includes the first subscription fetch before eBPF attachment; TLS setup failures
return download errors rather than panicking. Subscription URL credentials become
sensitive Basic Authorization headers unless explicitly overridden. They survive
same-origin redirects but are permanently removed on a host, port, or scheme
change, even if a later hop returns to the original origin. Redirect userinfo
does not supply new credentials. Body limits and HTTP(S) environment proxy
connections retain their download boundaries.

Marked UDP sockets request 8 MiB each for `SO_RCVBUF` and `SO_SNDBUF`. Linux
may clamp and reports twice the configured sysctl accounting value; the core
raises the corresponding maxima at startup.

`bootstrap.rs` prevents proxy-hostname resolution from depending on honk's own
intercepted DNS path. Node dial sites use `bootstrap::resolve` through
`connect_marked` or the QUIC setup and never call bare `lookup_host` directly.
The configured bootstrap resolver is queried over bypass-marked UDP/TCP; failure
falls back to `/etc/hosts` and marked DNS to the first numeric nameserver in
`/etc/resolv.conf`. This does not invoke libc NSS or apply search suffixes.
A and AAAA are queried concurrently, each within its own 3 s budget, and only a
response matching the random query ID and the exact question is accepted; a truncated UDP answer is retried over marked TCP.
`query_ech_config` uses the same raw path for DNS HTTPS records (`qtype 65`)
and extracts the SVCB `ech` parameter.

After resolution, `src/address_race.rs` schedules proxy-server TCP `connect_marked`
and shared QUIC `QuicClient` attempts with stable IPv4/IPv6 interleaving and at most
two addresses in flight. The first starts immediately;
the fallback starts after 250 ms. An earlier failure advances the fallback,
while keeping physical attempts at least 10 ms apart. Every in-flight address
attempt holds its own generation and process dial permits, so
at the configured ceiling a fallback waits for an earlier attempt to finish;
`max_concurrent_dials: 1` serializes addresses. The race stays inside the
already selected node: socket marks and security settings are identical, and
TCP TLS setup and QUIC protocol setup/authentication run only on the winning transport; QUIC TLS handshakes participate in address racing. Errors are reported deterministically in original address order.

`crates/honk-outbound/src/bootstrap.rs` provides bootstrap DNS resolution for proxy-server hostnames (dae `bootstrap_resolver` parity): process-wide resolver querying over bypass-marked UDP/TCP with a hand-rolled wire codec, falling back to `/etc/hosts` and marked DNS to the first numeric `/etc/resolv.conf` nameserver without libc NSS. Node dials must use it (wired into `util::connect_marked` and `quic.rs`), never bare `lookup_host` — otherwise resolution deadlocks against honk's own intercepted DNS path. Also carries the raw-query path behind ECH discovery: `query_ech_config` (HTTPS RR qtype 65, SVCB `ech` param parsing) used by `tls::discover_ech_config`.
`crates/honk-outbound/src/util.rs` holds `connect_marked` / `connect_outbound` (TCP `SO_MARK`, keepalive, timeout), `udp_marked_bind`. `marked_udp_socket` requests 8 MiB `SO_RCVBUF`/`SO_SNDBUF`; Linux clamps each request to `rmem_max`/`wmem_max` respectively and reports twice the accounting value. Non-mock honk-core startup attempts to raise `net.core.rmem_max`/`wmem_max` to 16 MiB and only warns on failure: the 208 KiB default caps QUIC at ~2 Gbps/ms RTT. Follow the runtime **Bypass mark** invariant; otherwise `wan_egress` loops sockets into `daens`.

## TLS, fingerprinting, ECH, and pins

All production TLS in the outbound and DNS transport stacks uses BoringSSL. TCP uses `boring` and
`tokio-boring`; QUIC uses the custom `quinn-proto` crypto backend. The trust
store is built from `webpki-root-certs`. Explicit no-verify connectors exist for
configured insecure operation and for REALITY, whose own post-handshake check
replaces PKI.

- `src/tls.rs` — **BoringSSL TLS client** with webpki/no-verify stores. Process-wide `set_tls_mode` (`tls_implementation = "utls"`) selects a Chrome-oriented ClientHello profile: GREASE, permuted extensions, hybrid then classic X25519 shares, Chrome-derived sigalgs/curves/ciphers, brotli certificate compression, ALPS-h2, and ECH GREASE. This is protocol emulation, not a claim of complete Chrome identity. Per-node **ECH** uses `ech_config` / `ech_config_path`; discovery uses DNS HTTPS records and remains best-effort/fail-open, while an explicit server ECH rejection fails closed.
  `build_reality_connector(chrome)` replaces PKI with post-handshake ed25519 authentication in `reality.rs`, permits TLS 1.3 only, and never offers REALITY resumption. REALITY necessarily adds ed25519 to the signature list, another reason not to describe it as a full browser fingerprint.
  Explicit structured TCP ALPN reaches `build_connector` in both tls/utls modes; empty lists retain existing profile defaults. Chrome ALPS follows exact `h2` membership. Registry publication and direct connector construction validate nonempty overrides; shared stream dispatch validates before choosing plaintext or REALITY, and direct QUIC configuration rejects TCP ALPN rather than ignoring it.
  `build_connector` and `build_reality_connector` return shared BoringSSL contexts, one per (REALITY, verification, pin, ALPN override, Chrome mode) shape, kept in a process-wide cache that restarts empty at 128 shapes. Each context holds the process-wide webpki store instead of the OS CA bundle that `SslConnector::builder` parses by default, so a dial parses no certificates and a live connection pins no private CA copy.

### Process-wide TLS profile

`tls_implementation = "utls"` enables the one implemented Chrome-oriented
emulation profile process-wide. It configures:

- GREASE and per-connection extension permutation;
- `X25519MLKEM768` followed by `X25519` key shares;
- Chrome-derived signature algorithms, curves, cipher set, and ALPN;
- brotli certificate compression;
- ALPS for h2 using the historical `0x4469` codepoint; the reviewed
  [uTLS Chrome_133 profile](https://github.com/refraction-networking/utls/blob/aa6edf4b11af/u_parrots.go)
  uses `0x44cd`; and
- ECH GREASE when no real ECHConfigList is available.

Other `utls_imitate` names warn and use this profile. `tls_implementation = "tls"`
keeps the ordinary BoringSSL ClientHello. Neither setting promises complete
browser identity.

### ECH and certificate pins

A node can provide a static ECHConfigList inline or by file. Invalid explicit
configuration fails registry construction. A server-side `ECH_REJECTED` is
fail-closed; offered retry configs are logged but not persisted.

When only ECH discovery is enabled, the connector queries DNS HTTPS records at
connect time through the bootstrap path. Positive results follow a bounded
record TTL and negative results cache for five minutes. Discovery is
best-effort and fail-open: a lookup failure means no real ECH for that
connection, while Chrome mode can still send ECH GREASE.

`pinSHA256` (`tls_pin_sha256`) compares the SHA-256 digest of the leaf certificate and replaces
both PKI chain validation and hostname validation. An invalid pin fails closed.
The same rule is implemented in TCP `tls.rs` and the QUIC crypto backend.

## REALITY client

`src/reality.rs` implements the specialized TLS-1.3-only REALITY BoringSSL
handshake through `RealityConfig`, `parse_reality_config`, and
`reality_connect`. The workspace's patched `boring-sys` supplies two client
hooks ([Technology stack](../../../AGENTS.md#technology-stack)):

- `SSL_set1_client_x25519_private_key` presets honk's ephemeral private key for
  the standalone X25519 share; and
- `SSL_set_client_hello_fixup_cb` rewrites the serialized ClientHello before it
  enters the handshake transcript.

### ClientHello authentication

The first ClientHello advertises `X25519MLKEM768` first and standalone `X25519`
second. REALITY authentication deliberately derives from the preset classic
X25519 private key/share even when the peer negotiates the hybrid share. The
fixup callback zeros the 32-byte legacy `session_id` slot and computes:

- `authKey = HKDF-SHA256(X25519(eph, pbk), salt=clientRandom[:20], "REALITY")`;
- nonce `clientRandom[20:32]`; and
- `AES-256-GCM(authKey).Seal([ver:3][0][ts:4][shortId:8])`, with unchanged
  version bytes `1,3,3`, reserved byte `0`, a big-endian u32 timestamp, and an
  eight-byte short ID. The AAD is the whole zero-session-ID ClientHello.

The 16-byte encrypted plaintext and 16-byte tag fill the session ID. An empty
short ID is eight zero bytes; a configured value is even-length hex of at most
eight bytes and is right-zero-padded. Parse or fixup failure aborts before an
unauthenticated ClientHello is sent. The callback seals exactly once: a second
invocation, including an HRR second ClientHello, aborts before GCM key/nonce
reuse. The client therefore does not claim HRR support.

### Server authentication and fingerprint constraints

REALITY replaces ordinary certificate verification: the peer leaf must be an
ephemeral ed25519 certificate whose signature is exactly
`HMAC-SHA512(authKey, raw ed25519 public key)`. A mismatch, an ordinary
mask-target certificate, or any other authentication failure is fail-closed;
the client does not infer a unique remote cause. There is no PKI fallback or
session resumption.

The shared VLESS/Trojan/VMess transport permits one compatibility attempt only
when the first completed TLS handshake presents a non-ed25519 leaf. It drops
that connection, then opens a fresh bypass-marked TCP socket to the same peer
address and offers only X25519. SNI, server public key and short ID are unchanged;
the SSL state, client random and ephemeral key are new. The replacement must
pass the same REALITY HMAC authentication before any proxy header or application
data is sent. An invalid ed25519 HMAC, missing certificate, TLS/IO error or HRR
does not trigger this attempt; every second-attempt failure is terminal.

This certificate outcome is unauthenticated, not proof of a legacy server:
wrong credentials or an active attacker can induce the classical attempt, but
cannot bypass its authentication. There is no cached profile or new setting.
Both attempts, admission waits and connections share one setup deadline of
`3 × connect_timeout`; outer caller deadlines can expire sooner. Cold replacement
holds the failed socket's admission credit through authentication; supplied or
pooled sockets acquire fresh credit rather than borrowing a sibling's permit.
Direct callers of the low-level `reality_connect` helper remain single-attempt.

The profile prepends ed25519 to the Chrome-derived signature list so BoringSSL
can verify the server's TLS CertificateVerify with that leaf key. This differs
from the reviewed uTLS Chrome_133 profile; no full Chrome-identity or specific
JA4 value is promised.

Target buffering is a server-version constraint, not a universal honk client
certificate limit. The documented sing-box 1.12 / MetaCubeX-uTLS 1.8.0 peer uses
an [8192-byte buffer for target TLS records](https://github.com/MetaCubeX/utls/blob/v1.8.0/reality.go),
including record framing; the limit is not based on DER certificate length alone.
The reviewed [XTLS/REALITY implementation](https://github.com/XTLS/REALITY/blob/8cdf7bf9c7f0/tls.go)
uses a 17-KiB buffer. Choose a target compatible with the deployed server version.

## VLESS wire contracts

Canonical configuration is `VlessConfig` in `honk-config/src/node/vless.rs`.
UDP permission, protocol packet encoding, and multiplexing are independent axes:

| Axis | Values | Path effect |
| --- | --- | --- |
| `network` | TCP-only or UDP-enabled | Sole UDP capability gate; disabling UDP does not select an encoding. |
| `udp_encoding` | `auto`, `native`, `xudp`, `uot-v2` | Selects the non-multiplexed packet protocol. `auto` uses native command-UDP on 53/443 without Vision and Single XUDP otherwise. |
| `multiplex` | `off`, H2, Xray | Independently selects direct/H2/Mux.Cool TCP and protocol/H2/Mux.Cool UDP paths. H2 alone owns its padding flag. |

Xray TCP concurrency zero means 8 and a negative value disables TCP mux. XUDP
concurrency zero follows the TCP pool, negative returns UDP to its protocol
encoding, and a positive value creates a separate UDP pool. Positive values
normalize to `1..=128`. Its UDP/443 policy defaults to `allow`: use the configured
UDP pool, or the protocol encoding when no pool is enabled. An explicit `reject`
remains terminal even with both pools disabled. `skip` selects the protocol
encoding instead of the pool. Vision adds no implicit port-443 restriction.

The client never probes the server for another path, retries with another
framing, or replays a first UDP packet. Native VLESS uses u16-framed connected
command-UDP without the UoT magic destination or setup preamble. Sends accept
1–8190 bytes; received zero-length frames are datagrams, not EOF. The writer is
flush-confirmed and a cancelled ambiguous write is not replayed.

Explicit `uot-v2` uses non-connect UoT v2: the request carries mode byte `0` and
the first destination, then every datagram in both directions is
`[ATYP 0/1/2][address][port][u16 length][payload]` (UoT v1 numbering) with up to
65535 payload bytes. One stream therefore serves every destination of a client
source (the core `Shared` source) and each reply keeps its real peer: numeric
peers are returned with IPv4-mapped IPv6 canonicalized, the captured dial domain
and port are projected back to the logical target, any other domain is dropped
without DNS and consumed whole, and an unknown ATYP ends the stream. Unlike XUDP
there is no empty-first or poisoned-child rule. The request and first datagram
share one write; an interrupted write poisons the stream and is never replayed.
A flow dialed by name sends that name in the request and per datagram; any other
name (and a numeric flow) goes out as the numeric target. Real sing-box 1.12.4
fixes its direct outbound's form by the first destination: after a domain request
it maps the same name per datagram, but after a numeric request a per-packet FQDN
fails with `invalid AddrPort: missing address` and ends the whole association.
The same rule applies to H2MUX PacketAddr, AnyTLS, Trojan, SOCKS5 and Shadowsocks
(`addr::dialed_name`); Juicity is unchanged and unverified, as no
juicity-server is available.

Typed policy, size, and carrier-capacity refusals are terminal local results,
distinct from congestion or transport failure. They do not demote health or
Score. Candidate admission checks policy before committing protocol state;
DNS, health, and CLI callers preserve the rejection rather than selecting a
fallback or reporting the path as not applicable.

### H2MUX

`src/proxy/uot.rs` and `src/proxy/vless/mux.rs` implement shared UoT v2 framing
and sing-box H2MUX. H2MUX sends the physical VLESS request to
`sp.mux.sing-box.arpa:444`, selects backend `2`, then runs HTTP/2 over that
carrier. Logical streams carry TCP or UDP. UDP streams set sing-mux flags
`UDP|Addr` (`3`) and, after the request naming the first destination, carry
`[SOCKS5 address][port][u16 length][payload]` in both directions (SOCKS5 ATYPs,
unlike UoT v1 numbering). One stream is the shared source of a client and
returns real peers under the same projection and drop rules as UoT; a dropped
frame still releases its HTTP/2 credit. There is no loopback bridge.

Optional H2 padding adds the sing-mux v1 randomized preface and record framing
for the first 16 records in each direction. A node has at most two reusable or
dialing H2 carriers, and each carrier admits at most 128 concurrent streams; a
draining carrier may overlap its replacement. The 128 value is a concurrency
limit, not a carrier-lifetime/open-count rollover.

HTTP/2 flow control drives backpressure. GOAWAY makes the carrier draining and
rolls new work to a replacement. Driver failure fans out to its children;
half-close, reset, receive-window release, and lazy response errors remain
per-stream. Receive credit stays 2 MiB per stream and connection credit remains
large enough for one maximum response frame for each admitted stream: status
byte, the widest address (259 bytes), the length and 65535 payload bytes. Credit
is released by the full consumed wire length of each frame, delivered or dropped.

### Mux.Cool and XUDP

`src/proxy/vless/cool.rs` and its `codec`/`child` modules implement the Xray mux
command, child TCP, and XUDP records. One ordered writer serializes every child
frame. Each carrier's effective concurrency is the configured positive limit
capped at 128. Session IDs increase monotonically and are not reused; issuing
ID 128 drains the carrier and a replacement takes new work. There is no
per-node two-carrier cap: the process VLESS-carrier FD gate is authoritative.

Receive payloads share an 8 MiB carrier budget. TCP delivery allows 100 ms for
transient budget or queue pressure before resetting only the stalled child;
UDP remains drop-on-full. Pooled Mux.Cool packets retain their 8 KiB cap;
Single XUDP retains its 7,526-byte cap.

### Source/session ownership and capacity

For source-shared protocols (Single XUDP, shared/separate Mux.Cool, Hysteria2, TUIC and every `MultiTargetTransport`), `honk-core` indexes
a source owner by reused `NodeRuntime` identity, normalized client address,
selected protocol/UDP path, and reply projection (`ActualPeer` or
`RewriteTo(original destination)`). One owner holds one protocol association
and one receiver; canonical five-tuple endpoints expose serialized send views. Single XUDP uses one
private unpooled SID 0 per scope; Mux.Cool gives scopes separate child SIDs that
may share physical pools.

Hysteria2 shares one Session ID and TUIC one association ID across the scope's
destinations. Different scopes can share a physical QUIC connection without
sharing their logical association. These QUIC source paths and their shutdown
joins remain available without `rprx`; only VLESS alternatives require it.

Hysteria2 and both TUIC receive modes retain concrete reply peers through the
existing bounded reassembler. Hysteria2 fragment addresses must agree; TUIC
continuations may omit the address and wait for fragment zero, even if it arrives
last. Peer metadata expires with its packet entry. A known requested domain and
port may use the captured target projection, with ASCII case-insensitive name
comparison; an unknown domain never triggers DNS or fabricates a foreign IP.
TUIC zero-length payloads remain datagrams; Hysteria2 keeps its existing rejection
of empty inbound payloads. Source preservation does not guarantee remote NAT
mapping or filtering behavior.

`MultiTargetTransport` is the one generic source transport for Shadowsocks,
Juicity, SOCKS5, Trojan, AnyTLS and VLESS UoT v2/H2MUX (Hysteria2, TUIC and VLESS
XUDP/Mux.Cool keep their concrete arms so their send path is not boxed). Each
client source owns one logical association for all destinations: one Shadowsocks
socket and crypto session (SS2022 never resets its session ID, packet counter or
replay windows per destination), one Juicity bidirectional stream, one SOCKS5
control connection with one relay socket, one Trojan associate stream, one
non-connect UoT v2 stream or one H2MUX PacketAddr stream. `recv_packet` returns
the real peer the server reports: an IPv4-mapped peer is IPv4, a domain source is
accepted only as the captured domain and port, any other domain (including an
empty or non-UTF-8 name) is dropped
without DNS, and stream protocols consume a dropped frame whole before reading
the next; an unknown address type stays terminal. `send_packet` and `send_to`
share one unboxed helper; `confirmed` reaches the transport only on each view's
first datagram, and `admitted` is set when the datagram reached the wire path or
the writer queue. Reliable-stream carriers (Trojan, Juicity, AnyTLS, UoT, H2MUX)
keep a partial-frame timeout terminal for the whole source, so destinations
sharing a stream also share its head-of-line blocking and failure fate. H2MUX
admits a datagram and starts its poison only when the first chunk is queued to
h2, so a flow-control wait before any byte is queued times out as packet-local
congestion and leaves the stream usable. Packet-local congestion lasts only while
the source still admits datagrams: a run of unadmitted deadlines that no admitted
datagram interrupts fails the source like any transport failure once it has
lasted 30 s, however far apart they fall, so replies cannot keep a wedged uplink
alive while an idle source, which sends nothing, is not blamed. A frame
write cancelled halfway poisons the stream with a typed `FrameInterrupted`: the
next send fails and the source retires every destination instead of appending to
a torn frame. When a view's own retirement cancelled that write, the retirement
is a neutral cancellation that charges no health or Score to the node; a
timeout-caused tear stays a transport failure. A native UDP size refusal (`EMSGSIZE`) is a typed
local `InvalidSize` rejection and ends nothing. The last view's endpoint permit
stays held until the source receiver exits or another view binds, which keeps
retiring sources inside the descriptor partition; for a short window a
saturated pool can therefore refuse a new endpoint. Core's send gate is the
only outer lock: backends hold their own leaf locks beneath it and never call
back into core.

The full `(client, destination)` endpoint map remains authoritative for route,
decision token, and per-flow Score. A reply for a Ready entry is delivered only
when that endpoint belongs to the source owner. A wrong owner or an
`Initializing`/`Retiring` entry is dropped, never reclassified as foreign. Only
an absent key in an `ActualPeer` scope is eligible for a foreign full-cone reply,
which updates source transport accounting but has no flow Score owner. Domain
routes use `RewriteTo(original)` and never become foreign replies.

The VLESS runtime lazily creates a private keyed source-ID hash from this scope.
Carrier replacement under a reused runtime preserves the ID; runtime
replacement or process restart creates a new key. This intentionally preserves
honk's per-source behavior, not Xray's source-only global identity and not a
collision-free NAT guarantee. Late callbacks recheck source owner and endpoint
token/generation before acting; ambiguous sends are never automatically replayed.

For comparison, the [reviewed Xray implementation](https://github.com/XTLS/Xray-core/blob/c412e77a9b712082ac9ebf27fa793951cb5a7d85/common/xudp/xudp.go)
uses a process-wide random base key by default. Keeping `XRAY_XUDP_BASEKEY`
across client restarts is an explicit opt-in, not Xray's default. Honk has no
persistent-base-key option and also separates runtime, path and reply projection.
Neither stable ID bytes nor a reused carrier guarantee that remote NAT state
survives expiry or server restart.

The source owner reports shared DataUdp transport health. Each bound endpoint
retains its own Score reporter; matched replies and a shared terminal outcome
settle those flows separately. Foreign replies have no per-flow Score. Source
capacity exhaustion is `PacketRejection::Capacity`, terminal for that candidate
but health- and Score-neutral.

Source admission closure also publishes its neutral or failure settlement. The
common endpoint Score finalizer uses it even if driver cleanup wins the reporter
race. Never-bound views and views retired before that closure retain their local
result; shutdown remains neutral.
The last bound view retires its source only after pending attachments are also
gone; an attachment can still commit while a sibling view retires.

For VLESS, intentional endpoint retirement after queue admission ends the ambiguous source
without replay or negative transport health. Later senders and the receiver
retain the same cancellation cause, so a sibling send cannot reinterpret it as
a carrier failure.

QUIC source send tokens begin only after the source gate admits I/O, but remain
owned by the endpoint driver through success/timeout/failure classification.
Waiting for that gate consumes the existing send deadline without creating a
QUIC attempt. Datagram congestion and TUIC stream failures retain their distinct
semantics; cancellation or partial acceptance never authorizes packet replay.
Send start/completion and retirement intent share the source-state critical
section. It publishes both endpoint and source-view retirement flags after the
matching sender's intent, before either send or receive can classify cancellation.

Selector and UDP warm retention resolve independently: the TCP-selected pool
answers `WarmRequirement::Session`, while the UDP-selected pool answers
`WarmRequirement::Udp`. A UDP-only Xray pool therefore remains eligible for UDP
warming while direct TCP remains bare-poolable. The existing outbound
maintenance pass reaps unretained idle VLESS sessions; there is no VLESS-only
timer. Active, provisional, draining, and idle carriers all hold the process
carrier permit until their actual I/O task tears down.
Synchronizing unchanged retention does not drain either pool. Only an actual
unpin drains that pool's excess carriers; existing children continue to finish.
Only Active carriers count toward the reusable warm/standby floor. Draining
carriers with live children remain independently and cannot displace the idle
replacement; idle reaping and unpin removal traverse the pool linearly.

The descriptor partition is fixed at process startup and shared across reloads
and DNS forks. With `rprx`, it reserves `min(after_dials / 8, 8192)` carrier slots
before sizing UDP endpoints, even when the initial configuration has no VLESS
nodes; native VLESS UDP, UoT, and Single XUDP consume this gate too. Without
`rprx`, no carrier slots are reserved and UDP endpoints retain that headroom.
Exhaustion returns an immediate typed Capacity refusal, not a wait queue.

| Effective `nofile` | UDP endpoints without carrier reserve | UDP endpoints with carrier reserve | Reduction |
| ---: | ---: | ---: | ---: |
| 1,024 | 50 | 44 | 12.00% |
| 4,096 | 216 | 189 | 12.50% |
| 65,536 | 4,588 | 4,015 | 12.49% |
| 1,048,576 | 32,768 | 32,768 | 0% (endpoint cap) |

These are descriptor-derived limits, not preallocated endpoint memory; startup
further caps endpoints by [memory](./control-plane.md#queue-and-descriptor-budgets).
Reload does not recompute or enlarge the startup partition.

### Vision and VLESS Encryption

`xtls-rprx-vision` is carried in the VLESS addons. The response header is
stripped lazily on first read because it may arrive with target bytes. Vision
removes response padding. Without VLESS Encryption it requires raw TCP with
TLS 1.3 or REALITY; TCP multiplexing is always invalid, even when Encryption is
enabled. UDP-only Xray multiplexing is legal. Vision rejects native, UoT, and H2
UDP paths. Base `xtls-rprx-vision` allows UDP/443 over Single XUDP, including
with `mux=off`; users can block QUIC with routing rules. The input spelling
`xtls-rprx-vision-udp443` normalizes to base Vision before identity and runtime
reuse decisions. An explicit Xray `reject` remains terminal; `skip` uses the
protocol fallback. The wire addon remains the base Vision flow.

**Uplink Vision.** The dial sends the VLESS request together with Vision's
first frame: the UUID and an empty long-padded Continue frame, as Xray's client
does when no payload is ready. The request therefore stays inside the dial's
failure and deadline scope. Later uploads are padded frame by frame with Xray's
default padding. Recognized application-data termination follows the inner TLS
record boundary, not read/write call boundaries. Non-TLS payload uses End once
classified. A ClientHello keeps padding until the first complete
application-data record ends; that frame carries Direct when the downstream
ServerHello chose TLS 1.3 with a cipher Xray accepts (0x1301–0x1304) and the
codec has a direct writer, otherwise End. A 64 KiB inspection budget per
direction is checked after each frame or read.
Early application data without an observed eligible ServerHello, or inspection
budget expiry before an application-record decision, ends padding with End and
retains the selected outer transport for the rest of the uplink.

After an uplink Direct frame has left the outer codec and been flushed, uploads
bypass it. On TLS/REALITY the SSL write half is marked closed without sending
anything, so a later fatal alert or KeyUpdate acknowledgement is never written
into the raw uplink, and shutdown closes the TCP write side instead of sending
close_notify. A downstream Direct command still switches only reads, and
plaintext the SSL session already decoded is delivered before raw bytes. Each
direction switches independently. Padding adds bytes to every Vision
connection. On a loopback A/B against the pre-uplink relay, short Vision flows
(1 KiB up, 4 KiB down) cost about 2.6% more relay CPU, nearly all of it
padding; the handover bookkeeping is within noise. Flows long enough to reach
Direct and splice use less; non-Vision relays are unchanged.

`src/proxy/vless/encryption.rs` wraps the selected transport before the VLESS
request. The implemented protocol is `mlkem768x25519plus`, with `native`,
`xorpub`, and `random` wire modes. It accepts X25519 or ML-KEM-768 server keys,
including chained relay keys; new 1-RTT connections combine ML-KEM-768 and
X25519, and authenticated records use the selected AEAD. The optional 0-RTT
cache remains keyed by normalized node identity and invalidates a rejected
ticket path.

Encryption can wrap direct and Xray/Mux.Cool paths, including supported Vision
combinations, but not H2 or UoT framing. Vision Direct in either direction
removes only AEAD framing; the outer transport and random mode's per-record
header XOR remain, following Xray `XorConn` including its skip rule for
TLS-shaped headers. This is not a raw-socket cutover claim for encrypted Vision.
Random-mode Direct acknowledges and copies at most 8 KiB per write. Header XOR
state survives those short writes; native Direct adds no wire-copy buffer.
While traffic flows the codec reuses one write buffer, shared with
random-mode Direct, and rotates two read buffers, so steady frames allocate
nothing. A write buffer above one maximum frame, such as a large 0-RTT
prewrite, is dropped after use. A completed flush releases the write buffer,
and a read that waits at a frame boundary releases the plaintext buffer, so
an idle stream keeps only the five-byte header buffer.

## QUIC stack

TUIC, Juicity, and Hysteria2 use quinn 0.11. `src/quic.rs` owns transport tuning,
marked endpoints, connection single-flight, rotation, stream wrappers, and
shared fragmentation support. Protocol handlers translate node settings into
`QuicClientOptions`; the shared layer does not inspect protocol-specific fields.

Async `client_config(node, alpn, QuicClientOptions)` may discover ECH and builds
a quinn ClientConfig over the BoringSSL crypto backend. Options include
`congestion_factory` for cubic/new_reno/bbr or hy2 fixed-rate `BrutalConfig`,
keep-alive, stream/conn receive windows, and MTU discovery. Client `Endpoint`
uses `SO_MARK`'ed UDP sockets. The module also owns `QuicBiStream` and
`#[cfg(test)] testutil` rustls in-process interop servers.

### BoringSSL crypto backend

`src/quic/boring.rs` implements the client side of `quinn_proto::crypto::Session`
over BoringSSL's QUIC APIs (`SSL_set_quic_method`, `SSL_provide_quic_data`,
`SSL_export_keying_material`). It provides:

- TLS 1.3 handshake bytes and traffic-secret delivery;
- RFC 9001 initial, handshake, and 1-RTT packet keys via HKDF;
- AES-GCM and ChaCha20-Poly1305 packet protection via `boring::aead`;
- AES or ChaCha20 header protection via `aes` and `chacha20`;
- key update and Retry integrity; and
- QUIC transport-parameter exchange.

Header protection is packet-number-length aware. The first byte is unmasked
before deriving a received packet's one-to-four-byte packet-number length; only
that many bytes are masked or unmasked. Treating every number as four bytes
corrupts the following payload for short packet numbers and self-cancels against same-bug peers.

A process-wide, bounded `SESSION_TICKETS` cache stores BoringSSL TLS 1.3
sessions by ticket key (proxy keys include host, port, SNI, and ordered ALPN, and every key is
partitioned by `skip_cert_verify`, so verified and unverified connections never share a ticket). BoringSSL has no implicit client cache and requires
explicit `SSL_set_session` for resumption. `pinSHA256` nodes neither resume nor store tickets because a PSK handshake would bypass
the certificate pin. Rejected cached sessions are evicted without deleting a
newer concurrent ticket.

The backend can carry real ECH for hy2/juicity/tuic/DoQ/DoH3 and the Chrome QUIC ClientHello. Proxy outbounds
do not expose early packet keys to quinn, so they send no 0-RTT early payload;
no supported official TUIC, Juicity, or Hysteria2 server has accepted such early
data in interoperability checks.

Server probing (`rtt_probe`) found that quic-go resumes and official tuic-server issues no tickets. rustls lacks client ECH; quiche lacks per-connection ECH hooks.

### Shared client ownership

Each generation-owned `QuicRuntime` has one type-erased protocol client slot
(`QuicRuntimeClient`). `QuicClient<C>` single-flights connection construction, so concurrent first dials
share one handshake. It retains at most one reusable active connection.

Rotation overlaps naturally: each flow owns its `(Connection, protocol state)`
pair, typed `(Connection, Arc<C>)`. When the holder replaces a closed or invalidated connection, new work
uses the replacement while existing flows can finish on their old clones.
Dropping final warm ownership removes future reuse without cutting active flows.
The two bounded IPv4/IPv6 flow-control profiles, including adaptive receive/send
floors and cooldowns, belong to the runtime, not the optional client slot, so warm
release, rebuild, and speculative clients reuse the same learned path profile.

Each pooled QUIC connection samples Quinn path and UDP I/O counters once per
second for the aggregate `quic` section of `/stats`. Temporary URL/health probe
connections are intentionally excluded.
The same sample drives per-address-family flow-control profiles using honk Quinn's application-delivered/peer-acknowledged stream counters, connection-credit gauges, and stream-blocked frames. Ten-second
receive and send goodput EWMAs require three consecutive high-BDP samples at
SRTT >= 80 ms before raising the connection receive or send floor toward
`2 x BDP`. A peer `DATA_BLOCKED` frame makes the connection receive sample qualify without the RTT gate and sets its floor's target to `max(adaptive_window(BDP), 2 × current_window)`, because a `2 x BDP` target derived from the throttled rate would be a no-op; the three-sample requirement and the cooldown below still apply. The stream receive floor doubles on `STREAM_DATA_BLOCKED` alone, without a three-sample requirement, since aggregate connection goodput cannot identify one stream's demand. Each floor is capped at 32 MiB, has its own five-minute promotion
cooldown, never shrinks automatically, and applies to the live connection and
active/future streams without reconnecting. Zero-progress samples preserve a pending
promotion only while the corresponding connection credit remains pressured.
Native TUIC and Hysteria2 UDP
endpoints use a per-send deadline of `clamp(4 × SRTT, 1 s, 5 s)`; a deadline
alone never closes the connection, because Quinn parks a send while
congestion control holds capacity. The path watchdog closes the connection, so the next flow
redials, only when no newly acknowledged QUIC packet is observed for
`max(8 × SRTT, 10 s)` while at least three ack-eliciting packets sent since
the last acknowledgement are still unacknowledged. Observed delivery
progress resets that clock. Attempted UDP packets are never replayed. TUIC
also enables Quinn PING keepalive, including its UDP-over-stream fallback where
protocol heartbeat datagrams are unavailable.

### Protocol contracts

| Protocol | Authentication and TCP | UDP | Transport policy |
| --- | --- | --- | --- |
| TUIC v5 (`src/proxy/tuic.rs`) | TLS-exporter authentication on a uni stream; one TCP bi stream per flow | QUIC datagrams, fragmentation, and uni-stream fallback when datagrams are unavailable | 10 s heartbeat; default 8 MiB stream and 8 MiB connection receive windows, the latter auto-tuned up to 32 MiB, with node overrides |
| Juicity (`src/proxy/juicity.rs`, verified juicity-rs server interop) | ALPN `h3`; TLS-exporter auth; bi-stream header `[network][trojanc metadata]` | One bi stream per client source; opened once with `[network=3][metadata]`, then `[metadata][u16 length][payload]` records in both directions, each naming its own destination or source | Upstream juicity/juicity-rs default BBR; 8 MiB stream and 8 MiB connection receive windows, the latter auto-tuned up to 32 MiB |
| Hysteria2 (`src/proxy/hysteria2/`, `mod.rs`) | ALPN `h3`; minimal `h3.rs` HTTP/3/QPACK `POST https://hysteria/auth`, success status `233` | Native Hysteria2 QUIC datagrams and fragmentation | A positive `hy2_up_mbps` selects `quic::BrutalConfig` (window = max(rate×RTT, 10×MTU), ignores loss), otherwise BBR; `hy2_down_mbps` is sent in bytes/s through `Hysteria-CC-RX`; same 8/8 MiB default receive windows with the same connection auto-tuning |

The Go `juicity-server` v0.4.3 has an implementation-specific UDP relay limit:
its 1,500-byte requested buffer is rounded to 2,048 bytes, and oversized framed
packets are truncated by the server. Interop observed 8,192-byte payloads returning
2,048 bytes; 2,048-byte echoes passed. This is not a Juicity wire limit, so honk
does not impose an arbitrary 2,048-byte cap on other servers.

Juicity UDP uses the deployed trojanc ATYP numbering (IPv4 1, domain 3, IPv6 4),
not the differing numbers illustrated in the Juicity specification, and adds no
session bytes. A client source shares one UDP stream across all destinations, so a
cooperating server can relay them through one socket, and `recv_packet` returns the
peer named by each reply frame (IPv4-mapped IPv6 normalized to IPv4). A domain
source is accepted only when it equals, ASCII case-insensitively, the name the
stream was opened with and carries the same port; it projects to that stream's
target. Any other domain frame is consumed and dropped without DNS. An unknown
ATYP is terminal. Destinations dialed by a rewritten domain scope per original
destination. Every destination shares the stream's head-of-line blocking and
failure fate; a write that times out may leave a partial frame, so it retires the
whole source rather than counting as congestion. The QUIC send-attempt hooks stay
on the source path.

Hysteria2's HTTP/3 layer is deliberately local and minimal: control/QPACK
unidirectional streams, static-table QPACK, and enough HEADERS handling for
authentication. It must not advertise `SETTINGS_H3_DATAGRAM`; doing so starts a
competing quic-go datagram reader that deterministically consumes the first Hysteria2 UDP datagram.

Hysteria2 follows sing-quic's lazy TCP setup: dial returns after opening the bi stream, the first write merges the request and payload, and the first read validates/strips the response, saving one RTT.

`salamander.rs` implements self-contained Salamander obfuscation: it prefixes
each wire datagram with an 8-byte random salt and XORs the payload with repeated
`BLAKE2b-256(password || salt)`. Client-side port hopping
(`hy2_port_hopping`/`hy2_hop_interval`) selects a configured destination port from
the first send onward.
The server must DNAT the range to its listener. Receive metadata rewrites the
reply source port to the nominal remote port so QUIC sees one stable peer.

quinn's 1.25 MiB limits streams to ~12.5MB/s per 100ms RTT. The connection window
also budgets memory; slow consumers buffer ~3× it. It starts at 8 MiB and honk's
quinn fork grows it (`TransportConfig::receive_window_autotune`) like quic-go: when
more than half the window was read in an epoch and reading that fraction took under
`4 × fraction × RTT`, it doubles, up to the larger of 32 MiB and the configured
window. Growth is driven by bytes the application read, so a slow consumer does not
inflate it, and the window never shrinks. Overrides:
`tuic_init_stream_recv_window`/`tuic_init_conn_recv_window`, hy2 `hy2_init_*`.

## AnyTLS session engine

`src/proxy/anytls/mod.rs` implements sing-anytls multiplexing with stateless handlers. Each generation's `NodeRuntime::AnyTls` owns one
`SessionPool<AnyTlsSession>` and a BoringSSL connector built on the first dial; the connector is never idle-reaped because TLS contexts are shared per shape.
Generation-free calls use a guarded ephemeral equivalent.

### Pool and session lifecycle

`src/session.rs` defines the generic node-owned `SessionPool` for AnyTLS, VLESS
H2MUX, VLESS Mux.Cool and XHTTP (QUIC keeps `quic::QuicClient`). It enforces `Active`,
`Draining`, and `Closed` states, atomic stream permits, event-driven capacity
waits, least-loaded selection, and pool-owned single-flight physical dials.
Draining sessions are excluded from the reusable cap and can overlap
replacements while live streams finish. The pool also owns bounded retry
classification, backoff, retirement, and idempotent force shutdown.
A session already closed when its dial completes counts as a dial failure and
is never published. A caller whose own dial already ran never dials again; in
order it takes the least-loaded active session with room, waits on another caller's
in-flight dial, fails fast inside the backoff window, or waits for room on a
full active session, and with no active session it fails and counts a dial
failure.
Initialization waiters receive one `SharedError`, which clones the original
`anyhow::Error` through an `Arc` and preserves its source chain. The pool never
flattens a builder failure to display text before broadcasting it.
A dial task refused by its terminal runtime owner clears its own in-flight
registration, wakes waiters and counts one establishment failure under the
existing redial backoff. A refused janitor leaves no running flag, a refused
drain worker force-closes the retained sessions, and Mux.Cool fails the carrier
when its owner refuses END delivery.

AnyTLS configures eight reusable physical sessions and 128 streams per session.
It spreads work: while every session is busy and fewer than eight exist, the
pool establishes another before adding more load, then schedules least-loaded,
so concurrent streams do not share one TCP carrier's head-of-line stalls. Consecutive dial
failures use bounded backoff instead of one physical connect per proxied flow.
H2MUX and Mux.Cool instead fill the least-loaded carrier within their caps.

After v2 server-settings negotiation (`CMD_SERVER_SETTINGS`, `v=2`), every reused logical stream (SID 2 and
later) joins a per-SID pending set once its SYN is on the wire. A SYNACK settles
only its own SID; an unrelated acknowledgement never clears another stream's
deadline, and local stream teardown cancels it. An open still pending
three seconds after its SYN was written is reset at stream level when the
session kept receiving frames during the window (the server was alive but
never acknowledged that open). A fully silent window does not prove the carrier
is dead: a loss burst silences every stream at once, and TCP delivers afterwards.
In that case, only the pending open is reset and the session leaves rotation.
The session and its streams retire only after another ten seconds of silence,
so the pool redials instead of reusing a dead carrier.
All opens that time out in one silent window and its eventual retirement share
one node-failure episode in Score, rather than one strike per affected stream.

Sessions enter age-based drain at 30 minutes with per-session jitter. The
configured `min_idle` floor (`anytls_min_idle_session`) and `anytls_idle_session_timeout` feed one node-local janitor.
Selector or UDP warm ownership independently raises effective retention; the
last owner release drains future reuse without terminating live streams.

### Ordered write path

Every frame crosses one `WriterQueue` and one physical writer task. Data permits
are bounded by 896 frames and 1 MiB of queued or in-flight payload per session,
whichever fills first. A full budget backpressures the writing stream; the byte
cap also bounds how long a new stream's SYN waits behind a saturated upload.
Control frames retain reserved headroom; the whole queue is capped at 1,024
commands. The byte budget bounds queued payload: a frame carries up to 65,535
bytes, so frames alone allowed 56 MiB per session, which a line-rate upload fills.
It does not count a UoT packet before its permit or the encoded batch buffer.
Exhausting the 1,024-command queue or a push after
close makes the session terminal instead of growing memory. The relay reads at
most 65,535 bytes at a time, so one nonempty read is at most one AnyTLS frame;
a 64 KiB read became a 65,535-byte frame and a 1-byte frame. A stream's SYN and
first PSH are inserted as one atomic batch,
so another stream cannot interleave between them.
Abandoned mid-open registrations send FIN rather than killing the session.

After one blocking pop, the writer gathers only frames already queued, up to 63
frames or 256 KiB on top of the first frame, and sends them with one `flush`. It never waits to fill
a batch. A data frame is serialized, header included, in the one copy that
admits its payload. Without padding the writer sends the frame's whole TLS
records straight from that buffer and copies only control frames and the data
bytes that do not fill a record of their own, so the batch keeps the record
boundaries of one contiguous write.
Data permits and confirmed-write completions are released only after
the physical batch succeeds or the session becomes terminal.

Control-only batches have a 5-second deadline (`writeControlFrame` sing-anytls
parity); expiry fails the session. Data-containing batches have no deadline:
congestion backpressures the cap without killing siblings.

`AnyTlsStream::poll_write` is cancellation-safe because it copies nothing until
it holds a writer-queue permit. It returns `Ok(n)` only after exactly those `n`
bytes have entered the ordered queue, and a retried write enqueues its chunk
once. A write that returned `Pending` accepted nothing: flush and shutdown drop
its permit wait, so the abandoned bytes are never sent, and return without
waiting for writer capacity.

### Non-blocking demultiplexing

Each TCP child has a bounded delivery queue, demultiplexed by `sid`. When it fills, the demultiplexer
parks frames in a per-SID ordered overflow instead of waiting, preserving
sibling progress and exact frame/byte accounting.

No separate timer resets a parked stream: a reader may pause for any
length of time, and queued bytes alone are not evidence of a stall. The
emergency hard limit is 768 parked data frames per session (at most two
terminal events per SID); there a stream is reset only if it has had no
successful overflow flush for a full 3 seconds. Retained payload bytes are
bounded separately by the pool-wide budgets below. If a stream is already
past the 3-second grace, admission at the hard limit reaps that stream
immediately.
Otherwise the demultiplexer waits in bounded 100 ms
`OVERFLOW_EMERGENCY_WAIT` rounds, shortened to the nearest grace expiry, and
re-evaluates after reader progress. This covers the measured 12–16 ms reader
startup at 9.4 Gbps; a healthy reader's first flush wakes the wait via
`overflow_notify`. Every removal returns its overflow counters to zero.

All current and draining sessions in one node pool use separate 12 MiB
pool-wide byte budgets for TCP and UoT retained payloads, for a 24 MiB
aggregate ceiling. Keeping the drop-on-full UoT class separate prevents a
stalled datagram consumer from starving TCP recovery. The TCP budget covers
primary delivery queues and overflow. Saturation waits in the same 100 ms
rounds. Once the oldest retained TCP payload has seen no application-read
progress for the full 3-second grace, only that stream is reset and its
retained payloads are discarded. A progressing reader renews the grace.

This prevents one abandoned primary queue from pinning every sibling session
in the pool.

FIN and error events bypass the data-frame quota so termination cannot be
hidden behind a full queue, but at most two terminal events park per SID; extras are dropped.
Ordinary overflow reaps drain admitted data before reset; pool-budget recovery
is the fail-safe exception and discards only the stalled stream's retained
payloads. A session failure becomes `ConnectionAborted`; a per-stream refusal
or slow-consumer reap becomes `ConnectionReset`, as does SYNACK-with-data.

Non-empty server ALERTs fail the session; empty ALERTs remain ignored.
ALERT and SYNACK diagnostics retain at most 1 KiB of source bytes before
lossy UTF-8 decoding and mark truncation, bounding each deferred error.
TCP streams release their capacity permit on delivery of a terminal read
result, including a deferred error after buffered data, or on stream drop.

UoT delivery uses nonblocking `try_send`. A full UoT sink is removed and that
SID is retired rather than blocking the session demux or dropping an arbitrary
chunk and continuing a corrupted length-delimited byte stream.

### Lazy UoT creation

Opening an AnyTLS UDP transport through `open_uot_stream` reserves a stream but defers its UoT
request. AnyTLS uses non-connect UoT v2: the request is `0x00` followed by the SOCKS5 address of
the first destination, which only informs server routing and address-family selection. The
request and the first encoded datagram are emitted together as one ordered PSH. Every datagram in
both directions then carries its own address in the UoT v1 layout
`[ATYP][address][port][u16 length][payload]`, with packet ATYP IPv4 `0`, IPv6 `1` and domain `2`
(not the SOCKS5 numbering of the request address). Payloads are limited to 16 KiB, matching
anytls-go 0.0.13's sing v0.5.1 relay buffer; larger inputs fail before consuming the lazy setup or
poisoning the logical stream. This avoids an otherwise empty setup round trip without permitting
first-packet replay.

One stream therefore serves every destination of a client source (the `Shared` source transport),
and the server can use one unconnected socket for all of them. `recv_packet` decodes the address
before consuming the frame: numeric sources are returned (IPv4-mapped IPv6 as IPv4), the captured
open-time domain and port project to the captured target, and any other domain frame is dropped
whole, with its header and payload credit released and no name resolution. An unknown ATYP is
terminal. On send, only the dialed name is written per datagram; any other name goes out as the
numeric target. The first send of each flow waits for the physical flush (`confirmed`); steady sends only
enqueue, and `admitted` is set when the frame is queued to the session writer. The queue and
credit limits are those of a single transport, so queue saturation or EOF retires every
destination sharing the SID. Domain-target flows (`RewriteTo`) keep one scope per original
destination.

## Cold URLTest speculative preparation

Cold URLTest is the only selection path that prepares more than one leaf. The
selection policy and staggering rules live in [Group design](./groups.md);
the outbound layer only makes preparation side-effect safe.

Session pools atomically return either a permit on an existing shared session
or a caller-owned provisional physical-dial slot counted against the pool cap.
A detached AnyTLS or VLESS mux session remains outside the reusable pool until
winner commit publishes it and starts its janitor. Dropping a loser cancels any
physical dial, removes its generation-safe slot and SID, and closes the attached
session synchronously.

QUIC candidates build detached clients. Losers are force-closed. Winner commit
publishes its client only if the generation slot is still empty. If ordinary
traffic populated the slot meanwhile, the incumbent remains; the winning flow
continues using the detached connection and protocol-state clones it already
owns.

Async `PreparedUdpTransport::commit` completes protocol-specific promotion before
the `PacketTransport` is exposed. Commit failure is fail-closed and drops the transport. QUIC slot arbitration performs no await
after mutating the slot, so cancellation cannot leave a published but
uncommitted winner.

## Related docs

- [Group design](./groups.md)
- [Control-plane design](./control-plane.md)
- [Node reference](../reference/nodes.md)


