# Outbound and proxy stack

This document describes the path from a selected leaf node to protocol bytes sent to the proxy server or target.

## Scope

The outbound stack begins after routing and group selection have produced one leaf
`Node`. It owns capability dispatch, reusable protocol state, transport setup,
TLS and REALITY, proxy framing, and the TCP or UDP-facing object returned to the
control plane.

It does not define the node configuration surface; see
[Node reference](../reference/nodes.md). It also does not choose a group
member or define health policy; see [Group design](./groups.md).

The boundary returned to the caller is one of:

- `ProxyStream`, an established target-bound TCP byte stream; or
- `Arc<dyn PacketTransport>`, an established framed packet path for one UDP
  target.

`direct` reaches the target without a proxy protocol. `block` terminates the
request. Every other handler turns the selected node into bytes understood by
its proxy server.

Outbound dialing, groups, and health checking. Re-exported by `honk-core` as `honk_core::{proxy, group, outbound}`.

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

- `src/proxy/mod.rs`: `ProxyStream::into_tcp_stream` preserves the zero-copy splice downcast invariant.
  `WarmAttempt` holds the retention lock across establishment. Failure or cancellation rolls back only its inserted bit, including a failed first warm attempt. Cancellation-driven QUIC cleanup reacquires the bitmap and releases the client only if no successor owner appeared.

### Capability traits

`WarmRequirement::Session|Udp` selects the reusable state to establish.

| Trait | Operations | Contract |
| --- | --- | --- |
| `TcpOutbound` | `dial`, `dial_with_tcp`, `dial_runtime` | Opens a target-bound `ProxyStream`. `dial_with_tcp` may consume an already connected bare server socket. `dial_runtime` pins session-owning work to the captured generation. |
| `PacketOutbound` | `dial_udp_transport`, `dial_udp_transport_runtime`, `dial_udp_transport_speculative_runtime` | Opens the only production UDP contract, `PacketTransport`. Runtime and speculative variants prevent reload or cold-race work from consulting mutable current state. |
| `WarmableOutbound` | `warm(runtime, timeout, WarmRequirement)` | Hysteria2 alone distinguishes `WarmRequirement::Udp` to verify that the server admitted UDP. |
| `ProbeableOutbound` | `test_connectivity` | Tests raw proxy-server reachability. Protocols may override the default marked TCP connect. |

`PacketTransport` exposes the relay target, `send_packet`,
`send_packet_confirmed`, and `recv_packet`. `send_packet_confirmed` is the
stronger first-packet admission point for queue-backed tunnels. Full-cone
protocols can additionally declare that server metadata authoritatively names
the reply source.

No production UDP handler returns a raw socket or a loopback bridge. Direct and
SOCKS5 wrap native sockets behind `PacketTransport`; tunnel protocols implement
framing on their actual transport.

### Protocol descriptors

`src/descriptor.rs` owns `ProtocolDescriptor`, the single per-protocol facts table.
Predicates accept the concrete node because VLESS `vless_mode`, `network`, and
Trojan transport affect capability or pooling. `network_allows_udp` is shared by
Trojan, AnyTLS, and VLESS.

| Protocol | `supports_udp` | `pool_ready_streams` | `pool_bare_tcp` | Generation runtime | Share-link schemes |
| --- | --- | --- | --- | --- | --- |
| Shadowsocks, including 2022 | yes | no | yes | `None` | `ss` |
| Trojan | when `network` is absent or contains `udp` | only `tcp`/empty transport | yes | `None` | `trojan` |
| VMess | no | no | yes | `None` | `vmess` |
| VLESS | non-`legacy` mode and UDP allowed by `network` | no | `legacy`, `uot-v2`, `xudp` only | H2MUX, Mux.Cool, or `None`, by mode | `vless` |
| SOCKS5 | yes | yes | yes | `None` | `socks5`, `socks4`, `socks4a` |
| Hysteria2 | yes | no | no | `Quic` | `hysteria2`, `hysteria` |
| TUIC | yes | no | no | `Quic` | `tuic` |
| Juicity | yes | no | no | `Quic` | `juicity` |
| AnyTLS | when `network` is absent or contains `udp` | no | no | `AnyTls` | `anytls` |
| Direct | yes | no | yes | `None` | none |
| Block | no | no | yes | `None` | none |

Ready-stream pooling stores a completed target-bound handshake. Bare-TCP
pooling stores only a connected proxy-server socket and lets `dial_with_tcp`
perform the per-target protocol handshake. Multiplexed and QUIC protocols
exclude both because their generation runtime is the sole reusable-state owner.

Registry assembly checks that descriptor capabilities, populated slots, and runtime kinds agree.
Node-dependent entries may carry a packet slot even when the default node lacks
UDP. `block` is the explicit exception: its descriptor says no UDP capability,
but its packet slot is allowed through dispatch so the selected block decision
can reject the flow terminally.

### Protocol and UDP inventory

| Handler | TCP behavior | `dial_udp_transport` |
| --- | --- | --- |
| `direct` | Native marked target connect | Native marked UDP behind `PacketTransport` |
| `block` | Rejects | Explicit reject-path exemption; carries no UDP |
| `socks5` | SOCKS CONNECT | RFC 1928 UDP association |
| `ss` / Shadowsocks 2022 | Shadowsocks stream | Shadowsocks packet framing |
| `trojan` | Trojan stream over shared transport | Trojan UDP framing when `network` allows UDP |
| `vmess` | VMess stream | Unimplemented |
| `vless` | Mode-dependent | Available only when `vless_mode != legacy` and `node.network` allows UDP |
| `hysteria2` | QUIC stream | Hysteria2 QUIC datagrams |
| `anytls` | AnyTLS logical stream | UoT v2 logical stream |
| `tuic` | TUIC v5 QUIC stream | QUIC datagrams or uni-stream fallback |
| `juicity` | Juicity QUIC stream | One length-framed QUIC bi stream |

VMess and VLESS entries are compiled only with the `rprx` feature. The default
`honk-core` feature set enables it. Without `rprx`, these node forms still parse,
but the registry contains no entry and dials fail with the ordinary
`No handler for protocol` refusal.

Unknown transports, invalid pins/REALITY keys, and reserved built-in names/protocols fail closed.

## Runtime ownership and reload

`src/runtime.rs` defines `OutboundRuntimeRegistry`, the control plane's single owner of reusable
outbound state for one immutable configuration generation. It maps `Node.id` to
`NodeRuntime`:

- immutable `Arc<Node>` configuration;
- the node-aware `udp_capable` result; and
- one `ProtocolRuntime` selected by the descriptor.

`ProtocolRuntime` is `None`, an AnyTLS `SessionPool`, a VLESS H2MUX or Mux.Cool
`SessionPool`, or one type-erased QUIC client slot. Handlers remain stateless
with respect to generation-owned sessions.

- Structured/imported raw TCP TLS ALPN lives in `TlsOptions.alpn` (flat serde `tls_alpn`, omitted when empty). `Node::validate_protocol` requires enabled ordinary TLS on AnyTLS or TCP Trojan/VMess/VLESS, rejects REALITY/WS/gRPC/QUIC overrides, and bounds names to 1–255 bytes plus the encoded list to 65,533 bytes. Nonempty ALPN derives a child UUID v5 using the legacy ID as namespace and the JSON tuple `["tls-alpn", <ordered list>]` as name, separating it from arbitrary credential text; empty lists keep all legacy IDs. URI/v2rayN ALPN compatibility and TUIC's separate `tuic_alpn` remain unchanged.

Admission-scoped TCP feedback starts once at the first admitted physical attempt or before logical open on a reused session/QUIC connection; cold admission waiting remains unstarted, while completed paths without either boundary retain the completion fallback.

### Generation lifecycle

Startup builds and validates the full runtime registry before publication.
Reload builds a replacement registry against the previous one. A runtime is
eligible for transfer only when the full node configuration is equal, ignoring
parse-time `created_at` and `updated_at` metadata.

Transfer occurs at the reload commit point. The old generation records moved
`Node.id` values only after the replacement is published, then skips those
runtimes during drain and shutdown. Consequently, unchanged nodes keep:

- TUIC, Juicity, and Hysteria2 QUIC clients and connections;
- AnyTLS physical sessions;
- VLESS H2MUX carriers; and
- VLESS Mux.Cool carriers.

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
aborted caller. Single XUDP has no generation runtime.

### Dial admission

Physical outbound connects—including direct TCP and proxy TCP/QUIC attempts—and their protocol handshakes acquire two permits:

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
`PreparedUdpTransport` retains neither gate nor successful dial permit.

## Shared stream, socket, and bootstrap layers

### Stream transport

`src/proxy/transport.rs` is shared by Trojan, VMess, and VLESS, driven by `node.transport`/`ws_path`/`ws_host`/`grpc_service`. The order is fixed:

```text
TCP -> optional TLS or REALITY -> optional WebSocket or gRPC -> protocol header
```

`maybe_tls_wrap_concrete` preserves the concrete TCP/TLS type needed by VLESS Vision direct-copy.
When REALITY parameters are present, it dispatches to `reality::reality_connect` instead
of ordinary TLS. The same shared path therefore gives Trojan, VMess, and VLESS
consistent TLS, REALITY, WS, and gRPC setup.

The gRPC transport is a hand-written minimal gRPC-over-HTTP/2 client that interoperates with official sing-box Trojan+gRPC. The
opening HEADERS frame does not set `END_STREAM`, and TLS requests use
`:scheme: https`. DATA carries gRPC length prefixes and the protobuf
single-bytes-field envelope expected by gun-style servers.

### Marked sockets and name resolution

`util.rs` centralizes outbound socket creation:

- `connect_marked` resolves then connects TCP with timeout, nodelay,
  keepalive, and optional `SO_MARK`;
- `connect_outbound` applies the bypass mark for proxy-server TCP; and
- `udp_marked_bind` and `marked_udp_socket` create bypass-marked UDP sockets.

Every control-plane-originated non-loopback socket must carry
`DAE_BYPASS_MARK` (`0x100`). Without it, WAN egress classification can redirect
honk's own proxy, DNS, or probe traffic back into `daens` and create a loop.
Mark application is best-effort only for unprivileged `EPERM` environments
without the production datapath; other errors propagate.

Marked UDP sockets request 8 MiB each for `SO_RCVBUF` and `SO_SNDBUF`. Linux
may clamp and reports twice the configured sysctl accounting value; the core
raises the corresponding maxima at startup.

`bootstrap.rs` prevents proxy-hostname resolution from depending on honk's own
intercepted DNS path. Node dial sites use `bootstrap::resolve` through
`connect_marked` or the QUIC setup and never call bare `lookup_host` directly.
The configured bootstrap resolver is queried over bypass-marked UDP/TCP; failure
falls back to the system resolver. `query_ech_config` uses the same raw path for
DNS HTTPS records (`qtype 65`) and extracts the SVCB `ech` parameter.

After resolution, `src/address_race.rs` schedules proxy-server TCP `connect_marked`
and shared QUIC `QuicClient` attempts with stable IPv4/IPv6 interleaving and at most
two addresses in flight. The first starts immediately;
the fallback starts after 250 ms. An earlier failure advances the fallback,
while keeping physical attempts at least 10 ms apart. Every in-flight address
attempt holds its own generation and process dial permits, so
at the configured ceiling a fallback waits for an earlier attempt to finish;
`max_concurrent_dials: 1` serializes addresses. The race stays inside the
already selected node: socket marks and security settings are identical, and
TLS and QUIC protocol setup run only on the winning transport, including QUIC
protocol authentication. Errors are reported deterministically in original address order.

`crates/honk-outbound/src/bootstrap.rs` provides bootstrap DNS resolution for proxy-server hostnames (dae `bootstrap_resolver` parity): process-wide resolver querying over bypass-marked UDP/TCP with a hand-rolled wire codec, falling back to the system resolver. Node dials must use it (wired into `util::connect_marked` and `quic.rs`), never bare `lookup_host` — otherwise resolution deadlocks against honk's own intercepted DNS path. Also carries the raw-query path behind ECH discovery: `query_ech_config` (HTTPS RR qtype 65, SVCB `ech` param parsing) used by `tls::discover_ech_config`.
`crates/honk-outbound/src/util.rs` holds `connect_marked` / `connect_outbound` (TCP `SO_MARK`, keepalive, timeout), `udp_marked_bind`. `marked_udp_socket` requests 8 MiB `SO_RCVBUF`/`SO_SNDBUF`; the kernel clamps to 2×`rmem_max`. honk-core raises `net.core.rmem_max`/`wmem_max` to 16 MiB at startup: the 208 KiB default caps QUIC at ~2 Gbps/ms RTT. Follow the runtime **Bypass mark** invariant; otherwise `wan_egress` loops sockets into `daens`.

## TLS, fingerprinting, ECH, and pins

All production TLS in the outbound and DNS transport stacks uses BoringSSL. TCP uses `boring` and
`tokio-boring`; QUIC uses the custom `quinn-proto` crypto backend. The trust
store is built from `webpki-root-certs`. Explicit no-verify connectors exist for
configured insecure operation and for REALITY, whose own post-handshake check
replaces PKI.

- `src/tls.rs` — **BoringSSL TLS client** with webpki/no-verify stores. Process-wide `set_tls_mode` (`tls_implementation = "utls"`) selects a **real Chrome fingerprint**: GREASE, permuted extensions, X25519MLKEM768+X25519 key shares (`mlkem`), Chrome sigalgs/curves, brotli cert compression, ALPS-h2, ECH GREASE. Per-node **ECH** uses `ech_config` / `ech_config_path` and `SSL_set1_ech_config_list`. Rejection fails closed per RFC and logs retry configs. Without static config, `ech_enabled` triggers connect-time **DNS HTTPS-RR discovery** (`discover_ech_config`, RFC 9460, bootstrap resolver or first system nameserver, per-domain cache, fail-open). `set_utls_imitate` accepts only `chrome*`; other values warn and fall back to the sole Chrome profile.
  Connectors: `build_connector(node)` for proxies, `build_dns_connector()` for DoT/DoH, `build_reality_connector(chrome)` with accept-all verification, replaced by post-handshake ed25519 auth in `reality.rs`; never offer REALITY resumption. Chrome pins old ALPS `0x4469` via `SSL_set_alps_use_new_codepoint(ssl, 0)`; BoringSSL's new default is JA4-distinguishable. REALITY Chrome JA4: `t13d1516h2_8daaf6152771_01adaf6b9c20`; ja4_a/ja4_b match Chrome, ja4_c differs only by added ed25519.
  Explicit structured TCP ALPN reaches `build_connector` in both tls/utls modes; empty lists retain existing profile defaults. Chrome ALPS follows exact `h2` membership. Registry publication and direct connector construction validate nonempty overrides; shared stream dispatch validates before choosing plaintext or REALITY, and direct QUIC configuration rejects TCP ALPN rather than ignoring it.

### Process-wide TLS profile

`tls_implementation = "utls"` enables the one implemented impersonation profile,
Chrome, process-wide. The profile configures:

- GREASE and per-connection extension permutation;
- `X25519MLKEM768` followed by `X25519` key shares;
- Chrome signature algorithms, curves, cipher set, and ALPN;
- brotli certificate compression;
- ALPS for h2, pinned to Chrome's old `0x4469` codepoint rather than
  BoringSSL's newer `0x44cd`; and
- ECH GREASE when no real ECHConfigList is available.

Other `utls_imitate` names warn and use Chrome. `tls_implementation = "tls"`
keeps the ordinary BoringSSL ClientHello.

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

`src/reality.rs` implements the specialized REALITY BoringSSL handshake through
`RealityConfig`, `parse_reality_config`, and `reality_connect`, byte-compatible
with Xray `reality.go`. The workspace's patched `boring-sys` supplies two client
hooks ([Technology stack](../../../AGENTS.md#technology-stack)):

- `SSL_set1_client_x25519_private_key` places honk's ephemeral private key into
  the serialized X25519 `key_share`; and
- `SSL_set_client_hello_fixup_cb` rewrites the serialized ClientHello before it
  enters the handshake transcript.

### ClientHello authentication

REALITY forces X25519-only groups and key shares. The fixup callback zeros the
32-byte legacy `session_id` slot in the complete ClientHello and computes:

- `authKey = HKDF-SHA256(X25519(eph, pbk), salt=clientRandom[:20], "REALITY")`,
  where `eph` is the client ephemeral private key and `pbk` the server public key;
- nonce `clientRandom[20:32]`; and
- `AES-256-GCM(authKey).Seal([ver:3][0][ts:4][shortId:8])`, with version bytes
  `1,3,3`, reserved byte `0`, a big-endian u32 timestamp, and an eight-byte short
  ID. The AAD is the whole ClientHello with `session_id` zeroed.

The 16-byte encrypted plaintext plus 16-byte GCM tag exactly fills the legacy
32-byte session ID. An empty short ID is eight zero bytes; a configured value is
even-length hex of at most eight bytes and is right-zero-padded. Unparseable
`reality_public_key`/`reality_short_id` or fixup failure aborts the handshake;
no unauthenticated ClientHello is sent.

### Server authentication and fingerprint constraints

REALITY replaces ordinary certificate verification: the peer leaf must be an
ephemeral ed25519 certificate whose signature is exactly
`HMAC-SHA512(authKey, raw ed25519 public key)`.

A relayed mask-target certificate, wrong key, redirection, or MITM fails closed.
There is no fallback to PKI and no session resumption.

The REALITY profile adds ed25519 to the Chrome signature-algorithm list because
BoringSSL otherwise rejects the ephemeral leaf before the custom check.
The widened signature list is the one known
`JA4_c` difference from Chrome; the verified REALITY Chrome JA4 is
`t13d1516h2_8daaf6152771_01adaf6b9c20`.

The REALITY `dest` must return a TLS Certificate message smaller than 8 KiB,
because compatible sing-box servers buffer 8192 bytes. A larger certificate
flight cannot complete this handshake.

## VLESS wire contracts

`WireMode` selects one of six explicit contracts. It is configuration, not
negotiation.

| Mode | TCP path | UDP path | Reusable shape |
| --- | --- | --- | --- |
| `legacy` | Ordinary VLESS stream | none | No generation runtime; bare proxy TCP may be pooled |
| `uot-v2` | Ordinary VLESS stream | One connected direct UoT v2 stream per packet transport | No generation runtime; bare proxy TCP may be pooled |
| `h2mux` | H2MUX logical TCP stream | Native connected H2MUX UDP using UoT length framing | Node-owned H2MUX pool, at most 2 reusable/dialing carriers × 128 streams |
| `h2mux-padded` | H2MUX logical TCP stream with sing-mux v1 padding | Same native connected UDP with padding | Same node-owned 2 × 128 H2MUX pool |
| `xudp` | Ordinary VLESS stream | Single XUDP on a dedicated mux-command carrier, reserved ID 0 | Unpooled; bare proxy TCP may be pooled |
| `mux-cool` | Mux.Cool logical TCP stream | Pooled XUDP | Node-owned Mux.Cool pool, at most 2 active carriers × 128 children |

The client never probes the server for a mode, falls back to another mode, or
replays a first UDP packet. A mismatch is a protocol failure. This keeps packet
admission and side effects single-commit.

### H2MUX

`src/proxy/uot.rs` and `src/proxy/vless_mux.rs` implement shared UoT v2 framing
and sing-box H2MUX. H2MUX sends the physical VLESS request to
`sp.mux.sing-box.arpa:444`, selects backend `2`, then runs HTTP/2 over that
carrier. Logical streams carry either TCP or native connected UDP. UDP uses the
shared UoT length codec rather than a loopback bridge.

`h2mux-padded` adds the sing-mux v1 randomized preface and record framing for
the first 16 records in each direction. Each carrier admits at most 128 logical
streams. At most two reusable or currently dialing carriers count toward the
pool cap; a draining carrier may overlap its replacement until its final live
stream exits.

HTTP/2 flow control drives backpressure. GOAWAY makes the carrier draining and
rolls new work to a replacement. Driver failure fans out to its children;
half-close, reset, receive-window release, and lazy response errors remain
per-stream.

Receive credit is fixed at 2 MiB per stream. Connection credit covers one
maximum UoT response frame for each of the 128 admitted streams
(8 MiB + 256 bytes). The larger stream window removes the old
one-datagram-per-RTT ceiling on long-fat TCP paths. The per-stream cap prevents
one unread child from consuming all connection credit, while the aggregate
bound lets interleaved maximum UDP frames always complete.

### Mux.Cool and XUDP

`src/proxy/vless_cool.rs` implements Mux.Cool: it sends the Xray VLESS mux command and multiplexes child TCP and XUDP
records. One ordered writer serializes every child frame. Session IDs increase
monotonically and are not reused; an exhausted carrier drains while a
replacement accepts new children.

The pool admits no more than two active carriers and 128 children per carrier.
Draining carriers do not consume the active cap but remain alive for existing
children. Saturation waits for capacity instead of bypassing the pool.

Receive payloads share an 8 MiB carrier budget. TCP delivery allows 100 ms for
transient budget or queue pressure before resetting only the stalled child;
UDP remains drop-on-full. This tolerates line-rate scheduler bursts without
letting an unread child pin the carrier indefinitely.

XUDP reply metadata can change the logical peer and therefore enables full-cone
reply sources. Pooled Mux.Cool packets are capped at 8 KiB. Single XUDP reuses
the codec on a dedicated unpooled carrier with global ID `0` and a 7,526-byte
packet cap.

### Vision

`xtls-rprx-vision` carries the flow in the VLESS addons. The response header is
stripped lazily on the first read because servers commonly send it with the
target's first downstream bytes; eager reading can deadlock a request whose
target waits for client data.

Vision removes response padding. Command `2` is direct-copy: the server abandons
the outer TLS session and the read side switches to the raw TCP socket. The
write side remains on the outer stream unless the client itself sends a direct
command, which honk does not.

The supported carrier is TCP with TLS or REALITY, and the supported wire modes
are `legacy` and Single `xudp`. H2MUX, padded H2MUX, Mux.Cool, and UoT own
incompatible inner framing.

### VLESS Encryption

`src/proxy/vless_encryption.rs` implements Xray-compatible VLESS Encryption, wrapping the selected stream transport before the ordinary VLESS
request. The only implemented protocol name is `mlkem768x25519plus`, with
`native`, `xorpub`, and `random` wire modes.

The prologue accepts X25519 or ML-KEM-768 server authentication keys, including
chained relay keys. Every new 1-RTT connection performs ML-KEM-768 plus X25519
forward secrecy. Payload records use AES-256-GCM when hardware acceleration is
available and ChaCha20-Poly1305 otherwise.

A `0rtt` configuration caches the server ticket and PFS key in the handler's
`Node.id`-keyed client config. A cold or expired cache takes the 1-RTT path. Any
record-authentication failure while using a ticket invalidates it, so the next
connection cannot repeat a rejected cached path.

VLESS Encryption is legacy-only. Configuration rejects it with Vision and with
every non-`legacy` wire mode because each combination would give two layers
ownership of the same inner framing.

Raw-TCP interop is verified against Xray 26.7.28 across all modes, both auth-key types, chained X25519 keys, and 1-RTT→0-RTT.

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

`src/quic_boring.rs` implements the client side of `quinn_proto::crypto::Session`
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
sessions by server hostname. BoringSSL has no implicit client cache and requires
explicit `SSL_set_session` for resumption. `pinSHA256` nodes never resume because a PSK handshake would bypass
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
`2 x BDP`. A peer `DATA_BLOCKED` or `STREAM_DATA_BLOCKED` frame makes its sample
qualify without the RTT gate and sets that floor's target to twice the current
window, because a `2 x BDP` target derived from the throttled rate would be a
no-op; the three-sample requirement and the cooldown below still apply. The
stream floor takes `STREAM_DATA_BLOCKED` alone, since aggregate connection
goodput cannot identify one stream's demand. Each floor is capped at 32 MiB, has its own five-minute promotion
cooldown, never shrinks automatically, and applies to the live connection and
active/future streams without reconnecting. Zero-progress samples preserve a pending
promotion only while the corresponding connection credit remains pressured.
Native TUIC and Hysteria2 UDP
endpoints use a per-send deadline of `clamp(4 × SRTT, 1 s, 5 s)`. Three
consecutive send deadlines, or no newly acknowledged QUIC packet is observed for
`max(8 × SRTT, 10 s)`, retires the endpoint and closes that connection so the
next flow redials. A successful send resets the send streak; observed delivery
progress resets both clocks. Attempted UDP packets are never replayed. TUIC
also enables Quinn PING keepalive, including its UDP-over-stream fallback where
protocol heartbeat datagrams are unavailable.

### Protocol contracts

| Protocol | Authentication and TCP | UDP | Transport policy |
| --- | --- | --- | --- |
| TUIC v5 (`src/proxy/tuic.rs`) | TLS-exporter authentication on a uni stream; one TCP bi stream per flow | QUIC datagrams, fragmentation, and uni-stream fallback when datagrams are unavailable | 10 s heartbeat; default 8 MiB stream and 8 MiB connection receive windows, with node overrides |
| Juicity (`src/proxy/juicity.rs`, verified juicity-rs server interop) | ALPN `h3`; TLS-exporter auth; bi-stream header `[network][trojanc metadata]` | One bi stream with `[metadata][u16 length][payload]` records (`[metadata][len u16][payload]`) | Upstream juicity/juicity-rs default BBR; 8 MiB stream and 8 MiB connection receive windows |
| Hysteria2 (`src/proxy/hysteria2/`, `mod.rs`) | ALPN `h3`; minimal `h3.rs` HTTP/3/QPACK `POST https://hysteria/auth`, success status `233` | Native Hysteria2 QUIC datagrams and fragmentation | `hy2_up_mbps` selects `quic::BrutalConfig` (window = rate×RTT, ignores loss), otherwise BBR; `hy2_down_mbps` is sent in bytes/s through `Hysteria-CC-RX`; same 8/8 MiB default receive windows |

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
also budgets memory; slow consumers buffer ~3× it. Reducing 32→8 MiB was
throughput-neutral on a 75ms/15%-loss link. Overrides:
`tuic_init_stream_recv_window`/`tuic_init_conn_recv_window`, hy2 `hy2_init_*`.

## AnyTLS session engine

`src/proxy/anytls.rs` implements sing-anytls multiplexing with stateless handlers. Each generation's `NodeRuntime::AnyTls` owns one
`SessionPool<AnyTlsSession>` and lazily materialized BoringSSL connector.
Generation-free calls use a guarded ephemeral equivalent.

### Pool and session lifecycle

`src/session.rs` defines the generic node-owned `SessionPool` for AnyTLS, VLESS
H2MUX, and VLESS Mux.Cool (QUIC keeps `quic::QuicClient`). It enforces `Active`,
`Draining`, and `Closed` states, atomic stream permits, event-driven capacity
waits, least-loaded selection, and pool-owned single-flight physical dials.
Draining sessions are excluded from the reusable cap and can overlap
replacements while live streams finish. The pool also owns bounded retry
classification, backoff, retirement, and idempotent force shutdown.

AnyTLS configures two reusable physical sessions and 128 streams per session.
It spreads work: after the first session becomes busy, the pool establishes the
second before adding more load, then schedules least-loaded. Consecutive dial
failures use bounded backoff instead of one physical connect per proxied flow.
H2MUX and Mux.Cool instead fill the least-loaded carrier within their caps.

After v2 server-settings negotiation (`CMD_SERVER_SETTINGS`, `v=2`), every reused logical stream (SID 2 and
later) joins a per-SID pending set once its SYN is on the wire, and a SYNACK
settles only its own SID — an unrelated acknowledgement never clears another
stream's deadline, and local stream teardown cancels it. An open still pending
three seconds after its SYN was written is reset at stream level when the
session kept receiving frames during the window (the server was alive but
never acknowledged that open); a fully silent window retires the physical
session so the pool redials instead of reusing a dead carrier.

Sessions enter age-based drain at 30 minutes with per-session jitter. The
configured `min_idle` floor (`anytls_min_idle_session`) and `anytls_idle_session_timeout` feed one node-local janitor.
Selector or UDP warm ownership independently raises effective retention; the
last owner release drains future reuse without terminating live streams.

### Ordered write path

Every frame crosses one `WriterQueue` and one physical writer task. Data uses
bounded permits, control frames retain reserved headroom, and the whole queue is
capped at 1,024 frames. Queue exhaustion or push-after-close makes the session terminal instead of
growing memory. A stream's SYN and first PSH are inserted as one atomic batch,
so another stream cannot interleave between them.
Abandoned mid-open registrations send FIN rather than killing the session.

After one blocking pop, the writer gathers only frames already queued, up to 63
frames or 256 KiB on top of the first frame, into one `write_all` and one `flush`. It never waits to fill
a batch. Data permits and confirmed-write completions are released only after
the physical batch succeeds or the session becomes terminal.

Control-only batches have a 5-second deadline (`writeControlFrame` sing-anytls
parity); expiry fails the session. Data-containing batches have no deadline:
congestion backpressures the cap without killing siblings.

`AnyTlsStream::poll_write` is cancellation-safe through an owned outbound slot.
It returns `Ok(n)` only after exactly those `n` bytes have entered the ordered
queue; cancellation cannot lose a pending chunk or enqueue it twice.

### Non-blocking demultiplexing

Each TCP child has a bounded delivery queue, demultiplexed by `sid`. When it fills, the demultiplexer
parks frames in a per-SID ordered overflow instead of waiting, preserving
sibling progress and exact frame/byte accounting.

Soft limits are:

- 512 parked frames and 8 MiB per session; and
- 2 MiB per stream.

Crossing a soft limit does not kill the stream. The first parked frame starts a
watchdog ticking every 250 ms; it retires on overflow drain and is aborted on close. Only a stream with no successful overflow flush
for a full 3 seconds is reset; queued bytes alone are not evidence of a stall.

Emergency hard limits are 768 frames or 12 MiB per session. If a stream is
already past the 3-second grace, admission reaps that stream immediately.
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

Opening an AnyTLS UDP transport through `open_uot_stream` reserves a stream but defers its UoT connect
request. The connect request and first encoded datagram are emitted together as
one ordered PSH. Payloads are limited to 16 KiB, matching anytls-go 0.0.13's
sing v0.5.1 relay buffer; larger inputs fail before consuming the lazy setup or
poisoning the logical stream. This avoids an otherwise empty setup round trip
without permitting first-packet replay.

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


