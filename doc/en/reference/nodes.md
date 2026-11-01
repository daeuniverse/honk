# Nodes and share links

`node { ... }` declares dialable outbounds from share links and assigns each one a stable runtime identity.

## `node {}` declarations

Each non-comment line is one share link. Tags and links may be quoted or bare:

Outside matching quotes, `#` starts a comment at the start of a statement or immediately after an ASCII space or tab.

| Position of `#` | Result | Example |
| --- | --- | --- |
| After whitespace in a bare link | Starts a comment | `ss://…#hk1 # note` keeps the name `hk1`. |
| Joined to text in a bare link | Remains link data | `ss://…#hk2#note` keeps `hk2#note`. |
| Immediately after a closing link quote | Starts a compatibility comment and emits `legacy-glued-hash` at that byte | `'ss://…#hk1'#note` keeps `hk1`. |

Put whitespace before a comment. Other text after a closing quote skips the entry with `trailing-entry-text`. See the [dialect reference](./dialect.md) for quote-error and block rules.

```dae
node {
    iris: 'socks5://10.10.10.1:2077'
    'hk1': 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@hk1.example.com:8388#fragment-name'
    'trojan://secret@example.com:443?sni=example.com#trojan1'
    socks5://10.10.10.2:1080
}
```

The parser accepts both tagged and untagged entries. A non-empty dae tag replaces the link's `#fragment` name. An untagged link keeps its decoded fragment; without one, it receives the credential-free fallback `{scheme}-{host}`.

An absent or empty VMess JSON `ps` remark uses `vmess-{host}` before validation. A non-empty dae tag then replaces it.

In quoted tags and links, a backslash escapes the next character when locating the closing quote; the source escape is retained in the parsed text.

The parser handles invalid entries as follows:

| Input | Result |
| --- | --- |
| Malformed link with a recognized scheme | Drop the entry with a warning. Known invalid fields retain a specific safe reason and schema path; unknown parse failures use `invalid-node-entry`. |
| Unknown scheme or removed VLESS `vless_mode` | Reject the configuration. |
| Standalone `mux:` or `mux=` line | Reject the configuration. Use the link's exact `packetEncoding=`, `mux=`, and `udp=` query parameters for VLESS packet and carrier choices. |

Diagnostics retain the original node-entry ordinal and source location. They never contain the raw link, value, or node name. Data entrypoints return diagnostics without logging; plain entrypoints report them once.

An accepted link warns only with `legacy-*` codes. Any other warning on a node entry means the parser dropped it. A client validating a single `node { name: 'link' }` declaration in `syntax` mode can distinguish skipped and accepted links by code alone.

In the legacy `ss://base64(method:password@host:port)` form, decoded credentials are literal text, not URL-decoded: `%20` stays `%20`, and `?`, `/`, `#`, `:` and `@` remain password characters. The last `@` separates the endpoint; the userinfo may itself be `base64(method:password)`. A decoded payload without `@`, or credentials that cannot supply a method and password, is rejected. URL userinfo forms still percent-decode their credentials. The endpoint, path, query (including `/?plugin=...`) and fragment keep the usual URL handling.

## Node identity

`Node::derive_id()` is the only identity derivation path. It computes UUID v5 over:

```text
protocol|host|port|credential-fingerprint|dial-shape
```

The credential fingerprint follows each handler's field precedence. The dial shape includes:

- `sni`, transport, and WebSocket/gRPC shape;
- Hysteria2 obfuscation, REALITY parameters, and `flow`;
- effective VLESS TLS posture, UDP permission, fallback encoding, and multiplex paths.

Plaintext VLESS has a different identity from TLS. A REALITY key selects the authenticated transport regardless of a redundant TLS flag.

| Structured `tls_alpn` | Identity derivation |
| --- | --- |
| Nonempty | Derive a child UUID v5 with the base ID as namespace and the JSON tuple `["tls-alpn", <ordered list>]` as name. This separates ALPN from arbitrary credential text. |
| Empty | Retain the base ID. |

Tuning and display metadata do not participate, except VLESS multiplex limits that change a physical path.

For XHTTP, identity also includes the effective TLS/plaintext posture and every accepted canonical XHTTP option, including headers, padding and POST pacing. Input aliases, header-name casing and equivalent range representations normalize before derivation. Existing TCP/WS/gRPC identity material is unchanged by adding XHTTP.

For WebSocket, a nonempty canonical header map also joins identity. Header-name casing, insertion order and equal-value aliases do not change it; different values do. An absent or empty map preserves the previous identity.

Before joining, each raw credential and dial-shape field and the effective host escapes `\` as `\\` and `|` as `\|`. Joined fingerprints are not escaped again. For nodes accepted by `Config::validate`, different identity fields produce different hash material. This guarantee does not cover nodes rejected by full configuration validation, even if `Node::from_share_link` can derive their IDs.

**Breaking upgrade:** every successfully re-derived VLESS node receives a new ID, including links that never specified `vless_mode`, UDP-disabled nodes, and nodes with ALPN overrides. ID-keyed health and warm/session state is rebuilt. For that migration, other protocols change ID only when `|` or `\` occurs in the pipe-joined identity fields; delimiters in ALPN alone do not trigger that change because ALPN uses a separate JSON child-UUID step.

**Addressed UDP framing:** VLESS nodes receive another new ID when their effective UDP path on port 53, 443, or 54 is UoT v2 or H2MUX. This covers `packetEncoding=uot-v2`, `mux=h2mux`, and pool fallback reaching either path, because these paths now carry an address per packet.

Auto, native, XUDP, Mux.Cool, and UDP-disabled nodes keep their IDs. Direct-node Selector choices use node IDs and are lost when those IDs change. A structured JSON/YAML/TOML configuration follows an old ID in a group's `nodes` to the new ID when loaded.

Do not delete the cache to migrate IDs. When persistence is enabled and readable:

| State | Effect of a node-ID change |
| --- | --- |
| Direct-node Selector choice | Lost because the pin is keyed by node ID. |
| Sub-group Selector choice | Retained because the choice is keyed by group name. |
| Valid TCP-v4 delay sample no older than 24 hours | Re-keyed by node name at startup. It seeds ranking, not liveness. Renamed or ambiguous duplicate names do not guarantee the same leaf. |

Ready streams already retire with their generation. The `name`/`subtag` filter semantics are unchanged.

Identity is stable across rename, reload, and subscription refresh when the dialable endpoint and dial shape are unchanged. Configuration/runtime assembly rejects duplicate derived IDs. `Node::default()` has a nil ID; construction paths derive it, and the outbound runtime registry rejects any nil ID that reaches it.

## Node fields

The Node model exposes the fields below. Share links populate operator-facing fields from their scheme, userinfo, authority, fragment, and query; structured loaders, import, or runtime own the rows explicitly marked as metadata. None are separate keys inside dae `node {}`. Defaults below are model defaults; a URL-shaped share link defaults an omitted port to `443`, while a v2rayN VMess payload requires a valid port.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | UUID | derived | Stable content identity described above; nil is invalid at runtime |
| `name` | string | `""` | Dae tag, decoded fragment, `remark` query, VMess `ps`, or credential-free fallback |
| `protocol` | enum | `ss` | Derived from the share-link scheme |
| `address` | string | `""` | Parsed links store `host:port` |
| `host` | string | `""` | Explicit server host; otherwise `Node::host()` derives it from `address` |
| `port` | u16 | `0` | Server port; URL-shaped links use `443` when omitted |
| `username` / `password` | string? | null | Authentication, UUID, or secret from userinfo |
| `encryption` | string? | null | SS/VMess cipher or VLESS Encryption client string; Shadowsocks falls back to `aes-128-gcm` at dial time when omitted |
| `packet_encoding` | `VlessUdpEncoding` | `auto` for VLESS | Structured VLESS fallback encoding: `auto`, `native`, `xudp`, or `uot-v2`; canonical URI `packetEncoding=none` maps to `native` |
| `multiplex` | `VlessMultiplex` | `{"protocol":"off"}` for VLESS | Structured VLESS carrier selection: `off`, `h2`, or `xray`; exact shapes are documented below |
| `plugin` / `plugin_opts` | string? | null | Parsed SIP002 plugin metadata; subscription import rejects non-empty values because proxy plugins are unsupported |
| `transport` | string | `"tcp"` | Stream transport: empty/`tcp`, `ws`, `grpc`, or canonical `xhttp`; input `splithttp` normalizes to `xhttp` |
| `tls` | bool | `false` | Stream TLS flag; Trojan/AnyTLS links enable it, canonical VLESS links historically default on |
| `sni` | string? | null | TLS server name; nonempty `sni` and `peer` claims must agree, then an unconsumed `host` supplies the fallback |
| `tls_alpn` | string[] | `[]` | Structured/imported raw-TCP TLS ALPN for AnyTLS and TCP Trojan/VMess/VLESS. XHTTP instead canonicalizes omission or `h2` to `["h2"]`, including REALITY and explicit cleartext H2. Other disabled-TLS/REALITY/WS/gRPC/QUIC overrides remain unsupported; TUIC retains `tuic_alpn`. |
| `skip_cert_verify` | bool | `false` | Certificate-verification bypass from agreeing `allowInsecure`, `allow_insecure`, and `insecure` claims; see the security note below |
| `ech_enabled` | bool | `false` | Static ECH config present, or `ech=1`/`true` |
| `ech_config` | string? | null | Base64 ECHConfigList from `ech_config` or `echconfig` |
| `ech_config_path` | string? | null | Structured-loader path to a base64 ECHConfigList; not a share-link query |
| `reality_public_key` | string? | null | REALITY X25519 public key from `pbk` |
| `reality_short_id` | string? | null | REALITY short ID from `sid` |
| `reality_spider_x` | string? | null | Stored `spx`; a REALITY link defaults it to `/` |
| `flow` | string? | null | VLESS `xtls-rprx-vision` or `xtls-rprx-vision-udp443`; Shadowrocket `xtls=2` selects the base flow |
| `network` | string? | null | Packet capability for supported protocols; independent of VMess JSON `net` and other stream-transport fields |
| `ws_path` / `ws_host` | string? | null | WebSocket `path` and Host header |
| `ws_headers` | object | `{}`; omitted on output | Additional upgrade headers as a string map, normalized to lowercase names; equal-value aliases merge and conflicting aliases reject. At most 64 entries and 16 KiB of name+value bytes; control bytes reject. Reserved names: `host`, `connection`, `upgrade`, `sec-websocket-key`, `sec-websocket-version`, `sec-websocket-extensions`, `sec-websocket-accept`, `sec-websocket-protocol`, `content-length`, `transfer-encoding`. Nonempty maps on non-WebSocket stream transports reject; protocols without a stream transport drop the field. Null is invalid. Only subscriptions and structured input supply headers; no share-link dialect carries them. |
| `grpc_service` | string? | null | gRPC `serviceName` or `service_name` |
| `xhttp` | object? | omitted | Canonical XHTTP options in flat structured input/output; options on another transport reject |
| `hy2_auth` / `hy2_obfs` | string? | null | Hysteria2 authentication and salamander password |
| `hy2_up_mbps` / `hy2_down_mbps` | u32? | null | Hysteria2 brutal sender/receiver bandwidth hints |
| `hy2_port_hopping` / `hy2_hop_interval` | string? / u64? | null | Hysteria2 `mport` list and `mhop` seconds; default interval is 30 s; configured values have a 5 s minimum |
| `hy2_init_stream_recv_window` / `hy2_init_conn_recv_window` | u64? | null | Hysteria2 QUIC receive windows; effective defaults are 8 MiB / 8 MiB, with the conn window auto-tuned up to 32 MiB while the application drains it quickly (the conn window doubles as the per-connection memory budget: slow consumers buffer up to ~3× it) |
| `hy2_disable_mtu_discovery` | bool? | null | Hysteria2 `disablePathMTUDiscovery` |
| `quic_mtu` | u16? | null | QUIC UDP payload size from `mtu`. Advertised receive size: default 1252, range 1200–65527. Send MTU starts at 1200 and grows through path-MTU discovery. Explicit `mtu` sets both the initial send MTU and discovery bound. Values above 1252 enable GSO on regular sockets, excluding the Hysteria2 obfuscation/hopping socket. `HONK_QUIC_GSO=0` disables GSO. |
| `tls_pin_sha256` | string? | null | Leaf-certificate SHA-256 pin from `pinSHA256` or `pin_sha256` |
| `tuic_uuid` / `tuic_password` | string? | null | TUIC credentials; flat aliases must agree with `username` / `password` |
| `tuic_congestion` / `tuic_alpn` | string? | null | TUIC `congestion_control` and comma-separated `alpn` |
| `tuic_init_stream_recv_window` / `tuic_init_conn_recv_window` | u64? | null | TUIC QUIC receive windows; effective defaults are 8 MiB / 8 MiB, with the conn window auto-tuned up to 32 MiB |
| `juicity_uuid` / `juicity_password` | string? | null | Juicity credentials; flat aliases must agree with `username` / `password` |
| `anytls_password` | string? | null | AnyTLS secret copied from link userinfo |
| `anytls_min_idle_session` | usize? | null | Requested idle-session floor from `min_idle_session`; effective default 0, bounded by the eight-session pool cap |
| `anytls_idle_session_check_interval` | u64? | null | Parsed `idle_session_check_interval` seconds; current runtime janitor cadence remains fixed at 30 s |
| `anytls_idle_session_timeout` | u64? | null | Idle eviction from `idle_session_timeout`; effective default 30 s |
| `mark` | u32? | null | Structured-model outbound `SO_MARK`; not a dae share-link query |
| `tags` | string[] | `[]` | Classification metadata; not a dae share-link query |
| `subscription_id` / `group_id` | UUID? | null | Import/runtime ownership metadata |
| `created_at` / `updated_at` | datetime | now | Runtime metadata |

Intrinsic validation requires a nonempty node name, effective host, and explicit nonzero `port`. `address` does not supply a missing port; address-only IPv6 requires an explicit `host`. Only exact injected `direct`/`block` identities are endpoint-exempt.

### Structured-loader compatibility

TOML, YAML, and JSON retain the legacy flat node keys. Loading reads fields owned by the selected `protocol`. Non-default fields from other protocols are stripped without rejecting the node; one warning lists their names. For example, `tls: true` on an `ss` node is ignored with a warning rather than enabling TLS.

`username` is not a credential alias for Trojan, VLESS, Hysteria2, or AnyTLS. Without the protocol's effective credential field, a supplied `username` is stripped with a targeted warning, preserving legacy behavior and IDs.

Values used by the selected protocol still undergo normal parsing and validation. Honk's own output remains round-trip safe. With `store_subscribe`, a raw subscription body is persisted only after successful parsing. A rejected refresh leaves the last valid body untouched.

`vless_mode` has been removed from VLESS flat input. Its raw presence rejects the node even when its value is `null` or an old recognized spelling; use `network` for packet permission, `packet_encoding` for fallback, and `multiplex` for carrier selection. The only remaining `vless_mode: "legacy"` field is a non-VLESS serialization placeholder retained for flat-format compatibility. It does not configure VLESS, and non-VLESS behavior and identity are unchanged.

Flat credential aliases are compared before incompatible fields are stripped:

| Protocol | Aliases that must agree |
| --- | --- |
| Hysteria2 | `hy2_auth` / `password` |
| TUIC | `tuic_uuid` / `username`; `tuic_password` / `password` |
| Juicity | `juicity_uuid` / `username`; `juicity_password` / `password` |
| AnyTLS | `password` / `anytls_password` |

Missing or null claims are absent. Supplied strings must agree byte for byte, including empty strings and surrounding spaces. An empty credential remains subject to its protocol's requirements. Flat credential fields remain strings; numeric coercion applies only to subscription feeds.

The new `tls_alpn` field is deliberately excluded from legacy stripping: a nonempty value on an unsupported protocol or TLS context rejects the node instead of silently changing its handshake.

Share-link verification booleans ignore surrounding whitespace and ASCII case:

| Value | Certificate verification |
| --- | --- |
| `true`, `yes`, `1`, `on` | Disabled |
| `false`, `f`, `no`, `n`, `0`, `off`, `t`, `y` | Enabled |
| Empty or unknown text, or conflicting aliases | Reject the link |

**Security change:** `yes` and `on` previously left verification enabled. They now disable it and emit a warning. Use explicit `true` or `false` and review these links before upgrading. Native structured booleans remain typed; strings and numbers are not coerced.

VMess cipher claims accept `auto` and `aes-128-gcm`, case-insensitively, and store lowercase names; empty optional claims use the default. JSON `scy`/`security`, encoded share-link `encryption`/`scy`/cipher-valued `security`, and supported feed cipher aliases must agree before assignment. Unsupported or conflicting values reject the node. In encoded share links, `security=none` and `security=tls` still select TLS behavior, not a cipher. Record positional ciphers remain lower-priority fallbacks.

TUIC share links and feeds accept only absent, empty, or `native` relay mode. Unsupported `udp-relay-mode`/`udp_relay_mode` claims reject the entry even beside a valid alias.

| Hysteria2 source | Obfuscation rules |
| --- | --- |
| Share link | Require exact lowercase `obfs=salamander`. Absent/empty disables obfuscation; unknown names, including `SALAMANDER`, reject. A missing/empty password disables Salamander. Repeated password claims and `obfs-password`/`obfs_password` must agree. |
| Clash | Accept case-insensitive Salamander with a nonblank password. |
| sing-box | Require an exact lowercase type; reject active incomplete obfuscation objects. |

Duration conversion rejects negative, nonfinite, and out-of-range values instead of saturating. Structured feed seconds fields round integer milliseconds up (`500ms` and `1000ms` both become `1`; zero stays zero), then compare aliases. Share-link Hy2 `mhop` remains bare unsigned integer seconds: `500ms` and `1s` are ignored with a redacted warning. AnyTLS share-link durations retain the seconds parser; dae millisecond settings retain bare/ms/s syntax and truncate fractional milliseconds.

Sing-box `hop_interval`, `idle_session_timeout`, and `idle_session_check_interval` preserve native numeric zero as an explicit value; missing or null remains absent. Hysteria2 records compare every `mhop`, `hop-interval`, and `hop_interval` occurrence after conversion to seconds, rejecting conflicts and invalid values even beside a valid alias.

Hysteria2 hopping sets reject repeated ports and overlapping ranges before dialing, including `443,443`. A singleton remains valid. Valid specifications retain their spelling; embedded authority lists retain their stricter empty-segment rule. The outbound constructor uses the same checked decoder for directly constructed nodes.

Every canonical adapter completion applies intrinsic validation: ordinary share links, VMess JSON, standalone flat Node serde, and subscription imports.

- UUID-based protocols require valid UUIDs. Unsupported cipher, transport, packet capability, flow, ALPN context, or hopping sets reject before identity derivation.
- Without VLESS Encryption, Vision requires TLS or REALITY. Constructed nodes also reject empty SNI/flow/network values that adapters normalize away.
- Feed-only nonempty-password requirements remain format-specific. Optional SOCKS authentication and handler-supported empty credentials remain valid.
- Invalid dae node lines and feed entries retain their existing skip policy; valid siblings survive.
- Parse-only Config fragments remain parse-only, except that invalid contained nodes now reject at construction.
- Standalone serde preserves a supplied ID; runtime identity admission is separate.

Direct `Node::validate()` calls return the same static, redacted errors as adapter completion. Validation errors never include the supplied node name or credential values.

Detailed Config loaders and configuration/registry admission retain the intrinsic field and cause, adding the original one-based node ordinal instead of replacing the reason with a generic invalid-node error. Credential conflicts identify the canonical alias field without exposing either value. Standalone `NodeSeed` and Node serde still return redacted generic serde errors.

For VMess JSON with `net: "ws"`, an omitted or empty `host` uses the endpoint host in the WebSocket handshake. A supplied nonempty `host` remains the explicit override.

## Protocols

| Protocol | Alias | TCP | UDP | Notes |
| --- | --- | --- | --- | --- |
| `ss` | `shadowsocks` | Yes | Yes | AEAD and Shadowsocks 2022 |
| `trojan` | — | Yes | Yes* | TLS; TCP/WS/gRPC/XHTTP transport |
| `vmess` | — | Yes | No | AEAD; TCP/WS/gRPC/XHTTP and REALITY; handler requires `rprx` |
| `vless` | — | Yes | Configurable* | Native UDP, UoT v2, H2MUX, XUDP, Mux.Cool, Encryption, REALITY, and Vision; handler requires `rprx` |
| `socks5` | — | Yes | Yes | CONNECT and UDP ASSOCIATE |
| `hysteria2` | — | Yes | Yes | QUIC/H3, salamander, brutal/BBR, and port hopping |
| `tuic` | — | Yes | Yes | TUIC v5 over QUIC |
| `juicity` | — | Yes | Yes | Juicity over QUIC |
| `anytls` | — | Yes | Yes* | Multiplexed TLS sessions and UoT v2 |
| `direct` | — | Yes | Yes | Reserved built-in bypass outbound; no share-link scheme |
| `block` | — | No | No | Reserved built-in reject outbound; no share-link scheme |

`network` can disable packet dialing for Trojan, AnyTLS and VLESS independently of their stream transport. VMess UDP is not implemented.

| Protocol | UDP behavior |
| --- | --- |
| AnyTLS | Reject payloads above 16 KiB, matching anytls-go 0.0.13's relay buffer. Non-connect UoT v2 carries each datagram's destination and the server's real source address. One stream serves all destinations of a client source; unsolicited replies retain their real source. |
| Trojan | One associate stream serves every destination of a client source and returns each reply's real source. A cooperating server can provide EIM/EIF behavior. Destinations share the stream's head-of-line blocking and fail together. |

SOCKS5 UDP ASSOCIATE keeps one control TCP connection and one relay socket per client source, shared by every destination of that source, and returns the real remote peer named in each reply header. Whether a peer the client never contacted can reach it depends on the server: Dante's default `udp.connectdst: yes` connects its outbound socket only while a single destination has been used.

**UDP full-cone.** These UDP-capable proxy protocols share one association across all destinations of a client source and return each reply's real remote peer:

- Hysteria2, TUIC, Shadowsocks (AEAD and 2022), Juicity, and SOCKS5;
- Trojan and AnyTLS;
- VLESS XUDP/Mux.Cool, UoT v2, and H2MUX.

VLESS native UDP is the exception: its stream names one target. This applies to explicit `native` and to `auto` on UDP/53 and UDP/443 without Vision.

A reply from a previously uncontacted peer is delivered with that peer's source address. This implements the client side of RFC 5780 full-cone. The server must also use one unconnected socket per association and forward replies from any peer. honk cannot override server-side filtering; `direct` traffic follows the host's NAT. Limits:

- A flow dialed by domain keeps one association per original destination, and its replies project to that destination, so it never gets endpoint-independent mapping.
- All destinations of a source share one association only on one node. A group can send a new destination, or a Score trial, to another node, which has its own mapping.
- With protocol fallback, neither H2MUX nor an Xray UDP pool owns the path. For non-Vision nodes, `packetEncoding=auto` uses connected native UDP on ports 53 and 443. Its stream names one target, so those ports cannot be full-cone. Vision nodes and other ports use Single XUDP. Set `packetEncoding=xudp` to opt in on the native paths.
- Single XUDP is not the default because of its measured cost. Against sing-box 1.12.4 on loopback with unpaced 1200-byte datagrams, it delivered about half of native's goodput and used 1.9–3.3 times the client CPU per MB. Its p99.9 latency tail was heavier; median and cold-start latency showed no measurable difference. XUDP also rejects datagrams above 7,526 bytes.
- A VLESS source whose selected paths differ per port (for example an Xray UDP pool with UDP/443 `skip`, where 443 takes the protocol fallback instead of the pool) gets one association per selected path, even on one node.
- Trojan, Juicity and AnyTLS carry all destinations of a source on one reliable stream, so a stalled destination delays its siblings and a failed write ends all of them. Datagram carriers (Hysteria2, TUIC, Shadowsocks, SOCKS5) do not.
- Port-53 flows do not publish client reply framing in the datapath, so an unsolicited reply to a port-53 flow depends on host forwarding.
- All client sources share one process-wide foreign-reply socket pool, with one socket per peer address and a cap of seven sockets per endpoint of capacity. A new foreign peer above the cap evicts the least recently used socket. The janitor closes a socket unused for one NAT timeout.
- Replies from a source's 64 most recently closed destinations are dropped instead of delivered as foreign replies. This covers connection closure and dead-node purges. Rebinding removes a destination from the list; the 65th closure removes the oldest entry. Idle expiry and transport errors do not add entries, so those peers can still send foreign replies while the source lives. Bound flows are unaffected.
- VMess has no UDP backend.

For protocols that own `network`, flat structured input accepts comma-separated `tcp`/`udp` tokens, ignoring token whitespace and ASCII case. `tcp` disables UDP; `udp` and `tcp,udp` both permit UDP. Empty or whitespace-only text becomes absent and retains the protocol's default capability. Unknown tokens such as `quic`, or empty tokens inside a nonempty list, reject the node. This controls UDP admission only: `udp` does not add a TCP rejection policy.

VMess and VLESS nodes still parse without the `rprx` Cargo feature, but no handler is registered and dialing fails with `No handler for protocol`; normal feature-off builds do not allocate VLESS pools or carrier semaphores. `honk-core` and `honk-tool` enable `rprx` by default.

`honk-core` injects `direct` and `block` at startup and reload with fixed reserved IDs. User nodes may use neither those names nor those protocols. Groups do not draw them from the pool: only `filter: name(direct)` or `name(block)` spelled exactly admits one; see the [group reference](./groups.md#syntax).

## Protocol parameters

### Shadowsocks 2022

| Method | Decoded base64 PSK length |
| --- | --- |
| `2022-blake3-aes-128-gcm` | 16 bytes |
| `2022-blake3-aes-256-gcm` | 32 bytes |
| `2022-blake3-chacha20-poly1305` | 32 bytes |

An incorrect or non-base64 key fails handler construction.

UDP replay protection retains separate current and previous server-session
windows. A third session is admitted only after the previous session has been
inactive for 60 seconds. Authentication and response-header validation precede
all receive-session state changes, so an invalid packet cannot reset replay history.

Shadowsocks UDP, legacy AEAD and 2022 alike, keeps one server-facing socket per
client source for all of its destinations. 2022 keeps one session ID, one
increasing packet counter and one set of replay windows across them.

Replies return the real remote address the server reports, so a host that was never
contacted can still reach the client when the server forwards it; a reply naming
a domain other than the dialed one is dropped.

A name other than the dialed one is
never sent per datagram: real servers (sing-box 1.12.4) pin their outbound form by the first
destination and end the association on a later different name, so it goes out as the numeric target.

### Stream transports

Stream-capable share links select transport with `type=` or its `network=` alias:

| Value | Transport | Field mapping |
| --- | --- | --- |
| Empty or `tcp` | Raw TCP | — |
| `ws` | WebSocket | `path` → `ws_path`; `host` → `ws_host`; upgrade headers have no share-link field |
| `grpc` | gRPC | `serviceName` or `service_name` → `grpc_service` |
| `xhttp` or input alias `splithttp` | XHTTP | See the H2 profile below. |

All supplied aliases must agree before assignment, including compatible `obfs` declarations and repeated query keys. Unsupported names such as `h2` and `kcp` reject the link during parsing. `sni` is independent. Outside XHTTP, share-link `alpn` remains compatibility-only and is not stored.

WebSocket paths and gRPC service names are percent-encoded where a URI cannot carry a character as is, such as a space or non-ASCII text. Existing `%XX` escapes and query delimiters stay unchanged; spaces and non-ASCII text in query values are also encoded (for example, `?tag=a b` becomes `?tag=a%20b`). XHTTP keeps its own escaping rules below.

```dae
node {
    trojan_ws: 'trojan://secret@example.com:443?type=ws&sni=example.com&host=example.com&path=/path#trojan_ws'
    vless_grpc: 'vless://uuid@example.com:443?security=tls&type=grpc&serviceName=GunService#vless_grpc'
}
```

VMess accepts v2rayN Base64 JSON (`net`, `host`, `path`, `sni`) and Shadowrocket's `vmess://base64(auto:UUID@host:port)?...` authority form. The latter maps `tls`, `peer`/`sni`, `obfs=websocket|grpc`, `obfsParam`, `path`, and `remark`; standard/URL-safe Base64 and optional padding are accepted. Encoded-authority VMess requires AEAD authentication and `auto`/`aes-128-gcm`; unsupported ciphers and REALITY parameters are rejected, not silently replaced.

VMess JSON `net` and Shadowrocket transport parameters select only the stream transport. They no longer populate packet-network capability; an omitted packet restriction retains the existing default UDP allowance for protocols with a UDP backend; VMess has none. Valid empty transport spelling is preserved where already used. On non-XHTTP transports, unrelated `mode` and `extra` export fields retain their legacy ignored behavior; they do not select XHTTP. Explicit conflicting transport claims still reject the node.

VLESS supports TCP+REALITY+Vision, TCP+REALITY, TCP+WS, TCP+WS+TLS, TCP+gRPC, and the H2 XHTTP profile below. Unencrypted Vision's direct-copy path requires raw TCP with TLS 1.3 or REALITY, not WS/gRPC/XHTTP; encrypted Vision follows the composition rules below.

Vision adds uplink padding and removes downstream padding. Uplink Direct needs
an eligible TLS 1.3 ServerHello before the first complete application-data record;
early data or an undecided inspection-budget expiry ends padding with End on the outer transport.
Each direction switches independently. See the
[Vision support boundary](../design/outbound.md#vision-and-vless-encryption).

#### XHTTP over H2

Trojan, VMess and VLESS share this outbound transport. VMess remains TCP-only. This profile supports XHTTP over H2, not full Xray or mihomo configuration parity.

| Security mode | H2 requirement |
| --- | --- |
| Ordinary TLS | Must negotiate `h2`. |
| Authenticated REALITY | Selects H2 by the transport contract even when the server omits ALPN. |
| Explicit cleartext | Requires an H2-capable peer. |

There is no H1/H3 fallback.

```dae
node {
    xhttp: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&type=xhttp&mode=stream-up&path=%2Fxhttp%2F&sni=edge.example&alpn=h2#xhttp'
}
```

`mode` defaults to `auto`:

| Mode | Request layout |
| --- | --- |
| `auto` | Select `packet-up` for ordinary TLS or cleartext, and `stream-one` for REALITY. |
| `packet-up` | Finite ordered POST bodies with a shared-session GET. |
| `stream-up` | Separate streaming POST and GET. |
| `stream-one` | One bidirectional POST. |

VMess JSON also accepts v2rayN's `type` as the mode on `net=xhttp|splithttp`; explicit `mode` and `type` must agree. JSON `fp`, `insecure` and `allowInsecure` are accepted and ignored, as on legacy VMess transports. Certificate verification remains enabled.

URI, VMess JSON and Mihomo imports trim ALPN strings and list members, then omit empty values. Omission selects `h2`. Bodies contain raw proxy bytes despite gRPC/SSE camouflage headers.

| XHTTP request field | Normalization and validation |
| --- | --- |
| `path` | Defaults to `/`. Add leading/trailing slashes before the query without cleaning dot segments or percent escapes. |
| HTTP `host` | Independent of the dial address and SNI. Falls back to SNI, then the server host. |
| Path component | A decoded literal. On the wire, Xray-style escaping converts literal `%` to `%25` and percent-encodes spaces, `<`, `>`, and UTF-8 bytes. |
| Query | Sent unchanged and validated as raw HTTP URI syntax. Literal spaces must already be percent-encoded. |
| Whole path and query | At most 16 KiB. Control bytes, DEL and `#` are rejected anywhere. |

URI share-link values are percent-decoded once before this processing. Thus `path=%2Fxhttp%2F` sends `/xhttp/`; Mihomo paths are literal YAML strings.

Directly constructed nodes must call `normalize_stream_transport()` before deriving their IDs. Immutable admission rejects noncanonical XHTTP spelling, options and ALPN.

URI `extra` accepts a percent-encoded JSON object containing `host`, `path` and `mode` with the same meaning, normalization and validation as the top-level fields, plus only the options below. Extra request fields fill absent top-level fields; explicit top-level presence wins even when empty. Repeated URI extras coalesce only when their effective canonical options agree.

| Xray extra key | Flat `xhttp` field | Default | Supported bounds |
| --- | --- | --- | --- |
| `headers` | `headers` | `{}` | At most 64 headers and 16 KiB of names plus values |
| `xPaddingBytes` | `x_padding_bytes` | `100-1000` | 1–8192 bytes |
| `noGRPCHeader` | `no_grpc_header` | `false` | Boolean |
| `scMaxEachPostBytes` | `sc_max_each_post_bytes` | `1000000` | 1–16777216 bytes |
| `scMinPostsIntervalMs` | `sc_min_posts_interval_ms` | `30` | 0–60000 ms; zero disables the minimum interval |

Ranges accept an unsigned scalar, a `min-max` string or `{"min":N,"max":N}` in structured input. Headers normalize to lowercase and equal aliases coalesce; conflicting aliases, control characters and protocol-managed headers (`host`, `content-type`, `content-length`, `referer`, hop-by-hop headers and trailers) reject. URI/VMess extra JSON rejects duplicate members before map construction. Padding remains enabled. The bounds are local safety limits, not a guarantee that a peer or CDN accepts every value.

Without a configured `User-Agent`, XHTTP requests use Xray's default Chrome `fetch()` headers:

| Headers | Behavior |
| --- | --- |
| Chrome-on-Windows `User-Agent` and `Sec-CH-UA` brands | The major version follows [Xray's estimate](https://github.com/XTLS/Xray-core/blob/836a6fed385b902e437dde43ee9adc82d23a5303/common/utils/browser.go#L26-L34), with a random delay drawn once per process. |
| `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`, `DNT`, `Accept-Language`, `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty`, `Sec-Fetch-Site: same-origin` | Replace configured values of those names, as Xray does. |
| `Accept`, `Priority`, `Cache-Control`, `Pragma` | Added only when not configured. |

CDN bot filters can reject XHTTP requests without these headers. A configured `User-Agent` disables the default set and is sent verbatim. Xray's `chrome`, `firefox`, `edge` and `golang` keywords are not interpreted. These headers are runtime-only and do not change node identity.

Top-level `host`, `path` and `mode` remain authoritative when `extra` is present.

| Compatibility input | Handling |
| --- | --- |
| URI `fp` | Accepted but ignored; global TLS mode owns the fingerprint. |
| `headerType` / `quicSecurity` set to `none` or empty; empty `serviceName` | Accepted but ignored because XHTTP owns HTTP framing. |
| `headers` query | Accepted and dropped only for a JSON object containing solely `Referer`. Xray's padding overwrites that header, so it never reaches the wire. |
| `allowInsecure`, `allow_insecure`, `insecure` | Retain shared TLS semantics; aliases must agree. |
| Extra `noSSEHeader`, `scMaxBufferedPosts`, `scStreamUpServerSecs` | Server-only Xray settings; type-checked and dropped. |
| `xmux` | Accepted and dropped only when all-zero or exactly Xray's fill-in for omitted XMUX: `maxConcurrency` 1, `hMaxRequestTimes` 600–900, `hMaxReusableSecs` 1800–3000, everything else 0. Other values reject. |

Unknown or unsupported options reject the entire node, even when null or empty. These include alternate session/sequence/payload placement, custom upload methods and padding-obfuscation profiles. Mihomo subscriptions use the corresponding `xhttp-opts` fields. Official sing-box and client-record XHTTP transports remain unsupported.

Extra `downloadSettings` is an Xray StreamConfig that sends the GET to a separate endpoint. It inherits nothing from the upload side, including configured headers. Download GETs therefore carry the default Chrome `fetch()` set even when upload requests have a configured `User-Agent`.

| Download setting | Requirement or mapping |
| --- | --- |
| Required fields | `address`, `port`, `network: xhttp`, `security: tls`. |
| `address` | Trimmed and lowercased. Must be a hostname or IPv4 literal because the dialer joins it with the port textually. |
| `tlsSettings.serverName`, `xhttpSettings.path`, `xhttpSettings.host` | Map to `xhttp.download.server_name`, `path`, and `host`. The flat `xhttp.download` object also contains `address`, `port`, and `x_padding_bytes`, which defaults to `100-1000`. |
| Top-level or `tlsSettings` ALPN | Only absent or `h2`. |
| `tlsSettings.fingerprint`, `xhttpSettings.mode` | Checked and ignored. |
| Known members set to null | Treated as absent. |
| HTTP host | Falls back to the download server name, then its address. |

The download peer always verifies TLS. Upload pins, insecure verification, ECH and REALITY do not apply to it. `allowInsecure: true`, REALITY, `sockopt`, download `headers` or `extra`, and any other member reject. Download settings also reject with `stream-one` mode or a REALITY upload.

Each peer has its own carrier pool. A Trojan or VMess node can therefore hold four reusable carriers outside the VLESS process permit. Delay probes and `honk-tool sub` address-family columns describe only the upload endpoint.

XHTTP does not permit TCP Mux.Cool; UDP-only XUDP carriers remain supported. Existing VLESS UDP permission, packet encoding and UDP/443 policy are unchanged. Packet-up has no wire upload-EOF marker: shutdown flushes accepted upload bytes and retains the GET for the application's final reply; closing the logical flow retires its requests.


### Shadowrocket VLESS

The unified parser accepts `vless://base64(auto:UUID@host:port)?...` and the same encoded authority without `auto:`. Standard and URL-safe Base64, with or without padding, are accepted; IPv6 endpoints must be bracketed. The encoded authority must contain a valid UUID and an explicit nonzero port. Malformed encoded authorities are rejected, never treated as hostnames or display names.

The query mapping follows the [Shadowrocket exporter](https://github.com/cedar2025/Xboard/blob/master/app/Protocols/Shadowrocket.php):

| Input | Meaning |
| --- | --- |
| `tls=0` / `tls=1` | Disable / enable TLS. Encoded links without security options default to plaintext; canonical `UUID@host:port` links retain their TLS-on default. |
| `pbk`, `sid`, `spx` without `security` | Select REALITY; a non-empty `pbk` is mandatory. Explicit `security=reality` remains supported. |
| `xtls=0` / `xtls=2` | No flow / `xtls-rprx-vision`. Retired XTLS Direct (`xtls=1`) and unknown values are rejected. |
| `remark` | Display name when a non-empty fragment is absent; decoded once as a query value. |
| `peer` | Explicit SNI alias; nonempty `sni` and `peer` must agree. Empty or whitespace-only names are absent. |
| `obfs=websocket`, `obfsParam`, `path` | WebSocket transport, Host header fallback, and path. |
| `obfs=grpc`, `path` | gRPC transport and service-name fallback. |

Conflicting TLS/REALITY, flow, or transport declarations are rejected rather than silently downgraded. `obfs` accepts only empty/`none`, `websocket`, or `grpc` for VLESS; unsupported transports are not reinterpreted as TCP. Canonical `host` and `serviceName`/`service_name` fields retain their existing fallback precedence. Explicit SNI aliases are compared before assignment; equal bytes coalesce, unequal names reject without case rewriting. Empty or whitespace-only SNI and flow normalize to absent before node-ID derivation. Nonempty flow must be `xtls-rprx-vision` or `xtls-rprx-vision-udp443`.

Clash imports compare `servername`, `server-name`, and `sni`; record imports additionally compare `tls-name` and `tls-host`, retaining `obfs_sni` as a lower-priority fallback, including Quantumult X WSS Host. Record `off` remains invalid. In share links and VMess JSON, WebSocket `host` is only the Host header; outside WebSocket it is a lower-priority SNI fallback. The endpoint hostname remains the final TLS consumer fallback.

### Hysteria2

Both `hysteria2://` and `hy2://` are accepted. The entire percent-decoded userinfo is the authentication string: literal `user:password` retains both halves and the colon, matching percent-encoded `user%3Apassword`.

| Link input | Node field / behavior |
| --- | --- |
| userinfo secret | `hy2_auth`; preserves the full `user:password` form rather than taking only the password |
| `obfs=salamander&obfs-password=...` | Exact lowercase `salamander` with a nonempty password sets `hy2_obfs`. Absent/empty obfuscation or a missing/empty password disables it. Unknown obfuscation names reject the link. |
| `upmbps` / `downmbps` | `hy2_up_mbps` / `hy2_down_mbps`; a positive upload value enables Brutal, otherwise BBR is used; download is advertised in bytes/s |
| `mport` / `mhop` | Port list/ranges and hop interval in seconds; interval defaults to 30 and clamps to the upstream minimum of 5. The official client form with hop ports embedded in the authority (`:443,5000-6000`) is equivalent to `mport`; specifying both is rejected, and a malformed embedded list fails at parse time |
| `pinSHA256` | `tls_pin_sha256`, replacing PKI/hostname verification |
| `initStreamReceiveWindow` / `initConnReceiveWindow` | QUIC receive-window overrides |
| `disablePathMTUDiscovery` | Disables QUIC PMTU discovery when `1`/`true` |
| `mtu` | Shared QUIC UDP-payload cap, accepted only in 1200–65527 |
| `sni` / `peer`, insecure aliases, ECH parameters | Shared TLS behavior; nonempty explicit SNI aliases must agree |

```dae
node {
    hy2: 'hysteria2://secret@example.com:443?sni=example.com&obfs=salamander&obfs-password=obfspw&upmbps=50&downmbps=200&mport=20000-30000&mhop=30#hy2'
}
```

### TUIC and Juicity

| Protocol | Link input | Node field / behavior |
| --- | --- | --- |
| TUIC | `uuid:password` userinfo | Generic `username` / `password`; handler fallback for `tuic_uuid` / `tuic_password` |
| TUIC | `congestion_control` | `cubic`, `new_reno`, or `bbr` (quinn's original BBR or BBRv3, selected by `HONK_QUIC_BBR`); `cubic` when omitted; unknown values warn and fall back to cubic |
| TUIC | `alpn` | Comma-separated ALPN override; share links default to `tuic`; original Clash/Mihomo imports use the source default described below |
| TUIC | `initStreamReceiveWindow` / `initConnReceiveWindow` | Receive-window overrides |
| Juicity | `uuid:password` userinfo | Generic `username` / `password`; handler fallback for `juicity_uuid` / `juicity_password` |
| Juicity | protocol defaults | ALPN `h3`, BBR, and 8 MiB / 8 MiB initial receive windows that the shared adaptive flow control can grow |
| Juicity | UDP | One QUIC bi stream per client source carries every destination; replies return the real remote peer, subject to the server's own UDP socket and egress policy |
| Both | `mtu`, `sni`, insecure aliases, pin, ECH | Shared QUIC/TLS parameters |

Original Clash/Mihomo `proxies` entries materialize `h3` when TUIC `alpn` is missing or null. Explicit nonempty lists retain their order; explicit empty lists or blank strings retain honk's existing `tuic` fallback, not a no-ALPN handshake. This source default does not apply to native share links, flat nodes, sing-box `outbounds`, or textual record formats.

**Upgrade:** imported TUIC nodes that relied on the previous `tuic` fallback must specify `alpn: [tuic]` to retain it. The protocol-specific ALPN does not change the node UUID, but an effective configuration change replaces its runtime for new work; existing flows retain the normal generation-retirement behavior.

### AnyTLS

| Link input | Node field / behavior |
| --- | --- |
| userinfo secret | `password` and `anytls_password` |
| `min_idle_session` | `anytls_min_idle_session`; parsed as u16 and used as the requested standby floor, bounded by the eight-session pool cap |
| `idle_session_check_interval` | Duration stored in seconds; currently not applied, because the janitor cadence is fixed at 30 s |
| `idle_session_timeout` | Duration stored in seconds; defaults to 30 s |

Durations accept bare seconds plus `ms`, `s`, `m`, and `h` suffixes.

## VLESS

<a id="vless-udp-and-multiplexing"></a>

### UDP and multiplexing

VLESS has three independent choices: `udp=0|1` controls packet-dialing permission; `packetEncoding=auto|none|xudp|uot-v2` selects the fallback packet protocol; `mux=off|h2mux|xray` selects the TCP/UDP carrier paths. These choices are not negotiated.

| Canonical URI query | Default | Accepted values and effect |
| --- | --- | --- |
| `udp` | enabled | `1`/`true` permits packet dialing; `0`/`false` disables it without disabling TCP. Text booleans are ASCII-case-insensitive; repeated claims must agree. |
| `packetEncoding` | `auto` | `auto`, `none` (native VLESS command-UDP), `xudp` (Single XUDP), or `uot-v2`. This is the fallback whenever mux does not own the UDP path. |
| `mux` | `off` | `off`, `h2mux`, or `xray`. |
| `padding` | `false` | Boolean, valid only with `mux=h2mux`; selects sing-mux v1 padding. |
| `concurrency` | `0` | Signed `i16`, valid only with `mux=xray`. Negative disables TCP mux; zero allows 8 concurrent logical children per TCP carrier. A positive value sets that per-carrier concurrency, capped at 128. It does not set the number of physical carriers. |
| `xudpConcurrency` | `0` | Signed `i16`, valid only with `mux=xray`. Negative uses the protocol fallback. Zero shares the TCP pool and its per-carrier concurrency when TCP mux is enabled; otherwise it uses the protocol fallback. A positive value creates a separate UDP pool with that many concurrent logical children per carrier, capped at 128. |
| `xudpProxyUDP443` | `allow` | `reject`, `skip`, or `allow`, valid only with `mux=xray`; the exact UDP/443 precedence is below. |

`packetEncoding`, `mux`, and each mux control may occur at most once. Repeated `udp` claims are accepted only when all values agree.

| `mux` value | TCP and UDP paths |
| --- | --- |
| `off` | Ordinary VLESS TCP; UDP uses `packetEncoding`. UoT v2 opens one non-connect stream per client source for all destinations and returns each reply's real source address. |
| `h2mux` | Logical TCP and sing-mux PacketAddr UDP share the node-owned HTTP/2 carrier pool. UDP uses one stream per client source with per-datagram addressing. `padding=true` selects the existing padded H2MUX wire format. |
| `xray` | Xray Mux.Cool serves each pool enabled by the two concurrency settings. TCP and UDP pooling are independent. |

H2MUX owns both paths, so the fallback encoding does not replace its UDP path. It retains its existing pool policy and does not inherit Mux.Cool's 128-child carrier rollover.

Canonical examples (with a synthetic UUID) are:

```dae
node {
    auto: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&packetEncoding=auto&mux=off&udp=1#auto'
    h2_padded: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&packetEncoding=auto&mux=h2mux&padding=true&udp=1#h2-padded'
    xray_shared: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&packetEncoding=auto&mux=xray&concurrency=0&xudpConcurrency=0&xudpProxyUDP443=skip&udp=1#xray-shared'
    vision_udp_pool: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&flow=xtls-rprx-vision&packetEncoding=auto&mux=xray&concurrency=-1&xudpConcurrency=8&xudpProxyUDP443=skip&udp=1#vision-udp-pool'
}
```

Structured TOML/YAML/JSON separates these fields:

| Field | Meaning |
| --- | --- |
| `network` | Packet permission: `tcp` disables UDP; omission, `udp`, or `tcp,udp` permits it. |
| `packet_encoding` | Fallback: `auto`, `native`, `xudp`, or `uot-v2`. |
| `multiplex` | Tagged carrier selection, with the shapes below. |

| Multiplex protocol | Structured shape |
| --- | --- |
| Off | `{"protocol":"off"}` |
| H2 | `{"protocol":"h2","padding":true\|false}` |
| Xray | `{"protocol":"xray","tcp":N\|null,"udp":"protocol"\|"shared-tcp"\|{"separate":N},"udp443":"reject"\|"skip"\|"allow"}` |

`tcp` and every `separate` value are positive per-carrier logical-child concurrency limits of at most 128. Omitting `tcp` or setting it to null disables the TCP mux pool.

`udp: "shared-tcp"` requires a non-null `tcp` limit. Limits outside `1..=128` or a shared pool without TCP reject the node, even with `network: "tcp"`; they are not clamped or normalized into a disabled pool. This differs from the signed URI controls above (and corresponding Clash controls), whose positive values above 128 are clamped to 128.

#### Migration from `vless_mode`

**Breaking configuration change:** `vless_mode` is removed, not a deprecated alias. Migrate static links and provider content before upgrading. A static `node {}` entry containing it rejects the candidate configuration; a subscription drops that entry while keeping other valid nodes. An all-old-mode cached subscription body cannot restore nodes offline. Ensure a migrated body is available locally before an offline upgrade; do not delete usable Selector or delay state. Failure to restore one provider does not itself abort startup, though the assembled configuration must still validate.

Every old mode has a direct capability-preserving replacement:

| Removed `vless_mode` | `packetEncoding` | `mux` | `udp` | Additional query |
| --- | --- | --- | --- | --- |
| `auto` | `auto` | `off` | `1` | — |
| `native` | `none` | `off` | `1` | — |
| `legacy` | `auto` | `off` | `0` | Preserves TCP-only behavior; the old identity is not retained. |
| `uot-v2` | `uot-v2` | `off` | `1` | — |
| `h2mux` | `auto` | `h2mux` | `1` | `padding=false` |
| `h2mux-padded` | `auto` | `h2mux` | `1` | `padding=true` |
| `xudp` | `xudp` | `off` | `1` | — |
| `mux-cool` | `auto` | `xray` | `1` | `concurrency=0&xudpConcurrency=0&xudpProxyUDP443=skip` |

The last row preserves TCP/UDP availability. A skipped UDP/443 target uses the protocol fallback rather than pooled XUDP. UDP/443 is now allowed by default, including with Vision; use routing rules to block QUIC when desired. Every admitted VLESS node uses the new identity derivation at this upgrade, as described under [Node identity](#node-identity).

Old `vless_mode` URI syntax is rejected. The parser also rejects ambiguous third-party URI spellings such as `smux`, `multiplex`, `udp-over-tcp`, `packet-encoding`, `packet_encoding`, `packet-addr`, `xudp`, `only-tcp`, Brutal controls, and H2 stream-count tuning; only the exact canonical parameters in the table above configure these choices.

#### Target selection and composition

Without Vision, `packetEncoding=auto` uses native VLESS UDP for destination ports 53 and 443 and Single XUDP elsewhere. With Vision, permitted targets use Single XUDP. Native sends accept 1–8190 bytes and Single XUDP sends 1–7526 bytes; empty or oversized sends are packet-local refusals, while a received zero-length frame is still a datagram.

UDP/443 is allowed by default, including with base `xtls-rprx-vision`. To block it, place `l4proto(udp) && dport(443) -> block` before a broader matching routing rule.

| `mux=xray` UDP/443 policy | Result |
| --- | --- |
| `reject` | Refuse UDP/443 even if both mux pools are disabled. |
| `skip` | Select `packetEncoding`. |
| `allow` (default) | Use the configured UDP pool, or protocol fallback when no pool is enabled. |

`xtls-rprx-vision-udp443` normalizes to base Vision. It no longer changes permission or identity; the wire addon remains the base flow. Policy and capacity refusals are terminal for that attempt and health/Score-neutral. They never trigger another-node/direct fallback or automatic packet replay.

Vision always requires a direct TCP path: `mux=off`, or `mux=xray` with TCP mux disabled. Every H2MUX TCP composition is invalid, including with Encryption.

An Xray UDP-only pool is legal with Vision; with `concurrency=-1`, use a positive `xudpConcurrency` to create it.

Unencrypted Vision additionally requires raw TCP over negotiated TLS 1.3 or REALITY. Encrypted Vision may retain its selected outer stream transport and random-XOR handling, but it still cannot enable TCP mux, H2MUX UDP, native UDP, or UoT v2; XUDP/Xray UDP or disabled UDP are valid.

VLESS carrier slots come from the process-wide file-descriptor budget and are carved out before UDP endpoint slots, trading endpoint count for reusable carrier capacity. Exhaustion is reported as local capacity rather than a remote protocol failure. Honk also scopes XUDP Global IDs to its reusable source/session ownership and per-destination routing semantics; they are not Xray's source-only identity and do not promise collision-free NAT identity. See [source/session ownership and capacity](../design/outbound.md#sourcesession-ownership-and-capacity) for the canonical lifecycle and scope definition.

### Encryption

The base client-string form accepted in `encryption=` is:

```text
mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<base64url-key>
```

A key decodes to either a 32-byte X25519 key or a 1184-byte ML-KEM-768 key; chained authentication keys are accepted. `0rtt` uses a cached ticket and takes the 1-RTT path while cold. VLESS Encryption runs inside the selected outer TCP/TLS/REALITY/WS/gRPC transport. It supports native or XUDP fallback and Xray UDP pools, but not H2MUX TCP/UDP or UoT v2. Encryption and Vision may be combined under the direct-TCP-path rules above.

### REALITY and Vision

For VLESS and Trojan URL links, `security=reality` enables TLS and maps the REALITY query fields instead of silently falling back to ordinary PKI TLS. Other share-link schemes reject REALITY intent; structured VMess REALITY remains supported. Only VLESS uses `flow` to select Vision.

| Query | Meaning |
| --- | --- |
| `security=reality` | Select REALITY and enable TLS. A node that selects REALITY without `pbk` is rejected at validation rather than degraded to plain TLS. |
| `pbk` | Base64url 32-byte X25519 server public key; invalid input fails closed. |
| `sid` | Even-length hexadecimal short ID, at most 8 bytes; empty is valid. |
| `spx` | Stored spider path; defaults to `/` when REALITY is selected. |
| `flow=xtls-rprx-vision` | Enable Vision with the UDP/443 rules above. |
| `flow=xtls-rprx-vision-udp443` | Normalizes to `xtls-rprx-vision`; UDP/443 is already allowed by default. |
| `fp` | Accepted but ignored; global TLS mode owns the ClientHello fingerprint. |

VLESS TLS selection follows these rules:

| Input | TLS behavior |
| --- | --- |
| Explicit `security=none` | Disable TLS, overriding the historical default. |
| Any other explicit `security=` value | Enable TLS. |
| No `security`, but explicit `tls=0\|1` | Use the explicit TLS choice. |
| Neither setting on an ordinary VLESS link | Enable TLS by default. |
| Neither setting on a Base64-authority Shadowrocket link | Disable TLS unless REALITY fields enable it. |

Standard VMess links use their v2rayN JSON `tls` field instead.

Repeated `security` and recognized `tls` claims must agree, including cross-alias TLS enablement. A later value never overrides an earlier contradiction. VLESS and encoded VMess accept only `tls=0|1`; other schemes retain their handling of unrecognized `tls` text. Trojan and AnyTLS reject explicit plaintext claims rather than silently retaining mandatory TLS.

REALITY is TLS-1.3-only. Its first attempt advertises hybrid `X25519MLKEM768` followed by the preset classic `X25519` share. Only a completed handshake with a non-ed25519 leaf permits one fresh same-peer X25519-only connection; it must still authenticate with the configured REALITY key/HMAC before proxy data is sent.

Both attempts share one `3 × connect_timeout` setup deadline and introduce no new setting. This unauthenticated trigger is not server-version detection. Invalid ed25519 HMAC, TLS/IO errors and HRR remain terminal. Each connection seals its ClientHello exactly once, without key/nonce reuse. See [compatibility and authentication boundaries](../design/outbound.md#server-authentication-and-fingerprint-constraints).

The bare-TCP pool admits a pre-handshake socket only while it is silent. Any queued server byte, including a fatal TLS alert, rejects that bare entry at admission or checkout; there is no SNI/alert exception and no handshake retry. This does not reject a fully prepared ready stream merely because it has valid buffered application data.

REALITY does not use CA verification or `skip_cert_verify`. Target TLS-record buffering depends on the server version: the documented sing-box 1.12 / MetaCubeX-uTLS 1.8.0 peer has an 8192-byte buffer including framing, not a universal honk certificate limit. See the [server-version constraints](../design/outbound.md#server-authentication-and-fingerprint-constraints). The REALITY profile also adds ed25519; neither ignored `fp` nor the global Chrome-oriented mode promises exact browser identity.

## TLS fingerprint and ECH

Global `tls_implementation` applies to proxy TCP TLS and QUIC:

| Value | Behavior |
| --- | --- |
| `tls` | Plain BoringSSL ClientHello |
| `utls` | Chrome-shaped ClientHello with GREASE, permuted extensions, Chrome algorithms/curves, certificate compression, ALPS, and ECH GREASE |

Per-node ECH controls are:

| Input | Behavior |
| --- | --- |
| `ech_config=<base64>` / `echconfig=<base64>` | Static ECHConfigList; implies `ech_enabled` and takes precedence |
| `ech_config_path` | Structured-loader file path; `ech_config` wins when both exist |
| `ech=1` / `ech=true` | Enable DNS HTTPS-RR discovery when no static config exists |

A static config offers real ECH and ECH rejection fails the handshake closed. Discovery is best-effort and fail-open: if no ECHConfigList is found, the handshake continues without real ECH; `utls` still emits ECH GREASE. Discovery uses the bootstrap resolver or the first system nameserver and caches results by domain. The same controls apply to QUIC protocols.

## Share-link schemes

| Scheme | Format and mapping |
| --- | --- |
| `ss://` | SIP002 userinfo/full-authority base64 forms, plus `plugin` |
| `vmess://` | Flexible-base64 v2rayN JSON (`add`, `port`, `id`, `scy`, `net`, `host`, `path`, `tls`, `sni`, `ps`) |
| `vless://` | URL userinfo UUID plus stream transport, TLS/REALITY, flow, Encryption, and the canonical UDP/mux queries above |
| `trojan://` | URL userinfo secret plus transport and TLS queries |
| `anytls://` | URL userinfo secret plus TLS and pool queries |
| `hysteria2://` | Hysteria2 query mapping above; `hysteria://` is also accepted |
| `tuic://` | TUIC userinfo and QUIC tuning above |
| `juicity://` | Juicity userinfo and shared QUIC/TLS queries |
| `socks5://` | SOCKS userinfo; `socks4://` and `socks4a://` are accepted into the same node protocol |

For a chain written as `a -> b`, only `a` is parsed. Automatic names come only from a decoded `#fragment`, VMess `ps`, or `{scheme}-{host}`; the parser never uses the raw URI or userinfo as a fallback, so credentials do not leak into generated names. Explicit tags, fragments, and `ps` values remain user-controlled.

## Related docs

- [Subscription reference](./subscription.md)
- [Group reference](./groups.md)
- [Outbound design](../design/outbound.md)
