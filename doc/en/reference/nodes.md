# Nodes and share links

`node { ... }` declares dialable outbounds from share links and assigns each one a stable runtime identity.

## `node {}` declarations

Each non-comment line is one share link. Tags and links may be quoted or bare:

Outside matching quotes, `#` starts a comment at the start of the statement or immediately after an ASCII space or tab. In a bare share link, a glued `#` remains data: `ss://…#hk1 # note` keeps the name `hk1`, while `ss://…#hk2#note` keeps `hk2#note`. A glued `#` after a closing link quote is accepted as a comment, with `legacy-glued-hash` at that byte: `'ss://…#hk1'#note` keeps `hk1`. Put whitespace before a comment. Other text after the closing quote skips the entry with `trailing-entry-text`. Quote-error and block rules are listed in the [dialect reference](./dialect.md).

```dae
node {
    iris: 'socks5://10.10.10.1:2077'
    'hk1': 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@hk1.example.com:8388#fragment-name'
    'trojan://secret@example.com:443?sni=example.com#trojan1'
    socks5://10.10.10.2:1080
}
```

The current parser accepts both tagged and untagged entries. A non-empty dae tag replaces the link's `#fragment` name. An untagged link keeps its decoded fragment; without one, it receives the credential-free fallback `{scheme}-{host}`.

An absent or empty VMess JSON `ps` remark uses `vmess-{host}` before validation. A non-empty dae tag then replaces it.

In quoted tags and links, a backslash escapes the next character when locating the closing quote; the source escape is retained in the parsed text.

A malformed recognized link is dropped with an `invalid-node-entry` diagnostic using the original node-entry ordinal, never the link or node name. Data entrypoints return it without logging; plain entrypoints report it once. An unknown scheme is a hard configuration error. A standalone `mux:` or `mux=` line is also rejected; VLESS wire behavior belongs in each link's `vless_mode=` query.

In the legacy `ss://base64(method:password@host:port)` form, decoded credentials are literal text, not URL-decoded: `%20` stays `%20`, and `?`, `/`, `#`, `:` and `@` remain password characters. The last `@` separates the endpoint; the userinfo may itself be `base64(method:password)`. A decoded payload without `@`, or credentials that cannot supply a method and password, is rejected. URL userinfo forms still percent-decode their credentials. The endpoint, path, query (including `/?plugin=...`) and fragment keep the usual URL handling.

## Node identity

`Node::derive_id()` is the only identity derivation path. It computes UUID v5 over:

```text
protocol|host|port|credential-fingerprint|dial-shape
```

The credential fingerprint follows each handler's field precedence. The legacy dial shape includes `sni`, transport, WebSocket/gRPC shape, Hysteria2 obfuscation, REALITY parameters, `flow`, and every non-`legacy` VLESS mode. Nonempty structured `tls_alpn` derives a child UUID v5 using the legacy ID as its namespace and the JSON tuple `["tls-alpn", <ordered list>]` as its name; this separates ALPN from arbitrary credential text. Empty `tls_alpn` retains legacy IDs. Tuning and display metadata do not participate.

Before joining, each raw credential and dial-shape field and the effective host escapes `\` as `\\` and `|` as `\|`. Joined fingerprints are not escaped again. For nodes accepted by `Config::validate`, different identity fields produce different hash material. This guarantee does not cover nodes rejected by full configuration validation, even if `Node::from_share_link` can derive their IDs.

At this upgrade, a node with `|` or `\` in one of these pipe-joined identity fields receives a new ID once; its ID-keyed health and warm state starts fresh. Nodes without either character in those fields retain their IDs. ALPN uses the separate JSON child-UUID step, so `|` or `\` in ALPN alone does not change an existing ID at this upgrade. Selector choices migrate by member name, pooled ready streams already retire per generation, and `name`/`subtag` filters are unaffected.

Identity is therefore stable across rename, reload, and subscription refresh when the dialable endpoint is unchanged. Configuration/runtime assembly rejects duplicate derived IDs. `Node::default()` has a nil ID; construction paths derive it, and the outbound runtime registry rejects any nil ID that reaches it.

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
| `encryption` | string? | null | SS/VMess cipher or VLESS Encryption client string |
| `vless_mode` | `WireMode` | `legacy` | `legacy`, `uot-v2`, `h2mux`, `h2mux-padded`, `xudp`, or `mux-cool` |
| `plugin` / `plugin_opts` | string? | null | Parsed SIP002 plugin metadata; subscription import rejects non-empty values because proxy plugins are unsupported |
| `transport` | string | `"tcp"` | Stream transport; validated as empty/`tcp`, `ws`, or `grpc` |
| `tls` | bool | `false` | Stream TLS flag; Trojan/AnyTLS links enable it, canonical VLESS links historically default on |
| `sni` | string? | null | TLS server name; nonempty `sni` and `peer` claims must agree, then an unconsumed `host` supplies the fallback |
| `tls_alpn` | string[] | `[]` | Structured/imported ordinary raw-TCP TLS ALPN; empty preserves the TLS profile default. Nonempty values are supported for AnyTLS and TCP Trojan/VMess/VLESS, not disabled TLS, REALITY, WS/gRPC, or QUIC. TUIC retains `tuic_alpn`; this is not a share-link query. |
| `skip_cert_verify` | bool | `false` | Certificate-verification bypass from agreeing `allowInsecure`, `allow_insecure`, and `insecure` claims; see the security note below |
| `ech_enabled` | bool | `false` | Static ECH config present, or `ech=1`/`true` |
| `ech_config` | string? | null | Base64 ECHConfigList from `ech_config` or `echconfig` |
| `ech_config_path` | string? | null | Structured-loader path to a base64 ECHConfigList; not a share-link query |
| `reality_public_key` | string? | null | REALITY X25519 public key from `pbk` |
| `reality_short_id` | string? | null | REALITY short ID from `sid` |
| `reality_spider_x` | string? | null | Stored `spx`; a REALITY link defaults it to `/` |
| `flow` | string? | null | VLESS flow from nonempty `flow` or Shadowrocket `xtls=2`; only `xtls-rprx-vision` is supported |
| `network` | string? | null | Packet capability for supported protocols; independent of VMess JSON `net` and other stream-transport fields |
| `ws_path` / `ws_host` | string? | null | WebSocket `path` and Host header |
| `grpc_service` | string? | null | gRPC `serviceName` or `service_name` |
| `hy2_auth` / `hy2_obfs` | string? | null | Hysteria2 authentication and salamander password |
| `hy2_up_mbps` / `hy2_down_mbps` | u32? | null | Hysteria2 brutal sender/receiver bandwidth hints |
| `hy2_port_hopping` / `hy2_hop_interval` | string? / u64? | null | Hysteria2 `mport` list and `mhop` seconds; effective interval is 30 s |
| `hy2_init_stream_recv_window` / `hy2_init_conn_recv_window` | u64? | null | Hysteria2 QUIC receive windows; effective defaults are 8 MiB / 8 MiB (the conn window doubles as the per-connection memory budget: slow consumers buffer up to ~3× it; RSS ≈ active connections × 3 × conn window) |
| `hy2_disable_mtu_discovery` | bool? | null | Hysteria2 `disablePathMTUDiscovery` |
| `quic_mtu` | u16? | null | QUIC UDP payload size from `mtu`; default 1252, accepted range 1200–65527; explicit values above 1252 enable GSO unless `HONK_QUIC_GSO=0` |
| `tls_pin_sha256` | string? | null | Leaf-certificate SHA-256 pin from `pinSHA256` or `pin_sha256` |
| `tuic_uuid` / `tuic_password` | string? | null | TUIC credentials; flat aliases must agree with `username` / `password` |
| `tuic_congestion` / `tuic_alpn` | string? | null | TUIC `congestion_control` and comma-separated `alpn` |
| `tuic_init_stream_recv_window` / `tuic_init_conn_recv_window` | u64? | null | TUIC QUIC receive windows; effective defaults are 8 MiB / 8 MiB |
| `juicity_uuid` / `juicity_password` | string? | null | Juicity credentials; flat aliases must agree with `username` / `password` |
| `anytls_password` | string? | null | AnyTLS secret copied from link userinfo |
| `anytls_min_idle_session` | usize? | null | Requested idle-session floor from `min_idle_session`; effective default 0, bounded by the two-session pool cap |
| `anytls_idle_session_check_interval` | u64? | null | Parsed `idle_session_check_interval` seconds; current runtime janitor cadence remains fixed at 30 s |
| `anytls_idle_session_timeout` | u64? | null | Idle eviction from `idle_session_timeout`; effective default 30 s |
| `mark` | u32? | null | Structured-model outbound `SO_MARK`; not a dae share-link query |
| `tags` | string[] | `[]` | Classification metadata; not a dae share-link query |
| `subscription_id` / `group_id` | UUID? | null | Import/runtime ownership metadata |
| `created_at` / `updated_at` | datetime | now | Runtime metadata |

Intrinsic validation requires a nonempty node name, effective host, and explicit nonzero `port`. `address` does not supply a missing port; address-only IPv6 requires an explicit `host`. Only exact injected `direct`/`block` identities are endpoint-exempt.

### Structured-loader compatibility

TOML, YAML, and JSON retain the legacy flat node keys. Loading reads the fields owned by the selected `protocol`; non-default fields left over from other protocols are stripped without rejecting the node, and one warning lists the stripped field names. For example, `tls: true` on an `ss` node is ignored with a warning rather than enabling TLS. `username` is not a credential alias for Trojan, VLESS, Hysteria2, or AnyTLS; when supplied without that protocol's effective credential field, it is stripped with a targeted warning, preserving legacy behavior and IDs. Values used by the selected protocol still undergo normal parsing and validation. Honk's own output remains round-trip safe. With `store_subscribe`, a raw subscription body is persisted only after it parses successfully, and a rejected refresh leaves the last valid body untouched.

Flat credential aliases are compared before incompatible fields are stripped: Hysteria2 `hy2_auth`/`password`, TUIC and Juicity dedicated UUID/`username` and dedicated password/`password`, and AnyTLS `password`/`anytls_password`. Missing or null claims are absent; supplied strings must agree byte for byte, including empty strings and surrounding spaces. An empty credential remains subject to its protocol's requirements. Flat credential fields remain strings; numeric coercion applies only to subscription feeds.

The new `tls_alpn` field is deliberately excluded from legacy stripping: a nonempty value on an unsupported protocol or TLS context rejects the node instead of silently changing its handshake.

Share-link verification booleans ignore surrounding whitespace and ASCII case. `true`, `yes`, `1`, and `on` disable certificate verification; `false`, `f`, `no`, `n`, `0`, `off`, `t`, and `y` leave verification enabled. Empty or unknown text and conflicting aliases reject the link. **Security change:** `yes` and `on` previously left verification enabled; they now disable it and emit a warning. Use explicit `true` or `false` and review these links before upgrading. Native structured booleans remain typed; strings and numbers are not coerced.

VMess cipher claims accept `auto` and `aes-128-gcm`, case-insensitively, and store lowercase names; empty optional claims use the default. JSON `scy`/`security`, encoded share-link `encryption`/`scy`/cipher-valued `security`, and supported feed cipher aliases must agree before assignment. Unsupported or conflicting values reject the node. In encoded share links, `security=none` and `security=tls` still select TLS behavior, not a cipher. Record positional ciphers remain lower-priority fallbacks.

TUIC share links and feeds accept only absent, empty, or `native` relay mode; unsupported `udp-relay-mode`/`udp_relay_mode` claims reject even beside a valid alias. Hy2 share links require exact lowercase `obfs=salamander`; absent/empty disables obfuscation, and unknown names (including `SALAMANDER`) reject. Salamander without a nonempty password still disables obfuscation. Repeated password claims and `obfs-password`/`obfs_password` must agree. Clash keeps case-insensitive Salamander with a nonblank password; sing-box keeps exact lowercase type and rejects active incomplete obfuscation objects.

Duration conversion rejects negative, nonfinite, and out-of-range values instead of saturating. Structured feed seconds fields round integer milliseconds up (`500ms` and `1000ms` both become `1`; zero stays zero), then compare aliases. Share-link Hy2 `mhop` remains bare unsigned integer seconds: `500ms` and `1s` are ignored with a redacted warning. AnyTLS share-link durations retain the seconds parser; dae millisecond settings retain bare/ms/s syntax and truncate fractional milliseconds.

Sing-box `hop_interval`, `idle_session_timeout`, and `idle_session_check_interval` preserve native numeric zero as an explicit value; missing or null remains absent. Hysteria2 records compare every `mhop`, `hop-interval`, and `hop_interval` occurrence after conversion to seconds, rejecting conflicts and invalid values even beside a valid alias.

Hysteria2 hopping sets reject repeated ports and overlapping ranges before dialing, including `443,443`. A singleton remains valid. Valid specifications retain their spelling; embedded authority lists retain their stricter empty-segment rule. The outbound constructor uses the same checked decoder for directly constructed nodes.

Every canonical adapter completion applies intrinsic validation: ordinary share links, VMess JSON, standalone flat Node serde, and subscription imports. UUID-based protocols require valid UUIDs; unsupported cipher, transport, packet capability, flow, ALPN context, or hopping sets reject before identity derivation. Vision requires TLS or REALITY. Constructed nodes also reject empty SNI/flow/network values that adapters normalize away. Feed-only nonempty-password requirements remain format-specific; optional SOCKS authentication and handler-supported empty credentials remain valid. Invalid dae node lines and feed entries retain their existing skip policy; valid siblings survive. Parse-only Config fragments remain parse-only, except that invalid contained nodes now reject at construction. Standalone serde preserves a supplied ID; runtime identity admission is separate.

Direct `Node::validate()` calls return the same static, redacted errors as adapter completion. Validation errors never include the supplied node name or credential values.

Detailed Config loaders and configuration/registry admission retain the intrinsic field and cause, adding the original one-based node ordinal instead of replacing the reason with a generic invalid-node error. Credential conflicts identify the canonical alias field without exposing either value. Standalone `NodeSeed` and Node serde still return redacted generic serde errors.

For VMess JSON with `net: "ws"`, an omitted or empty `host` uses the endpoint host in the WebSocket handshake. A supplied nonempty `host` remains the explicit override.

## Protocols

| Protocol | Alias | TCP | UDP | Notes |
| --- | --- | --- | --- | --- |
| `ss` | `shadowsocks` | Yes | Yes | AEAD and Shadowsocks 2022 |
| `trojan` | — | Yes | Yes* | TLS; TCP/WS/gRPC transport |
| `vmess` | — | Yes | No | AEAD; TCP/WS/gRPC and REALITY; handler requires `rprx` |
| `vless` | — | Yes | Mode-dependent* | Legacy, UoT v2, H2MUX, XUDP, Mux.Cool, Encryption, REALITY, and Vision; handler requires `rprx` |
| `socks5` | — | Yes | Yes | CONNECT and UDP ASSOCIATE |
| `hysteria2` | — | Yes | Yes | QUIC/H3, salamander, brutal/BBR, and port hopping |
| `tuic` | — | Yes | Yes | TUIC v5 over QUIC |
| `juicity` | — | Yes | Yes | Juicity over QUIC |
| `anytls` | — | Yes | Yes* | Multiplexed TLS sessions and UoT v2 |
| `direct` | — | Yes | Yes | Reserved built-in bypass outbound; no share-link scheme |
| `block` | — | No | No | Reserved built-in reject outbound; no share-link scheme |

`network` may further disable packet dialing for Trojan, AnyTLS, and non-legacy VLESS. AnyTLS rejects UDP payloads above 16 KiB, matching anytls-go 0.0.13's relay buffer. Legacy VLESS has no UDP, and VMess UDP is not implemented.

For protocols that own `network`, flat structured input accepts comma-separated `tcp`/`udp` tokens, ignoring token whitespace and ASCII case. `tcp` disables UDP; `udp` and `tcp,udp` both permit UDP. Empty or whitespace-only text becomes absent and retains the protocol's default capability. Unknown tokens such as `quic`, or empty tokens inside a nonempty list, reject the node. This controls UDP admission only: `udp` does not add a TCP rejection policy.

VMess and VLESS nodes still parse without the `rprx` Cargo feature, but no handler is registered and dialing fails with `No handler for protocol`. `honk-core` enables `rprx` by default.

`honk-core` injects `direct` and `block` at startup and reload with fixed reserved IDs. User nodes may use neither those names nor those protocols.

## Protocol parameters

### Shadowsocks 2022

| Method | Decoded base64 PSK length |
| --- | --- |
| `2022-blake3-aes-128-gcm` | 16 bytes |
| `2022-blake3-aes-256-gcm` | 32 bytes |
| `2022-blake3-chacha20-poly1305` | 32 bytes |

An incorrect or non-base64 key fails handler construction.

### Stream transports

Stream-capable share links select transport with `type=` or its `network=` alias. Empty text and `tcp` mean raw TCP; `ws` and `grpc` select WebSocket and gRPC. All supplied aliases, including compatible `obfs` declarations and repeated query keys, must agree before assignment. Unsupported names such as `h2` and `kcp` reject the link during parsing. For `ws`, `path` maps to `ws_path` and `host` maps to `ws_host`; for `grpc`, `serviceName` or `service_name` maps to `grpc_service`. `sni` is independent. `alpn` is accepted for compatibility but not stored.

```dae
node {
    trojan_ws: 'trojan://secret@example.com:443?type=ws&sni=example.com&host=example.com&path=/path#trojan_ws'
    vless_grpc: 'vless://uuid@example.com:443?security=tls&type=grpc&serviceName=GunService#vless_grpc'
}
```

VMess accepts v2rayN Base64 JSON (`net`, `host`, `path`, `sni`) and Shadowrocket's `vmess://base64(auto:UUID@host:port)?...` authority form. The latter maps `tls`, `peer`/`sni`, `obfs=websocket|grpc`, `obfsParam`, `path`, and `remark`; standard/URL-safe Base64 and optional padding are accepted. Encoded-authority VMess requires AEAD authentication and `auto`/`aes-128-gcm`; unsupported ciphers and REALITY parameters are rejected, not silently replaced.

VMess JSON `net` and Shadowrocket transport parameters select only the stream transport. They no longer populate packet-network capability; an omitted packet restriction retains the existing default UDP allowance. Valid empty transport spelling is preserved where already used.

Live interoperability has been verified for VLESS TCP+REALITY+Vision, TCP+REALITY, TCP+WS, TCP+WS+TLS, and TCP+gRPC. Vision's supported direct-copy combination is raw TCP with TLS or REALITY, not WS/gRPC.

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

Conflicting TLS/REALITY, flow, or transport declarations are rejected rather than silently downgraded. `obfs` accepts only empty/`none`, `websocket`, or `grpc` for VLESS; unsupported transports are not reinterpreted as TCP. Canonical `host` and `serviceName`/`service_name` fields retain their existing fallback precedence. Explicit SNI aliases are compared before assignment; equal bytes coalesce, unequal names reject without case rewriting. Empty or whitespace-only SNI and flow normalize to absent before node-ID derivation. Nonempty flow must be exactly `xtls-rprx-vision`.

Clash imports compare `servername`, `server-name`, and `sni`; record imports additionally compare `tls-name` and `tls-host`, retaining `obfs_sni` as a lower-priority fallback, including Quantumult X WSS Host. Record `off` remains invalid. In share links and VMess JSON, WebSocket `host` is only the Host header; outside WebSocket it is a lower-priority SNI fallback. The endpoint hostname remains the final TLS consumer fallback.

### Hysteria2

Both `hysteria2://` and `hy2://` are accepted. The entire percent-decoded userinfo is the authentication string: literal `user:password` retains both halves and the colon, matching percent-encoded `user%3Apassword`.

| Link input | Node field / behavior |
| --- | --- |
| userinfo secret | `hy2_auth`; preserves the full `user:password` form rather than taking only the password |
| `obfs=salamander&obfs-password=...` | Non-empty password becomes `hy2_obfs`; other/incomplete obfs input stays disabled |
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
| TUIC | `congestion_control` | `cubic`, `new_reno`, or `bbr`; unknown values warn and fall back to cubic |
| TUIC | `alpn` | Comma-separated ALPN override; default is `tuic` |
| TUIC | `initStreamReceiveWindow` / `initConnReceiveWindow` | Receive-window overrides |
| Juicity | `uuid:password` userinfo | Generic `username` / `password`; handler fallback for `juicity_uuid` / `juicity_password` |
| Juicity | protocol defaults | ALPN `h3`, BBR, and fixed 8 MiB / 8 MiB receive windows |
| Both | `mtu`, `sni`, insecure aliases, pin, ECH | Shared QUIC/TLS parameters |

### AnyTLS

| Link input | Node field / behavior |
| --- | --- |
| userinfo secret | `password` and `anytls_password` |
| `min_idle_session` | `anytls_min_idle_session`; parsed as u16 and used as the requested standby floor, bounded by the two-session pool cap |
| `idle_session_check_interval` | Duration stored in seconds; currently not applied, because the janitor cadence is fixed at 30 s |
| `idle_session_timeout` | Duration stored in seconds; defaults to 30 s |

Durations accept bare seconds plus `ms`, `s`, `m`, and `h` suffixes.

## VLESS

### Modes

`vless_mode` is one normalized, mutually exclusive mode. It is never negotiated.

| Mode | TCP | UDP | Behavior |
| --- | --- | --- | --- |
| `legacy` | Ordinary VLESS stream | No | Backward-compatible default; omission preserves legacy identity |
| `uot-v2` | Ordinary VLESS stream | Direct UoT v2 | One connected UoT stream per UDP transport |
| `h2mux` | H2MUX logical stream | Native connected sing-mux UDP | TCP and UDP share a node-owned HTTP/2 carrier pool |
| `h2mux-padded` | H2MUX logical stream | Native connected sing-mux UDP | `h2mux` with sing-mux v1 padding |
| `xudp` | Ordinary VLESS stream | Single XUDP | One unpooled mux-command carrier per UDP transport, session ID 0 |
| `mux-cool` | Mux.Cool logical stream | Pooled XUDP | TCP and UDP share a node-owned Xray Mux.Cool carrier pool |

The canonical query is `vless_mode=legacy|uot-v2|h2mux|h2mux-padded|xudp|mux-cool`. The legacy alias `packetEncoding=xudp` maps to `xudp`. Duplicate mode representations are rejected.

Every non-`legacy` mode rejects non-empty, non-`none` VLESS Encryption. Vision is supported only with `legacy` or `xudp`, TLS or REALITY, and raw TCP transport. No mode negotiation, fallback, or first-packet replay occurs.

Ambiguous third-party query forms are rejected instead of guessed: `mux`, `smux`, `multiplex`, `udp-over-tcp`, `udp_over_tcp`, `packet-encoding`, `packet_encoding`, `packet-addr`, `packet_addr`, `xudp`, `only-tcp`, `only_tcp`, `brutal`, `brutal-opts`, `brutal_opts`, `max-connections`, `max_connections`, `min-streams`, `min_streams`, `max-streams`, and `max_streams`.

This reference describes the configuration surface. See [Outbound design](../design/outbound.md) for carrier ownership and wire framing.

### Encryption

The base client-string form accepted in `encryption=` is:

```text
mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<base64url-key>
```

A key decodes to either a 32-byte X25519 key or a 1184-byte ML-KEM-768 key; chained authentication keys are accepted. `0rtt` uses a cached ticket and takes the 1-RTT path while cold. VLESS Encryption runs inside the selected TCP/TLS/REALITY/WS/gRPC transport, but requires `legacy` mode and cannot combine with `flow`.

### REALITY and Vision

For VLESS URL links, `security=reality` enables TLS and maps the REALITY query fields; `flow` selects Vision.

| Query | Meaning |
| --- | --- |
| `security=reality` | Select REALITY and enable TLS. A node that selects REALITY without `pbk` is rejected at validation rather than degraded to plain TLS |
| `pbk` | Base64url 32-byte X25519 server public key; invalid input fails closed |
| `sid` | Even-length hexadecimal short ID, at most 8 bytes; empty is valid |
| `spx` | Stored spider path; defaults to `/` when REALITY is selected |
| `flow=xtls-rprx-vision` | Enable the supported Vision flow |
| `fp` | Accepted but ignored; global TLS mode owns the ClientHello fingerprint |

An explicit `security=` overrides the historical VLESS default: `none` disables TLS; any other value enables it. Without `security`, VLESS defaults TLS on. Standard VMess links use their v2rayN JSON `tls` field instead.

REALITY authenticates the peer against its REALITY key and fails closed; it does not need CA verification or `skip_cert_verify`. Choose a server-side REALITY `dest`/client SNI whose TLS Certificate message remains under 8 KiB, because sing-box REALITY buffers 8192 bytes; `dl.google.com` is known to fit while `www.microsoft.com` does not.

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
| `vless://` | URL userinfo UUID plus transport, TLS/REALITY, flow, Encryption, and canonical mode queries |
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
