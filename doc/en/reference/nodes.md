# Nodes and share links

`node { ... }` declares dialable outbounds from share links and assigns each one a stable runtime identity.

## `node {}` declarations

Each non-comment line is one share link. Tags and links may be quoted or bare:

```dae
node {
    iris: 'socks5://10.10.10.1:2077'
    'hk1': 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@hk1.example.com:8388#fragment-name'
    'trojan://secret@example.com:443?sni=example.com#trojan1'
    socks5://10.10.10.2:1080
}
```

The current parser accepts both tagged and untagged entries. A non-empty dae tag replaces the link's `#fragment` name. An untagged link keeps its decoded fragment; without one, it receives the credential-free fallback `{scheme}-{host}`.

A malformed recognized link is dropped with `node section: skipping unparseable entry: ...` on stderr. An unknown scheme is a hard configuration error. A standalone `mux:` or `mux=` line is also rejected; VLESS wire behavior belongs in each link's `vless_mode=` query.

## Node identity

`Node::derive_id()` is the only identity derivation path. It computes UUID v5 over:

```text
protocol|host|port|credential-fingerprint|dial-shape
```

The credential fingerprint follows each handler's field precedence. The dial shape includes `sni`, transport, WebSocket/gRPC shape, Hysteria2 obfuscation, REALITY parameters, `flow`, and every non-`legacy` VLESS mode. Tuning and display metadata do not participate.

Identity is therefore stable across rename, reload, and subscription refresh when the dialable endpoint is unchanged. Configuration/runtime assembly rejects duplicate derived IDs. `Node::default()` has a nil ID; construction paths derive it, and the outbound runtime registry rejects any nil ID that reaches it.

## Node fields

The Node model exposes the fields below. Share links populate operator-facing fields from their scheme, userinfo, authority, fragment, and query; structured loaders, import, or runtime own the rows explicitly marked as metadata. None are separate keys inside dae `node {}`. Defaults below are model defaults; a URL-shaped share link defaults an omitted port to `443`, while a v2rayN VMess payload requires a valid port.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | UUID | derived | Stable content identity described above; nil is invalid at runtime |
| `name` | string | `""` | Dae tag, decoded fragment, VMess `ps`, or credential-free fallback |
| `protocol` | enum | `ss` | Derived from the share-link scheme |
| `address` | string | `""` | Parsed links store `host:port` |
| `host` | string | `""` | Explicit server host; otherwise `Node::host()` derives it from `address` |
| `port` | u16 | `0` | Server port; URL-shaped links use `443` when omitted |
| `username` / `password` | string? | null | Authentication, UUID, or secret from userinfo |
| `encryption` | string? | null | SS/VMess cipher or VLESS Encryption client string |
| `vless_mode` | `WireMode` | `legacy` | `legacy`, `uot-v2`, `h2mux`, `h2mux-padded`, `xudp`, or `mux-cool` |
| `plugin` / `plugin_opts` | string? | null | Parsed SIP002 plugin metadata; subscription import rejects non-empty values because proxy plugins are unsupported |
| `transport` | string | `"tcp"` | Stream transport; validated as empty/`tcp`, `ws`, or `grpc` |
| `tls` | bool | `false` | Stream TLS flag; Trojan/AnyTLS links enable it, VLESS historically defaults on |
| `sni` | string? | null | TLS server name from `sni`, or an unconsumed `host` query |
| `skip_cert_verify` | bool | `false` | `allowInsecure`, `allow_insecure`, or `insecure` equal to `1`/`true` |
| `ech_enabled` | bool | `false` | Static ECH config present, or `ech=1`/`true` |
| `ech_config` | string? | null | Base64 ECHConfigList from `ech_config` or `echconfig` |
| `ech_config_path` | string? | null | Structured-loader path to a base64 ECHConfigList; not a share-link query |
| `reality_public_key` | string? | null | REALITY X25519 public key from `pbk` |
| `reality_short_id` | string? | null | REALITY short ID from `sid` |
| `reality_spider_x` | string? | null | Stored `spx`; a REALITY link defaults it to `/` |
| `flow` | string? | null | VLESS flow from `flow`; only `xtls-rprx-vision` is supported |
| `network` | string? | null | Protocol network/capability hint; VMess JSON `net` and subscription import populate it |
| `ws_path` / `ws_host` | string? | null | WebSocket `path` and Host header |
| `grpc_service` | string? | null | gRPC `serviceName` or `service_name` |
| `hy2_auth` / `hy2_obfs` | string? | null | Hysteria2 authentication and salamander password |
| `hy2_up_mbps` / `hy2_down_mbps` | u32? | null | Hysteria2 brutal sender/receiver bandwidth hints |
| `hy2_port_hopping` / `hy2_hop_interval` | string? / u64? | null | Hysteria2 `mport` list and `mhop` seconds; effective interval is 30 s |
| `hy2_init_stream_recv_window` / `hy2_init_conn_recv_window` | u64? | null | Hysteria2 QUIC receive windows; effective defaults are 8 MiB / 8 MiB (the conn window doubles as the per-connection memory budget: slow consumers buffer up to ~3× it; RSS ≈ active connections × 3 × conn window) |
| `hy2_disable_mtu_discovery` | bool? | null | Hysteria2 `disablePathMTUDiscovery` |
| `quic_mtu` | u16? | null | QUIC UDP payload size from `mtu`; default 1252, accepted range 1200–65527; explicit values above 1252 enable GSO unless `HONK_QUIC_GSO=0` |
| `tls_pin_sha256` | string? | null | Leaf-certificate SHA-256 pin from `pinSHA256` or `pin_sha256` |
| `tuic_uuid` / `tuic_password` | string? | null | Dedicated TUIC credentials; handlers fall back to generic userinfo fields |
| `tuic_congestion` / `tuic_alpn` | string? | null | TUIC `congestion_control` and comma-separated `alpn` |
| `tuic_init_stream_recv_window` / `tuic_init_conn_recv_window` | u64? | null | TUIC QUIC receive windows; effective defaults are 8 MiB / 8 MiB |
| `juicity_uuid` / `juicity_password` | string? | null | Dedicated Juicity credentials; handlers fall back to generic userinfo fields |
| `anytls_password` | string? | null | AnyTLS secret copied from link userinfo |
| `anytls_min_idle_session` | usize? | null | Requested idle-session floor from `min_idle_session`; effective default 0, bounded by the two-session pool cap |
| `anytls_idle_session_check_interval` | u64? | null | Parsed `idle_session_check_interval` seconds; current runtime janitor cadence remains fixed at 30 s |
| `anytls_idle_session_timeout` | u64? | null | Idle eviction from `idle_session_timeout`; effective default 30 s |
| `mark` | u32? | null | Structured-model outbound `SO_MARK`; not a dae share-link query |
| `tags` | string[] | `[]` | Classification metadata; not a dae share-link query |
| `subscription_id` / `group_id` | UUID? | null | Import/runtime ownership metadata |
| `created_at` / `updated_at` | datetime | now | Runtime metadata |

Validation requires every non-built-in node to have a non-empty name and either `address` or `host`.

### Structured-loader compatibility

TOML, YAML, and JSON retain the legacy flat node keys. Loading reads the fields owned by the selected `protocol`; non-default fields left over from other protocols are stripped without rejecting the node, and one warning lists the stripped field names. For example, `tls: true` on an `ss` node is ignored with a warning rather than enabling TLS. Values used by the selected protocol still undergo normal parsing and validation. Honk's own output remains round-trip safe. With `store_subscribe`, a raw subscription body is persisted only after it parses successfully, and a rejected refresh leaves the last valid body untouched.

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

`network` may further disable packet dialing for Trojan, AnyTLS, and non-legacy VLESS. Legacy VLESS has no UDP, and VMess UDP is not implemented.

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

Trojan and VLESS URL links select transport with `type=` or its `network=` alias. For `ws`, `path` maps to `ws_path` and `host` maps to `ws_host`; for `grpc`, `serviceName` or `service_name` maps to `grpc_service`. `sni` is independent. `alpn` is accepted for compatibility but not stored. Configuration validation admits only TCP, WebSocket, and gRPC.

```dae
node {
    trojan_ws: 'trojan://secret@example.com:443?type=ws&sni=example.com&host=example.com&path=/path#trojan_ws'
    vless_grpc: 'vless://uuid@example.com:443?security=tls&type=grpc&serviceName=GunService#vless_grpc'
}
```

VMess uses v2rayN base64 JSON rather than URL query parameters: `net`, `host`, `path`, and `sni` populate the equivalent fields.

Live interoperability has been verified for VLESS TCP+REALITY+Vision, TCP+REALITY, TCP+WS, TCP+WS+TLS, and TCP+gRPC. Vision's supported direct-copy combination is raw TCP with TLS or REALITY, not WS/gRPC.

### Hysteria2

| Link input | Node field / behavior |
| --- | --- |
| userinfo secret | `username`, `password`, and `hy2_auth` |
| `obfs=salamander&obfs-password=...` | Non-empty password becomes `hy2_obfs`; other/incomplete obfs input stays disabled |
| `upmbps` / `downmbps` | `hy2_up_mbps` / `hy2_down_mbps`; a positive upload value enables Brutal, otherwise BBR is used; download is advertised in bytes/s |
| `mport` / `mhop` | Port list/ranges and hop interval in seconds; interval defaults to 30 and clamps to the upstream minimum of 5 |
| `pinSHA256` | `tls_pin_sha256`, replacing PKI/hostname verification |
| `initStreamReceiveWindow` / `initConnReceiveWindow` | QUIC receive-window overrides |
| `disablePathMTUDiscovery` | Disables QUIC PMTU discovery when `1`/`true` |
| `mtu` | Shared QUIC UDP-payload cap, accepted only in 1200–65527 |
| `sni`, insecure aliases, ECH parameters | Shared TLS behavior |

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
| `security=reality` | Select REALITY and enable TLS |
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
