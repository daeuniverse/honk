# Subscription reference

This reference defines `subscription {}` entries, durable recovery, and the subscription body formats accepted by the current runtime.

## `subscription {}` syntax

Declare the URL on the entry line. To override download settings for one subscription, add a block after the quoted URL, one key per line:

```dae
subscription {
    primary: 'https://example.com/sub'
    'https://example.com/no_tag_link'
    detailed: 'https://example.org/sub' {
        ua: 'honk/1.0'
        interval: 10000s
        cache: false
        route: direct
    }
}
```

The entry block accepts `ua`, `interval`, `cache` and `route`. `interval` is a duration; `0` disables periodic refresh. `cache: false` keeps this subscription's body out of the subscription store. `route` says how the fetch leaves (see below). A missing option takes the `assets.subscription` default, or `assets.route` for the route, then the built-in default: User-Agent `honk/<version>`, `86400s`, cache on, `routing`. See the [assets reference](./assets.md).

Two earlier forms still read, without a warning: a `(UA)` suffix after a quoted URL (`compatible: 'https://example.net/sub'(honk/1.0 like)`), and a block holding the URL (`detailed: { url: '…' ua: '…' }`), which also accepts `download_detour` as another name for `route`; setting both fails with `conflicting-subscription-route`. The rules below for suffixes and glued comments apply to the `(UA)` form.

Tags are optional. For a bare entry, the text before the first `:` is its tag unless that colon starts `://`; later colons in a URL do not split a tag. Tags and URLs may use matching single or double quotes. A quoted tag followed by `:` is explicit; otherwise the parser removes the URL's enclosing quotes before applying the same first-colon rule. Thus `'paid:https://example.com/sub'` has tag `paid`, while `'https://example.com/sub'` is tagless. Requiring quotes for the `(UA)` suffix keeps parentheses in bare URLs unambiguous. Both forms keep `sub_type: simple`, which automatically detects the supported body formats below.

The link suffix is parsed before embedded-tag normalization: `'paid:https://example.com/sub'(agent)` and `'paid:https://example.com/sub'#note` retain tag `paid`. Diagnostic entry ordinals count both block and inline declarations in source order, including skipped entries.
For a quoted head, only a colon immediately after the closing quote (allowing whitespace) declares an explicit tag. Colons in an unquoted User-Agent or glued comment suffix remain suffix data: `'https://example.com/sub'(agent:1)` is still tagless.

A tagless entry uses its URL host as its name: `'https://example.com/sub'` becomes `example.com`. A URL without a parseable host leaves the name empty and fails validation. Name uniqueness is not enforced: an explicit `example.com` tag and a tagless URL on that host share the same `subtag(example.com)` filter, which selects nodes from both subscriptions. Host-derived naming applies only to dae; JSON, YAML, and TOML still require `name`.

Tagless text without `://` is ignored. Explicitly tagged entries still reach validation, which requires a non-empty name and an HTTP(S) URL. `file://`, `http-file://`, and `https-file://` remain unsupported.

On entry lines, `#` starts a comment outside matching quotes at the start of the statement or immediately after an ASCII space or tab. In a bare URL, a glued `#` remains data, including after parentheses: `https://example.com/sub?filter=(hk)#token`. Quote a User-Agent containing a spaced `#`: `'https://example.com/sub'('agent # build')`; without UA quotes, the comment cuts off the suffix.

After a quoted URL, a glued `#` immediately after the closing quote or one balanced `(UA)` suffix is accepted as a comment, with `legacy-glued-hash` at that byte and the guidance “put whitespace before a comment”. `'http://q'#c` and `'http://q'(ua)#c` keep URL `http://q`, with UA `ua` only in the second form. Parentheses inside matching quotes do not affect nesting. A glued `#` inside the suffix remains UA data, including in `(Mozilla/5.0 (X11; (Linux)#build))`. Other trailing text, including `(ua)(x)` or `(agent) junk`, skips the entry with `trailing-entry-text` or `legacy-ua-boundary`.

This glued-tail compatibility runs after block recognition; it is not a lexical comment. In `sub: 'http://q'(ua)# }`, the separated `}` still closes the subscription block, so subsequent entries can fall outside it. Write `(ua) # }` to make the brace comment data instead.

Quote-error and block rules are listed in the [dialect reference](./dialect.md). An empty `route` follows routing, in every build.

## Internal model

| Field | Type | Default | Settable in dae | Meaning |
| --- | --- | --- | --- | --- |
| `id` | UUID | random UUID | No | Runtime subscription identity; SIGHUP preserves it when the fetch identity (URL + configured `ua` + headers) matches an existing subscription. |
| `name` | string | `""` | Yes, as the tag; otherwise the URL host | Display tag and the value used by group `subtag(...)` filters. |
| `url` | string | `""` | Yes | HTTP(S) fetch URL. |
| `sub_type` | enum | `simple` | No | Body parser: `simple`, `clash`, `sip008`, or `custom`. |
| `update_interval` | u64 | `86400` | Yes, as `interval` | Periodic refresh interval in seconds; `0` disables periodic refresh. |
| `user_agent` | string or null | `honk/<version>` | Yes, as `ua` | Optional `User-Agent` override; otherwise requests identify as `honk/<version>`. |
| `headers` | `{key,value}[]` | `[]` | No | Ordered extra request headers. |
| `download_detour` | string | `""` | Yes, as `route` | How the fetch leaves: empty or `routing` follows the routing rules, `direct` connects straight to the host, and a group name always goes through that group. An unknown group is refused at validation. |
| `enabled` | bool | `true` | No | Disabled subscriptions are not restored, fetched, or refreshed. |
| `cache` | bool | `true` | Yes, as `cache` | With `global.store_subscribe`, keep the fetched body for offline startup. `false` neither stores nor restores it, and maintenance deletes a body kept earlier. |
| `last_updated` | datetime or null | null | No | Model metadata; the current core runtime does not update it. |
| `node_count` | u32 | `0` | No | Model metadata; the current core runtime does not update it. |
| `created_at` | datetime | construction time | No | Model construction time. |

The internal body-selector behavior is:

| `sub_type` | Parser behavior |
| --- | --- |
| `simple` | Detects share-link lists, Clash YAML/JSON, SIP008, sing-box JSON, and supported client records. |
| `clash` | YAML or JSON with a top-level `proxies` sequence. |
| `sip008` | SIP008 `servers` objects or a bare server array; not a share-link list. |
| `custom` | The same format detection as `simple`. |

`honk-tool sub` uses the same parser for downloaded bodies and local files.

## Fetch, persistence, and recovery

`global.store_subscribe` defaults to `true`. When enabled, the runtime opens a private subscription store and fetches every enabled subscription immediately. Requests identify as `honk/<version>` unless `user_agent` supplies an override. A non-zero `update_interval` schedules later refreshes.

| Property | Current behavior |
| --- | --- |
| Location | The `subscription_body` table of the state db, `<data_dir>/state/honk.db` (0600 file in a 0700 directory; see the [API reference](./api.md#configuration-db---store-db)); the default `data_dir` is `/var/lib/honk`. |
| Key | URL-safe Base64 of a SHA-256 hash over the length-delimited URL, configured user-agent override (empty when unset or empty), and ordered header key/value pairs, plus `.sub`. The versioned default request UA is intentionally not part of the key, so default subscriptions retain their body across upgrades. The request identity is not exposed in plaintext. |
| Write boundary | After HTTP success and body acceptance, the complete raw response, including rejected entries, is written in one transaction. |
| Limits | Each body is at most 8 MiB, and all bodies together at most 32 MiB. A write that would pass 32 MiB first deletes bodies of subscriptions that are no longer enabled; if that is not enough it is refused, the previous body stays, and the fetch reports `subscription-store-write-failed`. A body whose subscription is not enabled at two consecutive maintenance ticks (every 60 seconds) is deleted, and a start with `store_subscribe: false` that still opens the state db, for `cache_file`, `password_auth` or `--store db`, empties the table. |
| Upgrade from `.sub` | Once the instance lock is held, a start copies the bodies of enabled subscriptions from the first private legacy store it finds in `<data_dir>/.sub`, `/var/share/honk/.sub` and `./.sub`, keeping bodies already in the state db. honk then unlinks the copied `*.sub` and every `.*.tmp` in that directory and removes it if empty; other legacy locations are left alone. A body that is unreadable, over 8 MiB, or would pass 32 MiB in total stays with a warning, and the body of a disabled subscription stays too, so a later start that enables the subscription imports it without a fetch. The previous process has exited by then, so a body it wrote last is copied like the others. An older binary started afterwards finds only the bodies left behind and fetches the others again. |
| Redirects | At most 5 hops. A redirect from `https` to another scheme fails the fetch, as does one to a loopback, private, link-local, or unspecified literal address that the configured URL did not itself use. A hostname resolving to such an address is not detected. |
| Body size | At most 8 MiB, enforced while reading rather than after the body is buffered. |

Subscription bodies and the nodes created from them remain runtime state; neither is written back into the dae configuration.

Subscription fetches follow routing unless the entry's `route` (or `assets.route`) says otherwise, like every other download honk makes itself. With `routing` the fetch target goes through the routing rules as user traffic does, so a rule can send it to a node, a group, `direct`, or `block`; each redirect is routed again. A group name forces that group. Routed requests share the route decision and tunnel of geodata and external UI downloads, send the same `User-Agent` and headers, and keep the 30-second timeout, 8 MiB limit, and redirect rules (only 301, 302, 303, 307 and 308, at most 5, never from HTTPS to HTTP, never to a private literal address from a public one). URL userinfo is sent as basic authentication, and a redirect to another scheme, host or port drops `Authorization`, `Cookie` and `Proxy-Authorization`, as the direct client does. `direct` keeps the previous transport: the bootstrap resolver and the bypass mark, with no routing involved. Builds without the `native-api` feature route these fetches the same way.

A subscription can route through nodes it supplies itself, for example when the rules send its URL to a group made only of its own nodes. On a fresh install those nodes do not exist yet. honk never falls back to direct: when the chosen route has no usable node, the fetch fails with an error that names the subscription and the outbound, says the route cannot carry the download yet, and suggests `route: direct` for that subscription. The provider status in the native API reports `last_error.code` `route_unavailable`. Nodes restored from the stored body stay in service throughout.

Routing starts after the startup subscription pass. Only `direct` subscriptions take part in the five-second first-fetch wait; routed subscriptions restore their stored body there and are fetched as soon as routing is ready.

Startup parses stored bodies before launching network refreshes. A valid restored body supplies active nodes immediately and excludes that subscription from the five-second first-fetch wait; its refresh still runs in the background. Missing, invalid or empty stored bodies are ignored. Only direct subscriptions without a valid restore enter the shared bounded wait, until their fetch finishes or the deadline expires; routed subscriptions fetch once routing is ready. A later accepted refresh replaces the SQLite body row, not a legacy file.

A restored or first-fetched body whose node ID is already used by an inline node or another subscription's node leaves that subscription out of the startup configuration instead of failing startup; a runtime publication rejects the same collision. A body may still replace the subscription's own nodes. The native API provider reports `last_error.code` `publication_rejected` with `last_error.details.diagnostic_code` `duplicate-node-id`. A restored body rejected this way still counts as restored: the subscription does not join the first-fetch wait, and its background refresh still runs and repeats the check.

On SIGHUP, subscriptions with the same fetch identity (URL + configured `ua` + headers) retain their runtime ID. The reload carries active nodes belonging to still-enabled subscriptions, commits the rebuilt configuration, and then starts an immediate background refresh. It does not read stored bodies, even when no nodes survive for a subscription; stored-body recovery runs only at startup.

Failure handling preserves a usable runtime rather than clearing it:

- HTTP, invalid UTF-8 encoding, parse, or no-usable-node failure publishes no replacement nodes and performs no write, so the active nodes and last valid stored body remain. Accepted bodies are persisted byte-for-byte, without repairing encoding.
- A persistence-write failure is non-fatal after parsing: the newly parsed nodes are still returned for publication, while the atomic path never installs a partially written body. The next restart can therefore restore whichever complete valid body remains on disk.
- An unsupported or malformed node is skipped individually. The shared node builder's warning includes a one-based proxy index and a static rejection reason, never the raw record or its credentials. The whole body fails only when no usable nodes remain; an empty result never clears the previous generation.

The last valid body is the last body accepted by the current import policy, not the last successfully published runtime generation. A partial body with one distinct usable node may replace the stored body; an all-invalid body cannot. Restore reparses with the current policy and may reject a body saved by an older version. Runtime collection or publication failure after a successful write retains the active generation but can leave the new body on disk. Disk and active state are not one transaction.

Changing `global.store_subscribe` through SIGHUP is rejected as restart-required.

## Subscription body formats

All accepted nodes receive the subscription ID. Duplicate derived node IDs retain the first usable occurrence; rejected entries do not reserve an identity. Later duplicates report both original indices. Array indices are one-based before normalization; URI and record indices are physical lines, including blanks and comments. Decoded Base64 has a child source referring to its original body, not fabricated encoded-byte offsets. Importing a full client profile extracts its nodes, not its DNS, routing, groups, or remote-provider configuration.

Normalized entries are admitted incrementally, without retaining a body-sized list of outcomes. Each body retains at most 128 nonterminal diagnostics, followed by one `subscription-diagnostics-truncated` summary with the omitted count; a terminal body failure is retained separately. The caller's existing diagnostic prefix is untouched and does not consume this budget. The limit applies to structured, URI, and record imports, including decoded Base64 and restored bodies, and never stops valid-node admission or changes first-usable duplicate selection.

Clash, SIP008, and sing-box credential scalars preserve string bytes and convert native finite numbers to the source format's canonical decimal text. Missing or null values are absent; booleans, lists, maps, and nonfinite numbers reject the entry. A valid alias cannot hide an invalid supplied credential. Numeric UUIDs still fail UUID validation; empty passwords remain subject to each protocol's requirements.

### Share-link lists

A list can be plain text or standard/URL-safe Base64, with optional padding and ASCII whitespace between encoded chunks. A leading UTF-8 BOM is accepted in raw and decoded bodies. Each line contains one share link:

```text
# blank lines and comments are ignored
socks5://user:password@127.0.0.1:1080#local
vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls#edge
```

Blank lines, comments, and Shadowrocket `REMARKS=` / `STATUS=` metadata lines are ignored without node warnings. Every remaining line is parsed by `Node::from_share_link`; unsupported or malformed lines are skipped with a warning. Share links with a non-empty proxy plugin are also skipped because honk does not execute plugins. The body is rejected when it contains no supported node URI, including metadata-only bodies. See the [node reference](./nodes.md) for canonical share-link fields and protocols.

### Clash YAML and JSON

A full profile or provider payload must contain a top-level `proxies` sequence. Entries without a supported `type`, server address, valid nonzero port, or required credentials are skipped. Ports may be integers or numeric strings. JSON is decoded natively, including UTF-16 surrogate-pair escapes in display names.

Accepted `type` values are `socks5`, `ss`/`shadowsocks`, `trojan`, `vmess`, `vless`, `hysteria2`/`hysteria`, `tuic`, `juicity`, and `anytls`. Unrelated client metadata is ignored; unsupported wire transports, proxy plugins, and contradictory security settings are not silently reinterpreted.

#### Common proxy fields

| Clash field | Internal field | Rule |
| --- | --- | --- |
| `name` | `name` | Defaults to `<type>-<server>:<port>`. |
| `server`, `port` | `host`, `port`, `address` | Required address and nonzero `u16` port; numeric port strings are accepted. |
| `username` | `username` | Optional string. |
| `password` | `password` | Optional string; VLESS applies the precedence below. |
| `cipher` | `encryption` | Optional string; VLESS applies the precedence below. |
| `plugin`, `plugin-opts` | — | Unsupported. An entry with either non-empty value is skipped before node publication; mapping-valued options are rejected too. |
| `network` | `transport` or packet capability | Trojan/VMess/VLESS use a stream transport (`tcp`, `ws`, or `grpc`); AnyTLS uses packet capability. |
| `tls` | `tls` | Optional boolean. Trojan, AnyTLS, Hysteria2, TUIC, and Juicity default to TLS and reject explicit disabling. |
| `servername`, `server-name`, `sni` | `sni` | Empty or whitespace-only names are absent; nonempty aliases must agree byte for byte. |
| `skip-cert-verify`, `skip_cert_verify`, `insecure` | `skip_cert_verify` | Native booleans; supplied aliases must agree. |
| `alpn` | `tls_alpn` | Ordered string list (or comma-separated string) for AnyTLS and ordinary raw-TCP Trojan/VMess/VLESS TLS; explicit values reach the TLS handshake in both `tls` and `utls` modes. QUIC retains the protocol-specific rules below. |

#### Protocol-specific options

Hysteria2 imports `password`/`auth`, `obfs: salamander` with `obfs-password`, upload/download bandwidth, `ports`/`mport` hopping ranges, `hop-interval`/`mhop`, receive windows, MTU, and MTU-discovery settings. TUIC imports UUID/password, congestion control, ALPN, receive windows, and MTU. AnyTLS imports `idle-session-check-interval`, `idle-session-timeout`, and `min-idle-session`. Supported spelling aliases are normalized before node identity is derived.

Explicit disabled feature blocks are treated as disabled, not as unsupported active features. `udp: true` is accepted for intrinsically UDP-capable protocols; an explicit UDP restriction is rejected where the node model cannot preserve it. TUIC permits an absent or empty password. Hysteria2 and Juicity accept an explicit `h3` ALPN matching their fixed runtime selection; Juicity receive windows remain fixed at 8 MiB, so non-default overrides are rejected.

AnyTLS packet claims are resolved once in this order: `anytls-network`, applicable `network`, then `udp`. Empty or null network text supplies no claim. Network strings use comma-separated `tcp`/`udp` tokens; aliases are compared by UDP allowance, so `udp` and `tcp,udp` agree, while `tcp` with `udp: true` conflicts. Unknown tokens such as `quic` reject the entry even beside a valid alias. Equivalent claims retain the first explicit network spelling; only a boolean-only input synthesizes `tcp` or `tcp,udp`.

TCP TLS ALPN list members are preserved verbatim, including order; each name must occupy 1–255 UTF-8 bytes and the length-prefixed list may not exceed 65,533 bytes. This is a syntactic ceiling; the complete ClientHello also has TLS-library size limits. Absent, null, or empty imported `alpn` lists preserve existing TLS-profile defaults and node IDs; the flat `tls_alpn` field accepts omission or a string array, not null. Nonempty overrides participate in identity and are rejected with disabled TLS, REALITY, WebSocket, or gRPC rather than silently discarded. Chrome ALPS is offered only when the actual ALPN list contains `h2`. Share-link ALPN compatibility is unchanged; this applies to structured subscription imports and the flat `tls_alpn` model field.

#### VLESS transport and REALITY

VLESS fields are applied before node identity is derived:

| Clash input | Mapping |
| --- | --- |
| `uuid`, then `password` | Credential; `uuid` wins and `password` is the fallback. |
| `encryption`, then `cipher` | VLESS Encryption; `encryption` wins. |
| `flow` | Empty or whitespace-only is absent; otherwise exactly `xtls-rprx-vision` or `xtls-rprx-vision-udp443`. |
| `network` | Stream transport. Packet permission remains the separate `udp` claim. |
| `reality-opts.public-key` | Enables the REALITY TLS carrier. It must be a non-empty string. |
| `reality-opts.short-id` | Optional REALITY short ID. |
| `reality-opts.spider-x` | REALITY spider path; missing or empty becomes `/`. |
| `ws-opts.path` | WebSocket path; falls back to flat `ws-path`. |
| `ws-opts.headers.Host` | WebSocket Host header, with case-insensitive key matching; falls back to scalar `ws-headers`, then `ws-host`. |
| `grpc-opts.grpc-service-name` | gRPC service name; falls back to `grpc-service`. |
| `client-fingerprint` | Intentionally not imported. TLS fingerprint selection is process-wide through `global.tls_implementation` and `global.utls_imitate`. |

Nested WS/gRPC values take precedence over their flat aliases. Active `reality-opts` must be a mapping with a non-empty `public-key`; an invalid active declaration is never downgraded to ordinary TLS. Empty or explicitly disabled feature blocks are ignored. Imported REALITY uses the same TLS-1.3-only, hybrid-then-classic key-share and fail-closed one-ClientHello behavior as a canonical share link; see the [node reference](./nodes.md#vless-udp-and-multiplexing).

#### VLESS UDP and multiplexing

Import defaults are source-specific. They do not all mean honk's canonical `packetEncoding=auto` default.

| Clash representation | Packet fallback | Multiplex | UDP permission |
| --- | --- | --- | --- |
| No packet declaration and no enabled wrapper | `auto` | off | disabled |
| Only an empty/null packet encoding | `auto` | off | disabled |
| `packet-encoding: none`/`legacy`, or `xudp: false` | native | off | enabled unless `udp: false` |
| `packet-encoding: xudp`, or `xudp: true` | Single XUDP | off | enabled unless `udp: false` |
| `udp: true` without another packet declaration | Single XUDP | off | enabled |
| `udp-over-tcp: true` or enabled object with version `0`/`2` | UoT v2 | off | enabled unless `udp: false` |
| enabled `smux`/`multiplex` with `protocol: h2mux` or explicit `padding` | auto (inactive while wrapped) | H2MUX | enabled unless `udp: false` |
| `mux: { enabled: true, ... }` | `auto`, unless an explicit packet encoding remains reachable through protocol fallback or `skip` | Xray Mux.Cool | enabled unless `udp: false` |

For H2MUX, `padding: true` selects the existing padded wire format; false selects unpadded H2MUX. Existing `only-tcp`, Brutal, and nonzero `max-connections`/`min-streams`/`max-streams` restrictions remain. Enabled H2MUX conflicts with Xray mux and UoT; enabled UoT also conflicts with Xray mux. Explicit XUDP conflicts with H2MUX or UoT, while their native/auto declarations are simply inactive behind the selected wrapper.

An enabled Clash `mux` block accepts active settings only for `enabled`, signed-`i16` `concurrency`, signed-`i16` `xudpConcurrency`, and `xudpProxyUDP443`; inactive extras are ignored. Zero TCP concurrency allows 8 concurrent logical children per carrier, a negative value disables TCP mux, and a positive value sets that per-carrier concurrency up to 128—it never specifies a physical-carrier count. Zero XUDP concurrency shares the enabled TCP pool and its per-carrier concurrency, or follows the packet fallback when TCP mux is disabled; negative always follows the fallback, and positive creates a separate UDP pool with that per-carrier logical-child concurrency, capped at 128. UDP/443 policy is `allow` by default and also accepts `skip` or `reject`; its precedence is documented in the [node reference](./nodes.md#vless-udp-and-multiplexing).

`udp: false` disables packet dialing independently; it does not disable an eligible bare TCP path. A VLESS Clash entry is also rejected for conflicting aliases, duplicate XUDP representations, enabled packet-address mode, unsupported packet encoding, unsupported UoT version, or an invalid/unsupported active Xray mux setting.

Canonical VLESS share links use exact `packetEncoding=auto|none|xudp|uot-v2`, `mux=off|h2mux|xray`, and `udp=0|1` queries. The removed `vless_mode` query and ambiguous third-party share-link spellings such as `smux`, `udp-over-tcp`, and `packet-encoding` are rejected rather than guessed.

### SIP008 and sing-box JSON

SIP008 version 1/2 wrappers (`{"servers":[...]}`) and bare server arrays import Shadowsocks `server`, `server_port`, `method`, `password`, and `remarks`. Empty plugin fields are harmless; active plugins remain unsupported.

sing-box profiles import supported entries from `outbounds`: Shadowsocks, SOCKS5, VMess, VLESS, Trojan, Hysteria2, TUIC, Juicity, and AnyTLS. Structural `selector`, `urltest`, `direct`, `block`, and `dns` entries are not proxy nodes. TLS/SNI, REALITY, WebSocket/gRPC, VLESS packet choices, and supported protocol tuning are normalized through the common node builder. A sing-box VLESS entry defaults specifically to Single XUDP with UDP permitted when no enabled H2MUX/UoT wrapper or explicit `packet_encoding` selects another path. This is a sing-box import default, not the global meaning of Auto. Empty or omitted gRPC service names retain sing-box's empty service rather than honk's `GunService` default. Hysteria2 accepts `server_ports` without `server_port`, using the first hopping port as its nominal endpoint. Unsupported chaining, wire features, or authentication requirements are not silently discarded, and per-node uTLS fingerprint hints do not override honk's process-wide TLS selection.

In sing-box input, `network` is packet capability, not a stream type; `transport.type` selects the stream. Unsupported stream names such as `h2` reject the entry rather than becoming raw TCP.

Where the sing-box mapping supports packet restrictions, `network: udp` and `network: tcp,udp` permit UDP, while `network: tcp` disables it. These values do not introduce UDP-only TCP rejection. `network` remains independent of VLESS fallback encoding and H2MUX/UoT carrier selection.

Explicit sing-box native VLESS UDP (`packet_encoding: ""`) maps to native. Enabled H2MUX or UoT v2 owns the packet path even when the source also specifies `packet_encoding`, including `"xudp"`; disabling a wrapper does not suppress the sing-box Single-XUDP default. Sing-box multiplex import remains H2MUX-only; it does not synthesize Xray Mux.Cool controls.

### Surge, Surfboard, Loon, and Quantumult X

The importer accepts named comma-separated records from Surge/Surfboard/Loon and `protocol=endpoint,...,tag=name` records from Quantumult X. Full profiles use `[Proxy]` or `[server_local]`; other sections are ignored. Quoted names/passwords may contain commas, equals signs, escaped quotes, and intentional edge spaces.

Explicit credential and cipher aliases must agree before conversion. In named records, positional credentials are used only when the corresponding named claim is absent; a different positional value does not conflict with a valid explicit claim. Quantumult X has no positional fallback. Empty explicit credentials participate in alias comparison rather than selecting a fallback.

Permitted optional record credentials retain empty strings and quoted whitespace byte for byte: SOCKS username/password, Hysteria2 authentication, and TUIC password. An explicit empty value still overrides a positional fallback; protocols requiring nonempty credentials continue to reject it.

Record `transport`/`network` stream claims are compared before assignment, including repeated keys. Empty text and `tcp` have the same raw-TCP meaning; conflicting or unsupported stream claims reject the entry.

AnyTLS record `network` occurrences are packet claims, not stream claims. Every repeated `network`, `udp`, and `udp-relay` value is validated before selection. Equivalent packet claims retain the first explicit network spelling; an invalid or conflicting occurrence rejects the record.

VLESS record `packet-encoding`/`packet_encoding`/`packetencoding` values `none` or empty select native UDP; `xudp` selects Single XUDP. Repeated aliases must agree, including explicit empty assignments. `udp`/`udp-relay` controls packet permission separately. With neither a packet encoding nor `udp: true`, a record remains UDP-disabled; `udp: true` without an encoding selects Single XUDP. Active record `mux` and UoT declarations remain unsupported rather than being reinterpreted.

Supported records map credentials, TLS/SNI, WebSocket/gRPC, REALITY, and implemented protocol options to the same node model. Quantumult X `obfs=wss` uses `obfs-host` for both WebSocket Host and the default TLS SNI; an explicit TLS hostname wins. SSR, unsupported plugins/obfuscation, and unsupported transports are skipped rather than imported as another protocol.

Surge `server-cert-fingerprint-sha256` maps to honk's leaf-certificate pin: both replace standard X.509 verification. Independent `server-cert-verify-name`, client certificates, `sni=off`, and Shadow TLS are not representable and are rejected rather than discarded ([Surge TLS reference](https://manual.nssurge.com/policies/tls.html)).

Record aliases `skip-cert-verify`, `allow-insecure`, and `insecure` are compared with the inverse of `tls-verification` before assignment. `tls-verification=false,insecure=true` agrees; `tls-verification=true,insecure=true` rejects the entry. Record text accepts `true/yes/1/on` and `false/no/0/off`, case-insensitively; empty text and `t/y/f/n` remain invalid. Certificate-pin restrictions still apply.

Effective Quantumult X `tls-cert-sha256` and `tls-pubkey-sha256` pins are rejected: honk's leaf-certificate pin replaces PKI, and it is not substituted for an unverified foreign verification contract. With explicit `tls-verification=false`, QX ignores both pins and the import preserves that disabled verification. Effective QX REALITY ignores customized `tls-alpn` and session-ticket settings, as its [official configuration](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf) specifies; ordinary TLS does not. Legacy VMess `aead=false`, active Shadowsocks UoT/SSR, unsupported TLS ALPN, and disabled TLS-session reuse are rejected rather than discarded.

## Offline parsing and probes

`honk-tool sub` accepts a fetched subscription URL or a local file in any supported body format. A local file avoids the subscription download and is useful for offline parsing, but the command then performs its configured connectivity and latency probes:

```console
honk-tool sub ./share-links.txt --limit 10
honk-tool sub https://example.com/sub --ua honk-tool
```

Downloaded bodies and local files use the same automatic detection. Passing `-` reads one HTTP(S) subscription URL from standard input; it does not read a subscription body from standard input. See the [CLI reference](./cli.md) for probe flags and output.

## Related docs

- [Node reference](./nodes.md)
- [Group reference](./groups.md)
- [CLI reference](./cli.md)
