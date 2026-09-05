# Subscription reference

This reference defines `subscription {}` entries, durable recovery, and the subscription body formats accepted by the current runtime.

## `subscription {}` syntax

Each entry has one of these forms:

```dae
subscription {
    primary: 'https://example.com/sub'
    compatible: 'https://example.net/sub'(honk/1.0 like)
    detailed: {
        url: 'https://example.org/sub'
        ua: 'honk/1.0'
        interval: '10000s'
    }
}
```

The short `tag: URL` form keeps the default `honk/<version>` User-Agent. Append `(UA)` after a quoted URL to override it. The block form accepts `url`, optional `ua`, and optional `interval`; `interval` is a duration and defaults to `86400s`. Set it to `0` to disable periodic refresh.

The URL may otherwise be single-quoted or bare, but ordinary HTTP(S) URLs must have a tag because the parser dispatches on the first `:`. Requiring quotes for the `(UA)` suffix keeps parentheses in bare URLs unambiguous. Both forms keep `sub_type: simple`; dae subscriptions do not auto-detect Clash YAML.

## Internal model

| Field | Type | Default | Settable in dae | Meaning |
| --- | --- | --- | --- | --- |
| `id` | UUID | random UUID | No | Runtime subscription identity; SIGHUP preserves it when the fetch identity (URL + configured `ua` + headers) matches an existing subscription. |
| `name` | string | `""` | Yes, as the tag | Display tag and the value used by group `subtag(...)` filters. |
| `url` | string | `""` | Yes | HTTP(S) fetch URL. |
| `sub_type` | enum | `simple` | No | Body parser: `simple`, `clash`, `sip008`, or `custom`. |
| `update_interval` | u64 | `86400` | Yes, as block `interval` | Periodic refresh interval in seconds; `0` disables periodic refresh. |
| `user_agent` | string or null | `honk/<version>` | Yes, as `(UA)` or block `ua` | Optional `User-Agent` override; otherwise requests identify as `honk/<version>`. |
| `headers` | `{key,value}[]` | `[]` | No | Ordered extra request headers. |
| `enabled` | bool | `true` | No | Disabled subscriptions are not restored, fetched, or refreshed. |
| `last_updated` | datetime or null | null | No | Model metadata; the current core runtime does not update it. |
| `node_count` | u32 | `0` | No | Model metadata; the current core runtime does not update it. |
| `created_at` | datetime | construction time | No | Model construction time. |

The internal body-selector behavior is:

| `sub_type` | Parser behavior |
| --- | --- |
| `simple` | Standard-Base64 or plain-text share-link list. |
| `clash` | Clash YAML with a top-level `proxies` sequence. |
| `sip008` | Currently uses the same share-link-list parser as `simple`. |
| `custom` | Tries `simple`, then Clash YAML. |

`honk-tool sub` uses `custom` for a fetched URL; dae entries remain `simple`.

## Fetch, persistence, and recovery

`global.store_subscribe` defaults to `true`. When enabled, the runtime opens a private subscription store and fetches every enabled subscription immediately. Requests identify as `honk/<version>` unless `user_agent` supplies an override. A non-zero `update_interval` schedules later refreshes.

| Property | Current behavior |
| --- | --- |
| Preferred location | `<data_dir>/.sub`; the default `data_dir` is `/var/lib/honk`. |
| Legacy locations | Prefer an existing `/var/share/honk/.sub` (`LEGACY_DATA_DIR`), then an existing `./.sub` when the configured store is absent. A custom `data_dir` follows the same order. No store is moved or deleted automatically; migrate it explicitly when ready. |
| Permissions | Directory mode `0700`; file mode `0600`. Symlink store directories are rejected. |
| Filename | URL-safe Base64 of a SHA-256 hash over the length-delimited URL, configured user-agent override (empty when unset or empty), and ordered header key/value pairs, plus `.sub`. The versioned default request UA is intentionally not part of the key, so default subscriptions retain their cache across upgrades. The request identity is not exposed in plaintext. |
| Write boundary | The raw response body is written only after HTTP success and successful parsing. A temporary file is synced, renamed atomically, and followed by a directory sync. |

Subscription bodies and the nodes created from them remain runtime state; neither is written back into the dae configuration.

Startup parses stored bodies before launching network refreshes. A valid restored body supplies active nodes immediately, so that subscription does not participate in the five-second first-fetch wait. Its network refresh still runs in the background. A missing or invalid stored body is ignored and keeps that subscription in the bounded first-fetch wait until the fetch finishes or the deadline expires; a later valid refresh replaces the corrupt file.

On SIGHUP, subscriptions with the same fetch identity (URL + configured `ua` + headers) retain their runtime ID. The reload carries active nodes belonging to still-enabled subscriptions, restores a stored body only when no nodes survive for that subscription, commits the rebuilt configuration, and then starts an immediate background refresh.

Failure handling preserves a usable runtime rather than clearing it:

- HTTP, parse, or no-usable-node failure publishes no replacement nodes and performs no write, so the active nodes and last valid stored body remain.
- A persistence-write failure is non-fatal after parsing: the newly parsed nodes are still returned for publication, while the atomic path never installs a partially written body. The next restart can therefore restore whichever complete valid body remains on disk.
- An individual unsupported share link or Clash proxy is skipped. The whole body fails only when no supported nodes remain; an empty result never clears the previous generation.

Changing `global.store_subscribe` through SIGHUP is rejected as restart-required.

## Subscription body formats

All accepted nodes receive the subscription ID. After parsing, duplicate derived node IDs are discarded with the first occurrence retained. A body whose supported entries all collapse to one duplicated identity is rejected rather than replacing the active subscription.

### `simple`

A `simple` body is either standard Base64 (padding optional) containing one share link per line, or the plain-text list itself:

```text
# blank lines and comments are ignored
socks5://user:password@127.0.0.1:1080#local
vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls#edge
```

Each non-comment line is parsed by `Node::from_share_link`. Unsupported or malformed lines are skipped. Share links with a non-empty proxy plugin are also skipped because honk does not execute plugins. The body is rejected when it contains no supported node URI. See the [node reference](./nodes.md) for canonical share-link fields and protocols.

### Clash YAML

A Clash body must contain a top-level `proxies` sequence. Non-mapping entries, entries without a string `type` or `server`, entries without an integer `port` fitting `u16`, and unsupported proxy types are skipped.

Accepted `type` values are `socks5`, `ss`/`shadowsocks`, `trojan`, `vmess`, `vless`, `hysteria2`/`hysteria`, `tuic`, `juicity`, and `anytls`. The importer maps only the fields documented below; unrelated Clash keys are ignored unless listed as VLESS rejection inputs.

#### Common proxy fields

| Clash field | Internal field | Rule |
| --- | --- | --- |
| `name` | `name` | Defaults to `<type>-<server>:<port>`. |
| `server`, `port` | `host`, `port`, `address` | Required as a string and integer respectively. |
| `username` | `username` | Optional string. |
| `password` | `password` | Optional string; VLESS applies the precedence below. |
| `cipher` | `encryption` | Optional string; VLESS applies the precedence below. |
| `plugin`, `plugin-opts` | — | Unsupported. An entry with either non-empty value is skipped before node publication; mapping-valued options are rejected too. |
| `network` | `transport` | Optional transport string. |
| `tls` | `tls` | Optional boolean. |
| `servername`, `sni` | `sni` | `servername` wins; `sni` is the fallback. |
| `skip-cert-verify` | `skip_cert_verify` | Optional boolean. |

#### VLESS transport and REALITY

VLESS fields are applied before node identity is derived:

| Clash input | Mapping |
| --- | --- |
| `uuid`, then `password` | Credential; `uuid` wins and legacy `password` is the fallback. |
| `encryption`, then `cipher` | VLESS Encryption; `encryption` wins. |
| `flow` | Non-empty VLESS flow. |
| `network` | Transport. |
| `reality-opts.public-key` | Enables the REALITY TLS carrier. It must be a non-empty string. |
| `reality-opts.short-id` | Optional REALITY short ID. |
| `reality-opts.spider-x` | REALITY spider path; missing or empty becomes `/`. |
| `ws-opts.path` | WebSocket path; falls back to flat `ws-path`. |
| `ws-opts.headers.Host` | WebSocket Host header, with case-insensitive key matching; falls back to scalar `ws-headers`, then `ws-host`. |
| `grpc-opts.grpc-service-name` | gRPC service name; falls back to `grpc-service`. |
| `client-fingerprint` | Intentionally not imported. TLS fingerprint selection is process-wide through `global.tls_implementation` and `global.utls_imitate`. |

Nested WS/gRPC values take precedence over their flat aliases. If `reality-opts` is present but is not a mapping or lacks a non-empty `public-key`, the entry is skipped; it is never downgraded to ordinary TLS.

#### VLESS packet modes

| Clash representation | Normalized mode | Conditions |
| --- | --- | --- |
| No enabled packet/multiplex option | `legacy` | Disabled blocks and `xudp: false` do not select a mode. |
| `smux` or `multiplex` with `enabled: true` | `h2mux` or `h2mux-padded` | Requires `protocol: h2mux` or an explicit boolean `padding`. `padding: true` selects `h2mux-padded`; otherwise `h2mux`. |
| `udp-over-tcp: true` | `uot-v2` | Boolean shorthand. |
| `udp-over-tcp: { enabled: true, version: 0|2 }` | `uot-v2` | Missing `version` is treated as `0`; `_` aliases are also accepted. |
| `packet-encoding: xudp` | `xudp` | `packet_encoding` is the flat alias. |
| `xudp: true` | `xudp` | Boolean shorthand. |
| Canonical share-link `vless_mode=mux-cool` | `mux-cool` | `mux-cool` is not accepted through Clash packet/mux aliases. |

A VLESS Clash entry is rejected for any of these conditions:

- duplicate aliases or duplicate XUDP representations;
- more than one enabled mode among H2MUX, UoT, and XUDP;
- enabled `packet-addr`/`packet_addr` or top-level `mux`;
- an enabled `smux`/`multiplex` block with neither `protocol: h2mux` nor an explicit `padding` boolean;
- a multiplex protocol other than `h2mux`, `only-tcp: true`, enabled Brutal settings, or non-zero `max-connections`, `min-streams`, or `max-streams` tuning;
- `udp-over-tcp` version other than `0` or `2`;
- `udp: true` without an explicit non-legacy packet mode, or `udp: false` with a non-legacy mode;
- a packet encoding other than empty or `xudp`, including packetaddr and `mux-cool` aliases;
- a non-legacy mode combined with VLESS Encryption, or with `flow` other than the supported `xudp` + `xtls-rprx-vision` combination.

Canonical VLESS share links use `vless_mode=legacy|uot-v2|h2mux|h2mux-padded|xudp|mux-cool`. Ambiguous third-party share-link keys such as `smux`, `udp-over-tcp`, and `packet-encoding` are rejected rather than guessed.

## Offline parsing and probes

`honk-tool sub` accepts a fetched subscription URL or a local file containing one share link per line. A local file avoids the subscription download and is useful for offline parsing, but the command then performs its configured connectivity and latency probes:

```console
honk-tool sub ./share-links.txt --limit 10
honk-tool sub https://example.com/sub --ua honk-tool
```

For a fetched URL, the tool uses `custom`, so it tries the simple list and then Clash YAML. Passing `-` reads one HTTP(S) subscription URL from standard input; it does not read a subscription body from standard input. See the [CLI reference](./cli.md) for probe flags and output.

## Related docs

- [Node reference](./nodes.md)
- [Group reference](./groups.md)
- [CLI reference](./cli.md)
