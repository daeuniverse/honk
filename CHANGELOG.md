# Changelog

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Entries live in [changes/](changes/) until release.

## [0.1.0-beta.6] - 2026-11-09

### Added

- DNS request rules accept `subtag(...)`, which resolves the server hosts of nodes from matching subscriptions through a chosen `-> direct` upstream (for example a provider's own DoH) instead of the bootstrap resolver. Each DNS generation precomputes host policy outcomes; native flow traces explicitly mark consumption of these decisions as incomplete evidence (`not_instrumented`). (#463)
- Add default-off `dns-syslog` Cargo support to send client DNS outcomes to a configured TCP syslog receiver with `global.syslog_dns_enabled` and `global.syslog_addr`, independently of native API history. (#462)
- Preserve complete DNS answers and include deduplicated IP, CNAME and record-type arrays for search. (#462)
- Include monotonic processing time as numeric `duration_ms` and final upstream name as `upstream` in DNS audit events; cache responses use `cache`, and results without upstream metadata use null. (#462)
- Configure sender hostname and application name only in syslog headers using `global.syslog_hostname` and `global.syslog_app_name`, avoiding duplicate fields when receivers parse the JSON body. (#462)
- Reuse one TCP connection with octet-counted whole events, bounded batching and reconnect backoff. (#462)
- Emit a fixed RFC 5424 header and JSON schema; optionally prefix CEE with `global.syslog_cee_enabled` (default false), and reject obsolete format-template settings. (#462)
- Preserve final-upstream and response-source metadata when a concurrent DNS query reuses an in-flight result without a cache hit, including stale-cache fallback. (#462)
- Include a readable `message` in DNS audit JSON so CEE syslog receivers can display each event; VictoriaLogs maps it to `_msg` instead of using its missing-message placeholder. (#462)
- Keep the DNS audit event when a delivered response's answers cannot be rendered, with `answers: null` and the reason in `answers_omitted`. (#462)

### Changed

- The shipped `honk-core` binary now allocates through jemalloc instead of mimalloc; `-stock` archives still use the system allocator. (#455)
- The `honk-core` Cargo feature formerly named `mimalloc` is now `jemalloc`; builds with `--no-default-features` keep the system allocator. (#455)
- Release downloads label the default allocator `jemalloc-*` instead of `mimalloc-*`. (#455)
- Removed the mimalloc-only `HONK_MI_COLLECT_SECS` and `MIMALLOC_PURGE_DELAY` environment variables and the worker idle-collection machinery they controlled. (#455)
- Runtime jemalloc options use `_RJEM_MALLOC_CONF`, not `MALLOC_CONF`: the crate prefixes jemalloc symbols and the environment variable with `_rjem_`. (#455)
- Startup verifies only the TC programs the configured interfaces bind (plus one routing target when they bind none), so a WAN-only Ethernet host no longer loads the LAN or L3 variants. Later variants are verified outside the shared backend lock and become bindable only after receiving the current routing generation; a failed variant does not block independent variants. Logging and event-consumer cancellation preserve the original map FDs required by deferred loads. (#450)

### Fixed

- Bound each DNS cache shard's answer bytes to `max(entry capacity × 1 KiB, 65,535 bytes)`, evicting LRU entries when large answers fill the budget. (#454)
- Inline DNS cache insert/remove accounting in size-optimized builds. (#454)
- Group probes measure up to 10 members at once, so a slow member no longer leaves later members at `deadline`. (#459)
- Probe target resolution failures are logged with the host and DNS error instead of appearing only as `address_unavailable`. (#459)
- Probe targets fall back to bootstrap DNS when the running DNS configuration cannot answer, so `asis` routing no longer reports every probe as `address_unavailable`. (#459)
- A refused `--store db` start no longer leaves an empty state database, or its data directory, behind. (#467)
- Subscription connection and HTTP status failures name the selected node and group in the log. Classified fetch failures report their stage and available outbound attribution in native API provider `last_error.details`, including completed failures retained during shutdown; unusable subscription content reports `parse_failed`. (#451)

### Internal

- Move the aya family to userspace `aya` 0.16, `aya-obj` 0.6, `aya-log` 0.4 and kernel-side `aya-ebpf` 0.3, adapting call sites to the new map, loader and TC context APIs while preserving programs, map names and shared binary layouts. (#436)
- Make shared payload padding explicit and restrict locked-value `Pod` implementations to the three audited payloads; reject stale BTF schemas without changing existing field offsets or map-value sizes. (#436)

## [0.1.0-beta.5] - 2026-11-03

### Added

- Formal releases attach `.deb`, `.rpm` and Arch Linux packages for `x86_64` and `aarch64`, which install `honk-core`, `honk-core.service` and an example configuration. (#417)

### Changed

- Full builds embed doona 0.1.0-rc.5 with both editions.
- Add reloadable `global.shutdown_wait_connections` (default `false`). Set `true` to retain the previous five-second connection grace; mandatory cleanup and native HTTP shutdown are unchanged. (#410)

### Fixed

- AnyTLS nodes with `min_idle_session` above one now keep that many idle sessions open. The pool janitor previously reused the idle session it already had and never dialed the rest ([#260](https://github.com/daeuniverse/honk/issues/260)). (#405)
- Clash subscriptions that pin a server certificate with `fingerprint` now import it as `tls_pin_sha256` instead of failing the TLS handshake. (#420)
- Clash and Clash-compatible subscriptions keep VMess nodes whose `udp: true` claim honk cannot honor; the node now imports for TCP instead of being dropped. (#443)
- Clash and sing-box subscriptions import WebSocket upgrade headers other than `Host`, so nodes that require `ws-opts.headers.User-Agent` are no longer dropped. The headers participate in node identity and are sent on the upgrade. (#421)
- Direct and supplied-TCP WebSocket dials enforce the same header limits and reserved-name rules as subscription admission, before network I/O. (#421)
- sing-box keeps empty WebSocket header strings and rejects invalid or conflicting claims instead of silently dropping them. (#421)
- Structured node errors retain the actual transport or header field instead of being mislabeled as XHTTP errors. (#421)
- Clash WebSocket Host extraction retains its first-usable scalar and lazy fallback behavior while additional headers remain strictly checked. (#421)
- Subscription stream-normalization failures retain their canonical field alongside the original entry index, preserving transport context without exposing supplied header names or values. (#421)
- A TCP health-check cooldown no longer skips a node's due UDP probe, and an emergency TCP probe no longer clears UDP cooldowns. (#408)
- Health-check cycles skip worker creation when both TCP and UDP probes are cooling down. (#408)
- When NFQUEUE is unavailable at startup, configuration writes and reloads are no longer refused because `global.nfqueue_enable` needs a restart; the reloaded configuration keeps NFQUEUE disabled. (#407)
- A subscription that shares a node with another subscription now loads its other nodes; the shared node stays with the subscription that published it first. (#406)
- Retry failed subscription fetches with exponential backoff instead of waiting for the full refresh interval. (#412)
- Traffic on L3-typed interfaces whose driver still sends Ethernet frames (for example RAWIP cellular modems) is intercepted again. (#427)

### Security

- AES-GCM no longer uses a `ctutils` release whose mask generation and `u128` comparisons are not constant-time (RUSTSEC-2026-0385); `ctutils` is now 0.4.7. (#441)

## [0.1.0-beta.4] - 2026-10-30

### Added

- `ui: 'embedded-lite'` serves doona lite from the binary, and full builds embed doona 0.1.0-rc.4 with both editions. (#363)

### Changed

- Negative cache-hit outcome expiry uses the stored deadline, excluding preferred-family waits without reconstructing the deadline from a rounded TTL. Wire TTLs and routing behavior are unchanged. (#390)
- Clash `/stats.dns` reports DNS socket admission refusals and timeouts, proxy admission timeouts, and idle resources selected for pressure retirement, without per-query warnings. (#390)
- DNS UDP client admission now shares one process-wide budget across reloads; requests in retiring generations keep their permits until they finish instead of receiving a fresh quota each generation. (#390)
- Tests that replace the process-global bootstrap resolver run in an isolated child process. (#390)
- The lint gates compile the DNS benchmarks. (#390)

### Fixed

- WebSocket and gRPC nodes whose path or service name contains a space now connect instead of failing with "invalid uri character"; non-ASCII text is now normalized to percent-encoded UTF-8 ([#378](https://github.com/daeuniverse/honk/issues/378)). (#382)
- The standalone `dns.bind` UDP listener handles much higher concurrent query load. Up to four supervisors, bounded by the Tokio worker count, receive datagrams in batches of up to eight, and an answer that is ready on its first poll is sent without spawning a task. A recent cache hit with an unchanged address set skips the route-projection locks for up to one second, so its route may expire up to one second later than the cache entry. (#381)
- Sockets owned by upstream DNS use one bounded budget that persists across reloads. Under pressure, idle transports are reclaimed and a busy direct UDP upstream spreads over up to four sockets per address. A query whose upstream cannot obtain a socket is answered with `SERVFAIL`. (#381)
- Concurrent UDP DNS client queries per DNS generation are capped at `min(1536, MemTotal / 4 / 256 KiB)`, replacing the previous cap of at most 256, with a fallback of 1536 when `MemTotal` is unreadable. Above the cap, `dns.bind` answers `REFUSED` and transparent port-53 UDP drops the query. (#381)
- The startup descriptor-budget log replaces `dns_slow` with `dns_sockets` and `dns_udp_queries`. (#381)

### Internal

- Changelog entries come from per-PR fragments in `changes/`, and release notes list the released CHANGELOG section with the embedded doona version. (#364)
- The README follows the doona README layout, with a table of release builds and both kinds of web UI. (#364)
- CI path filters list only the files each lane reads, the release-script tests run on every PR, and the CI report shows unfinished runs as pending. (#364)

## [0.1.0-beta.3] - 2026-10-27

Summarised from the [release notes](https://github.com/daeuniverse/honk/releases/tag/v0.1.0-beta.3), which list every change. Interface and VLAN handling changed for existing configurations: see the [migration guide](doc/migration/en/v0.1.0-beta.3.md).

### Changed

- honk plans and owns interface hooks per interface index, with type-aware framing and lazy reconciliation. (#352, #353)
- A missing or late interface no longer aborts startup, and TCX links follow device deletion and recreation. (#353)
- Per-device sysctl paths and the `interface_binding` degradation report interface setup failures explicitly.

### Fixed

- Bond interception and replies stay on the logical master, so active-backup failover keeps working while LAN bridge ports remain covered. (#354)
- VLAN-tagged and unsupported frames go to their own upper device. To manage a VLAN subnet, list the VLAN subinterface (for example `eth1.20`); a parent-only configuration no longer black-holes that subnet. (#355)

## [0.1.0-beta.2] - 2026-10-25

Summarised from the [release notes](https://github.com/daeuniverse/honk/releases/tag/v0.1.0-beta.2), which list every change.

### Changed

- The per-source UDP new-flow budget is 1024/s per CPU.
- The UDP endpoint pool scales with RAM: a quarter of `MemTotal` at 64 KiB per endpoint, capped at 32,768.
- The 64 KiB UDP receive buffers moved out of endpoint and source task futures, cutting per-source and per-destination memory.
- BBRv3 is the default BBR for QUIC, and direct QUIC dials bind fresh sockets to recover from carrier loss.

### Fixed

- All client sources share one reply-socket pool per peer, so more than seven foreign peers no longer kill an ordinary full-cone endpoint or drop replies; flows that end by themselves are no longer fenced.

## [0.1.0-beta.1] - 2026-10-23

Summarised from the [release notes](https://github.com/daeuniverse/honk/releases/tag/v0.1.0-beta.1), which list every change. Configuration moved since `v0.0.1.beta.84`: see the [migration guide](doc/migration/en/v0.1.0-beta.1.md).

### Added

- The opt-in native API (`native-api`) serves authenticated HTTP and SSE over runtime, sources, DNS, probes and lifecycle, and `native-ui` embeds the web UI. The Clash API remains the default.

### Changed

- AnyTLS uses eight carriers per node, a 1 MiB per-session write budget and single-copy frame serialization, raising upload throughput and lowering CPU and new-stream latency.
- Release archives are split by API (`full`, `clash-api`, `native-api`) and ship with `SHA256SUMS` and build provenance.
- Runtime state lives in `<data_dir>/state/honk.db`, `cache_file.enabled` changed meaning, and download defaults moved to the new `assets` block.

### Fixed

- A cancelled AnyTLS write no longer sends a payload the caller never accepted, and a spread re-election no longer fails a healthy pool or trips its dial breaker.
- OpenWrt kernels start from their external BTF.
- Shared UDP sources survive malformed SOCKS5, Trojan and Juicity datagrams.
- QUIC session tickets honour `skip_cert_verify`, and a reload restores warm carriers and probes.

[Unreleased]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.6...HEAD
[0.1.0-beta.6]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.5...v0.1.0-beta.6
[0.1.0-beta.5]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.4...v0.1.0-beta.5
[0.1.0-beta.4]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.3...v0.1.0-beta.4
[0.1.0-beta.3]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.2...v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/daeuniverse/honk/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/daeuniverse/honk/compare/v0.0.1.beta.84...v0.1.0-beta.1
