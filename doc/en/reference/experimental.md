# Experimental Configuration Reference

`experimental { ... }` contains the current nested sections.

## Section overview

| Nested section | Purpose |
| --- | --- |
| `clash_api` | Clash-compatible HTTP API and external dashboard |
| `cache_file` | Persistence of runtime choices, mode, delay samples, and optional DNS state in the state db |
| `native_api` | Independent, opt-in observations, bounded diagnostics, runtime/source control and local UI directory |

`udp_nfqueue { enabled: ... }` is a deprecated compatibility section. Dae and structured loaders accept it, print a migration warning, and copy its value to `global.nfqueue_enable`; new configurations should use the global field directly.

## `native_api`

Requires the opt-in `native-api` Cargo feature (build with `--features native-api` or `native-ui`; release builds include it). It does not require `clash-api`, and the listener is disabled by default. Enabling it without that feature fails startup. All effective fields require restart: SIGHUP rejects changes and preserves the active listener and configuration generation. Unknown fields, nested scalar blocks, malformed booleans, and empty security-list members are errors.

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Start the independent native listener. |
| `listen` | `"127.0.0.1:9527"` | Numeric IP plus port 1–65535; no hostname or `:port` shorthand. |
| `secret` | `""` | Static bearer credential, independent of the Clash credential. A nonempty value selects token mode and cannot be combined with `password_auth`. Listener secrets are masked by value in API responses; a value shorter than 8 bytes is not masked and is reported at startup. |
| `password_auth` | `false` | Select administrator password login when `secret` is empty. Cannot be combined with `allow_anonymous_loopback`. |
| `allow_anonymous_loopback` | `false` | Permit credential-free requests only when `secret` is empty, `password_auth` is false and the actual listening IP is loopback. |
| `allow_origins` | empty list | Additional explicit HTTP(S) origins, without paths, credentials, query, fragment, `null`, or wildcards. |
| `allowed_hosts` | empty list | Additional explicit HTTP Host authorities, without URL schemes, paths, credentials, or wildcards. Omitted port means 80, not the listener's port. |
| `ui` | `""` | Empty disables hosting; otherwise a trusted local directory with readable `index.html`, or `embedded` with the default-off `native-ui` feature. No startup download, extraction or frontend build. |
| `record_flows` | `true` | Permit bounded userspace flow recording under flow diagnostic demand or an explicit runtime pin. `false` prohibits recording, including runtime pins; configuration changes require restart. |
| `record_traffic` | `true` | Keep up to 600 traffic samples for 600 seconds, even without clients. `false` disables history and releases its buffer on restart; current counters remain available. |
| `record_memory` | `true` | Keep up to 600 memory samples for 600 seconds, even without clients. `false` disables history and releases its buffer on restart; current readings remain available. |
| `record_logs` | `true` | Permit up to 512 structured logs for 60 seconds under an admitted `/logs` SSE demand or an explicit runtime pin. `false` prohibits capture; configuration changes require restart. Console/Clash logging remains independent. |
| `record_dns_log` | `true` | Permit completed client DNS history under successful `/dns/log` GET demand or an explicit runtime pin, bounded to 512 records and 8 MiB. `false` prohibits history; configuration changes require restart. |
| `config_write` | `false` | Allow whole-source replacement and reload for the accepted main file and all accepted includes, and creation of new include-loaded `.dae` files, excluding listener-credential-bearing sources. Requires a nonempty `secret` or `password_auth`. |

Auto flow, log and DNS-log demand each have an independent 60-second grace. Ordinary events attach only for event capture; successful flow reads or explicit flow-event filters demand flows, `/logs` SSE demands logs, and successful `/dns/log` GET demands DNS logs. Other API requests, validation, failed GETs and HEAD do not request diagnostic capture. Runtime On/Off, configuration prohibitions and activation reset behavior remain as described in the [API reference](./api.md#recorded-userspace-flows).

Geodata download URLs and routes now belong to [`assets.geodata`](./assets.md). Their former `native_api` keys remain accepted with warnings; see the replacement table in the assets reference.

```dae
experimental {
    native_api {
        enabled: true
        listen: '127.0.0.1:9527'
        secret: 'operator-supplied-random-token'
        allow_anonymous_loopback: false
        ui: '/usr/share/doona'
    }
}
```

Nonempty native secrets must be visible ASCII without whitespace or commas, matching the HTTP bearer parser; unsupported bytes fail shared configuration admission rather than creating an unusable listener.

Authentication mode is restart-required. A nonempty `secret` selects the existing static-token mode. An empty `secret` with `password_auth: true` selects password mode. An empty `secret` with explicit anonymous loopback and an actual loopback bind selects the existing development mode. An enabled listener with none of these fails validation. Password mode requires an empty `secret` and is rejected with `allow_anonymous_loopback`; `config_write: true` likewise requires token or password mode.

Replace the example secret. For local credential-free development, omit `secret` and explicitly set `allow_anonymous_loopback: true`; never publish that anonymous listener through a reverse proxy. Plain HTTP with a token on a non-loopback network is not a secure deployment. Terminate TLS at a trusted proxy.

Default Host acceptance is the concrete listening authority; loopback also accepts `localhost`, `127.0.0.1`, and `[::1]` at that port. A wildcard bind accepts any IP-literal Host, and `localhost`, at the listening port, since those name the listener itself on whichever interface the request arrived; DNS names are still not authorized, because only a name can be rebound. Only directly corresponding plain-HTTP origins are automatically allowed; on a wildcard bind that origin must name the request's own Host, so a page served from another address at the same port needs `allow_origins`. A TLS proxy preserving `Host: panel.example` needs `allowed_hosts: 'panel.example'` and `allow_origins: 'https://panel.example'`; if it preserves `Host: panel.example:443`, add `allowed_hosts: 'panel.example', 'panel.example:443'`. Forwarded headers do not grant authorization.

Lists use individually quoted comma-separated entries, such as `allow_origins: 'http://localhost:3000', 'https://panel.example'`. Omit a list to leave it empty; JSON brackets and a single aggregate-quoted list are not accepted.

Relative UI paths follow the existing dependency search: an existing path under `global.data_dir`, then `/var/share/honk`, then the working directory; a missing dependency resolves under `global.data_dir` and startup fails. The administrator owns the directory and any symlink targets. See the [native API contract](./api.md#native-api).

For a single binary, use a release build or `HONK_DOONA_DIR=$(ci/fetch-doona.sh) cargo build -p honk-core --features native-ui`, and set `ui: embedded`; `native-ui` includes `native-api` without requiring Clash. Without `native-ui`, enabled embedded hosting fails startup. The assets receive no injected credentials; clients use public discovery to select static-token entry or password setup/login. Asset/source identities, corresponding-source distribution and the management contract are documented in the [API reference](./api.md#embedded-doona-provenance).

File-configured geodata sources are administrator-controlled, restart-required and cannot be changed through source writes. With a state db, downloads can also use authenticated URL overrides or built-in sources. Userinfo, fragments, redirects and content encoding are rejected. Direct hostname sources require `global.bootstrap_resolver`; no system-DNS fallback is used. `assets.geodata.route` or the stored route can send downloads through the routing rules or a group instead, and a route that cannot carry a request never falls back to direct. Updates use the applicable configured, stored or built-in sources. The [management contract](./api.md#managed-entries-and-geodata) distinguishes network limits, verified-byte activation and partial durable replacement from rollback.

Traffic and memory histories share the existing one-second sampler; missing samples/measurements remain gaps/nulls rather than zero-filled or interpolated points. Memory is actual process RSS and available cgroup-v2 data, not kernel accounting. File settings remain restart-required. `PATCH /api/v1/runtime/settings` can transiently adjust the supported log/DNS-log/flow limits and native log level, but cannot enable a disabled recorder. Accepted explicit activation, including no-op, restores configured values; provider/network refresh preserves overrides.

Configuration metadata, validation and reload operations require a genuine `.dae` source snapshot captured at startup; programmatic configs and compatibility serde loaders do not supply one. Configuration reads expose accepted content, masking only declared listener-secret values, including duplicate/overridden values and their other occurrences. Admitted anonymous loopback requests read the same data as bearer-authenticated requests. Credential-bearing sources stay read-only and retain original-byte hashes. Source `path` stays entry-directory-relative; `absolute_path` exposes the canonical absolute path. Move credentials to a dedicated read-only include locally if the main source must be editable. The API cannot change/move API credentials or alter native settings; those require a local edit and restart.

With `config_write: true`, all accepted noncredential includes are writable; ordinary `include` glob and no-match semantics remain unchanged. Save by opaque source ID with RFC 9110 `If-Match` over disk-content SHA-256 (strong tags, lists/multiple field lines or `*`; weak tags never match), then follow the real reload operation. A successful write is not activation success, and externally uncoordinated editors can still race the final check/rename window. Restricted Group PATCH uses the same source transaction but requires the accepted group/config ETag, checked before writing and again before activation; that revision is not the disk hash. See [source safety and failure semantics](./api.md#accepted-configuration-and-reload-operations).

Probe targets come only from accepted configuration. Resolution, IPv4-mapped IPv6 normalization and selected-IP pinning still apply; callers cannot supply URLs and probes do not follow redirects. Probes, geodata and shared downloads use configured targets without an address or port allowlist. Whoever can write the configuration or control subscription content decides those targets; provider content is trusted configuration.

The removed `probe_allowed_cidrs` and `probe_allowed_ports` keys are accepted in dae configuration and compatibility structured loaders with one warning per key; their values are ignored and the keys can be deleted. Neither key is serialized.

## `clash_api`

| Field | Default | Meaning |
| --- | --- | --- |
| `external_controller` | `""` | HTTP listen address. An empty value disables the API server. |
| `external_ui` | `""` | External dashboard directory. An empty value disables dashboard serving and download. |
| `secret` | `""` | API authentication secret. An empty value disables authentication. A value shorter than 8 bytes is not masked in native API responses. |
| `default_mode` | `"Rule"` | Startup mode when native API is disabled: `Rule`, `Global`, or `Direct`; with `cache_file.enabled: true`, a valid cached mode takes precedence. Native-enabled startup uses shared transient rule mode instead. |

Dashboard download URL and route belong to [`assets.ui`](./assets.md).

All `clash_api` fields are startup-owned. SIGHUP rejects a candidate configuration that changes any of them.

`--store db` does not run the Clash API. A non-empty `external_controller` refuses startup in that mode; see [Configuration db](./api.md#configuration-db---store-db).

### Authentication and transport

With a non-empty `secret`, API requests use `Authorization: Bearer <secret>`; WebSocket upgrades may instead pass `?token=<secret>`. Static `/ui` content is outside this authentication middleware. The built-in listener serves plain HTTP and provides no TLS. Bind it to a loopback address such as `127.0.0.1`, or put an authenticated TLS reverse proxy in front of it; do not expose it directly on an untrusted network. See the [Clash API reference](./api.md) for the endpoint inventory.

An explicitly enabled non-loopback bind with an empty secret emits `unsafe-api-bind` at `experimental.clash_api.external_controller`, including structured input. The diagnostic contains neither the endpoint nor the secret. Loopback sample configurations do not warn; this warning does not change bind, authentication, or CORS policy.

### External UI

An absolute `external_ui` path is used literally. A relative path selects an existing directory below `global.data_dir` first, then an existing directory below `/var/share/honk`, then an existing working-directory-relative directory; if none exists, honk creates the target below `global.data_dir`. A missing or empty target triggers a background dashboard ZIP download. A non-empty `assets.ui.url` replaces the built-in zashboard URL; `HONK_UI_DOWNLOAD_URL` has highest precedence over both.

`assets.ui.route` takes precedence over `assets.route` for the initial request and every redirect. `direct` downloads directly, `block` aborts when selected by routing rules, and a group resolves its authoritative leaf for each exchange. With no configured route, each URL follows the normal traffic routing decision. An unavailable tag, download failure, or extraction failure is logged without stopping the engine. The archive is written to an unnamed private file in the target's parent directory rather than memory; the archive is removed after extraction or a failed download. Extraction is refused past 10,000 entries or 128 MiB of content, the same bound as the archive itself. The partly written directory is emptied, so the next start downloads again.

### Startup mode

With native disabled, `default_mode` accepts `Rule`, `Global`, and `Direct`; with `cache_file.enabled: true`, a valid cached Clash mode takes precedence, and invalid values fall back to `Rule`. With native enabled, both APIs use one transient mode owner: no mode restore/persistence, rule at startup and on accepted explicit activation (including no-op) when the backend reset succeeds, and preservation across provider/network refresh. A reset failure after commit retains the previous mode, closes admission and returns `CommittedDegraded`. Native global mode targets a stable node/group identity and fails closed if refresh removes it. See [runtime mode](./api.md#connection-closing-mode-and-datapath-lifecycle).

## `cache_file`

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | unset | Persist runtime state in the state db, `<data_dir>/state/honk.db`. Unset keeps Selector choices and delay samples; `true` also keeps the Clash mode and GLOBAL selection and allows `store_dns`; `false` keeps nothing. |
| `store_dns` | `false` | With `enabled: true`, also persist and restore DNS cache answers. |

Both fields are startup-owned; SIGHUP rejects a candidate configuration that changes either.

Upgrade note: omitting `cache_file.enabled` now keeps Selector choices and delay samples by default; opt in with `true` for mode/GLOBAL and, separately, `store_dns: true` for DNS answers. Explicit `false` disables these runtime-cache stores, not unrelated configuration, credential or subscription storage.

`path`, `cache_id` and `store_fakeip` are no longer settings. They still parse, emit a `legacy-cache-file` warning and have no effect, and SIGHUP accepts edits to them. `path` and `cache_id` are read once, to import a legacy `cache.db` (below).

### Persisted state

Unless `enabled` is `false`, honk keeps per-network Selector choices and each node's last real delay sample in the state db, like mihomo's `store-selected`. Only `enabled: true` also restores and persists the Clash mode and the Clash GLOBAL selection, and only with native API disabled; with native disabled and no restored mode, a restart starts in `default_mode`, while native enabled always starts in `Rule`. Delay samples are written as one batch every minute; restoration discards zero samples and samples older than 24 hours. Liveness is not restored.

If the state db is corrupt and neither `--store db` nor `native_api.password_auth` is set, honk moves `honk.db` and `honk.db-wal` aside as `honk.db.corrupt` and `honk.db.corrupt-wal` once it holds the instance lock, and starts a new file. If `honk.db.corrupt` already exists, it keeps both files and runs without persistence until one is removed. In the same case a state db that is unavailable, unsafe (not a private file owned by the honk user) or locked by `honk-core admin reset` also leaves honk running without persistence, with a warning. For an unsafe path the `persistence_unavailable` degradation adds `rule` (`not_owner`, `group_or_other_bits`, `not_directory`, `not_file`, `symlink` or `identity_changed`) beside `reason`; the log names the path and how to fix it. A db from a newer honk or another program refuses startup in every mode, because moving it aside would destroy data only that program can read.

### Limits

A maintenance tick runs every 60 seconds. A Selector choice is kept only for a Selector group in the configuration, and a delay sample only for a configured node; a row whose group or node is missing at two consecutive ticks is deleted, so a reload that briefly drops one keeps its row. Delay samples older than 24 hours and expired DNS rows are deleted at each tick, and each tick returns up to 1 MiB of freed pages to the filesystem. At most 4,096 DNS rows are kept; after each batch the earliest expiry is evicted first.

At startup, if honk opens the state db (because `--store db`, `password_auth`, `store_subscribe` or `cache_file` needs it), `enabled: false` empties the Selector, delay, Clash-state and DNS tables; an unset `enabled` empties the Clash-state and DNS tables; `store_dns: false` empties the DNS table; and an enabled native API or a disabled Clash API empties the Clash-state table. Startup without a state db leaves the file unchanged.

The state db file is capped at 112 MiB. Cache writes keep 24 MiB of it free for configuration revisions and subscription bodies: when a batch would leave more than 88 MiB in use, the writer first deletes DNS rows down to 2,048, and rolls the batch back if that is not enough; skipped DNS entries are counted as `budget_skipped`, not as written. The legacy `cache.db` import obeys the same budget: a copy that would pass it is not committed, and the next start tries again.

### DNS persistence

With `store_dns: true`, each answer is one `dns_answer` row holding an `HDNS` version-2 payload, keyed by the digest of its exact cache key. A row is restored only while unexpired and only when its key digest, canonical query wire, response wire identity and active DNS policy match. The exact key also preserves the ingress profile, request scope and operation, preventing reuse across different DNS contexts. An entry that encodes to more than 4 KiB is not persisted and is counted as `oversize`.

### Upgrading from `cache.db`

The first start with `enabled` imports the legacy `cache.db` that `path` names, resolved as before: an absolute path is literal; a relative one prefers an existing file below `global.data_dir`, then below `/var/share/honk`, then relative to the original config directory. Only keys under this instance's `cache_id` prefix are read. Per-network Selector choices of Selector groups in the configuration, Clash mode, the Clash GLOBAL selection and delay samples newer than 24 hours of configured nodes are copied; rows already in the state db win. Name-only Selector choices from older releases, DNS answers and FakeIP rows are not imported, so persisted DNS answers are refetched. The import is recorded in the state db, one row per imported path, and never repeated, even if an older binary recreates the file. A `cache.db` that is a symlink, is not a regular file owned by the honk user, is writable by other users, or cannot be read as a `cache.db` is left in place with a warning, and the next start tries again.
In db mode this final fallback uses the active revision's original entry directory, even when the current `-c` points elsewhere and is ignored for startup.

With an empty `cache_id`, honk then deletes `cache.db`, its `-wal` and `-shm`; any `cache.db.corrupt-*` copies stay. With a non-empty `cache_id`, another instance may share the file, so it stays and honk logs a warning once. An older binary started afterwards finds no `cache.db` and starts with empty runtime state.

## Example

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'zashboard'
        secret: 'replace-me'
        default_mode: Rule
    }
    cache_file {
        enabled: true
        store_dns: true
    }
}
```

```dae
assets {
    ui {
        url: 'https://example.com/dashboard.zip'
        route: proxy
    }
}
```

## Related docs

- [Clash API reference](./api.md)
- [NFQUEUE design](../design/nfqueue.md)
- [Global configuration reference](./global.md)
