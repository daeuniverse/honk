# Experimental Configuration Reference

`experimental { ... }` configures the APIs and persistent runtime state.
The section shares its name with the Clash/mihomo `experimental` section but not its keys: honk uses it for its API listeners and persistence.

## Section overview

| Nested section | Purpose |
| --- | --- |
| `clash_api` | Clash-compatible HTTP API and external dashboard |
| `cache_file` | Persistence of runtime choices, mode, delay samples, and optional DNS state in the state db |
| `native_api` | Independent opt-in observation, bounded diagnostics, runtime and source control, and the local UI directory |

`udp_nfqueue { enabled: ... }` is a deprecated compatibility section. New configurations set the global field directly. Dae and structured loaders still accept the section and print a migration warning. They use its value for `global.nfqueue_enable` only when the global key is absent. `enabled` defaults to `false`, so an empty `udp_nfqueue {}` disables NFQUEUE. Delete the section to keep the global setting, which defaults to on. In this example the global key takes precedence, so NFQUEUE stays off:

```dae
global {
    nfqueue_enable: false
}
experimental {
    udp_nfqueue {
        enabled: true
    }
}
```

## `native_api`

The `native_api` section requires the opt-in `native-api` Cargo feature. Build with `--features native-api` or `native-ui`, or use a full or `-native-api` release. It does not require `clash-api`. The listener is off by default, and enabling it in a build without the feature fails startup.

Every effective field is startup-owned. Changing one requires a restart, and SIGHUP rejects the change while the active listener and configuration generation stay in place. Unknown fields, nested scalar blocks, malformed booleans and empty security-list members are errors.

Boolean fields take `true` or `false`. The loader also accepts `yes`/`no`, `1`/`0` and `on`/`off` in any case. Any other spelling, such as `t`, produces an `invalid-config-value` error.

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Start the independent native listener. |
| `listen` | `"127.0.0.1:9527"` | Numeric IP plus port 1–65535; no hostname or `:port` shorthand. |
| `secret` | `""` | Static bearer credential, independent of the Clash credential. A nonempty value selects token mode. It cannot be combined with `password_auth`. Listener secrets are masked by value in API responses; a value shorter than 8 bytes is not masked and is reported at startup. |
| `password_auth` | `false` | Select administrator password login when `secret` is empty. Cannot be combined with `allow_anonymous_loopback`. |
| `allow_anonymous_loopback` | `false` | Permit credential-free requests only when `secret` is empty, `password_auth` is false and the actual listening IP is loopback. |
| `allow_origins` | empty list | Additional explicit HTTP(S) origins, without paths, credentials, query, fragment, `null`, or wildcards. Omitted port means 80 for `http` and 443 for `https`. |
| `allowed_hosts` | empty list | Additional explicit HTTP Host authorities, without URL schemes, paths, credentials, or wildcards. Omitted port means 80, not the listener's port. |
| `ui` | `""` | Empty disables hosting. Otherwise, a trusted local directory with a readable `index.html`, or `embedded` / `embedded-lite` with the default-off `native-ui` feature. `embedded-lite` is the lighter doona lite edition (preview). honk performs no download, extraction or frontend build at startup. |
| `record_flows` | `true` | Permit bounded userspace flow recording under flow diagnostic demand or an explicit runtime pin. `false` prohibits recording, including runtime pins. Configuration changes require a restart. |
| `record_traffic` | `true` | Keep up to 600 traffic samples for 600 seconds, even without clients. `false` disables history and releases its buffer on restart. Current counters remain available. |
| `record_memory` | `true` | Keep up to 600 memory samples for 600 seconds, even without clients. `false` disables history and releases its buffer on restart. Current readings remain available. |
| `record_logs` | `true` | Permit up to 512 structured logs for 60 seconds under an admitted `/logs` SSE demand or an explicit runtime pin. `false` prohibits capture. Configuration changes require a restart. Console/Clash logging remains independent. |
| `record_dns_log` | `true` | Permit completed client DNS history under successful `/dns/log` GET demand or an explicit runtime pin, bounded to 512 records and 8 MiB. `false` prohibits history. Configuration changes require a restart. |
| `config_write` | `false` | Allow whole-source replacement and reload of the accepted main file and of every accepted include. Also allows creating new `.dae` files that an include loads. Listener-credential-bearing sources are excluded. Requires a nonempty `secret` or `password_auth`. |

Automatic flow, log and DNS-log capture each have their own 60-second grace. Ordinary events enable event capture only. A successful flow read or an explicit flow-event filter enables flow capture. `/logs` SSE enables log capture, and a successful `/dns/log` GET enables DNS-log capture. Other API requests, validation, failed GETs and HEAD never enable diagnostic capture. Runtime On/Off, configuration prohibitions and activation reset behavior are described in the [API reference](./api.md#recorded-userspace-flows).

Geodata download URLs and routes belong to [`assets.geodata`](./assets.md). The former `native_api` keys are still accepted, with a warning for each. The assets reference lists the replacement for each one.

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

Nonempty native secrets must be visible ASCII without whitespace or commas, matching the HTTP bearer parser. Unsupported bytes fail shared configuration admission instead of creating an unusable listener.

Use an unpredictable token of at least 16 bytes. In token mode, an enabled non-loopback listener with a secret shorter than 16 bytes emits one WARN at startup activation and at each accepted configuration reactivation. A wildcard bind counts as non-loopback. The WARN records only the structured `listen` and `secret_length` fields, never the secret, and does not reject the configuration. Loopback-only listeners and password mode do not emit this advisory. This warning is separate from the masking warning for values shorter than 8 bytes above.

Choose one authentication mode; changing it requires a restart:

- Static token: set a nonempty `secret`.
- Password login: leave `secret` empty and set `password_auth: true`. Do not combine this with `allow_anonymous_loopback`.
- Local development without credentials: leave `secret` empty, keep `password_auth` false, explicitly enable anonymous loopback and bind to an actual loopback address.

An enabled listener with none of these modes fails validation. `config_write: true` requires token or password mode.

Replace the example secret. For local credential-free development, omit `secret` and explicitly set `allow_anonymous_loopback: true`. Never publish that anonymous listener through a reverse proxy. A token over plain HTTP on a non-loopback network is not a secure deployment. Terminate TLS at a trusted proxy.

Host and Origin checks apply independently of authentication:

- By default, Host must name the concrete listening authority. Loopback also accepts `localhost`, `127.0.0.1` and `[::1]` at that port.
- A wildcard bind accepts any IP-literal Host, and `localhost`, at the listening port. These name the listener itself on whichever interface received the request. DNS names still need authorization, because a name can be rebound.
- Only directly corresponding plain-HTTP origins are automatically allowed. On a wildcard bind, the origin must name the request's own Host. A page served from another address at the same port needs `allow_origins`.
- A TLS proxy preserving `Host: panel.example` needs `allowed_hosts: 'panel.example'` and `allow_origins: 'https://panel.example'`. If it preserves `Host: panel.example:443`, add `allowed_hosts: 'panel.example', 'panel.example:443'`.

Forwarded headers do not grant authorization.

A host in either list is an IPv4 address, a bracketed IPv6 address such as `[::1]:9527`, or an ASCII DNS name. A DNS name uses letters, digits and inner hyphens only: no underscores, empty labels or trailing dot. An explicit port is 1 to 65535.

Lists are comma-separated, such as `allow_origins: 'http://localhost:3000', 'https://panel.example'`. Entries may be quoted individually or left bare. Omit a list to leave it empty. JSON brackets and a single aggregate-quoted list are not accepted.

Relative UI paths follow the existing dependency search: an existing path under `global.data_dir`, then `/var/share/honk`, then the working directory. A missing dependency resolves under `global.data_dir` and fails startup. The administrator owns the directory and any symlink targets. See the [native API contract](./api.md#native-api).

To serve the UI from a single binary, use a full release build. Alternatively, build with `HONK_DOONA_DIR=$(ci/fetch-doona.sh) cargo build -p honk-core --features native-ui`, then set `ui: embedded` or `ui: embedded-lite`. The `native-ui` feature includes `native-api` without requiring Clash. Enabled embedded hosting fails startup in a build without it. The assets receive no injected credentials; clients use public discovery to select static-token entry or password setup/login. The [API reference](./api.md#embedded-doona-provenance) documents asset and source identities, corresponding-source distribution, and the management contract.

An administrator controls file-configured geodata sources, and changing them requires a restart. Source writes cannot change them. With a state db, downloads can also use authenticated URL overrides or built-in sources. Userinfo, fragments, redirects and content encoding are rejected. Direct hostname sources require `global.bootstrap_resolver`; honk does not fall back to system DNS. `assets.geodata.route` or the stored route can send downloads through the routing rules or a group instead. A route that cannot carry a request never falls back to direct. Updates use the applicable configured, stored or built-in sources. The [management contract](./api.md#managed-entries-and-geodata) distinguishes network limits, verified-byte activation and partial durable replacement from rollback.

Traffic and memory histories share the one-second sampler. A missing sample stays a gap or a null; honk neither zero-fills nor interpolates it. A memory reading is the process RSS and available cgroup-v2 data, not kernel accounting. Settings in the configuration file still require a restart. `PATCH /api/v1/runtime/settings` can transiently adjust the supported log/DNS-log/flow limits and native log level, but cannot enable a disabled recorder. An accepted explicit activation, including a no-op, restores the configured values. A provider or network refresh preserves the overrides.

Configuration metadata, validation and reload operations require a genuine `.dae` source snapshot captured at startup. Programmatic configs and compatibility serde loaders do not supply one.

- Reads return the accepted content and mask only declared listener-secret values. This covers duplicate and overridden declarations, and every other occurrence of the same value. Admitted anonymous loopback requests read the same data as bearer-authenticated requests.
- Credential-bearing sources stay read-only and retain original-byte hashes.
- Source `path` stays entry-directory-relative; `absolute_path` exposes the canonical absolute path.
- To make the main source editable, move credentials to a dedicated read-only include locally, then restart. The API cannot change or move API credentials, or alter native settings. Both require a local edit and restart.

With `config_write: true`, every accepted noncredential include is writable. Ordinary `include` glob and no-match semantics remain unchanged. To save a source, send its opaque source ID with an RFC 9110 `If-Match` header over the disk-content SHA-256, then run the real reload operation. The header accepts strong tags, a list or multiple field lines, or `*`. Weak tags never match. A successful write does not mean activation succeeded. An editor that does not coordinate externally can still race the final check and rename. Restricted Group PATCH uses the same source transaction, but it requires the accepted group or config ETag, checked before writing and again before activation. That revision is not the disk hash. See [source safety and failure semantics](./api.md#accepted-configuration-and-reload-operations).

Probe targets come only from accepted configuration. Resolution, IPv4-mapped IPv6 normalization and selected-IP pinning still apply. Callers cannot supply URLs, and probes do not follow redirects. Probes, geodata and shared downloads use configured targets without an address or port allowlist. Whoever can write the configuration or control subscription content decides those targets. Provider content is trusted configuration.

The removed `probe_allowed_cidrs` and `probe_allowed_ports` keys are still accepted in dae configuration and in compatibility structured loaders, with one warning per key. Their values are ignored, and the keys can be deleted. Neither key is serialized.

## `clash_api`

The `clash_api` section requires the default-on `clash-api` Cargo feature. A build without it ignores `external_controller`.

| Field | Default | Meaning |
| --- | --- | --- |
| `external_controller` | `""` | Listen address as IP and port, such as `127.0.0.1:9090` or `[::1]:9090`. `:9090` means `0.0.0.0:9090`. Hostnames are not accepted. An empty value disables the API server. An invalid address logs a warning and the engine starts without the listener. |
| `external_ui` | `""` | External dashboard directory. An empty value disables dashboard serving and download. |
| `secret` | `""` | API authentication secret. An empty value disables authentication. A value shorter than 8 bytes is not masked in native API responses. |
| `default_mode` | `"Rule"` | Startup mode when the native API is disabled: `Rule`, `Global` or `Direct`. With `cache_file.enabled: true`, a valid cached mode takes precedence. With the native API enabled, startup uses the shared transient mode instead, which starts in `Rule`. |

Dashboard download URL and route belong to [`assets.ui`](./assets.md).

All `clash_api` fields are startup-owned. SIGHUP rejects a candidate configuration that changes any of them.

`--store db` does not run the Clash API. A non-empty `external_controller` refuses startup in that mode; see [Configuration db](./api.md#configuration-db---store-db).

### Authentication and transport

With a non-empty `secret`, API requests use `Authorization: Bearer <secret>`. WebSocket upgrades may instead pass `?token=<secret>`. Static `/ui` content is outside this authentication middleware. The built-in listener serves plain HTTP and provides no TLS. Bind it to a loopback address such as `127.0.0.1`, or put an authenticated TLS reverse proxy in front of it. Do not expose it directly on an untrusted network. See the [Clash API reference](./api.md) for the endpoint inventory.

A non-loopback bind that is explicitly enabled with an empty secret emits `unsafe-api-bind` at `experimental.clash_api.external_controller`. Structured input is no exception. The diagnostic contains neither the endpoint nor the secret. Sample configurations that bind loopback do not warn. This warning does not change bind, authentication or CORS policy.

### External UI

An absolute `external_ui` path is used literally. A relative path selects the first existing path, file or directory, below `global.data_dir`. If nothing exists there, it tries `/var/share/honk`, then the working directory. If the first match is a file, honk uses it instead of skipping to a directory. If none exists, honk creates the target below `global.data_dir`. A missing or empty target triggers a background dashboard ZIP download. A non-empty `assets.ui.url` replaces the built-in zashboard URL. `HONK_UI_DOWNLOAD_URL` has highest precedence over both.

`assets.ui.route` takes precedence over `assets.route` for the initial request and every redirect. `direct` downloads directly. `block` aborts when routing rules select it. A group resolves its authoritative leaf for each exchange. With no configured route, each URL follows the normal traffic routing decision. An unavailable tag, download failure, or extraction failure is logged without stopping the engine. The archive is written to an unnamed private file in the target directory, not to memory. honk removes it after extraction or a failed download. Extraction is refused past 10,000 entries or 128 MiB of content, the same bound as the archive itself. The partly written directory is emptied, so the next start downloads again.

A download follows at most five redirects. Each HTTP exchange has a 30-second timeout. Through a proxy, the timeout starts after the tunnel is dialed. When every ZIP entry sits under one top-level directory, that directory is stripped, so `dist/index.html` becomes `index.html`. Entries whose path has an empty, `.` or `..` component or a backslash are skipped.

### Startup mode

With the native API disabled, `default_mode` accepts `Rule`, `Global`, and `Direct` in any case. With `cache_file.enabled: true`, a valid cached Clash mode takes precedence, and invalid values fall back to `Rule`. With the native API enabled, both APIs share one transient mode owner. It does not restore or persist a mode. It starts at `Rule`, and returns to `Rule` on every accepted explicit activation, a no-op included, when the backend reset succeeds. It keeps its mode across a provider or network refresh. A reset failure after commit retains the previous mode, closes admission and returns `CommittedDegraded`. Native global mode targets a stable node/group identity and fails closed if a refresh removes it. See [runtime mode](./api.md#connection-closing-mode-and-datapath-lifecycle).

## `cache_file`

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | unset | Persist runtime state in the state db, `<data_dir>/state/honk.db`. Unset keeps Selector choices and delay samples; `true` also keeps the Clash mode and GLOBAL selection and allows `store_dns`; `false` keeps no runtime state. |
| `store_dns` | `false` | With `enabled: true`, also persist and restore DNS cache answers. |

Both fields are startup-owned. SIGHUP rejects a candidate configuration that changes either.

Upgrade note: an omitted `cache_file.enabled` keeps Selector choices and delay samples. Set it to `true` to keep the Clash mode and GLOBAL selection as well. Set `store_dns: true` separately to keep DNS answers. Explicit `false` disables these runtime-cache stores. It does not affect configuration, credential or subscription storage.

`path`, `cache_id` and `store_fakeip` are no longer settings. They still parse, emit a `legacy-cache-file` warning and have no effect, and SIGHUP accepts edits to them. `path` and `cache_id` are read once, to import a legacy `cache.db` (below).

An omitted or empty `path` means `cache.db`, and an omitted `cache_id` means `""`, which leaves keys without a prefix.

### Persisted state

Unless `enabled` is `false`, honk keeps per-network Selector choices and each node's last real delay sample in the state db, like mihomo's `store-selected`. Only `enabled: true` also restores and persists the Clash mode and the Clash GLOBAL selection, and only with the native API disabled. With the native API disabled and no restored mode, a restart starts in `default_mode`. With the native API enabled, it always starts in `Rule`. Delay samples are written as one batch every minute. Restoration discards zero samples and samples older than 24 hours. Liveness is not restored.

When neither `--store db` nor `native_api.password_auth` is set, database failures have these outcomes:

- Corrupt database: after taking the instance lock, honk moves `honk.db` and `honk.db-wal` to `honk.db.corrupt` and `honk.db.corrupt-wal`, then starts a new file.
- Existing `honk.db.corrupt`: honk keeps both files and runs without persistence until one is removed.
- Unavailable, unsafe or reset-locked database: honk warns and runs without persistence. An unsafe database is not a private file owned by the honk user. A reset lock belongs to `honk-core admin reset`.

For an unsafe path, the `persistence_unavailable` degradation adds `rule` in addition to `reason`, with these values: `not_owner`, `group_or_other_bits`, `not_directory`, `not_file`, `symlink` or `identity_changed`. The log names the path and how to fix it.

A database from a newer honk or another program refuses startup in every mode. Moving it aside would destroy data only that program can read.

### Limits

A maintenance tick runs every 60 seconds. honk keeps a Selector choice only for a Selector group in the configuration, and a delay sample only for a configured node. It deletes a row whose group or node is missing at two consecutive ticks, so a reload that briefly drops one keeps its row. Each tick deletes delay samples older than 24 hours and expired DNS rows. Each tick also returns up to 1 MiB of freed pages to the filesystem. At most 4,096 DNS rows are kept. After each batch the earliest expiry is evicted first.

If startup opens the state db because `--store db`, `password_auth`, `store_subscribe` or `cache_file` needs it, these settings clear stored cache state:

| Startup setting | Tables emptied |
| --- | --- |
| `enabled: false` | Selector, delay, Clash-state and DNS |
| `enabled` unset | Clash-state and DNS |
| `store_dns: false` | DNS |
| Native API enabled or Clash API disabled | Clash-state |

Startup without a state db leaves the file unchanged.

The state db file is capped at 112 MiB. Cache writes keep 24 MiB of it free for configuration revisions and subscription bodies. If a batch would leave more than 88 MiB in use, the writer first deletes DNS rows down to 2,048. If that is not enough, it rolls the batch back. Skipped DNS entries are counted as `budget_skipped`, not as written. The legacy `cache.db` import obeys the same budget: a copy that would pass it is not committed, and the next start tries again.

### DNS persistence

With `store_dns: true`, each answer is one `dns_answer` row holding an `HDNS` version-2 payload. The row is keyed by the digest of its exact cache key. honk restores a row only while it is unexpired, and only when its key digest, canonical query wire, response wire identity and active DNS policy match. The exact key also preserves the ingress profile, request scope and operation, so an entry is never reused across different DNS contexts. An entry that encodes to more than 4 KiB is not persisted and is counted as `oversize`.

### Upgrading from `cache.db`

On the first start with a state db and `enabled` not `false`, honk imports the
legacy `cache.db` that `path` names. An absolute path is used as written. A
relative path prefers an existing path below `global.data_dir`, then below
`/var/share/honk`, then relative to the original config directory. Only keys
under this instance's `cache_id` prefix are read. honk copies per-network
Selector choices of Selector groups in the configuration, and delay samples
newer than 24 hours of configured nodes. It copies the Clash mode and the Clash
GLOBAL selection only when `enabled: true`, the native API is disabled and
`external_controller` is set in a `clash-api` build. Rows already in the state
db win. Name-only Selector choices from older releases, DNS answers and FakeIP
rows are not imported, so persisted DNS answers are refetched. The import is
recorded in the state db per file and `cache_id`, and it never repeats, even if
an older binary recreates the file. Another `cache_id` can still import its own
keys from a kept file. honk leaves a `cache.db` in place with a warning when it
is a symlink, is not a regular file owned by the honk user, is writable by other
users, or cannot be read as a `cache.db`. The next start tries again. In db
mode, the relative-path fallback uses the active revision's original entry
directory, even when the current `-c` points elsewhere and is ignored for
startup.

With an empty `cache_id`, honk then deletes `cache.db`, its `-wal` and `-shm`. Any `cache.db.corrupt-*` copies stay. With a non-empty `cache_id`, another instance may share the file, so honk keeps the file and logs one warning. An older binary started afterwards finds no `cache.db` and starts with empty runtime state.

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
