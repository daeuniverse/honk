# Experimental Configuration Reference

This reference describes the two current nested sections under `experimental { ... }`.

## Section overview

| Nested section | Purpose |
| --- | --- |
| `clash_api` | Clash-compatible HTTP API and external dashboard |
| `cache_file` | SQLite persistence for runtime choices, mode, delay samples, and optional DNS state |

`udp_nfqueue { enabled: ... }` is a deprecated compatibility section. Dae and structured loaders accept it, print a migration warning, and copy its value to `global.nfqueue_enable`; new configurations should use the global field directly.

## `clash_api`

| Field | Default | Meaning |
| --- | --- | --- |
| `external_controller` | `""` | HTTP listen address. An empty value disables the API server. |
| `external_ui` | `""` | External dashboard directory. An empty value disables dashboard serving and download. |
| `external_ui_download_url` | `""` | HTTP(S) dashboard ZIP URL. An empty value uses the built-in zashboard URL. |
| `external_ui_download_detour` | `""` | Node or group tag used for the download. An empty value follows normal traffic routing. |
| `secret` | `""` | API authentication secret. An empty value disables authentication. |
| `default_mode` | `"Rule"` | Startup mode: `Rule`, `Global`, or `Direct`. A valid cached mode takes precedence. |

All `clash_api` fields are startup-owned. SIGHUP rejects a candidate configuration that changes any of them.

### Authentication and transport

With a non-empty `secret`, API requests use `Authorization: Bearer <secret>`; WebSocket upgrades may instead pass `?token=<secret>`. Static `/ui` content is outside this authentication middleware. The built-in listener serves plain HTTP and provides no TLS. Bind it to a loopback address such as `127.0.0.1`, or put an authenticated TLS reverse proxy in front of it; do not expose it directly on an untrusted network. See the [Clash API reference](./api.md) for the endpoint inventory.

### External UI

An absolute `external_ui` path is used literally. A relative path selects an existing directory below `global.data_dir` first, then an existing directory below `/var/share/honk`, then an existing working-directory-relative directory; if none exists, honk creates the target below `global.data_dir`. A missing or empty target triggers a background dashboard ZIP download. A non-empty `external_ui_download_url` replaces the built-in zashboard URL; `HONK_UI_DOWNLOAD_URL` has highest precedence over both.

A non-empty `external_ui_download_detour` forces the initial request and every redirect through that node or group. `direct` downloads directly, `block` aborts, and a group resolves its authoritative leaf for each exchange. When the field is empty, each URL follows the normal traffic routing decision as before. An unavailable tag, download failure, or extraction failure is logged without stopping the engine.

### Startup mode

`default_mode` accepts the canonical modes `Rule`, `Global`, and `Direct`. When `cache_file` is enabled and contains a valid cached Clash mode, that value is restored instead. Invalid cached or configured values fall back to `Rule`.

## `cache_file`

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Open the SQLite cache and enable runtime-state persistence. |
| `path` | `"cache.db"` | Database path. An absolute path is literal. For a relative path, an existing file below `global.data_dir` wins, then an existing file below `/var/share/honk`, then an existing path relative to the original config directory; a new file is created below `global.data_dir`. |
| `cache_id` | `""` | Namespace for every database key. A non-empty value prefixes keys with `<cache_id>:`. |
| `store_fakeip` | `false` | FakeIP persistence intent only. The `fakeip:` prefix and flush API exist, but the engine does not populate or restore mappings yet. |
| `store_dns` | `false` | Persist and restore DNS cache answers using the exact-key v2 format. |

The whole `cache_file` section is startup-owned. SIGHUP rejects a candidate configuration that changes any field.

### Always-persisted state

Whenever `enabled` successfully opens the database, honk persists Selector choices, the Clash mode, and each node's last real delay sample independently of `store_fakeip` and `store_dns`. Delay samples are snapshotted every minute; restoration discards malformed, zero, or older-than-24-hour samples. Liveness is not restored.

### DNS persistence

With `store_dns: true`, entries use the `dns:v2:` key namespace and an `HDNS` version-2 binary payload. The v2 namespace is rollback-safe: a pre-v2 binary reads the legacy `dns:` namespace while excluding `dns:v2:` rows, so it leaves v2 data untouched.

A v2 row is restored only while unexpired and only when its key digest, canonical query wire, response wire identity, and active DNS policy match. The exact key also preserves the ingress profile, request scope, and operation, preventing reuse across different DNS contexts.


## Example

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'zashboard'
        external_ui_download_url: 'https://example.com/dashboard.zip'
        external_ui_download_detour: proxy
        secret: 'replace-me'
        default_mode: Rule
    }
    cache_file {
        enabled: true
        path: 'cache.db'
        cache_id: 'gateway-main'
        store_fakeip: false
        store_dns: true
    }
}
```

## Related docs

- [Clash API reference](./api.md)
- [NFQUEUE design](../design/nfqueue.md)
- [Global configuration reference](./global.md)
