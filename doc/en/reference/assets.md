# Assets configuration reference

`assets {}` sets download defaults for geodata, the external Clash dashboard, and subscriptions, and the geodata update schedule and checksum verification.

```dae
assets {
    route: routing
    geodata {
        geosite: 'https://example.org/geosite.dat'
        geoip: 'https://example.org/geoip.dat'
        route: direct
        auto_update: true
        cron: '0 3 * * *'
        checksum: true
    }
    ui {
        url: 'https://example.org/dashboard.zip'
    }
    subscription {
        ua: 'clash.meta'
        interval: 86400s
        cache: true
    }
}
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `route` | `routing` | Default route for the downloads the file configures; when the file sets no route, a geodata route stored through the API stays in effect. `routing` follows the routing rules, `direct` connects directly, and a group name forces that group; an unknown group fails validation. |
| `geodata.geosite` | Built-in URLs (with a state db) | HTTP(S) source for the loaded geosite asset, at most 4096 bytes. Without a state db, updates require a configured URL. |
| `geodata.geoip` | Built-in URLs (with a state db) | HTTP(S) source for the loaded geoip asset, with the same limits. |
| `geodata.route` | `assets.route` | Route for geodata downloads, including checksum requests. |
| `geodata.auto_update` | `true` | Automatic geodata updates. |
| `geodata.cron` | `0 3 * * *` | When automatic updates run: a five-field cron expression (minute, hour, day of month, month, day of week) in the system's local time zone, plus a random delay of up to an hour. Nonexistent local times are skipped; repeated times fire only at their first occurrence. Fields take numbers, `*`, lists `a,b`, ranges `a-b` and steps `*/n` or `a-b/n`; day of week 0 and 7 are Sunday, and when neither day field starts with `*` a day matching either fires. Parsing is zone-independent: names, macros such as `@daily`, a seconds field, more than four fires a day, and expressions matching no calendar date are refused. |
| `geodata.checksum` | `true` | Verify each downloaded file against the `.sha256sum` published beside it; `false` accepts files unverified. |
| `ui.url` | Built-in zashboard URL | External dashboard ZIP source; `HONK_UI_DOWNLOAD_URL` overrides it. A missing or empty configured external-UI directory triggers the download. |
| `ui.route` | `assets.route` | Route for the external UI ZIP download; also accepts a node tag. |
| `subscription.ua` | `honk/<version>` | Default request User-Agent for subscription entries. |
| `subscription.interval` | `86400s` | Default periodic refresh interval; `0` disables scheduled refresh. |
| `subscription.cache` | `true` | Default per-entry body caching, subject to `global.store_subscribe`. |

With a state db, configured geodata URLs, route, schedule and checksum switch are written into the stored settings at startup; API changes override them until the next startup. `auto_update` and `cron` form one schedule: naming only one takes the default for the other. Removing both restores the default schedule if an earlier file wrote it; removing `checksum` likewise restores its default if file-owned. API-owned settings are kept when the file names no replacement.

Geodata owner startup also rejects an explicit cron with no future occurrence in the actual local zone, even with `auto_update: false`. A retained schedule is checked when enabled; a valid file override can repair an old stored plan. Unavailable plans are not replaced with defaults. See the [API reference](./api.md#geodata-sources-and-automatic-updates) for disabling or repairing a retained plan and handling later zone changes.

On Linux, honk's locked chrono 0.4.45 uses `TZ` when set: an empty value selects UTC, POSIX strings such as `CST-8` need no tzdata, and IANA names require a readable zoneinfo file. When `TZ` is unset, it reads `/etc/localtime`. If that primary load fails, it tries a system zone name discovered by `iana-time-zone` and its zoneinfo file, then falls back to UTC. OpenWrt's `/etc/TZ` must be passed as `TZ` when no usable zoneinfo file is available; the repository's `docker-compose.yml` mounts the host's `/etc/localtime`. Log timestamps use the same zone.

A `geodata.auto_update`, `geodata.cron` or `geodata.checksum` value that does not parse produces a warning and is ignored, as if the key were absent. An entry's options override `assets.subscription` and `assets.route`; `geodata.route` and `ui.route` override `assets.route`. Built-in defaults apply only where neither of them sets a value. See the [subscription reference](./subscription.md) for entry syntax and the [API reference](./api.md#geodata-sources-and-automatic-updates) for stored geodata settings.

The parser accepts the following `experimental` fields as aliases. Each occurrence emits a `legacy-assets-key` warning at that line. A nonempty legacy value together with the matching `assets` setting fails with `conflicting-assets-setting`; an empty legacy value does not conflict. A legacy route setting without a corresponding `assets` sub-block route can still override `assets.route`.

| Legacy setting | Replacement |
| --- | --- |
| `experimental.native_api.geosite_download_url` | `assets.geodata.geosite` |
| `experimental.native_api.geoip_download_url` | `assets.geodata.geoip` |
| `experimental.native_api.geodata_download_detour` | `assets.geodata.route` |
| `experimental.clash_api.external_ui_download_url` | `assets.ui.url` |
| `experimental.clash_api.external_ui_download_detour` | `assets.ui.route` |

Only `.dae` configs resolve `assets`. JSON, YAML and TOML configs store the resolved download fields; there `assets` records the defaults but is not applied again, so set the `experimental` download fields and each subscription's own fields directly in those formats. `assets.geodata.auto_update`, `cron` and `checksum` have no `experimental` field and are read from `assets` in every format.
