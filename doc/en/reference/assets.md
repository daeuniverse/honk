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
| `geodata.route` | `assets.route` | Route for geodata downloads, including checksum requests. With a state db, the URLs and route are written into the stored sources at startup; API changes override them until the next startup. `auto_update`, `cron` and `checksum` are written the same way: naming only one of `auto_update` and `cron` takes the default for the other, and a value an earlier file wrote returns to its default once the file names neither. |
| `geodata.auto_update` | `true` | Automatic geodata updates. |
| `geodata.cron` | `0 3 * * *` | When automatic updates run: a five-field cron expression (minute, hour, day of month, month, day of week) in the system's local time zone, plus a random delay of up to an hour. Fields take numbers, `*`, lists `a,b`, ranges `a-b` and steps `*/n` or `a-b/n`; day of week 0 and 7 are Sunday, and when neither day field starts with `*` a day matching either fires. Names, macros such as `@daily`, a seconds field, and an expression that fires more than four times a day or never are refused. |
| `geodata.checksum` | `true` | Verify each downloaded file against the `.sha256sum` published beside it; `false` accepts files unverified. |
| `ui.url` | Built-in zashboard URL | External dashboard ZIP source; `HONK_UI_DOWNLOAD_URL` overrides it. A missing or empty configured external-UI directory triggers the download. |
| `ui.route` | `assets.route` | Route for the external UI ZIP download; also accepts a node tag. |
| `subscription.ua` | `honk/<version>` | Default request User-Agent for subscription entries. |
| `subscription.interval` | `86400s` | Default periodic refresh interval; `0` disables scheduled refresh. |
| `subscription.cache` | `true` | Default per-entry body caching, subject to `global.store_subscribe`. |

honk takes the local time zone from the `TZ` environment variable (a zone name or a POSIX string such as `CST-8`), then from `/etc/localtime`, and uses UTC when neither gives a zone. OpenWrt keeps the zone in `/etc/TZ` unless a `zoneinfo-*` package is installed, so honk needs it passed as `TZ` there; the repository's `docker-compose.yml` mounts the host's `/etc/localtime`. Log timestamps use the same zone.

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
