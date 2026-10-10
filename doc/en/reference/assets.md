# Assets configuration reference

`assets {}` sets download defaults for geodata, the external Clash dashboard, and subscriptions. It does not control geodata update scheduling or checksum verification; those remain native API runtime settings.

```dae
assets {
    route: routing
    geodata {
        geosite: 'https://example.org/geosite.dat'
        geoip: 'https://example.org/geoip.dat'
        route: direct
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
| `geodata.route` | `assets.route` | Route for geodata downloads, including checksum requests. With a state db, the URLs and route are written into the stored sources at startup; API changes override them until the next startup. |
| `ui.url` | Built-in zashboard URL | External dashboard ZIP source; `HONK_UI_DOWNLOAD_URL` overrides it. A missing or empty configured external-UI directory triggers the download. |
| `ui.route` | `assets.route` | Route for the external UI ZIP download; also accepts a node tag. |
| `subscription.ua` | `honk/<version>` | Default request User-Agent for subscription entries. |
| `subscription.interval` | `86400s` | Default periodic refresh interval; `0` disables scheduled refresh. |
| `subscription.cache` | `true` | Default per-entry body caching, subject to `global.store_subscribe`. |

An entry's options override `assets.subscription` and `assets.route`; `geodata.route` and `ui.route` override `assets.route`. Built-in defaults apply only where neither of them sets a value. See the [subscription reference](./subscription.md) for entry syntax and the [API reference](./api.md#geodata-sources-and-automatic-updates) for stored geodata settings.

The following `experimental` fields remain accepted as aliases; each occurrence emits its own `legacy-assets-key` warning at that line. A nonempty legacy value together with the matching `assets` setting fails with `conflicting-assets-setting`; an empty legacy value does not conflict. A legacy route setting without a corresponding `assets` sub-block route can still override `assets.route`.

| Legacy setting | Replacement |
| --- | --- |
| `experimental.native_api.geosite_download_url` | `assets.geodata.geosite` |
| `experimental.native_api.geoip_download_url` | `assets.geodata.geoip` |
| `experimental.native_api.geodata_download_detour` | `assets.geodata.route` |
| `experimental.clash_api.external_ui_download_url` | `assets.ui.url` |
| `experimental.clash_api.external_ui_download_detour` | `assets.ui.route` |

Only `.dae` configs resolve `assets`. JSON, YAML and TOML configs store the resolved download fields; there `assets` records the defaults but is not applied again, so set the `experimental` download fields and each subscription's own fields directly in those formats.
