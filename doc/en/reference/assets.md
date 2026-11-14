# Assets configuration reference

`assets {}` sets download defaults for geodata, the external Clash dashboard, and subscriptions. It also sets the geodata update schedule and checksum verification.

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
        interval: 6h
        cache: true
    }
}
```

## Fields

| Key | Default | Meaning |
| --- | --- | --- |
| `route` | Omitted; `routing` | Default route for the downloads this file configures. See [`route`](#route). |
| `geodata.geosite` | Omitted; built-in URLs when a state db exists | HTTP(S) source for the loaded geosite asset. See [`geodata.geosite`](#geodatageosite). |
| `geodata.geoip` | Omitted; built-in URLs when a state db exists | HTTP(S) source for the loaded geoip asset. See [`geodata.geoip`](#geodatageoip). |
| `geodata.route` | Omitted; `assets.route` | Route for geodata downloads, including checksum requests. See [`geodata.route`](#geodataroute). |
| `geodata.auto_update` | Omitted; `true` | Update the geodata files that routing or DNS loaded. See [`geodata.auto_update`](#geodataauto_update). |
| `geodata.cron` | Omitted; `0 3 * * *` | Time of the automatic updates in the system's local time. See [`geodata.cron`](#geodatacron). |
| `geodata.checksum` | Omitted; `true` | Verify each downloaded file against its published `.sha256sum`. See [`geodata.checksum`](#geodatachecksum). |
| `ui.url` | Omitted; `https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip` | External dashboard ZIP source. See [`ui.url`](#uiurl). |
| `ui.route` | Omitted; `assets.route` | Route for the external UI ZIP download. See [`ui.route`](#uiroute). |
| `subscription.ua` | Omitted; `honk/<version>` | Default request User-Agent for subscription entries. |
| `subscription.interval` | Omitted; `86400s` | Default periodic refresh interval. See [`subscription.interval`](#subscriptioninterval). |
| `subscription.cache` | Omitted; `true` | Default per-entry body caching. See [`subscription.cache`](#subscriptioncache). |

### route

Default route for the downloads this file configures: geodata, the external dashboard, and subscriptions.

- `routing` follows the routing rules.
- `direct` connects directly.
- A group name forces that group.

An unknown group fails validation. When the file sets no route, a geodata route stored through the API stays in effect.

```dae
assets {
    route: Proxy
}
```

### geodata.geosite

HTTP(S) source for the loaded geosite asset. The URL follows the [geodata URL rules](#geodata-url-rules).

Without a state db, updates require a configured URL. With one, the asset defaults to the [built-in URLs](#geodata-url-rules).

```dae
assets {
    geodata {
        geosite: 'https://example.org/geosite.dat'
    }
}
```

### geodata.geoip

HTTP(S) source for the loaded geoip asset. Limits and defaults match [`geodata.geosite`](#geodatageosite).

```dae
assets {
    geodata {
        geoip: 'https://example.org/geoip.dat'
    }
}
```

### geodata.route

Route for geodata downloads, including checksum requests.

```dae
assets {
    geodata {
        route: direct
    }
}
```

### geodata.auto_update

Automatic updates of the geodata files that routing or DNS loaded. A file that was never loaded is not downloaded.

Updates run only with the native API enabled and a state db. See [geodata sources and automatic updates](./api.md#geodata-sources-and-automatic-updates).

```dae
assets {
    geodata {
        auto_update: true
    }
}
```

### geodata.cron

Time of the automatic updates. It is a five-field cron expression (minute, hour, day of month, month, day of week) in the system's local time zone, plus a random delay of up to an hour.

A nonexistent local time is skipped. A repeated local time fires only at its first occurrence.

Each field takes numbers, `*`, lists `a,b`, ranges `a-b` and steps `*/n` or `a-b/n`. Day of week 0 and 7 are Sunday, and when neither day field starts with `*`, a day matching either field fires.

Parsing is zone-independent. The parser refuses names, macros such as `@daily`, a seconds field, more than four fires a day, and expressions that match no calendar date.

A step applies only to `*` or a range, and a range cannot wrap: `0 */6 * * *` is valid, `0 3/2 * * *` and `23-2` are not.

```dae
assets {
    geodata {
        cron: '0 3 * * *'
    }
}
```

### geodata.checksum

Fetch the `.sha256sum` published beside each file. A 404 accepts the file unverified.

If the first token does not match the file's SHA-256, or the request fails otherwise, honk rejects that URL and tries the next one. `false` skips the request and accepts files unverified.

```dae
assets {
    geodata {
        checksum: true
    }
}
```

### ui.url

External dashboard ZIP source. `HONK_UI_DOWNLOAD_URL` overrides it.

A missing or empty configured external-UI directory triggers the download.

```dae
assets {
    ui {
        url: 'https://example.org/dashboard.zip'
    }
}
```

### ui.route

Route for the external UI ZIP download. It also accepts a node tag.

### subscription.ua

Default request User-Agent for subscription entries.

### subscription.interval

Default periodic refresh interval. `0` disables scheduled refresh.

The value uses the same grammar as an entry's [`interval`](./subscription.md).

### subscription.cache

Default per-entry body caching, subject to `global.store_subscribe`.

## Geodata URL rules

Geodata URLs must be HTTP(S), without userinfo or a fragment, and at most 4096 bytes. A query string is allowed.

With a state db, each asset falls back to these URLs in order:

| Asset | URLs |
| --- | --- |
| `geosite` | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geosite.dat`, then `https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat` |
| `geoip` | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.dat`, then `https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat` |

A URL in the file replaces that asset's list; honk does not add it as a mirror.

## Stored settings

With a state db, honk writes the configured geodata URLs, route, schedule and checksum switch into the stored settings at startup. API changes override them until the next startup.

`auto_update` and `cron` form one schedule: naming only one takes the default for the other. Removing both restores the default schedule if a file wrote the stored one. Removing `checksum` likewise restores its default when the file owned it. honk keeps API-owned settings when the file names no replacement.

## Precedence

An entry's options override `assets.subscription` and `assets.route`. `geodata.route` and `ui.route` override `assets.route`. Built-in defaults apply only when neither the entry nor `assets` sets a value.

See the [subscription reference](./subscription.md) for entry syntax and the [API reference](./api.md#geodata-sources-and-automatic-updates) for stored geodata settings.

An empty `geodata.route` or `ui.route` inherits `assets.route`. To send geodata through routing while other downloads use a group, set `routing` explicitly:

```dae
assets {
    route: Proxy
    geodata {
        route: routing
    }
}
```

## Restart and reload

Changing any `assets.geodata` setting, or the resolved UI download URL or route, requires a restart. SIGHUP rejects it. Subscription defaults reload with the subscriptions that use them.

## Time zone and schedule checks

Startup of the geodata owner rejects an explicit cron that has no future occurrence in the actual local zone, even with `auto_update: false`. A retained schedule is checked when enabled, and a valid file override can repair an old stored plan. Unavailable plans are not replaced with defaults.

See the [API reference](./api.md#geodata-sources-and-automatic-updates) for disabling or repairing a retained plan and for handling later zone changes.

On Linux, honk's locked chrono 0.4.45 uses `TZ` when set. An empty value selects UTC, POSIX strings such as `CST-8` need no tzdata, and IANA names require a readable zoneinfo file. When `TZ` is unset, chrono reads `/etc/localtime`. If that primary load fails, it tries a system zone name discovered by `iana-time-zone` and its zoneinfo file, then falls back to UTC. OpenWrt's `/etc/TZ` must be passed as `TZ` when no usable zoneinfo file is available; the repository's `docker-compose.yml` mounts the host's `/etc/localtime`. Log timestamps use the same zone.

## Invalid values

If a `geodata.auto_update`, `geodata.cron` or `geodata.checksum` value does not parse, honk warns and ignores it, as if the key were absent.

`geodata.auto_update` and `geodata.checksum` accept `true`, `yes`, `1`, `on`, `false`, `no`, `0` and `off`, in any case.

An invalid `subscription.interval` warns and becomes `0`. An invalid `subscription.cache` warns and becomes `true`.

## Legacy experimental aliases

The parser accepts the following `experimental` fields as aliases. Each occurrence emits a `legacy-assets-key` warning at that line.

| Legacy setting | Replacement |
| --- | --- |
| `experimental.native_api.geosite_download_url` | `assets.geodata.geosite` |
| `experimental.native_api.geoip_download_url` | `assets.geodata.geoip` |
| `experimental.native_api.geodata_download_detour` | `assets.geodata.route` |
| `experimental.clash_api.external_ui_download_url` | `assets.ui.url` |
| `experimental.clash_api.external_ui_download_detour` | `assets.ui.route` |

A nonempty legacy value together with the matching `assets` setting fails with `conflicting-assets-setting`; an empty legacy value does not conflict. A legacy route setting without a corresponding `assets` sub-block route can still override `assets.route`.

## Non-dae formats

Only `.dae` configs resolve `assets`. JSON, YAML and TOML configs store the resolved download fields.

In those formats, `assets` records the defaults but is not applied again. Set the `experimental` download fields and each subscription's own fields directly in those formats.

`assets.geodata.auto_update`, `cron` and `checksum` have no `experimental` field and are read from `assets` in every format.
