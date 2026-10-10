# Assets 配置参考

`assets {}` 为 geodata、外部 Clash dashboard 和订阅设置下载默认值。Geodata 的自动更新间隔与校验开关仍由原生 API 的运行时设置管理。

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

| 配置项 | 默认值 | 含义 |
| --- | --- | --- |
| `route` | `routing` | 配置文件中各项下载的默认出口；文件未指定出口时，已通过 API 保存的 geodata 出口继续生效。`routing` 遵循流量路由规则，`direct` 直连，组名强制经过该组；未知组在配置校验时被拒绝。 |
| `geodata.geosite` | 内置 URL（有状态数据库时） | 已加载 geosite 资产的 HTTP(S) 下载来源，最长 4096 字节。没有状态数据库时，更新要求配置来源。 |
| `geodata.geoip` | 内置 URL（有状态数据库时） | 已加载 geoip 资产的 HTTP(S) 下载来源，限制与 geosite 相同。 |
| `geodata.route` | `assets.route` | Geodata 下载及校验请求的出口。有状态数据库时，配置中的 URL 和出口在启动时写入已存储来源；API 的修改可在下次启动前覆盖。 |
| `ui.url` | 内置 zashboard URL | 外部 dashboard ZIP 来源；`HONK_UI_DOWNLOAD_URL` 的优先级更高。已配置的外部 UI 目录缺失或为空时才下载。 |
| `ui.route` | `assets.route` | 外部 UI ZIP 下载的出口；也接受节点 tag。 |
| `subscription.ua` | `honk/<version>` | 订阅条目的默认请求 User-Agent。 |
| `subscription.interval` | `86400s` | 默认定期刷新间隔；`0` 关闭定期刷新。 |
| `subscription.cache` | `true` | 条目正文的默认缓存开关，仍受 `global.store_subscribe` 限制。 |

条目中的设置优先于 `assets.subscription` 和 `assets.route`；`geodata.route` 与 `ui.route` 优先于 `assets.route`；两处均未设置时才使用内置默认值。条目语法见[订阅参考](./subscription.md)，已存储的 geodata 设置见 [API 参考](./api.md#geodata-来源与自动更新)。

以下 `experimental` 字段仍作为别名读取，每次出现都会在所在行产生一条 `legacy-assets-key` 警告。旧配置项的值非空且同时设置了对应的新配置项时，报 `conflicting-assets-setting`；旧值为空时不冲突。没有对应 `assets` 子块出口时，旧出口设置仍可覆盖 `assets.route`。

| 旧配置项 | 新配置项 |
| --- | --- |
| `experimental.native_api.geosite_download_url` | `assets.geodata.geosite` |
| `experimental.native_api.geoip_download_url` | `assets.geodata.geoip` |
| `experimental.native_api.geodata_download_detour` | `assets.geodata.route` |
| `experimental.clash_api.external_ui_download_url` | `assets.ui.url` |
| `experimental.clash_api.external_ui_download_detour` | `assets.ui.route` |

只有 `.dae` 配置会解析 `assets`。JSON、YAML 与 TOML 配置保存的是已解析的下载字段；其中的 `assets` 只记录默认值，不会再次应用，因此在这些格式中需直接设置 `experimental` 下载字段和各订阅自己的字段。
