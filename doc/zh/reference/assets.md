# Assets 配置参考

`assets {}` 为 geodata、外部 Clash 面板和订阅设置下载默认值，并设置 geodata 的自动更新计划与校验开关。

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

| 配置项 | 默认值 | 含义 |
| --- | --- | --- |
| `route` | `routing` | 配置文件中各项下载的默认出口；文件未指定出口时，已通过 API 保存的 geodata 出口继续生效。`routing` 遵循流量路由规则，`direct` 直连，组名强制经过该组；未知组在配置校验时被拒绝。 |
| `geodata.geosite` | 内置 URL（有状态数据库时） | 已加载 geosite 资产的 HTTP(S) 下载来源，最长 4096 字节。没有状态数据库时，更新要求配置来源。 |
| `geodata.geoip` | 内置 URL（有状态数据库时） | 已加载 geoip 资产的 HTTP(S) 下载来源，限制与 geosite 相同。 |
| `geodata.route` | `assets.route` | Geodata 下载及校验请求的出口。 |
| `geodata.auto_update` | `true` | 是否自动更新 geodata。 |
| `geodata.cron` | `0 3 * * *` | 自动更新的时间：五字段 cron 表达式（分、时、日、月、星期），按系统本地时区计算，另加最多一小时的随机延迟。跳过不存在的本地时间；重复时间仅在第一次出现时触发。各字段接受数字、`*`、列表 `a,b`、范围 `a-b` 与步长 `*/n` 或 `a-b/n`；星期的 0 与 7 都是星期日；日与星期字段都不以 `*` 开头时，任一字段匹配即触发。解析不依赖时区：不接受名称、`@daily` 等宏、秒字段、每天触发超过四次或不匹配任何日历日期的表达式。 |
| `geodata.checksum` | `true` | 按同目录发布的 `.sha256sum` 校验下载的文件；`false` 不校验直接使用。 |
| `ui.url` | 内置 zashboard URL | 外部面板 ZIP 来源；`HONK_UI_DOWNLOAD_URL` 的优先级更高。已配置的外部 UI 目录缺失或为空时才下载。 |
| `ui.route` | `assets.route` | 外部 UI ZIP 下载的出口；也接受节点 tag。 |
| `subscription.ua` | `honk/<version>` | 订阅条目的默认请求 User-Agent。 |
| `subscription.interval` | `86400s` | 默认定期刷新间隔；`0` 关闭定期刷新。 |
| `subscription.cache` | `true` | 条目正文的默认缓存开关，仍受 `global.store_subscribe` 限制。 |

有状态数据库时，配置中的 geodata URL、出口、更新计划与校验开关在启动时写入已存储设置；API 的修改可在下次启动前覆盖。`auto_update` 与 `cron` 共同构成一个更新计划：只设置其中一项时，另一项取默认值。两项都不再设置时，若先前计划由配置文件写入，则恢复默认计划；移除 `checksum` 时，若先前值由配置文件写入，也恢复默认值。文件未指定替代值时，API 写入的设置继续保留。

Geodata 所有者启动时还会拒绝在实际本地时区中没有未来触发时间的显式 cron，即使 `auto_update: false`。保留的计划在启用时接受此检查；有效的文件覆盖值可以修复旧的已存储计划。不可用的计划不会被替换为默认值。禁用或修复保留计划及后续时区变化的处理见 [API 参考](./api.md#geodata-来源与自动更新)。

在 Linux 上，honk 锁定的 chrono 0.4.45 在设置了 `TZ` 时使用它：空值选择 UTC，`CST-8` 等 POSIX 字符串无需 tzdata，IANA 时区名则需要可读的 zoneinfo 文件。未设置 `TZ` 时读取 `/etc/localtime`。若上述主加载失败，则尝试 `iana-time-zone` 发现的系统时区名及其 zoneinfo 文件，最后回退到 UTC。OpenWrt 没有可用的 zoneinfo 文件时，需将 `/etc/TZ` 的内容以 `TZ` 传给 honk；仓库的 `docker-compose.yml` 挂载宿主机的 `/etc/localtime`。日志时间戳使用同一时区。

`geodata.auto_update`、`geodata.cron` 或 `geodata.checksum` 的值无法解析时产生警告并被忽略，等同于未设置。条目中的设置优先于 `assets.subscription` 和 `assets.route`；`geodata.route` 与 `ui.route` 优先于 `assets.route`；两处均未设置时才使用内置默认值。条目语法见[订阅参考](./subscription.md)，已存储的 geodata 设置见 [API 参考](./api.md#geodata-来源与自动更新)。

以下 `experimental` 字段仍作为别名读取，每次出现都会在所在行产生一条 `legacy-assets-key` 警告。旧配置项的值非空且同时设置了对应的新配置项时，报 `conflicting-assets-setting`；旧值为空时不冲突。没有对应 `assets` 子块出口时，旧出口设置仍可覆盖 `assets.route`。

| 旧配置项 | 新配置项 |
| --- | --- |
| `experimental.native_api.geosite_download_url` | `assets.geodata.geosite` |
| `experimental.native_api.geoip_download_url` | `assets.geodata.geoip` |
| `experimental.native_api.geodata_download_detour` | `assets.geodata.route` |
| `experimental.clash_api.external_ui_download_url` | `assets.ui.url` |
| `experimental.clash_api.external_ui_download_detour` | `assets.ui.route` |

只有 `.dae` 配置会解析 `assets`。JSON、YAML 与 TOML 配置保存的是已解析的下载字段；其中的 `assets` 只记录默认值，不会再次应用，因此在这些格式中需直接设置 `experimental` 下载字段和各订阅自己的字段。`assets.geodata.auto_update`、`cron` 与 `checksum` 没有对应的 `experimental` 字段，任何格式都从 `assets` 读取。
