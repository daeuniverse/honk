# Assets 配置参考

`assets {}` 设置 geodata、外部 Clash 面板和订阅的下载默认值，也设置 geodata 的自动更新计划和校验开关。

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

## 字段

| Key | 默认值 | 含义 |
| --- | --- | --- |
| `route` | 省略，`routing` | 配置文件里各项下载的默认出口。见 [`route`](#route)。 |
| `geodata.geosite` | 省略，有状态数据库时用内置 URL | 已加载的 geosite 资产的 HTTP(S) 来源。见 [`geodata.geosite`](#geodatageosite)。 |
| `geodata.geoip` | 省略，有状态数据库时用内置 URL | 已加载的 geoip 资产的 HTTP(S) 来源。见 [`geodata.geoip`](#geodatageoip)。 |
| `geodata.route` | 省略，`assets.route` | Geodata 下载及校验请求的出口。见 [`geodata.route`](#geodataroute)。 |
| `geodata.auto_update` | 省略，`true` | 更新路由或 DNS 已加载的 geodata 文件。见 [`geodata.auto_update`](#geodataauto_update)。 |
| `geodata.cron` | 省略，`0 3 * * *` | 自动更新在系统本地时区的执行时间。见 [`geodata.cron`](#geodatacron)。 |
| `geodata.checksum` | 省略，`true` | 按随文件发布的 `.sha256sum` 校验每个下载文件。见 [`geodata.checksum`](#geodatachecksum)。 |
| `ui.url` | 省略，`https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip` | 外部 dashboard ZIP 来源。见 [`ui.url`](#uiurl)。 |
| `ui.route` | 省略，`assets.route` | 外部 UI ZIP 下载的出口。见 [`ui.route`](#uiroute)。 |
| `subscription.ua` | 省略，`honk/<version>` | 订阅条目的默认请求 User-Agent。 |
| `subscription.interval` | 省略，`86400s` | 默认定期刷新间隔。见 [`subscription.interval`](#subscriptioninterval)。 |
| `subscription.cache` | 省略，`true` | 条目正文的默认缓存开关。见 [`subscription.cache`](#subscriptioncache)。 |

### route

配置文件里各项下载的默认出口：geodata、外部 dashboard 和订阅。

- `routing` 按流量路由规则走。
- `direct` 直连。
- 代理组名强制经过该组。

未知组会在配置校验时被拒绝。文件没有指定出口时，已通过 API 保存的 geodata 出口继续生效。

```dae
assets {
    route: Proxy
}
```

### geodata.geosite

已加载的 geosite 资产的 HTTP(S) 来源。URL 遵循 [Geodata URL 规则](#geodata-url-规则)。

没有状态数据库时，必须配置 URL 才能更新。有状态数据库时，该资产默认使用[内置 URL](#geodata-url-规则)。

```dae
assets {
    geodata {
        geosite: 'https://example.org/geosite.dat'
    }
}
```

### geodata.geoip

已加载的 geoip 资产的 HTTP(S) 来源。限制和默认值与 [`geodata.geosite`](#geodatageosite) 相同。

```dae
assets {
    geodata {
        geoip: 'https://example.org/geoip.dat'
    }
}
```

### geodata.route

Geodata 下载及校验请求的出口。

```dae
assets {
    geodata {
        route: direct
    }
}
```

### geodata.auto_update

自动更新路由或 DNS 已加载的 geodata 文件。从未加载的文件不会被下载。

只有启用原生 API 且有状态数据库时才运行，见[Geodata 来源与自动更新](./api.md#geodata-来源与自动更新)。

```dae
assets {
    geodata {
        auto_update: true
    }
}
```

### geodata.cron

自动更新的时间。它是五字段 cron 表达式，依次是分、时、日、月、星期。更新按系统本地时区计算，另加最多一小时的随机延迟。

不存在的本地时间会跳过。重复出现的本地时间只在第一次出现时触发。

各字段接受数字、`*`、列表 `a,b`、范围 `a-b` 和步长 `*/n` 或 `a-b/n`。星期的 0 和 7 都是星期日；日与星期两个字段都不以 `*` 开头时，任一字段匹配就触发。

解析不依赖时区。解析器拒绝名称、`@daily` 等宏、秒字段、每天触发超过四次的表达式，以及不匹配任何日历日期的表达式。

步长只能跟在 `*` 或范围后面，范围也不能回绕：`0 */6 * * *` 有效，`0 3/2 * * *` 和 `23-2` 无效。

```dae
assets {
    geodata {
        cron: '0 3 * * *'
    }
}
```

### geodata.checksum

honk 请求与每个文件一同发布的 `.sha256sum`。服务器返回 404 时不校验，直接使用该文件。

校验文件的首个字段与文件的 SHA-256 不符，或出现其他失败时，honk 拒绝这个 URL 并尝试下一个。设为 `false` 时不发该请求，文件不校验直接使用。

```dae
assets {
    geodata {
        checksum: true
    }
}
```

### ui.url

外部 dashboard ZIP 来源。`HONK_UI_DOWNLOAD_URL` 优先。

只有配置的外部 UI 目录缺失或为空时才下载。

```dae
assets {
    ui {
        url: 'https://example.org/dashboard.zip'
    }
}
```

### ui.route

外部 UI ZIP 下载的出口。也接受节点 tag。

### subscription.ua

订阅条目的默认请求 User-Agent。

### subscription.interval

默认定期刷新间隔。`0` 关闭定期刷新。

语法与条目的 [`interval`](./subscription.md) 相同。

### subscription.cache

条目正文的默认缓存开关，仍受 `global.store_subscribe` 限制。

## Geodata URL 规则

Geodata URL 必须是 HTTP(S)，不能带 userinfo 和 fragment，最长 4096 字节。可以带查询字符串。

有状态数据库时，各资产按顺序尝试以下 URL：

| 资产 | URL |
| --- | --- |
| `geosite` | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geosite.dat`，然后 `https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat` |
| `geoip` | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.dat`，然后 `https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat` |

在配置文件中设置的 URL 会替换该资产的列表，不会追加成镜像。

## 已存储设置

有状态数据库时，honk 在启动时把配置中的 geodata URL、出口、更新计划和校验开关写入已存储设置。此后 API 的修改会覆盖它们，直到下次启动。

`auto_update` 和 `cron` 合起来是一个更新计划：只设置其中一项时，另一项取默认值。两项都不再设置时，如果先前的计划是配置文件写进去的，就恢复默认计划。移除 `checksum` 时也一样，前提是先前的值来自配置文件。文件没有指定替代值时，API 写入的设置继续保留。

## 优先级

条目里的设置优先于 `assets.subscription` 和 `assets.route`。`geodata.route` 与 `ui.route` 又优先于 `assets.route`。两处都没设置时才用内置默认值。

条目语法见[订阅参考](./subscription.md)，已存储的 geodata 设置见 [API 参考](./api.md#geodata-来源与自动更新)。

`geodata.route` 或 `ui.route` 为空时继承 `assets.route`。若要让 geodata 走路由规则、其他下载经过某个组，需显式设置 `routing`：

```dae
assets {
    route: Proxy
    geodata {
        route: routing
    }
}
```

## 重启与 reload

修改任何 `assets.geodata` 设置，或者修改解析后的 UI 下载 URL 或出口，都需要重启。SIGHUP 会拒绝这类修改。订阅默认值跟随使用它们的订阅一起 reload。

## 时区与计划校验

启动时，geodata owner 拒绝在实际本地时区里永远不会触发的显式 cron，即使 `auto_update: false` 也一样。保留下来的计划只在启用时做这项检查；配置文件里的有效覆盖值可以修好旧的已存储计划。不可用的计划不会被替换成默认值。

如何禁用或修复保留的计划，以及之后时区变化怎么处理，见 [API 参考](./api.md#geodata-来源与自动更新)。

在 Linux 上，honk 锁定的 chrono 0.4.45 会读取 `TZ`。空值表示 UTC，`CST-8` 这类 POSIX 字符串不需要 tzdata，IANA 时区名则需要可读的 zoneinfo 文件。没有设置 `TZ` 时读取 `/etc/localtime`。如果这一步失败，再试 `iana-time-zone` 发现的系统时区名及其 zoneinfo 文件，最后回退到 UTC。OpenWrt 没有可用的 zoneinfo 文件时，要把 `/etc/TZ` 的内容作为 `TZ` 传给 honk；仓库的 `docker-compose.yml` 会挂载宿主机的 `/etc/localtime`。日志时间戳使用同一个时区。

## 无效值

`geodata.auto_update`、`geodata.cron` 或 `geodata.checksum` 的值无法解析时，honk 会发出 warning 并忽略该值，效果和没写一样。

`geodata.auto_update` 和 `geodata.checksum` 接受 `true`、`yes`、`1`、`on`、`false`、`no`、`0` 和 `off`，不区分大小写。

`subscription.interval` 的值无效时产生 warning 并变为 `0`；`subscription.cache` 的值无效时产生 warning 并变为 `true`。

## 旧 experimental 别名

以下 `experimental` 字段仍按别名读取。每出现一次，都会在那一行产生一条 `legacy-assets-key` warning。

| 旧配置项 | 新配置项 |
| --- | --- |
| `experimental.native_api.geosite_download_url` | `assets.geodata.geosite` |
| `experimental.native_api.geoip_download_url` | `assets.geodata.geoip` |
| `experimental.native_api.geodata_download_detour` | `assets.geodata.route` |
| `experimental.clash_api.external_ui_download_url` | `assets.ui.url` |
| `experimental.clash_api.external_ui_download_detour` | `assets.ui.route` |

旧配置项的值非空，又同时设置了对应的 `assets` 设置时，报 `conflicting-assets-setting`；旧值为空不算冲突。`assets` 子块没有对应的出口时，旧出口设置仍可覆盖 `assets.route`。

## 非 dae 格式

只有 `.dae` 配置会解析 `assets`。JSON、YAML 和 TOML 配置保存的是已解析的下载字段。

用这些格式时，`assets` 只记录默认值，不会再次应用；请直接设置 `experimental` 下载字段和各订阅自己的字段。

`assets.geodata.auto_update`、`cron` 和 `checksum` 没有对应的 `experimental` 字段，任何格式都从 `assets` 读取。
