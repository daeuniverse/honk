# Experimental 配置参考

本文档说明 `experimental { ... }` 下当前支持的两个嵌套 section。

## Section 概览

| 嵌套 section | 用途 |
| --- | --- |
| `clash_api` | Clash 兼容 HTTP API 与外部 dashboard |
| `cache_file` | 用 SQLite 持久化运行时选择、模式、延迟样本和可选 DNS 状态 |

`udp_nfqueue { enabled: ... }` 是已弃用的兼容 section。dae 和结构化配置加载器仍会接受它，打印迁移 warning，并将值复制到 `global.nfqueue_enable`；新配置应直接使用全局字段。

## `clash_api`

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `external_controller` | `""` | HTTP 监听地址。空值关闭 API server。 |
| `external_ui` | `""` | 外部 dashboard 目录。空值关闭 dashboard 服务与下载。 |
| `external_ui_download_url` | `""` | HTTP(S) dashboard ZIP URL。空值使用内建 zashboard URL。 |
| `external_ui_download_detour` | `""` | 下载使用的节点或组 tag。空值遵循普通流量路由。 |
| `secret` | `""` | API 鉴权 secret。空值关闭鉴权。 |
| `default_mode` | `"Rule"` | 启动模式：`Rule`、`Global` 或 `Direct`。有效的缓存模式优先。 |

所有 `clash_api` 字段都由启动阶段持有。通过 SIGHUP 提交的候选配置只要修改其中任一字段就会被拒绝。

### 鉴权与传输

`secret` 非空时，API 请求使用 `Authorization: Bearer <secret>`；WebSocket upgrade 也可以改用 `?token=<secret>`。静态 `/ui` 内容不经过这层鉴权 middleware。内置 listener 只提供明文 HTTP，不提供 TLS。应绑定到 `127.0.0.1` 等 loopback 地址，或在前面部署带鉴权的 TLS reverse proxy；不得直接暴露到不受信任的网络。endpoint 清单见 [Clash API 参考](./api.md)。

### 外部 UI

绝对 `external_ui` 路径按原值使用。相对路径首先选择 `global.data_dir` 下的已有目录，其次选择 `/var/share/honk` 下的已有目录，再选择相对当前工作目录的已有目录；都不存在时，honk 在 `global.data_dir` 下创建目标目录。目标缺失或为空时，会在后台下载 dashboard ZIP。非空 `external_ui_download_url` 会替换内建 zashboard URL；`HONK_UI_DOWNLOAD_URL` 的优先级高于两者。

非空 `external_ui_download_detour` 会强制初始请求和每次 redirect 都经过该节点或组。`direct` 直接下载，`block` 中止下载，组则为每次 exchange 解析其权威叶节点。该字段为空时，每个 URL 仍按原有行为遵循普通流量路由。tag 不可用、下载失败或解压失败只写日志，不会停止引擎。

### 启动模式

`default_mode` 接受规范模式 `Rule`、`Global` 和 `Direct`。`cache_file` 已启用且包含有效的 Clash 缓存模式时，改为恢复该值。无效的缓存值或配置值回退到 `Rule`。

## `cache_file`

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `enabled` | `false` | 打开 SQLite 缓存并启用运行时状态持久化。 |
| `path` | `"cache.db"` | 数据库路径。绝对路径按原值使用。对相对路径，依次优先使用 `global.data_dir` 下、`/var/share/honk` 下和相对原配置目录的已有文件；新文件创建在 `global.data_dir` 下。 |
| `cache_id` | `""` | 所有数据库 key 的 namespace。非空值给 key 加上 `<cache_id>:` 前缀。 |
| `store_fakeip` | `false` | 仅表示 FakeIP 持久化意图。已有 `fakeip:` 前缀和 flush API，但引擎尚不写入或恢复映射。 |
| `store_dns` | `false` | 使用 exact-key v2 格式持久化并恢复 DNS 缓存应答。 |

整个 `cache_file` section 都由启动阶段持有。通过 SIGHUP 提交的候选配置只要修改任一字段就会被拒绝。

### 始终持久化的状态

只要 `enabled` 成功打开数据库，honk 就会持久化 Selector 选择、Clash 模式和每个节点最后一次真实延迟样本，不受 `store_fakeip` 与 `store_dns` 影响。延迟样本每分钟生成一次快照；恢复时丢弃格式错误、为零或超过 24 小时的样本。liveness 不会恢复。

### DNS 持久化

`store_dns: true` 时，条目使用 `dns:v2:` key namespace 和 `HDNS` version-2 二进制 payload。v2 namespace 可安全回滚：pre-v2 binary 读取旧 `dns:` namespace 时会排除 `dns:v2:` 行，因此不会改动 v2 数据。

只有未过期，并且 key digest、规范 query wire、response wire identity 与当前 DNS policy 全部匹配的 v2 行才会恢复。exact key 还保留 ingress profile、request scope 和 operation，防止在不同 DNS 上下文之间复用。


## 示例

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

## 相关文档

- [Clash API 参考](./api.md)
- [NFQUEUE 设计](../design/nfqueue.md)
- [全局配置参考](./global.md)
