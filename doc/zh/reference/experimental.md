# Experimental 配置参考

`experimental { ... }` 配置 API 与持久化运行时状态。

## Section 概览

| 嵌套配置段 | 用途 |
| --- | --- |
| `clash_api` | Clash 兼容 HTTP API 与外部面板 |
| `cache_file` | 在状态数据库中持久化运行时选择、模式、延迟样本和可选 DNS 状态 |
| `native_api` | 独立、显式启用的原生观测/控制、受控 `.dae` 源管理与本地 UI 目录 |

`udp_nfqueue { enabled: ... }` 是已弃用的兼容配置段。dae 和结构化配置加载器仍会接受它，输出迁移警告，并将值复制到 `global.nfqueue_enable`；新配置应直接使用全局字段。

## `native_api`

原生 API 需要显式启用 `native-api` Cargo 功能：以 `--features native-api` 或 `native-ui` 构建，或使用 full、`-native-api` 发布版本。不依赖 `clash-api`。监听器默认关闭；未编译该功能却启用配置时，启动报错。

所有生效字段都要求重启。SIGHUP 拒绝其变更，并保留当前监听器与配置代次。未知字段、标量中的嵌套块、无效布尔值及安全列表空成员均报错。

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `enabled` | `false` | 启动独立原生监听器。 |
| `listen` | `"127.0.0.1:9527"` | 数字 IP 与 1–65535 端口，不接受主机名或 `:port` 简写。 |
| `secret` | `""` | 独立于 Clash 的静态 Bearer 凭据。非空值选择令牌模式，不能与 `password_auth` 组合。API 响应按值遮蔽监听密钥；短于 8 字节的值不遮蔽，启动时会记录提示。 |
| `password_auth` | `false` | `secret` 为空时启用管理员密码登录。不能与 `allow_anonymous_loopback` 组合。 |
| `allow_anonymous_loopback` | `false` | 仅在 `secret` 为空、`password_auth` 为 false 且实际监听 IP 为回环地址时允许无凭据请求。 |
| `allow_origins` | 空列表 | 额外允许的完整 HTTP(S) Origin；不含路径、凭据、查询串、片段、`null` 或通配符。 |
| `allowed_hosts` | 空列表 | 额外允许的 HTTP Host 地址和端口；不含 URL 协议、路径、凭据或通配符。省略端口表示 80，不是监听端口。 |
| `ui` | `""` | 空值关闭托管；其他值为含可读 `index.html` 的可信本地目录，或配合默认关闭的 `native-ui` 功能使用 `embedded` / `embedded-lite`。`embedded-lite` 是更轻量的 doona lite 预览版。启动不下载、不解压、不构建前端。 |
| `record_flows` | `true` | 允许按 flow 诊断需求记录有界用户态 flow，或通过显式运行时设置持续记录。`false` 禁止记录，运行时设置不能覆盖；修改配置需重启。 |
| `record_traffic` | `true` | 无客户端也记录流量历史；最多 600 点/600 秒，false 在重启后释放对应缓冲，不关闭即时计数。 |
| `record_memory` | `true` | 无客户端也记录 RSS/cgroup 历史；最多 600 点/600 秒，false 在重启后释放对应缓冲，不关闭即时内存观测。 |
| `record_logs` | `true` | 允许按获准 `/logs` SSE 需求或显式运行时设置捕获结构化日志，最多保留 512 条、60 秒。`false` 禁止捕获；修改配置需重启。控制台和 Clash 日志保持独立。 |
| `record_dns_log` | `true` | 允许按成功 `/dns/log` GET 需求或显式运行时设置记录客户端 DNS 完成历史，最多保留 512 条、8 MiB。`false` 禁止记录；修改配置需重启。 |
| `config_write` | `false` | 允许已接受主文件及所有已接受 include 的原文替换与 reload，以及新建由 include 模式加载的 `.dae` 文件，含监听凭据的源除外；要求非空 `secret` 或启用 `password_auth`。 |

Auto flow、日志和 DNS 日志需求各自具有独立的 60 秒宽限期。普通 events 仅维持事件捕获；成功 flow 读取或显式 flow 事件过滤器请求 flows，`/logs` SSE 请求日志，成功 `/dns/log` GET 请求 DNS 日志。其他 API、validation、失败 GET 和 HEAD 不请求诊断捕获。运行时 On/Off、配置禁止及激活恢复语义保持不变，见 [API 参考](./api.md#用户态记录流)。

Geodata 下载 URL 与出口现由 [`assets.geodata`](./assets.md) 配置。旧版 `native_api` 字段仍可读取并产生警告；替代关系见 Assets 参考中的表格。

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

非空原生密钥必须为不含空白或逗号的可见 ASCII，与 HTTP Bearer 解析器一致。不支持的字节在共用配置准入处报错，不会启动无法认证的监听器。

请使用至少 16 字节、不可预测的令牌。令牌模式下，已启用的非回环监听（含通配地址）若密钥短于 16 字节，会在启动激活及每次已接受的配置重新激活时各记录一次 WARN。日志只包含结构化的 `listen` 与 `secret_length` 字段，绝不记录密钥，也不会拒绝配置。仅监听回环地址或使用密码模式时，不产生此提示。此提示与上文短于 8 字节值无法遮蔽的警告相互独立。

选择一种认证模式；变更模式需要重启：

- 静态令牌：设置非空 `secret`。
- 密码登录：将 `secret` 留空并设置 `password_auth: true`。不能与 `allow_anonymous_loopback` 组合。
- 本地无凭据开发：将 `secret` 留空，保持 `password_auth` 为 false，显式允许匿名回环访问，并绑定实际回环地址。

启用监听器却不满足任一模式时，配置校验失败。`config_write: true` 要求令牌或密码模式。

替换示例密钥。本地无凭据开发需省略 `secret` 并显式设置 `allow_anonymous_loopback: true`；不能通过反向代理公开该匿名监听器。非回环网络上的明文 HTTP 加令牌不是安全部署，应由可信代理终止 TLS。

Host 与 Origin 检查独立于认证：

- 默认 Host 必须对应具体监听地址和端口。回环监听还接受同端口的 `localhost`、`127.0.0.1` 与 `[::1]`。
- 通配监听接受同端口的任意 IP 字面量 Host 与 `localhost`，因为这些就是请求到达的监听器本身。DNS 名称仍需授权，因为名称可能被重绑定。
- 只有直接对应的明文 HTTP Origin 自动获准。通配监听时，Origin 必须与请求自身的 Host 相同；同端口其他地址上的页面需列入 `allow_origins`。
- TLS 反向代理若保留 `Host: panel.example`，需配置 `allowed_hosts: 'panel.example'` 与 `allow_origins: 'https://panel.example'`。若保留 `Host: panel.example:443`，则使用 `allowed_hosts: 'panel.example', 'panel.example:443'`。

转发请求头不授予权限。

列表采用逐项引号与逗号分隔，例如 `allow_origins: 'http://localhost:3000', 'https://panel.example'`。省略表示空列表；不接受 JSON 方括号或整段引号聚合。探测目标仅来自已接受的配置，仍解析并固定选中的 IP，将 IPv4-mapped IPv6 规范化为 IPv4，且不接受调用方 URL、不跟随 HTTP 重定向。探测、geodata 和共享下载使用配置的目标，不设地址或端口白名单。能够写入配置或控制订阅内容的人决定这些目标；provider 内容属于受信任的配置。

已移除的 `probe_allowed_cidrs` 与 `probe_allowed_ports` 键仍可在 dae 配置及兼容的结构化加载器中出现，每个键产生一条警告；其值被忽略，可以删除这两个键。配置序列化不输出这两个键。

相对 UI 路径沿用依赖搜索顺序：`global.data_dir` 下已有路径、`/var/share/honk` 下已有路径、工作目录已有路径；均不存在时定位到 `global.data_dir` 并在启动时报错。目录及其符号链接目标均由可信管理员负责。参见[原生 API 契约](./api.md#原生-api)。

单文件部署可使用 full 发布产物，或执行 `HONK_DOONA_DIR=$(ci/fetch-doona.sh) cargo build -p honk-core --features native-ui`，并设置 `ui: embedded` 或 `ui: embedded-lite`；`native-ui` 隐含 `native-api`，不要求 Clash。没有 `native-ui` 时启用内嵌托管会启动失败。静态资源不注入凭据；客户端通过公共 discovery 选择静态 token 输入或密码 setup/login。产物/源码身份、对应源码分发和管理契约见 [API 参考](./api.md#内嵌-doona-来源)。

配置文件中的 geodata 来源由管理员配置、需重启，不能通过源写入修改。启用状态数据库时，下载还可使用已认证的 URL 覆盖或内置来源；拒绝 userinfo、fragment、redirect 与 content encoding。直连的域名来源要求 `global.bootstrap_resolver`，不回退系统 DNS。`assets.geodata.route` 或已存储的路由可改为遵循路由规则或经过组下载；路由无法承载请求时不会回退到直连。更新使用适用的配置文件、已存储或内置来源。[主文件条目与 geodata 契约](./api.md#主文件条目与-geodata-管理)区分网络期限、已验证字节激活及部分耐久替换，不承诺回滚。

### 共用采样与可选历史

流量与内存历史共用既有一秒 sampler，错过 tick 时使用 Skip；仅存内存，重启清空，不插值、不补零，缺口与 null 原样保留。读取依据实际 RSS/cgroup v2 文件，未知值不设为零，不声明内核内存核算。关闭历史不关闭即时 runtime、出站或内存读取；所有记录开关仍需重启。已启用的日志/DNS 日志/flow 可通过 `/runtime/settings` 临时调整级别或留存上限，但不能动态开启被配置关闭的 recorder。完整合并结果通过校验后原子生效；显式配置激活（含 no-op）恢复配置值，provider/network refresh 保留临时值，见 [API 契约](./api.md#原生日志与运行时设置)。

### 配置管理的信任边界

配置来源仅在真实 `.dae` 启动加载时捕获；程序内构造的配置或 serde 加载不提供无损源管理。

- 读取返回已接受正文，仅遮蔽声明的监听凭据值，包括重复、被覆盖的值及其在其他位置的出现。获准访问的匿名回环请求与 bearer 认证请求读取相同的数据。
- 含凭据的源文件仍只读，哈希仍对应原始字节。
- 源 `path` 保持入口目录相对名称，`absolute_path` 提供规范化绝对路径。
- 若主文件需要通过 API 编辑，先在本地将凭据移至专用只读 include，再重启。API 禁止改变或迁移 API 凭据及原生设置；这些变更须由管理员本地修改并重启。

启用 `config_write` 后，所有已接受的非凭据 include 均可写；普通 include 的 glob、排序及无匹配语义不变。全量源/校验预算为 32 个来源、8 MiB，重复依赖的实体化也计入预算；HTTP JSON body 仍最多 64 KiB。源 PUT 使用按磁盘字节 SHA-256 求值的 RFC 9110 If-Match（strong tag、列表/多个 field line 或 `*`；weak tag 永不匹配），组 PATCH 使用 accepted revision 并独立检查源与依赖。正文披露与写入许可独立，遮蔽后的凭据源正文不能回写。Selector、受限组 PATCH 和主文件创建/删除均复用来源权威；自动策略的固定成员只在运行时生效，不写回来源。具体失败恢复见 [API 契约](./api.md#主文件条目与-geodata-管理)。


## `clash_api`

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `external_controller` | `""` | HTTP 监听地址。空值关闭 API 服务。 |
| `external_ui` | `""` | 外部面板目录。空值关闭面板服务与下载。 |
| `secret` | `""` | API 鉴权 secret。空值关闭鉴权。短于 8 字节的值在原生 API 响应里不遮蔽。 |
| `default_mode` | `"Rule"` | 原生 API 未启用时的启动模式：`Rule`、`Global` 或 `Direct`；`cache_file.enabled: true` 时有效的缓存模式优先。启用原生 API 时，启动改用共享的临时 rule 模式。 |

面板下载 URL 与出口见 [`assets.ui`](./assets.md)。

所有 `clash_api` 字段只在启动时生效。SIGHUP 提交的候选配置若修改其中任一字段，就会被拒绝。

`--store db` 模式不运行 Clash API，`external_controller` 非空时拒绝启动，详见[配置数据库](./api.md#配置数据库--store-db)。

### 鉴权与传输

`secret` 非空时，API 请求使用 `Authorization: Bearer <secret>`；WebSocket upgrade 也可以改用 `?token=<secret>`。静态 `/ui` 内容不经过这层鉴权中间件。内置 listener 只提供明文 HTTP，不提供 TLS。应绑定到 `127.0.0.1` 等 loopback 地址，或在前面部署带鉴权的 TLS 反向代理；不得直接暴露到不受信任的网络。endpoint 清单见 [Clash API 参考](./api.md)。

显式启用非回环地址监听且 secret 为空时，会在 `experimental.clash_api.external_controller` 产生 `unsafe-api-bind`，结构化输入也不例外。诊断不包含端点或 secret。使用回环地址的示例配置不产生该警告；此警告不会改变监听、鉴权或 CORS 规则。

### 外部 UI

绝对 `external_ui` 路径按原值使用。相对路径首先选择 `global.data_dir` 下的已有目录，其次选择 `/var/share/honk` 下的已有目录，再选择相对当前工作目录的已有目录；都不存在时，honk 在 `global.data_dir` 下创建目标目录。目标缺失或为空时，会在后台下载 dashboard ZIP。非空 `assets.ui.url` 会替换内建 zashboard URL；`HONK_UI_DOWNLOAD_URL` 的优先级高于两者。

`assets.ui.route` 优先于 `assets.route`，适用于初始请求及每次重定向。`direct` 直接下载，路由规则选中 `block` 时中止下载，组则为每次请求解析其权威叶节点。未配置出口时，每个 URL 遵循普通流量路由。标签不可用、下载失败或解压失败只写日志，不会停止引擎。压缩包写入目标目录中一个无文件名的私有文件，不保存在内存中；解压结束或下载失败后，honk 删除该压缩包。解压超过 10,000 个条目或 128 MiB 内容（与压缩包本身的上限相同）时拒绝继续，已写入的目录被清空，下次启动时重新下载。

### 启动模式

原生 API 未启用时，`default_mode` 接受规范模式 `Rule`、`Global` 和 `Direct`。`cache_file.enabled` 为 `true` 且包含有效的 Clash 缓存模式时，改为恢复该值。无效的缓存值或配置值回退到 `Rule`。启用原生 API 后，两种 API 共用同一临时模式所有者，不恢复或持久化模式；启动时使用 `Rule`，已接受的显式配置激活（含 no-op）在后端重置成功时恢复 `Rule`，provider 刷新或网络刷新时保留模式。提交后重置失败则保留原模式、关闭准入并返回 `CommittedDegraded`。`Global` 模式绑定稳定的节点或组身份，刷新移除目标时拒绝新的流量。见[运行时模式](./api.md#连接关闭模式与数据面生命周期)。

## `cache_file`

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `enabled` | 未设置 | 在状态数据库 `<data_dir>/state/honk.db` 中持久化运行时状态。未设置时保存 Selector 选择与延迟样本；`true` 时还保存 Clash 模式与 GLOBAL 选择，并允许 `store_dns`；`false` 时不保存任何状态。 |
| `store_dns` | `false` | 在 `enabled: true` 时同时持久化并恢复 DNS 缓存应答。 |

两个字段均只在启动时生效；SIGHUP 会拒绝修改任一字段的候选配置。

要保存 Clash 模式和 GLOBAL 选择，须显式设置 `true`；DNS 应答还须单独启用 `store_dns: true`。显式 `false` 禁用这些运行时缓存存储，不关闭独立的配置、凭据或订阅存储。

`path`、`cache_id` 与 `store_fakeip` 已不再是设置项。它们仍可解析，但只产生 `legacy-cache-file` 警告，不起作用；SIGHUP 也接受对它们的修改。`path` 与 `cache_id` 只在导入旧 `cache.db` 时读取一次，见下文。

### 持久化的状态

除非 `enabled` 为 `false`，honk 在状态数据库中保存 TCP/UDP 各自的 Selector 选择和每个节点最后一次真实延迟样本，与 mihomo 的 `store-selected` 一致。只有 `enabled: true` 且原生 API 未启用时，才恢复和保存 Clash 模式与 Clash GLOBAL 选择；原生 API 未启用且未恢复缓存模式时，重启后使用 `default_mode`；启用原生 API 后启动始终使用 `Rule`。延迟样本每分钟批量写入一次；恢复时丢弃为零或超过 24 小时的样本。存活状态不恢复。

未设置 `--store db` 与 `native_api.password_auth` 时，数据库故障按以下方式处理：

- 数据库损坏：honk 取得实例锁后，把 `honk.db` 与 `honk.db-wal` 改名为 `honk.db.corrupt` 与 `honk.db.corrupt-wal`，再创建新文件。
- 已有 `honk.db.corrupt`：honk 保留两份文件，在其中一份被删除前不做持久化。
- 数据库不可用、不安全或被重置操作锁定：honk 记录警告，并在不做持久化的情况下运行。不安全指数据库不是 honk 用户所有的私有文件；重置锁由 `honk-core admin reset` 持有。

路径不安全时，`persistence_unavailable` 降级在 `reason` 之外附带 `rule`：`not_owner`、`group_or_other_bits`、`not_directory`、`not_file`、`symlink` 或 `identity_changed`。日志给出路径与修复方法。

来自更新版本 honk 或其他程序的数据库在任何模式下都拒绝启动，因为移走它会毁掉只有该程序才能读取的数据。

### 容量限制

维护任务每 60 秒执行一次。Selector 选择只为配置中的 Selector 组保留，延迟样本只为已配置的节点保留；组或节点连续两次维护时都不在配置中，对应的行才会删除，因此 reload 短暂移除后又恢复的组或节点仍保留原记录。每次维护都会删除超过 24 小时的延迟样本和已过期的 DNS 行，并把至多 1 MiB 的空闲页归还给文件系统。DNS 行最多保留 4,096 条，每批写入后先淘汰最早过期的行。

启动时，如果 `--store db`、`password_auth`、`store_subscribe` 或 `cache_file` 要求打开状态数据库，以下设置会清空已存缓存状态：

| 启动设置 | 清空的表 |
| --- | --- |
| `enabled: false` | Selector、延迟、Clash 状态与 DNS |
| 未设置 `enabled` | Clash 状态与 DNS |
| `store_dns: false` | DNS |
| 启用原生 API 或未启用 Clash API | Clash 状态 |

不打开状态数据库的启动不改动该文件。

状态数据库文件上限为 112 MiB。缓存写入为配置 revision 与订阅正文保留其中 24 MiB：某批写入会使已用空间超过 88 MiB 时，写入线程先把 DNS 行删减到 2,048 条，仍然超出时回滚该批写入；被跳过的 DNS 条目计入 `budget_skipped`，不计为已写入。旧 `cache.db` 的导入受同一预算约束：会超出预算的复制不提交，下次启动时重试。

### DNS 持久化

`store_dns: true` 时，每条应答是 `dns_answer` 表中的一行，内容为 `HDNS` version 2 编码，以精确缓存 key 的摘要为主键。只有未过期，并且 key 摘要、规范 query wire、response wire 标识与当前 DNS policy 全部匹配的行才会恢复。精确 key 同时包含入口 profile、request scope 与 operation，因此不会在不同 DNS 上下文之间复用。编码后超过 4 KiB 的条目不写入，计入 `oversize`。

### 从 `cache.db` 升级

启用 `enabled` 后首次启动时，honk 导入 `path` 指向的旧 `cache.db`，解析规则与旧版本相同：绝对路径按原样使用；相对路径依次查找 `global.data_dir` 下、`/var/share/honk` 下以及相对原配置目录的已有文件。honk 只读取本实例 `cache_id` 前缀下的 key，复制配置中 Selector 组在 TCP/UDP 上各自的选择、Clash 模式、Clash GLOBAL 选择以及已配置节点 24 小时内的延迟样本；状态数据库中已有的行优先。旧版本按名称保存的 Selector 选择、DNS 应答与 FakeIP 记录不导入，因此已持久化的 DNS 应答需要重新查询。导入按路径记录在状态数据库中，每个路径一行；即使旧版本重新创建了该文件，也不会再次导入。如果 `cache.db` 是符号链接、不是 honk 用户所有的普通文件、可被其他用户写入，或无法按 `cache.db` 读取，honk 保留该文件并记录警告，下次启动时再次尝试。
数据库模式下，最后这项回退使用当前 revision 保存的原始入口目录；即使本次 `-c` 指向其他位置、启动时不读取它，也不会改变旧缓存的位置。

`cache_id` 为空时，honk 随后删除 `cache.db` 及其 `-wal`、`-shm`，保留 `cache.db.corrupt-*` 副本。`cache_id` 非空时，该文件可能由其他实例共用，因此保留，并只记录一次警告。此后再启动旧版本时，它找不到 `cache.db`，运行时状态从空开始。

## 示例

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

## 相关文档

- [Clash API 参考](./api.md)
- [NFQUEUE 设计](../design/nfqueue.md)
- [全局配置参考](./global.md)
