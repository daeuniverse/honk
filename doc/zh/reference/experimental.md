# Experimental 配置参考

`experimental { ... }` 配置 Clash 兼容 API、原生 API 和运行时状态的持久化。
它与 Clash/mihomo 的 `experimental` 配置段同名，但字段不同：honk 用它配置 API listener 和持久化。

## Section 概览

| 嵌套配置段 | 用途 |
| --- | --- |
| `clash_api` | Clash 兼容 HTTP API 与外部面板 |
| `cache_file` | 把运行时选择、模式、延迟样本和可选的 DNS 状态存进状态数据库 |
| `native_api` | 原生观测与控制接口，需显式启用；也负责受控地管理 `.dae` 源，并托管本地 UI 目录 |

`udp_nfqueue { enabled: ... }` 已弃用，只为兼容而保留。dae 加载器和结构化配置加载器仍接受它，但会输出迁移 warning。只有没设置 `global.nfqueue_enable` 时，这里的值才当作该全局字段使用。`enabled` 默认是 `false`，所以空段 `udp_nfqueue {}` 会关掉 NFQUEUE；想保留全局默认开启，必须把整段删掉。新配置请直接写全局字段。下例中全局字段优先，NFQUEUE 保持关闭：

```dae
global {
    nfqueue_enable: false
}
experimental {
    udp_nfqueue {
        enabled: true
    }
}
```

## `native_api`

原生 API 需要显式编译 `native-api` Cargo feature。用 `--features native-api` 或 `native-ui` 构建，或直接用 full 发布版本、名字带 `-native-api` 的发布版本。它不依赖 `clash-api`。listener 默认关闭；没编译该 feature 却在配置里启用时，启动会报错。

下表中的字段都只在启动时生效，改动后要重启。SIGHUP 会拒绝这类改动，继续用当前的 listener 和配置 generation。未知字段、标量字段里嵌块、无效布尔值，以及白名单里的空成员，都会报错。

布尔字段写 `true` 或 `false`，也接受 `yes`/`no`、`1`/`0` 和 `on`/`off`，不区分大小写。其他写法会报 `invalid-config-value` 错误，例如 `t`。

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `enabled` | `false` | 启动独立原生 listener。 |
| `listen` | `"127.0.0.1:9527"` | 数字 IP 加 1–65535 端口。不接受主机名，也不接受 `:port` 这种简写。 |
| `secret` | `""` | 独立于 Clash 的静态 Bearer 凭据。填非空值即选择 token 模式，不能和 `password_auth` 同时用。API 响应会按值遮蔽这个 listener secret；短于 8 字节的值不遮蔽，启动时发一条 warning。 |
| `password_auth` | `false` | `secret` 为空时，启用管理员密码登录。不能和 `allow_anonymous_loopback` 同时用。 |
| `allow_anonymous_loopback` | `false` | 只在 `secret` 为空、`password_auth` 为 false，且实际监听 IP 是 loopback 地址时，允许不带凭据的请求。 |
| `allow_origins` | 空列表 | 额外放行的完整 HTTP(S) Origin。不能含路径、凭据、查询串、片段、`null` 或通配符。省略端口时，`http` 按 80 算，`https` 按 443 算。 |
| `allowed_hosts` | 空列表 | 额外放行的 HTTP Host 地址和端口。不能含 URL 协议、路径、凭据或通配符。省略端口时按 80 算，不是按监听端口算。 |
| `ui` | `""` | 空值关闭托管。其他值可以是本地目录，要求目录可信并含可读的 `index.html`；启用默认关闭的 `native-ui` feature 后，也可以写 `embedded` 或 `embedded-lite`。`embedded-lite` 是更轻量的 doona lite 预览版。启动阶段不下载、不解压，也不构建前端。 |
| `record_flows` | `true` | 允许记录有界的用户态流，供流诊断使用，或由显式运行时设置要求持续记录。`false` 一律禁止，运行时设置也覆盖不了；改配置要重启。 |
| `record_traffic` | `true` | 即使没有客户端也记录流量历史，最多保留 600 秒内的 600 个采样点。`false` 会在重启后释放对应缓冲，但即时计数照常。 |
| `record_memory` | `true` | 即使没有客户端也记录 RSS/cgroup 历史，最多保留 600 秒内的 600 个采样点。`false` 会在重启后释放对应缓冲，但即时内存观测照常。 |
| `record_logs` | `true` | 在获准的 `/logs` SSE 需求下，或由显式运行时设置要求时，允许捕获结构化日志，最多保留 60 秒内的 512 条。`false` 禁止捕获；改配置要重启。控制台日志和 Clash 日志各走各的。 |
| `record_dns_log` | `true` | 在成功的 `/dns/log` GET 需求下，或由显式运行时设置要求时，允许记录已完成的客户端 DNS 查询历史，最多保留 512 条、8 MiB。`false` 禁止记录；改配置要重启。 |
| `config_write` | `false` | 允许直接替换已接受的主文件和 include 正文然后 reload，也允许新建由 include 模式加载的 `.dae` 文件；含 listener secret 的源除外。要求 `secret` 非空或启用 `password_auth`。 |

流、日志和 DNS 日志三种诊断需求各有独立的 60 秒宽限期。普通 events 请求只维持事件捕获，不会打开 flow 记录。请求 flow 记录的是成功的流读取和显式流事件过滤器；请求日志记录的是 `/logs` SSE；请求 DNS 日志记录的是成功的 `/dns/log` GET。其他 API 请求、配置校验、失败的 GET 和 HEAD 都不会请求诊断捕获。运行时的 On/Off、配置禁止和激活恢复语义不变，见 [API 参考](./api.md#用户态记录流)。

Geodata 的下载 URL 和出口现在由 [`assets.geodata`](./assets.md) 配置。加载器仍接受旧版 `native_api` 字段，并产生 warning；哪个字段替代哪个，见 Assets 参考中的表格。

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

非空的 secret 只能包含可见 ASCII 字符，不能有空白或逗号，与 HTTP Bearer 解析器的要求一致。出现不支持的字节时，共用的配置 admission 会报错，不会启动一个无法认证的 listener。

token 至少要有 16 字节，并且不可预测。token 模式下，如果已启用的 listener 不在 loopback 上，包括通配绑定，而 secret 短于 16 字节，honk 会在启动激活时记一次 WARN，之后每重新激活一次已接受配置再记一次。这条 WARN 只带 `listen` 和 `secret_length` 两个结构化字段，不记录 secret，也不拒绝配置。只监听 loopback 地址或使用密码模式时不会出现这条 warning。它和上文短于 8 字节无法遮蔽的 warning 是两条独立的 warning。

选择一种认证模式。换模式要重启：

- 静态 token：设置非空 `secret`。
- 密码登录：`secret` 留空，设置 `password_auth: true`。不能和 `allow_anonymous_loopback` 同时用。
- 本地无凭据开发：`secret` 留空，`password_auth` 保持 false，显式打开匿名 loopback 访问，并绑定实际的 loopback 地址。

启用 listener 却不符合任何一条，配置校验就失败。`config_write: true` 必须搭配 token 或密码模式。

示例里的 secret 要换掉。本地无凭据开发要省略 `secret`，显式设置 `allow_anonymous_loopback: true`，并且不要通过反向代理把这种匿名 listener 暴露出去。在非 loopback 网络上用明文 HTTP 加 token 不是安全部署，TLS 应该终止在可信代理上。

Host 和 Origin 的检查独立于认证：

- 默认情况下，Host 必须对应具体的监听地址和端口。loopback listener 还接受同端口的 `localhost`、`127.0.0.1` 和 `[::1]`。
- 通配绑定接受同端口的任意 IP 字面量 Host 和 `localhost`，因为这些地址都指向接收请求的 listener 自己。DNS 名称不行，仍要写进白名单，因为域名可能被重绑定。
- 只有直接对应的明文 HTTP Origin 会自动放行。通配绑定时，Origin 必须和请求自己的 Host 一致；同端口其他地址上的页面要写进 `allow_origins`。
- TLS 反向代理如果保留 `Host: panel.example`，就要配置 `allowed_hosts: 'panel.example'` 和 `allow_origins: 'https://panel.example'`。如果保留 `Host: panel.example:443`，则改用 `allowed_hosts: 'panel.example', 'panel.example:443'`。

转发 header 不会带来额外权限。

两个列表里的主机可以写 IPv4 地址、带方括号的 IPv6 地址，例如 `[::1]:9527`，或 ASCII DNS 名称。名称只能含字母、数字和中间的连字符，不能有下划线、空标签或末尾点。显式端口的范围是 1 到 65535。

列表用逗号分隔，每项可以单独加引号，也可以不加，例如 `allow_origins: 'http://localhost:3000', 'https://panel.example'`。省略该项就是空列表。不要写 JSON 方括号，也不要用一对引号把整个列表包起来。探测目标只来自已接受的配置。honk 会解析并固定选中的 IP，把 IPv4-mapped IPv6 规范化为 IPv4，不接受调用方提供的 URL，也不跟随 HTTP 重定向。探测、geodata 和共享下载都使用配置里的目标，没有地址或端口白名单。谁能写配置、谁能控制订阅内容，谁就决定这些目标；provider 内容按可信配置处理。

`probe_allowed_cidrs` 和 `probe_allowed_ports` 已移除，但仍能出现在 dae 配置和兼容的结构化加载器里，每个 key 产生一条 warning。honk 忽略它们的值，可以直接删掉。序列化配置时也不会输出这两个 key。

相对的 UI 路径和依赖用同一套搜索顺序：先看 `global.data_dir` 下有没有，再看 `/var/share/honk` 下，最后看工作目录。三处都没有时，路径定位到 `global.data_dir`，启动时报错。目录本身和它的符号链接目标都由可信管理员负责。参见[原生 API 契约](./api.md#原生-api)。

单文件部署可以用 full 发布产物，也可以执行 `HONK_DOONA_DIR=$(ci/fetch-doona.sh) cargo build -p honk-core --features native-ui` 自行构建，然后把 `ui` 设为 `embedded` 或 `embedded-lite`。`native-ui` 隐含 `native-api`，不需要 Clash。构建里没有 `native-ui` 却启用内嵌托管，启动会失败。静态资源里不注入凭据；客户端通过公共 discovery 选择静态 token 输入或密码 setup/login。产物与源码的身份、对应源码的分发方式和管理契约见 [API 参考](./api.md#内嵌-doona-来源)。

配置文件里的 geodata 来源由管理员决定，修改要重启，源写入无法改变它。启用状态数据库时，下载还可以用已认证的 URL 覆盖，或改用内置来源。honk 会拒绝 userinfo、fragment、redirect 和 content encoding。直连的域名来源需要配置 `global.bootstrap_resolver`，不会回退到系统 DNS。用 `assets.geodata.route` 或已存储的路由，可以让下载走路由规则，或改为经过某个代理组；路由承载不了请求时不会退回直连。每次更新都用当时适用的配置来源、已存储来源或内置来源。[主文件条目与 geodata 契约](./api.md#主文件条目与-geodata-管理)说明了网络期限、按已验证字节激活和部分耐久替换，不承诺回滚。

### 共用采样与可选历史

流量历史和内存历史共用现成的一秒 sampler，错过 tick 就记为 Skip。历史只放在内存里，重启即清空；不插值也不补零，缺口和 null 原样保留。内存读数取自实际的 RSS 和 cgroup v2 文件，未知值不记为零，也不声称采用了内核内存核算。关闭历史不会关掉实时的 runtime、出站或内存读数；所有记录开关仍要重启才生效。已启用的日志、DNS 日志和流可以通过 `/runtime/settings` 临时调整级别或留存上限，但配置里关掉的 recorder 不能动态打开。合并后的完整设置在通过校验后原子生效。显式配置激活哪怕只是 no-op，也会恢复配置值；provider 刷新或网络刷新则保留临时值。见 [API 契约](./api.md#原生日志与运行时设置)。

### 配置管理的信任边界

只有在启动时真正加载 `.dae` 文件，才能捕获配置来源。程序里构造的配置和 serde 加载都没有这种来源快照。

- 读取操作返回已接受的正文，只遮蔽声明过的 listener secret 值。重复声明的、已被覆盖的，以及同一值在别处出现的，也一并遮蔽。通过检查的匿名 loopback 请求和 Bearer 认证请求读到的是同一份数据。
- 含凭据的源文件保持只读，hash 仍按原始字节计算。
- 源的 `path` 是相对入口目录的名字，`absolute_path` 给出规范化后的绝对路径。
- 如果主文件要通过 API 编辑，先在本地把凭据移进一个专用的只读 include，然后重启。API 无法修改或迁移 API 凭据和原生设置，这些只能由管理员在本地改完重启。

启用 `config_write` 后，所有已接受的非凭据 include 都可写。普通 include 的 glob、排序和无匹配时的行为都不变。源和依赖的 admission 总额度是 32 个来源、8 MiB；同一个依赖被引用多次时，每次引用都各占一份。HTTP JSON 正文仍最多 64 KiB。源 PUT 的 `If-Match` 按磁盘字节的 SHA-256 求值，遵循 RFC 9110：strong tag、列表或多个 field line、`*` 都能匹配，weak tag 永不匹配。组 PATCH 用已接受的 revision，并分别检查源和依赖。能不能读正文和能不能写入是两件事。含凭据的源，正文被遮蔽后不能回写。Selector、受限组 PATCH，以及主文件的创建和删除，都走同一套来源写权限。自动策略里的固定成员只在运行时生效，不写回来源。具体怎么从失败中恢复，见 [API 契约](./api.md#主文件条目与-geodata-管理)。


## `clash_api`

`clash_api` 需要默认启用的 `clash-api` Cargo feature。没编译该 feature 时，`external_controller` 会被忽略。

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `external_controller` | `""` | 监听地址，由 IP 和端口组成，例如 `127.0.0.1:9090` 或 `[::1]:9090`；`:9090` 等于 `0.0.0.0:9090`。不接受主机名。空值关闭 API 服务。地址无效时记一条 warning，引擎照常启动，只是没有这个 listener。 |
| `external_ui` | `""` | 外部面板目录。空值关闭面板服务和下载。 |
| `secret` | `""` | API 认证 secret。空值关闭认证。短于 8 字节的值不会在原生 API 响应里遮蔽。 |
| `default_mode` | `"Rule"` | 原生 API 未启用时的启动模式，可选 `Rule`、`Global` 或 `Direct`；`cache_file.enabled: true` 且缓存里有有效模式时，以缓存为准。启用原生 API 后，启动改用共享的临时模式，初始值为 `Rule`。 |

面板的下载 URL 和出口见 [`assets.ui`](./assets.md)。

`clash_api` 的字段都只在启动时生效。候选配置里改了其中任一字段，SIGHUP 会拒绝。

`--store db` 模式不运行 Clash API。该模式下 `external_controller` 非空会导致启动被拒，详见[配置数据库](./api.md#配置数据库--store-db)。

### 认证与传输

`secret` 非空时，API 请求要带 `Authorization: Bearer <secret>`；WebSocket upgrade 也可以改用 `?token=<secret>`。静态 `/ui` 内容不经过这层认证中间件。内置 listener 只提供明文 HTTP，没有 TLS。它应该绑定到 `127.0.0.1` 这类 loopback 地址，或者前面放一个带认证的 TLS 反向代理；不要直接暴露到不可信的网络。endpoint 清单见 [Clash API 参考](./api.md)。

显式启用的非 loopback 绑定如果 `secret` 为空，honk 会在 `experimental.clash_api.external_controller` 上报 `unsafe-api-bind`，结构化输入也一样。诊断里不含 endpoint 或 secret。示例配置用的是 loopback 地址，所以不会产生这条 warning。这条 warning 不改变绑定、认证或 CORS 规则。

### 外部 UI

`external_ui` 写绝对路径就按原值使用。写相对路径时，honk 依次在 `global.data_dir` 下、`/var/share/honk` 下和当前工作目录里找第一个已存在的路径，文件或目录都算；先找到的是文件也直接使用。三处都没有时，honk 在 `global.data_dir` 下创建目标目录。目标目录不存在或为空时，honk 在后台下载 dashboard ZIP。`assets.ui.url` 非空会替换内置的 zashboard URL；`HONK_UI_DOWNLOAD_URL` 比两者优先级都高。

`assets.ui.route` 优先于 `assets.route`，初始请求和每次重定向都按这个优先级。出口写 `direct` 就直接下载；路由规则选中 `block` 时中止下载；写组名时，每次请求都解析出该组最终选用的叶节点。没配置出口时，每个 URL 都走普通流量路由。标签不可用、下载失败或解压失败只记日志，不会停掉引擎。压缩包写在目标目录里一个没有文件名的私有文件，不放在内存中；解压完成或下载失败后，honk 删掉这个压缩包。条目超过 10,000 个或内容超过 128 MiB 时，honk 拒绝继续解压，并清空已经写出的目录；上限和压缩包本身一样。下次启动会重新下载。

下载最多跟随五次重定向。每次 HTTP 交换超时 30 秒；经代理时，计时从隧道拨号完成后开始。所有 ZIP 条目都在同一个顶层目录下时，解压会去掉这一层，`dist/index.html` 变成 `index.html`。路径里含空分量、`.`、`..` 或反斜杠的条目，honk 会跳过。

### 启动模式

原生 API 没启用时，`default_mode` 接受 `Rule`、`Global` 和 `Direct`，不区分大小写。`cache_file.enabled` 为 `true` 且缓存里有有效的 Clash 模式时，恢复缓存里的值。缓存值或配置值无效时回退到 `Rule`。启用原生 API 后，两个 API 共用同一个临时模式 owner，既不恢复也不持久化模式，启动时用 `Rule`。已接受的显式配置激活，哪怕只是 no-op，都会在后端重置成功后恢复 `Rule`；provider 刷新或网络刷新则保留当前模式。如果提交后重置失败，honk 保留原模式、关闭 admission，并返回 `CommittedDegraded`。`Global` 模式绑定稳定的节点或组身份；刷新把目标移除后，honk 会拒绝新的流量。见[运行时模式](./api.md#连接关闭模式与数据面生命周期)。

## `cache_file`

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `enabled` | 未设置 | 把运行时状态存进状态数据库 `<data_dir>/state/honk.db`。不设置时保存 Selector 选择和延迟样本；设为 `true` 还会保存 Clash 模式和 GLOBAL 选择，并启用 `store_dns`；设为 `false` 什么都不存。 |
| `store_dns` | `false` | `enabled: true` 时，同时持久化和恢复 DNS 缓存应答。 |

两个字段都只在启动时生效。候选配置改了其中任一个，SIGHUP 会拒绝。

想保存 Clash 模式和 GLOBAL 选择，必须显式把 `enabled` 设为 `true`；DNS 应答还要另外打开 `store_dns: true`。显式写 `false` 会关掉这些运行时缓存存储，但配置、凭据和订阅各自的存储不受影响。

`path`、`cache_id` 和 `store_fakeip` 已不再是设置项。它们仍能解析，但只产生 `legacy-cache-file` warning，不起作用；SIGHUP 也不会因修改它们而拒绝。`path` 和 `cache_id` 只在导入旧 `cache.db` 时读取一次，见下文。

`path` 省略或为空时指 `cache.db`；`cache_id` 省略时为 `""`，也就是 key 不带前缀。

### 持久化的状态

只要 `enabled` 不是 `false`，honk 就在状态数据库里保存 TCP 和 UDP 各自的 Selector 选择，以及每个节点最后一次真实延迟样本，行为与 mihomo 的 `store-selected` 一致。只有在 `enabled: true` 且原生 API 未启用时，honk 才恢复并保存 Clash 模式和 Clash GLOBAL 选择。原生 API 没启用、缓存模式也没恢复时，重启后用 `default_mode`；启用原生 API 后，启动始终用 `Rule`。延迟样本每分钟批量写入一次；恢复时丢掉为零的和超过 24 小时的样本。存活状态不恢复。

没设置 `--store db`，也没启用 `native_api.password_auth` 时，数据库故障按下面的方式处理：

- 数据库损坏：honk 取得实例锁后，把 `honk.db` 和 `honk.db-wal` 改名成 `honk.db.corrupt` 和 `honk.db.corrupt-wal`，再建一个新文件。
- 已有 `honk.db.corrupt`：honk 保留这两份文件，在删掉其中一份之前不做持久化。
- 数据库不可用、不安全，或被重置操作锁住：honk 记一条 warning，然后在不做持久化的情况下运行。不安全是指数据库不是 honk 用户所有的私有文件；重置锁由 `honk-core admin reset` 持有。

路径不安全时，`persistence_unavailable` 降级除了 `reason`，还会带一个 `rule`，取值是 `not_owner`、`group_or_other_bits`、`not_directory`、`not_file`、`symlink` 或 `identity_changed`。日志里给出路径和修复方法。

如果数据库来自更新版本的 honk 或其他程序，honk 在任何模式下都拒绝启动。因为移走该文件，会破坏只有原程序才读得懂的数据。

### 容量限制

维护任务每 60 秒执行一次。Selector 选择只为配置里的 Selector 组保留，延迟样本只为已配置的节点保留。一个组或节点要连续两次维护都不在配置里，对应的行才会删除；所以 reload 时短暂移除、后来又恢复的组或节点，原记录还在。每次维护都会删掉超过 24 小时的延迟样本和已过期的 DNS 行，并把最多 1 MiB 的空闲页还给文件系统。DNS 行最多保留 4,096 条，每批写入后先淘汰最早过期的行。

启动时，如果 `--store db`、`password_auth`、`store_subscribe` 或 `cache_file` 要求打开状态数据库，下面的设置会清空已存的缓存状态：

| 启动设置 | 清空的表 |
| --- | --- |
| `enabled: false` | Selector、延迟、Clash 状态与 DNS |
| 未设置 `enabled` | Clash 状态与 DNS |
| `store_dns: false` | DNS |
| 启用原生 API 或未启用 Clash API | Clash 状态 |

启动时没打开状态数据库，honk 就不会动这个文件。

状态数据库文件上限是 112 MiB。缓存写入为配置 revision 和订阅正文预留其中 24 MiB：某批写入如果会让已用空间超过 88 MiB，写入线程先把 DNS 行删到 2,048 条；仍然超出时回滚这批写入。跳过的 DNS 条目计入 `budget_skipped`，不算已写入。导入旧 `cache.db` 受同一预算约束：超出预算的复制不提交，下次启动再试。

### DNS 持久化

`store_dns: true` 时，每条应答是 `dns_answer` 表里的一行，内容是 `HDNS` version 2 编码，以精确缓存 key 的摘要作 primary key。恢复时只接受同时满足这些条件的行：没过期，且 key 摘要、规范 query wire、response wire 标识和当前 DNS policy 全部匹配。精确 key 里同时有入口 profile、request scope 和 operation，所以不会在不同 DNS 上下文之间混用。编码后超过 4 KiB 的条目不写入，并计入 `oversize`。

### 从 `cache.db` 升级

有状态数据库，且 `enabled` 不是 `false` 时，首次启动会导入 `path` 指向的旧
`cache.db`。绝对路径按原样使用；相对路径依次在 `global.data_dir` 下、
`/var/share/honk` 下，以及原配置目录的相对位置找已存在的文件。honk 只读本实例
`cache_id` 前缀下的 key，复制配置里 Selector 组在各网络上的选择，以及已配置节点
24 小时内的延迟样本。Clash 模式和 Clash GLOBAL 选择只在同时满足三个条件时复制：
`enabled: true`、原生 API 未启用、`clash-api` 构建里设置了 `external_controller`。
状态数据库里已有的行优先。旧版本按名称保存的 Selector 选择、DNS 应答和 FakeIP 记
录不导入，所以已持久化的 DNS 应答需要重新查询。

honk 按文件和 `cache_id` 在状态数据库里记录导入进度；旧版本即使重新建了该文件，
也不会再导入一次。其他 `cache_id` 仍能从保留下来的文件里导入各自的 key。如果
`cache.db` 是符号链接、不是 honk 用户所有的普通文件、能被其他用户写入，或者无法
当作 `cache.db` 读取，honk 会保留该文件并记一条 warning，下次启动再试。

数据库模式下，上述回退使用当前 revision 保存的原始入口目录；即使本次 `-c` 指向其
他位置、启动时不读取它，也不会改变旧缓存的位置。

`cache_id` 为空时，honk 随后删掉 `cache.db` 及其 `-wal`、`-shm`，但保留 `cache.db.corrupt-*` 副本。`cache_id` 非空时，这个文件可能被其他实例共用，honk 会保留它，只记一条 warning。之后旧版本再启动时找不到 `cache.db`，运行时状态从空开始。

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
