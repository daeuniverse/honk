# 原生 API、Clash API 与 `/stats` 参考

本页列出 honk 的原生 API、已实现的 Clash 兼容 HTTP 接口及其用户态统计快照。原生与 Clash API 的 feature、listener、凭据及 HTTP 边界相互独立，共用底层引擎 handles 与用户态统计。

## 原生 API

`native-api` Cargo feature 需显式启用：以 `--features native-api`（或 `native-ui`）构建；两种 allocator 发布产物均包含它及内嵌 UI（`native-ui`）。listener 默认关闭，须显式启用 [`experimental.native_api`](./experimental.md#native_api)。`--no-default-features --features native-api` 可脱离 Clash 使用。`.dae` 仍是配置格式；显式授权后可读取与替换已接受的源文件，或以 `--store db` 把 revision 记录在 SQLite 配置数据库中（见[配置数据库](#配置数据库--store-db)）。

原生契约（包括认证、节点/provider 管理、geodata 与自动策略 override）为 [api-standardize e6b0dbab5599689d965bc18a71be67c809d99d0f](https://github.com/daeuniverse/api-standardize/tree/e6b0dbab5599689d965bc18a71be67c809d99d0f)；`crates/honk-core/tests/fixtures/native_api_openapi.yaml` 跟踪该 bundle。原生 runtime mode 仍未开放，不声明 `full_transparency`。源管理要求真实 `.dae` 启动，写入还需启用 `config_write` 并配置非空 secret 或 `password_auth`。可用功能以 capabilities 和逐源权限为准，不按路由名称推断。

`Node.stream_transport` 是可选、可为 null 的字符串，投影已接受的 Trojan/VMess/VLESS 配置：`tcp`、`ws`、`grpc` 或 `xhttp`（包括 `splithttp` 别名）。无法识别或不适用时，honk 返回 null。该字段表示配置的传输方式，不表示协商结果或健康状态；`protocol` 与 TCP/UDP 健康传输字段的含义不变。它不暴露凭据、host、path、extra 选项或链接。测试 fixture 复制 doona 契约 bundle，保留其 `read_only_reason` 扩展（SHA-256 `ef3e1ce08392c26d256b70277318d61a7ec932f4f5825ac8117d839944a33646`）；此固定版本不代表已发布的前端版本。

| 方法 | 路径 | 含义 |
| --- | --- | --- |
| GET | `/api` | 公共 discovery：所有请求都能获得认证状态与登录 links；已放行的请求另外获得固定 `/api/v1` base 与全部契约 links。 |
| POST | `/api/v1/auth/setup` | 创建首个密码模式管理员并签发会话。 |
| POST | `/api/v1/auth/login` | 校验密码模式管理员并签发会话。 |
| POST | `/api/v1/auth/logout` | 撤销已认证的密码模式会话。 |
| GET | `/api/v1/version` | 原生契约身份、引擎构建版本以及构建的提交与目标平台，不伪造构建时间。 |
| GET | `/api/v1/capabilities` | 已实现资源与请求上限。 |
| GET | `/api/v1/runtime?detail=summary\|full` | 引擎 phase、已接受代次与具有独立时间戳的用户态流量。 |
| GET | `/api/v1/connections?type=all\|tcp\|udp&src=192.0.2.1&limit=100&detail=summary\|full` | 可见的活跃用户态连接；可选 `src` 必须为无端口 IP literal。 |
| DELETE | `/api/v1/connections/{connection_id}`、`/api/v1/connections` | 确认精确 transport owner 关闭；批量需过滤器或显式 `all=true`。 |
| GET | `/api/v1/flows`、`/api/v1/flows/{flow_id}` | 活跃及保留的终态用户态决策；detail 包含执行源头记录的 trace。 |
| GET | `/api/v1/nodes` | 稳定节点 ID、当前直接成员/订阅来源与真实测量。 |
| POST | `/api/v1/nodes` | 用 `{name,link}` 创建主文件节点；真实激活后才返回 201。 |
| GET | `/api/v1/nodes/{id}` | 单个节点，字段与列表相同；未知 ID 返回 404。 |
| DELETE | `/api/v1/nodes/{id}` | 删除主文件 inline 节点；激活后返回 `{deleted:0\|1}`。 |
| GET | `/api/v1/groups`、`/api/v1/groups/{groupId}` | 无副作用组观测、直接成员、配置 revision 与捕获的健康数据；列表按配置中的声明顺序排列。 |
| GET | `/api/v1/groups/{groupId}/config` | 组的 `policy` 与 `config`，以配置 revision 作为 `ETag`。 |
| PUT | `/api/v1/groups/{groupId}/selection` | 按直接成员 ID 设置 `tcp`、`udp` 或 `both` 选择；Selector 替换选择，自动策略组固定成员。 |
| DELETE | `/api/v1/groups/{groupId}/selection` | 清除自动策略组在 `tcp`、`udp` 或 `both` 上的固定成员。 |
| PATCH | `/api/v1/groups/{groupId}/config` | 对可写 `.dae` 来源执行受限 JSON Patch，返回真实更新 operation。 |
| GET | `/api/v1/events` | 有界且需认证的 SSE，支持绑定过滤器的续传游标。 |
| GET | `/api/v1/runtime/outbounds` | 共用计数生命周期内按 `kind/name` 区分的全宽出站计数。 |
| GET | `/api/v1/runtime/memory` | 实际进程 RSS 与可读的 cgroup v2 内存事实。 |
| GET | `/api/v1/runtime/traffic/history`、`/api/v1/runtime/memory/history` | 可选 `window_seconds`、`max_points`，均默认 600、范围 1–600。 |
| GET / PUT | `/api/v1/x-honk/runtime/mode` | 失败契约未完整固定，保持 `404 capability_not_supported`。 |
| GET / PATCH | `/api/v1/runtime/settings` | 原子读取/合并支持的日志、DNS 日志与 flow 留存设置。 |
| GET | `/api/v1/datapath` | 后端实际观测的程序、hooks、路由发布和 map 状态，未知项不推测。 |
| POST | `/api/v1/probes` | 有界的节点/组 TCP、HTTP、DNS 测量 operation。 |
| POST | `/api/v1/dns/query` | 显式 DNS 诊断。 |
| GET | `/api/v1/dns/cache`、`/api/v1/dns/log` | 精确缓存快照与客户端查询历史。 |
| DELETE | `/api/v1/dns/cache/{entry_id}`、`/api/v1/dns/cache` | 删除精确缓存 incarnation，或按完整名称及可选 type 删除。 |
| POST | `/api/v1/dns/cache/flush` | 等待内存与启用的持久化缓存失效确认，不清空域名路由事实。 |
| POST | `/api/v1/routing/trace` | 固定当前 generation 的无联网路由模拟，仅支持 `resolve=none`。 |
| GET | `/api/v1/rules` | 当前 generation 的完整规则字典、fallback 与可用来源位置。 |
| GET | `/api/v1/dns/rules` | 当前 generation 的 DNS 请求规则与响应规则，每个列表以 fallback 结尾。 |
| GET | `/api/v1/providers`、`/api/v1/providers/{id}` | 真实订阅 owner 状态，不在读取时拉取。 |
| POST | `/api/v1/providers/{id}/refresh` | 显式刷新订阅，并等待真实 runtime publication 的 operation。 |
| POST | `/api/v1/providers` | 用 `{name,kind:"subscription",url}` 及可选的 `update_interval`、`user_agent`、`cache` 创建尚未拉取的主文件订阅。 |
| DELETE | `/api/v1/providers/{id}` | 删除主文件 HTTP(S) 订阅及其已加载节点。 |
| GET | `/api/v1/geodata` | 读取流量/DNS 路由实际已加载资产的保留元数据。 |
| POST | `/api/v1/geodata/update` | 下载配置资产、完整校验后，通过 operation 激活精确候选字节。 |
| GET | `/api/v1/logs` | 结构化、安全投影的原生日志 SSE，独立于 Clash 格式化日志。 |
| GET | `/api/v1/config` | 认证后返回已接受的源快照、配置 revision 与安全诊断，仅遮蔽监听凭据值。 |
| GET | `/api/v1/config/sources/{source_id}` | 认证后返回单个已接受源的元数据及正文，仅遮蔽监听凭据值。 |
| POST | `/api/v1/config/validate` | `syntax` 或离线 `full` 校验，不写盘、不 reload。 |
| PUT | `/api/v1/config/sources/{source_id}` | RFC 9110 `If-Match` 保护的单源原文替换；写盘后排队真实 reload，返回 operation。 |
| POST | `/api/v1/config/sources` | 新建一个由 include 模式加载的 `.dae` 文件；写盘后排队真实 reload，返回 operation。 |
| POST | `/api/v1/operations/reload` | 从磁盘重新加载，返回 daemon-owned operation；body 留空或为 `{}`。 |
| GET | `/api/v1/operations/{id}` | 真实排队、运行及终态结果。 |

获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的连接数据。显示字段遮蔽监听凭据值。Connections 的 `detail` 默认 `summary`，`type` 默认 `all`，`limit` 默认 100、范围 1–1000。拒绝重复单值或未知 query 参数。先过滤，再统计总量与应用 TCP+UDP 合计 limit；按注册观测时间降序、相同时间按 ID 字典序升序排列。total 是匹配的完整可见数量。IPv4-mapped IPv6 来源按 IPv4 比较。summary 省略 `src/dst/domain`，full 包含它们，未知 domain 为 null；full 不表示更高权限。

连接 `outbound` 是选路当时的组/动作，不是当前叶节点或重建选择。启用记录时，`flow_id`、捕获的 root-first 组/叶 ID、首次观测 UTC、domain 来源与用户态 rule ID 关联保留证据；缺失或淘汰的证据保持 unknown。逐连接 rate 仍为 null。空列表是 `visibility: partial`，不代表设备没有连接。Mock 数据面显示 disabled/none；真实后端只依据实际程序、hooks、routing root、listener 和 admission 观测报告状态，未知项为 unknown/null，覆盖仍为 partial。HTTP 就绪不等于数据面就绪。

TCP 在 copy 成功读取或 splice 成功写入目标 socket 时实时入账，成功写出的嗅探前缀仅计一次；UDP 保持原逐包语义。唯一的一秒 sampler 使用实际时间间隔；初次采样、reset 和 overflow 返回 null rate，不补零。`counter_since` 属于共用计数器生命周期，`sampled_at` 属于流量样本，`observed_at` 属于 HTTP 观察。UInt64 使用十进制字符串，有界数量仍为 JSON number。`process.cpu_percent` 在获得两次可用 CPU 样本前为 null，见[出站、内存与历史](#出站内存与历史)。`generation.activated_at` 是当前 generation 的发布时间，启动 generation 取引擎首次进入运行状态的时间。配置激活进行期间，`generation.state` 为 `reloading`；引擎运行且健康时，`lifecycle.state` 同为 `reloading`。有源管理器时提供配置 revision，`last_reload` 提供最近完成的 API reload operation 结果，否则为 null。

`degradations` 列出因故障降级但仍在运行的功能，每个组件最多一项。每项是一个安全错误（`code`、`message`、`details.reason`），另带 `component` 与 `since`；`since` 是该组件首次降级的时间，重复故障不更新。空列表表示没有已知降级；这些条目不改变 `lifecycle.state`。条目新增、变化或清除时发布 `runtime.updated`。组件：`persistence`（启动时无法打开或重置状态数据库）与 `state_cache`（无法打开其缓存表）在重启后清除；`quic_probe`（Score 组需要 QUIC 探测，但第一个 `tcp_check_url` 不是 HTTPS URL、主机无法解析或无法创建 QUIC 客户端；原因为 `restart_required` 时，启动时没有 Score 组，由重载加入）在应用的配置不再含 Score 组时清除，否则在重启后目标解析成功时清除；探测目标在启动时确定。`pname_routing`（路由规则使用了 `pname()`，但数据路径没有 cgroup v2 hook，`pname()` 条件无法获取进程名，肯定条件永不匹配，否定条件总是匹配；原因为 `comm_fallback` 时规则匹配线程名而非 argv）在每次应用配置后重新判定。使用真实 eBPF 后端时，`iface_watch`（接口监视器无法启动）在重启后清除；`udp_trace`（记录流时内核 UDP 接收追踪不可用）在每次启动 UDP 监听器时重新判定。

所有认证模式都公开 `GET /api`。密码 setup 与 login POST 也公开；version、capabilities 及其他 API 资源要求配置的静态 bearer 或有效密码会话。上述例外只针对不带凭据的请求：带有凭据的请求无论是否公开都会校验，错误或重复的凭据直接拒绝，不回退为匿名。query string 中的 token 一律拒绝。现有无 secret 开发模式要求显式匿名 loopback 授权，并拒绝 `Sec-Fetch-Site: cross-site`。Host 与 Origin 校验先于这些认证例外执行，也覆盖公共静态文件。OPTIONS preflight 无需 bearer，但必须通过 Host、Origin、method 与 header 白名单。不返回 cookie credentials 或通配 CORS。

已知禁用 action 返回 JSON `404 capability_not_supported`，未知 path 返回 JSON `404 resource_not_found`；已知资源不支持的 method 返回 JSON `405 method_not_allowed`，并带 `Allow`（GET 资源含 HEAD）；配置来源可读但未授权写入时，PUT 返回 `403 permission_denied`。错误信封为 `{error:{code,message,details},request_id}`。HEAD 保留 GET 状态/header，无 body。API 响应带 `no-store` 与 `nosniff`。应用上限为规范化 target 4096 字节、规范化 header 名/值合计 16384 字节、body 65536 字节（含 chunked）；已认证 GET/HEAD 携带非空 body 会被拒绝。普通观测读取不触发 probe 或选择变化；显式 `/dns/query` 是可联网的诊断请求。

错误的 `details` 只指出被拒绝的对象，不回显提交或配置的值。请求边界错误给出 `header` 或请求部分（`field`：`query`、`body` 或 `target`）及 `kind`。JSON 请求体无法解析或不符合 schema 时，该端点返回 `400 invalid_request`，`details` 为 `{field,kind}`：`field` 是出错成员的点分路径（如 `sources[0].content`）、含未知键的对象或 `body`；`kind` 为 `invalid_json`、`missing`、`wrong_type`、`unknown_field`、`duplicate`、`invalid_value` 或 `too_large`。422 `unsupported_value` 给出被拒绝的 `field` 或 `fields`，并视情况给出受管条目的 `resource` 路径、`allowed` 可选值或路径、未通过的 `check`，或可放行该请求的 `settings`。

原生 server 最多拥有 64 条 HTTP/1.1 连接，满时暂停 accept，header 读取上限五秒；关闭时全部连接共享五秒 graceful drain，随后 abort 并逐一 join。30 秒读空闲期限仅在连接没有进行中请求时生效（自请求 body 结束至响应完成），停滞写入另受 30 秒期限约束；SSE heartbeat 成功写入使健康长连接保持活跃，读取不能延长阻塞 writer 的期限。TLS/HTTP2 可由可信反代终止。Forwarded headers 不改写固定 discovery path，也不授予 Host/Origin 权限。

密码模式先关闭凭据准入，再执行上述 HTTP grace，随后等待真实的阻塞凭据任务结束。五秒 HTTP 预算不限制最后的 KDF/数据库 join。

**HTTP 传输边界：** Hyper 可在应用处理前以 400/414/431 或断连拒绝畸形/硬超限 HTTP；这些 transport 拒绝不保证 JSON 信封或应用 headers。

应用 target/header 上限作用于 Hyper **解析并规范化后的表示**，不是原始 wire 字节。Hyper 可能先移除 request-target fragment，或合并相同 `Content-Length` 字段，再交给应用计量；这些形式的原始文本即使超过应用上限，也可能得到正常响应而不是 413。原始输入仍受 Hyper 传输处理约束。这是已接受的边界差异，不另写 HTTP parser，也不宣称原始 wire 大小保证；body 限制仍覆盖全部交付的 body 字节。

配置 `ui` 后，`/` 与 `/ui` 重定向到 `/ui/`。目录托管保留无扩展名 SPA fallback；缺失静态资产、fonts/icons、manifest 或 service worker 返回 404，不返回 HTML。以 `--features native-ui` 构建（发布产物已启用）并设置 `ui: embedded`，即可直接提供固定真实 doona 产物，不解压到磁盘、不联网。其 hash router 使用 `/ui/#/...`；其他合法内嵌导航路径重定向回 `/ui/`，确保相对资产与 service worker 路径正确。内嵌 UI 以预压缩形式存储，浏览器接受时以 brotli 或 gzip 传输；目录托管以同样方式提供管理员放置的 `.br`/`.gz` 同名文件。`assets/` 下带内容哈希的文件按 immutable 缓存一年，其他静态响应使用 `no-cache`。静态响应带 `nosniff`，不带 framing header，以便 LuCI 等面板嵌入 UI；需要防御 clickjacking 的部署应在反向代理添加 `X-Frame-Options` 或 `Content-Security-Policy: frame-ancestors`。公开资产仍经过 Host/Origin 校验。Discovery 与密码 setup/login 使用上述公共例外，其他 API 请求要求 bearer；不向 UI 注入凭据。

### 认证发现与密码会话

Discovery 返回 `auth: {mode, setup_required, anonymous_loopback}`。配置非空 `secret` 或使用匿名 loopback 开发模式时，`mode` 为 `token`；`secret` 为空且启用 `password_auth` 时为 `password`。仅在密码模式尚无管理员记录时，`setup_required` 为 true。仅在实际 loopback 监听上显式启用开发模式时，`anonymous_loopback` 为 true。密码模式下，`links.auth_setup`、`links.auth_login`、`links.auth_logout` 为对应 endpoint 路径；其他模式下均为 null。

未被放行的无凭据请求只获得 `name`、`api_major`、`links.auth_setup`、`links.auth_login`、`auth.mode` 与 `auth.setup_required`，其余字段省略。通过 bearer、会话或显式匿名 loopback 放行的请求获得完整响应。

Token 模式不提供三个密码 endpoint，返回 `404 capability_not_supported`。密码模式使用以下契约：

| Endpoint | 请求与成功响应 | 模式特定失败 |
| --- | --- | --- |
| `POST /api/v1/auth/setup` | `{"username":"admin","password":"..."}` → `201 {"token":"hnk1_…","expires_at":"..."}` | 对端地址不符合要求时返回 `403 permission_denied`；首个管理员发布后返回 `409 setup_already_completed`。 |
| `POST /api/v1/auth/login` | 相同 body → `200 {"token":"hnk1_…","expires_at":"..."}` | setup 前返回 `409 setup_required`；用户名或密码错误均返回 `401 invalid_credentials`。 |
| `POST /api/v1/auth/logout` | `Authorization: Bearer <session>` → `204` | 无效或过期会话按普通 bearer 认证失败。 |

`expires_at` 是 RFC 3339 UTC 时间戳。Setup 与 login 要求 `Content-Type: application/json`，不能携带 query string 或未知 JSON 字段，body 最多 4096 字节。用户名区分大小写，必须是匹配 `[A-Za-z0-9_.-]{1,64}` 的 ASCII。密码须为 8–128 个 Unicode 标量值，UTF-8 编码最多 512 字节。无效 JSON 或字段返回 `400 invalid_request`；缺少或使用其他 media type 返回 `415 unsupported_media_type`。

Media type 不区分大小写。重复或非文本的 `Content-Type` 值返回 `400 invalid_request`；配置、认证、probe 和路由诊断共用同一 JSON/header 解析边界。

Setup 只信任 accept socket 的对端地址，不读取 `Forwarded`、`X-Forwarded-For` 或其他 header。允许范围为 `127.0.0.0/8`、`::1`、RFC 1918、`fc00::/7`、`169.254.0.0/16` 及 `fe80::/10`；IPv4-mapped IPv6 按 IPv4 分类。其他对端在读取账户状态或处理凭据前返回 `403 permission_denied`。

Setup 与 login 每分钟按规范化对端最多接受 5 次尝试，全局最多 10 次。连续 5 次凭据校验失败触发 60 秒全局锁定。拒绝尝试时返回 `429 rate_limited` 与 `Retry-After`；计数器与锁定状态仅保存在进程内。 成功的 setup/login 同样计入这些窗口；连续失败锁定是全局的，不是逐 peer 锁定。

凭据任务最多同时运行一个，并移出 Tokio worker；重叠请求返回 429 与 `Retry-After: 1`。HTTP 取消不会释放该任务的位置或丢弃其凭据处理结果。Discovery 只读取短时持有的凭据状态，不等待跨 KDF 或数据库 I/O 的锁。

会话 token 是不透明的 `hnk1_…` 值，通过 `Authorization: Bearer <session>` 使用。每个会话固定有效 12 小时。进程只保留 token 的 SHA-256 digest，最多保留 32 个有效会话；签发新会话时淘汰最早会话，重启结束全部会话。会话因 logout、过期或被淘汰而结束时，用它打开的 `/events` 与 `/logs` 流随之关闭；客户端须重新认证后再连接。通过配置 secret 或密码登录启动的 operation 属于管理员，而非某个 token，因此 logout 不删除 operation。

密码模式把唯一凭据记录保存在状态数据库 `<data_dir>/state/honk.db` 的 `admin` 行中（文件权限 0600，目录 0700，见[配置数据库](#配置数据库--store-db)）。记录畸形时拒绝启动；状态数据库损坏时同样拒绝启动，密码模式不会把它移走。

记录使用 PBKDF2-HMAC-SHA256、100,000 次迭代及新生成的 16 字节随机 salt。密码模式直接使用配置的 `global.data_dir`：该目录不可用时启动失败，不回退到其他目录，以免在别处重新开放 setup。首次 setup 插入该行，不替换已有记录，因此两个进程在同一个状态数据库上同时 setup 时只有一个成功。写入开始前数据库忙碌，或插入失败且已回滚时，setup 失败，可以重试。提交或该回滚失败时，由于该行是否已持久化无法确定，进程在重启前拒绝登录和再次 setup。

Setup 占有凭据状态后，discovery 返回 `setup_required:false`，耐久性不确定时也不重新开放。无法确认写入时返回 503 与 `durability_confirmed:false`，不带 `Retry-After`，不声称 `written:true`；须重启才能重新确认数据库中的账户状态。

不提供 HTTP 密码重置。恢复访问时，停止 honk，执行 `honk-core admin reset`，重启后重新 setup。把 `<data_dir>/state` 整个移走也能恢复，但会丢弃所有其他持久化状态。

Reset 在检查数据库是否存在前取得状态目录的排他锁，因此不会与正在创建数据库的首次启动竞态。

### 用户态记录流

获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的 flow 数据。

客户端通过 GET 建立且获准的 `/events` 或 `/logs` SSE 流仍连接时，通用 attachment 有效。最后一条流关闭后，或成功 GET `/flows`、`/flows/{id}`、`/dns/log` 后，通用 attachment 保留 60 秒。它只启用普通事件捕获，不开启任何 Auto 诊断 recorder；诊断需求独立：

| 获准请求 | Auto 诊断需求 |
| --- | --- |
| `/events` 显式 flow kinds 或有效 flow 事件 `flow_id` 过滤器 | 仅 flows |
| 成功 GET `/flows` 或 `/flows/{id}` | 仅 flows |
| GET `/logs` SSE | 仅日志 |
| 成功 GET `/dns/log` | 仅 DNS 日志 |
| 无过滤/非 flow `/events`、普通 API、validation、失败 GET 或 HEAD | 无 |

Flow 事件需求指显式 `kinds` 包含 `flow.updated` 或 `flow.gap`，或非空白 `flow_id` 的有效 kinds 包含 flow 事件。没有该过滤器且省略 `kinds` 时，不请求 flow 记录。每条获准的流独立持有本次请求所需的租约；准入失败不取得租约，关闭/Drop 即释放，即使从未 poll。Flows、日志、DNS 日志各自在最后一条对应流关闭后，或对应 GET 成功后，保留独立的 60 秒需求宽限期。通用活动和其他需求不能延长该期限。没有 DNS-log SSE kind。记录从需求建立时开始，因此首次历史为空。

`record_flows` 默认为 true，允许在 flow 诊断需求有效时记录。显式运行时设置 `record_flows: "on"` 可在无客户端时持续记录；运行时 `"off"` 强制关闭，配置中的 `record_flows: false` 禁止记录，修改后需重启。实际记录停止时释放 flow 记录和快照。进程内最多保留 1024 条 flow、每条 64 个步骤，含快照与内核字典预留的总预算为 8 MiB。终态最多保留 300 秒，压力下可提前淘汰，重启清空。由既有 sampler 清理，不新增 timer。

内核 witness 生产通过既有组合 datapath flags 跟随实际 flow 记录状态。既有 sampler 在后续 tick 同步变化；调度、telemetry 与发布锁竞争可能延迟收敛，不承诺固定一秒内完成。启用发布前已路由的流量可以明确报告内核证据缺失。关闭需求不丢弃已保留的 witness/字典，不改变路由或 NFQUEUE 权威，也不撤销操作已经取得的捕获资格。未录制的操作跳过 witness 解码。

Flow ID 表示 incarnation，不是五元组。TCP/UDP 捕获真实执行的路由谓词与短路、嗅探/校验、群组选择、DNS 子查询、物理尝试、会话复用/重试及终态边界；拨号失败或阻断即使没有 live connection 也保留。名称、ID、代次来自实际使用它们的操作，不按当前配置或路由模拟重建。DNS lookup/parent ID 与 outbound attempt/parent ID 保留因果关系；复用 carrier 记录为 attachment，不伪造新物理拨号。协议请求/确认 milestone 必须有真实协议证据，DNS 子步骤就绪不能成为业务目标确认。TCP/UDP 终态跟随所属清理边界；内核 offload 以 unknown 结束观察，不伪造 closed。

只有该 flow 范围内截至当前进度已执行的决策均被捕获，`trace_status` 与 `trace.status` 才是 `complete`。Active、failed、closed 均可完整；这不代表成功或全局覆盖。来源缺失/歧义、监听凭据值遮蔽及捕获预算耗尽，会保持 `partial` 并列出 `missing` 原因；达到 trace 上限不停止转发。用户态 TCP/UDP 和截获 DNS 的总体覆盖仍为 `partial`，仅内核处理的 direct/block/bypass 仍为 `none`，不开放 `full_transparency`。

每条 flow 的条件表达式使用与编译代次一起缓存的配置来源写法，GeoIP 保留引用而非展开后的网段列表。这避免了仅因展开而发生的截断，不取消真实捕获上限：原始配置文本超限、遮蔽、来源缺失及步骤/字节预算耗尽仍报告为 partial trace。

交接流量的内核规则结果来自编译程序实际执行的分支 witness，不做用户态重算。UDP 还必须使用收到报文携带的 capture ID；五元组、decision token、路由代次与动作均须匹配保留 witness，后来的同元组 incarnation 不能为旧报文提供证据。Capture ID 不回绕。冻结字典最多 16 份、每份 64 KiB、总计 1 MiB，计入 recorder 预留；字典拒绝/淘汰、witness 缺失、TCP 对应歧义及实际执行超出 256 个规则/条件值，都会使证据不完整；仅未执行的规则超出该值上限，不代表执行证据丢失。

若策略的内核追踪字典会超过 64 KiB，启动和 reload 时该策略都以关闭内核路由追踪的方式发布并记录警告，其 flow 报告 `kernel_trace_not_captured`，不再产生无法解码的 witness。检查按最长的代次编号估算规则 ID，因此恰好处于上限附近的策略可能已按关闭追踪发布。

原生扩展字段保留来源细节而不虚构身份：路由输入可携带 `ingress`、`domain_fact_bitmap`、`domain_fact_state`，不伪造 domain rule ID；DNS 关联的 outbound/connection step 带 `lookup_id`，已知物理对端带 `server_addr`。选择事实保留健康 IP 族以及实际应用还是仅 peek。Score 的 `previous_leaf_node_id` 与 `previous_member_id` 分开：叶节点历史不能重建过去经过的子组路径。

Flow list 接受 `network/state/connection_id/detail/limit/cursor`。最多八份有界不可变 snapshot，TTL 30 秒，游标绑定 instance 与原过滤器/detail。可识别的游标带不同过滤器、detail 或 limit 时返回 `400 invalid_request`。表满时淘汰最旧 snapshot；保留字节预算耗尽才返回 `503 snapshot_unavailable` 与 Retry-After。过期或被淘汰的列表返回 `410 snapshot_expired`，已知淘汰 ID 的有界 tombstone 返回 `410 flow_expired`，未知 ID 返回 `404 resource_not_found`。Detail 不接受 query，始终返回保留的 full input/trace。计数为十进制字符串，revision/seq/elapsed_us 为 safe JSON number；显示字段在 512 字节 `MAX_TEXT` 上限内保留路径、`@` 和 URL；标识符仍单独校验。无法表示或超限的文本、步骤/字节预算溢出仍明确报告为不完整证据，不丢弃因果 ID 或结果。保留的规则展示属于捕获时的代次，不从当前配置重建。

### 节点与组

节点读取接受 `group_id`、`limit`（1–1000）及 `cursor`；只筛直接成员，不展开叶节点。节点分页最多八份 snapshot、30 秒、4 MiB，冻结分页期间观测；放不下时返回 `503 snapshot_unavailable` 并带 `Retry-After`；无法识别的游标返回 `410 snapshot_expired`，可识别但过滤器或 `limit` 不同的游标返回 `400 invalid_request`。Groups 返回摘要数组；detail 含 `config_revision`，不带 `ETag`；`GET /groups/{groupId}/config` 返回 `{policy, config}`，并以该 revision 作为带引号的 `ETag`。组 ID 为进程生命周期随机身份：同名 reload/重排保持，删除再添加获得新 ID，重启重新发现；不使用位置 UUID 或名称 hash。

节点名、订阅标签、组名/成员名、icon、检查 URL、final 出站标签和出站计数名称，采用与源内容/flow 显示相同的监听凭据遮蔽规则。节点快照在有界序列化前遮蔽凭据，续页保留同一份已遮蔽字节；不修改不透明 ID、revision hash、成员身份或游标绑定。
遮蔽阈值不变：不足八字节的监听凭据值不遮蔽，启动时会发出警告。

健康数据来自 producer 已完成且符合资格要求的测量，不把乐观的 alive 标志、跨 IPv4/IPv6 复制的排名信号、合成失败或从缓存恢复的延迟当作真实测量。原始 TCP、HTTP 响应头、DNS 交换和 QUIC 握手测量保留实际目标地址族与完成时间。节点行另带每个测量维度的两个平均值，仅由成功的原生探测累计，重启后清零：`moving_avg_ms` 是 URLTest 排名使用的减半平均 `(previous + sample) / 2`，`avg10_ms` 是最近十次成功探测的算术平均（预热期不足十次时按已有次数）；测量行不可用时二者为 null，针对特定组的测量中恒为 null。未知的排名和冷热状态保持 null/unknown。针对特定组的测量保留测量时的成员和叶节点，不绑定到后来的选择。GET 不推进 URLTest、轮询或 Score 状态；`icon` 返回通过配置校验并应用监听凭据遮罩的 HTTP(S) URL 或 data URI，未配置为 null，不猜测或抓取图标。

`PUT /groups/{groupId}/selection` 的请求体为 `{"member_id":"<direct-member-id>","network":"tcp"}`，`network` 必填，另接受 `udp` 或 `both`。向 Selector 写入会替换其选择，报告 `source: runtime`。TCP 与 UDP 的选择分开保存，仅写入 TCP 不改变 UDP，`both` 在发布前一次校验两个网络，并原子发布选择；对自动策略组（`can_override: true`）的写入会固定该成员，报告 `source: override`；固定成员不可用时不改选同组其他成员。固定只存在于运行时，不持久化，每次配置激活（包括订阅刷新）都会清除，健康检查照常执行。`DELETE /groups/{groupId}/selection?network=` 清除 `tcp`、`udp` 或 `both`（默认）的固定，返回 `GroupOverrideCleared` 与各网络当前选择；未固定的网络保持原选择，对 Selector 返回 `409 state_conflict`。原生与 Clash 写入都由同一 control/reload 所有者串行处理，并更新既有持久化和预热逻辑，Clash 写入等价于 `both`，读取 `now` 是 TCP 投影。返回独立的 `selection_revision` 与实际 `connections_interrupted`，不将选择 revision 当作配置 ETag。启用 `interrupt_connections` 时，按流量建立时捕获的组身份/路径和发生变更的网络关闭旧所有者，而非按当前可达叶名称删除记录；重复写入当前选择不触发中断。关闭确认失败可能在选择已发布后报错，不承诺回滚。

组 PATCH 需要 `Content-Type: application/json-patch+json`、非空 RFC 6902 数组（最多 32 项）及按 accepted revision（`GET /groups/{groupId}/config` ETag）求值的 RFC 9110 `If-Match`；列表与多个 header field line 合并，weak tag 永不匹配，`*` 匹配已存在的组。缺失为 428，条件不再匹配为 412；检测到并发源/依赖变化而条件仍成立时为 409。操作对象中 `op`、`path`、`from`、`value` 以外的成员一律忽略。请求体错误（400、413）先于过期的 `If-Match`（412）报告。仅允许 `/policy`、`/config/default_member_id`、`/config/final_outbound`、`/config/tolerance`、`/config/idle_timeout`、`/config/interrupt_connections`、`/config/check_url`，支持 `add/replace/remove/test/copy/move`，其中路径和值类型均受上述字段约束。Policy 值如 `{"kind":"selector","native":"selector"}`，两者必须匹配；默认成员用直接成员 ID，final 用出站名称，tolerance/idle timeout 用非负安全整数或 null，`interrupt_connections` 用布尔值或 null；`check_url` 为 null，或以小写 `http://`/`https://` 开头、含主机的 URL，不含 userinfo、空白、控制字符与逗号，也不同时含单引号和双引号；PATCH 写入 GET 显示且探测实际发送的规范化形式（去掉 fragment、空路径补 `/`、主机转小写、省略默认端口），不超过 2048 字节，`test` 也按此形式比较。Selector 组接受并保存 `check_url`，但不据此探测。只有 URLTest 组报告并接受 `tolerance`：其他策略报告 `null`，`mutable_config` 不含该字段，把它设为非 null 值的 PATCH 返回 422 `unsupported_value`；允许 `remove`，同一 PATCH 把策略改为 URLTest 时可以设置。删除字段或设为 null 会恢复 dae 默认值。组来源未设置 `tolerance` 与 `interrupt_connections` 时，GET 报告 `null`，honk 仍按默认值（`interrupt_connections` 为 false）或 `global.check_tolerance` 生效。此接口不改成员列表或 icon。

源不可写时 `mutable_config` 为空，PATCH 返回 `404 capability_not_supported`。PATCH 只修改 parser 定位的可写源片段，保留其他原文字节、注释与 include 结构；权限、完整离线校验、耐久替换与 operation 幂等复用配置来源协调器。其 `If-Match` 是 accepted 组/配置 revision，**不是**文件 SHA-256：写前校验 revision，同时独立检查源字节 hash 和依赖拓扑，真实激活前还会在 reload lock 下再次检查 accepted revision。并发 provider publication 可在写后使激活被拒绝，此时 `written:true,committed:false`，磁盘不回滚。自动策略 pin/clear 可用（`can_override: true`）；仅原生 runtime mode 与完整内核透明性继续 gate。

### 原生事件

使用带 Bearer 与 `Accept: text/event-stream` 的流式 fetch；浏览器 EventSource 不能设置所需 Authorization。可选 `kinds/flow_id` 绑定续传游标。最多保留 512 个事件、60 秒，支持 16 个 client，每个 client 的 live 队列最多 64 条。队列满时断开流，不静默 skip 事件。16 个名额已满时，新连接返回 `503 temporarily_unavailable` 并带 `Retry-After`。每 15 秒发送 heartbeat。每个连接都先发送 ready；有效续传的顺序为 ready→replay→live，ready 保留请求游标，之后由 replay 推进，原子挂接不留空窗。过期、未知、旧实例或不同过滤器的游标在 HTTP 200 前返回 `409 event_cursor_expired`。

每条事件/日志记录最多为其首个精确过滤绑定缓存一份完整 frame；其他绑定仍独立签名。既有 2 MiB 留存 ring 预算在发布前预留 payload、一份可能的缓存 frame 及 cache cell，因此接近单条上限的 payload 可能在达到条数上限前过期。该 ring 预算不是所有排队或 HTTP 持有引用的进程级内存上限。

新连接的 ready 游标是不透明检查点，不是保留的事件记录。旧历史已经过期时，新签发的检查点仍可立即续传；它不会恢复已淘汰的记录游标，也不能跨过更新事件的丢失。时间、过滤器、instance 与记录重置检查保持有效。顺序指投递/重放位置，不是游标字节的排序。

发布的事件包括 `stream.ready/runtime.updated/flow.updated/flow.gap/generation.changed`，以及反映实际 operation 状态转换的 `operation.updated`。operation store 不依赖是否具有可写 `.dae` 来源。generation 事件只来自已接受的发布，不来自 reload 请求接收。事件仅含有界的安全 ID/状态，不含报文正文或原始配置。Flow/event 记录只保存在内存中，不是持久化日志。

`flow.updated` 是失效通知：通过其 `href` 读取最新保留 revision。每个客户端的 live 队列只保留同一 flow 尚未发送的最新通知，并按新事件序号追加到队尾；revision 可以跳跃，但发送游标保持有序。发布仍是即时的，包括终态更新，不增加批量定时器。事件捕获开启时，重放环记录每次发布，replay 不做合并。其他事件类型和日志不合并；不同 flow 或其他不可替换事件仍会在 live 队列满时断流。Flow 数据、revision 与捕获的 trace steps 不变。

客户端已连接，或获准的记录器通过显式运行时设置持续开启时，事件捕获开启。空闲事件中心仍接受新流；停止捕获后，旧事件游标失效。事件开启时，手动或自动记录切换通过 `flow.gap` 的 `reason=recording_changed` 表示记录连续性中断，不表示丢包或未捕获的 flow 数量。空闲事件中心不重放关闭时的 gap；重新连接建立新的记录边界。

### 出站、内存与历史

`runtime/outbounds` 复用逐出站账本，不按 HTTP 客户端建立计数器。`kind` 区分 `builtin/node/group`，名称可能相同，不能只按 name 合并。累计连接、upload/download bytes 与 errors 保留完整 UInt64 十进制字符串；`active_connections` 为 safe JSON number。计数与 `counter_since` 属于共用 StatsManager 生命周期，reload 不清零。

`/runtime` 的 `process.cpu_percent` 是进程 CPU 时间（`CLOCK_PROCESS_CPUTIME_ID`）增量除以采样器实际经过的墙钟间隔，以单个 CPU 为 100% 计：一个核心满载为 100，多线程负载可超过 100。名义采样周期为一秒；取得两次可用样本之前，或读数不可用、时间/计数倒退、墙钟间隔为零时，返回 null。

RSS 来自 `/proc/self/status`；cgroup v2 依据实际 membership/mountinfo 定位，读取 `memory.current`、`memory.max` 与 `memory.events`。不可读取或未知的值为 null，不伪造零；`memory.max=max` 的 limit 为 null，cgroup scope 保持 unknown。Capabilities 只声明实际读到的 metric，启动时即读取一次，不等第一次采样；`kernel` 为 null，不宣称内核内存核算，也不把 RSS、cgroup 和 kernel 相加。

`record_traffic` 与 `record_memory` 默认 true。两种 history 共用既有的一秒 sampler（错过 tick 使用 Skip），无客户端也记录；各最多 600 点、600 秒，仅存内存，重启清空。设 false 并重启后释放对应缓冲，history 返回 `404 capability_not_supported`，即时 runtime/outbounds/memory 仍可读。`max_points` 从最新点向前按能满足上限的最小 stride 抽取，再按时间从旧到新返回；`sampled_every_seconds` 表示该名义 stride，不保证无缺口。保留原始时间戳、null 与采样缺口，不插值或补零。

### 配置来源、校验与操作

只有真实 `.dae` 启动加载时捕获的源集合才启用配置管理；程序内构造的 Config 或 serde 格式加载不能冒充无损来源，其配置能力不可用。GET 返回最后已接受的快照，不临时重扫磁盘。源 ID 不含路径，源 `path` 与规则 `file` 保留规范化的入口目录相对名称（例如 `config.d/routing.dae`），源 `absolute_path` 另行提供规范化绝对路径；原文 SHA-256、字节数、加载时间与逐源 `writable` 单独提供。源集合与校验最多 32 个来源、8 MiB 原始字节，依赖的每次实体化也计入数量和字节预算；geodata 文件是引擎本来就整体加载的运行时资产，只参与哈希冲突检测，不计入预算；HTTP JSON body 的 64 KiB 上限仍独立生效，超限返回 413。因此 capabilities 中 `config.max_bytes` 为 61440，即 65536 字节正文上限扣除 4096 字节创建信封后单次请求能携带的最大替换或新建内容；`config_validate.max_bytes` 为 8 MiB 预算，因为完整校验还计入从磁盘读取的依赖。`resources.config` 不含 `content` 字段；替换或新建正文超过 `config.max_bytes` 时返回 `413 request_too_large`。

获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的配置数据。已接受正文包含普通凭据、分享链接及路径；仅遮蔽声明的原生/Clash 监听凭据值，包括重复、被覆盖的声明及这些值在源中其他位置的出现。解析器提供的范围用于识别凭据值，非凭据文本与行结构保持不变。凭据源仍只读，哈希仍对应原始字节。写入内容含有被遮蔽的值（原文或 JSON 转义写法）时返回 `403 permission_denied`。不足八字节的值既不遮蔽也不拒绝写入，可以写进普通源，读取时原样返回。必有的 `secrets_redacted` 布尔值表示是否遮蔽了监听凭据值；遮蔽后的正文不能用于编辑后回写。

启用 `config_write` 且配置非空 secret 或 `password_auth` 时，已接受的非凭据主文件与所有非凭据 include 均可写。只有已接受的源 ID 授权替换，新建只接受由 include 模式加载的新 `.dae` 路径，调用方提供的路径不能授权任意文件写入；generated/subscription 来源不可写。普通 include 仍使用原有入口相对 glob、排序、无匹配及重复/越界检查语义。API 禁止修改原生设置或改变、移动 API 凭据；如需编辑含凭据主文件，先在本地把凭据迁到专用只读 include 并重启，不能通过 API 完成迁移。

配置写入被拒绝时，`details.reason` 给出原因，并与 `stage` 等其他 details 字段合并；非对象 details 保存在 `value` 中；`code`、`message` 与 HTTP 状态不变。每个响应只给出第一个未通过的检查：`writes_disabled`（未启用 `config_write`，或既未配置 secret 也未启用 `password_auth`）；`configuration_unavailable`（配置协调器未运行）；`listener_secret_source`（该源声明了原生或 Clash 监听凭据，或写入后会声明）；`listener_secret_in_content`（该源或写入内容含有监听凭据值；数据库模式下也包括源路径含有该值）；`listener_settings_changed`（候选配置相对当前运行配置修改了 `experimental.native_api`、`clash_api.secret`，或在数据库模式下修改了 `global.data_dir`）；`credential_sources_changed`（本次写入，或上次 reload 后的磁盘编辑，改变了声明监听凭据的源；reload honk 后重试）；`import_entry_changed`（`-c` 入口不是数据库当前 revision 的入口）；`unsafe_path`（存储拒绝目标路径）。这些原因出现在源 PUT、新建、import 与 revision 激活返回的 `403 permission_denied`，Group PATCH 与节点、provider 写入返回的 `404 capability_not_supported`，节点、provider 的源写入被拒后返回的 `503`，以及存储拒绝新建源时的 `400 invalid_request`。数据库 import 在凭据字段之外仍有监听凭据值时返回 `422 unsupported_value`，原因是 `listener_secret_in_content`。源写入与管理写入先检查 `writes_disabled`，再检查 `configuration_unavailable`；候选配置依次检查凭据声明、正文中的凭据值、凭据源变化、监听设置变化。其他拒绝不带 `reason`。带原因的拒绝以 WARN 级别写入请求日志行，附带 `reason`，不记录路径或内容；原生 `/logs` 显示这一行的 `reason` 与 `status`，其他请求行仍 withheld。

`GET /config` 列出的源为 `writable: false` 时，`read_only_reason` 给出原因；源可写时没有该字段。原因只反映已接受的快照，给出第一个未通过的检查：`writes_disabled`、`store_blocked`（数据库模式下记录失败，在重新激活 head revision 前拒绝写入）、`listener_secret_source` 或 `listener_secret_in_content`，含义同上。`GET /config/sources/{source_id}` 与 `writable`、`loaded_at` 一样不返回该字段。源文本含有监听凭据值时，该源保持只读，honk 照常运行：启动时以及每次接受 reload（包括无变化的 reload）后，对每个这样的源记录一条 WARN 日志，包括声明凭据的源及未启用配置写入的情况；日志给出源 ID 与按列表方式脱敏的路径。换用任何源都不含的 secret 后，该源恢复可写。

校验使用 `Content-Type: application/json`，例如 `{"mode":"syntax","sources":[{"id":"candidate","content":"..."}]}`；mode 可选 `syntax` 或 `full`，每个 source 的 id/path 可省略。`syntax` 只解析提交的文档，path 仅作来源标签，不授权文件访问，也不跟随磁盘 include。`full` 的首份文档对应入口主文件，额外路径须通过入口根目录授权；使用 overlay、获准本地 include、只读订阅缓存、实际本地 geodata/hosts/ECH 依赖做完整离线准入。从未拉取的订阅以 warning 准入、不产生缓存节点；已有 same-fetch 活动节点仍可 rebase。其他缺失或无效依赖是错误。`full` 模式下，首份文档的 `path` 不是入口主文件、路径不是 `.dae` 或位于入口根目录外时，返回 `400 invalid_request`。校验不联网、不创建目录或改权限、不启动 worker、不发布 generation。完成的无效 dry-run 返回 `200` 与 `valid:false`；这不代替之后真实 reload 的运行时校验，也不承诺 reload 一定成功。

Full 校验先按 include 顺序合并，再判定有效配置语义。未进入实际 include 树的提交文档只检查结构（包含 lexer 恢复后保留的错误），其设置和告警不影响有效候选；其字节与源数量仍和每次依赖物化共用同一预算。

PUT 与校验请求体含未知字段（包括 `secrets_redacted`）时返回 `400 invalid_request`。PUT 的 JSON body 为 `{"content":"..."}`。`If-Match` 按 RFC 9110 求值；源的强 ETag 是加双引号的小写 SHA-256，可将读取到的 `content_sha256` 加双引号使用。它比较磁盘当前原始字节，不是 config revision 或 runtime generation。列表与多个 header field line 合并，任一匹配的 strong tag 即满足条件；weak tag 是合法语法但永不匹配，`*` 匹配已存在资源。合法但不匹配的 opaque tag（含大小写不同的 hash）返回 412，而非 schema 错误。源 GET 仍是 accepted 快照，因此外部编辑后可能需要本地处理或显式 reload，而不是用旧快照覆盖磁盘。

| 写入条件/结果 | HTTP 语义 |
| --- | --- |
| 缺少 `If-Match`（先于 `Content-Type` 与 body 检查） | `428 precondition_required` |
| 畸形 `If-Match` 语法或非文本值 | `400 invalid_request`；列表、weak、`*` 与多个 header field line 本身合法 |
| 条件不匹配；检测到目标/依赖变化后重新求值仍不匹配 | `412 stale_revision`，检测到的外部内容不覆盖 |
| 检测到目标/依赖变化，但条件仍成立（例如 `*` 或匹配列表） | `409 state_conflict`，不覆盖并发变化 |
| 候选配置或依赖校验失败 | `422 unsupported_value`，不写盘、不 reload |
| 修改当前运行配置中需重启的设置 | `422 unsupported_value`，不写盘、不 reload；每个设置一条 `error` 级 `restart-required` 诊断，消息写明设置名 |
| 未授权源、凭据或原生设置修改 | `403 permission_denied` |
| 操作容量或协调队列繁忙 | `503 temporarily_unavailable` 与 `Retry-After` |

因为 reload 会拒绝修改需重启设置的候选配置，而已写入的文件不回滚，磁盘 hash 会与 accepted hash 不一致，后续写入都返回 412，所以协调器在写入前拒绝。Group PATCH、节点与 provider 编辑、数据库模式的 import 与 revision 激活同样适用；`full` 模式校验以 warning 报告这些诊断。需重启的设置应在配置文件中修改，然后重启 honk。

协调器在副作用前预留 operation，串行处理 API 新写入和 SIGHUP，SIGHUP 也先入队再读盘。单源 overlay 完整校验后，采用目录 FD、拒绝符号链接的普通文件检查、独占临时文件、保留 mode、文件 fsync、目标与完整依赖集复查、原子 rename、目录 fsync。外部编辑器不受协调器约束，最后检查到 rename 之间仍有竞争窗口；UI 保存期间不要并行手工改同一文件。Rename 后若目录 fsync 失败，503 明确携带 `written:true,durability_confirmed:false`，不带 `Retry-After`：可见内容已经改变，不表示未写或回滚。写入后 reload 无法入队时同样返回 `written:true`，不带 `Retry-After`。

`POST /api/v1/config/sources` 新建一个源文件。能力中的 `config.create` 仅在 `config.writable` 为 true 时为 true；配置不可用或不可写时的响应与 PUT 相同；配置可写但 `config.create` 为 false 时返回 `404 capability_not_supported`。Body 为 `{"path":"config.d/proxies.dae","content":"..."}`。`path` 相对入口目录，只含普通路径段，以 `.dae` 结尾，不超过 1024 字节且不含控制字符；父目录必须位于入口根目录内，经符号链接指向根目录外同样拒绝。不满足时返回 `400 invalid_request`。路径已存在于磁盘或属于已接受的源时返回 `409 state_conflict`，不覆盖。候选配置执行与 PUT 相同的完整校验、凭据检查与需重启设置检查，且新文件必须由某个 include 模式加载；否则 422 携带归属主文件、位置为 null 的 `source-not-included` 错误诊断。文件经临时文件与禁止覆盖的 rename 写入，使用入口文件的 mode；数据库模式改为把新源记录到新 revision。Reload 失败时新建的文件保留在原处，因为删除它会与该路径的其他编辑者竞争。每个失败的新建 operation 都报告 `written`（文件创建后为 `true`）与 `committed`（`false`、`true` 或 `null`）。大小限制、`Idempotency-Key` 以及 413、415、429、503 响应与 PUT 相同。

PUT 仅在耐久写入并进入真实 reload 队列后返回 `202`；显式 POST reload 入协调队列后返回 `202`。响应含 `operation_id`、`href`、相同的 `Location` 与 `Retry-After: 1`，不表示配置已经生效。操作由 daemon 持有，HTTP 断连不取消它或其 supervisor reconciliation。可选 `Idempotency-Key` 绑定 principal、method、path、instance 与原始 body：同 key 同 body 的并发/重试共用结果，不重复写入或 reload，丢失首个 202 后仍可用原 If-Match 重试；不同 body 返回 `409 idempotency_conflict`。总共最多 32 个预留/保留操作，终态最多保留 300 秒。存储已满时，新准入先淘汰最早结束的终态操作，该 ID 随后返回 404。该操作结束后 300 秒内，其 `Idempotency-Key` 仍重放原来的 `202`，不同 body 仍返回 `409`；被淘汰的 key 最多保留 1024 个（`resources.operations.max_replay_keys`），超出时丢弃最早的一个。只有全部名额都是准备中或执行中的操作时，才返回 `503 temporarily_unavailable` 与 `Retry-After: 1`；重启后不保留。

通过 GET operation、`runtime.last_reload` 及 `operation.updated` 读取真实结果，不能把收到 202 当作 succeeded。Reload 拒绝时保留旧 accepted 快照和 generation，但已写入字节不回滚；提交后 degraded 时保留新快照/generation 并报告 failed，而不是声称旧代仍活动。管理员应据磁盘内容与结果修复，再显式 reload。磁盘文件无法加载时，失败的 operation 与 `last_reload` 返回 `unsupported_value` 错误、`details.diagnostics`（与写入同一内容时的响应相同）以及 `committed:false`，并标明 accepted 源 ID 与行号。全部行超过 4 KiB 的 operation 错误 details 上限时，只保留 error 级别的行。每次失败的 reload、源写入与节点/provider 写入都报告 `error.details.committed`（`false`、`true` 或 `null`）；普通 reload 的 details 不含 `written`，写入类操作才带它。SIGHUP 本身不创建 API operation。仅改注释也会更新 source hash/config revision，但有效配置未变时不增加 runtime generation；有效组成员变化会改变 revision，健康测量变化不会。这三种版本不是可互换的并发令牌。配置 secret 或密码登录保护 listener 时，所有会话使用同一个管理员 operation principal，logout 不删除保留的 operation。

### 配置数据库（`--store db`）

`honk-core --store db` 将受管理的 `.dae` 源以 revision 形式保存在状态数据库 `<data_dir>/state/honk.db` 中。`data_dir` 取自 `--data-dir`（默认 `/var/lib/honk`），必须与 `global.data_dir` 相同，不回退到工作目录。`state` 目录权限为 0700、文件为 0600，二者均属 daemon 用户且不能是符号链接。启动或执行 `honk-core admin reset` 时，若二者属 daemon 用户且只多出组或其他用户的读、执行权限，honk 移除这些权限并记录警告；其他情况一律拒绝，组或其他用户可写时也是如此。`config export` 与其他离线读取遇到 0700 与 0600 以外的权限一律拒绝，不修改权限。数据库采用 WAL 模式，同目录下的 `honk.db-wal` 与 `honk.db-shm` 权限与主文件相同；文件系统不支持 WAL（例如不支持共享内存）时，回退到回滚日志（`honk.db-journal`）并记录警告。配置中只有 `.dae` 源进入数据库；订阅正文在两种模式下都保存在数据库中。hosts、ECH 与 geodata 仍在磁盘上，按 `data_dir` 解析。导入源树所在的目录不授权任何依赖。

数据库为空时，启动过程导入 `-c`，要求启用 `native_api.enabled` 与 `config_write` 并配置凭据。导入删除 `native_api` 与 `clash_api` 中的全部 `secret:`，确认去除凭据的源树在重新套用凭据后解析出相同配置，再以 principal `startup` 记录 revision 1。若凭据值在删除后仍残留（例如在注释或文件名中），导入被拒绝。已有 revision 时，启动过程加载当前 revision，不读取 `-c`；若启动期间另一实例移动了 `head`，启动终止；只有不持有实例锁的 mock 模式实例会造成这种情况。数据库模式不提供 Clash API：无论导入的源树还是当前 revision，只要 `experimental.clash_api.external_controller` 非空，启动即被拒绝。数据库损坏、`application_id` 不符或 schema 版本更高时拒绝启动；数据库不会被改名或重建。
启动与 API 重新导入会恢复剥离的凭据，并对齐解析器临时生成的群组/订阅 ID 和解析时间戳，再严格比较配置值。节点派生身份、端点、群组定义和订阅抓取设置仍必须一致。

监听凭据与 revision 分开保存，从不返回。写入不能修改监听凭据、`native_api` 设置或 `global.data_dir`，否则返回 403；含已保存凭据值的源也会被拒绝。响应与 `--without-secrets` 导出均遮蔽这两个已保存的值。数据库模式下源省略 `absolute_path` 字段，源路径只是标签，不对应文件；`If-Match` 比较数据库中保存的源字节。

写入先激活再记录。激活提交后（包括 degraded 与 reconciliation 失败的提交）才写入 revision 行并移动 `head`；激活被拒绝时不增加记录，并报告 `written:false`。记录失败时，操作以错误代码 `store_unavailable` 和 `details {committed:true,written:false,active_generation_id}` 失败；引擎在确认激活前停止时，操作代码为 `activation_unconfirmed`，`details {committed:null}`。两种情况下，`store.recorded` 变为 false，capabilities 报告配置不可写，导出文件名不含 revision，写入返回 `503 temporarily_unavailable` 与 `details.stage:"store"`。激活 `head` 所在的 revision 会重新激活它而不增加记录，并解除该状态；重启同样会解除，重启后加载 `head`。最多保留 50 个 revision，按存储的 JSON 计共 16 MiB，从最旧的开始清理，不删除当前 revision。JSON 转义可能使 revision 大于源文件本身；单个 revision 的 JSON 超过 16 MiB 时拒绝写入。

新 accepted 源已发布、但耐久记录尚未完成时，`store.recorded` 为 false，导出文件名为 `honk.dae`；`revision` 和 `parent` 仍描述耐久 head。读取尚未变化的旧 accepted 源时仍可报告已记录。协调器等待阻塞 SQLite promotion 结束，才完成操作、处理下一项修改或确认关闭。

以下路由与字段是 honk 扩展，按契约的 Engine extensions 规则放在 `x-honk` 下。`GET /config` 增加 `x-honk.store {kind, revision, parent, recorded}`，`kind` 为 `file` 或 `db`。capabilities 增加 `config.x-honk.store`，并在 `resources.x-honk` 中增加 `config_export {available}`、`config_import {available, replace_required}` 与 `config_revisions {available, can_activate, max_revisions}`；已放行的 discovery 在 `links.x-honk` 中给出这三个链接。下列路径均位于 `/api/v1/x-honk` 下。

- `GET /config/export` 把已接受的源合并为一份文档返回：`text/plain; charset=utf-8`、`Content-Disposition: attachment; filename="honk-r<n>.dae"`（文件模式为 `honk.dae`）、基于正文的强 `ETag` 与 `Cache-Control: no-store`。正文不含监听凭据；有凭据被省略时，首行为 `# listener secrets omitted`，补回凭据后才能运行。两种模式均可用。
- `POST /config/import`（数据库模式，需可写）接受严格 JSON `{"replace":bool}`，必须带 `Idempotency-Key`。它重新读取 `-c` 源树，经 reload 操作记录为 origin 为 `import` 的新 revision。因为启动过程总会记录 revision 1，所以必须提交 `replace:true`，其他请求返回 `409 state_conflict`。凭据副本在删除后仍残留时返回 `422 unsupported_value`。源树必须保持入口路径、监听凭据、`native_api` 设置与 `data_dir` 不变，否则返回 403。
- `GET /config/revisions`（数据库模式）返回 `{active, max_revisions, revisions:[{revision, parent, created_at, principal, origin, content_sha256, bytes, sources:[{path, sha256}]}]}`，从新到旧排列，不含正文。`active` 与行来自同一数据库快照；父 revision 被留存清理删除后，`parent` 为 null。
- `POST /config/revisions/{n}/activate`（数据库模式，需可写）接受空 body 或 `{}`，`Idempotency-Key` 可选。它校验并激活 revision `n`，再记录为 origin 为 `activate` 的新 revision。`store.recorded` 为 true 时，激活当前 revision 不产生变更；未知的 `n` 返回 `404 resource_not_found`。

文件模式下，import 与 revision 路由返回 `404 capability_not_supported`。

回到文件模式时，执行 `honk-core config export --out /etc/honk/config.dae`，再去掉 `--store db` 重启。之后再以数据库模式启动时从 `head` 继续；文件改动只能通过 `replace:true` 的 import 进入数据库。数据库损坏时，先执行 `honk-core config export --out exported.dae`；导出只检查 application id 与 schema 版本，损坏的文件也可能读得出来。然后停止 honk，执行 `mv <data_dir>/state <data_dir>/state.bad` 移走整个目录，使 `honk.db-wal` 随主文件一起移走，再以 `--store db -c exported.dae` 启动。

### 有界探测

`POST /probes` 要求 JSON，例如 `{"target":{"type":"node","node_id":"<id>"},"kind":"http","transport":["tcp"],"ip_version":"ipv4","warmth":"cold"}`。组目标使用 `{"type":"group","group_id":"<id>"}`，可选 `members: "direct"`（默认）、`"leaves"` 或非空直接成员 ID 列表；节点目标不接受 `members`。`ip_version` 接受 `ipv4`、`ipv6` 或 `any`，`warmth` 接受 `cold` 或 `warm`。不接受任意调用方 URL。探测用途由 `kind` 决定，不在请求中提交：`tcp_connect` 与 `http` 为数据探测，仅用 TCP；`dns` 为 DNS 探测，可用 TCP、UDP 或两者。组可选直接成员、叶节点或显式成员 ID；先固定当前配置、成员和注册代次，再去重执行测量，并保留成员到叶节点的关联。TCP 连接探测测量节点实际配置的端口，不接受调用方指定的任意端口；HTTP 使用配置的检查 URL，不跟随重定向；DNS 执行实际 UDP 或带长度帧的 TCP 交换。探测目标仅来自已接受的配置，不对目标或节点服务器应用地址或端口策略；私网、回环地址与非默认配置端口无需放行。IPv4-mapped IPv6 规范化为 IPv4，选中的 IP 保持固定，HTTP Host/TLS SNI 保留配置的名称，不能交给代理重新解析。探测、geodata 和共享下载使用配置的目标，不设地址或端口白名单。能够写入配置或控制订阅内容的人决定这些目标；provider 内容属于受信任的配置。

每个 probe job 最多 64 个成员关联、256 行结果；最多 4 个 active、16 个 queued、每 target 1 个，准备/排队/测量共享 30 秒 deadline。最终 transport owner 清理即使超期也必须等待 join，因此 operation 总耗时可能超过 30 秒。每分钟 principal/global 均最多 30 次（当前只有一个 principal）；限流为 `429 rate_limited`，队列/owner 不可用为 503，均带正数 Retry-After。即使已有 4 个 active job，也立即返回 202 与 `queued` 操作；202 只表示 daemon 接管。测量开始前结束的 job 以 `probe_cancelled`、`probe_deadline`、`unsupported_value`（本地解析被拒绝，或节点不能向探测端口转发 UDP）或 `engine_unavailable` 失败；断开 HTTP 不取消任务。结果保留真实 measurement/family/warmth/时间与 health 更新是否被当前 epoch 接受；过时代次、取消或 deadline 不伪造成 unhealthy，TCP-connect 不冒充 HTTP 排名样本。最终清理失败时 operation 以 `probe_cleanup_failed` 失败，`result` 保持 null，已完成的测量放在 `error.details`。

直接成员中的子组只通过其当前选中的一个叶子节点探测，不会展开，因此父组的开销不随后代数量增长；目标组自身的规模只受 64 个成员和 256 行结果限制（更大的组可用 `members` 列表分批，每批最多 64 个 ID）。只有 `members: "leaves"` 会遍历后代，并且当该组图超过 256 项时同样被拒绝。

### DNS 查询、缓存与结果历史

`POST /dns/query` 接受严格的 JSON 请求体（`Content-Type` 须为 `application/json`，否则返回 `415`）：必填 `domain`；`type` 为可选数组，默认 `["A"]`，最多 8 个不同类型，超过时返回 `413 request_too_large`；`detail=summary|full` 仍放在查询字符串；支持 A、AAAA、NS、CNAME、SOA、PTR、MX、TXT、SRV、SVCB、HTTPS 和 CAA。可选字段 `cache_mode` 接受 `normal` 或 `bypass`。一次请求的所有类型固定同一 DNS generation，共享 10 秒期限；唯一认证主体和全局各限每分钟 30 次。可选字段 `upstream` 只接受已配置名称，包括未被规则引用的名称；它替换请求阶段的路由选择，不绕过 hosts/strategy 的优先级或响应侧 requery。Hosts 命中报告默认路由，且无上游。`cache_mode=bypass` 不读取或写入正缓存、负缓存及过期缓存，不加入会写入缓存的 singleflight、不替换缓存条目，也不启动刷新；不提供该选项时保留正常生产语义。完整详情展示经过校验的答案记录，各类型的超时、拒绝或错误仍按实际结果报告。

字面值 `.` 表示 DNS 根，支持实际查询、精确缓存列表和按名称删除。普通输入名称不区分大小写，末尾点可省略；展示名称保留规范化末尾点。合法根域 wire 问题也进入普通严格 DNS 路径；非 UTF-8 label 仍不属于该消费者契约。

缓存 GET 只观察运行时 exact-key 正/负记录（`persistent:false`），不提升 LRU 优先级或计入命中统计。支持 `name` 精确名称、`domain` 子串、重复 `type`、`include_expired=false|true`、`detail`、`limit`（1–1000，默认 100）及 `cursor`；最多 8 份过滤器和实例绑定的不可变快照、30 秒、合计 8 MiB，底层记录被淘汰后，快照占用仍计入预算；超出该预算返回 `503 snapshot_unavailable`。游标无法识别时返回 `410 snapshot_expired`，带不同过滤器或 `limit` 的已识别游标返回 `400 invalid_request`。`entry_id` 标识精确 incarnation，旧 ID 不能删除替代记录；按 name 删除可跨 exact-key 变体并用 type 限制。删除/flush 与入库发布串行化，等待启用的持久化失效确认，旧 foreground/refresh 不能在确认后复活所删缓存；flush 不清空 DNS 路由投影。DNS 查询、缓存和日志的完整 JSON 响应上限均为 262144 字节。缓存和日志分页在下一条会超出上限时提前结束并返回 `next_cursor`，因此 `limit` 只是上限，不保证条数。单条记录本身超限时独占一页完整返回，不受上限约束；因为原始报文最长 65535 字节，展开大小有界，拒绝它会让其后的记录都无法读取。查询响应超限或无法保留快照时返回 503 与 `Retry-After`，不裁剪 RRset 冒充完整答案。

`DELETE /dns/cache/{entry_id}` 不接受请求体或查询参数，返回 `{deleted}`；`DELETE /dns/cache?name=...&type=A` 不接受请求体，返回 `{matched,deleted}`，省略 `type` 时选择该名称的全部类型。`POST /dns/cache/flush` 接受空请求体或 JSON `{}`，返回 `{matched,deleted}`。

名称、类型及过期筛选在快照字节准入和复制之前完成；未选中的缓存记录不消耗本次快照预算。负应答优先级和过期筛选使用同一个观测时刻。

每页还带 `usage {entries, entry_capacity}`，描述快照时刻的整个运行时缓存，不受过滤器影响。`entry_capacity` 为 `max_cache_size` 钳制到 1–100,000 后的值。两个值均为十进制字符串，在所有分片同时加锁时读取；同一快照的后续页重复相同的值。淘汰按分片进行，因此单个热点分片可能已在淘汰，而合计值仍显示有余量。`usage.entries` 还计入 `total` 不包含的过期记录与非 exact-key 记录。

`record_dns_log` 默认为 `true`，允许在独立 DNS 日志需求有效时记录，最多保留 512 条、8 MiB。显式运行时设置 `record_dns_log: "on"` 可在无客户端时持续记录；配置中的 `false` 禁止记录，修改后需重启。实际记录停止时释放历史，已有游标失效。在客户端请求实际完成时记录普通 DNS 查询结果和来源已知的客户端解析结果，包括已知的客户端套接字、入口以及可解析的拒绝或错误结果；排除原生/Clash 诊断调用及后台刷新产生的重复记录。仅存内存；完整原始报文与元数据一起计入预算，按整条旧记录淘汰。`GET /dns/log` 最新优先，支持大小写不敏感的 `name` 子串、`type`、无端口 `src`、`limit`（1–500，默认 100）及与过滤器绑定的 `cursor`；淘汰或缩容使相关游标失效，无法识别的游标返回 `410 snapshot_expired`；带不同过滤器或 `limit` 的已识别游标返回 `400 invalid_request`。停止记录不影响正常 DNS 服务。

### 路由模拟与规则位置

获准访问的匿名回环请求与 Bearer 认证请求具有相同的规则读取和路由模拟权限。`POST /routing/trace` 接受 `{"input":{"network":"tcp","domain":"example.com","dst_port":443},"resolve":"none"}`。`input` 要求 TCP/UDP、非零目标端口及至少一个 `domain`/`dst_ip`；可选来源 IP/端口、`pname`、DSCP（0–63）与 `mark`。`resolve` 默认为 `none`，返回固定 `instance_id` 和 `generation_id` 的 `simulation` 结果；`live` 要求 `domain` 且不能带 `dst_ip`，违反此结构返回 400；结构合法但尚不支持的 `live` 请求返回 422。`Content-Type`、JSON/schema、`input` 与 `resolve` 校验先于限流准入；校验拒绝不消耗 路由模拟限流名额。模拟固定当前已编译路由器、配置和 generation，不查询 DNS、不探测、不推进组选择、不建立连接；缺失输入保留 `indeterminate/missing_inputs`，不能视为历史 flow 证据 或真实转发承诺。上限为 1 个地址、256 个规则或条件步骤、5 秒，唯一认证主体和全局各限每分钟 30 次。`GET /rules` 返回含 fallback 的完整当前字典，从不截断；`max_rules` 取 4096 与当前字典行数中的较大值，`dns_rules.max_rules` 同样不小于较长的 DNS 列表。fallback 条目的 `expression` 为其源语句，例如 `fallback: proxy`；未保留源文本时为 `fallback: <outbound>`。路由模拟的求值结果使用 `fallback: <outbound>`。两者在期限内无法固定路由器时返回 `503 snapshot_unavailable` 并带 `Retry-After`。规则 ID 与用户态捕获证据共用 generation 范围内的身份；存在已接受的解析器来源位置时，给出不透明的 `source_id`、从 1 开始的 `line` 和字节 `column`；`file` 与该来源相对于入口目录的 `path` 一致，否则 `source` 为 null。历史 flow 不从当前字典重建，内核 final 的来源仍可为 unknown；编辑应使用 source ID 及相应内容权限，不从显示标签推导文件系统路径。

对已接受 `.dae` 配置中的规则，包括含凭据来源的规则，`/rules` 与 `/routing/trace` 的规则 `expression` 保留编写时的条件值（包括 geosite/geoip 名称、否定和带引号参数），移除注释和出站子句。Trace 的逐条件表达式按实际编译后顺序以 dae 写法显示配置值，不加引号：一次 `domain(...)` 中的普通域名候选与 geosite 合为一个联集条件，否定作用于整个联集；目标 IP 与 geoip 候选同样共用一个条件。监听凭据值仍被遮蔽；普通条件文本无需写权限即可读取。没有已接受来源元数据的规则显示编译后条件值，来源保持 null。编译后展示反映规范化的谓词，不等同于原始编写语法，也不展开 geodata。Trace 的展示元数据与决策固定在同一已接受代次。磁盘编辑只有在 reload 被接受后才更新两种响应；reload 被拒绝时保留旧表达式。历史 flow 保留各自代次捕获的有界编译后值，包括程序内构造路由器的值。

### DNS 路由规则

`GET /dns/rules` 以 `{generation_id, request, response}` 返回当前 generation 的 `dns { routing { … } }` 规则。该接口只读，编辑 DNS 规则与 `/rules` 相同，通过来源 PUT 完成。两个列表均按求值顺序排列，并以恰好一条 `kind: "fallback"` 结尾。每条记录包含 `rule_id`、从 0 开始的 `index`、`expression`、`action`、`upstream`、`source` 与 `kind`。请求规则的 action 为 `upstream`、`asis`、`reject`；响应规则的 action 为 `accept`、`reject`、`requery`。action 为 `upstream` 或 `requery` 时，`upstream` 为引擎使用的小写名称，其他 action 为 null。`expression` 为编写时的整条语句，包含 action，去掉行尾注释，例如 `qname(suffix: example.com) -> AliDNS` 或 `fallback: googledns`。配置未写 fallback 时仍列出引擎默认值：请求为 `upstream` `default`，响应为 `accept`；其 expression 为 `fallback: <action>`，`source` 为 null。parser 以警告忽略的规则不列出。

`rule_id` 的格式为 `{instance}:{generation}:dns_request:rule:{index}` 或 `{instance}:{generation}:dns_request:fallback`，响应列表把 `dns_request` 换成 `dns_response`。它在两个列表间唯一，随 generation 变化，因此须同时用 `generation_id` 与 `rule_id` 定位规则。`source` 与 `/rules` 结构相同：不透明的 `source_id`，与该来源入口相对 `path` 一致的 `file`，以及语句在该来源中起始处从 1 开始的 `line` 和字节 `column`。没有已接受来源元数据的规则 `source` 为 null，expression 由解析后的条件生成。两个列表均完整返回，包含 fallback；`resources.dns_rules.max_rules` 至少为 4096，且不小于当前较长列表的条数。5 秒内无法固定当前配置时返回 `503 snapshot_unavailable`，带 `Retry-After`。磁盘编辑只有在 reload 被接受后才更新响应。

### Provider 观测与刷新

获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的 provider 数据。Provider GET 不联网。订阅条目连接真实 SubscriptionSupervisor 观测与已接受节点的 `subscription_id`，`Node.provider_id` 可用于关联。订阅返回配置名称，`url_redacted` 返回完整 URL；为兼容客户端保留字段名。GET 与成功操作结果使用相同表示。未观测 usage/expiry 仍为 null。与旧 `provider-<id>` 标签相同的配置名称只是普通名称，不作为 ID 别名。从未加载、等待加载或禁用且无缓存时是 stale、零节点及 null 时间/错误；真实失败且无节点才是 error，保留旧/缓存节点时为 stale。订阅条目还带有 `download`，即由 `download_detour` 决定的拉取路由，结构与 geodata 路由相同：`route` 为 `routing`、`direct` 或 `group`，`group_id` 为该组在 `GET /groups` 中的 ID，其他路由或组已不存在时为 null。文件与 inline 条目为 null。拉取失败时 `last_error.code` 为 `fetch_failed`；订阅的下载路由尚无可用节点时为 `route_unavailable`，见[订阅参考](./subscription.md#拉取持久化与恢复)。配置校验拒绝发布时（例如节点与静态节点重复），`last_error.code` 为 `publication_rejected`，诊断代码写在 `details.diagnostic_code`（例如 `duplicate-node-id`）；失败的 refresh operation 带相同的 details。列表 `limit` 默认 100、范围 1–1000，snapshot 上限 8 份/30 秒/4 MiB，放不下时返回 `503 snapshot_unavailable` 并带 `Retry-After`；游标无法识别时同样返回 `410 snapshot_expired`，带不同过滤器或 `limit` 的已识别游标返回 `400 invalid_request`。启用且有运行 supervisor 的订阅可 POST refresh；订阅已禁用或未挂接 supervisor（`can_refresh: false`）时返回 `404 capability_not_supported`；同 provider 的不同并发 refresh 为 409，保留的幂等重放先于冲突检查。刷新成功须真实 revision-fenced publication 被接受，fetch 或写缓存不等于成功，HTTP 断连不丢失结果。虚拟 inline provider 不可刷新/删除；它关联 `provider_id: inline` 的静态非 builtin 节点，builtin 归属保持 null，订阅 ID 仍为 UUID。

### 原生日志与运行时设置

`record_logs` 默认为 `true`，允许在独立 `/logs` SSE 需求有效时捕获日志，最多保留 512 条、60 秒，日志能力以 `max_buffered_records` 与 `retention_seconds` 声明这两个上限，并列出 `filters: [level, target]`。显式运行时设置 `record_logs: "on"` 可在无客户端时持续捕获；配置中的 `false` 禁止捕获，修改后需重启。实际记录停止时释放日志，续传游标失效。保留真实 `ts`、`level`、`target`；只有审查过的静态消息和有界、类型明确的安全字段可披露，其他 `message` 和 `fields` 明确标为不披露，不靠正则猜测所有秘密，也不转发控制台或 Clash 格式化输出。`GET /logs` 向认证调用方及获准访问的匿名 loopback 调用方以 SSE 返回 `stream.ready` 与日志，支持可选的最低 `level` 和 `target` 前缀过滤；以 `Last-Event-ID` 续传，游标绑定流、实例和过滤器；续传顺序与 `/events` 相同，为 **ready→replay→live**，ready 保留请求游标，之后才由 replay 推进。每条流最多 16 个客户端，每个客户端最多排队 64 个事件，每 15 秒发送一次心跳注释；16 个名额已满时新连接返回 `503 temporarily_unavailable` 并带 `Retry-After`；游标过期、属于其他流或实例，或过滤器不同时，在 HTTP 200 前返回 `409 event_cursor_expired`，队列已满或重放记录丢失时断开流。缩容使被淘汰记录的游标失效。
与 Clash `/logs` 相同，捕获始终排除 `quinn::endpoint` 目标：它的 endpoint driver ERROR 与 honk 自行报告、带有上下文的 carrier 故障重复。

`PATCH /runtime/settings` 使用 JSON 对象，仅合并能力声明列出的字段：`record_flows`、`record_logs`、`record_dns_log`（`"on"`、`"off"` 或 `"auto"`）、`log.level`（trace/debug/info/warn/error）、`log.buffered_records`（64–512）、`dns_log.max_records`（64–512）、`flows.max_flows`（64–1024）、`flows.retention_seconds`（1–300）以及单独存储的 `geodata`。未知、null（`geodata: null` 除外，它清除已存储的 geodata 设置）、空对象或越界值属于结构/边界错误，返回 `400 invalid_request`；geodata 凭据准入先于结构校验，含 `geodata` 的匿名请求先返回 `403 permission_denied`；不在 `resources.runtime_settings.fields` 内的字段（配置禁止该记录器时的 `log.*`/`dns_log.*`/`flows.*`，或没有状态库时的 `geodata`）返回 `422 unsupported_value`。GET 与成功的 PATCH 返回内部一致的记录器设置快照，含 `source: "config"|"runtime"`；geodata 单独读取，可能反映并发更新。配置中的 `log.buffered_records` 与 `dns_log.max_records` 均为 512，`flows.max_flows` 为 1024，`flows.retention_seconds` 为 300。完整合并结果通过校验后，记录器设置由同一所有者原子发布，`source` 为 `runtime`；仅修改 geodata 时保留顶层 `source`；缩容淘汰旧记录并使受影响游标失效。能力声明的是取值范围，不是当前值：`logs.min_buffered_records`、`dns_log.min_records` 与 `flows.min_flows` 均为 64，`flows` 能力声明返回 `max_flows` 与 `retention_seconds` 的上限（1024 与 300）。修改 `log.level` 同时替换控制台与日志文件的过滤器，包括由 `RUST_LOG` 或 `--debug` 设定的过滤器；Clash `/logs` 仍按各请求的级别过滤。这些运行时覆盖值不写入 `.dae` 或缓存数据库。每次已接受的显式配置激活（含 no-op 或提交后降级的激活）恢复配置级别、启动时的控制台与日志文件过滤器和初始留存上限，并将记录模式重置为 `"auto"`；激活被拒绝、provider 刷新或网络刷新时保留运行时设置。`geodata` 单独存储，不受激活影响，见 [Geodata 来源与自动更新](#geodata-来源与自动更新)。

顶层记录字段中，`"on"` 使获准的记录器持续开启，`"off"` 强制关闭；初始模式 `"auto"` 对 flow、日志、DNS 日志各自按对应独立诊断需求控制。省略的字段保持不变；null 被拒绝。配置中的 false 禁止记录，运行时请求开启该记录器会使整次 PATCH 以 `422 unsupported_value` 被拒绝。配置权限决定哪些级别和留存控制可用，与记录器是否暂时停止无关。

GET 和成功的 PATCH 响应包含只读 `recording`：`flows`、`logs`、`dns_log` 各含 `{allowed, mode, active}`，其中 `mode` 为 `"auto"`、`"on"` 或 `"off"`；`events.active` 表示事件捕获是否开启，`grace_remaining_seconds` 表示通用连接宽限期剩余秒数，不是任何独立 flow/日志/DNS 日志诊断需求的倒计时；仍有通用流连接时该字段为零。读取设置不延长任何期限。

### 主文件条目与 geodata 管理

`resources.nodes.can_manage` 与 `resources.providers.can_manage` 要求来源协调器运行，且 accepted 主文件可写、不含 API 凭据。创建节点提交 `{"name":"edge","link":"socks5://192.0.2.2:1080"}`；创建 provider 提交 `{"name":"feed","kind":"subscription","url":"https://example.net/sub"}`。`resources.providers.create_options` 列出可选 provider 字段省略时的生效值：`update_interval`（秒，最多一年，`0` 表示只在请求时刷新，内置默认 `86400`）、`user_agent`（1 至 256 个可打印 ASCII 字符，内置默认 `honk/<version>`），以及仅在 `global.store_subscribe` 打开订阅存储时列出的 `cache`（内置默认 `true`）。内置默认值只是回退值；`assets.subscription` 设置了对应默认值时，`create_options` 返回该设置值。`resources.providers` 还会声明 `create_unfetched: true`，表示支持这种未拉取即创建的方式。显式提供选项的 provider 写作 `tag: 'url' { ... }`，`ua`、`interval` 和 `cache` 各占一行；schema 长度、pattern、kind、interval 或 user-agent 边界违规返回 `400 invalid_request`；未声明的选项（如没有 store 时的 `cache`）返回 `422 unsupported_value`。严格 JSON 与 64 KiB 正文限制不变。复用引擎 parser、完整离线准入、FD 相对耐久写入及真实 reload；激活与订阅协调完成后才以 `201` 返回当前 Node/Provider 和 `Location`。HTTP 断连不取消已入队工作；使用 `--store db` 时，这些操作记录新 revision，不重写主文件。

节点名为 1–64 字符，链接最多 8192 字符；provider 名为 1–64 个 ASCII 字母/数字/`_.-`，HTTP(S) URL 最多 4096 字符。schema 长度、pattern、enum 或边界违规返回 `400 invalid_request`；重名返回 409；结构合法但不支持的链接、身份、provider URL scheme 或选项返回 422。新 provider 即使有旧缓存正文，也从零节点、stale、无更新时间开始。同一 source specification 的延迟拉取状态在无关编辑和 reload 中保留，直到显式 refresh。修改该 specification 或重启后，恢复普通订阅启动行为。API 不创建 same-fetch 别名；删除归属有歧义时直接拒绝，不转移 ID 或节点。

DELETE 不接受 body/query：带有任一项时返回 `400 invalid_request`，body 超限时返回 `413 request_too_large`，二者均不带 `Retry-After`。未知 ID 返回 `{"deleted":0}`，不写入；成功删除在激活后返回 `{"deleted":1}`。builtin 节点、订阅派生节点、非主文件条目及不支持或有歧义的归属返回 `404 capability_not_supported`。静态 include 仍在 inline 下可见；固定客户端没有逐节点 writable 字段，因此显示的删除按钮仍可能被拒绝。删除被某个组用作 `final` 的节点返回 `409 state_conflict`，`details.groups` 列出这些组的 ID；其他仍被引用的条目须先修正引用，否则写前校验失败。主文件读取后在磁盘上被修改时返回 `409 state_conflict`。编辑已有条目继续使用源 PUT，没有 node/provider PATCH 接口。

这些同步动作与源 PUT、Group PATCH、SIGHUP 共用协调器，检查 accepted revision、磁盘字节与依赖，但不锁住任意外部 editor。失败 details 包含 `stage`（这类同步写入始终带此字段）、`written`、`durability_confirmed`（只在 `written` 为 true 时出现）与 `committed`；无法确认时为 null，不伪造 false。生命周期与运行失败为带 Retry-After 的 503，POST 重名冲突为 409，写入期间磁盘上的源被修改时返回 `409 state_conflict`（请求不带前置条件）；DELETE 的其他校验失败仍映射为 503。已耐久写入但激活被拒绝报告 written true/committed false；`--store db` 在激活前不写入，被拒绝时报告 written false；提交后降级报告 committed true 并带上 `active_generation_id`，无法确认时为 null，不承诺回滚。源 PUT 仍使用独立磁盘 hash If-Match，旧编辑器会在管理修改后得到冲突。

获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的 geodata。Geodata GET 按既有 router-before-config 锁序读取流量/DNS 保留元数据，不扫描磁盘、不联网；hash/大小属于已加载字节，不属于后来的磁盘外部编辑。未记录或不一致的修改时间为 null；`source_redacted` 保留字段名，在 GET 与成功操作结果中返回第一个下载 URL，去掉 userinfo、query 和 fragment，可能含凭据的路径段替换为 `[redacted]`，并遮蔽监听凭据；没有 URL 的资产或无法安全显示的 URL 为 null。未使用资产不列出；互相冲突的已加载快照报告不可用，不任取其一。

更新需要 `config_write`、来源权威，以及每个已加载资产都有下载 URL：来自配置文件的 `assets.geodata.geosite`/`assets.geodata.geoip`，或在来源可配置时来自已存储或内置的 URL（见下节）。URL 不作为请求参数。只接受最终直达 HTTP(S) URL，拒绝 userinfo、fragment、redirect 和 content encoding；HTTPS 验证证书。直连请求只用配置的数字地址 `global.bootstrap_resolver` 解析域名，不回退系统 DNS；`routing` 匹配路由规则时先用该解析器查询域名，未配置或查询失败时再查 `/etc/hosts` 和系统 nameserver。请求经由下节所述的下载路由发出，默认为 `routing`。一次更新最多两个各 256 MiB 的资产；每个 URL 的文件须在请求发出后 30 秒内返回响应头，正文的每次停顿不得超过 30 秒，整个下载最长 10 分钟；校验文件请求在文件下载完成后另有 10 秒期限，涵盖路由决策、域名解析、隧道和 TLS 在内的整个请求；校验、磁盘操作与必须等待的 owner join 不承诺硬总期限。

全部下载完成、解析并编译完整候选后才替换任何文件；新文件缺少当前配置使用的分类时，更新以 `asset_validation_failed` 失败，已加载文件保持不变。已加载文件位于 `global.data_dir` 或 `$DAE_LOCATION_ASSET` 时就地替换。已加载文件来自优先级更低的位置（例如软件包安装的 `/usr/share/honk`）时不会被覆写：更新改为在 `global.data_dir/<file>` 新建文件，若该路径期间已出现文件则拒绝替换；此后查找顺序优先使用新文件。文件经无符号链接的父目录/文件 FD 打开，别名、字节/来源/依赖冲突和不安全路径均拒绝；父目录分量只在安全打开后做身份规范化。各文件独立原子替换并确认耐久，**不是多文件原子事务**；首个 rename 后失败保留逐资产 written/durability 信息，不自动撤回。真实 reload 在 no-op 与重建两条路径都使用不可变已验证 geo 快照，后续磁盘改动不能替换激活字节。成功结果来自实际发布的 GeoData；拒绝/降级仍失败并报告提交信息。重试前先修复磁盘冲突。
缓存订阅仍参与准入依赖检查，但其指纹标签指向数据库行，不是文件路径。Geodata 更新通过 rename 前的最后一次重新捕获检查正文是否变化；只有真实文件依赖才取得 inode guard。

`POST /geodata/update` 不带 body；同键幂等重放先于互斥检查，不同的在途请求返回 409，operation 容量满返回 503。`202` 只代表 daemon 接管，不代表文件或路由已变更。下载内容与已加载文件相同的资产不会写入；所有资产都相同时，更新直接成功，不激活，不产生 generation 事件，也不改变 `runtime.last_reload`。更新进入激活阶段后会写入 `runtime.last_reload`；激活前失败则不改变该字段。

### Geodata 来源与自动更新

有状态库时，`resources.geodata.configurable_sources` 为 true，`runtime_settings.fields` 列出 `geodata`，能力还报告 `max_urls: 4`、`interval_hours: {min: 6, max: 168, default: 24}` 与 `lifecycle: {file_values: start, overrides_persist: true}`：仅在启动时读取配置文件的值，修改在重启后保留。无论有无状态库，`checksum` 均为 `sha256sum`。启用原生 API 时总会打开 `<data_dir>/state/honk.db`；设置存于其中的严格表 `geodata_settings`，重启和激活后保留。没有状态库时只使用配置文件中的 URL，下列字段均不出现。

此时 `GET /runtime/settings` 包含 `geodata`：`source`、`geosite.urls`、`geoip.urls`、`auto_update`（`enabled`、`interval_hours`）、`download`（`route`、`group_id`）与 `verify_checksum`。只有已存储的设置生效。启动时，`assets.geodata` 设置了下载 URL 的，honk 将其写入已存储的设置，覆盖通过 API 修改的 URL。配置文件未设置 URL 的资产，若列表由先前的配置文件写入则删除，改用内置 URL；若由 API 修改则保留。配置文件的下载 URL 与出口由启动阶段持有；reload 改变生效值会因需要重启而被拒绝，因此其他激活不会改动已存储的设置，通过 API 修改的 URL 保持到下次启动。已存储的列表全部来自配置文件时 `source` 为 `config`，任一列表来自 API 修改时为 `override`；未存储列表时为 `default`，即内置的 MetaCubeX `meta-rules-dat` release 文件，先 raw.githubusercontent.com，后 fastly.jsdelivr.net。自动更新默认开启，间隔默认 24 小时。

`download.route` 决定每个 geodata 请求（包括校验文件）的出口。`routing` 为默认值，与用户流量一样遵循路由规则；`group` 始终经过 `group_id` 指定的组，该 ID 即 `GET /groups` 返回的 ID；`direct` 使用 bootstrap resolver 解析并带绕过标记直连主机。经规则或组的请求与外部 UI 下载共用同一套路由决策和隧道。路由无法承载的请求按连接错误处理，使这个 URL 失败：组不存在或没有可选成员时 `last_error.code` 为 `group_unavailable`，规则指向 `block` 时为 `route_blocked`，隧道建立失败时为 `connection_failed`。随后 honk 改试下一个 URL，不会回退到直连。启动后不久，路由或规则选中的组尚无可达节点时，更新就按此处理。经节点下载时，域名由节点出口解析。启动时，`assets.geodata.route` 优先于 `assets.route`，并将生效出口写入已存储设置，覆盖 API 的修改。配置文件没有设置出口时，保留通过 API 修改的出口；否则遵循路由规则，删除先前由配置文件写入的出口。出口不影响 `source`。见 [Assets 参考](./assets.md)。

`PATCH /runtime/settings` 合并并存储 `geodata`，不触发下载。`urls` 列表含 1–4 个互不相同的 HTTP(S) URL，每个最长 4096 字节，不含 userinfo 或 fragment，按回退顺序整体替换原列表；修改一个资产只存储该资产的列表，无论原来的 `source` 是什么，都随之变为 `override`，另一个资产仍取配置文件或内置 URL。`auto_update` 单独存储，`interval_hours` 取 6–168，配置文件不设置它。`download` 单独存储；`group` 路由必须带 `group_id`，其他路由不能带；ID 不对应当前任何组时返回 `409 state_conflict`。已存储的组被后续激活删除后，`group_id` 读作 null，下载以 `group_unavailable` 失败，直到修改路由。`verify_checksum` 单独存储，配置文件不设置它。`"geodata": null` 删除已存储的设置；配置文件中的 URL 在下次启动时重新写入。顶层 `source` 不受影响。`geodata` 与其他字段在同一请求中一起校验，任一部分失败则全部不变。匿名 loopback 主体不能修改 `geodata`（`403 permission_denied`）；所有获准访问的调用方都读到原始 URL，仅遮蔽监听凭据。

更新按顺序尝试资产的各个 URL，遇到连接错误、非 200 状态、超时或校验失败时改试下一个。校验文件的 URL 是在原 URL 的路径末尾加 `.sha256sum`，保留 query。返回 200 时，其第一个字段必须等于文件的 SHA-256；返回 404 视为未发布校验文件，文件按未校验使用；其他状态或失败都使这个 URL 失败。某个资产的所有 URL 都失败时，失败详情描述最后尝试的 URL，给出 `stage`、失败的资产 `asset`（`geosite` 或 `geoip`）；该 URL 因服务器响应而失败时，还给出该响应的 `http_status`，即文件的非 200 状态，或校验文件的非 200、非 404 状态。`asset: geoip, stage: checksum_unavailable, http_status: 403` 表示服务器拒绝的是 `.sha256sum`，而不是文件。配置文件、已存储和内置的 geodata URL（包括校验文件请求）均不设地址或端口白名单。

`verify_checksum` 默认为 `true`。设为 `false` 后，手动和自动更新都不请求 `.sha256sum`，下载的文件一律按未校验使用：`verified` 为 `false`，`sha256` 照常报告。此设置用于缺少校验文件时返回非 404 状态或返回非校验内容页面的镜像。以 `checksum_unavailable` 或 `checksum_mismatch` 失败时，日志中的警告会指出此设置；校验不会被自动关闭。

此时 `GET /geodata` 还为每个资产报告 `fetched_url_redacted`（已加载文件的下载 URL，显示方式与 `source_redacted` 相同）、`verified` 与 `download_route`（`route` 为该次下载时设置的路由，`group_id` 为请求经过的组，包括规则选中的组，否则为 null），并在顶层报告 `last_checked_at`、`last_updated_at`、`next_check_at`、`last_error` 和 `required_codes`；后者按资产列出当前配置引用的分类，已排序。`last_error.code` 为失败阶段，例如 `http_status_rejected`、`checksum_mismatch` 或 `asset_validation_failed`。`last_checked_at`、`last_updated_at`、`last_error` 与连续失败次数存于状态库的严格表 `geodata_status`，重启后保留。`next_check_at` 不存储，每次启动时据此重新计算，并重新抽取随机延迟。每个资产的字段只存于内存，因此重启后在下一次尝试前为 null，`verified` 为 false。

自动更新默认开启，间隔 24 小时；将 `auto_update.enabled` 设为 `false` 即关闭。启动后从上次记录的检查时间继续计时。若该时间距今已超过等待时间、晚于当前时间（时钟曾经超前），或没有记录，首次检查在启动后 5 分钟加随机延迟时执行，因此重启不会立即触发下载，重启间隔短于更新间隔的主机也会更新。需要立即更新时调用 `POST /geodata/update`。自动更新使用同一个 `geodata_update` operation，因此自动更新执行期间的手动更新返回 `409 state_conflict`；自动更新到期时若已有更新在执行，下次时间由该更新的结果决定。每次等待为间隔加 0–60 分钟随机延迟。连续失败后等待 1 小时，每次失败加倍，最长不超过间隔，失败次数在重启后保留；成功后恢复正常间隔。

### 内嵌 doona 来源

默认关闭的 `native-ui` 隐含 `native-api`，编译时从 `HONK_DOONA_DIR` 指定的绝对路径目录读取 doona 构建产物并内嵌；未设置该变量时构建失败。`ci/fetch-doona.sh` 下载 `.github/ci/pins.env` 固定的发布包（当前为 doona `0.1.0-beta.19`、提交 `2391fb7b622e180243aa71b2da5274566432683e`），校验 SHA-256，确认包内含 `THIRD-PARTY-NOTICES.txt` 及 `NOTICE` 引用的全部 `LICENSES/` 文件，删除字体并输出目录：`export HONK_DOONA_DIR=$(ci/fetch-doona.sh)`。未设置该变量时，`just lint` 与 `just test-ci` 自动执行该脚本。发布产物包含内嵌 UI；二进制内嵌 doona 程序包自带的 notices，每个发布 tarball 也在 `doona/` 目录附带这些文件。内嵌产物不含 Noto Sans TC 与 SC 字体。doona 的 CSS 以 `font-display: optional` 声明这些字体，因此字体请求返回 404 时浏览器使用系统字体。需要 Noto Sans 时，将 [doona 发布页](https://github.com/Zakkaus/doona/releases)的 `doona-<version>.tar.gz` 与 `doona-fonts-<version>.tar.gz` 解压到同一目录并让 `ui` 指向该目录，或安装 `doona` 与 `doona-fonts` 软件包并设置 `ui: /usr/share/doona`。对应的 GPL-3.0-only 源码是 doona 标签 [`v0.1.0-beta.19`](https://github.com/Zakkaus/doona/tree/v0.1.0-beta.19)。发布流程将 `doona-source-0.1.0-beta.19.tar.gz` 附加到正式标签发布与滚动 Debug 发布；该包由 `ci/fetch-doona.sh --source` 生成：先确认标签仍指向固定提交，再执行 `git archive --format=tar --prefix=doona/ v0.1.0-beta.19 | gzip -n`（GNU gzip）。再分发 `native-ui` 二进制时，须按 GPL-3.0 第 6 条一并提供该源码包与 notices。

复现时将源码包解压到独立目录，用 Node 22+、`pnpm@11.15.1` 执行 `pnpm install --frozen-lockfile`、`pnpm build`、`SOURCE_DATE_EPOCH=1791396201 pnpm package`。该 epoch 是固定上游提交的时间；源码包不含 Git 历史。`PATH` 中须使用 GNU tar 和 GNU gzip（已验证 tar 1.35、gzip 1.15）；其他 gzip 实现即使压缩相同 tar 字节，也可能产生不同包摘要。Cargo 构建只内嵌 `HONK_DOONA_DIR` 中的文件，不构建也不下载前端。该源码的 checker 为 `tools/conformance.mjs`；live walk 只读，跳过控制、诊断和缺少已观测 ID 的资源。基础与管理契约应分别核对，浏览器操作另行验收；schema 通过不等于完整 UI、内核或部署矩阵通过。

### 连接关闭、模式与数据面生命周期

单项 DELETE 的 `204` 表示已确认精确 TCP UUID 的转发任务结束，或精确 UDP token/generation/source view 的退役、后端确认及已准入发送和回复的排空；并非只删除连接跟踪记录。共享 XUDP 只关闭本 view，不关闭其他 view 共用的 carrier，也不重放报文。同一仍在连接跟踪记录中的所有者被并发或重复关闭时，共用真实完成信号（`Pending`），继承成功或 `Failed` 结果；处于 `Closing` 或 `Failed` 状态的所有者不会被报告为 `Gone`/404。ID 不存在，或捕获的所有者已被其他 incarnation 替换时，仍返回 `Gone`/404，不可关闭的非用户态所有者返回 409，无法确认退役返回 503。批量只捕获一次匹配集合，支持 `type=tcp|udp|all`、无端口 `src`；未限制网络或来源时必须 `all=true`（仅 `type=all` 不算过滤）。超过 1000 条先返回 413，不关闭任何连接；成功返回实际 `closed/skipped`。关闭已选集合后出现的新连接不受影响；批量关闭中任一退役无法确认时，等全部已选连接处理完再返回 503，`error.details` 带 `closed/skipped` 计数，这些连接不会回滚。DELETE 请求体必须为空；重复 `Idempotency-Key` 仍检查当前连接状态，不重放旧结果。

原生 `x-honk` 扩展 `runtime_mode` 暂不可用：固定 PUT 契约未声明暂停冲突与 owner/backend 不可用的错误响应，capability 又不区分读写。GET/HEAD/PUT 均返回 `404 capability_not_supported`，不宣告接受任何 mode。内部共享的 `DatapathFlagsHandle` 及 Clash 控制仍保留；它不是 `dial_mode`，不覆盖 must/block 终态，也不合成网关规则。**仅 native 启用时**，mode/global target 是临时状态，不恢复或写入模式缓存；启动及成功显式配置激活（含 no-op）重置 rule，provider/network refresh 保留。Global 绑定稳定身份，目标消失后新流量 fail closed，不回退普通路由或改投同名替代者。Native 未启用时保留原有 Clash 缓存行为。

显式激活的提交与模式 reset 是不同结果：若 routing/config 已提交但 backend mode 写入失败，settings 已恢复配置值，而 mode/source 保留先前值，控制面关闭准入并返回 committed-degraded，operation 失败。此时既不能声称 Rule 已生效，也不能声称配置回滚；通过 Clash `/configs`（启用时）与 operation 结果检查实际状态。正常 no-op 接受也触发 reset，provider/network 更新不触发。

关闭时间没有硬上限。abort async 外层不会取消已开始的 blocking 工作。StateTick 维护 owner 超过名义停止期限后告警，继续等待实际 SQLite 工作；凭据 KDF/数据库工作及已开始的系统解析/NSS 同样保留真实 join。清理阶段超期不能丢弃 owner。关闭准入、停止 watcher 并 detach hook 后，健康运行中的连接有默认 5 秒 drain grace，随后强制取消并 join；故障退出不承诺该 grace。原生 HTTP 自身另有 5 秒 graceful drain，上述阻塞 join 仍可能延长总退出时间。

## 启用与鉴权

仅当 `experimental.clash_api.external_controller` 非空，且二进制文件包含默认启用的 `clash-api` 特性时，API 服务才会启动。控制器地址必须是 `127.0.0.1:9090` 或 `[::1]:9090` 这样的数字套接字地址，不能使用 DNS 主机名；`:port` 会绑定 `0.0.0.0:port`。无效地址只会写入日志，不会停止引擎。

当 `experimental.clash_api.secret` 非空时，API 请求必须携带：

```http
Authorization: Bearer <secret>
```

WebSocket upgrade 也可以改用 `?token=<percent-encoded-secret>`。honk 会先对 token 做 percent-decode，再精确比较。query token 鉴权仅适用于 WebSocket upgrade；普通 HTTP 请求使用 Bearer header。`secret` 为空时关闭鉴权。`/ui` 静态目录不经过 API 鉴权 layer。

**API 自身不提供 TLS。** 应将其绑定到 localhost，或在前方部署 TLS 反向代理；不可信客户端能够访问 listener 时，必须设置强 `secret`。

随附的 `config.dae` 绑定 `127.0.0.1:9090`。非回环控制器地址配合空 `secret` 时，启动会发出警告，但仍允许监听；无论是否配置防火墙，通配地址和已分配的接口地址都适用。

## 端点表

下表与 `crates/honk-core/src/clash_api.rs` 中的 router 一致。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/` | 返回 Clash hello 文档；启用外部 UI hosting 时，将非 JSON 客户端重定向到 `/ui/`。 |
| GET | `/version` | 返回 `honk <build-version>`（包含发布 tag，与 CLI 共用构建版本）及 Clash premium/meta capability flag。 |
| GET | `/configs` | 返回当前模式、已实现的 Clash 兼容配置快照，以及 `honk-diagnostics` 下当前配置的安全诊断。 |
| PUT | `/configs` | 兼容性 no-op；接受请求并返回 `204 No Content`。 |
| PATCH | `/configs` | 将 `mode` 设为 `Rule`、`Global` 或 `Direct`；匹配不区分大小写。 |
| GET | `/proxies` | 返回所有节点和组，以及合成的 `GLOBAL` Selector。 |
| GET | `/proxies/{name}` | 返回一个节点、组或 `GLOBAL` Selector。 |
| PUT | `/proxies/{name}` | 用 `{"name":"member"}` 选择 Selector 组的直接成员；也可修改合成的 `GLOBAL` Selector。包括 Score 在内的自动组会拒绝写入。 |
| GET | `/proxies/{name}/delay` | 使用调用方的 `?url=`，对节点或组执行按需代理延迟测试。已预热的传输会复用；每个尚未预热的可复用会话或 QUIC 客户端都会先在临时运行时中预热，再开始计时。 |
| GET | `/group/{name}/delay` | 使用调用方的 `?url=` 测试全部组成员，最多并发 `URLTEST_MAX_CONCURRENT`（10）次代理拨号，并以相同计时语义返回成功成员的延迟。 |
| GET | `/rules` | 每条路由返回一行。简单 matcher 使用原生 Clash rule type；组合、取反和 `must` 规则使用 `complex`，并保留完整 dae 语句。 |
| GET | `/connections` | 返回连接快照；WebSocket upgrade 后改为推送快照。 |
| DELETE | `/connections` | 关闭所有已跟踪连接。 |
| DELETE | `/connections/{id}` | 关闭一个已跟踪连接。 |
| GET | `/traffic` | 通过 WebSocket 或分块 JSON 行推送每秒流量。 |
| GET | `/memory` | 通过 WebSocket 或分块 JSON 行推送进程 RSS。 |
| GET | `/stats` | 返回下文所述的用户态出站、ready pool、热资源、Score 选路原因和 UDP 快照。 |
| GET | `/logs` | 通过 WebSocket 或分块 JSON 行推送 tracing 事件；所有订阅者共用一个 256 槽位的广播队列，`?level=` 默认为 `info`。 |
| GET | `/dns/query` | 经 honk DNS 解析 `?name=` 并返回 DoH 风格 JSON；`?type=` 默认为 `A`。 |
| POST | `/cache/fakeip/flush` | 相容 no-op，返回 204；没有持久化 FakeIP 映射可清除。 |
| POST | `/cache/dns/flush` | 清除存活 DNS cache 及其持久化 DNS 状态。 |
| GET | `/providers/proxies` | 将非空组暴露为 Clash proxy provider。 |
| GET | `/providers/rules` | 返回当前空桩文档 `{"providers":[]}`。 |
| GET | `/ui`, `/ui/*` | 将 `/ui` 重定向到 `/ui/`，并提供已配置的外部 UI 目录。 |

对普通 HTTP GET，`/traffic`、`/memory` 和 `/logs` 每行发送一个 JSON 文档。`/logs` 只在存在订阅者时启用动态 `tracing` 事件过滤；无订阅者时，Clash 日志层不格式化事件。每个订阅者的级别过滤发生在共享队列之后。订阅者落后时会跳过被覆盖的事件，且不会收到事件丢失标记。

### `/configs` 中的诊断信息

`GET /configs` 保留现有 Clash 字段，并新增 `honk-diagnostics`。
配置项和诊断信息来自同一份已提交的配置快照。启动时只发布通过准入检查的
文件和订阅诊断。重载失败或订阅刷新被拒绝时，当前诊断列表保持不变；
接口不缓存最近一次失败尝试。

有效配置未变的成功重载可以替换诊断信息而不递增 `generation`。订阅刷新通过授权和
准入检查后，只替换该订阅的诊断，即使节点未变也是如此；
静态文件和其他订阅的诊断保持不变。

库调用方须向 `ControlPlane::reload_runtime_config(config, diagnostics)` 传入 `DiagnosticBuckets`，分别保留静态配置与订阅正文的诊断；没有诊断的程序构造输入使用 `DiagnosticBuckets::default()`。`merge_subscription_nodes(provider, nodes, diagnostics)` 接收该订阅的诊断向量，也支持已准入但没有 worker 声明的订阅。完整配置替换会移入候选配置的全部诊断来源信息，订阅替换只影响对应订阅。SIGHUP 仅保留重建候选配置时实际沿用的订阅正文的诊断；自动生成的拓扑/ECS 更新保留原输入来源。所有修改沿用配置写锁的发布屏障，先获取配置锁，再获取诊断锁。

完整替换载荷中的 provider bucket 必须使用唯一 UUID。重复 UUID 会在发布前拒绝整个重载，即使有效配置未变也是如此；当前配置与诊断保持不变。

| 字段 | 含义 |
| --- | --- |
| `honk-diagnostics.generation` | 当前配置的 `generation`；启动时为 `0`。 |
| `honk-diagnostics.sources` | 保留的诊断所引用的来源及这些来源的祖先，仅包含元数据。 |
| `sources[].id` | 本次快照内的不透明数字来源标识，供 `diagnostics[].source` 引用。 |
| `sources[].ordinal` | 来源在单次解析尝试的来源表中的原始序号，从 `0` 开始。 |
| `sources[].parent` | 父来源的 `id`；根来源为 `null`。 |
| `honk-diagnostics.diagnostics` | 当前配置和已准入订阅保留的安全诊断。 |
| `diagnostics[].code` | 稳定的诊断代码。 |
| `diagnostics[].severity` | 小写严重级别：`info`、`warning` 或 `error`。 |
| `diagnostics[].source` | 对应的 `sources[].id`。 |
| `diagnostics[].span` | 从 `0` 开始的字节范围 `{start, end}`，不含 `end`；未知时为 `null`。 |
| `diagnostics[].line` | 原始文本中的行号；未知时为 `null`。 |
| `diagnostics[].byte_column` | 按字节计数的列号；未知时为 `null`。 |
| `diagnostics[].setting` | 含原始条目序号的固定配置字段路径，不含用户提供的名称。 |
| `diagnostics[].value` | 安全值表示；私有值经过脱敏。 |
| `diagnostics[].message` | 静态诊断消息。 |
| `diagnostics[].entry_index` | 原始条目序号；未知时为 `null`。 |
| `diagnostics[].related_indices` | 相关原始条目的序号。 |
| `diagnostics[].terminal` | 该诊断是否表示本次尝试的终止错误。 |

配置的 `generation` 与当前 DNS 运行时一致。来源标识仅在本次快照内有效，不是文件系统标识。
来源先按静态文件、再按配置中的订阅声明顺序排列，最后按保留 bucket 的顺序列出已准入的非 worker 订阅；各来源表保留原始顺序。
仅列出诊断引用的来源及其祖先，不导出文件路径、原始输入、凭据、订阅名称或订阅 ID。

### 延迟测量

调用方通过 `?url=` 指定测试 URL。组请求最多同时执行 `URLTEST_MAX_CONCURRENT`（10）项经代理的测量。

延迟测试使用规范的 HTTP 检查目标解码器：HEAD 保留原始路径与查询串（包括点段和仅查询串的 `/?query`），authority 移除凭据和默认端口，fragment 不会发送。它与周期健康检查共享 HTTP 实现，报告第二轮请求的热路径 RTT，不含代理拨号、目标 TLS 与第一轮请求。HTTPS 验证证书，协商 HTTP/2 或 HTTP/1.1，并禁用 server push。两轮最终响应的解码状态都必须为有效的 200–499。第二轮传输失败或超时可回退到已验证的第一轮样本；HTTP/1 部分响应即使超时也不回退，而正常 HTTP/2 GOAWAY 可以回退。每轮 HTTP/1 临时响应头与最终响应头的累计上限为 16 KiB，H2 响应头列表上限同样为 16 KiB。session 预热、拨号、目标 TLS、H2 启动与每轮请求分别使用阶段预算。冷可复用 generation 探测使用带 guard 的临时 runtime，结束后关闭；HTTP/2 driver 在完成或取消后释放，因此组扫描不会为每个已测试节点留下新的常驻可复用 runtime。

当前锁定依赖的已知限制：[`h2` 0.4.19 可能把缺少 `:status` 的响应报告为 200](https://github.com/hyperium/h2/issues/958)，因此这种畸形 HTTP/2 响应仍可能得到成功的延迟结果。[上游修复 #959](https://github.com/hyperium/h2/pull/959) 已合并，但当前锁定版本尚未包含；等待包含修复的正式版本后更新依赖，不使用本地 fork/vendor 补丁。

成功测量会更新节点延迟历史。单节点失败返回 `503`，组测量会省略失败成员；任意手动测试目标的失败不会增加真实拨号失败连续计数。

按需 delay exchange 保留 Alive/API 延迟历史，但不报告业务结果，也不填充配置 Score 比较 cohort。实际的前置 server/session 准备可报告聚合预热 setup；不会把调用方 URL 虚构为预热自身目标，也不提供晋升证明。

两个延迟接口都会持有已接纳的任务直到测量清理结束，即使 HTTP 客户端已经断开。owner 接纳失败的 `503` 响应会区分容量耗尽、检查已停止，以及 worker 失败。QUIC 探测超时或正常关闭等待属于测量结果，不代表健康检查 owner 失败：有限的对端通知宽限期结束后，先停止并 join Quinn driver，再停止并 join packet-adapter worker。真正的受管 worker 失败仍会关闭健康检查接纳。

### Score 组表示

配置为 `policy: score` 的组始终可用，并为兼容 Clash 表示成 `type: "url_test"`。其 `all` 列表与其他组一样保留直接成员 tag，`now` 则报告当前聚合 TCP 胜者，而不是泄露某个精确目标的私有选择。Score 始终保持自动且权威：`PUT /proxies/{name}` 会被拒绝，不会固定成员。评分 cell 与仅由 scorer 持有的目标数据不会新增到 proxy 文档；`/stats.score` 只包含下文的安全聚合计数。`/connections` 只保留原有的目标元数据。

## 模式与 Selector 修改

`PATCH /configs` 接受如下 JSON 对象：

```json
{"mode":"Global"}
```

模式更新经过 `DatapathFlagsHandle`；它是 shared mode 与 `DATAPATH_FLAGS_MAP` 唯一的串行化 writer。因此模式修改会与 reload 的 NFQUEUE fence、reopen 和 disable 操作原子组合，不会重新发布过期的 readiness bit。规则派生的 feature bit 属于不可变的路由 policy descriptor。Native 未启用时，启用 cache database 会保存规范化模式；native 启用时两种 API 共用不恢复、不持久化且在显式配置激活后重置为 Rule 的临时模式。

`PUT /proxies/{name}` 不要求特定 `Content-Type`。对已配置 Selector，目标必须是直接成员 tag；只能经嵌套组到达的叶节点并非直接成员。写入同时原子设置 TCP/UDP，Clash `now` 只显示 TCP；原生 API 可分别设置两种网络。有效变更通过共同 control/reload owner 发布，启用 `cache_file` 后分别持久化网络选择。`interrupt_connections` 按建立时捕获的组路径及发生变化的网络关闭精确 TCP/UDP owner，并等待确认，不再只删 tracker。已有选择不触发中断；URLTest、LoadBalance、Fallback 与 Score 拒绝手动选择。

`GLOBAL` 是合成 Selector，但其 `all` 中每个成员都是具体的已配置组或节点，并有对应的顶层 proxy 文档。`PUT /proxies/GLOBAL` 只接受其中的名称，并通过同一个 `DatapathFlagsHandle` 更新。Native 未启用时，cache database 以 `GLOBAL` key 保存选择，空值、已移除、未知及旧虚拟选择会回退到第一个具体成员；native 启用时保留共用的稳定目标身份，不持久化，目标消失不自动改投同名对象或其他成员。

## 外部 UI hosting

设置 `experimental.clash_api.external_ui` 以提供静态 dashboard 目录。目录缺失或为空时，honk 会在后台下载 ZIP；启动不会等待，文件可用前静态路由返回 `404`。`assets.ui.url` 会替换内建 zashboard URL，`HONK_UI_DOWNLOAD_URL` 则保持最高覆盖优先级。

每次下载请求（含重定向）只接受 HTTP(S)，最多跟随五次重定向，下载的 ZIP 正文上限为 128 MiB。允许 HTTPS 降级到 HTTP，也允许 URL 直接使用 IP 地址；每一跳遵循路由或 `assets.ui.route`、`assets.route` 中的生效出口。

`assets.ui.route` 优先于 `assets.route`，适用于初始请求和每次重定向。`direct` 使用直连 HTTP client，组名强制经过选中的出站叶节点。没有配置出口时，每个 URL 遵循 honk 当前的流量路由决策：`direct` 使用直连 HTTP client，`block` 中止下载，proxy 结果使用选中的出站叶节点。每次直连或经代理且实际经过 Score 组的 HTTP 请求，都会向路径经过的 Score 组报告真实 host/IP、端口、setup、首响应、字节与终态；其他路径不创建评分 reporter 或 cell。setup 在连接/TLS 准备完成后、发送 HTTP 请求前记录；首响应仍由实际响应触发。共享 HTTP 错误保留原始 typed cause：目标故障保持 target 归因，typed carrier 故障即使在 setup 后仍保持 node 归因。下载或解压失败只写日志，不会停止引擎。

## `GET /stats`

`GET /stats` 是用户态快照，而不是 eBPF `OUTBOUND_STATS` map，也不暴露该 map 的报文 counter。固定 TCP、UDP 和 NFQUEUE schema 不创建动态的逐节点 label。

```text
{
  outbounds: [{ name, totalConns, activeConns, upload, download, errors }],
  pool: { readyHits, readyMisses, entries },
  quic: {
    activeConnections, srttUs, cwndBytes, flowReceivedBytes, flowSentBytes,
    receiveWindowBytes, receiveWindowAvailableBytes, streamReceiveWindowBytes,
    sendWindowBytes, sendWindowAvailableBytes, lossRatePpm, sentPackets,
    ackFrames, lostPackets,
    sentPlpmtudProbes, lostPlpmtudProbes, currentMtu, blackHoles,
    congestionEvents, txBytes, rxBytes, txDatagrams, rxDatagrams, txIos, rxIos,
    transportTxWouldBlock, transportTxDrops, transportRxDrops, sessionRxDrops,
    sendTimeouts, pathStalls
  },
  warm: {
    nodes: { preconnect, health, udp, selector, traffic },
    sessions: { anytls, vless, tuic, juicity, hysteria2 }
  },
  tcp: {
    activeFlows, limit, capacity: { rejected }
  },
  score: {
    groups: [{ name, tcp: R, udp: R, verification: { tcp: V, udp: V }, budget: { tcp: B, udp: B } }],
    businessStarts,
    cache: {
      exactCells, aggregateCells, exactEvictions, aggregateEvictions,
      comparisonCells, comparisonLogicalBytes, comparisonLogicalCapacity,
      comparisonEvictions, comparisonExpired, comparisonRejected
    }
  },
  udp: {
    endpoint: { hits, misses },
    latency: {
      route: H, dial: H, replyReady: H, firstSend: H, firstReply: H
    },
    capacity: { rejected },
    slowPermit: { accepted, rejected, closed },
    queue: { accepted, full, flowFull, globalPayloadFull, closed },
    firstSend: { failures },
    stagger: { attempts, winners, cancellations },
    warm: { attempts, successes, failures },
    nfqueue: {
      received, activeFlows, kernelQueueDepth, kernelStatsAvailable,
      kernelStatsReadErrors, kernelDropped, kernelUserDropped, heldPackets,
      heldPeak, socketReceiveBufferBytes, actorQueueFull, correlatorFull,
      actorQueueDepth, actorQueuedBytes, actorOldestAgeNanos, directAccepted,
      proxyCopied, proxyDropped, block, cancel, drop, tokenMismatch,
      tokenExhaustion, tokenRollovers, verdictErrors, receiptToVerdict: H
    }
  }
}
H = { count, sumNanos, buckets }  // buckets has 64 fixed log2 slots
R = {
  coldExplore, periodicExplore, reliabilityWinner, performanceWinner,
  incumbentHeld, insufficientEvidenceHeld, directionalTradeoffHeld, incumbentIneligible,
  freshFailureBypass, deadFiltered, ordinarySwitch, switchFlap,
  failStreakExcluded, exploreBackedOff, carrierPressure, carrierRttPressure,
  carrierLossPressure, carrierValidation
} // every R value is a u64 count
V = { provisionalSelections, usableSelections, validationSelections }
B = { businessStarts, sources: { cold, periodic, recovery }, trialStarts,
      reserved, spent, budgetBlocked, inFlightBlocked, refunded, expired,
      coldAllowance, coldAvailable, earnedAvailable, earningPeriod, scopes,
      trialSuccess, trialFailure, trialCancelled, trialSetupHistogram,
      trialSetupMillis, trialElapsedMillis }
```

### TCP 字段

| 字段 | 含义 |
| --- | --- |
| `activeFlows` | 当前持有 TCP admission permit 的透明 TCP 流。 |
| `limit` | 当前进程级 TCP 流准入上限；从描述符导出的 floor 开始，并随空闲描述符余量动态扩缩。 |
| `capacity.rejected` | 因 TCP 预算已满而等待 permit 的 accept-loop 单调计数；accepted socket 保留在内核 backlog 中，不会被丢弃。 |

### QUIC 字段

`srttUs`、`cwndBytes`、`currentMtu`、`receiveWindowBytes`、`receiveWindowAvailableBytes`、`streamReceiveWindowBytes`、`sendWindowBytes` 和 `sendWindowAvailableBytes` 是活动连接的平均值；没有活动连接时为零。`flowReceivedBytes` 统计已交付给应用的 stream 字节，`flowSentBytes` 统计已被对端确认的 stream 字节；与报文、UDP 字节、I/O、丢包、黑洞和拥塞计数一样，它们包含已完成的池化连接。

池中的 TUIC、Juicity 与 Hysteria2 连接每秒采样一次 flow-control 状态。收发方向的十秒 goodput EWMA 必须在 RTT 至少 80 ms 且连续三个样本确认高 BDP 后，才会把 connection 接收或发送 floor 提高到约 `2 x BDP`。peer 发来的 `DATA_BLOCKED` / `STREAM_DATA_BLOCKED` 直接表明窗口已成为瓶颈；此时不受 RTT 门限限制，connection 或 stream 的接收 floor 直接加倍。窗口限制流量时，goodput 估计值也偏低，不能作为升档的依据。零进展样本只有在对应 connection credit 仍受限时才会保留，但不推进 streak。每个 floor 独立执行五分钟调整冷却，自动提高的上限为 32 MiB，但不会降低更大的显式配置。honk 不会因应用需求低而缩小已学习窗口，也不会热切换拥塞控制。

`ackFrames` 统计收到的 ACK frame，是路径进度信号；重复 ACK frame 可能被重复计数。`lossRatePpm` 排除 PLPMTUD 探测：分母为 `sentPackets - sentPlpmtudProbes`，而 `lostPackets` 同样不包含探测丢包。`sentPlpmtudProbes` 与 `lostPlpmtudProbes` 单独暴露探测计数。`txIos` 与 `rxIos` 表示批处理效率。`transportTxWouldBlock` 统计满载的 64 包 adapter 队列（Quinn 会重试）；底层代理报告拥塞或超时后主动丢弃的报文计入 `transportTxDrops`；满载的 adapter 接收队列计入 `transportRxDrops`，满载的 TUIC/Hysteria2 256 包会话队列计入 `sessionRxDrops`。`sendTimeouts` 统计启用指标的连接上、仍被计入当前 no-ACK 等待时发送截止时间到期的 UDP 报文发送；它是拥塞诊断，不是全部超时、节点故障或恢复次数。`pathStalls` 统计路径 watchdog 在完整 no-ACK grace 后退役的共享 QUIC 连接；不是丢包数、受影响 flow 数或恢复次数。两者都是进程生命周期内的累计值。

### Score 选路原因字段

`score.groups` 是经鉴权 `/stats` 响应中的附加部分。当前没有任何组使用 `policy: score` 时它为 `[]`；否则它包含每个当前 Score 组（包括没有解析出叶节点的组），按 `name` 的字典序排列。每组始终都有 `tcp` 和 `udp` 对象，且每个对象始终包含全部 `R` 字段；没有网络活动时以零表示，绝不省略字段。

每个 `R` 值是饱和 `u64` 计数，不是延迟、吞吐或健康测量。一次已授权的多候选 Score Apply 记录一个最终原因：`coldExplore` 或 `periodicExplore` 表示验证；`incumbentIneligible` 表示现任已不满足普通资格；`freshFailureBypass` 表示合格现任的业务失败尚未恢复；`insufficientEvidenceHeld` 表示没有挑战者获得晋升且普通 utility 赢家缺少合格的共同性能比较；`directionalTradeoffHeld` 表示无挑战者晋升时，某个比较在一个已知方向提升至少 10%，另一个已知方向却退化超过 10%；`incumbentHeld` 表示比较优势未跨过保持门槛；其余 `reliabilityWinner`、`performanceWinner` 保留按替代候选资格分类的含义。`performanceWinner` 本身不证明提速或发生切换，`insufficientEvidenceHeld` 不表示可靠性历史缺失。`ordinarySwitch` 统计实际普通已提交 A→B 选择；`switchFlap` 统计其中同目标八次普通选择内返回前一赢家的情况。首次选择、试用及缺少之前历史时不能增加切换计数。`deadFiltered`、`failStreakExcluded` 和 `exploreBackedOff` 按 rank 累计受影响候选。Peek、API 读取、单例与最后尝试旁路不增加这些原因计数；嵌套组 rank 与实际出站连接并非一一对应。

对 UDP，`deadFiltered` 也统计因协议／配置不具备 UDP 能力而被排除的候选；它不是新发生故障的节点数或业务尝试数，这类排除不会增加 Score 失败或探索退避。

`carrierPressure` 统计被已有组／网络聚合 cell 接收的新鲜 carrier 地址族事件，不是包数或失败连接数；重复心跳读取不增加它。`carrierValidation` 统计普通赢家具有晚于上次验证的 carrier 提示时发生的周期验证选择；它是可重叠的诊断计数，不是新的互斥原因，也不证明只有该提示导致选择。提示不改变业务可靠性、资格或健康。字段在 API 读取时只读；carrier 观测由控制心跳接入，与选路调用独立。

`carrierRttPressure` 与 `carrierLossPressure` 保留被接收事件的原因。两种条件同时满足时，两个原因计数均增加，但 `carrierPressure` 只增加一次。这些可重叠计数不标识具体 carrier／传输协议，不是应用丢包率，也不增加失败；重复或过期提示均不增加它们。TCP 的 loss pressure 表示重传压力，不代表已确认应用包丢失。

计数在进程启动时从零开始，只在进程内存中累积。只要组名仍在已提交配置中，成功 reload 会保留它们，包括零叶节点以及临时 Score→非 Score→Score 转换；非 Score 组不会显示在此响应中。已提交的删除会清除该名称的计数，之后重新创建同名组从零开始。受 generation fence 约束的已淘汰 manager 在被替换后不能再修改计数，即使同名组随后被重新创建。快照在 JSON 序列化前复制，读取不会改变选路状态。

`/stats.score` 公开组名、固定的 TCP/UDP 原因、验证与预算字段、根业务计数，以及有界证据缓存总量，不包含节点身份、目标/domain/IP/port、原始 cell、cadence 键、authority 或凭据。`/proxies` 中既有公开成员名和 `/connections` 中目标元数据保持不变。

### Score 验证信息

`/proxies` 与 `/proxies/{name}` 中的 Score 组增加 `scoreVerification`。固定目标为 `responseQualityWithAvailability`，范围为 `aggregate`，不是对每个精确目的地的认证。`tcp` 和 `udp` 分别包含：

| 字段 | 含义 |
| --- | --- |
| `selected` | 本次只读判定对应的既有公开成员 tag；没有普通合格候选时为 null。存在时 TCP `now` 使用同一次判定的选择。 |
| `state` | `provisional` 或 `observedUsable`；后者要求连续 cohort 中四个不同的定向 Traffic reporter 在 setup/TX 后收到 RX，最近合格 RX 不足 60 秒。适用失败／reload 或 60 秒间隔重置 cohort，clone／重复回包不能增加信用。这不授予冷启动资格；真正失败后的 cohort 可独立用同样四份信用取得作用域恢复，聚合可用性不代表每个精确目标合格。 |
| `challengers` | `selected` 与已评估挑战者之间新鲜的成对响应比较；见下文。 |
| `nextAction` | `nextBusinessFlow` 表示未来真实工作补充证据、普通资格或恢复的需求，不是已预留或已派发 I/O；需同时查看 `waitReason`。`backoff` 保留失败隔离；`none` 表示没有可执行的缺失工作。缺少传输证据不会创建工作；方向 goodput 等待真实负载。 |
| `question` | `none`、`availability`、`response`、`qualification` 或 `recovery`：下一个尚未解决的证据问题。没有剩余动作时为 `none`；退避时保留被阻塞候选的问题，不回退到已解决现任的问题。 |
| `waitReason` | `none`；`budget` 表示没有可用额度，或选择可用时试用因反复失败而暂停；`comparableTraffic` 等待未来可比业务；`inFlight` 表示已有足够的同目标工作，或已达到独立的每节点四项工作上限；`backoff` 保留失败隔离。聚合读取检查已保留 IPv4/IPv6 作用域，不创建它们：两者预算均阻塞才返回 `budget`；任一可用／未创建作用域允许继续等待未来可比流量；其余情况保留在途等待。等待不证明工作必然成功。 |
| `coverage` | `scope`（`all` 或 `bounded`）；`candidates` 统计当前可见候选全体，`evaluated` 是该视图与共享服务池的交集，`unevaluated` 是两者之差。胜者不额外占位。父组入口与 target 共用该池，TCP／UDP 分开。池外成员不接受普通或可选策略工作；这些数量不是所有存量连接涉及的节点总数。`pending` 统计仍有未决问题的已评估成员，包括已有比较但仍需资格或恢复工作的成员。 |
| `network`、`targetFamily`、`healthFamily`、`targetSpecific` | transport 与适用范围；此聚合接口没有精确目标，不导出 domain/IP/port 或原始节点 ID。 |

Readonly／Peek 使用已提交参与者，不重新排名。Apply 初始化并刷新参与者。初始化前，只读查询使用临时有界投影。见[评估集生命周期](../design/groups.md#有条件的验证结论)。

`challengers` 列出所选成员当前的原始比较对（即普通晋升读取的同一批比较对）中具有新鲜合格响应指标的项；没有该指标的成员不出现，都没有时为空列表。每项包含 `name`（公开成员 tag，仅作显示，嵌套路径下可能重名）、`basis`（`targetResponse`、`commonTargets` 或 `configuredProbe`）、`relation`（`selectedFaster`、`equivalent` 或 `challengerFaster`）、`reporters` 与 `validForMs`。`equivalent` 对实际响应值使用包含边界的对称区间 `high - low <= 0.1 × low`，包括零与亚毫秒值。`reporters` 是双方已保留的不同 reporter 支持量中的较弱值：四个块各保留最多四个 ID，跨块去重并集最多十六个，不是所有已观测 reporter 的精确总数。`validForMs` 是该响应指标的剩余有效期。业务块为 15 秒，在块起点后 60 秒到期；配置探测按生产者周期 `I` 使用 `max(15s, 2I)` 块，有效期同时受最早支持块的四块保留期限与“较弱一侧最近支持加 `max(60s, 2I)`”限制。失败／reload／incarnation 边界保持不变。`commonTargets` 最多使用八个规范、等权、响应合格的共同目标，不是无关聚合均值；setup 与预热不是比较证据。

关系只描述测得的响应时间：它不是晋升决定，不是可靠性或带宽结论，不代表误判概率或保证最优，也不能证明所选成员优于列表之外的成员。普通切换仍使用自身依赖完成数的门槛，以及可靠性、可用性与方向保护。查询不派发验证，也不改变计数。

`/stats.score.groups[].verification.tcp` 与 `.udp` 增加饱和计数：`provisionalSelections`、`usableSelections`、`validationSelections`，只在授权 Apply 时推进。

### Score 工作预算与观测成本

`/stats.score.businessStarts` 对嵌套组去重，统计唯一原始 Score 业务开始。`/stats.score.groups[].budget.tcp` 与 `.udp` 聚合保留的目标地址族作用域；不能把嵌套组总量相加当作唯一业务数。原始业务被选为试用时仍计数，延续尝试即使切换网络或目标地址族，也不赚取另一份原始额度。节点专属工作早于代理 DNS／物理拨号准入等待开始，与 reporter 的物理／逻辑 I/O 边界独立。DNS 查询生命周期准入是在此前同步检查池是否开放，不是物理拨号准入等待。

预算计数器反映已记录的账本值。只读等待和冷启动判定还会考虑过期未开始预留中可退回的额度，但不更新 `refunded`、`expired` 或其他计数器。

| 字段 | 含义 |
| --- | --- |
| `businessStarts`、`scopes`、`earningPeriod` | 保留作用域原始开始数之和、作用域数，以及各作用域中最快的当前赚取周期 `q`：通常为 16；若该组近期每秒至少两条业务且作用域近期试用大多成功则为 8（尚无作用域时为 0）。它不能作为合并作用域预算公式的分母：每个作用域在创建时固定冷启动额度 `B`，每个原始开始按当时的 `q` 累积 `1/q`；每个作用域的 `spent + reserved` 不超过 `B` 加已赚额度的整数部分。 |
| `sources.cold`、`sources.periodic`、`sources.recovery` | 按来源区分的已开始工作：冷额度试用、已赚额度试用、不增加可选额度的延续尝试。`recovery` 包含 TCP 替代、DNS 改路／UDP 转 TCP 和 UI 重定向，不限于出错后的重试；它既不是可选试用，也不是新原始业务。普通非试用没有来源桶。 |
| `trialStarts`、`spent`、`reserved` | 已开始可选试用、累计已支出 token，以及尚未开始的 token 预留。开始只支出一次，开始后取消不退款。 |
| `coldAllowance`、`coldAvailable`、`earnedAvailable` | 固定初始额度与当前可用额度的合计。每作用域最多保留八个未花费已赚 token。时间、读取、目标变动与证据过期不赚额度，保留作用域在 reload／成员变化后不重置。 |
| `budgetBlocked`、`inFlightBlocked`、`refunded`、`expired` | 预留被拒计数（`budgetBlocked` 也计入作用域因试用反复失败而暂停时拒绝的候选）、最后引用释放／未开始失效的退款数，以及在途跟踪项过期数。只有未开始预留可退款；跟踪过期不退回已开始工作的支出。 |
| `trialSuccess`、`trialFailure`、`trialCancelled` | 已开始可选试用的 exactly-once 终态；拒绝／关闭／中性取消归入 `trialCancelled`。`trialFailure` 是实际观测失败，不是相对于未观测替代路径、因选择试用而额外造成的失败。 |
| `trialSetupHistogram`、`trialSetupMillis`、`trialElapsedMillis` | 八个固定 log2 毫秒 setup 桶（slot 0 包含 0–1 ms，末槽包含 128 ms 及以上）、已观测 setup 时长之和，以及开始至终态时长之和。它们是实际试用成本，不是因果额外延迟或开销。 |

`/stats.score.cache.comparisonCells` 上限为 512。`comparisonLogicalBytes` 计入比较存储、vector 容量及所持有键容量；`comparisonLogicalCapacity` 是按实现结构大小计算的最坏分配界限，不超过 1 MiB。两者均不是实测进程 RSS 或全部 Score 状态大小，均不包含分配器开销与进程其他分配。`comparisonEvictions`、`comparisonExpired`、`comparisonRejected` 统计存储移除／准入事件；只读过期可以先使支持失效，实际移除后才增加计数。既有精确／聚合 LRU 字段不变。

### 出站与 ready pool 字段

| 字段 | 含义 |
| --- | --- |
| `outbounds[].name` | 出站名称。 |
| `outbounds[].totalConns` | 经该出站启动的连接数。 |
| `outbounds[].activeConns` | 当前经该出站打开的连接数。 |
| `outbounds[].upload` | 用户态中从客户端到 proxy 的字节数。 |
| `outbounds[].download` | 用户态中从 proxy 到客户端的字节数。 |
| `outbounds[].errors` | 归因于该出站的连接尝试失败数。 |
| `pool.readyHits` | ready 裸连接 pool 命中数。 |
| `pool.readyMisses` | ready 裸连接 pool 未命中数。 |
| `pool.entries` | 当前 ready 裸连接条目数。 |

### Histogram 格式

每个 `H` 都是 `{count, sumNanos, buckets}`。`count` 是观测数，`sumNanos` 是以纳秒计的总和。`buckets` 是包含 64 个非累积计数的数组：slot $n$ 覆盖 $2^n$ 到 $2^{n+1}-1$ ns，slot 0 还包含零，最后一个 slot 在 `u64::MAX` 饱和。

### UDP 字段

| 字段 | 含义 |
| --- | --- |
| `endpoint.hits` | 已建立 UDP endpoint fast path 处理的报文数。 |
| `endpoint.misses` | cold flow 的 endpoint lookup miss 数。 |
| `latency.route` | cold route selection 延迟。 |
| `latency.dial` | cold UDP dial attempt 延迟。 |
| `latency.replyReady` | endpoint driver commit 前同步准备 reply socket 的延迟。 |
| `latency.firstSend` | 首次发送尝试延迟。 |
| `latency.firstReply` | 首个应答成功重新注入客户端之前的时间。 |
| `capacity.rejected` | 精确 endpoint capacity reservation 被拒次数。 |
| `slowPermit.accepted` | 进入活动 UDP slow path 的 admission 数。 |
| `slowPermit.rejected` | 因 shared connection semaphore 已满而拒绝的 slow-path admission 数。 |
| `slowPermit.closed` | generation draining 期间拒绝的 slow-path admission 数。 |
| `queue.accepted` | 进入有界 endpoint-driver queue 的报文数。 |
| `queue.full` | retained queue 的 drop-newest 事件总数。 |
| `queue.flowFull` | 单 flow packet slot 上限导致的 drop-newest 数。 |
| `queue.globalPayloadFull` | 全局 retained payload byte 上限导致的 drop-newest 数。 |
| `queue.closed` | 对正在关闭或已关闭 endpoint driver 发起的 queue 尝试数。 |
| `firstSend.failures` | 首次发送错误或超时数；两者都按 ambiguous send 处理。 |
| `stagger.attempts` | 已启动的 cold URLTest speculative preparation 尝试数。 |
| `stagger.winners` | 首个满足条件且成功的 staggered preparation 数。 |
| `stagger.cancellations` | 其他 candidate 获胜后取消的已启动 speculative preparation 数。 |
| `warm.attempts` | 已启动的 generation-owned UDP warm dispatch 数。 |
| `warm.successes` | 返回 `Ready` 的 warm dispatch 数。 |
| `warm.failures` | generation 仍存活时的真实 warm failure 数。`NotApplicable` 保持中性。 |

`queue` 衡量 endpoint-driver queue；它不同于衡量 UDP slow path admission 的 `slowPermit`。

### NFQUEUE 字段

| 字段 | 含义 |
| --- | --- |
| `received` | NFQUEUE listener 投递的报文数。 |
| `activeFlows` | 当前由 pending-verdict correlator 持有的 flow cell 数。 |
| `kernelQueueDepth` | 当前活动 kernel queue 实例中的排队报文数。 |
| `kernelStatsAvailable` | 最近一次 kernel queue statistics 读取是否成功。 |
| `kernelStatsReadErrors` | 累计 kernel queue statistics 读取失败数。 |
| `kernelDropped` | 因 kernel NFQUEUE 达到 queue 上限而丢弃的报文数；跨 queue hard rebind 累加为进程生命周期 counter。 |
| `kernelUserDropped` | kernel 向用户态投递 NFQUEUE message 时丢弃的报文数；跨 queue hard rebind 累加为进程生命周期 counter。 |
| `heldPackets` | 当前已投递但 verdict guard 仍被持有的报文数。 |
| `heldPeak` | queue service 报告的同时持有 verdict guard 峰值。 |
| `socketReceiveBufferBytes` | netlink socket 的有效接收 buffer 大小。 |
| `actorQueueFull` | 因有界 ingest actor queue 已满而 fail-closed 丢弃的报文数。 |
| `correlatorFull` | 达到任一 correlator 硬上限时丢弃的报文数：4,096 个 flow cell 或每流 64 个 retained verdict。 |
| `actorQueueDepth` | 当前 ingest actor queue 条目数。 |
| `actorQueuedBytes` | 当前 ingest actor queue 保留的 payload 字节数。 |
| `actorOldestAgeNanos` | 当前最老 ingest actor 条目的年龄，单位为纳秒。 |
| `directAccepted` | direct 决策成功执行 marked `NF_ACCEPT` verdict 的次数。 |
| `proxyCopied` | payload 所有权转交给规范 UDP 初始化器的次数。 |
| `proxyDropped` | proxy 决策成功对原始报文执行 `NF_DROP` verdict 的次数。 |
| `block` | policy block 成功执行 drop verdict 的次数。 |
| `cancel` | cancellation 成功执行 drop verdict 的次数。 |
| `drop` | 其他成功执行的 fail-closed drop verdict 数。 |
| `tokenMismatch` | 过期或不匹配的 decision token/flow identity 事件数。 |
| `tokenExhaustion` | 观测到持久化 decision-token allocator 耗尽的次数。 |
| `tokenRollovers` | token 耗尽后成功进行 generation rotation 的次数。 |
| `verdictErrors` | `NF_ACCEPT` 或 `NF_DROP` 操作失败数。 |
| `receiptToVerdict` | 从 listener 收包到成功 terminal verdict 的 histogram；它不是 kernel queue residence time。 |

独立的一秒 sampler 读取自有 kernel queue，不依赖报文 dispatch。读取失败后，先前的 `kernelQueueDepth`、`kernelDropped` 和 `kernelUserDropped` 仍保持可见，而本地 held-packet 与 receive-buffer gauge 继续刷新。

### 热资源字段

| 字段 | 含义 |
| --- | --- |
| `warm.nodes.preconnect` | 归因于启动时裸 TCP preconnect 的热节点。 |
| `warm.nodes.health` | health probing 期间观测到的热节点。 |
| `warm.nodes.udp` | 归因于 UDP warm coordinator 的热节点。 |
| `warm.nodes.selector` | 作为已配置 Selector 叶节点而保留的热节点。 |
| `warm.nodes.traffic` | 没有显式 attribution mark、因而归因于 traffic 的热节点。 |
| `warm.sessions.anytls` | 保留的 AnyTLS pool session 数。 |
| `warm.sessions.vless` | 保留的 VLESS pool session 数。 |
| `warm.sessions.tuic` | 已占用的 TUIC client slot 数。 |
| `warm.sessions.juicity` | 已占用的 Juicity client slot 数。 |
| `warm.sessions.hysteria2` | 已占用的 Hysteria2 client slot 数。 |

一个节点可以同时计入多个显式原因。gauge 跟随当前 runtime generation；已排干资源会从下一次快照中消失。

## Related docs

- [Experimental 配置](./experimental.md)
- [NFQUEUE 设计](../design/nfqueue.md)
- [控制面设计](../design/control-plane.md)
