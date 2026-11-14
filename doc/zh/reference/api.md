# 原生 API、Clash API 与 `/stats` 参考

原生 API 和已实现的 Clash 兼容 HTTP 接口共用同一个引擎 handle 和用户态统计，但两者的 Cargo feature、listener、凭据和 HTTP 边界各自独立。

## 原生 API

原生 API 不是默认功能，构建时要显式启用 `native-api` feature：加 `--features native-api`，或改用 `native-ui`。不需要 Clash API 时，用 `--no-default-features --features native-api` 单独构建。发布产物按包含的接口区分：

| 发布产物 | 原生 API | 内嵌 UI | Clash API |
| --- | --- | --- | --- |
| Full | 有 | 有（`native-ui`） | 有 |
| `-native-api` | 有 | 无 | 无 |
| `-clash-api` | 无 | 无 | 有 |

listener 默认关闭，要在配置里显式启用 [`experimental.native_api`](./experimental.md#native_api)。配置格式仍是 `.dae`。获得写入授权后，原生 API 可以读取和替换 `-c` 指定的已接受源文件；也可以加 `--store db`，把修订记录存进 SQLite 配置数据库，见[配置数据库](#配置数据库--store-db)。

原生契约来自 [api-standardize e6b0dbab5599689d965bc18a71be67c809d99d0f](https://github.com/daeuniverse/api-standardize/tree/e6b0dbab5599689d965bc18a71be67c809d99d0f)，覆盖认证、节点与 provider 管理、geodata 和自动策略覆盖，另有 `read_only_reason`、geodata cron 计划等本地扩展。本地测试使用的契约定义在 `crates/honk-core/tests/fixtures/native_api_openapi.yaml`。原生运行模式尚未开放，honk 不声明 `full_transparency`。

源管理要求 honk 从真实 `.dae` 文件启动。要写入，还需要启用 `config_write`，并配置非空 `secret` 或 `password_auth`。某个功能是否可用，看 capability 声明和每个源的权限，不要按路由名称推断。

| 方法 | 路径 | 含义 |
| --- | --- | --- |
| GET | `/api` | 公共发现接口。所有请求都能获得认证状态和登录 links；已放行的请求还会获得固定的 `/api/v1` base 和全部契约 links。 |
| POST | `/api/v1/auth/setup` | 创建首个密码模式管理员，并签发 session。 |
| POST | `/api/v1/auth/login` | 校验密码模式管理员，并签发 session。 |
| POST | `/api/v1/auth/logout` | 撤销已认证的密码模式 session。 |
| GET | `/api/v1/version` | 返回原生契约身份、引擎构建版本、构建提交和目标平台；`built_at` 始终为 `null`。 |
| GET | `/api/v1/capabilities` | 返回已实现的资源和请求上限。 |
| GET | `/api/v1/runtime?detail=summary\|full` | 返回引擎阶段、已接受的 generation，以及带独立时间戳的用户态流量。 |
| GET | `/api/v1/connections?type=all\|tcp\|udp&src=192.0.2.1&limit=100&detail=summary\|full` | 列出可见的活跃用户态连接。可选的 `src` 必须是不带端口的 IP literal。 |
| DELETE | `/api/v1/connections/{connection_id}`、`/api/v1/connections` | 确认精确的传输 owner 已关闭。批量关闭要带过滤器，或显式 `all=true`。 |
| GET | `/api/v1/flows`、`/api/v1/flows/{flow_id}` | 列出活跃和保留下来的终态用户态决策。详情里带追踪，证据按来源记录。 |
| GET | `/api/v1/nodes` | 返回稳定的节点 ID、当前直接成员或来源，以及符合资格要求的测量。 |
| POST | `/api/v1/nodes` | 用 `{name,link}` 在主文件里创建节点；真实激活后才返回 201。 |
| GET | `/api/v1/nodes/{id}` | 返回单个节点，字段与列表相同；未知 ID 返回 404。 |
| DELETE | `/api/v1/nodes/{id}` | 删除主文件里的内联节点；激活后返回 `{deleted:0\|1}`。 |
| GET | `/api/v1/groups`、`/api/v1/groups/{groupId}` | 只读的代理组观测，含直接成员、配置修订和捕获的健康数据；列表按配置中的声明顺序排列。 |
| GET | `/api/v1/groups/{groupId}/config` | 返回组的 `policy` 与 `config`，并以配置修订作为 `ETag`。 |
| PUT | `/api/v1/groups/{groupId}/selection` | 按直接成员 ID 设置 `tcp`、`udp` 或 `both` 的选择。写入 Selector 会替换它的选择；写入自动代理组会固定成员。 |
| DELETE | `/api/v1/groups/{groupId}/selection` | 清除自动代理组在 `tcp`、`udp` 或 `both` 上的固定成员。 |
| PATCH | `/api/v1/groups/{groupId}/config` | 对可写的 `.dae` 来源执行受限 JSON Patch，并返回真实执行的更新操作。 |
| GET | `/api/v1/events` | 有界、需认证的 SSE。续传游标绑定过滤器。 |
| GET | `/api/v1/runtime/outbounds` | 按 `kind/name` 区分出站计数，生命周期与共用计数器一致。 |
| GET | `/api/v1/runtime/memory` | 返回实际进程 RSS，以及可读的 cgroup v2 内存事实。 |
| GET | `/api/v1/runtime/traffic/history`、`/api/v1/runtime/memory/history` | 可选 `window_seconds`、`max_points`，默认 600，范围 1–600。 |
| GET / PUT | `/api/v1/x-honk/runtime/mode` | 失败响应的契约尚未完整固定，因此一律返回 `404 capability_not_supported`。 |
| GET / PATCH | `/api/v1/runtime/settings` | 原子读取或合并受支持的日志、DNS 日志和流留存设置。 |
| GET | `/api/v1/datapath?detail=summary\|full` | 有界的后端观测，默认 `summary`。 |
| POST | `/api/v1/probes` | 对节点或组做有界的 TCP、HTTP、DNS 测量。 |
| POST | `/api/v1/dns/query` | 显式 DNS 诊断。 |
| GET | `/api/v1/dns/cache`、`/api/v1/dns/log` | 精确缓存快照与客户端查询历史。 |
| DELETE | `/api/v1/dns/cache/{entry_id}`、`/api/v1/dns/cache` | 删除精确的缓存 incarnation，或按完整名称和可选 type 删除。 |
| POST | `/api/v1/dns/cache/flush` | 等待内存缓存和已启用的持久化缓存确认失效；不清空域名路由事实。 |
| POST | `/api/v1/routing/trace` | 固定当前 generation 的离线路由模拟，只支持 `resolve=none`。 |
| GET | `/api/v1/rules` | 返回当前 generation 的完整规则字典、回退和可用的来源位置。 |
| GET | `/api/v1/dns/rules` | 返回当前 generation 的 DNS 请求规则和响应规则，每个列表以回退结尾。 |
| GET | `/api/v1/providers`、`/api/v1/providers/{id}` | 返回真实订阅 owner 的状态；读取时不拉取。 |
| POST | `/api/v1/providers/{id}/refresh` | 显式刷新订阅，并等待真实的运行时发布操作。 |
| POST | `/api/v1/providers` | 用 `{name,kind:"subscription",url}` 创建尚未拉取的主文件订阅，可选 `update_interval`、`user_agent`、`cache`。 |
| DELETE | `/api/v1/providers/{id}` | 删除主文件的 HTTP(S) 订阅及其已加载节点。 |
| GET | `/api/v1/geodata` | 读取流量与 DNS 路由实际加载的资产的保留元数据。 |
| POST | `/api/v1/geodata/update` | 下载配置资产，完整校验后通过操作激活精确的候选字节。 |
| GET | `/api/v1/logs` | 经过安全投影的结构化原生日志 SSE，独立于 Clash 格式化日志。 |
| GET | `/api/v1/config` | 认证后返回已接受的源快照、配置修订和安全诊断；只遮蔽 listener secret 值。 |
| GET | `/api/v1/config/sources/{source_id}` | 认证后返回单个已接受源的元数据和正文；只遮蔽 listener secret 值。 |
| POST | `/api/v1/config/validate` | `syntax` 或离线 `full` 校验；不写盘，也不 reload。 |
| PUT | `/api/v1/config/sources/{source_id}` | 在 RFC 9110 `If-Match` 保护下替换单个源的原文。写盘后排队真实 reload，并返回对应操作。 |
| POST | `/api/v1/config/sources` | 新建一个由 include 模式加载的 `.dae` 文件。写盘后排队真实 reload，并返回对应操作。 |
| POST | `/api/v1/operations/reload` | 从磁盘 reload，返回守护进程持有的操作。正文留空或为 `{}`。 |
| POST | `/api/v1/operations/suspend`、`/api/v1/operations/resume` | 已注册但不可用，返回 `404 capability_not_supported`。 |
| GET | `/api/v1/operations/{id}` | 查询操作的排队、运行和终态结果。 |

### 连接观测

使用 Bearer 认证的请求和已放行的匿名 loopback 请求读到同一份连接数据。返回的显示字段会遮蔽 listener secret 值。

| 参数 | 默认值 | 取值 |
| --- | --- | --- |
| `detail` | `summary` | `summary` 省略 `src`、`dst`、`domain`；`full` 会带上这些字段。未知域名为 null。 |
| `type` | `all` | `all`、`tcp`、`udp` |
| `limit` | 100 | 1–1000，TCP 与 UDP 共用此上限 |

返回完整详情不代表权限更高。API 会拒绝未知参数和重复的单值参数。

`GET /connections?detail=full` 返回以下结构：

```json
{"observed_at":"2026-11-13T00:00:00Z","instance_id":"instance","visibility":"partial","truncated":false,"tcp":[{"id":"connection-id","flow_id":null,"pname":null,"state":"active","src":"192.0.2.1:50000","dst":"198.51.100.1:443","domain":null,"outbound":"proxy","chain":[],"chain_source":"unknown","rule_id":null,"rule_expression":null,"rule_source":"unknown","ingress":null,"domain_source":null,"started_at":null,"observed_by":"userspace","upload_bytes":"128","download_bytes":"256","upload_bytes_per_second":null,"download_bytes_per_second":null}],"udp":[],"total_tcp":1,"total_udp":0}
```

`total_tcp` 和 `total_udp` 是应用上限之前的匹配数。`src`、`dst`、`domain` 只在 `detail=full` 时出现。字节计数用十进制字符串表示。

过滤发生在总量统计和合计上限检查之前，总量包含所有匹配的可见记录。记录按注册的观测时间从新到旧排列；时间相同时，按 ID 字典序从低到高排列。

IPv4 映射的 IPv6 来源按 IPv4 地址比较。

连接里的 `outbound` 是选路当时的组或动作，既不是当前叶节点，也不是按现状重建的选择。开启记录后，`flow_id`、捕获的 root-first 组和叶 ID、首次观测的 UTC 时间、域名来源和用户态 rule ID 都会关联到保留下来的证据。证据缺失或已被淘汰时保持 unknown。

逐连接速率仍为 null。列表为空只说明 `visibility: partial`，不能据此断定设备上没有连接。Mock 数据面显示 `disabled` 和 `none`。

真实后端只根据实际程序、hook、路由 root、listener 和 admission 的观测报告状态。未知项为 unknown 或 null，覆盖范围仍是 partial。HTTP 已就绪并不代表数据面已就绪。

TCP 在 copy 读取成功或 splice 写入目标 socket 成功时立即计数，成功写出的嗅探前缀只计一次。UDP 仍按逐包语义计数。进程内只有一个一秒采样器，用它实际经过的时间间隔。

初次采样、重置和 overflow 时速率返回 null，不补零。`counter_since` 属于共用计数器的生命周期，`sampled_at` 属于流量样本，`observed_at` 属于本次 HTTP 观察。UInt64 用十进制字符串表示，有界的数量仍是 JSON number。

`process.cpu_percent` 在获得两次可用 CPU 样本之前为 null，见[出站、内存与历史](#出站内存与历史)。`generation.activated_at` 是当前 generation 的发布时间；启动时的 generation 取引擎首次进入运行状态的时间。配置激活期间，`generation.state` 为 `reloading`；引擎运行且健康时，`lifecycle.state` 也报告 `reloading`。

有源管理器时，响应会带配置修订。`last_reload` 是最近完成的 API reload 操作结果，没有时是 null。

`GET /runtime` 接受 `detail=summary`（默认）或 `full`。响应包含 `observed_at`、`instance_id`、`lifecycle`、`generation`、`datapath`、`traffic`、`process`、`last_reload` 和 `degradations`：

| 字段 | 内容 |
| --- | --- |
| `lifecycle` | `state`、UTC `started_at`，以及十进制字符串 `uptime_seconds`。`state` 为 `starting`、`running`、`reloading`、`degraded`、`draining` 或 `failed`。 |
| `generation` | `active_id`、可空的 `config_revision`、`state`（`active` 或 `reloading`）与可空的 `activated_at` |
| `datapath` | `kind`、`state`、`visibility` 与 `ebpf`，同 [`GET /datapath`](#连接关闭模式与数据面生命周期) 摘要 |
| `traffic` | `scope: "visible"`、`observed_by: "userspace"`、`counter_since`、`sampled_at`、`connections`（`tcp`、`udp`、`total`）、`bytes`（`upload`、`download`）与 `rates`（`null`，或含 `window_seconds`、`upload_bytes_per_second`、`download_bytes_per_second`）。首次采样前，`sampled_at`、计数、字节与 `rates` 均为 `null`。 |
| `process` | `cpu_percent`；只有 `detail=full` 额外包含 `pid` |

### 运行时降级

`degradations` 列出功能受损的组件。原因有两种：故障恢复之后仍处于降级状态，或已配置的接口还没完全绑定。每个组件最多一项。

| 字段 | 含义 |
| --- | --- |
| `code`、`message`、`details.reason` | 安全错误信息 |
| `component` | 受影响的组件 |
| `since` | 首次降级时间；重复故障不更新 |

空列表表示没有已知的降级项。条目不会改变 `lifecycle.state`：已配置接口还没绑定时，该状态仍是 `running`。要监控这类问题，请检查 `interface_binding`。

条目新增、变化或清除时发布 `runtime.updated`。

| 组件 | 条件 | 重新判定或恢复时机 |
| --- | --- | --- |
| `persistence` | 启动时无法打开或重置状态数据库。 | 重启 |
| `state_cache` | 无法打开状态数据库的缓存表。 | 重启 |
| `quic_probe` | Score 组需要 QUIC 探测，但启动时的目标或客户端不可用，详见下文。 | 已应用的配置不再含 Score 组，或重启后目标解析成功时清除。 |
| `pname_routing` | 规则使用 `pname()`，但缺少 cgroup v2 hook 或只能获取线程名。 | 每次应用配置 |
| `iface_watch` | 真实后端无法订阅 rtnetlink 事件或注册轮询。 | 重启 |
| `interface_binding` | 某个已配置的 `lan_interface` 或 `wan_interface` 条目尚未完全绑定。 | 所有条目绑定后自动清除。 |
| `udp_trace` | 记录流时，内核 UDP 接收追踪不可用。 | 每次启动 UDP listener |

`quic_probe` 的目标或客户端故障包括：

- 第一个 `tcp_check_url` 不是 HTTPS URL。
- 目标主机无法解析。
- 无法创建 QUIC 客户端。

探测目标在启动时确定。原因 `restart_required` 表示进程启动时还没有 Score 组，是 reload 之后才加进来的。

就 `pname_routing` 而言，缺少 hook 时 `pname()` 条件拿不到进程名：肯定条件永远不匹配，否定条件总是匹配。原因 `comm_fallback` 表示该条件用的是线程名，不是 argv。

进入 `iface_watch` 降级后，接口协调改为每 60 秒执行一次，不再接收事件通知。错误码是 `interface_watcher_disabled`，原因是 `subscribe_failed` 或 `poll_setup_failed`。

`interface_binding` 的错误码为 `interface_binding_incomplete`，消息为 `A configured network interface is not fully bound; traffic interception may be incomplete.`

| `details.reason` | 含义，按优先级降序排列 |
| --- | --- |
| `attach_failed` | TCX 链接创建、更新或校验失败。有效 hook 仍可能拦截部分流量。 |
| `unsupported_type` | 条目被[拒绝](./global.md#网卡语义)，包括不支持的嵌套或自身即主接口。 |
| `pending` | 接口不存在，或 `auto` 条目没有 IPv4 默认路由。 |

多个原因同时存在时，取表里靠前的一个。消息里不含接口名，名称只出现在日志中。拓扑读取失败不会改变这个条目。

`udp_trace` 的错误码固定为 `udp_trace_unavailable`。失败只影响 IPv4 或 IPv6 其中一个 listener 地址族时，`details.reason` 为 `ipv4_unavailable` 或 `ipv6_unavailable`；两个都受影响时为 `unavailable`。仍然可用的地址族会继续记录内核路由证据。

挂接失败的 warning 用 `family` 字段指出缺的是哪个地址族。listener 的 warning 带 `ipv4_unavailable` 和 `ipv6_unavailable` 字段。listener 启动时会重新判定，但不会重试回退 hook 的挂接：每个真实后端只尝试一次，改了内核或 BTF 支持后要重启。

所有认证模式都公开 `GET /api`，首次设置密码和登录的 POST 也公开。version、capabilities 和其他 API 资源要求已配置的静态 Bearer 或有效的密码 session；显式启用匿名 loopback 访问时例外。

这些例外只适用于不带凭据的请求。带凭据的请求无论接口是否公开都会校验；凭据错误或重复时直接拒绝，不回退成匿名。查询字符串里的 token 一律拒绝。没有 `secret` 的开发模式要求显式开启匿名 loopback 授权，并拒绝 `Sec-Fetch-Site: cross-site`。

Host 和 Origin 校验先于这些认证例外执行，公共静态文件也不例外。OPTIONS preflight 不需要 Bearer，但要通过 Host、Origin、方法和 header 白名单。响应不返回 cookie credentials，也不返回通配 CORS。

预检只允许 `Authorization`、`Last-Event-ID`、`Content-Type`、`If-Match`、`Idempotency-Key` 和 `Accept` 这些 header。预检成功返回 204。方法不支持返回 404，header 不允许返回 403，格式错误返回 400。对允许的 Origin，响应会暴露 `Location`、`Retry-After` 和 `ETag`。401 响应带 `WWW-Authenticate: Bearer`。

### HTTP 错误与上限

错误信封为 `{error:{code,message,details},request_id}`。

| 条件 | JSON 响应 |
| --- | --- |
| 已知但不可用的操作 | `404 capability_not_supported` |
| 未知路径 | `404 resource_not_found` |
| 已知资源不支持的方法 | `405 method_not_allowed`，附带 `Allow`；GET 资源包含 HEAD |
| 配置来源可读但未授权写入 | PUT 返回 `403 permission_denied` |

HEAD 沿用 GET 的状态码和响应头，但不返回正文。API 响应带 `Cache-Control: no-store` 和 `X-Content-Type-Options: nosniff`。

| 应用层限制 | 字节数 |
| --- | --- |
| 规范化请求目标 | 4096 |
| 规范化 header 名称与值合计 | 16384 |
| 请求体，包括分块传输 | 65536 |

已认证的 GET/HEAD 请求如果带非空请求体，会被拒绝。普通的观测读取不会触发探测或选择变化；`/dns/query` 是会联网的显式诊断请求。

错误的 `details` 只指出被拒绝的对象，不回显提交的值或配置里的值。请求边界错误会给出 `header`，或请求的部分（`field` 为 `query`、`body` 或 `target`），以及 `kind`。JSON 请求体无法解析或不符合模式时，该 endpoint 返回 `400 invalid_request`，`details` 为 `{field,kind}`。这里的 `field` 可以是出错成员的点分路径，例如 `sources[0].content`；也可以是含未知 key 的对象，或 `body`。

`kind` 的取值为 `invalid_json`、`missing`、`wrong_type`、`unknown_field`、`duplicate`、`invalid_value` 或 `too_large`。422 的 `unsupported_value` 会给出被拒绝的 `field` 或 `fields`，并按情况附带受管条目的 `resource` 路径、`allowed` 可选值或路径、没通过的 `check`，或能放行该请求的 `settings`。

原生服务器最多同时接受 64 条 HTTP/1.1 连接，同一个规范化 socket 对端 IP 最多 16 条。达到全局上限时暂停 accept。超过单个对端上限的连接在 accept 后立刻关闭，不返回 HTTP 响应，并记一条 DEBUG 日志。

Forwarded header 不改变对端地址，所以同一个反向代理后面的客户端共用该代理的额度。header 读取的 deadline 是五秒。关闭时所有连接共享五秒的 graceful drain，然后 abort，并逐一等待结束。

30 秒的读空闲 deadline 只在连接没有进行中的请求时计时，从请求正文结束算到响应完成；写入停滞另受 30 秒 deadline 约束。SSE heartbeat 写成功会让健康的长连接保持活跃，读取不能延长阻塞 writer 的 deadline。TLS 和 HTTP/2 可以交给可信的反向代理终止。

Forwarded header 不改写固定的发现接口路径，也不授予 Host/Origin 权限。

密码模式下，先关闭凭据 admission，再走上面说的 HTTP 宽限期，最后等待真实正在执行的阻塞凭据任务结束。五秒的 HTTP 预算不限制最后这段 KDF 或数据库等待。

HTTP 传输边界：Hyper 可能在应用处理之前就用 400/414/431 或断连拒绝畸形或硬超限的 HTTP。这类传输层拒绝不保证返回 JSON 信封或应用 header。

应用层的 target/header 上限针对的是 Hyper 解析并规范化之后的表示，不是原始 wire 字节。Hyper 可能先去掉 request-target 里的片段，或合并相同的 `Content-Length` 字段，再交给应用计量。因此这类原始文本即使超过应用上限，也可能得到正常响应而不是 413。

原始输入仍然受 Hyper 的传输处理约束。这是一个已接受的边界差异：honk 不另写 HTTP 解析器，也不承诺原始 wire 大小上的限制。正文限制仍然覆盖实际交付的全部正文字节。

配置 `ui` 后，`/` 和 `/ui` 都重定向到 `/ui/`。外部 UI 目录托管会保留无扩展名的 SPA 回退。静态资产、fonts/icons、manifest 或 service worker 缺失时返回 404，不返回 HTML。

构建时加上 `--features native-ui`，完整发布产物已经包含这个 feature。再设置 `ui: embedded`，就能直接提供固定的 doona 正式发行版，不解压到磁盘，也不联网。`ui: embedded-lite` 选用更轻的 doona lite 预览版，同样需要 `native-ui`。两个版本都连接与页面同源的原生 API。

内嵌 UI 的 hash router 用 `/ui/#/...`。其他合法的内嵌导航路径都重定向回 `/ui/`，这样相对资产和 service worker 的路径才正确。内嵌 UI 以预压缩形式存储，浏览器接受时用 brotli 或 gzip 传输。

外部 UI 目录托管也按同样方式提供管理员放好的同名 `.br`/`.gz` 文件。`assets/` 下文件名带内容 hash 的按 immutable 缓存一年，其他静态响应用 `no-cache`。静态响应带 `nosniff`，但不带 framing header，方便 LuCI 之类的面板嵌入 UI。

要防 clickjacking，请在反向代理上加 `X-Frame-Options` 或 `Content-Security-Policy: frame-ancestors`。公开资产仍要经过 Host/Origin 校验。发现接口和密码 setup/login 走上面说的公共例外；其他 API 请求要求静态 Bearer 或 session Bearer，显式启用匿名 loopback 访问时例外。

不向 UI 注入凭据。

### 认证发现与密码 session

发现接口返回 `auth: {mode, setup_required, anonymous_loopback}`。配置了非空 `secret`，或使用匿名 loopback 开发模式时，`mode` 为 `token`。`secret` 为空且启用 `password_auth` 时，`mode` 为 `password`。

只有密码模式还没有管理员记录时，`setup_required` 才为 true。只有实际绑定在 loopback 上并显式开启开发模式时，`anonymous_loopback` 才为 true。密码模式下，`links.auth_setup`、`links.auth_login`、`links.auth_logout` 给出对应 endpoint 的路径。

其他模式下这三个链接均为 null。

无凭据又未获放行的请求只获得 `name`、`api_major`、`links.auth_setup`、`links.auth_login`、`auth.mode` 和 `auth.setup_required`，其余字段都省略。通过 Bearer、session 或显式匿名 loopback 放行的请求获得完整响应。

下面是已放行的 token 模式发现响应，`links` 有删减：

```json
{"name":"daeuniverse/native","status":"draft","api_major":1,"base_path":"/api/v1",
 "links":{"version":"/api/v1/version","capabilities":"/api/v1/capabilities","runtime":"/api/v1/runtime","operations":"/api/v1/operations/{operation_id}","auth_login":null,"x-honk":{"config_export":"/api/v1/x-honk/config/export"}},
 "auth":{"mode":"token","setup_required":false,"anonymous_loopback":false}}
```

`links` 还包含 `config`、`config_validate`、`runtime_outbounds`、`traffic_history`、`memory_history`、`logs`、`providers`、`rules`、`geodata`、`auth_setup` 和 `auth_logout`；`x-honk` 还包含 `config_import` 和 `config_revisions`。token 模式下 `auth_*` 链接为 `null`。

`GET /version` 返回：

```json
{"api":{"name":"daeuniverse/native","major":1,"status":"draft"},"engine":{"name":"honk","version":"<build-version>"},"build":{"revision":null,"target":null,"built_at":null}}
```

构建没有设置 `build.revision` 和 `build.target` 时，两者为 `null`；`built_at` 始终为 `null`。

`GET /capabilities` 返回 `observed_at`、`profiles: ["base"]`、`limits` 和 `resources`。`limits` 含 `max_request_target_bytes` 4096、`max_header_bytes` 16384、`max_json_body_bytes` 65536。`resources` 按资源名索引，并含 `x-honk` 扩展。使用某个资源之前，先看它的 `available` 和声明的字段。

Token 模式不提供三个密码 endpoint，返回 `404 capability_not_supported`。密码模式使用以下契约：

| endpoint | 请求与成功响应 | 模式特定失败 |
| --- | --- | --- |
| `POST /api/v1/auth/setup` | `{"username":"admin","password":"..."}` → `201 {"token":"hnk1_…","expires_at":"..."}` | 对端地址不符合要求时返回 `403 permission_denied`；首个管理员发布后返回 `409 setup_already_completed`。 |
| `POST /api/v1/auth/login` | 相同正文 → `200 {"token":"hnk1_…","expires_at":"..."}` | 首次设置前返回 `409 setup_required`；用户名或密码错误均返回 `401 invalid_credentials`。 |
| `POST /api/v1/auth/logout` | `Authorization: Bearer <session>` → `204` | 无效或过期 session 按普通 Bearer 认证失败。 |

`expires_at` 是 RFC 3339 UTC 时间戳。首次设置与登录使用以下限制：

| 输入 | 要求 |
| --- | --- |
| `Content-Type` | `application/json` |
| 查询字符串 | 不允许 |
| 未知 JSON 字段 | 不允许 |
| 请求体 | 最多 4096 字节 |
| 用户名 | 区分大小写的 ASCII，匹配 `[A-Za-z0-9_.-]{1,64}` |
| 密码 | 8–128 个 Unicode 标量值，UTF-8 编码最多 512 字节 |

无效 JSON 或字段返回 `400 invalid_request`。缺少媒体类型或使用其他媒体类型时返回 `415 unsupported_media_type`。

Media type 不区分大小写。`Content-Type` 重复或不是文本时返回 `400 invalid_request`。配置、认证、探测和路由诊断共用同一套 JSON/header 解析边界。

首次设置只看已接受 socket 的对端地址，不读 `Forwarded`、`X-Forwarded-For` 或其他 header。允许的地址范围是 `127.0.0.0/8`、`::1`、RFC 1918、`fc00::/7`、`169.254.0.0/16` 和 `fe80::/10`。IPv4-mapped IPv6 按 IPv4 归类。

其他对端在读取账户状态或处理凭据之前，就会收到 `403 permission_denied`。

首次设置和登录每分钟按规范化对端 IP 最多接受 5 次尝试，全局最多 10 次。同一个对端连续 5 次凭据校验失败时，只锁它 60 秒，从最后一次失败算起。其他对端的失败或成功登录都不会延长或清除这把锁。

成功的 setup/login 只清除该对端的失败状态，这次尝试仍然计入尝试窗口。被拒绝时返回 `429 rate_limited` 和 `Retry-After`。计数器和锁定状态只保存在进程内存里。

对端状态是有界的：尝试窗口和锁定都过期之后，honk 丢弃这份状态。所以不活跃的对端即使连续失败还没到阈值，它的记录也会过期。全局尝试窗口对所有对端仍然共同生效。

凭据任务最多同时跑一个，放在 Tokio worker 之外执行；重叠的请求返回 429 和 `Retry-After: 1`。HTTP 请求取消不会释放这个名额，也不会丢掉它已经算出的凭据处理结果。发现接口只读一份短时持有的凭据状态，不会去等跨越 KDF 或数据库 I/O 的锁。

session token 是 `hnk1_…` 形式的不透明值，用 `Authorization: Bearer <session>` 提交。每个 session 固定有效 12 小时。进程只保存 token 的 SHA-256 摘要，最多保留 32 个有效 session。

签发新 session 时会淘汰最早的 session，重启则结束全部 session。session 因注销、过期或被淘汰而结束时，它打开的 `/events` 和 `/logs` 流也随之关闭，客户端要重新认证后再连。

通过配置的 `secret` 或密码登录发起的操作属于管理员，不属于某个 token，所以注销不会删除操作。

密码模式把唯一的凭据记录保存在状态数据库 `<data_dir>/state/honk.db` 的 `admin` 行里，文件权限 0600、目录 0700，见[配置数据库](#配置数据库--store-db)。记录格式不对时 honk 拒绝启动；状态数据库损坏时同样拒绝启动，密码模式不会把它挪走。

记录用 PBKDF2-HMAC-SHA256、100,000 次迭代和新生成的 16 字节随机盐。密码模式直接使用配置的 `global.data_dir`：该目录不可用时启动失败，不会退回其他目录，以免在别处把首次设置重新打开。首次设置只插入这一行，不替换已有记录，所以两个进程在同一个状态数据库上同时做首次设置时，只有一个会成功。

如果写入开始前数据库正忙，或者插入失败但已回滚，首次设置就算失败，可以重试。如果提交或这次回滚本身失败，就无法确定该行有没有落盘，进程在重启之前会拒绝登录和再次设置。

首次设置一旦占用凭据状态，发现接口就返回 `setup_required:false`，即使持久化结果还没确认也一样。无法确认写入时返回 503 和 `durability_confirmed:false`，不带 `Retry-After`，也不会声称 `written:true`；要重启才能重新确认数据库里的账户状态。

honk 不提供 HTTP 密码重置。需要恢复访问时，先停掉 honk，执行 `honk-core admin reset`，重启后重新设置管理员。把 `<data_dir>/state` 整个移走也能恢复，但会丢掉其他所有持久化状态。

重置命令在检查数据库是否存在之前，先取得状态目录的排他锁，所以不会和正在创建数据库的首次启动发生 race。

### 用户态记录流

已放行的匿名 loopback 请求和 Bearer 认证请求读到同一份流数据。

客户端通过 GET 建立并已放行的 `/events` 或 `/logs` SSE 流，在连接期间持有通用 attachment。最后一条流关闭之后，或成功 GET `/flows`、`/flows/{id}`、`/dns/log` 之后，通用 attachment 再保留 60 秒。它只开启普通事件捕获，不会启动任何 Auto 诊断记录器；诊断需求是另一套：

| 已放行请求 | Auto 诊断需求 |
| --- | --- |
| `/events` 显式流 kinds 或有效流事件 `flow_id` 过滤器 | 仅流 |
| 成功 GET `/flows` 或 `/flows/{id}` | 仅流 |
| GET `/logs` SSE | 仅日志 |
| 成功 GET `/dns/log` | 仅 DNS 日志 |
| 无过滤/非流 `/events`、普通 API、validation、失败 GET 或 HEAD | 无 |

流事件需求指的是：显式 `kinds` 里包含 `flow.updated` 或 `flow.gap`，或者 `flow_id` 非空白、有效 kinds 里含流事件。既没有这个过滤器又省略 `kinds` 时，不会请求流记录。每条已放行的流各自持有一份本次请求需要的 lease。

admission 失败时不会取得 lease；关闭或 Drop 时就释放，即使从未 poll 过。流、日志、DNS 日志三类需求各自在最后一条对应流关闭后，或对应 GET 成功后，单独保留 60 秒宽限期。通用活动和其他需求都不能延长这个期限。

DNS 日志没有 SSE 类型。记录从需求建立时开始，所以第一次读到的历史是空的。

`record_flows` 默认是 true，流诊断需求有效时允许记录。把运行时设置显式改成 `record_flows: "on"`，就能在没有客户端时持续记录。运行时设成 `"off"` 强制关闭；配置里写 `record_flows: false` 则禁止记录，改了要重启。

记录实际停止时会释放流记录和快照。进程内最多保留 1024 条流，每条 64 个步骤；含快照和内核字典预留在内，总预算 8 MiB。终态最多保留 300 秒，内存紧张时可能提前淘汰，重启后清空。

清理复用既有的采样器，没有新增定时器。

内核 witness 的产出走既有的组合 datapath 标志，跟随实际的流记录状态。既有采样器会在之后的 tick 同步这个变化。调度、遥测和发布锁竞争都可能让收敛变慢，honk 不承诺一秒内完成。

记录开启之前就已经路由的流量，会明确报告内核证据缺失。关掉需求不会丢弃已经保留的 witness 和字典，不改变路由或 NFQUEUE 的 authority，也不撤销操作已经取得的捕获资格。没有录制的操作会跳过 witness 解码。

流 ID 标识的是 incarnation，不是五元组。TCP/UDP 流记录会捕获实际执行的路由谓词和短路、嗅探与校验、组选择、DNS 子查询、物理尝试、session 复用与重试，以及终态边界。拨号失败或阻断时，即使没有实时 connection，记录也会保留。

名称、ID 和 generation 都取自实际使用它们的操作，不会按当前配置或路由模拟重建。DNS lookup 与 parent ID、outbound attempt 与 parent ID 之间保留因果关系。复用 carrier 时记录为 attachment，不会伪造一次新的物理拨号。

协议的请求、确认阶段标志必须有真实协议证据；DNS 子步骤就绪不能当作业务目标已确认的证据。TCP/UDP 的终态跟随所属的清理边界。内核 offload 的观察以 unknown 结束，不会伪造成 closed。

只有该流范围内、截至当前进度已执行的决策全部被捕获，`trace_status` 和 `trace.status` 才是 `complete`。active、failed、closed 状态都可以完整。这不代表流成功，也不代表全局覆盖。

来源缺失或歧义、listener secret 值被遮蔽、捕获预算耗尽时，状态保持 `partial`，并在 `missing` 里列出原因。达到追踪上限不会停止转发。用户态 TCP/UDP 和截获 DNS 的总体覆盖仍是 `partial`，只由内核处理的 direct/block/bypass 仍是 `none`，honk 不开放 `full_transparency`。

每条流的条件表达式用配置源里的写法，缓存在编译 generation 上；GeoIP 保留引用，不展开成网段列表。这样不会仅仅因为展开就发生截断，但真实的上限仍然存在：原始配置文本超限、遮蔽、来源缺失、步骤或字节预算耗尽，仍会报告为 partial 追踪。

交接流量的内核规则结果来自编译程序实际执行到的分支 witness，用户态不重算。UDP 还必须用收到报文里带的 capture ID。五元组、decision token、路由 generation 和动作都要与保留的 witness 匹配；同一个五元组后来的 incarnation 不能给旧报文提供证据。

Capture ID 不会回绕。冻结字典最多 16 份，每份 64 KiB，合计 1 MiB，计入记录器的预留。字典被拒绝或淘汰、witness 缺失、TCP 对应关系有歧义，以及实际执行超过 256 个规则或条件值，都会让证据不完整。

如果只是未执行的规则超过这个上限，并不代表执行证据丢了。

如果策略的内核追踪字典会超过 64 KiB，这个策略在启动和 reload 时都会以关闭内核路由追踪的方式发布，并记一条 warning。它的流会报告 `kernel_trace_not_captured`，不再产生无法解码的 witness。检查时按最长的 generation 编号估算规则 ID，所以刚好卡在上限附近的策略，也可能已经按关闭追踪发布。

原生扩展字段保留来源细节，不虚构身份：路由输入可以带 `ingress`、`domain_fact_bitmap`、`domain_fact_state`，但不会伪造域名 rule ID。DNS association 的 outbound/connection step 带 `lookup_id`，已知物理对端带 `server_addr`。选择事实保留健康的地址族，以及这个决策是实际应用还是只 peek。

Score 的 `previous_leaf_node_id` 和 `previous_member_id` 分开记录：仅有叶节点历史，重建不出过去经过的子组路径。

流分页结果是 `{instance_id,observed_at,coverage,dropped_records,flows,next_cursor}`。`dropped_records` 是十进制字符串，最后一页的 `next_cursor` 为 `null`。`coverage` 对 `userspace_tcp`、`userspace_udp`、`dns_intercept`、`kernel_direct`、`kernel_block` 和 `kernel_bypass` 分别报告 `partial` 或 `none`。

`GET /flows/{flow_id}` 返回带 `input` 与 `trace` 的单条记录。列表行只在 `detail=full` 时带 `input`，从不带 `trace`：

```json
{"id":"flow-id","instance_id":"instance","revision":1,"network":"tcp","state":"observed","pname":null,"connection_id":null,"outbound":null,"chain":[],"chain_source":"unknown","rule_id":null,"rule_generation_id":null,"rule_expression":null,"rule_source":"unknown","ingress":null,"domain_source":null,"observed_by":"userspace","started_at":"2026-11-13T00:00:00Z","ended_at":null,"trace_status":"partial","input":{"src":"192.0.2.1:50000","dst":"198.51.100.1:443","domain":null,"domain_source":null,"pid":null,"process_path":null,"src_mac":null,"ingress":null,"domain_rule_ids":null,"dscp":null,"mark":null},"trace":{"status":"partial","missing":["not_instrumented"],"steps":[]}}
```

`trace.missing` 的原因是 `not_instrumented`、`started_late`、`buffer_overflow` 和 `redacted`。每个步骤含 `seq`、`observed_at`、可空的 `elapsed_us` 与 `generation_id`、`evidence`、`stage` 和 `data`。`stage` 取 `input`、`route`、`dns`、`datapath`、`dial_mode`、`reroute`、`outbound` 或 `connection`，决定 `data` 里有哪些字段。

流列表接受 `network/state/connection_id/detail/limit/cursor`。最多保留八份有界、不可变的快照，TTL 30 秒；游标绑定 instance 和原来的过滤器与 detail。可识别的游标如果带着不同的过滤器、详情或 limit，返回 `400 invalid_request`。

| 参数 | 默认值 | 取值 |
| --- | --- | --- |
| `network` | `all` | `all`、`tcp`、`udp` |
| `state` | `all` | `all`、`observed`、`routing`、`dialing`、`active`、`closed`、`blocked`、`failed`、`unknown` |
| `detail` | `summary` | `summary`、`full` |
| `limit` | 100 | 1–1000 |
| `connection_id` | 省略 | 非空字符串 |
| `cursor` | 省略 | 非空不透明游标 |

表满时淘汰最旧的快照。只有保留字节预算耗尽，才返回 `503 snapshot_unavailable` 和 Retry-After。过期或已被淘汰的列表返回 `410 snapshot_expired`；已淘汰的已知 ID 由有界 tombstone 返回 `410 flow_expired`；未知 ID 返回 `404 resource_not_found`。

详情接口不接受查询参数，始终返回保留下来的完整 input 和 trace。计数是十进制字符串，revision、seq、elapsed_us 是 safe JSON number。显示字段在 512 字节的 `MAX_TEXT` 上限内保留路径、`@` 和 URL。

标识符单独校验。无法表示或超限的文本、步骤或字节预算溢出，都会明确报告为证据不完整，不会丢掉因果 ID 或结果。保留下来的规则展示属于捕获时的 generation，不从当前配置重建。

### 节点与代理组

`Node.stream_transport` 是可选、可为 null 的字符串，反映已接受的 Trojan/VMess/VLESS 配置：`tcp`、`ws`、`grpc` 或 `xhttp`，包括 `splithttp` 别名。无法识别或不适用时，honk 返回 null。这个字段表示配置的传输方式，不表示协商结果或健康状态。

`protocol` 和 TCP/UDP 健康传输字段的含义不变。`stream_transport` 不暴露凭据、host、路径、extra 选项或链接。测试 fixture 来自 doona 契约包，并包含 `read_only_reason`、geodata cron 计划等本地扩展；本地文件的 SHA-256 是 `444a9e4f6c8d35617cc36590e9d3fb985a164c8fb898cc70696ad1de66b1d0ab`。

这个固定版本不代表已发布的前端版本。

节点读取接受 `group_id`、`limit`（1–1000）和 `cursor`。筛选只作用于直接成员，不展开叶节点。节点分页最多用八份快照、30 秒和 4 MiB，分页期间冻结观测。

`limit` 默认 100。分页结果是 `{observed_at,nodes,next_cursor}`，不含 `total`；最后一页的 `next_cursor` 为 `null`。节点行含 `id`（UUID）、`name`、`protocol`、可空的 `stream_transport`（仅 XHTTP）、可空的 `subscription_tag`、`provider_id`、`group_ids`（直接所属的组）和 `health`。`provider_id` 是订阅 ID；配置文件里的节点为 `"inline"`，`direct` 与 `block` 为 `null`。

容量不足时返回 `503 snapshot_unavailable`，带 `Retry-After`。无法识别的游标返回 `410 snapshot_expired`；可识别但过滤器或 `limit` 不同的游标返回 `400 invalid_request`。组返回摘要数组。

组详情含 `config_revision`，但不带 `ETag`。`GET /groups/{groupId}/config` 返回 `{policy, config}`，并以该修订作为带引号的 `ETag`。组 ID 是进程生命周期内的随机身份：同名 reload 或重排会保留 ID，删除后重新添加会获得新 ID，重启后则要重新发现。它不用位置 UUID，也不用名称 hash。

| 组视图 | 字段 |
| --- | --- |
| 列表行 | `id`、`name`、可空的 `icon`、`config_revision`、`policy`（`kind`、`native`）、`member_count`、`selection`（`tcp_member_id`、`udp_member_id`，均可空） |
| 详情 | `id`、`name`、`icon`、`config_revision`、`policy`、`members`、`config`、`runtime`、`capabilities` |
| `members[]` | `id`、`name`、`kind`（`node` 或 `group`） |
| `config` | `default_member_id`、`final_outbound`、`check_url`、`check_interval`、`tolerance`、`idle_timeout`、`interrupt_connections` |
| `runtime` | `selection`（`tcp`、`udp`）与 `health` |
| 运行时选择 | `null` 或 `{member_id,resolved_leaf_node_id,source}`；`source` 为 `runtime`、`override`、`health` 或 `policy` |
| `capabilities` | `can_select`、`can_override`、`supports_nested_groups`、`mutable_config`、`probe_transports` |

`config.check_interval` 是只读的：周期检查用全局间隔，值为 0 时读出来是 `null`。

节点名、订阅标签、组名和成员名、icon、检查 URL、final 出站标签以及出站计数名称，
都按与源内容、流显示相同的规则遮蔽 listener secret。节点快照在有界序列化之前就遮
蔽凭据，续页沿用同一份已遮蔽的字节；不透明 ID、修订 hash、成员身份和游标绑定都不
受影响。遮蔽阈值没有变：不足八字节的 listener secret 值不遮蔽，启动时会发一条
warning。

健康数据来自生产者已经完成、且符合资格要求的测量。乐观的存活标志、跨 IPv4/IPv6 复制过来的排名信号、合成出来的失败、缓存恢复出来的延迟，都不算真实测量。

健康行含 `transport`（`tcp`、`udp`）、`purpose`（`data`、`dns`）、`ip_version`（`ipv4`、`ipv6`）、`warmth`（`cold`、`warm`、`unknown`）、`measurement`（`tcp_connect`、`http_headers`、`dns_round_trip`、`quic_handshake`、`mixed`）、`sample_source: "probe"`、`state`（`healthy`、`unavailable`）、可空的 `latency_ms`、`moving_avg_ms` 与 `avg10_ms`、`observed_at` 以及可空的 `error`。组健康行另含 `member_id`、`resolved_leaf_node_id`，以及为 `null` 的 `sorting_latency_ms` 与 `ranking`。

原始 TCP、HTTP 响应头、DNS 交换和 QUIC 握手测量会保留实际的目标地址族和完成时间。节点行还带每个测量维度的两个平均值；它们只累计成功的原生探测，重启后清零：

| 字段 | 计算方式 |
| --- | --- |
| `moving_avg_ms` | URLTest 排名使用的减半平均 `(previous + sample) / 2` |
| `avg10_ms` | 最近十次成功探测的算术平均；预热期不足十次时按已有次数计算 |

测量行不可用时两者为 null；针对特定组的测量里，两者恒为 null。未知的排名和冷热状态保持 null 或 unknown。针对特定组的测量保留测量当时的成员和叶节点，不绑定到后来的选择。

GET 不会推进 URLTest、轮询或 Score 状态。`icon` 返回通过配置校验、并已遮蔽 listener secret 的 HTTP(S) URL 或 data URI；没配置时为 null，honk 不去猜，也不抓取图标。

在同一个测量 key 上，完成时间早于已保留样本的健康数据会被丢弃。但如果已保留样本的时间晚于当前系统时钟，也就是时钟回拨过，新样本会被接受。同一时间戳的重放只更新该行，不会在平均值里重复计入。针对特定组的样本最多保留 4096 个测量 key。

容量满时用第二次机会替换，而不是严格淘汰最久未更新的 key：扫描器自上次经过之后刷新过的 key 会被跳过，所以一直有刷新的 key 比长期没更新的 key 留得更久。

`PUT /groups/{groupId}/selection` 的请求体是 `{"member_id":"<direct-member-id>","network":"tcp"}`，`network` 必填，也可以填 `udp` 或 `both`。写入 Selector 会替换它的选择，报告 `source: runtime`。TCP 和 UDP 的选择分开保存，只写 TCP 不会动 UDP；`both` 在发布前一次校验两个网络，然后原子发布选择。

写入自动代理组（`can_override: true`）会把该成员固定住，报告 `source: override`。固定成员不可用时，honk 不会改选同组的其他成员。固定只存在于运行时，不持久化，每次配置激活都会清除，包括改了节点的订阅刷新。

内容没变或为空的刷新不会激活配置，固定保留，健康检查照常执行。`DELETE /groups/{groupId}/selection?network=` 清除 `tcp`、`udp` 或 `both`（默认）上的固定，返回 `GroupOverrideCleared` 和各网络当前的选择。没有固定的网络保持原选择；对 Selector 调用 DELETE 返回 `409 state_conflict`。

原生和 Clash 的写入都由同一个 `control/reload` owner 串行处理，并沿用既有的持久化和预热逻辑。Clash 的写入等价于 `both`，读 `now` 得到的是 TCP 投影。响应返回独立的 `selection_revision` 和实际的 `connections_interrupted`，不要把选择修订当作配置 ETag。启用 `interrupt_connections` 时，honk 按流量建立时捕获的组身份和路径、以及发生变更的网络关闭旧 owner，而不是按当前可达的叶名称删记录。

重复写入当前选择不会触发中断。关闭确认失败时，报错可能发生在选择已经发布之后，honk 不承诺回滚。

`member_id` 为 1–256 字节。PUT 返回 `{group_id,member_id,network,source,selection_revision,connections_interrupted}`。DELETE 返回 `{group_id,network,selection_revision,connections_interrupted,selection}`，其中 `selection` 的 `tcp` 和 `udp` 采用上面说的运行时选择结构。`selection_revision` 与配置修订互相独立。

选择接口会返回这些错误：组或成员不存在返回 `404 resource_not_found`；成员或操作不受支持返回 `422 unsupported_value`；状态冲突，例如清除 Selector 的覆盖，返回 `409 state_conflict`；无法确认切换结果返回 `503 temporarily_unavailable`。

#### 代理组配置补丁

`PATCH /groups/{groupId}/config` 有三个要求：

- `Content-Type: application/json-patch+json`。
- 非空的 RFC 6902 数组，最多 32 项操作。
- RFC 9110 `If-Match`，按 `GET /groups/{groupId}/config` ETag 里的已接受修订求值。

`If-Match` 的列表和多个 header 字段行按合并处理。弱标签永远不匹配；`*` 匹配已存在的组。条件不匹配时返回 412。

如果检测到并发源或依赖变化、但条件仍然匹配，返回 409。

操作对象里 `op`、`path`、`from`、`value` 以外的成员一律忽略。请求体错误（400、413）先于过期的 `If-Match`（412）上报。`add`、`replace`、`remove`、`test`、`copy`、`move` 都限于下面这些路径：

| 路径 | 接受的值 |
| --- | --- |
| `/policy` | 只能包含 `kind` 与 `native` 两个字符串 key，值必须相同，接受 `selector`、`urltest`、`loadbalance`、`fallback` 或 `score` |
| `/config/default_member_id` | 直接成员 ID |
| `/config/final_outbound` | 已配置的出站名称 |
| `/config/tolerance` | 非负安全整数，单位毫秒，或 `null`；只有 URLTest 接受非 `null` 值 |
| `/config/idle_timeout` | 非负安全整数，单位秒，或 `null`（1800 秒） |
| `/config/interrupt_connections` | 布尔值或 null |
| `/config/check_url` | null 或满足以下要求的 URL |

`check_url` 必须满足：

- 以小写 `http://` 或 `https://` 开头，且包含主机。
- 不含 userinfo、空白、控制字符或逗号。
- 不同时含单引号和双引号。
- 规范化后不超过 2048 字节。

PATCH 保存的是规范化之后的 URL，GET 显示的和探测实际发送的也是这个形式：去掉片段，空路径补成 `/`，主机转小写，默认端口省略。`test` 按这个形式比较。Selector 组也会保存 `check_url`，但不用它探测。

只有 URLTest 组会报告并接受 `tolerance`。其他策略报告 null，`mutable_config` 里也没有这个字段。把它设成非 null 值返回 `422 unsupported_value`；`remove` 是允许的。

在同一个补丁里把策略改成 URLTest 时，可以顺便设置这个字段。

删掉字段或设成 null 会恢复 dae 的默认值。源里没有设置 `tolerance` 或 `interrupt_connections` 时，GET 报告 null，但引擎仍会应用 `global.check_tolerance` 或默认的 `interrupt_connections: false`。

| 失败原因 | HTTP 状态 |
| --- | --- |
| 不支持的路径或值 | 422 |
| 补丁格式错误 | 400 |
| `test` 失败 | 409 |
| 缺少前置条件 | 428 |
| 修订已过期 | 412 |

这个接口不会修改成员列表或图标。

源不可写时 `mutable_config` 为空，PATCH 返回 `404 capability_not_supported`。PATCH 只改解析器定位到的可写源片段，其他原文字节、注释和 include 结构都保留。权限、完整离线校验、耐久替换和操作幂等复用配置源协调器。

这里的 `If-Match` 是已接受的组或配置修订，不是文件 SHA-256。写入前会校验修订，同时独立检查源字节 hash 和依赖拓扑；真正激活之前，还会在 reload lock 下再检查一次已接受修订。并发的 provider 发布可以让写入之后的激活被拒绝，这时返回 `written:true,committed:false`，磁盘不回滚。自动策略的 pin 和 clear 可用（`can_override: true`）。

仍然受限制的只有原生运行时 mode 和完整内核透明性。

### 原生事件

接口需要 Bearer 认证时，请用流式 fetch，带上 Bearer 和 `Accept: text/event-stream`。浏览器的 EventSource 不能设置 Authorization header。可选的 `kinds/flow_id` 会绑定到续传游标。

`kinds` 是逗号分隔的列表，取值来自 capability 里 `events.kinds` 列出的名称，不能重复；省略就选全部。不管过滤条件是什么，每条流都以 `stream.ready` 开始。`flow_id` 必须是 1–256 字节，且不含控制字符。过滤条件无效时返回 `400 invalid_request`。

恢复时，把最后收到的事件 `id` 作为 `Last-Event-ID` 发送：

```http
GET /api/v1/events?kinds=flow.updated,flow.gap&flow_id=flow-id HTTP/1.1
Authorization: Bearer <secret>
Accept: text/event-stream
Last-Event-ID: <previous-opaque-cursor>
```

最多保留 512 个事件、60 秒；同时支持 16 个客户端，每个客户端的实时队列最多 64 条。队列满时直接断开流，不会悄悄跳过事件。16 个名额用满后，新连接返回 `503 temporarily_unavailable`，带 `Retry-After`。

每 15 秒发一次 heartbeat。每个连接都先发 ready。有效续传的顺序是 ready、重放、实时：ready 保留请求里的游标，之后由重放推进，原子挂接，不留空档。

游标过期、未知、属于旧实例或对应不同过滤器时，在 HTTP 200 之前返回 `409 event_cursor_expired`。

每条事件或日志记录最多为它的第一个精确过滤绑定缓存一份完整帧，其他绑定仍然各自签名。既有 2 MiB 的留存 ring 预算会在发布前预留载荷、一份可能的缓存帧以及缓存 cell，所以接近单条上限的载荷可能在达到条数上限之前就过期。这个 ring 预算不是所有排队数据或 HTTP 持有引用的进程级内存上限。

新连接获得的 ready 游标是一个不透明检查点，不是保留下来的事件记录。旧历史已经过期时，新签发的检查点仍能立即续传；它不会恢复已淘汰的记录游标，也不能越过更新事件的丢失。时间、过滤器、instance 和记录重置的检查照旧有效。

这里的顺序指投递和重放的位置，不是游标字节的排序。

发布的事件有 `stream.ready`、`runtime.updated`、`flow.updated`、`flow.gap`、`generation.changed`，以及反映实际操作状态变化的 `operation.updated`。操作 store 不依赖有没有可写的 `.dae` 来源。generation 事件只来自已接受的发布，不来自收到 reload 请求这个动作。

事件里只有有界的安全 ID 和状态，不含报文正文或原始配置。flow 和 event 记录只存在内存里，不是持久化日志。

每个事件的 JSON 数据都含 `instance_id` 和 UTC 的 `observed_at`：

| 事件 | 其他数据字段 |
| --- | --- |
| `runtime.updated` | `href` |
| `flow.updated` | `resource_id`、安全整数 `revision`、`href` |
| `flow.gap` | 可空的 `resource_id`、`reason`（`buffer_overflow`、`evicted` 或 `recording_changed`）、可空的十进制字符串 `dropped_records` |
| `operation.updated` | `resource_id`、`status`（`queued`、`running`、`succeeded` 或 `failed`）、`href` |
| `generation.changed` | `previous_generation_id`、`generation_id` |

`flow.updated` 是一条失效通知：要用它的 `href` 去读最新的保留修订。每个客户端的实时队列只留同一流还没发出的最新通知，并按新事件的序号追加到队尾。修订号可以跳，但发送游标保持有序。

发布仍然是即时的，终态更新也一样，没有增加批量定时器。事件捕获开启时，重放环记录每一次发布，重放时不做合并。其他事件类型和日志不合并。

不同流的事件、以及其他不可替换的事件，仍然会在实时队列满时断流。流数据、修订和捕获到的追踪 steps 不变。

客户端连接着，或者已放行的记录器通过显式运行时设置持续开启时，事件捕获就是开启的。空闲的事件中心仍接受新流；停止捕获后，旧事件游标失效。事件捕获开启时，手动或自动切换记录状态会用 `flow.gap` 的 `reason=recording_changed` 表示记录连续性中断，它不表示丢包，也不表示没捕获到的流数量。

空闲的事件中心不会重放关闭期间的 gap；重新连接会建立新的记录边界。

### 出站、内存与历史

`runtime/outbounds` 复用逐出站的账本，不按 HTTP 客户端建计数器。`kind` 区分 `builtin`、`node`、`group`，名称可能相同，所以不能只按 name 合并。累计连接数、upload/download 字节和错误都用完整的 UInt64 十进制字符串表示。

`active_connections` 是 safe JSON number。计数和 `counter_since` 属于共用的 StatsManager 生命周期，reload 不会清零。

`GET /runtime/outbounds` 返回 `{observed_at,counter_since,outbounds}`。每行含 `name`、`kind`、数字 `active_connections`，以及十进制字符串 `total_connections`、`upload_bytes`、`download_bytes` 和 `errors`。

`GET /runtime/memory` 返回 `observed_at`、`process`（`rss_bytes`）、`cgroup` 和 `kernel`。`cgroup` 为 `null`，或含 `scope`、`current_bytes`、`limit_bytes` 与 `events`（`high`、`oom`、`oom_kill`）。所有字节值和事件计数都是十进制字符串或 `null`。

两个历史接口都返回 `{observed_at,window_seconds,sampled_every_seconds,samples}`。流量样本含 `sampled_at`、`upload_bytes_per_second`、`download_bytes_per_second` 和可空的数字 `connections`。内存样本含 `sampled_at`、`rss_bytes`、`cgroup_current_bytes` 和 `kernel_ebpf_bytes`。其余样本值是十进制字符串或 `null`。

`/runtime` 的 `process.cpu_percent` 用进程 CPU 时间（`CLOCK_PROCESS_CPUTIME_ID`）的增量，除以采样器实际经过的墙钟间隔，以单个 CPU 为 100% 计：一个核心满载是 100，多线程负载可以超过 100。名义采样周期为一秒。在获得两次可用样本之前，或者读数不可用、时间或计数倒退、墙钟间隔为零时，返回 null。

RSS 来自 `/proc/self/status`。cgroup v2 按实际的 membership 和 mountinfo 定位，读取 `memory.current`、`memory.max` 和 `memory.events`。无法读取或未知的值一律为 null，不伪造成零。

`memory.max=max` 时 `limit` 为 `null`，cgroup 的 `scope` 保持 `unknown`。capability 里的 `runtime_memory.metrics` 列出已经读到的指标：初始是启动时可读的那些，之后的采样只会增加名称，不会删除。`kernel` 为 `null`，honk 不宣称做了内核内存核算，也不会把 RSS、cgroup 和 kernel 相加。

`record_traffic` 和 `record_memory` 默认是 true。两种 history 共用既有的那一秒采样器，错过 tick 用 Skip，没有客户端也照常记录。各自最多 600 个点、600 秒，只存在内存里，重启后清空。

设成 false 并重启后，对应的缓冲会释放，history 返回 `404 capability_not_supported`，即时的 runtime、outbounds、memory 仍可读。`max_points` 从最新点往前，按能满足上限的最小 stride 抽取，再按时间从旧到新返回。`sampled_every_seconds` 是这个名义 stride，不保证没有缺口。

原始时间戳、null 和采样缺口都保留，不做插值，也不补零。

### 配置来源、校验与操作

只有从真实 `.dae` 启动、加载时捕获到的源集合，才会启用配置管理。在程序里构造的 Config，或用 serde 格式加载的配置，都不是无损来源，它们的配置 capability 不可用。GET 返回最后已接受的快照，不会临时重新扫磁盘。

源 ID 不含路径。源的 `path` 和规则的 `file` 保留规范化后的、相对入口目录的名称，例如 `config.d/routing.dae`；源的 `absolute_path` 另外给出规范化绝对路径。原文 SHA-256、字节数、加载时间和每个源的 `writable` 分别提供。源集合和校验最多 32 个来源、8 MiB 原始字节；依赖每加载一次，也各计一份来源数量和字节预算。

`GET /config` 返回 `{generation_id,revision,sources,diagnostics,secrets_redacted,x-honk:{store}}`。每个来源含 `id`、`path`、`kind`（`main` 或 `include`）、`content_sha256`、`content`、`bytes`、`line_count`、`writable` 与 `loaded_at`。只读来源另含 `read_only_reason`；文件模式另含 `absolute_path`。`GET /config/sources/{source_id}` 返回单个来源对象，不含 `writable`、`read_only_reason` 与 `loaded_at`。

geodata 文件是引擎整体加载的运行时资产，只参与 hash 冲突检测，不计入前面说的来源预算。HTTP JSON 正文的 64 KiB 上限仍然独立生效，超限返回 413。所以 capabilities 里的 `config.max_bytes` 是 61440：从 65536 字节的正文上限里扣掉 4096 字节的创建信封，就是单次请求能携带的最大替换或新建内容。

`config_validate.max_bytes` 是 8 MiB 预算，因为完整校验还要算上从磁盘读到的依赖。`resources.config` 里没有 `content` 字段。替换或新建的正文超过 `config.max_bytes` 时，返回 `413 request_too_large`。

reload 会刷新之前捕获的依赖指纹；来源和指纹都没变时，保留原来的配置修订。

已放行的匿名 loopback 请求和 Bearer 认证请求读到同一份配置数据。已接受的正文里会有普通凭据、分享链接和路径。honk 只遮蔽声明的原生或 Clash listener secret 值，包括重复的声明、被覆盖的声明，以及这些值出现在源里其他位置的情况。

honk 用解析器给出的范围来识别凭据值，非凭据文本和行结构保持不变。凭据源仍然是只读的，hash 仍然对应原始字节。写入内容里含有被遮蔽的值时，无论原文还是 JSON 转义写法，都返回 `403 permission_denied`。

不足八字节的值既不遮蔽，也不拒绝写入，可以写进普通源，读出来是原样。`secrets_redacted` 是必有字段，布尔值，表示这次有没有遮蔽 listener secret 值。遮蔽之后的正文不能拿去编辑再回写。

启用 `config_write`、并配置了非空 secret 或 `password_auth` 时，已接受的、不含凭据的主文件和所有不含凭据的 include 都可以写。只有已接受的源 ID 才能授权替换；新建只接受由 include 模式加载的新 `.dae` 路径，调用方给的路径不能用来授权写任意文件。generated 和 subscription 来源不可写。

普通 include 仍然沿用原来的语义：入口相对 glob、排序、无匹配以及重复或越界检查。API 不允许修改原生设置，也不允许改变或移动 API 凭据。要编辑含凭据的主文件，先在本地把凭据迁到专门的只读 include，然后重启；这个迁移没法通过 API 完成。

配置写入被拒绝时，`details.reason` 给出原因，并和 `stage` 等其他 details 字段合并。details 不是对象时，原值放在 `value` 里。`code`、`message` 和 HTTP 状态都不变。

每个响应只报告首个未通过的检查：

| 原因 | 首个未通过的检查 |
| --- | --- |
| `writes_disabled` | 未启用 `config_write`，或既未配置 secret 也未启用 `password_auth` |
| `configuration_unavailable` | 配置协调器未运行 |
| `listener_secret_source` | 该源声明了原生或 Clash listener secret，或写入后会声明 |
| `listener_secret_in_content` | 该源或写入内容含有 listener secret 值；数据库模式下也包括源路径含有该值 |
| `listener_settings_changed` | 候选配置相对当前运行配置修改了 `experimental.native_api`、`clash_api.secret`，或在数据库模式下修改了 `global.data_dir` |
| `credential_sources_changed` | 本次写入，或上次 reload 后的磁盘编辑，改变了声明 listener secret 的源；reload honk 后重试 |
| `import_entry_changed` | `-c` 入口不是数据库当前修订的入口 |
| `unsafe_path` | 存储拒绝目标路径 |

这些原因会出现在这些响应里：源 PUT、新建、import 和修订激活返回的 `403 permission_denied`；组 PATCH 以及节点、provider 写入返回的 `404 capability_not_supported`；节点、provider 的源写入被拒之后返回的 `503`；存储拒绝新建源时返回的 `400 invalid_request`。数据库 import 如果在凭据字段之外还有 listener secret 值，返回 `422 unsupported_value`，原因是 `listener_secret_in_content`。源写入和管理写入都先检查 `writes_disabled`，再检查 `configuration_unavailable`。

候选配置按顺序检查：凭据声明、正文里的凭据值、凭据源变化、listener 设置变化。其他拒绝不带 `reason`。带原因的拒绝会以 INFO 级别写进请求日志行，附带 `reason`，不记录路径和内容。

原生 `/logs` 会显示这一行的 `reason` 和 `status`，其他请求行仍然不输出。

在 `GET /config` 里，`writable: false` 的源用 `read_only_reason` 报出第一个没通过的检查。可写的源省略这个字段。这里的原因只反映已接受的快照：

| 原因 | 含义 |
| --- | --- |
| `writes_disabled` | 配置写入已禁用，含义同上。 |
| `store_blocked` | 数据库模式下记录失败，在重新激活当前 head 修订前拒绝写入。 |
| `listener_secret_source` | 源声明了 listener secret。 |
| `listener_secret_in_content` | 源包含 listener secret 值。 |

`GET /config/sources/{source_id}` 不返回 `read_only_reason`、`writable` 和 `loaded_at`。

源里含 listener secret 值时保持只读，honk 照常运行。启动时以及每次 reload 被接受之后，honk 都会为每个这样的源记一条 WARN 日志，内容没变的 reload 也一样。声明凭据的源、以及禁用配置写入的情况，同样照此处理。

warning 里有源 ID 和按列表方式遮蔽的路径。换成任何源里都没有的凭据之后，这个源就恢复可写。

校验请求用 `Content-Type: application/json`，例如 `{"mode":"syntax","sources":[{"id":"candidate","content":"..."}]}`。`mode` 可以是 `syntax` 或 `full`，每个来源的 `id` 和 `path` 都可以省略。`syntax` 只解析提交的文档；路径只作来源标签，不授权文件访问，也不会去跟随磁盘上的 include。

省略的 `sources[].id` 依次默认为 `source-1`、`source-2`，以此类推。ID 是 1–128 字节的 ASCII 字母、数字、`-`、`_` 或 `.`，在请求内唯一，只用于标注诊断。提供的路径必须非空且唯一。ID 或路径无效、`sources` 是空数组时返回 400；来源超过 32 个返回 413；`mode` 未知返回 422。

原生诊断的格式是 `{level,source_id,line,column,span,code,message}`。`level` 为 `error`、`warning` 或 `info`。诊断无法精确定位到来源时，`line` 和按字节计的 `column` 为 `null`，`span` 也是 `null`。

`full` 模式下，第一份文档对应入口主文件，额外的路径必须落在入口根目录之内。完整离线 admission 会用到 overlay、已放行的本地 include、只读订阅缓存，以及实际的本地 geodata/hosts/ECH 依赖。从未拉取过的订阅按 warning 级别 admission，不会产生缓存节点。

已经有相同拉取配置的活动节点仍然可以 rebase。其他缺失或无效的依赖都算错误。`full` 模式下，如果首份文档的 `path` 不是入口主文件、不是 `.dae`，或者跑到入口根目录之外，返回 `400 invalid_request`。

校验不联网，不创建目录，也不改权限，不启动 worker，不发布 generation。一次完成但无效的 dry-run 返回 `200` 和 `valid:false`。它代替不了之后真实 reload 时的运行时校验，也不保证 reload 一定成功。

`full` 校验先按 include 顺序合并，再判定有效配置的语义。没有进入实际 include 树的提交文档只做结构检查，包括 lexer 恢复之后保留的错误；它的设置和 warning 不影响有效候选。但它的字节和来源数量仍然和每次依赖加载共用同一份预算。

PUT 和校验的请求体里如果有未知字段，包括 `secrets_redacted`，返回 `400 invalid_request`。PUT 的 JSON 正文是 `{"content":"..."}`，`If-Match` 按 RFC 9110 求值。

源的强 ETag 是加了双引号的小写 SHA-256；把读到的 `content_sha256` 加上双引号就能用。它比较的是磁盘上当前的原始字节，不是配置修订，也不是运行时 generation。列表和多个 header 字段行按合并处理，只要有一个 strong 标签匹配，条件就算满足。

weak 标签语法合法，但永远不匹配；`*` 匹配已存在的资源。合法却不匹配的 opaque 标签，包括大小写不同的 hash，返回 412，而不是模式错误。源 GET 返回的仍是已接受快照，所以外部编辑之后可能需要本地处理或显式 reload，而不是拿旧快照去覆盖磁盘。

| 写入条件/结果 | HTTP 语义 |
| --- | --- |
| 缺少 `If-Match`（先于 `Content-Type` 与正文检查） | `428 precondition_required` |
| 畸形 `If-Match` 语法或非文本值 | `400 invalid_request`；列表、weak、`*` 与多个头部 field line 本身合法 |
| 条件不匹配；检测到目标/依赖变化后重新求值仍不匹配 | `412 stale_revision`，检测到的外部内容不覆盖 |
| 检测到目标/依赖变化，但条件仍成立（例如 `*` 或匹配列表） | `409 state_conflict`，不覆盖并发变化 |
| 候选配置或依赖校验失败 | `422 unsupported_value`，不写盘、不 reload |
| 修改当前运行配置中需重启的设置 | `422 unsupported_value`，不写盘、不 reload；每个设置一条 `error` 级 `restart-required` 诊断，消息写明设置名 |
| 未授权源、凭据或原生设置修改 | `403 permission_denied` |
| 操作容量或协调队列繁忙 | `503 temporarily_unavailable` 与 `Retry-After` |

reload 会拒绝那些修改了需重启设置的候选配置，但已经写入的文件不会回滚。于是磁盘上的 hash 和已接受的 hash 不再一致，后续写入都会返回 412。所以协调器在写入之前就拒绝这类修改。组 PATCH、节点与 provider 编辑、数据库模式的 import 和修订激活同样如此；`full` 校验会以 warning 报出这些诊断。需重启的设置请在配置文件里改，然后重启 honk。

协调器在产生副作用之前先预留操作，把 API 新写入和 SIGHUP 串行处理。SIGHUP 也要先入队，再去读盘。

单源覆盖通过完整校验后，写入使用目录文件描述符，依次执行：

1. 检查目标为非符号链接的普通文件。
2. 创建独占临时文件并保留文件权限。
3. 对文件执行 fsync。
4. 复查目标与完整依赖集。
5. 原子重命名。
6. 对目录执行 fsync。

外部编辑器不受协调器约束，最后一次检查和 rename 之间仍然有 race 窗口。UI 正在保存时，不要同时手工改同一个文件。rename 之后如果目录 fsync 失败，503 会明确带上 `written:true,durability_confirmed:false`，且不带 `Retry-After`：可见内容已经变了，这不表示没写成功，也不表示回滚了。

写入之后 reload 无法入队时，同样返回 `written:true`，不带 `Retry-After`。

`POST /api/v1/config/sources` 用来新建一个源文件。只有 `config.writable` 为 true 时，capability 里的 `config.create` 才为 true。配置不可用或不可写时，响应与 PUT 相同。

配置可写但 `config.create` 为 false 时返回 `404 capability_not_supported`。请求正文是 `{"path":"config.d/proxies.dae","content":"..."}`。`path` 相对入口目录，只含普通路径段，以 `.dae` 结尾，不超过 1024 字节，不含控制字符。

父目录必须位于入口根目录之内；通过符号链接指向根目录外同样会被拒绝。不满足时返回 `400 invalid_request`。路径已经在磁盘上存在，或属于已接受的源时，返回 `409 state_conflict`，不覆盖。

候选配置要过和 PUT 一样的完整校验、凭据检查和需重启设置检查，而且新文件必须被某个 include 模式加载进来。否则返回 422，并带上 `source-not-included` 错误诊断：归属主文件，位置为 null。文件先写临时文件，再用不覆盖目标的 rename 写入，权限沿用入口文件的 mode。

数据库模式下改成把新源记录成新修订。reload 失败时，新建的文件留在原处，因为删掉它会和该路径上的其他编辑器抢。每个失败的新建操作都会报告 `written`（文件创建之后为 `true`）和 `committed`（`false`、`true` 或 `null`）。

大小限制、`Idempotency-Key` 以及 413、415、429、503 响应都与 PUT 相同。

只有耐久写入完成并进入真实 reload 队列之后，PUT 才返回 `202`。显式 POST reload 进入协调队列后返回 `202`。响应含 `operation_id`、`href`、同样的 `Location` 和 `Retry-After: 1`，不表示配置已经生效。

admission 的结果是 `{operation_id,kind,status,href}`。轮询 `href` 返回：

```json
{"operation_id":"operation-id","kind":"reload","status":"queued","created_at":"2026-11-13T00:00:00Z","started_at":null,"finished_at":null,"result":null,"error":null}
```

`status` 为 `queued`、`running`、`succeeded` 或 `failed`；还没到终态时，响应带 `Retry-After: 1`。操作结束之前，`result` 和 `error` 都是 `null`。

| `kind` | 成功时的 `result` |
| --- | --- |
| `reload` | `{active_generation_id,datapath_generation_id}`，两个 ID 均可空 |
| `probe` | 有界探测一节中的探测结果 |
| `provider_refresh` | 下文的 provider 结构 |
| `group_update` | `{group_id,config_revision}` |
| `geodata_update` | 下文的 GeoData 结构 |

操作由守护进程持有。HTTP 断连不会取消操作，也不会中断监督器的状态协调。

可选的 `Idempotency-Key` 绑定主体、方法、路径、实例和原始正文。同一个 key、同样正文的并发请求或重试共用结果，不会重复写入或 reload。如果丢了第一个 202，还可以用原来的 If-Match 重试。正文不同则返回 `409 idempotency_conflict`。

`Idempotency-Key` 重复、为空或不是文本时返回 `400 invalid_request`。

预留和保留的操作合计最多 32 个，终态最多保留 300 秒。存储满时，新的 admission 先淘汰最早结束的终态操作，那个 ID 之后返回 404。操作结束后的 300 秒内，它的 `Idempotency-Key` 仍然重放原来的 `202`，正文不同仍然返回 `409`。

被淘汰的 key 最多保留 1024 个，上限由 `resources.operations.max_replay_keys` 给出；超出就丢掉最早的一个。只有当全部名额都落在准备中或执行中的操作上时，才返回 `503 temporarily_unavailable` 和 `Retry-After: 1`。重启后不保留。

真实结果要通过 GET 操作、`runtime.last_reload` 和 `operation.updated` 去读，不能把收到 202 当成 succeeded。reload 被拒绝时，旧的已接受快照和 generation 保留，但已经写入的字节不回滚。提交之后进入 degraded 时，保留新的快照和 generation，并报告 failed，而不是声称旧 generation 还在活动。

管理员应该根据磁盘内容和操作结果去修，然后再显式 reload。磁盘文件加载不了时，失败的操作和 `last_reload` 会返回 `unsupported_value` 错误、`details.diagnostics`（与写入同样内容时的响应相同）和 `committed:false`，并标明已接受的源 ID 与行号。如果全部诊断行超过操作错误 details 的 4 KiB 上限，只保留 error 级别的行。

每次失败的 reload、源写入，以及节点或 provider 写入，都会在 `error.details.committed` 里报告结果（`false`、`true` 或 `null`）。普通 reload 的 details 不带 `written`，只有写入类操作才带。SIGHUP 本身不会创建 API 操作。

只改注释也会更新来源 hash 和配置修订，但有效配置没变时不会新增运行时 generation。有效组成员变化会改变修订，健康测量变化不会。来源 hash、配置修订和运行时 generation 是三种不同的并发 token，不能互相替代。

配置 `secret` 或密码登录保护 listener 时，所有 session 共用一个管理员操作 principal，注销不会删除保留的操作。操作也用于探测、订阅刷新和组更新。探测和订阅刷新不要求源管理 capability。

原生暂停和恢复仍不可用，返回 `404 capability_not_supported`。

### 配置数据库（`--store db`）

`honk-core --store db` 把受管理的 `.dae` 源以修订形式存进状态数据库 `<data_dir>/state/honk.db`。`data_dir` 取自 `--data-dir`（默认 `/var/lib/honk`），必须与 `global.data_dir` 一致，不会退回工作目录。`state` 目录权限 0700，文件 0600；两者都属于守护进程用户，且不能是符号链接。

启动时，或执行 `honk-core admin reset` 时，如果这两者属于守护进程用户、只是多了组或其他用户的读和执行权限，honk 会去掉这些权限并记一条 warning。其他情况一律拒绝，组或其他用户可以写时也一样。`config export` 和其他离线读取遇到 0700 与 0600 以外的权限时一律拒绝，也不改权限。

数据库使用 WAL 模式，同目录下的 `honk.db-wal` 和 `honk.db-shm` 权限与主文件相同。文件系统不支持 WAL 时，例如不支持共享内存，honk 退回回滚日志 `honk.db-journal` 并记一条 warning。配置里只有 `.dae` 源会进数据库。

订阅正文在两种模式下都保存在数据库里。hosts、ECH 和 geodata 仍然在磁盘上，按 `data_dir` 解析。导入源树所在的目录不授权任何依赖。

数据库为空时，启动过程会导入 `-c`。这要求启用 `native_api.enabled` 和 `config_write`，并配置凭据。导入会删掉 `native_api` 和 `clash_api` 里所有的 `secret:`，确认去掉凭据的源树在重新套上凭据后解析出同样的配置，然后以 principal `startup` 记录修订 1。如果凭据值删掉后还有残留，例如留在注释或文件名里，导入就被拒绝。

已经有修订时，启动过程加载当前修订，不读 `-c`。如果启动期间另一个实例移动了 `head`，启动会终止。只有不持实例锁的 mock 模式实例会造成这种情况。

数据库模式不提供 Clash API：不管是导入的源树还是当前修订，只要
`experimental.clash_api.external_controller` 非空，启动就会被拒绝。数据库损坏、
`application_id` 不符，或 schema 版本更高时，也拒绝启动，honk 不会给数据库改名或
重建。启动和 API 重新导入都会恢复剥离掉的凭据，对齐解析器临时生成的组和订阅 ID
以及解析时间戳，再严格比较配置值。节点派生身份、endpoint、组定义和订阅抓取设置仍
然必须一致。

listener secret 和修订分开保存，从不返回。写入不能改 listener secret、`native_api` 设置或 `global.data_dir`，否则返回 403。含已保存凭据值的源也会被拒绝。

响应和 `--without-secrets` 导出都会遮蔽这两个已保存的值。数据库模式下源省略 `absolute_path` 字段，源路径只是标签，不对应任何文件。`If-Match` 比较的是数据库里保存的源字节。

写入先激活，再记录。只有激活提交之后，包括 degraded 和 reconciliation 失败的提交，才写入修订行并移动 `head`。激活被拒绝时不增加记录，并报告 `written:false`。

记录失败时，操作以错误码 `store_unavailable` 失败，`details` 为 `{committed:true,written:false,active_generation_id}`。引擎在确认激活之前就停了，操作错误码是 `activation_unconfirmed`，`details` 为 `{committed:null}`。这两种情况下，`store.recorded` 都会变成 false，capabilities 报告配置不可写，导出文件名不带修订，写入返回 `503 temporarily_unavailable` 和 `details.stage:"store"`。

激活 `head` 所在的修订会重新激活它，不新增记录，并解除这个状态。重启也会解除；重启后加载 `head`。最多保留 50 个修订，按存储的 JSON 算共 16 MiB，从最旧的开始清理，当前修订不删。

JSON 转义会让修订比源文件本身更大。单个修订的 JSON 超过 16 MiB 时拒绝写入。

新的已接受源已经发布、但耐久记录还没完成时，`store.recorded` 为 false，导出文件名是 `honk.dae`；`revision` 和 `parent` 仍然描述耐久的 head。如果读到的旧已接受源本身没变，仍可报告为已记录。协调器要等阻塞的 SQLite promotion 结束，才完成操作、处理下一项修改或确认关闭。

以下路由与字段是 honk 扩展，按契约的 Engine extensions 规则放在 `x-honk` 下。`GET /config` 增加 `x-honk.store {kind, revision, parent, recorded}`，`kind` 为 `file` 或 `db`。capabilities 增加 `config.x-honk.store`，并在 `resources.x-honk` 中增加 `config_export {available}`、`config_import {available, replace_required}` 与 `config_revisions {available, can_activate, max_revisions}`。

已放行的发现接口在 `links.x-honk` 中给出这三个链接。下列路径均位于 `/api/v1/x-honk` 下。

- `GET /config/export` 把已接受的源合并成一份文档返回，带 `text/plain; charset=utf-8`、`Content-Disposition: attachment; filename="honk-r<n>.dae"`、基于正文的强 `ETag` 和 `Cache-Control: no-store`。文件模式下文件名是 `honk.dae`。正文不含 listener secret。有凭据被省略时，第一行是 `# listener secrets omitted`，补回凭据之后才能运行。两种模式都能用。
- `POST /config/import` 用于数据库模式，要求可写。它接受严格 JSON `{"replace":bool}`，必须带 `Idempotency-Key`。它会重新读取 `-c` 源树，通过 reload 操作记录成 origin 为 `import` 的新修订。因为启动过程总会记录修订 1，这里必须提交 `replace:true`，其他请求返回 `409 state_conflict`。凭据副本在删除后还有残留时返回 `422 unsupported_value`。源树必须保持入口路径、listener secret、`native_api` 设置和 `data_dir` 不变，否则返回 403。
- `GET /config/revisions` 用于数据库模式，返回 `{active, max_revisions, revisions:[{revision, parent, created_at, principal, origin, content_sha256, bytes, sources:[{path, sha256}]}]}`，从新到旧排列，不含正文。`active` 和各行来自同一个数据库快照。父修订被留存清理删掉后，`parent` 为 null。
- `POST /config/revisions/{n}/activate` 用于数据库模式，要求可写。它接受空正文或 `{}`，`Idempotency-Key` 可选。它会校验并激活修订 `n`，再记录成 origin 为 `activate` 的新修订。`store.recorded` 为 true 时，激活当前修订不会产生变更。未知的 `n` 返回 `404 resource_not_found`。

文件模式下，import 和修订路由返回 `404 capability_not_supported`。

要恢复文件模式：

1. 执行 `honk-core config export --out /etc/honk/config.dae`。
2. 去掉 `--store db` 后重启。

之后再用数据库模式启动时，从 `head` 继续。对文件的改动只能通过 `replace:true` 的导入进数据库。

恢复损坏的数据库：

1. 执行 `honk-core config export --out exported.dae`。导出只检查应用 ID 与模式版本，因此仍可能读取损坏的文件。
2. 停止 honk。
3. 执行 `mv <data_dir>/state <data_dir>/state.bad`，移走整个目录，确保 `honk.db-wal` 与主文件一起移动。
4. 以 `--store db -c exported.dae` 启动。

### 有界探测

`POST /probes` 要求 JSON，例如 `{"target":{"type":"node","node_id":"<id>"},"kind":"http","transport":["tcp"],"ip_version":"ipv4","warmth":"cold"}`。

`target`、`kind`、`transport`、`ip_version` 和 `warmth` 都必填。`members` 可以省略，但不能为 `null`；成员 ID 列表不能含空 ID 或重复 ID，节点目标不能带 `members`。下面是同时用两种传输的 DNS 探测：

```json
{"target":{"type":"group","group_id":"<id>"},"kind":"dns","transport":["tcp","udp"],"ip_version":"ipv4","warmth":"cold","members":"direct"}
```

| 字段 | 取值 |
| --- | --- |
| 节点目标 | `{"type":"node","node_id":"<id>"}`；不接受 `members` |
| 组目标 | `{"type":"group","group_id":"<id>"}` |
| 组 `members` | `"direct"`（默认）、`"leaves"` 或非空直接成员 ID 列表 |
| `kind` | `tcp_connect`、`http` 为数据探测，仅用 TCP；`dns` 为 DNS 探测，可用 TCP、UDP 或两者。 |
| `transport` | `["tcp"]`、`["udp"]` 或 `["tcp","udp"]`；只有 `dns` 接受 UDP |
| `ip_version` | `ipv4`、`ipv6`、`any` |
| `warmth` | `cold`、`warm` |

honk 不接受调用方指定的 URL。探测用途由 `kind` 决定，不用在请求里提交：`tcp_connect` 和 `http` 是数据探测，只用 TCP；`dns` 是 DNS 探测，可以用 TCP、UDP 或两者。

组可以用直接成员、叶节点或显式成员 ID。honk 先固定当前配置、成员和注册的 generation，再去重执行测量，并保留成员到叶节点的 association。TCP 连接探测测的是节点实际配置的端口，不接受调用方指定任意端口。

HTTP 用配置里的检查 URL，不跟随重定向。DNS 执行真实的 UDP 交换或带长度帧的 TCP 交换。探测目标只来自已接受的配置；honk 不对目标或节点服务器施加地址、端口策略。

目标主机名按当前 DNS 配置解析；这份配置答不上来时，例如用了 `asis` 路由，就退回 bootstrap DNS。私网、loopback 地址和非默认配置端口不需要额外放行。IPv4-mapped IPv6 会规范化成 IPv4；选中的 IP 保持固定，HTTP Host 和 TLS SNI 保留配置里的名称，不能交给代理重新解析。探测、geodata 和共享下载都使用配置里的目标，不设地址或端口白名单。

能够写入配置或控制订阅内容的人，决定这些目标是什么。provider 内容属于可信的配置。

对 `direct` 或 `block` 节点做 `tcp_connect`，或对不支持 UDP 的节点做 UDP 探测，会在这项测量开始之前返回 `422 unsupported_value`。

| 探测预算 | 上限 |
| --- | --- |
| 每项任务的成员 association | 64 |
| 每项任务的结果行 | 256 |
| 每项任务的并发测量 | 10 |
| 活动任务 | 4 |
| 排队任务 | 16 |
| 每个目标的任务 | 1 |
| 准备、排队与测量 | 共用 30 秒期限 |
| 每个资源的每分钟请求数 | 唯一认证主体与全局各 30 次 |

最终传输 owner 的清理即使超期，也要等到结束，所以一个操作的总耗时可能超过 30 秒。限流返回 `429 rate_limited`；容量不足或 owner 不可用返回 503，两者都带正数的 `Retry-After`。

即使已经有四个活动任务，也会立刻返回 202 和一个 `queued` 操作。

202 只表示守护进程接手了任务。在测量开始前就结束的任务，会以 `probe_cancelled`、`probe_deadline`、`unsupported_value` 或 `engine_unavailable` 失败。`unsupported_value` 表示本地解析被拒绝，或者节点没法把 UDP 转发到探测端口。断开 HTTP 连接不会取消任务。

重复使用可选的 `Idempotency-Key` 时，会重放仍然保留的探测 admission 结果。

结果会保留真实的 measurement、地址族、warmth 和时间，以及健康状态更新有没有被当前时期接受。过时的 generation、取消或超期不会伪造成 unhealthy，TCP-connect 也不会冒充 HTTP 排名样本。最终清理失败时，操作以 `probe_cleanup_failed` 失败，`result` 保持 null，已完成的测量放在 `error.details` 里。

探测操作成功时的 `result`：

```json
{"target":{"type":"group","group_id":"group-id"},"selection_changed":{"tcp":false,"udp":false},"selection_before":{"tcp":"member-id","udp":null},"selection_after":{"tcp":"member-id","udp":null},"results":[{"member_id":"member-id","resolved_leaf_node_id":"node-id","kind":"dns","purpose":"dns","transport":"udp","ip_version":"ipv4","warmth":"cold","state":"healthy","latency_ms":12.5,"health_updated":true,"error":null,"observed_at":"2026-11-13T00:00:00Z"}]}
```

`latency_ms`、`resolved_leaf_node_id` 与 `error` 可为 `null`。`health_updated` 表示该样本是否计入健康状态。

直接成员里的子组，会通过它选中的一个叶节点来探测。选这个叶节点可能展开后代；除了没有子组、也没设置 `final` 的 Selector，规划图超过 256 项就拒绝。目标组仍然受 64 个成员和 256 行结果限制，更大的组可以用 `members` 列表分批，每批最多 64 个 ID。`members: "leaves"` 在整组图超过 256 项时也会被拒绝。

### DNS 查询、缓存与结果历史

`POST /dns/query` 要求严格的 JSON 请求体，`Content-Type` 必须是 `application/json`；其他媒体类型返回 415。

请求体上限 4096 字节，超出返回 `413 request_too_large`。

| 字段 | 位置 | 要求或默认值 |
| --- | --- | --- |
| `domain` | 请求体 | 必填 |
| `type` | 请求体 | 可选非空数组，最多八个不同记录类型；默认 `["A"]`。超过上限返回 `413 request_too_large`。 |
| `cache_mode` | 请求体 | `normal` 为默认值，或 `bypass` |
| `upstream` | 请求体 | 已配置的上游名称，包括未被规则引用的上游 |
| `detail` | 查询字符串 | `summary` 为默认值，或 `full` |

支持 A、AAAA、NS、CNAME、SOA、PTR、MX、TXT、SRV、SVCB、HTTPS 和 CAA。

类型可以写成大写名称、十进制数字，或 `TYPE` 加数字，所以 `"A"`、`"1"` 和 `"TYPE1"` 等价。类型名称区分大小写。类型无效或重复时返回 400；合法但不在上面十二种之内的类型返回 422。缓存和日志的 `type` 过滤接受任意合法类型。

所有类型固定同一个 DNS generation，共享十秒 deadline。唯一认证主体和全局各限每分钟 30 次。

指定 upstream 会替换请求阶段的路由选择，但不改变 hosts 和 strategy 的优先级，也不改变响应侧策略，包括重新查询。命中本地 hosts 记录时，仍然报告默认路由，而且没有 upstream。

`bypass` 不执行以下操作：

- 读取或写入正缓存、负缓存及过期缓存。
- 加入会写入缓存的 singleflight。
- 替换缓存条目或启动刷新。

没有提供 `cache_mode` 时，保留正常的生产语义。完整详情会展示经过校验的答案记录；各类型的超时、拒绝或错误仍按实际结果报告。

`detail=full` 响应如下；摘要省略 `answers`：

```json
{"domain":"example.com.","cache_mode":"normal","query_time":"2026-11-13T00:00:00Z","results":[{"type":"A","question":{"name":"example.com.","type":"A","class":"IN"},"elapsed_ms":12,"cached":false,"cache_entry_id":null,"upstream":"dns1","route":{"source":"default","rule":null},"status":"NOERROR","answers":[{"name":"example.com.","type":"A","class":"IN","ttl":60,"data":"192.0.2.1"}]}]}
```

`route.source` 为 `default`、`dns.routing` 或 `forced`，`route.rule` 可空。缓存结果的 `upstream` 为 `null`。`status` 为响应码；某个类型失败时为 `TIMEOUT`、`REFUSED` 或 `ERROR`。

DNS 查询、缓存响应和 DNS 日志分页都会遮蔽用于显示的 listener secret 值，但不改变不透明 ID 或游标绑定。

字面值 `.` 表示 DNS 根，可以用在实际查询、精确缓存列表和按名称删除里。普通输入名称不区分大小写，末尾的点可以省略；展示名称会保留规范化后的末尾点。合法的根域 wire 问题也走普通严格 DNS 路径；非 UTF-8 标签仍不在这份消费者契约范围内。

名称去掉可选的末尾点之后是 1–253 字节，由 1–63 字节的标签组成，标签只含 ASCII 字母、数字、`-` 或 `_`。实时查询、缓存的 `name` 和路由追踪的 `domain` 都用这条规则。

缓存 GET 只观察运行时精确 key 上的正、负记录（`persistent:false`），不会提升 LRU 优先级，也不计入命中统计。它支持 `name` 精确名称、`domain` 子串、可重复的 `type`、`include_expired=false|true`、`detail`、`limit`（1–1000，默认 100）和 `cursor`。最多保留 8 份绑定过滤器和实例的不可变快照，30 秒，合计 8 MiB；底层记录被淘汰之后，快照占用的空间仍计入预算。

`name` 匹配一个精确名称；`domain` 匹配大小写不敏感的子串。分页结果是 `{observed_at,coverage,entries,total,next_cursor,usage}`，`total` 是匹配的条目数。条目为 `{entry_id,domain,type,class,status,expires_at,stale_until}`，`stale_until` 可空；`detail=full` 时另含 `answers`。

超出这份预算时返回 `503 snapshot_unavailable`。游标无法识别时返回 `410 snapshot_expired`；可识别但过滤器或 `limit` 不同的游标返回 `400 invalid_request`。`entry_id` 标识精确的 incarnation，用旧 ID 删不掉替代它的记录。

按 name 删除可以跨精确 key 的各种变体，并用 type 限定范围。删除和 flush 与入库发布串行化，会等已启用的持久化确认失效；确认之后，旧的 foreground 或 refresh 不能把已删的缓存复活。flush 不清空 DNS 路由投影。

DNS 查询、缓存和日志的完整 JSON 响应上限都是 262144 字节。缓存和日志分页如果下一条会超出上限，就提前结束并返回 `next_cursor`，所以 `limit` 只是上限，不保证条数。单条记录本身就超限时，会独占一页完整返回，不受这个上限约束。

原始报文最长 65535 字节，展开后大小有界；拒绝它会让其后的记录都读不出来。查询响应超限或无法保留快照时返回 503 和 `Retry-After`，不会裁剪 RRset 去冒充完整答案。

`DELETE /dns/cache/{entry_id}` 不接受请求体或查询参数，返回 `{deleted}`。`DELETE /dns/cache?name=...&type=A` 不接受请求体，返回 `{matched,deleted}`，省略 `type` 时选择该名称的全部类型。`POST /dns/cache/flush` 接受空请求体或 JSON `{}`，返回 `{matched,deleted}`。

名称、类型和过期筛选在快照的字节 admission 与复制之前就完成；没选中的缓存记录不占本次快照预算。负应答优先级和过期筛选使用同一个观测时刻。

每页还带 `usage {entries, entry_capacity}`，描述快照那一刻的整个运行时缓存，不受过滤器影响。`entry_capacity` 是 `max_cache_size` 钳制到 1–100,000 之后的值。两个值都是十进制字符串，在所有分片同时加锁时读取。

同一快照的后续页会重复同样的值。淘汰按分片处理，也受缓存应答字节数限制，所以某个分片可能已经在淘汰，而合计值看起来还有余量。`usage.entries` 还会计入 `total` 不包含的过期记录和非精确 key 记录。

`record_dns_log` 默认是 `true`，独立 DNS 日志需求有效时允许记录，最多保留 512 条、8 MiB。显式设成 `record_dns_log: "on"` 之后，即使没有客户端也会持续记录。配置里写 `false` 就禁止记录，改了要重启。

记录实际停止时会释放历史，已有的游标随之失效。记录发生在客户端请求实际完成时：记的是普通 DNS 查询结果，以及来源已知的客户端解析结果，包括已知的客户端 socket、入口，还有能解析出结果的拒绝或错误。原生和 Clash 的诊断调用、以及后台刷新产生的重复记录都排除在外。

只存在内存里。完整的原始报文和元数据一起计入预算，淘汰时按整条旧记录算。`GET /dns/log` 按最新优先，支持大小写不敏感的 `name` 子串、`type`、不带端口的 `src`、`limit`（1–500，默认 100），以及和过滤器绑定的 `cursor`。

`name` 匹配大小写不敏感的子串；`src` 是不带端口的 IP 地址。分页结果是 `{observed_at,total,next_cursor,records}`，`total` 是全部保留记录数，不是匹配数。记录含 `id`、`observed_at`、可空的客户端 `src`（地址加端口）、`question`、`status`、`cached`、可空的 `upstream`、`route`、`elapsed_ms` 和 `answers`，结构与 DNS 查询结果相同。

淘汰或缩容会让受影响的游标失效；无法识别的游标返回 `410 snapshot_expired`。可识别但过滤器或 `limit` 不同的游标返回 `400 invalid_request`。停止记录不影响正常的 DNS 服务。

### 路由模拟与规则位置

已放行的匿名 loopback 请求和 Bearer 认证请求，在读取规则和路由模拟上的权限相同。`POST /routing/trace` 接受 `{"input":{"network":"tcp","domain":"example.com","dst_port":443},"resolve":"none"}`。`input` 要求 TCP 或 UDP、非零目标端口，以及至少一个 `domain` 或 `dst_ip`。

其他输入字段都可选：`dst_ip`、`src_ip`、`src_port`（1–65535）、`pname`、`dscp`（0–63）和 `mark`（32 位，接受但不参与求值）。未知字段返回 400。`resolve` 默认是 `none`，返回固定 `instance_id` 和 `generation_id` 的 `simulation` 结果。`live` 要求带 `domain` 且不能带 `dst_ip`，违反这个结构返回 400。

结构合法但暂时不支持的 `live` 请求返回 422。`Content-Type`、JSON 与 schema、`input` 和 `resolve` 的校验先于限流 admission；被校验拒绝的请求不占路由模拟的限流名额。

模拟固定当前已编译的路由器、配置和 generation：不查 DNS，不探测，不推进组选择，也不建立连接。缺失的输入保留 `indeterminate/missing_inputs`，不能当作历史流证据，也不代表真的会这样转发。上限是 1 个地址、256 个规则或条件步骤、5 秒；唯一认证主体和全局各限每分钟 30 次。

`GET /rules` 返回当前完整字典，含回退，从不截断。`max_rules` 取 4096 和当前字典行数中较大的那个；`dns_rules.max_rules` 同样不小于较长的那个 DNS 列表。回退条目的 `expression` 是它的源语句，例如 `fallback: proxy`。

`GET /rules` 返回 `{generation_id,rules,fallback}`。规则含 `rule_id`、`index`、`expression`、`outbound`、`must`、可空的 `source` 与 `kind`；`fallback` 为 `{outbound,source}`。

追踪结果为 `{mode,instance_id,generation_id,observed_at,evaluations,dns}`。每个求值含可空的 `dst_ip`、`decision`、可空的 `outbound`、`missing_inputs` 与 `rules`。规则求值为 `{rule_id,expression,result,missing_inputs,conditions}`，条件为 `{id,expression,result,missing_inputs}`；`result` 为 `matched`、`not_matched`、`indeterminate` 或 `skipped`。

没有保留源文本时，用 `fallback: <outbound>`。路由模拟的求值结果也用 `fallback: <outbound>`。两者在 deadline 内无法固定路由器时，返回 `503 snapshot_unavailable`，带 `Retry-After`。

规则 ID 和用户态捕获证据共用同一个 generation 范围内的身份。有已接受的解析器来源位置时，给出不透明的 `source_id`、从 1 开始的 `line` 和按字节计的 `column`。`file` 与该来源相对入口目录的 `path` 一致；否则 `source` 为 null。

历史流不会从当前字典重建；内核 final 的来源仍然可能是 unknown。编辑时请用来源 ID 和对应的内容权限，不要从显示标签推导文件系统路径。

对已接受 `.dae` 配置里的规则，包括含凭据来源的规则，`/rules` 和 `/routing/trace` 的规则 `expression` 保留编写时的条件值，包括 geosite/geoip 名称、否定和带引号参数，同时去掉注释和出站子句。追踪的逐条件表达式按实际编译后的顺序，以 dae 写法显示配置值，不加引号：一个 `domain(...)` 里的普通域名候选和 geosite 会合成一个联集条件，否定作用于整个联集。目标 IP 和 geoip 候选同样共用一个条件。

listener secret 值仍然被遮蔽。普通条件文本不需要写权限就能读到。没有已接受来源元数据的规则，显示编译后的条件值，来源保持 null。

编译后的展示反映的是规范化之后的谓词，不等于原始写法，也不展开 geodata。追踪的展示元数据和决策固定在同一已接受 generation 上。磁盘上的编辑只有在 reload 被接受之后，才会更新这两种响应。

reload 被拒绝时保留旧的表达式。历史流保留各自 generation 捕获到的有界编译后值，包括在程序里构造路由器时的值。

### DNS 路由规则

`GET /dns/rules` 以 `{generation_id, request, response}` 返回当前 generation 的 `dns { routing { … } }` 规则。这个接口是只读的；要改 DNS 规则，和改 `/rules` 一样，通过源 PUT 完成。两个列表都按求值顺序排列，末尾恰好一条 `kind: "fallback"`。

每条记录含 `rule_id`、从 0 开始的 `index`、`expression`、`action`、`upstream`、`source` 和 `kind`。请求规则的 action 是 `upstream`、`asis`、`reject`；响应规则的是 `accept`、`reject`、`requery`。

action 是 `upstream` 或 `requery` 时，`upstream` 是引擎实际使用的小写名称；其他 action 下为 null。`expression` 是编写时的整条语句，含 action，去掉行尾注释，例如 `qname(suffix: example.com) -> AliDNS` 或 `fallback: googledns`。配置里没写回退时，也会列出引擎的默认值：请求侧是 `upstream` `default`，响应侧是 `accept`。

它的 expression 是 `fallback: <action>`，`source` 为 null。被解析器以 warning 级别忽略的规则不会列出。

`rule_id` 的格式是 `{instance}:{generation}:dns_request:rule:{index}` 或 `{instance}:{generation}:dns_request:fallback`，响应列表把 `dns_request` 换成 `dns_response`。它在两个列表之间唯一，随 generation 变化，所以定位一条规则要同时用 `generation_id` 和 `rule_id`。`source` 与 `/rules` 结构相同：不透明的 `source_id`，与该来源相对入口目录的 `path` 一致的 `file`，以及语句在该来源中起始处从 1 开始的 `line` 和按字节计的 `column`。

没有已接受来源元数据的规则，`source` 为 null，expression 由解析后的条件生成。两个列表都完整返回，包含回退。`resources.dns_rules.max_rules` 至少是 4096，也不小于当前较长列表的条数。

5 秒内无法固定当前配置时返回 `503 snapshot_unavailable`，带 `Retry-After`。磁盘上的编辑只有在 reload 被接受之后才会反映到响应里。

### Provider 观测与刷新

已放行的匿名 loopback 请求和 Bearer 认证请求读到同一份 provider 数据。provider 的 GET 不联网。订阅条目把真实的 SubscriptionSupervisor 观测和已接受节点的 `subscription_id` 关联起来；可以用 `Node.provider_id` 去对应。

分页为 `{providers,next_cursor}`。provider 含 `id`、`name`、`kind`（`inline` 或 `subscription`）、可空的 `url_redacted`、`updated_at` 与 `expires_at`、`node_count`、`status`（`ok`、`stale` 或 `error`）、`traffic`（`null`，或十进制字符串组成的 `{upload_bytes,download_bytes,total_bytes}`）、`last_error`（`null` 或 `{code,message,details}`）与 `download`（下述路由对象或 `null`）。

订阅对象带的是配置里的名称，`url_redacted` 返回完整 URL；字段名是为了兼容客户端才保留的。GET 和成功操作的结果用同一种表示。

`traffic` 和 `expires_at` 来自 provider 的 `subscription-userinfo` 响应 header；没有这个 header 时为 null。配置名称如果和旧的 `provider-<id>` 标签相同，那只是普通名称，不当 ID 别名。从未加载、正在等待加载，或已禁用又没有缓存时，状态为 `stale`，节点数为零，时间和错误都是 null。

只有真的失败、且没有可用节点时，状态才是 `error`；保留了旧节点或缓存节点时是 `stale`。订阅条目还带 `download`，也就是由 `download_detour` 决定的拉取路由，结构和 geodata 路由相同：`route` 为 `routing`、`direct` 或 `group`，`group_id` 是该组在 `GET /groups` 里的 ID，其他路由或组已不存在时为 `null`。内联条目的 `download` 为 `null`。没有文件 provider 这种类型。

拉取失败时，`last_error.code` 为 `fetch_failed`。订阅的下载路由暂时没有可用节点时为 `route_unavailable`，见[订阅参考](./subscription.md#拉取持久化与恢复)。已分类的 `fetch_failed` 错误会用 `details` 给出失败阶段 `stage`，例如 `connection_failed`、`download_timeout`、`tls_failed`、`parse_failed`，以及选中的节点 `node` 和选中该节点的组 `group_id`。无效 URL、重定向之类没分类的失败返回 `details: null`。直连下载、选中节点之前就失败，以及解析失败到无法保留下载归属时，`node` 为 null；没有组归属，或对应的组已经不在目录里时，`group_id` 为 null。配置校验拒绝发布时，例如节点和静态节点重复，`last_error.code` 为 `publication_rejected`，诊断代码写在 `details.diagnostic_code` 里，例如 `duplicate-node-id`。

因发布被拒而失败的 refresh 操作带同样的 `details.diagnostic_code`；拉取方面的 `stage`、`node` 和 `group_id` 只出现在 provider 的 `last_error` 里。列表的 `limit` 默认 100，范围 1–1000；快照上限是 8 份、30 秒、4 MiB，容量不足时返回 `503 snapshot_unavailable`，带 `Retry-After`。游标无法识别时同样返回 `410 snapshot_expired`；可识别但过滤器或 `limit` 不同的游标返回 `400 invalid_request`。

订阅已启用、且 supervisor 正在运行时，才能向 refresh endpoint 发 POST。订阅已禁用，或没有挂接 supervisor（`can_refresh: false`）时，返回 `404 capability_not_supported`。同一个 provider 上不同的并发 refresh 返回 409；保留的幂等重放先于冲突检查。

`POST /providers/{id}/refresh` 要求空请求体，可以带 `Idempotency-Key`，返回 202 操作响应。

刷新成功的要求是真实的 revision-fenced 发布被接受；拉取成功或写了缓存都不算成功，HTTP 断连也不会丢结果。虚拟的内联 provider 不能刷新，也不能删除。它关联的是 `provider_id: inline` 的静态、非内置节点；内置归属保持 null，订阅 ID 仍是 UUID。

### 原生日志与运行时设置

`record_logs` 默认是 `true`，独立 `/logs` SSE 需求有效时允许捕获日志，最多保留 512 条、60 秒。日志 capability 用 `max_buffered_records` 和 `retention_seconds` 声明这两个上限，并列出了 `filters: [level, target]`。显式把运行时设置改成 `record_logs: "on"` 后，即使没有客户端也会持续捕获。配置里写 `false` 就禁止捕获，改了要重启。

记录实际停止时会释放日志，续传游标随之失效。真实的 `ts`、`level`、`target` 会保留。只有审查过的静态消息，以及有界、类型明确的安全字段可以输出；其他 `message` 和 `fields` 明确标记为不输出。honk 不靠正则去猜所有秘密，也不转发控制台或 Clash 的格式化输出。

`GET /logs` 以 SSE 向认证调用方和已放行的匿名 loopback 调用方返回 `stream.ready` 和日志，可选最低 `level` 和 `target` 前缀作为过滤。续传用 `Last-Event-ID`，游标绑定流、实例和过滤器。续传顺序和 `/events` 一样，是 ready、重放、实时：ready 保留请求里的游标，之后才由重放推进。

`GET /logs` 接受 `level` 和 `target`。`level` 是小写的 `error`、`warn`、`info`、`debug` 或 `trace`，默认 `trace`；`target` 是 1–256 字节的模块路径前缀。过滤只是从已捕获的记录里挑，不会提高捕获级别。每个 `log` 事件的数据是 `{ts,level,target,message,fields}`，`fields` 可空。不会输出的消息显示为 `[message withheld: not audited for native disclosure]`。

每条流最多 16 个客户端，每个客户端最多排队 64 个事件，每 15 秒发一次心跳注释。16 个名额用满后，新连接返回 `503 temporarily_unavailable`，带 `Retry-After`。游标过期、属于别的流或实例、或过滤器不同时，在 HTTP 200 之前返回 `409 event_cursor_expired`；队列已满或重放记录丢失时直接断流。

缩容会让被淘汰记录的游标失效。

和 Clash `/logs` 一样，捕获始终排除 `quinn::endpoint` 目标：它由 endpoint 驱动任务报出的 ERROR，会和 honk 自己报告、带上下文的 carrier 故障重复。

`PATCH /runtime/settings` 使用 JSON 合并语义，只接受 capability 声明列出的字段：

完整合并请求示例：`{"log":{"level":"debug","buffered_records":128},"flows":{"retention_seconds":60}}`。

| 字段 | 允许的值 | 配置值 |
| --- | --- | --- |
| `record_flows`、`record_logs`、`record_dns_log` | `"on"`、`"off"`、`"auto"` | `"auto"` |
| `log.level` | `trace`、`debug`、`info`、`warn`、`error` | 配置的原生日志捕获级别 |
| `log.buffered_records` | 64–512 | 512 |
| `dns_log.max_records` | 64–512 | 512 |
| `flows.max_flows` | 64–1024 | 1024 |
| `flows.retention_seconds` | 1–300 | 300 |
| `geodata` | 见 [Geodata 来源与自动更新](#geodata-来源与自动更新) | 单独存储，不因激活重置 |

未知字段、null、空对象和越界值都算结构或边界错误，返回 `400 invalid_request`。`geodata: null` 是例外，它表示清除已存储的 geodata 设置。geodata 的凭据 admission 先于结构校验执行：请求里含 `geodata` 的匿名请求会先拿到 `403 permission_denied`。不在 `resources.runtime_settings.fields` 里的字段返回 `422 unsupported_value`，例如配置禁止了对应记录器时的 `log.*`、`dns_log.*`、`flows.*`，或没有状态数据库和 geodata owner 时的 `geodata`。

GET 和成功的 PATCH 返回内部一致的记录器设置快照，含 `source: "config"|"runtime"`。geodata 单独读取，可能已经反映了并发更新。配置里的 `log.buffered_records` 和 `dns_log.max_records` 都是 512，`flows.max_flows` 是 1024，`flows.retention_seconds` 是 300。

整个合并结果通过校验后，记录器设置由同一个 owner 原子发布，`source` 为 `runtime`。只改 geodata 时，顶层 `source` 保持不变。缩容会淘汰旧记录，并让受影响的游标失效。

capability 声明的是取值范围，不是当前值：`logs.min_buffered_records`、`dns_log.min_records` 和 `flows.min_flows` 都是 64；`flows` capability 声明返回 `max_flows` 和 `retention_seconds` 的上限，即 1024 和 300。修改 `log.level` 会同时替换控制台和日志文件的过滤器，包括由 `RUST_LOG` 或 `--debug` 设下的过滤器。Clash `/logs` 仍按各请求的级别过滤。

这些运行时覆盖值不会写进 `.dae` 或缓存数据库。每次显式配置激活被接受时，包括 no-op 或提交后 degraded 的激活，都会恢复配置里的级别、启动时的控制台与日志文件过滤器、初始留存上限，并把记录模式重置成 `"auto"`。激活被拒绝、provider 刷新或网络刷新时，运行时设置保留。

`geodata` 单独存储，不受激活影响，见 [Geodata 来源与自动更新](#geodata-来源与自动更新)。

在顶层记录字段里，`"on"` 让已放行的记录器一直开着，`"off"` 强制关闭。初始的 `"auto"` 让流、日志、DNS 日志各自按对应的独立诊断需求决定。省略的字段保持不变。

null 会被拒绝。配置里写了 `false` 就禁止记录；运行时请求开启这个记录器，会让整次 PATCH 以 `422 unsupported_value` 被拒绝。哪些级别和留存控制可用，由配置权限决定，和记录器是不是暂时停着无关。

GET 和成功的 PATCH 响应里有只读的 `recording`：`flows`、`logs`、`dns_log` 各含 `{allowed, mode, active}`，其中 `mode` 为 `"auto"`、`"on"` 或 `"off"`。`events.active` 表示事件捕获是否开启；`grace_remaining_seconds` 表示通用连接的宽限期还剩几秒，不是任何独立流、日志或 DNS 日志诊断需求的倒计时。还有通用流连接时，这个字段为零。

读取设置不会延长任何期限。

### 主文件条目与 geodata 管理

`POST /api/v1/nodes` 接受 1–8192 个字符的链接。更长的声明要通过编辑配置源写入，例如接近 16 KiB header 上限的 XHTTP `extra`。引擎拒绝的链接返回 `422 unsupported_value`，`error.message` 是解析器给出的静态原因，例如 `XHTTP xPaddingBytes must stay within 1-8192`，`details.fields` 为 `["name","link"]`。

响应不会回显提交的名称、链接或选项值，也不会写入任何内容。`POST /api/v1/providers` 用同样方式报告被拒绝的订阅条目。其他拒绝仍然用通用消息。

`resources.nodes.can_manage` 和 `resources.providers.can_manage` 要求源协调器正在运行，已接受的主文件可写，且不含 API 凭据。创建节点提交 `{"name":"edge","link":"socks5://192.0.2.2:1080"}`。创建 provider 提交 `{"name":"feed","kind":"subscription","url":"https://example.net/sub"}`。

`resources.providers.create_options` 列出省略 provider 字段时实际生效的默认值：

| 字段 | 限制 | 内置默认值 |
| --- | --- | --- |
| `update_interval` | 秒，最多一年；`0` 表示仅按请求刷新 | `86400` |
| `user_agent` | 1–256 个可打印 ASCII 字符 | `honk/<version>` |
| `cache` | 仅在 `global.store_subscribe` 打开订阅存储时可用 | `true` |

如果 `assets.subscription` 设置了对应的默认值，`create_options` 返回那个值，而不是内置的回退值。

`resources.providers` 还会声明 `create_unfetched: true`，表示支持先创建、暂不拉取的方式。显式写了选项的 provider 会写成 `tag: 'url' { ... }`，`ua`、`interval` 和 `cache` 各占一行。结构里的长度、匹配模式、类型、interval 或 user-agent 边界不满足时，返回 `400 invalid_request`。

未声明的选项返回 `422 unsupported_value`，例如没有 store 时的 `cache`。严格 JSON 和 64 KiB 正文限制不变。这里复用引擎解析器、完整离线 admission、FD 相对的耐久写入和真实 reload。

只有激活和订阅协调都完成之后，才以 `201` 返回当前的 Node 或 Provider 和 `Location`。HTTP 断连不会取消已经入队的工作。使用 `--store db` 时，这些操作记录新修订，不重写主文件。

节点名 1–64 字符，链接最多 8192 字符。provider 名是 1–64 个 ASCII 字母、数字或 `_.-`，HTTP(S) URL 最多 4096 字符。违反结构定义里的长度、匹配模式、枚举或边界要求时，返回 `400 invalid_request`。

重名返回 409。结构合法但不支持的链接、身份、provider URL scheme 或选项返回 422。新 provider 即使有旧的缓存正文，也从零节点、`stale`、没有更新时间的状态开始。

同一个源定义上的延迟拉取状态，会在无关编辑和 reload 中保留，直到显式 refresh。修改这份 specification 或重启之后，恢复普通的订阅启动行为。API 不会创建相同拉取配置的别名。

删除时如果归属有歧义，直接拒绝，不会转移 ID 或节点。

DELETE 不接受请求体和查询参数：带了任意一个就返回 `400 invalid_request`；正文超限返回 `413 request_too_large`。两种都不带 `Retry-After`。未知 ID 返回 `{"deleted":0}`，不写入。成功删除则在激活之后返回 `{"deleted":1}`。

内置节点、订阅派生节点、非主文件条目，以及不支持或有歧义的归属，都返回 `404 capability_not_supported`。静态 include 仍然在内联视图里可见。固定的客户端契约没有逐节点的 `writable` 字段，所以界面上的删除按钮仍可能被拒绝。

删除被某个组用作 `final` 的节点返回 `409 state_conflict`，`details.groups` 列出这些组的 ID。其他仍被引用的条目要先改掉引用，否则写入前的校验会失败。主文件读取之后又在磁盘上被改动时，返回 `409 state_conflict`。

编辑已有条目仍然用源 PUT；节点和 provider 都没有 PATCH 接口。

这些同步动作和源 PUT、组 PATCH、SIGHUP 共用协调器，会检查已接受修订、磁盘字节和依赖，但拦不住任意的外部编辑器。失败时的 `details` 含 `stage`、`written`、`durability_confirmed` 和 `committed`；这类同步写入始终带 `stage`，`durability_confirmed` 只在 `written` 为 true 时出现。无法确认时是 null，不伪造成 false。

生命周期和运行失败返回带 `Retry-After` 的 503；POST 重名冲突返回 409；写入期间磁盘上的源被改动时返回 `409 state_conflict`，这类请求没有前置条件。DELETE 的其他校验失败仍然映射成 503。已经耐久写入、但激活被拒绝时，报告 `written:true` 和 `committed:false`。

`--store db` 在激活之前不写入，被拒绝时报告 `written:false`。提交后 degraded 时报告 `committed:true`，并带上 `active_generation_id`；无法确认时为 null，不承诺回滚。源 PUT 仍然使用独立的磁盘 hash If-Match，旧编辑器在管理修改之后会收到冲突。

已放行的匿名 loopback 请求和 Bearer 认证请求读到同一份 geodata。geodata 的 GET 按既有的 router-before-config 锁序读取流量与 DNS 的保留元数据，不扫磁盘，也不联网。这里的 hash 和大小属于已加载的字节，不是之后在磁盘上做的外部编辑。

`GET /geodata` 返回 `{observed_at,assets}`。资产为 `{kind,sha256,size_bytes,modified_at,source_redacted}`：`kind` 为 `geosite` 或 `geoip`，`size_bytes` 是十进制字符串，`modified_at` 和 `source_redacted` 可空。存在已初始化的 geodata owner 时，每个资产还含 `fetched_url_redacted`、`verified` 和 `download_route`，响应也含下文的更新状态字段。

没有记录或前后不一致的修改时间为 null。`source_redacted` 保留了字段名，在 GET 和成功操作的结果里返回第一个下载 URL：去掉 userinfo、查询和片段，可能含凭据的路径段替换成 `[redacted]`，再遮蔽 listener secret。没有 URL 的资产，或无法安全显示的 URL，为 null。

没有用到的资产不会列出。已加载快照互相冲突时报告不可用，不会随便挑一个。

更新需要 `config_write`、源写入权限，且每个已加载资产都要有下载 URL：来自配置文件的 `assets.geodata.geosite`/`assets.geodata.geoip`，或在来源可配置时来自已存储或内置的 URL，见下节。URL 不作为请求参数。只接受最终直达的 HTTP(S) URL，拒绝 userinfo、片段、redirect 和 content encoding。

HTTPS 会验证证书。直连请求只用配置里那个数字地址的 `global.bootstrap_resolver` 解析域名，不回退到系统 DNS。`routing` 按路由规则匹配时，先用这个解析器查域名；没配置或查询失败时，再查 `/etc/hosts` 和系统域名服务器。

请求走下一节说的下载路由，默认是 `routing`。一次更新最多两个资产，各 256 MiB。每个 URL 对应的文件必须在请求发出后 30 秒内返回响应 header；正文每次停顿不得超过 30 秒，整个下载最长 10 分钟。

文件下载完成后，校验文件请求另有 10 秒 deadline，覆盖路由决策、域名解析、隧道和 TLS 在内的整个请求。校验、磁盘操作和必须完成的等待，都不构成硬性的总时限保证。

要等全部下载完成、解析并编译出完整候选之后，才会替换任何文件。新文件缺少当前配置用到的分类时，更新以 `asset_validation_failed` 失败，已加载的文件保持不变。已加载文件位于 `global.data_dir` 或 `$DAE_LOCATION_ASSET` 时，就地替换。

已加载文件来自优先级更低的位置时，例如软件包安装的 `/usr/share/honk`，honk 不会覆写它，而是改在 `global.data_dir/<file>` 新建文件；如果这期间该路径已经出现了文件，就拒绝替换。此后查找时会优先用新文件。文件通过不跟随符号链接的父目录 FD 和文件 FD 打开；别名、字节、来源或依赖冲突，以及不安全的路径，都拒绝。

父目录分量只在安全打开之后才做身份规范化。各文件独立原子替换，并确认耐久，这不是跨多个文件的原子事务。第一个 rename 之后失败时，会保留逐资产的 written 和 durability 信息，不会自动撤回。

真实 reload 在 no-op 和重建两条路径上都使用不可变的、已验证的 geo 快照，之后磁盘上的改动替换不了激活的字节。成功结果来自实际发布的 GeoData。被拒绝或降级时仍然失败，并报告提交信息。

重试之前，先修掉磁盘上的冲突。缓存订阅仍然参与 admission 的依赖检查，但它的指纹
标签指向数据库行，不是文件路径。geodata 更新会在 rename 之前做最后一次重新捕获，
检查正文有没有变；只有真实的文件依赖才会取得 inode guard。

`POST /geodata/update` 不带正文。同 key 的幂等重放先于互斥检查；不同的在途请求返回 409；操作容量满返回 503。`202` 只代表守护进程接手了，不代表文件或路由已经变了。

下载内容和已加载文件相同的资产不会写入。所有资产都相同时，更新直接成功：不激活，不产生 generation 事件，也不改 `runtime.last_reload`。更新一旦进入激活阶段，之后就会写 `runtime.last_reload`。

激活之前失败时，这个字段不变。

### Geodata 来源与自动更新

有状态数据库、且 geodata owner 已初始化时，`resources.geodata.configurable_sources` 为 true，`runtime_settings.fields` 里会列出 `geodata`。capability 还会报告 `max_urls: 4`、`interval_hours: {min: 6, max: 168, default: 24}` 和 `lifecycle: {file_values: start, overrides_persist: true}`。cron 计划下，`interval_hours` 读出来就是这个默认值。`lifecycle` 说明配置文件的值只在启动时读取，而 API 覆盖在重启后仍然保留。不管有没有状态数据库，`checksum` 都是 `sha256sum`。启用原生 API 时，honk 总会尝试打开 `<data_dir>/state/honk.db`。

数据库模式、启用了 `password_auth`、数据库里是外来的 application ID 或更新的 schema、或者数据库被另一个 honk 实例占用时，打开失败会中止启动。其他打开失败时，honk 可能以无持久化的模式继续运行。打开成功时，设置会存在其中一张严格表 `geodata_settings` 里，重启和激活之后都保留。

如果这张表打不开，listener 仍会启动，记一条 warning，不宣告 geodata capability。没有状态数据库或 geodata owner 时，只用配置文件里的 URL，下面这些字段都不会出现。

这种情况下，`GET /runtime/settings` 里会含 `geodata`：`source`、`geosite.urls`、`geoip.urls`、`auto_update`（`enabled`、`interval_hours`、`cron`）、`download`（`route`、`group_id`）和 `verify_checksum`。只有已存储的设置生效。启动时，honk 会把 `assets.geodata` 里设置的下载 URL、出口、`auto_update`、`cron` 或 `checksum` 写进已存储的设置，覆盖通过 API 改过的值。

如果配置文件没有给某个资产设置 URL，那之前由配置文件写入的列表会被删掉，改用内置 URL；通过 API 改过的列表则保留。更新计划和 `verify_checksum` 同理：配置文件不再设置时，之前由配置文件写入的值会被删掉，恢复默认值；API 改过的值保留。配置文件里的下载 URL、出口、更新计划和校验开关，都由启动阶段持有。

reload 如果改变这些生效值，会因为需要重启而被拒绝；所以其他激活不会动已存储的设置，通过 API 改过的 URL 会保留到下次启动。

| `source` | 含义 |
| --- | --- |
| `config` | 已存储的列表全部来自配置文件。 |
| `override` | 至少一个已存储列表来自 API URL 修改。 |
| `default` | 没有已存储列表。使用内置 MetaCubeX `meta-rules-dat` 发布文件，先尝试 raw.githubusercontent.com，再尝试 fastly.jsdelivr.net。 |

`download.route` 决定每个 geodata 请求的出口，校验文件请求也算。`routing` 是默认值，和用户流量一样遵循路由规则。`group` 始终走 `group_id` 指定的那个组，这个 ID 就是 `GET /groups` 返回的 ID。

`direct` 用引导解析器解析主机，并以 bypass mark 直连。走规则或组的请求，和外部 UI 下载共用路由决策和隧道。路由不可用时，这个 URL 会按连接错误失败：

| `last_error.code` | 条件 |
| --- | --- |
| `group_unavailable` | 组不存在或没有可选成员 |
| `route_blocked` | 路由规则选择 `block` |
| `connection_failed` | 隧道无法建立 |

之后 honk 会改试下一个 URL，不会退回直连。启动后不久，如果路由或规则选中的组还没有可达节点，更新也按连接错误处理。经节点下载时，域名由节点出口解析。

启动时，`assets.geodata.route` 优先于 `assets.route`，生效的出口会写进已存储的设置，覆盖 API 改过的值。配置文件没有设置出口时，保留通过 API 改过的出口；否则遵循路由规则，并删掉之前由配置文件写入的出口。

出口不影响 `source`。见 [Assets 参考](./assets.md)。

`PATCH /runtime/settings` 会合并并存储 `geodata`，不触发下载。`urls` 列表含 1–4 个互不相同的 HTTP(S) URL，每个最长 4096 字节，不含 userinfo 或片段，按回退顺序整体替换原列表。修改一个资产时只存这个资产的列表，`source` 不管原来是什么都会变成 `override`，另一个资产仍然取配置文件或内置 URL。

`auto_update` 单独存储。带 `interval_hours`（6–168）就切换成间隔计划，带 `cron` 就切换成 cron 计划；同一个请求里两个都带返回 400，只带 `enabled` 时保留当前计划。cron 计划读出来是 `interval_hours: 24`，`cron` 为表达式；间隔计划的 `cron` 是 null。`assets.geodata.auto_update` 和 `cron` 会在启动时写进这里，见 [Assets 参考](./assets.md)。`download` 也单独存储。`group` 路由必须带 `group_id`，其他路由不能带。

以下 `PATCH /runtime/settings` 请求体分别只替换 geosite URL 列表，以及启用经组下载的 cron 计划：

```json
{"geodata":{"geosite":{"urls":["https://example.net/geosite.dat"]}}}
```

```json
{"geodata":{"auto_update":{"enabled":true,"cron":"0 3 * * *"},"download":{"route":"group","group_id":"<id-from-GET-groups>"}}}
```

cron 语法和日历解析不依赖时区。geodata owner 启动和 PATCH 还会拒绝一种显式 cron：在实际本地时区里没有未来的触发时间，即使 `enabled: false` 也拒绝。已保留的计划要到启用时才做这个检查：不可用的计划仍然可以通过 PATCH 禁用或修好，有效的文件覆盖值也能在启动时修好旧的已存储计划。不可用的计划不会被换成默认值。

ID 不对应当前任何组时返回 `409 state_conflict`。已存储的组被后续激活删掉后，`group_id` 读出来是 null，下载以 `group_unavailable` 失败，直到改动路由为止。`verify_checksum` 单独存储，`assets.geodata.checksum` 在启动时写进它。

`"geodata": null` 删除已存储的设置。配置文件里的值会在下次启动时重新写入。顶层 `source` 不受影响。

`geodata` 和其他字段在同一个请求里一起校验，任何一部分校验失败，全部都不改。匿名
loopback 主体不能修改 `geodata`，会收到 `403 permission_denied`。所有已放行的调
用方都能读到原始 URL，只有 listener secret 被遮蔽。如果 geodata 已经存下，而关闭
过程让记录器设置无法生效，PATCH 返回 `503 temporarily_unavailable`，并带
`details.geodata_stored: true`；已存储的 geodata 不会回滚。

更新会按顺序尝试资产的各个 URL；遇到连接错误、非 200 状态、超时或校验失败，就改试下一个。校验文件的 URL 是在原 URL 路径末尾加上 `.sha256sum`，查询部分保留。返回 200 时，它的第一个字段必须等于文件的 SHA-256。

返回 404 视为没有发布校验文件，文件按未校验处理。其他状态或失败，都会让这个 URL 失败。某个资产的所有 URL 都失败时，失败详情描述最后尝试的那个 URL，给出 `stage` 和失败的资产 `asset`（`geosite` 或 `geoip`）。

如果这个 URL 是因为服务器响应而失败，还会给出该响应的 `http_status`，也就是文件返回非 200，或校验文件返回非 200 且非 404 的那个状态。`asset: geoip, stage: checksum_unavailable, http_status: 403` 表示服务器拒绝的是 `.sha256sum`，不是文件本身。配置文件、已存储和内置的 geodata URL，包括校验文件请求，都不设地址或端口白名单。

`verify_checksum` 默认是 `true`。设成 `false` 后，手动和自动更新都不再请求 `.sha256sum`，下载的文件一律按未校验处理：`verified` 为 `false`，`sha256` 照常报告。这个设置用于那些缺少校验文件时会返回非 404 状态、或返回非校验内容页面的镜像站。

以 `checksum_unavailable` 或 `checksum_mismatch` 失败时，日志里的 warning 会指出这个设置。校验不会被自动关掉。

geodata owner 存在时，`GET /geodata` 还会报告下面这些字段：

| 范围 | 字段 | 含义 |
| --- | --- | --- |
| 每个资产 | `fetched_url_redacted` | 已加载文件的下载 URL，显示方式与 `source_redacted` 相同 |
| 每个资产 | `verified` | 下载是否经过校验 |
| 每个资产 | `download_route.route` | 该次下载使用的路由设置 |
| 每个资产 | `download_route.group_id` | 请求经过的组，包括规则选中的组；否则为 null |
| 顶层 | `last_checked_at`、`last_updated_at`、`next_check_at`、`last_error` | 更新状态与计划 |
| 顶层 | `required_codes` | 当前配置为每个已加载资产引用的分类，按顺序排列 |

`last_error.code` 表示失败阶段，例如 `http_status_rejected`、`checksum_mismatch` 或 `asset_validation_failed`。

`last_checked_at`、`last_updated_at`、`last_error` 和连续失败次数都存在状态数据库的严格表 `geodata_status` 里。每次启动会根据这些状态重新计算 `next_check_at`，并重新抽一次随机延迟；这个字段本身不存储。

每个资产的字段只存在内存里。重启后、下一次尝试之前，这些字段为 null，`verified` 为 false。

自动更新默认开启，每天本地时间 03:00（`0 3 * * *`）。把 `auto_update.enabled` 设成 `false` 就关掉了。cron 计划在上次记录的检查之后、表达式按系统本地时区给出的第一个时间执行；间隔计划则在上次检查之后过了一个间隔时执行，这种计划可能由 API 设置，也可能是沿用 cron 计划出现之前存下的记录。启动后从上次记录的检查时间继续计时。

不存在的本地时间会跳过；重复的时间只在第一次出现时触发。如果之后的时区变化让计划变得不可用，honk 在进入该状态时发一条 warning，不再安排未来的计划下载。失败退避仍然单独生效，所以 `next_check_at` 仍可能表示重试时间。`last_error` 继续描述最后一次实际的更新尝试。

满足以下任一条件时，第一次检查在启动后五分钟再加随机延迟执行：

- 上次检查距今已超过等待时间，或此后已经错过了 cron 表达式给出的时间。
- 上次检查时间晚于当前时间，也就是时钟曾经超前。
- 没有上次检查记录。

所以重启不会立刻触发下载；重启间隔比更新计划还短的主机，也仍会更新。`POST /geodata/update` 可以立即更新。

自动更新使用同一个 `geodata_update` 操作。自动更新执行期间，手动更新返回 `409 state_conflict`。

自动更新到期时如果已经有更新在执行，下次时间由那次更新的结果决定。每次计划检查都加 0–60 分钟的随机延迟。连续失败后先等 1 小时，之后每次失败加倍，但不会晚于下一次计划检查；失败次数在重启后保留。

成功后恢复正常计划。

### 内嵌 doona 来源

默认关闭的 `native-ui` 隐含启用 `native-api`。构建时内嵌以下两个版本：

| 版本 | 资产绝对目录 |
| --- | --- |
| 标准版 doona | `HONK_DOONA_DIR` |
| doona lite | `${HONK_DOONA_DIR}-lite`，忽略 `HONK_DOONA_DIR` 的末尾斜杠 |

两个目录都必须含 `index.html`。只需设置 `HONK_DOONA_DIR` 这一个环境变量。

| `.github/ci/pins.env` 中的固定项 | 值 |
| --- | --- |
| doona 版本 | `0.1.0-rc.5` |
| 提交 | `6102778700c6cd15908cf2a76be7121d0355da21` |
| 压缩包校验和 | `DOONA_SHA256`、`DOONA_LITE_SHA256` |

在仓库根目录执行 `export HONK_DOONA_DIR=$(ci/fetch-doona.sh)`。脚本依次执行：

1. 从固定发布版本下载两种程序包。
2. 分别核对压缩包的校验和。
3. 检查各包中的 `THIRD-PARTY-NOTICES.txt` 及其 `NOTICE` 引用的全部 `LICENSES/` 文件。
4. 删除字体，将标准版解压到指定目录，将 lite 解压到其 `-lite` 同级目录。
5. 只输出标准版目录。

未设置该变量时，`just lint` 与 `just test-ci` 自动执行脚本。

完整发布产物包含内嵌 UI，精简的 `-clash-api` 和 `-native-api` 产物不包含。二进制里内嵌两个版本各自的声明；每个完整发布压缩包也会在 `doona/` 和 `doona-lite/` 目录里附带这些文件。lite 版使用系统字体。

内嵌产物不含 Noto Sans TC 和 SC 字体。doona 的 CSS 用 `font-display: optional` 声明这些字体，所以字体请求返回 404 时，浏览器会用系统字体。

需要 Noto Sans 时，可以从下面两种方式里选一种：

- 从 [doona 发布页](https://github.com/Zakkaus/doona/releases)下载 `doona-<version>.tar.gz` 与 `doona-fonts-<version>.tar.gz`，解压到同一目录，并让 `ui` 指向该目录。
- 安装 `doona` 与 `doona-fonts` 软件包，并设置 `ui: /usr/share/doona`。

两个版本共用的 GPL-3.0-only 源码，是 doona 标签 [`v0.1.0-rc.5`](https://github.com/Zakkaus/doona/tree/v0.1.0-rc.5)。发布流程会把 `doona-source-0.1.0-rc.5.tar.gz` 附加到正式标签发布和滚动 Debug 发布上。这个包由 `ci/fetch-doona.sh --source` 生成：先确认标签仍指向固定的提交，再执行 `git archive --format=tar --prefix=doona/ v0.1.0-rc.5 | gzip -n`，用 GNU gzip。

再分发 `native-ui` 二进制时，要保留声明，并按 GPL-3.0 第 6 条允许的方式提供对应的源码。

复现时，把源码包解压到独立目录，用符合 `^22.13.0 || ^24.0.0 || >=26.0.0` 的 Node 和 `pnpm@11.15.1`。在解压后的源码目录里依次执行：

1. `pnpm install --frozen-lockfile`。
2. `pnpm build`。
3. `pnpm -C apps/lite build`。
4. `SOURCE_DATE_EPOCH=1793194168 pnpm package`。

这个时间戳是固定上游提交的时间。源码包里没有 Git 历史。需要安装 brotli，`PATH` 里必须是 GNU tar 和 GNU gzip；已验证的是 tar 1.35 和 gzip 1.15。

换成别的 gzip 实现，即使压缩的是同样的 tar 字节，也可能得到不同的包摘要。Cargo 构建只内嵌 `HONK_DOONA_DIR` 和它 `-lite` 同级目录里的文件，既不构建也不下载前端。这份源码的检查器是 `tools/conformance.mjs`。

实时 walk 是只读的，会跳过控制、诊断和缺少已观测 ID 的资源。基础契约和管理契约要分别核对，浏览器操作另外验收。模式检查通过，不等于完整的 UI、内核或部署矩阵都通过了。

### 连接关闭、模式与数据面生命周期

单项 DELETE 的 `204` 表示已经确认对应的 owner 完成关闭，而不只是删掉了连接追踪记录：

| owner | 完成条件 |
| --- | --- |
| 精确 TCP UUID | 转发任务结束 |
| 精确 UDP token/generation/source view | 完成退役、后端确认，以及已通过 admission 的发送和回复的排空 |

共享 XUDP 只关闭当前视图，不关闭其他视图共用的 carrier，也不重放报文。

同一个 owner 还在连接追踪记录里时，并发或重复的关闭会共用同一个真实完成信号，也就是 `Pending`，并继承成功或 `Failed` 的结果。处于 `Closing` 或 `Failed` 状态的 owner 不会被报告成 `Gone` 或 404。ID 不存在，或捕获的 owner 已被别的 incarnation 替换时，仍然返回 `Gone` 或 404；不可关闭的非用户态 owner 返回 409；无法确认退役返回 503。

批量关闭只捕获一次匹配集合，支持 `type=tcp|udp|all` 和不带端口的 `src`。既没限制网络也没限制来源时，必须带 `all=true`；只写 `type=all` 不算过滤。匹配超过 1000 条时先返回 413，一条连接都不关。

成功时返回实际的 `closed/skipped`。关闭选定集合之后新出现的连接不受影响。批量关闭里只要有一项退役无法确认，就等所有选定的连接处理完，再返回 503，`error.details` 带上 `closed/skipped` 计数；这些连接不会回滚。

DELETE 请求体必须为空。重复 `Idempotency-Key` 仍检查当前连接状态，不重放旧结果。

原生 `x-honk` 扩展里的 `runtime_mode` 暂时不可用：它固定的 PUT 契约没有声明生命周期冲突，也没声明 owner 或后端不可用时该返回什么错误；capability 也不区分读写。GET、HEAD、PUT 都返回 `404 capability_not_supported`，不宣告接受任何 mode。内部共用的 `DatapathFlagsHandle` 和 Clash 控制仍然保留。

它不是 `dial_mode`，不覆盖 must/block 的终态，也不合成网关规则。只有在原生 API 未启用时，才会缓存模式。原生 API 启用后，两种 API 共用同一套临时模式契约：不恢复，也不写模式缓存；启动和成功的显式配置激活（包括 no-op）会把它重置成 `Rule`，provider 刷新和网络刷新则保留。

Global 绑定的是稳定身份：目标消失后，新流量按 fail-closed 处理，也就是拒绝转发，不会退回普通路由，也不会改投同名的替代者。原生 API 未启用时，保留原来的 Clash 缓存行为。

显式配置激活时，配置提交和模式重置是两个独立的结果。路由和配置已经提交、但后端写入模式失败时，记录器设置已经恢复成配置值，模式及其来源还保留着之前的值。控制面关闭 admission，报告 `committed-degraded`，操作失败。

此时既不能声称 Rule 已生效，也不能声称配置回滚。实际状态通过 Clash `/configs` 和操作结果检查；`/configs` 只在启用 Clash API 时可用。

正常的 no-op 接受也会触发重置，provider 与网络更新则不触发。

`GET /datapath` 和运行时里的数据面摘要都使用后端的程序、挂接、路由和 admission 观测，不按配置的接口去猜。Mock 报告 `disabled` 和 `none`。真实观测是 `partial`，没有验证过的事实保留未知值或 `null`，路由 generation 的身份独立于运行时 generation。已知映射容量不代表知道占用量。hook 只是挂上了，不代表 admission 已经开启，也不声明 `full_transparency`。

`GET /datapath` 返回 `{observed_at,kind,state,visibility,ebpf,errors}`。`kind` 不是 `ebpf` 时 `ebpf` 为 `null`。`detail=full` 增加 `ebpf.attachments` 与 `ebpf.maps`，默认的 `summary` 省略二者。

| 字段 | 取值 |
| --- | --- |
| `kind` | `ebpf`、`mock`、`unknown` |
| `state` | `active`、`degraded`、`detached`、`disabled`、`unknown` |
| `visibility` | `ebpf` 为 `partial`，其他为 `none` |
| `ebpf` | `backend: "real"`、`programs`、`hooks`、`routing`、`health`、可空的 `last_error`、`checked_at` |
| `ebpf.programs` | `loaded`、`not_loaded`、`error`、`unknown` |
| `ebpf.hooks` | `attached`、`detached`、`partially_attached`、`unknown` |
| `ebpf.routing` | `state`（`published`、`not_published`、`error`、`unknown`）、形如 `<instance>:datapath:<n>` 的可空 `generation_id`、为 `null` 的 `epoch` |
| `ebpf.health` | `healthy`、`degraded`、`unknown` |
| `ebpf.attachments[]` | `name`、`kind: "interface"`、`interface`、`direction`（`ingress` 或 `egress`）、`state`（`attached`、`detached`、`error`、`unknown`） |
| `ebpf.maps` | `state`（`partial`、`error`、`unknown`）与 `conn_state`：`null` 或 `{occupancy,capacity,occupancy_known}` |

`errors[]` 为 `{code,message}`，`code` 取 `program_observation_failed`、`hook_observation_incomplete`、`routing_observation_failed`、`admission_observation_failed`、`map_observation_failed` 或 `observation_limit_reached`。

关闭时间没有硬上限。abort async 的外层不会取消已经开始执行的 blocking 工作。StateTick 维护的 owner 超过名义停止期限后，honk 会记一条 warning，然后继续等真实的 SQLite 工作结束。

凭据的 KDF 和数据库工作、以及已经开始的系统解析和 NSS，同样会等到真实结束。可选的[业务连接宽限等待](./global.md#关闭)不允许在清理阶段超期时丢掉 owner，来声称关闭成功。

原生 HTTP 自己另有五秒的 graceful drain；上面这些阻塞等待结束之前，总退出时间还可能被拉长。见[终止所有权](../design/control-plane.md#终止所有权)。

## 启用与认证

只有 `experimental.clash_api.external_controller` 非空，且二进制包含默认启用的 `clash-api` feature 时，API 服务才会启动。控制器地址必须是 `127.0.0.1:9090` 或 `[::1]:9090` 这样的数字 socket 地址，不能写 DNS 主机名。写成 `:port` 会绑定到 `0.0.0.0:port`。

无效地址只会写入日志，不会停止引擎。

当 `experimental.clash_api.secret` 非空时，API 请求必须携带：

```http
Authorization: Bearer <secret>
```

WebSocket 升级也可以改用 `?token=<percent-encoded-secret>`。honk 会先对 token 做百分号解码，再精确比较。查询参数里的 token 认证只适用于 WebSocket 升级；普通 HTTP 请求要用 Bearer header。

header 必须精确是 `Bearer ` 加凭据，大小写一致，中间只有一个空格。WebSocket 升级带了非空 `token` 时只检查 `token`，不检查 header，所以 `token` 写错时，即使 header 是对的也会失败。失败返回 `401 {"message":"Unauthorized"}`。

`secret` 为空时关闭认证。`/ui` 静态目录不经过 API 认证层。

API 自身不提供 TLS。请把它绑定到 localhost，或在前面放一个 TLS 反向代理；如果有不可信的客户端能访问 listener，必须设置足够强的 `secret`。

Clash listener 允许任意 CORS 来源，没有原生 API 那样的 Host 和 Origin 检查。

随附的 `config.dae` 绑定的是 `127.0.0.1:9090`。如果控制器地址不是 loopback、`secret` 又为空，启动会发一条 warning，但仍然允许监听；这时不管有没有配防火墙，通配地址和已分配的接口地址都适用。

## endpoint 表

下表与 `crates/honk-core/src/clash_api.rs` 中的 router 一致。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/` | 返回 Clash hello 文档；启用外部 UI 托管时，将非 JSON 客户端重定向到 `/ui/`。 |
| GET | `/version` | 返回 `honk <build-version>`（包含发布标签，与 CLI 共用构建版本）及 Clash premium/meta capability 标志。 |
| GET | `/configs` | 返回当前模式、已实现的 Clash 兼容配置快照，以及 `honk-diagnostics` 下当前配置的安全诊断。 |
| PUT | `/configs` | 兼容性 no-op；接受请求并返回 `204 No Content`。 |
| PATCH | `/configs` | 将 `mode` 设为 `Rule`、`Global` 或 `Direct`；匹配不区分大小写。 |
| GET | `/proxies` | 返回所有节点和组，以及合成的 `GLOBAL` Selector。 |
| GET | `/proxies/{name}` | 返回一个节点、组或 `GLOBAL` Selector。 |
| PUT | `/proxies/{name}` | 用 `{"name":"member"}` 选择 Selector 组的直接成员；也可修改合成的 `GLOBAL` Selector。包括 Score 在内的自动组会拒绝写入。 |
| GET | `/proxies/{name}/delay` | 使用调用方的 `?url=`，对节点或组执行按需代理延迟测试。已预热的传输会复用；每个尚未预热的可复用 session 或 QUIC 客户端都会先在临时运行时中预热，再开始计时。 |
| GET | `/group/{name}/delay` | 使用调用方的 `?url=` 测试全部组成员，最多并发 `URLTEST_MAX_CONCURRENT`（10）次代理拨号，并以相同计时语义返回成功成员的延迟。 |
| GET | `/rules` | 每条路由返回一行。简单 matcher 使用原生 Clash rule type；组合、取反和 `must` 规则使用 `complex`，并保留完整 dae 语句。 |
| GET | `/connections` | 返回连接快照；WebSocket 升级后改为推送快照。 |
| DELETE | `/connections` | 关闭所有已追踪连接。 |
| DELETE | `/connections/{id}` | 关闭一个已追踪连接。 |
| GET | `/traffic` | 通过 WebSocket 或分块 JSON 行推送每秒流量。 |
| GET | `/memory` | 通过 WebSocket 或分块 JSON 行推送进程 RSS。 |
| GET | `/stats` | 返回下文所述的用户态出站、ready 池、热资源、Score 选路原因和 UDP 快照。 |
| GET | `/logs` | 通过 WebSocket 或分块 JSON 行推送 tracing 事件；所有订阅者共用一个 256 槽位的广播队列，`?level=` 默认为 `info`。 |
| GET | `/dns/query` | 经 honk DNS 解析 `?name=` 并返回 DoH 风格 JSON；`?type=` 默认为 `A`。 |
| POST | `/cache/fakeip/flush` | 兼容性 no-op，返回 204；没有持久化 FakeIP 映射可清除。 |
| POST | `/cache/dns/flush` | 清除存活 DNS 缓存及其持久化 DNS 状态。 |
| GET | `/providers/proxies` | 将非空组暴露为 Clash proxy provider。 |
| GET | `/providers/rules` | 返回当前空桩文档 `{"providers":[]}`。 |
| GET | `/ui`, `/ui/*` | 将 `/ui` 重定向到 `/ui/`，并提供已配置的外部 UI 目录。 |

普通 HTTP GET 下，`/traffic`、`/memory` 和 `/logs` 每行发一个 JSON 文档。`/logs` 只在有订阅者时才开启动态的 `tracing` 事件过滤；没有订阅者时，Clash 日志层不格式化事件。每个订阅者的级别过滤发生在共享队列之后。

订阅者落后时会跳过被覆盖的事件，且不会收到事件丢失标记。

`GET /` 返回 `{"hello":"clash"}`；启用外部 UI 且 `Accept` 不含 `application/json` 时，返回指向 `/ui/` 的 302。`/ui` 以 301 重定向。`GET /version` 返回：

```json
{"version":"honk <build-version>","premium":true,"meta":true}
```

`GET /configs` 还返回固定的兼容字段，它们不配置任何功能：`mode-list: ["Rule","Global","Direct"]`、值为 0 的 `port`、`socks-port` 与 `mixed-port`、为 `false` 的 `allow-lan` 与 `ipv6`、`bind-address: "*"`、配置的 `log-level`，以及 `tun: {"enable":false}`。

`GET /proxies` 返回 `{"proxies":{"<name>":<document>}}`；`GET /proxies/{name}` 返回单个文档。节点文档含 `name`、`type`、`udp: true` 与 `history`。组文档含 `name`、`type`、成员名列表 `all`、TCP 选择 `now` 与 `history`；Score 另含 `scoreVerification`。`GLOBAL` 含 `type: "selector"`、`all` 与 `now`，没有 `history`。

节点 `type` 为 `Shadowsocks`、`Trojan`、`Vmess`、`Vless`、`Socks5`、`Hysteria2`、`Tuic`、`Juicity`、`AnyTLS`、`Direct` 或 `Reject`，其中 `Reject` 对应 `block`。组 `type` 为 `selector`、`url_test`、`load_balance` 或 `fallback`；Score 报告为 `url_test`。`history` 条目为 `{time,delay}`，取最近一次真实 TCP IPv4 测量。

`GET /rules` 返回 `{"rules":[{"type","payload","proxy"}]}`，由配置的路由规则生成，不含原生规则 ID，也没有 fallback 行。

`GET /connections` 返回 `{downloadTotal,uploadTotal,connections,memory}`。两个总量是当前各行之和，`memory` 是进程 RSS 字节数。每行为 `{id,metadata,upload,download,start,chains,rule,rulePayload}`。`metadata` 含 `network`、`type`、字符串形式的 `sourceIP`、`destinationIP`、`sourcePort` 与 `destinationPort`、`host`、`dnsMode: "normal"`、`process` 与 `processPath`；未知值为 `""`。

WebSocket 连接上，`?interval=` 设置推送间隔，单位毫秒，默认 1000。它会向上取整到 100、200、500、1000、2000、5000、10000、30000 或 60000，最大 60000。

`DELETE /connections/{id}` 在连接已关闭或 ID 未知时返回 204，无法关闭时返回 409，关闭失败时返回 503。`DELETE /connections` 返回 204，任一关闭失败时返回 503。两者都没有响应体。

`/traffic` 帧为 `{"up":<bytes>,"down":<bytes>}`，即上一帧以来的字节数。`/memory` 帧为 `{"inuse":<rss-bytes>,"oslimit":0}`；无法读取 RSS 时 `inuse` 为 0。

`/logs?level=` 接受 `trace`、`debug`、`info`、`warn`、`warning` 或 `error`，不区分大小写；其他值返回 `400 {"message":"invalid log level"}`。帧为 `{"type":"<level>","payload":"<text>"}`。

`GET /dns/query` 接受 `name` 和 `type`。`type` 可以是 `A`、`NS`、`CNAME`、`SOA`、`PTR`、`MX`、`TXT`、`AAAA`、`SRV`、`SVCB`、`HTTPS`、`CAA` 这些名称，不区分大小写，也可以是数字。缺少名称或类型无效时返回 400。响应是数字类型的 DoH JSON：

```json
{"Status":0,"Question":[{"name":"example.com","type":1}],"Answer":[{"name":"example.com.","type":1,"TTL":60,"data":"192.0.2.1"}]}
```

解析失败时仍返回 200，`Status` 为 2，`Answer` 为空。

`GET /providers/proxies` 返回 `{"providers":{"<group>":{"name","type":"Proxy","vehicleType":"Compatible","updatedAt":null,"proxies":[...]}}}`，每个代理为节点文档。

### `/configs` 中的诊断信息

`GET /configs` 保留现有的 Clash 字段，另外新增 `honk-diagnostics`。配置项和诊断信息来自同一份已提交的配置快照。启动时只发布通过 admission 的文件诊断和订阅诊断。reload 失败或订阅刷新被拒绝时，当前诊断列表保持不变；接口不缓存最近一次失败的尝试。

有效配置没变的成功 reload，可以替换诊断信息而不递增 `generation`。订阅刷新通过授权和 admission 检查之后，只替换这个订阅的诊断，即使节点没变也一样；静态文件和其他订阅的诊断保持不变。

库调用方要传给 `ControlPlane::reload_runtime_config(config, diagnostics)` 一个 `DiagnosticBuckets`，分别保存静态配置和订阅正文的诊断。程序里构造、没有诊断的输入用 `DiagnosticBuckets::default()`。`merge_subscription_nodes(provider, nodes, diagnostics)` 接收这个订阅的诊断向量，也支持已通过 admission 但没有 worker 声明的订阅。

完整配置替换会移入候选配置的全部诊断来源信息；订阅替换只影响对应的订阅。SIGHUP 只保留重建候选配置时实际沿用的那些订阅正文的诊断。自动生成的拓扑和 ECS 更新保留原输入的来源。

所有修改都沿用配置写锁的发布屏障：先拿配置锁，再拿诊断锁。

完整替换的载荷里，provider bucket 必须用唯一的 UUID。出现重复 UUID 时，整个 reload 会在发布前被拒绝，即使有效配置没变也一样；当前配置和诊断都保持不变。

| 字段 | 含义 |
| --- | --- |
| `honk-diagnostics.generation` | 当前配置的 `generation`；启动时为 `0`。 |
| `honk-diagnostics.sources` | 保留的诊断所引用的来源及这些来源的祖先，仅包含元数据。 |
| `sources[].id` | 本次快照内的不透明数字来源标识，供 `diagnostics[].source` 引用。 |
| `sources[].ordinal` | 来源在单次解析尝试的来源表中的原始序号，从 `0` 开始。 |
| `sources[].parent` | 父来源的 `id`；根来源为 `null`。 |
| `honk-diagnostics.diagnostics` | 当前配置和已通过 admission 的订阅保留的安全诊断。 |
| `diagnostics[].code` | 稳定的诊断代码。 |
| `diagnostics[].severity` | 小写严重级别：`info`、`warning` 或 `error`。 |
| `diagnostics[].source` | 对应的 `sources[].id`。 |
| `diagnostics[].span` | 从 `0` 开始的字节范围 `{start, end}`，不含 `end`；未知时为 `null`。 |
| `diagnostics[].line` | 原始文本中的行号；未知时为 `null`。 |
| `diagnostics[].byte_column` | 按字节计数的列号；未知时为 `null`。 |
| `diagnostics[].setting` | 含原始条目序号的固定配置字段路径，不含用户提供的名称。 |
| `diagnostics[].value` | 安全值表示；私有值经过遮蔽。 |
| `diagnostics[].message` | 静态诊断消息。 |
| `diagnostics[].entry_index` | 原始条目序号；未知时为 `null`。 |
| `diagnostics[].related_indices` | 相关原始条目的序号。 |
| `diagnostics[].terminal` | 该诊断是否表示本次尝试的终止错误。 |

配置的 `generation` 与当前 DNS 运行时一致。来源标识只在本次快照内有效，不是文件
系统标识。来源的排列顺序是：先静态文件，再按配置里的订阅声明顺序，最后按保留
bucket 的顺序列出已通过 admission 的非 worker 订阅；各来源表内部保留原始顺序。只
列出诊断引用到的来源及其祖先，不导出文件路径、原始输入、凭据、订阅名称或订阅 ID。

### 延迟测量

两个接口使用上表所列的 URL 参数与并发上限。

两个延迟接口都接受以毫秒计的 `timeout`；省略或为 0 时为 15000。示例：`GET /proxies/edge/delay?url=https%3A%2F%2Fexample.com%2Fgenerate_204&timeout=5000`。

延迟测试用规范的 HTTP 检查目标解码器。HEAD 保留原始路径和查询串，点段和只有查询串的 `/?query` 也算在内；authority 会去掉凭据和默认端口；片段不会发送。它和周期健康检查共用 HTTP 实现，报告第二轮请求的热路径 RTT，不含代理拨号、目标 TLS 和第一轮请求。HTTPS 会验证证书，协商 HTTP/2 或 HTTP/1.1，并禁用服务器 push。

两轮最终响应的解码状态都必须是有效的 200–499。第二轮传输失败或超时时，可以退回已经验证过的第一轮样本。HTTP/1 的部分响应即使超时也不回退；正常的 HTTP/2 GOAWAY 则可以回退。

每轮 HTTP/1 的临时响应 header 和最终响应 header 累计上限是 16 KiB，HTTP/2 的响应 header 列表上限也是 16 KiB。session 预热、拨号、目标 TLS、HTTP/2 启动和每轮请求各自使用阶段预算。针对冷的可复用 generation 的探测，使用带 guard 的临时运行时，结束后关闭。

HTTP/2 驱动任务在完成或取消后释放，因此组扫描不会为每个已测试节点留下新的常驻可复用运行时。

测量成功会更新节点的延迟历史。单节点失败返回 `503`；组测量会省略失败的成员；任意手动测试目标的失败，都不会增加真实拨号失败的连续计数。

`/proxies/{name}/delay` 返回 `{"delay":12}`；`/group/{name}/delay` 返回 `{"<member>":12,...}`。延迟以毫秒计，上限 65535。对 URLTest 组，两个接口都可能根据新测量切换其选择。

按需的 delay exchange 会保留 Alive/API 的延迟历史，但不报告业务结果，也不填充配置里 Score 的比较 cohort。实际的 server 或 session 前置准备可以报告聚合的预热建立情况；honk 不会把调用方的 URL 虚构为预热自身的目标，也不提供晋升证明。

两个延迟接口都会一直持有已接纳的任务，直到测量清理结束，即使 HTTP 客户端已经断开。owner 接纳失败时返回 `503`，这个响应会区分容量耗尽、检查已停止和 worker 失败。

QUIC 探测超时，或等待正常关闭，都属于测量结果，不代表健康检查 owner 失败。有限的对端通知宽限期结束之后，先停止并等 Quinn 驱动任务结束，再停止并等 packet-adapter worker 结束。

真正的受管 worker 失败，仍然会关闭健康检查的接纳。

### Score 代理组表示

配置成 `policy: score` 的组始终可用，为了兼容 Clash 表示成 `type: "url_test"`。它的 `all` 列表和其他组一样保留直接成员标签；`now` 报告当前聚合的 TCP 胜者，不会暴露某个精确目标的私有选择。Score 始终是自动的，`PUT /proxies/{name}` 会被拒绝，无法固定成员。

评分 cell 和只由 scorer 持有的目标数据不会加进 proxy 文档。`/stats.score` 只包含下文那些安全的聚合计数。`/connections` 只保留原有的目标元数据。

## 模式与 Selector 修改

`PATCH /configs` 不看 `Content-Type`，直接按 JSON 解析请求体，只处理字符串 `mode`。没有该字段时返回 204，不做修改。JSON 无效或模式未知时返回 400，模式切换失败时返回 500 或 503。例如：

```json
{"mode":"Global"}
```

模式更新走 `DatapathFlagsHandle`。它是 shared mode 和 `DATAPATH_FLAGS_MAP` 唯一的串行化 writer，所以模式修改会和 reload 的 NFQUEUE fence、reopen、disable 操作原子地组合，不会重新发布过期的就绪状态 bit。

由规则派生的 feature bit 属于不可变的路由 policy descriptor。原生 API 未启用时，启用缓存数据库会保存规范化的模式。原生 API 启用后，两种 API 共用一种临时模式：不恢复，不持久化，并在显式配置激活之后重置成 Rule。

`PUT /proxies/{name}` 不要求特定的 `Content-Type`。对已配置的 Selector，目标必须是直接成员的标签；只能通过嵌套组到达的叶节点不是直接成员。

写入会同时原子地设置 TCP 和 UDP，Clash 的 `now` 只显示 TCP。原生 API 可以分别设置两种网络。有效变更通过共用的 `control/reload` owner 发布；状态缓存可用时，默认分别持久化网络选择。

只有显式设置 `experimental.cache_file.enabled: false` 才会关闭；省略这个设置仍然保留持久化。`interrupt_connections` 会按建立时捕获的组路径和发生变化的网络，关闭对应的精确 TCP/UDP owner，并等待确认，不再只是删掉 tracker。选择没有变化时不会触发中断。

URLTest、LoadBalance、Fallback 和 Score 都拒绝手动选择。

`GLOBAL` 是合成的 Selector，但它的 `all` 里每个成员都是具体的已配置组或节点，也都有对应的顶层 proxy 文档。`PUT /proxies/GLOBAL` 只接受这些名称，并通过同一个 `DatapathFlagsHandle` 更新。原生 API 未启用时，缓存数据库以 `GLOBAL` 为 key 保存选择；空值、已移除、未知和旧的虚拟选择都会退回第一个具体成员。

原生 API 启用时，保留共用的稳定目标身份，不持久化；目标消失时，不会自动改投同名对象或其他成员。

## 外部 UI hosting

设置 `experimental.clash_api.external_ui` 可以提供一个静态控制面板目录。目录缺失或为空时，honk 会在后台下载 ZIP；启动不会等它，文件可用之前静态路由返回 `404`。`assets.ui.url` 会替换内置的 zashboard URL，`HONK_UI_DOWNLOAD_URL` 则保持最高的覆盖优先级。

每次下载请求连同重定向在内只接受 HTTP(S)，最多跟随五次重定向，下载的 ZIP 正文上限 128 MiB。允许从 HTTPS 降级到 HTTP，也允许 URL 直接写 IP 地址；每一跳都遵循路由或 `assets.ui.route`、`assets.route` 里生效的出口。

`assets.ui.route` 优先于 `assets.route`，对初始请求和每次重定向都适用。`direct` 走直连的 HTTP 客户端，组名则强制经过选中的出站叶节点。没有配置出口时，每个 URL 都遵循 honk 当前的流量路由决策：`direct` 走直连客户端，`block` 中止下载，代理结果则经过选中的出站叶节点。

凡是直连或经代理、且实际经过 Score 组的 HTTP 请求，都会向路径上经过的 Score 组报告真实的 host 或 IP、端口、建立、首响应、字节和终态。其他路径不会创建评分 reporter 或 cell。建立的记录点在连接和 TLS 准备完成之后、发出 HTTP 请求之前。

首响应仍然由实际响应触发。共享 HTTP 错误会保留原始的 typed cause：目标故障归因于目标，typed carrier 故障即使在建立之后也仍然归因于 node。下载或解压失败只写日志，不会停掉引擎。

## `GET /stats`

`GET /stats` 是用户态快照，而不是 eBPF `OUTBOUND_STATS` map，也不暴露该 map 的报文计数器。固定 DNS、TCP、UDP 和 NFQUEUE 模式不创建动态的逐节点标签。

```text
{
  outbounds: [{ name, totalConns, activeConns, upload, download, errors }],
  pool: { readyHits, readyMisses, entries },
  dns: {
    socketAdmission: { refused, timeouts },
    proxyAdmission: { timeouts },
    pressure: { retiredUdpPools, retiredTransports }
  },
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

### DNS 字段

全部 `dns` 字段均为进程生命周期 `u64` 事件计数器，由活跃与退役 generation 共用，reload 不清零。各字段独立采样，单次快照不保证跨计数器一致性。这些总数由 Clash `/stats` 暴露，原生 DNS 诊断或历史 API 不提供。

| 字段 | 含义 |
| --- | --- |
| `socketAdmission.refused` | Endpoint 网络 bootstrap 需要两个额度，而整个 DNS socket 分区不足两个时被拒绝的次数。 |
| `socketAdmission.timeouts` | 因 admission 期限耗尽而返回的必要物理 socket admission 调用。 |
| `proxyAdmission.timeouts` | 因 admission 期限耗尽而返回的必要代理 stream 或非原始 packet 准备 admission 调用。 |
| `pressure.retiredUdpPools` | 因压力而选中退役的空闲 UDP socket pool，每个被摘除的 pool 只计一次。 |
| `pressure.retiredTransports` | 首次因压力而选中退役的空闲 TCP/TLS/H2/QUIC transport pool；恢复已保留的 teardown 不重复计数。 |

`socketAdmission.refused` 和 `socketAdmission.timeouts` 互不重叠。初次竞争、可选 UDP shard 扩容失败和调用方取消，都不算 admission 失败。计数在 admission 处加，不按 singleflight follower 或客户端应答重复加。压力计数表示被选中的资源，不是查询数、丢包数，也不是已经释放的描述符数；一个 transport pool 可能持有多个 socket。DNS admission 失败可能表现为 `SERVFAIL`，和 singleflight 的 `REFUSED` 各自独立。既有的节流失败日志保持不变。

### TCP 字段

| 字段 | 含义 |
| --- | --- |
| `activeFlows` | 当前持有 TCP admission permit 的透明 TCP 流。 |
| `limit` | 当前进程级 TCP 流 admission 上限；从描述符导出的下限开始，并随空闲描述符余量动态扩缩。 |
| `capacity.rejected` | 因 TCP 预算已满而等待 permit 的 accept-loop 单调计数；已接受 socket 保留在内核 backlog 中，不会被丢弃。 |

### QUIC 字段

| QUIC 字段 | 含义 |
| --- | --- |
| `srttUs`、`cwndBytes`、`currentMtu` | 活动连接的平均值；没有活动连接时为零 |
| `receiveWindowBytes`、`receiveWindowAvailableBytes`、`streamReceiveWindowBytes` | 活动连接的平均值；没有活动连接时为零 |
| `sendWindowBytes`、`sendWindowAvailableBytes` | 活动连接的平均值；没有活动连接时为零 |
| `flowReceivedBytes` | 已交付给应用的流字节数 |
| `flowSentBytes` | 已被对端确认的流字节数 |

字节计数包含已完成的池化连接。报文、UDP 字节、I/O、丢包、黑洞和拥塞计数同样包含这些连接。

池中的 TUIC、Juicity 与 Hysteria2 连接每秒采样一次流量控制状态。

| 窗口增长依据 | 效果 |
| --- | --- |
| 收发方向的十秒有效吞吐量 EWMA，RTT 至少 80 ms，且连续三个样本确认高 BDP | 将活动连接的接收或发送下限提高到约 `2 x BDP`。 |
| 对端的 `DATA_BLOCKED` 或 `STREAM_DATA_BLOCKED` | 直接表明已通告窗口受限。绕过 RTT 门限，将连接或流的接收下限加倍。 |
| 连接额度仍受限时的零进展样本 | 保留但不增加连接级连续样本计数。 |

窗口正在限制流量时，有效吞吐量的估计会偏低，不能拿来作为升档依据。每个下限独立执行五分钟的调整冷却。自动提高的上限是 32 MiB，但不会降低更大的显式配置。

honk 不会因为应用需求低就缩小已经学到的窗口，也不会在活动连接上切换拥塞控制。

| 计数器 | 含义 |
| --- | --- |
| `ackFrames` | 收到的 ACK 帧，表示路径进展；重复帧可能重复计数。 |
| `lossRatePpm` | 排除 PLPMTUD 探测的丢包率；分母为 `sentPackets - sentPlpmtudProbes` |
| `lostPackets` | 排除 PLPMTUD 探测的丢包数 |
| `sentPlpmtudProbes`、`lostPlpmtudProbes` | 独立的 PLPMTUD 探测计数 |
| `txIos`、`rxIos` | 反映批处理效率的 I/O 次数 |
| `transportTxWouldBlock` | 64 包适配器队列已满的次数；Quinn 会重试 |
| `transportTxDrops` | 代理传输报告拥塞或超时后主动丢弃的报文数 |
| `transportRxDrops` | 适配器接收队列已满的次数 |
| `sessionRxDrops` | TUIC/Hysteria2 的 256 包 session 队列已满的次数 |
| `sendTimeouts` | 启用指标的连接上，仍计入当前 no-ACK 等待、但发送期限已到的 UDP 发送次数 |
| `pathStalls` | 路径监视器在完整 no-ACK 宽限期后退役的共享 QUIC 连接数 |

`sendTimeouts` 是拥塞诊断，不是全部超时、节点故障或恢复次数。`pathStalls` 不是丢包数、受影响流数或恢复次数。两者均为进程生命周期内的累计值。

### Score 选路原因字段

`score.groups` 是认证后的 `/stats` 响应里额外的一部分。当前没有任何组使用 `policy: score` 时，它是 `[]`。否则它包含每个当前的 Score 组，包括没解析出叶节点的组，按 `name` 的字典序排列。

每组的 `tcp` 和 `udp` 对象始终存在，每个对象也始终包含全部 `R` 字段。没有网络活动时这些值是零，字段从不省略。

每个 `R` 值是饱和 `u64` 计数，不是延迟、吞吐或健康测量。一次已授权的多候选 Score Apply 记录一个最终原因：

| 最终原因 | 含义 |
| --- | --- |
| `coldExplore`、`periodicExplore` | 验证 |
| `incumbentIneligible` | 离开已不满足普通资格的当前成员 |
| `freshFailureBypass` | 合格的当前成员存在尚未恢复的业务失败。 |
| `insufficientEvidenceHeld` | 没有挑战者获得晋升，且普通效用排名的胜者缺少合格的共同性能比较。 |
| `directionalTradeoffHeld` | 没有挑战者获得晋升。某个比较在一个已知方向提升至少 10%，在另一个方向退化超过 10%。 |
| `incumbentHeld` | 比较优势未超过保持门槛。 |
| `reliabilityWinner`、`performanceWinner` | 其他情况下，保留按替代候选资格分类的含义。 |

`performanceWinner` 本身不证明性能提升或发生切换。`insufficientEvidenceHeld` 不表示可靠性历史缺失。

| 附加计数器 | 含义 |
| --- | --- |
| `ordinarySwitch` | 实际提交的普通 A→B 选择 |
| `switchFlap` | 同一目标八次普通选择内返回前一胜者的次数 |
| `deadFiltered`、`failStreakExcluded`、`exploreBackedOff` | 每次排名中受影响的候选数 |

首次选择、试用及缺少先前历史时不增加切换计数。Peek、API 读取、单例旁路和最后尝试不增加原因计数。嵌套组排名与实际出站连接并非一一对应。

对 UDP 来说，`deadFiltered` 还会统计因协议或配置不具备 UDP capability 而被排除的候选。它不是新出故障的节点数，也不是业务尝试数；这类排除不会增加 Score 失败，也不会增加探索退避。

`carrierPressure` 统计被已有的组或网络聚合 cell 接收的新鲜 carrier 地址族事件，不是包数，也不是失败连接数。重复的心跳读取不会增加它。`carrierValidation` 统计的是一种周期验证选择：普通赢家身上有比上次验证更新的 carrier 提示。

这是可重叠的诊断计数，不是新的互斥原因，也不证明只有这个提示导致了选择。提示不会改变业务可靠性、资格或健康。该字段在 API 读取时是只读的。

carrier 观测由控制心跳接入，和选路调用相互独立。

`carrierRttPressure` 和 `carrierLossPressure` 保留被接收事件的原因。两种条件同时满足时，两个原因计数都加一，但 `carrierPressure` 只加一次。这些可重叠的计数不标识具体的 carrier 或传输协议，不是应用丢包率，也不会增加失败次数。

重复或过期的提示都不会增加它们。TCP 的 loss pressure 表示重传压力，不代表已经确认有应用包丢失。

计数在进程启动时从零开始，只在进程内存里累积。只要组名还在已提交的配置里，成功的 reload 就会保留它们，包括零叶节点以及临时的 Score→非 Score→Score 转换。非 Score 组不会出现在这个响应里。

已经提交的删除会清除这个名称的计数，之后重新创建同名组从零开始。受 generation fence 约束的已淘汰 manager 在被替换之后不能再改计数，即使同名组随后又被创建。快照在 JSON 序列化之前复制，读取不会改变选路状态。

`/stats.score` 只公开组名、固定的 TCP/UDP 原因、验证与预算字段、根业务计数，以及有界的证据缓存总量。它不含节点身份、目标 domain/IP/port、原始 cell、cadence key、权限依据或凭据。

`/proxies` 中既有公开成员名和 `/connections` 中目标元数据保持不变。

### Score 验证信息

`/proxies` 和 `/proxies/{name}` 里的 Score 组会增加 `scoreVerification`。它固定的目标是 `responseQualityWithAvailability`，范围是 `aggregate`，并不保证每一个精确目的地。`tcp` 和 `udp` 里分别包含：

| 字段 | 含义 |
| --- | --- |
| `selected` | 本次只读判定对应的既有公开成员标签；没有普通合格候选时为 null。存在时 TCP `now` 使用同一次判定的选择。 |
| `state` | `provisional` 或 `observedUsable`。后者要求同一个连续 cohort 里，四个不同的定向 Traffic reporter 在 setup 或 TX 之后收到了 RX，而且最近一次合格 RX 距今不到 60 秒。失败、reload 或 60 秒间隔都会重置 cohort；clone 和重复的回包不能增加信用。这个状态不授予冷启动资格。真正失败之后的 cohort 可以独立地用同样四份信用取得作用域恢复。聚合可用并不代表每个精确目标都合格。 |
| `challengers` | `selected` 与已评估挑战者之间新鲜的成对响应比较，见下文。 |
| `nextAction` | `nextBusinessFlow` 表示要靠未来的真实业务来补充证据、普通资格或恢复，不是已经预留或已经派发的 I/O；要同时看 `waitReason`。`backoff` 表示保留失败隔离。`none` 表示没有可以执行的缺失工作。缺少传输证据不会创建工作；方向的有效吞吐量要等真实负载。 |
| `question` | `none`、`availability`、`response`、`qualification` 或 `recovery`，表示下一个还没解决的证据问题。没有剩余动作时是 `none`。退避时保留被阻塞候选的问题，不会退回到已解决现任的问题。 |
| `waitReason` | 工作等待的原因。取值和聚合作用域的规则见下表。等待不代表工作一定会成功。 |
| `coverage` | `scope` 为 `all` 或 `bounded`。`candidates` 统计当前可见的候选全体；`evaluated` 是这个视图与共享服务池的交集；`unevaluated` 是两者之差。胜者不额外占位。父组入口和目标共用这个池，TCP 与 UDP 分开。池外成员不接受普通或可选策略的工作；这些数量不是所有存量连接涉及的节点总数。`pending` 统计还有未决问题的已评估成员，包括已有比较、但仍需资格或恢复工作的成员。 |
| `network`、`targetFamily`、`healthFamily`、`targetSpecific` | 传输与适用范围；此聚合接口没有精确目标，不导出 domain/IP/port 或原始节点 ID。 |


| `waitReason` | 含义 |
| --- | --- |
| `none` | 没有等待 |
| `budget` | 额度不可用；或者已有可用选择时，试用因反复失败而暂停 |
| `comparableTraffic` | 等待未来出现可比较的业务 |
| `inFlight` | 已有的同目标工作够了，或达到了独立的每节点四项工作上限 |
| `backoff` | 失败隔离 |

聚合读取会检查已保留的 IPv4/IPv6 作用域，不会创建新作用域：

- 两者都因预算阻塞：返回 `budget`。
- 任一作用域可用，或尚未创建：仍然可以等未来的可比较流量。
- 其他情况：保留在途等待。

只读和 Peek 使用已提交的参与者，不重新排名。Apply 会初始化并刷新参与者。初始化之前，只读查询使用临时的有界投影。

见[评估集生命周期](../design/groups.md#有条件的验证结论)。

`challengers` 列出所选成员当前原始比较对里、具有新鲜合格响应指标的项；这些比较对就是普通晋升读取的同一批。没有该指标的成员不会出现，全都没有时是空列表。每项含 `name`、`basis`、`relation`、`reporters` 和 `validForMs`。`name` 是公开成员标签，仅作显示，嵌套路径下可能重名；`basis` 为 `targetResponse`、`commonTargets` 或 `configuredProbe`；`relation` 为 `selectedFaster`、`equivalent` 或 `challengerFaster`。

`equivalent` 对实际响应值使用含边界的对称区间 `high - low <= 0.1 × low`，零和亚毫秒值也算在内。`reporters` 取双方已保留的不同 reporter 支持量中较小的那个：四个块各保留最多四个 ID，跨块去重后并集最多十六个，不是所有已观测 reporter 的精确总数。`validForMs` 是这个响应指标还剩多久有效。

业务块是 15 秒，在块起点之后 60 秒到期。配置探测按生产者周期 `I` 使用 `max(15s, 2I)` 的块；有效期同时受两个条件限制：最早支持的块的四块保留期限，以及较弱一侧最近支持再加上 `max(60s, 2I)`。失败、reload、incarnation 的边界不变。

`commonTargets` 最多用八个规范、等权、响应合格的共同目标，不是无关的聚合均值。建立和预热都不算比较证据。

这里的关系只描述测得的响应时间：它不是晋升决定，不是可靠性或带宽结论，不是误判概率，也不保证最优，更不能证明所选成员比列表之外的成员更好。普通切换仍然使用自己依赖完成数的门槛，以及可靠性、可用性和方向保护。查询不会派发验证，也不改变计数。

`/stats.score.groups[].verification.tcp` 和 `.udp` 里增加了饱和计数 `provisionalSelections`、`usableSelections` 和 `validationSelections`，只在授权 Apply 时推进。

### Score 工作预算与观测成本

`/stats.score.businessStarts` 对嵌套组去重，统计唯一的原始 Score 业务开始数。`/stats.score.groups[].budget.tcp` 和 `.udp` 聚合的是保留下来的目标地址族作用域。不要把嵌套组的总量相加当作唯一业务数。

原始业务被选为试用时仍然计数；延续尝试即使换了网络或目标地址族，也不会累积另一份原始额度。节点专属工作在代理 DNS 和物理拨号的 admission 等待之前就开始，和 reporter 的物理、逻辑 I/O 边界无关。DNS 查询生命周期的 admission，是在这之前同步检查池是否开放，不是物理拨号的 admission 等待。

预算计数器反映的是已经记录的账本值。只读等待和冷启动判定还会考虑过期未开始预留里可以退回的额度，但不更新 `refunded`、`expired` 或其他计数器。

| 字段 | 含义 |
| --- | --- |
| `businessStarts` | 保留作用域中原始业务开始数之和。 |
| `scopes` | 保留的作用域数量。 |
| `earningPeriod` | 各作用域里最快的当前累积周期 `q`，通常是 16。如果组最近每秒至少两条业务，且作用域的试用大多成功，就是 8。还没有作用域时为 0。这个值不能当合并作用域预算公式的分母。每个作用域创建时固定一份冷启动额度 `B`，之后每次原始业务开始，按当时的 `q` 累积 `1/q`。各作用域的 `spent + reserved` 不超过 `B` 加上已累积额度的整数部分。 |
| `sources.cold`、`sources.periodic`、`sources.recovery` | 按来源区分的已开始工作：冷额度试用、已赚额度试用、不增加可选额度的延续尝试。`recovery` 包含 TCP 替代、DNS 改路和 UDP 转 TCP，以及 UI 与订阅重定向，不限于出错后的重试；它既不是可选试用，也不是新的原始业务。普通的非试用没有来源桶。 |
| `trialStarts`、`spent`、`reserved` | 已开始的可选试用数、累计已支出的 token，以及尚未开始的 token 预留。开始只支出一次，开始之后取消不退回额度。 |
| `coldAllowance`、`coldAvailable`、`earnedAvailable` | 固定初始额度和当前可用额度的合计。每个作用域最多保留八个未花费的已赚 token。时间流逝、读取、目标变动和证据过期都不赚额度；保留下来的作用域在 reload 或成员变化之后不重置。 |
| `budgetBlocked`、`inFlightBlocked`、`refunded`、`expired` | 四个都是计数。前两个是预留被拒绝的次数，其中 `budgetBlocked` 也计入作用域因试用反复失败而暂停时被拒绝的候选。`refunded` 是最后引用释放或未开始失效时退回的额度数，`expired` 是在途追踪项过期的数量。只有未开始的预留能退回额度；追踪过期不会退回已经开始工作的支出。 |
| `trialSuccess`、`trialFailure`、`trialCancelled` | 已开始的可选试用的 exactly-once 终态。拒绝、关闭和中性取消都归入 `trialCancelled`。`trialFailure` 是实际观测到的失败，不是相对于未观测的替代路径、因为选择试用而额外造成的失败。 |
| `trialSetupHistogram`、`trialSetupMillis`、`trialElapsedMillis` | 八个固定 log2 毫秒建立桶（槽位 0 包含 0–1 ms，末槽包含 128 ms 及以上）、已观测建立时长之和，以及开始至终态时长之和。它们是实际试用成本，不是因果额外延迟或开销。 |

`/stats.score.cache.comparisonCells` 上限是 512。`comparisonLogicalBytes` 计入比较存储、vector 容量和所持 key 的容量。`comparisonLogicalCapacity` 是按实现结构大小算出的最坏分配界限，不超过 1 MiB。

这两个值都不是实测的进程 RSS，也不是全部 Score 状态的大小，都不含分配器开销和进程里的其他分配。`comparisonEvictions`、`comparisonExpired`、`comparisonRejected` 统计存储移除和 admission 事件。只读访问可以先让支持失效，要等实际移除之后才增加计数。

既有的精确和聚合 LRU 字段不变。

### 出站与 ready pool 字段

| 字段 | 含义 |
| --- | --- |
| `outbounds[].name` | 出站名称。 |
| `outbounds[].totalConns` | 经该出站启动的连接数。 |
| `outbounds[].activeConns` | 当前经该出站打开的连接数。 |
| `outbounds[].upload` | 用户态中从客户端到 proxy 的字节数。 |
| `outbounds[].download` | 用户态中从 proxy 到客户端的字节数。 |
| `outbounds[].errors` | 归因于该出站的连接尝试失败数。 |
| `pool.readyHits` | ready 裸连接池命中数。 |
| `pool.readyMisses` | ready 裸连接池未命中数。 |
| `pool.entries` | 当前 ready 裸连接条目数。 |

### Histogram 格式

每个 `H` 都是 `{count, sumNanos, buckets}`。`count` 是观测数，`sumNanos` 是以纳秒计的总和。`buckets` 是包含 64 个非累积计数的数组：槽位 $n$ 覆盖 $2^n$ 到 $2^{n+1}-1$ ns，槽位 0 还包含零，最后一个槽位在 `u64::MAX` 饱和。

### UDP 字段

| 字段 | 含义 |
| --- | --- |
| `endpoint.hits` | 已建立 UDP endpoint fast 路径处理的报文数。 |
| `endpoint.misses` | 冷启动流的 endpoint lookup miss 数。 |
| `latency.route` | 冷启动 route selection 延迟。 |
| `latency.dial` | 冷启动 UDP dial attempt 延迟。 |
| `latency.replyReady` | endpoint 驱动任务 commit 前同步准备 reply socket 的延迟。 |
| `latency.firstSend` | 首次发送尝试延迟。 |
| `latency.firstReply` | 首个应答成功重新注入客户端之前的时间。 |
| `capacity.rejected` | 精确 endpoint capacity reservation 被拒次数。 |
| `slowPermit.accepted` | 进入活动 UDP slow 路径的 admission 数。 |
| `slowPermit.rejected` | 因 shared connection semaphore 已满而拒绝的 slow-path admission 数。 |
| `slowPermit.closed` | generation draining 期间拒绝的 slow-path admission 数。 |
| `queue.accepted` | 进入有界 endpoint-driver 队列的报文数。 |
| `queue.full` | retained 队列的 drop-newest 事件总数。 |
| `queue.flowFull` | 单流 packet 槽位上限导致的 drop-newest 数。 |
| `queue.globalPayloadFull` | 全局 retained 载荷 byte 上限导致的 drop-newest 数。 |
| `queue.closed` | 对正在关闭或已关闭 endpoint 驱动任务发起的队列尝试数。 |
| `firstSend.failures` | 首次发送错误或超时数；两者都按 ambiguous send 处理。 |
| `stagger.attempts` | 已启动的冷启动 URLTest speculative preparation 尝试数。 |
| `stagger.winners` | 首个满足条件且成功的 staggered preparation 数。 |
| `stagger.cancellations` | 其他 candidate 获胜后取消的已启动 speculative preparation 数。 |
| `warm.attempts` | 已启动的 generation-owned UDP 预热 dispatch 数。 |
| `warm.successes` | 返回 `Ready` 的预热 dispatch 数。 |
| `warm.failures` | generation 仍存活时的真实预热 failure 数。`NotApplicable` 保持中性。 |

`queue` 衡量 endpoint-driver 队列；它不同于衡量 UDP slow 路径 admission 的 `slowPermit`。

### NFQUEUE 字段

| 字段 | 含义 |
| --- | --- |
| `received` | NFQUEUE listener 投递的报文数。 |
| `activeFlows` | 当前由 pending-verdict correlator 持有的流 cell 数。 |
| `kernelQueueDepth` | 当前活动 kernel 队列实例中的排队报文数。 |
| `kernelStatsAvailable` | 最近一次 kernel 队列 statistics 读取是否成功。 |
| `kernelStatsReadErrors` | 累计 kernel 队列 statistics 读取失败数。 |
| `kernelDropped` | 因 kernel NFQUEUE 达到队列上限而丢弃的报文数；跨队列 hard rebind 累加为进程生命周期计数器。 |
| `kernelUserDropped` | kernel 向用户态投递 NFQUEUE message 时丢弃的报文数；跨队列 hard rebind 累加为进程生命周期计数器。 |
| `heldPackets` | 当前已投递但 verdict guard 仍被持有的报文数。 |
| `heldPeak` | 队列 service 报告的同时持有 verdict guard 峰值。 |
| `socketReceiveBufferBytes` | netlink socket 的有效接收缓冲区大小。 |
| `actorQueueFull` | 因有界 ingest 执行单元队列已满而失败时拒绝转发丢弃的报文数。 |
| `correlatorFull` | 达到任一 correlator 硬上限时丢弃的报文数：4,096 个流 cell 或每流 64 个 retained verdict。 |
| `actorQueueDepth` | 当前 ingest 执行单元队列条目数。 |
| `actorQueuedBytes` | 当前 ingest 执行单元队列保留的载荷字节数。 |
| `actorOldestAgeNanos` | 当前最老 ingest 执行单元条目的年龄，单位为纳秒。 |
| `directAccepted` | direct 决策成功执行 marked `NF_ACCEPT` verdict 的次数。 |
| `proxyCopied` | 载荷所有权转交给规范 UDP 初始化器的次数。 |
| `proxyDropped` | proxy 决策成功对原始报文执行 `NF_DROP` verdict 的次数。 |
| `block` | policy block 成功执行 drop verdict 的次数。 |
| `cancel` | cancellation 成功执行 drop verdict 的次数。 |
| `drop` | 其他成功执行的失败时拒绝转发 drop verdict 数。 |
| `tokenMismatch` | 过期或不匹配的 decision token/流 identity 事件数。 |
| `tokenExhaustion` | 观测到持久化 decision-token allocator 耗尽的次数。 |
| `tokenRollovers` | token 耗尽后成功完成 generation rotation 的次数。 |
| `verdictErrors` | `NF_ACCEPT` 或 `NF_DROP` 操作失败数。 |
| `receiptToVerdict` | 从 listener 收包到成功 terminal verdict 的 histogram；它不是 kernel 队列 residence time。 |

独立的一秒采样器读取自己的 kernel 队列，不依赖报文 dispatch。读取失败之后，之前的 `kernelQueueDepth`、`kernelDropped` 和 `kernelUserDropped` 仍然可见，而本地的 held-packet 和 receive-buffer 瞬时值会继续刷新。

### 热资源字段

| 字段 | 含义 |
| --- | --- |
| `warm.nodes.preconnect` | 归因于启动时裸 TCP 预连接的热节点。 |
| `warm.nodes.health` | 健康状态 probing 期间观测到的热节点。 |
| `warm.nodes.udp` | 归因于 UDP 预热 coordinator 的热节点。 |
| `warm.nodes.selector` | 作为已配置 Selector 叶节点而保留的热节点。 |
| `warm.nodes.traffic` | 没有显式 attribution mark、因而归因于 traffic 的热节点。 |
| `warm.sessions.anytls` | 保留的 AnyTLS 池 session 数。 |
| `warm.sessions.vless` | 保留的 VLESS 池 session 数。 |
| `warm.sessions.tuic` | 已占用的 TUIC 客户端槽位数。 |
| `warm.sessions.juicity` | 已占用的 Juicity 客户端槽位数。 |
| `warm.sessions.hysteria2` | 已占用的 Hysteria2 客户端槽位数。 |

一个节点可以同时计入多个显式原因。瞬时值跟随当前运行时 generation；已排干资源会从下一次快照中消失。

## Related docs

- [Experimental 配置](./experimental.md)
- [NFQUEUE 设计](../design/nfqueue.md)
- [控制面设计](../design/control-plane.md)
