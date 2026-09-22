# 原生 API、Clash API 与 `/stats` 参考

原生与 Clash API 具有独立的 feature、listener、凭证及 HTTP 边界，共用底层引擎 handles 与用户态统计。

## 原生 API (M1)

本节保留 M1 标题锚点，说明当前已实现的原生观测与控制契约。默认构建及两种 allocator 发布产物均包含 `native-api` Cargo feature，但 listener 默认关闭，须显式启用 [`experimental.native_api`](./experimental.md#native_api)。`--no-default-features --features native-api` 可脱离 Clash 使用。`.dae` 仍是唯一配置权威；显式授权后可读取与替换已接受的源文件，不引入 SQLite 配置主存储。

基础契约为 [api-standardize cb8ac07c6520b7fb08539cc0b7701695f5a07992](https://github.com/Zakkaus/api-standardize/tree/cb8ac07c6520b7fb08539cc0b7701695f5a07992)，节点/provider 管理与 geodata 使用 [doona-pin ba3e4c3648e04d093d32164ecca018f51bd74e00](https://github.com/Zakkaus/api-standardize/tree/ba3e4c3648e04d093d32164ecca018f51bd74e00) 中的 M9 补充。没有整体切换到该后续 bundle 的 mode/自动 override 变更：原生 mode 与自动策略 override 继续 gate，不声明 `full_transparency`。源管理要求真实 `.dae` 启动，写入还需启用 `config_write` 并配置非空 secret；以 capabilities 和逐源权限为准，不按路由名称推断全部可用。

| 方法 | 路径 | 含义 |
| --- | --- | --- |
| GET | `/api` | Discovery，固定 `/api/v1` base 与全部契约 links。 |
| GET | `/api/v1/version` | 原生契约身份、引擎构建版本以及构建的提交与目标平台，不伪造构建时间。 |
| GET | `/api/v1/capabilities` | 已实现资源与请求上限。 |
| GET | `/api/v1/runtime?detail=summary\|full` | 引擎 phase、已接受代次与具有独立时间戳的用户态流量。 |
| GET | `/api/v1/connections?type=all\|tcp\|udp&src=192.0.2.1&limit=100&detail=summary\|full` | 可见的活跃用户态连接；可选 `src` 必须为无端口 IP literal。 |
| DELETE | `/api/v1/connections/{connection_id}`、`/api/v1/connections` | 确认精确 transport owner 关闭；批量需过滤器或显式 `all=true`。 |
| GET | `/api/v1/flows`、`/api/v1/flows/{flow_id}` | 活跃及保留的终态用户态决策；detail 包含执行源头记录的 trace。 |
| GET | `/api/v1/nodes` | 稳定节点 ID、当前直接成员/订阅来源与真实测量。 |
| POST | `/api/v1/nodes` | 用 `{name,link}` 创建主文件节点；真实激活后才返回 201。 |
| DELETE | `/api/v1/nodes/{id}` | 删除主文件 inline 节点；激活后返回 `{deleted:0\|1}`。 |
| GET | `/api/v1/groups`、`/api/v1/groups/{groupId}` | 无副作用组观测、直接成员、配置 revision/ETag 与捕获的健康数据。 |
| PUT | `/api/v1/groups/{groupId}/selection` | 按直接成员 ID 设置 Selector 的 `tcp`、`udp` 或 `both` 选择。 |
| PATCH | `/api/v1/groups/{groupId}` | 对可写 `.dae` 来源执行受限 JSON Patch，返回真实更新 operation。 |
| GET | `/api/v1/events` | 有界且需认证的 SSE，支持绑定过滤器的续传游标。 |
| GET | `/api/v1/runtime/outbounds` | 共用计数生命周期内按 `kind/name` 区分的全宽出站计数。 |
| GET | `/api/v1/runtime/memory` | 实际进程 RSS 与可读的 cgroup v2 内存事实。 |
| GET | `/api/v1/runtime/traffic/history`、`/api/v1/runtime/memory/history` | 可选 `window_seconds`、`max_points`，均默认 600、范围 1–600。 |
| GET / PUT | `/api/v1/runtime/mode` | 失败契约未完整固定，保持 `404 capability_not_supported`。 |
| GET / PATCH | `/api/v1/runtime/settings` | 原子读取/合并支持的日志、DNS 日志与 flow 留存设置。 |
| GET | `/api/v1/datapath` | 后端实际观测的程序、hooks、路由发布和 map 状态，未知项不推测。 |
| POST | `/api/v1/probes` | 有界的节点/组 TCP、HTTP、DNS 测量 operation。 |
| GET | `/api/v1/dns/query`、`/api/v1/dns/cache`、`/api/v1/dns/log` | 显式 DNS 诊断、精确缓存快照与客户端查询历史。 |
| DELETE | `/api/v1/dns/cache/{entry_id}`、`/api/v1/dns/cache?name=example.org` | 删除精确缓存 incarnation，或按完整名称及可选 type 删除。 |
| POST | `/api/v1/dns/cache/flush` | 等待内存与启用的持久化缓存失效确认，不清空域名路由事实。 |
| POST | `/api/v1/routing/trace` | 固定当前 generation 的无联网路由模拟，仅支持 `resolve=none`。 |
| GET | `/api/v1/rules` | 当前 generation 的完整规则字典、fallback 与可用来源位置。 |
| GET | `/api/v1/providers`、`/api/v1/providers/{id}` | 真实订阅 owner 状态，不在读取时拉取。 |
| POST | `/api/v1/providers/{id}/refresh` | 显式刷新订阅，并等待真实 runtime publication 的 operation。 |
| POST | `/api/v1/providers` | 用 `{name,kind:"subscription",url}` 创建尚未拉取的主文件订阅。 |
| DELETE | `/api/v1/providers/{id}` | 删除主文件 HTTP(S) 订阅及其已加载节点。 |
| GET | `/api/v1/geodata` | 读取流量/DNS 路由实际已加载资产的保留元数据。 |
| POST | `/api/v1/geodata/update` | 下载配置资产、完整校验后，通过 operation 激活精确候选字节。 |
| GET | `/api/v1/logs` | 结构化、安全投影的原生日志 SSE，独立于 Clash 格式化日志。 |
| GET | `/api/v1/config` | 认证后返回已接受的源快照、配置 revision 与安全诊断，仅遮蔽监听凭据值。 |
| GET | `/api/v1/config/sources/{source_id}` | 认证后返回单个已接受源的元数据及正文，仅遮蔽监听凭据值。 |
| POST | `/api/v1/config/validate` | `syntax` 或离线 `full` 校验，不写盘、不 reload。 |
| PUT | `/api/v1/config/sources/{source_id}` | 强 `If-Match` 保护的单源原文替换；写盘后排队真实 reload，返回 operation。 |
| POST | `/api/v1/operations/reload` | 从磁盘重新加载，返回 daemon-owned operation；body 留空或为 `{}`。 |
| POST | `/api/v1/operations/suspend`、`/api/v1/operations/resume` | 关闭连接的真实无网络负载暂停/恢复，返回 operation。 |
| GET | `/api/v1/operations/{id}` | 真实排队、运行及终态结果。 |

获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的连接数据。显示字段遮蔽监听凭据值。Connections 的 `detail` 默认 `summary`，`type` 默认 `all`，`limit` 默认 100、范围 1–1000。拒绝重复单值或未知 query 参数。先过滤，再统计总量与应用 TCP+UDP 合计 limit；按注册观测时间降序、相同时间按 ID 字典序升序排列。total 是匹配的完整可见数量。IPv4-mapped IPv6 来源按 IPv4 比较。summary 省略 `src/dst/domain`，full 包含它们，未知 domain 为 null；full 不表示更高权限。

连接 `outbound` 是选路当时的组/动作，不是当前叶节点或重建选择。启用记录时，`flow_id`、捕获的 root-first 组/叶 ID、首次观测 UTC、domain 来源与用户态 rule ID 关联保留证据；缺失或淘汰的证据保持 unknown。逐连接 rate 仍为 null。空列表是 `visibility: partial`，不代表设备没有连接。Mock 数据面显示 disabled/none；真实后端只依据实际程序、hooks、routing root、listener 和 admission 观测报告状态，未知项为 unknown/null，覆盖仍为 partial。HTTP 就绪不等于数据面就绪。

单项 DELETE 的 `204` 表示已确认精确 TCP UUID 的转发任务结束，或精确 UDP token/generation/source view 的退役、backend 确认及已准入发送/回复排空；不是删除 tracker 行。共享 XUDP 只关闭本 view，不关闭其他 view 共用的 carrier，也不重放报文。已消失返回 404，不可关闭的非用户态 owner 返回 409，无法确认退役返回 503。批量只捕获一次匹配集合，支持 `type=tcp|udp|all`、无端口 `src`；未限制网络或来源时必须 `all=true`（仅 `type=all` 不算过滤）。超过 1000 条先返回 413，零关闭；成功返回实际 `closed/skipped`。关闭已选集合后出现的新连接不受影响；503 不表示已完成的关闭回滚。DELETE body 必须为空；重复 `Idempotency-Key` 仍检查当前连接状态，不重放旧结果。

TCP 在 copy 成功读取或 splice 成功写入目标 socket 时实时入账，成功写出的嗅探前缀仅计一次；UDP 保持原逐包语义。唯一的一秒 sampler 使用实际时间间隔；初次采样、reset 和 overflow 返回 null rate，不补零。`counter_since` 属于共用计数器生命周期，`sampled_at` 属于流量样本，`observed_at` 属于 HTTP 观察。UInt64 使用十进制字符串，有界数量仍为 JSON number。CPU 与 activation 时间仍未知；有源管理器时提供配置 revision，`last_reload` 提供最近完成的 API reload operation 结果，否则为 null。

配置 secret 后，所有 API 路径（包括 discovery/version/capabilities、禁用 action、未知 API path）都要求单个有效 Bearer header。Query token、重复凭据、错误凭据均不能回退匿名，同源 UI 也不豁免。无 secret 需显式 loopback 授权，并拒绝 `Sec-Fetch-Site: cross-site`。公共静态文件也接受 Host/Origin 校验；OPTIONS preflight 无需 bearer，但必须通过 Host、Origin、method 与 header 白名单。不返回 cookie credentials 或通配 CORS。

已知禁用 action 返回 JSON `404 capability_not_supported`，未知 path 或未定义 method 返回 JSON `404 resource_not_found`；配置来源可读但未授权写入时，PUT 返回 `403 permission_denied`。错误信封为 `{error:{code,message,details},request_id}`。HEAD 保留 GET 状态/header，无 body。API 响应带 `no-store` 与 `nosniff`。应用上限为规范化 target 4096 字节、规范化 header 名/值合计 16384 字节、body 65536 字节（含 chunked）；已认证 GET/HEAD 携带非空 body 会被拒绝。普通观测读取不触发 probe 或选择变化；显式 `/dns/query` 是可联网的诊断请求。

原生 server 最多拥有 64 条 HTTP/1.1 连接，满时暂停 accept，header 读取上限五秒；关闭时全部连接共享五秒 graceful drain，随后 abort 并逐一 join。空闲 I/O 与停滞写入分别受 30 秒期限约束；SSE heartbeat 成功写入使健康长连接保持活跃，读取不能延长阻塞 writer 的期限。TLS/HTTP2 可由可信反代终止。Forwarded headers 不改写固定 discovery path，也不授予 Host/Origin 权限。

**已记录的契约差异：** bootstrap 采用 common bearer 安全规则，尽管该 pin 的 bootstrap 标记了 `security: []`。Hyper 可在应用处理前以 400/414/431 或断连拒绝畸形/硬超限 HTTP；这些 transport 拒绝不保证 JSON 信封或应用 headers。

应用 target/header 上限作用于 Hyper **解析并规范化后的表示**，不是原始 wire 字节。Hyper 可能先移除 request-target fragment，或合并相同 `Content-Length` 字段，再交给应用计量；这些形式的原始文本即使超过应用上限，也可能得到正常响应而不是 413。原始输入仍受 Hyper 传输处理约束。这是已接受的边界差异，不另写 HTTP parser，也不宣称原始 wire 大小保证；body 限制仍覆盖全部交付的 body 字节。

配置 `ui` 后，`/` 与 `/ui` 重定向到 `/ui/`。目录托管保留无扩展名 SPA fallback；缺失静态资产、fonts/icons、manifest 或 service worker 返回 404，不返回 HTML。以 `--features native-ui` 构建并设置 `ui: embedded`，即可直接提供固定真实 doona 产物，不解压到磁盘、不联网。其 hash router 使用 `/ui/#/...`；其他合法内嵌导航路径重定向回 `/ui/`，确保相对资产与 service worker 路径正确。静态响应保留 `no-cache`、`nosniff`、`X-Frame-Options: DENY`；公开资产仍经过 Host/Origin 校验，API bootstrap 与请求仍需 bearer，不向 UI 注入凭据。

### 用户态记录流（M2）

获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的 flow 数据。

客户端通过 GET 建立且获准的 `/events` 或 `/logs` SSE 流仍连接时，视为已连接。最后一条流关闭后，或成功的 GET 请求访问 `/flows`、`/flows/{id}`、`/dns/log` 后，连接状态保留 60 秒。其他请求不延长此期限。这种通用连接状态只启用获准的 Auto 日志、DNS 日志和事件捕获，不启用完整 flow trace。

Auto flow 记录要求诊断需求：成功的 GET `/flows` 或 `/flows/{id}`，或获准的 GET `/events` 流显式通过 `kinds` 包含 `flow.updated`、`flow.gap` 中任意一个，或使用非空白 `flow_id` 过滤器且有效 kinds 包含 flow 事件。省略 `kinds` 的无过滤流、非 flow 事件流、`/logs` 和 `/dns/log` 不建立或维持 flow 需求。每条流持有独立租约；最后一条诊断流关闭后，或成功读取 flow 后，需求保留 60 秒。通用 Activity 不能延长 flow 宽限期。被拒绝的请求、准入失败的流、HEAD 和运行时设置读取都不建立需求。记录从需求建立时开始，首次读取历史为空是正常情况。

`record_flows` 默认为 true，允许在 flow 诊断需求有效时记录。显式运行时设置 `record_flows: true` 可在无客户端时持续记录；运行时 false 强制关闭，配置中的 `record_flows: false` 禁止记录，修改后需重启。实际记录停止时释放 flow 记录和快照。进程内最多保留 1024 条 flow、每条 64 steps，含 snapshot 与内核字典预留的总预算 8 MiB；终态最多保留 300 秒，压力下可提前淘汰，重启清空。由既有 sampler 清理，不新增 timer。

Flow ID 表示 incarnation，不是五元组。TCP/UDP 捕获真实执行的路由谓词与短路、嗅探/校验、群组选择、DNS 子查询、物理尝试、会话复用/重试及终态边界；拨号失败或阻断即使没有 live connection 也保留。名称、ID、代次来自实际使用它们的操作，不按当前配置或路由模拟重建。DNS lookup/parent ID 与 outbound attempt/parent ID 保留因果关系；复用 carrier 记录为 attachment，不伪造新物理拨号。协议请求/确认 milestone 必须有真实协议证据，DNS 子步骤就绪不能成为业务目标确认。TCP/UDP 终态跟随所属清理边界；内核 offload 以 unknown 结束观察，不伪造 closed。

只有该 flow 范围内截至当前进度已执行的决策均被捕获，`trace_status` 与 `trace.status` 才是 `complete`。Active、failed、closed 均可完整；这不代表成功或全局覆盖。来源缺失/歧义、监听凭据值遮蔽及捕获预算耗尽，会保持 `partial` 并列出 `missing` 原因；达到 trace 上限不停止转发。用户态 TCP/UDP 和截获 DNS 的总体覆盖仍为 `partial`，仅内核处理的 direct/block/bypass 仍为 `none`，不开放 `full_transparency`。

每条 flow 的条件表达式使用与编译代次一起缓存的配置来源写法，GeoIP 保留引用而非展开后的网段列表。这避免了仅因展开而发生的截断，不取消真实捕获上限：原始配置文本超限、遮蔽、来源缺失及步骤/字节预算耗尽仍报告为 partial trace。

交接流量的内核规则结果来自编译程序实际执行的分支 witness，不做用户态重算。UDP 还必须使用收到报文携带的 capture ID；五元组、decision token、路由代次与动作均须匹配保留 witness，后来的同元组 incarnation 不能为旧报文提供证据。Capture ID 不回绕。冻结字典最多 16 份、每份 64 KiB、总计 1 MiB，计入 recorder 预留；字典拒绝/淘汰、witness 缺失、TCP 对应歧义及实际执行超出 256 个规则/条件值，都会使证据不完整；仅未执行的规则超出该值上限，不代表执行证据丢失。

原生扩展字段保留来源细节而不虚构身份：路由输入可携带 `ingress`、`domain_fact_bitmap`、`domain_fact_state`，不伪造 domain rule ID；DNS 关联的 outbound/connection step 带 `lookup_id`，已知物理对端带 `server_addr`。选择事实保留健康 IP 族以及实际应用还是仅 peek。Score 的 `previous_leaf_node_id` 与 `previous_member_id` 分开：叶节点历史不能重建过去经过的子组路径。

Flow list 接受 `network/state/connection_id/detail/limit/cursor`。最多八份有界不可变 snapshot，TTL 30 秒，游标绑定 instance 与原过滤器/detail。表满时淘汰最旧 snapshot；保留字节预算耗尽才返回 503 与 Retry-After。过期或被淘汰的列表返回 `410 snapshot_expired`，已知淘汰 ID 的有界 tombstone 返回 `410 flow_expired`，未知 ID 返回 `404 resource_not_found`。Detail 不接受 query，始终返回保留的 full input/trace。计数为十进制字符串，revision/seq/elapsed_us 为 safe JSON number；显示字段在 512 字节 `MAX_TEXT` 上限内保留路径、`@` 和 URL；标识符仍单独校验。无法表示或超限的文本、步骤/字节预算溢出仍明确报告为不完整证据，不丢弃因果 ID 或结果。保留的规则展示属于捕获时的代次，不从当前配置重建。

### 节点与组（M3）

节点读取接受 `group_id`、`limit`（1–1000）及 `cursor`；只筛直接成员，不展开叶节点。节点分页最多八份 snapshot、30 秒、4 MiB，冻结分页期间观测；无效或过滤器不匹配游标返回 400。Groups 返回摘要数组，detail 的带引号 ETag 对应仅由配置决定的 revision。组 ID 为进程生命周期随机身份：同名 reload/重排保持，删除再添加获得新 ID，重启重新发现；不使用位置 UUID 或名称 hash。

Health 来自已完成且维度明确的 producer 测量，不把乐观 alive、跨族复制的排名信号、synthetic failure 或恢复延迟当真实测量。Raw TCP、HTTP 响应头、DNS exchange、QUIC handshake 保留实际目标地址族与完成时间；未知 average/ranking/warmth 保持 null/unknown。自定义组测量保留当时 member/leaf，不绑定到后来的选择。GET 不推进 URLTest、轮询或 Score 状态；`icon` 原样返回通过配置校验的 HTTP(S)/data URI，未配置为 null，不猜测或抓取图标。

Selector selection body 为 `{"member_id":"直接成员 ID","network":"tcp"}`，network 必填且接受 `tcp/udp/both`。TCP 与 UDP 分开保存，`both` 一次校验并原子发布；自动策略拒绝手动选择。原生与 Clash 写入都由共同 control/reload owner 串行化，Clash 写入等价于 both，读取 `now` 是 TCP 投影。返回独立的 `selection_revision` 与实际 `connections_interrupted`，不将选择 revision 当作配置 ETag。启用 `interrupt_connections` 时，按流量建立时捕获的组身份/路径和发生变更的网络关闭旧 owner，而非按当前可达叶名称删除记录；已有选择不触发中断。关闭确认失败可能在选择已发布后报错，不承诺回滚。

组 PATCH 需要 `Content-Type: application/json-patch+json`、非空 RFC 6902 数组（最多 32 项）及 detail GET 的带引号强 `If-Match`；缺失 428、过期 412。仅允许 `/policy`、`/config/default_member_id`、`/config/final_outbound`、`/config/tolerance`、`/config/idle_timeout`、`/config/interrupt_connections`，支持 `add/replace/remove/test/copy/move`，其中路径和值类型均受上述字段约束。Policy 值如 `{"kind":"selector","native":"selector"}`，两者必须匹配；默认成员用直接成员 ID，final 用出站名称，tolerance/idle timeout 用非负安全整数。此接口不改成员列表或 icon。

PATCH 只修改 parser 定位的可写源片段，保留其他原文字节、注释与 include 结构；权限、完整离线校验、耐久替换与 operation 幂等复用 M6 源协调器。其 `If-Match` 是 accepted 组/配置 revision，**不是**文件 SHA-256：写前校验 revision，同时独立检查源字节 hash 和依赖拓扑，真实激活前还会在 reload lock 下再次检查 accepted revision。并发 provider publication 可在写后使激活被拒绝，此时 `written:true,committed:false`，磁盘不回滚。自动策略 pin/clear 仍受双网络 divergent/null 响应形状限制而关闭（`can_override=false`）。

### 原生事件（M4）

使用带 Bearer 与 `Accept: text/event-stream` 的 streaming fetch；浏览器 EventSource 不能设置所需 Authorization。可选 `kinds/flow_id` 绑定续传游标。最多保留 512 事件/60 秒，16 clients，每 client 64 条 live 队列；队满断流，不静默 skip。每 15 秒 heartbeat。Fresh 先 ready；有效续传 replay→ready→live，原子挂接不留空窗。过期、未知、旧 instance 或不同过滤器游标在 HTTP 200 前返回 `409 event_cursor_expired`。

实际发布 `stream.ready/runtime.updated/flow.updated/flow.gap/generation.changed` 及真实 operation 状态转换的 `operation.updated`；operation store 不依赖是否具有可写 `.dae` 来源。Generation 事件只来自已接受发布，不来自 reload 收件。事件仅含有界安全 ID/状态，不含包正文或原始配置。Flow/event 保留只在内存，不是耐久日志。

`flow.updated` 是失效通知：通过其 `href` 读取最新保留 revision。每个客户端的 live 队列只保留同一 flow 尚未发送的最新通知，并按新事件序号追加到队尾；revision 可以跳跃，但发送游标保持有序。发布仍是即时的，包括终态更新，不增加批量定时器。事件捕获开启时，重放环记录每次发布，replay 不做合并。其他事件类型和日志不合并；不同 flow 或其他不可替换事件仍会在 live 队列满时断流。Flow 数据、revision 与捕获的 trace steps 不变。

客户端已连接，或获准的记录器通过显式运行时设置持续开启时，事件捕获开启。空闲事件中心仍接受新流；停止捕获后，旧事件游标失效。事件开启时，手动或自动记录切换通过 `flow.gap` 的 `reason=recording_changed` 表示记录连续性中断，不表示丢包或未捕获的 flow 数量。空闲事件中心不重放关闭时的 gap；重新连接建立新的记录边界。

### 出站、内存与历史（M5）

`runtime/outbounds` 复用逐出站账本，不按 HTTP 客户端建立计数器。`kind` 区分 `builtin/node/group`，名称可能相同，不能只按 name 合并。累计连接、upload/download bytes 与 errors 保留完整 UInt64 十进制字符串；`active_connections` 为 safe JSON number。计数与 `counter_since` 属于共用 StatsManager 生命周期，reload 不清零。

RSS 来自 `/proc/self/status`；cgroup v2 依据实际 membership/mountinfo 定位，读取 `memory.current`、`memory.max` 与 `memory.events`。不可读取或未知的值为 null，不伪造零；`memory.max=max` 的 limit 为 null，cgroup scope 保持 unknown。Capabilities 只声明实际读到的 metric，`kernel` 为 null，不宣称内核内存核算，也不把 RSS、cgroup 和 kernel 相加。

`record_traffic` 与 `record_memory` 默认 true。两种 history 共用既有的一秒 sampler（错过 tick 使用 Skip），无客户端也记录；各最多 600 点、600 秒，仅存内存，重启清空。设 false 并重启后释放对应缓冲，history 返回 `404 capability_not_supported`，即时 runtime/outbounds/memory 仍可读。`max_points` 从最新点向前按能满足上限的最小 stride 抽取，再按时间从旧到新返回；`sampled_every_seconds` 表示该名义 stride，不保证无缺口。保留原始时间戳、null 与采样缺口，不插值或补零。

### 配置来源、校验与操作（M6）

只有真实 `.dae` 启动加载时捕获的源集合才启用配置管理；程序内构造的 Config 或 serde 格式加载不能冒充无损来源，其配置能力不可用。GET 返回最后已接受的快照，不临时重扫磁盘。源 ID 不含路径，源 `path` 与规则 `file` 保留规范化的入口目录相对名称（例如 `config.d/routing.dae`），源 `absolute_path` 另行提供规范化绝对路径；原文 SHA-256、字节数、加载时间与逐源 `writable` 单独提供。源集合与校验最多 32 个来源、8 MiB 原始字节，依赖的每次实体化也计入数量和字节预算；geodata 文件是引擎本来就整体加载的运行时资产，只参与哈希冲突检测，不计入预算；HTTP JSON body 的 64 KiB 上限仍独立生效，超限返回 413。

获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的配置数据。`config_content` 与 `writable_includes` 仍可配置，但不产生作用。已接受正文包含普通凭据、分享链接及路径；仅遮蔽声明的原生/Clash 监听凭据值，包括重复、被覆盖的声明及这些值在源中其他位置的出现。解析器提供的范围用于识别凭据值，非凭据文本与行结构保持不变。凭据源仍只读，哈希仍对应原始字节。必有的 `secrets_redacted` 布尔值表示是否遮蔽了监听凭据值；遮蔽后的正文不能作为可编辑的往返载荷。

启用 `config_write` 且 secret 非空时，已接受的非凭据主文件与所有非凭据 include 均可写。只有已接受的源 ID 授权替换，调用方提供的路径不能授权任意文件写入；generated/subscription 来源不可写。普通 include 仍使用原有入口相对 glob、排序、无匹配及重复/越界检查语义。API 禁止修改原生设置或改变、移动 API 凭据；如需编辑含凭据主文件，先在本地把凭据迁到专用只读 include 并重启，不能通过 API 完成迁移。

校验使用 `Content-Type: application/json`，例如 `{"mode":"syntax","sources":[{"id":"source-1","content":"..."}]}`；mode 可选 `syntax` 或 `full`，每个 source 的 id/path 可省略。`syntax` 只解析提交的文档，path 仅作来源标签，不授权文件访问，也不跟随磁盘 include。`full` 的首份文档对应入口主文件，额外路径须通过入口根目录授权；使用 overlay、获准本地 include、只读订阅缓存、实际本地 geodata/hosts/ECH 依赖做完整离线准入。从未拉取的订阅以 warning 准入、不产生缓存节点；已有 same-fetch 活动节点仍可 rebase。其他缺失或无效依赖是错误。校验不联网、不创建目录或改权限、不启动 worker、不发布 generation。完成的无效 dry-run 返回 `200` 与 `valid:false`；这不代替之后真实 reload 的运行时校验，也不承诺 reload 一定成功。

Full 校验先按 include 顺序合并，再判定有效配置语义。未进入实际 include 树的提交文档只检查结构（包含 lexer 恢复后保留的错误），其设置和告警不影响有效候选；其字节与源数量仍和每次依赖物化共用同一预算。

PUT 与校验 source 对象接受并忽略可选的回传布尔字段 `secrets_redacted`；其他未知字段返回 `400 invalid_request`。PUT 的 JSON body 为 `{"content":"完整的新原文"}`。`If-Match` 必须是**单个带双引号、含 64 个小写十六进制字符的 SHA-256 强标签**，可将读取到的 `content_sha256` 加双引号使用；它比较磁盘当前原始字节，不是 config revision 或 runtime generation。源 GET 仍是 accepted 快照，因此外部编辑后可能需要本地处理或显式 reload，而不是用旧快照覆盖磁盘。

| 写入条件/结果 | HTTP 语义 |
| --- | --- |
| 缺少 `If-Match` | `428 precondition_required` |
| weak、wildcard、多个标签/重复 header、非小写 SHA-256 | `400 invalid_request` |
| 磁盘 hash 或复查的目标/依赖变化 | `412 stale_revision`，检测到的外部内容不覆盖 |
| 候选配置或依赖校验失败 | `422 unsupported_value`，不写盘、不 reload |
| 未授权源、凭据或原生设置修改 | `403 permission_denied` |
| 操作容量或协调队列繁忙 | `503 temporarily_unavailable` 与 `Retry-After` |

协调器在副作用前预留 operation，串行处理 API 新写入和 SIGHUP，SIGHUP 也先入队再读盘。单源 overlay 完整校验后，采用目录 FD、拒绝符号链接的普通文件检查、独占临时文件、保留 mode、文件 fsync、目标与完整依赖集复查、原子 rename、目录 fsync。外部编辑器不受协调器约束，最后检查到 rename 之间仍有竞争窗口；UI 保存期间不要并行手工改同一文件。Rename 后若目录 fsync 失败，错误明确携带 `written:true,durability_confirmed:false`：可见内容已经改变，不表示未写或回滚。

PUT 仅在耐久写入并进入真实 reload 队列后返回 `202`；显式 POST reload 入协调队列后返回 `202`。响应含 `operation_id`、`href`、相同的 `Location` 与 `Retry-After: 1`，不表示配置已经生效。操作由 daemon 持有，HTTP 断连不取消它或其 supervisor reconciliation。可选 `Idempotency-Key` 绑定 principal、method、path、instance 与原始 body：同 key 同 body 的并发/重试共用结果，不重复写入或 reload，丢失首个 202 后仍可用原 If-Match 重试；不同 body 返回 `409 idempotency_conflict`。总共最多 32 个预留/保留操作，终态保留 300 秒，未过期记录不因容量提前淘汰；重启后不保留。

通过 GET operation、`runtime.last_reload` 及 `operation.updated` 读取真实结果，不能把收到 202 当作 succeeded。Reload 拒绝时保留旧 accepted 快照和 generation，但已写入字节不回滚；提交后 degraded 时保留新快照/generation 并报告 failed，而不是声称旧代仍活动。管理员应据磁盘内容与结果修复，再显式 reload。SIGHUP 本身不创建 API operation。仅改注释也会更新 source hash/config revision，但有效配置未变时不增加 runtime generation；有效组成员变化会改变 revision，健康测量变化不会。这三种版本不是可互换的并发令牌。

### 有界探测、DNS 与路由诊断

`POST /probes` 接受节点/组 target、`kind=tcp_connect|http|dns`、purpose、transport 数组、地址族与 `warmth=cold|warm`，不接受任意调用方 URL。组可选直接成员、叶节点或显式成员 ID；先固定当前配置/成员/注册代次，再去重执行并保留 member→leaf 关联。TCP-connect 测节点实际端口；HTTP 使用配置检查 URL，不跟随重定向；DNS 执行实际 UDP 或带长度帧的 TCP exchange。HTTP/HTTPS 默认仅端口 80/443，DNS 默认 53，额外端口需管理员 `probe_allowed_ports`；私网、loopback、link-local 等受限目标（包括节点地址）另需 `probe_allowed_cidrs`。解析后的地址规范化、校验并固定，不能以端口许可代替 CIDR 许可或交给代理重新解析。

每个 probe job 最多 64 个成员关联、256 行结果；最多 4 个 active、16 个 queued、每 target 1 个，准备/排队/测量共享 30 秒 deadline。最终 transport owner 清理即使超期也必须等待 join，因此 operation 总耗时可能超过 30 秒。每分钟 principal/global 均最多 30 次（当前只有一个 principal）；限流为 `429 rate_limited`，队列/owner 不可用为 503，均带正数 Retry-After。202 只表示 daemon 接管；断开 HTTP 不取消任务。结果保留真实 measurement/family/warmth/时间与 health 更新是否被当前 epoch 接受；过时代次、取消或 deadline 不伪造成 unhealthy，TCP-connect 不冒充 HTTP 排名样本。

`GET /dns/query` 必填 `domain`，`type` 默认 A，可重复指定最多 8 个不同类型；支持类型见 capabilities。一次请求的所有类型固定同一 DNS generation，共享 10 秒期限；每分钟 principal/global 各 30 次。`upstream` 只接受已配置名称，包括未被规则引用的名称；它替换请求路由选择，不绕过 hosts/strategy 或响应侧 requery。Hosts 命中报告 default route、无 upstream。`cache_mode=bypass` 不读正/负/stale 缓存，不写缓存，不加入普通写入 singleflight/refresh，也不启动后台刷新；不提供该选项时保留正常生产语义。

缓存 GET 只观察运行时 exact-key 正/负记录（`persistent:false`），不提升 LRU 或计入 hit。支持 `name` 精确名称、`domain` 子串、重复 `type`、`include_expired`、`detail`、`limit`（1–1000，默认 100）及 cursor；最多 8 份过滤器/instance 绑定的不可变快照、30 秒、合计 8 MiB，底层淘汰后快照占用仍计费。`entry_id` 标识精确 incarnation，旧 ID 不能删除替代记录；按 name 删除可跨 exact-key 变体并用 type 限制。删除/flush 与入库发布串行化，等待启用的持久化失效确认，旧 foreground/refresh 不能在确认后复活所删缓存；flush 不清空 DNS 路由投影。DNS query/cache/log 的完整 JSON 响应上限均为 262144 字节，不能完整表示或保留快照时返回 503 与 Retry-After，不裁剪 RRset 冒充完整答案。

名称、类型及过期筛选在快照字节准入和复制之前完成；未选中的缓存记录不消耗本次快照预算。负应答优先级和过期筛选使用同一个观测时刻。

获准访问的匿名 loopback 请求与 bearer 认证请求具有相同的规则读取和路由模拟权限。`POST /routing/trace` 仅支持 `resolve=none`，返回 `mode:simulation`；`live` 为 422。模拟固定当前 compiled router/config/generation，不查询 DNS、不探测、不推进组选择、不建立连接；缺失输入保留 `indeterminate/missing_inputs`，不能视为历史 flow 或真实转发承诺。上限为 1 个地址、256 个规则/条件 steps、5 秒和每分钟 principal/global 各 30 次。`GET /rules` 返回含 fallback 的完整当前字典，最多 4096 行，超限拒绝而不截断。规则 ID 与用户态捕获证据共用 generation-scoped 身份；真实 parser 来源可用时给出 `source_id/line/column`，file 与该来源的入口相对 `path` 一致，否则 source 为 null。历史 flow 不从当前字典重建，内核 final provenance 仍可为 unknown；编辑应使用 source ID，不猜私有路径。

对已接受 `.dae` 配置中的规则，包括含凭据来源的规则，`/rules` 与 `/routing/trace` 的规则 `expression` 保留编写时的条件值（包括 geosite/geoip 名称、否定和带引号参数），移除注释和出站子句。Trace 的逐条件表达式按实际编译后顺序以 dae 写法显示配置值，不加引号：普通域名候选与 geosite 分属不同条件，目标 IP 与 geoip 候选共用一个条件。监听凭据值仍被遮蔽；普通条件文本无需写权限即可读取，`config_content` 不产生作用。没有已接受来源元数据的规则显示编译后条件值，来源保持 null。编译后展示反映规范化的谓词，不等同于原始编写语法，也不展开 geodata。Trace 的展示元数据与决策固定在同一已接受代次。磁盘编辑只有在 reload 被接受后才更新两种响应；reload 被拒绝时保留旧表达式。历史 flow 保留各自代次捕获的有界编译后值，包括程序内构造路由器的值。

### Provider、日志与临时设置

获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的 provider 数据。Provider GET 不联网。订阅条目连接真实 SubscriptionSupervisor 观测与已接受节点的 `subscription_id`，`Node.provider_id` 可用于关联。订阅返回配置名称，`url_redacted` 返回完整 URL；为兼容客户端保留字段名。GET 与成功操作结果使用相同表示。未观测 usage/expiry 仍为 null。与旧 `provider-<id>` 标签相同的配置名称只是普通名称，不作为 ID 别名。从未加载、等待加载或禁用且无缓存时是 stale、零节点及 null 时间/错误；真实失败且无节点才是 error，保留旧/缓存节点时为 stale。列表 `limit` 默认 100、范围 1–1000，snapshot 上限 8 份/30 秒/4 MiB。启用且有运行 supervisor 的订阅可 POST refresh；同 provider 的不同并发 refresh 为 409，保留的幂等重放先于冲突检查。刷新成功须真实 revision-fenced publication 被接受，fetch 或写缓存不等于成功，HTTP 断连不丢失结果。虚拟 inline provider 不可刷新/删除；它关联 `provider_id: inline` 的静态非 builtin 节点，builtin 归属保持 null，订阅 ID 仍为 UUID。

`record_logs` 默认为 true，允许在客户端已连接时捕获日志，最多保留 512 条、60 秒。显式运行时设置 `record_logs: true` 可在无客户端时持续捕获；配置中的 false 禁止捕获，修改后需重启。实际记录停止时释放日志，续传游标失效。保留真实 timestamp/level/target；只有审查过的静态消息和有类型的安全字段可披露，其他 message/fields 明确 withheld，不靠正则猜测所有秘密，也不转发控制台或 Clash 格式化输出。`GET /logs` 以 SSE 返回 `stream.ready` 与日志，支持 level/target 过滤和绑定 stream/instance/过滤器的 cursor；与 `/events` **不同，续传顺序为 ready→replay→live**，ready 保留请求 cursor，之后才由 replay 推进。每 stream 最多 16 clients、每 client 64 队列、15 秒 heartbeat；过期 cursor 在 200 前返回 409，队满或 replay 丢失则断流。

`record_dns_log` 默认为 true，允许在客户端已连接时记录，最多保留 512 条、8 MiB。显式运行时设置 `record_dns_log: true` 可在无客户端时持续记录；配置中的 false 禁止记录，修改后需重启。实际记录停止时释放历史，已有游标失效。在真实客户端完成点记录普通 DNS 和有来源的客户端解析，排除原生/Clash 诊断与后台刷新重复项。仅存内存；完整 wire 与元数据一起计费，按整条旧记录淘汰。`GET /dns/log` 最新优先，支持大小写不敏感的 name 子串、type、无端口 src、limit（1–500，默认 100）及过滤器绑定 cursor；淘汰使相关 cursor 失效。停止记录不影响正常 DNS 服务。

`PATCH /runtime/settings` 使用 JSON 对象，仅合并 capabilities 列出的字段：`record_flows`、`record_logs`、`record_dns_log`（`true`、`false` 或 `"auto"`）、`log.level`（trace/debug/info/warn/error）、`log.buffered_records`（64–512）、`dns_log.max_records`（64–512）、`flows.max_flows`（64–1024）与 `flows.retention_seconds`（1–300）。未知、null、空对象、越界值，或对配置禁止的记录器修改级别、留存上限，均使整次请求返回 400，任何字段都不改变。通过校验后由一个 owner 原子发布，source 为 runtime；缩容淘汰旧记录并使受影响 cursor 失效。原生日志级别只影响该 capture layer，不修改控制台/Clash 过滤器。这些 override 不写 `.dae` 或 cache DB；每次成功的显式配置激活（含 no-op）恢复配置级别和初始留存上限，并将记录模式重置为 `"auto"`；provider/network refresh 保留运行时设置。

顶层记录字段中，`true` 使获准的记录器持续开启，`false` 强制关闭；初始模式 `"auto"` 对 flow 按诊断需求控制，对日志/DNS 日志按通用客户端连接状态控制。省略的字段保持不变；null 被拒绝。配置中的 false 禁止记录，运行时请求开启该记录器会使整次 PATCH 被拒绝。配置权限决定哪些级别和留存控制可用，与记录器是否暂时停止无关。

GET 和成功的 PATCH 响应包含只读 `recording`：`flows`、`logs`、`dns_log` 各含 `{allowed, mode, active}`，其中 `mode` 为 `"auto"`、`"on"` 或 `"off"`；`events.active` 表示事件捕获是否开启，`grace_remaining_seconds` 表示通用连接宽限期剩余秒数，不是独立的 flow 需求宽限期。读取设置不延长任何一个期限。

### 主文件条目与 geodata 管理（M9）

`resources.nodes.can_manage` 与 `resources.providers.can_manage` 要求来源协调器运行，且 accepted **主文件**可写、不含 API 凭据。创建节点提交 `{"name":"edge","link":"socks5://192.0.2.2:1080"}`；创建 provider 提交 `{"name":"feed","kind":"subscription","url":"https://example.net/sub"}`。严格 JSON 与 64 KiB 正文限制不变。复用引擎 parser、完整离线准入、FD 相对耐久写入及真实 reload；激活与订阅协调完成后才以 `201` 返回当前 Node/Provider 和 `Location`。HTTP 断连不取消已入队工作，不引入第二份配置数据库。

节点名为 1–64 字符，链接最多 8192 字符；provider 名为 1–64 个 ASCII 字母/数字/`_.-`，HTTP(S) URL 最多 4096 字符。重名返回 409，不支持的链接、身份或值返回 422。新 provider 即使有旧缓存正文，也从零节点、stale、无更新时间开始；相同 source specification 的延迟拉取状态在无关编辑、reload 和 suspend/resume 中保留，直到显式 refresh。修改该 specification 或重启恢复普通订阅启动行为。API 不创建 same-fetch 别名，歧义删除直接拒绝，不让 ID/节点悄悄转移。

DELETE 不接受 body/query。未知 ID 无写入地返回 `{"deleted":0}`，成功删除在激活后返回 `{"deleted":1}`；builtin、订阅派生节点、非主文件条目及不支持/歧义归属返回 `404 capability_not_supported`。静态 include 仍在 inline 下可见；固定客户端没有逐节点 writable 字段，因此显示的删除按钮仍可能被拒绝。仍被引用的条目须先修正引用，否则写前校验失败。编辑已有条目继续使用源 PUT，不新增 node/provider PATCH。

这些同步动作与源 PUT、Group PATCH、SIGHUP 共用协调器，检查 accepted revision、磁盘字节与依赖，但不锁住任意外部 editor。失败 details 包含 `stage`、`written`、`durability_confirmed`、`committed`；无法确认时为 null，不伪造 false。生命周期与运行失败为带 Retry-After 的 503，POST 重名冲突为 409；DELETE 的受限失败契约也将校验/冲突映射为 503。已耐久写入但激活被拒绝报告 written true/committed false，提交后降级报告 committed true，不承诺回滚。源 PUT 仍使用独立磁盘 hash If-Match，旧编辑器会在管理修改后得到冲突。

获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的 geodata。Geodata GET 按既有 router-before-config 锁序读取流量/DNS 保留元数据，不扫描磁盘、不联网；hash/大小属于已加载字节，不属于后来的磁盘外部编辑。未记录或不一致的修改时间为 null；`source_redacted` 保留字段名，在 GET 与成功操作结果中返回完整配置 URL，未配置来源才为 null。未使用资产不列出；互相冲突的已加载快照报告不可用，不任取其一。

更新需要 `config_write`、来源权威，以及为**每个已加载资产**配置 `geosite_download_url`/`geoip_download_url`。它们是需重启的管理员设置，不是请求参数。只接受最终直达 HTTP(S) URL，拒绝 userinfo、fragment、redirect 和 content encoding；HTTPS 验证证书，域名来源必须使用配置的数字地址 `global.bootstrap_resolver`，不回退系统 DNS。使用带 bypass mark 的直连 socket，不选代理 detour。一次更新最多两个各 256 MiB 的资产，共享 30 秒网络期限；校验、磁盘操作与必须等待的 owner join 不承诺硬总期限。

全部下载完成、解析并编译完整候选后才替换任何文件。目标只能是确切已加载文件，经无符号链接的父目录/文件 FD 打开，别名、字节/来源/依赖冲突和不安全路径均拒绝；父目录分量只在安全打开后做身份规范化。各文件独立原子替换并确认耐久，**不是多文件原子事务**；首个 rename 后失败保留逐资产 written/durability 信息，不自动撤回。真实 reload 在 no-op 与重建两条路径都使用不可变已验证 geo 快照，后续磁盘改动不能替换激活字节。成功结果来自实际发布的 GeoData；拒绝/降级仍失败并报告提交信息。重试前先修复磁盘冲突。

`POST /geodata/update` 不带 body；同键幂等重放先于互斥检查，不同的在途请求返回 409，operation 容量满返回 503。`202` 只代表 daemon 接管，不代表文件或路由已变更。相同内容可以 no-op 完成，不伪造 generation.changed。

### 内嵌 doona 来源

默认关闭的 `native-ui` 隐含 `native-api`，内嵌 doona `0.3.0`、提交 `9b0ae26b684fd997082ee9abd5c411d03662440d` 的真实产物、字体与 notices。`crates/honk-core/assets/doona-provenance.json` 记录源码/程序/字体包 SHA-256、构建身份及逐文件摘要；`doona-source.tar.gz` 保留对应 GPL-3.0-only 源码，位于 HTTP/内嵌目录之外。分发二进制/资产时须一并保留对应源码与 notices，不能只给接收者不可访问的私有上游链接。

复现时将源码包解压到独立目录，用 Node 22+、`pnpm@11.15.1` 运行 `pnpm install --frozen-lockfile`、`pnpm build`、`SOURCE_DATE_EPOCH=1789793083 pnpm package`。该 epoch 是固定上游提交的时间；源码包不含 Git 历史。`PATH` 中须使用 GNU tar 和 GNU gzip（已验证 tar 1.35、gzip 1.13）；其他 gzip 实现即使压缩相同 tar 字节，也可能产生不同包摘要。普通 Cargo 构建只使用已检入资产，不调用前端 build/下载。真实 checker 在该源码的 `tools/conformance.mjs`；live walk 只读，主动跳过控制、诊断和缺少已观测 ID 的资源。基础与管理契约应分别核对，浏览器动作另行验收；schema 通过不等于完整 UI、内核或部署矩阵通过。

### 共用模式与数据面生命周期

原生 `runtime_mode` 暂不可用：固定 PUT 契约未声明暂停冲突与 owner/backend 不可用的错误响应，capability 又不区分读写。GET/HEAD/PUT 均返回 `404 capability_not_supported`，不宣告接受任何 mode。内部共享的 `DatapathFlagsHandle` 及 Clash 控制仍保留；它不是 `dial_mode`，不覆盖 must/block 终态，也不合成网关规则。**仅 native 启用时**，mode/global target 是临时状态，不恢复或写入模式缓存；启动及成功显式配置激活（含 no-op）重置 rule，provider/network refresh 和 suspend/resume 保留。Global 绑定稳定身份，目标消失后新流量 fail closed，不回退普通路由或改投同名替代者。Native 未启用时保留原有 Clash 缓存行为。

显式激活的提交与模式 reset 是不同结果：若 routing/config 已提交但 backend mode 写入失败，settings 已恢复配置值，而 mode/source 保留先前值，控制面关闭准入并返回 committed-degraded，operation 失败。此时既不能声称 Rule 已生效，也不能声称配置回滚；通过 Clash `/configs`（启用时）与 operation 结果检查实际状态。正常 no-op 接受也触发 reset，provider/network 更新不触发。

Suspend/resume 经现有配置协调器和 control owner 串行执行；202 和 HTTP 断连均不代表终态。Suspend 先关闭 datapath admission、完成 NFQUEUE fence/held-verdict 排空，再关闭可见及尚未产生 ID 的 TCP、精确 UDP views、独立 DNS listener，并停止/join probe、健康检查、预热、订阅网络、协议后台任务和接口扫描。只有这些 owner 完成停止才报告 suspended；不是仅暂停健康探测。API、accepted 配置/来源、同一 GroupManager 的策略状态、mode/settings、计数、缓存与已有内存历史保留（仍受留存期限约束）。程序、maps 与自有 hooks 可继续加载/附着，但 closed admission 下 TC 放行，不代表数据面 active。

Resume 使用 accepted 内存配置与 artifact，不重读磁盘配置/geodata/hosts；保留 Selector/Fallback/轮询/Score 状态，重新绑定 listener、创建 fresh TCP/UDP/DNS/协议 transport owner，仍共享进程物理资源上限。重新检查真实拓扑、routing/listener/queue 就绪后才开放准入，不恢复旧连接或重放取消的数据。重复 suspend/resume，或已知暂停/转换状态下的新 probe/provider refresh、组变更与配置激活返回 409；owner 实际失败或不可用返回 503。DNS query 按固定端点契约，在所有不可用生命周期状态下均于联网前返回带 `Retry-After` 的 503。内存/缓存/历史读取仍可用，不涉及网络 owner 的 recorder settings 与缓存管理也可使用，并非一律禁止所有修改。安全清理完成的恢复失败保持 suspended；fence、队列或清理所有权不确定则进入 failed 并终止。若恢复已发布新代次后失败，operation 如实报告 committed/current generation，不声称旧代仍 active。

暂停不是硬时间上限承诺：已开始的阻塞系统解析/NSS 不能被 Tokio 取消，仍须等真实 join；清理阶段超期不能丢弃 owner 或宣称暂停成功。终止关闭不同于 suspend：关闭准入并停止 watcher、detach hooks 后，健康运行中的连接有默认 5 秒 drain grace，随后强制取消并 join；故障退出不承诺该 grace。原生 HTTP 自身另有 5 秒 graceful drain，上述阻塞 join 仍可能延长总退出时间。

## 启用与鉴权

仅当 `experimental.clash_api.external_controller` 非空，且二进制文件包含默认启用的 `clash-api` 特性时，API 服务才会启动。控制器地址必须是 `127.0.0.1:9090` 或 `[::1]:9090` 这样的数字套接字地址，不能使用 DNS 主机名；`:port` 会绑定 `0.0.0.0:port`。无效地址只会写入日志，不会停止引擎。

当 `experimental.clash_api.secret` 非空时，API 请求必须携带：

```http
Authorization: Bearer <secret>
```

WebSocket upgrade 也可以改用 `?token=<percent-encoded-secret>`。honk 会先对 token 做 percent-decode，再进行精确比较。query token 鉴权仅适用于 WebSocket upgrade；普通 HTTP 请求使用 Bearer header。`secret` 为空时关闭鉴权。`/ui` 静态目录位于 API 鉴权 layer 之外。

**API 自身不提供 TLS。** 应将其绑定到 localhost，或在前方部署 TLS reverse proxy；当不可信客户端能够访问 listener 时，必须设置强 `secret`。

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
| POST | `/cache/fakeip/flush` | cache database 存在时，清除持久化的 FakeIP 前缀条目。 |
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

手动延迟测量不会创建 Score exchange reporter。实际发生的前置 server/session 准备仍可报告聚合预热 setup 质量，但不会虚构业务结果或 URL 目标测量。

两个延迟接口都会持有已接纳的任务直到测量清理结束，即使 HTTP 客户端已经断开。owner 接纳失败的 `503` 响应会区分容量耗尽、检查已暂停或停止，以及 worker 失败。QUIC 探测超时或正常关闭等待属于测量结果，不代表健康检查 owner 失败：有限的对端通知宽限期结束后，会停止并 join packet-adapter worker 和 Quinn driver。真正的受管 worker 失败仍会关闭健康检查接纳。

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

设置 `experimental.clash_api.external_ui` 以提供静态 dashboard 目录。目录缺失或为空时，honk 会在后台下载 ZIP；启动不会等待，文件可用前静态路由返回 `404`。`external_ui_download_url` 会替换内建 zashboard URL，`HONK_UI_DOWNLOAD_URL` 则保持最高覆盖优先级。

每次下载请求（含重定向）只接受 HTTP(S)，最多跟随五次重定向，下载的 ZIP 正文上限为 128 MiB。允许 HTTPS 降级到 HTTP，也允许 URL 直接使用 IP 地址；每一跳仍遵循路由或指定的 `external_ui_download_detour`。

非空 `external_ui_download_detour` 会强制初始请求和 redirect 都经过该节点或组。该字段为空时，每个 URL 遵循 honk 当前的流量路由决策：`direct` 使用直连 HTTP client，`block` 中止下载，proxy 结果使用选中的出站叶节点。每次直连或经代理且实际经过 Score 组的 HTTP exchange，都会向路径经过的 Score 组报告真实 host/IP、端口、setup、首响应、字节与终态；其他路径不创建评分 reporter 或 cell。下载或解压失败只写日志，不会停止引擎。

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
    groups: [{ name, tcp: R, udp: R }],
    cache: { exactCells, aggregateCells, exactEvictions, aggregateEvictions }
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
  incumbentHeld, insufficientEvidenceHeld, incumbentIneligible,
  freshFailureBypass, deadFiltered, ordinarySwitch, switchFlap,
  failStreakExcluded, exploreBackedOff, carrierPressure, carrierRttPressure,
  carrierLossPressure, carrierValidation
} // R 的每个值均为 u64 计数
```

### TCP 字段

| 字段 | 含义 |
| --- | --- |
| `activeFlows` | 当前持有 TCP admission permit 的透明 TCP 流。 |
| `limit` | 当前进程级 TCP 流准入上限；从描述符导出的 floor 开始，并随空闲描述符余量动态扩缩。 |
| `capacity.rejected` | 因 TCP 预算已满而等待 permit 的 accept-loop 单调计数；accepted socket 保留在内核 backlog 中，不会被丢弃。 |

### QUIC 字段

`srttUs`、`cwndBytes`、`currentMtu`、`receiveWindowBytes`、`receiveWindowAvailableBytes`、`streamReceiveWindowBytes`、`sendWindowBytes` 和 `sendWindowAvailableBytes` 是活动连接的平均值；没有活动连接时为零。`flowReceivedBytes` 统计已交付给应用的 stream 字节，`flowSentBytes` 统计已被对端确认的 stream 字节；与报文、UDP 字节、I/O、丢包、黑洞和拥塞计数一样，它们包含已完成的池化连接。

池化 TUIC、Juicity 与 Hysteria2 连接每秒采样一次 flow-control 状态。收发方向的十秒 goodput EWMA 必须在 RTT 至少 80 ms 且连续三个样本确认高 BDP 后，才会把 connection 接收或发送 floor 提高到约 `2 x BDP`。peer 发来的 `DATA_BLOCKED` / `STREAM_DATA_BLOCKED` 是窗口成为瓶颈的直接证据：不受 RTT 门限限制，直接把 connection 或 stream 接收 floor 加倍——窗口压流时 goodput 估计值本身也被压扁，无法用作升档依据。零进展样本只有在对应 connection credit 仍受压时才会保留但不推进 streak。每个 floor 独立执行五分钟升档冷却，自动升档最大为 32 MiB，但不会降低更大的显式配置。honk 不会因应用需求低而缩小已学习窗口，也不会热切换拥塞控制。

`ackFrames` 统计收到的 ACK frame，是路径进度信号；重复 ACK frame 可能被重复计数。`lossRatePpm` 排除 PLPMTUD 探测：分母为 `sentPackets - sentPlpmtudProbes`，而 `lostPackets` 同样不包含探测丢包。`sentPlpmtudProbes` 与 `lostPlpmtudProbes` 单独暴露探测计数。`txIos` 与 `rxIos` 表示批处理效率。`transportTxWouldBlock` 统计满载的 64 包 adapter 队列（Quinn 会重试）；底层代理报告拥塞或超时后主动丢弃的报文计入 `transportTxDrops`；满载的 adapter 接收队列计入 `transportRxDrops`，满载的 TUIC/Hysteria2 256 包会话队列计入 `sessionRxDrops`。`sendTimeouts` 与 `pathStalls` 是进程生命周期内的恢复事件。

### Score 选路原因字段

`score.groups` 是经鉴权 `/stats` 响应中的附加部分。当前没有任何组使用 `policy: score` 时它为 `[]`；否则它包含每个当前 Score 组（包括没有解析出叶节点的组），按 `name` 的字典序排列。每组始终都有 `tcp` 和 `udp` 对象，且每个对象始终包含全部 `R` 字段；没有网络活动时以零表示，绝不省略字段。

每个值是饱和 `u64` 计数，不是延迟、吞吐或健康测量。一次已授权的多候选 Score Apply 记录一个最终原因：`coldExplore` 或 `periodicExplore` 表示验证；`incumbentIneligible` 表示现任已不满足普通资格；`freshFailureBypass` 表示合格现任的业务失败尚未恢复；`insufficientEvidenceHeld` 表示没有挑战者获得晋升且普通 utility 赢家缺少双方合格的性能比较；`incumbentHeld` 表示比较优势未跨过保持门槛；其余 `reliabilityWinner`、`performanceWinner` 保留按替代候选资格分类的含义。`performanceWinner` 不证明提速或发生切换，`insufficientEvidenceHeld` 不表示可靠性历史缺失。`ordinarySwitch` 统计实际普通已提交 A→B 选择；`switchFlap` 统计其中同目标八次普通选择内返回前一赢家的情况。首次选择、试用及缺少之前历史时不能增加切换计数。`deadFiltered`、`failStreakExcluded` 和 `exploreBackedOff` 按 rank 累计受影响候选。Peek、API 读取、单例与最后尝试旁路不增加这些计数；嵌套组 rank 与实际出站连接并非一一对应。

对 UDP，`deadFiltered` 也统计因协议／配置不具备 UDP 能力而被排除的候选；它不是新发生故障的节点数或业务尝试数，这类排除不会增加 Score 失败或探索退避。

`carrierPressure` 统计被已有组／网络聚合 cell 接收的新鲜 carrier 地址族事件，不是包数或失败连接数；重复心跳读取不增加它。`carrierValidation` 统计普通赢家具有晚于上次验证的 carrier 提示时发生的周期验证选择；它是可重叠的诊断计数，不是新的互斥原因，也不证明只有该提示导致选择。提示不改变业务可靠性、资格或健康。字段在 API 读取时只读；carrier 观测由控制心跳接入，与选路调用独立。

`carrierRttPressure` 与 `carrierLossPressure` 保留被接收事件的原因。两种条件同时满足时，两个原因计数均增加，但 `carrierPressure` 只增加一次。这些可重叠计数不标识具体 carrier／传输协议，不是应用丢包率，也不增加失败；重复或过期提示均不增加它们。TCP 的 loss pressure 表示重传压力，不代表已确认应用包丢失。

计数在进程启动时从零开始，只在进程内存中累积。只要组名仍在已提交配置中，成功 reload 会保留它们，包括零叶节点以及临时 Score→非 Score→Score 转换；非 Score 组不会显示在此响应中。已提交的删除会清除该名称的计数，之后重新创建同名组从零开始。受 generation fence 约束的已淘汰 manager 在被替换后不能再修改计数，即使同名组随后被重新创建。快照在 JSON 序列化前复制，读取不会改变选路状态。

`/stats.score` 公开组名、固定的 TCP/UDP 原因与验证计数，以及有界证据缓存的占用/淘汰数，不包含节点身份、目标/domain/IP/port、原始 cell、cadence 键、authority 或凭据。`/proxies` 中既有公开成员名和 `/connections` 中目标元数据保持不变。

### Score 验证信息

`/proxies` 与 `/proxies/{name}` 中的 Score 组增加 `scoreVerification`。固定目标为 `responseQualityWithAvailability`，范围为 `aggregate`，不是对每个精确目的地的认证。`tcp` 和 `udp` 分别包含：

| 字段 | 含义 |
| --- | --- |
| `selected` | 本次只读判定对应的既有公开成员 tag；没有普通合格候选时为 null。存在时 TCP `now` 使用同一次判定的选择。 |
| `state` | `provisional` 或 `observedUsable`；后者要求同一连续可用性 cohort 中四个不同的定向 Traffic reporter 在 setup/TX 后收到 RX，且 cohort 最近的合格 RX 距今不足 60 秒。未结束的 flow 也可取得资格；clone／重复回包不增加信用。失败／reload 或 60 秒进展间隔会重置 cohort。这不授予普通选路资格，也不清除连败。 |
| `comparison` / `basis` | `unconfirmed`、`equivalent` 或 `supported`，依据为 `none`、`configuredProbe`、`targetResponse`、`aggregateResponse`、`upload` 或 `download`。不代表误判概率或保证最优。 |
| `missing` | 相关候选覆盖范围内的 availability/response/transfer 布尔缺口；当前路径已观测可用时，备选仍可能需要验证。 |
| `nextAction` | `nextBusinessFlow` 仅在共享预算允许时使用未来真实流量，补充证据、普通选路资格或恢复验证；`awaitTransfer` 等待真实负载，不主动大流量测速；`backoff` 保留失败隔离；`none` 表示没有可执行的缺失工作。 |
| `coverage` | 候选、已比较与待确认数量；即使 availability/response 缺口已关闭，pending 仍可包含普通资格／恢复工作。单节点可以证明已观测可用，不代表优于其他路径。 |
| `evidenceAgeMs` / `validForMs` | 最弱支持证据的年龄与条件性剩余有效期；没有结论时为 null。新证据可以提前撤销结论。 |
| `network`、`targetFamily`、`healthFamily`、`targetSpecific` | transport 与适用范围；此聚合接口没有精确目标，不导出 domain/IP/port 或原始节点 ID。 |

`/stats.score.groups[].verification.tcp` 与 `.udp` 增加饱和计数：`provisionalSelections`、`usableSelections`、`validationSelections`、`confirmations`、`expired`、`contradicted`、`confirmationMillis`。确认计数包括新成立的配置探测比较等经验性结论，不表示所有维度的业务或带宽认证；`confirmationMillis / confirmations` 是这些结论的累计平均确认耗时，不是网络延迟。只读查询立即反映过期，转移计数只在后续授权 Apply 时推进。没有流量或预算不能授予确认；查询不派发验证，也不改变计数。10% 比较容差表示实际意义上的近似等价，不是已校准的误判概率。

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
