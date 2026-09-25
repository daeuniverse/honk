# Clash API 与 `/stats` 参考

本文档说明 honk 已实现的 Clash 兼容 HTTP 接口及其用户态统计快照。

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

成功测量会更新节点延迟历史。单节点失败返回 `503`；组测量会省略失败成员；两者都会追加供 URLTest 选择使用的 failure strike。

按需 delay exchange 保留 Alive/API 延迟历史，但不报告业务结果，也不填充配置 Score 比较 cohort。实际的前置 server/session 准备可报告聚合预热 setup；不会把调用方 URL 虚构为预热自身目标，也不提供晋升证明。

### Score 组表示

配置为 `policy: score` 的组始终可用，并为兼容 Clash 表示成 `type: "url_test"`。其 `all` 列表与其他组一样保留直接成员 tag，`now` 则报告当前聚合 TCP 胜者，而不是泄露某个精确目标的私有选择。Score 始终保持自动且权威：`PUT /proxies/{name}` 会被拒绝，不会固定成员。评分 cell 与仅由 scorer 持有的目标数据不会新增到 proxy 文档；`/stats.score` 只包含下文的安全聚合计数。`/connections` 只保留原有的目标元数据。

## 模式与 Selector 修改

`PATCH /configs` 接受如下 JSON 对象：

```json
{"mode":"Global"}
```

模式更新经过 `DatapathFlagsHandle`；它是 shared mode 与 `DATAPATH_FLAGS_MAP` 唯一的串行化 writer。因此模式修改会与 reload 的 NFQUEUE fence、reopen 和 disable 操作原子组合，不会重新发布过期的 readiness bit。规则派生的 feature bit 属于不可变的路由 policy descriptor。启用 cache database 时会保存规范化后的模式。

`PUT /proxies/{name}` 不要求特定 `Content-Type`。对已配置的 Selector 组，目标必须是直接成员 tag；只能经嵌套组到达的叶节点并非直接成员。选择确实发生变化时会调用 group manager 的 cache callback，因此启用 `cache_file` 后会把选择持久化到 `cache.db`。若该组设置了 `interrupt_connections`，honk 会移除与该组、其成员 tag 及可达叶节点关联的已跟踪连接，使后续流量通过新选择重新拨号。写入已有选择不会触发操作。URLTest、LoadBalance、Fallback 及 Score 组都会拒绝该修改。

`GLOBAL` 是合成 Selector，但其 `all` 中每个成员都是具体的已配置组或节点，并有对应的顶层 proxy 文档。`PUT /proxies/GLOBAL` 只接受其中的名称，并通过同一个 `DatapathFlagsHandle` 更新；启用 cache database 时以 `GLOBAL` Selector key 保存。空值、已移除、未知及旧虚拟选择都会回退到第一个具体成员。

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
} // R 的每个值均为 u64 计数
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

池化 TUIC、Juicity 与 Hysteria2 连接每秒采样一次 flow-control 状态。收发方向的十秒 goodput EWMA 必须在 RTT 至少 80 ms 且连续三个样本确认高 BDP 后，才会把 connection 接收或发送 floor 提高到约 `2 x BDP`。peer 发来的 `DATA_BLOCKED` / `STREAM_DATA_BLOCKED` 是窗口成为瓶颈的直接证据：不受 RTT 门限限制，直接把 connection 或 stream 接收 floor 加倍——窗口压流时 goodput 估计值本身也被压扁，无法用作升档依据。零进展样本只有在对应 connection credit 仍受压时才会保留但不推进 streak。每个 floor 独立执行五分钟升档冷却，自动升档最大为 32 MiB，但不会降低更大的显式配置。honk 不会因应用需求低而缩小已学习窗口，也不会热切换拥塞控制。

`ackFrames` 统计收到的 ACK frame，是路径进度信号；重复 ACK frame 可能被重复计数。`lossRatePpm` 排除 PLPMTUD 探测：分母为 `sentPackets - sentPlpmtudProbes`，而 `lostPackets` 同样不包含探测丢包。`sentPlpmtudProbes` 与 `lostPlpmtudProbes` 单独暴露探测计数。`txIos` 与 `rxIos` 表示批处理效率。`transportTxWouldBlock` 统计满载的 64 包 adapter 队列（Quinn 会重试）；底层代理报告拥塞或超时后主动丢弃的报文计入 `transportTxDrops`；满载的 adapter 接收队列计入 `transportRxDrops`，满载的 TUIC/Hysteria2 256 包会话队列计入 `sessionRxDrops`。`sendTimeouts` 与 `pathStalls` 是进程生命周期内的恢复事件。

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
| `waitReason` | `none`；`budget` 表示没有可用额度；`comparableTraffic` 等待未来可比业务；`inFlight` 表示已有足够的同目标工作，或已达到独立的每节点四项工作上限；`backoff` 保留失败隔离。聚合读取检查已保留 IPv4/IPv6 作用域，不创建它们：两者预算均阻塞才返回 `budget`；任一可用／未创建作用域允许继续等待未来可比流量；其余情况保留在途等待。等待不证明工作必然成功。 |
| `coverage` | `scope`（`all` 或 `bounded`）、`candidates`、`evaluated`、`unevaluated`、`pending` 数量。评估成员由显式有界身份决定，跨过滤视图也不例外。未评估成员不参与比较。`pending` 统计仍有未决问题的已评估成员，包括已有比较但仍需资格或恢复工作的成员。 |
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
| `businessStarts`、`scopes`、`earningPeriod` | 保留作用域原始开始数之和、作用域数，以及固定赚取周期 `q = 16`（尚无作用域时为 0）。它不能作为合并作用域预算公式的分母：每个作用域在创建时固定冷启动额度 `B`；`spent + reserved <= B + floor(businessStarts/q)` 按作用域成立。 |
| `sources.cold`、`sources.periodic`、`sources.recovery` | 按来源区分的已开始工作：冷额度试用、已赚额度试用、不增加可选额度的延续尝试。`recovery` 包含 TCP 替代、DNS 改路／UDP 转 TCP 和 UI 重定向，不限于出错后的重试；它既不是可选试用，也不是新原始业务。普通非试用没有来源桶。 |
| `trialStarts`、`spent`、`reserved` | 已开始可选试用、累计已支出 token，以及尚未开始的 token 预留。开始只支出一次，开始后取消不退款。 |
| `coldAllowance`、`coldAvailable`、`earnedAvailable` | 固定初始额度与当前可用额度的合计。每作用域最多保留八个未花费已赚 token。时间、读取、目标变动与证据过期不赚额度，保留作用域在 reload／成员变化后不重置。 |
| `budgetBlocked`、`inFlightBlocked`、`refunded`、`expired` | 预留被拒计数、最后引用释放／未开始失效的退款数，以及在途跟踪项过期数。只有未开始预留可退款；跟踪过期不退回已开始工作的支出。 |
| `trialSuccess`、`trialFailure`、`trialCancelled` | 已开始可选试用的 exactly-once 终态；拒绝／关闭／中性取消归入 `trialCancelled`。`trialFailure` 是实际观测失败，不是相对于未观测替代路径、因选择试用而额外造成的失败。 |
| `trialSetupHistogram`、`trialSetupMillis`、`trialElapsedMillis` | 八个固定 log2 毫秒 setup 桶（slot 0 包含 0–1 ms，末槽包含 128 ms 及以上）、已观测 setup 时长之和，以及开始至终态时长之和。它们是实际试用成本，不是因果额外延迟或开销。 |

`/stats.score.cache.comparisonCells` 上限为 256。`comparisonLogicalBytes` 计入比较存储、vector 容量及所持有键容量；`comparisonLogicalCapacity` 是按实现结构大小计算的最坏分配界限，不超过 1 MiB。两者均不是实测进程 RSS 或全部 Score 状态大小，均不包含分配器开销与进程其他分配。`comparisonEvictions`、`comparisonExpired`、`comparisonRejected` 统计存储移除／准入事件；只读过期可以先使支持失效，实际移除后才增加计数。既有精确／聚合 LRU 字段不变。

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
