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

已知限制：[`h2` 0.4.19 可能把缺少 `:status` 的响应报告为 200](https://github.com/hyperium/h2/issues/958)，因此这种畸形 HTTP/2 响应仍可能得到成功的延迟结果。该依赖修复已明确延期，等待上游处理，不使用本地 fork/vendor 补丁。

成功测量会更新节点延迟历史。单节点失败返回 `503`；组测量会省略失败成员；两者都会追加供 URLTest 选择使用的 failure strike。

每次经代理或内建 `direct` 叶节点执行、并实际经过 Score 组的 delay-test exchange，都会把真实 URL 目标及成功或失败反馈给包含该被测叶节点的每个 Score 组。之前仅连接 server/session 的预热只报告聚合 setup，不会把该 URL 虚构为预热自身的目标；非 Score 路径不会创建 reporter 或评分 cell。

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
  incumbentHeld, freshFailureBypass, deadFiltered, switchFlap,
  failStreakExcluded, exploreBackedOff
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

每个值都是饱和的 `u64` 计数，不是延迟、字节、时长、目标或健康度量。前六个字段按固定优先级分类一次已授权的多候选 Score **Apply**：初始预算探索为 `coldExplore`；周期上置信界非现任为 `periodicExplore`；成功保持现任为 `incumbentHeld`；只有新鲜失败证据打破已训练且效用差距很小的保持条件时为 `freshFailureBypass`；所有备选均在所选可靠性带之外时为 `reliabilityWinner`；其余为 `performanceWinner`。`deadFiltered` 独立计数活性过滤移除的唯一叶候选。`switchFlap` 独立计数已提交胜者在八次选择内切回前一胜者；有意的冷探索和周期探索不改变这段后悔窗口。`failStreakExcluded` 按每次已授权 rank 累计被三连败新鲜失败门排除的候选数，`exploreBackedOff` 累计当前处于探索退避的候选数。Peek、`/proxies`、`/stats`、单例旁路和最后尝试选择均不计数。

计数在进程启动时从零开始，只在进程内存中累积。只要组名仍在已提交配置中，成功 reload 会保留它们，包括零叶节点以及临时 Score→非 Score→Score 转换；非 Score 组不会显示在此响应中。已提交的删除会清除该名称的计数，之后重新创建同名组从零开始。受 generation fence 约束的已淘汰 manager 在被替换后不能再修改计数，即使同名组随后被重新创建。快照在 JSON 序列化前复制，读取不会改变选路状态。

`/stats.score` 只公开组名和 TCP/UDP 的二十个聚合计数，外加一个 `cache` 对象，给出两个 4,096 项证据 LRU 的当前 cell 数（`exactCells`、`aggregateCells`）与累计淘汰数（`exactEvictions`、`aggregateEvictions`）。它绝不包含节点、节点 ID/tag、目标/domain/IP/port、目标地址族、评分 cell、cadence 键、manager authority、凭据或其他 scorer 私有值；这些值也不会进入新的 Score 日志或持久化。此新增内容不改变 `/proxies` 或 `/stats.outbounds` 中既有的节点名，也不改变 `/connections` 中既有的目标元数据。

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
