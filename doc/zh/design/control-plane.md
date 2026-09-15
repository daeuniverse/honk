# 用户态控制平面

本文描述位于内核数据路径与出站栈之间的 `honk-core` 用户态引擎。

## 范围

控制平面负责透明代理入口、消费内核交接、用户态路由、嗅探、出站选择、中继、资源准入与运行时发布。向用户态交付流量的内核机制见[数据路径设计](./datapath.md)。组策略和健康状态驱动的选择见[组设计](./groups.md)，DNS 运行时行为见 [DNS 设计](./dns.md)。

主要实现在 `crates/honk-core/src/control/`。它消费 `EbpfBackend` 状态，并把 TCP 流或 `PacketTransport` UDP 契约交给 `honk-outbound`。

## 启动与关闭

配置诊断在初始化 tracing 前收集。加载或配置校验提前失败时，先向标准错误输出已有的非终止诊断，每条仅输出一次，再由二进制程序返回一次脱敏后的终止错误。加载成功时，诊断延迟到配置指定的 tracing 订阅器就绪后输出。后续运行时致命错误仍保留原有的日志文件记录。

启动时保持内核准入关闭，直到用户态能够接收每个重定向流：

1. 加载并校验配置、选择 `global.data_dir`，提升 `RLIMIT_NOFILE`，并取得一次不可变的描述符预算快照。
2. 在网络刷新前恢复持久化订阅。只有没有有效已恢复正文的订阅才参与五秒首次拉取宽限期。
3. 选择后端。真实模式取得 `/run/honk-core.lock`，并把进程 PID 发布到已锁文件；`honk-core reload` 读取该 PID 并发送 `SIGHUP`。Mock 模式不取得进程全局锁。
4. 真实实例完成锁交接后，再探测固定 NFQUEUE 队列前置条件。mock/不带 `ebpf` 的模式或前置检查失败时记录 warning，仅在本进程关闭 NFQUEUE；前置检查不会拒绝保留的 nftables table，因为安装阶段会回收残留的自有状态。
5. 在真实模式下，通过 rtnetlink 创建由 FD 持有的 `daens` 命名空间和 `dae0`/`dae0peer` 链路。引擎优先尝试 L2 netkit pair，仅在内核报告不支持 netkit 时回退到 veth。进程留在宿主命名空间；只有同步的 socket、链路和挂载操作通过有作用域的 `setns` 调用进入 `daens`。
6. 加载 BPF 对象并挂载真实数据路径。默认对象通过 `include_bytes!` 嵌入；`--bpf-object` 提供运行时覆盖。启用 `ebpf` feature 时，`build.rs` 定位对象，拒绝过期或无 BTF 的产物，在移除继承的 `RUSTFLAGS` 和 `CARGO_ENCODED_RUSTFLAGS` 后用 nightly 重建，校验 `.BTF`，再复制到 `OUT_DIR` 供嵌入。
7. 复用或创建固定的 `UDP_DECISION_SEQUENCE` 分配器，并校验其 map ABI、BTF、加锁值、token 范围与耗尽状态。NFQUEUE 启动时再次检查加锁的分配器状态；若没有回滚安全的 generation，则保持暂存关闭。
8. 构建用户态 Router、出站运行时 registry、DNS 运行时、GroupManager、cache DB、可选 Clash API 和控制平面 supervisor。
9. 绑定透明 TCP/UDP listener，发布完整 listener FD 集，启动独立 DNS 和 UDP 接收循环；仅当生效开关仍开启时，才启动 NFQUEUE 服务及其 ingest actor、correlator、watchdog 和统计采样器。
10. 检查 NFQUEUE 健康状态，发布其 ready 状态，开放 pending verdict 准入，最后把 `DATAPATH_STATE_MAP[0]` 设为 ready。随后 TCP accept loop 在控制面 supervisor 中运行。
`RealEbpfBackend` 负责 aya program、map、link、持久分配器处理和真实 NFQUEUE 集成。`MockEbpfBackend` 在没有特权内核资源时提供相同控制面接口。请求的 NFQUEUE 路径无法通过锁交接后的固定队列前置检查时会记录 warning 并关闭；服务准入后的失败仍为 fatal。

关闭时在资源消失前逆序释放所有权：fence NFQUEUE、关闭数据路径准入、拒绝新的用户态工作、取消并排空持有的 verdict 和 UDP initializer、停止 UDP driver 和 removal 处理、停止接口 watcher、卸载 BPF hook、最多用五秒排空已接受流、退役出站运行时、停止 NFQUEUE、停止 DNS controller 和 persistence，并清理 generation 持有的 BPF 状态。普通清理保留固定分配器。随后 listener 和 `daens`/link-pair 所有权离开作用域。

## 透明代理入口

真实 TCP 和 UDP listener 在 `daens` 内创建，并设置透明 socket 选项和 `DAE_BYPASS_MARK` (`0x100`)。该 mark 使数据路径把它们识别为 honk 自己的 listener，而不是普通本地服务。已接受 TCP socket 会继承 mark，因此每个 accept loop 在处理流前将其清零。Mock listener 是宿主命名空间内不带特权透明选项的普通 socket。

原始目的地址按下表恢复：

| 入口 | 首选来源 | 回退 |
| --- | --- | --- |
| TCP/IPv4 | `SO_ORIGINAL_DST` | 透明 socket 的 `local_addr()` |
| TCP/IPv6 | `IP6T_SO_ORIGINAL_DST` | 透明 socket 的 `local_addr()` |
| UDP | `IP_RECVORIGDSTADDR` / IPv6 original-destination cmsg | 下文所述的受约束 provenance 规则 |

形成规范 tuple 后，普通非 DNS 流通过 `routing_handoff_take` 消费 `ROUTING_HANDOFF_MAP`。没有 handoff，或出站为 `ControlPlaneRouting` 时，回退到 `Router::route_with_must`。最终的 `must` 和 `block` 结果不能被 Clash mode 覆盖。

端口 53 的控制器与原始转发归属遵循[有序流量规则契约](../reference/routing.md#出站目标与-must)，包括畸形非 `must` UDP 的通用回退。

真实透明 UDP/53 无论归控制器还是原始转发，都要求有效的逐报文 `SO_RCVMARK` / `SOL_SOCKET` `SO_MARK` 凭据及当前已提交路由代际，tuple handoff 不能替代。透明 TCP/53 必须有 SYN handoff；只有原始 `must` TCP 还要求当前路由代际，并在原始 I/O 前固定配置、语义分组与出站 runtime。非 `must` TCP 保留控制器查询准入，不执行该路由代际检查。缺失必需元数据或必需的代际检查失败时，在 I/O 前拒绝准入。物理兼容性见[handoff ABI 与 UDP 携带位](./datapath.md#map-清单)。

## 嗅探与流初始化

TCP 嗅探最多读取 4096 字节，并提取 TLS SNI 或 HTTP `Host`。返回的缓冲区属于流状态，并在中继开始前写入已选出站，因此嗅探不会消费应用数据。`dial_mode: ip`、最终的 direct/block 或 `must` handoff，或命中 TCP negative cache 时跳过 TCP 嗅探。连续三次失败会抑制同一目的地址/出站签名十分钟；嗅探成功会移除 negative 条目。

UDP 域名发现解密 QUIC v1/v2 Initial packet，重组 CRYPTO fragment，并解析 TLS ClientHello SNI。每流 session 五秒过期，最多检查八个 Initial packet，并把 CRYPTO stream 限制为 64 KiB。首个 ClientHello 分片时，initializer 最多保留八个 FIFO follower，最多等待 250 ms。failed-DCID cache 限制对非 QUIC 或不可解密流量的重复工作。

`dial_mode: domain` 对嗅探到的 TCP 或 QUIC 名称执行 DNS reality check。目的地址同族答案精确匹配时接受；只有另一地址族答案时，为兼容双栈仍保留该名称。同族不匹配、查询失败或超时时丢弃嗅探名称并按 IP 继续。

`connection/` 是每流 route/sniff/mode/selection 的规范边界。Socket UDP 入口与 NFQUEUE 持有的 payload 都在同一个 `UdpEndpointPool` 中预留相同的 `UdpInitLease`；NFQUEUE 没有第二套 Router、dialer 或 packet replay 路径。暂存流在 token 校验的终态转换前计算唯一最终出站与 mark。

`build_tuples_key` 必须用 `mem::zeroed()` 初始化 `TuplesKey`。这个 `#[repr(C)]` key 在 40 字节布局中只有 37 字节字段，内核会散列包括三个 padding 字节在内的全部 40 字节。因此逐字段初始化可能产生用户态无法可靠查询或删除的 key。

权威单候选 TCP 的 transport 失败只重试一次，且重新解析必须提供有效替代项。URLTest 使用 target-aware retry plan 中按延迟排序的前三个候选；Score 记录失败、重新评估精确目标，只重试不同的替代节点。本地 typed refusal 是终态，包括排空竞速任务时发现的已完成拒绝；其他策略或真正的单叶结果不重试。

## UDP endpoint 流水线

### 目的地址 provenance

`udp_ingress.rs` 负责目的地址校验和有界准入，`sockets.rs` 负责 syscall/cmsg 解码。真实透明监听必须具有权威 ORIGDST；普通/mock 监听保留以下回退规则。所有路径都在 endpoint 预留前拒绝无效元数据：

1. 存在、有效且已指定的 ORIGDST cmsg 具有权威性。未指定的 ORIGDST 无效，不能回退到其他来源。
2. 没有 ORIGDST 时，只有精确 DNS query 加上已指定的 `PKTINFO` 目的地址才能形成 `IP:53`。
3. 其他情况只有非 wildcard listener bind 可以提供目的地址。
4. 缺失、畸形、重复、截断或未指定的元数据，会在 slow-path 预留或 payload 保留前被丢弃。

UDP 入口在任何可能等待的校验前捕获 initializer epoch。原始 UDP/53 随后按 Config → backend 读锁顺序，在一致快照下验证策略代际并固定语义分组名，再通过既有 epoch gate 预留和入队。同一 tuple 的不兼容普通/原始/其他分组报文被拒绝，而不是借用错误的 transport。非 `must` 有效 DNS 保留独立查询预算；UDP/53 不进入普通 UDP conn-state 或 NFQUEUE staging，也不分配 decision token。

归控制器所有的畸形 UDP/53 可保留兼容的 controller handoff 事实用于通用路由，但会丢弃不兼容的终局原始 handoff 及其过期报文事实。

### Transport 与事务

普通 transport 使用 `PacketTransport`；native handler 包装真实 socket，tunnel
直接实现 packet framing。来源共享的 VLESS XUDP/Mux.Cool 则提交类型化 source
attachment，让 endpoint view 共用一条 transport receiver。两种形态都不创建
loopback bridge。

Endpoint 创建是事务性的：

1. 把 `(client, original destination)` 预留为 `Initializing`；lease 持有首个 datagram、queue permit、slow-path permit、token、generation 和 cancellation epoch。
2. 路由、嗅探、选择并准备合格 transport。在发布前创建透明 anyfrom reply socket。
3. 只提交选中候选的 `PreparedUdpTransport<T>` 或 VLESS source preparation；fallible commit 返回选中的 `Arc<T>`/attachment，drop loser 自动回滚。
4. 启动 endpoint driver，并等待其 ready barrier。
5. 在共享 epoch fence 下，把精确的 `Initializing` identity 原子替换为 `Ready`。
6. 转移保留的首包，通过已提交 transport 发送并等待 acknowledgement。
7. 按 FIFO 顺序发送嗅探保留的 fragment 和未触碰的 queue follower，再运行 steady send 和 receive 路径。

透明 UDP preparation 在路由与选择完成后开始，到选中 transport 的协议状态
commit 完成才结束。权威路径与冷启动 URLTest 共用一个绝对
`max(10s, 4 × connect_timeout)` deadline，覆盖解析、物理拨号准入、控制协商、
stagger／满容量等待与 commit。到期后不再启动后续候选，并在返回前排空所有
已启动 preparation。嗅探／路由位于该边界之前；reply socket 创建、发布与
packet I/O 位于其后，受已有事务及 I/O 上限约束。不会自动重放 packet。

对于来源共享 VLESS，`udp_endpoint/source.rs` 按 reused runtime identity、
规范化 client、UDP path 与 `ActualPeer` 或 `RewriteTo(original destination)`
索引一个 owner。它持有一条 XUDP session、一条 receiver 与多个 endpoint send
view。完整 `(client, destination)` endpoint map 仍权威持有 route、token、
generation 与逐 flow Score。reply classification 不会把已占用 wrong-owner、
`Initializing` 或 `Retiring` entry 当作 foreign；只有缺失的 `ActualPeer` key
可做 foreign delivery，且没有逐 flow Score。domain route 保持 original
destination scope。迟到的 send/reply/removal callback 在动作前重新校验 owner、
token、generation 与 endpoint identity。
Source sharing 不会合并 kernel/NFQUEUE flow ownership：每个规范 endpoint
继续保有独立 decision token、generation、terminal transition 与五元组
retirement fence。

每个透明 socket 在一次 readiness 轮次中通过 `recvmmsg` 最多接收八个 datagram。每个 slot 独立保留 ORIGDST、PKTINFO 与逐报文 `SO_MARK` 元数据，packet 保持内核顺序，元数据异常也只丢弃对应 slot。队列排空后，下一次唤醒先使用一个 slot；若读取满载则立即恢复八 slot batch，从而避免稀疏流量的准备开销。该上限把调度公平性和 payload 存储限制在每 socket 512 KiB；当前每地址族四个 socket、双栈全部启用时共 4 MiB。Listener 循环只做校验、预留和入队；它从不等待 `PacketTransport` I/O。Endpoint driver 持有全部 transport 调用。首次与稳态发送各有五秒超时。超时或错误具有歧义，因为 transport 可能已接受 packet 的一部分，因此 driver 不会重放该 datagram，也不会继续后续 follower。

SOCKS5 UDP 在 endpoint 整个生命周期内保持 TCP `UDP ASSOCIATE` 控制流，并把控制流 EOF 或意外控制数据视为 endpoint 失败。其 connected UDP socket 向服务器物理 `BND.ADDR` relay 发送；若回复为域名则解析，若地址未指定则替换为控制连接对端 IP。`PacketTransport::relay_addr()` 和接收来源元数据暴露的是逻辑目标，因此 endpoint 首回复校验不会把 SOCKS relay 与远端 peer 混淆。

回复使用在 `daens` 内创建、透明绑定到 packet 原始目的地址的 anyfrom socket。通过 transport peer 校验后，按域名拨号的 endpoint 始终使用原始 IP、端口和地址族回复，即使远端 DNS 选择了其他地址。按 IP 拨号的 endpoint 保留其 original-destination socket，并按 endpoint 缓存已接受的其他 full-cone 来源。端口 53 回复另外共享每地址族一个透明 socket，并用 `IP_PKTINFO` 或 `IPV6_PKTINFO` 选择精确源 IP。从 TPROXY listener 回复会使用内部 `dae0` 源地址，因此不可用。

Reload 在等待前推进 cancellation epoch。Initializer 在 await 前捕获该 epoch 和 incarnation generation；若 cancellation 先于 `commit_ready` 线性化，则阻止发布。Reload 取消并排空 `Initializing` lease 及其保留资源，`Ready` endpoint 仍遵循既有生命周期。已有原始 UDP `Ready` 会话在语义分组名相同且符合该生命周期时可以保留，但 `Initializing` 不能跨 reload 存活。每次 retirement 和 acknowledgement 都指定 token 与 generation，因此延迟工作不能删除替代 mapping。

## Queue 与描述符预算

每个 UDP 流最多保留 64 个 datagram，包括首包。所有流共享精确的 8 MiB payload permit 预算。准入在复制前取得每流 slot 和全局 byte permit；FIFO 饱和时丢弃最新 datagram。NFQUEUE 有独立 ingest actor，限制为 256 个条目和 8 MiB 排队 payload。

启动时，`honk-core` 尝试提升软 `RLIMIT_NOFILE`，只快照一次活动值，并把预算
输入上限设为 1,048,576。在剩余描述符决定 UDP endpoint 数量之前，先按
`min(after_dials / 8, 8192)` 分出 VLESS carrier 容量。在上限处固定分区为：

| 所有者 | 容量 | 描述符记账 |
| --- | ---: | ---: |
| 固定/运行时预留 | 256 | 256 |
| 已接受 TCP 流 | 16,384 | 每个 6 = 98,304 |
| 保留 TCP pool | 2048 | 每个 1 = 2048 |
| 临时出站 dial | 1024 | 每个 1 = 1024 |
| VLESS 物理 carrier | 8192 | 每个 1 = 8192 |
| UDP endpoint | 8192 | 每个 10 = 81,920 |
| **合计** |  | **191,744** |

一个 UDP endpoint 为 relay socket、可能存在的 SOCKS5 控制流和全部八个
anyfrom reply socket 记账。一个 TCP 流为 accepted/outbound socket 和两组
各含两个 FD 的 splice pipe 记账。更小限制使用相同的饱和分区；VLESS carrier
结果为零时保持零。

进程 VLESS-carrier semaphore 由 traffic generation 与 DNS runtime fork 共享。
carrier 在 actual I/O 的 provisional、active、draining 与 idle 状态中始终持有
permit，直到 task teardown 才释放。权威 physical-FD 上限是该进程 gate，
而不是逐节点 pool limit 的总和。耗尽返回类型化 local capacity rejection，
不影响节点 health 或 Score。

其余 descriptor headroom 有意不分配：较高 `RLIMIT_NOFILE` 不代表拥有等量
memory 或 scheduler capacity。TCP 从描述符导出的 floor 开始，封顶 16,384
个 flow；它可借用 idle non-TCP headroom，同时保留一半作为 burst reserve，
且不超过 floor 的两倍。已有 flow 不会被切断，固定 reserve 保护控制面 FD。

各准入上限彼此独立：

| 准入 | 上限 |
| --- | ---: |
| TCP 流 permit | 描述符导出的 floor，加上对观测到的 idle non-TCP headroom 的有界借用 |
| VLESS 物理 carrier | 启动时固定的 `min(after_dials / 8, 8192)` 进程 gate |
| 冷 non-DNS UDP slow path | `min(udp_endpoints, 256)` |
| 端口 53 入口 slow path | `min(transient_dials, 256)` |
| NFQUEUE ingest actor | 256 个条目和 8 MiB |

不存在单独的 256 条 TCP slow-path 上限。TCP accept 使用由描述符导出的流预算。Endpoint-removal channel 限制为 1024 条消息，每批排空 128 条。非阻塞投递遇到满队列时，去重的 `removal_dirty` 集保留补偿；worker 每批完成后刷新该集合，再确认精确 endpoint tombstone。

透明 TCP 先等待任一 IP 族监听器变为可读，再预留共享流 permit，最后用非阻塞系统调用完成 accept。因此空闲监听器不占用流容量，达到上限后到达的连接仍留在内核 listen backlog。`/stats` 的 `tcp` 对象提供 `activeFlows`、`limit` 和 `capacity.rejected`；后者统计等待 permit 的 accept-loop，而不是 accept 后被丢弃的连接。动态上限低于 256 时启动会告警；网关部署应提高服务的 `RLIMIT_NOFILE` 限制。

## TCP 中继与 conn-state 所有权

当两端都是普通 `TcpStream` 时，`relay_splice` 运行两个并发 `splice(2)` pump。每个方向持有一条最多 64 KiB 的非阻塞 pipe，因此全双工中继最多请求四个 pipe FD 和 128 KiB pipe page。EOF 对另一端 write side 执行 half-close，并允许反向继续排空。

每个方向的首次 splice 同时是 capability probe。在任何字节到达目的 socket 前返回 `EINVAL`、`ENOSYS` 或 `EXDEV`，即可无损回退到用户态 copy，并设置进程全局 latch；后续连接跳过 probe。其他错误，或字节已经暂存后返回 unsupported，会使中继失败，而不是冒数据丢失风险。TLS 或协议包装流使用 `relay_auto`，它始终使用基于 select 的 copy loop。

copy pump 在读取新输入前先 flush 嗅探或协议设置阶段已缓冲的字节，再使用
Tokio 原生 copier；输入暂时空闲时也会 flush 待发字节。每个方向使用默认
8 KiB 缓冲区，不要求应用再发一个请求或关闭连接才能送出当前请求。

首次 EOF 后，两条中继路径只限制空闲排空时间：`DRAIN_DEADLINE` 是没有任何字节进展的 30 秒。活跃 survivor 可以运行超过 30 秒；静默 survivor 不能无限持有 accepted socket。

Accepted TCP socket 只有在其规范正向 `CONN_STATE_MAP` 条目仍存在时才会被接管。`TcpFlowPins` 为每个 accepted owner 引用计数该方向 tuple。BPF janitor 跳过已 pin 的 conn-state 和匹配的 redirect 元数据。最后一个 owner 退役时读取当前条目，并且只在 state 与 timestamp 仍匹配已观察 incarnation 时条件删除；旧 relay 不能删除复用的 tuple。

## Reload 与运行时 generation

SIGHUP 为每次尝试单独收集诊断。无论加载和配置校验成功与否，警告都只报告一次；被拒绝的尝试另报告一次脱敏后的原因，不进入运行时发布流程。报告本次诊断不会替换当前运行时状态，也不会新增最近失败尝试的缓存。

`apply_runtime_config` 首先构建替代 Router、GroupManager、出站 registry、DNS 运行时与路由计划，不修改 live state。提交顺序为：

1. Fence NFQUEUE readiness，并等待内核 reader-epoch 宽限期。
2. 拒绝新的透明代理准入。
3. 取消 correlator cell 和 token-bound original，推进 UDP initializer epoch，排空 `Initializing` lease，等待 correlator 变空，并排空精确 endpoint retirement。
4. 构建 generation 私有事实、加载生成函数并附着全部 inactive slot，最后切换 `ROUTING_POLICY_ROOT`，再于同一串行边界内发布出站 registry、DNS runtime pointer、Router、配置、组和 projection snapshot。
5. 开放 pending 准入，最后重开 NFQUEUE。规则派生 feature bit 存在 policy descriptor 中，不再单独发布到静态 flag map。

提交前失败保留活动代码与事实，不再重放旧路由计划。Fence 后发布被拒绝时，控制器恢复组连通性并重开旧 generation；连通性恢复失败则继续拒绝准入。Root 切换成功后新 generation 已提交，之后若 NFQUEUE 重开失败，保留已发布的新 generation 并继续 fence 准入，直到后续成功 reload 修复。

`DnsServiceProvider` 是一致的 DNS generation pointer。请求 lease 保留其 generation 的 forwarder、projection、transport pool 和出站运行时，直到退役。出站 registry 同样按 generation 持有：未变化的 node runtime 只在提交点转移，旧 registry 把这些 runtime 标记为已移出，然后开始优雅退役。现有 stream 与 `Ready` UDP endpoint 保持引用，同时旧 reusable pool 停止接受新工作并排空。

编译路由发布有独立于 DNS runtime generation 的[进程生命周期上限](./routing.md#同步槽与原子发布)。发布后，排队中的 UDP53 与原始 `must` TCP53 元数据可能按上述准入规则被拒绝；已准入 DNS 查询仍按固定代际排空。

`DrainTracker` 是进程全局的 accepted-flow gate。Reload 和关闭在 drain 前设置 reject-new；关闭最多等待五秒，然后带着剩余计数继续拆除。

### 需要重启的变更

当前进程级消费者在以下任一值变化时拒绝 `SIGHUP` reload：

| 区域 | 需要重启的字段 |
| --- | --- |
| Listener/数据路径 | `global.tproxy_port`、`global.tproxy_mark`、`global.tproxy_port_protect`、`global.pprof_port`、`global.so_mark_from_dae`、`global.lan_interface`、`global.wan_interface`、`global.auto_config_kernel_parameter` |
| 进程状态 | `global.log_level`、`global.data_dir`、`global.store_subscribe` |
| DNS listener | `dns.bind` endpoint 或 transport 的语义变更 |
| Clash API | `experimental.clash_api.external_controller`、`external_ui`、`external_ui_download_url`、`external_ui_download_detour`、`secret`、`default_mode` |
| 持久化 | 任意 `experimental.cache_file` 变更 |
| NFQUEUE | `global.nfqueue_enable` |
| 健康检查与 TLS | `global.check_interval`、生效的第一个 `global.tcp_check_url`、启用 HTTP 检查时的 `global.tcp_check_http_method`、选中的 `global.udp_check_dns` 目标，或原生 TLS/uTLS 模式切换（参见[健康检查重载语义](../reference/global.md#重载健康检查与-tls-模式)） |

当旧值和新值都能解析时，`dns.bind` 的语义比较使用解析后的 bind endpoint，因此描述同一 endpoint 的纯拼写变更不会强制重启。

## 订阅编排

启动时先解析已存正文，再开始网络刷新。有效且非空的恢复结果立即提供节点，并从五秒首次拉取等待中移除该订阅；缺失、无效或空正文只会在共享 grace 期间等待。之后所有订阅仍在后台刷新。

`ControlPlane::run` 首次被 poll 时便取得控制命令接收端的所有权，早于所有启动阶段的 await。这个已开始运行的 future 返回或被丢弃时，即使监听器启动失败也会关闭通道，使阻塞在满队列上的订阅投递解除等待，随后调用方才能等待 supervisor 关闭。

`SIGHUP` 会按 fetch 身份（URL + 配置的 User-Agent + headers）稳定订阅 ID，并把活动订阅节点带入候选配置。只有启用订阅且当前没有活动节点时才恢复缓存，随后安排立即网络刷新。网络、解析或没有可用节点的失败会保留活动节点，不替换上一次有效正文。持久化失败不是致命错误：校验成功的节点仍可合并，旧正文仍可恢复。定期刷新与立即刷新使用同一串行的 runtime 发布路径，订阅节点不会写回配置文件。

正文通过校验与运行时发布分别报告。节点集合准入失败时，只输出一次脱敏诊断，并保留活动配置；已经保存的正文不会回滚。

当 `global.store_subscribe` 启用时，经过校验的原始正文存放在 `<global.data_dir>/.sub`。切换数据目录期间，若配置存储不存在，则依次保留并使用已有的 `/var/share/honk/.sub` 与 `./.sub`；honk 不会自动移动或删除它们。目录必须是非符号链接目录、权限 `0700`；文件权限 `0600`，文件名由请求 URL、配置中的 User-Agent 覆盖值（未设置或为空时贡献空组件）与 headers 共同计算 URL-safe SHA-256。未配置订阅覆盖值时，请求标识为 `honk/<version>`。写入使用新的临时文件、`sync_all`、原子 rename 和目录 sync。

- `src/subscription.rs` 负责拉取、解析与原始正文持久化。`src/subscription/supervisor.rs` 管理启动、立即与周期刷新任务，并按修订版本校验任务授权；重新协调或关闭时会等待被替换的任务结束。`src/lib.rs` 只在 `SIGHUP` 提交后协调这些任务。
- 守护进程的拉取/恢复路径与 `honk-tool sub` 的本地文件共用正文格式检测。`Simple`/`Custom` 接受 BOM、可换行的标准/URL-safe Base64、原始分享链接、Clash YAML/JSON、SIP008、sing-box JSON，以及 Surge/Surfboard/Loon/Quantumult X 记录。`src/subscription/json.rs` 与 `records.rs` 规范化外部记录，`clash.rs` 构造并校验类型化节点。
  只导入节点，不导入完整配置中的路由、DNS 或组。原生 JSON 保留以 Unicode 代理项对编码的名称。跳过不支持的节点，身份重复时保留首个可用节点，空结果不替换活动订阅。导入的 Trojan/AnyTLS/QUIC 节点必须使用 TLS，不会静默降级为明文。
  Clash 与 sing-box 的 TCP ALPN 归入共享 TLS 模型，而不是 TUIC 的 QUIC 字段。共享构造器的跳过告警只包含从 1 开始的代理序号和静态拒绝原因，不包含原始节点记录或凭据。

## Clash API 与 cache DB

可选的 Clash-compatible axum server 是当前配置、GroupManager、mode/flags handle、connection tracker、DNS service、统计和出站 runtime pointer 上的用户态视图与修改接口；endpoint 细节见 [API 参考](../reference/api.md)。当 API 成功绑定，或任一配置组使用 `interrupt_connections` 时，才启用连接元数据，因此即使没有 API 也能在选择变化时中断连接。可选 SQLite `cachedb` 在数据路径准入前打开，持久化 Selector 选择、Clash 模式和可选 DNS 应答。相对路径依次优先使用 `global.data_dir` 下、`/var/share/honk` 下和原始配置目录中的已有数据库；缺失数据库在 `global.data_dir` 下创建。配置和持久化语义见 [Experimental 参考](../reference/experimental.md)。

## 相关文档

- [数据路径设计](./datapath.md)
- [路由设计](./routing.md)
- [NFQUEUE 设计](./nfqueue.md)
- [出站设计](./outbound.md)
- [组设计](./groups.md)
