# 用户态控制平面

本文描述位于内核数据路径与出站栈之间的 `honk-core` 用户态引擎。

## 范围

控制平面负责透明代理入口、消费内核交接、用户态路由、嗅探、出站选择、中继、资源准入与运行时发布。向用户态交付流量的内核机制见[数据路径设计](./datapath.md)。组策略和健康状态驱动的选择见[组设计](./groups.md)，DNS 运行时行为见 [DNS 设计](./dns.md)。

主要实现在 `crates/honk-core/src/control/`。它消费 `EbpfBackend` 状态，并把 TCP 流或 `PacketTransport` UDP 契约交给 `honk-outbound`。

模块分工：

- `src/control/`：
    - `mod.rs` — `ControlPlane` 的[启动与关闭](#启动与关闭)。
    - `connection/` — 规范的[流初始化器](#嗅探与流初始化)。
    - `nfqueue/` — `PendingUdpVerdicts` correlator；[NFQUEUE 暂存协议](./nfqueue.md)。
    - `sockets.rs` — [透明代理入口](#透明代理入口)、anyfrom 回复；`udp_ingress.rs` 负责 `udp_fast_path`。
    - `dns_control.rs` — `DnsController`；[查询准入与投影](./dns.md#解析管线)。
    - `dns_listener.rs` — `DnsListener`；[独立入口生命周期](./dns.md#入口路径)。
    - `reload/` — `apply_runtime_config`；[运行时发布](#reload-与运行时-generation)。
    - `routing_matcher.rs` — [原子路由发布](./routing.md#同步槽与原子发布)与[内核规则 lowering](./routing.md#受限原生后端)。
    - `quic.rs`、`packet_sniffer.rs`、`tcp_sniff.rs` — 分别负责 QUIC 解密/重组、逐流嗅探会话与 TCP 负缓存。
    - `udp_endpoint/mod.rs` — `UdpEndpointPool`；[endpoint 事务](#udp-endpoint-流水线)。
    - `probers.rs` — `ProxyHttpProber`、`ProxyUdpProber`；[健康探测](./groups.md#健康状态与探测)。
    - `janitor.rs` — `BpfJanitor`；[map 维护](./datapath.md#用户空间维护与计数)。
    - `drain.rs` — `DrainTracker`；[已接受流的排空](#reload-与运行时-generation)。

## 启动与关闭

- `src/lib.rs` — `run()`、`Cli`/`ClashCommand`、资源限制、后端选择与固定队列启动前置检查（[配置指南](../configuration.md)）。真实实例持有 `/run/honk-core.lock` 并发布 `reload` PID。通过 rtnetlink 创建由 FD 持有的 `daens` 与 L2 netkit `dae0`；仅遇到 `EOPNOTSUPP` 时回退 veth。加载或复用持久化 allocator pin，然后在数据路径准入前启动 NFQUEUE。

配置诊断在初始化 tracing 前收集。加载或配置校验提前失败时，先向标准错误输出已有的非终止诊断，每条仅输出一次，再由二进制程序返回一次脱敏后的终止错误。加载成功时，诊断延迟到配置指定的 tracing 订阅器就绪后输出。后续运行时致命错误仍保留原有的日志文件记录。

启动时保持内核准入关闭，直到用户态能够接收每个重定向流：

1. 真实模式取得 `/run/honk-core.lock`，最多等待 240 秒让前一个实例退出，并把进程 PID 发布到已锁文件；`honk-core reload` 读取该 PID 并发送 `SIGHUP`。未取得锁的后继实例在读取配置和打开状态数据库之前退出。Mock 模式不取得进程全局锁。
2. 加载并校验配置、选择 `global.data_dir`，在任何网络 I/O 前初始化进程旁路 mark，提升 `RLIMIT_NOFILE`，并取得一次不可变的描述符预算快照。
3. 在网络刷新前恢复持久化订阅。只有没有有效已恢复正文的订阅才参与五秒首次拉取宽限期。
4. 真实实例完成锁交接后，再探测固定 NFQUEUE 队列前置条件。mock/不带 `ebpf` 的模式或前置检查失败时记录 warning，仅在本进程关闭 NFQUEUE；前置检查不会拒绝保留的 nftables table，因为安装阶段会回收残留的自有状态。
5. 在真实模式下，通过 rtnetlink 创建由 FD 持有的 `daens` 命名空间和 `dae0`/`dae0peer` 链路。引擎优先尝试 L2 netkit pair，仅在内核报告不支持 netkit 时回退到 veth。进程留在宿主命名空间；只有同步的 socket、链路和挂载操作通过有作用域的 `setns` 调用进入 `daens`。
6. 加载 BPF 对象并挂载真实数据路径。默认对象通过 `include_bytes!` 嵌入；`--bpf-object` 提供运行时覆盖。启用 `ebpf` feature 时，`build.rs` 定位对象，拒绝过期或无 BTF 的产物，在移除继承的 `RUSTFLAGS` 和 `CARGO_ENCODED_RUSTFLAGS` 后用 nightly 重建，校验 `.BTF`，再复制到 `OUT_DIR` 供嵌入。
7. 复用或创建固定的 `UDP_DECISION_SEQUENCE` 分配器，并校验其 map ABI、BTF、加锁值、token 范围与耗尽状态。NFQUEUE 启动时再次检查加锁的分配器状态；若没有回滚安全的 generation，则保持暂存关闭。
8. 构建用户态 Router、出站运行时 registry、DNS 运行时、GroupManager、cache DB、可选 Clash API 和控制平面 supervisor。
9. 绑定透明 TCP/UDP listener，发布完整 listener FD 集，启动独立 DNS 和 UDP 接收循环；仅当生效开关仍开启时，才启动 NFQUEUE 服务及其 ingest actor、correlator、watchdog 和独立的队列压力采样器（每秒采样一次）。
10. 检查 NFQUEUE 健康状态，发布其 ready 状态，开放 pending verdict 准入，最后把 `DATAPATH_STATE_MAP[0]` 设为 ready。随后 TCP accept loop 在控制面 supervisor 中运行。
`RealEbpfBackend` 负责 aya program、map、link、持久分配器处理和真实 NFQUEUE 集成。`MockEbpfBackend` 在没有特权内核资源时提供相同控制面接口。请求的 NFQUEUE 路径无法通过锁交接后的固定队列前置检查时会记录 warning 并关闭；服务准入后的失败仍为 fatal。

关闭时在资源消失前逆序释放所有权：fence NFQUEUE、关闭数据路径准入、拒绝新的用户态工作、取消并排空持有的 verdict 和 UDP initializer、停止 UDP driver 和 removal 处理、停止接口 watcher、卸载 BPF hook、最多用五秒排空已接受流、退役出站运行时、停止 NFQUEUE、停止 DNS controller 和 persistence，并清理 generation 持有的 BPF 状态。普通清理保留固定分配器。随后 listener 和 `daens`/link-pair 所有权离开作用域。

UDP receive-priority 辅助元数据不可用时，真实 backend 持有 receive-trace fallback 的 link 与 map。`cleanup()` 先卸载 ingress hook、join ring consumer，再于 BPF 对象释放前 drop `receive_trace`；即使 backend 自身仍存活也会释放，不等到其 Drop。普通清理仍保留两个持久化 sequence pin。

## 透明代理入口

真实 TCP 和 UDP listener 在 `daens` 内创建，并设置透明 socket 选项和有效的 `global.so_mark_from_dae`（零值选择 `0x100`）。该 mark 使数据路径把它们识别为 honk 自己的 listener，而不是普通本地服务。已接受 TCP socket 会继承 mark，因此每个 accept loop 在处理流前将其清零。Mock listener 是宿主命名空间内不带特权透明选项的普通 socket。

原始目的地址按下表恢复：

| 入口 | 首选来源 | 回退 |
| --- | --- | --- |
| TCP/IPv4 | `SO_ORIGINAL_DST` | 透明 socket 的 `local_addr()` |
| TCP/IPv6 | `IP6T_SO_ORIGINAL_DST` | 透明 socket 的 `local_addr()` |
| UDP | `IP_RECVORIGDSTADDR` / IPv6 original-destination cmsg | 下文所述的受约束 provenance 规则 |

形成规范 tuple 后，普通非 DNS 流通过 `routing_handoff_take` 消费 `ROUTING_HANDOFF_MAP`。没有 handoff，或出站为 `ControlPlaneRouting` 时，回退到 `Router::route_action`。最终的 `must` 和 `block` 结果不能被 Clash mode 覆盖。该回退不是透明 DNS 的所有权边界。

端口 53 的控制器与原始转发归属遵循[有序流量规则契约](../reference/routing.md#出站目标与-must)，包括畸形非 `must` UDP 的通用回退。

真实透明 UDP/53 无论归控制器还是原始转发，都要求有效的逐报文 `SO_RCVMARK` / `SOL_SOCKET` `SO_MARK` 凭据及当前已提交路由代际，tuple handoff 不能替代。透明 TCP/53 必须有 SYN handoff；只有原始 `must` TCP 还要求当前路由代际，并在原始 I/O 前固定配置、语义分组与出站 runtime。非 `must` TCP 保留控制器查询准入，不执行该路由代际检查。缺失必需元数据或必需的代际检查失败时，在 I/O 前拒绝准入。物理兼容性见[handoff ABI 与 UDP 携带位](./datapath.md#map-清单)。

## 嗅探与流初始化

嗅探器向规范初始化器提供信息，可解决暂存决策，但不持有 verdict，也不拥有独立的卸载路径。

TCP 嗅探最多读取 4096 字节，并提取 TLS SNI 或 HTTP `Host`。返回的缓冲区属于流状态，并在中继开始前写入已选出站，因此嗅探不会消费应用数据。`dial_mode: ip`、最终的 direct/block 或 `must` handoff，或命中 TCP negative cache 时跳过 TCP 嗅探。连续三次失败会抑制同一目的地址/出站签名十分钟；嗅探成功会移除 negative 条目。

UDP 域名发现解密 QUIC v1/v2 Initial packet，重组 CRYPTO fragment，并解析 TLS ClientHello SNI。每流 session 五秒过期，最多检查八个 Initial packet，并把 CRYPTO stream 限制为 64 KiB。首个 ClientHello 分片时，initializer 最多保留八个 FIFO follower，最多等待 250 ms。failed-DCID cache 限制对非 QUIC 或不可解密流量的重复工作。

`dial_mode: domain` 对嗅探到的 TCP 或 QUIC 名称执行 DNS reality check。目的地址同族答案精确匹配时接受；只有另一地址族答案时，为兼容双栈仍保留该名称。同族不匹配、查询失败或超时时丢弃嗅探名称并按 IP 继续。

`connection/` 是每流 route/sniff/mode/selection 的规范边界。Socket UDP 入口与 NFQUEUE 持有的 payload 都在同一个 `UdpEndpointPool` 中预留相同的 `UdpInitLease`；NFQUEUE 没有第二套 Router 或拨号器，也没有克隆报文、重放或主动重传路径。暂存流在 token 校验的终态转换前计算唯一最终出站与 mark。

`build_tuples_key` 必须用 `mem::zeroed()` 初始化 `TuplesKey`。这个 `#[repr(C)]` key 在 40 字节布局中只有 37 字节字段，内核会散列包括三个 padding 字节在内的全部 40 字节。因此逐字段初始化可能产生用户态无法可靠查询或删除的 key。

权威 URLTest 建立失败保留按延迟前三候选的一轮重赛。Score 所属失败可顺序尝试一个不同的合格叶节点，在排名前排除失败身份，即使普通评分仍把它排在第一。Score 两次尝试共享绝对 deadline，并保留固定 generation、Selector 选择和首选真正经过的 final 边。类型化拒绝、本地拨号容量耗尽、取消和关闭均为终态，包括排空竞速时发现的已完成拒绝；应用写入和已建立 relay 从不重放。

- `src/sniffing.rs` — **仅 TCP**：TLS SNI + HTTP Host（≤4096 字节；返回缓冲字节供转发）；`parse_client_hello_body` 与 `control/quic.rs` 中的 QUIC sniffer 共用。

## UDP endpoint 流水线

### 目的地址 provenance

`udp_ingress.rs` 负责目的地址校验和有界准入，`sockets.rs` 负责 syscall/cmsg 解码。真实透明监听必须具有权威 ORIGDST；普通/mock 监听保留以下回退规则。所有路径都在 endpoint 预留前拒绝无效元数据：

1. 存在、有效且已指定的 ORIGDST cmsg 具有权威性。未指定的 ORIGDST 无效，不能回退到其他来源。
2. 没有 ORIGDST 时，只有精确 DNS query 加上已指定的 `PKTINFO` 目的地址才能形成 `IP:53`。
3. 其他情况只有非 wildcard listener bind 可以提供目的地址。
4. 缺失、畸形、重复、截断或未指定的元数据，会在 slow-path 预留或 payload 保留前被丢弃。

UDP 入口在任何可能等待的校验前捕获 initializer epoch。原始 UDP/53 按 Config → backend 读锁顺序验证；带 mark 的直连先取得 Router 读锁。在一致快照下校验策略代际，并固定语义分组或报文携带的不可变直连 mark 表项，再通过既有 epoch gate 预留和入队。同一 tuple 的不兼容普通/原始/其他分组/直连 mark 报文被拒绝，而不是借用错误的 transport。非 `must` 有效 DNS 保留独立查询预算；UDP/53 不创建普通 UDP conn-state 或 decision token。重组后的分片通过 [NFQUEUE](./nfqueue.md#lan-dns-分片) 共用该准入，原包确认丢弃后才发布工作。

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

Reload 在等待前推进 cancellation epoch。Initializer 在 await 前捕获该 epoch 和 incarnation generation；若 cancellation 先于 `commit_ready` 线性化，则阻止发布。Reload 取消并排空 `Initializing` lease 及其保留资源，`Ready` endpoint 仍遵循既有生命周期。已有原始 UDP `Ready` 会话在语义分组名相同且符合该生命周期时可以保留，但 `Initializing` 不能跨 reload 存活。编译策略发布后，过期的排队路由元数据仍会被准入检查拒绝。每次 retirement（包括其 `Retiring` tombstone）和 acknowledgement 都指定 token 与 generation，因此延迟工作不能删除替代 mapping。
编译后的流量计划成功变更，且旧策略或新策略包含直连 mark 时，才会退役直连 `Ready` endpoint，避免后续流量复用旧 socket mark；无变化、不相关重载，以及新旧策略均无直连 mark 的路由变更，都会保留这些端点。显式标记为用户态所有的 WAN UDP 决策（包括带 mark 的 `direct(must)`）会在 tuple/reader fence 下同时清理 token 为零的 conn state、handoff 与 redirect track；原生 LAN direct/offloaded 决策及更新的非零 token 保持不变。

对于 NFQUEUE 入口，按 client/destination 建键的 `PendingUdpVerdicts` 只携带 token、endpoint generation、phase、FIFO verdict guard 与最终直连 mark。Endpoint 准入接收自有 `Bytes`，对应唯一保留的 NFQUEUE 载荷缓冲区。Direct/block 完成后移除 initializer 并交接给内核；proxy 完成后把 token/generation 转入 `Ready`。[NFQUEUE 协议](./nfqueue.md#终态转换)定义有序终态转换、绝对 deadline 与致命失败处理。

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

每个方向的首次 splice 同时是 capability probe。在任何字节暂存前返回 `EINVAL`、`ENOSYS`、`EXDEV` 或策略拒绝（`EPERM`），即可无损回退到用户态 copy，并设置进程全局 latch；后续连接跳过 probe。pipe 创建失败同样发生在任何字节移动之前，因此只让当前连接改用 copy，不设置 latch。其他错误，或字节已经暂存后返回 unsupported，会使中继失败，而不是冒数据丢失风险。TLS 或协议包装流使用 `relay_auto`，它始终使用基于 select 的 copy loop。

未启用 Encryption 的 Vision TLS/REALITY carrier 先走 copy loop；两个方向都进入 Direct 且连接已转发 256 KiB 后，relay 在两个方向都不持有未写出字节的位置交接：一个方向处于读边界，另一个方向挂起在读取上。此时 relay 把 carrier 的 TCP socket 借给同一个双向 splice 引擎，Vision/TLS 栈仍归 relay 所有，carrier pressure 采样在借出的 socket 上继续。probe 不支持或 pipe 创建失败时，任何字节尚未移动，relay 恢复同一个 Vision 流的 copy loop；每条连接只尝试一次交接。两个阶段共用连接计数器，统计覆盖整条连接，first-response 回调只触发一次。

copy pump 在读取新输入前先 flush 嗅探或协议设置阶段已缓冲的字节；输入暂时
空闲时也会 flush 待发字节。每个方向先使用 8 KiB 缓冲区；第一次读满即判定为大流量，该方向随后改用 65,535 字节缓冲区，使满载 read 恰好容纳一个最大 AnyTLS frame，不拆成 8 KiB write，也不留下单字节尾帧（仅首帧较小）。空闲和小流量连接不会扩容，因此一条空闲连接的 copy 缓冲区是 16 KiB，而不是 128 KiB。
应用不需要再发一个请求或关闭连接才能送出当前请求。

首次 EOF 后，两条中继路径只限制空闲排空时间：`DRAIN_DEADLINE` 是没有任何字节进展的 30 秒。活跃 survivor 可以运行超过 30 秒；静默 survivor 不能无限持有 accepted socket。

客户端不发 FIN 或 RST 就消失的情况单独限制：TPROXY TCP listener 启用 TCP keepalive（空闲 3600 秒、间隔 15 秒、4 次探测），accepted socket 继承该设置。静默的客户端约一小时后结束其 relay；仍在线的空闲客户端会应答探测，因此长时间空闲的连接保持打开。该错误是客户端侧的 `TimedOut`，按取消结算 Score。

Accepted TCP socket 只有在其规范正向 `CONN_STATE_MAP` 条目仍存在时才会被接管。`TcpFlowPins` 为每个 accepted owner 引用计数该方向 tuple。BPF janitor 跳过已 pin 的 conn-state 和匹配的 redirect 元数据。最后一个 owner 退役时读取当前条目，并且只在 state 与 timestamp 仍匹配已观察 incarnation 时条件删除；旧 relay 不能删除复用的 tuple。

真实 relay 完成后，TCP owner 先按实际结果恰一次结算 Score 与 relay-error 统计，再传播退役失败。退役失败不会把成功 relay 证据改成取消。TCP 补池仍要求 relay 成功且退役已确认；主动取消保留独立的中性路径。

`splice.rs` 的 `relay_splice` 与 `vision.rs` 共用双向引擎。**不得恢复单向 splice**，它曾导致超时；空闲排空期限可防止无数据传输的对端使任务和套接字长期停留在 CLOSE-WAIT。

## Reload 与运行时 generation

SIGHUP 为每次尝试单独收集诊断。无论加载和配置校验成功与否，警告都只报告一次；被拒绝的尝试另报告一次脱敏后的原因，不进入运行时发布流程。报告本次诊断不会替换当前运行时状态，也不会新增最近失败尝试的缓存。

`apply_runtime_config` 首先构建替代 Router、GroupManager、出站 registry、DNS 运行时与路由计划，不修改 live state。提交顺序为：

1. Fence NFQUEUE readiness，并等待内核 reader-epoch 宽限期。
2. 拒绝新的透明代理准入。
3. 取消 correlator cell 和 token-bound original，推进 UDP initializer epoch，排空 `Initializing` lease，等待 correlator 变空，并排空精确 endpoint retirement。
4. 编译 generation 的 `RoutingPushPlan`；在下述发布 guard 内，只有 compiled plan、learned facts 变化或数据路径健康需要恢复时才调用 `EbpfBackend::publish_routing_plan(&plan, learned_domains)`。后端选择 inactive slot，暂存由该 generation 持有的 IP/source/MAC/domain 事实 map（使用完整的 256 位谓词值），把生成函数附着到每个相关 target，最后切换 `ROUTING_POLICY_ROOT`。调用成功后，原生显式激活使用已经持有的 backend 重置 mode，用户态再于同一串行边界内发布替代出站 registry、DNS runtime pointer、Router、配置、组与 projection snapshot；root 已提交后 mode reset 失败会提交新代为 degraded，并保持准入 fence。
5. 开放 pending 准入，最后重开 NFQUEUE。规则派生 feature bit 存在 policy descriptor 中，不再单独发布到静态 flag map。

`control/reload/transaction.rs` 在候选准备与提交外层持有 `reload_lock`。新代发布依次取得 `router` → `config` → `datapath_flags.publication()`（仅原生显式源激活）→ `ebpf`，随后是 DNS projection-publication guard → `group_manager` → `outbound_id_map` → `active_routing_plan` → `runtime_registry`；provider 的 DNS publication guard 在这些 guard 内准备。原生 no-op 激活取得 `config` → flags publication → `ebpf`，不替换 Router。`mode.rs` 独立 mode/fence 更新按 flags mutex → `ebpf`；`reset_for_activation` 不重新取得这两者，也不 await。NFQUEUE fence/reopen 在 router/config 发布 guard 外运行。这只是记录既有锁边，不授权新增锁边；变更仍须遵守 CONTRIBUTING §2/§11 与人工审查。

`RoutingPushPlan::compile` 是唯一用户态 lowering 路径；调用方不选择 slot，也没有独立 domain-publication handshake。`routing_policy.rs` ABI 分别为 `RoutingInput` 128 字节、`RoutingDecision` 24 字节与 `RoutingPolicyDescriptor` 24 字节。真实 eBPF 要求 Linux 6.12+；生成的进程名匹配代码在固定偏移读取前检查 `pname_len`，以符合 6.12 verifier。已加载路由 slot 的 BTF 必须暴露当前输出布局。

提交前失败保留活动代码与事实，不再重放旧路由计划。Fence 后发布被拒绝时，控制器恢复组连通性并重开旧 generation；连通性恢复失败则继续拒绝准入。Root 切换成功后新 generation 已提交，之后若 NFQUEUE 重开失败，保留已发布的新 generation 并继续 fence 准入，直到后续成功 reload 修复。

候选构建仅在路由输入及内容指纹未变时复用不可变用户态 `Router` 与编译 DNS router。Hosts 及被引用的 Geo 资源在解析前计算指纹；内容变化会强制替换。仅当完整 `RoutingPushPlan` 与 learned-domain projection 字节均未变时，才跳过 native 路由发布；数据路径健康状态仍会强制执行恢复性发布。

`DnsServiceProvider` 是一致的 DNS generation pointer。请求 lease 保留其 generation 的 forwarder、projection、transport pool 和出站运行时，直到退役。出站 registry 同样按 generation 持有：未变化的 node runtime 只在提交点转移，旧 registry 把这些 runtime 标记为已移出，然后开始优雅退役。现有 stream 与 `Ready` UDP endpoint 保持引用，同时旧 reusable pool 停止接受新工作并排空。

编译路由发布有独立于 DNS runtime generation 的[进程生命周期上限](./routing.md#同步槽与原子发布)。发布后，排队中的 UDP53 与原始 `must` TCP53 元数据可能按上述准入规则被拒绝；已准入 DNS 查询仍按固定代际排空。

`DrainTracker` 是进程全局的 accepted-flow gate。Reload 和关闭在 drain 前设置 reject-new；关闭最多等待五秒，然后带着剩余计数继续拆除。

Selector 与 UDP warm 所有权仍绑定 generation，见[预热所有权](./groups.md#预热与所有权)。

- `src/mode.rs` — `DatapathFlagsHandle` 在同一异步互斥锁下串行更新 `ModeState` 与 `DATAPATH_FLAGS_MAP`。Initialize/mode/GLOBAL/static 更新与 NFQUEUE fence/reopen/disable 协同，避免并发 API 更新在 reload 中重新发布 ready。Fence 完成前须发布 READY=false、等待内核 reader-epoch grace period，并移除全部未交付的 Preparing/Pending 状态。

### 需要重启的变更

当前进程级消费者在以下任一值变化时拒绝 `SIGHUP` reload：

| 区域 | 需要重启的字段 |
| --- | --- |
| Listener/数据路径 | `global.tproxy_port`、`global.tproxy_mark`、`global.tproxy_port_protect`、`global.pprof_port`、`global.so_mark_from_dae`、`global.lan_interface`、`global.wan_interface`、`global.auto_config_kernel_parameter` |
| 进程状态 | `global.log_level`、`global.data_dir`、`global.store_subscribe` |
| DNS listener | `dns.bind` endpoint 或 transport 的语义变更 |
| Clash API | `experimental.clash_api.external_controller`、`external_ui`、`secret`、`default_mode`；生效的 `assets.ui.url` 和 `assets.ui.route` |
| 原生 API | 任意 `experimental.native_api` 变更；生效的 `assets.geodata.geosite`、`assets.geodata.geoip`、`assets.geodata.route` |
| 持久化 | `experimental.cache_file.enabled`、`store_dns` |
| NFQUEUE | `global.nfqueue_enable` |
| 健康检查与 TLS | `global.check_interval`、生效的第一个 `global.tcp_check_url`、启用 HTTP 检查时的 `global.tcp_check_http_method`、选中的 `global.udp_check_dns` 目标，或原生 TLS/uTLS 模式切换（参见[健康检查重载语义](../reference/global.md#重载健康检查与-tls-模式)） |

UI 与 geodata 的生效设置包含从 `assets.route` 继承的值；该默认出口的变更若影响任一启动阶段持有的下载出口，则需重启。`assets.subscription` 默认值与订阅条目设置交由订阅协调处理。

当旧值和新值都能解析时，`dns.bind` 的语义比较使用解析后的 bind endpoint，因此描述同一 endpoint 的纯拼写变更不会强制重启。

`EbpfBackend` 负责 token/state 检查、`commit_udp_decision(key, token, transition)`、token 校验的 abort/removal、内核 staging quiescence、兼容回滚的持久化 allocator 校验、状态查询与重置，以及 routing/map 操作。12 字节 pin 的 `next` 保存完整 raw token：两位 generation + 28 位 sequence；启动不重写。只有暂存路径的 fence 与排空完成，且候选 **及直到 3 的全部更高 generation** 均未出现在 live conn-state/handoff/redirect/retirement-fence map 中，才允许 reset。回滚后的旧 allocator 会从 reset 值单调递增，因此整个后缀都必须为空。

## 订阅编排

启动时先解析已存正文，再开始网络刷新。有效且非空的恢复结果立即提供节点，并从五秒首次拉取等待中移除该订阅。只有未有效恢复的 direct 订阅进入共享 grace；经路由的拉取等待路由就绪，不阻塞启动。之后仍在后台联网刷新。

`ControlPlane::run` 首次被 poll 时便取得控制命令接收端的所有权，早于所有启动阶段的 await。这个已开始运行的 future 返回或被丢弃时，即使监听器启动失败也会关闭通道，使阻塞在满队列上的订阅投递解除等待，随后调用方才能等待 supervisor 关闭。

`SIGHUP` 会按 fetch 身份（URL + 配置的 User-Agent + headers）稳定订阅 ID，并把活动订阅节点带入候选配置，但不恢复缓存正文。网络、解析或没有可用节点的失败会保留活动节点，不替换上一次有效正文。持久化失败不是致命错误：校验成功的节点仍可合并，旧正文仍可恢复。定期刷新与立即刷新使用同一串行的 runtime 发布路径，订阅节点不会写回配置文件。

正文通过校验与运行时发布分别报告。节点集合准入失败时，只输出一次脱敏诊断，并保留活动配置；已经保存的正文不会回滚。

当 `global.store_subscribe` 启用时，通过校验的原始响应存放在固定状态数据库 `<data_dir>/state/honk.db` 的 `subscription_body` 表，key 由请求 URL、配置的 user-agent 覆盖值与有序 headers 决定。完整正文在一个 SQLite 事务中替换，单份最多 8 MiB、总量最多 32 MiB。启动从 `<data_dir>`、`/var/share/honk`、CWD 下找到的第一个私有旧 `.sub` 目录一次导入已启用订阅正文；已有行优先，已复制文件与临时文件被删除，未导入正文保留供后续符合条件的启动处理。迁移与失败细节见[订阅参考](../reference/subscription.md#拉取持久化与恢复)。

- `src/subscription.rs` 负责拉取与解析；`subscription/store.rs` 持有 SQLite 正文存储与 FD 相对的旧存储导入。`subscription/supervisor.rs` 将当前授权及 deferred/可刷新调度状态放在同一 provider record；`supervisor/startup.rs` 恢复缓存正文并执行仅限 direct 的共用五秒启动宽限。启动与稳态使用同一 supervisor state；在途工作独立保留捕获的 revision 与发布确认，关闭等待其结束，reconcile 不丢弃可能已提交的确认。
- 守护进程的拉取/恢复路径与 `honk-tool sub` 的本地文件共用正文格式检测。`Simple`/`Custom` 接受 BOM、可换行的标准/URL-safe Base64、原始分享链接、Clash YAML/JSON、SIP008、sing-box JSON，以及 Surge/Surfboard/Loon/Quantumult X 记录。`src/subscription/json.rs` 与 `records.rs` 规范化外部记录，`clash.rs` 构造并校验类型化节点。
  只导入节点，不导入完整配置中的路由、DNS 或组。原生 JSON 保留以 Unicode 代理项对编码的名称。跳过不支持的节点，身份重复时保留首个可用节点，空结果不替换活动订阅。导入的 Trojan/AnyTLS/QUIC 节点必须使用 TLS，不会静默降级为明文。
  Clash 与 sing-box 的 TCP ALPN 归入共享 TLS 模型，而不是 TUIC 的 QUIC 字段。共享构造器的跳过告警只包含从 1 开始的代理序号和静态拒绝原因，不包含原始节点记录或凭据。

## 原生观测 API

独立且需显式编译的 `native-api` feature（以 `--features native-api` 或 `native-ui` 构建；发布产物包含）提供默认关闭的 listener，启用后在控制面准入前绑定。按需 phase watch 仅在真实 admission-open 成功后报告 running，在关闭栅栏前报告 draining；现有 health handle 可将 running 细化为 degraded。读取 generation 与 health 期间保留 config 发布屏障，不改变发布锁序。HTTP 可用不代表数据面健康。

`native_api/server.rs` 完整持有 listener、64 连接 JoinSet、唯一一秒 sampler 与 native tracker consumer，直到关闭 join。Header 预算五秒，30 秒读空闲期限仅在该连接没有进行中请求时生效（请求自 body 结束至响应完成视为进行中），停滞写入另有独立 30 秒期限，健康 SSE 与慢 handler 可持续超过 30 秒；accept 错误记录日志后重试，EMFILE/ENFILE/ENOBUFS/ENOMEM 退避 100 ms；连接任务失败只记录日志，不终止 server；HTTP 关闭共享五秒 grace，随后等待已准入的真实阻塞凭据任务结束。`crate::observe`（`observe.rs` 的 `Observation`、flows、rules、catalog 身份、`DnsRecorder`）拥有进程身份与引擎侧有界存储，独立于客户端；`native_api` 只负责 HTTP 投影。未启用 `native-api` 时观测 hook 编译为零开销 inert 替身。TCP/UDP/DNS producer 在真实执行点捕获不可变来源证据，已接受发布在既有屏障下发出 generation 事件。逐 flow 完整性描述已捕获的执行进度，独立于生命周期与总体覆盖；native-only final handoff 不重复生成旧选路证据，不宣称完整内核透明观测。日志直接捕获审查过的结构化安全字段，不转发 Clash 格式化输出；`/events` 与 `/logs` 续传均为 ready → replay → live。

`native_api/handlers.rs` 为每个资源只注册一份方法分派；共用安全边界仍先于方法和资源校验执行。`observe/flows/record.rs` 持有类型化摘要、输入及证据步骤，留存预算计入实际持有的堆容量、snapshot 与有界内核字典预留，JSON 只在 wire 边界投影。核心生命周期与模式命令返回类型化结果，而不是 HTTP 错误或 JSON。

`observe/flows/producer.rs` 持有 FlowGuard 更新及 TCP/UDP、DNS 共用的组选择证据投影。DNS wire 输入模型归入统一 record；`observe/flows/dns.rs` 保留 lookup/catalog scope 与 DNS 专属捕获。`auth.rs` 持有会话、有界准入和唯一受跟踪的阻塞任务；storage 子模块发布短时持有的凭据状态，不跨 KDF 或 SQL 持有状态锁。

`control/connection/observation.rs` 根据已捕获的 handoff、route、selection 和 transport 事实组装 TCP/UDP 证据。连接编排不构造 wire record，也不使用当前配置重算历史；关闭记录时不分配 capture，精确连接关闭仍独立于记录。

`observe/flows/dns.rs` 与 outbound flow observer 为 scoped/retained 工作绑定实际 lookup、attempt 与 generation 身份。会话 attachment、逻辑 open/readiness 重试与新物理连接、协议确认分开。可选异步 scope 借用调用方 pin 的操作，不复制大型 future 状态；pin 不越过操作的所有权/析构边界。内核证据使用不可变编译字典与报文绑定 witness；UDP receive priority 来自原生辅助元数据，或严格对应 syscall/batch 的 receiver-owned fallback。丢失只改变证据，不改变路由或报文交付。

既有原生 sampler 通过 `DatapathFlagsHandle` 同步实际 flow 需求，保留模式/NFQUEUE 位，仅在后端写入成功后提交追踪准入。等待后端所有权后重新读取需求，sampler 停止并 join 后再同步一次；不新增 writer、timer 或路由重编译。内核对每次调用复用同一 flags 快照来控制可选 witness 生产，已保留的捕获与真实路由判定不受后续需求变化重解释。

TCP copy 成功读取与 splice 成功写入实时累加既有逐出站 atomics；成功接受的嗅探前缀仅计一次，部分写失败也保留已写字节。Relay 关闭或取消不再次累加总量。既有统计与原生采样共用这些计数，UDP 原逐包语义不变。Wire 契约、上限与未知字段见 [API 参考](../reference/api.md#原生-api)。

出站读取保留共用账本的 `kind/name` 与完整 UInt64，reload 不重置计数生命周期。`telemetry.rs` 复用唯一一秒 sampler（Skip），无客户端也保留各 600 点/600 秒的流量与内存 history；关闭对应记录开关并重启后释放缓冲，不插值或补零。内存读取实际 RSS/cgroup v2 文件，未知值为 null，未实现 kernel memory 核算。

`configuration/accepted.rs` 持有启动捕获的 `.dae` accepted 源及发布栅栏，`native_api/config.rs` 只投影权限与 HTTP。原生协调器在读盘前串行化 API 写入和 SIGHUP 加载，`configuration::Activation` 为 native 与 nonnative 调用方共用 reload、reply、订阅 reconciliation 链。HTTP 断开不取消 daemon-owned 任务，同 scope/key/body 重放共用结果；PUT 的 202 仅代表耐久写入且真实 reload 已排队。外部编辑器仍可能在最后检查与 rename 间竞争，rename 后目录 fsync 失败必须报告已写但耐久性未确认，不能称为回滚。

`native_api/config/http.rs` 持有源 HTTP adapter。数据库记录通过 awaited blocking promotion 由协调器持续持有，包括 HTTP 取消与关闭；待记录的新 accepted 源不会被错误标成旧的耐久 revision。

Accepted 源在真实 no-op 或 commit 时随原有 config 发布屏障更新，遵循上述包含 datapath flags publication 的锁序及订阅 revision fence。拒绝 reload 保留旧快照/代次但不回滚已写文件；提交后 degraded 保留新快照/代次并令 operation 失败。API operation 的真实结果投影到 GET、`runtime.last_reload` 与 `operation.updated`，SIGHUP 本身不创建 API operation。注释变更可更新 source hash/config revision 而不推进 runtime generation，有效组成员变更影响 revision，健康变化不影响。

Selector 写入由同一 control/reload owner 序列化，TCP/UDP 分开保存，both 原子发布；Clash 写 both、读 TCP 投影。精确连接关闭绑定 TCP UUID 或 UDP token/generation/source view，等待实际 transport 与 backend/driver 退役，不用 tracker 删除充数；同一 owner 的重复 close 共用完成结果与失败，不存在或 replacement 才是 Gone。组中断按捕获的组路径与网络关闭旧 owner，在同步 guard 外等待。组 PATCH 使用 parser span、原源码协调器，写前及 reload lock 下都检查 accepted revision，独立检查 hash/依赖。Provider 并发发布可使已写文件不能激活，必须保留 written/committed 区分；自动策略的分网络 pin/clear 已开放，pin 只属于当前 GroupManager。

主文件创建/删除复用相同协调器、parser span、revision fence 与 reload reply，但等真实激活后才返回 201/200。订阅 supervisor 持有绑定身份的初次拉取延迟，所有离线准入都携带这些排除项和有效运行时数据目录。Geodata 先暂存并验证所有资产，再经 FD 相对替换；临时不可变 `SourceUpdate.geo_sources` 同时进入 reload 的两条路径，发布后不再由 accepted 源元数据保留。Router/DnsRouter 保留实际加载字节的元数据，观测按 router-before-config 锁序且不重读磁盘；部分文件替换与提交后降级如实报告，不承诺回滚。

暂存 writer 返回保留的 installed-file FD 及耐久结果；geodata 从待替换文件推进到 installed guards，不再重新打开文件重建所有权。路径、inode 与字节复查仍拒绝外部编辑；可见但未确认耐久的替换仍明确报告。

激活执行只产生一份类型化完成结果，分别投影到 operation、管理响应和 SIGHUP 日志。创建响应在协调器接受下一项修改前保留已提交的资源表示。源元数据在取得 config 写锁前准备，发布时复核捕获的 revision/generation。Rename 前的依赖复查将逻辑读取方绑定到规范化目标及字节：有序 hosts/ECH 引用、订阅声明位置与 geodata 类型。它重新发现 source/glob 和依赖选择，但不重复编译未变化的已准入候选；交换两个读取方的文件目标仍会冲突。

Probe worker 拥有有界准备/排队/执行/清理，DNS 诊断使用真实 generation 与精确缓存 owner，provider refresh 由 SubscriptionSupervisor 拉取并等待 revision-fenced publication；GET 不伪造这些 producer。Routing trace 只模拟当前 compiled predicate，不 DNS/探测/选组；当前规则字典只在 parser 来源可用时提供脱敏 source location。Runtime settings 由一个 owner 先校验全量 merge 再发布，native+Clash mode 共用 `DatapathFlagsHandle`。Native 启用时模式不恢复/持久化；显式接受配置激活（含 no-op）重置 Rule 与 settings，provider/network refresh 不重置。

自动诊断采集由 `native_api/settings.rs` 持有相互独立的需求：成功的 flow GET 或显式 flow-event kind/`flow_id` 开启 flows，logs stream 开启 logs，成功的 DNS-log GET 开启 DNS log。普通 events 只维持自己的 attachment，不开启这三个 recorder。准入失败及普通 API/validation 请求不增加诊断需求。每个 stream lease 只释放其实际取得的集合；每类 recorder 独立保有最后需求释放后的六十秒 grace，不由其他读取/stream 续期。配置许可与显式 runtime On/Off 仍有优先权；显式激活重置 override，provider/network refresh 保留。

Probe 准备阶段将捕获的计划消费为具体地址的可执行尝试或明确的家族地址不可用结果。DNS-owned resolver 保留代次及 canonical accepted-positive 应答资格；即使另一家族有地址，终止性 packet refusal 也拒绝整个准备。健康 ticket 与探测配置在同一发布屏障内捕获。

Native cold/warm HTTP probe 与 URLTest 共用 dial/TLS/ALPN 和 H1/H2 exchange；native 保留总 deadline 且不写 Score，传统调用方保留分阶段预算。临时 runtime 的 joined cleanup 返回类型化结果：私有 child panic 令 operation 失败并阻止之后成功确认暂停，但保留已完成的测量证据；主动取消不伪造不健康样本。

显式激活已提交 routing/config 后若 backend mode reset 失败，保留先前 mode/source，但 settings 已恢复配置值；事务报告 committed-degraded 并关闭准入，operation 失败。不把这一结果写成 mode 已重置为 Rule 或旧配置仍 active。

原生 mode 资源因固定 PUT 契约缺少生命周期冲突及 owner/backend 不可用的响应而暂缓；同一 capability 覆盖读写，所以 GET/HEAD/PUT 均返回 `404 capability_not_supported`。内部临时模式、Clash 控制与上述激活 reset 不受影响。

### 终止所有权

`control/lifecycle/teardown.rs` 共用网络清理支持存在或不存在 listener epoch，涵盖部分启动。独立 DNS supervisor 保留已回收 child 的失败，并经 joined teardown 传播；主动关闭导致的取消是中性的，但 owner panic 会使清理失败。

网络维护任务属于 `RuntimeEpoch`。延迟缓存 writer 属于进程，仅在终止关闭时 join。

已开始的 blocking 工作无法靠取消 async waiter 停止，持有它的 owner 必须等待实际 join。通用 cleanup/join 阶段使用十秒 `STAGE_TIMEOUT`，超时的已 join async task 会被 abort，teardown 报告失败。`control/cache.rs::StateTick` 是例外：十秒后告警并继续 join 真实维护任务及在途 blocking SQLite 写入，不 abort；取消这次等待时 handle 仍留在 owner，可再次等待；owner 被 Drop 时只发出停止信号，外层 task 继续持有 blocking 写入。因此总关闭时间没有严格十秒上限。TCP 连接任务 panic 时记录日志并回收，不停止引擎。正常退出保留既有 accepted-flow 五秒 drain grace，故障退出可跳过；原生 HTTP 另有五秒 graceful drain。

健康检查 owner 也会在五秒 drain deadline 后继续等待实际 drain（包括其阻塞解析任务），再返回 deadline 错误。若后续清理发现子任务失败，该失败优先于 deadline 错误。

## Clash API 与 cache DB

可选 Clash-compatible axum server 是共享引擎 handle 上的用户态视图与修改接口；endpoint 细节见 [API 参考](../reference/api.md)。任一 API 成功绑定，或任一配置组使用 `interrupt_connections` 时启用连接元数据；真实 transport 关闭不等于移除记录。Selector 写入与 accepted-manager 替换串行化，Clash 写 both、读 TCP。运行时缓存表位于固定状态数据库 `<data_dir>/state/honk.db`；旧 `cache_file.path` 与 `cache_id` 仅用于一次导入旧 `cache.db`，不决定活动数据库位置。升级后不设 `cache_file.enabled` 即默认保存 Selector 选择与延迟样本；`true` 额外启用 mode/GLOBAL 以及配合 `store_dns` 的 DNS 应答，`false` 禁用这类缓存持久化。Mode 仅在 native 未启用时持久化。目录锁覆盖全部已持有 SQLite connection 的存活期，包括 cache writer connection 到线程退出。见 [Experimental 参考](../reference/experimental.md)。

- `src/stats.rs` — `StatsManager` 持有固定、无分配的 `GET /stats` UDP schema。`udp.nfqueue` 包含 listener/correlator 计数、actor 队列深度、排队字节数与最老条目的等待时间、当前队列深度、跨 hard rebind 累积的进程生命周期内核丢包数、最近一次内核读取的可用性与累计读取错误、held/peak guard gauge、生效接收缓冲大小、终态 verdict、token exhaustion/rotation、verdict error 与 `receiptToVerdict`。该延迟从 listener 收包计到 verdict 成功，不是内核队列驻留时间。顶层 `warm.sessions` 报告保留的 `anytls`、`vless` pool session 及各协议 QUIC client。
- `src/clash_api.rs` + `clash_api/{logs,doh,ui}.rs` — Clash REST/WS API 与外部 UI。UI 目录缺失或为空时在后台下载；URL/detour 优先级见[配置指南](../configuration.md)。`GET /stats` 返回用户态统计，不是 eBPF `OUTBOUND_STATS`；经鉴权的 `/stats.score.groups[]` 包含 `name`、TCP/UDP 原因计数、`verification` 与 `budget`。Mode/GLOBAL 修改通过 `DatapathFlagsHandle` 原子组合 reload fence 与最新 mode/static bit；Selector 修改通过 group manager。Score 组保留 `type: "url_test"`，在 `now` 显示当前聚合 TCP 胜者，并拒绝 `PUT /proxies/{name}`。不返回 score cell 或私有 target 数据。
- Clash API 成功绑定或任一组配置 `interrupt_connections` 时才启动连接元数据跟踪。API 关闭只移除自己的 consumer；由组触发的中断仍然有效。

## 相关文档

- [数据路径设计](./datapath.md)
- [路由设计](./routing.md)
- [NFQUEUE 设计](./nfqueue.md)
- [出站设计](./outbound.md)
- [组设计](./groups.md)
