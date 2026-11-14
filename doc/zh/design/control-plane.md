# 用户态控制面

`honk-core` 用户态引擎连接内核数据路径与出站栈。

## 范围

控制面负责透明代理入口、内核交接、用户态路由、嗅探、出站选择、中继、资源 admission 和运行时发布。内核怎么把流量交给用户态，见[数据路径设计](./datapath.md)。代理组策略和健康状态怎么驱动选择，见[代理组设计](./groups.md)；DNS 运行时行为见 [DNS 设计](./dns.md)。

主要实现在 `crates/honk-core/src/control/`。控制面读取 `EbpfBackend` 状态，并把 TCP 流或 `PacketTransport` UDP 契约交给 `honk-outbound`。

模块分工：

- `src/control/`：
    - `mod.rs` — `ControlPlane` 的[启动与关闭](#启动与关闭)。
    - `connection/` — 规范的[流初始化器](#嗅探与流初始化)。
    - `nfqueue/` — `PendingUdpVerdicts` correlator；[NFQUEUE 暂存协议](./nfqueue.md)。
    - `sockets.rs` — [透明代理入口](#透明代理入口)、anyfrom 回复；`udp_ingress.rs` 负责 `udp_fast_path`。
    - `dns_control.rs` — `DnsController`；[查询 admission 与投影](./dns.md#解析管线)。
    - `dns_listener.rs` — `DnsListener`；[独立入口生命周期](./dns.md#入口路径)。
    - `reload/` — `apply_runtime_config`；[运行时发布](#reload-与运行时-generation)。
    - `routing_matcher.rs` — [原子路由发布](./routing.md#同步槽与原子发布)与[内核规则 lowering](./routing.md#受限原生后端)。
    - `quic.rs`、`packet_sniffer.rs`、`tcp_sniff.rs` — 分别负责 QUIC 解密/重组、逐流嗅探 session 与 TCP 负缓存。
    - `udp_endpoint/mod.rs` — `UdpEndpointPool`；[endpoint 事务](#udp-endpoint-流水线)。
    - `probers.rs` — `ProxyUdpProber`；`probers/http.rs` — `ProxyHttpProber`；[健康探测](./groups.md#健康状态与探测)。
    - `janitor.rs` — `BpfJanitor` 的调度与压力策略；`janitor/sweep.rs` 持有 [map 维护](./datapath.md#用户态维护与计数)的有界扫描与 fenced retirement；`janitor/health.rs` 持有 map 压力与 BPF 失败计数 warning。
    - `retirement_worker.rs` — joined TCP/UDP/hint 退役所有权；`drain.rs` 持有 `DrainTracker` 与[已接受流的排空](#reload-与运行时-generation)。

## 启动与关闭

- `src/lib.rs` — `run()`、`Cli`/`ClashCommand`、资源限制、后端选择，以及固定队列的启动前置检查，见[配置指南](../configuration.md)。真实实例持有 `/run/honk-core.lock`，并把自己发布成 `reload` 用的 PID。`src/daens.rs` 负责 FD 持有的 `daens`/`dae0` 初始化和有作用域的命名空间切换；`src/sysctl.rs` 负责写 sysctl 并验证加固结果。加载或复用持久化的 allocator pin，然后在数据路径 admission 之前启动 NFQUEUE。

配置诊断在初始化 tracing 之前就收集。加载或配置校验提前失败时，先往标准错误输出已有的非终止诊断，每条只输出一次，然后由二进制程序返回一次脱敏后的终止错误。加载成功时，诊断会等到配置指定的 tracing 订阅器就绪后再输出。之后运行时的致命错误仍按原有方式写入日志文件。

启动时保持内核 admission 关闭，直到用户态能够接收每个重定向流：

1. 真实模式取得 `/run/honk-core.lock`，最多等待 240 秒让前一个实例退出，并把进程 PID 发布到已锁文件；`honk-core reload` 读取该 PID 并发送 `SIGHUP`。未取得锁的后继实例在读取配置和打开状态数据库之前退出。Mock 模式不取得进程全局锁。
2. 加载并校验配置、选择 `global.data_dir`，在任何网络 I/O 前初始化进程 bypass mark，提升 `RLIMIT_NOFILE`，并取得一次不可变的描述符预算快照。
3. 在网络刷新前恢复持久化订阅。只有没有有效已恢复内容的订阅，才参与五秒首次拉取宽限期。
4. 真实实例完成锁交接后，再探测固定 NFQUEUE 队列的前置条件。mock 模式、不带 `ebpf` 的模式，或前置检查失败时，记 warning，只在本进程关掉 NFQUEUE；前置检查不会拒绝保留的 nftables table，因为安装阶段会回收残留的自有状态。
5. 真实模式下，`src/daens.rs` 通过 rtnetlink 创建 FD 持有的 `daens` 命名空间和 `dae0`/`dae0peer` 链路。引擎优先尝试 L2 netkit pair，只有内核报告不支持 netkit 时才回退到 veth。进程留在宿主命名空间；只有同步的 socket、链路和挂接操作通过 `daens::with_daens_netns` 进入 `daens`。
6. 加载 BPF 对象并绑定真实数据路径 hook。默认对象通过 `include_bytes!` 嵌入，`--bpf-object` 提供运行时覆盖。启用 `ebpf` feature 时，`build.rs` 会定位对象，拒绝过期或没有 BTF 的产物，在移除继承的 `RUSTFLAGS` 和 `CARGO_ENCODED_RUSTFLAGS` 之后用 nightly 重建，校验 `.BTF`，再复制到 `OUT_DIR` 供嵌入。`dae0` 就绪后，启动流程按[接口协调](./datapath.md#接口协调)执行，绑定顺序和失败条件都由那一节定义。`local_ip` 遵循[本地路由不变量](./overview.md#运行时不变量)。
7. 复用或创建固定的 `UDP_DECISION_SEQUENCE` 分配器，并校验它的 map ABI、BTF、加锁值、token 范围和耗尽状态。NFQUEUE 启动时会再查一次加锁的分配器状态；如果没有回滚安全的 generation，就保持暂存关闭。
8. 构建用户态 Router、出站运行时 registry、DNS 运行时、GroupManager、cache DB、可选的 Clash API，以及控制面 supervisor。
9. 绑定透明 TCP/UDP listener，发布完整的 listener FD 集，启动独立 DNS 和 UDP 接收循环。只有生效开关还开着时，才启动 NFQUEUE 服务，以及它的 ingest actor、correlator、watchdog 和独立的队列压力采样器，采样器每秒采一次。
10. 检查 NFQUEUE 健康状态，发布 ready，开放 pending verdict admission，最后把
    `DATAPATH_STATE_MAP[0]` 设为 ready。之后 TCP accept loop 在控制面 supervisor
    里运行。

`RealEbpfBackend` 负责 aya program、map、link、持久分配器处理和真实的 NFQUEUE 集
成。`MockEbpfBackend` 在没有特权内核资源时，提供同样的控制面接口。请求的 NFQUEUE
路径如果过不了锁交接后的固定队列前置检查，或者过不了随后 admission 之前的队列、
规则、健康检查，honk 会记一条 warning 并关掉 NFQUEUE；这个启动降级在 reload 之后
仍然生效，见[全局配置参考](../reference/global.md)。持久化 token generation 恢复
失败，以及服务 admission 之后的失败，仍然是 fatal。

对象 admission 会在进程名 probe 和任何 Aya loader 之前，拒绝隐式的 `ByName` map pinning。外部对象必须声明未 pin 的 map；包括持久分配器在内，所有 pin 路径都由 core 显式提供，免得 loader 造出的别名逃出启动回滚。

真实 backend 在 pin map 之后启动失败时，启动 guard 只删除本次成功创建的临时 pin；没能替换的已有 pin，以及无关的已有 pin，都不归本次所有。`UDP_DECISION_SEQUENCE` 和 `ROUTING_GENERATION_SEQUENCE` 在启动失败和普通清理之后都会保留；启动成功时，临时 pin 的所有权转给 backend 清理。

关闭时在资源消失之前逆序释放所有权。顺序是：fence NFQUEUE；关闭数据路径 admission；拒绝新的用户态工作；取消并排空持有的 verdict 和 UDP initializer；停止 UDP driver 和 removal 处理；停止接口 watcher，并等进行中的批次结束；卸载 BPF hook；按[业务连接宽限等待](../reference/global.md#关闭)规则执行可选等待；关闭剩余连接；退役出站运行时；停止 NFQUEUE；停止 DNS controller 和 persistence；最后清理 generation 持有的 BPF 状态。普通清理保留固定分配器。之后 listener 和 `daens`/link-pair 的所有权离开作用域。

UDP receive-priority 的辅助元数据不可用时，真实 backend 会保留 receive-trace fallback 用的 link 和 map。每个地址族都必须有完整的 enter/exit 对：失败就卸载这一对，不会因此禁用另一个地址族。两个地址族都依赖 `__skb_recv_udp` 上共享的 hook，它失败时两者都不可用。注册时会检查 socket 地址族，所以缺少对应 hook 对的 listener 会报告不可用，而不是在没有证据的情况下静默注册。每个 backend 只尝试一次 fallback，失败或只成功一部分也一样。listener reload 会重新检查原生辅助元数据的支持和注册结果，但不会重试挂接；改了内核或 BTF 支持后需要重启。追踪缺失只影响已经记录的内核路由证据，不改变路由，也不影响 UDP 交付。`cleanup()` 先卸载 ingress hook，join ring consumer，然后在 BPF 对象释放之前 drop `receive_trace`；即使 backend 自己还活着，也会释放这些资源，不等到它的 Drop。普通清理仍保留两个持久化 sequence pin。

## 透明代理入口

真实 TCP 和 UDP listener 在 `daens` 里创建，带上透明 socket 选项和有效的 `global.so_mark_from_dae`；这个值配成零时用 `0x100`。数据路径靠这个 mark 把它们认成 honk 自己的 listener，而不是普通本地服务。已接受的 TCP socket 会继承 mark，所以每个 accept loop 在处理流之前先把它清零。Mock listener 只是宿主命名空间里的普通 socket，没有特权透明选项。

原始目的地址按下表恢复：

| 入口 | 首选来源 | 回退 |
| --- | --- | --- |
| TCP/IPv4 | `SO_ORIGINAL_DST` | 透明 socket 的 `local_addr()` |
| TCP/IPv6 | `IP6T_SO_ORIGINAL_DST` | 透明 socket 的 `local_addr()` |
| UDP | `IP_RECVORIGDSTADDR` / IPv6 original-destination cmsg | 下文所述的受约束 provenance 规则 |

真实 TCP 先验证 accepted-FD 的所有权，再用这个 socket 上不可变的 SYN handoff。证明缺失或已被替代时，honk 关闭 socket，不会退而使用当前 tuple 元数据。普通 UDP 按捕获的 incarnation 和 decision token，以非破坏性方式读取 handoff。所有权已经确认的 `ControlPlaneRouting` 结果，或者允许缺 handoff 的 token-zero UDP，仍可以用 `Router::route_action`。最终的 `must` 和 `block` 结果不受 Clash mode 覆盖；透明 DNS 保留自己的所有权边界。

端口 53 上控制器和原始转发的归属，按[有序流量规则契约](../reference/routing.md#出站目标与-must)处理，畸形的非 `must` UDP 也走那条通用回退。

真实透明 UDP/53 无论交给控制器还是原始转发，都要求有效的逐报文 `SO_RCVMARK` / `SOL_SOCKET` `SO_MARK` 凭据，以及当前已提交的路由 generation，tuple handoff 替代不了。透明 TCP/53 必须有 SYN handoff；只有原始 `must` TCP 还要求当前路由 generation，并在原始 I/O 之前固定配置、语义分组和出站 runtime。非 `must` TCP 保留控制器的查询 admission，不做那个路由 generation 检查。缺少必需元数据，或必需的 generation 检查失败时，在 I/O 之前就拒绝 admission。物理兼容性见[handoff ABI 与 UDP 携带位](./datapath.md#map-清单)。

## 嗅探与流初始化

嗅探器向规范初始化器提供信息，能帮它解决暂存的决策，但嗅探器不持有 verdict，也没有自己的卸载路径。

TCP 嗅探最多读 4096 字节，从中提取 TLS SNI 或 HTTP `Host`。返回的缓冲区属于流状态，会在中继开始前写进已选出的出站，所以嗅探不会消费应用数据。`dial_mode: ip`、最终的 direct/block 或 `must` handoff、命中 TCP negative cache，这几种情况都跳过 TCP 嗅探。连续三次失败后，同一目的地址和出站签名会被抑制十分钟；嗅探成功则移除 negative 条目。

UDP 域名发现会解密 QUIC v1/v2 的 Initial packet，重组 CRYPTO fragment，再解析 TLS ClientHello 的 SNI。每流 session 五秒过期，最多检查八个 Initial packet，CRYPTO stream 限制在 64 KiB。遇到第一个 ClientHello 分片时，initializer 最多保留八个 FIFO follower，最多等 250 ms。failed-DCID cache 用来限制非 QUIC 或不可解密流量上的重复工作。

`dial_mode: domain` 会对嗅探到的 TCP 或 QUIC 名称做一次 DNS reality check。目的地址的同族答案精确匹配时接受；只有另一地址族的答案时，为兼容双栈仍然保留这个名称。同族不匹配、查询失败或超时，就丢弃嗅探到的名称，按 IP 继续。

`connection/` 是每流 route/sniff/mode/selection 的规范边界。Socket UDP 入口和 NFQUEUE 持有的 payload 都在同一个 `UdpEndpointPool` 里预留同样的 `UdpInitLease`；NFQUEUE 没有第二套 Router 或拨号器，也没有克隆报文、重放或主动重传的路径。暂存流在 token 校验通过的终态转换之前，算出唯一的最终出站和 mark。

`TuplesKey` 的 40 字节 `#[repr(C)]` 布局里有一个显式的三字节 `padding`。内核会把全部 40 字节都参与 hash，所以每个构造入口都必须把这个字段置零；`build_tuples_key` 会零初始化规范 key，retirement 会拒绝 padding 非零的 key。

权威 URLTest 建立失败时，保留按延迟排序的前三候选重赛一轮。Score 所属的建立失败可以按顺序尝试一个不同的合格叶节点，在排名之前就排除失败的身份，即使普通评分还把它排在第一。Score 的两次尝试共享一个绝对 deadline，并保留固定的 generation、Selector 选择，以及首选真正走过的 final 边。类型化拒绝、本地拨号容量耗尽、取消和关闭都是终态，排空 race 里发现的已完成拒绝也一样；应用数据写入之后，以及已经建立的 relay，从不重放。

- `src/sniffing.rs` — 只处理 TCP，提取 TLS SNI 和 HTTP Host，最多 4096 字节，并返回缓冲字节供转发。`parse_client_hello_body` 与 `control/quic.rs` 里的 QUIC sniffer 共用。

## UDP endpoint 流水线

### 目的地址 provenance

`udp_ingress.rs` 负责目的地址校验和有界 admission，`sockets.rs` 负责 syscall/cmsg 解码。真实透明 listener 必须有权威的 ORIGDST；普通 listener 和 mock listener 按下面的回退规则处理。所有路径都会在预留 endpoint 之前拒绝无效元数据：

1. ORIGDST cmsg 存在、有效且已指定时，它就是权威来源。未指定的 ORIGDST 无效，不能回退到其他来源。
2. 没有 ORIGDST 时，只有精确的 DNS query 加上已指定的 `PKTINFO` 目的地址，才能形成 `IP:53`。
3. 其他情况下，只有非 wildcard 的 listener bind 能提供目的地址。
4. 缺失、畸形、重复、截断或未指定的元数据，会在 slow-path 预留或保留 payload 之前丢掉。

UDP 入口在任何可能等待的校验之前先捕获 initializer epoch。原始 UDP/53 按 Config → backend 的读锁顺序验证；带 mark 的直连先取 Router 读锁。在一致快照下校验策略 generation，并固定语义分组，或者固定报文携带的不可变直连 mark 表项，然后通过既有的 epoch gate 预留并入队。同一个 tuple 上不兼容的普通、原始、其他分组或直连 mark 报文会被拒绝，而不是借错 transport。非 `must` 的有效 DNS 保留独立的查询预算；UDP/53 不创建普通 UDP conn-state，也不创建 decision token。重组后的分片经 [NFQUEUE](./nfqueue.md#lan-dns-分片) 共用这份 admission，原包确认丢弃后才发布工作。

归控制器所有的畸形 UDP/53 可以保留兼容的 controller handoff 事实，用于通用路由；但不兼容的终局原始 handoff 及其过期报文事实会被丢弃。

### Transport 与事务

普通 transport 用 `PacketTransport`。原生 handler 包装真实 socket，tunnel 则直接
实现 packet framing。来源共享协议提交类型化的 source attachment，让多个 endpoint
view 共用一个 transport receiver；具体包括 VLESS XUDP/Mux.Cool、Hysteria2、TUIC，
以及所有 `MultiTargetTransport`。控制面不创建 loopback bridge。

Endpoint 创建是事务性的：

1. 先把 `(client, original destination)` 预留成 `Initializing`。lease 持有首个 datagram、queue permit、slow-path permit、token、generation 和 cancellation epoch。
2. 路由、嗅探、选择，并准备合格的 transport。发布之前先创建透明的 anyfrom reply socket。
3. 只提交选中候选的 `PreparedUdpTransport<T>` 或 source preparation。可失败的 commit 返回选中的 `Arc<T>` 或 attachment；drop loser 会自动回滚。
4. 启动 endpoint driver，并等它的 ready barrier。
5. 在共享 epoch fence 下，把精确的 `Initializing` identity 原子替换成 `Ready`。
6. 把保留的首包转过去，通过已提交的 transport 发送，并等 acknowledgement。
7. 按 FIFO 顺序发送嗅探保留的 fragment 和没被碰过的 queue follower，然后进入 steady 的发送和接收路径。

透明 UDP preparation 在路由和选择完成之后开始，到选中 transport 的协议状态
commit 完成才结束。权威路径和冷启动 URLTest 共用一个绝对的
`max(10s, 4 × connect_timeout)` deadline，覆盖解析、物理拨号 admission、控制协商、
stagger 和满容量时的等待，以及 commit。到期后不再启动后续候选，并在返回前排空所
有已启动的 preparation。嗅探和路由在这个边界之前；reply socket 创建、发布和
packet I/O 在它之后，受既有事务和 I/O 上限约束。不会自动重放 packet。

`udp_endpoint/source.rs` 为来源共享协议索引 owner，索引依据是 reused runtime
identity、规范化 client、协议/UDP path，以及 `ActualPeer` 或
`RewriteTo(original destination)`。它持有一条协议 association、一个 receiver 和
多个 endpoint send view。完整的 `(client, destination)` endpoint map 仍然是权威，
持有 route、token、generation 和逐 flow Score。reply classification 不会把已占用
的 wrong-owner、`Initializing` 或 `Retiring` 条目当成 foreign；只有缺失的
`ActualPeer` key 才能做 foreign delivery，而且没有逐 flow Score。domain route 保
持 original destination 的 scope。迟到的 send、reply、removal callback 在动手之
前，会重新校验 owner、token、generation 和 endpoint identity。Source sharing 不
会合并 kernel/NFQUEUE 的 flow ownership：每个规范 endpoint 仍保有独立的 decision
token、generation、terminal transition 和五元组 retirement fence。

关闭 `rprx` 时，共用的 source admission 和 shutdown join 仍然启用，只有 VLESS 分
支受 feature gate 限制。Hy2/TUIC 经有界重组保留真实来源；它们的 QUIC send guard
在 source gate admission 之后开始，并由 driver 保留到最终 I/O 结果分类完成。

每个透明 socket 在一次 readiness 轮次里通过 `recvmmsg` 最多收八个 datagram。每个 slot 独立保留 ORIGDST、PKTINFO 和逐报文 `SO_MARK` 元数据；packet 保持内核顺序，某条元数据异常时也只丢弃对应的 slot。队列排空后，下一次唤醒先用一个 slot；如果读取满载，就立刻恢复八 slot 的 batch，省掉稀疏流量上的准备开销。这个上限把调度公平性和 payload 存储限制在每 socket 512 KiB；现在每个地址族四个 socket，双栈全开时共 4 MiB。listener 循环只做校验、预留和入队，从不等待 `PacketTransport` I/O。Endpoint driver 持有全部 transport 调用。首次发送和稳态发送都用 transport 的 deadline：默认五秒，QUIC 用从路径 SRTT 派生的 deadline。超时或失败可能发生在部分数据已被接受之后，所以 datagram 不重放；单包拥塞可以丢掉这个包继续，终止性失败则结束受影响的流或 source。

SOCKS5 UDP 在整个 source association 生命周期内保持 TCP `UDP ASSOCIATE` 控制流；控制流 EOF 或意外的控制数据都算 association 失败。它的 connected UDP socket 向服务器物理 `BND.ADDR` 中继发送；回复是域名就解析，地址未指定就换成控制连接对端的 IP。每个 header 写入自己的目的地，每个应答返回头部里的真实来源，域名来源只投影成捕获到的名称和端口。`PacketTransport::relay_addr()` 是第一个目的地，所以 SOCKS relay 自己不会被误认成远端 peer。

回复用在 `daens` 里创建、透明绑定到 packet 原始目的地址的 anyfrom socket。通过 transport peer 校验后，按域名拨号的 endpoint 始终用原始 IP、端口和地址族回复，即使远端 DNS 选了别的地址。按 IP 拨号的 endpoint 保留自己的 original-destination socket。普通流和共享 source 的 receiver 共用一个进程级 full-cone 回复 socket 缓存，按 peer 地址索引，每个 endpoint 容量上限七个，空闲超过一个 NAT 超时就清理。超出上限的新 peer 会关掉最久没用的 socket；描述符预算耗尽时，主回复 socket 也照此处理，于是外来回复给新流让位。端口 53 的回复另外共享每个地址族一个透明 socket，并用 `IP_PKTINFO` 或 `IPV6_PKTINFO` 选出精确的源 IP。从 TPROXY listener 回复会带上内部的 `dae0` 源地址，所以不可用。来自其他来源的回复没有精确的 `REDIRECT_TRACK` 记录，`dae0_ingress` 改用只有客户端的 `CLIENT_REPLY_TRACK` 帧信息把它送回客户端，不经过主机转发，限制性的转发策略也不会丢掉它。收到这类回复并不授权客户端随后向该来源发来的包：`lan_egress` 不会从来自 `dae0` 的包学习反向方向，那些包仍走正常路由。

reload 在开始等待之前推进 cancellation epoch。Initializer 在 await 之前捕获这个
epoch 和 incarnation generation；如果 cancellation 比 `commit_ready` 先线性化，
就阻止发布。reload 会取消并排空 `Initializing` lease 及其保留资源，`Ready`
endpoint 仍按既有生命周期走。已有原始 UDP 的 `Ready` session，只要语义分组名相同
且符合该生命周期，就可以保留；`Initializing` 不能跨 reload 存活。编译策略发布之
后，过期的排队路由元数据仍会被 admission 检查拒绝。每次 retirement，包括它的
`Retiring` tombstone，以及每个 acknowledgement，都指定 token 和 generation，所以
延迟的工作删不掉替代的 mapping。

只有编译后的流量计划确实变了，而且旧策略或新策略包含直连 mark 时，才退役直连的
`Ready` endpoint，免得后续流量复用旧的 socket mark。没有变化、不相关的 reload，
以及新旧策略都没有直连 mark 的路由变更，都会保留这些 endpoint。显式标记为用户态
所有的 WAN UDP 决策，包括带 mark 的 `direct(must)`，会在 tuple/reader fence 下同
时清理 token 为零的 conn state、handoff 和 redirect track；原生 LAN
direct/offloaded 决策和更新的非零 token 保持不变。

NFQUEUE 入口由 `PendingUdpVerdicts` 持有 token/generation、phase、FIFO verdict guard 和最终的直连 mark。admission 接收自己持有的 `Bytes`，对应唯一保留的 payload；direct/block 完成后把 initializer 交给内核，proxy 则把身份转入 `Ready`。commit 顺序、deadline 和生命周期由 [NFQUEUE 协议](./nfqueue.md#终态转换)维护。

## Queue 与描述符预算

每个 UDP 流最多保留 64 个 datagram，首包也算在内。所有流共享精确的 8 MiB payload permit 预算。admission 在复制之前取得每流 slot 和全局 byte permit；FIFO 饱和时丢弃最新的 datagram。NFQUEUE 有独立的 ingest actor，限制为 256 个条目和 8 MiB 排队 payload。

启动时，`honk-core` 会尝试提升软 `RLIMIT_NOFILE`，只快照一次活动值，并把预算输入
上限设为 1,048,576。DNS socket 先独立分出 `min(transient_dials, 256)`，同时受剩
余描述符约束。接下来按 `min(after_dns / 8, 8192)` 分配 VLESS carrier，再用剩下的
预算决定 UDP endpoint 数量。到了上限时，固定分区如下：

| owner | 容量 | 描述符记账 |
| --- | ---: | ---: |
| 固定/运行时预留 | 256 | 256 |
| 已接受 TCP 流 | 16,384 | 每个 6 = 98,304 |
| 保留 TCP pool | 2048 | 每个 1 = 2048 |
| 临时出站 dial | 1024 | 每个 1 = 1024 |
| DNS 自有 socket | 256 | 每 socket 一个额度；endpoint 网络 bootstrap 预留两个，原始代理节点的 resolver socket 不计入，见 [DNS admission](./dns.md#解析管线) |
| VLESS 物理 carrier | 8192 | 每个 1 = 8192 |
| UDP endpoint | 32,768 | 每个 10 = 327,680 |
| **合计** |  | **437,760** |

一个 UDP endpoint 的记账包括这些：relay socket、可能存在的 SOCKS5 控制流、自己的
anyfrom reply socket，以及进程级外来池里的一份；每个 endpoint 容量共八个回复
socket。一个 TCP 流按 accepted/outbound socket，加上两组各含两个 FD 的 splice
pipe 记账。更小的限制用同样的饱和分区；VLESS carrier 算出来是零时就保持零。

启动时还会把 UDP endpoint 限制在 `MemTotal` 的四分之一以内，每个 endpoint 按 64 KiB
算：2 GiB 主机是 8,192，8 GiB 及以上到 32,768 的硬上限。实测一个 Shadowsocks 共
享 source 约占 35 KiB，每多一个目的地约 11 KiB，所以这份预算给每流状态更多的
transport 留了余量。不读 cgroup 的内存限制。

进程 VLESS-carrier 的 semaphore 由 traffic generation 和 DNS runtime fork 共享。
carrier 在 actual I/O 的 provisional、active、draining 和 idle 状态下一直持有
permit，直到 task teardown 才释放。物理 FD 的权威上限是这个进程 gate，不是逐节点
pool limit 的总和。耗尽时返回类型化的 local capacity rejection，不影响节点
health 或 Score。

其余 descriptor headroom 是有意不分配的：`RLIMIT_NOFILE` 高，不代表内存或调度能
力一样多。TCP 从描述符导出的 floor 起步，封顶 16,384 个流。它可以借用空闲的非
TCP headroom，但要留一半作为 burst reserve，并且不超过 floor 的两倍。已有流不会
被切断，固定 reserve 留给控制面 FD。

各 admission 上限彼此独立：

| admission | 上限 |
| --- | ---: |
| TCP 流 permit | 描述符导出的 floor，加上对观测到的 idle non-TCP headroom 的有界借用 |
| VLESS 物理 carrier | 启动时固定的 `min(after_dns / 8, 8192)` 进程 gate |
| 冷 non-DNS UDP slow path | `min(udp_endpoints, 256)` |
| UDP DNS 客户端生命周期 | 进程级 `min(1536, MemTotal / 4 / 256 KiB)`，跨 reload 共用 |
| 所有 controller DNS 查询生命周期 | 每个 generation 2,048，TCP 与 UDP 共用 |
| DNS 自有 socket / endpoint 网络 bootstrap | 独立描述符分区支持的进程 gate，最多 256 个额度，跨 reload 共享 |
| DNS 代理 stream / 非原始 UDP 的 packet 准备 | 不超过 DNS socket 上限的进程级保守逻辑 lease；不是所有代理 FD 的总上限 |
| NFQUEUE ingest actor | 256 个条目和 8 MiB |

代理 carrier 的所有权仍独立管理；查询与 socket 的 admission 约束见 [DNS admission](./dns.md#解析管线)。

TCP accept 用的是描述符导出的流预算，没有独立的 256 项上限。[Joined removal worker](./datapath.md#用户态维护与计数) 处理 TCP、UDP 和 expiry hint；UDP 保留 1024 条消息的 channel，以及去重用的 `removal_dirty` 补偿。只有自己的 I/O 和后端退役都完成后，才确认精确的 tombstone。

透明 TCP 先等任一 IP 族的 listener 变成可读，再预留共享流 permit，最后用非阻塞系统调用完成 accept。所以空闲 listener 不占流容量，达到上限后到达的连接还留在内核的 listen backlog 里。`/stats` 的 `tcp` 对象提供 `activeFlows`、`limit` 和 `capacity.rejected`；最后一个统计的是等待 permit 的 accept-loop，不是 accept 之后被丢弃的连接。动态上限低于 256 时，启动会记 warning；网关部署应当提高服务的 `RLIMIT_NOFILE`。

## TCP 中继与 conn-state 所有权

两端都是普通 `TcpStream` 时，`relay_splice` 运行两个并发的 `splice(2)` pump。每个方向持有一条最多 64 KiB 的非阻塞 pipe，所以全双工中继最多请求四个 pipe FD 和 128 KiB pipe page。遇到 EOF 就对另一端的 write side 做 half-close，并允许反方向继续排空。

每个方向的首次 splice 同时是一次 capability probe。如果在任何字节暂存之前返回 `EINVAL`、`ENOSYS`、`EXDEV` 或策略拒绝，也就是 `EPERM`，就可以无损回退到用户态 copy，并设置进程全局 latch，后续连接跳过 probe。pipe 创建失败同样发生在任何字节移动之前，所以只让当前连接改用 copy，不设置 latch。其他错误，或者字节已经暂存之后才说不支持，都会让中继失败，而不是冒数据丢失的风险。TLS 或协议包装的流走 `relay_auto`，它始终使用基于 select 的 copy loop。

未启用 Encryption 的 Vision TLS/REALITY carrier 先走 copy loop。两个方向都进入 Direct、且连接已经转发 256 KiB 之后，relay 会在两个方向都不持有未写出字节的位置交接：一个方向在读取边界，另一个方向挂起在读取上。这时 relay 把 carrier 的 TCP socket 借给同一个双向 splice 引擎，Vision/TLS 栈仍归 relay 所有，carrier pressure 采样也在借出的 socket 上继续。probe 不支持或 pipe 创建失败时，还没有字节移动，relay 就回到同一个 Vision 流的 copy loop；每条连接只尝试一次交接。两个阶段共用连接计数器，统计覆盖整条连接，first-response 回调只触发一次。

copy pump 在读取新输入之前，先 flush 嗅探或协议设置阶段已经缓冲的字节；输入暂时
空闲时也会 flush 待发字节。每个方向先用 8 KiB 缓冲区。第一次读满就判定为大流量，
该方向此后改用 65,535 字节缓冲区，让满载 read 正好装下一个最大的 AnyTLS frame，
不会拆成多次 8 KiB write，也不留下单字节的尾帧，只有首帧较小。空闲和小流量连接不
会扩容，所以一条空闲连接的 copy 缓冲区是 16 KiB，不是 128 KiB。应用不必再发一个
请求，也不必关闭连接，才能把当前请求送出去。

首次 EOF 之后，两条中继路径只限制空闲排空的时间：`DRAIN_DEADLINE` 是没有任何字节进展的 30 秒。活跃的 survivor 可以跑超过 30 秒；静默的 survivor 不能一直占着 accepted socket。

客户端不发 FIN 或 RST 就消失的情况，另外单独限制：TPROXY TCP listener 启用 TCP keepalive，空闲 3600 秒、间隔 15 秒、探测 4 次，accepted socket 继承这套设置。静默客户端大约一小时后结束它的 relay；仍在线的空闲客户端会应答探测，所以长时间空闲的连接保持打开。这种情况报成客户端侧的 `TimedOut`；内核有待处理的 ICMP/ARP 软错误时，则是 `HostUnreachable` 或 `NetworkUnreachable`。两种都按取消结算 Score。

Accepted TCP FD 在 tuple 路由、pin 或取得清理 authority 之前，必须带着原始 SYN 的有效证明；这个证明由 `honk_tcp_passive` 在握手完成时写入。不可变的 handoff 和 incarnation 必须匹配当前的 conn/handoff/redirect 所有权。证明缺失或已被替代时，关闭 socket，但不删除当前 tuple。admission 在同一个 backend 读 guard 内完成校验，保留 tuple-local 的 `TcpFlowPins` 引用和精确的 `TCP_LIVE_PINS` incarnation。内核的 Closing/redirect 老化检查只查这个 incarnation 的原生 pin，所以存活的空闲或半关闭 owner 能恢复传输，不用靠 timer 伪造时间戳。新的 SYN 不继承旧的 pin。

Janitor 的收集阶段在消耗 candidate budget 之前先排除 pinned TCP，并在 backend 写所有权下再查一次当前 pin。child 的 socket storage 保留自己的证明，和 janitor 的状态无关。退役只用 guard 捕获的 incarnation，不会去选 tuple 的后继占用者。

I/O 完成后，joined retirement worker 持有已通过 admission 的 TCP 退役、socket、tracker/close completion 和出站统计 guard，即使等待方取消也不会丢所有权。它的 `FlowPin` 在同一个 backend 写 guard 内释放 local 和精确 native pin，然后才检查外部 owner；释放失败就不能确认清理成功。admission 之前取消会同步 Drop native pin，物理 tuple 的回收交给原子 janitor，不声称已经确认。控制面的 `RetirementPort` 把 native Drop 错误发到当前 worker epoch 的 critical channel，并通过 joined worker handle 收回 hint receiver。Worker 和 janitor 在关闭 warning 之后仍会 join 已通过 admission 的工作，不执行 abort。

普通 UDP 只在冷 admission、异步准备之前捕获一次校验过的 `UdpFlowOwner`，里面有 token 和可选的非零 kernel incarnation；这个 owner 贯穿 initializer、endpoint 和 tombstone。Ready enqueue 不会多查一次 backend。Token-zero UDP 只要任一端口是 53，以及畸形目的端口 53 的回退，都保持无状态；源端口 53 的 transport 不是控制器 DNS，模型执行不声称有原生证明。Hint/janitor 请求真正删除 conn 之后，只通过 tombstone 和 acknowledgement 退役匹配 client/destination/incarnation 的 endpoint，也包括 batch 出错前已经完成的那部分删除。只涉及辅助项、`Missing`、`Superseded`、外来 incarnation、无状态 endpoint 或无身份 owner 的，都不授权退役。

NFQUEUE 冷 cell 重建会在同一个读锁 guard 内保留 conn-state 快照，并调用 backend 自有的 UDP admission 校验。retirement 所有权解决不了，或身份超出 allocator 范围时，不能重建 ActiveDirect 放行；已经通过 admission 的 fast follower 仍保留原有的无查询路径。

真实 relay 完成后，TCP owner 先按实际结果结算一次 Score 和 relay-error 统计，再传播退役失败。退役失败不会把成功的 relay 证据改成取消。TCP 补池仍要求 relay 成功并且退役已确认；主动取消保留自己的中性路径。

`splice.rs` 的 `relay_splice` 在普通 `TcpStream` 之间用双向零拷贝 `splice(2)`，并传播半关闭。每个方向的首次 splice 都会探测 capability。在任何字节进入管道之前，EINVAL、ENOSYS、EXDEV、EPERM 会触发无损 copy 回退，并设置进程级禁用标志；创建管道失败也会回退到 copy，但不设这个标志。不要恢复单向 splice，它曾导致超时。

`relay_auto` 对 TLS 或协议封装的流用同一个基于 select 的 copy loop。`vision.rs` 把 Direct Vision carrier 的 socket 借给同一个双向引擎。两条路径都会在首次 EOF 时半关闭对端，剩下的排空时间只受空闲期限 `DRAIN_DEADLINE` 限制：连续 30 秒没有字节进展才结束，不会截断仍在传输的另一方向。这样，一个不发数据的对端就无法让任务和 socket 长期停在 CLOSE-WAIT。UDP 走 `UdpEndpointPool`。

## Reload 与运行时 generation

SIGHUP 为每次尝试单独收集诊断。不管加载和配置校验成功与否，warning 都只报一次；被拒绝的尝试会另外报一次脱敏后的原因，不进入运行时发布流程。报告这次的诊断不会替换当前运行时状态，也不会新增最近失败尝试的缓存。

公共 reload 事务在指纹比较、no-op 判断和重启检查之前，先归一化候选配置的 NFQUEUE 生效值，并保留已经记录的、早先或较晚的数据路径 admission 前启动降级。原生 API 的写入前检查和完整校验共用这套重启策略，不改写请求的源文本；参见[启动例外](../reference/global.md)和[原生配置 API](../reference/api.md)。

`apply_runtime_config` 先构建替代的 Router、GroupManager、出站 registry、DNS 运行时和路由计划，不动 live state。提交顺序是：

1. fence NFQUEUE readiness，并完成同步的内核 grace barrier。
2. 拒绝新的透明代理 admission。
3. 取消 correlator cell 和 token-bound original，推进 UDP initializer epoch，排空 `Initializing` lease，等 correlator 和已通过 admission 的 commit-pump 工作变空，并排空精确的 endpoint retirement。
4. 编译这个 generation 的 `RoutingPushPlan`。在下面说的发布 guard 内，只有
   compiled plan、learned facts 有变化，或数据路径健康需要恢复时，才调用
   `EbpfBackend::publish_routing_plan(&plan, learned_domains)`。后端起用
   inactive slot，暂存这个 generation 持有的 IP/source/MAC/domain 事实 map，使用
   完整的 256 位谓词值，把生成函数挂到每个相关 target，最后切换
   `ROUTING_POLICY_ROOT`。调用成功后，原生显式激活会用自己的 backend 重置 mode；
   用户态接着在同一串行边界内发布替代的 outbound registry、DNS runtime pointer、
   Router、配置、组和 projection snapshot。root 已经提交之后，如果 mode reset 失
   败，就把新 generation 提交为 degraded，并保持 admission fence。发布完成后，退
   役旧 generation，替换它的 UDP 与 Selector warm coordinator，并同步健康检查节
   点、URLTest 组和自定义组的检查 URL。已经提交但处于 degraded 的 generation 也
   会走完这些步骤，只是 admission 继续 fence。停止 warm coordinator 会取消可能依
   赖另一个 coordinator 的 retention-reconciliation 等待；coordinator 退出之前，
   仍会 abort 并 join 自己派发的子任务。QUIC warm 释放和终止关闭在 client 槽位上
   串行，即使没启用原生任务所有权也一样；取消释放不会提前清空槽位，终止关闭仍能
   拿到 client。
5. 开放 pending admission，最后重开 NFQUEUE。规则派生 feature bit 存在 policy descriptor 中，不再单独发布到静态 flag map。

`control/reload/transaction.rs` 在候选准备和提交之外持有 `reload_lock`。新 generation 发布时，依次取得 `router` → `config` → `datapath_flags.publication()`，这一项只在原生显式源激活时取，然后是 `ebpf`；随后是 DNS projection-publication guard → `group_manager` → `outbound_id_map` → `active_routing_plan` → `runtime_registry`。在这些 guard 内，provider 的 DNS publication guard 会等到 backend staging 完成后再取，紧挨着 registry 权限替换之前，并一直持有到原来的 DNS pointer 提交点。所以 backend staging 不再占着 provider admission 锁，而 registry 转移、回调安装和 Score 权限发布仍会阻止新的旧 generation DNS admission。原生 no-op 激活取 `config` → flags publication → `ebpf`，不替换 Router。`mode.rs` 的独立 mode/fence 更新按 flags mutex → `ebpf` 取锁；`reset_for_activation` 不会重新取这两个锁，也不 await。NFQUEUE fence/reopen 在 router/config 发布 guard 之外运行。这里只是记录现有的锁边，不代表允许新增锁边；改动仍要遵守 CONTRIBUTING §2/§11 和人工审查。

`RoutingPushPlan::compile` 是唯一一条用户态 lowering 路径；调用方不选 slot，也没有独立的 domain-publication 握手。`routing_policy.rs` 的 ABI 是：`RoutingInput` 128 字节、`RoutingDecision` 24 字节、`RoutingPolicyDescriptor` 24 字节。真实 eBPF 要求 Linux 6.12+；生成的进程名匹配代码在固定偏移读取之前检查 `pname_len`，以符合 6.12 的 verifier。已加载路由 slot 的 BTF 必须暴露当前的输出布局。

提交前失败时，保留活动代码和事实，不再重放旧的路由计划。fence 之后发布被拒绝时，控制器恢复组连通性并重开旧 generation；连通性恢复失败就继续拒绝 admission。root 切换成功后，新 generation 就算提交了；之后如果 NFQUEUE 重开失败，保留已发布的新 generation，继续 fence admission，直到后面一次成功的 reload 修好。

候选构建只在路由输入和内容指纹都没变时，复用不可变的用户态 `Router` 和编译好的 DNS router。Hosts 和被引用的 Geo 资源在解析前计算指纹；内容一变就强制替换。只有完整的 `RoutingPushPlan` 和 learned-domain projection 字节都没变时，才跳过 native 路由发布；数据路径健康状态仍会强制执行一次恢复性发布。

`control/reload/dns.rs` 负责 hosts/policy 准备、DNS router 和 hosts 的复用，以及候选 forwarder 的构建；`transaction.rs` 保留 generation 绑定、发布锁、fence 和退役顺序。

`DnsServiceProvider` 是一个一致的 DNS generation pointer。请求 lease 会保留它所属 generation 的 forwarder、projection、transport pool 和出站运行时，直到退役。出站 registry 也按 generation 持有：没变化的 node runtime 只在提交点转移，旧 registry 把这些 runtime 标记为已移出，然后开始优雅退役。现有的 stream 和 `Ready` UDP endpoint 保持引用，同时旧 reusable pool 停止接受新工作并排空。

编译路由的发布有自己独立于 DNS runtime generation 的[进程生命周期上限](./routing.md#同步槽与原子发布)。发布之后，排队中的 UDP53 和原始 `must` TCP53 元数据可能按上面的 admission 规则被拒绝；已经通过 admission 的 DNS 查询仍按固定的 generation 排空。

`DrainTracker` 是进程全局的 accepted-flow gate。reload 和关闭都会设置 reject-new；仅用于关闭的[业务连接宽限等待](../reference/global.md#关闭)不改变 reload 的退役语义。

Selector 和 UDP warm 的所有权仍绑定 generation，见[预热所有权](./groups.md#预热与所有权)。

- `src/mode.rs` — `DatapathFlagsHandle` 在同一把异步互斥锁下串行更新 `ModeState` 和 `DATAPATH_FLAGS_MAP`。Initialize、mode、GLOBAL、static 四种更新会和 NFQUEUE 的 fence、reopen、disable 协调，避免 API 更新在 reload 中重新发布 ready。fence 完成要求 READY=false、成功的同步内核 grace，以及 fenced 清理掉所有未交付的 Preparing/Pending/Aborted 状态。

### 需要重启的变更

当前进程级消费者在以下任一值变化时拒绝 `SIGHUP` reload：

| 区域 | 需要重启的字段 |
| --- | --- |
| listener/数据路径 | `global.tproxy_port`、`global.tproxy_mark`、`global.tproxy_port_protect`、`global.pprof_port`、`global.so_mark_from_dae`、`global.lan_interface`、`global.wan_interface`、`global.auto_config_kernel_parameter` |
| 进程状态 | `global.log_level`、`global.data_dir`、`global.store_subscribe` |
| DNS listener | `dns.bind` endpoint 或 transport 的语义变更 |
| Clash API | `experimental.clash_api.external_controller`、`external_ui`、`secret`、`default_mode`；生效的 `assets.ui.url` 和 `assets.ui.route` |
| 原生 API | 任意 `experimental.native_api` 变更；生效的 `assets.geodata.geosite`、`assets.geodata.geoip`、`assets.geodata.route`；`assets.geodata.auto_update`、`assets.geodata.cron`、`assets.geodata.checksum` |
| 持久化 | `experimental.cache_file.enabled`、`store_dns` |
| NFQUEUE | `global.nfqueue_enable`，已记录数据路径 admission 前启动降级时除外（[例外说明](../reference/global.md)） |
| 健康检查与 TLS | `global.check_interval`、生效的第一个 `global.tcp_check_url`、启用 HTTP 检查时的 `global.tcp_check_http_method`、选中的 `global.udp_check_dns` 目标，或原生 TLS/uTLS 模式切换（参见[健康检查 reload 语义](../reference/global.md#reload-健康检查与-tls-模式)） |

UI 和 geodata 的生效设置里，包含从 `assets.route` 继承来的值。如果这个默认出口的变更影响到启动阶段持有的任一下载出口，就需要重启。`assets.subscription` 的默认值和订阅条目设置交给订阅协调处理。

旧值和新值都能解析时，`dns.bind` 的语义比较用的是解析后的 bind endpoint，所以只是拼写不同、实际描述同一个 endpoint 的变更不会强制重启。

`EbpfBackend` 负责这些事：token/state 检查；`commit_udp_decision(key, token, transition)`；经过 token 校验的 abort 和 removal；内核 staging 的 quiescence；兼容回滚用的持久化 allocator 校验；状态查询和重置；以及 routing 和 map 操作。12 字节 pin 的 `next` 保存完整的 raw token，也就是两位 generation 加 28 位 sequence，启动时不会重写。只有暂存路径的 fence 和排空都完成，并且候选 generation，直到 3 在内的全部更高 generation，都没有出现在 live 的 conn-state、handoff、redirect 或 retirement-fence map 里，才允许 reset。回滚后的旧 allocator 会从 reset 值单调递增，所以整个后缀都必须是空的。

## 订阅编排

启动时先解析已经存下的内容，再开始网络刷新。恢复结果有效且非空时，节点会立刻可用，这个订阅也不再等那五秒的首次拉取。只有没能有效恢复的 direct 订阅才会进入共享 grace；经路由的拉取会等路由就绪，不阻塞启动。之后它仍在后台联网刷新。

`ControlPlane::run` 第一次被 poll 时就取得控制命令接收端的所有权，早于所有启动阶段的 await。这个已经开始运行的 future 一旦返回或被丢弃，就算 listener 启动失败，也会关闭通道；这样卡在满队列上的订阅投递才能解除等待，调用方随后也才能等 supervisor 关闭。

`SIGHUP` 按 fetch 身份稳定订阅 ID，身份由 URL、配置的 User-Agent 和 headers 组成。它会把活动订阅里的节点带进候选配置，但不恢复缓存内容。网络失败、解析失败，或结果里没有可用节点时，活动节点会保留，上一次有效的内容也不会被替换。持久化失败不算致命错误：校验通过的节点仍可合并，旧内容仍可恢复。定期刷新和立即刷新走同一条串行的 runtime 发布路径，订阅节点不会写回配置文件。

内容校验和运行时发布是分开报告的。节点集合的 admission 失败时，只输出一次脱敏诊断，并保留活动配置；已经保存的内容不会回滚。

启用 `global.store_subscribe` 后，校验通过的原始响应会存进固定状态数据库 `<data_dir>/state/honk.db` 的 `subscription_body` 表。key 由请求 URL、配置的 user-agent 覆盖值和有序 headers 决定。完整内容在一次 SQLite 事务里替换，单份最多 8 MiB，总量最多 32 MiB。启动时会从 `<data_dir>`、`/var/share/honk` 和 CWD 下找到的第一个私有旧 `.sub` 目录，一次性导入已启用订阅的内容；已有行优先，复制过的文件和临时文件会被删除，没导入的内容保留，等后续符合条件的启动再处理。迁移和失败细节见[订阅参考](../reference/subscription.md#拉取持久化与恢复)。

- `src/subscription.rs` 负责拉取和解析；`subscription/store.rs` 持有 SQLite 内容存储，以及相对 FD 的旧存储导入。`subscription/supervisor.rs` 持有授权和在途工作；`supervisor/schedule.rs` 管理 provider 的刷新期限，`supervisor/startup.rs` 恢复缓存内容，并执行只限 direct 的共用五秒启动宽限。启动和稳态用同一份 supervisor state；在途工作独立保留捕获的 revision 和发布确认，关闭时会等它结束，reconcile 不会丢弃可能已经提交的确认。
- 守护进程的拉取和恢复路径，与 `honk-tool sub` 的本地文件共用内容格式检测。
  `Simple`/`Custom` 接受 BOM、可换行的标准 Base64 和 URL-safe Base64、原始分享链
  接、Clash YAML/JSON、SIP008、sing-box JSON，以及 Surge、Surfboard、Loon、
  Quantumult X 的记录。`src/subscription/json.rs` 和 `records.rs` 规范化外部记录，
  `clash.rs` 构造并校验类型化节点。只导入节点，不导入完整配置里的路由、DNS 或组。
  原生 JSON 会保留用 Unicode 代理项对编码的名称。不支持的节点直接跳过；身份重复
  时保留第一个可用节点；空结果不替换活动订阅。导入的 Trojan、AnyTLS、QUIC 节点必
  须用 TLS，不会静默降级成明文。Clash 和 sing-box 的 TCP ALPN 归入共享的 TLS 模
  型，不放进 TUIC 的 QUIC 字段。共享构造器的跳过 warning 只带从 1 开始的代理序号
  和静态拒绝原因，不含原始节点记录或凭据。

## 原生观测 API

`native-api` 是独立且需要显式编译的 feature，用 `--features native-api` 或 `native-ui` 构建；full 和 `-native-api` 的发布产物也包含它。它提供一个默认关闭的 listener，启用后在控制面 admission 之前绑定。可选的 phase watch 只在 admission 开放后才报 running，在关闭 fence 之前报 draining；现有的 health handle 可以把 running 细化为 degraded。读取 generation 和 health 期间会保留 config 发布屏障，但不改变发布锁序。HTTP 可用并不代表数据面健康。

`native_api/server.rs` 完整持有 listener、64 连接的 JoinSet、唯一的一秒 sampler 和 native tracker consumer，直到关闭时 join。header 预算五秒。30 秒读空闲期限只在这条连接没有进行中的请求时生效；请求从 body 结束算到响应完成都算进行中。停滞的写入另有独立的 30 秒期限；健康 SSE 和慢 handler 可以超过 30 秒。accept 出错时记日志后重试，EMFILE、ENFILE、ENOBUFS、ENOMEM 退避 100 ms；连接任务失败只记日志，不终止 server。HTTP 关闭共享五秒 grace，然后等已通过 admission 的真实阻塞凭据任务结束。

`crate::observe` 拥有进程身份和引擎侧的有界存储，独立于客户端；`observe.rs` 里的 `Observation`、flows、rules、catalog 身份和 `DnsRecorder` 都属于它。`native_api` 只负责 HTTP 投影。没有启用 `native-api` 时，观测 hook 会编译成零开销的 inert 替身。TCP/UDP/DNS 的 producer 在真实执行点捕获不可变的来源证据，已接受的发布在既有屏障下发出 generation 事件。逐流完整性描述的是已捕获的执行进度，与生命周期和总体覆盖无关；native-only 的 final handoff 不会重复生成旧的选路证据，也不声称完整的内核透明观测。日志直接捕获审查过的结构化安全字段，不转发 Clash 的格式化输出；`/events` 和 `/logs` 的续传都是 ready → replay → live。

`native_api/handlers.rs` 为每个资源只注册一份方法分派；共用安全边界仍先于方法和资源校验执行。`observe/flows/record.rs` 持有类型化摘要、输入及证据步骤，留存预算计入实际持有的堆容量、snapshot 与有界内核字典预留，JSON 只在 wire 边界投影。核心生命周期与模式命令返回类型化结果，而不是 HTTP 错误或 JSON。

`observe/flows/producer.rs` 持有 FlowGuard 更新及 TCP/UDP、DNS 共用的组选择证据投影。DNS wire 输入模型归入统一 record；`observe/flows/dns.rs` 保留 lookup/catalog scope 与 DNS 专属捕获。`auth.rs` 持有 session、有界 admission 和唯一受追踪的阻塞任务；storage 子模块发布短时持有的凭据状态，不跨 KDF 或 SQL 持有状态锁。

`native_api/events/http.rs` 负责事件 query/cursor 解析、Accept 协商以及与日志共用的 HTTP 流响应；replay、签名、订阅和帧预算核算仍归 `native_api/events.rs` 所有。

`control/connection/observation.rs` 根据已捕获的 handoff、route、selection 和 transport 事实组装 TCP/UDP 证据。连接编排不构造 wire record，也不使用当前配置重算历史；关闭记录时不分配 capture，精确连接关闭仍独立于记录。

`DnsRecorder` 在 `observe/dns/history.rs` 中持有具体的客户端 DNS 历史；记录 epoch、入口 admission 及按字节/条数淘汰归引擎所有。`native_api/dns/log.rs` 读取同一持锁视图，完成 cursor 绑定的过滤、listener secret 遮蔽及完整记录的 JSON 分页投影。

`observe/flows/dns.rs` 与 outbound flow observer 为 scoped/retained 工作绑定实际 lookup、attempt 与 generation 身份。session attachment、逻辑 open/readiness 重试与新物理连接、协议确认分开。可选异步 scope 借用调用方 pin 的操作，不复制大型 future 状态；pin 不越过操作的所有权/析构边界。内核证据使用不可变编译字典与报文绑定 witness；UDP receive priority 来自原生辅助元数据，或严格对应 syscall/batch 的 receiver-owned fallback。丢失只改变证据，不改变路由或报文交付。

既有原生 sampler 通过 `DatapathFlagsHandle` 同步实际流需求，保留模式/NFQUEUE 位，仅在后端写入成功后提交追踪 admission。等待后端所有权后重新读取需求，sampler 停止并 join 后再同步一次；不新增 writer、timer 或路由重编译。内核对每次调用复用同一 flags 快照来控制可选 witness 生产，已保留的捕获与真实路由判定不受后续需求变化重解释。

TCP copy 成功读取与 splice 成功写入实时累加既有逐出站 atomics；成功接受的嗅探前缀仅计一次，部分写失败也保留已写字节。Relay 关闭或取消不再次累加总量。既有统计与原生采样共用这些计数，UDP 原逐包语义不变。Wire 契约、上限与未知字段见 [API 参考](../reference/api.md#原生-api)。

出站读取保留共用计数的 `kind/name` 与完整 UInt64，reload 不重置计数生命周期。`telemetry.rs` 复用唯一的一秒 sampler（Skip），无客户端也保留各 600 点/600 秒的流量与内存历史。关闭对应记录开关并重启后释放缓冲，不插值或补零。内存读取实际 RSS/cgroup v2 文件，未知值为 null，未实现 kernel memory 核算。

`configuration/accepted.rs` 持有启动捕获的 `.dae` accepted 源及发布 fence，`native_api/config.rs` 只投影权限与 HTTP。原生协调器在读盘前串行化 API 写入和 SIGHUP 加载，`configuration::Activation` 为 native 与 nonnative 调用方共用 reload、reply、订阅 reconciliation 链。HTTP 断开不取消 daemon-owned 任务，同 scope/key/body 重放共用结果；PUT 的 202 仅代表耐久写入且真实 reload 已排队。外部编辑器仍可能在最后检查与 rename 间 race，rename 后目录 fsync 失败必须报告已写但耐久性未确认，不能称为回滚。

`native_api/config/http.rs` 持有源 HTTP adapter。协调器持续负责数据库记录，直到 awaited blocking promotion 结束；HTTP 取消与关闭不改变该所有权。待记录的新 accepted 源不会被错误标成旧的持久化 revision。

Accepted 源在真实 no-op 或 commit 时随原有 config 发布屏障更新，遵循上述包含 datapath flags publication 的锁序及订阅 revision fence。拒绝 reload 保留旧快照/generation 但不回滚已写文件；提交后 degraded 保留新快照/generation 并令 operation 失败。API operation 的真实结果投影到 GET、`runtime.last_reload` 与 `operation.updated`，SIGHUP 本身不创建 API operation。注释变更可更新 source hash/config revision 而不推进 runtime generation，有效组成员变更影响 revision，健康变化不影响。

Selector 写入由同一 `control/reload` owner 序列化，TCP/UDP 分开保存，both 原子发布；Clash 写 both、读 TCP 投影。精确连接关闭绑定 TCP UUID 或 UDP token/generation/source view，等待实际 transport 与 backend/driver 退役，而非只删除 tracker 记录。同一 owner 的重复关闭共用完成结果与失败，不存在或已被替换的 owner 才是 Gone。组中断按捕获的组路径与网络关闭旧 owner，在同步 guard 外等待。组 PATCH 使用 parser span 和原源码协调器，写前及 reload lock 下都检查 accepted revision，独立检查 hash 与依赖。Provider 并发发布可使已写文件不能激活，必须保留 written/committed 区分。自动策略的分网络 pin/clear 已开放，pin 成员只属于当前 GroupManager。

主文件创建/删除复用相同协调器、parser span、revision fence 与 reload reply，但等真实激活后才返回 201/200。订阅 supervisor 持有绑定身份的初次拉取延迟，所有离线 admission 都携带这些排除项和有效运行时数据目录。Geodata 先暂存并验证所有资产，再经 FD 相对替换；临时不可变 `SourceUpdate.geo_sources` 同时进入 reload 的两条路径，发布后不再由 accepted 源元数据保留。Router/DnsRouter 保留实际加载字节的元数据，观测按 router-before-config 锁序且不重读磁盘；部分文件替换与提交后 degraded 如实报告，不承诺回滚。

暂存 writer 返回保留的 installed-file FD 及耐久结果。Geodata 从待替换文件转为 installed guard，不再重新打开文件重建所有权。路径、inode 与字节复查仍拒绝外部编辑；可见但未确认耐久的替换仍明确报告。

激活执行只产生一份类型化完成结果，分别投影到 operation、管理响应和 SIGHUP 日志。协调器接受下一项修改前，创建响应保留已提交的资源表示。源元数据在取得 config 写锁前准备，发布时复核捕获的 revision/generation。Rename 前的依赖复查将逻辑读取方绑定到规范化目标及字节：有序 hosts/ECH 引用、订阅声明位置与 geodata 类型。复查重新发现 source/glob 和依赖选择，但不重复编译未变化的已通过 admission 的候选；交换两个读取方的文件目标仍会冲突。

Probe worker 拥有有界准备/排队/执行/清理，DNS 诊断使用真实 generation 与精确缓存 owner，provider refresh 由 SubscriptionSupervisor 拉取并等待 revision-fenced publication；GET 不伪造这些 producer。Routing trace 只模拟当前 compiled predicate，不 DNS/探测/选组；当前规则字典只在 parser 来源可用时提供脱敏 source location。Runtime settings 由一个 owner 先校验全量 merge 再发布，native+Clash mode 共用 `DatapathFlagsHandle`。Native 启用时模式不恢复/持久化；显式接受配置激活（含 no-op）重置 Rule 与 settings，provider/network refresh 不重置。

`native_api/settings.rs` 分别管理各类自动诊断采集需求：成功的 flow GET 或显式 flow-event kind/`flow_id` 开启 flows，logs stream 开启 logs，成功的 DNS-log GET 开启 DNS log。普通 events 只维持自己的 attachment，不开启这三个 recorder。admission 失败及普通 API/validation 请求不增加诊断需求。每个 stream lease 只释放自己取得的集合；每类 recorder 独立保有最后需求释放后的六十秒 grace，不由其他读取/stream 续期。配置 permission 与显式 runtime On/Off 仍有优先权；显式激活重置 override，provider/network refresh 保留。

Probe 准备阶段将捕获的计划消费为具体地址的可执行尝试或明确的家族地址不可用结果。DNS-owned resolver 保留 generation 及 canonical accepted-positive 应答资格；即使另一家族有地址，终止性 packet refusal 也拒绝整个准备。健康 ticket 与探测配置在同一发布屏障内捕获。

Native cold/warm HTTP probe 与 URLTest 共用 dial/TLS/ALPN 和 H1/H2 exchange；native 保留总 deadline 且不写 Score，传统调用方保留分阶段预算。临时 runtime 的 joined cleanup 返回类型化结果：私有 child panic 令 operation 失败并阻止之后成功确认暂停，但保留已完成的测量证据；主动取消不伪造不健康样本。

显式激活已提交 routing/config 后，若 backend mode 重置失败，保留先前 mode/source，但设置已恢复配置值。事务报告 committed-degraded 并关闭 admission，operation 失败。这不表示 mode 已重置为 Rule，也不表示旧配置仍 active。

原生 mode 资源暂缓提供：固定 PUT 契约无法表达生命周期冲突，也无法表达 owner/backend 不可用；同一 capability 覆盖读写，所以 GET/HEAD/PUT 均返回 `404 capability_not_supported`。内部临时模式、Clash 控制与上述激活 reset 不受影响。

### 终止所有权

`control/lifecycle/teardown.rs` 的共用网络清理在有无 listener epoch 时都适用，涵盖部分启动。独立 DNS supervisor 保留已回收 child 的失败，并经 joined teardown 传播；主动关闭导致的取消是中性的，但 owner panic 会使清理失败。

网络维护任务属于 `RuntimeEpoch`。延迟缓存 writer 属于进程，仅在终止关闭时 join。

已开始的阻塞工作无法靠取消 async waiter 停止，持有它的 owner 必须等待实际 join。通用清理/join 阶段使用十秒 `STAGE_TIMEOUT`，超时的 async task 会被 abort，teardown 报告失败。`control/cache.rs::StateTick` 是例外：十秒后记录 warning 并继续 join 实际维护任务及在途阻塞 SQLite 写入，不 abort。取消这次等待时，handle 仍留在 owner 中，可再次等待；owner 被 Drop 时只发出停止信号，外层 task 继续持有阻塞写入。因此总关闭时间没有严格十秒上限。TCP 连接任务 panic 时记录日志并回收，不停止引擎。关闭时可选的[业务连接宽限等待](../reference/global.md#关闭)在 joined teardown 之前执行。

健康检查 owner 也会在五秒 drain deadline 后继续等待实际 drain（包括其阻塞解析任务），再返回 deadline 错误。若后续清理发现子任务失败，该失败优先于 deadline 错误。

## Clash API 与 cache DB

可选 Clash-compatible axum server 是共享引擎 handle 上的用户态视图与修改接口；endpoint 细节见 [API 参考](../reference/api.md)。任一 API 成功绑定，或任一配置组使用 `interrupt_connections` 时启用连接元数据；真实 transport 关闭不等于移除记录。Selector 写入与 accepted-manager 替换串行化，Clash 写 both、读 TCP。运行时缓存表位于固定状态数据库 `<data_dir>/state/honk.db`；旧 `cache_file.path` 与 `cache_id` 仅用于一次导入旧 `cache.db`，不决定活动数据库位置。升级后不设 `cache_file.enabled` 即默认保存 Selector 选择与延迟样本；`true` 额外启用 mode/GLOBAL 以及配合 `store_dns` 的 DNS 应答，`false` 禁用这类缓存持久化。Mode 仅在 native 未启用时持久化。目录锁覆盖全部已持有 SQLite connection 的存活期，包括 cache writer connection 到线程退出。见 [Experimental 参考](../reference/experimental.md)。

- `src/stats.rs` — `StatsManager` 持有固定、无分配的 `GET /stats` UDP schema。`udp.nfqueue` 包含 listener/correlator 计数、actor 队列深度、排队字节数与最老条目的等待时间、当前队列深度、跨 hard rebind 累积的进程生命周期内核丢包数、最近一次内核读取的可用性与累计读取错误、held/peak guard gauge、生效接收缓冲大小、终态 verdict、token exhaustion/rotation、verdict error 与 `receiptToVerdict`。该延迟从 listener 收包计到 verdict 成功，不是内核队列驻留时间。顶层 `warm.sessions` 报告保留的 `anytls`、`vless` pool session 及各协议 QUIC client。
- `src/clash_api.rs` + `clash_api/{logs,doh,ui}.rs` — Clash REST/WS API 与外部 UI。UI 目录缺失或为空时在后台下载；URL/detour 优先级见[配置指南](../configuration.md)。`GET /stats` 返回用户态统计，不是 eBPF `OUTBOUND_STATS`；经认证的 `/stats.score.groups[]` 包含 `name`、TCP/UDP 原因计数、`verification` 与 `budget`。Mode/GLOBAL 修改通过 `DatapathFlagsHandle` 原子组合 reload fence 与最新 mode/static bit；Selector 修改通过 group manager。Score 组保留 `type: "url_test"`，在 `now` 显示当前聚合 TCP 胜者，并拒绝 `PUT /proxies/{name}`。不返回 score cell 或私有 target 数据。
- Clash API 成功绑定或任一组配置 `interrupt_connections` 时才启动连接元数据追踪。API 关闭只移除自己的 consumer；由组触发的中断仍然有效。

## 相关文档

- [数据路径设计](./datapath.md)
- [路由设计](./routing.md)
- [NFQUEUE 设计](./nfqueue.md)
- [出站设计](./outbound.md)
- [组设计](./groups.md)
