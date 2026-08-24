# 用户态控制平面

本文描述位于内核数据路径与出站栈之间的 `honk-core` 用户态引擎。

## 范围

控制平面负责透明代理入口、消费内核交接、用户态路由、嗅探、出站选择、中继、资源准入与运行时发布。向用户态交付流量的内核机制见[数据路径设计](./datapath.md)。组策略和健康状态驱动的选择见[组设计](./groups.md)，DNS 运行时行为见 [DNS 设计](./dns.md)。

主要实现在 `crates/honk-core/src/control/`。它消费 `EbpfBackend` 状态，并把 TCP 流或 `PacketTransport` UDP 契约交给 `honk-outbound`。

## 启动与关闭

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

当 `global.store_subscribe` 启用时，经过校验的原始正文存放在 `<global.data_dir>/.sub`。切换 data directory 时会保留已有的旧 `./.sub`，直到运维人员迁移它。目录必须是非符号链接目录、权限 `0700`；文件权限 `0600`，文件名由请求 URL、配置中的 User-Agent 覆盖值（未设置或为空时贡献空组件）与 headers 共同计算 URL-safe SHA-256。未配置订阅覆盖值时，请求标识为 `honk/<version>`。写入使用新的临时文件、`sync_all`、原子 rename 和目录 sync。

关闭时在资源消失前逆序释放所有权：fence NFQUEUE、关闭数据路径准入、拒绝新的用户态工作、取消并排空持有的 verdict 和 UDP initializer、停止 UDP driver 和 removal 处理、停止接口 watcher、卸载 BPF hook、最多用五秒排空已接受流、退役出站运行时、停止 NFQUEUE、停止 DNS controller 和 persistence，并清理 generation 持有的 BPF 状态。普通清理保留固定分配器。随后 listener 和 `daens`/link-pair 所有权离开作用域。

## 透明代理入口

真实 TCP 和 UDP listener 在 `daens` 内创建，并设置透明 socket 选项和 `DAE_BYPASS_MARK` (`0x100`)。该 mark 使数据路径把它们识别为 honk 自己的 listener，而不是普通本地服务。已接受 TCP socket 会继承 mark，因此每个 accept loop 在处理流前将其清零。Mock listener 是宿主命名空间内不带特权透明选项的普通 socket。

原始目的地址按下表恢复：

| 入口 | 首选来源 | 回退 |
| --- | --- | --- |
| TCP/IPv4 | `SO_ORIGINAL_DST` | 透明 socket 的 `local_addr()` |
| TCP/IPv6 | `IP6T_SO_ORIGINAL_DST` | 透明 socket 的 `local_addr()` |
| UDP | `IP_RECVORIGDSTADDR` / IPv6 original-destination cmsg | 下文所述的受约束 provenance 规则 |

形成规范 tuple 后，用户态通过 `routing_handoff_take` 消费 `ROUTING_HANDOFF_MAP`。没有 handoff，或出站为 `ControlPlaneRouting` 时，回退到 `Router::route_with_must`。最终的 `must` 和 `block` 结果不能被 Clash mode 覆盖。

## 嗅探与流初始化

TCP 嗅探最多读取 4096 字节，并提取 TLS SNI 或 HTTP `Host`。返回的缓冲区属于流状态，并在中继开始前写入已选出站，因此嗅探不会消费应用数据。`dial_mode: ip`、最终的 direct/block 或 `must` handoff，或命中 TCP negative cache 时跳过 TCP 嗅探。连续三次失败会抑制同一目的地址/出站签名十分钟；嗅探成功会移除 negative 条目。

UDP 域名发现解密 QUIC v1/v2 Initial packet，重组 CRYPTO fragment，并解析 TLS ClientHello SNI。每流 session 五秒过期，最多检查八个 Initial packet，并把 CRYPTO stream 限制为 64 KiB。首个 ClientHello 分片时，initializer 最多保留八个 FIFO follower，最多等待 250 ms。failed-DCID cache 限制对非 QUIC 或不可解密流量的重复工作。

`dial_mode: domain` 对嗅探到的 TCP 或 QUIC 名称执行 DNS reality check。目的地址同族答案精确匹配时接受；只有另一地址族答案时，为兼容双栈仍保留该名称。同族不匹配、查询失败或超时时丢弃嗅探名称并按 IP 继续。

`connection.rs` 是每流 route/sniff/mode/selection 的规范边界。Socket UDP 入口与 NFQUEUE 持有的 payload 都在同一个 `UdpEndpointPool` 中预留相同的 `UdpInitLease`；NFQUEUE 没有第二套 Router、dialer 或 packet replay 路径。暂存流在 token 校验的终态转换前计算唯一最终出站与 mark。

`build_tuples_key` 必须用 `mem::zeroed()` 初始化 `TuplesKey`。这个 `#[repr(C)]` key 在 40 字节布局中只有 37 字节字段，内核会散列包括三个 padding 字节在内的全部 40 字节。因此逐字段初始化可能产生用户态无法可靠查询或删除的 key。

## UDP endpoint 流水线

### 目的地址 provenance

UDP 准入采用 fail-closed，并在 endpoint 预留前运行：

1. 存在、有效且已指定的 ORIGDST cmsg 具有权威性。未指定的 ORIGDST 无效，不能回退到其他来源。
2. 没有 ORIGDST 时，只有精确 DNS query 加上已指定的 `PKTINFO` 目的地址才能形成 `IP:53`。
3. 其他情况只有非 wildcard listener bind 可以提供目的地址。
4. 缺失、畸形、重复、截断或未指定的元数据，会在 slow-path 预留或 payload 保留前被丢弃。

### Transport 与事务

`PacketTransport` 是生产 UDP 的唯一接口。原生 UDP handler 包装真实 socket；隧道 handler 直接实现 framing，并暴露 `relay_addr()`、`send_packet`、`send_packet_confirmed` 和 `recv_packet`。控制平面不会为 framed transport 创建 loopback socket bridge。

Endpoint 创建是事务性的：

1. 把 `(client, original destination)` 预留为 `Initializing`；lease 持有首个 datagram、queue permit、slow-path permit、token、generation 和 cancellation epoch。
2. 路由、嗅探、选择并最终确定一个合格 transport。在发布前创建透明 anyfrom reply socket。
3. 启动 endpoint driver，并等待其 ready barrier。
4. 在共享 epoch fence 下，把精确的 `Initializing` identity 原子替换为 `Ready`。
5. 转移保留的首包，用 `send_packet_confirmed` 发送并等待 acknowledgement。
6. 按 FIFO 顺序发送嗅探保留的 fragment 和未触碰的 queue follower，再运行 steady send 和 receive 路径。

透明 listener 接收循环只做校验、预留和入队；它从不等待 `PacketTransport` I/O。Endpoint driver 持有全部 transport 调用。首次与稳态发送各有五秒超时。超时或错误具有歧义，因为 transport 可能已接受 packet 的一部分，因此 driver 不会重放该 datagram，也不会继续后续 follower。

SOCKS5 UDP 在 endpoint 整个生命周期内保持 TCP `UDP ASSOCIATE` 控制流，并把控制流 EOF 或意外控制数据视为 endpoint 失败。其 connected UDP socket 向服务器物理 `BND.ADDR` relay 发送；若回复为域名则解析，若地址未指定则替换为控制连接对端 IP。`PacketTransport::relay_addr()` 和接收来源元数据暴露的是逻辑目标，因此 endpoint 首回复校验不会把 SOCKS relay 与远端 peer 混淆。

回复使用在 `daens` 内创建、透明绑定到 packet 原始目的地址的 anyfrom socket。通用 endpoint 保留其 original-destination socket，并按 endpoint 缓存已接受的其他 full-cone 来源。端口 53 回复另外共享每地址族一个透明 socket，并用 `IP_PKTINFO` 或 `IPV6_PKTINFO` 选择精确源 IP。从 TPROXY listener 回复会使用内部 `dae0` 源地址，因此不可用。

Reload 在等待前推进 cancellation epoch。Initializer 捕获该 epoch 和 incarnation generation；若 cancellation 先于 `commit_ready` 线性化，则阻止发布。Reload 排空 `Initializing` lease 及其保留资源，但保留 `Ready` endpoint。每次 retirement 和 acknowledgement 都指定 token 与 generation，因此延迟工作不能删除替代 mapping。

## Queue 与描述符预算

每个 UDP 流最多保留 64 个 datagram，包括首包。所有流共享精确的 8 MiB payload permit 预算。准入在复制前取得每流 slot 和全局 byte permit；FIFO 饱和时丢弃最新 datagram。NFQUEUE 有独立 ingest actor，限制为 256 个条目和 8 MiB 排队 payload。

启动时，`honk-core` 尝试提升软 `RLIMIT_NOFILE`，只快照一次活动值，并把预算输入上限设为 16,384。在该上限处，不可变分区为：

| 所有者 | 容量 | 描述符记账 |
| --- | ---: | ---: |
| 固定/运行时预留 | 256 | 256 |
| 已接受 TCP 流 | 672 | 每个 6 = 4032 |
| 保留 TCP pool | 2016 | 每个 1 = 2016 |
| 临时出站 dial | 1008 | 每个 1 = 1008 |
| UDP endpoint | 3024 | 每个 3 = 9072 |
| **合计** |  | **16,384** |
TCP 从描述符导出的 floor 开始，在不使用的 non-TCP 描述符余量内动态扩容，最多达到该 floor 的两倍，同时保留一半 non-TCP 预算作为突发余量；4,096 描述符服务在余量空闲时可从 160 个流 permit 扩展到 320 个。已有流不会被切断，固定预留用于保护控制平面描述符。

一个 TCP 流为 accepted socket、outbound socket 和两组各含两个 FD 的 splice pipe 记账。一个 UDP endpoint 按常见最坏所有权形态记账：relay socket、SOCKS5 控制流和 anyfrom reply socket。较小的 `RLIMIT_NOFILE` 值以相同的饱和算术缩放分区。

各准入上限彼此独立：

| 准入 | 上限 |
| --- | ---: |
| TCP 流 permit | 描述符导出的 floor；16,384 上限时为 672，动态扩容最多到 1344 |
| 冷 non-DNS UDP slow path | `min(udp_endpoints, 256)` |
| 端口 53 入口 slow path | `min(transient_dials, 256)` |
| NFQUEUE ingest actor | 256 个条目和 8 MiB |

不存在单独的 256 条 TCP slow-path 上限。TCP accept 使用由描述符导出的流预算。Endpoint-removal channel 限制为 1024 条消息，每批排空 128 条。非阻塞投递遇到满队列时，去重的 `removal_dirty` 集保留补偿；worker 每批完成后刷新该集合，再确认精确 endpoint tombstone。

透明 TCP 在任一 IP 族监听器 accept 之前预留一个共享 permit。所有 permit 占用时，新连接留在内核 listen backlog 中，不会先 accept 再关闭含有未读数据的 socket。`/stats` 的 `tcp` 对象提供 `activeFlows`、`limit` 和 `capacity.rejected`；后者统计等待 permit 的 accept-loop，而不是 accept 后被丢弃的连接。动态上限低于 256 时启动会告警；网关部署应提高服务的 `RLIMIT_NOFILE` 限制。

## TCP 中继与 conn-state 所有权

当两端都是普通 `TcpStream` 时，`relay_splice` 运行两个并发 `splice(2)` pump。每个方向持有一条最多 64 KiB 的非阻塞 pipe，因此全双工中继最多请求四个 pipe FD 和 128 KiB pipe page。EOF 对另一端 write side 执行 half-close，并允许反向继续排空。

每个方向的首次 splice 同时是 capability probe。在任何字节到达目的 socket 前返回 `EINVAL`、`ENOSYS` 或 `EXDEV`，即可无损回退到用户态 copy，并设置进程全局 latch；后续连接跳过 probe。其他错误，或字节已经暂存后返回 unsupported，会使中继失败，而不是冒数据丢失风险。TLS 或协议包装流使用 `relay_auto`，它始终使用基于 select 的 copy loop。

首次 EOF 后，两条中继路径只限制空闲排空时间：`DRAIN_DEADLINE` 是没有任何字节进展的 30 秒。活跃 survivor 可以运行超过 30 秒；静默 survivor 不能无限持有 accepted socket。

Accepted TCP socket 只有在其规范正向 `CONN_STATE_MAP` 条目仍存在时才会被接管。`TcpFlowPins` 为每个 accepted owner 引用计数该方向 tuple。BPF janitor 跳过已 pin 的 conn-state 和匹配的 redirect 元数据。最后一个 owner 退役时读取当前条目，并且只在 state 与 timestamp 仍匹配已观察 incarnation 时条件删除；旧 relay 不能删除复用的 tuple。

## Reload 与运行时 generation

`apply_runtime_config` 首先构建替代 Router、GroupManager、出站 registry、DNS 运行时与路由计划，不修改 live state。提交顺序为：

1. Fence NFQUEUE readiness，并等待内核 reader-epoch 宽限期。
2. 拒绝新的透明代理准入。
3. 取消 correlator cell 和 token-bound original，推进 UDP initializer epoch，排空 `Initializing` lease，等待 correlator 变空，并排空精确 endpoint retirement。
4. 暂存并激活路由，再把新的出站 registry、DNS runtime pointer、Router、配置、组和 projection snapshot 作为一次串行 generation 变更发布。
5. 发布新的静态 datapath flag，开放 pending 准入，最后重开 NFQUEUE。此后才停止拒绝新流。

提交前构建失败不会触碰当前 generation。若 fence 后发布失败，控制平面重放精确的旧路由计划，恢复旧静态 flag，并重开旧 generation。若恢复不能证明数据路径健康，则继续拒绝准入。

`DnsServiceProvider` 是一致的 DNS generation pointer。请求 lease 保留其 generation 的 forwarder、projection、transport pool 和出站运行时，直到退役。出站 registry 同样按 generation 持有：未变化的 node runtime 只在提交点转移，旧 registry 把这些 runtime 标记为已移出，然后开始优雅退役。现有 stream 与 `Ready` UDP endpoint 保持引用，同时旧 reusable pool 停止接受新工作并排空。

`DrainTracker` 是进程全局的 accepted-flow gate。Reload 和关闭在 drain 前设置 reject-new；关闭最多等待五秒，然后带着剩余计数继续拆除。

### 需要重启的变更

当前进程级消费者在以下任一值变化时拒绝 `SIGHUP` reload：

| 区域 | 需要重启的字段 |
| --- | --- |
| Listener/数据路径 | `global.tproxy_port`、`global.tproxy_mark`、`global.tproxy_port_protect`、`global.pprof_port`、`global.so_mark_from_dae`、`global.lan_interface`、`global.wan_interface`、`global.auto_config_kernel_parameter` |
| 进程状态 | `global.log_level`、`global.data_dir`、`global.store_subscribe` |
| DNS listener | `dns.bind` endpoint 或 transport 的语义变更 |
| Clash API | `experimental.clash_api.external_controller`、`external_ui`、`secret`、`default_mode` |
| 持久化 | 任意 `experimental.cache_file` 变更 |
| NFQUEUE | `global.nfqueue_enable` |

当旧值和新值都能解析时，`dns.bind` 的语义比较使用解析后的 bind endpoint，因此描述同一 endpoint 的纯拼写变更不会强制重启。

启动时先解析已存正文，再开始网络刷新。有效且非空的恢复结果立即提供节点，并从五秒首次拉取等待中移除该订阅；缺失、无效或空正文只会在共享 grace 期间等待。之后所有订阅仍在后台刷新。

`SIGHUP` 会按 URL 稳定订阅 ID，并把活动订阅节点带入候选配置。只有启用订阅且当前没有活动节点时才恢复缓存，随后安排立即网络刷新。网络、解析或没有可用节点的失败会保留活动节点，不替换上一次有效正文。持久化失败不是致命错误：校验成功的节点仍可合并，旧正文仍可恢复。定期刷新与立即刷新使用同一串行的 runtime 发布路径，订阅节点不会写回配置文件。

当 `global.store_subscribe` 启用时，经过校验的原始正文存放在 `<global.data_dir>/.sub`。切换 data directory 时会保留已有的旧 `./.sub`，直到运维人员迁移它。目录必须是非符号链接目录、权限 `0700`；文件权限 `0600`，文件名由请求 URL、配置中的 User-Agent 覆盖值（未设置或为空时贡献空组件）与 headers 共同计算 URL-safe SHA-256。未配置订阅覆盖值时，请求标识为 `honk/<version>`。写入使用新的临时文件、`sync_all`、原子 rename 和目录 sync。

## Clash API 与 cache DB

可选的 Clash-compatible axum server 是当前配置、GroupManager、mode/flags handle、connection tracker、DNS service、统计和出站 runtime pointer 上的用户态视图与修改接口；endpoint 细节见 [API 参考](../reference/api.md)。可选 SQLite `cachedb` 在数据路径准入前打开，持久化 Selector 选择、Clash mode，并可选持久化 DNS 答案。相对路径优先位于 `global.data_dir`，同时在切换期继续使用已有的配置目录相对旧数据库。配置与持久化语义见[实验性配置参考](../reference/experimental.md)。

## 相关文档

- [数据路径设计](./datapath.md)
- [路由设计](./routing.md)
- [NFQUEUE 设计](./nfqueue.md)
- [出站设计](./outbound.md)
- [组设计](./groups.md)
