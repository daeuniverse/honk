# Linux 捕获数据路径

Linux capture 向共享用户态策略和出站路径交付流量。用户态路径见[控制平面](./control-plane.md)，TC 持有首包的 UDP 路径见 [NFQUEUE](./nfqueue.md)。

## Linux TUN Endpoint

`backend: tun; direct: endpoint` 选择 daemon-owned Linux TUN 路径。
[全局参考](../reference/global.md#linux-tun-endpoint)列出完整语法、必填资源值、
准入及精确五条 RPDB rule。TUN 通过真实 FD 消费已有 scoped Stack、canonical
Router、DNS projector 与出站流初始化器，不创建 TC hook、NFQUEUE、`dae0` 或
`daens`。仅 `host_facts: true` 要求 `ebpf` feature；拒绝 `--mock-ebpf`。

每个队列独占一个非持久化 `TunDevice` FD，以 `O_RDWR|O_NONBLOCK|O_CLOEXEC` 打开。
单队列用 `IFF_TUN|IFF_NO_PI|IFF_VNET_HDR|IFF_TUN_EXCL` 创建。配置 2–8 个队列时，
首个 FD 增加 `IFF_MULTI_QUEUE`，其余 FD 保留该位、去掉 `IFF_TUN_EXCL` 并附加到同一链路。
所有 FD 都须核对网络命名空间、名称、ifindex、附加标志及 10 字节小端 vnet 格式。
Netlink 必须回读到配置的队列数且禁用队列为零。仅启用 `TUN_F_CSUM|TUN_F_TSO4|TUN_F_TSO6`。
HostFacts 与辅助私有 TUN 保持单队列。honk 拒绝不支持的设置，只使用自己新建的设备和 FD。

### Setup 与就绪

1. 完成静态/runtime 准入，取得真实 instance lock，初始化 required 精确旁路
   mark M。`prepare_dns_bind(&Config)` 解析并保留启用 bind endpoint 的实际
   `SocketAddr` 候选；关闭监听时返回 `None`。先计费 runtime/RX 与 plain scope；
   true 额外准备独立 Host scope 和 source owner，均共用 384 MiB 预算。
2. 用真实 TCP/UDP socket 验证 required mark，先订阅 rtnetlink 再 snapshot。
   拒绝已占用的名称/表/五个优先级及不支持的 RPDB/main/default 拓扑。先创建
   私有 setup receipt，持久化 create intent，再执行 exclusive TUN ioctl；
   立即记录实际 netns cookie、ifindex 与 attachment
   incarnation。设置 MTU、明确地址、自有 link sysctl 与 UP，逐项记录 ACK/回读。
   UP ACK 后，先等精确自有 link、永久 host address 与 local host route 回读完成，
   再安装任何 guard/rule。IPv6 NODAD 仍会排队执行 local-route 工作；仅缺失其
   `/128` route 时按通知等待，所有回读共用一个两秒截止时间，不延长。冲突、
   外部非法拓扑或损坏观察立即拒绝，失败发生在改路之前。
3. 每项变更前先写 intent，安装 capture prefix 的 static blackhole（metric
   32760）和五条 rule；此时不安装 unicast capture，Endpoint 未 ready 期间所选
   prefix 由 guard 拒绝，不能原生漏过。
4. 将已计费 scope 与原 owner 交给 driven packet supervisor，传入保留的 DNS
   bind 候选和明确的 plain 独立 DNS scope。就绪和失败清理期间服务所有 driver；
   DNS、软件 flags 与订阅 authorization 均须 ready。true 模式在捕获激活前将
   source owner 绑定到真实 FD 与 attachment。
   多队列模式等待全部队列工作任务就绪，并完成最终 FD 和队列回读，才发布捕获路由。
5. 回读 link/address/rule，安装并回读 metric-1024 capture route；保留旧
   watch 的同时建立最终 `Topology::admit_tun` 订阅及完整 snapshot。全部准入成功
   后才开共享 gate，调用 `capture_ready()`，报告 `TUN datapath ready`、lifecycle
   Running 和 sd_notify READY。close 不能在此竞争中被绕过。

Receipt 位于 `<data_dir>/state/tun-<netns_cookie>-<instance_nonce>.json`，
create-new、mode 0600、拒绝 symlink。它记录完整源码 SHA、PID/starttime、实际
netns/link/attachment identity，以及精确 address/route/rule key 的
Intent/Acknowledged/Removed 状态，每次转换都持久化并 fsync。多队列收据区分独占创建
和后续附加，并记录预期与回读队列数。仅删除已确认仍属本实例的对象。归属不明时保留
对象和收据。收据不授予自动重放或接管的权限。

两个地址族的 active capture route 使用 metric 1024，static blackhole guard
仍为 32760。Linux 会规范化 IPv6 metric 0，IPv4 route delete 的 metric 0
则表示通配，因此 1024 是相对初始 metric-0 设计的明确表示调整。Exclusive
create、回读及 exact delete 都包含 table、family、prefix、output interface
和 metric，移除 active route 时不能选中 guard。

操作者保持 main/WAN/LAN 路由、源地址、forwarding、NAT、防火墙稳定。每个启用
地址族都须有非 TUN 的有效 main uplink 与源地址；main/default 不得通过 unicast、
multipath、nexthop、VRF 或 lwt 路径引用 TUN。额外早期/local rule、VRF/l3mdev、
未知 selector/action 均拒绝，不近似解释。route/address/link/rule 变化、ENOBUFS、
dump 中断/未知解析或 ifindex 替换都会 sticky invalidation 并关闭捕获。订阅不是
抵御任意并发 root 改路的原子栅栏，保留 guard 也不是完整宿主防火墙 kill switch。

### FD 报文管线

FD read 接收 kernel egress；FD write 注入**新的 interface ingress 包**，不能恢复
原始 skb。plain 记录进入原 plain scope；`host_facts: true` 时，真实 read 的
经认证应用 socket 事实选择 Host scope，见证过但无归属的记录仍为 plain。来源
错误不能变成 plain。两条路径均使用解码 vnet metadata、canonical Router、真实
outbound 和同一 FD 的生成 output lease。Direct 新建 dial；scope/tuple/mark 或
生成回复不提供原 operation 或 pre-NAT/TTL 等价。

每个队列复用一个已计费的 65,586 字节 buffer（10 字节 vnet + 65,575 字节普通 IPv6
以及一个字节 sentinel），一轮共用同一个入口时间戳。读满 buffer 可能截断，直接拒绝；
在组合 metadata/source/admission 路径之前，必须验证精确 IP 长度以及 vnet
flag/type/family/header/checksum 范围。TCPv4/TCPv6 GSO 以一个连续 run 接收；
普通 UDP partial checksum 无需 USO。IPv4 头、ICMP 和重组完成包仍验证校验和，
Endpoint/WireGuard 信任规则不变。借用 UDP 在下一次 read 前经 funded ingress
接纳/复制。source callback 仅检查该 scope/attachment 的真实 reverse consumer
存活，不写 FD、不阻塞、不重入 scope mutex。

多队列模式下，一个协调任务管理每队列各一个 Tokio 工作任务和 PacketDriver。
非分片报文若已在规范归属队列上，就直接从 RX buffer 处理。其他队列通过启动前已计费的
有界 FIFO 传递自有报文。队列 0 负责 IP 重组，以 `RxMeta::VERIFY` 和重组完成入站时间
将完整报文交给规范归属者。普通报文保留原 RX 元数据和入站时间。FIFO 满时计数并丢包。
每个归属者用自己的 FD 写回，Linux 据此可将已建立的流导向该队列。

TX 为 CPU frame 单独计费 65,535 字节容量，不放大逻辑 MTU、MSS/PMTU 或普通
UDP MTU。所有输出均带 10 字节 vnet 头，包括普通 ACK/UDP/control；一次 writev
提交该头与不可变 lease 字节，由内核分段 TSO 并完成 partial checksum。

Owner 在有界 RX 前后服务所有 driver。RX 每轮最多 32 次 syscall 尝试/包、1 MiB
或 1 ms。TX 轮转 scope/class 组并保留 pending lease，共用有界 syscall/byte/time
输出预算。EINTR 计数；这些是调度限额，不是可抢占 syscall 的硬期限。
多队列模式下，各工作任务在有界轮次内服务自己的 driver。

| TUN write 结果 | 所有权 |
| --- | --- |
| 完整 vnet+IP record 长度 | 内核接受这一个 record，锁外释放 lease；不代表远端交付或 TCP ACK。 |
| EAGAIN/EWOULDBLOCK | 原 lease、metadata、bytes、scope、FlowId 保持在该类别队首，注册 writable 后重试该记录。 |
| EINTR | 保留同一 lease、metadata 和 bytes，在有限 syscall 预算内重试/让出。 |
| 零或短写 | 致命 packet-boundary violation，禁止写 suffix 或重发整包；保留已报告的部分结果，明确处置本地所有权。 |
| 其他错误 | 致命 owner I/O failure，不回退后端或由其他 executor 重放；模糊提交结果保持模糊。 |

仅 EAGAIN 才清 readiness。空闲前注册 readable，仅 blocked pending 注册 writable，
并注册 topology/driver/close/supervisor waker 与最早真实 driver deadline，再重查。
无 flow/deadline/pending 时没有周期数据面 timer；TUN 没有 XSK CQ/FILL 后备轮询。
任何 scope/config/Router/projection 锁均不跨 await。

### 停止与失败保留

正常 operator stop 先关 admission、移除 metric-1024 capture route，让 prefix 命中
guard，再停止 FD RX，同时保留 setup/watcher/FD/driver。`endpoints.close()` 先关
协议准入，再停止 DNS/command 准入。不再发送新协议输出；pending/closing lease
锁外明确处置，同时继续 driver service 和 `owner.poll_join_plane`，直到 TCP/UDP
initializer、source/receiver、retirement、DNS 与原 scope owner 真正 join。
`shutdown_wait_connections` 不提供自然结束宽限。

Supervisor 返回后，等待全部队列工作任务退出并关闭所有队列 FD。启用来源捕获时，在必需资源
仍存活时排空单读者 source owner。确认自有链路消失后，只删除收据记录且仍可证明归属的对象。
全部业务清理成功后先删除 P+4，
再清 guard/table、bypass/return rule，最后删除 receipt。这个显式 stop 恢复普通
main 路由；之后进行软件 policy cleanup 和已有 API/订阅 shutdown。

任一工作任务或 FD 遭遇致命故障时，整个设备关闭准入。运行失败、崩溃或清理未经确认时，保留 blackhole、规则和收据，并返回错误。
先停源并核对精确归属再由操作者清理，不按名称/表盲删后重启。Drop 只同步关闭
本地 admission/endpoint、处置本地 lease、归还驱动权并关闭 FD，不做 rtnetlink
清理或成功 ack。原 supervisor 在原 Tokio runtime 上继续持有 joined cleanup，
嵌入方必须保持该 runtime 存活。不自动重开 FD、接管资源或回退 TC/XDP。

第一阶段的原生测试覆盖归属、启动与回滚。Linux 真实多队列行为及 1/2/4/8 队列扩展性须通过第二阶段的最低和近期内核一次性 VM 验证。

## Full-XDP 启动

未配置 `datapath` 时仍默认使用 TC。Full-XDP 是显式选择的真实 daemon 后端，不是 XSK fixture，也不会回退到 TC/NFQUEUE/TUN：

```dae
global {
    dial_mode: ip
    nfqueue_enable: false
    so_mark_from_dae: 0x100
}
datapath {
    backend: xdp
    direct: core
    interface {
        dut0: lan
        dut1: wan
    }
}
routing {
    fallback: direct
}
```

`direct: endpoint` 通过现有 packet Endpoint 终止 Direct TCP/UDP，再使用 outbound relay；`direct: core` 则通过 Core forwarding owner 与带输入上下文的内核 FIB 保留 transit 语义。`lan`/`wan`（模型中的 `Lan`/`Wan`）是物理接口角色，不是执行模式。选择 XDP 必须指定 `backend: xdp` 与显式 Direct profile；无效配置在内核挂载前拒绝。不要同时使用 TC 的 `global.lan_interface`/`wan_interface`。所有选中物理接口的全部 RX 队列均打开，每队列一个 ring owner，跨端口/队列共享一个 routing-domain owner。后端、profile 与设备变化要求重启；firewall/NAT 规则通过事务式 generation 发布，拒绝更新时保留原有效策略。

每个 Port 为 retained RX slot 预留 `R * 1024` 字节，其中 `R = min(rx_frames, ring_size)`。这些内存与 UMEM 及其他 capture 资源共用 384 MiB `CAPTURE_MEMORY` 预算（见 `honk-xsk/src/port.rs::RetainedRxSlots::{layout,new}` 与 `honk-core/src/xdp.rs::prepare`）。

借用 RX 不占用 retained slot。Port 校验并取得整包的全部帧后才调用回调，在批末发布 RX consumer 并补充 FILL。后缀有误只提交已接纳的前缀；回调 panic 时关闭 Port，不发布该批，也不回收被中断包的帧。关闭后再次调用接收接口不能改变这个结果。即使先完成的 TX 帧已被复用，原包的 owner 槽也要等最后一个描述符完成后才归还空闲链表。

Endpoint 启动时检查所有路由表中已安装的默认路由，包括 multipath 和 nexthop，拒绝任何可能经捕获端口及其下层出口的路由。运行时不监测这一条件，操作者须自行保持。捕获的以太网和 bond 接口允许有地址；Core 有自己的输入上下文 FIB 要求。物理入口没有经认证的进程身份；未启用 Host 时路由器本机发起的连接留在内核。

Endpoint 的本机地址集合包含命名空间所有有效地址，包括 deprecated 但仍有效的 IPv6 地址。可分类的本机 TCP/UDP 目的地址交给内核，端口 53 例外，仍须经过策略。后续分片使用首片判定；后片先到时会丢弃。未连接 UDP 以及带 options、扩展头或分片的回复也依赖这一行为；如需本机 DNS listener 接收 53 流量，请按顺序配置静态 `direct(must)` 规则。

TUN 使用独立 watcher：无关 link/address/route/rule 变化触发依赖复查，不关闭 TUN；自有 link、地址、路由或规则变化以及畸形或丢失通知仍为致命错误。

Endpoint 回复身份以逻辑 scope 和源 IP 为键，共用 4096 项表。只有不再被协议状态、
TIME_WAIT、initializer/source receiver、DNS 工作及排队/已导出输出持有的条目才可
回收。冲突的 MAC/VLAN 声明不能替换活跃 owner，陌生 RST 不能学习或毒化 peer；
静默条目的冲突仍保留 60 秒，表满也不能绕过。若全表均被持有则拒绝新 peer，不抢占
回复路径。完整 VLAN TCI 随输出导出并保留到 TX credit 等待之后。需要不可用原始
MAC/process 来源事实的 firewall/NAT 谓词在捕获准入前拒绝。

所有捕获逻辑域的 MTU 都必须至少为 1280，包括可能 handoff 给 Endpoint 的 Core
profile；不兼容逻辑域在挂载前拒绝。捕获入口在挂载前选择两种合同之一：已验证关闭
RX VLAN stripping、且不需要恢复标签的物理设备使用 wire-only 解码，由自有 XSK
提供设备/队列权威，并从实际字节解析 inline L2；不读取或伪造 metadata 前缀。
需要 metadata 的路径保留 32 字节 v2 producer 记录，通过真实 device-bound
`bpf_xdp_metadata_rx_vlan_tag` kfunc 获取标签，函数 ID 由内核 BTF 解析。
veth 必须使用该路径，因为本地关闭 RX stripping 不能限制对端 TX 插入标签。
恢复的一层加 inline 标签最多两层；缺失或畸形 metadata 不会触发 wire-only 回退。
最小帧填充上限仅按每层 **inline** VLAN 增加四字节。

就绪前会重新核对设备事实与 topology 订阅。内核没有通用 `data_meta` 能力通告；
必须的 metadata 调整失败时丢包，并与 capture 分开计数。runtime 至多每秒采样一次，
观察到失败后关闭捕获，不承诺一秒硬上限，也不把它称为任意驱动的启动前能力证明。
device-bound 程序必须以真实入站验证，不能使用 `BPF_PROG_TEST_RUN`。

L2 group 地址不能让单播 IP 获得原生 socket 豁免。原生 ARP/ND 和 IP 特殊地址
处理保留；定向广播取自最多 64 条精确的本地表 `RTN_BROADCAST` 路由，不猜后缀。

物理捕获默认强制 ZeroCopy；`xsk_mode: copy` 指定 Copy，`xsk_mode: auto` 根据每个成员的能力与所需 segment 数选择模式。Auto 选择 ZeroCopy 后 bind 失败不会重试 Copy。每次 bind 均回读验证；模式变更需重启。Host 不使用 AF_XDP 队列。

只读启动准入最多汇总 256 条问题，额外问题计入 omitted，前置条件失败导致无法检查的项目标为 `NOT_CHECKED`。检查包含捕获布局、队列、设备能力、外来 XDP、拓扑、内存，以及 Endpoint 的 zone-0 CT 和上联条件。通过后才准备 VLAN feature、加载程序、创建 FD 持有的 link 并绑定队列；supervisor 就绪和拓扑验证之后激活。后续队列失败也会撤销已创建 link。物理 Endpoint/Core link 和程序不 pin；外来 XDP 会被拒绝。进程退出或 SIGKILL 关闭 link FD，内核恢复转发，但已有代理会话可能需要重连。Host 出口独立使用 FD 持有的 TCX 绑定。

物理协调器在 RTNL 就绪时排空通知。Core 若可能从 RX 队列 0 直接转发缓存命中的流量，仍在消费这批输入前做完整检查。链路静默时，协调器会在一秒后读回每个自有 link FD 的身份，不依赖 Core 策略读锁。该检查能发现自有链接脱离或所挂程序变化，不查询其他 XDP 模式，也不代表全量拓扑快照。每个存活的 RTNL watcher 都独立计费 64 KiB 接收缓冲，包括最终启动准入时新旧实例短暂重叠的时段。

Linux 以 `NLM_F_DUMP_INTR` 标记拓扑转储时，honk 丢弃本次不完整的快照，在同一网络命名空间新开 dump socket，从头读取。XDP 和 TUN 的拓扑读取在同一个两秒截止时间内最多尝试八次。若各次转储都被中断，准入失败。非法拓扑和监听通知丢失沿用各自的失败处理。

停止时，honk 先禁止物理 worker 开始新的收发，再撤销 XSK 映射。从进入抓包关闭流程起，撤销策略发布、等待物理 TX 完成和第二个 worker 确认共用 100 ms 等待预算。只有尚有未完成描述符的 TX 才可请求唤醒。超时或设备报错仍会尝试拆除 link，并将关停记为失败，不当作完成。拆除后，物理队列只回收真实 CQ 条目。该预算不限制已经进入内核的调用，也不保证从 SIGTERM 到内核恢复转发的实际耗时。

没有 VLAN upper 时，honk 关闭它所修改的两个 RX VLAN stripping feature，并在正常停止或启动失败时恢复。SIGKILL 后这两位保持关闭，内核软件处理 VLAN。设备身份失权时不再恢复，以免写入已替换的设备。veth 仍需 VLAN metadata。

本机非 53 流量先交内核，本机目的端口 53 仍须走策略。Endpoint hold 优先于 zone-0 conntrack。DNS 原生 pending 命中 CT 后由 CT 接管；没有 CT 时，重复 SYN 或完整 UDP 数据报仍须重新取得许可，pending 本身不授权转发。没有 hold 或 CT 时，TCP 仅纯 SYN 进入 D1，非 SYN miss 交内核。真正需要重组的 UDP 首片不能建立或续签 DNS 原生归属。非 TCP/UDP 通常交内核；ICMP 错误检查引用的流。无法分类的传输层头丢弃。后片在 30 秒内沿用缓存的首片判定，无判定则丢弃。见[网关 DNS 路由](../reference/global.md#xdp-endpoint-dns-投影)。

IPv4 和 IPv6 的原方向初始 TCP SYN 在匹配连接已进入 `TIME_WAIT` 或 `CLOSE` 时重新判定策略。回复流量、引用报文和进行中的连接保留原归属。

仅支持 zone 0。启动拒绝非零或无法证明安全的 nft 和 legacy zone。运行期不安全的 nft zone 或 CT 查询合同错误仍是致命错误。legacy raw 表的周期采样可以关闭 DNS 原生转发，但不是完整的运行期 legacy zone 准入；修改 legacy zone 前应停止 honk，修改后重启。

准入的 802.3ad bond 是一个逻辑 realm，XDP 挂在物理以太网或 veth 成员上；其他 bond 模式或不支持的哈希策略被拒绝。同 realm 的 peer 可以换成员，已导出输出保持原成员。多成员 realm 使用 CPU 输出而不使用 generated output，有性能代价；单成员 bond 可以使用 generated output。realm worker 数受成员中最小队列数限制。捕获身份变化、新成员加入 bond、ENOBUFS 或 `Desynchronized` 为致命错误；carrier、LACP 状态、统计及其他设备变化忽略。地址更新刷新本机集合；成功重同步前保持已发布 map，重同步失败为致命错误。FIB dump 中断在三轮同步内重试。

内核 map/program 内存与 UMEM 一同计入共享 384 MiB 捕获预算；重载期间新旧 generation 同时计费。见[重载限制](./control-plane.md#reload-与运行时-generation)。

[辅助 L3 LAN](../reference/global.md#辅助-l3-lan) 从 TCX ingress 进入同一策略，不提供 MAC 事实。原生判定继续执行内核链；选中 Endpoint 的包重定向到该绑定独占、无地址的 TUN。TCX 使用独立的 per-CPU scratch 和 skb conntrack 查询；解析同时受 IP 声明长度和 skb 线性区长度约束，只有必需首部不在线性区时才拉取。已知归属 Endpoint 的 ICMP 错误交给 Stack 核查引用；未知传输流的引用不会建立新归属。

读写内部 TUN 和驱动 packet scope 的任务在共享运行时执行，不占物理 AF_XDP 队列循环。两个方向均检查本次绑定的设备对；ifindex 数字被复用不构成重定向许可。即使 FD 托管的回向程序先关闭，内 TUN 随设备持有的终态丢弃仍生效。更换绑定时先注销旧 TUN 并退役其在途业务和 DNS 许可，再准入新绑定；`writev` 成功不能证明内核旧队列已空。重载按顺序替换物理和在役辅助 link，失败按逆序回滚；Linux 不提供所有 link 在同一包边界同时切换的保证。

SG/multi-buffer 能力通告和 bind 成功都不等于 jumbo 实测。手动 veth smoke
在 Copy 模式覆盖 MTU 1500 和 9000：每次 UDP 回复必须是单个完整数据报，
jumbo 用例还要求在客户端接口的收发两个方向观察到大于 4096 字节、完整且
未分片的 IP 包。物理 NIC zero-copy、jumbo 性能与 DMA 释放仍需各自证据。

仅符合条件的单成员 realm 且经检查的 `14 + 4 * vlan_count + logical_mtu.max(1280)` 不超过 `FRAME_SIZE` 时，Endpoint 才直接在已预留 UMEM frame 内生成输出。多成员、jumbo 和其他不符合条件的 realm 继续使用 CPU 输出和整链 SG，包括控制包。应用 UDP 首包/首分片、未分片和零长度数据报及控制器 DNS 回复仍为计费的 CPU 输出；后续直接分片不能越过更早 CPU 前缀。

`Port::transmit_generated(class, max_length, generate)` 先预留真实单帧/ring/sidecar 容量，再调用同步 generator；scope credit 也早于 Stack emitter 预留。私有 guard 在无输出、错误或 panic 时取消未发布预留。原始 FlowId 持有先在 scope mutex 内安装，随后在锁外完成精确 peer/header，中间不 await 或服务 RX。只按实际长度补零到以太网最小帧，并以未偏移的 frame base 发布；后续错误不释放已发布 owner，仍须真实 CQ。CPU 与直接 Endpoint owner 共用按精确 scope 混合归还的 CQ batch。既有每 realm 每类别 32 个候选输出、64 个 CQ descriptor 的上限、相互独立的 ACK/重传/CQ 生命周期、E3.1 handoff 及进程生命周期 UMEM 计费不变。符合资格的 driver 轮次只跳过 CPU 拉取，在直接输出后完成 timer/event/close/deadline 收尾，不增加 busy polling。只移除一次中间 Endpoint CPU-IP-frame 到 UMEM 的复制，TCP payload/校验和与 relay 复制仍存在；这不是通用 UDP zero-copy、常驻内存减少或已测收益。

XDP 通过 userspace backend 拥有规范 routing、domain 与 health 发布。native API 报告 datapath kind `userspace`，不声称拥有硬件计数器或 program/attachment 清单。TC listener/token 及 kernel witness API 仍不支持。

固定聚合计数区分队列/credit/容量拒绝、native-ID 历史精度下降及成功 peer 回收。
只有实际拒绝 episode 会告警，持续压力以 debug 汇总，不逐包写日志。
同一 owner sampler 在 DEBUG 过滤外读取六项内核 socket 计数与原始 ring 索引，
只在既有 owner turn 中至多每秒一次；DEBUG 复用样本并报告 port 计数。
就绪时取一次初始样本，正常关闭在 socket 拆除前另取最终样本，不增加空闲采样 timer。
`StatsManager` 仅共享最新有界观测，供 native `/api/v1/datapath` 的
`x-honk.xdp` 与 Clash `/stats` 的 `xdp` 使用；GET 不读取内核、不改变 polling。
按实际准入队列数分配共享存储，构造前计费，最后一个诊断读者释放后才退还预算；
诊断不保留 Port、FD 或包 lease。身份采用真实 namespace/attachment/ifindex/queue，
并保留实际 bind 模式与容量、采样时间/序列、不可用/错误/恢复，以及
starting/active/closing/closed/failed-retained 生命周期。各 ring/队列顺序读取，
不是原子快照。空 FILL 事件和 wakeup 错误不能相加当成丢包；当前 FILL 有内容
不能否定历史饥饿。详见 [API 语义](../reference/api.md#连接关闭模式与数据面生命周期)。

### Event 与有限 adaptive 服务

`datapath.poll_mode` 选择 Event 或 adaptive 策略，两者都从 Event 开始。Adaptive 要求精确匹配可执行文件、计数位置、设备/offload 和参数的校准，RX 或 TX 独立在至少两个完整非重叠窗口内持续高 PPS，真实可轮询设备义务以及共享进程配额。未知 source receipt、异步 SYN/Initializing/DNS 准入、队列拒绝、descriptor、CQ 和空探测都不计资格。TX 按完整 producer publication 计包，包括 generated 与 SG，不按发送函数的成功返回或 descriptor 数。边界与 candidate/qualified 记录见[全局参考](../reference/global.md)。

同一 capture Runtime 服务 driver、timer、completion/FILL、control、有限 RX/TX 和 close；真实策略 reader 的 Pending 获取保持 pinned，并与这些服务复用，blocked-ready 本身不持续 spin。每个活动区间都结算并执行 Event 重评估/协作 yield。只有真实 owner 边界观察到时间经过时才补充配额，不设空闲配额/采样 timer；真实设备可见性与 completion 义务所需的 Event 后备 deadline 仍保留。

每个选中设备（包括 metadata/veth）都持有冷路径计费的 ethtool FD 和有界查询缓冲。每个有限 Busy 探测轮前读取真实 active bit，查询/比较成本计入活动区间；轮内变化在下次扫描发现，不宣称原子排除。MONOTONIC-before/BOOTTIME/MONOTONIC-after 形成的 offset 区间逐次求交：普通重叠不确定性允许累积资格，分离/错误/倒退/长间隔则清空资格。报告的分辨率及非原子读取不确定性不能证明更短 suspend 不存在。协议 Instant 与 scoped 最终发布/权威检查保持原义。

Event 启动即使无校准，也输出可复现的 executable/context/counting 身份；完整数值块还输出参数摘要。因此 candidate 可在测量前绑定预登记实验 manifest，但只有显式实验 CLI 参数才准入该记录。Qualified 仍是特权操作员经外部评审的证据声明，不是 runtime 科学认证。不据此宣称未经测量的吞吐或节能收益；未合格平台继续 Event。

被忽略的 `xdp::tests::driven_kernel::adaptive` 入口
`actual_owner_clock_budget_fairness_and_live_features`（Copy）与
`actual_zerocopy_owner_clock_budget_fairness_and_live_features`（ZeroCopy）
运行同一完整 fixture。一个 Core owner 与独立 Endpoint owner 在同一进程中
共用账本，Endpoint 的每次重建也沿用该账本。唯一的 45 秒绝对 deadline 在
初始化前开始，包含流量、clock/publication 间隔、真实 socket 应用数据/重传/
timer/close、所有队列进展、Core 两个设备的 egress、同线程公平性、配额/债务、
独立发布、真实 feature 修改/恢复、保留查询的 `ENODEV` 及 joined 清理。
ZeroCopy 入口要求实际 `igb` driver 身份、精确队列 `[0, 1]`，以及每个绑定
port 的实际 ZeroCopy 回读，包括每次重建。

独立 recent-kernel igb rig 要求六块 igb NIC、三个封闭 hub、两个 KVM vCPU、
1536 MiB、只读 host root 和一个私有可写 export，不使用 host TAP、bridge
或 socket 网络后端。每个 capture 设备必须回读两个 combined 队列、UDP IPv4
哈希字段 `sdfn` 及双队列 RSS indirection table（`ethtool -N DEV rx-flow-hash
udp4 sdfn` 与 `ethtool -X DEV equal 2`）。producer 变化 64 个 UDP 源端口；
只有真实逐队列 RX 增长才满足队列证据。`HONK_XDP_ARTIFACT_ROOT` 下的
`adaptive-runtime.bindings.jsonl` 与对应 `adaptive-runtime.binding ` stdout
记录保留五次启动：A 一次、B 四次。每条记录包含实际 capture incarnation
（`startup_id`）、namespace/inode、driver、device/ifindex、配置模式及每个队列
的实际 bind 模式。只有真实 peer、scope/CQ、socket、worker 与 OS thread
完成 join 且自有 link 已 detach 后，才写 `adaptive-runtime.joined`。这些源码覆盖仍须 rig 实际通过才能接受某次运行；
不构成 virtio 等价、物理 NIC 性能或 DMA 释放结论。既有 Copy 与 virtio Event
profile 仍作为独立结果。

### Host 来源托管

Host TCX egress 位于原路由选择与 POSTROUTING 之后。转发包和恰好携带 honk bypass mark 的包原样继续。豁免本机服务回包需要**此 skb** 已跟踪的回复标识及同一个 zone 0 conntrack 对象；仅查到反向元组或 ORIGINAL 条目都不能豁免。非适配帧、非 TCP/UDP、DHCP、特殊地址及本机非 53 流量沿用内核路径。

新流按有序网关策略分类。五个 FD 持有的 cgroup hook 将第一次取得的 argv0（不可用时取线程名）存入不随 clone 复制的 socket storage。只有 TCP 使用第二张 socket storage 保存本次连接的决策；断开后在同一 socket 上重连是新决策。UDP 始终按元组分流。Endpoint 的执行、回复和待释放工作都归最初出口及其绑定代。新流的进程信息需与 hold 核对，不是逐包来源凭据，也不恢复原系统调用。`backend: tun` 的 HostFacts 保持独立。 共享 UDP 接收者保留绑定和地址，不继承首个目标的进程事实；物理回复路径与经认证的 TUN 来源不因此被清除。

已证明的 Direct 走原生路径。只有 hold 表确实已满时，**当前策略已经明确判为 Direct** 的新 UDP 包可以不记归属而放行；下一包重新判决。同键争用、未知结果或 Endpoint 容量不足均不能变为 Direct。8,192 行进程元数据表不限制 Direct；LAN 的 8,192 个 native-pending 名额另算。 原生 TCP 另有 8,192 个可按元组查询的归属槽，为没有完整 socket 的控制包保留依据。65,536 行 Host UDP/Endpoint 表满不挤占 TCP Direct 或物理、辅助 LAN 的 hold；TCP 专用表也满时拒绝新 SYN，不作无记录的 TCP 放行。

每个出口单独使用一个私有单队列 TUN。连接空闲后新发的包不算迟到包；已重定向的包到达 TUN 驱动时若已滞留**超过 30 秒**，在进入私有 FIFO 前丢弃，内部时间戳不改 IP 负载。空闲回收要等内核读者通过 grace、唯一读者处理完此前可能已入队的记录，并核实协议、应用和输出都不再保留原归属。定时器触发或一次 TUN 写成功不算排空。不会改投其他出口或重放。

外口 TCX link 由 FD 持有；回复从原活动出口 ingress 注入，以太网使用核验后的本机 MAC。重绑先撤回双向重定向并排空原工作；接口下线或 ifindex 复用不能接收旧回复。终态保护只随自建私有 TUN 存在，不创建 Host XSK、持久外口 pin 或 Host 收据，也不回退到 TC/NFQUEUE。内核防火墙、路由、NAT 与严格反向路径检查仍决定是否交付，不能仅凭它们存在就声称回包成功或失败。

已关闭的 Host 绑定依次退役。队首删除自己的 gate 和设备映射时，不占捕获注册表或绑定锁。删除失败会保留原设备对及其预算；该出口的旧归属清理完毕前不得重绑。

### 物理捕获与 smoke

物理 UDP 包若在 Endpoint 关闭准入前刚通过校验，校验得到的源信息仍然有效。若队列因准入已关闭而拒收该包，它不算被接管，也不计入有效 RX；这次拒收不会导致设备 owner 失败。

物理 link FD 在正常停止或进程退出时 detach。非法 CQ/completion 是致命错误，不算成功排空；未归还 buffer 和 owner 保留到进程退出。启动拒绝外来 XDP，无须手工移除物理 guard 或程序 pin。

`.github/ci/xdp-daemon-smoke.sh` 属于使用匹配预构建 daemon 和测试程序的 floor/recent disposable VM gate。D3 合同检查进程退出或 SIGKILL 后 link detach 和内核转发恢复，以及后续队列启动失败时全部 link 的撤销。保留独立 Host custody 与 TC/NFQUEUE 选择。虚拟覆盖不等于物理 NIC 性能或 DMA 释放认证。

smoke 将 daemon 状态保存在私有 `/run` tmpfs，关闭后再归档。guest cgroup2
挂载放在 `/sys` 之外，避免 `ip netns exec` 为 TC 回归重挂 sysfs 时隐藏该层级。

## 网络命名空间与 hook 架构

需要代理的数据包由 honk 重定向到隔离的网络命名空间，主机上不需要 TPROXY 规则：

```mermaid
flowchart LR
  LAN[LAN traffic] --> LI[lan_ingress]
  LOCAL[Host-originated traffic] --> WE[wan_egress]
  LI -->|local/special or native direct| HOST[Host routing]
  LI -->|proxy, non-must DNS, or raw DNS group must| DAE0[dae0]
  WE -->|proxy, non-must DNS, or raw DNS group must| DAE0
  DAE0 --> PEER[dae0peer in daens]
  PEER --> ASSIGN[dae0peer_ingress / sk_lookup]
  ASSIGN --> SOCK[LISTEN_SOCKET_MAP]
  SOCK --> TPROXY[Transparent listeners]
  TPROXY --> USER[Userspace control plane]
  USER -->|transparent reply socket| PEER
  PEER --> DI[dae0_ingress]
  DI --> LAN
```

### 网络命名空间生命周期

honk 用一个临时线程建立 `daens`：该线程调用 `unshare(CLONE_NEWNET)`，打开 `/proc/thread-self/ns/net`，再把得到的 `OwnedFd` 交回进程。这个 FD 在整个进程生命周期内固定住 `daens`。`/var/run/netns/daens` 只是尽力创建的兼容 bind 挂载，引擎不依靠它持有网络命名空间。

内核支持时，honk 用 rtnetlink 创建 L2 netkit pair `dae0`/`dae0peer`；不支持时回退到 veth pair。随后 honk 通过网络命名空间 FD 把 `dae0peer` 移入 `daens`，再配置链路、地址、邻居、策略规则与路由。两端地址如下：

| 一侧 | IPv4 | IPv6 |
| --- | --- | --- |
| 主机 `dae0` | `169.254.0.1/32` | `fd00:686f:6e6b::1/64` |
| `daens` 的 `dae0peer` | `169.254.0.11/32` | `fd00:686f:6e6b::2/64` |

两个 IPv4 endpoint 各是独立的 `/32` 地址，不共享一个 `/30`。honk 用链路作用域路由和静态邻居让对端可达。在 `daens` 里，fwmark `TPROXY_MARK` 选中表 `100`；该表的 IPv4 与 IPv6 local 默认路由把数据包交给本地透明 socket。

其余时间进程都留在主机网络命名空间。每次切换由 `with_daens_netns` 串行执行：它用进程级 mutex 排队，保存 `/proc/thread-self/ns/net`，进入 `daens`，运行一个纯同步闭包，然后在正常返回或 panic 时恢复原网络命名空间。闭包不能跨越 `.await`，因为 `setns(2)` 只作用于线程。恢复失败时进程直接 abort，否则某个 worker 会留在 `daens` 里，并在那里发起后续拨号。

### 接口 hook 集合

honk 按每个接口的[帧格式分类](../reference/global.md#网卡语义)选用 `_l2` 或 `_l3` 变体。启动只验证初始计划要用的变体，需要时再加一个路由目标。之后新需要的变体在共享后端锁之外验证，通过后才能绑定。

配置里的每个名称先解析为规范根接口。bond 或 bridge 的成员解析到它的 master；本身是 bridge 端口的 bond 解析到该 bridge；其他 master 的成员也解析到 master，但 `vrf` 和 `openvswitch` 的成员保持自身。honk 支持一层 bond/bridge 嵌套，外加作为 bridge 端口的 bond。其他 bond/bridge 嵌套，或自身就是 master 的接口，honk 只拒绝该配置项并给出原因 `unsupported_type`，其余项照常在启动时绑定并 reconcile。各根接口独立规划：只出现在 `lan_interface` 的根算 LAN，只出现在 `wan_interface` 的算 WAN，两边都出现的算 LAN/WAN 共用：

| 根接口角色 | hook |
| --- | --- |
| LAN | `lan_ingress` + `lan_egress` |
| WAN | `wan_ingress` + `wan_egress` |
| LAN/WAN 共用 | `lan_ingress` + `wan_egress`；跳过 `lan_egress` 和 `wan_ingress` |

角色按接口各自判断，所以多 LAN 配置里出现一个共用接口，不会改变其他 LAN 接口的 hook。流量可能绕过 bridge master 上的 hook，因此 LAN bridge 根接口还会给每个端口绑定 hook，角色固定为 LAN，WAN 名称不会把它提升为共用。bond 根接口只把逻辑 master 按表中角色绑定，不绑定成员。作为 LAN bridge 端口的 bond 仍是一个逻辑 LAN 端口，保留 `lan_ingress` + `lan_egress`，不展开成员。假设 LAN 是 `br0`、WAN 是 `bond0`，而 `bond0` 属于 `br0`，那么 bridge 为 LAN/WAN 共用，`bond0` 与其他端口仍为 LAN。没有配置 `lan_interface` 的纯 WAN 部署不装任何 LAN hook。

bond 上只拦截经过逻辑 master TC hook 的正常软件 skb。bonding 先决定哪些接收帧进入 master，honk 随后才分类，所以不会抢在 bonding 的接收决策前接管 inactive 成员上的帧。直接注入成员的原始 `AF_PACKET` 帧，以及绕过这些 TC hook 的路径，包括这类硬件卸载，都不在覆盖范围内。

LAN TCP 与非 DNS UDP 在 bond 上被拦截时，`REDIRECT_TRACK` 记下 master ifindex；符合条件的 LAN UDP `CLIENT_REPLY_TRACK` 条目也保留这个 index。回复从 master 的 TX 发出，即 `dev_queue_xmit`，由 bonding 选择当前出端口。WAN 本机流量被拦截时保存 master ifindex 和 `from_wan=1`，回复经 master RX 回来，即 `BPF_F_INGRESS`，不依赖 `CLIENT_REPLY_TRACK`。active 成员切换和成员热插拔都不需要 honk 在成员上挂 hook。WAN 本机回复的目的 MAC 用的是捕获时读到的 bond MAC，所以 honk 不支持 `fail_over_mac=active`，内核在成员无法设置 MAC 时会强制使用该模式，honk 也未验证过：故障切换一旦改变 bond MAC，已有流上的后续回复就不再作为本机报文交给主机 socket。

`lan_ingress` 分类转发的客户端流量，`wan_egress` 单独分类主机自己创建的流量。拓扑提供独立方向时，反向 ingress/egress hook 只刷新已有连接状态。TCP 状态只由正向 SYN 发布：反向的纯 SYN 既不创建也不刷新它。

在 Linux 6.12+ 上，honk 把接口 hook 建成 FD 持有的 TCX BPF link，排在已有 TCX 程序之后。启动、重绑定和关闭只释放自己的 link。honk 不会创建或删除物理接口上的 `clsact` qdisc 和旧式 filter；遗留项如果不需要，请手动删除。启动时 honk 重建遗留的 `dae0`/`dae0peer` 对。内核选项见[开始使用](../how-to-start.md#内核配置)。

不写 mark、也不受所有权 guard 保护的直通出口返回 `TC_ACT_UNSPEC`，值为 `-1`，在 TCX 里等同 `NEXT`，让后面的 TCX 程序继续运行；反向刷新和跳过 DNS 都属于这类出口。在最低支持的内核上，`TC_ACT_PIPE` 不能当作继续动作。写 mark 的路径返回 `TC_ACT_OK`，值为 `0`，在 TCX 里等同 `PASS`，链到此为止；这类路径包括显式写零的 WAN 路径，以及 LAN classified/pending 和 WAN 精确 socket-mark/classified 的所有权 guard。

属于其他设备的帧同样以 `NEXT` 继续，因此同一设备上排在后面的 TCX 程序以及 legacy `clsact`/`cls_bpf` 过滤器都能看到它们：

- **带 VLAN 标签的帧。** 在以太网父设备上，也就是 `_l2` 变体，`lan_ingress` 和 `wan_egress` 不处理仍带标签、VID 非零的帧，把它们留给 VLAN 设备。VLAN 设备自己的 hook 会分类去标签后的帧。如果父设备把它们重定向进 `daens`，会在那里按 `PACKET_OTHERHOST` 丢掉。跳过的只有这两个 hook，反向的 `lan_egress` 和 `wan_ingress` 仍会刷新连接状态。VID 0 的优先级标签由父设备直接上交，照常分类。`_l3` 程序只在按以太网头解析的帧上遇到标签，见[帧格式](../reference/global.md#网卡语义)。
- **不支持的 LAN 入站帧。** 非 IP 的 EtherType 和不支持的 L4 以 `NEXT` 返回，并且不写 `CLASSIFIED_MARK`，好让 `macsec0` 这类上层设备能分类自己解密后的帧。非 IP EtherType 有 ARP 和 MACsec，不支持的 L4 有 GRE、IPIP、ESP、ICMPv4，以及 Redirect 之外的 ICMPv6。NDP Redirect、非首分片和畸形包则保持终结性的 classified `PASS`。不带标签、但已带 `CLASSIFIED_MARK` 或 pending 标记的帧也一样，因为所有权 guard 先于解析执行。

### 接口协调

`InterfaceBindings` 是接口绑定的唯一 owner。它保存已加载的 TC 程序 FD，并为每个自有 `(ifindex, direction)` 保存一个 FD 持有的 TCX link。启动时它先打开 rtnetlink 订阅，再读一次拓扑快照，打断的 link dump 最多重试三次。然后它推导计划、解析 `local_ip`、加载 BPF 对象并绑定。配置项的行为契约见[网卡语义](../reference/global.md#网卡语义)。

启动只在以下情况失败：

- 无法读取拓扑。打断的 dump 除外，其他错误立即失败。
- 有 `auto` 项时无法读取默认路由。
- 启动集合里的 TC 变体加载不了。启动集合指启动计划绑定的变体；若其中没有路由目标，再加上 `lan_ingress_l2`，没配 LAN 时换成 `wan_egress_l2`。
- 内部 link 失败，包括 `dae0`/`dae0peer`、cgroup 和 `sk_lookup`。

`dae0`/`dae0peer` 的 ifindex 为零，或 `dae0peer` 的 MAC 全零，同样算失败。

启动序列只有一个实现，真实 eBPF VM 测试用的也是它。序列在数据路径 admission 或 READY 之前结束。之后某个计划第一次需要的变体在阻塞线程上验证，不持有共享后端锁；`auto` 切换到 PPP 或 WireGuard 设备就是例子。提交时先挂上当时有效的路由 generation，再把变体发布为可绑定。一个变体加载或扩展失败，不影响其他独立变体的尝试。加载器始终持有未加载程序中嵌入的原始 map FD，日志和事件消费者拿的是副本，因此它们失败或取消不会让后续加载失效。

只有某项为 `auto` 时才读 `/proc/thread-self/net/route`。读取错误不等于“没有默认路由”：启动阶段它是致命错误，之后算 reconcile 失败，保留现有绑定。

[API 参考](../reference/api.md#原生-api)定义 `interface_binding` 降级与原因优先级。reconcile 失败时，绑定和降级保持最近一轮已完成 apply/commit 的结果。

`IfaceWatcher` 接管启动时在拓扑 dump 之前打开的 rtnetlink 订阅。每 60 秒一次的 tick 是事件交付的后备，首次 reconcile 无条件执行，覆盖启动期间的变化。订阅或它的 poll 注册失败时，reconcile 只由 tick 驱动，并报告 `iface_watch` 降级。拓扑发现、程序验证和 TCX link I/O 都在 backend 锁之外运行。watcher 只在读锁下准备验证任务或复制 link 快照；写锁下只做三件事，挂接当前路由扩展、发布已验证变体、转移 link commit。路由发布和接收追踪准备都不会持这把锁等 TC verifier。计划不变且 link 健康时不提交任何内容。角色变化时就地更新已有 link，不会再叠一个。

关闭时先发 stop，再 join watcher。watcher 会等进行中的批次完成；超过阶段超时只记 warning，仍继续等，之后才释放 BPF hook。

链路、地址、路由或接口角色变化时，接口地址仍用于拓扑检测和 ECS 刷新。honk 不再生成 `direct(must)` 规则，也没有隐藏的内核地址白名单。系统清除健康检查 cooldown 并触发新探测。新探测成功之前，失效的 UDP 和多叶节点出站仍保持 fail-closed；未配置 `final` 的单叶节点 TCP 代理组仍可在用户态作为最后尝试。

## 程序清单

| 程序 | hook | 内核职责 |
| --- | --- | --- |
| `lan_ingress_l2`, `lan_ingress_l3` | LAN TC ingress | 检查 admission，绕过特殊/控制面及非 DNS 本地流量，执行单源新流限制与包含端口 53 的有序路由策略、DNS 接管判断、连接状态、direct 卸载、代理重定向、TX 计数、分片 verdict 记录，以及可选的歧义 UDP 暂存。 |
| `wan_ingress_l2`, `wan_ingress_l3` | WAN TC ingress | 刷新反向连接状态；LAN/WAN 共用接口上不挂接。 |
| `lan_egress_l2`, `lan_egress_l3` | LAN TC egress | 刷新反向连接状态，不从 `dae0` 的 UDP 包创建新条目；抑制本机生成的 ICMPv6 Redirect。LAN/WAN 共用接口上跳过。 |
| `wan_egress_l2`, `wan_egress_l3` | WAN TC egress | 路由主机发起的 TCP/UDP，使用进程名与控制面旁路数据，检查出站连通性，缓存决策并重定向代理流量；抑制本机生成的 ICMPv6 Redirect（LAN/WAN 共用接口的 LAN-egress hook 被跳过）。 |
| `dae0_ingress` | 主机 `dae0` 的 TC ingress | 从 `REDIRECT_TRACK` 恢复回复帧信息与 RX 归属，或使用不计数的客户端回退；[续期符合条件的 UDP owner](#udp-生存期续期)。 |
| `dae0peer_ingress` | `daens` `dae0peer` 的 TC ingress | 在链路 scrub 后恢复 UDP53 provenance 与 SYN incarnation；分配 UDP listener。TCP 保留原生 established/TIME_WAIT 查找。 |
| `tproxy_sk_lookup` | `daens` 中的 `sk_lookup` | 用 `LISTEN_SOCKET_MAP` 中的透明 listener 覆盖普通 socket 查找。 |
| `tproxy_wan_cg_sock_create` | cgroup `sock_create` | 保留 socket 首次捕获的进程身份；捕获失败只计数，创建不受影响。 |
| `tproxy_wan_cg_connect4`, `tproxy_wan_cg_connect6` | cgroup `connect4`, `connect6` | 保留已有身份，缺失时在 connect 前捕获；捕获失败只计数，连接不受影响。 |
| `tproxy_wan_cg_sendmsg4`, `tproxy_wan_cg_sendmsg6` | cgroup `sendmsg4`, `sendmsg6` | 保留已有身份，缺失时在发送前捕获；捕获失败只计数，发送不受影响。 |
| `honk_tcp_passive` | cgroup2 根上的必需 `sock_ops` | 在自有 `daens` 内 child 的 `PASSIVE_ESTABLISHED_CB` 上，验证 child 的 tuple、ISN 与 conn/handoff/redirect incarnation，再把已证明的 handoff 写入 child 的 socket storage。 |

`LISTEN_SOCKET_MAP` 的 key 固定为 `0` TCP4、`1` TCP6、`2..=5` UDP4、`6..=9` UDP6。所有 UDP 路径共用 `udp_listener_index`；输入是源和目的地址的低位地址字以及端口，都取主机字节序。`tproxy_sk_lookup` 在 `src/sk_lookup.rs`，它的 IPv4/IPv6 context 读取必须保留为独立的 `#[inline(never)]` 子程序。优化级别 2 下内联可能产生计算偏移读取，verifier 会以解引用已修改的 context 指针为由拒绝。

TC 入口点是原始函数，接受 `*mut __sk_buff`，带 `#[unsafe(no_mangle)]` 和 `#[unsafe(link_section = "classifier")]`。它们不用 Aya 的 `#[tc]` 宏，因为该宏的结构化参数形状在 7.0 及更高版本内核上会被 verifier 拒绝。程序主体返回 `Verdict = Result<c_long, c_long>`，即 `action::Verdict`：`Ok` 表示正常路径，`Err` 表示提前退出，两者都携带真实的 `TC_ACT_*` 值；`flatten` 把任一变体归约为内核的 `i32` verdict。`action::flatten` 定义 `flatten`，实现在 `src/action.rs`，`TC_ACT_*` 常量也在那里。解析器和辅助函数的哨兵值单独表示，不与 verdict 混用，例如 `transport::ERR_FALLBACK`、`ERR_FRAGMENT`、`PASS_UNSUPPORTED`。`bpf_loop` 回调用来控制是否继续执行的返回值同样独立。

`src/sk.rs` 里，`sk_assign_by_index` 是 TC 侧对应 aya `SockMap::redirect_sk_lookup` 的 helper，后者只接受 `SkLookupContext`；`probe_udp_socket` 查询非 DNS 的本地 UDP socket。全部辅助函数都会释放隐式查找引用。各程序的分工如下：

- `lan_ingress_l2/l3`：分类、路由和重定向 LAN 流量，在有序策略下判断 DNS 所有权，并用 `CLASSIFIED_MARK` 去重。NFQUEUE 已启用且 ready 时，它只把有歧义的非 DNS UDP 决策以唯一 token 暂存为 Pending；已启用但未 ready 时 fail-closed，实现在 `src/ingress.rs`。
- `wan_ingress_l2/l3`：刷新反向 conntrack，LAN/WAN 共用接口上跳过。
- `lan_egress_l2/l3`、`wan_egress_l2/l3`：刷新反向 conn state，并路由本机流量。本机流量用实际 skb socket 的 `SOCKET_IDENTITY` 匹配 pname，查控制面旁路和 `OUTBOUND_CONNECTIVITY_MAP` 里的活性，再重定向到控制面。存活的非 DNS WAN UDP 条目只查询缓存路由；未命中时才求值一次路由，并发布完整 conntrack 元数据。实现在 `src/egress.rs`。
- `dae0_ingress`：重写回复 MAC，并把回复重定向到原 LAN 接口。未知对端的 UDP 回复使用客户端帧信息，不归属任何出站；honk 自己的链路源地址从不使用这个回退。
- LAN 与 WAN egress 只抑制本机发起的 ICMPv6 Redirect，判断依据是遍历扩展头之后的 ICMPv6 header；转发的 Redirect 和其他 ICMPv6 仍放行。LAN/WAN 共用接口不挂 `lan_egress`，这条不变式改由该接口上的 WAN hook 承担。`honk-core/tests/ebpf_datapath_test.rs` 用 `BPF_PROG_TEST_RUN` 检查 L2，用隔离 TUN 接口检查 L3，并覆盖精确 tuple RX 计数和 cached-route 策略。
- `dae0peer_ingress`：恢复 UDP53 provenance 和 TCP SYN incarnation。它按重定向点写进 `cb[4]` 的标记 `0x100 | index`，用 `bpf_sk_assign` 分配 UDP，不解析报文字节。缺标记时 UDP 留给 `sk_lookup`；TCP SYN 保留自己的 `cb[3]`/`cb[4]` incarnation carrier，继续走原生 established/TIME_WAIT 处理。
- cgroup sock_create/connect4/6/sendmsg4/6：原生 socket storage 保留首次捕获的 `SocketIdentity{pid, pname}`，供进程名规则和控制面旁路使用。`pname` 通过运行时 kernel-BTF offset 读取 `argv[0]` 可执行文件的 basename，最长 15 字节；不可用或读取失败时回退到线程 `comm`。内核在 socket 对象销毁时回收 storage，所以不再需要 release hook 或 cookie janitor。缺少必需的 cgroup/storage 支持会拒绝启动。这些 hook 挂在根 cgroup 上，所以身份捕获失败，例如 storage 分配或 optmem 计费失败，不会拒绝宿主机操作：只计数，该 socket 的流量没有身份，进程名规则也不会匹配它。honk 自己的 socket 仍通过 `dae_socket_mark` 识别。实现在 `src/cgroup.rs`。

## Map 清单

`crates/honk-ebpf/src/maps.rs` 声明以下 map：

| Map | 形状与职责 |
| --- | --- |
| `CONN_STATE_MAP` | 不预分配的普通 hash，最多 524,288 项。原生 value lock 保护每流 TCP/UDP 状态和已发布的路由元数据，物理回收由用户态负责。 |
| `REDIRECT_TRACK` | 不预分配的 65,536 项 token-bound hash。带锁的有方向五元组 payload 保存原始 MAC 和接口、出站、时间戳、决策身份，用来恢复回复路径。 |
| `CLIENT_REPLY_TRACK` | 16,384 项 LRU hash，把客户端地址和端口映射到 `REDIRECT_TRACK` 的帧信息 payload，让未联系过对端的回复不必经主机转发就能到达客户端。只用于目的端口非 53 的 UDP，客户端源端口为 53 时也算。写入时目的字段清零，payload 不含 lock header，token 也清零。内核淘汰是近似行为：CPU 较多时，近期没发过包的客户端可能在表满前就被淘汰，这类回复随后退回主机转发。该缓存不持有流归属，也不由用户态清扫。 |
| `ROUTING_HANDOFF_MAP` | 不预分配的 65,536 项 hash。TCP SYN handoff 里存已提交策略 generation，暂存 UDP 携带 decision token。原始 must UDP/53 不发布 tuple handoff，所有权改用逐报文 mark。非 must UDP/53 保留事实，供畸形 payload 回退时使用。 |
| `ROUTING_POLICY_ROOT` | 单项 map-in-map，在不可变 policy descriptor 和两个同步生成函数槽之间二选一。替换 root 成功返回时，旧的 non-sleepable 读者已经走完 grace。 |
| 按 generation 持有的 IP/MAC 索引 | 分离的目的和源 IPv4、IPv6 LPM maps，以及 MAC LPM。value 是本 generation 完整的谓词 bitmap，更具体的前缀继承祖先的位。 |
| 按 generation 持有的 domain map | 不预分配的 hash，把 IP 映射到域名谓词 bitmap。DNS 和 sniff 得到的事实都写入，正向和否定条件都覆盖；已存在的零 bitmap 表示 known-false。descriptor 记录它的 map ID，供诊断读取。 |
| `OUTBOUND_CONNECTIVITY_MAP` | 1,536 项数组。每个出站有六个存活槽，覆盖 TCP/UDP 类别与 IPv4/IPv6；缺失槽按存活处理。 |
| `OUTBOUND_STATS` | 直接以 `u8` 出站编号为索引的 256 项（`MAX_OUTBOUNDS`）per-CPU 数组。每个 32-byte `OutboundStatsCounters` 值紧凑保存 `tx_packets`、`tx_bytes`、`rx_packets`、`rx_bytes`；当前 ABI 不使用 `outbound * 4 + counter` 索引。 |
| `LISTEN_SOCKET_MAP` | 16 槽 `SockMap`；key `0..=9` 保存两个 TCP 和八个 UDP 透明 listener。 |
| `DATAPATH_STATE_MAP` | 单槽 admission 数组。零值不改动地放行流量；非零值启用分类与重定向。 |
| `DATAPATH_FLAGS_MAP` | 单槽运行时策略字，存 Rule/Direct 卸载属性、`global.nfqueue_enable` 和 NFQUEUE ready fence。新流分类时读它；已建立流的 direct 卸载只用缓存元数据。 |
| `SOCKET_IDENTITY` | 不克隆的 `SK_STORAGE`，保存 socket 第一次被捕获时的 PID 和可执行文件 basename。存储跟着实际 socket 的生命周期走，不受固定 hash 项数和用户态过期清理约束。WAN TC 只查询；cgroup 的 create/connect/sendmsg 会同步补捕缺失的身份。 |
| `CONN_STATE_OCCUPANCY` | 两槽 per-CPU 插入和内核删除计数，再结合用户态的实际删除数估算占用。这条路径不再由内核删除 tuple，所以内核删除计数一直是零。 |
| `AUX_OCCUPANCY` | 两槽 per-CPU 计数器，统计 redirect 和 handoff 的插入；用户态减去实际删除数。 |
| `ADMISSION_PRESSURE` | janitor 写入的 conn-state 压力锁存。辅助 map 有压力不会置位它。 |
| `NEW_FLOW_RATE` | 16,384 项 per-CPU LRU hash，key 是 LAN 源地址。每个 CPU 为单源新流限制保存一个一秒的 `(second, count)` 窗口。 |
| `FRAG_VERDICT` | 4,096 项 LRU，key 是源、目的和 IP identification，IPv4 还要加协议；见[分片处置记录](#重定向数据报的分片)。 |
| `BPF_STATS_MAP` | 由 [`honk-tool bpf stats`](../reference/cli.md#bpf) 公开的计数器。标签与布局不匹配的说明见该参考页。 |
| `EVENT_RINGBUF` | 262,144 字节的 ring，每条记录 80 字节，其中有实际使用的 tuple/incarnation 过期提示。producer 直接在 ring 存储里预留并初始化事件，不再经过有界 TC 栈复制。 |
| `FLOW_EXPIRY_HINT` | 私有的 4,096 项 per-CPU LRU hash，key 是 tuple，保存最近一次提示的 incarnation 和时间戳。它只尽力抑制重复的 `FlowExpired` 提示，从不持有流，也没有回收 authority。 |
| `UDP_DECISION_SEQUENCE` | NFQUEUE 决策身份的单槽 pinned allocator 状态。协议细节见 [NFQUEUE](./nfqueue.md)。 |
| `FLOW_INCARNATION_SEQUENCE` | 按 generation 持有、spin-lock 保护、不可回绕的 56 位身份域，用 `u64` 表示，独立于持久化的 UDP decision token。 |
| `RETIRE_FENCE`、`RETIRE_ACTIVE` | 不预分配的 65,536 项规范 tuple fence，加一个单槽 active 标志。每个 fence 保存独立的操作 owner 和 decision token。 |
| `RETIRE_GRACE_ROOT` | 私有单项 map-in-map。重新装入同一个 inner map 成功之后，fence 之前的 non-sleepable 内核读者会被同步排空。 |
| `TCP_PUBLISHING` | 不预分配的 65,536 项 hash，对同一个 key 的 SYN 发布做互斥。owner 只活一个 TC invocation，竞争的 SYN 在修改前就被拒绝。没有用户态清扫；已建立连接上的包不会取得这个 claim。 |
| `TCP_SOCKET_BINDING` | 不克隆的 socket storage，存已接受 child 的原始 tuple 和 handoff，由 `honk_tcp_passive` 写入。用户态在接管前用 accepted FD 读取。 |
| `TCP_LIVE_PINS` | 不预分配的 65,536 项 hash，把 incarnation 映射到 presence。已验证的 accepted owner 取得精确 pin，只有老化 TCP 的查询会读它。每个 guard 各自释放自己的 incarnation，不依赖 tuple-local 引用计数是否归零。 |

内核/用户态共用的 map key 和 value 是 `#[repr(C)]` ABI。共享流结构中的 IPv4 地址都以网络字节序的 IPv4-mapped IPv6 值保存。

`ConnState`、`RedirectEntry`、`RoutingHandoffEntry` 的 payload 分别是 72、40、72 字节，各含独立的 `incarnation: u64`。对应的 tuple map 用 `FlowMapValue<T>`：原生 lock 在 offset 0，payload 在 offset 8，实际 value 大小依次为 80、48、80 字节。payload 内的 decision token 偏移不变。`ConnState` 还记录原始 SYN ISN 和已提交拦截标志；offset 68 的 `reserved` 字恒为零。`TuplesKey` 仍是 40 字节，尾部 padding 显式清零。不可变的 `TcpSocketBinding` payload 为 120 字节，offset 116 是 `syn_isn`。持久化的 `UDP_DECISION_SEQUENCE` 严格保留 12 字节。Core 在挂接前验证实际 map 的 BTF/value 布局，工具在解码前验证存储布局。必须使用匹配版本，不提供兼容 shim。

既有 tuple element 只原地更新，从不替换。Linux 的普通 hash 替换会在 RCU 读者仍持有旧指针时复用存储，所以不能替换。内核在原生锁内取得一致快照或窄投影；修改时在同一把锁内比较之前捕获的身份。持锁期间除 unlock 外不调用 helper。物理删除仍要经过 tuple fence、成功的内核 grace，以及事后再验证所有权。外部工具使用 bucket 保护的 batch 和加锁的 value copy，不回退到不安全的单项读取。

无状态 UDP tuple 元数据的 token 和 incarnation 都是 `0/0`。每个新求值的报文只在一个专用的 `0/0` 项上原地更新完整的 handoff/redirect payload，不会覆盖普通或 staged owner。原始 must 目的端口 53 仍用逐报文 carrier，不用 tuple handoff。无状态 redirect 更新在既有刷新间隔到期前保留原时间戳。

`auxiliary.rs` 负责客户端帧信息的首次发布和按间隔续期。目的端口非 53 的精确 LAN UDP 流量，包括源端口 53 的流量，在任一方向都可以沿用既有的一秒时间戳刷新节奏，补回被淘汰的客户端记录。它先在原生锁内复制当前保存的 MAC 和接口 payload，解锁后再投影。未知对端的 fallback 不续期该缓存，也不取得出站归属。这个操作仍是 best effort，不增加 timer，也不逐包写 LRU。

`RoutingMeta` 的 bit 58 仍表示 WAN UDP 归用户态所有，bit 57 即 `OFFLOAD`，用来区分原生直连。未发布 UDP claim 失败时，honk 在原地给精确 owner 记下 `Aborted` 和实际已分配的 token，辅助项保留到 fenced 的用户态清理。Preparing/Aborted 报文不能续期 claim。Aborted 立即满足过期清理条件，但不能转发，也不能激活。advisory hint 丢失时，仍由既有 janitor 兜底。

新对象校验成功后，启动只删除六个已废弃的 honk pin：`COOKIE_PID_MAP`、`UDP_DECISION_EPOCH`、`UDP_DECISION_INFLIGHT`、`UDP_DECISION_RETIRE_FENCE`、`TCP_REQUEST_BINDINGS`、`REQUEST_FENCE`。它不清扫无关 pin，也不删除持久化的 UDP allocator。

`crates/honk-ebpf-common/src/lib.rs` — 共享 mark、NFQUEUE token 编码、`OutboundIndex`、`RoutingMeta`、`DaeParam`、`OutboundStatsCounters` 与 map 常量。
`crates/honk-ebpf-common/src/routing_policy.rs` — 固定 `RoutingInput`/`RoutingDecision`/`RoutingPolicyDescriptor` ABI（128/24/24 字节）、feature bit 与进程名归一化限制。`RoutingDecision` 含直连 mark 索引（未指定时为 `u32::MAX`）；loader 检查 slot 的 BTF 输出布局并拒绝旧外部对象。
`crates/honk-ebpf-common/src/redirect_need.rs` — `TuplesKey`、`Tuples`、携带 token 的 `RoutingResult`/`RoutingHandoffEntry`、256 位 `DomainRouting` 与 `SocketIdentity`。
`crates/honk-ebpf-common/src/conn.rs` — `ConnState`（含 `UdpDecisionState` 与 `decision_token`）、`ParseTransportCtx`、`BpfStatsKey`、`TcpState`，以及与用户态共享的辅助项过期时限。
`crates/honk-ebpf/src/maps.rs` — 静态 TC map 声明与内核侧容量。
`crates/honk-ebpf/src/contrack.rs` 持有 incarnation 分配、内核私有的 `ConntrackArgs` scratch 与共享的生命周期检查；`contrack/tcp.rs` 持有 SYN 分类与 TCP 发布，`contrack/udp.rs` 持有 UDP claim/发布/中止协议。`flow.rs` 持有加锁快照/投影；`auxiliary.rs` 持有辅助项过期、LAN 与 WAN 共用的 `AuxPrep` 发布策略、身份匹配的刷新与稳定发布。

`crates/honk-ebpf/src/route.rs` — 静态 root/slot facade 与固定 ABI dispatch；生成的 policy code 由用户态加载。
`crates/honk-ebpf/src/tcp_binding.rs` 与 `honk-core/src/ebpf/real/tcp_binding.rs` 持有必需的 SYN 发布桥与 `honk_tcp_passive` child 证明；二者都不读取内核内存，因此 TCP 不需要任何内核结构偏移。Peer ingress 恢复后，SYN 使用 mark 低 24 位与 priority 的 32 位携带 56 位身份；request 证明移除后，TCP 不再有该 carrier 的读取方，写入方的移除推迟处理。身份耗尽后拒绝发布，不回绕。

被拦截 SYN 在 TC 中分类，不读内核内存。`bpf_skc_lookup_tcp` 查询 FD 持有的 `daens`；查询为空、`LISTEN` 和 `NEW_SYN_RECV` 都视为不存在，所以 request 本身从不被检查。`TIME_WAIT` 会发布新 incarnation。已有 child 时，结论看它的 socket storage：缺少 child storage 就拒绝，ISN 不同就发布新 incarnation，证明有效则复用存储的 incarnation。

查询不存在时，honk 取第一条匹配的规则作用在 conn-state 条目上：

- ISN 与该 SYN 不同：发布新 incarnation。
- 状态不是 Active：发布新 incarnation。
- incarnation 被存活 relay pin 住：发布新 incarnation。
- handoff 或 redirect 辅助项缺失：拒绝。
- 辅助项存在但已老化：发布新 incarnation。
- 其余情况：复用缓存的 incarnation 和原始路由快照，即使期间策略已经改变。

已提交拦截缺少证据时，honk 拒绝重传，不重建归属，也不转为原生放行。TC 无从得知 request 的 ISN，所以重传可能复用缓存，而内核仍持有由更早、ISN 不同的 SYN 创建的 request。该 request 的 ACK 过不了回调的 ISN 检查，保持未证明并被关闭。原生直连流不取得拦截证明。

`honk_tcp_passive` 以 BPF link 挂接到 cgroup2 根，而且是必需的：没有它启动就失败，TCP admission 也无法开放。它忽略 `PASSIVE_ESTABLISHED_CB` 以外的所有回调，也忽略自有 `daens` 之外的 socket。判断 socket 是否在 `daens` 内，靠 netns cookie 等于用户态在加载前从 `daens` 内 socket 读到的 `SO_NETNS_COOKIE`；cookie 为零时该程序被停用。已接受 child 的 tuple 取自回调上下文，ISN 是 `rcv_nxt - 1`。

在既有 value lock 下，回调要求以下几项都成立：

- tuple 没有在退役。
- conn-state 的 incarnation 非零，带 `ORIGINAL_INTERCEPT`，且 ISN 相同。
- handoff 和 redirect 的 incarnation 与它相等。
- handoff 仍在 established 时限内。

conn-state 可能已经是 Closing：TC 在任何 FIN 或 RST 上标记 Closing，而 FIN/RST 可能先于完成握手的报文到达，也可能就在该报文上。条件满足后，回调用一次 `bpf_sk_storage_get(F_CREATE)` 写入完整的 `TcpSocketBinding`。回调始终返回成功，所以拒绝和存储失败都不会阻断连接：child 只是不带证明，接管时被关闭；存储失败还会累加 child 证明计数。child 存在到 storage 写入之间有一小段窗口，窗口内被拒绝的 SYN 重传由客户端重试。ctx 读取仍是按地址族拆分的 `#[inline(never)]` 常量偏移读取，形态和 `tproxy_sk_lookup` 相同，回调只用栈上 scratch。

自有 `daens` 关闭时会校验 SYN cookies、request migration 和 Fast Open。只有缺少 `tcp_syncookies` key 这一种情况，可以当作内核不提供该 feature 处理；检查、写入或校验出错仍然是致命错误。无法挂接 `sock_ops` 时拒绝启动，包括根 cgroup 槽位已被旧式 flags=0 程序占用的情况。证明缺失、未证明、分配失败，或被新 owner 替代时，honk 关闭 accepted socket，不授权删除 tuple。已取得证明的 child storage 跟随实际 socket 生命周期，没有单独的过期。Backlog 溢出依赖客户端重试，honk 不猜 cookie 归属。因此 LAN 主机大量发送不完成握手的 SYN 时，可以占满透明 listener 的 backlog，在这些 request 过期前拖慢新的被拦截 TCP 连接。先以 IPv4-only 启动、后来再启用 IPv6，仍需要重启：IPv6 socket 族探测在加载时固定，TCP6 listener 在启动时绑定。

有两个窗口用重试或重新发布代替拒绝。内核先把 child 放进 accept 队列，再执行 `PASSIVE_ESTABLISHED_CB` 回调，所以已经在运行的 acceptor 可能在证明写入前看到这个 child。x86 loopback 上实测中位数约 1 µs，最坏约 17 µs；ARM64 只有源码分析给出的上界。`adopt_tcp_flow` 对缺失的证明每隔 1 ms 重试三次，之后才关闭 socket。仍存活的 request 如果收到 30 秒 handoff 时限之后才到达的重传 SYN，会发现发布已老化，于是在旧 request 仍存活时发布新的 incarnation 和路由快照。ISN 匹配的 child 绑定到当时有效的 incarnation，因此沿用替代者的路由。

历史归属证明构建中，最大的分类程序在 Linux 6.12.94 aarch64 上验证了 464,596 条指令（`verified_insns`），而引入归属证明前的 beta.82 发行版为 74,469。增加状态检查的改动应在同一 fixture 上报告改动前后的 `verified_insns`。

`crates/honk-ebpf-common/src/event.rs` — 固定布局的 ring event，包括 conntrack overflow 与 UDP decision-token exhaustion。
`crates/honk-ebpf-common/src/dae_ip.rs` — `In6Addr` union 与 v4-mapped helper。
`crates/honk-core/src/routing/ir.rs` — 规范 `CompiledPredicate` 与用户态 `PortRange`；`crates/honk-core/src/control/routing_matcher.rs` 将其转换为生成函数 ABI。

## Mark 及其所有权

| 常量 | 值 | 含义 |
| --- | --- | --- |
| `TPROXY_MARK` | `0x08000000` | 选择 `daens` 表 100 的 local-delivery 路由，并标记要交给 listener 的重定向数据包。`global.tproxy_mark` 必须等于这个编译期值。 |
| `DAE_BYPASS_MARK` | `0x00000100` | `global.so_mark_from_dae` 为零时的默认值；非零时 honk socket 和 listener 识别使用配置值精确匹配。 |
| `CLASSIFIED_MARK` | `0x40000000` | 防止同时挂在 bridge master 和 slave 上的数据包被重复分类；也标记最终 direct verdict。 |
| `NFQUEUE_PENDING_MARK` | `0x80000000` | 标识必须在 conntrack/NAT 前持有的流量；有效的暂存 mark 还携带 `CLASSIFIED_MARK` 和非零 token。 |
| `NFQUEUE_TOKEN_MASK` | `0x3fffffff` | 选取 NFQUEUE 暂存数据包中承载 decision token 的 skb mark 低 30 bit。 |

`SKB_MARK_RESERVED_MASK` 是 `0xc0000000`，也就是 `CLASSIFIED_MARK` 和 `NFQUEUE_PENDING_MARK` 合起来占用的位。配置校验会拒绝与这些 bit 重叠的 `global.so_mark_from_dae` 和路由规则 mark。NFQUEUE direct 完成路径在接受规则 mark 之前会重复同样的检查。

最终直连报文会带 mark，值为 `rule_mark | CLASSIFIED_MARK`。LAN 原生转发、NFQUEUE 接受和用户态 TCP/UDP socket 都这样。Linux 策略路由只匹配用户位，也就是 `fwmark 0x200/0x3fffffff`。WAN egress 的旁路有两种：精确匹配非零的全局 socket mark，或报文带分类位且不含 `NFQUEUE_PENDING_MARK`。只含 `0x100` 位不再算旁路。宿主发起、带非零直连 mark 的流量会交给用户态，因为到 WAN TC 才改 skb mark 已经晚于原始 Linux 路由查询。

真实透明 UDP/53 从 `SO_RCVMARK` 启用的 `SOL_SOCKET`/`SO_MARK` 辅助数据里取逐报文的出站和策略 generation。同一个 skb 的 `cb[2]` 跨链路保存路由编码和一个不回绕的 20 位已提交策略 generation，由必需的 `dae0peer` TC 恢复。签名掩码是 `0xc8000000`，可变携带位是 `0x37ffffff`。位 `0x100` 表示这个 8 位字段是不可变直连 mark 索引，不是出站编号；索引通过当前 Router 的排序 mark 表解析。`daens` 内部的 fwmark 规则忽略这些可变位。用户 mark 的保留位和 `UDP_DECISION_SEQUENCE` 保持不变。原始直连和分组的归属绝不依赖可变 tuple handoff。

探测非 DNS 本地 socket 时，honk 比较完整 socket mark 和 `PARAM.dae_socket_mark`，据此区分自己的透明 listener 和普通本地服务。主机网络命名空间里的 `dns.bind` socket 仍是普通未标记 listener，但它的存在不能绕过 LAN 端口 53 策略。

## 数据包行为与不变量

### DNS 与本地 listener 优先级

LAN/WAN 的 TCP/UDP 目的端口 `53` 先经过既有入口和控制面排除，然后只执行一次正常有序策略，不另外扫 must 规则。走原生、丢弃、原始转发还是控制器，由[流量规则所有权](../reference/routing.md#出站目标与-must)决定。具体地址或通配地址上的本地 `:53` listener 都不能覆盖这个策略。端口 `53` 仍豁免 LAN ingress 和 WAN egress 上的出站健康检查丢包，但已选的用户 `must` 结果不豁免。

只有非 DNS 流量会在流量策略之前探测本地 socket。探测用的是报文所在的当前网络命名空间，即负 netns ID，不是相对命名空间 ID `0`。匹配到的非 honk socket 可以接收；通配匹配还要求完整 FIB 返回 `NOT_FWDED`。TCP 纯 SYN 跳过探测的行为保留。解析出的目的端口 `53` 请求，在标记非零且完全匹配控制面 bypass mark 时保留原生投递；普通请求继续执行路由，不探测本地 listener。后端回包仍受非 53 策略约束。bind 留空不代表关闭透明 DNS。

实际本地 socket 的优先接收不等于所有网关地址强制直连。非 DNS TCP 纯 SYN 的现有探测策略不变，所以不能承诺不做配置就能一直访问网关管理面；需要时使用[显式用户规则](../reference/routing.md#显式本地路由)。

原生直连仍受外部防火墙/NAT 影响；它与 `asis` 及客户端侧 anyfrom 回复的区别见[DNS 来源边界](./dns.md#入口路径)。
UDP53 不创建普通 UDP conn-state 或 decision token。LAN 查询分片需要控制器或原始组处理时，使用[内核重组与 NFQUEUE](./nfqueue.md#lan-dns-分片)；未分片查询仍走 TC redirect。持久化路由 generation 计数器隔离重启前的排队元数据。其他数据报遵循[分片处置记录](#重定向数据报的分片)。

### 单源新流限制

每个 LAN 源地址都有始终开启、不可配置的预算：每 CPU 每秒 1024 次新流尝试，按固定的一秒窗口计。计数范围包括纯 TCP SYN，含重传；未缓存流的第一个普通 UDP 包；以及任一端口为 53 的每个被路由 UDP 包。direct 流和代理流共用这份预算；同一个 NAT 路由器或接入点后面的所有客户端也共用；每个 IPv6 地址各算一个源。超额的尝试在分配状态前丢弃，并计入 `honk-tool bpf stats` 的 `new_flow_rate_limited`；计数增长时 janitor 记 WARN。本地服务回复学习也用这份预算，但请求不会被丢弃，见[反向学习](#反向-udp-学习与-conn-压力)。LRU 淘汰会忘掉近期计数。限制不覆盖主机发起的 WAN 流量、已缓存流的辅助项重建，以及大量伪造或轮换的源地址。

窗口按 CPU 计，所以有效上限是 CPU 数乘以 1024/s。这份预算只减缓、并不限制单个源占用共享辅助 map：一个 CPU 的预算就够一台主机用 UDP 流占满 `REDIRECT_TRACK`，该 map 有 65,536 项、空闲 120 秒过期；流量分散到 3 个及以上 CPU 时，可以用任一协议的新流占满 `ROUTING_HANDOFF`，它有 65,536 项、30 秒过期。janitor 的压力节奏和回收是兜底；map 写满由 `redirect_track_insert_failure` 和 `routing_handoff_insert_failure` 计数。

### 重定向数据报的分片

在 `lan_ingress` 和 `wan_egress` 上，首片带 more-fragments、偏移为 0，如果它的 verdict 是 `TC_ACT_SHOT` 或 `TC_ACT_REDIRECT`，honk 会把这个 verdict 记进 `FRAG_VERDICT` 并保留 30 秒；匹配的后续分片直接丢弃，不交给代理重组。其他首片 verdict 会清除旧记录，direct、staged、pending 流量照旧。任一端口为 53 的 UDP 被排除，LAN DNS 保留[原生重组](./nfqueue.md#lan-dns-分片)。解析不了的微小首片放行。后续片先到，或记录已过期、被淘汰、插不进去时，后续片可能放行。IPv6 只按源、目的和 identification 匹配，所以 UDP 之前的扩展头不会把同一数据报的分片拆开。

### 反向 UDP 学习与 conn 压力

本地非 honk 的 UDP 请求原生放行。创建它的反向回复 tuple 会消耗[单源预算](#单源新流限制)；缓存命中的请求和回复绕过 socket/FIB 探测。预算耗尽时 honk 跳过学习，不丢请求，也不增加 `new_flow_rate_limited`，于是回复可能作为新流被路由。`wan_ingress`/`lan_egress` 也学习反向 tuple，不受这份预算约束；反向观察不会覆盖正向所有权。即使本地服务已经关闭，持续请求仍会续期学习条目，让它继续原生绕过，直到 [UDP 空闲超时](#udp-生存期续期)。

`ADMISSION_PRESSURE` 置位时，反向学习只做查询：未命中就增加 `udp_reverse_learning_suspended`，新观察到的服务回复可能作为新流被路由，已有条目仍然有效。没有进入压力状态时，未经请求的反向流量可以抢先占据后续正向流的同一 tuple，让后续正向流原生放行。

### UDP 生存期续期

UDP conn state 的空闲超时是 120 秒。三种流量会续期它，至多每秒一次：正向流量、拓扑具备的 `wan_ingress`/`lan_egress` 反向 hook，以及经 `dae0_ingress` 精确匹配非 DNS `REDIRECT_TRACK` 的回复。精确回复先在加锁状态下检查身份、状态和 fence，通过后只续期匹配的存活 owner，包括绑定 token 的代理流；它不创建状态。以下都不续期：无状态端口 53 UDP、`Preparing`、`Aborted`、已过期、`Pending`、`DirectArmed`，以及 `CLIENT_REPLY_TRACK` 回退。代理回复在单网卡和双网卡网关上都有用；单网卡原生 direct 流量不会增加反向 hook。用户态计时器见[长连接](../operations/long-connections.md)。

### 特殊与内部流量

在 LAN ingress/egress 和 WAN egress 上，`dst_is_special` 遇到以下目的地址时，会在路由和 conntrack 前放行流量：

- L2 目的 MAC 的 individual/group bit 已设置，覆盖 broadcast 和 multicast；
- IPv4 `255.255.255.255`、`224.0.0.0/4` 或 `0.0.0.0`；
- IPv6 `ff00::/8`。

这样 DHCP、mDNS、SSDP、LLMNR 这类链路流量就不会进入代理。内部链路地址空间是 `169.254.0.0/16` 和 `fd00:686f:6e6b::/64`。任一 endpoint 落在这些范围时，控制面 UDP admission 会拒绝初始化代理；引擎自己的交付路径由 `dae0`/`dae0peer` hook 处理。

### 出站存活状态

用户态按组向 `OUTBOUND_CONNECTIVITY_MAP` 发布健康状态。新 LAN 流被路由到显式标为失效的槽时，内核会用 `TC_ACT_SHOT` 丢弃。只有一个唯一叶节点且未配置 `final` 的 TCP 组可以保持槽开放，让同一条已选路径做最后尝试。LAN ingress 和 WAN egress 上的 TCP/UDP 目的端口 `53` 都豁免健康检查丢包，仍遵循前述 DNS 所有权规则和已选策略。网关原生路由依赖用户配置的规则。

对于带出口路由或支持 UDP 的配置链的组，发布 UDP 槽时按健康域和地址族检查已提交组管理器中的合格路径。检查跟随当前 Selector 选择和显式 `final`，考虑完整路径的能力和健康状态，并包含 IPv6 槽对 IPv4 健康状态的常规回退。匹配的跳点或有序前缀发生故障且没有其他合格路径时，槽可以关闭。受影响路径恢复后，可重新打开该槽。合格的终止成员 `block` 可以让槽保持开放，由用户态拒绝流量。普通 UDP 组仍对可达的、支持 UDP 的叶节点及终止成员 `block` 做 group-OR。

涉及 UDP 链路的数字槽位更换所属组，或同名组新增、失去承载多跳 UDP 的能力时，重载可能提高该槽位的最低路由代际。缓存流需要重建用户态端点时，必须提供达到下限的代际。代际缺失或过旧时会在拨号前丢弃该流，即使槽位现在选择的是普通节点。已有端点继续使用原先接纳的传输。全量重载被拒绝时保留原代际下限。

TCP 健康检查只作用于新 SYN 的发布；已建立的连接和缓存命中的重传不受后续健康变化影响。UDP 在普通 LAN redirect 以及 WAN 路由/缓存路径上逐包检查健康，原生 direct 卸载和已提交、绑定 token 的 LAN `Proxy` redirect 除外。配置的 UDP block 保持 final。

### 路由时 direct 卸载

非 `must`、非 DNS 流是否留在内核走 direct 路由，只在路由时决定一次，结果缓存到 `RoutingMeta` 的 bit 57。已建立的流检查这个缓存 bit，不再读 `DATAPATH_FLAGS_MAP`。下表里的模式卸载不适用于非 `must` DNS，也不能剥夺 DNS 控制器的接管权限。

| 有效模式 | 路由时策略 |
| --- | --- |
| `Rule`（也包括没有 Clash 模式覆盖） | 只有 SNI 不可能改变结果时才卸载非 `must` 的 `direct` 结果。满足任意一条即可：不存在域名类重新求值；DNS 学习已经提供该流的域名 bitmap；或者从首条 live 规则到当前 direct 规则，包含当前这条，前缀里没有域名谓词。后置的域名规则不再阻止卸载；前置或当前规则里尚未确定的域名谓词仍按保守处理。 |
| `Direct` | LAN ingress、WAN TCP 和 WAN UDP 都把每个非 `must`、非 `block` 流当成 `direct` 卸载，不经过代理健康门控。只有规则本身路由到 `direct` 时才保留规则 mark。这里不参考 SNI，和用户态的模式覆盖不同，所以只靠 sniff 域名命中的 `block` 或 `must` 规则不会生效。 |
| `Global` | 全局选择正好是 `direct` 时，用同一套全 direct 策略。其他全局选择让非 final 流留在用户态，以便应用选出的出站。 |

`direct(must)` 始终保持 direct，不需要 bit 57 标志。普通非 DNS 的 `block` 与 `block(must)` 保持 final；普通非 `must` DNS `block` 仍交给 DNS 控制器。完整规则求值与模式语义见[路由设计](./routing.md)。

### 主机发起的 WAN UDP

`wan_egress` 只分类本机生成的流量。转发数据包带着真实的 ingress ifindex，因此原样放行。带 honk 自有 mark 的 socket，以及匹配控制面 socket 身份的流量，也会 bypass。存活且已发布连接状态的非 DNS UDP 流走只查询的缓存路由路径。miss 时只跑一次路由并发布完整状态，后续数据包再用缓存。DNS 是短生命周期，不创建这项 UDP 缓存。准备 redirect 失败时，例如 handoff/redirect map 已满或归属不匹配，WAN TCP 和 UDP 数据包会被丢弃，不会原生放行；map 已满由现有插入失败计数记录。

## admission 顺序

`DATAPATH_STATE_MAP[0]` 一直保持为零，流量原样放行，直到四件事都完成：内部 hook 全部就绪；listener 绑定并发布完整的 TCP/UDP FD 集合；接收循环启动；已启用的 NFQUEUE 已经 ready。已配置的接口是 lazy 绑定，不是 admission 的前提，见[接口协调](#接口协调)。纯 WAN 部署也必须挂 `dae0_ingress`；挂接失败会在 admission 前中止启动。

关闭时，系统先在适用的情况下阻止新的 NFQUEUE 暂存；接着在拆除 listener 之前关闭 `DATAPATH_STATE_MAP[0]`；然后 drain 并 detach producer。admission map 操作失败是 fatal，不会在所有权不明确时静默继续。

## 用户态维护与计数

`BpfJanitor` 每两秒醒一次。已接受的 TCP relay 在自己的生命周期内 pin 住 conn 和 redirect 项；没有 pin 的 closing TCP 在 10 秒后过期，没有 pin 的 active TCP 有 120 秒 backstop，UDP 按[空闲续期](#udp-生存期续期)处理。没有 pin 的 TCP，以及 token/incarnation 为 `0/0` 的无状态 UDP53 redirect，30 秒后回收但不删 conn state；其他 redirect 保留内核的 120 秒过期。

conn、redirect、handoff 的最高占用率决定每张 map 的清理节奏和候选预算：通常 60 秒扫 1,024 项，占用 70% 时 15 秒扫 2,048 项，85% 时每两秒 tick 扫 4,096 项。以下情况同样切到压力节奏：overflow 计数增长，辅助扫描没做完，或覆盖率 ≥85%。各 map 的游标继续有界扫描，只有完整遍历时才用新鲜的插入/删除计数加上用户态删除记录来校准占用。独立的 `ADMISSION_PRESSURE` 锁存只看 conn-state 占用率，70% 置位，低于 60% 清除。socket 身份不做清扫。

overflow、conn/辅助占用或健康统计读失败时，系统保留上次的样本，初值为零，至多每 10 秒记一次 WARN 并指出是哪个信号失败，清扫不会停。漏读 overflow 不算退出压力所需的安静轮次，校准也要求计数是新鲜的。日志会区分 conn/redirect/handoff 占用；overflow 的 WARN 只在计数确实增长时才出现。退役或 admission 压力发布失败仍是 fatal，并记录完整的原因链。

内核过期会拒绝报文并发出一条 advisory hint，但不删状态。UDP handoff 如果仍匹配存活 conn 的 token/incarnation，即使超过名义上的 30 秒，也会在加锁检查身份后原地续期，每秒至多一次；不匹配仍然拒绝。`FLOW_EXPIRY_HINT` 把缓存里的 tuple/incarnation 合并成每 CPU 每秒一条提示，只有 ring 接受后才记下来。新 incarnation 会重置抑制；淘汰或插入失败可能丢记录。因此 ring 满不会让某个 tuple 静默一秒，代价是 ring 一直满时，每个符合条件的包都多一次失败的预留。hint 不受诊断日志限速影响，也不授予回收 authority。ring/queue 丢提示由 janitor 清扫兜底，过载下不保证及时恢复。

Removal worker 每批最多处理 1,024 项 TCP/UDP/过期请求，使用 [NFQUEUE fence/grace 协议](./nfqueue.md#精确-tuple-退役)。它会按规范 tuple 去重，并保留第一个 token 以及获取/释放顺序。TCP pin 在后端写锁内复验；已经通过 admission 的清理在关闭 warning 之后仍会 join。真正的 UDP conn 删除会触发[精确 endpoint 退役](./control-plane.md#tcp-中继与-conn-state-所有权)。

每个出站的流量计数器都是 per-CPU。路由结果一产生，`lan_ingress` 就对重定向和 direct 卸载结果统计 TX 数据包与字节。`dae0_ingress` 在 `REDIRECT_TRACK` 认出返回流量属于哪个出站后，统计 RX 数据包与字节；经 `CLIENT_REPLY_TRACK` 交付的回复没有对应出站，不计数。未分类的直通流量和丢包没有出站计数。

Backend API 使用 `TuplesKey`/`ConnState`、有界 map 扫描和条件退役。旧 `ConnTuple` CRUD、字符串 IP/域名路由、参数缓存 setter 与 backend 统计适配器已删除；加载时配置的 `DaeParam` global、带 generation fence 的 IP/规则位投影、`StatsManager` 和 pinned `OUTBOUND_STATS` 仍是正式路径。

`just test-netns` 包含生产 TC 报文回归：完整反向 tuple 的 RX 计数、缓存路由的健康/就绪政策，以及 LAN 与 WAN egress 的本机 ICMPv6 Redirect 抑制。L2 使用 `BPF_PROG_TEST_RUN`；L3 使用隔离网络命名空间内的真实 TUN 接口，并验证转发报文与卸载 hook 后的对照行为。

## Core 转发防火墙与 IPv4 NAT

可选的[强类型防火墙/NAT 配置](../reference/routing.md#core-转发防火墙与-ipv4-nat)
扩展现有 CoreForward owner，不是第二套执行器，也不反向解析 nftables。
阶段顺序是捕获域/接口身份、已有原始/回复 binding、原始事实防火墙与 DNAT、
真实输入 FIB、转换后事实转发防火墙、SNAT，然后复用 TTL/MTU/校验和及设备
输出路径。条件沿用规范流量编译器与 matcher，allow/drop/reject 与转换动作
则保留独立的强类型语义。

一个有界表按精确逻辑入口身份保留原始与 DNAT alias；不同 LAN/VLAN 接口可
并存相同私网元组。完整转换后的反向 alias 与公网地址/端口分配器仍在
namespace/scope 域内共享。各方向绑定真实 ifindex 与 attachment incarnation，
错误接口不能借用许可。TCP 由 SYN 开始准入，必须观察匹配序号及
确认号的 SYN-ACK 和最终 ACK 才进入 established。已建立 owner 保留实际观察到的
握手证明，允许匹配的 SYN/SYN-ACK 重传（包括既有 SYN 数据与同时打开），但新
SYN 序号不能接管元组。UDP 反向所有权限定精确对端，不把公网端口作为通配许可。
首包接收时间隔离更早的排队输入；空闲新鲜度同样依据接收事件，而当前处理时间
驱动超时与容量清理。IPv6 使用同一防火墙 owner，但不做地址转换。IPv4 NAT
地址必须满足 transit 单播校验，除回环、多播和有限广播外，也拒绝
`0.0.0.0/8` 与 `240.0.0.0/4`。

已建立 TCP binding 的空闲期限为 7440 秒，UDP 为 120 秒；握手/关闭证明状态保留
30 秒期限。没有接收窗口权威时，FIN/RST 标志本身不能缩短 established 保护。
当前 traffic Block 先于可变 lookup：被拒包既不续期 binding，也不分配转换 ID。

表存储与每个 binding 的 Arc 元数据在分配前计费；改包使用 Core 已计费的
原始缓冲区。端口搜索跳过依赖候选端口的自身 alias 冲突；冲突或端口池耗尽
不发布任何部分 alias。超时、策略撤销及 MASQUERADE
地址移除立即关闭准入，但输出 lease 在真实资源归还前继续保留 binding、端口
与费用。仅修改流量路由不改变安全 epoch；防火墙/NAT 或相关捕获 GeoIP 变化
在发布前推进 epoch，移除再启用也不会将其重置。失败候选保留原编译 sidecar。
路由刷新不会迁移 owner。runtime 慢表为 1024 项（纯 API 最多允许 4096 项），
使用线性查询/分配；这不构成 fast-path、卸载或性能验证声明。

NAT 为转换后的 DF-clear IPv4 数据报分配不同 ID，包括只会在下游分片的包；
DF-set atomic 流量不需要这项分配。全局计费身份目录最多保留
`min(binding_capacity × 64, 65536)` 个数据报（daemon 为 65536），输出及 CQ
owner 保留 binding/quote 权威。观察到最后一个 owner 归还后，还要隔离 120 秒
才能复用。这采用 RFC 6864 的惯例最大数据报寿命，不保证任意更长的远端分片
队列或网络延迟。耗尽只拒绝当前包，不复用活跃 ID；保守的全局池即使不计额外
持有时间，也可能把持续 DF-clear 转换限制在约 546 个数据报/秒，不能宣称高吞吐 NAT。

Core 在尚未启用 firewall/NAT 策略时就记录不授予权限的原生 IPv4 ID 历史，覆盖
普通包先于 NAT、NAT 先于普通包两种顺序。未改写 ID 被记住，只有与保留转换输出
碰撞的普通包才重映射 ID。输出/quote lease 不代表 conntrack grant，并跨 CQ、
策略变更及首次启用 NAT 保留。授权始终使用收到的 wire facts；原生 quote 的 ID
只在最终转发前恢复，不在 lookup 或邻居等待前修复。ICMP echo 标识仍参与匹配。

精确原生历史另有 `min(capacity × 64, 65536)` 项上限，不占用 managed-ID 池；
重复原始 ID 复用历史。目录或预算耗尽时，预先计费的逐 ID 计数器仅把未知 ID
保守地在全域保留，不丢普通转发，也不把转换数据报的速率上限强加给普通流量。
overflow 等待最后 owner 归还，再等待 120 秒加 Core 有界重组期限（当前 30 秒）；
完成的 quote 在任何过期或排队前取得独立保留。这只在饱和时降低域区分精度；
确实需要转换但没有可证明安全 ID 的包仍被拒绝，不复用活跃身份。

历史与实际 conntrack/managed-ID 存储分别计费，后者按需分配。overflow owner
包含 65536 项原子引用计数/退休时刻及有界 bitmap，保留至最后输出/quote guard
归还。动态身份记录持有独立 reservation，table 丢弃也不会提前退还导出 lease
仍占用的内存。这些是逻辑内存边界，不是进程 RSS 或高吞吐 NAT 认证。

分片复用现有重组器，不新建 NAT 重组器，也不虚构非首片端口。存活/正在完成的
重组及导出的 timeout quote 只保留其可能关联的 scoped 地址/协议域；tombstone
和不相关分片不能重置全表身份退休时钟。仅在完整包及校验和验证后转换，
之后的分片仍由 CoreForward 处理。
已准入 IPv4 ICMP 错误引用会还原内层地址、端口、原 ID 及实际存在的校验和字段；
仅含八字节 TCP 首部的引用不会读取不存在的校验和。非首片引用使用保留的 ID
权威，绝不把载荷当作端口。IPv4 UDP 零校验和保持零；未知/截断引用及不支持
的引用扩展布局 fail-closed，IPv6 related 错误不代表支持 IPv6 NAT。

必要的非特权回归位于 `honk-datapath::firewall::tests`、
`honk-core::routing::firewall::tests` 和 `honk-config/tests/firewall.rs`。
集成 owner 生成测试产物后，无需重新构建的 smoke 入口为：直接运行现有
datapath 测试可执行文件并传入 `firewall::tests`，运行 core 测试可执行文件并
传入 `routing::firewall::tests`，以及直接运行 config 的 `firewall` 集成测试
可执行文件。无需操作主机接口、加载 BPF 或创建网络命名空间。源码实现及这些
报文测试不证明设备/硬件、真实内核或性能已验证；完整跨后端验证矩阵仍属独立阶段。

## 相关文档

- [路由设计](./routing.md)
- [NFQUEUE 持包路径](./nfqueue.md)
- [控制面](./control-plane.md)
