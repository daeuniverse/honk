# 全局配置参考

`global { ... }` 定义进程级设置。字段及其运行时效果如下。

## 字段

仅用于兼容的字段会被 dae 解析器接受并存入 `GlobalConfig`，但当前运行时不会使用它们。下表均已明确标注。

| dae 键 | 内部字段 | 默认值 | 含义 |
| ------- | -------- | ------ | ---- |
| `tproxy_port` | `tproxy_port` | `12345` | 同时写入用户态监听器和 eBPF 数据路径的 TCP/UDP 透明监听端口；修改后需重启。 |
| `tproxy_port_protect` | `tproxy_port_protect` | `true` | 用于避免透明监听端口被再次拦截的兼容开关；当前运行时不读取该字段。 |
| `pprof_port` | `pprof_port` | `0` | pprof HTTP 端口兼容字段；`0` 表示关闭。honk 当前不启动 pprof 服务，也不读取该字段。 |
| `so_mark_from_dae` | `so_mark_from_dae` | `0`（实际 `0x100`） | honk 主动创建的套接字使用的进程级 `SO_MARK`，并用于数据路径精确旁路匹配。非零值替换 `0x100`，不会与其按位 OR；修改需重启。拒绝保留位 `0xc8000000`。见[套接字 mark](#套接字-mark)。 |
| `log_level` | `log_level` | `"info"` | 启动日志过滤器。优先级依次为有效的 `RUST_LOG`、`--debug`、该值。通过 SIGHUP 修改需重启；原生 API 的 `log.level` PATCH 会替换该过滤器，直到下一次激活。`info` 只记录运行状态（启动、重载、健康检查、订阅）；每条连接的分流记录（`TCP connection`、`UDP connection`、eBPF 卸载）在 `debug`，这样路由器的 syslog 不会被流量刷满。要核对分流结果，用 `debug` 运行，或从 API 读取 `/logs?level=debug`。 |
| `log_file` | `log_file` | `""` | 可选的追加写日志路径。空值关闭文件输出；相对路径在 `data_dir` 下解析，控制台日志保持启用。仅当解析后的实际目标发生变化时，SIGHUP 才要求重启；`--log-file` 会遮蔽此配置值。 |
| `disable_waiting_network` | `disable_waiting_network` | `false` | 兼容键；当前启动路径不读取该字段。未解析的 `auto` 网卡本就保持待定，不会阻塞启动。 |
| `shutdown_wait_connections` | `shutdown_wait_connections` | `false` | 可重载、显式启用的业务连接宽限等待；见[关闭](#关闭)。 |
| `lan_interface` | `lan_interface` | `[]` | 拦截转发流量的 LAN 网卡，逗号分隔。空值不安装任何 LAN hook。参见[网卡语义](#网卡语义)。 |
| `wan_interface` | `wan_interface` | `[]` | 安装 hook 以拦截本机发起 TCP/UDP 的 WAN 网卡，逗号分隔。字面值 `auto` 跟随 metric 最低的 IPv4 默认路由。WAN 绑定规则见[网卡语义](#网卡语义)。 |
| `auto_config_kernel_parameter` | `auto_config_kernel_parameter` | `false` | 自动配置 sysctl 的兼容开关。当前运行时不会按该字段分支；真实数据路径会执行固定的 best-effort sysctl 设置。该设置会把 `net.ipv6.conf.all.forwarding` 固定为 1，并因此对每个 WAN 根接口（包括同时也是 LAN 的接口）一出现在网卡拓扑中（启动时，或之后出现时）就写入 `net.ipv6.conf.<wan>.accept_ra=2`，不等待其 hook，也不要求链路 UP，保证 SLAAC/RA 学来的 IPv6 默认路由不会因 forwarding 被固定而过期消失。同样地，对第一个已解析、存在且未被拒绝的 LAN 名称写入 `net.ipv4.conf.<lan>.rp_filter=0`，按配置原样、不做规范化。新加入设备的 udev `systemd-sysctl` 会在首次写入后立即恢复发行版默认值，因此每个值约一秒后会再写一次；此后 honk 不再改动，直到该设备被重建。使用 systemd-networkd 的主机建议在 WAN 的 `.network` 文件中显式配置 `IPv6AcceptRA=yes`。 |
| `nfqueue_enable` | `nfqueue_enable` | `true` | 将有歧义的 LAN 转发 UDP 原始包保留在 NFQUEUE，直到用户态得到终态决策。需要真实 eBPF 后端；单实例交接后若固定队列不可用，或数据路径准入前的队列/规则/健康检查失败，honk 记录 warning，仅在本进程关闭该功能且不改写配置。持久化 token generation 恢复失败仍为 fatal，因为分配器状态无法确定。安装阶段会回收保留的 nftables table。除实际发生启动降级的情况外，修改后需重启（见下文）。新配置应使用此字段；已弃用的 `experimental.udp_nfqueue.enabled` 写法仍接受并给出迁移 warning；两者同时存在时以此 canonical 字段为准。 |
| `data_dir` | `data_dir` | `"/var/lib/honk"` | 生成状态和相对运行时资源的非空绝对根目录。缺失目录会递归创建；每个候选目录都必须通过私有的 create-new/remove 探测。候选目录不可用时，仅回退到通过同一探测的工作目录，但 `--store db` 和已启用的原生 API 密码登录不允许这种回退。旧根目录 `/var/share/honk`（`LEGACY_DATA_DIR`）中的已有资源按下方各路径规则继续使用；旧缓存和订阅导入则会将符合条件的状态复制到 `state/honk.db`。修改后需重启。 |
| `store_subscribe` | `store_subscribe` | `true` | 将每个订阅最近一次有效正文持久化到状态数据库 `data_dir/state/honk.db`，仅供启动恢复；重载沿用活动节点而不读取已存正文。修改后需重启。 |
| `tcp_check_url` | `tcp_check_url` | `["https://www.gstatic.com/generate_204"]` | TCP/HTTP 健康检查 URL，逗号分隔。健康检查循环使用第一个值；空列表退回普通 TCP 检查。URI 解析分别处理用户信息、带方括号的 IPv6、端口、路径、查询和片段。用户信息不会生成授权头；请求保留路径和查询，不发送片段，无斜杠的查询以 `/?query` 发送。HTTP/HTTPS 默认端口为 80/443；无协议的健康检查目标使用 HTTP/80。URLTest 的无协议目标使用 HTTPS/443，并向解码后的路径和查询串发送 HEAD。 |
| `tcp_check_http_method` | `tcp_check_http_method` | `"HEAD"` | URL 健康检查发送的 HTTP 方法；空值按 `HEAD` 处理。 |
| `udp_check_dns` | `udp_check_dns` | `["dns.google:53", "8.8.8.8", "2001:4860:4860::8888"]` | UDP 健康检查的 DNS 目标，逗号分隔。裸 IPv4/IPv6、`[IPv6]` 和域名默认使用端口 `53`；显式端口必须为 `1..65535` 内的整数。无效括号或端口会使校验失败，并产生带位置的诊断。优先选择第一个 IP 字面量，否则解析第一个域名。解析与 Score 共用解码后的主机和端口，解析完成后仍保留域名身份。 |
| `check_interval` | `check_interval_secs` | `30s` | 全局健康检查间隔。必须为正；解析失败的值会变成零并在校验时被拒绝。UDP 预热协调器也使用该值，但实际下限为 10 秒。 |
| `check_tolerance` | `check_tolerance_ms` | `50ms` | URLTest 切换所选成员前要求的延迟改善量。接受裸毫秒数、`ms` 或 `s`，其余写法沿用此默认值并记录一条警告。 |
| `dial_mode` | `dial_mode` | `"domain"` | 目的域名发现和路由模式：`ip`、`domain`、`domain+` 或 `domain++`。参见[拨号模式](#拨号模式)。 |
| `allow_insecure` | `allow_insecure` | `false` | 全局 TLS 校验回退兼容字段。当前 TLS connector 不读取该字段；跳过证书校验需在节点分享链接中按节点配置。 |
| `sniffing_timeout` | `sniffing_timeout_ms` | `30ms` | 嗅探超时兼容字段；当前控制面不读取它。解析规则同 `check_tolerance`，无效值产生警告并保留默认的 `30ms`。 |
| `tls_implementation` | `tls_implementation` | `"tls"` | `tls` 使用常规 BoringSSL 客户端配置；`utls` 启用 honk 的 Chrome 风格 ClientHello 模拟，不承诺精确浏览器身份。 |
| `utls_imitate` | `utls_imitate` | `"chrome_auto"` | 兼容指纹配置。`utls` 模式使用唯一的 Chrome 风格配置；此值不会切换实现。 |
| `tls_fragment` | `tls_fragment` | `false` | TLS ClientHello 分片兼容开关；当前 TLS connector 不读取该字段。 |
| `tls_fragment_length` | `tls_fragment_length` | `""` | 分片长度范围兼容字段；当前 TLS connector 不读取该字段。 |
| `tls_fragment_interval` | `tls_fragment_interval` | `""` | 分片间隔范围兼容字段；当前 TLS connector 不读取该字段。 |
| `mptcp` | `mptcp` | `false` | MPTCP 兼容开关；当前拨号路径不读取该字段。 |
| `bootstrap_resolver` | `bootstrap_resolver` | `""` | 使用带 mark 的 UDP/TCP 解析节点主机名和控制面拨号目标。为空或查询失败时先查 `/etc/hosts`，再向 `/etc/resolv.conf` 第一个数字 nameserver 发送带 mark 的 DNS；不调用 libc NSS 或追加搜索后缀。 |
| `fallback_resolver` | `fallback_resolver` | `"8.8.8.8:53"` | 回退 resolver 兼容值；当前运行时不读取该字段。 |
| `bandwidth_max_tx` | `bandwidth_max_tx` | `""` | 发送带宽提示兼容值，例如 `'200 mbps'`；当前运行时不读取该字段。 |
| `bandwidth_max_rx` | `bandwidth_max_rx` | `""` | 接收带宽提示兼容值；当前运行时不读取该字段。 |
| `preconnect_node_count` | `preconnect_node_count` | `'auto'` | 启动时执行一次预热的合格裸 TCP 节点数；`0` 关闭，`'auto'` 最多选择八个。 |
| `udp_warm_node_count` | `udp_warm_node_count` | `0` | 每组 UDP 预热候选数；`0` 关闭独立 UDP 预热协调器。 |
| `max_concurrent_dials` | `max_concurrent_dials` | `64` | 各运行时代次内物理代理连接和协议握手的请求上限；运行时资源预算可能进一步收紧。 |
| —（dae 语法中不可配置） | `tproxy_mark` | `0x08000000` | 用户态策略路由与编译后的 eBPF 数据路径共享的固定 fwmark。 |
| —（dae 语法中不可配置） | `udphop_interval_secs` | `30s` | 旧全局 UDP hop 间隔字段。当前拨号器不读取它；协议特定的端口跳跃使用节点字段。 |
| —（dae 语法中不可配置） | `connect_timeout_ms` | `3000ms` | 代理连接、协议准备、预连接、健康检查和控制面拨号使用的阶段超时。透明 TCP 候选竞速与 UDP transport preparation 还使用绝对总预算 `max(10s, 4 × connect_timeout)`；不新增配置键。 |
| —（dae 语法中不可配置） | `dns_resolve_timeout_ms` | `2000ms` | 控制面 DNS 解析超时，包括拨号前必须转换为 IP 的目标。 |
| —（dae 语法中不可配置） | `relay_idle_timeout_secs` | `300s` | 旧中继空闲超时字段；当前中继路径不读取它。 |

仅当实际发生启动早期降级（mock/不带 `ebpf` 或固定队列前置检查失败），或数据路径准入前较晚的队列/规则/健康检查降级时，写入和重载才允许在 NFQUEUE 生效值保持关闭的情况下请求 `nfqueue_enable: true`，包括省略该键、采用默认值 `true` 的情况。请求的源文本保持原样，但生效值在本进程整个生命周期内保持 `false`；不会自动重试启用，需重启才能重试。没有发生该降级时，开关变更仍需重启。[公共重载流程](../design/control-plane.md#reload-与运行时-generation) 在指纹/no-op 检查前归一化生效配置；原生 API 的写入前检查与完整校验共用同一重启策略。持久化 token generation 恢复失败和[准入后的失败](../design/nfqueue.md#启用与范围)仍为 fatal。

`nfqueue_enable` 同时控制 [LAN UDP/53 分片交付](../design/nfqueue.md#lan-dns-分片)：控制器/原始组分片要求 NFQUEUE ready，否则丢弃，不能绕过 DNS 策略。原生 `direct(must)` 和未分片 DNS 不变。

HTTP 健康检查和 URLTest 的 `Host` 使用不含凭据的主机与端口：IPv6 保留方括号，非默认端口不会省略。建立连接和处理 TLS 服务端名称时仍使用不带方括号的主机。

请求路径和查询字符串保留配置中的原始点路径段和百分号编码。在构造请求前拒绝 authority 含多余斜杠、包含反斜杠或内嵌 ASCII 空白／控制字符的 URL；健康检查警告不回显被拒绝的 URL。

## 关闭

仅设为 `shutdown_wait_connections: true`，且正常关闭、数据路径健康并存在活动 runtime epoch 时，才给已接受连接最多五秒自然结束，再关闭并 join 剩余连接。其他情况跳过宽限等待，不区分长短连接。

关闭使用最近接受的配置；重载被拒绝时保留旧值。此开关不改变 reload 退役、DNS/状态持久化、NFQUEUE/eBPF 清理或原生 API 独立的[五秒 HTTP 宽限期](./api.md#原生-api)。

这不是优雅重启，也不限制总退出时间：[持有的清理及阻塞工作](../design/control-plane.md#终止所有权)仍须完成。

## 套接字 mark

`so_mark_from_dae: 0` 或省略该项时，保留历史实际 mark `0x100`。
非零值会在 connect/send 之前原样应用，包括代理承载连接、bootstrap/DNS、
健康检查、订阅与 UI 下载。数据路径按配置值精确匹配旁路；仅含有 `0x100`
这一位并不能免于拦截。透明监听套接字使用相同 mark 供内核识别；
accept 得到的 TCP 客户端套接字会清除此 mark。独立 `dns.bind` 入口仍是
普通的无 mark 本地服务。

dae 全局标量保留 honk 既有的十六进制优先规则：`10` 与 `0x10` 都表示 16；
格式错误或溢出文本会产生诊断，并回退到原始值 `0`，即实际 `0x100`。
建议显式写 `0x`。这与[直连规则 mark](./routing.md#策略路由-mark) 不同：
后者无前缀时按十进制解析，错误值直接拒绝配置。
全局与规则 mark 校验均拒绝保留位 `0xc0000000`；全局 mark 还拒绝 TPROXY 位 `0x08000000`，daens 会把该位路由到其本地监听器。

该值在启动网络 I/O 前确定，作用于整个进程；修改需要重启，不能通过 SIGHUP
切换。非零直连规则 mark 会替换该直连流的全局策略路由有效位，而代理承载连接
与 bootstrap 仍使用全局值。直连流还携带内部分类元数据；请使用
[路由参考](./routing.md#策略路由-mark) 中带掩码的 IPv4/IPv6 `ip rule` 示例。
honk 不负责安装用户的 WAN 策略路由表、路由、源地址规则或 NAT 配置。

## 重载健康检查与 TLS 模式

以下参数在启动时确定。重载若改变生效值，会被拒绝；当前配置与已安装的探测器保持不变：

- `check_interval`。
- 第一个 `tcp_check_url`，包括回退地址、路径和查询字符串。缺失或空的首项均关闭 HTTP 探测；后续项不参与比较。
- HTTP 探测启用时的 `tcp_check_http_method`。空值与 `HEAD` 等价。
- `udp_check_dns` 选中的目标：去除首尾空白并忽略空项，优先选择列表中的第一个 IP 字面量，否则选择第一个域名，再无可用项则使用 `8.8.8.8:53`。重载检查只比较配置中的地址或域名及端口，不解析 DNS。未选中项的变化仍可重载。
- `tls_implementation` 在原生 TLS 与 uTLS 之间的切换。比较 `utls` 时不区分大小写。

dae 配置中的 `check_tolerance` 仍可通过重载更新 URLTest 组的容差。组级检查 URL 与直接连接探测仍沿现有路径动态更新。重载 `utls_imitate` 只保存兼容配置值，不改变指纹。

UDP DNS 目标在启动时按健康检查超时尝试初始化。本地拒绝或初始化超时会使
配置目标保持待定，留给后续健康检查周期重试，不替换默认目标，也不降低节点
健康状态；独立 QUIC 检查仍可继续。首次成功解析的地址随后保持固定。
延后的解析与 DNS 交换共用一次探测的绝对期限；普通解析失败保留原有默认回退。

## 网卡语义

`lan_interface` 为空时，honk 不安装 LAN TC hook，也绝不会用 `lo` 替代。WAN-only 网关因此只使用 `wan_interface`；经过这些 WAN hook 的本机 TCP/UDP 流量仍会被代理，但不会额外安装 LAN 拦截。

在以太网父设备上，VID 非零的 VLAN 标签帧属于 VLAN 设备；要管理该子网，请列出 `eth1.20`（VLAN-aware bridge 请列出 `br0.N`）。VLAN-aware bridge 拓扑尚未经过真实流量测试验证。参见[接口挂钩集合](../design/datapath.md#接口挂钩集合)。

`auto`（在所有使用处均去除首尾空白并不区分 ASCII 大小写，因此 `AUTO`、` auto ` 与仅含空白的条目都算；`.dae` 列表解析器会丢弃真正为空的项，所以空列表仍表示没有接口）解析为拥有 metric 最低 IPv4 默认路由的网卡。如果不存在该路由，此项保持待定（绝不回退到 `lo`），直到默认路由出现。同一列表中显式命名的网卡继续工作。仅当某项为 `auto` 时才读取路由表；路由表无法读取是错误，而不是“没有默认路由”：启动时会失败，运行期间的失败则保持现有绑定不变。

网卡存在即绑定，不要求 `IFF_UP`。角色按网卡区分（见[接口挂钩集合](../design/datapath.md#接口挂钩集合)），因此 LAN/WAN 共用网卡不会改变其他 LAN 网卡的 hook。bond、bridge 或其他 master 的成员通过该 master 绑定，但 `vrf` 与 `openvswitch` 的成员保持自身；LAN bridge 还会以 LAN 角色绑定其端口，bond 的 hook 只挂在逻辑 master 上，不挂成员。

每个已配置的条目都是惰性绑定，绝不会导致启动失败。网卡尚不存在、没有默认路由的 `auto` 条目或被拒绝的链路类型（见下）不会绑定任何 hook：其流量在绑定之前不被拦截。无法创建、更新或校验的 TCX link 可能让条目只绑定了部分 hook，因此有效的 hook 仍可能拦截流量。两种情况都由 `interface_binding` [降级](./api.md#原生-api)报告；`lifecycle.state` 仍为 `running`，监控必须读取该降级。只有内核的主名称会被匹配，altname 视为不存在。出现的设备会被绑定，消失的设备会释放其 hook，以新网卡 index 重建的设备会重新绑定。属于尚不存在的网卡的 `dns.bind` 地址不是网卡条目：绑定它仍会导致启动失败（`EADDRNOTAVAIL`）。

链路类型决定程序族：

| 链路类型（`ifi_type`） | 帧格式 |
| --- | --- |
| 以太网：eth、bond/team（其第一个端口为以太网时）、bridge、vlan、macvlan/macvtap、ipvlan、veth、netkit、vxlan、geneve、gretap、tap、dummy、macsec | `_l2` |
| `ARPHRD_NONE`（wireguard、tun、`collect_md` GRE、无 MAC 模式的 geneve/VXLAN-GPE）、PPP、RAWIP、IPIP、IP6TNL、SIT | `_l3` |
| GRE / IP6GRE | 仅当置位 `IFF_POINTOPOINT` 且未置位 `IFF_BROADCAST` 时为 `_l3`；否则拒绝 |
| `lo`、`vcan`、InfiniBand、802.15.4、nlmon 及其他所有类型 | 拒绝 |

此表描述分类器，而不是经过验证的设备支持矩阵。IPv4 GRE 与 `collect_md` GRE 的内核测试检查标志与 TCX hook，不验证隧道负载转发。本次变更未验证真实 IP6GRE、IPIP、SIT、IP6TNL、PPP、RAWIP、tun 与 wireguard 设备；GRE 与这些 L3/NONE 程序族也都缺少端到端流量覆盖。

当内核报告网络头位于帧起点后 14 字节、且第 12–13 字节与数据包协议一致时，`_l3` 程序按以太网头解析而不是裸 IP，例如先设成以太网、再改类型（如 RAWIP）的设备。线性头超过 65550 字节的帧仍按裸 IP 解析。L3 bond 上经 AF_PACKET raw socket 发出的裸 IP，若源地址字节恰好等于 EtherType，会被误当作以太网解析；这类发送方需要 `CAP_NET_RAW`，而该权限本身就允许设置 honk 的 bypass mark。内核测试覆盖改类型为 RAWIP 的 TAP，不包括真实蜂窝模组。

只有单播 remote、没有显式 local 地址的 IP6GRE 可能没有 `IFF_POINTOPOINT`，即使其数据包本可按裸 IP 处理也会被拒绝。不支持用 `ip link change` 原地修改已有 IP6GRE：内核可能改变点对点标志而不清除 `header_ops`，使分类器在隧道头仍存在时选择 `_l3`。请删除并重建设备，而非原地修改；IP6GRE 的创建与流量仍未经验证。

被拒绝的项不绑定任何 hook，并按每个 episode 记录一次指明网卡与原因的错误日志：链路类型不受支持、不支持的 bond/bridge 嵌套或自身即 master、`vrf` 设备（请配置成员；VRF 成员绑定自身）或 `dae0`/`dae0peer`。降级以原因 `unsupported_type` 报告；即使它是第一个已解析的 LAN 或 WAN 项，也不会导致启动失败或阻止其他项绑定。类型不受支持的 bridge 端口被静默跳过。bond 或 team master 的类型取自其当前第一个端口，因此 InfiniBand bond 会被拒绝。L3S 模式的 ipvlan 与 `reorder_hdr off` 的 VLAN 设备属于不支持的组合。

`IfaceWatcher` 订阅链路、地址和 IPv4/IPv6 路由事件，并每 60 秒执行一次协调。若无法订阅或无法注册轮询，它仍每 60 秒协调一次，但没有事件通知，并报告 `iface_watch` 降级。它会随网卡和默认路由变化创建、更新或释放所需的 LAN/WAN hook。拓扑变化仍用于 ECS 刷新，并立即唤醒受健康状态控制的出站探测，但不再生成网关地址 `direct(must)` 规则，也没有隐藏的内核地址白名单。网卡列表配置本身发生变化仍需重启；网关管理访问应使用[显式用户路由](./routing.md#显式本地路由)。启动顺序与导致启动失败的条件见[接口协调](../design/datapath.md#接口协调)。

真实 LAN 绑定还会执行提示性的[自保覆盖检查](./routing.md#显式本地路由)。无法确认时仅告警，不拒绝启动或重载，也不插入路由规则。

## 拨号模式

| 模式 | 嗅探 | 域名校验 | 路由与拨号行为 |
| ---- | ---- | -------- | -------------- |
| `ip` | 否 | 不适用 | 保留原始目的 IP；不嗅探，也不重新执行路由。 |
| `domain` | 是 | 嗅探到的名称必须通过目的 IP reality check。 | 校验通过后可按域名重新执行路由；没有域名规则命中时，仍由普通 IP/端口规则决定。代理出站可按已校验域名拨号。 |
| `domain+` | 是 | 否 | 保留初始 IP 规则决策，但允许代理出站使用嗅探域名作为目标。 |
| `domain++` | 是 | 否 | 根据嗅探到的 SNI/Host 重新计算非保留决策，再使用所得代理域名目标。 |

直连、阻断、`must` 及其他保留 handoff 保持最终决策，并保留原始 IP 目标。

## 数据目录与资源路径

`data_dir` 默认为 `/var/lib/honk`，必须是非空绝对路径，并在进程内只设置一次。启动时 honk 会递归创建目录，并以私有随机文件执行 create-new/remove 探测。候选目录不可用时，只有通过同一探测的进程工作目录才能作为回退；两者都不可用时，启动失败并报告两项原因。使用 `--store db` 或启用原生 API 密码登录时，启动过程不允许这种回退。旧根目录是 `/var/share/honk`（`LEGACY_DATA_DIR`），用于复用已有资源。旧缓存和订阅导入会将符合条件的状态复制到 `state/honk.db`。即使使用自定义 `data_dir`，也遵循相同的回退顺序。子项使用绝对路径时保持不变。

`geoip.dat` 和 `geosite.dat` 严格使用以下顺序中第一个已存在的普通文件：

1. `$DAE_LOCATION_ASSET/<name>`
2. `<data_dir>/<name>`
3. `/var/share/honk/<name>`（`LEGACY_DATA_DIR`）
4. 进程工作目录中的 `./<name>`
5. `/usr/local/share/honk/<name>`，然后 `/usr/share/honk/<name>`
6. `/usr/local/share/dae/<name>`、`/usr/share/dae/<name>`，然后 `/etc/dae/<name>`

其他相对运行时路径按下表保留旧安装。除日志外，每次查找先检查实际生效数据目录中已有的副本，再检查 `/var/share/honk` 中已有的副本，最后检查各调用方的已有旧候选路径。都不存在时，返回 `data_dir` 下的路径用于创建；绝对路径保持原样。

| 路径 | 解析与旧路径回退 |
| ---- | ---------------- |
| 节点 `ech_config_path` | 依次优先使用已存在的 `<data_dir>/<path>`、已存在的 `/var/share/honk/<path>`，以及已存在的工作目录相对路径。都不存在时解析为 `<data_dir>/<path>`，使读取错误指出预期位置。 |
| `global.log_file` | 相对路径始终通过仅用于创建的路径 helper 解析为 `<data_dir>/<path>`，启动时创建父目录；不会读取或迁移 `/var/share/honk` 中已有的日志。绝对路径保持原样。在 Linux 上，新日志文件使用 mode `0600`；符号链接与非普通文件会被拒绝，已有普通文件的权限保持不变。honk 追加写入，文件达到 10 MiB 时轮转：当前文件改名为 `<name>.1` 并覆盖旧副本，再按相同检查打开新文件，因此日志最多占用 20 MiB。重启交接期间两个实例共用该文件时，只有文件仍在原路径上的实例执行改名，另一个实例直接切换到新文件，因此不会互相覆盖轮转副本。轮转失败（例如新文件无法打开）时，honk 不再尝试轮转，继续写入当前文件直到 20 MiB，之后丢弃日志行，并在 stderr 输出一次警告，直到重启。控制台与文件里的时间戳都是本机本地时间并带 UTC 偏移（`2026-09-12T02:30:15.123456+10:00`）。 |
| `experimental.cache_file.path` | 不再决定存储位置，状态保存在 `<data_dir>/state/honk.db`。首次启动时按旧的解析顺序读取一次，用于导入旧 `cache.db`（见[升级说明](./experimental.md#从-cachedb-升级)）。 |
| `experimental.clash_api.external_ui` | 依次优先使用已存在的 `<data_dir>/<path>`、已存在的 `/var/share/honk/<path>`，以及已存在的工作目录相对目录。都不存在时，dashboard 下载使用 `<data_dir>/<path>`。 |
| 订阅存储 | 正文保存在 `<data_dir>/state/honk.db` 中。每次启动时，honk 依次在 `<data_dir>/.sub`、`/var/share/honk/.sub`、`./.sub` 中查找第一个私有的旧存储，导入已启用订阅的正文，然后删除已复制的文件（见[订阅参考](./subscription.md#拉取持久化与恢复)）。 |

## 预热与拨号预算

| 键 | 默认值 | 运行时语义 | 详情 |
| -- | ------ | ---------- | ---- |
| `preconnect_node_count` | `'auto'` | 仅启动时执行一轮裸 TCP 预连接。`'auto'` 最多选择八个合格节点，并发四次尝试；显式 `N` 最多选择 `N` 个，并发不超过 `min(N, 8)`。各组当前选择优先，之后按节点配置顺序补充。`0` 关闭。 | [组设计](../design/groups.md) |
| `udp_warm_node_count` | `0` | `0` 关闭。正值 `N` 按组和 IP family 选择 top `min(N, 3)` 的可复用 UDP 叶子，去重后全局最多保留 `4 × N` 个。最多并发四次尝试；启动后立即运行，之后每批完成再等待 `max(check_interval, 10s)`。 | [组设计](../design/groups.md) |
| `max_concurrent_dials` | `64` | 限制每个 generation 的物理代理连接和握手，实际值至少为一，并受重叠 reload generation 共享的文件描述符预算上限约束。Ready pool 命中、已热 transport 上的逻辑流以及 `direct`/`block` 不占 permit。 | [组设计](../design/groups.md) |

## 示例

```dae
global {
    tproxy_port: 12345
    log_level: info
    log_file: 'honk.log'
    data_dir: '/var/lib/honk'
    store_subscribe: true
    nfqueue_enable: true

    lan_interface: br0
    wan_interface: auto

    tcp_check_url: 'https://www.gstatic.com/generate_204'
    tcp_check_http_method: HEAD
    udp_check_dns: 'dns.google:53,8.8.8.8,2001:4860:4860::8888'
    check_interval: 30s
    check_tolerance: 50ms

    dial_mode: domain++
    bootstrap_resolver: '223.5.5.5:53'

    preconnect_node_count: 'auto'
    udp_warm_node_count: 0
    max_concurrent_dials: 64
}
```

## 相关文档

- [配置指南](../configuration.md)
- [节点参考](./nodes.md)
- [组参考](./groups.md)
- [组设计](../design/groups.md)
