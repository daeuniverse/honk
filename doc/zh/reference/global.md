# 全局配置参考

本文定义当前 `global { ... }` 配置字段及其运行时效果。

## 字段

仅兼容字段会被 dae 解析器接受并存入 `GlobalConfig`，但当前运行时不会使用它们。下表均已明确标注。

| dae 键 | 内部字段 | 默认值 | 含义 |
| ------- | -------- | ------ | ---- |
| `tproxy_port` | `tproxy_port` | `12345` | 同时写入用户态监听器和 eBPF 数据路径的 TCP/UDP 透明监听端口；修改后需重启。 |
| `tproxy_port_protect` | `tproxy_port_protect` | `true` | 用于避免透明监听端口被再次拦截的兼容开关；当前运行时不读取该字段。 |
| `pprof_port` | `pprof_port` | `0` | pprof HTTP 端口兼容字段；`0` 表示关闭。honk 当前不启动 pprof 服务，也不读取该字段。 |
| `so_mark_from_dae` | `so_mark_from_dae` | `0` | 套接字 mark 兼容值。校验会拒绝与数据路径保留 mark 位重叠的值，但当前运行时不会将其应用到套接字。 |
| `log_level` | `log_level` | `"info"` | 启动日志过滤器。优先级依次为 `--debug`、`RUST_LOG`、该值。通过 SIGHUP 修改需重启。 |
| `log_file` | `log_file` | `""` | 可选的追加写日志路径。空值关闭文件输出；相对路径在 `data_dir` 下解析，控制台日志保持启用。仅当解析后的实际目标发生变化时，SIGHUP 才要求重启；`--log-file` 会遮蔽此配置值。 |
| `disable_waiting_network` | `disable_waiting_network` | `false` | 兼容键；当前启动路径不读取该字段。未解析的 `auto` 网卡本就保持待定，不会阻塞启动。 |
| `lan_interface` | `lan_interface` | `[]` | 拦截转发流量的 LAN 网卡，逗号分隔。空值不安装任何 LAN hook。参见[网卡语义](#网卡语义)。 |
| `wan_interface` | `wan_interface` | `[]` | 安装 hook 以拦截本机发起 TCP/UDP 的 WAN 网卡，逗号分隔。字面值 `auto` 跟随 metric 最低的 IPv4 默认路由。 |
| `auto_config_kernel_parameter` | `auto_config_kernel_parameter` | `false` | 自动配置 sysctl 的兼容开关。当前运行时不会按该字段分支；真实数据路径会执行固定的 best-effort sysctl 设置。该设置会把 `net.ipv6.conf.all.forwarding` 固定为 1，并因此向每个已解析的 WAN 接口（含运行期晚挂载的）写入 `net.ipv6.conf.<wan>.accept_ra=2`，保证 SLAAC/RA 学来的 IPv6 默认路由不会因 forwarding 被固定而过期消失。使用 systemd-networkd 的主机建议在 WAN 的 `.network` 文件中显式配置 `IPv6AcceptRA=yes`。 |
| `nfqueue_enable` | `nfqueue_enable` | `true` | 将有歧义的 LAN 转发 UDP 原始包保留在 NFQUEUE，直到用户态得到终态决策。需要真实 eBPF 后端；单实例交接后若固定队列不可用，或数据路径准入前的队列/规则/健康检查失败，honk 记录 warning，仅在本进程关闭该功能且不改写配置。持久化 token generation 恢复失败仍为 fatal，因为分配器状态无法确定。安装阶段会回收保留的 nftables table。修改后需重启。新配置应使用此字段；已弃用的 `experimental.udp_nfqueue.enabled` 写法仍接受并给出迁移 warning；两者同时存在时以此 canonical 字段为准。 |
| `data_dir` | `data_dir` | `"/var/share/honk"` | 生成状态和相对运行时资源的非空绝对根目录。缺失目录会递归创建；每个候选目录都必须通过私有的 create-new/remove 探测。候选目录不可用时，仅回退到通过同一探测的工作目录；修改后需重启。 |
| `store_subscribe` | `store_subscribe` | `true` | 将每个订阅最近一次有效正文持久化到 `data_dir/.sub`，供启动和重载恢复；修改后需重启。 |
| `tcp_check_url` | `tcp_check_url` | `["https://www.gstatic.com/generate_204"]` | TCP/HTTP 健康检查 URL，逗号分隔。当前健康检查循环使用第一个值；空列表退回普通 TCP 检查。 |
| `tcp_check_http_method` | `tcp_check_http_method` | `"HEAD"` | URL 健康检查发送的 HTTP 方法；空值按 `HEAD` 处理。 |
| `udp_check_dns` | `udp_check_dns` | `["dns.google:53", "8.8.8.8", "2001:4860:4860::8888"]` | UDP 健康检查的 DNS 目标，逗号分隔；省略端口时默认为 `53`。 |
| `check_interval` | `check_interval_secs` | `30s` | 全局健康检查间隔。UDP 预热 coordinator 也使用该值，但实际下限为 10 秒。 |
| `check_tolerance` | `check_tolerance_ms` | `50ms` | URLTest 切换所选成员前要求的延迟改善量。 |
| `dial_mode` | `dial_mode` | `"domain"` | 目的域名发现和路由模式：`ip`、`domain`、`domain+` 或 `domain++`。参见[拨号模式](#拨号模式)。 |
| `allow_insecure` | `allow_insecure` | `false` | 全局 TLS 校验回退兼容字段。当前 TLS connector 不读取该字段；跳过证书校验需在节点分享链接中按节点配置。 |
| `sniffing_timeout` | `sniffing_timeout_ms` | `30ms` | 嗅探超时兼容字段。dae 解析器会保存该时长，但当前控制面不读取它。 |
| `tls_implementation` | `tls_implementation` | `"tls"` | `tls` 使用常规 BoringSSL 客户端 profile；`utls` 启用 honk 的真实 Chrome ClientHello profile。 |
| `utls_imitate` | `utls_imitate` | `"chrome_auto"` | 使用 `utls` 时请求的指纹 profile。当前只实现 `chrome*`；其他值会告警并仍使用 Chrome。 |
| `tls_fragment` | `tls_fragment` | `false` | TLS ClientHello 分片兼容开关；当前 TLS connector 不读取该字段。 |
| `tls_fragment_length` | `tls_fragment_length` | `""` | 分片长度范围兼容字段；当前 TLS connector 不读取该字段。 |
| `tls_fragment_interval` | `tls_fragment_interval` | `""` | 分片间隔范围兼容字段；当前 TLS connector 不读取该字段。 |
| `mptcp` | `mptcp` | `false` | MPTCP 兼容开关；当前拨号路径不读取该字段。 |
| `bootstrap_resolver` | `bootstrap_resolver` | `""` | 解析节点主机名和控制面拨号目标的 resolver，用于避免经 honk 递归拦截。空值使用普通 bootstrap 行为。 |
| `fallback_resolver` | `fallback_resolver` | `"8.8.8.8:53"` | 回退 resolver 兼容值；当前运行时不读取该字段。 |
| `bandwidth_max_tx` | `bandwidth_max_tx` | `""` | 发送带宽提示兼容值，例如 `'200 mbps'`；当前运行时不读取该字段。 |
| `bandwidth_max_rx` | `bandwidth_max_rx` | `""` | 接收带宽提示兼容值；当前运行时不读取该字段。 |
| `preconnect_node_count` | `preconnect_node_count` | `'auto'` | 启动时执行一次预热的合格裸 TCP 节点数；`0` 关闭，`'auto'` 最多选择八个。 |
| `udp_warm_node_count` | `udp_warm_node_count` | `0` | 每组 UDP 预热候选数；`0` 关闭独立 UDP 预热 coordinator。 |
| `max_concurrent_dials` | `max_concurrent_dials` | `64` | 物理代理连接和协议握手的 generation 局部请求上限；运行时资源预算可能进一步收紧。 |
| —（dae 语法中不可配置） | `tproxy_mark` | `0x08000000` | 用户态策略路由与编译后的 eBPF 数据路径共享的固定 fwmark。 |
| —（dae 语法中不可配置） | `udphop_interval_secs` | `30s` | 旧全局 UDP hop 间隔字段。当前拨号器不读取它；协议特定的端口跳跃使用节点字段。 |
| —（dae 语法中不可配置） | `connect_timeout_ms` | `3000ms` | 代理连接、协议准备、预连接、健康检查和控制面拨号使用的超时。 |
| —（dae 语法中不可配置） | `dns_resolve_timeout_ms` | `2000ms` | 控制面 DNS 解析超时，包括拨号前必须转换为 IP 的目标。 |
| —（dae 语法中不可配置） | `relay_idle_timeout_secs` | `300s` | 旧 relay 空闲超时字段；当前 relay 路径不读取它。 |

## 网卡语义

`lan_interface` 为空具有字面含义：honk 不安装 LAN TC hook，也绝不会用 `lo` 替代。WAN-only 网关因此只使用 `wan_interface`；经过这些 WAN hook 的本机发起 TCP/UDP 仍会被代理，但不会增加任何合成的 LAN 拦截。

`auto` 解析为拥有 metric 最低 IPv4 默认路由的网卡。如果不存在该路由，此项会从期望 hook 集合中省略并保持待定。由于没有挂载 hook，未解析网卡上的流量保持 fail-open；同一列表中显式命名的网卡继续工作。

`IfaceWatcher` 订阅 link、address 和 IPv4 route 事件，并每 60 秒执行一次 reconciliation。它会随网卡和默认路由变化挂载、卸载或重新绑定所需的 LAN/WAN hook，也覆盖 LAN bridge/bond 成员与 WAN bond slave。拓扑变化会刷新生成的网关地址 `direct(must)` 规则，并立即唤醒受健康状态控制的出站探测。网卡列表配置本身发生变化仍需重启。

## 拨号模式

| 模式 | 嗅探 | 域名校验 | 路由与拨号行为 |
| ---- | ---- | -------- | -------------- |
| `ip` | 否 | 不适用 | 保留原始目的 IP；不嗅探，也不重新执行路由。 |
| `domain` | 是 | 嗅探到的名称必须通过目的 IP reality check。 | 校验通过后可按域名重新执行路由；没有域名规则命中时，仍由普通 IP/端口规则决定。代理出站可按已校验域名拨号。 |
| `domain+` | 是 | 否 | 保留初始 IP 规则决策，但允许代理出站使用嗅探域名作为目标。 |
| `domain++` | 是 | 否 | 根据嗅探到的 SNI/Host 重新计算非保留决策，再使用所得代理域名目标。 |

直连、阻断、`must` 及其他保留 handoff 保持最终决策，并保留原始 IP 目标。

## 数据目录与资源路径

`data_dir` 默认为 `/var/share/honk`，必须是非空绝对路径，并在进程内只设置一次。启动时 honk 会递归创建目录，并以私有随机文件执行 create-new/remove 探测。候选目录不可用时，只有通过同一探测的进程工作目录才能作为回退；两者都不可用时，启动失败并报告两项原因。子项使用绝对路径时保持不变。

`geoip.dat` 和 `geosite.dat` 严格使用以下顺序中第一个存在的文件：

1. `$DAE_LOCATION_ASSET/<name>`
2. `<data_dir>/<name>`
3. 进程工作目录中的 `./<name>`
4. `/usr/local/share/dae/<name>`、`/usr/share/dae/<name>`，然后 `/etc/dae/<name>`

其他相对运行时路径按下表保留旧安装：

| 路径 | 解析与旧路径回退 |
| ---- | ---------------- |
| 节点 `ech_config_path` | 优先使用已存在的 `<data_dir>/<path>`，其次使用已存在的工作目录相对路径。两者都不存在时解析为 `<data_dir>/<path>`，使读取错误指出预期位置。 |
| `global.log_file` | 相对路径解析为 `<data_dir>/<path>`，启动时创建父目录；绝对路径保持原样。在 Linux 上，新日志文件使用 mode `0600`；符号链接与非普通文件会被拒绝，已有普通文件的权限保持不变。honk 只追加写且不负责轮转，需要时使用系统日志轮转工具。 |
| `experimental.cache_file.path` | 优先使用已存在的 `<data_dir>/<path>`，其次使用相对于原始配置目录且已存在的路径。新数据库在 `data_dir` 下创建。 |
| `experimental.clash_api.external_ui` | 优先使用已存在的 `<data_dir>/<path>`，其次使用已存在的工作目录相对目录。两者都不存在时，dashboard 下载使用 `<data_dir>/<path>`。 |
| 订阅存储 | 使用 `<data_dir>/.sub`；已有旧 `./.sub` 会继续使用，直至迁移。 |

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
    data_dir: '/var/share/honk'
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
