# TPROXY 数据路径

TPROXY 数据路径使用 netfilter 而非 eBPF 拦截流量，服务于 [eBPF 数据路径](./datapath.md) 无法加载的内核（Linux 4.19 至其最低版本之间）以及 Android（netd 占用根 cgroup 的 BPF 挂载点）。由 `global.datapath` 选择（[数据路径选择](../reference/global.md#数据路径选择)）；代码位于 `crates/honk-core/src/tproxy.rs`。

## 拦截

启动时对每个地址族通过 `iptables-restore --noflush` 安装两条 `mangle` 链，并添加一条策略路由：

| 对象 | 内容 |
| --- | --- |
| `HONK_PREROUTING` | 放行 honk 的精确旁路 mark 和已分类的直连 mark；对 LAN UDP/TCP 53 端口执行 TPROXY；放行本机、广播、组播和链路本地目的地址；其余 TCP 与 UDP 以 `tproxy_mark` TPROXY 到 `tproxy_port`。 |
| `HONK_OUTPUT` | 同样的放行，然后对 TCP 与 UDP 执行 `MARK --set-mark tproxy_mark/tproxy_mark`。 |
| `PREROUTING` 跳转 | 每个 `lan_interface` 一条；转发本机流量时另加一条匹配 `-i lo` 且带 `tproxy_mark` 的跳转。 |
| `OUTPUT` 跳转 | 未配置 `wan_interface` 时没有；每个具名网卡一条；`auto` 项覆盖所有网卡。 |
| 策略路由 | IPv4 及（主机有 IPv6 协议栈时）IPv6 各添加优先级 5000 的 `fwmark tproxy_mark/tproxy_mark lookup 0x686f`，以及表 `0x686f` 中的 `local default dev lo`。 |

本机发出的包在 OUTPUT 被重新打标，经策略路由折回 `lo`，再在 PREROUTING 被 TPROXY。内置链上的跳转以插入方式置于最前，先于其他工具的规则。

依赖：`mangle` 表，xtables 扩展 `TPROXY`、`MARK`、`mark` 与 `addrtype`，`IP_TRANSPARENT`，以及 1.6.2 及以上的 `iptables-restore`（`-w`）。Linux 4.19 与 Android GKI 内核均已具备。

## 用户态

控制面使用内存模型后端，其类型报告为 `tproxy`。不存在内核路由交接，因此所有 TCP 连接与 UDP 流都走 `ControlPlaneRouting` 交接已在使用的用户态路由路径：嗅探、`Router::route_full`、模式覆盖与常规拨号。直连流量在用户态中继；没有内核 offload、NFQUEUE 暂存、内核 `must` 终态或 conn-state token。

透明监听器与 UDP 回复套接字以 `IP_TRANSPARENT` 绑定在主机 netns，并保留配置的旁路 mark，因此 honk 自身的回复与拨号总会从两条链放行。UDP 监听器不设置 `SO_RCVMARK`（Linux 5.19），携带路由的 mark 只有 eBPF 数据路径会产生。

路由输入：仅当有规则使用 `process_name` 时，才对本机发起的流量通过 `/proc/net/{tcp,udp}{,6}` 与属主 uid 的 `/proc/<pid>/fd` 解析，结果为进程 `comm`。LAN 客户端、`mac` 与 `dscp` 没有来源，这些条件不会匹配。

## 生命周期

规则在控制面构建完成、即将运行时安装，并替换崩溃实例遗留的链与规则；控制面停止后移除。监听器关闭到规则移除之间，被转发的包找不到套接字而被丢弃：数据路径失败即关闭，不会让流量泄漏为直连。进程崩溃时规则保留，效果相同，直到下次启动。此模式同样持有单实例锁。

## Android

Android 构建（`just build-android`）始终把 `auto` 解析为 TPROXY，并拒绝 `datapath: ebpf`：以单程序模式挂载根 cgroup 程序会替换 netd 的程序。默认旁路 mark 为 `0x400000`（[套接字 mark](../reference/global.md#套接字-mark)）；规则优先级 5000 先于 netd 的规则。Android 没有 `/etc/resolv.conf`，节点主机名需设置 `global.bootstrap_resolver`。默认数据目录为 `/data/adb/honk`，实例锁为 `/dev/honk-core.lock`。
