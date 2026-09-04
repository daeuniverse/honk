# 路由引擎

本文说明内核与用户态如何为每条流选择出站；路由语法与字段见[路由参考](../reference/routing.md)。

## 决策路径

新流首先由 eBPF 路由引擎分类。安全直连卸载得到完整内核决策后可留在原生路径；其他决策会产生到控制平面的交接。用户态接收原始目的地址，按需获知域名，在必要时重新运行 `Router`，应用 Clash 模式，并把得到的组解析为叶子出站。

因此，路由结果是流的属性，而不是每个数据包的属性。已建立流的数据包使用 conntrack 状态中保存的决策，不会重复执行规则求值，也不会读取当前 Clash 模式标志。

## 内核路由

### `MatchSet` 求值

`RoutingMatcherBuilder` 按优先级升序排列已编译路由，并把每条规则降低为 `honk-core` 与 `honk-ebpf` 共享的 dae `match_set` ABI。每个按类型拆分的 `MatchSet` 都携带 matcher 值、取反位、中间或最终出站、`must` 位与 mark。

同一条件内的多个值形成 OR 链，不同条件形成 AND 链。中间结果 `LogicalOr` 与 `LogicalAnd` 保留这一结构，内核中无需分配规则对象。最后的 fallback 条目为未匹配流提供真实出站。

进入路由时，`route()` 准备全前缀的源、目的与 MAC key，并对选中的 bank 调用 `bpf_loop`。`RouteCtx` 在循环迭代之间维护 `GoodSubrule`、`BadRule`、`Must`、DNS 查询和域名已知状态。最终结果以 0–7 位编码出站、8–39 位编码 mark、40 位编码 `must`。

| 索引 | 在路由状态机中的含义 |
| --- | --- |
| `0` | `Direct` |
| `1` | `Block` |
| `2+` | 用户组，顺序与配置一致 |
| `0xFC` | `MustRules`：记录 `Must` 并继续求值 |
| `0xFD` | `ControlPlaneRouting`：把决策推迟到用户态 |
| `0xFE` | `LogicalOr`：继续当前 OR 子规则 |
| `0xFF` | `LogicalAnd`：结束一个条件并继续当前规则 |

`ControlPlaneRouting` 是中间交接结果，不是有效 fallback。fallback 必须解析为 `direct`、`block` 或用户组。

### 流分组预过滤

每个物理规则 bank 有四个组：TCP/IPv4、TCP/IPv6、UDP/IPv4 与 UDP/IPv6。编译器为同一规则链内的每个 `MatchSet` 分配相同组成员关系。`ROUTING_GROUP_META_MAP` 为每个组和 generation 保存一个打包的 `RoutingGroupMeta { rule_count, bitmap }`。

数据平面只读取一次 generation 选择器，选择流分组，并只加载一次该打包条目。bitmap 位为零时跳过相应的 `ROUTING_MAP` 查找与状态机步骤。规则链不会跨组拆分，因此跳过操作不会遗留 `LogicalOr` 或 `LogicalAnd` 状态。取反的协议或 IP 版本条件保留在所有组中，因为其补集可能匹配任何原本会被跳过的组。

### LPM 与已学习域名 map

目的 CIDR、源 CIDR 与 MAC 前缀位于各自的 LPM trie。每个 LPM value 都是物理 `MatchSet` slot 的 bitmap，因此多条规则共享的前缀会合并各自 bit，而不会互相覆盖。仅当当前 slot 的 bit 已设置时，LPM 查找才算匹配。

TCP SYN 时内核看不到主机名。域名与 geosite 条件编译为 `DomainSet` 占位符。`DOMAIN_ROUTING_MAP` 把 DNS 学习到的目的 IP 映射到对应的、按 generation 划分的规则 bitmap；条目存在时还会设置 `DomainKnown`，证明本轮所有 domain-set 检查均使用了完整的已学习 bitmap。

在 `domain++` 模式中，如果通用代理规则带有目的端口条件，但没有 domain/geosite、进程、MAC 或 DSCP 限制，且出站不是 `direct` 或 `block`，编译器会把它改为 `ControlPlaneRouting`。`domain` 与 `domain+` 在内核中保留初始端口/IP 决策。`DOMAIN_ROUTING_MAP` 学到条目后，后续流仍可由内核完成决策。

## 原子路由发布

路由推送是选择器最后写入的双阶段提交。它绝不调用 `clear_routes`；清空活动 map 会在重载发布期间暴露空 generation 并丢弃新流量。

1. 编译不可变的 `RoutingPushPlan`——`MatchSet`、LPM bitmap、流分组 bitmap 与域名投影元数据——且不写任何 BPF map。
2. 读取活动 generation，并填充另一个 `ROUTING_MAP` bank。
3. 暂存同时包含活动 generation 与 replacement generation 的目的、源及 MAC LPM value。只删除两个 plan 均不使用的 key。
4. 写入 replacement generation 的展开自省元数据与全部四个打包 `RoutingGroupMeta` 条目。
5. 最后翻转 `ROUTING_META_ACTIVE_GENERATION_SLOT`。

一次路由求值只读取一次选择器，因此只能看到完整的旧 bank 或完整的 replacement bank。旧的物理尾部 slot 不会造成影响，因为 `rule_count` 限制了 `bpf_loop`。replacement 淘汰的 LPM key 会在旧 bank 仍可能被观察时保留，并在下一次转换中消失。

DNS 学习到的域名 bitmap 使用同一 generation 边界。重载会在切换规则 bank 前暂存其 inactive generation 一半。

### 重载期间的组序号与健康状态

配置顺序同时定义路由出站序号与 connectivity slot：组 `i` 使用 `2 + i`。该组所有叶子成员共享此 slot。对于 TCP、DNS-UDP 或数据 UDP 的每种网络以及每个 IP 地址族，用户态发布的是成员健康状态的 OR，而非某个节点的状态。

重载可能重新排列组，从而改变序号含义。切换路由 generation 前，用户态先把所有旧组或新组涉及的转换 slot 标记为存活。这份临时 fail-open 健康快照可防止旧健康 bit 杀死新分配的组。随后，用户态暂存已学习域名、切换路由 generation，再发布准确的新每组、每网络、每地址族存活快照。发布出错后尚未覆盖的 slot 保持 fail-open，不会继承陈旧失败状态。

## 用户态 `Router`

`Router::new` 一次性编译全部规则，并按优先级升序排列。正向 matcher 组之间为 AND，组内备选项为 OR；任一取反条件命中都会否决该规则。`route_full` 按优先级扫描并返回第一条匹配，`route_with_must` 返回该出站及其 `must` 标志；若无规则匹配，则返回默认出站与 `must = false`。

内核保留结果 `MustRules` 具备 Go dae 的非终结行为：它记录 `Must` 后继续扫描。当前用户态实现并未复现该行为：携带 `must` 的规则仍是 `route_full` 的第一匹配终结结果。因此，完全回退到用户态 `Router` 的流不会在匹配 `must` 规则后继续；返回的标志只阻止后续嗅探与 Clash override。这是当前实现限制。

IP 与源 IP 条件使用 `BinaryLpmTrie`：IPv4 有 32 层，IPv6 有 128 层的紧凑二叉 trie。查找遇到已匹配前缀或缺失子节点后立即停止。

`GeoAssets` 在每次构建 `Router` 时至多解析一次 `geoip.dat` 与 `geosite.dat`，且只解码配置引用的类别。`category@attr` 在第一个 `@` 处分割，索引基础类别，并保留携带该属性 key 的条目；key 是否存在的判断不区分大小写。`GeositeMatcher` 对精确名称和点边界后缀使用 hash set，对关键词使用一个 Aho-Corasick 自动机，对 regex 条目使用已编译正则表达式。

## 域名路由与嗅探

域名路由有两个视图：

- DNS 应答把域名规则 bitmap 投影到 `DOMAIN_ROUTING_MAP`，后续连接到返回 IP 时可使用内核视图。
- 没有已学习 IP 映射的连接进入用户态；嗅探到的名称加入 `ConnectionInfo` 后，完整 `Router` 可求值域名视图。

DNS 投影拥有固定到 generation 的 `Router` 与 bitmap 快照。worker 先取得 backend，再取得发布 fence，并重新检查 generation；若 batch 已过期，则在写入前跳过。因此，发布 replacement 快照后，旧 DNS batch 无法再修改 map。reconcile 期间 generation 发生变化时，会按当前快照重建 desired state。

TCP 嗅探提取 TLS SNI 或 HTTP `Host`，并返回缓冲的前缀供转发。读取上限为 4096 字节。negative cache 会为反复得不到可用域名的目的地址抑制重复工作。

UDP 嗅探处理 QUIC v1 与 v2 Initial 包。它派生 Initial key、移除 header protection、解密 payload、收集 CRYPTO frame、跨 fragment 或 packet 重组，再运行共享的 TLS ClientHello parser。每流 session 与 negative cache 限制重复尝试。ClientHello 未完成时不会把结果视为最终无域名，因为后续 Initial fragment 仍可能改变路由。

初始的 IP 路由决策与可选的域名拨号目标彼此独立。只有 `domain` 的 reality check 通过，或处于 `domain++` 时，嗅探名称才会影响路由；`domain+` 不会改变路由。`must`、`block` 与保留的直连决策保持最终状态。negative-cache 命中会跳过名称提取并保留现有路径。

### 拨号模式

| 模式 | 嗅探 | 对目的 IP 校验名称 | 重新执行路由 | 拨号行为 |
| --- | --- | --- | --- | --- |
| `ip` | 否 | 不适用 | 否 | 使用原始目的 IP。 |
| `domain` | 是，除非最终决策或 negative cache 跳过 | 是；不匹配则丢弃名称 | 仅校验通过后 | 代理按已校验名称拨号；域名规则未命中时继续匹配后续 IP/端口规则。 |
| `domain+` | 是，跳过条件相同 | 否 | 否 | 代理使用嗅探名称拨号，同时保留初始路由。 |
| `domain++` | 是，跳过条件相同 | 否 | 是，仅针对非保留决策 | 根据 SNI/HTTP Host 重新路由，再使用所得代理目标。 |

## Clash 模式与直连卸载

`ModeState` 只在得到路由结果后应用 Clash 模式。它绝不覆盖 `block` 或携带 `must` 的结果。

| 模式 | 用户态 override | 路由时内核策略 |
| --- | --- | --- |
| `Rule` | 保留路由得到的出站 | 仅当 SNI 无法改变结果时卸载普通 `direct`：`dial_mode: ip` 或 `domain+`、不存在 domain-class 规则，或该流通过 `DOMAIN_ROUTING_MAP` 设置了 `DomainKnown`；否则交给用户态 |
| `Global` | 当前 GLOBAL 选择可解析时使用该选择 | 通常交给用户态。GLOBAL 选择恰好是小写 `direct` 时例外：此时发布 `OFFLOAD_ALL`，因为每个非最终结果都会收敛到直连 |
| `Direct` | 强制 `direct` | 卸载每个非 `must`、非 `block` 结果，并把缓存出站规范化为 `Direct` |

`lan_ingress` 对每条新流只读取一次 `DATAPATH_FLAGS_MAP`。模式策略卸载非 `must` 流时，会把决策记录到 `RoutingMeta` 第 57 位；已建立流的数据包随后只检查缓存的 `outbound == Direct && (must || offload)`。`direct(must)` 流使用 `must` 位，不需要第 57 位。

卸载流不会创建用户态中继或 `/connections` 条目，也无法再由后续 SNI 重路由。其发送包数与字节数仍在 `lan_ingress` 计数。

## 与健康状态的交互

重定向或原生转发前，数据平面检查 `OUTBOUND_CONNECTIVITY_MAP`。选中出站已死时返回 `TC_ACT_SHOT`：honk 以 fail-closed 方式处理，而不会把流量泄漏到 `direct`。TCP 与 UDP 的目的端口 53 都免除此检查，以便 DNS 到达控制平面并应用自己的 fallback 策略。

组共享槽通常保存全部叶节点健康状态的 OR。未配置 `final` 且只有一个唯一叶节点的 TCP 组会保持该槽开放，作为用户态最后尝试；控制面仍拨同一个代理，成功的真实流量可以将其复活。UDP 和全部叶节点失活的多叶节点组仍保持 fail-closed；但含有 `direct`/`block` 内建成员的组永不失活：内建节点永远不会被判定死亡，因此 group-OR 槽保持开放。Clash `Global` 与 `Direct` override 仍无法绕过 `must` 或 `block` 结果。精确重定向与丢弃路径见[数据平面设计](./datapath.md)。

## 相关文档

- [数据平面设计](./datapath.md)
- [控制平面设计](./control-plane.md)
- [路由配置参考](../reference/routing.md)
