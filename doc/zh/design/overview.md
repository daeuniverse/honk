# 架构概览

`honk` 是面向网关与本机流量的 Linux eBPF 透明代理引擎；本页概述其架构及承载运行时的关键规则。项目当前为实验性 alpha `v0.0.1-alpha`，采用 `GPL-3.0-only` 许可证，仓库为 `Glassyiris/honk`。

其配置语法和 TC 数据路径源自 dae 技术脉络，并在文档声明的范围内保持 dae 兼容；出站 Handler、组与 Clash API 则采用 sing-box 风格的设计。`honk` 是独立实现，现已与两者显著分化。

## 目标与非目标

### 目标

- 通过 eBPF 透明代理数据路径拦截 Linux 上的 LAN 转发流量和本机发起流量。
- 将原生 `.dae` 配置语法保持为首要且唯一有文档说明的配置格式。
- 提供多协议出站、Selector/URLTest/LoadBalance/Fallback/Score 组、健康检查和 Clash 兼容控制 API。
- 只交付引擎 `honk-core`，不另设 GraphQL 服务或内置 dashboard 应用。

### 非目标

- 完整对齐 Clash Meta/mihomo；honk 尤其不提供 FakeIP 引擎，也不追求远程 rule provider/rule-set 对齐。
- 在 Windows 或 macOS 上进行透明代理；数据路径仅支持 Linux。

## Crate 分工

根 workspace 包含六个 crate。`honk-ebpf` 因面向 `bpfel-unknown-none` 而作为独立 Cargo 项目：它被排除在 workspace 外，并维护自己的 `Cargo.lock`。

| Crate | Workspace | 职责 |
| --- | --- | --- |
| `honk-config` | 成员 | 共享配置模型、dae 语法解析器、include 处理、分享链接解析和订阅解码。 |
| `honk-ebpf-common` | 成员 | 内核程序与用户态 map 写入端共享的 `no_std`、`#[repr(C)]` 常量和 ABI 类型。 |
| `honk-nfqueue` | 成员 | raw `NETLINK_NETFILTER` 队列 `320`、verdict 所有权和自有 nftables 事务。 |
| `honk-outbound` | 成员 | 协议 Handler、逐节点 runtime、出站组、健康状态、URLTest 探测和始终编译的 Score 评分器。 |
| `honk-core` | 成员 | 引擎库与二进制：eBPF/NFQUEUE runtime、控制面、DNS、路由、中继和 Clash API。 |
| `honk-tool` | 成员 | 用于订阅/节点探测、数据路径诊断、固定 map 检查和 geo 资源查询的 CLI 工具箱。 |
| `honk-ebpf` | 排除 | TC、`sk_lookup` 和 cgroup eBPF 程序；单独构建，并在启用真实 eBPF 时嵌入 `honk-core`。 |

```mermaid
flowchart LR
  CFG[honk-config] --> CORE[honk-core]
  CFG --> OUT[honk-outbound]
  COMMON[honk-ebpf-common] --> CORE
  COMMON --> OUT
  COMMON --> EBPF[honk-ebpf]
  CORE --> OUT
  CORE -->|可选 ebpf feature| NFQ[honk-nfqueue]
  CORE -->|build.rs 嵌入目标文件| EBPF
  TOOL[honk-tool] --> CFG
  TOOL --> COMMON
  TOOL --> OUT
  TOOL -->|core 库| CORE
```

共享 map 键、值、常量或布局的修改必须同步落到 `honk-ebpf-common`、`honk-ebpf` 和 `honk-core` 的 map 写入逻辑。

独立 Node 反序列化会报告忽略的协议不兼容字段；后续转换失败也不会丢失这些警告，每条只记录一次。诊断只包含配置字段名，不包含节点名称或字段值。`node::NodeSeed` 将警告写入调用方提供的列表，不自行记录日志；`FlatNode` 仍是唯一的扁平格式适配器。

`ConfigSeed` 对节点数组中的每个原始条目使用 Node 适配器。结构化输入失败时，诊断保留节点、组和订阅的原始序号、安全的配置字段路径及解码器提供的行列号，不保留解码器的原始错误文本；映射和按字段声明顺序排列的序列均保留序号。详细文件和 JSON 加载接口在失败时保留调用方已有的诊断；格式回退成功时，只移除已放弃尝试的诊断。所有格式均失败时，按尝试顺序保留诊断，并附上一个终止错误。dae 语义错误会终止加载，除非完整文档能按 YAML、TOML 或 JSON 解码为至少含一个已知 Config 顶层键的映射；此时交由结构化格式加载器处理并报告结果。包含文件错误和不受支持的策略错误仍会终止加载。

解析器和分享链接的数据接口保留安全诊断，不自行记录日志。标量值、名称、链接和原始错误内容不对外输出，但保留固定错误原因和 `dns.hosts_file` → `dns.use_host` 等迁移说明。组、过滤器、订阅和条目使用原始序号定位；只有最外层加载尝试追加终止错误。

`src/node/validation.rs` 负责集合准入与共享检查；`src/node/vless.rs` 独占规范 `VlessConfig` 的 normalization、path selection 与组合校验；`src/node/protocol.rs` 持有其他协议配置及共享 TLS/stream/QUIC options。详细 loader 保留类型化 cause 与原始 one-based 节点坐标。

`src/parser/mod.rs` 负责文件级 `include` 和有序顶层分派。`lexer.rs` 与 `cursor.rs` 保留引用源文本的词法单元、注释范围及有界片段，`read.rs` 提供共享的标量与表达式读取接口；各节由 `scalars.rs`、`entries.rs`、`groups.rs`、`dns.rs` 和 `routing.rs` 读取。包含文件的 glob 模式以入口文件所在目录为基准解析；匹配文件的规范化路径不得超出入口目录。重复包含和循环包含均被拒绝。允许忽略未知内容的读取器整块跳过未知嵌套块，不应用其子项；节点和订阅的兼容包装块仍会遍历，`experimental` 外层和 NFQUEUE 错误仍会终止解析。

各读取器直接返回类型化错误；只有最外层尝试发布终止诊断。诊断提示在尝试结束时借助按来源区分的前缀最大值索引统一排序，保留原有追加顺序和调用方已有诊断，避免反复插入向量。

片段明确区分已接纳或已忽略的语句、紧凑块和普通花括号块，读取器不再根据末尾词法单元猜测结构。语句准入先于紧凑块切分和续接状态更新；组的动态块头与条目值分开处理，条目值开始后不再提前切分声明。结构注释花括号诊断使用游标当前作用域判定，在 EOF 检查前统一发出。过滤器诊断保留原始词法单元的错误来源；遍历节点、订阅和组的同级声明时重置语义诊断归属。

遍历语法区分单行条目和多行表达式；括号保护状态仅随实际返回的表达式语句跨越同源分段，在来源边界重置。已建立索引的起始花括号保留其块头和子树归属。订阅原始字段独立于结构块头视图保留完整起始词法单元的字节。

`src/share_link.rs` 是唯一 `Node::from_share_link` parser；`src/share_link/options.rs` 把 URI packet encoding 与独立 mux controls 归入规范协议模型，再进行 normalization、validation 与 identity derivation。`src/node/wire.rs` 是唯一 flat serde adapter；VLESS 输入即使以 `null` 出现已移除的旧字段也会拒绝，而同一字段在非 VLESS 输入上仅为兼容 artifact。`VlessConfig.network`、`udp_encoding` 与 `multiplex` 参与 identity，因此规范 cutover 可以改变 VLESS `Node.id`，但不改变 VMess 行为或 identity。行为概要见[出站设计](./outbound.md#vless-wire-契约)，字段语法见[节点参考](../reference/nodes.md)。

## 高层数据路径

```mermaid
flowchart TB
  PACKET[LAN 转发或本机发起的 TCP/UDP] --> TC[入口排除、本地监听优先、有序策略]
  TC -->|本地 socket 优先接收| LOCAL[本地服务]
  TC -->|direct must 或非 DNS 安全 direct| NATIVE[Linux 原生路径]
  TC -->|block must、非 DNS block 或失活丢包| DROP[丢弃]
  TC -->|非 must DNS :53| DAE0[dae0]
  TC -->|proxy 或用户态决策| DAE0
  TC -->|有歧义的 LAN UDP，可选| NFQ[NFQUEUE 320]
  DAE0 --> SK[daens sk_lookup]
  SK --> LISTEN[透明 TCP/UDP 监听器]
  LISTEN --> CP[原始目的地址、handoff 或逐报文 mark]
  NFQ --> CP
  CP -->|非 must DNS| DNS[DnsController]
  CP -->|其余流量，must 跳过嗅探| DECIDE[嗅探、路由回退、Clash 模式、组叶子]
  DECIDE --> DIAL[出站拨号与中继]
  DIAL -->|DAE_BYPASS_MARK 0x100| WAN[WAN 出口]
  DIAL -->|anyfrom| REPLY[以原始目的地址发出 UDP 回包]
```

### 报文路径

1. [数据路径](./datapath.md)在 LAN TC 分类 LAN 转发流量，并在 WAN TC 分类本机发起的 TCP/UDP。现有入口排除和实际本地 socket 所有权先于有序流量策略；`direct(must)` 与非 DNS 路由时已安全的 direct 决策留在 Linux 原生路径。
2. [流量规则所有权](../reference/routing.md#出站目标与-must)决定哪些端口 53 查询进入[DNS 管线](./dns.md)。已准入的透明查询、可选 host-netns `dns.bind` 与流关联 reality/目标查询共用按代固定的 DNS 策略、缓存/singleflight、上游池和路由投影。
3. [数据路径](./datapath.md)将普通 proxy 和用户态决策经 `dae0` 重定向；在 `daens` 内，`sk_lookup` 将其指派给[控制面](./control-plane.md)的透明 TCP 或 UDP 监听器。
4. [NFQUEUE 暂存](./nfqueue.md)默认由 `global.nfqueue_enable` 开启，但只有启动前置条件通过时才激活；它仅在 LAN TC 之后、conntrack/NAT 之前保留仍有歧义的 LAN 转发 UDP。每个暂存流在固定队列 `320` 中携带唯一决策 token；本机发起的 WAN 流量继续走普通透明路径。
5. [控制面](./control-plane.md)恢复原始目的地址；普通流消费 eBPF 路由 handoff，缺失或结果为 `ControlPlaneRouting` 时进入用户态路由。端口 53 流量遵循不同的[TCP handoff 与 UDP 逐报文准入规则](./control-plane.md#透明代理入口)。
6. [路由路径](./routing.md)可嗅探 TLS SNI、HTTP Host 或 QUIC Initial SNI，并在内核结果尚未终结时运行用户态 `Router`。
7. [组层](./groups.md)应用 Clash 模式覆盖但不改写最终 `must`/`block` 结果，再将权威策略选择解析为叶节点。Score 只用逐目标 TCP/UDP 证据在健康合格成员中排名。TCP/UDP 通常只采用一个权威叶节点；只有冷启动顶层 URLTest 会先 stagger 候选，且只有 winner 提交 endpoint 或 source transport。
8. [出站层](./outbound.md)通过 `TcpOutbound` 或 fallible prepared UDP commit 拨号该叶节点。普通 packet path 为 endpoint 绑定一条 `PacketTransport`；XUDP/Mux.Cool 可以改为提交由 core 所有、供多个规范五元组 endpoint view 共用的 source session。嗅探得到的 TCP 字节先于后续流量转发。
9. 控制面出口携带 `DAE_BYPASS_MARK`（`0x100`），避免再次被 WAN TC 拦截。代理 UDP 与透明 53 端口回包使用绑定原始目的地址的 [anyfrom 套接字](./control-plane.md)，使[返回数据路径](./datapath.md)保持源地址。

## 运行时不变量

- **旁路标记纪律：** 拨号、探测、DNS 上游、QUIC endpoint 和透明监听器携带 `DAE_BYPASS_MARK`（`0x100`）或使用 loopback。接受后的 TCP 套接字会清除监听器标记；普通 host-netns `dns.bind` 入口套接字则有意保持无标记。
- **Anyfrom UDP 回包：** 代理 UDP 与透明 53 端口 DNS 回包使用在 `daens` 中创建、并绑定到流量原始目的地址的透明套接字。直接从 TPROXY 监听器回包会暴露 `dae0` 源地址，并在返回路径失败。
- **DNS 来源边界：** 透明入口与 `dns.bind` adapter 从 socket peer 得到逻辑客户端来源；流关联查询使用已准入流的来源。缓存仅在路由确定所选、与来源无关的 scope 后复用，而每个 policy generation 的域名谓词投影仍为全局且不区分来源。
- **VLESS source 边界：** 共享 XUDP/Mux.Cool 按 reused runtime、规范化 client、UDP path 与 actual-peer/original-destination reply projection 复用。完整五元组 endpoint map 仍持有 route、token/generation 与逐 flow Score；source session 持有唯一 receiver 与 transport health。
- **网络命名空间纪律：** 进程常驻 host netns。它只通过有作用域且完全同步的 `with_daens_netns` 调用进入 `daens`；`setns` 跨度内不得出现 `.await`，恢复原命名空间失败时进程必须中止。
- **数据路径准入：** `DATAPATH_STATE_MAP[0]` 在全部监听 FD 已发布且全部接收循环已运行前保持关闭，并在拆除监听器前关闭。gate 关闭期间，TC 原样放行流量。
- **NFQUEUE 就绪与所有权：** 启用但尚未 ready 时，只丢弃需要暂存的新流。honk 独占队列 `320` 和 nftables `inet honk_nfqueue` / `udp_decision`；ready 变更必须经过 fence，生命周期歧义为致命错误，同一 netns 的防火墙管理器不得修改这些对象。
- **Token 校验终态：** 暂存 UDP token 必须在 skb mark、内核状态、handoff、redirect track、用户态 verdict 状态、lease/endpoint 和后端转换间一致。Direct 遵循 Arm → 全部带标记 verdict → Activate；proxy 在唯一的规范拨号/发送路径之前发布最终状态。
- **`must`/`block` 终结性：** Clash 模式覆盖永远不会替换 `block` 结果或 dae `(must)` 结果。
- **失活出站 fail-closed：** `lan_ingress` 丢弃路由到失活出站的新流。未配置 `final` 且只有一个唯一叶节点的 TCP 组会让同一代理继续作为用户态最后尝试；UDP 和全部叶节点失活的多叶节点组仍保持 fail-closed；但含有 `direct`/`block` 内建成员的组永不失活：内建节点永远不会被判定死亡，因此 group-OR 槽保持开放。TCP 与 UDP 端口 `53` 豁免该健康检查丢包，但仍遵循用户的终局 `must` 结果。
- **显式本地路由：** 网关管理访问由用户[显式配置](../reference/routing.md#显式本地路由)，不依赖自动生成的接口规则或隐藏白名单；接口观察仍用于拓扑/ECS/健康，非 DNS TCP 纯 SYN 的现有本地探测跳过策略不变。
- **组 OR 连通性：** 一个组的 eBPF alive slot 是全部叶子成员状态的 OR，并包含上述单叶 TCP 最后尝试例外。多叶节点组中的单个成员失活不得使整个组 fail-closed。
- **Score 隔离与原因：** Score 用业务目标地址族评分，用代理服务器地址族过滤健康状态；其权威单叶选择不能让死亡成员重新入选。周期探索按 `(group, TCP/UDP, 目标 IP 地址族或 none)` 分域，并选择 Beta 可靠性上置信界最高的非当前成员；连败将叶节点按指数退避移出探索（5 分钟起翻倍、上限 6 小时，独立于证据衰减），成功恢复探索资格但连败只逐级递减；连败只由真实流量驱动（探测结果中立）；连续三次新鲜失败还会让叶节点在存在更健康候选时退出可靠性带；组内相对延迟/吞吐只微调可靠性接近区间，现任余量随有效完成证据增长。全局、地址族与精确目标的新鲜失败 envelope 取最大值而非相加。每次已授权的多候选 Apply 按优先级只记录一个最终原因：`coldExplore`、`periodicExplore`、`incumbentHeld`、`freshFailureBypass`、`reliabilityWinner`，然后是 `performanceWinner`；`deadFiltered` 计数唯一死亡叶节点，`switchFlap` 计数同一目标作用域内八次选择切回前一已提交胜者，`failStreakExcluded` 累计被新鲜失败门排除的候选数，`exploreBackedOff` 累计处于探索退避的候选数。精确目标键与聚合先验只存在于两个各 4,096 项的进程内 LRU，通过共享状态跨成功 reload 保留，进程重启即清空，且不会进入日志或持久化。经鉴权的 `/stats.score` 只导出组名和这些聚合 TCP/UDP 计数，绝不导出 cell、节点、目标、cadence 或 authority；`/stats.score.cache` 另导出每个证据 LRU 的 cell 数与累计淘汰数；既有 `/proxies`、`/stats.outbounds` 与 `/connections` 元数据契约保持不变。
- **Score 反馈覆盖：** 评分器始终编译，但仅在计划经过 Score 组时按需创建 `ScoreReporter` 和评分 cell；非 Score 路径不创建它们。实际 attempt 会报告 setup、首响应、双向字节和一个紧凑终态，包括透明 TCP/UDP、受支持的 DNS transport、健康与 delay 探测、preconnect/session/UDP 预热，以及直连或经代理的 UI 下载；没有业务目标的任务只更新聚合 setup 证据。
- **内部与特殊流量：** honk 的内部链路地址范围 `169.254.0.0/16` 和 `fd00:686f:6e6b::/64` 永不代理。L2 广播/组播、IPv4 广播/组播/未指定目的地址以及 IPv6 组播会在路由或 conntrack 前直通。

## 构建 feature 与 mock 模式

`honk-core` 默认启用 `clash-api`、`mimalloc` 和 `rprx`；真实 eBPF 需显式启用。

| Feature | 默认 | 作用 |
| --- | --- | --- |
| `ebpf` | 否 | 引入 `aya`、`aya-obj`、`aya-log` 和可选 `honk-nfqueue`；`build.rs` 嵌入静态 `honk-ebpf` 对象，用户态在运行时编译 policy extension。运行时要求 Linux kernel 6.12+。 |
| `clash-api` | 是 | 引入可选 `axum` 与 `tower-http`，提供 Clash 兼容 REST/WebSocket 服务。 |
| `mimalloc` | 是 | 引入 `mimalloc` 与 `libmimalloc-sys`，并将 mimalloc 安装为 `honk-core` 二进制的 allocator。在 Linux 上，程序会在启动 Tokio 前为当前进程禁用透明大页。 |
| `rprx` | 是 | 启用 `honk-outbound/rprx`，注册 VLESS 与 VMess Handler，包括受支持的 VLESS Encryption 和 `xtls-rprx-vision` 路径。 |

`mock-ebpf` 不是 Cargo feature。不带 `ebpf` 的构建使用 `MockEbpfBackend`，`--mock-ebpf` 则显式选择无特权开发路径。若请求 `global.nfqueue_enable = true`，启动会记录 warning，仅在本进程关闭 NFQUEUE 暂存，配置文件保持不变。

## 作者与分工说明

- eBPF 数据路径——`honk-ebpf`、`honk-ebpf-common` 以及 `honk-core` 中的挂载/map 路径——是项目维护者主要投入人工设计、实现 review 与验证的部分。
- 其余多数用户态子系统——配置解析器、出站 Handler、组与健康检查、用户态 DNS、Clash API 及大量控制面粘合代码——主要由 AI 辅助编写。维护者做了部分代码 review，并非逐行负责。

## 相关文档

- [配置指南](../configuration.md)
- [数据路径设计](./datapath.md)
- [Global 配置参考](../reference/global.md)
