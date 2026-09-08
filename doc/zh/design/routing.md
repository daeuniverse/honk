# 编译化路由决策面

## 范围

路由只有一个手写语义模型，执行方式可以不同：用户态 `Router` 解释规范化的
policy IR，受限编译器把同一 IR 降低为原生 eBPF 比较代码。内核不再解释另一套
`MatchSet` 程序。真实后端的内核基线为 Linux 7.2。

静态 TC 程序继续负责报文解析、特殊/本地/DNS 排除、conntrack、mode 与健康检查、
NFQUEUE 所有权、重定向和回包统计。生成函数只负责
`RoutingInput -> RoutingDecision`。不会因为采用编译策略而把所有首包送到用户态；
native-direct 与已有流缓存路径保持原生执行。

## 规则语义

规范化 IR 保存有序 RuleId、展示信息、条件与 outbound/mark/must 动作。priority
数值越小越先匹配，同优先级保持声明顺序。条件之间 AND，同一条件的候选值 OR，
否定只作用一次且覆盖整个条件。fallback 是独立的终结动作。空展开不能被丢弃：
正向空集合为 false，负向空集合为 true，不能因 geo 资源没有匹配项而放宽复合规则。

切换保留当前用户态匹配合同：

- 普通 domain pattern/suffix/keyword 是同一条件内的 OR；与 geosite 字段同时存在
  时，geosite 仍是独立条件。suffix、regex、keyword、大小写和 geosite 属性行为不变。
- 目的/源 IP 保留 IPv4/IPv6 身份，覆盖 `/0`、裸主机地址及重叠前缀。
- 端口区间包含两端；TCP/UDP 和 IPv4/IPv6 mask 可以同时包含两种值。
- pname 保留配置端 15 字节规范化及子串匹配语义。内核进程字节按照 handoff 相同的
  lossy UTF-8 与 trim 规则转换，热路径不分配堆内存。
- 缺失 pname/MAC/DSCP 不是普通零值。缺失 domain 不满足正向条件，也不会触发负向
  条件的 veto。
- 配置 `(must)` 是终结结果，不是历史内部 `MustRules` opcode。Clash mode 不能
  覆盖 must 或 block。

旧 lowering 丢弃 full/regex、把协议 OR 降成 TCP、截断规则链、DNS 只投影首条整规则、
重叠 LPM 丢失祖先位图，都不是要保留的兼容行为。共享 IR 和独立 golden 案例需要
阻止这些错误，不能把旧缺陷编码进新后端。

## 唯一 policy 与域名事实

`CompiledRoute` 保存元数据和 `CompiledCondition` 列表，不再平行维护正负 matcher
字段。每个条件包含一个 `CompiledPredicate` 和否定标志。域名条件引用 policy 内
不可变的已编译 matcher registry。规则名只用于展示，不能当作 bitmap 身份；相同
域名谓词可以在同一 policy 内共享 PredicateId。

用户态 reference 与内核编译器消费这一表示。DNS 和 sniffing 产生的是**全部域名
谓词**的真值位，而不是用伪造五元组选择一条完整 traffic rule。用于否定规则的谓词
同样投影其正向真值，not 由 evaluator 应用。一个已知域名即使没有匹配任何谓词，也
产生存在的零 bitmap；该 IP 的最后一个有效 owner 消失时才删除条目。

DNS 关联仍按 IP、与源客户端无关，并延续多个有效 owner 的 OR 聚合。这不证明共享
IP 上每条连接的精确 SNI。dial-mode reality check 与允许的 sniff 重路由仍由用户态
负责；迁移不采用“所有 unknown 都 punt”，也不暗改四种 dial mode。

## 生成函数 ABI

固定布局放在 `honk-ebpf-common`，字段仅使用固定宽度整数。Rust enum 布局、引用、
String 和 allocator 对象都不跨边界。

`RoutingInput` 包含网络序源/目的地址、规范化的 16 字节 MAC key、规范化进程字节及
长度、主机序端口、协议/family mask、DSCP 和 provenance/presence 信息。
`RoutingDecision` 包含 outbound、mark、must、domain-finality 与 RuleId；独立的
标量返回码区分成功结果与 evaluator 不可用/执行失败。

`domain_final` 表示在当前 dial mode 下，后续域名观察不能改变这一阶段的路由：
policy 没有域名谓词、禁用了域名重路由，或已经取得完整的 learned-domain bitmap。
它是 policy-generation 内的数据，不是另行发布、可能错代的全局路由 flag。

非 `must` 的 direct 结果若域名 finality 尚未确定，交接给用户态时必须编码为
`ControlPlaneRouting`；若仍写成最终 direct，TCP/UDP 初始化会跳过嗅探。
已知 direct、must、block 以及 mode 控制的 direct offload 保留终态语义。

只在路由 miss 时初始化输入，复用现有 per-CPU packet scratch，缓存包不清空它。
slot 的 volatile 访问防止 LLVM 删除输入或折叠输出；pname 规范化由独立验证、
有界的 global subprogram 完成，避免 Unicode 分支与 WAN parser 状态相乘。

静态 caller 把逻辑结果转换为原有 datapath action。`ControlPlaneRouting` 不是
`TC_ACT_*`。evaluator 出错时执行 caller 原有的 fail-closed 清理，包括尚未完成的
UDP Preparing claim，不能把故障伪装成用户态补判请求。

## 受限原生后端

后端发射有类型的 8 字节 BPF 指令、经检查的 label/fixup、常量比较、mask、map lookup
和终结结果写入。它不拥有 TLS/QUIC 解析、拨号、mode、健康检查或通用 VM。大的 IP、
MAC、domain 集合保留为索引，不展开成成千上万条立即数比较。

每一代拥有独立的目的 IPv4/IPv6、源 IPv4/IPv6 LPM maps、MAC 索引和 domain hash map。
IP 分 family，避免 IPv6 前缀误匹配 mapped IPv4。更具体的 LPM 条目继承所有匹配祖先
谓词的位，使最长前缀查找不破坏规则顺序。每一代使用完整 `DomainRouting` bitmap，
不再共享可能被新前缀提前遮挡的双 bank LPM value。

每个事实 LPM 保留 2,048,000 条容量且不预分配；学习到的 domain hash 保留 65,536 条。
前缀数量与谓词数量独立：一个 GeoIP 谓词可以包含数十万个前缀。emitter 在每次插入指令前
检查 1,000,000 条指令预算，耗尽时立即返回错误，不再继续展开指令或 fixup。

容量和 verifier 限制是明确错误，不能截断规则链或把缺失 outbound 默认为 direct。
生成源映射记录 RuleId 和规范化规则描述。raw loader 复用现有 syscall/BTF 基础，不
增加运行时 clang/LLVM 或另一个 ELF writer。函数原型必须真实；raw `func_info` 与
`line_info` 使用指令槽偏移，不能直接套用 ELF `.BTF.ext` 的字节偏移。

## 同步槽与原子发布

每个相关 TC 程序暴露两个真正保留的、非内联、BTF-global 函数：
`honk_route_slot0` 和 `honk_route_slot1`。未安装槽返回错误，不实现第二套 fallback
路由器。后端在放行前加载 LAN/WAN L2/L3 路由目标，包括将来可能动态附着的 variant。

`ROUTING_POLICY_ROOT` 是单项 map-in-map，指向不可变的
`RoutingPolicyDescriptor`。descriptor 标识 slot、policy generation、feature bits
及供诊断使用的 active domain-map ID。一次路由只取一个 descriptor，再同步调用一个
槽；缓存命中报文不新增这个 lookup。

发布与现有 reload、DNS publication fence 串行协调：

1. 编译、校验完整候选，保留 active policy。
2. 创建并填充本代事实 maps，包括 learned-domain 快照。
3. 用这些确切 map FD 和合法 BTF 加载生成扩展。
4. 给全部相关 TC target 的 inactive 槽完成 attach。
5. 最后只替换一个 generation root。
6. 成功更新返回后才允许退休旧 TC 槽和旧 maps；用户态 IR/reference lease 独立保有
   自己的生命周期。

Linux 7.2 在 map-in-map 更新成功返回前等待旧 non-sleepable BPF 调用完成。普通 root
store、固定延时或“有两个槽”不是等价 grace。不能依赖不支持的 freplace
`BPF_LINK_UPDATE`，也不 detach/attach 活跃槽。

后端发布操作在 root commit 前必须 all-or-nothing。map 构建、verifier、任一 inactive
attach 失败，都保留旧代码与旧事实。不能用关闭 datapath admission 来掩盖错误，因为
当前关闭状态会直接放行；也不能把全部流量 punt。规则派生 flags 与 domain writer
必须属于同一 policy generation。mode/NFQUEUE 协调和已有流仍由原 controller 管理。

稳定 policy pin 只保留 generation root。诊断工具通过 descriptor 查找 active domain
map，不能假设重 pin 一个同名 map 就能改变已加载程序持有的引用。

## 验证与验收

完整实现必须覆盖全部已有 matcher，并通过：

- 独立 golden：顺序、OR/AND/not、缺失事实、must/block/mark、IPv4/IPv6、前缀重叠、
  pname 规范化、domain 投影及容量失败。
- reference 与真实生成 BPF 的完整 decision 比较，不只比较 outbound 或生成结构；
  包含源元数据和 finality。
- 真实 TC/cgroup/netns：native direct、proxy、block、DNS、LAN/WAN、TCP/UDP 和缓存流；
  queue/token 路径保留真实 NFQUEUE 合同测试。
- staging/verification/attach 故障、连续换代、旧读者场景，证明不存在半发布且旧流
  所有权不变。
- 配对测量完整路由/流量成本、冷热事实、reload、JIT 大小和内存峰值。强化后的
  packed-data/AOT bounded-loop 是基线；端口微基准不代表整个引擎不退化。

此前 Linux 7.2.3 隔离原型只覆盖协议/端口片段。以下分支验证使用生产 caller 和
完整 policy，而不是把片段结果外推为整条 datapath 的收益。

### 分支验证记录

`just test-routing` 单独构建 test object，沿真实 root/slot 路径执行 117 个手写用例
在四种 dial mode 下的 468 次完整 decision 比较，同时验证 domain、目的/源 IP、MAC
的谓词 bit 255、谓词容量 257 的拒绝，以及包含 65,537 个独立前缀的单条规则首尾命中
和相邻地址不命中。发布失败检查保留依赖真实事实的命中和不命中结果，在解除占用的
attachment 后成功重新发布，确认冻结 root 的具体 syscall 错误，并重新附着所有
inactive target 以验证 link 清理。`just test-netns` 包含这个 gate。

扩展后的 gate 已在 Linux `7.2.0-cachyos` 通过。独立的生产 parser 到 emitter 检查
在 256 MiB 地址空间限制下处理 10,000 个进程名候选时正常返回容量错误，不再 abort。
以下 VM 和实验室记录早于这些新增容量与发布恢复检查。

固定的 Ubuntu `7.2.0-070200-generic` VM 通过全部 12 项 root-only 检查：
TC/cgroup 生命周期与 allocator 兼容性、生成 policy 发布、TC/TUN 报文合同、
生产 NFQUEUE 合同和真实 netns 流量。CI 在 hosted runner 构建 executable，
再于这个内核中运行相同产物，不在 guest 中重复编译。

隔离的 Linux 7.2.3 实验机通过 IPv4/IPv6 LAN 21 项、WAN 12 项检查，覆盖
direct/proxy/block TCP/UDP、MAC/源地址/目的地址组合、DSCP、pname、透明 DNS、
冷热域名 TLS，以及 NFQUEUE 持有首包后的 native direct UDP。16 MiB TCP 流持续
12.802 秒，跨越阻断新流的 reload 后完整结束；policy 发布为 9.43 ms，
恢复为 9.24 ms。Direct/global mode 检查保留了 block 与 must 的优先级。

配对基线为 `8b2ad586`（packed group metadata 与原有 bounded-loop matcher），
同机同配置、五次重复；短连接每次 512 条、并发 16，bulk 每次 8 × 8 MiB、
并发 4。下表 kernel 时间是包含缓存包的整条 TC 平均值，不是单独的生成函数时间。

| 等价负载 | 基线 | 编译版 | LAN TC 均值：基线 → 编译版 |
| --- | ---: | ---: | ---: |
| must-direct，连接/秒 | 9,719 | 9,738 | 382 → 342 ns |
| compound-proxy，连接/秒 | 4,149 | 4,084 | 684 → 694 ns |
| cold-facts fallback，连接/秒 | 6,241 | 6,709 | 598 → 563 ns |
| must-direct bulk，MiB/s | 2,145 | 2,158 | 292 → 281 ns |
| compound-proxy bulk，MiB/s | 1,944 | 2,011 | 422 → 423 ns |

最终产物的等价路径吞吐变化为 -1.6% 至 +7.5%；整条 TC 均值随负载而异，
不能视为全面无回归保证。观测到的进程峰值 RSS 为
84,628 → 78,636 KiB。编译版加载的程序合计 135,560 JIT 字节，包含预加载的
L3 variants 与 10,014 字节生成函数。未变化配置的 reload 分配基准为
15.33 → 15.29 ms，两者均为 20 次分配、68,097 字节且没有 flag 写入。

正向域名路径不作为等价性能比较：基线错误地直连，编译版按配置走代理。
基线在 DNS 后的 known-zero 流量超时，编译版通过 native 路径达到
9,780 连接/秒。这些是正确性差异，不能包装成同路径加速比。

## 相关文档

- [路由配置参考](../reference/routing.md)
- [数据面](./datapath.md)
- [DNS](./dns.md)
- [NFQUEUE](./nfqueue.md)
- [控制面](./control-plane.md)
