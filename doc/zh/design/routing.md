# 编译化路由决策面

## 范围

路由只有一个手写语义模型，执行方式可以不同：用户态 `Router` 解释规范化的
policy IR，受限编译器把同一 IR 降低为原生 eBPF 比较代码。内核不再解释第二套
policy 表示。真实后端的内核基线为 Linux 6.12。

静态 TC 程序继续负责报文解析、特殊/本地排除、DNS 接管判断、conntrack、mode 与健康检查、
NFQUEUE 所有权、重定向和回包统计。生成函数只负责
`RoutingInput -> RoutingDecision`。不会因为采用编译策略而把所有首包送到用户态；
native-direct 与已有流缓存路径保持原生执行。

## 规则语义

规范化 IR 保存有序 RuleId、展示信息、条件与 outbound/mark/must 动作。priority
数值越小越先匹配，同优先级保持稳定的源码顺序。dae 解析器按源码顺序分配
`0, 1, ...`；流量规则及其顺序完全由用户配置决定。启动、重载和接口变化不再
注入网关地址 `direct(must)` 规则，也没有隐藏的内核地址白名单。
条件之间 AND，同一条件的候选值 OR，否定只作用一次且覆盖整个条件。fallback
是独立的终结动作。空展开不能被丢弃：正向空集合为 false，负向空集合为 true，
不能因 geo 资源没有匹配项而放宽复合规则。


配置模型及解析器位于
[`crates/honk-config/src/routing.rs`](../../../crates/honk-config/src/routing.rs)
及对应的路由解析模块。`RoutingRule` 保存出站标签、优先级、mark 和显式的终结
`must` 标志；`RoutingCondition` 保存正向与否定匹配列表。`RoutingOutbound` 是
单个字符串目标，指向组或内置的 `direct`/`block`。`ClashRuleDisplay` 保留简单
匹配类型，对复合、否定或解析器记录的 `must` 语句使用 `complex`。
`Config::validate` 拒绝直接指向已配置节点的规则或 fallback；应使用组，
也可以是只筛选一个节点的组。

## 内核路由

切换保留当前用户态匹配语义：

- 普通 domain pattern/suffix/keyword 是同一条件内的 OR；与 geosite 字段同时存在
  时，geosite 仍是独立条件。suffix、regex、keyword、大小写和 geosite 属性行为不变。
- 目的/源 IP 保留 IPv4/IPv6 身份，覆盖 `/0`、裸主机地址及重叠前缀。
- 端口区间包含两端；TCP/UDP 和 IPv4/IPv6 mask 可以同时包含两种值。
- pname 保留配置端 15 字节规范化及子串匹配语义。内核进程字节按照 handoff 相同的
  lossy UTF-8 与 trim 规则转换，热路径不分配堆内存。
- 缺失 pname/MAC/DSCP 不是普通零值。缺失 domain 不满足正向条件，也不会触发负向
  条件的 veto。
- 配置 `(must)` 是终结结果：设置显式的 `must` 决策字段并跳过嗅探。
  Clash 模式不能覆盖 `must` 或 `block`。

LAN/WAN TCP/UDP 目的端口 `53` 在既有入口与控制平面排除后，
执行一次正常有序策略，不单独扫描 must 规则；本地监听器不能提前放行普通 LAN DNS。[路由参考](../reference/routing.md#出站目标与-must)
定义 DNS 所有权及[显式本地路由迁移](../reference/routing.md#显式本地路由)。

旧 lowering 丢弃 full/regex、把协议 OR 降成 TCP、截断规则链、DNS 只投影首条整规则、
重叠 LPM 丢失祖先位图，都不是要保留的兼容行为。共享 IR 和独立 golden 案例需要
阻止这些错误，不能把旧缺陷编码进新后端。

## 唯一 policy 与域名事实

`CompiledRoute` 保存元数据和 `CompiledCondition` 列表，不再平行维护正负 matcher
字段。每个条件包含一个 `CompiledPredicate` 和否定标志。域名条件引用 policy 内
不可变的已编译 matcher registry。规则名只用于展示，不能当作 bitmap 身份；相同
域名谓词可以在同一 policy 内共享 PredicateId。

### 源码组织

- [`crates/honk-core/src/routing/`](../../../crates/honk-core/src/routing/) —
  用户态 `Router`、按优先级排序的编译规则、`route_with_must`、`GeositeMatcher`
  以及 `BinaryLpmTrie`/Geo 资源辅助代码。`geo.rs` 在每次构建 `Router` 时只解析
  一次 `geoip.dat`/`geosite.dat`，且只解码被引用的类别。`category@attr` 在首个
  `@` 处分隔，并以不区分大小写的方式筛选属性键。
  启动时，流量路由与 DNS 路由共用同一份 Geo 资源快照；两者完成编译后即释放
  原始资源快照，已编译的 matcher 与指纹仍由各自的 router 持有。
- [`crates/honk-core/src/control/routing_matcher.rs`](../../../crates/honk-core/src/control/routing_matcher.rs)
  把 IR 编译为 `RoutingPushPlan`，不修改 map。
  [`crates/honk-core/src/ebpf/real/routing.rs`](../../../crates/honk-core/src/ebpf/real/routing.rs)
  负责 generation map、扩展加载、目标挂接与发布。
- [`crates/honk-ebpf/src/route.rs`](../../../crates/honk-ebpf/src/route.rs) —
  静态根/槽位接口与固定 ABI 分派，不包含解释器或备用规则引擎。
  静态 TC 调用方在这次同步调用前后负责报文解析与决策执行。
- 旧的 sockops/sk_msg 重定向实验不属于当前数据路径；部分内核出现 panic 报告后，
  这些实验代码已被移除。当前支持 TC 重定向，加载器只查找现有程序名称。

用户态参考实现与内核编译器使用这一表示。DNS 和嗅探产生的是**全部域名
谓词**的真值位，而不是首条命中的完整流量规则。用于否定规则的谓词
同样投影其正向真值，由求值器应用否定。一个已知域名即使没有匹配任何谓词，也
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

非 DNS 流量中，非 `must` 的 direct 结果若域名 finality 尚未确定，交接给用户态时
必须编码为 `ControlPlaneRouting`；若仍写成最终 direct，TCP/UDP 初始化会跳过嗅探。
该非 DNS 路径保留已知 direct、must、block 与 mode direct offload 的终态语义；
端口 53 所有权遵循上述参考。

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

emitter 在生成指令前折叠空的内联谓词：正向空谓词使整条规则不可能命中，取反空谓词
不增加条件。规则因此变成无条件时，在其 action 处结束生成；后续规则和 fallback
不能留下不可达指令，否则内核会在语义验证前拒绝加载。保留的 action 仍使用原始
RuleId 和元数据。

每一代拥有独立的目的 IPv4/IPv6、源 IPv4/IPv6 LPM maps、MAC 索引和 domain hash map。
IP 分 family，避免 IPv6 前缀误匹配 mapped IPv4。更具体的 LPM 条目继承所有匹配祖先
谓词的位，使最长前缀查找不破坏规则顺序。每一代使用完整 `DomainRouting` bitmap，
不再共享可能被新前缀提前遮挡的双 bank LPM value。

同一次调用中，出现至少两次的目的 IP、源 IP 或 MAC 类别，在实际执行到第一个相关
条件时才 lookup。对齐栈槽保存 pointer（包括 NULL）及独立的 ready 标志；每个条件仍
先检查自己的正向 bit，再应用否定。未使用或只使用一次的类别没有缓存状态。提前返回
不预查未到达的类别，但重复类别仍有入口栈初始化成本。fact pointer 不跨调用或
generation 保留。domain 入口 lookup 不变，因为它还负责确定 `domain_final`。

发射时用两个三位掩码跟踪“必然已计算”和“可能已计算”。每个失败条件都是下一规则的
前驱：合流时前者取交集，后者取并集。确定首次使用时省去 ready 检查，必然已计算时只
重载 pointer，不确定时保留运行时守卫。NULL 和输入缺失也算完成计算，否定不改变此
状态；入口缓存初始化保持不变。IPv4/IPv6 分别构造 key、选择 map，再合流到一次
lookup；仅清零 IPv4 key 的 padding，不清零马上会被覆盖的字节。

事实准备先用 hash 合并重复键，只排序唯一键，再在原向量中继承祖先位并压缩保留容量。
内部跳转由 assembler 自己分配的 ordinal label 标识，只有规则 source record 保留
诊断文本。输入/输出偏移从共享 ABI 声明推导，不再独立维护一份偏移表。

策略身份散列带长度边界的规范化规则字段、有序 domain registry key 和选定 geo digest，
不遍历派生 trie，也不依赖 `Debug` 文本。有效 no-op reload 的身份保持不变：只修改被
忽略的进程名后缀，不应重新发布相等的 native plan 并丢弃 sniff-only facts。

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

已提交路由代际不回绕。`ROUTING_GENERATION_SEQUENCE` 跨进程重启保留预留值，
20 位空间最多预留 1,048,575 次，包括失败发布和仅替换 descriptor 的 NFQUEUE fence。
耗尽时保留当前策略、拒绝进一步发布，并保持 NFQUEUE fence 关闭；只要 host 分片队列
仍可能存活，就不能删除该 pin。未变化策略可跳过重编译，但队列 fence 仍发布新 descriptor 代际。物理携带格式见
[数据路径 ABI](./datapath.md#map-清单)，排队元数据与代际生命周期见
[控制面准入](./control-plane.md#透明代理入口)。

控制器用一次 backend 发布调用传入不可变 plan 和完整 learned-domain slice。
后端自行选择 inactive slot 并局部持有候选，不再需要调用方选槽或 pending-domain
握手。静态 plan 复用与 DNS projection ownership 仍然分离。

发布与现有 reload、DNS publication fence 串行协调：

1. 编译、校验完整候选，保留 active policy。
2. 创建并填充本代事实 maps，包括 learned-domain 快照。
3. 用这些确切 map FD 和合法 BTF 加载生成扩展。
4. 给全部相关 TC target 的 inactive 槽完成 attach。
5. 最后只替换一个 generation root。
6. 成功更新返回后才允许退休旧 TC 槽和旧 maps；用户态 IR/reference lease 独立保有
   自己的生命周期。

Linux 6.12 在 map-in-map 更新成功返回前等待旧 non-sleepable BPF 调用完成：
[`maybe_wait_bpf_programs`](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/syscall.c)
使用 `synchronize_rcu()`。普通 root store、固定延时或“有两个槽”不是等价 grace。
不能依赖不支持的 freplace `BPF_LINK_UPDATE`，也不 detach/attach 活跃槽。

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

### 分支验证记录

当前 CI 的真实内核基线是固定的 Ubuntu Linux
`6.12.0-061200-generic` VM。CI 在 hosted runner 上构建测试 executable，
再在该 VM 中运行完全相同的产物，不会在 guest 内重新编译。VM 执行 root-only
路由与集成 gate；`just test-routing` 还会沿真实 root/slot 路径检查生成 policy，
包括优先级、完整 decision 元数据、容量失败和发布失败保留旧状态。
`just test-netns` 包含该路由 gate。

性能测量及历史原型/实验室记录有意不保留在本设计页。reload 基准定义见
[`crates/honk-core/benches/reload.rs`](../../../crates/honk-core/benches/reload.rs)；
[`CI workflow`](../../../.github/workflows/ci.yml) 选择 VM 检查，
[`run-vm-gate.sh`](../../../.github/ci/run-vm-gate.sh) 负责宿主机准备和 VM 命令，
[`pins.env`](../../../.github/ci/pins.env) 定义固定镜像。

## 相关文档

- [路由配置参考](../reference/routing.md)
- [数据面](./datapath.md)
- [DNS](./dns.md)
- [NFQUEUE](./nfqueue.md)
- [控制面](./control-plane.md)
