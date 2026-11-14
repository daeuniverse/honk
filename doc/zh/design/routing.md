# 编译化路由决策面

## 范围

路由只有一套手写语义模型，执行方式可以不同。用户态 `Router` 解释规范化的 policy
IR；受限编译器把同一份 IR 编译成原生 eBPF 比较代码。内核不会去解释第二套 policy
表示。真实后端的内核基线是 Linux 6.12。

报文解析、特殊和本地排除、DNS 接管判断、conntrack、mode 与健康检查、NFQUEUE 所有
权、重定向和回包统计，仍由静态 TC 程序负责。生成函数只管
`RoutingInput -> RoutingDecision`。采用编译策略不代表 honk 把每个首包都送到用户
态；native-direct 和已有流缓存路径仍在内核执行。

## 规则语义

规范化的 IR 保存有序 RuleId、展示信息、条件和 outbound/mark/must 动作。priority
越小越先匹配，同优先级保持稳定的源码顺序。dae 解析器按源码顺序分配 `0, 1, ...`，
流量规则的内容和顺序完全由用户配置决定。启动、reload 和接口变化都不再注入网关地
址的 `direct(must)` 规则，也没有隐藏的内核地址白名单。条件之间是 AND，同一条件的
候选值之间是 OR；否定只作用一次，覆盖整个条件。fallback 是独立的终结动作。空展开
不能丢掉：正向空集合为 false，负向空集合为 true，不能因为 geo 资源里没有匹配项就
放宽复合规则。

配置模型和解析器在
[`crates/honk-config/src/routing.rs`](../../../crates/honk-config/src/routing.rs)
及对应的路由解析模块里。`RoutingRule` 保存出站标签、优先级、mark 和显式的终结
`must` 标志；`RoutingCondition` 保存正向和否定匹配列表。`RoutingOutbound` 是一个
字符串目标，指向代理组或内置的 `direct`/`block`。`ClashRuleDisplay` 保留简单匹配类型，
对复合、否定或解析器记录的 `must` 语句使用 `complex`。`Config::validate` 拒绝直
接指向已配置节点的规则或 fallback；应该用组，也可以是只筛一个节点的组。

## 内核路由

内核路由保留用户态的匹配语义：

- 普通 domain 的 pattern、suffix、keyword、regex 和 geosite 在同一条件内按 OR 匹
  配，否定作用于整个并集。suffix、regex、keyword、大小写和 geosite 属性的行为不
  变。
- 目的 IP 和源 IP 保留 IPv4/IPv6 身份，覆盖 `/0`、裸主机地址和重叠前缀。
- 端口区间包含两端；TCP/UDP 和 IPv4/IPv6 mask 可以同时包含两种值。
- pname 保留配置端 15 字节规范化和子串匹配语义。内核里的进程字节按与 handoff 相
  同的 lossy UTF-8 和 trim 规则转换，热路径不分配堆内存。
- 缺失的 pname、MAC、DSCP 不等于普通零值。domain 缺失时不满足正向条件，也不会触
  发负向条件的 veto。
- 配置的 `(must)` 是终结结果：设置显式的 `must` 决策字段，并跳过嗅探。Clash 模式
  不能覆盖 `must` 或 `block`。

LAN/WAN 的 TCP/UDP 目的端口 `53` 先经过既有入口和控制面排除，然后只执行一次正常
有序策略，不单独扫 must 规则；本地 listener 不能提前放行普通 LAN DNS。[路由参考](../reference/routing.md#出站目标与-must)
定义 DNS 所有权和[显式本地路由迁移](../reference/routing.md#显式本地路由)。

旧的 lowering 会丢掉 full/regex、把协议 OR 降成 TCP、截断规则链、让 DNS 只投影第
一条整规则、让重叠 LPM 丢失祖先位图。这些都不是需要保留的兼容行为。共享 IR 和独
立的 golden 案例要能阻止这些错误，不能把旧缺陷编码进新后端。

## 唯一 policy 与域名事实

`CompiledRoute` 保存元数据和 `CompiledCondition` 列表，不再另外维护一组正负
matcher 字段。每个条件有一个 `CompiledPredicate` 和一个否定标志。域名条件引用
policy 内不可变的已编译 matcher registry。规则名只用于展示，不能当作 bitmap 身份；
相同的域名谓词可以在同一个 policy 内共享 PredicateId。

### 源码组织

- [`crates/honk-core/src/routing/`](../../../crates/honk-core/src/routing/) — 用
  户态 `Router`、按优先级排序的编译规则、`route_action`，以及 `BinaryLpmTrie` 和
  Geo 资源的辅助代码。`domain.rs` 负责域名 matcher、`GeositeMatcher` 和构建期的
  内部去重表。`geo.rs` 在每次构建 `Router` 时只解析一次
  `geoip.dat`/`geosite.dat`，而且只解码被引用到的类别。`category@attr` 在第一个
  `@` 处分开，属性 key 按不区分大小写的方式筛选。启动时，流量路由和 DNS 路由共用
  同一份 Geo 资源快照；两者编译完成后就释放原始快照，已编译的 matcher 和指纹仍由
  各自的 router 持有。
- [`crates/honk-core/src/control/routing_matcher.rs`](../../../crates/honk-core/src/control/routing_matcher.rs)：
  把 IR 编译成 `RoutingPushPlan`，不改 map。
  [`crates/honk-core/src/ebpf/real/routing.rs`](../../../crates/honk-core/src/ebpf/real/routing.rs)
  负责 generation map、扩展加载、目标挂接和发布。
- [`crates/honk-ebpf/src/route.rs`](../../../crates/honk-ebpf/src/route.rs) — 静
  态根和槽位接口，以及固定 ABI 的分派，不含解释器或备用规则引擎。静态 TC 调用方
  在这次同步调用前后负责报文解析和决策执行。
- 旧的 sockops/sk_msg 重定向实验不属于当前数据路径。部分内核出现 panic 报告后，
  这些实验代码已被移除。现在只支持 TC 重定向，加载器只查找现有的程序名称。

用户态参考实现和内核编译器用的都是这套表示。DNS 和 sniff 产生的是全部域名谓词的
真值位，不是首条命中的完整流量规则。用于否定规则的谓词也投影自己的正向真值，由求
值器负责否定。一个已知 domain 即使没有匹配任何谓词，也会产生一个存在的零 bitmap；
这个 IP 的最后一个有效 owner 消失时，才删除条目。

DNS association 仍按 IP 组织，与源客户端无关，多个有效 owner 之间按 OR 聚合。它
不能证明共享 IP 上每条连接的精确 SNI。dial-mode reality check 和允许的 sniff 重
路由仍由用户态负责；迁移不会把 unknown 一律 punt，也不隐式改变四种 dial mode 的
语义。

## 生成函数 ABI

固定布局放在 `honk-ebpf-common`，字段只用固定宽度整数。Rust 的 enum 布局、引用、
`String` 和 allocator 对象都不跨边界。

`RoutingInput` 里有网络序的源地址和目的地址、规范化的 16 字节 MAC key、规范化的
进程字节及其长度、主机序端口、协议和 family mask、DSCP，以及 provenance/presence
信息。`RoutingDecision` 里有 outbound、mark、must、domain-finality 和 RuleId。独
立的标量返回码用来区分成功结果与 evaluator 不可用或执行失败。

`RoutingInput.flags` 分别保存 MAC 存在位和 direct-finality permission。静态
caller 从本次执行策略所用的同一份 Rule-mode flags 快照重建 permission，不再读一
次 map。输入仍是 128 字节。loader 会拒绝最后一个字段仍是 `mac_present` 的旧外部
eBPF 对象，所以用这个用户态 compiler 之前必须先重建这些对象。

`domain_final` 表示在当前 dial mode 下，后续的域名观察改变不了这一阶段的路由。三
种情况会成立：policy 里没有域名谓词；禁用了域名重路由；或者已经取得完整的
learned-domain bitmap。Rule 模式下，如果从首条 live 规则到当前命中规则，包含当前
这条，前缀都不依赖域名，那么普通的 direct action 也可以成为 final，后置的域名规
则覆盖不了 first-match。folded-false 规则不计入前缀；正向和取反的域名谓词都计入。
fallback 用同一套前缀证明。没有捕获到 Rule-mode permission 时不套用这个额外证明，
以保留 Global 模式原有的交接和域名嗅探 authority。

非 DNS 流量里，非 `must` 的 direct 结果如果域名 finality 还没确定，交给用户态时
必须编码成 `ControlPlaneRouting`；如果照旧写成最终 direct，TCP/UDP 初始化就会跳
过嗅探。这条非 DNS 路径保留已知 direct、must、block 和 mode direct offload 的终
态语义。端口 53 的所有权按上面的参考处理。

输入只在路由 miss 时初始化：复用现有的 per-CPU packet scratch，缓存包不会清空它。
slot 的 volatile 访问防止 LLVM 删掉输入或折叠输出。pname 规范化由一个独立验证、
有界的 global subprogram 完成，避免 Unicode 分支和 WAN parser 的状态相乘。

静态 caller 把逻辑结果转成原有的 datapath action。`ControlPlaneRouting` 不是
`TC_ACT_*`。evaluator 出错时，caller 执行原有的 fail-closed 清理，包括尚未完成的
UDP Preparing claim，不能把故障伪装成一个请用户态补判的请求。

## 受限原生后端

后端发射有类型的 8 字节 BPF 指令、经过检查的 label/fixup、常量比较、mask、map
lookup 和终结结果写入。它不负责 TLS/QUIC 解析、拨号、mode、健康检查或通用 VM。大
的 IP、MAC、domain 集合保留为索引，不展开成成千上万条立即数比较。

emitter 在生成指令之前先折叠空的内联谓词：正向空谓词让整条规则不可能命中，取反空
谓词不增加条件。规则因此变成无条件时，生成就在它的 action 处结束。后续规则和
fallback 不能留下不可达指令，否则内核会在语义验证前拒绝加载。保留下来的 action
仍用原始 RuleId 和元数据。

每个 generation 都有自己的目的 IPv4/IPv6、源 IPv4/IPv6 LPM maps、MAC 索引和
domain hash map。IP 按 family 分开，避免 IPv6 前缀误匹配 mapped IPv4。更具体的
LPM 条目继承所有匹配祖先谓词的位，最长前缀查找因此不会破坏规则顺序。每个
generation 用完整的 `DomainRouting` bitmap，不再共享一个可能被新前缀提前遮挡的双
bank LPM value。

事实是值，不是指针。每个类别，也就是 domain、目的 IP、源 IP、MAC，每次调用最多解
析一次：lookup 把 map value 里 32 字节的 `DomainRouting` bitmap 复制到该类别固定
的栈区域；输入没有这项事实，或 map 里没有条目时，就把区域填零。之后每处使用都基
于这次解析，不再读任何 map 指针。每个条件直接在自己的区域里测 bit，全零 bitmap
会让所有正向 bit 都不成立，正好对应“没有条目”；测完再应用否定。domain 在入口解析，
因为命中后还要置 `domain_final`。每条规则先执行完整的正向和取反目的端口、源端口
条件，再执行其余条件。

非 domain 事实在第一个真正到达的使用点解析，而不是在规则入口。每个使用点检查本次
调用的 `R8` readiness mask 中对应类别的 bit，只有完整复制或填零结束后才置位。map
miss、缺失 MAC、非法 family 和已有全零 bitmap 都算已解析。前面的使用点如果被短路
跳过，bit 仍是零，后面的使用点仍会去解析。每次调用从空 mask 开始，不跨调用或
generation 保留状态。逐使用点的 lazy guard 会增加代码，但能跳过已被前置条件拒绝
的路径上的事实工作；这不代表已经测得净吞吐量提升。

verifier 不能把 mask 的初值当成常数。如果用 `mov 0` 置零，它在每种解析历史下都是
一个精确值；值不同的状态互不吸收，后面每条进程名链都要按值的数量重走。#280 策略
在 Linux 6.12.107 上处理 160,415 条指令；四条事实规则排在二十九条进程名规则之前
的策略则是 368,874 条。所以入口从刚清零的 decision `mark` 把 mask 读回来：
verifier 不会把内存读取折叠成刚存入的常数，低 32 位是未知值，运行时则恒为零。三
个 lazy 区域都用同一字段的独立读取来预填，让先于解析被验证的使用点读到已初始化的
栈；存入的字各自独立，不和 mask 共享 scalar id。如果直接把 mask 寄存器存进去，两
者会被关联，状态又分裂成 133,354 条。

每个 guard 都是对 mask 寄存器本身的一条 `jset`，两条边上都会细化被测的 bit，跳过
边和解析边到 bit 测试时一致。如果先复制到 `R0` 再测，跳过边上的寄存器没有细化，
那就是 82,234 条。三者齐备时，两份策略分别为 53,741 和 100,645 条处理指令，接近
在规则入口无条件解析；在常数 mask 上只改 `jset` 则没有变化。运行时，每处事实使用
都在解析完成之后。这些是 Linux 6.12.107 上的测量；如果 verifier 将来能沿存储追踪
内存内容，mask 又会变回常数。由于 mask 从 `mark` 读回，入口从不往该字段写入配置
值。带 mark 或 `must` 的 fallback，只在全部规则都失败后到达的 fallback 出口写入
mark、`must` 和直连 mark 索引；普通 fallback 不增加写入。

复制 bitmap 可以限制 verifier 状态增长。指针类型取决于 lookup 结果，verifier 不
会把 NULL 和 map 指针合并成一个状态。于是一个跨越后续规则仍然存活的事实指针，会
让它后面所有指令的状态数成倍增长。两条 `sip && dip && dport` 规则放在十五条进程
名规则前面，就能把一份策略推过 1,000,000 条指令预算：#280 在 Linux 6.12 上去掉这
两条处理 159,837 条指令，加上就超过 1,000,000。复制出来的 bitmap 是标量，其余状
态相容时，已记录的非精确标量状态可以吸收其他路径。

分支布局同样受 verifier 约束。verifier 先探索未定条件跳转的 fall-through，所以每
个分叉，包括 IPv4/IPv6 分派，都把从 map value 复制的路径放在 fall-through，把填
零放在跳转目标。先被记录的填零路径一旦有 bit 测试可预测，就会变成精确值，无法吸
收后来的未知值。同一内核上实测，这份策略去掉两条规则时处理 53,383 条指令，加上时
为 53,741。verifier-budget 测试通过只能证明可加载，不能证明这个指令数。IPv4/IPv6
仍分别构造 key、选择 map，再合流到一次 lookup；只清零 IPv4 key 的 padding，不清
零马上就会被覆盖的字节。

事实准备先用 hash 合并重复 key，只排序唯一 key，再在原向量里继承祖先位并压缩保留
容量。内部跳转由 assembler 自己分配的 ordinal label 标识，只有规则 source record
保留诊断文本。输入和输出偏移从共享 ABI 声明推导，不再单独维护一份偏移表。

策略身份 hash 覆盖带长度边界的规范化规则字段、有序 domain registry key 和选定的
geo digest。它不遍历派生 trie，也不依赖 `Debug` 文本。有效的 no-op reload 身份保
持不变：只修改被忽略的进程名后缀，不应该重新发布相等的 native plan 并丢掉
sniff-only facts。

每个事实 LPM 保留 2,048,000 条容量，不预分配；学习到的 domain hash 保留 65,536
条。前缀数量和谓词数量是独立的：一个 GeoIP 谓词可以包含几十万个前缀。emitter 在
每次插入指令前检查 1,000,000 条指令预算，耗尽时立即返回错误，不再继续展开指令或
fixup。

事实位按每个 generation 分配资源：目的 IP、源 IP、MAC 各有 256 个 ID，按不同的列表计数，不按规则数量计数。引用同一个 IP 列表的规则共享 ID，列表按 interned matcher 身份识别；引用同一个 MAC 列表的规则也共享 ID，列表按值识别，顺序敏感。取反仍保留在规则条件上。域名谓词另有 256 个 ID，规范化 matcher key 相等时就共享。分支距离必须能用一个有符号 16 位指令偏移表示，否则以 `routing jump out of range` 错误拒绝发布。

容量和 verifier 限制都是明确的错误，不能截断规则链，也不能把缺失的 outbound 默认
成 direct。生成源映射记录 RuleId 和规范化规则描述。raw loader 复用现有的
syscall/BTF 基础，不引入运行时的 clang/LLVM，也不写另一个 ELF writer。函数原型必
须真实；raw `func_info` 和 `line_info` 用指令槽偏移，不能直接套用 ELF `.BTF.ext`
的字节偏移。

## 同步槽与原子发布

每个相关的 TC 程序都暴露两个真正保留的、非内联的 BTF-global 函数：
`honk_route_slot0` 和 `honk_route_slot1`。没有安装的函数返回错误，其中不含
fallback 规则引擎。放行流量之前，后端把策略挂到每个已加载的 LAN/WAN L2/L3 路由目
标上。启动时至少加载一个目标。后续目标在后端锁之外验证，两个路由槽的目标元数据会
保留下来。提交时先挂上提交当时有效的路由 generation，即使验证期间策略已经更新，
然后才发布为可绑定。之后每次发布都包含已提交目标，并且不去获取 verifier 的锁。

`ROUTING_POLICY_ROOT` 是单项 map-in-map，指向不可变的 `RoutingPolicyDescriptor`。
descriptor 标出 slot、policy generation、feature bit，以及供诊断使用的 active
domain-map ID。一次路由只取一个 descriptor，再同步调用一个槽；缓存命中的报文不会
多出这次 lookup。

已提交的路由 generation 不回绕。`ROUTING_GENERATION_SEQUENCE` 跨进程重启保留预留
值，20 位空间最多预留 1,048,575 次，其中包括失败的发布和只替换 descriptor 的
NFQUEUE fence。耗尽时保留当前策略、拒绝进一步发布，并让 NFQUEUE fence 保持关闭；
只要 host 分片队列还可能存活，就不能删除这个 pin。策略没变可以跳过重编译，但队列
fence 仍会发布新的 descriptor generation。物理携带格式见[数据路径
ABI](./datapath.md#map-清单)，排队元数据和 generation 生命周期见[控制面
admission](./control-plane.md#透明代理入口)。

控制器只调用一次 backend 发布，传入不可变的 plan 和完整的 learned-domain slice。
后端自己挑 inactive slot，并在局部持有候选，调用方不必选槽，也没有
pending-domain 握手。静态 plan 复用和 DNS projection ownership 仍然是分开的。

发布与现有 reload、DNS publication fence 串行协调：

1. 编译并校验完整候选，保留 active policy。
2. 创建并填充本 generation 的事实 maps，包括 learned-domain 快照。
3. 用这些确切的 map FD 和合法 BTF 加载生成扩展。
4. 给全部相关 TC target 的 inactive 槽完成挂接。
5. 最后只替换一个 generation root。
6. 更新成功返回后，才允许退役旧 TC 槽和旧 maps；用户态 IR/reference lease 独立保
   有自己的生命周期。

Linux 6.12 在 map-in-map 更新成功返回之前，会等旧的 non-sleepable BPF 调用结束：
[`maybe_wait_bpf_programs`](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/syscall.c)
用的是 `synchronize_rcu()`。普通 root store、固定延时或者“有两个槽”，都不是等价
的 grace。不能依赖不受支持的 freplace `BPF_LINK_UPDATE`，也不要 detach 或挂接活
跃槽。

root commit 之前，后端发布必须 all-or-nothing。map 构建、verifier、任意一个
inactive 槽挂接失败，都保留旧代码和旧事实。不能用关闭数据路径 admission 来掩盖错
误，因为关闭状态会直接放行流量；也不能把所有流量 punt。规则派生的 flags 和
domain writer 必须属于同一个 policy generation。mode/NFQUEUE 协调和已有流仍由原
来的 controller 管理。

稳定的 policy pin 只保留 generation root。诊断工具通过 descriptor 找到 active
domain map，不能假设把同名 map 重新 pin 一次就能改变已加载程序持有的引用。

## 验证与验收

完整实现必须覆盖现有的全部 matcher，并通过下面这些检查：

- 独立 golden：顺序、OR/AND/not、缺失事实、must/block/mark、IPv4/IPv6、前缀重叠、
  pname 规范化、domain 投影和容量失败。
- 把 reference 的完整 decision 和真实生成的 BPF 相比较，不只比 outbound 或生成结
  构，还要包含源元数据和 finality。
- 真实 TC/cgroup/netns：native direct、proxy、block、DNS、LAN/WAN、TCP/UDP 和缓
  存流；queue/token 路径保留真实的 NFQUEUE 合同测试。
- staging、verification、挂接故障，连续换 generation，以及旧读者场景，用来证明不
  存在半发布，旧流的所有权也不变。
- 配对测量完整路由和流量的成本、冷热事实、reload、JIT 大小和内存峰值。强化后的
  packed-data/AOT bounded-loop 是基线；端口微基准不能代表整个引擎没有退化。

### 分支验证记录

当前 CI 的真实内核基线是固定的 Ubuntu Linux `6.12.0-061200-generic` VM。CI 在
hosted runner 上构建测试 executable，再到这个 VM 里运行完全相同的产物，不会在
guest 内重新编译。`just test-routing` 和依赖它的 `just test-netns` 共用同一个完
整、前置条件已就绪的一次性 VM gate，沿真实 root/slot 路径检查优先级、完整
decision 元数据、容量失败和发布失败后的保留，然后执行所有权和 netns 套件。工具链、
两个对象和 VM 环境的前置条件见 `honk-real-ebpf-tests` skill；受保护的夹具不在共
享宿主机上运行。

性能测量和历史原型、实验室记录有意不放在本设计页。reload 基准定义见
[`crates/honk-core/benches/reload.rs`](../../../crates/honk-core/benches/reload.rs)；
[`CI workflow`](../../../.github/workflows/ci.yml) 选择 VM 检查，
[`run-vm-gate.sh`](../../../.github/ci/run-vm-gate.sh) 负责宿主机准备和 VM 命令，
[`pins.env`](../../../.github/ci/pins.env) 定义固定镜像。

## 相关文档

- [路由配置参考](../reference/routing.md)
- [数据路径](./datapath.md)
- [DNS](./dns.md)
- [NFQUEUE](./nfqueue.md)
- [控制面](./control-plane.md)
