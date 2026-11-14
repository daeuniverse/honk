# 代理组选择、健康检查与预热设计

honk 将代理组解析为叶子出站，追踪其健康状态，并限制预热资源的保留量。

## 范围

组运行时由这几部分组成：`GroupManager`、`AliveDialerSet`、始终编译的 Score 评分器、冷启动 URLTest 准备流程，以及预热资源协调器。组字段和策略语法见[组参考](../reference/groups.md)。进程级的健康检查、预热和拨号配置 key 见[全局参考](../reference/global.md)。

## 代理组管理器与选择流水线

`SharedGroupManager` 是稳定、可热切换的 handle：

`SharedGroupManager = Arc<parking_lot::RwLock<Arc<GroupManager>>>`

普通 reload 会构建一个完整的替代 `GroupManager`。它先通过 `migrate_selector_choices_from`，把 TCP 和 UDP Selector 里仍然存在的成员身份分别迁过去，再安装连接中断、预热和持久化回调，最后切换内部 `Arc`。已删除节点的选择不会转到同名的新节点上。原生 API 和 Clash API 的选择写入、以及管理器替换，都由同一个 `control/reload` owner 串行处理；写向已被替换的管理器无法确认。因此读取方看到的只会是完整的旧管理器或新管理器。

共用 reload 的规范化在 `control/reload/fingerprint.rs` 里做。它按名字保留配置组的 UUID 和 `created_at`，插入、删除、重排都不影响。改名就算新组，不继承旧身份；程序化改名如果还带着旧 UUID，也会重新生成。SIGHUP、显式激活，以及 provider/runtime reload，包括 no-op 比较，都按这条规则处理，与原生观测是否启用无关。

`src/group/` 对外接口与内部实现按职责拆分：

| 模块 | 职责 |
| --- | --- |
| `mod.rs` | `GroupManager` 类型、共享 handle 与选择计划入口 |
| `resolver.rs` | 嵌套组展开、成员/叶节点内省、环切断与 Selector 选择迁移 |
| `filter.rs` | 按网络和地址族过滤存活性 |
| `policy.rs` | Selector、URLTest、LoadBalance、Fallback 选择与延迟排名 |
| `score.rs`、`score/selection.rs` | Score 共享状态、公开契约及按目标的组选择 |
| `score/ranking.rs`、`score/budget.rs` | 普通排名；保留的业务额度和在途记账 |
| `score/evidence.rs`、`score/feedback.rs` | 作用域结果／来源规则与 exact-once 观测所有权 |
| `score/comparison/`、`score/verification.rs` | 有界观测存储、成对响应证据、验证问题、唯一的可选工作派发遍历和只读成对关系；`score/tests/` 按职责拆分场景 |
| `state.rs` | URLTest/Fallback 缓存、Selector 选择与回调 |

选择遵循一条不变量：解析和存活性过滤完成后，拨号路径只用策略选出的结果。Selector 返回有效的手动选择，URLTest 返回当前胜者，LoadBalance 返回下一个成员，Fallback 返回固定成员，Score 返回排序后的合格叶节点，其中包含确定性的冷探索。失败后的重试 race 由 `connection/` 负责，其他地方不再加并行 race。

唯一的多候选例外是没有测量值的顶层 URLTest 组。已有测量值的 URLTest，以及所有非 URLTest 计划，都是权威的单叶节点计划。未配置 `final` 的组如果只剩一个唯一叶节点，而 TCP 存活性过滤把它排除了，那么只有当当前 Selector 选择路径能到达该节点时，才会把它作为权威的最后尝试。此时健康状态仍是 dead，但真实拨号可以证明恢复，而且不会泄漏到其他成员或 `direct`。UDP 仍执行正常的存活性排除。最后尝试服务会记一条限流 warning，每组 60 秒一条；预热 peek 保持静默。

UDP 选择会先排除规范协议或配置不支持 UDP 的转发叶节点，即使还没有健康观测也一样。TCP 存活不能让 VMess 或只支持 TCP 的节点获得 UDP 资格。这些叶节点也不参与 Score 验证，发布组连通性时不能拿它们当作既有 capability 又存活的依据。`block` 仍是终态动作。Selector 已选的节点不具备 UDP capability 时，只能按原规则走显式 `final`，不能改选兄弟成员。VLESS UDP/443 拒绝这类目标相关策略仍在 admission 处终止，不能靠候选过滤绕过去。

## 策略语义

| 策略 | 运行时行为 |
| --- | --- |
| Selector | TCP 和 UDP 各维护一份选择。健康过滤之前，按顺序找对应网络的运行时选择、`group.default`，然后是第一个成员；只有 tag 缺失或不是成员时才继续往后找。没有合格叶节点时，只执行显式 `final` 或同叶 TCP 最后尝试。原生 API 可写 tcp、udp 或 both；Clash 写 both，读的是 TCP 投影。写 both 时一次校验、原子发布。有效选择按网络持久化。启用 `interrupt_connections` 时，会关闭捕获了该组路径的旧 transport owner，不只是删掉 tracker。 |
| URLTest | 选择最小减半递推移动平均，TCP 和 UDP 各存一份选择，应用 tolerance 滞后，并在拨号和选择查询时 lazy 重算。真实选择变化时可以调用 `InterruptCallback`。 |
| LoadBalance | 按声明顺序轮询合格成员。每个组的 TCP 和 UDP 各有一个独立的 `AtomicUsize` 游标。轮转从不调用 `InterruptCallback`。 |
| Fallback | TCP 和 UDP 各自固定为声明顺序里的第一个合格成员。该成员死亡前一直固定；更靠前的成员恢复也不会触发 failback。 |
| Score | 用 `policy: score` 显式选择后，Score 依据实际可靠性、新鲜目标质量和有界验证，选出一个健康合格的叶节点；历史样本数量不算性能加分。不写策略时仍默认 Selector。 |

组中断靠连接建立时捕获的已选组身份或路径，加上网络选择，精确匹配 TCP/UDP owner。它不按当前组成员或叶名称重建匹配，也不依赖流 recorder 是否启用。显式选择在发布前捕获旧集合；回调在同步 guard 之外运行，然后等待选中的网络确认关闭。选择没变就不会重拨。TCP 绑定 UUID、cancel 和 completion；UDP 绑定 token、generation 和 source view，并确认 backend 和 driver 已经退役。共享 XUDP 不会关闭其他 view 的 carrier，也不重放数据。选择已经发布、但关闭确认失败时可以返回错误，这不表示回滚。

同一已捕获 owner 的并发 close 共用实际完成结果。退役失败也由所有等待者继承；不会仅因为已经处于 Closing 或 Failed 就报告 `Gone`。不存在或已被替换的 owner 仍是 `Gone`。自动中断回调只发起退役，需要确认的调用者等待该 owner 的 completion。

组配置和运行时选择是分开的。受限的原生 JSON Patch 按解析器记录的来源位置，经既有协调器写入 `.dae`，完整校验后才执行真正的 reload。已接受的配置 revision 和磁盘文件的 SHA-256 分别校验，激活前还会再查一次 revision。配置里的 `icon` 只以校验通过的 HTTP(S) URL 或 data URI 展示；至少 8 字节长的 listener secret 值会被遮蔽。honk 不推测图标，也不下载图标。自动策略的固定成员只存在于当前 GroupManager 中，配置一激活就失效。节点和 provider 的创建、删除走另一套主文件源事务；修改已有条目仍用源 PUT，见[API 参考](../reference/api.md#主文件条目与-geodata-管理)。

### Score 评分与生命周期

Score 先经过与其他策略相同的存活性过滤。过滤用的 health family 描述到代理服务器的连通性，单独携带的 target family 决定评分分桶。所以经 IPv4 到达的服务器仍能承载 IPv6 业务目标，而评分绝不会让已经判死的节点重新入选。过滤后的计划只包含一个权威叶节点，只有冷 URLTest 仍可按既有规则做推测性准备。

精确 key 是 `(group, TCP/UDP, target IPv4/IPv6, normalized target, NodeId)`。domain 会转成 ASCII 小写，去掉末尾的一个点，保留端口；IP 目标保留 socket address。第二个有界的 `(group, TCP/UDP, target family or no family, NodeId)` 聚合层为冷目标提供先验，也接收无目标的预热样本。精确目标、target-family 和全局聚合层按衰减后的有效证据分层混合：精确证据变多时逐步覆盖聚合证据，老化后又逐步让出权重。递归选择带着同一 target context，并把叶节点结果归因到路径上的每个 Score 组。

目标路径失败仍计入全局、地址族和精确目标的数值结果，但硬失败状态只在精确目标上建立。类型化代理、认证、协议帧或共享 carrier 故障，setup 前的未知错误，以及无目标失败，都归为节点故障；setup 前明确的目标拒绝仍算目标侧。节点故障 fence 依赖它的目标和探测证据：无关目标失败不会让配置探测失效，探测失败只撤销自己当前的槽位。子 cell 继承节点 incarnation、失败时间和共享源事件身份。迟到的 fanout 仍逐流计失败，但不能重新打开已经恢复的同一事件。同一次分发里的 carrier、源、packet endpoint 或共享拨号故障，每条受影响的流，包括同一 H2MUX 连接上的各流，都报告该故障唯一的事件身份；独立产生的故障仍各自计入。

carrier 来源由实际拥有代理连接的边界标记，不能从通用 QUIC 错误推断。经过健康 packet 代理、连接已建立后的端到端 DoQ／DoH3 失败，不证明代理 carrier 失败。Packet-backed DNS endpoint 单独保留实际的 adapter 故障，只在类型化 endpoint 丢失时附加这个来源，不覆盖已缓冲的流重置、EOF 或畸形 H3 响应。setup 前的未知失败仍按上面的保守规则处理。H2MUX 流重置和用户态流错误仍属于单流，连接 I/O 和 GOAWAY 属于节点。AnyTLS session 仍活跃时出现的 TCP SYNACK 超时属于目标；静默 session 退役和 UoT 服务 open 失败仍属于节点。VMess 一个响应头字节都没收到就 EOF 时，含义不确定，保留为 I/O 失败；部分或畸形的响应头，以及真正的 carrier 错误，仍保留节点来源。XUDP END|ERROR 关闭的是多目标共享源，绑定流仍归因于共享源失败，不能虚构出某一个失败目标。

业务 attempt 和终态证据都用 30 分钟半衰期。setup 失败在 Beta 置信界里受更重的惩罚。首次取得资格需要四个有效的 useful 完成。新鲜的定向业务 RX 能把已取得的资格保留到事件时间之后 60 秒，但不增加完成数；失败和 reload 会撤销 lease。低于门槛的 RX 不能重新授予冷启动资格，也不能恢复仅因 reload 失效的资格；真正失败后的恢复走下面四个 reporter 的规则。历史可靠性继续影响 utility 和晋升。全局、地址族、精确目标的计数重叠时不相加，混合与保持成熟度仍用实际衰减后的计数。

首次选择的性能启发式保留独立的事件时间，以及四次观测封顶的 `WeightedMean` 惯性。各指标 60 秒后降低置信度、120 秒时过期，不受历史完成数影响。配置探测 RTT 提供基线，新鲜且可比的目标响应和分方向 goodput 可以覆盖基线。探测 RTT、setup 和首响应分别在自己的测量范围内归一，不把含义不同的毫秒值混在同一个池里。HTTP 探测身份包含规范化 URI 和方法，探测 domain 和健康地址族也各自隔离。这套启发式只用来提出候选，不是晋升证明。

普通首次选择在服务池内比较相对 utility 和资格。不合格、或失败后尚未恢复的现任，可以立刻逃到池内另一个成员。第一个发生在 setup/TX 之后、且严格晚于适用失败／reload 边界的合格定向 Traffic RX，会清除探索延迟，但只允许有额度的半开验证。在同一个 cell 连续的失败后可用性 cohort 中，四个不同 reporter 才能清除硬失败事件，并授予当前 60 秒的资格 lease；历史失败不会被清空，也不会凭空虚构一个终态成功。即使其他目标已经恢复了节点聚合层，每个精确目标仍需自己的四份信用；只有 reload 造不出失败来源。setup、单向 TX、探测、预热和取消都不能恢复节点；取消会保留事实 RX。原始 cell 和父节点 incarnation 仍然是权威。

只有真正改选其他叶节点的普通逃逸，才能压过可选验证。失败现任如果仍是普通赢家，可执行的备选仍能在预算内试探；失败、退避和额度检查继续生效。

现任已经训练、合格并恢复后，评估集里所有合格挑战者都要和这个固定的现任比。晋升证据单独维护。优先用双方的精确目标观测；没有时，按规范顺序挑至多八个双方都响应、且挑战者已合格的共同目标，等权比较；再不然就用同一个当前配置探测 cohort。先检查支持资格，再套用目标数量上限，不能按测量值好坏挑目标。方向指标必须在同一组已选响应目标上一起合格，未知方向仍然是未知。跳过尚未合格、或因上限被截断的已匹配共同目标时，比较保持部分覆盖：已合格的子集仍能用于晋升和只读关系，但该成员的响应缺口仍待解决。没匹配上的目标，以及没有保留共同时间块的目标，不属于这次比较的 cohort。

业务比较保留四个共同的 15 秒块，各自在块起点后 60 秒到期。配置探测携带生产者的实际周期 `I`，块宽是 `max(15s, 2I)`，仍然只保留四块，于是正常的 30s／60s 周期不必提高探测频率也能攒到四个独立 reporter。探测支持到期时间取两者中较早的一个：最早支持块的起点加四倍块宽，或者较弱一侧最近一次支持加 `max(60s, 2I)`。未知周期沿用业务时间规则；周期为零或无法表示时不产生比较证明。周期和配置请求一起组成探测身份，每个指标仍要求双方各有四个不同 reporter。无关的聚合均值、setup 和预热不算证明；失败、reload、incarnation 和探测 cohort 边界继续生效。

分方向 goodput 只有在以下条件都满足时才贡献优势：某个已知方向至少提升 10%；其他已知方向都没有退化超过 10%；响应没有慢超过 10%；而且合格的终态可靠性不低于现任。未知的上传或下载仍然是未知，不当成零，也不算胜出；已知方向一升一降会报告为权衡。合格的实际可靠性优势和成对响应优势仍参与比较。综合优势必须跨过已有的保持门槛，上限仍是 `0.005`。支撑量取全局、地址族、精确完成数各自衰减后的最大值，不能相加。稀疏的精确证据不会削弱成熟保护。性能缺失或过期本身不构成优势；保持现任不等于确认它可用，也不阻止在预算内试用，而且不新增固定的驻留时间。

`ScoreFeedback` 是不可变的归属和来源工厂；每次启动产生独立观测，clone 的含义不变。已选的业务计划持有 `ScoreAttempt`，它的 `begin()` 可以失败，成功后返回唯一的、已通过 admission 的 `ScoreBusinessGuard`。guard 负责取消清理，直到在既有的物理或逻辑 I/O 起点把所有权交给 `ScoreReporter`。setup 和首响应按事件时间各发布一次。TCP 已接受的写入、UDP 已成功发送和交付的进展，进入互不重叠的 1–10 秒事件驱动窗口。被测方向至少要传输 64 KiB，流还要有双向进展和响应；这个窗口不增加 Beta 成功次数。终态最多结算一次，不会重复加入已发布的字节；最后一个未完成 handle 释放时取消。拒绝、取消和关闭只撤销 attempt，不制造失败，已经实际发生的观测会保留。空闲或应用层限速不是拥塞证据；不新增采样任务、负载重放或连接迁移。

Score 权限切换之前捕获的普通待开始尝试，只要不持有可选 token，就可以继续转发，但不评分。guard 保留原始业务身份，不发布当前证据，也不发额度。失效的可选工作仍会被拒绝，不能降级成免费的挑战者拨号。物理 runtime admission、路由和类型化拒绝的语义都不变。

TCP relay 在 copy 和 splice 路径中区分客户端断开与上游失败。客户端侧的 reset、abort、broken pipe、未连接 socket、异常 EOF、socket 超时或主机／网络不可达错误，对 Score 按中性取消结算，不撤回已接受的 RX，也不清除既有失败／退避；relay 仍返回原始 I/O 错误，连接错误统计保持不变。同类上游错误、协议错误及未明确归因的本地失败保留既有失败处理。日志级别较低本身不代表错误中性。

业务 RX 上报独立于吞吐窗口：首次合格非零 RX 立即发布，随后每个 reporter 每秒至多一次。普通单向 TX 回调不补发被限频的接收事件，也没有定时器把静默变成进展。共享源首次确认成功的非零发送可补认其串行发送开始后已交付的回包，使用实际 RX 时间而非确认时间；排队、失败或已退役的发送不能授予证据。限频中的失败后 RX 仍可能等待下一次可发布 RX 或终态，不保证一个自然秒内恢复。活跃发布更新可用性及作用域内恢复门槛，不增加 Beta 终态。

共享源 witness 描述的是传输尝试区间，不是 UDP 请求与回包的逐包关联：匹配的 peer 可能在此区间内返回延迟数据。时间点记录在通过 core source gate 后、backend 队列 admission 前，只有发送成功获接受后才可用于证据；它不证明是哪一个 datagram 导致回包。

可选工作在节点专属工作开始时记账，早于 DNS 和物理拨号 admission 等待；这与业务 reporter 的边界不同。带拨号 admission 作用域的 TCP 拨号，在首个物理尝试获准后，或复用 session/QUIC 连接上的逻辑 open 开始前启动 reporter；等待冷物理拨号 admission 时不启动。回调只执行一次；未经过这两个边界便已完成的路径保留完成时的兜底回调。

尚未开始工作的作用域，只有仍在等待物理拨号 admission 时，超时才属于本地容量拒绝。admission 前的 DNS 解析超时仍是普通超时，保留既有的合格候选重试路径。分类先检查作用域，再取消 future；取消只移除该次申请的待 admission 登记。

普通路径和 race 后的 TCP ready/bare 补池仍记录 setup 质量，但其成功与失败都不改变真实流量的连败计数或探索退避。UDP driver 在自己的健康回调可能同步退役 endpoint 之前判定终态，避免该回调把错误改写成中性的取消或成功。主动退役在没有回包时保持中性，已有回包时计为成功；进程关闭和单包拥塞保持中性，回包空闲到期仅在从未收到回包时计为超时。

对仍存活的 endpoint，已证明的 QUIC 通路停滞会退役共享 carrier，因此 Score 按节点故障归因，即使当前错误属于单包拥塞或已有回包后的空闲到期。拒绝、主动退役和本地回包交付取消保留原有优先级；Alive 仍独立分类原始 I/O 错误。

Traffic reporter 覆盖透明 TCP/UDP、受支持的 DNS exchange 和 UI 下载，DNS 归因跟随实际 carrier，包括 UDP 截断后的 TCP 重试。`HealthProbe` 只在全局聚合探测槽记录配置测量质量，不结算业务可靠性或清除真实连败；`Warmup` 只记录 setup 质量。按需 delay 测量保留 API/Alive 延迟历史，但不创建无消费者的 Score exchange reporter，也不把任意目标失败计入真实拨号序列；实际 session 准备仍可报告预热质量。独立 QUIC 握手提供 DataUdp 探测质量和既有存活性恢复，不虚构吞吐或业务成功。

每个保留的 `(group, TCP/UDP, target family)` 预算固定两件事：首次成员数 `n`，和冷启动额度 `B`。成员不超过四个时 `B` 覆盖全部成员，否则取 `ceil(sqrt(n)) + 1`。额度从原始业务里赚：每开始一次原始业务，计数为 `N`，额度增加 `1/q`。通常 `q = 16`。如果该组在这个网络上的近期原始业务按五分钟半衰期折合每秒至少两条，并且该作用域近期至少有三个可选试用结果，按十分钟半衰期、衰减权重超过 2.5，其成功不低于 80%，那么 `q = 8`。证据需要的试用次数是固定的，所以试用有效的繁忙组能更快攒到额度，空闲组则保持较小的比例。目标拒绝不计入这里的试用结果，reload 会清除这些结果。

普通选择处于 observedUsable，并且本次读取涉及的每个作用域近期结果成功率都低于 20% 时，可选试用暂停。近期失败达到两次及以上时，等失败衰减；只有一次时，每次只放行一个试用。暂停的作用域拒绝试用，效果和额度耗尽一样：每个被拒绝的候选计入 `budgetBlocked`，以 `budget` 等待呈现，已有试用在途的成员仍显示 `inFlight`。没有可用的选择时，探索继续进行，因为这是 Score 脱离故障的途径；恢复性延续不受影响。

设已赚额度为 `E`、已花费的可选试用为 `V`、未开始的预留为 `R`，始终满足 `V + R <= B + floor(E)`；未花费的已赚额度最多为八。`N` 包含被选为试用的原始业务，但重试、clone、嵌套重复计数、读取、时间流逝、证据过期和新目标都不能产生额度。一次原始计划经过的每个作用域只计一次；延续尝试即使进入其他组、网络或目标地址族，也不能再次赚取额度。根业务计数对整个嵌套路径去重。保留作用域在成员变化和 reload 后仍持有额度；只有删除组或重启才结束这段生命周期。

reload 后，已开始的试用仍结算历史结果与成本计数。只有 `(group, node)` 仍是当前配置成员时，其结果才影响当前试用收益；已移除成员不能暂停或加速替补成员的额度赚取。保留成员仍可跨 authority 变化贡献结果。

预留只在节点专属工作开始时支出；释放最后一个未开始引用或使未开始预留失效会退款，开始后取消不退款。reload 保留已开始工作的在途记录，直到结算或既有到期边界。UI 与订阅重定向、DNS 重试和 TCP 替代尝试保留原始业务身份，不能产生试用额度或把已有试用重标为免费恢复。可选工作只有一条路径：已授权的定向 rank 按派发顺序遍历已评估挑战者，为账本首个接受的成员预留一份额度；预算拒绝结束遍历，在途拒绝则尝试下一个成员。每个成员针对其未决问题在同一目标上至多有一个尚未得到回答的试用，资格问题跨目标计算。缺少流量时仍无结论。真实失败保留 5 分钟至 6 小时退避，除非真正的作用域内 RX 打开恢复；试用不取得已提交现任保护。

成员的未决问题只有一个，按下面的顺序取第一个成立的：

- 连败后的恢复；
- 没有近期可用性时的可用性；
- 成对问题。条件是普通选择本来能比较这个成员，但所选成员与它的原始比较对缺少本作用域的业务响应，而且该响应要新鲜、非部分，并且晚于所选成员最近一次退化。这里的本作用域，精确目标就是该目标本身，聚合读取则是共同目标；
- 以上都不成立时为资格。

配置探测不能解决成对问题。派发顺序先放没训练过的成员，再按未决问题的进展从多到少排；成对问题的进展，是与参考成员共享有效时间块的挑战者 reporter 数量。然后按最久未被选中排。从未被选中过的成员，用配置探测提示打破平局。近期顺序只在归属工作于 begin 时获准后推进，未开始、被拒绝或未计分的预案不改变顺序。除恢复外，只有完成数加上未完成工作仍少于所选成员完成数的成员才会被派发。首次选择跟随证据；先训练挑战者会挤掉探测优先的所选成员，所以冷启动探索要等所选成员取得一次完成后才开始。只读的 question、action 和 wait 取自同一顺序里的第一个成员；wait 只附加账本当前的预算或在途拒绝。节点来源明确区分失败时间与失效边界；借用的 cell stamp 统一当前父节点和有效 fence 检查，不增加缓存。

Carrier 压力提示独立于业务结果和性能评分。与 Score 绑定的 runtime 在 honk→代理服务器的物理连接上观测持续 TCP RTT／重传或 QUIC RTT／丢包压力，已有五秒心跳接收新鲜事件。提示只在既有验证频率、资格与退避约束内重新打开比较新鲜度问题，不改变 utility、资格、失败计数、Alive 或已有连接。晋升仍需真实业务观测支持。

采样使用 1–10 秒活跃区间，要求有新 ACK 进展，以及至少 4 KiB payload 字节进展或 32 个 QUIC DATAGRAM frame。RTT 先以四个活跃样本训练基线，再要求连续三个区间同时达到基线的 1.5 倍且增加至少 20 ms。发送侧重传／丢包压力要求足够出站 payload、至少 32 次发送、三个重传／丢失包、非零重传／丢失字节及 5% 计数比，连续满足三个区间。这只是压力启发式，不是应用丢包率，计数未必对应同一批包。未知／空闲区间不能证明压力或恢复；两个合格正常区间才能重新解锁事件。每个 runtime／carrier 地址族至多每 30 秒发布一次，提示在 60 秒后过期，读取不续期。

健康过滤地址族不一定是地址 race 最终使用的 socket 地址族。生产者保留实际地址族槽，Score 则把最新新鲜事件视为节点 owner 需要重新比较的提示，而非目标／地址族性能惩罚。只有被测 carrier 承载的网络接收提示，Shadowsocks TCP 压力不影响原生 Shadowsocks UDP。热连接上的配置探测可能贡献 carrier 活动，但不能成为业务证据。普通 UDP 丢包、裸 SOCKS／direct splice、反向丢包及代理到目标的丢包仍未知。reload fence 旧事件和已替换的 owner，不导出 carrier 或目标身份。

Score 状态随 manager 初始化，证据条目按需填充，由 mutex 保护且仅存于当前进程内存：精确 cell 使用 4,096-entry LRU，聚合 cell 使用另一个 4,096-entry LRU。精确目标证据衡量 transport 质量，并不是语义解锁 capability 的结果；需要这种粗粒度 cohort 时，可用已有 routing 或 geosite 规则选择专用服务 Score 组。已提交的进程内 reload 会复用同一状态 `Arc`、发布新的合法 `(group, member)` 集合并裁剪已删除 cell；已删除成员的迟到反馈会被忽略。进程重启会清空一切。Score 不提供调节项；评分 cell 与仅由 scorer 持有的目标数据不会进入日志、持久化存储或任何 API 输出，已有的 `/connections` 目标元数据保持不变。

独立比较存储最多保留 512 个 cell，逻辑记账分配上限为 1 MiB，包含存储／vector 容量及持有 key 的容量。这个界限不是进程 RSS：分配器开销、其他 Score 状态和进程其余部分均不在其中。淘汰或拒绝后，比较证据保持未知，不回退为无关均值。

中性 cell 保留在有界 LRU 中，不在其他 reporter 仍持有 incarnation 时提前删除。reload 清空配置探测基线并拒绝旧 generation 探测观测；已通过 admission 的业务流对存续成员和匹配 incarnation 仍可报告。淘汰后的旧 reporter 不能重建 cell。

#### 有条件的验证结论

默认目标是在已观测业务可用性的保护下比较响应质量，有可比证据时普通晋升才纳入分方向 goodput。转发仍立即选择。`provisional` 与 `observedUsable` 描述当前路径的业务证据；只读 `challengers` 另行报告所选成员与已评估挑战者之间新鲜的成对响应关系，不存在全组比较结论。10% 指标容差表示实际意义上的近似等价，不是误判概率，也不是全局最优证明。

关系不使用普通切换门槛或完成数成熟度，而是对实际响应值使用包含边界的对称 10% 容差（`high - low <= 0.1 × low`），支持零值和亚毫秒响应，边界只容许浮点舍入误差：落在容差内为 `equivalent`，否则响应更低的一方更快。关系读取所选成员的原始比较对（即普通晋升读取的同一批比较对），且只读取其中新鲜的合格响应指标；可靠性、可用性、分方向 goodput 与保持仍由普通选择负责。每项关系标明其依据，并随该响应指标到期。

比较对不需要联合对齐：每个挑战者与所选成员的原始比较对只按自身共享时间块判断，不同挑战者的历史之间不产生验证需求。不新增探测、不复制请求，也不保证任意负载下必然完成。

同一判定器识别可用性与响应证据缺口，安排下一次预算内真实流量验证，并生成只读 API 摘要。精确目标视图不会把共同目标或探测证据标为 `targetResponse`；HEAD/QUIC 成功最多支持其当前配置测量 cohort，不证明业务目标可用或持续带宽。`nextBusinessFlow` 表示未来真实工作需求，不是已预留或已派发 I/O；`question` 与 `waitReason` 区分证据问题，以及预算、在途、可比流量和退避等待。缺少传输证据不产生问题或工作：分方向 goodput 等待真实负载，不后台测速或复制用户请求。聚合读取检查已保留 IPv4/IPv6 预算的等待状态，不创建或花费作用域。

业务比较支持保留 60 秒边界，配置探测比较采用上述随周期调整的保留窗口与最近支持边界。业务失败与提交 reload 撤销近期可用性，但不清空长期可靠性。API 读取即时重算有效性，不推进采样或计数；已授权 Apply 利用既有有界历史记录临时、可用与验证选择。详见 [API 语义](../reference/api.md#score-验证信息)。

每个 Score 组／网络只拥有一个已提交的服务候选池，所有父组入口与 target 共用。普通首次选择、失败逃逸、恢复、晋升和可选试用都从池内选择，胜者不再额外占用一个名额。冷启动把普通首选纳入已排名名额，刷新排序先考虑普通资格，再比较 utility 与探测平局，避免未合格成员挤掉唯一可用服务。容量 k 仍随真实业务变化：原始开始数按五分钟半衰期衰减，再折算到 30 分钟证据半衰期；在 `q = 16` 下赚得的可选开始额度，一半用于让每个挑战者保持四个有效完成。记折算需求为 D，则 k = 1 + ⌊D/128⌋；超过四个唯一候选的视图下限为 3，上限为 min(25, ⌈√n⌉ + 1)，45 个候选时为 8。更小的组只使用实际可用成员。视图大于 k 时，从这 k 个名额中保留一个十分钟轮转位置。轮转成员被选为普通服务胜者时，与一个已排名成员交换位置，成员集合不变，被换出的成员获得新的轮转周期；不能仅因轮转到期就驱逐该服务胜者。该上限集中工作，但不保证足够的可比流量或全局最优选择。

只有已授权 Apply 初始化或刷新候选池。每五分钟重新排名一次；容量扩大等待该刷新，需求下降引起的收缩要求 k 至少下降 2。连续三次节点级失败或权威健康过滤可以提前换入替补，但不增加容量。仅在过滤／重试视图中暂缺，或某个精确目标失败，本身不会移除共享成员。没有替补时，失败成员仍可在预算内恢复。reload 重置成员与容量并保留衰减后的需求；Readonly／Peek 使用已提交成员，初始化前则使用临时有界投影。

嵌套名额保存直接子组名称，而不是可配置 UUID。该子组提供不同的合格代表节点时，Apply 在同一名额内替换旧代表；暂缺子组和直接成员不会被误判为代表发生变化。Selector 只 Apply 已选子组，即使子组当前已提交的 Peek 看不到成员，也不能阻断这次 Apply。Selector 父组不另建 Score 池或钱包；独立配置为 Score 的祖先仍拥有各自预算。

完整解析子组后仍无候选时，可以撤回该子组保留的名额，包括健康／capability 过滤及 Selector 固定选择不可用的情况；仅重试排除造成的缺席不能撤回。选择 IPv6 `final` 前，内部 IPv4 预检通过同一选择路径推导可能的候选池，但不提交池、不预留工作或更新计数。预检必须具有当前 authority，不改变公开 Peek 的语义。

每份尚未开始的策略选路尝试，都会在 begin 时、证据锁内、节点专属 I/O 之前重新检查其捕获的普通服务池义务。成员离池或池尚未初始化时，以类型化取消拒绝，并退还未开始的预留；过期普通计划和重试都不能把这种拒绝降级成免费工作。已开始的尝试与 relay 保留原有生命期及结算规则。新重试虽然沿用原始业务身份，仍须重新通过 admission。因此，活跃连接可能跨越已退出候选池的成员，k 不是所有存量连接所用节点的历史并集上限。

原生 pin 使自动代理组按 Selector 行事时，不为该 owner 附加普通 Score 池义务；原有 attribution 和嵌套普通 Score owner 的池义务仍须保留。即使多个子组别名共用叶节点，候选观测仍保留各成员的健康排除事实；Score utility 与资格原因只更新通过筛选的行。

显式 `final` 只豁免其所属组的普通候选池，普通选择该路径的 Score 祖先仍须约束叶节点。唯一 TCP 叶节点恢复路径也进入同一个池，不能借此改选未选中的 Selector 兄弟。独立健康探测和预热观测不属于策略选中的业务，保留原有作用域。探测基线仍可用；比较单元的 admission 跟随服务池成员，并保留四个近期 Apply 胜者及初始收集的既有例外。原有信用、身份和 TTL 规则不变。成员检查受 k 限制；池重新排名对候选排序，轮转则遍历一次。

近期失败排除会让不具普通资格的成员退出待验证，直到该失败早于性能证据期限。排除不表示该成员的指标已测得近似等价或无退化，分层权重衰减仍可能让它更早重新取得普通资格。响应退化会重新要求比较证据刷新，它只把 setup 或响应样本与同一精确目标的历史比较；聚合 cell 混合了延迟本就不同的目标，因此聚合比较只因 carrier 压力重新打开，不因跨目标差异打开。

近期可用性要求所选 cell 的连续可用性 cohort 中有四个不同的 Traffic reporter，每个都在 setup 和非零 TX 之后报告定向非零 RX；流尚未结束也能取得资格。每个 reporter 及其 clone 在同一 cell/cohort 内只计一次，后续合格 RX 仅刷新 cohort 的事件时间。这不表示四条当前仍打开的流，也不表示统计独立；全局／地址族／精确目标的重叠计数不能相加。探测、预热、单向 TX，以及早于 setup/TX 的 RX 都不能取得可用性证据。

适用失败、提交 reload 或至少 60 秒的进展间隔会重置 cohort。一个恢复接收的 reporter 不能复活四份旧信用；存续 reporter 可在失败／reload 与 incarnation 边界内各贡献真正新增的 RX。终态与活跃上报共用去重，只按实际 RX 时间补发合格进展，不能使用清理时间或跨越已过期窗口。中性取消保留事实 RX 而不增加成功。可用性本身不授予冷启动资格；只有真正失败 cohort 的四个新 reporter 才能取得上述恢复 lease。资格和恢复缺口仍独立于比较支持接受有界试用。

一次已授权的多候选 rank 只增加一个最终原因：`coldExplore`、`periodicExplore`、`incumbentIneligible`、`freshFailureBypass`、`insufficientEvidenceHeld`、`directionalTradeoffHeld`、`incumbentHeld`、`reliabilityWinner` 或 `performanceWinner`。`insufficientEvidenceHeld` 表示没有挑战者获得晋升，且普通 utility 赢家缺少合格的共同性能比较，并不表示没有可靠性历史。`directionalTradeoffHeld` 表示无挑战者晋升时，存在已知方向一升一降的权衡。`ordinarySwitch` 独立统计同一 `(group, network, family, target)` 历史中的普通已提交 A→B 变更，不含首次选择和试用；`switchFlap` 是其中八次普通选择内返回前一赢家的子集。`deadFiltered`、`failStreakExcluded`、`exploreBackedOff` 累计受影响候选，不是失败连接数。历史仍是 4,096 项 LRU，缺失／淘汰历史不能证明发生了切换。Peek、proxy/stat 读取、单例旁路和最后尝试不增加这些原因计数。经认证的 `/stats.score` 导出固定组／网络原因、验证和预算字段，以及证据缓存总量，不导出 scorer 私有节点／目标／cell 身份。试用结果与耗时／setup 成本计数描述实际观测工作，不表示反事实额外失败或因果额外开销。

Clash 将 Score 组表示为 `type: "url_test"`，在 `now` 中报告当前聚合 TCP 胜者，并拒绝 `PUT /proxies/{name}`。

### URLTest 排名与滞后

延迟用减半递推移动平均：

`next = (previous + sample) / 2`

第一个样本直接把平均值初始化。这个算法沿用 dae 的 `min_moving_avg` 语义：近期变化能较快体现，单次抖动不会成为既定值。

`SelectionNetwork::Tcp` 和 `SelectionNetwork::Udp` 各自保留胜者。TCP 用 TCP 探测的平均值；组配置了自定义目标时，改用 `(member tag, check_url)` 的平均值。UDP 先用 `DataUdp`，再用 `DnsUdp`。如果在当前地址族下，所有合格候选在这两个域保留的移动平均值里都没有真实的 UDP 排名依据，就沿用 TCP 的选择。仅由拨号失败产生的合成样本不会让这个回退失效；真实样本被历史环形缓冲区淘汰后，保留下来的排名依据仍然有效。所以有效的回退顺序是 `DataUdp → DnsUdp → TCP`。

有效 tolerance 是 `max(configured tolerance, 1 ms)`，即 `group.tolerance.max(1)`。满足下式时保留当前选择：

`best latency + tolerance >= incumbent current measured latency`

当前选择的基线在每次选择时重新读取，不保留胜出时的旧值，所以已经退化的现任可以被替换；这与 sing-box 的 `Select()` 行为一致。现任如果带着未清除的失败标记，即 strike，就跳过滞后，立即替换这个刚失败的节点。

探测失败只更新活性和冷却，不产生合成延迟样本，也不记排名 strike。只有连续两次真实拨号失败，才会追加一个不显示的 10 秒合成占位样本，并记一次失败 strike。单次瞬时失败，也就是这条流量被重试 race 救回的那种，不留下任何选路状态。连续计数只在真实拨号成功时清零，所以探测活着但拨号失败的节点仍会继续累积失败。真实历史和移动平均都保留，但带有未清除拨号失败 strike 的候选会排在所有未降级候选之后。strike 只有连续 `max(strikes, 2)` 次真实成功后才会清除，避免不稳定节点靠一次探测成功就重新排到第一。

真实流量也会直接回馈排名，但只对 TCP 生效。每个节点为自己新鲜的拨号延迟维护一个自引用 EMA，α=1/8，前 3 次拨号算预热期。命中就绪连接池的拨号没有网络往返，不计入。连续 3 次拨号慢于 `max(min(2×EMA, EMA+500 ms), 250 ms)`，在 `report_dial_latency` 里写作 `max(min(2×ema, ema+500ms), 250ms)`，就记一次失败 strike 并触发紧急探测。250 ms 的下限是为了避免当前选中的低延迟节点因正常负载抖动误判，例如从 60 ms 变成 120 ms。探测的移动平均不受影响。误报，也就是目标分布变化而非节点变差，会自行恢复：紧急探测成功后，连续的探测成功会清除 strike。渐进式劣化仍由探测周期负责；UDP 劣化还是按探测周期加 `DataUdp` 流量阈值处理。

权威 URLTest 建立失败保留既有的一轮前三候选重赛。重赛的新 deadline 不会创建另一份原始 Score 业务，即使首轮在自己的 deadline 之后才结束。Score 所属建立失败则至多顺序尝试一个不同叶节点，在排名前排除失败 `NodeId`，不要求普通评分先改选。Score 两次尝试共享一个绝对建立 deadline 和物理拨号预算；规范解析保留 Selector 选择，只允许首选真正经过的 final 组边，显示名称不授权兜底。类型化本地拒绝、未通过 admission 时容量耗尽、取消和 generation 关闭均为终态；应用负载写入后不重试。

组的 `check_url` 会建立独立的 TCP-only 存活性和延迟状态，key 为 `(member tag, check_url)`。失败只会从使用该目标的组中排除该成员。Selector 组忽略 `check_url` 并打印 warning。URLTest 在超过 `idle_timeout` 后暂停探测；未设置时使用健康层默认的 30 分钟，下一次真实选择会立即唤醒探测。

## 嵌套代理组与成员身份

`Group.groups` 指定子组。每个子组只贡献一个候选：该子组策略针对当前网络和地址族选出的叶节点。父组将其作为一个成员排名或固定，不把所有后代合并进父策略。

解析受 `MAX_GROUP_DEPTH = 8` 和每次遍历的 visited set 限制。构造阶段还会对组边执行 DFS，切断每条形成环的边并打印 warning，防止异常组图阻塞选择或内省。

成员边与显式 `final` 边使用同一个有界递归解析器。子组策略没有合格选择时，
只沿自己的配置 final 继续；父组仍把该子组视为已选成员。Final 链保留选择链和
Score 归属。普通成员/展示列表不包含 final 边；健康注册、预热发现、Score 成员
和 datapath 连通性使用包含 final 的可达集合。叶节点健康转换会重算所有受影响
祖先的 alive slot，而不只更新首次映射到的一个组。IPv6 健康地址族重试会先选
可用的普通 IPv4 代理路径，再执行 final，业务目标地址族不变。缺失或成环的
final 仍然拒绝；这里不重试传输错误或终态 packet rejection。

Selector 在候选展开和健康过滤前绑定具体节点或子组成员；按名称配置的默认选择和 Clash 写入在节点 tag 重复时，按声明顺序绑定第一个匹配的 `NodeId`；原生成员 ID 可选择特定直接成员。服务选择只对已选子组执行 Apply，再检查父组健康条件；不预览未选兄弟，也不要求子组已提交的 Peek 必须先成功。TCP 与 UDP 的已选路径不可用时，都只能通过其显式配置的 final 继续选择。候选保留来源子组的引用，不再根据显示 tag 反查身份。选中的自动策略子组仍可在自己的成员范围内选择其他叶节点。唯一 TCP 叶节点的最后尝试遍历也遵守每一级 Selector 选择，而显式延迟测试仍可检查全部成员以发现恢复。

展示和 API 输出仍使用成员 tag；即使物理拨号落到更深的叶节点，实际选择也会单独保留具体节点或子组身份：

| API | 返回内容 |
| --- | --- |
| `node_names_in_group` | 直接节点 tag 加子组 tag |
| `leaf_node_names_in_group` | 该组下可达且去重的真实叶节点 |
| `delay_test_members` | 每个有效成员一个 `(member tag, current leaf)` 对 |
| `selection_chain` | 从组经已选子组到叶节点的当前链 |

自定义 URL 探测会在每个周期重新解析 `delay_test_members`。子组通过其当前选择接受探测，但结果记录在子组 tag 下。因此父组把子组视为一个稳定成员，符合 sing-box RealTag 语义。

## 冷启动 URLTest UDP 准备

只有没有可用测量值的顶层 URLTest 计划，才能准备多个 UDP transport。候选按绝对偏移 `0 ms`、`30 ms`、`80 ms` 启动，之后每隔 `80 ms` 启动一个，同时最多三个准备任务。绝对调度可以避免较早的慢任务把后面所有启动时间一起推后。

第一个成功且仍然合格的候选获胜。出现胜者或到达 deadline 时，honk 会在 scheduler 返回之前中止并排空所有已启动的 loser。随后它再次检查胜者资格，并在 endpoint 发布或发送第一个应用报文之前提交协议状态。只有已经观察到的准备 `Err` 会影响流量健康。未启动的任务、取消、已经变为不合格的成功结果，以及成功排空的 loser，都是中性的；排空时发现的已完成错误仍算已观察错误，会计数。AnyTLS 用调用者自己的 provisional pool slot，所以 loser 不会发布 session。QUIC 协议构建 detached client，只发布最终胜者；loser client 连同它的推测任务一起关闭。

权威单节点计划和冷启动 URLTest 共用一个绝对的 transport preparation deadline：`max(10s, 4 × connect_timeout)`。它在前面的准备开始前就建立，覆盖代理主机名解析、物理拨号 admission、协议／控制协商、stagger 等待、满三个任务时的容量等待，以及最终胜者的 commit；到期后不再启动新候选。此前的嗅探／路由，以及之后的 reply socket 创建、endpoint driver ready 和报文发送，不在这段 deadline 之内，继续按各自的生命周期或 I/O 上限处理。

## 健康状态与探测

`AliveDialerSet` 使用节点 `NodeId` UUID 作为节点健康状态、注册、历史、紧急触发器与延迟集合的 key。显示名只用于日志和探测查找，不是身份。每个节点有六个独立状态：三个域分别覆盖 IPv4 与 IPv6。

| 失败来源 | `Tcp` | `DnsUdp` | `DataUdp` |
| --- | ---: | ---: | ---: |
| 周期探测 | 3 | 3 | 3 |
| 真实流量 | 10 | 3 | 50 |

探测失败和流量失败各有独立的计数器。探测失败用 5 秒到 300 秒的指数冷却。另有一个 `min(5s, check_interval)` 的恢复调度器，只检查冷却已到期的死亡域和地址族；深度退避的状态仍按 300 秒节奏继续探测，不会永久停掉。

周期检查用 `Tcp`/IPv4 和 `DataUdp`/IPv4 的冷却分别决定 TCP 探测和共享 UDP 探测的 admission。TCP 还在冷却，不会阻止已经到期的 UDP 探测。派发时两个条件都还没出冷却的节点不会创建 worker，留到后续周期再查。只做 TCP 的紧急探测只清除节点的 TCP IPv4/IPv6 冷却，两个 UDP 域的冷却保留。

作为对比，Go 版 dae 用 TCP=1，一次短暂的探测丢包就会在 URLTest 选择前把当前节点从候选集里移出，绕过 tolerance 滞后。

死亡状态通常需要连续两次探测成功才能恢复。相关链路、地址或路由变化后，`notify_network_change` 会清除旧冷却、预置死亡状态并触发探测，使一次新的成功即可验证恢复。新注册节点有 60 秒宽限期；其间非强制失败会写入记录，但不计入死亡。探测历史为每个节点、域和地址族保留 100 条。

| 探测路径 | 行为 |
| --- | --- |
| TCP | 通过节点向 `tcp_check_url` 发送配置的 HTTP 方法；HTTP 探测不适用时，改成裸 TCP 连接。`ProxyHttpProber` 把 HTTP 执行交给 outbound 的共享测量路径。只有 `NodeRuntime::is_warm_or_stateless_for(WarmRequirement::Session)` 成立时才复用 runtime，否则探测结束后关闭 guarded cold runtime。只有成功的 warm-path RTT 会进入对应 TCP 地址族的状态；setup 和目标交换失败只更新 liveness/cooldown，不贡献 latency，也不记 ranking strike。 |
| UDP 健康 | 通过节点的 packet path，向第一个 `udp_check_dns` 目标发一个最小的 DNS query。它单独检查 `NodeRuntime::is_warm_or_stateless_for(WarmRequirement::Udp)`；这个 requirement 没有预热时，探测结束后关闭 guarded cold runtime。成功时记录 RTT，并把 `DnsUdp` 和 `DataUdp` 标为存活。失败时给两个 UDP 域各加一次 probe failure，除非同一周期里独立的 Score QUIC handshake 成功；那种情况下只让 `DnsUdp` 失败，`DataUdp` 保持存活。它绝不改动 TCP state。 |
| Score QUIC 质量 | 每次周期性 UDP 探测，都会通过每个 Score 叶节点单独做一次 ALPN 为 `h3` 的真实 TLS-in-QUIC 握手，目标是第一个配置的 `global.tcp_check_url`，而且必须是有效的 HTTPS URL。测得的时长提供独立的 `DataUdp` 探测质量，既不增加业务成功，也不虚构吞吐；DNS 探测失败、但握手成功时，仍可恢复 `DataUdp` 活性。没有 URL，或 URL 不是 HTTPS 时，这个探测禁用；非 Score 的叶节点既不建这次握手，也不建 Score cell。 |
| 按组 URL | 用和全局 TCP 探测相同的临时暖路径计时，探测动态解析出的 `(member tag, current leaf)` 对。状态是 TCP-only，连续三次失败即死亡，冷却和恢复规则同上，连续两次成功才恢复。reload 时 `sync_group_check_urls` 替换有效的组/URL 注册表。 |

`has_udp_state(node)` 用来区分两种情况：节点从没观察过 UDP，以及节点已被明确观察为死亡。对普通 endpoint，终止性的 send/receive error，以及从未收到 reply 时的 idle expiry，会在 driver 捕获到 terminal 的 per-flow Score outcome 之后上报 `DataUdp` failure。对来源共享协议，transport health 由 source owner 报告，每个绑定 endpoint 仍保留并结算自己的 Score reporter；匹配的 reply 属于对应 endpoint，外来的 reply 没有 flow Score owner。source 的 terminal event 会退役它的 endpoints，并把 terminal outcome 分发给这些流。

类型化 policy、size，以及 `PacketRejection::Capacity` 拒绝，对候选都是 terminal，但不影响 health 或 Score；CLI 调用方收到的是 capacity error，不是 `NotApplicable`。单包拥塞、已有 reply 之后的 idle expiry、主动退役、节点死亡取消和进程关闭，也都不影响健康。alive→dead 转换会调用带 `(NodeId, name)` 的控制面回调，清除 pool connection 和 UDP endpoint。同族的另一个 UDP 域已经明确存活时，就跳过这个 UDP 域的死亡清理，避免被阻断的 `:53` 探测把正常流一起清除。

每个节点最近一次真实 TCP 延迟样本每 60 秒写入状态数据库；启动时只恢复不超过 24 小时的样本。存活性不从缓存恢复。合成的 10 秒占位样本带标记，不出现在历史里，不进入移动平均，也不会当作最近真实样本持久化。选择降级由失败 strike 计数负责，与占位样本无关。

- `src/alive/` API 包括 `register_node`、`notify_check_*`、`report_*_traffic` 和 `record_dial_failure`。组表和 `(member tag, check_url)` 状态仍以名称为 key，因为组没有 NodeId、成员可能是子组，即 sing-box RealTag。`mod.rs` 负责状态、阈值、registry 和 eBPF 连通性推送回调。`probe.rs` 负责 HTTP/raw-connect 的 `probe_node`，以及经 `dial_udp_transport` 的 DNS `probe_node_udp` 测量。`runner.rs` 负责健康检查的 admission、取消和排空，并发探测周期，以及周期、恢复、紧急三种探测循环。`collection.rs` 负责 `DialerCollection` 的延迟、移动平均和拨号失败追踪。`latencies.rs` 用操作复杂度 O(1)、容量 10 的环形缓冲区，测量的 `SystemTime` 提供真实的 Clash 历史记录时间。`last_real_sample()` 会排除合成条目，免得仪表盘显示虚构的 10000 ms。

`honk-outbound/src/urltest.rs` 负责 HTTP 请求构造和测量，URL 解释委托给
`honk-config::check` 的规范解码器。core 和 generation URLTest 还共享显式的冷
session 预热，并在创建资源或反馈之前保留一个可以失败的节点 admission；独立工具调
用保留 handler 内部的 setup 和 CLI 外层的 deadline。请求使用不含凭据的 authority，
只保留非默认端口，去掉 fragment，原始路径、查询串和点段照旧；只有查询串的 URL 写
成 `/?query`。HTTPS 会验证证书并协商 `h2,http/1.1`，禁用 server push。第一轮用
HEAD，第二轮用配置的方法，delay 测试是 HEAD；两轮最终响应的解码状态都必须是有效
的 200–499。HTTP/1 会在同一轮内先消费临时响应头再读最终响应，但不支持协议切换；
每轮响应头累计上限 16 KiB。HTTP/2 的响应头列表用同样的上限。

HTTP/2 探测连接遇到第一个本地检测到的协议错误就终止，避免后面的远端 reset 盖掉已
经拒绝的响应头错误、误触发首轮样本回退。已取消流的记录保留窗口是每轮超时的两倍，
覆盖两轮请求的预算，迟到的合法 warm 流帧仍可忽略。每次探测最多保留两条流记录；完
成或取消时随连接释放，不等记录过期。

报告值是第二轮热路径的 RTT，不含代理拨号、目标 TLS 和 session 准备。第二轮传输失
败时可以返回已验证的第一轮样本；HTTP/1 要求没有部分响应，HTTP/2 接受正常的
GOAWAY 或远端 `REFUSED_STREAM`，畸形或部分响应仍然算失败。冷可复用探测会关闭
guarded runtime，HTTP/2 driver 在完成或取消后停止。准备、拨号、TLS、HTTP/2 启动
和每轮请求各有阶段预算，core 保留连接超时。delay URL 留空时用
`https://www.gstatic.com/generate_204`。健康调度由 `alive` 负责，只有真实流量会
增加拨号失败 strike；组 delay 的并发上限仍是 10。API 返回的首轮预热回退值不会作
为配置方法的 Score 证据发布；只有成功测得的第二轮才更新该方法的质量 cohort。

## UDP 候选资格

`filter_alive_candidates` 按节点和地址族决定 UDP 选择：

- `DataUdp` 存活或 `DnsUdp` 存活：可选择。
- 两个 UDP 域都明确死亡：排除，即使 TCP 存活。
- 从未记录过 UDP 状态：继承 TCP 存活性。

TCP 健康但 UDP 已失效的节点不再接收报文流，尚未启用 UDP 探测的部署不受影响。

## eBPF 连通性发布

eBPF alive slot 属于组，不属于单个节点。对每个域和地址族，发布值取所有可达叶成员状态的 OR，并保留一个 TCP admission 例外：组里恰好只有一个唯一叶节点，且没有配置 `final`。单个节点状态转换触发的回调会重新计算该组的值，绝不直接写正在转换的节点自己的值。admission 不覆盖用户态选择：即使 slot 仍存活，选中的空 Selector 路径仍会拒绝流量。

reload 先把旧组或新组布局需要的所有 slot 置为存活，让转换期 fail-open。发布新路由 generation 后，honk 再写入精确的新组快照。这样组重排不会继承过时的 ordinal 状态；精确发布中途失败时，还没填的转换 slot 保持 fail-open，不会错误地把某个组标成失活。

## 预热与所有权

预热有三个相互独立的机制：

| 机制 | 候选与生命周期 | 保留资源 | 边界 |
| --- | --- | --- | --- |
| 启动预连接 | 仅在启动时运行一轮；先取各组当前选择，再按配置顺序。只有可池化裸 TCP 的代理节点合格。 | 向池中存入一条服务端裸 TCP 连接 | `'auto'` 最多选择 8 个节点；`0` 关闭。它不持有策略 retention bit。 |
| Selector 固定 | 追踪每个 Selector 的 TCP 配置选择叶，包括不健康的显式选择；共享叶按 UUID 去重。UDP 预热另按 UDP 选择。 | TCP path 选择的可复用 session（AnyTLS 或 VLESS H2/shared Mux.Cool）、一个 QUIC client/connection，否则一条服务端裸 TCP | 有效选择变化会立即唤醒；10 秒周期修复丢失、已消费或已过期状态。 |
| UDP 预热集 | 需显式启用；每轮对每个地址族重新选择各组 top `min(N, 3)` 的可复用 UDP 叶节点，再按 UUID 全局去重。 | UDP path 选择的可复用状态，包括 VLESS H2/shared/separate Mux.Cool pool，或一个 QUIC client | 最多并发 4 个预热尝试；进程保留集会重新排名并封顶 `4 × N`。 |

Selector 和 UDP ownership 是 reusable node runtime 上两个互相独立的 bit。
`WarmRequirement::Session` 跟随 TCP path，`WarmRequirement::Udp` 跟随 UDP path。
所以只有 UDP 的 VLESS pool 不会改变 direct-TCP warming 或 bare-TCP eligibility。
移除一个 owner 时，另一个 owner 仍可保留共享 pool；最后一个适用的 owner 释放后，
才停止后续复用并排空资源。active 流不会被切断，启动预连接只往池里放初始连接。

reload 时，配置没变的节点把现有 `NodeRuntime` 转给 replacement，包括 AnyTLS、
VLESS pool/source key 和 QUIC 状态；配置变了的节点得到 fresh runtime。现有
outbound maintenance pass 会和其他 idle resource 一起回收未受 retention 的 idle
VLESS carrier，不创建新的 protocol timer。

原生探测固定成员到叶节点的 association 以及 generation owner，不推进策略状态。实际的 TCP-connect、HTTP 和 TCP/UDP DNS 测量保留传输协议、用途、地址族和冷热状态；过期或取消的结果不发布新的健康状态。探测、geodata 和共享下载使用配置的目标，不设地址或端口白名单。谁能写配置、谁控制订阅内容，谁就决定这些目标；provider 内容属于可信的配置。探测仍然固定解析出来的 IP。参见[有界探测](../reference/api.md#有界探测)。

## 拨号 admission 预算

`max_concurrent_dials` 默认为 64，并为物理代理连接和协议握手各创建一个 generation-local semaphore。配置值会被启动时算出的不可变进程级描述符 gate 限制。reload 可以改动替代 generation 的本地上限，但重叠的新旧 generation 仍共享同一个进程 gate。

Ready 池命中和已预热 generation 传输上的逻辑流不占额度。`block` 不会拨号；`DirectHandler::dial` 和其他物理连接一样经过 `admit_physical_dial`。已经卸载到数据路径的直连流量，以及通过标记 HTTP 客户端直连的 UI 下载，不使用这个 handler 的 admission gate。裸 TCP 池命中仍要执行协议握手，所以仍受拨号预算 admission。

每条 VLESS 物理 carrier 还要从启动时确定的进程 carrier gate 取得 permit，reload
generation 和 DNS fork 共用这个 gate。permit 跨越 provisional、active、draining
和 idle carrier I/O，一直持有到 task teardown。这个全局 gate 就是权威边界；
Mux.Cool 不再叠加逐节点两 carrier 的限制。

## 相关文档

- [出站设计](./outbound.md)
- [控制面设计](./control-plane.md)
- [组参考](../reference/groups.md)
- [全局参考](../reference/global.md)
