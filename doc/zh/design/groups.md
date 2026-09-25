# 组选择、健康检查与预热设计

本文说明 honk 如何把组解析为叶子出站、跟踪其健康状态，并以有界方式保留预热资源。

## 范围

本文覆盖 `GroupManager`、`AliveDialerSet`、始终编译的 Score 评分器、冷启动 URLTest 准备流程与预热资源 coordinator。组字段和策略语法见[组参考](../reference/groups.md)；进程级健康检查、预热与拨号配置键见[全局参考](../reference/global.md)。

## 组管理器与选择流水线

`SharedGroupManager` 是稳定且可热切换的句柄：

`Arc<parking_lot::RwLock<Arc<GroupManager>>>`

重载会构建完整的替代 `GroupManager`，迁移组和成员 tag 仍然存在的 Selector 选择，在发布前安装连接中断、预热和持久化回调，再切换内部 `Arc`。因此读者只会看到旧管理器或新管理器，不会看到构建到一半的组图。

facade 与内部实现按职责拆分：

| 模块 | 职责 |
| --- | --- |
| `mod.rs` | `GroupManager` 类型、共享句柄与选择计划入口 |
| `resolver.rs` | 嵌套组展开、成员/叶节点内省、环切断与 Selector 选择迁移 |
| `filter.rs` | 按网络和地址族过滤存活性 |
| `policy.rs` | Selector、URLTest、LoadBalance、Fallback 选择与延迟排名 |
| `score.rs`、`score/selection.rs` | Score 共享状态、公开契约及按目标的组选择 |
| `score/ranking.rs`、`score/validation.rs`、`score/budget.rs` | 普通排名；验证需求／轮次／准入的单一所有者；保留的业务额度和在途记账 |
| `score/evidence.rs`、`score/feedback.rs` | 作用域结果／来源规则与 exact-once 观测所有权 |
| `score/comparison/`、`score/verification.rs` | 有界观测存储、成对／联合证明和只读结论；`score/tests/` 按职责拆分场景 |
| `state.rs` | URLTest/Fallback 缓存、Selector 选择与回调 |

选择遵循一个不变量：完成解析和存活性过滤后，拨号路径只使用策略选出的结果。Selector 返回其有效手动选择，URLTest 返回当前胜者，LoadBalance 返回下一个成员，Fallback 返回固定成员。唯一的多候选例外是尚无测量值的顶层 URLTest 组；已有测量值的 URLTest 和所有非 URLTest 计划都是权威的单叶节点计划。若未配置 `final` 的组只有一个唯一叶节点，且 TCP 存活性过滤将其排除，只有当前 Selector 选择路径能到达该节点时，才会将它作为权威的最后尝试：健康状态仍是 dead，但真实拨号可以证明恢复，且不会泄漏到其他成员或 `direct`。UDP 继续执行正常的存活性排除。最后尝试服务会记录限流警告（每组 60 秒）；预热 peek 保持静默。

UDP 选择首先排除规范协议／配置不支持 UDP 的转发叶节点，即使尚无健康观测也如此；TCP 存活不能让 VMess 或仅支持 TCP 的节点取得 UDP 资格。这些叶节点也不参与 Score 验证，发布组连通性时不能作为同时具备能力与存活性的依据。`block` 仍是终态动作；Selector 的已选节点不具备 UDP 能力时，只能按原有规则走显式 `final`，不能改选兄弟成员。VLESS UDP/443 拒绝等目标相关策略仍在准入处终止，不能靠候选过滤换路绕过。

## 策略语义

| 策略 | 运行时行为 |
| --- | --- |
| Selector | TCP 与 UDP 都不依赖健康状态，依次解析运行时选择、`default` 和声明顺序中的第一个成员；只有缺失或不再属于该组的 tag 才继续向后查找。该成员没有合格候选时，仅执行该组显式 `final` 或上述同一叶节点的 TCP 最后尝试；两者都不可用时计划为空。GroupManager 在每级嵌套中解析 final。Clash API 修改运行时选择。`PersistCallback` 把有效写入持久化到 `cache.db`；启用 `interrupt_connections` 时，`InterruptCallback` 只移除跟踪记录，不会取消正在运行的转发任务。配置诊断会对此限制发出警告。 |
| URLTest | 选择最小减半递推移动平均，分别保存 TCP 与 UDP 选择，应用 tolerance 滞后，并在拨号和选择查询时惰性重算。真实选择变化可以调用 `InterruptCallback`。 |
| LoadBalance | 按声明顺序轮询合格成员。每个组分别为 TCP 和 UDP 持有独立 `AtomicUsize` 游标。轮转从不调用 `InterruptCallback`。 |
| Fallback | 分别为 TCP 和 UDP 固定声明顺序中的第一个合格成员。该成员死亡前保持固定；更靠前的成员恢复不会触发 failback。 |
| Score | 以 `policy: score` 显式选择后，根据实际可靠性、新鲜目标质量和有界验证选择一个健康合格叶节点；历史样本数量不是性能加分。省略策略仍默认 Selector。 |

### Score 评分与生命周期

Score 首先运行与其他策略相同的存活性过滤。过滤所用的 health family 描述到代理服务器的连通性；单独携带的 target family 决定评分分桶。因此经 IPv4 到达的服务器仍可承载 IPv6 业务目标，而评分绝不会让已被判死的节点重新入选。健康过滤后的计划只包含一个权威叶节点；只有冷 URLTest 仍可按既有规则进行推测准备。

精确键为 `(group, TCP/UDP, target IPv4/IPv6, normalized target, NodeId)`。domain 会转为 ASCII 小写、去掉一个末尾点并保留端口；IP 目标保留 socket address。第二个有界的 `(group, TCP/UDP, optional target family, NodeId)` 聚合层为冷目标提供先验，并接收无目标预热样本。精确目标、target-family 和全局聚合层按衰减后的有效证据分层混合：精确证据增多时逐渐覆盖聚合证据，老化后又逐渐让出权重。递归选择携带同一 target context，并把叶节点结果归因到路径上的每个 Score 组。

目标路径失败仍计入全局／地址族／精确目标的数值结果，但只在精确目标上建立硬失败状态。类型化代理／认证／协议帧或共享 carrier 故障、setup 前的未知错误及无目标失败仍归为节点故障；setup 前明确的目标拒绝仍属于目标。节点故障隔离依赖它的目标和探测证据，无关目标失败不使配置探测失效，探测失败只撤销自身当前槽位。子 cell 继承节点 incarnation、失败时间和共享源事件身份；迟到 fanout 仍逐流计失败，但不能重新打开已恢复的同一事件。收到同一次分发的 carrier、源、packet endpoint 或共享拨号故障的每条流（包括同一 H2MUX 连接上的各流）都报告该故障唯一的事件身份；独立产生的故障仍各自计入。

Carrier 来源由实际拥有代理连接的边界标记，不能从通用 QUIC 错误推断：经过健康 packet 代理、连接已建立后的端到端 DoQ／DoH3 失败，不证明代理 carrier 失败。Packet-backed DNS endpoint 单独保留实际 adapter 故障，只在类型化 endpoint 丢失时附加该来源，不覆盖已缓冲的流重置、EOF 或畸形 H3 响应。Setup 前的未知失败仍遵循上述保守规则。H2MUX 流重置／用户态流错误仍属于单流，连接 I/O 与 GOAWAY 属于节点。AnyTLS 会话仍活跃时的 TCP SYNACK 超时属于目标，静默会话退役和 UoT 服务 open 失败仍属于节点。VMess 尚未收到任何响应头字节时的 EOF 含义不确定，保留为 I/O 失败；部分／畸形响应头及实际 carrier 错误仍保留节点来源。XUDP END|ERROR 关闭的是多目标共享源，绑定 flow 仍归因于共享源失败，不能虚构单一失败目标。

业务 attempt 与终态证据使用 30 分钟半衰期，setup 失败在 Beta 置信界中承担更强惩罚。首次资格要求四个有效 useful 完成。新鲜定向业务 RX 可将已取得资格保留到事件时间之后 60 秒，不增加完成数；失败与 reload 撤销租约。低于门槛的 RX 不能重新授予冷启动或仅 reload 失效的资格；真正失败后的恢复使用下述四 reporter 规则。历史可靠性继续影响 utility 和晋升；全局／地址族／精确目标重叠计数不相加，混合与保持成熟度仍使用实际衰减计数。

首次选择的性能启发式保留独立事件时间与四次观测封顶的 `WeightedMean` 惯性；各指标在 60 秒后降低置信度、120 秒时过期，不受历史完成数影响。配置探测 RTT 提供基线，新鲜且可比的目标响应和分方向 goodput 可以覆盖基线。探测 RTT、setup 与首响应分别在自己的测量范围内归一，不把不同含义的毫秒值混池。HTTP 探测身份包含规范化 URI 与方法，探测 domain 和健康地址族也分别隔离。这套启发式用于提出候选，不是晋升证明。

普通首次选择仍使用组内相对 utility，不合格或失败尚未恢复的现任可以立即逃逸。首个在 setup/TX 之后、严格晚于适用失败／reload 边界的合格定向 Traffic RX 清除探索延迟，但只允许有额度的半开验证。同一 cell 连续的失败后可用性 cohort 中，四个不同 reporter 清除硬失败事件并授予当前 60 秒资格租约，不清空历史失败，也不虚构终态成功。即使其他目标恢复了节点聚合层，每个精确目标仍需自己的四份信用；仅 reload 不能制造失败来源。只有 setup、单向 TX、探测、预热或取消都不能恢复节点；取消保留事实 RX。原始 cell 和父节点 incarnation 继续保持权威。

只有真正改选其他叶节点的普通逃逸才压过可选验证。若失败现任仍是普通赢家，可执行的备选仍能获得预算内试探；失败、退避和额度检查继续生效。

对于已训练、合格且已恢复的现任，评估集内的所有合格挑战者均与该固定现任比较。晋升证据独立维护：双方精确目标观测，否则按规范顺序选取至多八个响应支持已合格的共同目标并等权比较，或使用同一当前配置探测 cohort。先检查支持资格再应用目标数量上限，不能按测量值优劣挑选目标。方向指标必须在同一组已选响应目标上共同合格，未知方向仍未知。跳过尚未合格或因上限截断的已匹配共同目标时，比较保持部分覆盖：可以保留局部支持，但响应缺口仍待解决，不授予全组确认。未匹配目标及没有保留共同时间块的目标不属于本次比较 cohort。

业务比较保留四个共同 15 秒块，各自在块起点后 60 秒到期。配置探测携带生产者的实际周期 `I`，块宽为 `max(15s, 2I)`，仍只保留四块，使正常 30s／60s 周期无需增加探测频率也能积累四个独立 reporter。探测支持在“最早支持块起点加四倍块宽”与“较弱一侧最近支持加 `max(60s, 2I)`”中较早的时刻到期。未知周期沿用业务时间规则；零或不可表示的周期不产生比较证明。周期与配置请求共同组成探测身份，每个指标仍要求双方各四个不同 reporter。无关聚合均值、setup 与预热不是证明；失败、reload、incarnation 与探测 cohort 边界继续生效。

分方向 goodput 只有在某个已知方向至少提升 10%、其他已知方向均未退化超过 10%、响应变慢不超过 10%，且合格终态可靠性不低于现任时才贡献优势。未知上传／下载仍是未知，不视为零或胜出；已知方向一升一降会报告为权衡。合格的实际可靠性优势和成对响应优势仍参与比较。综合优势必须跨过既有保持门槛，上限仍为 `0.005`；支撑量取全局／地址族／精确完成数分别衰减后的最大值，不能相加。稀疏精确证据不削弱成熟保护。性能缺失或过期本身不构成优势；保持现任不等于确认可用，也不阻止预算内试用，不新增固定驻留时间。

`ScoreFeedback` 是不可变的归属／来源工厂，每次启动产生独立观测，不改变 clone 的含义。已选业务计划持有 `ScoreAttempt`，其可失败的 `begin()` 返回唯一的已准入 `ScoreBusinessGuard`；guard 负责取消清理，直到在既有物理／逻辑 I/O 起点把所有权交给 `ScoreReporter`。setup 与首响应按事件时间各发布一次；TCP 已接受的写入和 UDP 已成功发送、交付的进展进入互不重叠的 1–10 秒事件驱动窗口。被测方向至少传输 64 KiB，且 flow 已有双向进展及响应；窗口不增加 Beta 成功次数。终态最多结算一次，不重复加入已发布字节，最后一个未完成 handle 被释放时取消。拒绝、取消与关闭撤销 attempt 而不制造失败，已实际发生的观测保留。空闲或应用限速不是拥塞证据；不新增采样任务、负载重放或连接迁移。

Score 权限切换前捕获的普通待开始尝试，只有既不持有可选 token、也不绑定验证轮次 deadline 时，才可继续转发但不评分。Guard 保留原始业务身份，不发布当前证据或额度。失效的可选或轮次绑定工作仍被拒绝，不能降级为免费的挑战者拨号。物理 runtime 准入、路由和类型化拒绝语义保持不变。

TCP relay 在 copy 和 splice 路径中区分客户端断开与上游失败。客户端侧的 reset、abort、broken pipe、未连接 socket、异常 EOF 或 socket 超时，对 Score 按中性取消结算，不撤回已接受的 RX，也不清除既有失败／退避；relay 仍返回原始 I/O 错误，连接错误统计保持不变。同类上游错误、协议错误及未明确归因的本地失败保留既有失败处理。日志级别较低本身不代表错误中性。

业务 RX 上报独立于吞吐窗口：首次合格非零 RX 立即发布，随后每个 reporter 每秒至多一次。普通单向 TX 回调不补发被限频的接收事件，也没有定时器把静默变成进展。共享源首次确认成功的非零发送可补认其串行发送开始后已交付的回包，使用实际 RX 时间而非确认时间；排队、失败或已退役的发送不能授予证据。限频中的失败后 RX 仍可能等待下一次可发布 RX 或终态，不保证一个自然秒内恢复。活跃发布更新可用性及作用域内恢复门槛，不增加 Beta 终态。

共享源凭据描述的是传输尝试区间，不是 UDP 请求与回包的逐包关联：匹配的 peer 可能在此区间内返回延迟数据。时间点记录在通过 core source gate 后、backend 队列准入前，只有发送成功获接受后才可用于证据；它不证明是哪一个 datagram 导致回包。

可选工作在节点专属工作开始时记账，早于 DNS 和物理拨号准入等待；这与业务 reporter 的边界不同。带拨号准入作用域的 TCP 拨号，在首个物理尝试获准后，或复用 session/QUIC 连接上的逻辑 open 开始前启动 reporter；等待冷物理拨号准入时不启动。回调只执行一次；未经过这两个边界便已完成的路径保留完成时的兜底回调。

尚未开始工作的作用域，只有仍在等待物理拨号准入时，超时才属于本地容量拒绝。准入前的 DNS 解析超时仍是普通超时，保留既有的合格候选重试路径。分类先检查作用域，再取消 future；取消只移除该次申请的待准入登记。

普通路径和竞速后的 TCP ready/bare 补池仍记录 setup 质量，但其成功与失败都不改变真实流量的连败计数或探索退避。UDP driver 在自己的健康回调可能同步退役 endpoint 之前判定终态，避免该回调把错误改写成中性的取消或成功。主动退役在没有回包时保持中性，已有回包时计为成功；进程关闭和单包拥塞保持中性，回包空闲到期仅在从未收到回包时计为超时。

对仍存活的 endpoint，已证明的 QUIC 通路停滞会退役共享 carrier，因此 Score 按节点故障归因，即使当前错误属于单包拥塞或已有回包后的空闲到期。拒绝、主动退役和本地回包交付取消保留原有优先级；Alive 仍独立分类原始 I/O 错误。

Traffic reporter 覆盖透明 TCP/UDP、受支持的 DNS exchange 和 UI 下载，DNS 归因跟随实际 carrier，包括 UDP 截断后的 TCP 重试。`HealthProbe` 只在全局聚合探测槽记录配置测量质量，不结算业务可靠性或清除真实连败；`Warmup` 只记录 setup 质量。按需 delay 测量保留 API/Alive 延迟历史，但不创建无消费者的 Score exchange reporter，也不把任意目标失败计入真实拨号序列；实际 session 准备仍可报告预热质量。独立 QUIC 握手提供 DataUdp 探测质量和既有存活性恢复，不虚构吞吐或业务成功。

每个保留的 `(group, TCP/UDP, target family)` 预算固定首次成员数 `n`、冷启动额度 `B`（四个及以下覆盖全部，否则 `ceil(sqrt(n)) + 1`）和固定赚取周期 `q = 16`。原始业务开始数为 `N`、已花费可选试用为 `V`、未开始预留为 `R` 时，始终满足 `V + R <= B + floor(N/q)`；未花费的已赚额度最多为八。`N` 包括被选为试用的原始业务，但重试、clone、嵌套重复计数、读取、时间流逝、证据过期和新目标均不能产生额度。原始计划经过的每个作用域只计一次；延续尝试即使进入其他组、网络或目标地址族也不能再次赚取额度。根业务计数对整个嵌套路径去重。保留作用域在成员变化和 reload 后保持额度；删除组或重启才结束这段生命周期。

预留只在节点专属工作开始时支出；释放最后一个未开始引用或使未开始预留失效会退款，开始后取消不退款。Reload 保留已开始工作的在途记录，直到结算或既有到期边界。UI 重定向、DNS 重试和 TCP 替代尝试保留原始业务身份，不能产生试用额度或把已有试用重标为免费恢复。每个组／网络／地址族 cadence 至多保留一个绑定精确目标、固定对照与挑战者的验证轮次。普通比较先攒足剩余 reporter 需求，再交替提供不收费的普通对照与有额度的挑战者工作；初始冷可用性和单步恢复不必等待四份额度。只有新原始业务真正 begin 才推进轮次。每轮至多 45 秒、16 次匹配目标的选择机会或八次可选预留尝试，暂存等待也计入上限；失败、reload、incarnation 丢失或同目标对照变化也会使其失效。无关目标保留仍活跃或仍缺成对证据的已绑定焦点，但已终结的暂存工作及已完成／失效的已绑定轮次立即释放焦点，不必等待旧目标再次出现。缺少流量仍保持未确认，完成或无进展后按有界近期顺序轮转。真实失败保留 5 分钟至 6 小时退避，除非真正的作用域内 RX 打开恢复；试用不取得已提交现任保护。

验证分配与只读预算等待使用同一响应需求规则，包括已合格响应只需一份额度的刷新。验证模块区分暂存与已绑定轮次；准入在同一状态锁内重新检查待开始凭据和比较 fence，再支出额度。新接纳的硬失败在同一锁内取消受影响轮次，不必等待再次 rank 或 begin：节点失败覆盖任一轮次参与者及各目标地址族，目标失败只影响匹配的目标和地址族。重复共享 carrier 故障事件与无关目标失败不取消轮次。普通排名不再计算无人消费的展示等待。节点来源明确区分失败时间与失效边界，借用的 cell stamp 统一当前父节点及有效 fence 检查，不增加缓存。

Carrier 压力提示独立于业务结果和性能评分。与 Score 绑定的 runtime 在 honk→代理服务器的物理连接上观测持续 TCP RTT／重传或 QUIC RTT／丢包压力，已有五秒心跳接收新鲜事件。提示只在既有验证频率、资格与退避约束内重新打开比较新鲜度问题，不改变 utility、资格、失败计数、Alive 或已有连接。晋升仍需真实业务观测支持。

采样使用 1–10 秒活跃区间，要求有新 ACK 进展，以及至少 4 KiB payload 字节进展或 32 个 QUIC DATAGRAM frame。RTT 先以四个活跃样本训练基线，再要求连续三个区间同时达到基线的 1.5 倍且增加至少 20 ms。发送侧重传／丢包压力要求足够出站 payload、至少 32 次发送、三个重传／丢失包、非零重传／丢失字节及 5% 计数比，连续满足三个区间。这只是压力启发式，不是应用丢包率，计数未必对应同一批包。未知／空闲区间不能证明压力或恢复；两个合格正常区间才能重新解锁事件。每个 runtime／carrier 地址族至多每 30 秒发布一次，提示在 60 秒后过期，读取不续期。

健康过滤地址族不一定是地址竞速最终使用的 socket 地址族。生产者保留实际地址族槽，Score 则把最新新鲜事件视为节点所有者需要重新比较的提示，而非目标／地址族性能惩罚。只有被测 carrier 承载的网络接收提示，Shadowsocks TCP 压力不影响原生 Shadowsocks UDP。热连接上的配置探测可能贡献 carrier 活动，但不能成为业务证据。普通 UDP 丢包、裸 SOCKS／direct splice、反向丢包及代理到目标的丢包仍未知。reload 隔离旧事件和被替换所有者，不导出 carrier 或目标身份。

共享状态由 mutex 保护且仅存于当前进程内存：精确 cell 使用 4,096-entry LRU，聚合 cell 使用另一个 4,096-entry LRU。精确目标证据衡量 transport 质量，并不是语义解锁能力的结果；需要这种粗粒度 cohort 时，可用已有 routing 或 geosite 规则选择专用服务 Score 组。已提交的进程内 reload 会复用同一共享状态、发布新的合法 `(group, member)` 集合并裁剪已删除 cell；已删除成员的迟到反馈会被忽略。进程重启会清空一切。Score 不提供调节项；评分 cell 与仅由 scorer 持有的目标数据不会进入日志、持久化存储或任何 API 输出，已有的 `/connections` 目标元数据保持不变。

独立比较存储最多保留 256 个 cell，逻辑记账分配上限为 1 MiB，包含存储／vector 容量及持有键的容量。这个界限不是进程 RSS：分配器开销、其他 Score 状态和进程其余部分均不在其中。淘汰或拒绝后，比较证据保持未知，不回退为无关均值。

中性 cell 保留在有界 LRU 中，不在其他 reporter 仍持有 incarnation 时提前删除。reload 清空配置探测基线并拒绝旧代探测观测；已准入业务 flow 对存续成员和匹配 incarnation 仍可报告。淘汰后的旧 reporter 不能重建 cell。

#### 有条件的验证结论

默认目标是以已观测业务可用性为保护比较响应质量，有可比证据时才纳入分方向 goodput。转发仍立即选择，但选中不等于确认。`provisional` 与 `observedUsable` 描述当前路径的业务证据；`unconfirmed`、`equivalent`、`supported` 独立描述所标明依据的比较结论。10% 指标容差表示实际意义上的近似等价，不是误判概率，也不是全局最优证明；这里的置信度是经验性证据门槛，不是时间一致置信序列。

比较分类不使用普通切换门槛或完成数成熟度，而是对实际指标使用包含边界的对称 10% 容差（`high - low <= 0.1 × low`），支持零值和亚毫秒响应，边界只容许浮点舍入误差。资格和测量值不变时，增加完成数不会撤销响应支持。双方均合格时，优势一侧的已观测可靠性不得更差；响应明显更快可以在方向性取舍存在时取得支持，响应落在容差内时则可由合格可靠性或满足保护条件的方向 goodput 提供优势。所选成员必须至少优于一个已比较挑战者，且不存在合格对手优势；普通保持仍可能保留未取得该比较认证的成员。全范围等价优先于优势分类，真实测量之间的冲突也可能保持 `unconfirmed`，不表示缺少样本。

每个合格指标独立携带作用域与共同时间块身份。未合格传输样本，以及在已选共同目标交集中消失的方向，不会污染响应一致性。全 cohort 的方向结论需要该方向自己的完整一致支持；但第三个成员缺少某方向，不能掩盖另一对手已成立的成对优势。结论指纹和有效期包含所有实际参与判断的合格指标，包括方向保护和后续挑战者。

请求响应对齐工作之前，Score 仅对被覆盖的合格挑战者求新鲜共同时间块交集，并要求交集内双方各有四个不同 reporter；选择只依据身份、时间与资格，不依据测量值。合格联合支持可立即对齐不同的成对历史。可选成员不缩小此交集，也不产生缺失对齐的阻塞；其原始合格比较对仍在身份与有效期检查下贡献不利否决和区间。原始比较对也继续决定晋升，所有实际参与判断的合格支持都约束结论指纹与有效期。方向指标使用最终响应目标 cohort。被覆盖成员的联合支持不足时，请求有额度的响应验证；缺失比较对与部分目标覆盖仍明确保留。不新增探测、不复制请求，也不保证任意负载都能完成确认。

对于双方已经合格、但彼此时间块不一致的响应 cohort，复用已有的预算内近期顺序采样，而不是固定一个挑战者轮次。近期顺序只在归属工作于 begin 时获准后推进：未开始、被拒绝、重复或未计分的预案不算一次机会，不改变轮转。只集中刷新一对节点会反复产生互不重叠的时间块。每次获准的对齐试用只需一份可用额度，不重新等待攒满四份；普通转发提供对照观测。退避、在途上限、无关目标的现有轮次及证据资格／有效期均不变，真实负载不足时仍可保持未确认。

同一判定器识别可用性、响应和传输证据缺口，安排下一次预算内真实流量验证，并生成只读 API 摘要。精确目标结论不能继承共同目标或探测认证；HEAD/QUIC 成功最多支持其当前配置测量 cohort，不证明业务目标可用或持续带宽。`nextBusinessFlow` 表示未来真实工作需求，不是已预留或已派发 I/O；`question` 与 `waitReason` 区分证据问题，以及预算、在途、可比流量、传输和退避等待。未知传输对应 `awaitTransfer`，不后台测速或复制用户请求。`localComparison` 只描述活跃挑战者集合，不能将不完整覆盖变成全局比较。聚合读取检查已保留 IPv4/IPv6 预算的等待状态，不创建或花费作用域。

结论在最弱支持证据的期限到达时失效；作为依据的失败排除更早失效时相应提前。业务可用性和比较支持保留 60 秒边界，配置探测比较采用上述随周期调整的保留窗口与最近支持边界。业务失败与提交 reload 撤销近期可用性确认，但不清空长期可靠性。API 读取即时重算有效性，不推进采样或计数；已授权 Apply 利用既有有界历史累计确认、过期/矛盾、验证选择和确认耗时。一次确认可以仅指探测比较，业务仍处于临时状态；详见 [API 语义](../reference/api.md#score-验证信息)。

大组在由显式 NodeId 组成的有界集合内比较。容量 k 随真实业务变化：原始开始数按五分钟半衰期衰减，再折算到 30 分钟证据半衰期。在 `q = 16` 下赚得的可选开始额度，一半用于让每个挑战者保持四个有效完成；记折算需求为 D，则 k = 1 + ⌊D/128⌋，限制在 3–25（每分钟 46 条业务时约为 16）。视图大于 k 时预留一个轮转位置，按 NodeId 顺序访问其余成员，每位 10 分钟；排名先按首选 utility，平局再按主导配置探测延迟与 NodeId。较小视图仍使用显式有界身份，不能隐式放行全部成员。加上本次决策胜者，成员数至多为 k + 1。

只有已授权 Apply 初始化或刷新参与者，并将当前合格的排名成员纳入覆盖。最多每五分钟重新排名一次，扩大在刷新时生效，收缩要求 k 至少下降 2。过滤／重试视图中暂缺成员，本身不移除已保留身份或准入状态。已接纳业务反馈也在状态锁及既有有效性／incarnation 边界内，为已在排名中的成员锁存资格，包括终态与活跃恢复。准入状态在资格失效后仍保留，直到被排名移出或 reload。Readonly／Peek 使用已提交参与者，不重新排名或纳入成员；初始化前，仅冷启动配置探测可使用临时有界投影。初始已有合格成员的多节点结论，须等待 Apply 提交参与者。

当前基线存在合格成员时，覆盖包含所选成员与已准入排名成员；否则覆盖全部排名成员。此冷门控取决于当前状态，不是历史上曾经合格就永久开启。被覆盖成员必须已比较或已结清，且完整结论至少需要一个被覆盖挑战者。门控生效时，尚待首次资格的排名成员与轮转成员可接受可选工作，但不能阻碍完整性或联合对齐；其原始合格比较对仍可否决或贡献区间。准入后资格失效会重新打开结论，而不是缩小覆盖。

未评估成员不算作已比较、已排除或被击败，也不接受新的可选工作预留；挑战者离开评估集时，其轮次失去见证。此前已预留且未绑定轮次的工作，仍可在原 token、身份和 TTL 检查下开始；离开集合既不退还已开始工作的支出，也不产生免费工作。探测基线仍保留在统计中，比较单元通常仅接纳评估集成员，但最多四个近期 Apply 胜者，以及初始／尚无已初始化集合时的收集除外。普通首选、逃逸与恢复仍考虑全部成员。证明成员检查受 k 限制；重新排名为 O(n log n)，轮转则通过一次无分配遍历选取下一个身份。按时间推进的评估轮转与按 begin 推进的验证 recency 相互独立。

评估集覆盖在两种情况下无需配对即可结清成员：近期失败排除，或可靠性支配——该成员不具普通资格，它与所选成员都有四个有效完成，且它的实际可靠性更低。优势规则永远不会让这种对手取得优势。这种结清只限于具备资格的成员范围：未配对成员的指标不被视为已测得近似等价或无退化。只有双方都保持四个有效完成时才成立，其失效时间同时限制结论有效期；分层权重衰减仍可能让该成员更早取得普通资格，从而在该期限前撤销结论，这与已比较成员离开资格范围时的既有行为相同。被结清的成员保留既有恢复与验证试用，因此也可能仍在 pending 中。响应退化会重新要求比较证据刷新，它只把 setup 或响应样本与同一精确目标的历史比较；聚合 cell 混合了延迟本就不同的目标，因此聚合结论只因 carrier 压力重新打开，不因跨目标差异打开。

近期可用性要求所选 cell 的连续可用性 cohort 中有四个不同的 Traffic reporter，每个都在 setup 和非零 TX 之后报告定向非零 RX；flow 尚未结束也能取得资格。每个 reporter 及其 clone 在同一 cell/cohort 内只计一次，后续合格 RX 仅刷新 cohort 的事件时间。这不表示四条当前仍打开的 flow，也不表示统计独立；全局／地址族／精确目标的重叠计数不能相加。探测、预热、单向 TX，以及早于 setup/TX 的 RX 都不能取得可用性证据。

适用失败、提交 reload 或至少 60 秒的进展间隔会重置 cohort。一个恢复接收的 reporter 不能复活四份旧信用；存续 reporter 可在失败／reload 与 incarnation 边界内各贡献真正新增的 RX。终态与活跃上报共用去重，只按实际 RX 时间补发合格进展，不能使用清理时间或跨越已过期窗口。中性取消保留事实 RX 而不增加成功。可用性本身不授予冷启动资格；只有真正失败 cohort 的四个新 reporter 才能取得上述恢复租约。资格和恢复缺口仍独立于比较支持接受有界试用。

一次已授权的多候选 rank 只增加一个最终原因：`coldExplore`、`periodicExplore`、`incumbentIneligible`、`freshFailureBypass`、`insufficientEvidenceHeld`、`directionalTradeoffHeld`、`incumbentHeld`、`reliabilityWinner` 或 `performanceWinner`。`insufficientEvidenceHeld` 表示没有挑战者获得晋升，且普通 utility 赢家缺少合格的共同性能比较，并不表示没有可靠性历史。`directionalTradeoffHeld` 表示无挑战者晋升时，存在已知方向一升一降的权衡。`ordinarySwitch` 独立统计同一 `(group, network, family, target)` 历史中的普通已提交 A→B 变更，不含首次选择和试用；`switchFlap` 是其中八次普通选择内返回前一赢家的子集。`deadFiltered`、`failStreakExcluded`、`exploreBackedOff` 累计受影响候选，不是失败连接数。历史仍是 4,096 项 LRU，缺失／淘汰历史不能证明发生了切换。Peek、proxy/stat 读取、单例旁路和最后尝试不增加这些原因计数。经鉴权的 `/stats.score` 导出固定组／网络原因、验证和预算字段，以及证据缓存总量，不导出 scorer 私有节点／目标／cell 身份。试用结果与耗时／setup 成本计数描述实际观测工作，不表示反事实额外失败或因果额外开销。

### URLTest 排名与滞后

延迟采用减半递推移动平均：

`next = (previous + sample) / 2`

第一个样本初始化平均值。这就是 dae `min_moving_avg` 语义：近期变化能较快生效，同时不让单次抖动成为权威值。

`SelectionNetwork::Tcp` 与 `SelectionNetwork::Udp` 分别保留胜者。TCP 使用 TCP 探测平均值；若组配置了自定义目标，则使用 `(member tag, check_url)` 平均值。UDP 先使用 `DataUdp`，再使用 `DnsUdp`；如果在当前地址族下，所有合格候选在这两个域保留的移动平均值中都没有真实 UDP 排名依据，则沿用 TCP 选择。仅有拨号失败产生的合成样本不会停用这一回退；真实样本被历史环形缓冲区淘汰后，保留的排名依据仍然有效。因此有效回退顺序是 `DataUdp → DnsUdp → TCP`。

有效 tolerance 为 `max(配置值, 1 ms)`。满足下式时继续保留当前选择：

`best latency + tolerance >= incumbent current measured latency`

当前选择的基线在每次选择时重新读取，而不是保留它胜出时的旧值。因此已退化的当前节点可以被替换；这与 sing-box `Select()` 行为一致。若当前节点带有未清除的失败标记（strike），则跳过滞后——刚失败的当前节点会被立即替换。

探测失败只更新活性与冷却，不会产生合成延迟样本或排名 strike。只有连续两次真实拨号失败才会追加一个不显示的 10 秒合成占位样本并记一次失败 strike——单次瞬时失败（该流量由重试 race 救回）不留任何选路状态；只有真实拨号成功才清零连续计数，因此探测存活但拨号失败的节点仍会累积。真实历史与移动平均仍保留，但带有未清除拨号失败 strike 的候选排在所有无降级候选之后。strike 只有在连续 `max(strikes, 2)` 次真实成功后才会清除——这就是防止不稳定节点凭一次走运探测重回第一的防抖保护。

真实流量也会直接回馈排名（仅 TCP）。每个节点为自身的新鲜拨号延迟维护一个自引用 EMA（α=1/8，前 3 次拨号为预热期）；命中就绪连接池的拨号不产生网络往返，不计入。连续 3 次拨号慢于 `max(min(2×EMA, EMA+500 ms), 250 ms)` 会记一次失败 strike 并触发紧急探测；250 ms 下限避免快节点现任的正常负载抖动（如 60→120 ms）误触发判定。探测移动平均不受影响；误报（目标分布变化而非节点劣化）会自愈——紧急探测成功后，连续探测成功会清除 strike。渐进式劣化仍由探测周期负责；UDP 劣化保持探测周期加 `DataUdp` 流量阈值的处理方式。

权威 URLTest 建立失败保留既有的一轮前三候选重赛。重赛的新 deadline 不会创建另一份原始 Score 业务，即使首轮在自己的 deadline 之后才结束。Score 所属建立失败则至多顺序尝试一个不同叶节点，在排名前排除失败 `NodeId`，不要求普通评分先改选。Score 两次尝试共享一个绝对建立 deadline 和物理拨号预算；规范解析保留 Selector 选择，只允许首选真正经过的 final 组边，显示名称不授权兜底。类型化本地拒绝、未准入时容量耗尽、取消和 generation 关闭均为终态；应用负载写入后不重试。

组的 `check_url` 会建立独立的 TCP-only 存活性和延迟状态，键为 `(member tag, check_url)`。失败只会从使用该目标的组中排除该成员。Selector 组忽略 `check_url` 并打印告警。URLTest 在超过 `idle_timeout` 后暂停探测；未设置时使用健康层默认的 30 分钟，下一次真实选择会立即唤醒探测。

## 嵌套组与成员身份

`Group.groups` 指定子组。每个子组只贡献一个候选：该子组自己的策略针对当前网络和地址族选出的叶节点。父组把它作为一个成员进行排名或固定，而不是把所有后代合并进父策略。

解析受 `MAX_GROUP_DEPTH = 8` 和每次遍历的 visited set 限制。构造阶段还会对组边执行 DFS，并切断每条形成环的边，同时打印告警。这些检查可防止异常组图卡住选择或内省。

成员边与显式 `final` 边使用同一个有界递归解析器。子组策略没有合格选择时，
只沿自己的配置 final 继续；父组仍把该子组视为已选成员。Final 链保留选择链和
Score 归属。普通成员/展示列表不包含 final 边；健康注册、预热发现、Score 成员
和 datapath 连通性使用包含 final 的可达集合。叶节点健康转换会重算所有受影响
祖先的 alive slot，而不只更新首次映射到的一个组。IPv6 健康地址族重试会先选
可用的普通 IPv4 代理路径，再执行 final，业务目标地址族不变。缺失或成环的
final 仍然拒绝；这里不重试传输错误或终态 packet rejection。

Selector 在候选展开和健康过滤前绑定具体节点或子组成员；节点 tag 重复时，按声明顺序绑定第一个匹配的 `NodeId`。父组保留现有的子组 Peek、父组健康检查和服务提交顺序，不推进未选中 Score 子组的状态。TCP 与 UDP 的服务提交失败时都不能恢复之前 peek 的叶节点；只有显式配置的 final 可以继续选择。候选保留来源子组的引用，不再根据显示 tag 反查身份。选中的自动策略子组仍可在自己的成员范围内选择其他叶节点。唯一 TCP 叶节点的最后尝试遍历也遵守每一级 Selector 选择，而显式延迟测试仍可检查全部成员以发现恢复。

展示和 API 输出仍使用成员 tag；即使物理拨号落到更深的叶节点，实际选择也会单独保留具体节点或子组身份：

| API | 返回内容 |
| --- | --- |
| `node_names_in_group` | 直接节点 tag 加子组 tag |
| `leaf_node_names_in_group` | 该组下可达且去重的真实叶节点 |
| `delay_test_members` | 每个有效成员一个 `(member tag, current leaf)` 对 |
| `selection_chain` | 从组经已选子组到叶节点的当前链 |

自定义 URL 探测会在每个周期重新解析 `delay_test_members`。子组通过其当前选择接受探测，但结果记录在子组 tag 下。因此父组把子组视为一个稳定成员，符合 sing-box RealTag 语义。

## 冷启动 URLTest UDP 准备

只有没有可用测量值的顶层 URLTest 计划可以准备多个 UDP transport。候选按绝对偏移 `0 ms`、`30 ms`、`80 ms` 启动，之后每隔 `80 ms` 启动一个；同时最多有三个准备任务。绝对调度可避免较早的慢任务推迟所有后续启动时间。

第一个成功且仍然合格的候选获胜。出现胜者或到达 deadline 时，honk 会在 scheduler 返回前中止并排空所有已启动 loser；随后再次检查胜者资格，并在 endpoint 发布或发送第一个应用报文前提交协议状态。只有已观察到的准备 `Err` 会影响流量健康。未启动任务、取消、已变为不合格的成功结果以及成功排空的 loser 都是中性的；排空时发现的已完成错误仍属于已观察错误并会计数。AnyTLS 使用调用者所有的 provisional pool slot，因此 loser 不会发布 session。QUIC 协议构建 detached client，只发布最终胜者；loser client 与其推测任务一起关闭。

权威单节点计划与冷启动 URLTest 共用一个绝对 transport preparation deadline：`max(10s, 4 × connect_timeout)`。该 deadline 在准备开始前建立，覆盖代理主机名解析、物理拨号准入、协议／控制协商、stagger 等待、满三任务时的容量等待，以及最终胜者的 commit；到期后不再启动新候选。此前的嗅探／路由，以及之后的 reply socket 创建、endpoint driver ready 和报文发送不在此 deadline 内，继续使用各自的生命周期或 I/O 上限。

## 健康状态与探测

`AliveDialerSet` 使用节点 `NodeId` UUID 作为节点健康状态、注册、历史、紧急触发器与延迟集合的键。显示名只用于日志和探测查找，不是身份。每个节点有六个独立状态：三个域分别覆盖 IPv4 与 IPv6。

| 失败来源 | `Tcp` | `DnsUdp` | `DataUdp` |
| --- | ---: | ---: | ---: |
| 周期探测 | 3 | 3 | 3 |
| 真实流量 | 10 | 3 | 50 |

探测失败与流量失败使用独立计数器。探测失败应用从 5 秒到 300 秒的指数冷却。另一个 `min(5s, check_interval)` 恢复调度器只检查冷却已到期的死亡域/地址族状态；深度退避状态仍以 300 秒节奏继续探测，不会永久停止。

死亡状态通常需要连续两次探测成功才能恢复。相关链路、地址或路由变化后，`notify_network_change` 会清除旧冷却、预置死亡状态并触发探测，使一次新的成功即可验证恢复。新注册节点有 60 秒宽限期；其间非强制失败会写入记录，但不计入死亡。探测历史为每个节点、域和地址族保留 100 条。

| 探测路径 | 行为 |
| --- | --- |
| TCP | 通过节点向 `tcp_check_url` 发送已配置 HTTP 方法；不适用 HTTP 探测时执行裸 TCP 连接。`ProxyHttpProber` 将 HTTP 执行交给 outbound 共享测量路径；只有 `NodeRuntime::is_warm_or_stateless_for(WarmRequirement::Session)` 才复用 runtime，否则探测后关闭 guarded cold runtime。只有成功 warm-path RTT 进入匹配 TCP 地址族状态；setup 与目标交换 failure 更新 liveness/cooldown，但不贡献 latency 或 ranking strike。 |
| UDP 健康 | 通过节点 packet path 向第一个 `udp_check_dns` 目标发送最小 DNS query。它独立检查 `NodeRuntime::is_warm_or_stateless_for(WarmRequirement::Udp)`；该 requirement 未预热时，探测后关闭 guarded cold runtime。成功记录 RTT，并把 `DnsUdp` 与 `DataUdp` 标为存活；失败分别给两个 UDP domain 增加一次 probe failure，除非同周期独立 Score QUIC handshake 成功，此时只让 `DnsUdp` 失败而保持 `DataUdp` 存活。它绝不修改 TCP state。 |
| Score QUIC 质量 | 通过新的 packet transport 为每个 Score 叶节点执行 ALPN 为 `h3` 的真实 TLS-in-QUIC 握手，目标为第一个 HTTPS `tcp_check_url`，与 DNS 探测成败无关。测得时长提供独立 DataUdp 探测质量，不增加业务成功或虚构吞吐；DNS 探测失败而握手成功时仍按既有规则恢复 DataUdp 活性。 |
| 按组 URL | 用与全局 TCP 探测相同的临时暖路径计时，探测动态解析出的 `(member tag, current leaf)` 对。状态为 TCP-only，连续三次失败即死亡，并使用相同冷却与连续两次成功恢复。重载时 `sync_group_check_urls` 替换有效的组/URL 注册表。 |

`has_udp_state` 区分从未观察过 UDP 的节点与已明确观察为死亡的节点。对于普通 endpoint，终止性 send/receive error 与从未收到 reply 时的 idle expiry，会在 driver 捕获 terminal per-flow Score outcome 后上报 `DataUdp` failure。对于来源共享 VLESS，source owner 负责报告 transport health，而每个绑定 endpoint 保留并结算自己的 Score reporter；匹配 reply 属于对应 endpoint，foreign reply 没有 flow Score owner。source terminal event 会退役其 endpoints，并把 terminal outcome 分发给这些 flow。

类型化 policy、size 与 `PacketRejection::Capacity` refusal 对候选是 terminal，但不影响 health 或 Score；CLI 调用方收到 capacity error，而不是 `NotApplicable`。单包拥塞、已有 reply 后的 idle expiry、主动退役、节点死亡取消和进程关闭也不影响健康。alive→dead 转换调用带 `(NodeId, name)` 的控制面回调，清除 pool connection 与 UDP endpoint。若 sibling UDP domain 明确存活，则跳过该 UDP domain 的死亡清理，避免被阻断的 `:53` 探测清除正常 flow。

每个节点最近一次真实 TCP 延迟样本每 60 秒写入 `cache.db`；启动时只恢复不超过 24 小时的样本。存活性从不由缓存恢复。合成 10 秒占位样本带有标记，不显示在历史中，不进入移动平均，也不会作为最近真实样本持久化；选择降级由失败 strike 计数承担，与占位样本无关。

`honk-outbound/src/urltest.rs` 统一负责 HTTP 请求构造和测量，URL 解释委托给 `honk-config::check` 的规范解码器。core 与 generation URLTest 还共享显式冷 session 预热，并在创建资源或反馈之前保留可失败的节点准入；独立工具调用保留 handler 内部的 setup 和 CLI 外层 deadline。请求使用不含凭据的 authority，仅保留非默认端口，移除 fragment，并保留原始路径、查询串及点段；仅有查询串的 URL 使用 `/?query`。HTTPS 验证证书并协商 `h2,http/1.1`，禁用 server push。第一轮使用 HEAD，第二轮使用配置方法（delay 测试为 HEAD）；两轮最终响应的解码状态都必须为有效的 200–499。HTTP/1 会在同一轮内消费临时响应头后再读取最终响应，但不支持协议切换；每轮响应头累计上限为 16 KiB。HTTP/2 响应头列表使用相同大小上限。
HTTP/2 探测连接在首个本地检测到的协议错误时终止，避免后续远端 reset 覆盖已经拒绝的响应头错误并触发首轮样本回退。
已取消流的记录保留窗口设为每轮超时的两倍，覆盖两轮请求预算，使迟到的合法 warm 流帧仍可被忽略。每次探测最多保留两条流记录；完成或取消时随连接释放，不等待记录过期。

报告值为第二轮热路径 RTT，不含代理拨号、目标 TLS 和 session 准备。第二轮传输失败可返回已验证的第一轮样本；HTTP/1 要求没有部分响应，HTTP/2 接受正常 GOAWAY 或远端 `REFUSED_STREAM`，畸形或部分响应仍失败。冷可复用探测关闭 guarded runtime，HTTP/2 driver 在完成或取消后停止。准备、拨号、TLS、HTTP/2 启动和每轮请求分别有阶段预算，core 保留连接超时。空 delay URL 使用 `https://www.gstatic.com/generate_204`。`alive` 负责健康调度，只有真实流量增加拨号失败 strike；组 delay 并发上限仍为 10。
API 返回的首轮预热回退值不会作为配置方法的 Score 证据发布；只有成功测得的第二轮才更新该方法的质量 cohort。

当前锁定依赖的已知限制：[`h2` 0.4.19 会把缺少响应 `:status` 的情况默认解码为 200](https://github.com/hyperium/h2/issues/958)。探测器只能检查解码后的状态，无法恢复被遗漏的伪头，因此这种畸形 HTTP/2 响应仍可能被判为健康。[上游修复 #959](https://github.com/hyperium/h2/pull/959) 已于 2026-09-14 合并，但当前锁定版本尚未包含；等待包含修复的正式版本后更新依赖，不引入本地 fork 或 vendor 补丁。

## UDP 候选资格

UDP 选择按节点和地址族决定：

- `DataUdp` 存活或 `DnsUdp` 存活：可选择。
- 两个 UDP 域都明确死亡：排除，即使 TCP 存活。
- 从未记录过 UDP 状态：继承 TCP 存活性。

这样既不会让 TCP 健康但 UDP 已坏的节点继续吸引报文流，也不会惩罚尚未启用 UDP 探测的部署。

## eBPF 连通性发布

eBPF alive slot 属于组，而不是某个节点。对于每个域和地址族，发布值使用所有可达叶成员状态的 OR，并保留“恰有一个唯一叶节点且未配置 `final`”的 TCP 准入例外。由单个节点转换触发的回调会重新计算该组值；绝不会直接写入正在转换节点自身的值。准入不覆盖用户态选择：即使该 slot 仍存活，选中的空 Selector 路径仍会拒绝流量。

重载先把旧组或新组布局所需的所有 slot 设置为存活，使转换期 fail-open。发布新路由 generation 后，honk 再写入精确的新组快照。因此组重排不会继承陈旧的 ordinal 状态；若精确发布中途失败，尚未填写的转换 slot 保持 fail-open，而不会错误地杀死某个组。

## 预热与所有权

预热有三个相互独立的机制：

| 机制 | 候选与生命周期 | 保留资源 | 边界 |
| --- | --- | --- | --- |
| 启动预连接 | 仅在启动时运行一轮；先取各组当前选择，再按配置顺序。只有可池化裸 TCP 的代理节点合格。 | 向池中存入一条服务端裸 TCP 连接 | `'auto'` 最多选择 8 个节点；`0` 关闭。它不持有策略 retention bit。 |
| Selector 固定 | 始终跟踪每个 Selector 的配置叶节点，包括不健康的显式选择；多个组共享的叶节点按 UUID 去重。 | TCP path 选择的可复用 session（AnyTLS 或 VLESS H2/shared Mux.Cool）、一个 QUIC client/connection，否则一条服务端裸 TCP | 有效选择变化会立即唤醒；10 秒周期修复丢失、已消费或已过期状态。 |
| UDP 预热集 | 需显式启用；每轮对每个地址族重新选择各组 top `min(N, 3)` 的可复用 UDP 叶节点，再按 UUID 全局去重。 | UDP path 选择的可复用状态，包括 VLESS H2/shared/separate Mux.Cool pool，或一个 QUIC client | 最多并发 4 个预热尝试；进程保留集会重新排名并封顶 `4 × N`。 |

Selector 与 UDP ownership 是 reusable node runtime 上相互独立的 bit。
`WarmRequirement::Session` 跟随 TCP path，`WarmRequirement::Udp` 跟随 UDP
path，因此仅 UDP 的 VLESS pool 不改变 direct-TCP warming 或 bare-TCP
eligibility。移除一个 owner 时，另一个 owner 仍可保留共享 pool；最后一个适用
owner 释放后才排空未来 reuse。active flow 不会被切断，startup preconnect
仍只是一颗 pool seed。

重载时，配置不变的节点把现有 `NodeRuntime` 转移给 replacement，包括 AnyTLS、
VLESS pool/source key 与 QUIC state；配置变化时得到 fresh runtime。现有 outbound
maintenance pass 与其他 idle resource 一起回收未受 retention 的 idle VLESS
carrier，不创建新的 protocol timer。

## 拨号准入预算

`max_concurrent_dials` 默认为 64，并为物理代理连接和协议握手创建 generation-local semaphore。配置值会被启动时计算出的不可变进程级描述符 gate 限制。重载可以改变替代 generation 的本地上限，但重叠的新旧 generation 仍共享同一个进程 gate。

Ready 池命中和已预热 generation 传输上的逻辑流不占额度。`block` 不会拨号；`DirectHandler::dial` 与其他物理连接一样经过 `admit_physical_dial`。已卸载到数据路径的直连流量，以及通过标记 HTTP 客户端直连的 UI 下载，不使用该 handler 的准入 gate。裸 TCP 池命中仍需执行协议握手，因此仍受拨号预算准入。

每条 VLESS 物理 carrier 还从启动时确定的进程 carrier gate 取得 permit；重载
generation 与 DNS fork 共用该 gate。permit 经 provisional、active、draining
与 idle carrier I/O 一直持有到 task teardown。该全局 gate 是权威边界；
Mux.Cool 不再叠加逐节点两 carrier 限制。

## 相关文档

- [出站设计](./outbound.md)
- [控制面设计](./control-plane.md)
- [组参考](../reference/groups.md)
- [全局参考](../reference/global.md)
