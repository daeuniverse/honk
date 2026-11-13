# 组参考

`group { ... }` 配置组及其成员选择规则。每份配置最多可定义 250 个顶层用户组；更高的路由序号由 ABI 保留。

## 语法

每个组都是 `group { ... }` 中的命名子节。同名声明不会合并，以最后一份为准。不要在包含文件里重复声明同一个组来扩展它。

```dae
group {
    hk {
        filter: subtag('airport') && name(keyword: 'HK')
        filter: name(regex: '^Hong Kong ')
        policy: min_moving_avg
        check_url: 'https://probe.example:8443/check,192.0.2.10,2001:db8::10'
        icon: 'https://example.com/icon.svg'
        tolerance: 50
        idle_timeout: 1800
        interrupt_connections: true
        final: direct
    }

    proxy {
        filter: group('hk')
        filter: name('backup')
        policy: select
        default: 'hk'
        final: direct
    }
}
```

## 键

| dae 键 | 内部字段 | 默认值 | 含义 |
| ------- | -------- | ------ | ---- |
| （子节名） | `name` | 必填 | 在路由和 API 中用作出站的组 tag。 |
| `policy` | `policy` | `selector` | 成员选择策略；接受的拼写见下表。 |
| `icon` | `icon` | `null` | 带主机名且不含凭据的绝对 HTTP(S) URL，或 data URI；最多 2048 个字符，不能含空白。其他值会使配置被拒绝。原生组读取会遮蔽至少 8 字节长的监听凭据值，不推测图标。 |
| `filter: name(...)` | `filters` + `nodes` | `[]` | 按节点名选择节点。解析器把匹配结果解析为节点 UUID。 |
| `filter: subtag(...)` | `filters` + `nodes` | `[]` | 按产生节点的订阅的当前 tag 选择节点。 |
| `filter: group(...)` | `groups` | `[]` | 加入嵌套组 tag。接受逗号分隔的参数和竖线分隔的 tag。 |
| `default` | `default` | `null` | `selector` 的初始或回退成员 tag。 |
| `final` | `final_outbound` | `null` | 组策略没有合格选择时使用的节点、组、`direct` 或 `block`，该组被嵌套时同样生效。未知目标会使配置在启动或重载时以 `invalid-group-final-target` 被拒绝。`final` 节点仍受健康检查约束。绕回自身的 `final` 路径不选择任何节点，也不会退回 `direct`。 |
| `check_url` | `check_url` | `null` | 非 Selector 策略的按组 TCP 健康检查目标。不要在 Selector 上设置：honk 只记录警告，从不探测该 URL，但 Selector 的 TCP 选择仍读取该 URL 的健康状态，而未探测的 URL 视为健康，结果是 TCP 健康检查不再约束该组。 |
| —（dae 中不可配置） | `check_interval` | `null` | 按组间隔字段，单位为秒。当前运行时不读取该字段，而使用全局间隔。 |
| `tolerance` | `tolerance` | `50` | URLTest 切换阈值，单位为毫秒，写成纯整数：`tolerance: 50`，不能写 `50ms`。dae URLTest 组未显式设置时继承 `global.check_tolerance`。有效下限为 1 ms。 |
| `idle_timeout` | `idle_timeout` | `null` | URLTest 组持续多少秒没有被选择后暂停成员探测，写成纯整数：`idle_timeout: 1800`，不能写 `30m`。为 `null` 时使用 1800 秒。 |
| `interrupt_connections` | `interrupt_connections` | `false` | 选择变化时，按捕获的组身份和网络关闭受影响的用户态传输。这会退役传输，而不只是移除跟踪记录；共享 UDP 载体保留未受影响的视图。LoadBalance 轮换从不关闭连接。接受 `true`/`false`、`yes`/`no`、`on`/`off` 或 `1`/`0`，不区分 ASCII 大小写；其他值会使配置被拒绝。 |
| —（dae 中不可配置） | `id` | 随机 UUID | 字段缺失时生成的内部组标识。 |

`filter:` 条目累加。其他键都以最后一次出现的值为准，较早的无效值不会被检查。

`check_url` 接受 HTTP(S) URL；不写协议的目标按 HTTP 处理。URL 后以逗号分隔的条目是 IPv4 或 IPv6 字面地址，使用 URL 的端口，并先于 DNS 返回的地址尝试。无效条目会被忽略。

URLTest 组在首次被选择前处于空闲状态，此后连续 `idle_timeout` 秒没有被选择也会转为空闲。空闲期间暂停成员的周期探测，下一次选择时恢复。`idle_timeout: 0` 表示两次选择之间即为空闲，它不是连接超时。只要还有非 URLTest 组或处于活跃状态的 URLTest 组能到达某个节点，该节点就继续接受探测。

## 策略

| 规范名 | 接受的 dae 拼写 | 行为 |
| ------ | --------------- | ---- |
| `selector` | `selector`、`select`、`fixed`、`fixed(0)` | TCP/UDP 各自维护运行时选择，在健康过滤前依次使用对应网络的选择、`default` 和第一个现存成员。健康状态不会把有效选择替换成兄弟成员；选择可为直接节点或嵌套组 tag。 |
| `urltest` | `urltest`、`min_moving_avg`、`min_avg10`、`min_last_delay` | 选择减半移动平均 `(prev + sample) / 2` 最低的存活成员；近期失败尚未恢复的成员排在其他成员之后。`tolerance` 限制切换。TCP 与 UDP 选择相互独立。 |
| `loadbalance` | `loadbalance`、`roundrobin`、`round_robin`、`balance` | 对存活成员轮询；每个组以及 TCP/UDP 网络各有独立计数器。连向同一目标的相邻连接会从不同节点出去，TCP 与 UDP 也各自轮换，因此把会话绑定到客户端地址的服务会断开：登录状态失效，Cloudflare 的放行记录会被重新质询。需要稳定出口时改用 `urltest` 或 `score`。 |
| `fallback` | `fallback` | 分别为 TCP 和 UDP 按成员顺序固定第一个存活成员；更靠前的成员恢复后不会立即切回。 |
| `score` | `score` | 根据实际可靠性、新鲜目标质量与有界验证选择一个存活成员；TCP/UDP 和目标 IPv4/IPv6 证据各自隔离。 |

策略名按 ASCII 大小写不敏感匹配。解析器匹配前会去掉可选的括号后缀，因此接受 `fixed(0)`。无法识别的策略会变为 `selector`，并在诊断信息中注明组名；旧策略名 `honk` 明确无效，必须改用 `score`。

直接成员保持节点列表的顺序，不按过滤器行或参数顺序排列：`filter: name(backup, primary)` 不会把 `backup` 排到前面。嵌套组排在全部直接成员之后，按 tag 的书写顺序排列。这个顺序决定 Selector 的首个成员、Fallback 优先级和 LoadBalance 轮换顺序。

要显式指定 Fallback 优先级，把每个节点放进单独的子组，再按顺序列出这些子组：

```dae
group {
    primary-only {
        filter: name('primary')
    }
    backup-only {
        filter: name('backup')
    }
    preferred {
        filter: group('primary-only', 'backup-only')
        policy: fallback
    }
}
```

URLTest 组会保留当前成员，直到另一成员的延迟低出 `max(tolerance, 1 ms)` 以上。当前成员没有新测量值或有近期失败时，不享受这一保留。

TCP 按 TCP 探测延迟排序；设置了 `check_url` 时按该组的 `check_url` 探测排序。UDP 先按数据 UDP 探测延迟排序，其次是 DNS UDP；没有 UDP 测量值的成员排在最后，不借用其 TCP 延迟。`check_url` 不影响 UDP。在任何成员有 UDP 测量值之前，UDP 沿用该组的 TCP 选择。

只有在选择缺失或已不属于该组时，才继续使用 `default` 或声明顺序中的第一个成员。现存的已选成员没有合格叶节点时，TCP 和 UDP 都不会回退到兄弟成员：仅可继续执行显式配置的 `final` 或下述同一叶节点的 TCP 最后尝试。选中的嵌套组仍执行自己的策略，因此 URLTest 可以在该子组内部选择其他叶节点。

已选子组会先解析自己的显式 `final`，再向父组返回空结果。这不允许改选其他 Selector 兄弟成员，也不允许重试终态协议拒绝。IPv6 目标仍优先尝试经 IPv4 代理健康状态可达的普通已选叶节点，然后才执行 final 路径。

UDP 资格同时要求协议／配置支持和健康条件；VMess 与显式仅支持 TCP 的叶节点在选择及 Score 比较前被排除，TCP 选择不受影响。Selector 已选节点不具备 UDP 能力并不允许改选兄弟成员，内置 `block` 仍保持终态。能力过滤不能绕过已选节点针对具体目标的 UDP 策略拒绝。

不同节点使用同一显示 tag 时，按名称指定的默认选择和 Clash 写入在健康过滤前按组内声明顺序绑定第一个匹配成员的 `NodeId`；原生成员 ID 可选择特定的直接成员。健康状态不会把任一选择改选为另一个同名且健康的节点。
按名称指定的 `final` 节点同样绑定配置中第一个匹配声明，不会用健康的同名节点替换；选择与 final 节点健康注册使用同一身份。

若组只有一个唯一叶节点、未配置 `final`，且 TCP 健康状态排除了该节点，honk 仍可把同一节点作为最后尝试，但当前 Selector 选择路径必须能到达它。这不能绕过选中的空子组，也不表示回退到 `direct`。节点保持 dead，直到真实流量或探测使其恢复；UDP 继续正常排除死亡成员。最后尝试服务会记录限流警告（每组 60 秒）。

每个已配置 Selector 的代理叶节点都保持热态。解析嵌套选择后，honk 会按叶节点协议保留可复用的多路复用 session、QUIC client 或一条到服务端的裸 TCP 连接；`direct` 与 `block` 不需要热资源。

原生 `PUT /api/v1/groups/{groupId}/selection` 接受直接成员的 `member_id` 和必填 `network: "tcp"|"udp"|"both"`，用于更新选择；`both` 一次校验、原子发布，TCP 写入不改变 UDP。Clash 写入映射为 `both`，`now` 明确显示 TCP 选择。两者共用 control/reload 所有者、分网络持久化与预热回调；中断只影响实际发生选择变化的网络，且按既有流量捕获的组路径匹配，不用当前叶节点列表倒推。Selector 固定预热跟随 TCP 选择，UDP 预热集使用 UDP 选择。

组 PATCH 通过解析器记录的来源位置修改可写 `.dae` 的 `policy`、`default`、`final`、`tolerance`、`idle_timeout`、`interrupt_connections` 和 `check_url`，保留其他原文字节并经完整校验、持久写入与真实重载；不是只改内存。需要组 ETag 的强 `If-Match`，与源文件哈希独立校验；写后激活被拒绝不回滚磁盘。`icon` 可在配置或源编辑器修改，不属于受限 PATCH 字段。自动策略组可在运行时固定成员，下次配置激活或通过 DELETE 请求清除固定成员时失效，详见[原生组控制](./api.md#节点与组)。

### URLTest 冷启动

在任何成员有延迟测量值之前，路由到 URLTest 组的连接会让多个成员竞速，采用最先连通的一个。TCP 最多启动三个成员，间隔 200 ms。UDP 在 0、30、80、160 ms 依次启动成员，之后每隔 80 ms 再启动一个，同时最多三个，并在胜出者确定前不发送应用数据。嵌套在其他组中的冷启动 URLTest 组只贡献一个成员，不参与竞速。

### Score 策略

Score 始终编译，必须以 `policy: score` 显式选择；省略策略仍默认 Selector。没有运行时调节项。可靠性保护准入，但更多历史成功次数本身不能长期排除已经验证且更快的少样本节点。

Score 经普通健康过滤后选择一个权威叶节点；代理健康地址族与业务目标地址族独立。首次选择的 utility 和 `WeightedMean` 性能启发式保持不变；充分观测的候选比较实际失败风险，而不是样本最多者的下置信界。证据稀疏者获得有界试用。配置探测质量只是基线，新鲜可信的目标业务证据仍可覆盖它；平局按声明顺序与稳定身份解决。健康现任的晋升比较使用独立有界证据，不能只靠启发式。

可选试用按每个保留的 `(group, TCP/UDP, target family)` 作用域管理预算：

- 初始额度：作用域固定成员数 `n` 和冷启动额度 `B`。成员不超过四个时，`B` 覆盖全部成员；否则为 `ceil(sqrt(n)) + 1`。
- 赚取额度：每次原始业务开始（计入 `N`）增加 `1/q`，通常 `q = 16`。仅当该组在此网络上的近期原始业务（五分钟半衰期）折合每秒至少两条，且作用域近期至少有三个可选试用结果、成功率至少为 80%（十分钟半衰期，衰减权重超过 2.5）时，才使用 `q = 8`。证据需要的试用次数固定，因此试用有效的繁忙组能更快得到额度，空闲组保持较小比例。目标拒绝不计入试用结果，重载会清除这些结果。
- 低收益暂停：普通选择已观测可用，且本次读取涉及的每个作用域近期成功率都低于 20% 时，近期失败达到两次及以上会暂停可选试用，直到失败衰减。只有一次近期失败时，每次只放行一个试用。暂停作用域拒绝的每个候选都计入 `budgetBlocked`，并显示为 `budget` 等待，与额度耗尽相同；已有试用在途的成员仍显示 `inFlight`。没有可用选择时继续探索，使 Score 能脱离故障；恢复性延续不受影响。
- 预算上限：已支出试用 `V` 加未开始预留 `R`，始终不超过 `B` 加已赚额度的整数部分。未花费的已赚额度最多为八。
- 计数：`N` 包括被选中的试用，但重试、克隆和嵌套重复归因不能放大计数；根计数对嵌套组去重。时间、读取、新目标和证据过期不产生额度。保留的作用域在重载和成员变化后保持额度。
- 支出与退款：节点专属工作在 DNS／准入等待前开始支出，与物理／逻辑报告器的开始时间分离。工作开始前释放最后一个引用会退还预留额度，开始后取消不退款。恢复重试单独计数，不花可选预算。
- 在途上限：每个成员针对其未决问题，在同一目标上至多有一个尚未得到回答的试用。除恢复外，只有完成数加上未完成工作仍少于所选成员完成数的成员才会获得试用。
- 失败处理：试用不成为普通现任。真实失败保留指数退避和三连败普通排除；退避到期后仍可尝试恢复。

业务可靠性仍使用 30 分钟半衰期；启发式性能置信度独立老化，120 秒后过期，不受样本数量影响。setup 与首响应即时发布，已接受的传输进展使用互不重叠的 1–10 秒窗口，被测方向至少 64 KiB 且 flow 已有双向进展和响应。窗口不增加终态次数。goodput 受业务需求影响，不等于链路容量，静默不是拥塞。成熟保持在八次有效完成后仍达到 `0.005`，支撑量取适用层分别衰减后的最大值。不合格现任和未恢复的业务失败可绕过保持；已恢复的历史失败量不再单独取消保护。

只有真正改选另一叶节点的普通逃逸才优先于可选验证。若失败现任仍被选中，不会阻止有额度且可执行的挑战者试探；这不清除失败或退避。

晋升比较共享服务候选池（容量 k 随需求变化，大组另受 √n 上限约束，普通与试用选择均受池约束，胜者不额外增加名额，见[有条件的验证结论](../design/groups.md#有条件的验证结论)）内所有合格挑战者与同一个固定现任，使用双方精确目标、至多八个按规范顺序选取且响应支持已合格的共同目标，或同一当前配置探测 cohort。共同目标先判定支持资格再应用数量上限，不能按测量值挑选；跳过尚未合格或被上限截断的已匹配目标时，只形成部分比较，该成员的响应缺口仍待解决。方向指标在同一组已选响应目标上取交集。业务证明使用四个共同 15 秒块，在各自起点后 60 秒到期；配置探测按实际周期 `I` 使用四个 `max(15s, 2I)` 块，有效期还受“较弱一侧最近支持加 `max(60s, 2I)`”限制。每个指标仍要求双方各四个不同 reporter，改变周期不能继承旧探测支持。方向优势要求至少提升 10%，其他已知方向均未退化超过 10%，响应变慢不超过 10%，且合格终态可靠性不低于现任。未知方向保持未知；一升一降报告为权衡，不以最佳方向分数掩盖。成对响应与合格可靠性优势仍参与既有保持门槛判定。不新增 Score 调节项，详见[生命周期设计](../design/groups.md#score-评分与生命周期)。

只读成对关系与上述切换决策分离：它对实际响应值使用对称 10% 近似等价容差，不使用完成数成熟度或毫秒下限，且只描述响应时间；可靠性与方向保护仍由切换负责。缺少成对响应时请求预算内可比业务流量，不是带宽测速，详见[有条件的验证结论](../design/groups.md#有条件的验证结论)。

setup/TX 后的定向 Traffic RX 可在 flow 结束前打开有额度的半开恢复。精确 cell 连续失败后 cohort 中的四个不同 reporter 清除硬失败事件并授予当前 60 秒资格租约；一次回包或其他目标恢复的聚合层均不足够。历史失败仍影响 utility 和晋升，不虚构终态成功。初始冷资格仍需四个有效 useful 完成；RX 可续期已取得租约，但仅 reload 不授予恢复。首个合格 RX 后，每个 reporter 按事件驱动每秒至多发布一次。目标路径失败只改变精确目标的硬状态，同时保留聚合数值结果；明确的 carrier／代理故障及 setup 前未知失败仍按节点归因并隔离依赖证据。详见[作用域恢复与可选验证](../design/groups.md#score-评分与生命周期)。

业务评分仍按组、transport、目标地址族、规范化目标和节点身份隔离；全局/地址族/精确目标可靠性分层混合，但不把重叠完成数相加。目标性能仅在新鲜可比时覆盖基线。探测 RTT 单独保留 protocol/family 与规范化 HTTP URI/方法身份；预热只提供 setup 质量。一次真实结果向经过的每个 Score 组归因一次。

透明 TCP/UDP、受支持的 DNS exchange 和 UI 下载反馈真实业务 attempt。配置 HTTP/UDP/QUIC 探测提供近期质量，不增加业务成功或清除真实连败。手动 Clash delay 保留 Alive/API 历史，但不建立配置 Score 基线，也不把任意目标失败变成真实拨号降级；实际准备仍记预热质量。独立 Score QUIC 握手保留既有 DataUdp 健康恢复，不虚构字节流量。

持续且实际测得的 carrier 压力可以重新打开预算内比较，但不增加业务失败，也不直接改变赢家。这是 honk→代理服务器的提示证据，不是端到端 UDP 丢包率或首请求保证；不支持观测的路径仍未知。详见[提示范围](../design/groups.md#score-评分与生命周期)。

全部评分状态仅存于当前进程内存。精确 node-target cell 使用硬上限为 4,096 的 LRU，聚合 cell 使用另一个 4,096 项 LRU。精确目标证据衡量的是实际 transport 质量，不表示服务在语义上已解锁；需要这种粗粒度 cohort 时，应使用已有 routing 或 geosite 规则选择专用的服务 Score 组。成功的进程内 reload 复用同一共享状态并移除已删除组或成员的 cell；进程重启会清空状态。评分 cell 与仅由 scorer 持有的 domain/IP 键不会进入日志、持久化存储或任何 API 输出。已建立连接的元数据不受影响。Clash 仍将 Score 表示为 `type: "url_test"`，在 `now` 中显示当前聚合 TCP 胜者，并拒绝对该组执行 `PUT /proxies/{name}`。

独立比较存储最多有 512 个 cell，逻辑分配上限为 1 MiB，包含所持有键与 vector 的容量。这不是进程 RSS 上限，分配器开销和其他状态不在其中；缺失或被淘汰的支持保持未知。

可重试的 TCP 建立失败后，Score 所属请求至多顺序尝试一个不同的合格叶节点，不要求普通评分先改选。两次尝试共享 deadline 和既有拨号准入；Selector 边界与首选实际经过的 final 边保持权威，不新增 direct/final 兜底或重放应用负载。提交 reload 时清空探测基线，但保留有效在途业务证据；中性 cell 仍受既有 LRU 容量约束。

每次已授权的多候选 rank 只记录一个互斥原因：`coldExplore`、`periodicExplore`、`incumbentIneligible`、`freshFailureBypass`、`insufficientEvidenceHeld`、`directionalTradeoffHeld`、`incumbentHeld`、`reliabilityWinner` 或 `performanceWinner`。`ordinarySwitch` 记录同作用域普通已提交 A→B 变更，不含首次选择和试用；`switchFlap` 是其中八次普通选择内返回前一赢家的子集。候选过滤／退避计数保持独立。Peek 与展示/API 读取保持中性。经鉴权的 `/stats.score.groups[]` 导出固定组／网络原因、验证和预算字段；`/stats.score.cache` 描述证据与比较存储。试用结果和 setup／总耗时成本是实际观测，不是因果额外失败或开销估计。详见 [API 原因语义](./api.md#score-选路原因字段)，不导出 scorer 私有节点或目标身份。

采样在共享预算内解决可用性、响应、普通资格和恢复缺口。新鲜等价 cohort 须在资格／恢复缺口也关闭后才停止强制采样，缺少传输证据则等待真实负载。`scoreVerification` 区分临时转发、已观测可用性、新鲜的成对 `challengers` 关系、证据问题 `question` 和等待原因 `waitReason`；聚合读取检查已保留 IPv4/IPv6 等待状态，不花费额度。详见 [API 验证](./api.md#score-验证信息)。这些关系是可撤销的经验观测，不是最优候选识别或未来网络行为的保证。

每个挑战者与所选成员的比较对只按自身共享时间块判断，不在挑战者之间联合对齐。可选工作只有一个派发顺序：先未训练成员，再按成员未决问题的进展，然后按最久未被选中。试用保留业务额度和在途上限，不重放请求。只读 `question`、`nextAction` 与 `waitReason` 报告该顺序的首个成员，不暴露目标身份。

## 过滤解析

1. 单独的 `group('tag')` 行把嵌套 tag 加入 `groups`，不作为节点谓词求值。嵌套 tag 可以贡献该组当前策略选出的叶节点。包含其他谓词或尾随文本的 `group(...)` 行会被忽略并报告诊断信息；如果组内只有这一条过滤器，该组的成员为空。
2. `name(...)` 匹配 `Node.name`。`subtag(...)` 把 `Node.subscription_id` 映射到当前订阅 tag 并匹配该 tag。普通参数是精确匹配，`keyword:` 是子串匹配，`regex:` 使用 [Rust regex 语法](https://docs.rs/regex/latest/regex/#syntax)。匹配区分大小写；同一谓词中的多个参数互为候选。正则表达式无效时，honk 忽略该过滤器行；其他过滤器行仍可提供成员。
3. 同一行中由 `&&` 连接的谓词按 AND 求值。在谓词前加 `!` 会对其取反。不同 `name(...)` 和 `subtag(...)` `filter:` 行之间按 OR 求值；单独的 `group(...)` 行加入嵌套候选。
4. 每次订阅刷新后都会重建过滤后的成员关系。因此，节点 UUID 即使不变，也不会在订阅来源变化后保留过期成员关系。
5. 既没有节点过滤器也没有嵌套组的组会接收当前全部节点。显式 `group()`、空过滤器、空嵌套组或订阅刷新后变空的过滤器均不选择节点。这些空结果在 JSON/YAML/TOML 序列化与重新解析以及刷新后仍保留；有效的同级过滤器继续按 OR 提供候选，`final` 保持独立。

honk 会忽略无法解析的过滤器，并在诊断中注明其在组内节点过滤器中的序号；只有非空的独立 `group(...)` 行不参与计数，混合谓词行仍参与计数。`group()` 产生 `empty-subgroup` 警告。需要全部节点时请删除过滤器；显式 `group()` 现在不选择任何节点。注入的 `direct` 与 `block` 是出站，不是节点池成员：无过滤器的组、`keyword:`、`regex:` 与 `subtag(...)` 都不会选中它们，只有按名字写出的过滤器（`filter: name(direct)`）才会收入。

```dae
group {
    paid-nodes {
        filter: subtag(paid, regex: '^premium-') && !name(keyword: 'Expired')
    }
    named-nodes {
        filter: name('primary', 'backup')
    }
    literal-names {
        filter: name('a&&b', 'a,b', 'keyword: HK')
    }
    provider-only {
        filter: subtag('paid') && !subtag('expired-provider')
    }
}
```

值含 `&&` 或 `,` 时应加引号，例如 `name('a&&b')`。`name(keyword: 'HK')` 匹配子串，`name('keyword: HK')` 则只匹配名字恰好为 `keyword: HK` 的节点。

内联节点等没有当前订阅 tag 的节点永远不匹配 `subtag(...)`，因此会匹配 `!subtag(...)`。只允许订阅节点时，再加一个正向 `subtag(...)`。

嵌套组建议写成 `group('hk', 'jp')`，也可以写 `group(hk|jp)`。引号在这里不保护 `|` 和 `,`：`group('hk|jp')` 仍会加入两个组，并产生 `legacy-quoted-list`。重复的 tag 会被去掉。

## 嵌套组

嵌套 tag 必须指向已声明的组；未知 tag 会使配置在启动或重载时以 `invalid-nested-group-reference` 被拒绝。组管理器构图时删除每条构成环的边并记录警告。嵌套选择深度上限为 8。每个嵌套组贡献其自身策略选出的单个叶节点，因此每次拨号最终都会解析到一个节点。

面向 Clash 的组输出保留成员 tag：`all` 字段列出直接节点名和嵌套组 tag，而不展开嵌套组。面向叶节点的健康状态与连通性遍历会展开这些 tag 下的实际节点。

## 相关文档

- [节点参考](./nodes.md)
- [路由参考](./routing.md)
- [组设计](../design/groups.md)
