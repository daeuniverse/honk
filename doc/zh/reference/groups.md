# 代理组参考

`group { ... }` 配置代理组及其成员选择规则。每份配置最多可定义 250 个顶层用户组；更高的路由序号由 ABI 保留。

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

## Key

| dae key | 内部字段 | 默认值 | 含义 |
| ------- | -------- | ------ | ---- |
| （子节名） | `name` | 必填 | 在路由和 API 中用作出站的组 tag。 |
| `policy` | `policy` | `selector` | 成员选择策略；接受的拼写见下表。 |
| `icon` | `icon` | `null` | 带主机名且不含凭据的绝对 HTTP(S) URL，或 data URI；最多 2048 个字符，不能含空白。其他值会使配置被拒绝。原生组读取会遮蔽至少 8 字节长的 listener secret 值，不推测图标。 |
| `filter: name(...)` | `filters` + `nodes` | `[]` | 按节点名选择节点。解析器把匹配结果解析为节点 UUID。 |
| `filter: subtag(...)` | `filters` + `nodes` | `[]` | 按产生节点的订阅的当前 tag 选择节点。 |
| `filter: group(...)` | `groups` | `[]` | 加入嵌套组 tag。接受逗号分隔的参数和竖线分隔的 tag。 |
| `default` | `default` | `null` | `selector` 的初始或回退成员 tag。 |
| `final` | `final_outbound` | `null` | 组策略没有合格选择时使用的节点、组、`direct` 或 `block`，该组被嵌套时同样生效。未知目标会使配置在启动或 reload 时以 `invalid-group-final-target` 被拒绝。`final` 节点仍受健康检查约束。绕回自身的 `final` 路径不选择任何节点，也不会退回 `direct`。 |
| `check_url` | `check_url` | `null` | 给非 Selector 策略用的按组 TCP 健康检查目标。不要在 Selector 上设置：honk 只记一条 warning，从不探测这个 URL；但 Selector 的 TCP 选择仍会读该 URL 的健康状态，未探测即视为健康，于是 TCP 健康检查不再约束该组。 |
| —（dae 中不可配置） | `check_interval` | `null` | 按组间隔字段，单位为秒。当前运行时不读取该字段，而使用全局间隔。 |
| `tolerance` | `tolerance` | `50` | URLTest 切换阈值，单位为毫秒，写成纯整数：`tolerance: 50`，不能写 `50ms`。dae URLTest 组未显式设置时继承 `global.check_tolerance`。有效下限为 1 ms。 |
| `idle_timeout` | `idle_timeout` | `null` | URLTest 组连续多少秒没有被选用后暂停成员探测，作用类似 Clash 的 `lazy`。写成纯整数：`idle_timeout: 1800`，不能写 `30m`。为 `null` 时使用 1800 秒。 |
| `interrupt_connections` | `interrupt_connections` | `false` | 选择变化时，按捕获的组身份和网络关闭受影响的用户态传输。这会退役传输，而不只是移除追踪记录；共享 UDP carrier 保留未受影响的视图。LoadBalance 轮换从不关闭连接。接受 `true`/`false`、`yes`/`no`、`on`/`off` 或 `1`/`0`，不区分 ASCII 大小写；其他值会使配置被拒绝。 |
| —（dae 中不可配置） | `id` | 随机 UUID | 字段缺失时生成的内部组标识。 |

`filter:` 条目累加。其他 key 都以最后一次出现的值为准，较早的无效值不会被检查。

`check_url` 接受 HTTP(S) URL；不写协议的目标按 HTTP 处理。URL 后面可以接逗号分隔的 IPv4 或 IPv6 字面地址，这些地址使用 URL 的端口，并先于 DNS 返回的地址尝试。无效条目会被忽略。

本文区分三个词：健康检查是代理组周期性执行的检查；延迟测试是通过 API 或界面按需触发的测试；探测是一次测量，前两者都由探测组成。

URLTest 组在第一次被选中之前保持空闲。之后只要连续 `idle_timeout` 秒没有流量选中它，就再次转入空闲。空闲期间暂停成员的周期探测，下一次选中时恢复。`idle_timeout: 0` 表示两次选择之间就进入空闲，它不是连接超时。只要还有非 URLTest 组，或者有活跃的 URLTest 组能到达某个节点，该节点就继续接受探测。

## 策略

| 规范名 | 接受的 dae 拼写 | 行为 |
| ------ | --------------- | ---- |
| `selector` | `selector`、`select`、`fixed`、`fixed(0)` | TCP 和 UDP 各自维护运行时选择：先看对应网络的选择，再看 `default`，最后取第一个现存成员，全部在健康过滤之前决定。健康状态不会把有效选择换成兄弟成员；选择可以是直接节点，也可以是嵌套组 tag。 |
| `urltest` | `urltest`、`min_moving_avg`、`min_avg10`、`min_last_delay` | 选择减半移动平均 `(prev + sample) / 2` 最低的存活成员；近期失败尚未恢复的成员排在其他成员之后。`tolerance` 限制切换。TCP 与 UDP 选择相互独立。 |
| `loadbalance` | `loadbalance`、`roundrobin`、`round_robin`、`balance` | 对存活成员轮询；每个组以及 TCP/UDP 网络各有独立计数器。连向同一目标的相邻连接会从不同节点出去，TCP 与 UDP 也各自轮换，因此把 session 绑定到客户端地址的服务会断线：登录状态失效，Cloudflare 会重新质询其放行记录。需要稳定出口时改用 `urltest` 或 `score`。 |
| `fallback` | `fallback` | 分别为 TCP 和 UDP 按成员顺序固定第一个存活成员；更靠前的成员恢复后不会立即切回。 |
| `score` | `score` | 根据实际可靠性、新鲜目标质量与有界验证选择一个存活成员；TCP/UDP 和目标 IPv4/IPv6 证据各自隔离。 |

策略名不区分 ASCII 大小写。解析器匹配前会去掉可选的括号后缀，因此 `fixed(0)` 也可以用。无法识别的策略会当作 `selector` 处理，诊断信息里会注明组名；旧策略名 `honk` 明确无效，必须改用 `score`。

直接成员的顺序来自节点列表，跟过滤器行和参数顺序无关：`filter: name(backup, primary)` 不会把 `backup` 排到前面。嵌套组排在全部直接成员之后，按 tag 的书写顺序排列。这个顺序决定 Selector 的首个成员、Fallback 优先级和 LoadBalance 轮换顺序。

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

URLTest 组会保留当前成员，直到另一个成员的延迟比它低出 `max(tolerance, 1 ms)`。当前成员没有新测量值，或近期有失败时，不享受这份保留。

TCP 按 TCP 探测延迟排序；设置了 `check_url` 时，按该组的 `check_url` 探测排序。UDP 先按数据 UDP 探测延迟排序，其次按 DNS UDP；没有 UDP 测量值的成员排在最后，不会借用它的 TCP 延迟。`check_url` 不影响 UDP。在任何成员产生 UDP 测量值之前，UDP 沿用该组的 TCP 选择。

选择缺失，或者选中的成员已不属于该组时，才回落到 `default` 或声明顺序里的第一个成员。选中的成员没有合格叶节点时，TCP 和 UDP 都不会改选兄弟成员：只能继续执行显式配置的 `final`，或下述针对同一叶节点的 TCP 最后尝试。选中的嵌套组仍执行自己的策略，因此 URLTest 可以在该子组内部挑另一个叶节点。

选中的子组会先解析自己的显式 `final`，然后向父组返回空结果。这不代表可以改选其他 Selector 兄弟成员，也不代表可以重试终态的协议拒绝。IPv6 目标仍会先尝试经 IPv4 代理健康状态可达的普通已选叶节点，之后才走 final 路径。

UDP 资格同时要求协议或配置支持，以及健康条件。VMess 和显式仅支持 TCP 的叶节点会在选择与 Score 比较之前被排除，TCP 选择不受影响。Selector 选中的节点没有 UDP capability 时，也不会改选兄弟成员；内置 `block` 仍保持终态。capability 过滤绕不过已选节点针对具体目标的 UDP 策略拒绝。

不同节点共用同一个显示 tag 时，按名称指定的默认选择和 Clash 写入会在健康过滤之前，绑定组内声明顺序里第一个匹配成员的 `NodeId`。原生成员 ID 可以直接选中某个直接成员。健康状态不会把任何一个选择改到同名的健康节点上。按名称指定的 `final` 节点同样绑定配置里第一个匹配的声明，不会被健康的同名节点替换；选择和 `final` 节点的健康注册使用同一个身份。

组只有一个叶节点、没有配置 `final`，而 TCP 健康状态排除了这个节点时，honk 仍可把它作为最后尝试，但当前 Selector 的选择路径必须能到达它。这不能绕过选中的空子组，也不表示回退到 `direct`。节点保持失活，直到真实流量或探测让它恢复；UDP 仍按正常规则排除失活成员。走到这种最后尝试时，honk 会记录限流 warning，每组每 60 秒一条。

每个已配置 Selector 的代理叶节点都保持热态。解析嵌套选择后，honk 会按叶节点协议保留可复用的多路复用 session、QUIC client 或一条到服务端的裸 TCP 连接；`direct` 与 `block` 不需要热资源。

原生 `PUT /api/v1/groups/{groupId}/selection` 用直接成员的 `member_id` 更新选择，`network: "tcp"|"udp"|"both"` 必填。`both` 会一起校验、原子发布，TCP 写入不会连带改变 UDP。Clash 写入映射为 `both`，`now` 明确显示 TCP 选择。两者共用 `control/reload` owner、按网络分开的持久化和预热回调。中断只影响真正发生选择变化的网络，并按既有流量捕获的组路径匹配，不用当前叶节点列表倒推。Selector 的固定预热跟随 TCP 选择，UDP 预热集使用 UDP 选择。

组 PATCH 按解析器记录的来源位置，改写可写 `.dae` 文件里的 `policy`、`default`、`final`、`tolerance`、`idle_timeout`、`interrupt_connections` 和 `check_url`。其他原文字节保持不变。改动会走完整校验、持久写入和真实 reload，不只停留在内存。请求必须带针对组 ETag 的强 `If-Match`，并独立于源文件 hash 校验。写入后激活被拒绝时，磁盘内容不回滚。`icon` 可以在配置或源编辑器里改，不属于受限 PATCH 字段。自动代理组可以在运行时固定成员；下次配置激活，或通过 DELETE 请求清除固定成员时，固定失效。详见[原生组控制](./api.md#节点与代理组)。

### URLTest 冷启动

在任何成员有延迟测量值之前，路由到 URLTest 组的连接会让多个成员 race，采用最先连通的一个。TCP 最多启动三个成员，间隔 200 ms。UDP 在 0、30、80、160 ms 依次启动成员，之后每隔 80 ms 再启动一个，同时最多三个，并在胜出者确定前不发送应用数据。嵌套在其他组中的冷启动 URLTest 组只贡献一个成员，不参与 race。

### Score 策略

Score 始终编译，但只有组上写 `policy: score` 才会启用；省略策略仍默认 Selector。Score 没有运行时调节项。可靠性只保护 admission：历史成功次数再多，也不能长期排除一个已验证、样本更少却更快的节点。

Score 在普通健康过滤之后选出唯一要用的叶节点，代理健康地址族和业务目标地址族相互独立。首次选择所用的 utility 分数和 `WeightedMean` 性能启发式保持不变。候选的观测足够多时，比较的是实际失败风险，不是样本最多者的置信下界。证据稀疏的候选会获得有界试用。配置的探测质量只是基线，新鲜可信的目标业务证据仍能覆盖它；数值相等时按声明顺序和稳定身份决定。健康现任成员的晋升比较使用另一套有界证据，不能只看启发式。

可选试用以 `(group, TCP/UDP, target family)` 作用域为单位管理预算，每个保留的作用域各有一份：

- 初始额度：作用域建立时固定成员数 `n` 和冷启动额度 `B`。成员不超过四个时，`B` 覆盖全部成员；否则 `B` 为 `ceil(sqrt(n)) + 1`。
- 赚取额度：每次原始业务开始都会增加 `1/q` 的额度，并计入 `N`；`q` 通常为 16。只有两个条件同时成立才改用 `q = 8`：该组在这个网络上近期的原始业务折合每秒至少两条，按五分钟半衰期统计；作用域近期至少有三个可选试用结果，成功率至少 80%，按十分钟半衰期统计，且衰减权重超过 2.5。证据所需的试用次数是固定的，所以试用确实有效的繁忙组能更快攒够额度，空闲组则维持较小的比例。目标拒绝不计入试用结果，reload 会清除这些结果。
- 低收益暂停：普通选择已被观测到可用，且本次读取涉及的每个作用域近期成功率都低于 20% 时，只要有两次及以上近期失败，就暂停可选试用，直到这些失败衰减。只有一次近期失败时，试用每次只放一个。被暂停的作用域拒绝的候选会计入 `budgetBlocked`，读出来是 `budget` 等待，与额度耗尽时相同；已经有一个试用在途的成员仍显示 `inFlight`。没有可用选择时继续探索，Score 才能从故障中恢复；恢复过程照常进行，不受这些暂停影响。
- 预算上限：已支出的试用 `V` 加上尚未开始的预留 `R`，始终不超过 `B` 加已赚额度的整数部分。未花掉的已赚额度最多为八。
- 计数：`N` 包括被选中的试用，但重试、克隆和嵌套重复归因不能放大计数；根计数会对嵌套组去重。时间、读取、新目标和证据过期都不产生额度。保留的作用域在 reload 和成员变化后仍保持额度。
- 支出与退款：节点专属工作会在 DNS／admission 等待之前就支出额度，这个时间点与物理、逻辑报告器的开始时间不同。工作开始前释放最后一个引用，预留额度会退还；工作开始后取消，则不退款。恢复重试单独计数，不动可选预算。
- 在途上限：对同一个目标，每个成员每个未决问题最多只有一个没有回音的试用。除恢复外，成员获得试用还要满足：它的完成数加上未完成工作，仍少于当前选择成员的完成数。
- 失败处理：试用不会成为普通现任。真实失败保留指数退避和连续三次失败的普通排除；退避到期后仍可尝试恢复。

业务可靠性仍按 30 分钟半衰期统计。启发式性能置信度单独老化，120 秒后过期，与样本数量无关。setup 和首个响应会立即发布；后续的传输进展按 1–10 秒的不重叠窗口统计，被测方向至少要有 64 KiB，流也要有双向进展和响应。窗口不会增加终态次数。goodput 随业务需求变化，不等于链路容量；静默也不能当作拥塞。八次有效完成之后，成熟保护仍为 `0.005`，支撑量取各适用层分别衰减后的最大值。不合格的现任成员和尚未恢复的业务失败可以绕过这层保护；只靠已恢复的历史失败量则不行。

只有普通选择真正切换到另一个叶节点，才优先于可选验证。失败现任仍被选中时，不会阻止一个还有额度、可以执行的挑战者试用；试用本身也不会清除失败记录或退避。

晋升比较在共享的服务候选池里进行：池内所有合格挑战者都与同一个固定现任比较。池容量 k 随需求变化，大组还受 √n 上限约束。普通选择和试用选择都受池约束，胜者不额外占名额，见[有条件的验证结论](../design/groups.md#有条件的验证结论)。

比较使用的目标有三种来源：双方的精确目标；至多八个按规范顺序选出、响应支持已合格的共同目标；或同一份当前配置探测 cohort。共同目标先判定支持资格，再套用数量上限，不能按测量值挑选。如果跳过了尚未合格或被上限截断的已匹配目标，比较就是不完整的，该成员的响应缺口仍然待解决。方向指标在同一组已选响应目标上取交集。

业务证明使用四个共同的 15 秒块，在各自起点后 60 秒到期。配置探测按实际周期 `I` 使用四个 `max(15s, 2I)` 块，有效期还受较弱一侧最近一次支持时间加 `max(60s, 2I)` 的限制。每个指标仍要求双方各有四个不同的 reporter；探测周期改变后，不能继承旧的探测支持。

方向优势要求至少提升 10%，其他已知方向都没有退化超过 10%，响应变慢不超过 10%，且合格终态可靠性不低于现任。未知方向保持未知；一升一降按权衡报告，不用最佳方向的分数掩盖。成对响应与合格可靠性优势仍参与既有的保持门槛判定。Score 不新增调节项，详见[生命周期设计](../design/groups.md#score-评分与生命周期)。

只读的成对关系与上面的切换决策分开。它只描述响应时间，用对称的 10% 近似等价容差比较实际响应值，不看完成数成熟度，也没有毫秒下限；可靠性和方向保护仍由切换逻辑负责。缺少成对响应时，honk 会在预算内请求可比的业务流量，而不是做带宽测速。详见[有条件的验证结论](../design/groups.md#有条件的验证结论)。

setup/TX 之后的定向 Traffic RX 可以在流结束前开启一次半开恢复，但受预算限制。在精确 cell 连续失败后的 cohort 里，要有四个不同的 reporter 才能清除硬失败事件，并授予当前 60 秒的资格 lease；只收到一次回包，或其他目标恢复后的聚合结果，都不够。历史失败仍计入 utility 和晋升，也不会凭空造出终态成功。初始冷资格仍要求四个有效的 useful 完成；RX 可以续期已经获得的 lease，但光靠 reload 不会授予恢复。首个合格 RX 之后，每个 reporter 按事件发布，每秒至多一次。目标路径失败只改变精确目标的硬状态，聚合的数值结果仍然保留；明确的 carrier／代理故障，以及 setup 之前的未知失败，仍按节点归因，并会 fence 依赖它的证据。详见[作用域恢复与可选验证](../design/groups.md#score-评分与生命周期)。

业务评分仍按组、transport、目标地址族、规范化目标和节点身份分别隔离；全局、地址族和精确目标的可靠性分层混合，但不把重叠的完成数相加。目标性能只在新鲜且可比时覆盖基线。探测 RTT 单独保留 protocol/family 身份，以及规范化后的 HTTP URI 和方法身份；预热只贡献 setup 质量。一次真实结果会向它经过的每个 Score 组各归因一次。

透明 TCP/UDP、受支持的 DNS exchange 和 UI 下载都会反馈真实的业务 attempt。配置的 HTTP/UDP/QUIC 探测只提供近期质量：它们不增加业务成功数，也不清除真实的连续失败。手动 Clash delay 保留 Alive/API 历史，但不作为配置 Score 的基线，也不会把任意目标上的失败变成真实拨号降级；实际准备过程仍记入预热质量。独立的 Score QUIC 握手保留既有的 DataUdp 健康恢复，但不会虚构字节流量。

持续且实际测得的 carrier 压力可以重新打开预算内的比较，但不增加业务失败，也不直接改变赢家。这是一种提示性证据，从 honk 发给代理服务器，不是端到端 UDP 丢包率，也不是首请求保证；无法观测的路径仍保持未知。详见[提示范围](../design/groups.md#score-评分与生命周期)。

所有评分状态都只在当前进程内存里。精确的 node-target cell 用一个容量上限为 4,096 的 LRU，聚合 cell 用另一个 4,096 项 LRU。精确目标证据衡量的是实际 transport 质量，不代表某个服务在语义上已经解锁；需要这种粗粒度 cohort 时，用现有的 routing 或 geosite 规则选出专用的服务 Score 组。成功的进程内 reload 复用同一份共享状态，并移除已删除组或成员的 cell；进程重启则清空状态。评分 cell 和只由 scorer 持有的 domain/IP key 不会写进日志、持久化存储或任何 API 输出。已建立连接的元数据不受影响。Clash 仍把 Score 表示为 `type: "url_test"`，`now` 显示当前聚合后的 TCP 胜者，并拒绝对该组执行 `PUT /proxies/{name}`。

独立的比较存储最多有 512 个 cell，逻辑分配上限为 1 MiB，包含所持有 key 与 vector 的容量。这不是进程 RSS 上限，分配器开销和其他状态都不在其中；缺失或被淘汰的支持保持未知。

TCP 建立失败且可重试时，Score 组处理的请求最多再顺序试一个不同的合格叶节点，不需要普通评分先切换。两次尝试共用 deadline 和既有的拨号 admission。Selector 边界，以及首选实际走过的 final 边，仍然起决定作用；这里不新增 direct/final 兜底，也不重放应用负载。提交 reload 会清空探测基线，但保留有效的在途业务证据；中性 cell 仍受既有 LRU 容量约束。

每次实际执行的多候选选择只记录一个互斥原因：`coldExplore`、`periodicExplore`、`incumbentIneligible`、`freshFailureBypass`、`insufficientEvidenceHeld`、`directionalTradeoffHeld`、`incumbentHeld`、`reliabilityWinner` 或 `performanceWinner`。`ordinarySwitch` 记录同一作用域内普通选择已提交的 A→B 变更，不含首次选择和试用；`switchFlap` 是其中在八次普通选择内又回到前一赢家的子集。候选过滤和退避计数保持独立。Peek 以及展示、API 读取保持中性。经认证的 `/stats.score.groups[]` 导出固定的组／网络原因、验证和预算字段；`/stats.score.cache` 描述证据与比较存储。试用结果和 setup／总耗时成本都是实际观测值，不能当作额外失败或开销的因果估计。详见 [API 原因语义](./api.md#score-选路原因字段)，它不导出 scorer 私有的节点或目标身份。

采样在共享预算内补上可用性、响应、普通资格和恢复方面的缺口。只有资格／恢复的缺口也补上后，honk 才会对新鲜的等价 cohort 停止强制采样；缺少传输证据时，则等待真实负载出现。`scoreVerification` 区分临时转发、已观测可用性、新鲜的成对 `challengers` 关系、证据问题 `question` 和等待原因 `waitReason`；聚合读取会检查保留的 IPv4/IPv6 等待状态，不花费额度。详见 [API 验证](./api.md#score-验证信息)。这些关系是可撤销的经验观测，不是最优候选识别，也不保证未来的网络行为。

每个挑战者与所选成员的比较，只在各自共享的时间块内判断，不会在挑战者之间联合对齐。可选工作只有一个派发顺序：先派发未训练的成员，再按成员未决问题的进展排序，最后按最久未被选中排序。试用保留业务额度和在途上限，不重放请求。只读的 `question`、`nextAction` 与 `waitReason` 报告这个顺序里的首个成员，不暴露目标身份。

## 过滤解析

1. 单独的 `group('tag')` 行把嵌套 tag 加入 `groups`，不作为节点谓词求值。嵌套 tag 可以贡献该组当前策略选出的叶节点。包含其他谓词或尾随文本的 `group(...)` 行会被忽略并报告诊断信息；如果组内只有这一条过滤器，该组的成员为空。
2. `name(...)` 匹配 `Node.name`。`subtag(...)` 把 `Node.subscription_id` 映射到当前订阅 tag 并匹配该 tag。普通参数是精确匹配，`keyword:` 是子串匹配，`regex:` 使用 [Rust regex 语法](https://docs.rs/regex/latest/regex/#syntax)。匹配区分大小写；同一谓词中的多个参数互为候选。正则表达式无效时，honk 忽略该过滤器行；其他过滤器行仍可提供成员。
3. 同一行中由 `&&` 连接的谓词按 AND 求值。在谓词前加 `!` 会对其取反。不同的 `name(...)` 与 `subtag(...)` `filter:` 行之间按 OR 求值；单独的 `group(...)` 行只加入嵌套候选。
4. 每次订阅刷新后都会重建过滤后的成员关系。因此订阅来源变化后，即使节点 UUID 没变，旧的成员关系也不会留下。
5. 既没有节点过滤器也没有嵌套组的组会接收当前全部节点。显式 `group()`、空过滤器、空嵌套组或订阅刷新后变空的过滤器均不选择节点。这些空结果在 JSON/YAML/TOML 序列化、重新解析和刷新后仍然保留；有效的同级过滤器继续按 OR 提供候选，`final` 保持独立。

honk 会忽略无法解析的过滤器，并在诊断中注明它在组内节点过滤器中的序号；只有非空的独立 `group(...)` 行不参与计数，混合谓词行仍参与计数。`group()` 会产生 `empty-subgroup` warning。需要全部节点时请删除过滤器；显式 `group()` 现在不选择任何节点。注入的 `direct` 与 `block` 是出站，不是节点池成员：无过滤器的组、`keyword:`、`regex:` 和 `subtag(...)` 都不会选中它们，只有按名字写出的过滤器才会收入，例如 `filter: name(direct)`。

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

## 嵌套代理组

嵌套 tag 必须指向已声明的组；未知 tag 会使配置在启动或 reload 时以 `invalid-nested-group-reference` 被拒绝。组管理器构图时删除每条构成环的边并记录 warning。嵌套选择深度上限为 8。每个嵌套组贡献其自身策略选出的单个叶节点，因此每次拨号最终都会解析到一个节点。

面向 Clash 的组输出保留成员 tag：`all` 字段列出直接节点名和嵌套组 tag，而不展开嵌套组。面向叶节点的健康状态与连通性遍历会展开这些 tag 下的实际节点。

## 相关文档

- [节点参考](./nodes.md)
- [路由参考](./routing.md)
- [组设计](../design/groups.md)
