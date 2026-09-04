# 组参考

本文定义当前 `group { ... }` 配置面与成员选择语义。

## 语法

每个组都是 `group { ... }` 中的命名子节：

```dae
group {
    hk {
        filter: subtag('airport') && name(keyword: 'HK')
        filter: name(regex: '^Hong Kong ')
        policy: min_moving_avg
        check_url: 'https://www.gstatic.com/generate_204'
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
| `filter: name(...)` | `filters` + `nodes` | `[]` | 按节点名选择节点。解析器把匹配结果解析为节点 UUID。 |
| `filter: subtag(...)` | `filters` + `nodes` | `[]` | 按产生节点的订阅的当前 tag 选择节点。 |
| `filter: group(...)` | `groups` | `[]` | 加入嵌套组 tag。接受逗号分隔的参数和竖线分隔的 tag。 |
| `default` | `default` | `null` | `selector` 的初始或回退成员 tag。 |
| `final` | `final_outbound` | `null` | 没有存活成员时使用的节点、组、`direct` 或 `block`。 |
| `check_url` | `check_url` | `null` | 非 Selector 策略的按组 TCP 健康检查目标。Selector 会忽略该字段并告警。 |
| —（dae 中不可配置） | `check_interval` | `null` | 按组间隔字段，单位为秒。当前运行时不读取该字段，而使用全局间隔。 |
| —（dae 中不可配置） | `tolerance` | `50` | URLTest 切换阈值，单位为毫秒。dae URLTest 组接收 `global.check_tolerance`；运行时的有效下限为 1 ms。 |
| —（dae 中不可配置） | `idle_timeout` | `null` | URLTest 在不活跃后暂停探测的阈值，单位为秒。值为 `null` 时，健康检查层使用 1800 秒。 |
| —（dae 中不可配置） | `interrupt_connections` | `false` | Selector、URLTest 或 Fallback 的选择实际变化时关闭已跟踪连接。LoadBalance 轮转不会触发。 |
| —（dae 中不可配置） | `id` | 随机 UUID | 字段缺失时生成的内部组标识。 |

## 策略

| 规范名 | 接受的 dae 拼写 | 行为 |
| ------ | --------------- | ---- |
| `selector` | `selector`、`select`、`fixed`、`fixed(0)` | 依次使用运行时选择、`default` 和第一个存活成员；选择可以是直接节点或嵌套组 tag。 |
| `urltest` | `urltest`、`min_moving_avg`、`min_avg10`、`min_last_delay` | 使用减半移动平均 `(prev + sample) / 2` 和 tolerance 选择延迟最低的存活成员；TCP 与 UDP 选择相互独立。 |
| `loadbalance` | `loadbalance`、`roundrobin`、`round_robin`、`balance` | 对存活成员轮询；每个组以及 TCP/UDP 网络各有独立计数器。 |
| `fallback` | `fallback` | 分别为 TCP 和 UDP 按声明顺序固定第一个存活成员；更靠前的成员恢复后不会立即 failback。 |
| `score` | `score` | 按目标的可靠性优先评分自动选择一个存活成员；TCP/UDP 与目标 IPv4/IPv6 地址族各自隔离。 |

策略名按 ASCII 大小写不敏感匹配。解析器匹配前会去掉可选的括号后缀，因此接受 `fixed(0)`。无法识别的策略会静默变为 `selector`；旧策略名 `honk` 明确无效，必须改用 `score`。

若组只有一个唯一叶节点、未配置 `final`，且 TCP 健康状态排除了该节点，honk 仍会把同一节点作为最后尝试。节点保持 dead，直到真实流量或探测使其恢复；这绝不表示回退到 `direct`。UDP 继续正常排除死亡成员。

每个已配置 Selector 的代理叶节点都保持热态。解析嵌套选择后，honk 会按叶节点协议保留可复用的多路复用 session、QUIC client 或一条到服务端的裸 TCP 连接；`direct` 与 `block` 不需要热资源。

### Score 策略

Score 始终随程序编译，必须以 `policy: score` 显式选择；省略 `policy` 时仍默认使用 Selector。Score 没有运行时调节项，也不会改变其他策略的行为。定位是可靠性优先，延迟与吞吐只微调可靠性已经接近的候选。

Score 先用普通健康过滤排除死亡候选，再作出权威的单成员选择。健康状态使用代理服务器可达的 IPv4/IPv6 地址族，与评分使用的业务目标地址族相互独立；因此 IPv4 代理服务器仍可承载 IPv6 目标。剩余成员先经过带 Beta 先验的 useful-outcome 可靠性下置信区间筛选；区间内的 setup/首响应延迟相对组内最快已观测候选归一，合格的主导方向 bytes/s 相对组内最高速率归一。只有未训练候选进入确定性冷探索；已训练候选不会因 attempt 数较少获得路由 bonus。最终平局按声明顺序和稳定节点身份解决，因此既不竞速成员，也不让死亡节点重新入选。

冷探索对不超过 4 个成员的组覆盖每个候选。更大的组只采样 `ceil(sqrt(n)) + 1` 个候选（不超过组大小），并周期性复检 Beta 可靠性上置信界最高的非当前成员；每 `2n` 次 Score 选择触发一次，间隔限制在 16–64。cadence 作用域为 `(group, TCP/UDP, 目标 IPv4/IPv6 地址族或 none)`，绝不包含精确目标、节点、代理健康地址族、地址或端口。小组仍完整覆盖，大组则把探测预算优先用于仍可能优于现任的候选。

所有历史计数和加权和按固定 30 分钟半衰期指数衰减。现任保护从零开始，随有效完成证据线性增长，在八次完成时达到完整 `0.01` utility 余量，因此新胜者容易纠正，久经验证的胜者获得完整滞回。新鲜失败证据会绕过该余量；全局、目标地址族和精确目标失败 envelope 取最大值而非相加，有效衰减值低于一个样本的 `0.01` 后普通保护恢复。延迟采用衰减加权均值。吞吐样本仅接纳终态成功、双向均有字节、持续至少 1 秒且主导方向至少 64 KiB 的交换；合格样本汇总主导方向 bytes/s。更短小的交换仍可影响可靠性和延迟，但不影响吞吐。这些常量不可配置。

评分按组、TCP/UDP、目标 IPv4/IPv6 地址族、规范化精确目标（小写 domain 或 IP 加端口）及节点身份隔离。精确目标证据会与有界的组/网络/地址族聚合证据分层混合，随后随衰减逐渐取得或让出主导权。有真实目标的任务同时更新两层；无目标预热只更新聚合层。嵌套选择会把一次完成的尝试归因到路径经过的每个 Score 组。

评分器的 instrumentation 虽然始终编译，但按需运行：非 Score 路径不会创建 reporter 或评分 cell。所有经过 Score 组且真实启动的 attempt 都会反馈，包括透明 TCP/UDP、DNS upstream exchange、周期 HTTP/UDP 健康探测、按需 Clash delay test、启动/Selector/UDP 预热，以及外部 UI 下载。有目标的任务使用真实 host/IP、端口、transport 和目标地址族；仅连接代理服务器的 preconnect 与 session warm-up 只更新聚合层，不会虚构业务目标。每个周期 UDP 探测还会通过属于 Score 组的每个节点，对第一个 HTTPS `global.tcp_check_url` 执行一次 ALPN 为 `h3` 的真实 TLS-in-QUIC 握手，且无论 DNS 探测成败都会运行；这个独立 `DataUdp` 样本影响 Score 评分，并且当 DNS exchange 失败而握手成功时还会把 `DataUdp` 标记为存活，使被封禁的 `:53` 检查目标不能永久判死一条正常的 UDP 数据通路。未配置 check URL 或 URL 不是 HTTPS 时不运行额外探测。该握手只记录双向有效性，不虚构 wire-byte 流量。每个已启动 attempt 都记录 setup、存在时的首响应、双向字节，以及唯一的紧凑终态；取消或进程 shutdown 保持中性，retry 则作为独立 attempt。

全部评分状态仅存于当前进程内存。精确 node-target cell 使用硬上限为 4,096 的 LRU，聚合 cell 使用另一个 4,096 项 LRU。精确目标证据衡量的是实际 transport 质量，不表示服务在语义上已解锁；需要这种粗粒度 cohort 时，应使用已有 routing 或 geosite 规则选择专用的服务 Score 组。成功的进程内 reload 复用同一共享状态并移除已删除组或成员的 cell；进程重启会清空状态。评分 cell 与仅由 scorer 持有的 domain/IP 键不会进入日志、持久化存储或任何 API 输出。Clash 仍将 Score 表示为 `type: "url_test"`，在 `now` 中显示当前聚合 TCP 胜者，并拒绝对该组执行 `PUT /proxies/{name}`。

每次已授权的多候选 Apply 按固定优先级只记录一个原因：初始探索（`coldExplore`）、周期探索（`periodicExplore`）、保持现任（`incumbentHeld`）、新鲜失败绕过（`freshFailureBypass`）、可靠性胜出（`reliabilityWinner`）或性能胜出（`performanceWinner`）。`deadFiltered` 独立记录活性过滤移除的唯一叶候选。`switchFlap` 记录已提交胜者在八次选择内返回前一胜者；探索不进入该窗口。`failStreakExcluded` 按每次 rank 累计被三连败新鲜失败门排除的候选数，`exploreBackedOff` 累计当前处于探索退避的候选数。Peek 与展示/API 读取保持中性。经鉴权的 `/stats.score.groups[]` 只导出这些按组汇总的 TCP/UDP 计数和组名，不导出 cell、节点、目标、cadence 或 manager authority。`/stats.score.cache` 导出两个 4,096 项证据 LRU 的当前 cell 数与累计淘汰数，不含任何组、节点或目标身份。

## 过滤解析

1. `group('tag')` 把嵌套 tag 加入 `groups`，不作为节点谓词求值。嵌套 tag 可以贡献该组当前策略选出的叶节点。
2. `name(...)` 匹配 `Node.name`。`subtag(...)` 把 `Node.subscription_id` 映射到当前订阅 tag 并匹配该 tag。普通参数是精确匹配，`keyword:` 是子串匹配，`regex:` 是原始正则表达式。匹配区分大小写；同一谓词中的多个参数互为候选。
3. 同一行中由 `&&` 连接的谓词按 AND 求值。在谓词前加 `!` 会对其取反。不同 `name(...)` 和 `subtag(...)` `filter:` 行之间按 OR 求值；`group(...)` 行加入嵌套候选。
4. 每次订阅刷新后都会重建过滤所得的成员关系。因此，稳定的节点 UUID 不会在订阅来源变化后保留过期成员关系。
5. 既没有节点过滤器也没有嵌套组的组会接收当前全部节点。只有嵌套组而没有节点过滤器的组只接收嵌套候选，不会接收全部节点。

## 嵌套组

嵌套选择深度上限为 8。组管理器构图时会删除每条闭环边并记录告警；未知的嵌套 tag 不会贡献候选。每个嵌套组贡献其自身策略选出的单个叶节点，因此每次拨号最终都会解析到一个节点。

面向 Clash 的组输出保留成员 tag：`all` 字段列出直接节点名和嵌套组 tag，而不展开嵌套组。面向叶节点的健康状态与连通性遍历会展开这些 tag 下的实际节点。

## 相关文档

- [节点参考](./nodes.md)
- [路由参考](./routing.md)
- [组设计](../design/groups.md)
