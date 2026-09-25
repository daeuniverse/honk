# 路由参考

`routing { ... }` 定义有序的流量匹配器及其出站目标。

## 规则语法

```text
condition [&& condition ...] -> outbound[(must)]
condition [&& condition ...] -> direct(mark: value[, must])
fallback: outbound[(must)] | direct(mark: value[, must])
```

- 规则按 `priority` 升序执行，数值越小越先运行；同优先级保持稳定的源码顺序。dae 解析器按源码顺序分配 `0, 1, ...`，流量规则及其顺序完全由用户配置决定。
- `default:` 是 `fallback:` 的别名。没有规则最终确定结果时使用 fallback 目标；省略时默认为 `direct`。
- 同一个 matcher 内以逗号分隔的参数互为备选。不同的非空条件组必须全部匹配。
- 匹配器的括号参数列表可以在同一源文件内跨物理行，语句一直延续到右括号和 `-> outbound`。被包含的文件不能补全另一文件中未完成的调用。
- 成对的单引号或双引号保留内部的全部字节，包括空白、`#`、花括号、`,`、`)`、`&&` 和 `->`。引号只在词法单元开头，或紧接引号外的 `(`、`,` 时开启；带前缀的参数可把加引号的值写成独立词法单元，例如 `domain(full: 'example.com')`。反斜杠保留原样，不作转义解码。已开启的引号必须在同一物理行闭合，否则配置以 `unterminated-quote` 错误失败。
- 前缀 `!` 只对紧随其后的单个 matcher 取反。规则仅在正向条件匹配且所有取反 matcher 都未命中时匹配。
- 对取反的域名或 geosite matcher，未知或尚未嗅探到的域名视为“不是 x”，因此不会否决该规则。
- 未知的非空匹配器、匹配器名称与左括号之间的空格、调用后的多余文本均使配置校验失败，并产生带位置的诊断。合取中不支持的非空条件不会被单独丢弃。空流量条件和空参数的既有行为保持不变。
- 引号外、词法单元开头的 `#` 才开始注释；紧贴前文的 `#` 是数据。`domain(x) -> proxy#c` 指向字面名称 `proxy#c`，并产生 `legacy-glued-hash` 警告。注释请写成 `-> proxy # comment`。第一个引号外的箭头分隔动作，后续箭头保留在目标名称中，并产生 `legacy-arrow-target` 警告。

```dae
routing {
    sip(
        10.10.10.24/32,
        10.10.10.25/32
    ) && !dport(53) -> direct(must)
    default: proxy
}
```

## 条件函数

| 函数 | 接受的参数 | 内部 `RoutingCondition` 字段 |
| --- | --- | --- |
| `domain(...)` | 裸值或 `suffix:` 表示后缀；`keyword:` 表示子串；`full:` 表示完整名称；`regex:` 表示正则表达式；`geosite:` 表示 geosite 代码 | `domain_suffix`, `domain_keyword`, `domain`, `domain_regex`, `geosite` |
| `dip(...)` | 目的 IP/CIDR；`geoip: code` | `ip`, `geo_ip` |
| `sip(...)` | 源 IP/CIDR | `source_ip` |
| `dport(...)` | 目的端口或闭区间 `start-end` | `port` |
| `sport(...)` | 源端口或闭区间 `start-end` | `source_port` |
| `l4proto(...)` | `tcp`, `udp` | `protocol` |
| `pname(...)` | 按 15 字节规范化的子串模式，匹配 `argv[0]` 的可执行文件 basename；运行时 BTF 偏移或 cgroup verifier 拒绝内核 argv 读取时，cgroup hook 同步使用调用线程的 `comm` | `process_name` |
| `mac(...)` | 源 MAC 地址 | `mac` |
| `ipversion(...)` | `4`/`ipv4`, `6`/`ipv6` | `ip_version` |
| `dscp(...)` | 十进制或带 `0x`/`0X` 前缀的十六进制 DSCP 值 | `dscp` |

每个正向字段在 `RoutingCondition.not` 下都有对应列表；解析器把 `!matcher(...)` 放入该列表。同一字段中的多个值互为备选。

普通 domain pattern/suffix/keyword 互为同一条件内的备选；同一规则另有 `geosite`
字段时，它仍是一个独立的 AND 条件。

`mac(...)` 与其他流量条件一样，可以通过终局 `direct(must)` 规则绕过透明 DNS；普通 `direct` 不会取消 DNS 接管。LAN/WAN TCP/UDP 目的端口 `53` 在既有入口与控制平面排除后，执行一次正常有序流量策略，不单独扫描 must 规则。LAN 端口 `53` 跳过本地套接字探测，即使 dnsmasq 或 `dns.bind` 已监听该目的地址也不例外。

## 出站目标与 `must`

| 目标 | 含义 |
| --- | --- |
| `direct` | 内建直连出站 |
| `block` | 内建阻断出站 |
| 组名 | 按该出站组及其策略解析 |

裸节点名不是合法的出站目标，`Config::validate` 会拒绝：把节点包进一个组（例如 `filter: name('node')`）后引用组名。组与节点也不允许同名。每份配置最多可定义 250 个顶层用户组；更高的路由序号由 ABI 保留。

追加 `(must)` 后，命中的结果立即终结规则搜索，并跳过嗅探与后续域名重路由（`no_sniff` 语义）。它保留选中的 direct、block 或 group 动作，并非一概绕过 honk。Clash `Global` 和 `Direct` 模式都不能覆盖 must 结果或 `block`。它不是历史内部“设置 must 后继续扫描”的 `MustRules` opcode。

TCP/UDP 目的端口 `53` 的接管权限如下；本地 `:53` 监听 socket 不能先于 LAN 流量策略接收报文：

| 流量策略结果 | DNS 行为 |
| --- | --- |
| `direct(must)` | 跳过 DNS 控制器。LAN 流量及无 mark 的 WAN 流量使用 Linux 原生交付；非零 mark 的 WAN 结果由带 mark 的直连套接字重新执行策略路由查找。 |
| `block(must)` | 丢弃报文。 |
| `group(must)` | 通过该组的原始 TCP relay / UDP `PacketTransport` 转发，跳过 honk DNS 的 hosts、缓存、请求/响应策略和投影。 |
| 非 `must` 的 `direct`、组或 `block` | 有效 DNS 查询仍归 DNS 控制器处理；Clash 模式直连 offload 不会抢走接管权限。 |

畸形的非 `must` UDP53 payload 保留通用 UDP 回退，不进入 `DnsController`；控制器一行不表示所有端口 53 payload 都是 DNS。路由元数据准入遵循[控制面的 TCP/UDP 区分](../design/control-plane.md#透明代理入口)。LAN 本地 socket 优先接收仅适用于非 53 目的端口，按 transport 分别判断；通配监听仍需完整 FIB 返回 `NOT_FWDED`，非 DNS TCP 纯 SYN 仍跳过探测。透明 LAN 与原生/loopback 交付的区别见[DNS 所有权状态机](../design/dns.md#dns-所有权状态机)。

## 策略路由 mark

`direct(mark: 512)` 与 `direct(mark: 0x200)` 选择相同的直连 mark。
无前缀数字按十进制解析（包括前导零），`0x`/`0X` 前缀表示十六进制。
范围为 `0..=0x3fffffff`；`0xc0000000` 位属于数据路径，不供用户策略使用。
二进制/八进制前缀、下划线、正负号、溢出、未知选项以及重复的 `mark`/`must`
选项均拒绝配置。与全局 mark 标量不同，格式错误的直连 mark 不会静默变为零。
mark 只支持 `direct`，不支持代理/组目标。

`direct(mark: 0x200, must)` 与 `direct(must, mark: 0x200)` 等价，
直连选项列表内部允许空白。`fallback:` 及其别名 `default:` 接受相同形式。
合并 include 后最后出现的 fallback 替换整个回退动作（普通 `direct` 会清除 mark 与 `must`），
且只在全部普通规则之后生效，即使部分规则在该 fallback 后面声明。

对于 IPv4/IPv6 的 TCP 和 UDP，非零直连 mark 替换全局套接字 mark 的策略有效位，
**不会与 `so_mark_from_dae` 或 `0x100` 按位 OR**。原生直连、
NFQUEUE 批准的直连以及用户态直连套接字，会在低 30 位策略值之外保留
`CLASSIFIED_MARK`（`0x40000000`）。例如配置 `0x200` 时可观测到
`0x40000200`，Linux 策略路由规则必须使用掩码排除保留位。
`mark: 0` 表示未指定：用户态发起的直连套接字使用全局 mark，
原生直连不添加用户 mark。代理承载连接、bootstrap 和 DNS 控制器上游
使用全局值，不继承被拦截流量规则的 mark。

例如，选择两个由用户配置的 WAN 路由表：

```dae
global {
    so_mark_from_dae: 0x200
}
routing {
    domain(suffix: example.net) -> direct(mark: 0x300)
    fallback: direct(mark: 0x200)
}
```

```sh
ip -4 rule add pref 10000 fwmark 0x200/0x3fffffff lookup 100
ip -6 rule add pref 10000 fwmark 0x200/0x3fffffff lookup 100
ip -4 rule add pref 10001 fwmark 0x300/0x3fffffff lookup 200
ip -6 rule add pref 10001 fwmark 0x300/0x3fffffff lookup 200
```

请为表 `100`、`200` 分别配置对应地址族的直连路由和默认路由，
并处理各 WAN 的源地址、NAT 与防火墙权限；honk 不管理这些路由表。
LAN 原生直连在 Linux 转发路由查找前设置 mark。主机/WAN 出站命中非零
直连 mark 时会经过用户态直连转发，由新套接字触发带 mark 的路由查找；
这也适用于 `must`（包括原始端口 53 流量），不会保留客户端原始源套接字。
`must` 仍跳过 DNS 控制器。未指定 mark 的原生 `direct(must)`
保持既有的源地址保留路径。修改全局 mark 需重启，流量规则可重载。
编译策略最多允许 256 个不同的非零 `direct(mark: ..., must)` 值，包括带 mark 的 `must` fallback。WAN 原始 UDP/53 报文携带绑定路由代际的不可变 mark 表索引，绝不从另一报文的 tuple handoff 借用 mark。

## Geo 资源

`geoip:` 和 `geosite:` 条件使用 `geoip.dat` 与 `geosite.dat`。引擎按以下顺序选择第一个已存在的普通文件：

| 优先级 | 位置 |
| --- | --- |
| 1 | `$DAE_LOCATION_ASSET/<file>` |
| 2 | `global.data_dir/<file>` |
| 3 | `/var/share/honk/<file>`（`LEGACY_DATA_DIR`） |
| 4 | 进程工作目录中的 `./<file>` |
| 5 | `/usr/local/share/honk/<file>` |
| 6 | `/usr/share/honk/<file>` |
| 7 | `/usr/local/share/dae/<file>` |
| 8 | `/usr/share/dae/<file>` |
| 9 | `/etc/dae/<file>` |

运行时资源解析规则见[全局参考](./global.md)。`geoip: private` 使用内建 CIDR 集，不需要 `geoip.dat`。

找不到被引用的 Geo 资源时，引擎会记录包含缺失文件名的警告。未使用的资源不会触发缺失文件警告。

geosite 代码可以用 `category@attr` 选择属性。属性名按大小写不敏感方式比较。第一个 `@` 后的全部内容都是选择器，包括后续的 `@`。未知类目或没有条目命中的选择器会记录告警、展开为零个 matcher，并且永不匹配。

## 显式本地路由

honk 不再在启动、重载或接口变化时注入网关地址的 `direct(must)` 规则，也不会用隐藏的内核地址白名单替代。接口地址仍用于拓扑检测、ECS 刷新和健康探测。需要保障网关管理访问时，请按所需顺序显式配置直连规则，例如：

```dae
dip(192.168.50.1, fd00:50::1) && !dport(53) -> direct(must)
```

这是一条可选的用户规则，不是运行时自动规则。它保留端口 `53` 的透明 DNS 接管，除非其他终局 `must` 结果取得所有权。非 53 本地 socket 的优先接收属于入口归属判断，不等于所有网关地址强制直连；探测在报文所在的当前网络命名空间进行。非 DNS TCP 纯 SYN 的现有探测策略不变，因此不能承诺无需配置即可始终访问网关管理面。

使用真实 LAN 绑定时，如果无法按已编译规则的实际顺序确认：已观测到的配置
LAN/WAN 网卡地址，其 TCP/UDP 目的端口 `1–65535`（排除 `53`）均有无条件
`direct(must)` 覆盖（`direct(must)` fallback 也计入），honk 会告警。检查发生在启动、成功应用流量路由变化和
观测到网络变化时；无变化或仅节点变化的重载不会重复路由检查。尚不存在的网卡
或尚未取得的地址会在被发现后重新检查。
这只是提示，不阻止启动或重载，也不改变显式阻断和规则顺序。依赖来源、域名、
进程等条件的规则，以及拆分的端口覆盖，可能是用户有意设置的合法策略，
仍可能得到“无法确认”的告警；它不证明监听器、防火墙或端到端管理访问可达。

现有宽泛私网 `direct(must)` 规则现在也会绕过 LAN 私网 DNS。希望保留这部分 DNS 接管时，由用户显式加入 `!dport(53)`。原生 `direct(must)` 不会由 honk 改写客户端源 IP/端口，但是否仍发生 SNAT/MASQUERADE 取决于其他防火墙和网络配置。绕过应答的投影影响及其与 `asis` 的区别见[DNS 来源边界](../design/dns.md#入口路径)。

## Fail-closed 行为

健康检查把出站标记为死亡后，eBPF 数据面通常会用 `TC_ACT_SHOT` 丢弃路由到该出站的新流，绝不会静默泄漏到 `direct`。未配置 `final` 且只有一个唯一叶节点的 TCP 组会让同一代理继续作为最后尝试，使真实流量可以证明恢复。UDP 和全部叶节点失活的多叶节点组仍保持 fail-closed；但含有 `direct`/`block` 内建成员的组永不失活：内建节点永远不会被判定死亡，因此 group-OR 槽保持开放。TCP 和 UDP 的目的端口 `53` 均豁免该健康检查丢包；没有终局用户 `must` 结果时，DNS 仍可到达控制面。

要让网关能承受节点故障：

- 添加 `dip(geoip: private) -> direct(must)`，使私有网络流量不依赖代理健康状态；它也会绕过 LAN 私网 DNS，希望保留接管时需显式加上 `&& !dport(53)`。
- 让 `fallback:` 指向至少包含两个节点的 [`fallback` 策略组](./groups.md)，而不是单个节点。
- 至少保留一个走直连路径的 DNS 上游。

## 完整示例

```dae
routing {
    domain(suffix: doubleclick.net) -> block
    pname(NetworkManager, systemd-resolved) && l4proto(udp) && dport(53) -> direct(must)
    # 宽泛私网 must 也绕过 LAN 私网 DNS；需保留接管时显式加上 && !dport(53)。
    dip(geoip: private) -> direct(must)
    sip(
        10.10.10.24/32,
        10.10.10.25/32
    ) && !dport(53) -> direct(must)
    mac(aa:bb:cc:dd:ee:ff) && ipversion(4) -> direct
    domain(
        full: api.example.com,
        suffix: example.org,
        keyword: tracker,
        regex: '^bad[0-9]+\.example$',
        geosite: category-games@cn
    ) -> proxy
    dip(geoip: cn, 203.0.113.0/24) && sport(1024-65535) && dscp(46) -> hk
    l4proto(tcp) && dport(80, 443, 8080-8090) -> proxy
    !domain(geosite: category-ads-all) && !dip(geoip: cn) -> resilient
    fallback: resilient
}
```

这里 `proxy`、`hk` 和 `resilient` 都是组名。

## 相关文档

- [路由设计](../design/routing.md)
- [全局参考](./global.md)
- [组参考](./groups.md)
