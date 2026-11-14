# 路由参考

`routing { ... }` 按顺序匹配流量，再把命中的流量交给指定的出站。

## 规则语法

```text
condition [&& condition ...] -> outbound[(must)]
condition [&& condition ...] -> direct(mark: value[, must])
fallback: outbound[(must)] | direct(mark: value[, must])
```

- 规则按 `priority` 升序执行，数值越小越先匹配；同优先级保持稳定的源码顺序。dae 解析器按源码顺序分配 `0, 1, ...`，流量规则及其顺序完全由用户配置决定。
- `default:` 是 `fallback:` 的别名。没有规则最终确定结果时使用 fallback 目标；省略时默认为 `direct`。
- 同一个 matcher 内以逗号分隔的参数互为备选。不同的非空条件组必须全部匹配。
- matcher 的括号参数列表可以在同一源文件内跨物理行，语句一直延续到右括号和 `-> outbound`。被包含的文件不能补全另一文件中未完成的调用。
- 成对的单引号或双引号保留内部的全部字节，包括空白、`#`、花括号、`,`、`)`、`&&` 和 `->`。引号在词法单元开头，或紧接引号外的 `(`、`,`、`:` 时开启，因此 `domain(suffix:'example.com')` 等同于 `domain(suffix: 'example.com')`。反斜杠保留原样，不作转义解码。已开启的引号必须在同一物理行闭合，否则配置以 `unterminated-quote` 错误失败。
- 前缀 `!` 只对紧随其后的单个 matcher 取反。规则仅在正向条件匹配且所有取反 matcher 都未命中时匹配。
- 流量缺少域名、进程名、MAC 或 DSCP 元数据时，对应的 matcher 算作未命中，加上 `!` 的写法反而会命中：尚未嗅探出域名的流量满足 `!domain(...)` 和 `!geosite:...`，没有进程名的流量满足 `!pname(...)`。
- 未知的非空 matcher、matcher 名称与左括号之间的空格、调用后的多余文本均使配置校验失败，并产生带位置的诊断。合取中不支持的非空条件不会被单独丢弃。
- 空项、单独的 `!` 和空参数会被跳过：`domain() && dport(443)` 等同于 `dport(443)`。没有剩余条件的规则永不匹配；兜底请用 `fallback:`。
- 引号外、词法单元开头的 `#` 才开始注释；紧贴前文的 `#` 是数据。`domain(x) -> proxy#c` 指向字面名称 `proxy#c`，并产生 `legacy-glued-hash` warning。注释请写成 `-> proxy # comment`。第一个引号外的箭头分隔动作，后续箭头保留在目标名称中，并产生 `legacy-arrow-target` warning。

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
| `domain(...)` | 裸值或 `suffix:` 表示原始后缀；`keyword:` 表示子串；`full:` 表示支持 `*` 和 `?` 的整名 glob；`regex:` 表示 Rust 正则表达式；`geosite:` 表示 geosite 代码 | `domain_suffix`, `domain_keyword`, `domain`, `domain_regex`, `geosite` |
| `dip(...)` | 目的 IPv4/IPv6 地址或 CIDR，不接受主机名；`geoip: code`。单个地址转换为 `/32` 或 `/128`；CIDR 的主机位会被清零。 | `ip`, `geo_ip` |
| `sip(...)` | 源 IPv4/IPv6 地址或 CIDR，解析方式与 `dip(...)` 相同 | `source_ip` |
| `dport(...)` | 十进制目的端口或闭区间 `start-end`，范围为 `0` 到 `65535`，且 `start <= end` | `port` |
| `sport(...)` | 十进制源端口或闭区间 `start-end`，范围为 `0` 到 `65535`，且 `start <= end` | `source_port` |
| `l4proto(...)` | `tcp`、`udp`，不区分大小写 | `protocol` |
| `pname(...)` | 子串模式，按 15 字节规范化后匹配 `argv[0]` 里可执行文件的 basename。运行时没有 BTF 偏移，或没有 verifier 允许的内核 argv 访问方式时，cgroup hook 同步改用调用线程的 `comm`。只匹配 honk 所在主机上的进程，不匹配 LAN 客户端上的应用。 | `process_name` |
| `mac(...)` | 源 MAC 地址，写作 `aa:bb:cc:dd:ee:ff`、`aa-bb-cc-dd-ee-ff`、`aabb.ccdd.eeff` 或 `aabbccddeeff`，不区分大小写 | `mac` |
| `ipversion(...)` | `4`/`ipv4`、`6`/`ipv6`，不区分大小写 | `ip_version` |
| `dscp(...)` | 十进制或带 `0x`/`0X` 前缀的十六进制值；数据包的 DSCP 值为 `0` 到 `63` | `dscp` |

每个正向字段在 `RoutingCondition.not` 下都有对应列表；解析器把 `!matcher(...)` 放入该列表。同一字段中的多个值互为备选。

domain 模式、后缀、关键字、正则表达式与 `geosite` 都是同一条件内的备选，因此 `domain(geosite: netflix, suffix: imgur.com)` 命中任一即可。同一规则中多个 `domain(...)` 调用写入相同字段，同样互为备选。

`full:`、`suffix:` 和 `keyword:` 区分大小写。`full:` 匹配整个名称，`*` 匹配任意字符序列，`?` 匹配一个字符，其他字符都按字面处理。`suffix:` 按原始文本比较后缀，因此 `suffix: example.com` 也会匹配 `notexample.com`。要按标签边界匹配域名本身及其子域名，使用 `domain(regex: '(^|\.)example\.com$')`。geosite 条目不区分大小写，并按标签边界匹配后缀。

`regex:` 使用 [Rust regex 语法](https://docs.rs/regex/latest/regex/#syntax)，不是 glob 语法；无效模式会使 honk 构建路由器时失败。带前缀的空值会保留：`domain(suffix: '')` 匹配所有域名，与 `domain()` 不同。

dae 也接受独立的 `geosite:`、`geoip:`、`domain:`、`suffix:`、`keyword:`、`full:` 和 `regex:` 谓词，可加前缀 `!` 并参与合取。`domain:example.com` 表示后缀匹配，不是 `full:` 匹配。

```dae
routing {
    domain(full: '*.example.com') -> proxy
    domain(regex: '(^|\.)example\.com$') -> proxy
    domain(suffix:'example.com') -> proxy
    !geosite:cn -> proxy
    fallback: direct
}
```

上面的 glob 匹配子域名，但不匹配 `example.com` 本身；正则表达式同时匹配两者。与 `suffix: example.com` 不同，两者均不匹配 `notexample.com`。

`dip(...)` 和 `sip(...)` 中的无效地址、无效的 MAC 或 DSCP 值，以及不支持的 `l4proto` 或 `ipversion` 值，都会被直接丢弃，不报错。没有剩下有效值的 matcher 不匹配任何流量，其取反形式则匹配满足规则其余条件的全部流量。格式错误的端口以 `Invalid port` 失败；内核路由策略编译器会拒绝 `443-80` 这样的反向区间。

`mac(...)` 规则命中后，`direct(must)` 可以让该客户端绕过透明 DNS；普通 `direct` 不行。LAN/WAN 的 TCP/UDP 目的端口 `53` 在完成既有入口与控制面排除后，会执行一次正常的有序流量策略，不单独扫描 must 规则。LAN 端口 `53` 跳过本地 socket 探测，即使 dnsmasq 或 `dns.bind` 已监听该目的地址也不例外。

## 出站目标与 `must`

| 目标 | 含义 |
| --- | --- |
| `direct` | 内置直连出站 |
| `block` | 内置阻断出站 |
| 代理组名 | 按该出站组及其策略解析 |

裸节点名不能直接作出站目标，`Config::validate` 会拒绝这类配置。先把节点加入组，例如用 `filter: name('node')` 建一个组，再引用组名。组与节点也不允许同名。每份配置最多可定义 250 个顶层用户组；更高的路由序号由 ABI 保留。

在目标后追加 `(must)`，命中的结果会立即结束规则搜索，并跳过嗅探与后续的域名重路由，语义同 `no_sniff`。选中的 direct、block 或 group 动作照常执行，`must` 并不等于整体绕过 honk。Clash 的 `Global` 和 `Direct` 模式都无法覆盖 must 结果或 `block`。它也不是历史上那个先设置 must、再继续扫描的内部 `MustRules` opcode。

TCP/UDP 目的端口 `53` 的接管权限如下；本地 `:53` listener socket 不能先于 LAN 流量策略接收报文：

| 流量策略结果 | DNS 行为 |
| --- | --- |
| `direct(must)` | 跳过 DNS 控制器。LAN 流量及无 mark 的 WAN 流量使用 Linux 原生交付；非零 mark 的 WAN 结果由带 mark 的直连 socket 重新执行策略路由查找。 |
| `block(must)` | 丢弃报文。 |
| `group(must)` | 通过该组的原始 TCP relay / UDP `PacketTransport` 转发，跳过 honk DNS 的 hosts、缓存、请求/响应策略和投影。 |
| 非 `must` 的 `direct`、组或 `block` | 有效 DNS 查询仍归 DNS 控制器处理；Clash 模式直连 offload 不会剥夺接管权限。 |

畸形的非 `must` UDP53 负载走通用 UDP 回退，不进入 `DnsController`。表中的控制器行为只描述合法 DNS，并不表示端口 53 上的所有负载都是 DNS。路由元数据的 admission 遵循[控制面的 TCP/UDP 区分](../design/control-plane.md#透明代理入口)。LAN 本地 socket 优先接收报文这条规则，只适用于非 53 目的端口，并按传输分别判断。通配绑定还要求完整 FIB 返回 `NOT_FWDED`，非 DNS 的 TCP 纯 SYN 仍然跳过探测。透明 LAN 与原生/loopback 交付的区别，见[DNS 所有权状态机](../design/dns.md#dns-所有权状态机)。

admission 与策略规模限制见 [LAN 单源新流预算](../design/datapath.md#单源新流限制)和[编译策略容量](../design/routing.md#受限原生后端)。

## 嗅探

honk 只嗅探数据路径交给控制面的流量；TC hook 留在 Linux 原生路径上的流量不经过嗅探。

- TCP：最多读取 4096 字节，提取 TLS SNI 或 HTTP `Host`。读到的字节在中继开始前写入选中的出站，所以嗅探不消费应用数据。
- UDP：解密 QUIC v1/v2 的 Initial packet，提取 TLS ClientHello 的 SNI。

以下情况跳过嗅探：

- `dial_mode` 为 `ip`。
- 数据路径的 handoff 已是最终的 `direct` 或 `block`。
- 命中的规则以 `(must)` 结尾。
- 仅 TCP：同一目的地址和出站签名连续三次失败后进入 negative cache，十分钟内不再嗅探。

嗅探到的名称如何使用取决于 `dial_mode`，见[拨号模式](./global.md#拨号模式)；`domain` 模式下名称要先通过 DNS reality check。`sniffing_timeout` 是兼容字段，控制面不读取它。上限与超时见[嗅探与流初始化](../design/control-plane.md#嗅探与流初始化)。

## 策略路由 mark

`direct(mark: 512)` 与 `direct(mark: 0x200)` 选择相同的直连 mark。无前缀数字按十进制解析，包括前导零；`0x`/`0X` 前缀表示十六进制。范围为 `0..=0x3fffffff`；`0xc0000000` 位属于数据路径，不供用户策略使用。二进制/八进制前缀、下划线、正负号、溢出、未知选项以及重复的 `mark`/`must` 选项均拒绝配置；与全局 mark 标量不同，格式错误的直连 mark 不会静默变为零。mark 只支持 `direct`，不支持代理目标和组目标。

`direct(mark: 0x200, must)` 与 `direct(must, mark: 0x200)` 等价，直连选项列表内部允许空白。`fallback:` 及其别名 `default:` 接受相同形式。合并 include 后，最后出现的 fallback 会替换整个回退动作，普通 `direct` 不保留 mark 与 `must`。fallback 只在全部普通规则之后生效，即使源文件里有些规则声明在它后面。

在 IPv4/IPv6 的 TCP 和 UDP 上，非零直连 mark 替换全局 socket mark 的策略有效位，**不与 `so_mark_from_dae` 或 `0x100` 按位 OR**。原生直连、NFQUEUE 批准的直连以及用户态直连 socket，会在低 30 位策略值之外额外保留 `CLASSIFIED_MARK`，这个位是 `0x40000000`。例如配置 `0x200` 时可观测到 `0x40000200`，Linux 策略路由规则必须用掩码排除保留位。`mark: 0` 表示未指定：用户态发起的直连 socket 使用全局 mark，原生直连不添加用户 mark。代理 carrier、bootstrap 和 DNS 控制器上游使用全局值，不继承被拦截流量规则的 mark。

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

请为表 `100`、`200` 分别配置对应地址族的直连路由和默认路由，并处理各 WAN 的源地址、NAT 与防火墙权限；honk 不管理这些路由表。LAN 原生直连在 Linux 转发路由查找前设置 mark。主机/WAN 出站命中非零直连 mark 时，会经过用户态直连转发，由新 socket 触发带 mark 的路由查找，不会保留客户端的原始源 socket；这条路径也适用于 `must`，包括原始端口 53 的流量。`must` 仍跳过 DNS 控制器。未指定 mark 的原生 `direct(must)` 保持既有的源地址保留路径。修改全局 mark 需要重启，流量规则可以 reload。编译策略最多允许 256 个不同的非零 `direct(mark: ..., must)` 值，包括带 mark 的 `must` fallback。WAN 原始 UDP/53 报文携带一个 mark 表索引，该索引随它的路由 generation 固定，不会借用其他报文 tuple handoff 的 mark。

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

运行时资源解析规则见[全局参考](./global.md)。`geoip: private` 使用内置 CIDR 集，不需要 `geoip.dat`。

`private` 不限于 RFC 1918 LAN 地址，还包括 CGNAT、loopback、链路本地、文档和组播等范围：

| 地址族 | CIDR |
| --- | --- |
| IPv4 | `10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.0.0.0/24`、`192.0.2.0/24`、`192.88.99.0/24`、`192.168.0.0/16`、`198.18.0.0/15`、`198.51.100.0/24`、`203.0.113.0/24`、`224.0.0.0/4`、`240.0.0.0/4`、`255.255.255.255/32` |
| IPv6 | `::1/128`、`fc00::/7`、`fe80::/10` |

找不到被引用的 Geo 资源时，引擎会记一条带缺失文件名的 warning，并以空的 matcher 启动。没有规则引用的资源不会产生缺失文件 warning。空的 Geo matcher 不匹配任何流量，因此 `!domain(geosite: ...)` 或 `!dip(geoip: ...)` 会匹配满足规则其余条件的全部流量：资源缺失只会扩大取反规则的范围，不会让规则失效。

geosite 类目和 GeoIP 代码不区分大小写。geosite 代码可以用 `category@attr` 选择属性，属性 key 不区分大小写。第一个 `@` 之后的全部内容都是选择器，包括后续的 `@`。未知的 geosite 类目、未知的 GeoIP 代码，或不匹配任何条目的选择器，都会记一条 warning 并按空 matcher 处理，对取反规则的影响同上。

## 显式本地路由

honk 不会在启动、reload 或接口变化时注入网关地址的 `direct(must)` 规则，也没有隐藏的内核地址白名单可以替代。接口地址仍用于拓扑检测、ECS 刷新和健康探测。要让网关管理访问不随代理健康状态消失，请按所需顺序自己写一条直连规则，例如：

```dae
dip(192.168.50.1, fd00:50::1) && !dport(53) -> direct(must)
```

这是一条可选的用户规则，honk 不会自动插入。它把端口 `53` 留给透明 DNS 接管，除非另一条终局 `must` 结果接管了该端口。本地 socket 优先接收非 53 目的端口，这是入口归属判断，并不意味着所有网关地址都强制直连；探测在报文所在的当前网络命名空间里进行。非 DNS 的 TCP 纯 SYN 仍沿用现有探测策略，因此不加配置时，honk 不保证网关管理面始终可达。

使用真实 LAN 绑定时，honk 会按编译后规则的实际顺序检查覆盖情况。如果无法确认下列条件成立，它就发出 warning：配置中已观测到的 LAN/WAN 网卡地址，在 TCP 和 UDP 的目的端口 `1–65535` 上都有无条件的 `direct(must)` 覆盖，端口 `53` 除外。`direct(must)` fallback 也算覆盖。

检查在启动时、成功应用流量路由变化后，以及观测到网络变化时执行；无变化或仅节点变化的 reload 不会重复检查。尚不存在的网卡或尚未取得的地址，会在发现后重新检查。这只是提示，不阻止启动或 reload，也不改变显式阻断和规则顺序。依赖来源、域名、进程等条件的规则，以及拆分的端口覆盖，可能是你有意设置的合法策略，仍可能被判为无法确认。该 warning 不证明 listener、防火墙或端到端管理访问可达。

宽泛的私网 `direct(must)` 规则现在也会绕过 LAN 私网 DNS。要保留这部分 DNS 接管，必须在规则里显式加上 `&& !dport(53)`。原生 `direct(must)` 不会由 honk 改写客户端源 IP/端口，但是否仍发生 SNAT/MASQUERADE，取决于其他防火墙和网络配置。被绕过的应答如何投影，以及它与 `asis` 有何区别，见[DNS 来源边界](../design/dns.md#入口路径)。

## Fail-closed 行为

健康检查把一个出站标记为失活后，eBPF 数据面通常会用 `TC_ACT_SHOT` 丢弃路由到它的新流，绝不会静默泄漏到 `direct`。未配置 `final`、且只有一个唯一叶节点的 TCP 组是例外：它仍把这个代理作为最后尝试，让真实流量有机会证明恢复。UDP 和全部叶节点都失活的多叶节点组仍保持 fail-closed。含有 `direct` 或 `block` 内置成员的组则永远不会失活，因为内置节点从不被判定失活，group-OR 槽始终开放。目的端口 `53` 在 TCP 和 UDP 上都豁免这种健康检查丢包；没有终局用户 `must` 结果时，DNS 仍可到达控制面。

为应对节点故障，可以配置以下路径：

- 添加 `dip(geoip: private) -> direct(must)`，让私有网络流量不依赖代理健康状态。这条规则也会绕过 LAN 私网 DNS，要保留接管就显式加上 `&& !dport(53)`。
- 让 `fallback:` 指向至少包含两个节点的 [`fallback` 代理组](./groups.md)，而不是单个节点。
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
