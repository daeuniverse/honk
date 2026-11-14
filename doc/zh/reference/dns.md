# DNS 配置参考

`dns { ... }` 用 dae 语法配置 DNS，覆盖命名上游、request 和 response 路由、hosts、EDNS Client Subnet、缓存和可选的独立 listener。

## 示例

```dae
dns {
    # 省略 bind 可保持独立 listener 关闭。
    # bind: 'tcp+udp://:1053'
    use_host: true
    ipversion_prefer: 4

    upstream {
        default: 'udp://223.5.5.5:53'
        cloudflare_dot: 'tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com'
        google_doh: 'https://dns.google/dns-query' -> proxy
    }

    routing {
        request {
            sip(192.168.50.0/24, 100.64.0.0/10) -> google_doh
            qname(geosite: category-ads-all) -> reject
            qname(suffix: cn) -> default
            qtype(https) -> reject
            fallback: default
        }
        response {
            upstream(google_doh) -> accept
            ip(geoip: private) && !qname(geosite: cn) -> google_doh
            fallback: accept
        }
    }

    optimistic_cache: true
    optimistic_cache_ttl: 600
    max_cache_size: 10000
    fixed_domain_ttl {
        ddns.example.org: 10
        nocache.test: 0
    }
}
```

## 字段

| Key | 默认值 | 含义 |
| --- | --- | --- |
| `bind` | `省略`（`""`） | 可选的独立 DNS listener；空值只关掉这个 listener。见 [`bind`](#独立-listenerbind)。 |
| `use_host` | `省略`（`false`） | 可重复配置的 hosts 来源：`true` 或路径 `/etc/hosts` 按标准 hosts 语法读取，其他路径按 OxiDNS 兼容的规则文件读取。见 [`use_host`](#hosts-快照use_host)。 |
| `client_subnet` | `省略`（`""`） | 命名上游使用的可选 EDNS Client Subnet 预设值，可取 IPv4、IPv4 CIDR、`auto` 或 `auto(IPv4)`。见 [`client_subnet`](#edns-client-subnetclient_subnet)。 |
| `upstream { ... }` | `省略`（`default: 'udp://223.5.5.5:53'`） | 命名上游服务器，即 Clash 配置中的 `nameserver`；第一个显式 `upstream` 块会替换内置条目。见 [上游](#上游)。 |
| `routing { ... }` | `省略`（无规则；request fallback 为 `default`；response fallback 为 `accept`） | 有序的 request 和 response 路由，第一条匹配的规则生效。见 [DNS 路由](#dns-路由)。 |
| `ipversion_prefer` | `省略`（`both`） | 地址族偏好；honk 解析不了的值保持 `both`，并输出诊断。见 [`ipversion_prefer`](#ipversion_prefer)。 |
| `optimistic_cache` | `省略`（`true`） | 启用正、负缓存的读取和写入。见 [`optimistic_cache`](#optimistic_cache)。 |
| `optimistic_cache_ttl` | `省略`（`600` 秒） | 除 NXDOMAIN、SERVFAIL 和 NODATA 外，把所有应答的缓存 TTL 和报文 TTL 设为固定值；写 `0` 用上游应答里的最小 TTL。见 [`optimistic_cache_ttl`](#optimistic_cache_ttl)。 |
| `optimistic_stale_reply_ttl` | `省略`（`30` 秒） | serve-stale 正应答使用的 TTL；非零值替换每个非 OPT RR 的 TTL，写 `0` 保留缓存里已按策略改写的 wire TTL。见 [`optimistic_stale_reply_ttl`](#optimistic_stale_reply_ttl)。 |
| `max_cache_size` | `省略`（`10000`） | 缓存条目数上限，最大 100,000；它也决定分片字节预算。见 [`max_cache_size`](#max_cache_size)。 |
| `fixed_domain_ttl { domain: seconds }` | `省略`（空） | 按域名覆盖正应答和 NODATA 的 TTL；写 `0` 时，所有响应码的应答都不缓存。见 [`fixed_domain_ttl`](#fixed_domain_ttl)。 |

所有 key 都是可选的。默认值栏写 `省略`，表示该 key 可以省略，括号里是它的默认值或等效写法。标量的延伸范围、注释规则和布尔取值见[解析规则](#解析规则)。

SIGHUP reload 会把 `bind` 的主机、端口或传输集合变化当作需重启项并拒绝；见 [`bind`](#独立-listenerbind)。

## 独立 listener（`bind`）

独立 listener 用主机网络命名空间里的普通 socket，不设置 bypass mark。关掉它不影响透明 TCP/UDP 53 端口拦截；透明路径遵循[流量规则所有权](./routing.md#出站目标与-must)。

| 值 | 结果 |
| --- | --- |
| 省略或 `""` | 不创建独立 listener。 |
| 数字 `IP:port`，如 `127.0.0.1:1053` 或 `[::1]:1053` | UDP listener。 |
| `udp://host:port` | UDP listener。 |
| `tcp://host:port` | TCP listener。 |
| `tcp+udp://host:port` | 在同一地址和端口创建 TCP 和 UDP listener。 |

主机名必须带 scheme，例如 `udp://localhost:1053`。IPv6 字面量必须加方括号。`tcp+udp://:1053` 这种空 host 表示通配地址。每种形式都要显式写出十进制 `u16` 端口。端口写 `0` 表示申请临时端口，honk 会记录最终选定的地址。

裸主机名无效。解析器还会拒绝 userinfo、path、query、fragment、反斜杠、IPv6 zone identifier、错误的方括号、不支持的 scheme 和超范围的端口。用主机名时，honk 按系统解析顺序逐个尝试地址，选出第一个能让所有请求传输都绑定成功的地址。绑定是同步执行的，而且必须全部成功；有一个失败，honk 就关掉其他已选的 socket，让启动失败。

listener 归进程所有。SIGHUP reload 接受语义等价的不同写法；但主机、端口或传输集合只要变了，就算需重启项，SIGHUP 会拒绝。通配绑定或绑在 LAN 侧会暴露一个无认证的递归解析器，必须用主机防火墙限制来源，绝不能发布到不可信网络。

监听 `:53` 不会抢在 LAN 流量策略之前收到查询。即使 dnsmasq 或 `dns.bind` 占着这个 socket，不带 `must` 的 LAN TCP/UDP53 查询仍然进入 honk 透明 DNS。主机 loopback 上的查询，以及显式原生 `direct(must)` 交付的查询，仍能到达这个普通 listener；见[listener 矩阵](../design/dns.md#dns-所有权状态机)。

```dae
dns {
    bind: 'tcp+udp://127.0.0.1:1053'
}
```

## Hosts 快照（`use_host`）

`use_host` 可以重复配置。不区分大小写的 `true`、`yes`、`1` 或 `on` 会把 `/etc/hosts` 加进来。`false`、`no`、`0`、`off` 或空值不加来源，也不会移除此前的来源。其他值都是路径。`/etc/hosts` 不管是用 `true` 加入还是直接写成路径，都按标准 `IP canonical-name aliases...` 语法读取；其他路径都是 OxiDNS 兼容的 `matcher target...` 规则文件。honk 按声明顺序把每个来源读一次，合并成一份快照；后面的来源会覆盖前面相同的精确名称或 matcher。同一路径只加载一次。

```dae
dns {
    use_host: true
    use_host: false # 不会移除上面加入的 /etc/hosts。
    use_host: 'hosts.txt'
}
```

绝对路径保持原样。相对路径依次在 `global.data_dir` 下、`/var/share/honk` 下和工作目录里找已有的副本；三处都没有时，路径仍定位到 `global.data_dir` 下。查询时只用生成好的不可变快照，不做文件 I/O。

自定义 matcher 支持 `full:example.com`，也可以只写不带前缀的精确名称；`domain:example.com` 匹配该名称以及标签边界内的所有子域；另外支持 `keyword:text` 和 `regexp:pattern`。匹配优先级依次是精确名称、最长的 domain 后缀、第一个匹配的 regexp、第一个匹配的 keyword。同一 matcher 定义多次时，后者替换它的目标。full、domain 和 keyword 名称按 ASCII 大小写不敏感处理，末尾点会归一化。regexp 保持大小写敏感，匹配的是不带末尾点的小写名称；需要忽略大小写时写 `(?i)`。honk 会去掉重复地址。

规则文件每行一个 matcher，后面跟一个或多个 IPv4/IPv6 地址，或者恰好一个别名目标主机名。`#` 总是开始注释，也没有引号机制，所以 matcher 里不能有空白或 `#`。`hosts.txt` 示例：

```text
full:api.example.com 192.0.2.10 2001:db8::10
domain:example.org 192.0.2.20
keyword:internal 192.0.2.30
regexp:^(foo|bar)\.example$ 192.0.2.40 # 共享地址
```

`ipv4only`/`ipv6only` 的硬地址族过滤之后，已知名称的 IN class A 或 AAAA 查询优先于 request 规则、缓存查询和上游交换，`reject` 规则也不例外。地址条目没有所请求的地址族时，honk 返回 NOERROR/NODATA，不查上游。其他 class 和 qtype 照常走正常管线。本地地址记录用 60 秒 TTL，hosts 应答不走 honk 的 DNS 缓存。

honk 在 OxiDNS 格式上做了扩展：规则可以只写域名、不写地址，此时这个名称就成为该域名的别名：

```text
full:a.example b.example
domain:corp.example gateway.example
```

目标和 matcher 名称一样要归一化，并且必须是有效主机名。名称与地址混写、写两个域名，或者精确名称以自身为别名，都是无效规则。查询别名的 A 或 AAAA 记录时，honk 用相同 qtype 让目标走完整管线：hosts、request 规则、缓存、上游。应答先给出从查询名称经各级别名到目标的 `CNAME` 记录，再附上目标应答里的 CNAME 和所请求的地址记录。本地别名 CNAME 和本地地址记录用 60 秒 TTL；来自目标应答的记录沿用目标自己的 TTL 策略。合成的应答不缓存；目标查询保留调用者的缓存策略，显式绕过缓存也一样。

派生的目标查询要求恰好一个问题，即 `QD=1`；answer 和 authority section 为空，即 `AN=NS=0`；additional section 为空，或恰好包含一个 OPT，即 `AR=0` 或 `1`。派生查询替换 QNAME，保留事务 ID、全部 header flags、QTYPE 和 QCLASS。有 OPT 时，精确保留它的 class、TTL 和选项字节，根名称 owner 单独编码，不依赖原问题的编码方式。其他 section 形状会让查询在发往目标前就失败；honk 不会把记录直接丢掉，也不会退回去查原名称。

目标为 NODATA 时，honk 返回只含 CNAME 链的 NOERROR；目标为 NXDOMAIN 时，按 RFC 6604 返回带 CNAME 链的 NXDOMAIN。其他完整的 12 位 RCODE 不带 answer 记录：EDNS 客户端收到完整 RCODE；客户端没用 EDNS、无法表示该 RCODE 时，返回不带记录的 SERVFAIL。目标查询失败，本次查询就失败。合成应答保留目标最终应答的 `TC` 位，即使合成后的包没有超出客户端的大小限制。

全部来源合并后，每个别名目标都必须在 8 级以内走到一个不是别名的名称。出现环路，或者链更长，都算无效配置，错误信息会给出对应的 matcher 和目标。经[节点域名 hook](#节点服务器域名) 解析的域名也遵守别名规则。

SIGHUP 会构建新快照。启动时任一来源不可读，或者自定义规则无效，启动就失败。reload 时，新的运行时 generation 会在发布前失败，当前的运行时 generation 继续运行。

## EDNS Client Subnet（`client_subnet`）

ECS 会把近似的客户端网络告诉上游权威服务器。只有 CDN 本地性确实需要时才设置 `client_subnet`，否则留空。该设置只作用于命名上游。

- 显式值：IPv4 地址表示 `/32`；honk 会把 IPv4 CIDR 规范化为网络地址，所以 `203.0.113.7/24` 实际发送 `203.0.113.0/24`。写 IPv6、主机名或端口会让配置失败。
- 自动值：不区分大小写的 `auto` 会带 bypass mark 向 `1.1.1.1` 的 `33434` 到 `33469` 端口发 UDP 探测；`auto(IPv4)` 只替换目标地址。路由选出的本地地址是公网地址时，honk 直接用它。否则每个 TTL 用 3 个独立 UDP 流，最多检查 12 个 TTL，选第一个公网 ICMP 路由跳点。结果总是 `/24`。推断在 2 秒后放弃。探测不依赖 DNS 或 HTTP 服务。
- 刷新：启动时、SIGHUP 时，以及路由、链路或地址变化时，honk 都会为新的 DNS 运行时 generation 解析出一个不可变值。有界探测失败时，这个 generation 不生成 ECS。

改用其他探测目标：

```dae
dns {
    client_subnet: auto(9.9.9.9)
}
```

客户端自己带的 ECS，honk 不会覆盖，`/0` 也不覆盖。客户端查询只要带任何 EDNS 选项，包括自带的 ECS，就既不缓存也不合并；honk 自己添加的 ECS 不影响缓存。生成的 ECS 按下面的规则走：

- 显式 `-> tag` 选择和普通流量路由都走完后，以最终解析出的拨号路径为准。直连尝试可以注入 ECS，`-> direct` 也算；走代理叶节点的尝试不注入。
- 每次 UDP 地址重试，honk 都单独判断。失败的直连尝试带上的 ECS 不会进入后续代理重试。
- 查询没有 ECS、又发往合格的命名上游时，honk 在 cache/singleflight admission 之后加上配置的选项，校验上游回显的 ECS，并在缓存或答复之前只移除自己注入的状态。
- 有效前缀参与 DNS 策略身份，所以自动前缀变化前后的应答不会交叉复用。`asis` 请求保持逐字节不变。

## 上游

每行写 `name: 'uri'`，后面可选 `-> node-or-group`：

```dae
upstream {
    default: 'udp://223.5.5.5:53'
    google_doh: 'https://dns.google/dns-query' -> proxy
}
```

上游声明保留名称原来的拼写。dae 的请求动作和应答动作解析器先去掉首尾空白，再调用 Rust 的 `to_lowercase()`，然后识别关键字或生成上游目标。查找时，转换后的目标必须和声明的名称完全一致。声明名称建议用小写：声明 `alidns`、动作写 `AliDNS` 能匹配；两边都写 `AliDNS` 反而匹配不上。旧版结构化目标不做大小写转换。

启动和 reload 时，完整配置校验会检查生效的请求规则、应答规则，以及 `fallback` 引用的每个上游名称。只解析配置的 API 不做这项校验。第一个显式 `upstream` 块会替换内置条目，所以必须保留名为 `default` 的声明，或者选一个已声明的回退上游，或者把请求 `fallback` 设为 `reject`、`asis`。即使请求规则覆盖了所有查询，`fallback` 校验也免不掉。

后续的 `upstream` 块，honk 会追加到第一个块后面。同一名称声明多次时，以最后一条为准。

### URI scheme 与默认值

| URI 形式 | 运行时协议 | 默认端口 / path |
| --- | --- | --- |
| `host[:port]` 或 `udp://host[:port]` | UDP；应答带 `TC` 时改用 TCP 重试 | `53` |
| `tcp://host[:port]` | TCP DNS | `53` |
| `tcp+udp://host[:port]` 或 `udp+tcp://host[:port]` | 与 UDP 相同 | `53` |
| `tls://host[:port]` | DNS over TLS（DoT） | `853` |
| `https://host[:port][/path]` | DNS over HTTPS（DoH，HTTP/2） | `443`，path 为 `/dns-query` |
| `h3://host[:port][/path]` 或 `http3://host[:port][/path]` | DNS over HTTP/3（DoH3） | `443`，path 为 `/dns-query` |
| `quic://host[:port]` | DNS over QUIC（DoQ） | `853` |

scheme 只能小写。未知或大写的 scheme，honk 不会拒绝，而是把整个字符串当作 UDP 地址，所以要自己检查拼写。

带端口的 IPv6 字面量要加方括号，例如 `[2606:4700:4700::1111]:53`；不带端口的 IPv6 字面量用默认端口。

```dae
upstream {
    default: 'udp://[2606:4700:4700::1111]:53'
    cloudflare_v6_dot: 'tls://[2606:4700:4700::1111]:853?tls_server_name=cloudflare-dns.com'
}
```

基于 TLS 的协议由解析器从主机名派生 `tls_server_name`。证书校验需要 DNS 名称时，IP 字面量 endpoint 要显式写 query 参数：

```dae
cloudflare_dot: 'tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com'
```

这个参数会从拨号地址里移除，并覆盖从主机名派生的值。key 名区分大小写，值不做百分号解码，出现多次时最后一个非空值生效。其他 query 项留在地址里；写在 DoH 或 DoH3 路径之后时，它们会成为请求 URI 的一部分。

DoH 和 DoH3 用 `application/dns-message` 发 `POST` 请求。HTTP authority 是 endpoint 的主机和端口。`tls_server_name` 只改 SNI 和证书校验，所以 IP 字面量形式的 DoH 服务器必须接受把这个 IP 当作 authority。

### 出站选择

末尾的 `-> tag` 强制该上游走指定的节点或代理组。`-> direct` 直接拨号，不经过流量路由；`-> block` 让每个查询都失败。tag 与任何节点或组都不匹配，或者组里没有可用节点时，查询失败，不会退回直连。省略后缀时，honk 解析上游目的地址，再套用普通流量的 `routing { ... }` 规则；这条路由仍然可以选到代理叶节点。旧版的同行写法 `name: 'uri' outbound: tag` 也还接受。

```dae
upstream {
    default: 'udp://223.5.5.5:53' -> direct
}
```

流量路由把上游当作 honk 自己发起的流量。输入有上游主机名、解析出的 IP 和端口、来源 `0.0.0.0:0`，还有 `l4proto`；上游主机名只在写明了的时候才有。`l4proto` 的取值是：UDP、DoQ 和 DoH3 为 `udp`，TCP、DoT 和 DoH 为 `tcp`。即使选中的代理用 TCP-DNS 承载，UDP 上游仍按 `udp` 路由。

只有引号外的 `->` 和 `outbound:` 后缀才选出站。它们写在 URI 引号里仍算数据；如果这种写法与旧版的拆分结果不同，会产生 `legacy-upstream-separator` warning。引号外的词法单元开头出现 `#`，就开始行尾注释，行为有变化时会产生 `legacy-upstream-comment`。注释和出站后缀都应写在 URI 引号外。

| 协议 | 经过选定的节点或组 |
| --- | --- |
| UDP（`udp`、裸地址、`tcp+udp`、`udp+tcp`） | 通过该出站承载为 TCP-DNS。 |
| TCP | 支持通过出站 TCP stream。 |
| DoT | 支持；TLS 在出站 TCP stream 上运行。 |
| DoH | 支持；TLS 与 HTTP/2 在出站 TCP stream 上运行。 |
| DoQ | 支持经出站的 UDP-capable `PacketTransport`。 |
| DoH3 | 支持经出站的 UDP-capable `PacketTransport`。 |

## DNS 路由

`routing` 里是排好序的 `request` 和 `response` 规则，第一条匹配的生效。同一个条件里的参数按 OR 组合；用 `&&` 连起来的条件按 AND 组合。条件前加 `!` 表示取反。

在 `request` 和 `response` 规则里，matcher 参数内的单引号或双引号可以保护 `,`、`)`、`&&`、`->`、`#` 和 `//`。只有引号外、词法单元开头的 `#` 才开始注释，前面的空格或制表符可以留。紧贴前文的 `#` 仍是数据。`//` 不是注释：行尾写斜杠注释会让规则无效，产生 `legacy-slash-comment` warning，整条规则被省略；应改用 `#`。`qtype('a,aaaa')` 仍然选中两种类型，并产生 `legacy-quoted-list` warning；建议裸写，或者逐项加引号。

未知、格式错误或不支持的条件会产生带位置的 warning，整条规则被省略，不会只丢掉合取里的一个条件。未知的 QTYPE 名称产生 `invalid-qtype`，混合列表和取反条件也一样；应改正名称或改用数字类型码。显式写的 `qtype()` 仍不匹配任何类型。无效的 `qname` 或 `subtag` 正则表达式，以及空的 `sip()`，能通过解析，但会让启动或 reload 失败。

每条完整调用和它的动作必须写在同一物理行上。不完整的非空行会被省略，并产生带位置的 `incomplete-dns-rule`；DNS 不会把这些行拼起来。完整 matcher 后面多了文本，会产生 `trailing-matcher-text`，整条规则省略。词法单元开头和参数位置的引号，都必须在同一行闭合。未闭合引号会产生一条词法诊断；只有每个块都保留了有效的右花括号时，honk 才省略该行并继续处理，否则整个文档失败。未闭合引号覆盖到的右花括号不算块结束符。

### 条件

| 语法 | 范围 | 含义 |
| --- | --- | --- |
| `qname(suffix: example.com)` | Request 与 response | 点边界后缀；裸参数也表示后缀。 |
| `qname(keyword: ads)` | Request 与 response | 子串匹配。 |
| `qname(full: api.example.com)` | Request 与 response | 精确域名匹配。 |
| `qname(regex: ...)` | Request 与 response | Rust 正则表达式匹配；包含括号时需加引号。 |
| `qname(geosite: cn)` | Request 与 response | 匹配指定 geosite 类别展开出来的域名；`category@attr` 只保留带该属性的条目。 |
| `qtype(a, aaaa, ...)` | Request 与 response | 匹配 QTYPE 名称或数字 `u16`。可识别名称为 `A`、`AAAA`、`CNAME`、`MX`、`TXT`、`NS`、`PTR`、`SOA`、`SRV`、`HTTPS`、`SVCB`、`ANY` 和 `*`。`*` 是 `ANY` 的别名，不是通配符。 |
| `sip(192.168.50.1, 100.64.0.0/10, 2001:db8::/32)` | 仅 request | 把逻辑客户端来源和列出的任一个 IP 主机地址或 CIDR 匹配。 |
| `subtag(MyAirport, keyword: Air, regex: ^Paid)` | 仅 request | 匹配[节点服务器域名](#节点服务器域名)查询所属订阅的 tag：精确值、`keyword:` 或 `regex:`，区分大小写。 |
| `upstream(name, ...)` | 仅 response | 匹配生成当前应答的上游。名称精确比较，且不像动作目标那样转为小写。 |
| `ip(192.0.2.0/24, geoip: private, ...)` | 仅 response | 任一应答 IP 属于所列 CIDR 或 GeoIP 集时匹配。 |

`qname` 用去掉末尾点的小写查询名称匹配。`full:` 和 `suffix:` 的模式会转成小写，但模式里的末尾点会保留，所以带末尾点的模式永远匹配不上。`keyword:` 和 `regex:` 模式区分大小写；应写小写，或者加 `(?i)`。

第一个没加引号的 `)` 会结束条件，所以含括号的正则表达式要加引号：

```dae
dns {
    routing {
        request {
            qname('regex: ^(foo|bar)\.example$') -> default
            qname(geosite: geolocation-!cn@cn) -> default
            qtype(*) -> reject
            qtype(a, aaaa) -> default
        }
    }
}
```

`geosite.dat` 或 `geoip.dat` 不可用时，对应的展开结果不匹配任何内容。未知的类别、代码或属性会产生 warning，同样不匹配任何内容，所以单独把它们取反，条件就恒为真。`geoip: private` 是内置集合，不需要资源文件；见[资源位置](./global.md#数据目录与资源路径)。

整个 `subtag` 参数加引号时表示精确 tag：`subtag('keyword: Air')` 匹配名为 `keyword: Air` 的 tag，而 `subtag(keyword: Air)` 匹配包含 `Air` 的任意 tag。

透明 53 端口和 `dns.bind` 入口的逻辑来源是 socket peer。为已通过 admission 的 TCP/UDP 流做 DNS 解析时，逻辑来源是这条流的客户端地址。内部查询、bootstrap 查询、prefetch 和 Clash API 查询都没有逻辑来源。来源未知时，正向和取反的 `sip` 条件都是 false，请求路由继续看下一条规则或 fallback。response 路由不接受 `sip`。

DNS 的 `sip()` 和 `ip()` 共用同一个 IP/CIDR 解码器。裸 IPv4 和 IPv6 地址分别表示 `/32` 和 `/128`；honk 会把 CIDR 里的主机位清零，并产生 `dns-network-host-bits` warning。无效网络会产生带位置的 `invalid-dns-network` 诊断，整条 dae 规则被省略；用代码构造的无效路由则在路由器或策略构建时失败。等价的网络写法使用相同的策略标识，参数顺序不变，重复参数也不会删除。

### 节点服务器域名

节点服务器域名经 `global.bootstrap_resolver`、`/etc/hosts` 和系统 nameserver 解析，不走 DNS 路由。含 `subtag(...)` 的 request 规则会接管匹配订阅里节点的服务器域名，XHTTP 下载域名也包括在内：

```dae
dns {
    upstream {
        alidns: 'udp://223.5.5.5:53'
        providerdoh: 'https://doh.provider.example/dns-query' -> direct
    }
    routing {
        request {
            subtag(MyAirport) && qname(suffix: private.provider.example) -> providerdoh
            fallback: alidns
        }
    }
}
```

- 节点域名只匹配含 `subtag()` 的规则；普通规则、fallback 和没匹配上的域名仍走 bootstrap 解析。其他查询不带订阅，对它们来说 `subtag()` 和 `!subtag()` 都是 false。
- 被接管的查询只发往选中的上游，遵守 `strategy` 和 `use_host`，不走缓存和 response 规则，也不回退：查询失败就表示物理节点连接或探测连接失败。
- 接管按域名生效，不是端到端的下载目标解析策略。下载时为选路而预先解析 URL 域名，只是尽力而为；代理下载的 URL 域名仍由代理解析，而承载代理自身的节点服务器解析遵守这条规则。显式使用 bootstrap 解析器的下载绕过这个 hook。
- tag 属于主机名，不属于节点：不同订阅里共用同一主机名的节点，各自的 tag 会合并，所以第一条匹配的规则就为这个主机名选定一个上游。
- 这条规则只能和 `qname()` 组合，而且所选上游的每条声明都必须是 `-> direct`，否则校验报错：`subtag-dns-condition`、`subtag-dns-action` 或 `subtag-dns-upstream-route`。
- 上游自身的域名、ECH 发现和离线 `delay` 子命令仍使用 bootstrap 解析器。
- 域名匹配到 `use_host` 中的[别名](#hosts-快照use_host)时，honk 改为解析别名目标。别名链停在地址条目上，就直接用这些地址；否则把目标域名当作节点域名解析，也就是交给接管该目标的 `subtag()` 规则，没有接管就走 bootstrap。直接匹配原始域名的地址条目不会经这个 hook 接管；honk 用的是别名链终点的地址条目。所有被接管的查询，包括本地地址结果和 bootstrap 目标，都遵守 DNS 运行时 admission 与取消机制。目标或 subtag 路径一旦选定，该路径失败就是最终结果。查询执行前 reload 删掉了这个别名时，原域名按没有别名的情况解析。
- 别名匹配所有交给 bootstrap 解析器的域名，不限于节点服务器域名：没有指定显式 bootstrap 解析器的订阅、Geo 数据和外部 UI 下载的 URL 域名，SOCKS5 节点的 UDP 中继域名，以及健康检查、延迟测试、连通性探测和内部解析回退到 bootstrap 时的域名。DNS 上游自身的域名和 ECH 发现不走这个 hook。
- 每个 DNS generation 根据订阅 tag 和有序规则，预先算出节点域名的策略结果，包括没匹配上的结果。用到这些结果时，原生流追踪会以 `not_instrumented` 标成 `partial`：节点域名的规则决策证据还没有采集。

### Request 动作

| 动作 | 结果 |
| --- | --- |
| `reject` | 返回空的成功应答。 |
| `asis` | 用 honk 自己发起的 socket，向拦截时得到的原始 DNS 目的地址重新查询，不保留客户端的网络来源 IP 和端口。透明查询保留入口 transport；UDP 应答带 `TC` 时，对同一目的地址改用 TCP 重试。独立查询没有原始目的地址，会直接失败，不会递归拨回 listener。 |
| 上游名 | 查询该命名上游。 |
| `fallback: reject\|asis\|<upstream>` | 没有 request 规则匹配时使用的动作；默认用上游 `default`。 |

两个路由块都接受 `default:` 作为 `fallback:` 的旧版别名。

代表已通过 admission 的流执行、带有来源的查询，没有拦截时得到的 DNS 服务器原始目的地址。如果它的 request 策略选了 `asis`，解析按 fail-closed 处理，绝不会退回到兼容的默认上游。

原生 `direct(must)` 的绕过与 `asis` 重新查询不同；见[DNS 来源/NAT 与投影限制](../design/dns.md#入口路径)。

### Response 动作

| 动作 | 结果 |
| --- | --- |
| `accept` | 返回当前应答。 |
| `reject` | 把当前应答换成空的成功应答。 |
| 上游名 | 通过该命名上游重新查询，然后再次执行 response 路由。 |
| `fallback: accept\|reject\|<upstream>` | 没有 response 规则匹配时使用的判定或命名上游；默认是 `accept`。 |

`NXDOMAIN` 和 `SERVFAIL` 跳过应答规则和回退动作。对可缓存的查询，如果上游交换失败或返回 `SERVFAIL`，而[过期应答](#缓存与固定-ttl)还在，honk 就改为返回它；本地数据包拒绝不会触发这一行为。

一次 response 遍历最多查三个上游，初始上游也算在内；第四次交换 honk 会拒绝。重新查询形成环路时，honk 同样拒绝。

## 地址族策略

### ipversion_prefer

`ipversion_prefer` 设置 A 和 AAAA 查询的地址族偏好。

| dae 设置 | 内部策略 | 行为 |
| --- | --- | --- |
| 省略 | `both` | 并发执行符合条件的 A 和 AAAA 查询，不压制任何地址族。 |
| `ipversion_prefer: 0` | `both` | dae 的无偏好取值，行为与省略相同。 |
| `ipversion_prefer: 4` | `preferipv4` | 偏好 IPv4，同时保留 IPv6 回退。 |
| `ipversion_prefer: 6` | `preferipv6` | 偏好 IPv6，同时保留 IPv4 回退。 |

`ipversion_prefer` 默认 `both`。honk 解析不了的值保持 `both`，并输出诊断。内部的 `ipv4only` 和 `ipv6only` 模式无法用 dae 的 `ipversion_prefer` 语法表达。

```dae
dns {
    ipversion_prefer: 4
}
```

### 偏好族查询

偏好模式下，两个地址族仍可查询。收到非偏好族的 A/AAAA 请求时，honk 会让偏好族的 sibling query 走同一条管线，并保留调用方的逻辑来源、原始目的地址、入口 profile，以及除 QTYPE 外的 wire profile。偏好族有地址时，honk 把非偏好族应答压制为 NODATA；偏好族没有地址，或者 sibling 遇到普通的可用性失败时，就返回非偏好族的应答。typed local packet refusal 会按原始原因终止解析，carrier Capacity 也算在内，honk 不会拿过期缓存应答替换它。相关缓存未命中时，这样做会多出一次上游查询。

### bootstrap 拨号顺序

同一策略也决定上游主机名经 bootstrap 解析后的拨号顺序。`both` 和 `preferipv4` 先拨 IPv4，`preferipv6` 先拨 IPv6。TCP、DoT、DoH、DoQ、DoH3 以及经代理承载的 DNS，在拨号失败后会继续试后面的地址。直连 UDP 把那唯一一次重试优先给另一个地址族，再考虑同族的其他地址，并复用连接成功的 socket。`ipv4only` 和 `ipv6only` 只在兼容格式里可用，会把上游拨号候选限制在对应地址族。

## 缓存与固定 TTL

### optimistic_cache

启用正、负缓存的读取和写入。默认 `true`；设为 `false` 时，回复保留上游 TTL。

```dae
dns {
    optimistic_cache: false
}
```

### optimistic_cache_ttl

设置除 NXDOMAIN、SERVFAIL 和 NODATA 外所有应答的缓存生命周期和回复里的 RR TTL；这三类响应码按[负应答](#负应答)处理。默认 `600` 秒。写 `0` 用上游应答里的最小 TTL。只接受十进制秒数：`10m` 这类值会产生诊断，并回落到 `60`，不是 `600`。

```dae
dns {
    optimistic_cache_ttl: 600
}
```

### optimistic_stale_reply_ttl

设置 serve-stale 正应答使用的 TTL。默认 `30` 秒。非零值替换每个非 OPT RR 的 TTL。写 `0` 时保留缓存里已按策略改写的 wire TTL，不用权威 TTL。此时 outcome TTL 从该 wire 的 `extract_min_ttl` 得出，没有正 TTL 时回落到 60 秒。非零时，即使没有正 TTL，outcome TTL 仍是配置值。值无效会产生诊断，并回落到 `30`。

```dae
dns {
    optimistic_stale_reply_ttl: 30
}
```

### max_cache_size

设置缓存条目数上限和每个分片的应答字节预算。默认 `10000`。条目上限最多分摊到 16 个分片，每个分片的预算按 `max(条目容量 × 1 KiB, 65,535 字节)` 计算；honk 按 LRU 淘汰，直到两个上限都满足。单条超过 65,535 字节的应答不缓存。大于 100,000 的值会被钳到 100,000，`0` 会被钳成一个条目；两种情况都产生 warning。无法解析的值会触发诊断，并回落到 `10000`。

```dae
dns {
    max_cache_size: 20000
}
```

### fixed_domain_ttl

按域名覆盖正应答和 NODATA 的 TTL，先于 `optimistic_cache_ttl` 应用。默认空。写 `0` 时，所有响应码的应答都不缓存，NXDOMAIN 和 SERVFAIL 也一样。key 只匹配一个精确名称，用不带末尾点的小写形式，不覆盖子域。

例如，`www.example.com` 需要单独的条目：

```dae
dns {
    fixed_domain_ttl {
        example.com: 120
        www.example.com: 120
        ddns.example.org: 10
        nocache.test: 0
    }
}
```

每个固定 TTL 必须正好是一个无符号 32 位十进制标量。裸值和带引号的值都接受，包括 `0` 和 `4294967295`；新接受的带引号十进制值会产生 `legacy-ttl-quoting` warning。值无效或溢出会产生 `invalid-ttl`，多出词法单元会产生 `trailing-value`，两种情况都会省略该条目。说明文字写在 ` # ` 后面，不要紧贴数值。

### 缓存条目与过期

Request 路由在缓存查询之前执行。查询除事务 ID 外完全相同，走同一类入口，又选中相同的 DNS 策略和相同的上游或 `asis` 目的地址时，客户端才共享缓存条目；原始客户端来源不参与缓存 key。偏好地址族的渲染仍保留来源元数据，所以依赖来源的 sibling 策略不会经由 foreground singleflight 泄漏。

设了 `optimistic_cache_ttl: 0`，又没有 `fixed_domain_ttl` 覆盖时，`NOERROR` 正应答取 answer、authority 和 additional 段里所有非 OPT 记录的最小 TTL。缓存这份应答时，honk 把每个非 OPT 记录的 TTL 改写成这个最小值。只要有一条记录的 TTL 为零，honk 就不缓存该应答，并移除精确缓存槽，避免旧地址或更早的负应答再次返回。非零的配置 TTL 或固定 TTL 仍能覆盖零值。

honk 只在缓存应答时改写回复 TTL；不可缓存的查询，或者 `optimistic_cache: false` 时，保留上游 TTL。除 `NXDOMAIN` 和 `SERVFAIL` 外的失败码，例如 `REFUSED`，按 `optimistic_cache_ttl` 处理，默认缓存 600 秒。

即使响应策略 `reject` 把回复换成合成的 NOERROR，缓存生命周期仍按原始上游应答的分类、响应码和 TTL 决定。所以被拒绝的 REFUSED 保留失败响应码的 TTL 规则；没有配置 TTL 或固定 TTL 覆盖时，被拒绝的 NOERROR 正应答用原始 TTL。

缓存命中时，报文里的记录 TTL 不会递减。这种改写只发生在内存里，已保存的持久化行不会被删。

### 负应答

NXDOMAIN 的缓存时间是 `min(SOA TTL, SOA MINIMUM, 300)` 秒。缺少 SOA，或者 SOA 生命周期为零时，honk 不缓存，并移除精确缓存 key 下已有的正、负缓存，避免旧地址又作为过期应答返回。前台结果替换当时已有的写入结果；后台刷新只移除它开始时读到的那一版。`fixed_domain_ttl: 0` 禁止缓存，但已有的条目不删。除此之外，SERVFAIL 仍按 SOA 算出的生命周期处理，默认 60 秒，并限制在 `1..=300` 秒。

这里的 NODATA 指没有 answer 记录的 NOERROR 应答，即 `ANCOUNT=0`。answer 非空时，honk 仍把它归为正应答，只含 CNAME/DNAME 的也算。NODATA 的完整报文留在正缓存槽里，生命周期是 `min(SOA TTL, SOA MINIMUM, 300)` 秒。非零的 `fixed_domain_ttl` 优先于 SOA 和上限，即使缺 SOA 也生效。没有这个覆盖值时，缺 SOA 或生命周期为零的 NODATA 和 NXDOMAIN 一样处理：移除精确缓存槽，新应答不保留。

缓存的 NODATA 仍能作为过期应答返回；过期应答改写的是 SOA 记录 TTL，不是 SOA MINIMUM。对上游 NODATA 套用响应策略 `reject`，会生成空的 NOERROR 报文；它的缓存生命周期按同样的 TTL 规则算，SOA 取被拒绝的应答，不取合成报文。后续请求在这个生命周期内复用合成应答。

### serve-stale 与刷新

过期应答，包括缓存的 `NODATA`，到期后 1 小时内还能用于 serve-stale，除非已经被淘汰。`optimistic_stale_reply_ttl` 只设置回复 TTL，不管这个窗口。缓存命中时，剩余时间不超过 `max(原 TTL / 10, 1)` 秒就启动一次后台刷新。

### 路由投影

不保留缓存不等于关闭 DNS 路由投影。已接受但不可缓存的正应答，`fixed_domain_ttl: 0` 的结果也算，用 wire 里非 OPT 记录的最小正 TTL 作为投影寿命；这些 TTL 全为零时回落到 60 秒。这条规则不改写应答，也不会让应答变得可缓存；缓存命中的剩余寿命和 served-stale 寿命都不变。

## 解析规则

### 标量与注释

标量值占掉该物理行剩下的部分，只在 key 后面的冒号处切开，所以裸写的 IPv6 地址和 `client_subnet: auto(9.9.9.9)` 都能保持完整。解析器只去掉包围整个值的一对匹配引号。值一旦以引号开头，就必须在同一行闭合，否则配置失败。

标量设置里，只有引号外、词法单元开头的 `#` 才开始注释。`use_host: /tmp/a#b` 选的是字面路径 `/tmp/a#b`，并产生 `legacy-glued-hash` warning；注释要写成 `use_host: /tmp/a # comment`。重复的 `use_host` 声明按来源顺序保留，去重行为与原来一样。

### 布尔值

`optimistic_cache` 接受 `true`、`yes`、`1`、`on`、`false`、`no`、`0` 和 `off`，不区分大小写。其他值会关掉缓存，并产生诊断。

对 `optimistic_cache`，布尔简写 `t`、`y`、`f`、`n` 仍表示假，但会产生 `legacy-bool-shorthand` warning；应改用 `true` 或 `false`。

### 未知 key 与已移除的 key

`dns` 里的未知 key、块和语句会产生 `unknown-key`、`unknown-block` 或 `unknown-statement` warning，honk 直接忽略。`dns.routing` 只接受 `request` 和 `response` 块。

`hosts_file` 已移除，改用 `use_host` 路径；配置里仍写着它时，honk 以 `removed-dns-hosts-file` 报错，配置失败。

## 旧版转换

兼容性配置里保留扁平的 `routing.rules` 条目，字段是 `domain` 和 `upstream`，另外还有命名 `fallback`。这些是结构化兼容字段，不是当前 dae 语法里的附加语句。`suffix:`、`keyword:`、`full:` 和 `regex:` 前缀用来选匹配方式；不带前缀的旧版域名按 `full` 精确匹配。

结构化的 YAML、TOML 或 JSON 输入不能包含 request 或 response 规则：`dns.routing.request` 和 `dns.routing.response` 必须省略，或者写成 `null`。这类规则请用 dae 写。

生效的请求路由按下面的优先级选：

1. 新式 `request.rules` 非空时，用新式规则和它的回退动作，忽略所有旧版字段。
2. 新式规则为空、旧版 `rules` 非空时，把旧版规则转换成请求规则，旧版回退名称保留原来的拼写。即使另外配了新式回退动作，也以旧版为准。
3. 两组规则都为空时，用已配置的请求路由。只有回退动作是 `Upstream("default")`，并且旧版回退值不是 `""`、`"upstream"` 或 `"default"` 时，才用旧版值替换它。

`"upstream"` 只在第三个分支里当哨兵值忽略；有旧版规则时，它就是普通的上游名称，必须有对应声明。旧版目标按原样精确匹配，不套用 dae 动作的大小写转换规则。

校验诊断保留原始字段路径。新式规则和回退用 `dns.routing.request.rules[i].action` 和 `dns.routing.request.fallback`；转换后的旧版规则用 `dns.routing.rules[i].upstream`；转换或提升的回退用 `dns.routing.fallback`。

旧版规则生效时，默认回退的 `upstream` 没声明会报告 `missing-dns-fallback`；空回退没有匹配声明会报告 `empty-dns-fallback`；其他没声明的目标会报告 `unknown-dns-upstream`。诊断保留字段路径，但不回显目标名称，也不列出已声明的名称。省略旧版回退等同于显式写 `upstream`，只要声明了该上游，两种写法都有效。没有旧版规则时，honk 仍会忽略空值和 `upstream` 哨兵。

## 相关文档

- [DNS 设计](../design/dns.md)
- [实验性配置参考（`store_dns`）](./experimental.md)
- [全局配置参考](./global.md)
