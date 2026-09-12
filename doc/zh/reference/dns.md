# DNS 配置参考

本文定义当前 dae 语法的 `dns { ... }` 段及其运行时语义。

## 顶层键

| 键 | 默认值 | 含义 |
| --- | --- | --- |
| `bind` | 省略 / `""` | 可选的独立 DNS 监听器；空值只关闭此监听器。 |
| `use_host` | `false` | 可重复的 hosts 来源：`true` 选择 `/etc/hosts`；路径选择 OxiDNS 兼容规则文件。 |
| `client_subnet` | 省略 / `""` | 可选的 EDNS Client Subnet preset：IPv4、IPv4 CIDR、`auto` 或 `auto(IPv4)`。 |
| `upstream { ... }` | `default: 'udp://223.5.5.5:53'` | 命名上游服务器。第一个显式 `upstream` 块会替换内置条目。 |
| `routing { ... }` | 无规则；request fallback 为 `default`；response fallback 为 `accept` | 有序的 request 与 response 路由。 |
| `ipversion_prefer` | 省略：`both` | `4` 选择 `preferipv4`；`6` 选择 `preferipv6`；`0` 是 dae 的无偏好，即 `both`。honk 无法解析的值保持 `both`，并输出诊断。 |
| `optimistic_cache` | `true` | 启用正、负缓存的读取与写入。 |
| `optimistic_cache_ttl` | `600` 秒 | 固定正应答的缓存和报文 TTL，不适用于 NODATA；`0` 保留应答 TTL。 |
| `optimistic_stale_reply_ttl` | `30` 秒 | serve-stale 正应答使用的 TTL；非零值替换每个非 OPT RR 的 TTL，`0` 保留缓存中已按策略改写的 wire TTL，而不是权威 TTL。 |
| `max_cache_size` | `10000` | 缓存最大条目数，也是保留 wire 字节预算的输入。 |
| `fixed_domain_ttl { ... }` | 空 | 按域名覆盖正应答和 NODATA 的 TTL；`0` 禁止缓存所有响应码的应答，包括负应答。 |

标量值占据该物理行的剩余部分，只在键后的冒号处分隔，因此裸写的 IPv6 地址和 `client_subnet: auto(9.9.9.9)` 保持完整。解析器只移除一对包围整个值的匹配引号。已开启的标量引号必须在同一行闭合，否则配置失败。

标量设置中，只有引号外、词法单元开头的 `#` 才开始注释。`use_host: /tmp/a#b` 选择字面路径 `/tmp/a#b`，并产生 `legacy-glued-hash` 警告；注释请写成 `use_host: /tmp/a # comment`。重复的 `use_host` 声明保持来源顺序和既有去重行为。`optimistic_cache` 的布尔简写 `t`、`y`、`f`、`n` 仍表示假，但产生 `legacy-bool-shorthand` 警告；请改用 `true` 或 `false`。

## 独立监听器（`bind`）

独立监听器使用 host 网络命名空间中的普通、未打 mark 的 socket。关闭独立监听器时，透明 TCP/UDP 53 端口拦截仍然生效。

| 值 | 结果 |
| --- | --- |
| 省略或 `""` | 不创建独立监听器。 |
| 数字 `IP:port`，如 `127.0.0.1:1053` 或 `[::1]:1053` | UDP 监听器。 |
| `udp://host:port` | UDP 监听器。 |
| `tcp://host:port` | TCP 监听器。 |
| `tcp+udp://host:port` | 在同一地址和端口创建 TCP 与 UDP 监听器。 |

主机名必须带 scheme，例如 `udp://localhost:1053`。IPv6 字面量必须使用方括号。`tcp+udp://:1053` 这样的空 host 表示通配地址。每种形式都必须显式给出十进制 `u16` 端口。端口 `0` 表示申请临时端口；honk 会记录最终选择的地址。

裸主机名无效。解析器也会拒绝 userinfo、path、query、fragment、反斜杠、IPv6 zone identifier、错误的方括号、不支持的 scheme 和超出范围的端口。使用主机名时，honk 按系统解析顺序尝试地址，并使用第一个能让全部请求 transport 成功 bind 的地址。bind 同步且 all-or-nothing：任一失败都会关闭其他已选 socket 并令启动失败。

监听器归进程所有。SIGHUP 重载接受语义等价的不同写法，但 host、port 或 transport 集合的任何变化都会作为 restart-required 被拒绝。通配或 LAN 侧 bind 会暴露一个无认证的递归 resolver；必须用主机防火墙限制来源，绝不能发布到不可信网络。

## Hosts 快照（`use_host`）

`use_host` 可以重复配置。`true` 会按标准 `IP 规范名 别名...` 格式加入 `/etc/hosts`；`false` 不加入来源；每个路径会按 OxiDNS 兼容的 `matcher IP...` 规则文件加载。所有来源按声明顺序各读取一次并合并为一个快照；后面的来源会覆盖前面来源中相同的精确名称或 matcher。重复路径只加载一次。

```dae
dns {
    use_host: true
    use_host: 'hosts.txt'
}
```

绝对路径保持原样。相对路径依次优先使用 `global.data_dir` 下、`/var/share/honk` 下和工作目录中的已有副本；缺失路径仍定位到 `global.data_dir` 下。查询路径只使用生成的不可变快照，不执行文件 I/O。

自定义 matcher 支持 `full:example.com`（或无前缀的精确名称）、`domain:example.com`（该名称及标签边界内的所有子域）、`keyword:text` 和 `regexp:pattern`。匹配优先级依次为精确、最长 domain 后缀、首个匹配的 regexp、首个匹配的 keyword；重复定义同一 matcher 时，后者替换其地址。Full、domain 和 keyword 名称按 ASCII 大小写不敏感方式处理，并归一化末尾点。Regexp 保持大小写敏感，匹配不带末尾点的小写名称；需要忽略大小写时使用 `(?i)`。重复地址会去除。

在 `ipv4only`/`ipv6only` 的硬地址族过滤之后，已知名称的 IN class A 或 AAAA 查询优先于 request 规则（包括 `reject`）、缓存查询和上游交换。名称存在但没有所请求地址族时，honk 返回 NOERROR/NODATA，且不查询上游。其他 class 和 qtype 继续走正常管线。Hosts 应答使用 60 秒 TTL，并绕过 honk 的 DNS 缓存。

SIGHUP 会构建新快照。任一来源不可读或自定义规则无效时启动失败；重载时，替换 generation 会在发布前失败，当前 generation 继续使用。

## EDNS Client Subnet（`client_subnet`）

`client_subnet` 只作用于命名上游。IPv4 地址表示 `/32`；IPv4 CIDR 会归一化到网络地址。`auto` 向 `1.1.1.1:33434` 发送带 bypass mark 的 UDP 探测，`auto(IPv4)` 只替换该探测目标。若路由选出的本地地址是公网地址则直接使用；否则每个 TTL 使用 3 个独立 UDP flow、最多检查 12 个 TTL，并把首个公网 ICMP hop 作为 `/24`。探测不依赖 DNS 或 HTTP 服务。启动、SIGHUP 以及 route/link/address 变化会为替换 DNS generation 解析一个新的不可变值；有界探测失败时，该 generation 不生成 ECS。

honk 不会覆盖客户端自带的 ECS，包括 `/0`。生成的 ECS 会在显式 `-> tag` 选择和普通流量路由都完成后，跟随最终解析出的拨号路径：直连尝试（包括 `-> direct`）可以注入；解析出代理 leaf 的尝试不注入。UDP 地址重试会逐次独立判断，因此失败的直连尝试所带 ECS 不会进入后续代理重试。对于没有 ECS 且发往合格命名上游的查询，honk 在 cache/singleflight 接纳后添加配置的 option，校验上游回显的 ECS，并在缓存或答复前只移除自身注入的状态。有效 prefix 会进入 DNS policy identity，因此自动 prefix 变化前后的应答不会交叉复用。`asis` 请求保持逐字节不变。ECS 会向上游权威服务器暴露近似客户端网络；只有 CDN 本地性确有需要时才应启用。

## 上游

每行使用 `name: 'uri'`，后面可选 `-> node-or-group`：

```dae
upstream {
    default: 'udp://223.5.5.5:53'
    google_doh: 'https://dns.google/dns-query' -> proxy
}
```

上游声明保留名称的原有拼写。dae 请求和应答动作解析器先去除首尾空白，再调用 Rust `to_lowercase()`，然后识别关键字或生成上游目标。查找时，转换后的目标必须与声明名称完全一致。建议声明名称使用小写：声明 `alidns` 配合动作 `AliDNS` 可以匹配；声明和动作都写成 `AliDNS` 则不能匹配。旧版结构化目标不做大小写转换。

启动和重载时，完整配置校验会检查生效的请求及应答规则和 `fallback` 引用的每个上游名称。只解析配置的 API 不执行这项校验。第一个显式 `upstream` 块会替换内置条目，因此必须保留名为 `default` 的声明、选择已声明的回退上游，或将请求 `fallback` 设为 `reject`、`asis`。即使请求规则覆盖所有查询，也不能省略回退上游的声明。

### URI scheme 与默认值

| URI 形式 | 运行时协议 | 默认端口 / path |
| --- | --- | --- |
| `host[:port]` 或 `udp://host[:port]` | UDP；应答带 `TC` 时改用 TCP 重试 | `53` |
| `tcp://host[:port]` | TCP DNS | `53` |
| `tcp+udp://host[:port]` | 当前解析器将其归一化为上面的 UDP 行为 | `53` |
| `tls://host[:port]` | DNS over TLS（DoT） | `853` |
| `https://host[:port][/path]` | DNS over HTTPS（DoH，HTTP/2） | `443`，path 为 `/dns-query` |
| `h3://host[:port][/path]` 或 `http3://host[:port][/path]` | DNS over HTTP/3（DoH3） | `443`，path 为 `/dns-query` |
| `quic://host[:port]` | DNS over QUIC（DoQ） | `853` |

对于基于 TLS 的协议，解析器会从主机名派生 `tls_server_name`。当证书校验要求 DNS 名称时，IP 字面量 endpoint 需要显式 query 参数：

```dae
cloudflare_dot: 'tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com'
```

该参数会从拨号地址中移除，并覆盖从主机名派生的值。

### 出站选择

末尾的 `-> tag` 强制该上游经过指定节点或组。省略时，honk 会解析上游目的地址并应用普通流量的 `routing { ... }` 规则；该路由仍可选择代理 leaf。旧版同一行写法 `name: 'uri' outbound: tag` 仍然接受。

只有引号外的 `->` 与 `outbound:` 后缀选择出站。它们在 URI 引号内仍是数据；与旧版拆分结果不同的写法产生 `legacy-upstream-separator` 警告。引号外词法单元开头的 `#` 开始行尾注释，行为变化产生 `legacy-upstream-comment`。注释和出站后缀请放在 URI 引号外。

| 协议 | 经过选定节点/组 |
| --- | --- |
| UDP（`udp`、裸地址、`tcp+udp`） | 通过该出站承载为 TCP-DNS。 |
| TCP | 支持通过出站 TCP stream。 |
| DoT | 支持；TLS 在出站 TCP stream 上运行。 |
| DoH | 支持；TLS 与 HTTP/2 在出站 TCP stream 上运行。 |
| DoQ | 支持经出站的 UDP-capable `PacketTransport`。 |
| DoH3 | 支持经出站的 UDP-capable `PacketTransport`。 |

## DNS 路由

`routing` 包含有序的 `request` 和 `response` 规则，首条匹配规则生效。同一个条件内的参数按 OR 组合；用 `&&` 连接的条件按 AND 组合。在条件前加 `!` 可将其取反。

在 `request` 和 `response` 规则中，匹配器参数内的单引号或双引号保护 `,`、`)`、`&&`、`->`、`#` 和 `//`。只有引号外词法单元开头的 `#` 开始注释，前面可以是空格或制表符；紧贴前文的 `#` 仍是数据。`//` 不是注释：行尾斜杠注释文本使规则无效，产生 `legacy-slash-comment` 警告并省略整条规则，请改用 `#`。`qtype('a,aaaa')` 仍选择两种类型，并产生 `legacy-quoted-list` 警告；建议裸写或逐项加引号。

未知、格式错误或不支持的条件会产生带位置的警告，并省略整条规则，不会只丢弃合取中的一个条件。未知 QTYPE 名称产生 `invalid-qtype`，混合列表和取反条件也不例外；请修正名称或使用数字类型码。显式 `qtype()` 仍不匹配任何类型。

每条完整调用及其动作必须位于同一物理行。不完整的非空行被省略，并产生带位置的 `incomplete-dns-rule`；DNS 不合并这些行。完整匹配器后的多余文本产生 `trailing-matcher-text`，并省略整条规则。词法单元开头和参数位置的引号都必须在同一行闭合。未闭合引号产生一条词法诊断；只有每个块都保留了有效右花括号时才省略该行并继续，否则整个文档失败。被未闭合引号覆盖的右花括号不作为块结束符。

### 条件

| 语法 | 范围 | 含义 |
| --- | --- | --- |
| `qname(suffix: example.com)` | Request 与 response | 点边界后缀；裸参数也表示后缀。 |
| `qname(keyword: ads)` | Request 与 response | 子串匹配。 |
| `qname(full: api.example.com)` | Request 与 response | 精确域名匹配。 |
| `qname(regex: ...)` | Request 与 response | Rust 正则表达式匹配。 |
| `qname(geosite: cn)` | Request 与 response | 匹配由指定 geosite 代码展开的域名。 |
| `qtype(a, aaaa, ...)` | Request 与 response | 匹配 QTYPE 名称或数字 `u16`。可识别名称为 `A`、`AAAA`、`CNAME`、`MX`、`TXT`、`NS`、`PTR`、`SOA`、`SRV`、`HTTPS`、`SVCB`、`ANY` 和 `*`。 |
| `sip(192.168.50.1, 100.64.0.0/10, 2001:db8::/32)` | 仅 request | 将逻辑客户端来源与任一所列 IP 主机地址或 CIDR 匹配。 |
| `upstream(name, ...)` | 仅 response | 匹配生成当前应答的上游。 |
| `ip(192.0.2.0/24, geoip: private, ...)` | 仅 response | 任一应答 IP 属于所列 CIDR 或 GeoIP 集时匹配。 |

透明 53 端口与 `dns.bind` 入口的逻辑来源是 socket peer；代表已接纳 TCP/UDP 流执行的 DNS 解析使用该流的客户端地址。内部、bootstrap、prefetch 与 Clash API 查询没有逻辑来源。来源未知时，正向和取反的 `sip` 条件都为 false，请求路由会继续执行下一条规则或 fallback。response 路由不接受 `sip`。

DNS `sip()` 与 `ip()` 共用 IP/CIDR 解码器。裸 IPv4 和 IPv6 地址分别表示 `/32` 和 `/128`；CIDR 中的主机位会被清零，并产生 `dns-network-host-bits` 警告。无效网络产生带位置的 `invalid-dns-network` 诊断，并省略整条 dae 规则；通过代码构造的无效路由会在路由器或策略构建时失败。等价网络写法使用相同策略标识，不改变参数顺序或删除重复参数。

### Request 动作

| 动作 | 结果 |
| --- | --- |
| `reject` | 返回空的成功应答。 |
| `asis` | 拨向拦截所得的原始 DNS 目的地址。透明查询保留入口 transport；UDP 应答带 `TC` 时，对同一目的地址改用 TCP 重试。独立查询没有原始目的地址，会失败而不会递归拨回监听器。 |
| 上游名 | 查询该命名上游。 |
| `fallback: reject\|asis\|<upstream>` | 无 request 规则匹配时使用的动作；默认使用上游 `default`。 |

代表已接纳流执行的带来源查询没有被拦截 DNS 服务器的原始目的地址。若其 request 策略选择 `asis`，解析会 fail closed，绝不会回退到兼容/default 上游。

### Response 动作

| 动作 | 结果 |
| --- | --- |
| `accept` | 返回当前应答。 |
| `reject` | 将当前应答替换为空的成功应答。 |
| 上游名 | 通过该命名上游重新查询，然后再次执行 response 路由。 |
| `fallback: accept\|reject\|<upstream>` | 无 response 规则匹配时使用的判定或命名上游；默认为 `accept`。 |

NXDOMAIN 和 SERVFAIL 应答会直接返回，不经过应答路由，也不应用应答规则或回退动作。

一次 response 遍历的最大重新查询深度为三个上游，其中包括初始上游；第四次交换会被拒绝。重新查询形成环路时也会被拒绝。

### 旧版转换

兼容性配置保留扁平的 `routing.rules` 条目（包含 `domain` 和 `upstream`）以及命名 `fallback`。这些是结构化兼容字段，不是当前 dae 语法的附加语句。`suffix:`、`keyword:`、`full:` 和 `regex:` 前缀选择匹配方式；不带前缀的旧版域名采用 `full` 精确匹配。

生效的请求路由按以下优先级选择：

1. 新式 `request.rules` 非空时，使用新式规则及其回退动作，忽略所有旧版字段。
2. 否则，旧版 `rules` 非空时，将其转换为请求规则，并保留旧版回退名称的原有拼写。即使另有新式回退动作，也以旧版为准。
3. 两组规则都为空时，使用已配置的请求路由。仅当其回退动作为 `Upstream("default")`，且旧版回退值不是 `""`、`"upstream"` 或 `"default"` 时，才用旧版值替换。

`"upstream"` 仅在第三个分支中作为哨兵值被忽略；存在旧版规则时，它是普通的上游名称，必须有对应声明。旧版目标按原样精确匹配，不采用 dae 动作的大小写转换规则。

校验诊断保留原始字段路径：新式规则和回退使用 `dns.routing.request.rules[i].action` 与 `dns.routing.request.fallback`；转换后的旧版规则使用 `dns.routing.rules[i].upstream`；转换或提升的回退使用 `dns.routing.fallback`。
旧版规则生效时，默认回退 `upstream` 未声明会报告 `missing-dns-fallback`，空回退没有匹配声明会报告 `empty-dns-fallback`，其他未声明目标报告 `unknown-dns-upstream`。诊断保留字段路径，但不回显目标名称或列出已声明名称。省略旧版回退等同于显式设置 `upstream`；只要声明了该上游，两者都有效。没有旧版规则时，空值和 `upstream` 哨兵仍会被忽略。

## 地址族策略

| dae 设置 | 内部策略 | 行为 |
| --- | --- | --- |
| 省略 | `both` | 并发执行符合资格的 A 与 AAAA 工作；不压制任何地址族。 |
| `ipversion_prefer: 4` | `preferipv4` | 偏好 IPv4，同时保留 IPv6 回退。 |
| `ipversion_prefer: 6` | `preferipv6` | 偏好 IPv6，同时保留 IPv4 回退。 |

偏好模式下，两个地址族仍可查询。对于非偏好族的 A/AAAA 请求，honk 会让偏好族 sibling query 经过同一管线，并保留调用方的逻辑来源、原始目的地址、入口 profile 以及除 QTYPE 外的 wire profile。偏好族有地址时，非偏好族应答会被压制为 NODATA；偏好族没有地址或 sibling query 失败时，则返回非偏好族应答。相关缓存未命中时，这会增加一次上游查询。

同一策略也决定上游主机名经 bootstrap 解析后的地址拨号顺序。`both` 与 `preferipv4` 先拨 IPv4；`preferipv6` 先拨 IPv6。TCP、DoT、DoH、DoQ、DoH3 以及经代理承载的 DNS 会在拨号失败后继续尝试后续地址。直连 UDP 会把唯一一次重试优先用于另一地址族，再考虑同族的其他地址，并复用成功的 socket。仅兼容格式可用的 `ipv4only` 与 `ipv6only` 会把上游拨号候选限制在对应地址族。

内部 `ipv4only` 和 `ipv6only` 模式无法通过 dae 的 `ipversion_prefer` 语法表达。

## 缓存与固定 TTL

| 键 | 默认值 | 行为 |
| --- | --- | --- |
| `optimistic_cache` | `true` | 启用缓存读取与发布。 |
| `optimistic_cache_ttl` | `600` | 覆盖正应答的最小 TTL，用于缓存生命周期和返回的记录 TTL，不适用于 NODATA。`0` 保留应答 TTL。 |
| `optimistic_stale_reply_ttl` | `30` 秒 | serve-stale 正应答使用此 TTL；非零值替换每个非 OPT RR 的 TTL。`0` 保留缓存中已按策略改写的 wire TTL，而不是权威 TTL；此时 outcome TTL 从该 wire 的 `extract_min_ttl` 得出，不存在正 TTL 时回退为 60 秒。非零值时，即使不存在正 TTL，outcome TTL 仍为配置值。 |
| `max_cache_size` | `10000` | 条目上限。它还按每个配置条目 4 KiB 缩放保留 query/response wire 字节预算；每个分片至少 65,535 字节，全局上限 64 MiB。`0` 会告警并钳制为一个条目。 |
| `fixed_domain_ttl { domain: seconds }` | 空 | 先于 `optimistic_cache_ttl` 应用的按域名覆盖；`0` 禁止缓存所有响应码的应答，包括 NXDOMAIN 和 SERVFAIL。 |

Request 路由先于缓存查询执行。缓存与后台 refresh 的标识使用选中的上游或精确 `asis` 目的地址，而不是原始客户端来源：选择相同交换 scope 的客户端共享条目，选择不同上游或 `asis` 目的地址的客户端仍相互隔离。偏好地址族的渲染继续保留来源元数据，因此依赖来源的 sibling 策略不会经 foreground singleflight 泄漏。

设置 `optimistic_cache_ttl: 0` 且没有 `fixed_domain_ttl` 覆盖时，NOERROR 正应答使用 answer、authority 和 additional 段中所有非 OPT 记录的最小 TTL。任一记录 TTL 为零时，honk 不缓存该应答，并移除精确缓存槽，避免旧地址或更早的负应答再次返回。非零的配置 TTL 或固定 TTL 仍可覆盖零值。其他失败响应码的 TTL 行为不变。

不保留缓存不等于禁用 DNS 路由投影。已接受但不可缓存的正应答（包括 `fixed_domain_ttl: 0`）使用 wire 中非 OPT 记录的最小正 TTL 作为投影寿命；这些 TTL 全为零时回退为 60 秒。此规则不会改写应答，也不会使其变得可缓存；缓存命中的剩余寿命与 served-stale 寿命保持不变。

### 负应答

NXDOMAIN 的缓存时间为 `min(SOA TTL, SOA MINIMUM, 300)` 秒。缺少 SOA 或 SOA 生命周期为零时不缓存，并移除精确缓存键下已有的正、负缓存，避免旧地址再次作为过期应答返回。前台结果替换当时已有的发布结果；后台刷新只移除开始时读取的版本。`fixed_domain_ttl: 0` 禁止缓存，但不移除已有条目。除此之外，SERVFAIL 仍使用 SOA 得出的生命周期，缺省为 60 秒，并限制在 `1..=300` 秒。

此处 NODATA 指没有 answer 记录的 NOERROR 应答（`ANCOUNT=0`）；answer 非空时仍归为正应答，包括仅含 CNAME/DNAME 的应答。NODATA 的完整报文保留在正缓存槽中，生命周期为 `min(SOA TTL, SOA MINIMUM, 300)` 秒。非零 `fixed_domain_ttl` 优先于 SOA 和上限，即使缺少 SOA 也生效。没有该覆盖值时，缺少 SOA 或生命周期为零的 NODATA 与 NXDOMAIN 一样：移除精确缓存槽，不保留新应答。

缓存的 NODATA 仍可作为过期应答返回；过期应答改写的是 SOA 记录 TTL，而不是 SOA MINIMUM。对上游 NODATA 应用响应策略 `reject` 会生成空的 NOERROR 报文；其缓存生命周期按相同的 TTL 规则计算，使用被拒绝应答的 SOA，而非合成报文。后续请求会在该生命周期内复用合成应答。

即使响应策略 `reject` 将回复替换为合成的 NOERROR，缓存生命周期仍按原始上游应答的分类、响应码和 TTL 选择。被拒绝的 REFUSED 因此保留失败响应码的 TTL 规则；没有配置 TTL 或固定 TTL 覆盖时，被拒绝的 NOERROR 正应答使用原始 TTL。

缓存命中时不会递减报文中的记录 TTL。替换只影响内存，不删除已保存的持久化行。

例如：

```dae
fixed_domain_ttl {
    ddns.example.org: 10
    nocache.test: 0
}
```

每个固定 TTL 必须恰好是一个无符号 32 位十进制标量。接受裸值和带引号的值，包括 `0` 与 `4294967295`；新接受的带引号十进制值产生 `legacy-ttl-quoting` 警告。无效或溢出值产生 `invalid-ttl`，多余词法单元产生 `trailing-value`；两种情况都会省略该条目。说明文字放在 ` # ` 后，不要紧贴数值。

## 示例

```dae
dns {
    # 省略 bind 可保持独立监听器关闭。
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

## 相关文档

- [DNS 设计](../design/dns.md)
- [实验性配置参考（`store_dns`）](./experimental.md)
- [全局配置参考](./global.md)
