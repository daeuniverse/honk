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
| `ipversion_prefer` | 省略：`both` | `4` 选择 `preferipv4`；`6` 选择 `preferipv6`。 |
| `optimistic_cache` | `true` | 启用正、负缓存的读取与写入。 |
| `optimistic_cache_ttl` | `600` 秒 | 固定的正应答缓存和 wire TTL；`0` 保留应答 TTL。 |
| `max_cache_size` | `10000` | 缓存最大条目数，也是保留 wire 字节预算的输入。 |
| `fixed_domain_ttl { ... }` | 空 | 按域名覆盖正应答 TTL；`0` 表示该域名永不缓存。 |

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
| `reject` | 返回空的成功应答。 |
| 上游名 | 通过该命名上游重新查询，然后再次执行 response 路由。 |
| `fallback: accept\|reject` | 无 response 规则匹配时使用的判定；默认为 `accept`。 |

一次 response 遍历的最大重新查询深度为三个上游，其中包括初始上游；第四次交换会被拒绝。重新查询形成环路时也会被拒绝。

### 旧版转换

兼容性 schema 保留扁平的 `routing.rules` 条目，其中包含 `domain` 和 `upstream`，以及一个命名 `fallback`。不存在新式 request 规则时，honk 会在加载时将其转换成 request 规则。`suffix:`、`keyword:`、`full:` 和 `regex:` 前缀选择 matcher；不带前缀的旧版域名是精确 `full` 匹配。旧版 fallback 会成为 request fallback。这些是结构化兼容字段，不是额外的当前 dae statement。

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
| `optimistic_cache_ttl` | `600` | 覆盖正应答的最小 TTL，用于缓存生命周期和返回的 wire RR TTL。`0` 保留应答 TTL。 |
| `max_cache_size` | `10000` | 条目上限。它还按每个配置条目 4 KiB 缩放保留 query/response wire 字节预算；每个分片至少 65,535 字节，全局上限 64 MiB。`0` 会告警并钳制为一个条目。 |
| `fixed_domain_ttl { domain: seconds }` | 空 | 先于 `optimistic_cache_ttl` 应用的按域名覆盖；`0` 使该域名不可缓存。 |

Request 路由先于缓存查询执行。缓存与后台 refresh 的标识使用选中的上游或精确 `asis` 目的地址，而不是原始客户端来源：选择相同交换 scope 的客户端共享条目，选择不同上游或 `asis` 目的地址的客户端仍相互隔离。偏好地址族的渲染继续保留来源元数据，因此依赖来源的 sibling 策略不会经 foreground singleflight 泄漏。

例如：

```dae
fixed_domain_ttl {
    ddns.example.org: 10
    nocache.test: 0
}
```

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
