# honk 配置指南

本指南说明如何组合和运行 honk 配置；字段清单不在此重复，统一由参考文档提供。

honk 使用 dae 配置语法。下表列出运行时分段与 CLI 入口；`include {}` 用于组合文件，下一节单独说明。

| 分段 | 用途 | 参考 |
| --- | --- | --- |
| `global` | 选择接口、拨号行为、健康检查与运行时路径。 | [Global 参考](./reference/global.md) |
| `node` | 用分享链接声明静态代理节点。 | [节点参考](./reference/nodes.md) |
| `group` | 在节点与嵌套组之间进行选择。 | [组参考](./reference/groups.md) |
| `routing` | 应用有序流量规则与默认出站。 | [路由参考](./reference/routing.md) |
| `dns` | 配置监听、上游、请求/响应策略与缓存行为。 | [DNS 参考](./reference/dns.md) |
| `subscription` | 获取远程节点列表。 | [订阅参考](./reference/subscription.md) |
| `experimental` | 启用 Clash API 或持久化缓存。 | [Experimental 参考](./reference/experimental.md) |
| CLI | 选择配置、后端、目标文件或本地命令。 | [CLI 参考](./reference/cli.md) |

内置出站 `direct` 与 `block` 会在启动时注入，可用于组和路由规则。

## 配置格式

- 配置项放在 `section { ... }` 块中，每行一个 `key: value`。
- URL、含空白的值以及含 `:`、`+`、`#` 等语法字符的值需要加引号。标量值及 `include`、`node` 条目接受单引号或双引号；带引号的 `subscription` URL 使用单引号。
- 配置项或 matcher 接受列表时，用逗号分隔：`lan_interface: eth0, eth1` 或 `dport(80, 443)`。
- 以秒为单位的时长接受裸秒数或 `ms`、`s`、`m`、`h` 后缀。`check_tolerance` 等毫秒配置项接受裸毫秒数、`ms` 或 `s`。
- `#` 开始整行注释或引号外的行尾注释。`node` 与 `subscription` 条目的说明应另起注释行。

### 使用 `include {}` 拆分配置

```dae
include {
    config.d/*.dae
    'config.d/extra config.dae'
}
```

`include` 条目可裸写或加引号，并支持 `*`、`?`、`[]` glob 模式。模式按声明顺序执行，每个模式的匹配项按字典序加载。未匹配的模式、目录以及扩展名不是 `.dae` 的文件会被跳过。

所有相对 include，包括嵌套被包含文件中的 include，都以传给 `--config` 的入口配置所在目录为基准解析。加载器会 canonicalize 入口目录与每个匹配项；指向该目录之外的绝对路径或符号链接会被拒绝。同一个 canonical 文件无论直接重复还是通过循环再次加载，也会被拒绝。

入口文件自身的分段始终最先合并，不受 `include` 块位置影响；之后依次合并每个被包含文件及其后代。后出现的标量键覆盖先前值。节点、订阅、组、DNS 上游、固定 TTL 与路由规则等集合条目按合并顺序追加。

## 运行时数据目录

`global.data_dir` 是运行时状态与相对运行时资源的进程级根目录。默认值为 `/var/share/honk`，必须是非空绝对路径，修改后需重启。启动时 honk 会递归创建目录，再以 create-new 方式创建并删除一个私有随机探测文件，且不跟随探测文件的符号链接。候选目录不可用时，只有通过同一探测的进程工作目录才能作为回退；两者均不可用时启动失败并保留两项原因。相对的 `global.log_file`、`experimental.cache_file.path`、`experimental.clash_api.external_ui`、`.sub` 订阅存储、`geoip.dat`、`geosite.dat` 与节点 `ech_config_path` 均在实际生效的目录下解析；绝对子路径保持原样。若首选的数据目录副本不存在，honk 会继续使用入口配置旁已有的旧缓存、已有 `./.sub`、或工作目录中已有的 UI/ECH 路径，直至手动迁移。Geo 查找首先使用已存在的 `$DAE_LOCATION_ASSET/<file>`，随后检查实际生效的数据目录、工作目录与 dae 标准资源目录。

详见 [Global 参考](./reference/global.md)。

## 最小配置

部署前请替换 `eth0` 与示例节点地址。每条注释只说明对应配置项或规则的一项用途。

```dae
# 设置拦截基线。
global {
    # 跟随 IPv4 默认路由接口。
    wan_interface: auto
    # 拦截来自该 LAN 接口的转发流量。
    lan_interface: eth0
    # 输出常规运行日志。
    log_level: info
    # 同时追加写入 <data_dir>/honk.log。
    log_file: 'honk.log'
    # 嗅探域名并校验目的 IP。
    dial_mode: domain
    # 应用推荐的网关 sysctl。
    auto_config_kernel_parameter: true
    # 解析代理主机名时避免自拦截。
    bootstrap_resolver: '1.1.1.1:53'
}

# 声明一个静态代理节点。
node {
    # 将 SOCKS5 分享链接命名为 `edge`。
    edge: 'socks5://192.0.2.2:1080'
}

# 将节点组成可选择的出站。
group {
    proxy {
        # 只包含指定节点。
        filter: name('edge')
        # 固定第一个匹配成员。
        policy: fixed(0)
    }
}

# 私网目的地直连，Web 流量经过代理组。
routing {
    # 私网目的地不经过代理。
    dip(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) -> direct(must)
    # 代理常用 Web 端口。
    dport(80, 443) -> proxy
    # 其余流量直连。
    fallback: direct
}

# 用直连路径保持 DNS 可用。
dns {
    upstream {
        # 使用普通直连 DNS 服务器。
        public: 'udp://1.1.1.1:53' -> direct
    }
    routing {
        request {
            # 未匹配问题发送到 `public`。
            fallback: public
        }
    }
}
```

## 完整配置

本例组合了订阅、静态后备节点、`subtag` 过滤、Geo 路由、经代理的 DoH、Clash API 与持久化状态。

```dae
global {
    wan_interface: auto
    lan_interface: br-lan
    log_level: info
    log_file: 'honk.log'
    dial_mode: domain++
    auto_config_kernel_parameter: true
    data_dir: '/var/share/honk'
    bootstrap_resolver: '1.1.1.1:53'
    store_subscribe: true
}

node {
    backup: 'socks5://192.0.2.2:1080'
}

subscription {
    paid: 'https://subscription.example/sub'
}

group {
    proxy {
        filter: subtag('paid') && !name(keyword: 'ExpireAt-')
        filter: name('backup')
        policy: fallback
        final: block
    }
}

routing {
    dip(geoip: private) -> direct(must)
    domain(geosite: geolocation-cn) -> direct
    domain(geosite: geolocation-!cn) -> proxy
    fallback: proxy
}

dns {
    ipversion_prefer: 4
    # client_subnet: auto  # 可选：为命名上游推断公网路径上的一个 /24。
    upstream {
        direct_dns: 'udp://1.1.1.1:53' -> direct
        proxy_doh: 'https://dns.google/dns-query' -> proxy
    }
    routing {
        request {
            qname(geosite: geolocation-cn) -> direct_dns
            fallback: proxy_doh
        }
        response {
            fallback: accept
        }
    }
}

experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'ui'
        external_ui_download_url: 'https://example.com/dashboard.zip'
        external_ui_download_detour: proxy
        secret: 'replace-me'
        default_mode: 'Rule'
    }
    cache_file {
        enabled: true
        path: 'cache.db'
        store_dns: true
    }
}
```

## 选择接口

将 `lan_interface` 设为接收 LAN 转发流量的一个或多个逗号分隔接口，将 `wan_interface` 设为承载本机发起流量的接口。`auto` 跟随 IPv4 默认路由接口；没有默认路由时保持待定而不会回退到 loopback，之后在链路、地址或路由变化时自动协调。仅代理本机流量时省略 `lan_interface`：已配置的 WAN hook 仍处理本机发起的 TCP 与 UDP。绝不要把 `lo` 当作虚构的 LAN 接口加入配置。

详见 [Global 参考](./reference/global.md)。

## 选择拨号模式

| 模式 | 适用场景 |
| --- | --- |
| `ip` | 仅按 IP 元数据路由；关闭域名嗅探。 |
| `domain` | 默认：嗅探域名并校验目的 IP；仅在校验通过后重新执行路由。未命中时继续使用普通 IP/端口规则。代理出站可按已校验名称拨号。 |
| `domain+` | 嗅探但不执行目的 IP reality check；保留初始路由，仅把嗅探名称作为代理目标。 |
| `domain++` | 嗅探但不校验，并强制根据 SNI/HTTP Host 重新执行非保留决策。 |

详见 [Global 参考](./reference/global.md)。

## 声明节点

每个 `node` 行都是分享链接：`tag: 'scheme://...'` 或带引号的裸链接。显式 tag 会成为路由/API 名称，并覆盖链接内嵌名称；裸链接使用其 fragment 或生成的协议/主机名称。凭据、TLS/REALITY、transport 与协议调优项都放在链接的 userinfo 与 query 参数中。无法解析的条目会附诊断后跳过，已移除的协议则是硬配置错误。

详见 [节点参考](./reference/nodes.md)。

## 构建组

静态名称使用 `filter: name(...)`，订阅来源使用 `filter: subtag(...)`，嵌套组使用 `filter: group(...)`。以 `&&` 连接的谓词执行 AND，`!` 对单个谓词取反；不同 `filter:` 行执行 OR。没有 filter 且没有嵌套组时包含全部节点，仅有嵌套组时不会自动包含全部节点。策略可选 `selector`/`fixed`、`urltest`/`min_moving_avg`、`loadbalance`/`roundrobin` 或 `fallback`；用 `final` 指定全部成员死亡后的结果。组拨号最终总会解析到一个叶子节点。

详见 [组参考](./reference/groups.md)。

## 编写路由规则

规则按源码顺序执行，写作 `matcher(...) [&& !matcher(...)] -> outbound`，最后是 `fallback: outbound`。目标可以是 `direct`、`block` 或组；裸节点名会在加载时被拒绝——需要先包一层组（例如 `filter: name('节点名')`）。`(must)` 决策是终局的：跳过嗅探，且 Clash Global/Direct 模式绝不会覆盖 `must` 或 `block`。GeoIP 使用 `dip(geoip: private)`/`dip(geoip: cn)`，geosite 使用 `domain(geosite: category)`。

honk 会在启动与重载时注入 `dip(<每个已配置 LAN/WAN 接口地址>) -> direct(must)`，使网关服务不依赖代理健康状态。失活出站通常执行 fail-closed：新流会被丢弃而不会泄漏到 `direct`。未配置 `final` 且只有一个唯一叶节点的 TCP 组会让同一代理继续作为最后尝试；UDP 和全部叶节点失活的多叶节点组仍保持 fail-closed。应保留 `dip(geoip: private) -> direct(must)`，让公网 `fallback` 指向多成员且 `policy: fallback`、带显式 fail-closed `final` 的组，并至少保留一个强制经 `direct` 的 DNS 上游。

详见 [路由参考](./reference/routing.md)。

## DNS 设置

上游可裸写 `host:port`（UDP），也可使用 `udp://`、`tcp://`、`tcp+udp://`/`udp+tcp://`、`tls://`、`https://`、`quic://`、`h3://`。追加 `-> node-or-group` 可强制拨号路径；所选叶节点具备对应能力时，上述 transport 均可使用代理出站。DoQ 与 DoH3 要求叶节点提供 UDP-capable `PacketTransport`；缺少代理 registry 或 packet capability 时会 fail closed。请求路由选择 `reject`、`asis` 或命名上游；响应路由选择 `accept`、`reject` 或用于有界重查询的命名上游：

```dae
dns {
    upstream {
        home: 'udp://223.5.5.5:53' -> direct
        lan_proxy: 'https://dns.google/dns-query' -> proxy
    }
    routing {
        request {
            sip(192.168.50.0/24, 100.64.0.0/10) -> lan_proxy
            sip(127.0.0.0/8, ::1/128) && qname(suffix: example-isp.cn) -> asis
            fallback: home
        }
    }
}
```

`sip(...)` 仅用于 request，将逻辑 DNS 客户端 IP 与主机地址或 CIDR 匹配。透明 53 端口与 `dns.bind` 查询使用 socket peer；代表已接纳 TCP/UDP 流执行的 DNS 查询使用该流的客户端地址。内部、bootstrap、prefetch 与 Clash API 查询没有客户端来源，因此 `sip(...)` 和 `!sip(...)` 都不匹配并继续执行 fallback。带来源的流查询仍没有被拦截 DNS 服务器的原始目的地址，因此选择 `asis` 会 fail closed。

`bind` 留空时仅使用透明 53 端口拦截。独立监听形式都要求显式端口：裸数字 `IP:port`（仅 UDP）、`udp://host:port`、`tcp://host:port` 或 `tcp+udp://host:port`；空 host 表示绑定通配地址。除非有主机防火墙保护 LAN 暴露，否则只绑定 loopback。省略 `ipversion_prefer` 时策略为 `both`，也可设为 `4`/`6` 以同时控制 DNS 结果和 bootstrap 解析出的上游拨号顺序；偏好地址族拨号失败时会回退到另一地址族。

`client_subnet` 默认关闭。需要确定性的 ECS 时写固定 IPv4/CIDR；写 `auto` 则无需 DNS 或 HTTP，把公网路径上的首个公网 hop 推断为 `/24`。自动推断会在 reload 与网络变化时刷新；有界探测失败时不生成 ECS。客户端自带的 ECS 始终优先。启用前请阅读参考文档中的隐私警告。

详见 [DNS 参考](./reference/dns.md)。

## 订阅

每个来源可写作 `tag: 'url'`，在带引号的 URL 后追加 `(UA)` 可指定该订阅的 User-Agent；需要同时指定刷新周期时使用 `tag: { url, ua, interval }`。`subtag(...)` 匹配的就是该 tag。默认 `global.store_subscribe: true` 时，成功获取并解析的原始正文会原子存储到 `.sub`。请求默认使用 `honk/<version>`，可由 `ua` 覆盖；缓存 key 包含配置中的覆盖值，因此不同请求身份会使用不同的已存正文。启动时先恢复有效且非空的存储再后台刷新；SIGHUP 会沿用活动订阅节点，仅在没有节点可沿用时从存储恢复；获取、解析或没有可用节点的失败会保留活动节点与上一次有效正文，空刷新不会清空上一代。订阅节点仅存在于运行时。修改 `store_subscribe` 后需重启。

详见 [订阅参考](./reference/subscription.md)。

## 启用 Clash API、缓存文件与首包保留 UDP

**Clash API。** 非空的 `experimental.clash_api.external_controller` 会启用服务器。除非防火墙和非空 `secret` 已提供保护，否则应保持 loopback 绑定；空 secret 会关闭 API 认证。相对 `external_ui` 通过 `data_dir` 解析，缺失时可在后台下载。`external_ui_download_url` 选择 ZIP 来源，`external_ui_download_detour` 强制下载经过指定节点或组；空值分别保留内建 URL 和普通流量路由。

**缓存文件。** 设置 `experimental.cache_file.enabled: true` 可持久化 Selector 选择与 Clash 模式；`store_dns: true` 还会持久化符合条件的 DNS 应答。相对 `path` 使用 `data_dir`，并遵循前述旧路径规则。

**首包保留 UDP。** `global.nfqueue_enable` 默认值为 `true`；设置为 `false` 可关闭有歧义 LAN 转发 UDP 的 NFQUEUE 暂存。该设置修改后需重启。若使用 mock eBPF、不带 `ebpf` 的构建，或固定队列前置检查失败，honk 会记录 warning，仅在本进程关闭 NFQUEUE，不会改写配置文件。真实实例取得锁后，启动会绑定队列 `320`，并在发布 `inet honk_nfqueue` / `udp_decision` 前回收残留的自有 nftables table；honk 运行期间，防火墙管理器不得修改这些保留对象。

详见 [Global 参考](./reference/global.md)、[Experimental 参考](./reference/experimental.md)与 [UDP NFQUEUE 设计](./design/nfqueue.md)。

## 预热与拨号预算

这些机制互相独立，按已配置组或显式预算限制，而不会按原始订阅规模无限增长。按需 Clash 延迟测试属于独立路径：冷 session/QUIC 节点只在临时 runtime 中预热 transport，并在测量结束后关闭。

| 机制 | 配置项 | 默认 | 行为 |
| --- | --- | --- | --- |
| 裸 TCP 预连接 | `preconnect_node_count` | `'auto'` | 启动时执行一轮。`'auto'` 最多尝试 8 个合格节点，组当前选择优先；`0` 关闭。显式 `N` 可覆盖全部合格节点，但最多 8 个并发尝试。拥有 session 的 AnyTLS/VLESS 模式、QUIC、`direct` 与 `block` 会被跳过。 |
| Selector 常驻 | — | 始终启用 | 保持每个 Selector 的已配置叶节点热态，包括不健康但被显式选择的节点。协议允许时保留可复用 session/client 或一条服务端裸 TCP；切换选择与 reload 会转移所有权而不中断活动流。 |
| UDP 预热集合 | `udp_warm_node_count` | `0` | 每组每个 IP 族取 top `min(N,3)` 个 UDP 叶子，最多并发 4 个尝试，并将驻留节点封顶为 `4×N`。UDP 与 Selector 所有权互相独立。 |
| 并发拨号上限 | `max_concurrent_dials` | `64` | 按 generation 限制物理代理连接与握手。Ready 池命中、已热 transport 上的逻辑流、`direct` 与 `block` 不占额度；重叠的 reload generation 还共享启动时描述符 gate。 |

周期 HTTP 健康检查与 Clash 延迟测试使用相同的临时暖路径计时：冷的可复用 transport 在计时外预热，并在结束后关闭；报告的延迟是已热连接上第二个请求的耗时——一个 round trip，拨号与 TLS 握手不计。只有预热后的目标交换成功才报告健康并提供选择 RTT；setup 与交换失败都会更新活性/冷却，但不产生延迟样本或排名 strike。扫描也不会为每个节点保留一条空闲隧道。

详见 [组选择设计](./design/groups.md)。

## 运行

```bash
# 使用内嵌目标文件的真实 eBPF。
sudo ./target/release/honk-core --config /etc/honk/config.dae

# 使用外部目标文件的真实 eBPF。
sudo ./target/release/honk-core \
  --config /etc/honk/config.dae \
  --bpf-object /etc/honk/honk-ebpf.o

# 使用 mock 后端进行非特权开发。
cargo run --release -p honk-core -- \
  --config config.min.dae --mock-ebpf --debug
```

详见 [CLI 参考](./reference/cli.md)。

## 校验建议

1. 从仓库的 `config.min.dae` 或 `config.dae` 开始，并替换其中的接口、端点与凭据。
2. 确保每个路由规则/`fallback`、DNS `fallback`、组 `final` 与 `->` 代理目标都按场景指向已有的组、节点、`direct` 或 `block`。
3. 对首连域名规则使用 `dial_mode: domain`/`domain++`，或确保客户端 DNS 经过 honk 以填充域名路由 map。
4. 修改组或策略后，SIGHUP 会重建 `GroupManager`；仍有效的 Selector 选择会迁移到 replacement generation。
5. 修改 `global.nfqueue_enable` 后需重启；若希望启用暂存，确认真实 eBPF 后端和启动前置条件可用，并确保防火墙管理器不修改 `inet honk_nfqueue` / `udp_decision`。
6. 增加或修改配置 fixture 时，运行 `cargo test -p honk-config` 以保持解析器示例有效。

## 相关文档

- [设计总览](./design/overview.md)
- [Global 配置参考](./reference/global.md)
- [DNS 发布运维](./operations/dns-rollout.md)
