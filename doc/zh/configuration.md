# honk 配置指南

使用本指南组合并运行 honk 配置。安装步骤以及仅直连、代理、界面/API 的起步配置见[启动指南](./how-to-start.md#最小配置)。字段清单见参考文档。

honk 使用 dae 配置语法的方言；与 dae 的已知差异见[方言参考](./reference/dialect.md)。下表列出运行时分段与 CLI 入口；`include {}` 用于组合文件。

| 分段 | 用途 | 参考 |
| --- | --- | --- |
| `global` | 选择接口、拨号行为、健康检查与运行时路径。 | [Global 参考](./reference/global.md) |
| `node` | 用分享链接声明静态代理节点。 | [节点参考](./reference/nodes.md) |
| `group` | 在节点与嵌套组之间选择。 | [组参考](./reference/groups.md) |
| `routing` | 应用有序流量规则与默认出站。 | [路由参考](./reference/routing.md) |
| `dns` | 配置监听、上游、请求/响应策略与缓存行为。 | [DNS 参考](./reference/dns.md) |
| `subscription` | 获取远程节点列表。 | [订阅参考](./reference/subscription.md) |
| `assets` | 为 geodata、外部 UI 和订阅设置下载默认值。 | [Assets 参考](./reference/assets.md) |
| `experimental` | 启用独立原生 API、Clash API 或持久化缓存。 | [Experimental 参考](./reference/experimental.md) |
| CLI | 选择配置、后端、目标文件或本地命令。 | [CLI 参考](./reference/cli.md) |

内置出站 `direct` 与 `block` 会在启动时注入，可用于组和路由规则。

## 配置格式

入口文件和被包含的 `.dae` 文件必须使用 UTF-8，其他编码会被拒绝。

- 配置项放在 `section { ... }` 块中，每行一个 `key: value`。也接受 `global { log_level: debug }` 这样的单行块，以及嵌套的单行块。
- 建议为 URL、含空白的值以及含 `:`、`+`、`#` 等语法字符的值加引号。标量值及 `include`、`node`、`subscription` 条目接受单引号或双引号。
- 引号内的文本按字面读取：不解码 `\n` 等转义，反斜杠只防止下一个引号结束字符串。引号必须在同一行闭合。`filter: name(regex: '^edge\.example$')` 向正则引擎传入 `^edge\.example$`。
- 在匹配器参数和过滤、路由表达式中，成对单引号或双引号内的逗号、右圆括号、`&&` 和 `->` 按字面值保留。但 `group(...)` 和 `qtype(...)` 仍将带引号的逗号分隔文本按列表解释。
- 配置项或 matcher 接受列表时，用逗号分隔：`lan_interface: eth0, eth1` 或 `dport(80, 443)`。
- `check_interval`、订阅 `interval` 等以秒为单位的时长只接受整秒，可裸写或添加 `s`、`m`、`h` 后缀，`1.5s` 无效。`ms` 值向上取整为整秒，`500ms` 即 `1s`。无效值会产生警告并变为 `0`，而 `check_interval` 为 `0` 时报错 `check_interval must be a positive duration`。
- `check_tolerance` 等毫秒配置项接受裸毫秒数、带 `ms` 的整数或带 `s` 的秒数，`1.5s` 即 1500 ms。不足 1 ms 的小数部分会被舍去；`1.5ms` 以及 `m`、`h` 后缀无效。无效值会产生警告并保留默认值。
- 引号外、词法单元开头的 `#` 引入注释；裸值内的 `#` 保留为数据。条目读取器也接受链接结束引号或订阅 `(UA)` 后缀之后紧贴的 `#` 注释，并产生 `legacy-glued-hash` 警告；注释前应留空白。词法单元开头的注释内，花括号不会闭合配置块。
- 成对单引号或双引号内的花括号视为数据。多余的右花括号 `}` 会被忽略并报告诊断；未闭合的块会导致整个文档被拒绝。当前解析器能够定位时，详细诊断会附上物理行号；错误文本不回显任意输入内容。
- 未知标量键产生诊断并被忽略。未知嵌套块按完整的已闭合子树跳过，不再将其中内容作为父块内容读取。只有文档列出的 `node` 和 `subscription` 包装块保留兼容遍历。未知的 `experimental` 外层设置、`experimental.native_api` 中的未知内容、旧版 NFQUEUE 中不支持的内容，以及以 `tolerance` 等组标量命名的块都是错误，见[方言参考](./reference/dialect.md#配置段与-include)。

### 使用 `include {}` 拆分配置

```dae
include {
    config.d/*.dae
    config.d/*/*.dae
    'config.d/extra config.dae'
}
```

`include` 条目是文件模式，可裸写或加引号，支持 `*`、`?`、`[]` glob。空路径、嵌套块或无效 glob 都是配置错误。模式按声明顺序执行，每个模式的匹配项按字典序加载。未匹配的模式、目录以及扩展名不是 `.dae` 的文件会被跳过。路径分量 `**` 与 `*` 一样只匹配一层目录，不会递归，因此示例用 `config.d/*/*.dae` 加载 `config.d` 下一级目录中的文件。

被包含的空文件或纯注释 `.dae` 文件不提供配置段；dae 入口文档必须含块的要求不适用于这些片段。

只有顶层 `include` 允许起始花括号另起一行，并产生 `legacy-include-opener` 警告；建议在同一行写 `include {`。`include` 注释遵循词法单元规则：`path.dae # note` 加载 `path.dae`，而 `path.dae#note` 是字面 glob 模式，并产生 `legacy-include-hash` 警告。字面 `#` 可加引号，以免触发迁移警告。字符串解析检查 `include` 结构，但不打开被包含文件；`include` 不能把片段拼接到尚未闭合的块中。

所有相对 include，包括嵌套包含文件中的 include，都以传给 `--config` 的入口配置所在目录为基准解析。加载器会解析入口目录与每个匹配项的规范路径；指向该目录之外的绝对路径或符号链接会被拒绝。同一规范路径的文件无论直接重复加载，还是通过循环再次加载，都会被拒绝。

入口文件自身的分段始终最先合并，不受 `include` 块位置影响；之后依次合并每个被包含文件及其后代。后出现的标量键覆盖先前值。节点、订阅、组、DNS 上游、固定 TTL 与路由规则等集合条目按合并顺序追加。

## 运行时数据目录

`global.data_dir` 是运行时状态与相对运行时资源的进程级根目录，默认值为 `/var/lib/honk`，必须是非空绝对路径。修改后需重启。

启动时，honk 递归创建目录，并通过新建、删除私有文件检查目录是否可用。候选目录不可用时，只有通过同一检查的工作目录才能作为回退；但 `--store db` 和已启用的原生 API 密码登录不允许这种回退。

相对可写资源和只读依赖依次使用第一个已存在的路径：

1. `<data_dir>/<path>`。
2. `/var/share/honk/<path>`。
3. 调用方的旧位置：缓存使用原始配置目录，其他依赖使用工作目录。

都不存在时，honk 返回 `<data_dir>/<path>` 用于创建。旧根目录 `/var/share/honk`（`LEGACY_DATA_DIR`）中的已有资源可通过这些回退路径继续使用，但旧缓存和订阅导入会将符合条件的状态复制到 `state/honk.db`。相对日志始终使用 `<data_dir>/<path>` 创建。绝对路径保持原样。

Geo 资源独立按普通文件查找：`$DAE_LOCATION_ASSET`、`<data_dir>`、`/var/share/honk`、工作目录、honk share 目录，最后是 dae share 目录。

详见 [Global 参考](./reference/global.md)。

## 最小配置

部署前须替换 `eth0` 与示例节点地址。

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
    # 为兼容 dae 而保留；honk 按固定规则设置 sysctl。
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
    # 此规则也会绕过私网 DNS；需保留接管时显式加上 && !dport(53)。
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
    data_dir: '/var/lib/honk'
    bootstrap_resolver: '1.1.1.1:53'
    store_subscribe: true
}

node {
    backup: 'socks5://192.0.2.2:1080'
}

subscription {
    paid: 'https://subscription.example/sub' {
        interval: 3600s
    }
}

assets {
    subscription {
        ua: 'clash.meta'
    }
    ui {
        url: 'https://example.com/dashboard.zip'
        route: proxy
    }
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
    # 此规则也会绕过私网 DNS；需保留接管时显式加上 && !dport(53)。
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
        secret: 'replace-me'
        default_mode: 'Rule'
    }
    cache_file {
        enabled: true
        store_dns: true
    }
}
```

## 选择接口

- 将 `lan_interface` 设为接收 LAN 转发流量的接口，多个接口用逗号分隔。
- 将 `wan_interface` 设为承载本机发起流量的接口。`auto` 跟随 IPv4 默认路由接口；没有默认路由时保持待定，不会回退到回环接口，之后在链路、地址或路由变化时重新协调。
- 仅代理本机流量时省略 `lan_interface`：已配置的 WAN 挂钩仍处理本机发起的 TCP 与 UDP。不得把 `lo` 作为虚构的 LAN 接口加入配置。

不存在、被拒绝（`lo`、VRF 设备、`dae0`）或无法挂载的接口不会阻止启动。见[网卡语义](./reference/global.md#网卡语义)。

接口设置详见 [Global 参考](./reference/global.md)。

## 选择拨号模式

| 模式 | 适用场景 |
| --- | --- |
| `ip` | 仅按 IP 元数据路由；关闭域名嗅探。 |
| `domain` | 默认：嗅探域名并校验目的 IP；仅在校验通过后重新执行路由。未命中时继续使用普通 IP/端口规则。代理出站可按已校验名称拨号。 |
| `domain+` | 嗅探但不执行目的 IP reality check；保留初始路由，仅把嗅探名称作为代理目标。 |
| `domain++` | 嗅探但不校验，并强制根据 SNI/HTTP Host 重新执行非保留决策。 |

拨号模式详见 [Global 参考](./reference/global.md)。

## 声明节点

每个 `node` 行都是分享链接：`tag: 'scheme://...'` 或带引号的裸链接。显式 tag 会成为路由/API 名称，并覆盖链接内嵌名称；裸链接使用其 fragment 或生成的协议/主机名称。凭据、TLS/REALITY、传输与协议调优项都放在链接的 userinfo 与 query 参数中。格式错误的链接会附诊断后跳过。未知或已移除的协议、已移除的 VLESS `vless_mode` 参数以及独立的 `mux` 行都是配置错误；请在各条 VLESS 链接上设置 `mux=`。

`direct` 和 `block` 保留给内置出站，不能用作节点名。组名不能与节点名相同。

详见 [节点参考](./reference/nodes.md)。

## 构建组

按以下顺序构建组：

1. 选择成员：静态名称使用 `filter: name(...)`，订阅来源使用 `filter: subtag(...)`，嵌套组使用 `filter: group(...)`。
2. 用 `&&` 组合 `name(...)` 和 `subtag(...)` 谓词表示 AND，用 `!` 对单个谓词取反。`group(...)` 必须独占整个 `filter:` 值；与 `&&` 或 `!` 组合的行会附诊断后被忽略。不同 `filter:` 行表示 OR。没有过滤条件且没有嵌套组时包含全部节点；仅有嵌套组时不会自动包含全部节点。
3. 选择策略：可用 `selector`/`fixed`、`urltest`/`min_moving_avg`、`loadbalance`/`roundrobin`、`fallback` 或 `score`。用 `final` 指定策略选择为空时的结果。

组声明块头以及 `->`、`fallback:` 之后的组名不要加引号，即使名称含空格。这些位置的引号会成为名称的一部分，因此 `fallback: 'proxy'` 找不到组 `proxy`。`group(...)`、`final` 和 `default` 会去掉引号。子组和节点选择应放在不同的过滤行：

```dae
group {
    Hong Kong {
        filter: name(regex: '^edge\.example$')
    }
    proxy {
        filter: group('Hong Kong')
        filter: name('edge')
    }
}
routing {
    dport(443) -> Hong Kong
    fallback: Hong Kong
}
```

Selector 的 TCP 与 UDP 都遵循已选成员，不会因健康状态切换到兄弟成员。同一叶节点的 TCP 最后尝试也不能绕过嵌套 Selector 的选择。组拨号最终总会解析到一个叶节点。

每份配置最多可定义 250 个顶层用户组；更高序号由路由 ABI 保留。

详见 [组参考](./reference/groups.md)。

## 编写路由规则

规则按 `priority` 升序执行；dae 解析器按源码顺序分配 `0, 1, ...`，同优先级保持稳定的源码顺序。目标可以是 `direct`、`block` 或组；裸节点名会在加载时被拒绝，须先将节点加入一个组（例如 `filter: name('node')`）。`(must)` 决策是最终结果：跳过嗅探，且 Clash Global/Direct 模式不会覆盖 `must` 或 `block`。GeoIP 使用 `dip(geoip: private)`/`dip(geoip: cn)`，geosite 使用 `domain(geosite: category)`。

网关管理访问与私网 DNS 绕过请按[显式本地路由迁移](./reference/routing.md#显式本地路由)配置；honk 不会自动生成接口规则。

失活出站通常执行 fail-closed：新流会被丢弃而不会泄漏到 `direct`。未配置 `final` 且只有一个唯一叶节点的 TCP 组，仅可在当前 Selector 成员路径内对同一代理做最后尝试；UDP 和全部叶节点失活的多叶节点组仍保持 fail-closed。让公网 `fallback` 指向多成员且 `policy: fallback`、带显式 fail-closed `final` 的组，并至少保留一个强制经 `direct` 的 DNS 上游。

详见 [路由参考](./reference/routing.md)。

## DNS 设置

上游可裸写 `host:port`（UDP），也可使用 `udp://`、`tcp://`、`tcp+udp://`/`udp+tcp://`、`tls://`、`https://`、`quic://`，以及 `h3://` 或其别名 `http3://`。追加 `-> node-or-group` 可强制拨号路径；所选叶节点具备对应能力时，上述 transport 均可使用代理出站。DoQ 与 DoH3 要求叶节点提供 UDP-capable `PacketTransport`；缺少代理 registry 或 packet capability 时会 fail closed。请求路由选择 `reject`、`asis` 或命名上游；响应路由选择 `accept`、`reject` 或用于有界重查询的命名上游：

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

`bind` 留空只关闭独立监听，不关闭透明 53 端口拦截；[流量规则所有权](./reference/routing.md#出站目标与-must)仍然适用。

独立监听形式都要求显式端口：裸数字 `IP:port`（仅 UDP）、`udp://host:port`、`tcp://host:port` 或 `tcp+udp://host:port`；空 host 表示绑定通配地址。除非有主机防火墙保护 LAN 暴露，否则只绑定 loopback。省略 `ipversion_prefer` 时策略为 `both`，也可设为 `4`/`6` 以同时控制 DNS 结果和 bootstrap 解析出的上游拨号顺序；偏好地址族拨号失败时会回退到另一地址族。

`client_subnet` 默认关闭。需要确定性的 ECS 时写固定 IPv4/CIDR；写 `auto` 则无需 DNS 或 HTTP，将公网路径上的首个公网 hop 推断为 `/24`。自动推断会在 reload 与网络变化时刷新；有界探测失败时不生成 ECS。客户端自带的 ECS 始终优先。启用前须阅读参考文档中的隐私警告。

详见 [DNS 参考](./reference/dns.md)。

## 订阅

每个来源写作 `tag: 'url'`，`subtag(...)` 匹配该标签。要单独覆盖 `ua`、`interval`、`cache` 或 `route`，在带引号的 URL 后接一个块。

- 共用默认值：`assets.subscription` 提供 `ua`、`interval` 和 `cache`；未单独设置下载出口时使用 `assets.route`。
- 请求身份：请求默认使用 `honk/<version>`，条目或 `assets.subscription` 设置的 `ua` 会覆盖它。缓存键包含配置中的覆盖值，因此不同请求身份使用不同的已存正文。
- 持久化：仅当 `global.store_subscribe`（默认 `true`）与条目生效的 `cache` 均为 `true` 时，成功获取并解析的原始正文才会存入状态数据库。修改 `store_subscribe` 后需重启。
- 启动与重载：启动时先恢复有效且非空的已存正文，再后台刷新。SIGHUP 沿用活动订阅节点，不从存储恢复。
- 失败处理：获取、解析或没有可用节点的失败会保留活动节点与上一次有效正文。订阅节点仅存在于运行时。

详见 [订阅参考](./reference/subscription.md)。

## 启用 Clash API、缓存文件与首包保留 UDP

**原生 API。** `native-api` 需显式编译：以 `--features native-api`（或 `native-ui`）构建；full 与 `-native-api` 发布产物包含它。listener 须配置 `experimental.native_api.enabled: true`，并满足以下条件之一：配置 bearer `secret`、设置 `password_auth: true`，或在 loopback `listen` 上设置 `allow_anonymous_loopback: true`。honk 不限制 `secret` 的最短长度，应使用足够长的随机值。默认监听地址为 `127.0.0.1:9527`，匿名 loopback 访问仅供本地开发。所有生效的原生字段均需重启。用户态观测、事件与有界历史独立于 Clash；流量/内存历史默认保留最多 600 点/600 秒。可选 `ui` 目录需已有可读 `index.html`，也可用 `--features native-ui` 与 `ui: embedded` 内嵌固定版本的 doona；运行时不下载或构建 UI。`ui: embedded-lite` 选择更轻量的 doona lite 预览版，同样需要 `native-ui`。

对于启动时已捕获 `.dae` 来源的配置，来源元数据、离线校验和实际重载操作共用现有引擎。配置读取返回已接受正文，仅遮蔽监听凭据值，包括重复、被覆盖的值及其在其他位置的出现。凭据源仍只读，哈希仍对应原始字节。源 `path` 保持相对路径，`absolute_path` 另行提供规范化绝对路径。获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的数据。`config_write` 默认 false，要求非空 secret 或 `password_auth`。主文件节点/provider 创建删除、授权源 PUT 和受限组 PATCH 复用该权威。启用 `config_write` 后，所有已接受的非凭据 include 均可编辑源，但不授予专用条目删除权限。配置的 geodata 更新将不可变的已验证字节交给同一 reload owner。激活失败不会自动回滚已写字节，应避免并发外部编辑。详见[原生设置](./reference/experimental.md#native_api)与 [主文件条目与 geodata 契约](./reference/api.md#主文件条目与-geodata-管理)。

使用 `--store db` 时，honk 运行数据库中的当前修订；启动时仅在数据库为空时导入 `-c` 文件，见[配置数据库](./reference/api.md#配置数据库--store-db)。

**Clash API。** 非空的 `experimental.clash_api.external_controller` 会启用服务器。除非防火墙和非空 `secret` 已提供保护，否则应保持 loopback 绑定；空 secret 会关闭 API 认证。相对 `external_ui` 依次优先使用 `data_dir` 下、`/var/share/honk` 下和工作目录中的已有目录；都不存在时，在 `data_dir` 下下载 dashboard。`assets.ui.url` 选择 ZIP 来源，`assets.ui.route` 选择下载出口，未设置时出口继承 `assets.route`。没有配置 URL 或出口时，分别使用内置 URL 和普通流量路由。`HONK_UI_DOWNLOAD_URL` 可覆盖 ZIP URL。

**缓存文件。** 默认情况下，Selector 选择与延迟样本保存在 `<data_dir>/state/honk.db` 中。设置 `experimental.cache_file.enabled: true` 后，在原生 API 未启用时还保存 Clash 模式与 GLOBAL 选择（启用原生 API 时这两项为临时状态，不持久化），再设置 `store_dns: true` 时还会持久化符合条件的 DNS 应答；设为 `false` 时不保存这些状态。`path`、`cache_id` 与 `store_fakeip` 已不起作用；首次启动时 honk 导入并删除旧 `cache.db`（见[升级说明](./reference/experimental.md#从-cachedb-升级)）。

**首包保留 UDP。** `global.nfqueue_enable` 默认值为 `true`；设置为 `false` 可关闭有歧义 LAN 转发 UDP 的 NFQUEUE 暂存。该设置修改后需重启。若使用 mock eBPF、不带 `ebpf` 的构建，或固定队列前置检查失败，honk 会记录 warning，仅在本进程关闭 NFQUEUE，不会改写配置文件。真实实例取得锁后，启动会绑定队列 `320`，并在发布 `inet honk_nfqueue` / `udp_decision` 前回收残留的自有 nftables table；honk 运行期间，防火墙管理器不得修改这些保留对象。

详见 [Global 参考](./reference/global.md)、[Experimental 参考](./reference/experimental.md)与 [UDP NFQUEUE 设计](./design/nfqueue.md)。

## 预热与拨号预算

这些机制互相独立，受已配置组或显式预算限制，不会按原始订阅规模无限增长。按需 Clash 延迟测试使用独立路径：冷 session/QUIC 节点只在临时 runtime 中预热 transport，并在测量结束后关闭。

| 机制 | 配置项 | 默认 | 行为 |
| --- | --- | --- | --- |
| 裸 TCP 预连接 | `preconnect_node_count` | `'auto'` | 启动时执行一轮。`'auto'` 最多尝试 8 个合格节点，组当前选择优先；`0` 关闭。显式 `N` 可覆盖全部合格节点，但最多 8 个并发尝试。拥有 session 的 AnyTLS/VLESS 模式、QUIC、`direct` 与 `block` 会被跳过。 |
| Selector 常驻 | — | 始终启用 | 保持每个 Selector 的已配置叶节点热态，包括不健康但被显式选择的节点。协议允许时保留可复用 session/client 或一条服务端裸 TCP；切换选择与 reload 会转移所有权而不中断活动流。 |
| UDP 预热集合 | `udp_warm_node_count` | `0` | 每组每个 IP 族取 top `min(N,3)` 个 UDP 叶子，最多并发 4 个尝试，并将驻留节点封顶为 `4×N`。UDP 与 Selector 所有权互相独立。 |
| 并发拨号上限 | `max_concurrent_dials` | `64` | 按 generation 限制物理代理连接与握手。Ready 池命中、已热 transport 上的逻辑流、`direct` 与 `block` 不占额度；重叠的 reload generation 还共享启动时描述符 gate。 |

周期 HTTP 健康检查与 Clash 延迟测试使用相同的临时预热路径：冷的可复用 transport 在计时外预热，并在结束后关闭。报告的延迟是已预热连接上第二个请求的耗时，即一次往返，不计拨号与 TLS 握手。只有预热后的目标交换成功才报告健康并提供选择 RTT；setup 与交换失败都会更新活性/冷却，但不产生延迟样本或排名 strike。扫描不会为每个节点保留一条空闲隧道。

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
4. 修改组或策略后，SIGHUP 会重建 `GroupManager`；仍有效的 Selector 选择会迁移到新的运行时代次。
5. 修改 `global.nfqueue_enable` 后需重启；若希望启用暂存，确认真实 eBPF 后端和启动前置条件可用，并确保防火墙管理器不修改 `inet honk_nfqueue` / `udp_decision`。
6. 增加或修改配置 fixture 时，运行 `cargo test -p honk-config` 以保持解析器示例有效。

## 相关文档

- [设计总览](./design/overview.md)
- [Global 配置参考](./reference/global.md)
- [DNS 发布运维](./operations/dns-rollout.md)
