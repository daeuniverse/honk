# 订阅参考

`subscription {}` 配置远程节点列表。条目语法、持久化恢复机制与支持的订阅正文格式如下。

## `subscription {}` 语法

URL 写在条目行。要为单个订阅覆盖下载设置，在带引号的 URL 后接一个块，每行一个键：

```dae
subscription {
    primary: 'https://example.com/sub'
    'https://example.com/no_tag_link'
    detailed: 'https://example.org/sub' {
        ua: 'honk/1.0'
        interval: 10000s
        cache: false
        route: direct
    }
}
```

条目块接受四个选项：

| 选项 | 作用 | 内置默认值 |
| --- | --- | --- |
| `ua` | 覆盖请求的 User-Agent。 | `honk/<version>` |
| `interval` | 设置刷新间隔；`0` 禁用定期刷新。 | `86400s` |
| `cache` | `false` 使该订阅的正文不写入订阅存储。 | 开启 |
| `route` | 指定拉取出口（见下文）。 | `routing` |

未设置的选项先取 `assets.subscription` 的默认值（出口取 `assets.route`），再取内置默认值。见 [Assets 配置参考](./assets.md)。

两种旧写法仍可解析，且不产生警告：

| 写法 | 示例 |
| --- | --- |
| 带引号的 URL 后追加 `(UA)` | `compatible: 'https://example.net/sub'(honk/1.0 like)` |
| URL 写在块内 | `detailed: { url: '…' ua: '…' }` |

块内也接受 `download_detour` 作为 `route` 的别名。同时设置两者会产生 `conflicting-subscription-route` 错误。下文的后缀和紧接注释规则适用于 `(UA)` 写法。

标签可以省略。标签和 URL 都可使用配对的单引号或双引号。

| 条目形式 | 标签解析规则 |
| --- | --- |
| 裸条目 | 第一个 `:` 之前的文本为标签，除非该冒号属于 `://`。URL 中后续的冒号不会拆分标签。 |
| 带引号的标签后接 `:` | 显式标签。 |
| 没有显式标签的带引号 URL | 去除外层引号后，应用首个冒号规则。`'paid:https://example.com/sub'` 的标签为 `paid`；`'https://example.com/sub'` 无标签。 |

`(UA)` 后缀要求 URL 带引号，避免与裸 URL 中的括号混淆。两种形式均保留 `sub_type: simple`，自动识别下文支持的正文格式。

解析器先处理链接后缀，再规范化引号内的标签：`'paid:https://example.com/sub'(agent)` 和 `'paid:https://example.com/sub'#note` 都保留标签 `paid`。诊断条目序号按源顺序统一计算块形式和行内声明，包括被跳过的条目。
条目以引号开头时，只有紧接结束引号后的冒号（允许中间有空白）才声明显式标签。未加引号的 User-Agent 或紧贴链接的注释后缀中的冒号仍是后缀数据：`'https://example.com/sub'(agent:1)` 仍是不带标签的条目。

不带标签的条目使用 URL 的主机名作为名称：`'https://example.com/sub'` 的名称是 `example.com`。如果无法解析出主机名，名称保持为空，配置验证会拒绝该条目。验证不要求名称唯一：显式标签 `example.com` 与该主机上不带标签的 URL 都匹配 `subtag(example.com)`，该筛选条件会选中两个订阅的节点。按主机名生成名称仅适用于 dae；JSON、YAML 和 TOML 仍要求提供 `name`。

不带标签且不含 `://` 的文本会被忽略。带显式标签的条目仍交给配置验证，要求名称非空且 URL 使用 HTTP(S)。`file://`、`http-file://` 和 `https-file://` 仍不受支持。

条目行中，配对引号之外的 `#` 位于语句开头或紧跟 ASCII 空格、制表符时，会开始注释。裸 URL 中紧贴前文的 `#` 仍是数据，即使前一个字符是括号也不例外，例如 `https://example.com/sub?filter=(hk)#token`。User-Agent 中若包含前有空格的 `#`，应给 UA 加引号：`'https://example.com/sub'('agent # build')`；否则，注释会截断该后缀。

URL 带引号时，紧贴结束引号或一个完整 `(UA)` 后缀的 `#` 作为注释接受，并在该字节处产生 `legacy-glued-hash` 警告，提示在注释前加空白。`'http://q'#c` 和 `'http://q'(ua)#c` 都保留 URL `http://q`，只有后者设置 UA `ua`。配对引号内的括号不计入嵌套深度。后缀内部紧贴前文的 `#` 仍是 UA 数据，包括 `(Mozilla/5.0 (X11; (Linux)#build))` 中的 `#`。其他尾随文本（包括 `(ua)(x)` 或 `(agent) junk`）使条目被跳过，并产生 `trailing-entry-text` 或 `legacy-ua-boundary` 诊断。

这种紧贴尾部的兼容截断发生在块结构识别之后，并非词法注释。`sub: 'http://q'(ua)# }` 中独立的 `}` 仍会关闭订阅块，后续条目可能因此落在块外。请写成 `(ua) # }`，使花括号成为注释数据。

引号错误与块结构规则见[方言参考](./dialect.md)。空 `route` 在所有构建中都跟随路由。

## 内部模型

| 字段 | 类型 | 默认值 | 可在 dae 中设置 | 含义 |
| --- | --- | --- | --- | --- |
| `id` | UUID | 随机 UUID | 否 | 运行时订阅身份；SIGHUP 时，若拉取身份（URL + 配置的 `ua` + 标头）与已有订阅匹配则保留该值。 |
| `name` | string | `""` | 是，作为标签；省略时取 URL 主机名 | 显示标签，也是组 `subtag(...)` 过滤条件使用的值。 |
| `url` | string | `""` | 是 | HTTP(S) 拉取 URL。 |
| `sub_type` | enum | `simple` | 否 | 正文解析器：`simple`、`clash`、`sip008` 或 `custom`。 |
| `update_interval` | u64 | `86400` | 是，对应 `interval` | 定期刷新间隔，单位为秒；`0` 禁用定期刷新。 |
| `user_agent` | string 或 null | `honk/<version>` | 是，对应 `ua` | 可选的 `User-Agent` 覆盖值；未设置时请求标识为 `honk/<version>`。 |
| `headers` | `{key,value}[]` | `[]` | 否 | 有序的额外请求标头。 |
| `download_detour` | string | `""` | 是，对应 `route` | 拉取的出口：空值或 `routing` 遵循路由规则，`direct` 直连主机，组名则始终经过该组。未知组在校验时被拒绝。 |
| `enabled` | bool | `true` | 否 | 禁用的订阅不会恢复、拉取或刷新。 |
| `cache` | bool | `true` | 是，对应 `cache` | 在 `global.store_subscribe` 启用时保存拉取到的正文，供离线启动恢复。设为 `false` 时既不保存也不恢复，维护任务会删除此前保存的正文。 |
| `last_updated` | datetime 或 null | null | 否 | 模型元数据；当前 core 运行时不更新它。 |
| `node_count` | u32 | `0` | 否 | 模型元数据；当前 core 运行时不更新它。 |
| `created_at` | datetime | 构造时间 | 否 | 模型构造时间。 |

按以下规则选择正文解析器：

| `sub_type` | 解析行为 |
| --- | --- |
| `simple` | 自动识别分享链接列表、Clash YAML/JSON、SIP008、sing-box JSON 和受支持的客户端记录。 |
| `clash` | 带顶层 `proxies` 序列的 YAML 或 JSON。 |
| `sip008` | SIP008 `servers` 对象或裸服务器数组；不是分享链接列表。 |
| `custom` | 与 `simple` 使用相同的格式识别。 |

`honk-tool sub` 的下载正文与本地文件使用同一个解析器。

## 拉取、持久化与恢复

`global.store_subscribe` 默认为 `true`。启用后，运行时会打开私有订阅存储并立即拉取每个已启用订阅。请求默认使用 `honk/<version>`，可由 `user_agent` 覆盖。非零 `update_interval` 会安排后续刷新。

| 属性 | 当前行为 |
| --- | --- |
| 位置 | 状态数据库 `<data_dir>/state/honk.db` 的 `subscription_body` 表（文件权限 0600，目录 0700，见 [API 参考](./api.md#配置数据库--store-db)）；`data_dir` 默认值为 `/var/lib/honk`。 |
| Key | 对带长度边界的 URL、配置中的 user agent 覆盖值（未设置或为空时为空）及有序标头 key/value 对计算 SHA-256，再用 URL-safe Base64 编码并添加 `.sub`。版本化的默认请求 UA 不参与键，因此默认订阅升级后仍保留已存正文。请求身份不会以明文暴露。 |
| 写入边界 | HTTP 成功且正文通过导入校验后，在一个事务中保存完整原始响应，包括被拒绝的条目。 |
| 容量限制 | 单个正文最多 8 MiB，全部正文合计最多 32 MiB。写入会超过 32 MiB 时，先删除已停用订阅的正文。仍然超出时拒绝写入，保留原正文，本次拉取报告 `subscription-store-write-failed`。订阅连续两次维护（每 60 秒一次）都未启用时，其正文被删除。`store_subscribe: false` 的启动若因 `cache_file`、`password_auth` 或 `--store db` 仍打开状态数据库，会清空该表。 |
| 从 `.sub` 升级 | 取得实例锁后导入符合条件的旧正文，步骤见下文。 |
| 重定向 | 最多 5 跳。从 `https` 重定向到其他协议方案会让本次拉取失败；重定向到配置 URL 自身未使用的回环、私有、链路本地或未指定字面地址同样失败。解析到这类地址的主机名不在检测范围内。 |
| 正文大小 | 最多 8 MiB，在读取过程中判定，而不是缓冲完整正文之后。 |

启动时取得实例锁后，按以下步骤导入旧 `.sub` 存储：

1. 依次检查 `<data_dir>/.sub`、`/var/share/honk/.sub`、`./.sub`，选择第一个私有旧存储。
2. 复制已启用订阅的正文；状态数据库中已有的正文优先。
3. 删除已复制的 `*.sub` 和该目录中所有 `.*.tmp` 文件。目录为空时一并删除，其他旧位置保持不变。

无法读取、超过 8 MiB 或会使总量超过 32 MiB 的正文保留在原处，并记录警告。已停用订阅的正文也保留。后续启动时若启用该订阅，可直接导入正文，无需拉取。

导入前，旧进程已退出，因此其最后写入的正文与其他正文一样会被复制。此后再启动旧版本时，只能找到保留的正文，其余订阅会重新拉取。

订阅正文及其产生的节点都属于运行时状态，不会写回 dae 配置。

与 honk 自身发起的其他下载一样，订阅拉取默认经过路由，除非条目的 `route` 或 `assets.route` 另行指定。

| 出口 | 行为 |
| --- | --- |
| 空值或 `routing` | 每个 URL 都按流量路由规则处理，包括重定向。规则可选择节点、组、`direct` 或 `block`。 |
| 组名 | 强制经过该组。 |
| `direct` | 使用引导解析器和绕过标记，不经过路由。保留原有直连传输。 |

经路由的请求与 Geo 数据、外部 UI 下载共用路由决策和隧道。请求保留相同的 `User-Agent`、请求头和下载限制：

| 限制 | 行为 |
| --- | --- |
| 超时与正文大小 | 30 秒；最多 8 MiB。 |
| 重定向状态码 | 仅跟随 301、302、303、307、308，最多 5 次。 |
| 重定向目标 | 禁止从 HTTPS 转到 HTTP，或从公网地址转到私有字面地址。前表的重定向限制同样适用。 |
| URL 用户信息 | 以基本认证发送。 |
| 协议、主机或端口变化 | 与直连客户端一样，移除 `Authorization`、`Cookie` 和 `Proxy-Authorization`。 |

未启用 `native-api` 的构建使用相同的订阅拉取路由规则。

订阅可能经由自身提供的节点拉取，例如规则把订阅 URL 发往一个只含该订阅节点的组。全新安装时这些节点尚不存在。honk 不会回退到直连：所选路由没有可用节点时，拉取失败，错误信息指明订阅名和出站，说明该路由暂时无法承载这次下载，并建议为该订阅设置 `route: direct`。原生 API 的订阅源状态中 `last_error.code` 为 `route_unavailable`。期间从已存正文恢复的节点继续生效。

启动时先恢复节点，再刷新订阅：

1. 联网刷新前先解析已存正文。有效正文立即提供活动节点；缺失、无效或空正文被忽略。
2. 未有效恢复的 `direct` 订阅共用五秒首次拉取等待，直到拉取完成或期限到达。有效恢复的订阅不参与等待，但仍在后台刷新。
3. 启动阶段的订阅处理完成后，路由就绪，再拉取经路由的订阅。

后续通过校验的刷新替换 SQLite 正文行，而不是旧存储文件。

恢复或首次拉取的正文中，若有节点 ID 已被内联节点占用，启动配置会排除该订阅，而不是让启动失败；运行时发布同样会拒绝这种冲突。若节点 ID 已由其他订阅发布，该节点会从本订阅中去掉并记录警告，其余节点照常发布，节点保留在先发布的订阅中。正文仍可替换该订阅自己的节点。

原生 API 订阅源报告 `last_error.code` 为 `publication_rejected`，`last_error.details.diagnostic_code` 为 `duplicate-node-id`。以此方式被拒绝的已恢复正文仍视为已恢复：该订阅不参与首次拉取等待，其后台刷新仍会运行并重复该检查。

SIGHUP 时，拉取身份（URL + 配置的 `ua` + 标头）相同的订阅保留运行时 ID。重载会沿用仍处于启用状态的订阅所属活动节点，提交重建后的配置，再立即开始后台刷新。即使某订阅没有存活节点，重载也不会读取已存正文；只有启动时才会从存储恢复正文。

拉取失败时保留可用的运行时状态：

- HTTP、UTF-8 编码、解析或无可用节点错误不会发布替换节点，也不会写入，因此活动节点与上一次有效正文都会保留。通过校验的正文按原始字节保存，不修复编码。
- 拉取失败后，首次等待 30 秒与 `interval` 中的较小值，再翻倍退避，最多为 10 分钟与 `interval` 中的较小值；`interval: 0` 禁用自动重试。发布成功或被拒绝都会结束已有退避，恢复正常刷新间隔。
- 解析成功后，持久化写入失败属于非致命错误。新解析出的节点仍会返回用于发布，原子写入不会保存不完整的正文。下次重启可以恢复磁盘上保留的任一完整有效正文。
- 不支持或格式错误的节点会逐个跳过。共用节点构建器的警告包含从 1 开始的 proxy 索引和固定拒绝原因，不包含原始记录或凭据。只有没有剩余可用节点时，整个正文才失败；空结果绝不会清空上一代节点。

上一次有效正文指通过当前导入规则校验的正文，不是最后一次成功发布的运行时配置。部分条目无效但仍有一个可用节点的正文可以替换存储；全部无效的正文不能。恢复时会按当前规则重新解析，因此旧版本保存的正文可能被拒绝。写入成功后，若节点集合校验或发布失败，活动配置保持不变，但磁盘上可能已保存新正文。磁盘与活动配置不属于同一事务。

通过 SIGHUP 修改 `global.store_subscribe` 会因需要重启而被拒绝。

## 首次启动时订阅 URL 被阻断

如果订阅 URL 被阻断或其域名受到 DNS 污染，可先添加一个可达的静态代理节点，并将订阅的 `route` 指向仅包含该节点的组。
该组在首次启动时即可使用，不依赖任何订阅提供的节点。
请将下方 SOCKS5 地址替换为能够访问订阅源的代理地址，并将订阅 URL 替换为实际地址。

```dae
node {
    bootstrap: 'socks5://192.168.1.2:1080'
}

group {
    Bootstrap {
        filter: name(bootstrap)
    }
}

subscription {
    provider: 'https://example.com/sub' {
        route: Bootstrap
    }
}
```

## 订阅正文格式

所有接受的节点都会获得订阅 ID。重复的派生节点 ID 保留第一个可用条目；被拒绝的条目不会占用身份。后续重复条目的诊断同时记录两个原始索引。数组索引从 1 开始，在规范化前确定；URI 和记录索引使用包含空行与注释的物理行号。Base64 解码后的来源引用原始正文，不虚构编码字节偏移。完整客户端配置只提取节点，不导入其中的 DNS、路由、组或远程订阅配置。

规范化条目逐个进入准入流程，不保留与正文条目数等大的中间结果列表。每份正文最多保留 128 条非终止诊断，超出时追加一条 `subscription-diagnostics-truncated` 摘要记录省略数量；正文失败的终止错误单独保留。调用方已有的诊断不变，也不占用此限额。结构化、URI 和记录导入均使用该限额，包括 Base64 解码与持久化正文恢复；达到限额不会停止有效节点准入，也不改变重复节点保留第一个可用条目的规则。

Clash、SIP008 和 sing-box 的凭据标量保留字符串原始字节，并把原生有限数转换为来源格式的规范十进制文本。缺失或 null 表示未提供；布尔值、列表、映射和非有限数会使条目被拒绝。有效别名不能掩盖已提供的无效凭据。数字 UUID 仍无法通过 UUID 校验；空密码仍须满足对应协议的要求。

### 分享链接列表

正文可以是纯文本，也可以使用标准或 URL-safe Base64 编码；填充可以省略，编码块之间允许 ASCII 空白。原始正文与解码正文均接受开头的 UTF-8 BOM。每行包含一个分享链接：

```text
# blank lines and comments are ignored
socks5://user:password@127.0.0.1:1080#local
vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls#edge
```

空行、注释和 Shadowrocket 的 `REMARKS=` / `STATUS=` 元信息行会被忽略，不产生节点警告。其余每行都由 `Node::from_share_link` 解析；不支持或格式错误的行会被跳过并警告。honk 不执行代理插件，因此带有非空插件值的分享链接也会被跳过。若正文没有受支持的节点 URI（包括只有元信息的正文），则拒绝整个正文。规范分享链接字段与协议见[节点参考](./nodes.md)。

### Clash YAML 与 JSON

完整配置或订阅源正文必须包含顶层 `proxies` 序列。缺少受支持的 `type`、服务器地址、有效非零端口或必需凭据的条目会被跳过。端口可以是整数或数字字符串。JSON 使用原生解码，支持显示名称中的 UTF-16 代理对转义。

接受的 `type` 值包括 `socks5`、`ss`/`shadowsocks`、`trojan`、`vmess`、`vless`、`hysteria2`/`hysteria`、`tuic`、`juicity` 与 `anytls`。无关的客户端元信息会被忽略；不支持的线协议传输、代理插件和相互矛盾的安全设置不会被静默替换。

#### 通用代理字段

| Clash 字段 | 内部字段 | 规则 |
| --- | --- | --- |
| `name` | `name` | 默认为 `<type>-<server>:<port>`。 |
| `server`, `port` | `host`, `port`, `address` | 必需的地址和非零 `u16` 端口；接受数字形式的端口字符串。 |
| `username` | `username` | 可选 string。 |
| `password` | `password` | 可选 string；VLESS 使用下文优先级。 |
| `cipher` | `encryption` | 可选加密算法；VLESS 的字段优先级见下文。 |
| `plugin`, `plugin-opts` | — | 不支持；任一字段具有非空值时，条目会在发布节点前被跳过，映射类型的 options 也会被拒绝。 |
| `network` | `transport` 或数据包网络能力 | Trojan/VMess/VLESS 使用流传输（`tcp`、`ws`、`grpc`、`xhttp`）；AnyTLS 使用数据包网络能力。 |
| `tls` | `tls` | 可选 bool。Trojan、AnyTLS、Hysteria2、TUIC 和 Juicity 默认启用 TLS，并拒绝显式关闭。 |
| `servername`、`server-name`、`sni` | `sni` | 空值或纯空白名称视为未指定；非空别名必须逐字节一致。 |
| `skip-cert-verify`、`skip_cert_verify`、`insecure` | `skip_cert_verify` | 须使用原生布尔值；已提供的别名必须一致。 |
| `fingerprint`、`pin-sha256`、`pin_sha256` | `tls_pin_sha256` | 叶证书 SHA-256 固定值（十六进制，忽略冒号和空白），取代 PKI 与主机名校验。所有 TLS 协议都会导入 Clash 的 `fingerprint`；无 TLS 协议则跳过该条目。已提供的别名必须一致。 |
| `alpn` | `tls_alpn` | raw TCP TLS 的有序字符串列表或逗号分隔字符串；XHTTP 只接受 H2，省略时规范化为 `["h2"]`。QUIC 保留下文的协议专属规则。 |

#### 协议专属选项

支持的拼写别名会在派生节点身份前规范化。

| 协议 | 导入的选项 |
| --- | --- |
| Hysteria2 | `password`/`auth`，以及 `obfs: salamander` 与 `obfs-password`。支持上传/下载带宽、`ports`/`mport` 跳跃端口范围、`hop-interval`/`mhop`、接收窗口、MTU 与 MTU 发现设置。 |
| TUIC | UUID/密码、拥塞控制、ALPN、接收窗口、MTU。 |
| AnyTLS | `idle-session-check-interval`、`idle-session-timeout`、`min-idle-session`。 |

显式关闭的功能块按禁用处理，不会误判为启用未支持功能。原生支持 UDP 的协议接受 `udp: true`。节点模型无法保留显式 UDP 限制时会拒绝导入。

TUIC 允许省略密码或使用空密码。Hysteria2 和 Juicity 接受与运行时固定选择一致的 `h3` ALPN。

Juicity 的流和连接接收窗口初始均为 8 MiB，自适应流控可将两者分别调高至最多 32 MiB。导入的初始窗口字段接受缺失值、`0` 或 `8388608`，拒绝其他覆盖值。

AnyTLS 按 `anytls-network`、适用的 `network`、`udp` 的顺序一次性解析数据包能力声明。空文本或 null 不提供网络声明。网络字符串使用逗号分隔的 `tcp`/`udp`；别名按是否允许 UDP 比较，因此 `udp` 与 `tcp,udp` 一致，而 `tcp` 与 `udp: true` 冲突。即使存在有效别名，`quic` 等未知值仍会使条目被拒绝。等价声明保留第一个显式网络字段的写法；仅提供布尔值时，才生成 `tcp` 或 `tcp,udp`。

以下 TCP TLS ALPN 规则适用于结构化订阅导入及扁平字段 `tls_alpn`。分享链接的 ALPN 兼容行为不变。

| 输入或限制 | 行为 |
| --- | --- |
| 列表成员 | 原样保留字节和顺序。每个名称占 1–255 个 UTF-8 字节。 |
| 带长度前缀的完整列表 | 最多 65,533 字节。完整 ClientHello 还受 TLS 库的大小限制。 |
| 导入的 `alpn` 缺失、为 null 或为空 | 保留原有 TLS 配置方案默认值及节点 ID。 |
| 扁平 `tls_alpn` | 接受省略或字符串数组，不接受 null。 |
| 非空覆盖值 | 参与节点身份派生。与关闭 TLS、REALITY、WebSocket 或 gRPC 组合时拒绝，不会静默丢弃。 |
| Chrome ALPS | 仅在实际 ALPN 列表包含 `h2` 时发送。 |

XHTTP 不受裸 TCP ALPN 规则限制：它始终使用 H2，包括 REALITY 和显式明文 H2。Mihomo 接受 `network: xhttp` 或输入别名 `splithttp`。

| `xhttp-opts` 字段 | 导入行为 |
| --- | --- |
| `path`、`host`、`mode`、`headers`、`x-padding-bytes`、`no-grpc-header`、`sc-max-each-post-bytes`、`sc-min-posts-interval-ms` | 接受。 |
| `no-sse-header`、`sc-max-buffered-posts`、`sc-stream-up-server-secs` | 仅服务端使用，检查类型后丢弃。 |
| `reuse-settings`、`xmux` | 按 Xray 语义遵循 URI `xmux` 规则。Mihomo 则只要存在 `reuse-settings` 就启用自己的复用管理器。 |
| `download-settings` | 须为 Xray StreamConfig 映射，见下文。 |

`download-settings` 接受面板导出的 Xray 结构。字段为 `address`、`port`、`network`、`security`、`alpn`、`tlsSettings`、`xhttpSettings`。还可包含扁平 `x-padding-bytes`、仅上传端使用的 `no-grpc-header`/`sc-*` 键，以及默认值的 `reuse-settings`/`xmux`。其语义与 URI `downloadSettings` 相同，因此同一订阅的两种导出得到相同节点 ID。

Mihomo 自身具有继承语义的键会被拒绝，如 `server`、`servername`、`tls`、`skip-cert-verify`。这与 mihomo 有意不同：mihomo 忽略 Xray 结构的键，将 GET 发往上传服务器。规范默认值、范围和请求头限制见 [XHTTP 节点参考](./nodes.md#h2-上的-xhttp)。

其他不支持的参数，包括其他字段位置和填充混淆设置，只要存在就会使条目被拒绝，即使值为 null、空值或 false。其他有效节点保留。URI/VMess extra JSON 在构造映射前拒绝重复成员。

#### VLESS transport 与 REALITY

VLESS 字段会在派生节点身份前应用：

| Clash 输入 | 映射 |
| --- | --- |
| `uuid`, then `password` | 凭据；`uuid` 优先，`password` 作为回退。 |
| `encryption`, then `cipher` | VLESS Encryption；`encryption` 优先。 |
| `flow` | 空值或纯空白视为未指定；否则必须为 `xtls-rprx-vision` 或 `xtls-rprx-vision-udp443`。 |
| `network` | 流传输；数据包权限仍由独立的 `udp` 声明控制。 |
| `reality-opts.public-key` | 启用 REALITY TLS 承载连接；必须是非空 string。 |
| `reality-opts.short-id` | 可选 REALITY short ID。 |
| `reality-opts.spider-x` | REALITY spider path；缺失或为空时使用 `/`。 |
| `ws-opts.path` | WebSocket path；回退到扁平别名 `ws-path`。 |
| `ws-opts.headers.Host` | WebSocket Host 标头，键匹配不区分大小写；依次回退到 scalar `ws-headers`、`ws-host`。 |
| `grpc-opts.grpc-service-name` | gRPC service name；回退到 `grpc-service`。 |
| `client-fingerprint` | 有意不导入。TLS 指纹由进程级 `global.tls_implementation` 与 `global.utls_imitate` 选择。 |

嵌套 WS/gRPC 值优先于其扁平别名。启用的 `reality-opts` 必须是映射且含非空 `public-key`；无效的启用声明绝不会降级成普通 TLS。空 block 或显式禁用的功能 block 会被忽略。导入的 REALITY 与规范分享链接使用相同的仅 TLS 1.3、先 hybrid 后 classic 键 share 及 fail-closed 单 ClientHello 行为；见[节点参考](./nodes.md#vless-udp-and-multiplexing)。

#### VLESS UDP 与多路复用

导入默认值取决于来源格式；它们并不都表示 honk 规范的 `packetEncoding=auto` 默认值。

| Clash 表示 | Packet 回退 | Multiplex | UDP 权限 |
| --- | --- | --- | --- |
| 没有数据包声明且没有启用的封装 | `auto` | off | 关闭 |
| 只有空/null 数据包编码 | `auto` | off | 关闭 |
| `packet-encoding: none`/`legacy`，或 `xudp: false` | 原生 | off | 除非 `udp: false`，否则开启 |
| `packet-encoding: xudp`，或 `xudp: true` | Single XUDP | off | 除非 `udp: false`，否则开启 |
| 未声明其他数据包设置时的 `udp: true` | Single XUDP | off | 开启 |
| `udp-over-tcp: true`，或 version 为 `0`/`2` 的启用 object | UoT v2 | off | 除非 `udp: false`，否则开启 |
| 启用 `smux`/`multiplex`，并指定 `protocol: h2mux` 或显式 `padding` | auto（被封装接管时不生效） | H2MUX | 除非 `udp: false`，否则开启 |
| `mux: { enabled: true, ... }` | `auto`，除非显式数据包编码仍能通过 protocol 回退或 `skip` 生效 | Xray Mux.Cool | 除非 `udp: false`，否则开启 |

对 H2MUX，`padding: true` 选择现有 padded 线协议格式，false 选择无填充的 H2MUX。现有 `only-tcp`、Brutal 和非零 `max-connections`/`min-streams`/`max-streams` 限制不变。启用 H2MUX 与 Xray mux、UoT 互斥；启用 UoT 也与 Xray mux 互斥。显式 XUDP 与 H2MUX 或 UoT 冲突；原生/auto 声明只会在封装接管时不生效。

启用的 Clash `mux` 块只接受 `enabled`、有符号 `i16` 的 `concurrency` 和 `xudpConcurrency`，以及 `xudpProxyUDP443` 作为有效设置。未启用的额外设置会被忽略。

| 并发值 | TCP `concurrency` | `xudpConcurrency` |
| --- | --- | --- |
| 负值 | 关闭 TCP 多路复用。 | 使用数据包回退路径。 |
| 零 | 每条 TCP 承载连接允许同时承载 8 个逻辑子流。 | 共用已启用的 TCP 池及其逐连接并发值。TCP 多路复用关闭时，使用数据包回退路径。 |
| 正值 | 设置每条承载连接的逻辑子流并发上限，最多 128。 | 建立独立 UDP 池，按该值设置每条承载连接的逻辑子流并发上限，最多 128。 |

并发值不表示物理承载连接数量。UDP/443 策略默认为 `allow`，也接受 `skip` 或 `reject`。优先级见[节点参考](./nodes.md#vless-udp-and-multiplexing)。

`udp: false` 独立关闭数据包拨号，不会关闭仍符合条件的裸 TCP 路径。别名冲突、重复 XUDP 表示、启用 packet-address、未支持的数据包编码、未支持的 UoT version，或启用的 Xray mux 中无效/未支持的设置，也会使 VLESS Clash 条目被拒绝。

规范 VLESS 分享链接使用精确的 `packetEncoding=auto|none|xudp|uot-v2`、`mux=off|h2mux|xray` 和 `udp=0|1` 查询参数。已移除的 `vless_mode` 查询参数，以及 `smux`、`udp-over-tcp`、`packet-encoding` 等含义不明确的第三方分享链接拼写会被拒绝，不会猜测其语义。

### SIP008 与 sing-box JSON

SIP008 version 1/2 封装（`{"servers":[...]}`）及裸服务器数组会导入 Shadowsocks 的 `server`、`server_port`、`method`、`password` 和 `remarks`。空插件字段不会导致拒绝；有效的插件配置仍不受支持。

sing-box 配置从 `outbounds` 导入受支持的条目：

- 代理节点：Shadowsocks、SOCKS5、VMess、VLESS、Trojan、Hysteria2、TUIC、Juicity、AnyTLS。
- 结构性条目，不属于代理节点：`selector`、`urltest`、`direct`、`block`、`dns`。

TLS/SNI、REALITY、WebSocket/gRPC、VLESS 数据包选项和受支持的协议调优通过共用节点构建器规范化。

| 来源特有情况 | 导入行为 |
| --- | --- |
| VLESS 未启用 H2MUX/UoT 封装，且没有显式 `packet_encoding` 选择其他路径 | 使用 Single XUDP 并允许 UDP。这是 sing-box 导入默认值，不是 Auto 的全局含义。 |
| gRPC 服务名为空或省略 | 保留 sing-box 的空服务名，不使用 honk 的 `GunService` 默认值。 |
| Hysteria2 提供 `server_ports`，未提供 `server_port` | 以第一个跳跃端口作为名义端点。 |
| 节点级 uTLS 指纹提示 | 不覆盖 honk 的进程级 TLS 选择。 |

不支持的链式代理、线协议功能和认证要求不会被静默丢弃。

在 sing-box 输入中，`network` 表示数据包网络能力，不是流传输类型；`transport.type` 选择流传输方式。`h2` 等不支持的名称会使条目被拒绝，不会被当作裸 TCP。

官方 sing-box 没有原生 XHTTP 传输。导入器明确拒绝 `transport.type: xhttp` 与 `splithttp`，不会把旧 `http`、H2、QUIC 或第三方 fork 解释为 XHTTP。Client-record 中的 XHTTP 传输同样不支持。

在支持数据包限制的 sing-box 映射中，`network: udp` 与 `network: tcp,udp` 允许 UDP，`network: tcp` 则关闭 UDP。这些值不会额外禁止 TCP。`network` 与 VLESS 回退编码和 H2MUX/UoT 承载连接选择保持独立。

显式 sing-box 原生 VLESS UDP（`packet_encoding: ""`）映射为原生路径。启用 H2MUX 或 UoT v2 时由封装承载数据包路径，即使来源同时显式指定 `packet_encoding`（包括 `"xudp"`）；禁用封装不会关闭 sing-box 的 Single-XUDP 默认值。sing-box 多路复用导入仍只支持 H2MUX，不会合成 Xray Mux.Cool 控制项。

### Surge、Surfboard、Loon 与 Quantumult X

导入器接受 Surge/Surfboard/Loon 的具名逗号分隔记录，以及 Quantumult X 的 `protocol=endpoint,...,tag=name` 记录。完整配置使用 `[Proxy]` 或 `[server_local]`；其他配置段会被忽略。带引号的名称/密码可以包含逗号、等号、转义引号和有意保留的首尾空格。

显式凭据和加密方法别名在转换前须一致。具名记录仅在对应具名值缺失时使用位置参数；有效的显式值不会因位置参数不同而冲突。Quantumult X 不使用位置参数回退。显式空凭据参与别名比较，不会触发回退。

允许为空的可选记录凭据会逐字节保留空字符串和带引号的空白：SOCKS 用户名与密码、Hysteria2 认证值及 TUIC 密码。显式空值仍优先于位置参数；要求非空凭据的协议仍会拒绝空值。

记录中的 `transport`/`network` 流传输声明在赋值前比较，包括重复键。空文本与 `tcp` 都表示裸 TCP；声明冲突或包含不支持的传输方式时，拒绝该条目。

AnyTLS 记录中的 `network` 表示数据包能力，不是流传输方式。所有重复的 `network`、`udp` 和 `udp-relay` 值都会在选择前校验。等价声明保留第一个显式网络值的写法；任一值无效或冲突时，拒绝该记录。

VLESS 记录的 `packet-encoding`/`packet_encoding`/`packetencoding` 值为 `none` 或空时选择原生 UDP，`xudp` 选择 Single XUDP。重复别名必须一致，包括显式空赋值；`udp`/`udp-relay` 独立控制数据包权限。既没有数据包编码也没有 `udp: true` 时，记录保持关闭 UDP；仅有 `udp: true` 时选择 Single XUDP。记录格式中有效的 `mux` 与 UoT 声明仍不受支持，不会被重新解释。

受支持的记录把凭据、TLS/SNI、WebSocket/gRPC、REALITY 和已实现的协议选项映射到同一节点模型。Quantumult X 的 `obfs=wss` 同时使用 `obfs-host` 作为 WebSocket Host 和默认 TLS SNI；显式 TLS 主机名优先。SSR、不支持的插件/混淆及传输方式会被跳过，不会冒充另一种协议导入。

Surge `server-cert-fingerprint-sha256` 映射到 honk 的叶证书 pin：两者都替代标准 X.509 验证。独立的 `server-cert-verify-name`、客户端证书、`sni=off` 和 Shadow TLS 无法表达，会被拒绝，不会静默丢弃（[Surge TLS 参考](https://manual.nssurge.com/policies/tls.html)）。

记录格式会在赋值前比较 `skip-cert-verify`、`allow-insecure`、`insecure`，以及取反后的 `tls-verification`。`tls-verification=false,insecure=true` 一致；`tls-verification=true,insecure=true` 则拒绝该条目。记录文本仅接受不区分大小写的 `true/yes/1/on` 和 `false/no/0/off`；空文本及 `t/y/f/n` 仍为无效值。证书固定规则的限制不变。

有效的 Quantumult X `tls-cert-sha256` / `tls-pubkey-sha256` 固定证书设置会被拒绝：honk 的叶证书 pin 会替代 PKI，不能替换尚未确认等价的外部验证约定。显式设置 `tls-verification=false` 时，QX 会忽略两类 pin，导入会保留该禁用验证行为。有效的 QX REALITY 会按[官方配置](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf)忽略自定义 `tls-alpn` 和 session-ticket 设置；普通 TLS 不适用该例外。旧 VMess `aead=false`、启用的 Shadowsocks UoT/SSR、不支持的 TLS ALPN 和禁用 TLS 会话复用会被拒绝，不会静默丢弃。

## 离线解析与探测

`honk-tool sub` 接受需要拉取的订阅 URL，或任一种受支持正文格式的本地文件。本地文件不触发订阅下载，可用于离线解析；随后命令仍会执行配置的连通性与延迟探测：

```console
honk-tool sub ./share-links.txt --limit 10
honk-tool sub https://example.com/sub --ua honk-tool
```

传入 `-` 会从标准输入读取一个 HTTP(S) 订阅 URL，而不是订阅正文。探测参数与输出见 [CLI 参考](./cli.md)。

## 相关文档

- [节点参考](./nodes.md)
- [组参考](./groups.md)
- [CLI 参考](./cli.md)
