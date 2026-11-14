# 订阅参考

`subscription {}` 配置远程节点列表。下面说明条目语法、持久化与恢复机制，以及支持的订阅正文格式。

## `subscription {}` 语法

URL 写在条目行上。要给单个订阅覆盖下载设置，可以在带引号的 URL 后面追加一个块，每行一个 key：

```dae
subscription {
    primary: 'https://example.com/sub'
    'https://example.com/no_tag_link'
    detailed: 'https://example.org/sub' {
        ua: 'honk/1.0'
        interval: 6h
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
| `cache` | `false` 表示该订阅的正文不写入订阅存储。 | 开启 |
| `route` | 指定拉取出口，见下文。 | `routing` |

没设置的选项先取 `assets.subscription` 的默认值，出口则取 `assets.route`，再取内置默认值。见 [Assets 配置参考](./assets.md)。

`interval` 取整数秒，可以不带单位，也可以带小写的 `s`、`m` 或 `h` 后缀；`ms` 表示毫秒，会向上取整到秒。`d`、`1h30m` 这类组合值，以及 `0.5s` 这类小数都无效。值无效时产生 warning，并把 `interval` 设为 `0`，也就是关闭定期刷新和失败重试，不会回退到继承来的值。

`cache` 接受 `true`、`yes`、`1`、`on`、`false`、`no`、`0` 和 `off`，不区分大小写。值无效时产生 warning，并把 `cache` 设为 `true`。

`ua: ''` 会把继承来的 `assets.subscription.ua` 重置为内置的 `honk/<version>`，不会删掉 `User-Agent` header。`ua` 不是合法的 HTTP header 值时，拉取失败。

两种旧写法仍可解析，且不产生 warning：

| 写法 | 示例 |
| --- | --- |
| 带引号的 URL 后追加 `(UA)` | `compatible: 'https://example.net/sub'(honk/1.0 like)` |
| URL 写在块内 | `detailed: { url: '…' ua: '…' }` |

只有把 URL 写在块里的写法接受 `download_detour`，作为 `route` 的别名。两个都设置会产生 `conflicting-subscription-route` 错误。URL 写在条目行上时，`download_detour` 是未知 key，会触发 warning 并被忽略。下文的后缀规则和紧接注释规则只适用于 `(UA)` 写法。

标签可以省略。标签和 URL 都能用成对的单引号或双引号。

| 条目形式 | 标签解析规则 |
| --- | --- |
| 裸条目 | 第一个 `:` 之前的文本是标签，除非这个冒号属于 `://`。URL 里后面的冒号不再拆出标签。 |
| 带引号的标签后接 `:` | 显式标签。 |
| 没有显式标签的带引号 URL | 去掉外层引号后，按首个冒号规则处理。`'paid:https://example.com/sub'` 的标签是 `paid`；`'https://example.com/sub'` 没有标签。 |

整体加引号的 `'paid:https://example.com/sub'` 会产生 `legacy-embedded-tag` warning，应改写成 `paid: 'https://example.com/sub'`。

`(UA)` 后缀要求 URL 带引号，避免和裸 URL 里的括号混淆。两种形式都保留 `sub_type: simple`，自动识别下文支持的正文格式。

解析器先处理链接后缀，再规范化引号里的标签。
`'paid:https://example.com/sub'(agent)` 和 `'paid:https://example.com/sub'#note`
都保留标签 `paid`。诊断里的条目序号按源顺序计算，块形式和行内声明一样，被跳过的
条目也占一个序号。

条目以引号开头时，只有紧接结束引号后的冒号才算显式标签，中间可以有空白。未加引号
的 User-Agent，或紧贴链接的注释后缀里的冒号，都仍算后缀数据：
`'https://example.com/sub'(agent:1)` 依然是不带标签的条目。

不带标签的条目用 URL 的主机名作名称，`'https://example.com/sub'` 的名称就是 `example.com`。解析不出主机名时，名称留空，配置校验会拒绝该条目。校验不要求名称唯一：显式标签 `example.com` 和同一主机上不带标签的 URL 都匹配 `subtag(example.com)`，这个筛选条件会选中两个订阅的节点。按主机名生成名称只在 dae 里适用；JSON、YAML 和 TOML 仍要求提供 `name`。

不带标签且不含 `://` 的文本，honk 会直接忽略。带显式标签的条目仍要过配置校验：名称必须非空，URL 必须用 HTTP(S)。`file://`、`http-file://` 和 `https-file://` 仍不受支持。

在条目行里，成对引号之外的 `#` 只要位于语句开头，或者紧跟 ASCII 空格、制表符，就开始注释。裸 URL 里紧贴前文的 `#` 仍是数据，前一个字符是括号也一样，例如 `https://example.com/sub?filter=(hk)#token`。User-Agent 里如果有前面带空格的 `#`，要给 UA 加引号，写成 `'https://example.com/sub'('agent # build')`，否则注释会把这段后缀截断。

URL 带引号时，紧贴结束引号或完整 `(UA)` 后缀的 `#` 会被当作注释接受，并在该字节处产生 `legacy-glued-hash` warning，提示在注释前加空白。`'http://q'#c` 和 `'http://q'(ua)#c` 都保留 URL `http://q`，只有后者设置 UA `ua`。成对引号里的括号不计入嵌套深度。后缀内部紧贴前文的 `#` 仍是 UA 数据，例如 `(Mozilla/5.0 (X11; (Linux)#build))` 里的 `#`。其他尾随文本会让 honk 跳过该条目，并产生 `trailing-entry-text` 或 `legacy-ua-boundary` 诊断，例如 `(ua)(x)` 或 `(agent) junk`。

这种紧贴尾部的兼容截断发生在块结构识别之后，不算词法注释。`sub: 'http://q'(ua)# }` 里独立的 `}` 仍会关闭订阅块，后面的条目就会落到块外。应写成 `(ua) # }`，让花括号变成注释数据。

引号错误和块结构规则见[方言参考](./dialect.md)。`route` 为空时，所有构建都跟随路由。

## 内部模型

| 字段 | 类型 | 默认值 | 可在 dae 中设置 | 含义 |
| --- | --- | --- | --- | --- |
| `id` | UUID | 随机 UUID | 否 | 运行时订阅身份。SIGHUP 时，如果拉取身份与已有订阅匹配，就保留这个值；拉取身份由 URL、配置的 `ua` 和 header 组成。结构化配置设置 `id` 时，值不能为 nil，并且要在所有条目中唯一。 |
| `name` | string | `""` | 是，作为标签；省略时取 URL 主机名 | 显示标签，也是代理组 `subtag(...)` 过滤条件和 DNS `subtag(...)` 规则用的值。 |
| `url` | string | `""` | 是 | HTTP(S) 拉取 URL。 |
| `sub_type` | enum | `simple` | 否 | 正文解析器：`simple`、`clash`、`sip008` 或 `custom`。 |
| `update_interval` | u64 | `86400` | 是，对应 `interval` | 定期刷新间隔，单位为秒；`0` 禁用定期刷新。 |
| `user_agent` | string 或 null | null | 是，对应 `ua` | 可选的 `User-Agent` 覆盖值；为 null 或空时发送 `honk/<version>`。 |
| `headers` | `{key,value}[]` | `[]` | 否 | 按顺序发送的额外请求 header；同名 header 逐条发送。header 名称或值无效时，拉取失败。 |
| `download_detour` | string | `""` | 是，对应 `route` | 拉取的出口。空值或 `routing` 按路由规则处理，`direct` 直连主机，组名表示始终经过该组。未知组在校验时被拒绝。 |
| `enabled` | bool | `true` | 否 | 禁用的订阅不恢复、不拉取、不刷新。 |
| `cache` | bool | `true` | 是，对应 `cache` | `global.store_subscribe` 启用时，保存拉取到的正文，供离线启动恢复。设为 `false` 时既不保存也不恢复，维护任务会删掉此前保存的正文。 |
| `last_updated` | datetime 或 null | null | 否 | 模型元数据；当前 core 运行时不会更新该字段。 |
| `node_count` | u32 | `0` | 否 | 模型元数据；当前 core 运行时不会更新该字段。 |
| `created_at` | datetime | 构造时间 | 否 | 模型构造时间。 |

正文解析器按下面的规则选择：

| `sub_type` | 解析行为 |
| --- | --- |
| `simple` | 自动识别分享链接列表、Clash YAML/JSON、SIP008、sing-box JSON/YAML 和受支持的客户端记录。 |
| `clash` | 带顶层 `proxies` 序列的 YAML 或 JSON。 |
| `sip008` | SIP008 `servers` 对象或裸服务器数组；不是分享链接列表。 |
| `custom` | 与 `simple` 使用相同的格式识别。 |

`honk-tool sub` 对下载的正文和本地文件使用同一个解析器。

## 拉取、持久化与恢复

`global.store_subscribe` 默认是 `true`。启用后，运行时打开私有订阅存储，并立即拉取每个已启用的订阅。请求默认用 `honk/<version>`，可以用 `user_agent` 覆盖。`update_interval` 非零时，运行时安排后续刷新。

| 属性 | 当前行为 |
| --- | --- |
| 位置 | 状态数据库 `<data_dir>/state/honk.db` 里的 `subscription_body` 表。文件权限 0600，目录 0700，见 [API 参考](./api.md#配置数据库--store-db)。`data_dir` 默认是 `/var/lib/honk`。 |
| Key | 对带长度边界的 URL、配置里的 user agent 覆盖值，以及有序的 header key/value 对计算 SHA-256，再用 URL-safe Base64 编码并加上 `.sub`。user agent 覆盖值未设置或为空时，按空值参与计算。版本化的默认请求 UA 不参与计算，所以默认订阅升级后仍能沿用已存正文。请求身份不会以明文暴露。 |
| 写入边界 | HTTP 请求成功且正文通过导入校验后，honk 在一个事务里保存完整的原始响应，被拒绝的条目也算在内。 |
| 容量限制 | 单个正文最多 8 MiB，全部正文合计最多 32 MiB。写入会让总量超过 32 MiB 时，honk 先删除已停用订阅的正文；仍然超出就拒绝写入，保留原正文，并在本次拉取中报告 `subscription-store-write-failed`。订阅连续两次维护都没启用时，honk 删掉它的正文；维护每 60 秒一次。启动时 `store_subscribe: false`，但因 `cache_file`、`password_auth` 或 `--store db` 仍打开了状态数据库时，honk 会清空该表。 |
| 从 `.sub` 升级 | 取得实例锁后，honk 导入符合条件的旧正文，步骤见下文。 |
| 重定向 | 最多 5 跳。从 `https` 重定向到其他 scheme，本次拉取失败。重定向到 loopback、私有、链路本地或未指定的字面地址，也同样失败，除非配置的 URL 自己就用了该地址。解析到这类地址的主机名不在检查范围内。 |
| 正文大小 | 最多 8 MiB，在读取过程中判定，不等整个正文缓冲完。 |

启动时，honk 取得实例锁，然后按下面的步骤导入旧 `.sub` 存储：

1. 依次检查 `<data_dir>/.sub`、`/var/share/honk/.sub`、`./.sub`，选第一个私有旧存储。
2. 复制已启用订阅的正文；状态数据库里已有的正文优先。
3. 删掉已复制的 `*.sub`，以及该目录里所有 `.*.tmp` 文件。目录空了就一并删掉，其他旧位置不动。

无法读取、超过 8 MiB，或会让总量超过 32 MiB 的正文留在原处，honk 记一条 warning。已停用订阅的正文也保留。以后启动时启用该订阅，honk 可以直接导入正文，不用拉取。

导入前旧进程已经退出，所以它最后写入的正文和其他正文一样会被复制。此后旧版本再启动时，只能找到保留下来的正文，其余订阅会重新拉取。

订阅正文及其产生的节点都属于运行时状态，不会写回 dae 配置。

除非条目的 `route` 或 `assets.route` 另有指定，订阅拉取默认走路由，和 honk 发起的其他下载一样。

| 出口 | 行为 |
| --- | --- |
| 空值或 `routing` | 每个 URL 都按流量路由规则处理，重定向也不例外。规则可以选择节点、组、`direct` 或 `block`。 |
| 组名 | 强制经过该组。 |
| `direct` | 使用引导解析器和 bypass mark，不经过路由。沿用原来的直连传输。 |

经路由的请求与 Geo 数据、外部 UI 下载共用路由决策和隧道，并保留同样的 `User-Agent`、header 和下载限制：

| 限制 | 行为 |
| --- | --- |
| 超时与正文大小 | 30 秒；最多 8 MiB。 |
| 重定向状态码 | 仅跟随 301、302、303、307、308，最多 5 次。 |
| 重定向目标 | 不允许从 HTTPS 转到 HTTP，也不允许从公网地址转到私有字面地址。前一张表的重定向限制同样适用。 |
| URL userinfo | URL 中的 userinfo 以基本认证发送。 |
| 协议、主机或端口变化 | 协议、主机或端口一变，honk 就去掉 `Authorization`、`Cookie`、`Cookie2`、`WWW-Authenticate`、`Proxy-Authorization` 和配置的 `Host`。 |
| Referer | Referer 设为上一跳 URL，并去掉 userinfo 和 fragment。 |

未启用 `native-api` 的构建使用相同的订阅拉取路由规则。

订阅可能经由它自己提供的节点拉取，比如规则把订阅 URL 发往一个只含该订阅节点的组。全新安装时这些节点还不存在。honk 不会退回直连：所选路由没有可用节点时，拉取失败，错误信息给出订阅名和出站，说明这条路由暂时承载不了这次下载，并建议为该订阅设置 `route: direct`。原生 API 的 provider 状态里 `last_error.code` 是 `route_unavailable`。这期间，从已存正文恢复的节点照常生效。

启动时先恢复节点，再刷新订阅：

1. 联网刷新前先解析已存正文。有效正文会立刻提供活动节点；缺失、无效或空的正文，honk 直接忽略。
2. 没能有效恢复的 `direct` 订阅，共用五秒的首次拉取等待，直到拉取完成或等待期满。有效恢复的订阅不参与等待，但仍会在后台刷新。
3. 启动阶段的订阅处理完成后，路由就绪，再拉取经路由的订阅。

之后通过校验的刷新替换 SQLite 里的正文行，不再写旧存储文件。

恢复或首次拉取的正文里，如果某个节点 ID 已被内联节点占用，启动配置会排除该订阅，而不是让启动失败；运行时发布也会拒绝这种冲突。如果节点 ID 已经由其他订阅发布，honk 会从本订阅里去掉这个节点并记一条 warning，其余节点照常发布，该节点仍归先发布的订阅。正文仍然可以替换该订阅自己的节点。

原生 API 的 provider 会把 `last_error.code` 报为 `publication_rejected`，把 `last_error.details.diagnostic_code` 报为 `duplicate-node-id`。发布这样被拒绝后，已恢复的正文仍算已恢复：该订阅不参与首次拉取等待，后台刷新照常运行，并重复这项检查。

SIGHUP 时，拉取身份相同的订阅保留运行时 ID；拉取身份由 URL、配置的 `ua` 和 header 组成。reload 沿用仍处于启用状态的订阅的活动节点，提交重建后的配置，然后立刻开始后台刷新。即使某个订阅没有存活节点，reload 也不会读已存正文；只有启动时才从存储恢复正文。

拉取失败时，honk 会保留可用的运行时状态：

- HTTP 错误、UTF-8 编码错误、解析错误，或者没有可用节点，都不会发布替换节点，也不会写入存储，所以活动节点和上一次有效正文都还在。通过校验的正文按原始字节保存，不修复编码。
- 拉取失败后，honk 先等待 30 秒和 `interval` 中较小的那个，之后每次翻倍，上限是 10 分钟和 `interval` 中较小的那个；`interval: 0` 关闭自动重试。发布成功或被拒绝都会结束已有的退避，恢复正常刷新间隔。
- 解析成功后，持久化写入失败算非致命错误。新解析出的节点仍会返回，供发布使用；原子写入不会留下不完整的正文。下次启动时，可以从磁盘恢复任何一份完整有效的正文。
- 不支持或格式错误的节点逐个跳过。共用节点构建器给出的 warning 带从 1 开始的条目索引和固定的拒绝原因。流传输规范化错误还会带上规范字段，例如 `proxies[1].xhttp` 或 `outbounds[1].ws_headers`，不暴露提交的 header 名称、值或凭据。只有剩余可用节点为零时，整个正文才算失败；空结果绝不会清空上一 generation 的节点。

上一次有效正文指通过当前导入规则校验的正文，不是最后一次成功发布的运行时配置。部分条目无效、但还剩一个可用节点的正文，可以替换存储；全部条目无效的不行。恢复正文时，honk 按当前规则重新解析，所以旧版本保存的正文可能被拒绝。写入成功后，如果节点集合校验或发布失败，活动配置不变，但磁盘上可能已经存了新正文。磁盘和活动配置不在同一个事务里。

SIGHUP 会拒绝修改 `global.store_subscribe`，因为该设置需要重启。

## 首次启动时订阅 URL 被阻断

订阅 URL 被阻断，或它的域名被 DNS 污染时，可以先添加一个可达的静态代理节点，再把
订阅的 `route` 指向只含这个节点的组。该组在首次启动时就能用，不依赖任何订阅提供
的节点。示例里的 SOCKS5 地址要换成能访问 provider 的代理地址，订阅 URL 换成实际
地址。

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

所有被接受的节点都会获得订阅 ID。派生出的节点 ID 重复时，保留第一个可用条目；被拒绝的条目不占身份。后续重复条目的诊断会同时记下两个原始索引。数组索引从 1 开始，在规范化前确定；URI 和记录索引用物理行号，空行和注释也算在内。解码后的 Base64 带一个指向原始正文的子来源，不虚构编码字节偏移。导入完整客户端配置时只取节点，其中的 DNS、路由、组和远程订阅配置都不导入。

规范化后的条目逐个进入 admission 流程，不保留一个和正文条目数一样大的中间结果列表。每份正文最多保留 128 条非终止诊断；超出时追加一条 `subscription-diagnostics-truncated` 摘要，记下省略了多少条。导致正文失败的终止错误单独保留。调用方原有的诊断不变，也不占这个限额。结构化导入、URI 导入、记录导入都用同一限额，Base64 解码和持久化正文恢复也不例外；达到限额不会中断有效节点的 admission，也不改变重复节点保留第一个可用条目的规则。

`simple` 和 `custom` 先尝试标准或 URL-safe 的 Base64 解码，所以 Base64 编码能承载任何可识别的格式，不限于分享链接列表。`clash` 和 `sip008` 要求正文不编码。

| 诊断代码 | 结果 |
| --- | --- |
| `malformed-subscription-entry` | 跳过字段无效或语法错误的条目。 |
| `unsupported-subscription-entry` | 跳过依赖不支持的协议或 feature 的条目。 |
| `duplicate-subscription-entry` | 跳过节点身份重复的后续条目。 |
| `subscription-profile-entry` | 忽略配置文件中的非代理内容。 |
| `invalid-subscription-encoding` | 拒绝不是 UTF-8 的正文，包括 Base64 解码后的内容。 |
| `invalid-subscription-body` | 拒绝无法解析的结构化正文。 |
| `empty-subscription-body` | 拒绝没有可用节点的正文。 |

Clash、SIP008 和 sing-box 的凭据标量保留字符串的原始字节，原生有限数则转成来源格式的规范十进制文本。缺失或 null 表示未提供。布尔值、列表、映射和非有限数会让条目被拒绝。有效的别名掩盖不了已提供的无效凭据。数字 UUID 仍然过不了 UUID 校验；空密码仍要满足对应协议的要求。

### 分享链接列表

正文可以是纯文本，也可以用标准或 URL-safe Base64 编码；填充可以省略，编码块之间允许 ASCII 空白。原始正文和解码后的正文都能以 UTF-8 BOM 开头。每行一个分享链接：

```text
# blank lines and comments are ignored
socks5://user:password@127.0.0.1:1080#local
vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls#edge
```

空行、注释和 Shadowrocket 的 `REMARKS=`、`STATUS=` 元信息行，honk 会忽略，也不产生节点 warning。其余每行交给 `Node::from_share_link` 解析；不支持或格式错误的行会跳过并记 warning。honk 不执行代理插件，所以带非空插件值的分享链接也跳过。正文里没有一个受支持的节点 URI 时，包括只有元信息的正文，honk 拒绝整个正文。规范的分享链接字段和协议见[节点参考](./nodes.md)。

### Clash YAML 与 JSON

完整配置或 provider 正文必须包含顶层 `proxies` 序列。缺少受支持的 `type`、服务器地址、有效非零端口或必需凭据的条目，honk 会跳过。端口可以是整数，也可以是数字字符串。JSON 用原生解码，支持显示名称里的 UTF-16 代理对转义。

可接受的 `type` 有 `socks5`、`ss`/`shadowsocks`、`trojan`、`vmess`、`vless`、`hysteria2`/`hysteria`、`tuic`、`juicity` 和 `anytls`。无关的客户端元信息，honk 会忽略；不支持的线协议传输、代理插件，以及相互矛盾的安全设置，也不会被悄悄替换。

#### 通用代理字段

| Clash 字段 | 内部字段 | 规则 |
| --- | --- | --- |
| `name` | `name` | 默认为 `<type>-<server>:<port>`。 |
| `server`, `port` | `host`, `port`, `address` | 必需的地址和非零 `u16` 端口；接受数字形式的端口字符串。 |
| `username` | `username` | 可选 string。 |
| `password` | `password` | 可选 string；VLESS 按下文列出的优先级取值。 |
| `cipher` | `encryption` | 可选加密算法；VLESS 的字段优先级见下文。 |
| `plugin`, `plugin-opts`, `plugin_opts` | — | 不支持。任一字段非空时，honk 在发布节点前跳过该条目，映射类型的 options 也拒绝。 |
| `network` | `transport` 或数据包网络 capability | Trojan/VMess/VLESS 用流传输，可取 `tcp`、`ws`、`grpc`、`xhttp`；AnyTLS 用数据包网络 capability。 |
| `tls` | `tls` | 可选 bool。Trojan、AnyTLS、Hysteria2、TUIC 和 Juicity 默认启用 TLS，显式关闭会被拒绝。 |
| `servername`、`server-name`、`sni` | `sni` | 空值或纯空白名称视为未指定；非空别名必须逐字节一致。 |
| `skip-cert-verify`、`skip_cert_verify`、`insecure` | `skip_cert_verify` | 须使用原生布尔值；已提供的别名必须一致。 |
| `fingerprint`、`pin-sha256`、`pin_sha256` | `tls_pin_sha256` | 叶证书 SHA-256 固定值，十六进制，忽略冒号和空白；它取代 PKI 与主机名校验。所有 TLS 协议都会导入 Clash 的 `fingerprint`，不带 TLS 的协议则跳过该条目。已提供的别名必须一致。 |
| `alpn` | `tls_alpn` | raw TCP TLS 的有序字符串列表或逗号分隔字符串；XHTTP 只接受 H2，省略时规范化为 `["h2"]`。QUIC 保留下文的协议专属规则。 |
| `disable-sni`, `disable_sni` | — | `true` 时跳过该条目；`false` 可以接受。 |

#### 协议专属选项

支持的拼写别名会在派生节点身份前规范化。

| 协议 | 导入的选项 |
| --- | --- |
| Hysteria2 | `password`/`auth`，以及 `obfs: salamander` 与 `obfs-password`。支持上传/下载带宽、`ports`/`mport` 跳跃端口范围、`hop-interval`/`mhop`、接收窗口、MTU 与 MTU 发现设置。 |
| TUIC | UUID/密码、拥塞控制、ALPN、接收窗口、MTU。 |
| AnyTLS | `idle-session-check-interval`、`idle-session-timeout`、`min-idle-session`。 |

显式关闭的 feature block 按禁用处理，honk 不会把它当成已启用的不支持的 feature。原生支持 UDP 的协议接受 `udp: true`；VMess 没有 UDP 路径，honk 忽略这个声明，节点仍按 TCP 导入。节点模型保留不了显式 UDP 限制时，honk 拒绝导入。

TUIC 允许省略密码或使用空密码。Hysteria2 和 Juicity 接受与运行时固定选择一致的 `h3` ALPN。

Juicity 的流接收窗口和连接接收窗口初始都是 8 MiB，自适应流控可以分别把它们调高到最多 32 MiB。导入时的初始窗口字段接受缺失、`0` 或 `8388608`，其他覆盖值拒绝。

AnyTLS 按 `anytls-network`、适用的 `network`、`udp` 的顺序，一次性解析数据包 capability 声明。空文本或 null 不提供网络声明。网络字符串用逗号分隔 `tcp` 和 `udp`。别名按是否允许 UDP 比较，所以 `udp` 与 `tcp,udp` 一致，`tcp` 与 `udp: true` 冲突。即使已有有效别名，`quic` 这类未知值仍会让条目被拒绝。等价的声明保留第一个显式网络字段的写法；只给布尔值时，才生成 `tcp` 或 `tcp,udp`。

以下 TCP TLS ALPN 规则适用于结构化订阅导入和扁平字段 `tls_alpn`。分享链接的 ALPN 兼容行为不变。

| 输入或限制 | 行为 |
| --- | --- |
| 列表成员 | 原样保留字节和顺序。每个名称占 1–255 个 UTF-8 字节。 |
| 带长度前缀的完整列表 | 最多 65,533 字节。完整 ClientHello 还受 TLS 库的大小限制。 |
| 导入的 `alpn` 缺失、为 null 或为空 | 保留原有 TLS 配置方案默认值及节点 ID。 |
| 扁平 `tls_alpn` | 接受省略或字符串数组，不接受 null。 |
| 非空覆盖值 | 参与节点身份派生。与关闭 TLS、REALITY、WebSocket 或 gRPC 组合时，honk 会拒绝，不会直接忽略。 |
| Chrome ALPS | 仅在实际 ALPN 列表包含 `h2` 时发送。 |

XHTTP 不受裸 TCP ALPN 规则限制：它始终使用 H2，包括 REALITY 和显式明文 H2。Mihomo 接受 `network: xhttp` 或输入别名 `splithttp`。

| `xhttp-opts` 字段 | 导入行为 |
| --- | --- |
| `path`、`host`、`mode`、`headers`、`x-padding-bytes`、`no-grpc-header`、`sc-max-each-post-bytes`、`sc-min-posts-interval-ms` | 接受。 |
| `no-sse-header`、`sc-max-buffered-posts`、`sc-stream-up-server-secs` | 仅服务端使用，检查类型后丢弃。 |
| `reuse-settings`、`xmux` | 按 Xray 语义遵循 URI `xmux` 规则。Mihomo 则只要存在 `reuse-settings` 就启用自己的复用管理器。 |
| `download-settings` | 须为 Xray StreamConfig 映射，见下文。 |

`download-settings` 接受面板导出的 Xray 结构。字段有 `address`、`port`、`network`、`security`、`alpn`、`tlsSettings`、`xhttpSettings`。还可以包含扁平的 `x-padding-bytes`、只在上传端使用的 `no-grpc-header`/`sc-*` key，以及默认值的 `reuse-settings`/`xmux`。它的语义与 URI 的 `downloadSettings` 相同，所以同一订阅用两种方式导出会得到相同的节点 ID。

Mihomo 自身有继承语义的 key，honk 会拒绝，例如 `server`、`servername`、`tls`、`skip-cert-verify`。这一点和 mihomo 有意不同：mihomo 忽略 Xray 结构的 key，把 GET 发往上传服务器。规范的默认值、范围和 header 限制见 [XHTTP 节点参考](./nodes.md#h2-上的-xhttp)。

其他不支持的参数，包括放在别的字段位置和填充混淆设置，只要出现就会让条目被拒绝，值为 null、空值或 false 也一样。其他有效节点照常保留。解析 URI 或 VMess extra JSON 时，honk 在构造映射前就拒绝重复成员。

#### VLESS transport 与 REALITY

VLESS 字段会在派生节点身份前应用：

| Clash 输入 | 映射 |
| --- | --- |
| `uuid`, then `password` | 凭据；`uuid` 优先，`password` 作为回退。 |
| `encryption`, then `cipher` | VLESS Encryption；`encryption` 优先。 |
| `flow` | 空值或纯空白视为未指定；否则必须为 `xtls-rprx-vision` 或 `xtls-rprx-vision-udp443`。 |
| `network` | 流传输；数据包权限仍由独立的 `udp` 声明控制。 |
| `reality-opts.public-key` | 启用 REALITY TLS carrier；必须是非空 string。 |
| `reality-opts.short-id` | 可选 REALITY short ID。 |
| `reality-opts.spider-x` | REALITY spider path；缺失或为空时使用 `/`。 |
| `ws-opts.path` | WebSocket path；回退到扁平别名 `ws-path`。 |
| `ws-opts.headers.Host` | WebSocket Host header。key 匹配不区分大小写，第一个非空白值优先；字符串保留原始字节，有限数字转成文本。无效或空白的 Host 值，honk 忽略。取值依次回退到 scalar `ws-headers`、`ws-host`，只有前面都没有可用值时才看下一项。 |
| `ws-opts.headers.<name>` | 附加的 WebSocket 升级 header，所有支持 WebSocket 的代理共用；以小写名称导入，例如 `User-Agent`。null 值忽略，非 scalar 值会让条目被丢弃；保留的握手 header 会按[节点字段约定](./nodes.md#节点字段)拒绝该条目。 |
| `grpc-opts.grpc-service-name` | gRPC service name；回退到 `grpc-service`。 |
| `client-fingerprint` | 有意不导入。TLS 指纹由进程级 `global.tls_implementation` 与 `global.utls_imitate` 选择。 |

嵌套的 WS/gRPC 值优先于对应的扁平别名。启用的 `reality-opts` 必须是映射，并且含非空 `public-key`；无效的启用声明绝不会降级成普通 TLS。空 block 或显式禁用的 feature block，honk 直接忽略。导入的 REALITY 和规范分享链接行为一致：只用 TLS 1.3，key share 先 hybrid 后 classic，单个 ClientHello 且 fail-closed；见[节点参考](./nodes.md#vless-udp-and-multiplexing)。

#### VLESS UDP 与多路复用

导入的默认值取决于来源格式，而且并不都等于 honk 规范的 `packetEncoding=auto` 默认值。

| Clash 表示 | Packet 回退 | Multiplex | UDP 权限 |
| --- | --- | --- | --- |
| 没有数据包声明且没有启用的封装 | `auto` | off | 关闭 |
| 只有空/null 数据包编码 | `auto` | off | 关闭 |
| `packet-encoding: none`/`legacy`，或 `xudp: false` | 原生 | off | 除非 `udp: false`，否则开启 |
| `packet-encoding: xudp`，或 `xudp: true` | Single XUDP | off | 除非 `udp: false`，否则开启 |
| 未声明其他数据包设置时的 `udp: true` | Single XUDP | off | 开启 |
| `udp-over-tcp: true`，或 version 为 `0`/`2` 的启用 object | UoT v2 | off | 除非 `udp: false`，否则开启 |
| 启用 `smux`/`multiplex`，并指定 `protocol: h2mux` 或显式 `padding` | auto，被封装接管时不生效 | H2MUX | 除非 `udp: false`，否则开启 |
| `mux: { enabled: true, ... }` | `auto`，除非显式数据包编码还能通过 protocol 回退或 `skip` 生效 | Xray Mux.Cool | 除非 `udp: false`，否则开启 |

启用 H2MUX 时，必须设置 `protocol: h2mux` 或显式的 `padding`。`padding` 默认是 `false`，设为 `true` 选择带填充的 H2MUX。`only-tcp: true`、启用的 Brutal，以及非零的 `max-connections`、`min-streams` 或 `max-streams`，都会让条目被拒绝。启用的 H2MUX 与 Xray mux、UoT 互斥，启用的 UoT 也与 Xray mux 互斥。显式 XUDP 与 H2MUX 或 UoT 冲突。封装接管后，原生或 auto 声明不生效。

启用的 Clash `mux` 块只把 `enabled`、有符号 `i16` 的 `concurrency` 和 `xudpConcurrency`，以及 `xudpProxyUDP443` 当作有效设置。未生效的额外设置直接忽略。

| 并发值 | TCP `concurrency` | `xudpConcurrency` |
| --- | --- | --- |
| 负值 | 关闭 TCP 多路复用。 | 使用数据包回退路径。 |
| 零 | 每条 TCP carrier 允许同时承载 8 个逻辑 child。 | 共用已启用的 TCP 池和它的逐连接并发值。TCP 多路复用关闭时，走数据包回退路径。 |
| 正值 | 设置每条 carrier 的逻辑 child 并发上限，最多 128。 | 建立独立 UDP 池，按该值设置每条 carrier 的逻辑 child 并发上限，最多 128。 |

并发值不表示物理 carrier 数量。UDP/443 策略默认是 `allow`，也接受 `skip` 或 `reject`。优先级见[节点参考](./nodes.md#vless-udp-and-multiplexing)。

`udp: false` 单独关闭数据包拨号，仍然符合条件的裸 TCP 路径不受影响。遇到下面这些情况，honk 也会拒绝该 VLESS Clash 条目：别名冲突、重复的 XUDP 表示、启用的 packet-address 模式、不支持的数据包编码、不支持的 UoT version，以及启用的 Xray mux 里无效或不支持的设置。

规范 VLESS 分享链接用精确的 `packetEncoding=auto|none|xudp|uot-v2`、`mux=off|h2mux|xray` 和 `udp=0|1` 查询参数。已移除的 `vless_mode` 查询参数，以及 `smux`、`udp-over-tcp`、`packet-encoding` 这类含义不明确的第三方拼写，honk 一律拒绝，不猜测语义。

### SIP008 与 sing-box JSON 或 YAML

SIP008 和 sing-box 正文可以是 JSON，也可以是等价的 YAML。SIP008 的 `{"servers":[...]}` 封装和裸服务器数组会导入 Shadowsocks 的 `server`、`server_port`、`method`、`password` 和 `remarks`。封装里的 `version` 必须是整数 `1` 或 `2`。空的插件字段不会导致拒绝；有效的插件配置仍不受支持。

sing-box 配置从 `outbounds` 导入受支持的条目：

- 代理节点：Shadowsocks、SOCKS5、VMess、VLESS、Trojan、Hysteria2、TUIC、Juicity、AnyTLS。
- 结构性条目，不属于代理节点：`selector`、`urltest`、`direct`、`block`、`dns`。

TLS/SNI、REALITY、WebSocket/gRPC 升级 header、VLESS 数据包选项，以及受支持的协议调优，都会经过共用的节点构建器规范化。`Host` 以外的升级 header 同样包括在内。

没设置 `tls` 或 `tls.enabled` 时，sing-box 的 TLS 处于关闭状态，所以没有 `tls.enabled: true` 的 Trojan、Hysteria2、TUIC、Juicity 和 AnyTLS 条目，honk 会跳过。

| 来源特有情况 | 导入行为 |
| --- | --- |
| WebSocket `transport.headers` | `Host` 保留为独立的 string 字段，重复的 Host 别名会被拒绝。其他 string 值原样保留，空字符串也算；null 忽略，其他类型会让条目被拒绝。名称和值遵循[节点 header 约定](./nodes.md#节点字段)。 |
| VLESS 未启用 H2MUX/UoT 封装，且没有显式 `packet_encoding` 选择其他路径 | 使用 Single XUDP 并允许 UDP。这是 sing-box 导入的默认值，不是 Auto 的全局含义。 |
| gRPC 服务名为空或省略 | 保留 sing-box 的空服务名，不使用 honk 的 `GunService` 默认值。 |
| Hysteria2 提供 `server_ports`，未提供 `server_port` | 以第一个跳跃端口作为名义 endpoint。 |
| 节点级 uTLS 指纹提示 | 不覆盖 honk 的进程级 TLS 选择。 |

不支持的链式代理、wire feature 或认证要求，honk 会报错，不会直接忽略。

在 sing-box 输入里，`network` 表示数据包网络 capability，不是流传输类型；流传输方式由 `transport.type` 选择。`h2` 这类不支持的名称，honk 会拒绝，不会把它当成裸 TCP。

官方 sing-box 没有原生 XHTTP 传输。导入器明确拒绝 `transport.type: xhttp` 和 `splithttp`，也不会把旧的 `http`、H2、QUIC 或第三方 fork 解释成 XHTTP。Client-record 里的 XHTTP 传输同样不受支持。

在支持数据包限制的 sing-box 映射里，`network: udp` 和 `network: tcp,udp` 允许 UDP，`network: tcp` 关闭 UDP。这些值不会反过来禁止 TCP。`network` 和 VLESS 回退编码、H2MUX/UoT carrier 的选择互不影响。

显式写出的 sing-box 原生 VLESS UDP，即 `packet_encoding: ""`，映射为原生路径。启用 H2MUX 或 UoT v2 后，数据包路径由封装承载，即使来源同时显式指定了 `packet_encoding` 也一样，包括 `"xudp"`。禁用封装不会关掉 sing-box 的 Single-XUDP 默认值。sing-box 多路复用导入仍只支持 H2MUX，不会合成 Xray Mux.Cool 控制项。

### Surge、Surfboard、Loon 与 Quantumult X

导入器接受 Surge/Surfboard/Loon 的具名逗号分隔记录，也接受 Quantumult X 的 `protocol=endpoint,...,tag=name` 记录。完整配置用 `[Proxy]` 或 `[server_local]`；其他配置段 honk 忽略。带引号的名称和密码可以包含逗号、等号、转义引号，以及有意保留的首尾空格。

显式凭据和加密方法别名在转换前必须一致。具名记录只有在对应的具名值缺失时，才使用位置参数；有效的显式值不会因为位置参数不同而冲突。Quantumult X 不用位置参数回退。显式空凭据也参与别名比较，不会触发回退。

允许为空的可选记录凭据会逐字节保留空字符串和带引号的空白，包括 SOCKS 用户名和密码、Hysteria2 认证值、TUIC 密码。显式空值仍优先于位置参数；要求非空凭据的协议仍然拒绝空值。

honk 在赋值前比较记录里的 `transport`/`network` 流传输声明，重复 key 也比。空文本和 `tcp` 都表示裸 TCP。声明冲突或含不支持的传输方式时，honk 拒绝该条目。

AnyTLS 记录里的 `network` 表示数据包 capability，不是流传输方式。honk 在选择前校验所有重复的 `network`、`udp` 和 `udp-relay` 值。等价声明保留第一个显式网络值的写法；只要有一个值无效或冲突，honk 就拒绝该记录。

VLESS 记录的 `packet-encoding`/`packet_encoding`/`packetencoding` 值为 `none` 或空时，选择原生 UDP；值为 `xudp` 时选择 Single XUDP。重复别名的值必须一致，显式空赋值也算。`udp`/`udp-relay` 单独控制数据包权限。既没有数据包编码也没有 `udp: true` 时，记录保持 UDP 关闭；只有 `udp: true` 时选择 Single XUDP。记录格式里有效的 `mux` 和 UoT 声明仍不受支持，honk 不会重新解释它们。

受支持的记录把凭据、TLS/SNI、WebSocket/gRPC、REALITY 和已实现的协议选项映射到同一个节点模型。Quantumult X 的 `obfs=wss` 会把 `obfs-host` 同时用作 WebSocket Host 和默认 TLS SNI；显式 TLS 主机名优先。SSR、不支持的插件、混淆和传输方式，honk 直接跳过，不会当成别的协议导入。

Surge 的 `server-cert-fingerprint-sha256` 映射到 honk 的叶证书 pin，两者都替代标准 X.509 验证。`server-cert-verify-name`、客户端证书、`sni=off` 和 Shadow TLS 在 honk 里表达不出来，honk 会拒绝，不会直接忽略，见 [Surge TLS 参考](https://manual.nssurge.com/policies/tls.html)。

honk 在赋值前比较记录里的 `skip-cert-verify`、`allow-insecure`、`insecure`，以及取反后的 `tls-verification`。`tls-verification=false,insecure=true` 算一致；`tls-verification=true,insecure=true` 时，honk 拒绝该条目。记录文本只接受不区分大小写的 `true/yes/1/on` 和 `false/no/0/off`；空文本和 `t/y/f/n` 仍是无效值。证书固定规则的限制不变。

Quantumult X 里有效的 `tls-cert-sha256` / `tls-pubkey-sha256` 固定证书设置，honk 会拒绝：honk 的叶证书 pin 替代 PKI，不能替换一个尚未确认等价的外部验证约定。显式设置 `tls-verification=false` 时，QX 会忽略这两类 pin，导入后保留这种禁用验证的行为。有效的 QX REALITY 会按[官方配置](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf)忽略自定义的 `tls-alpn` 和 session-ticket 设置；普通 TLS 没有这个例外。旧 VMess `aead=false`、启用的 Shadowsocks UoT/SSR、不支持的 TLS ALPN，以及禁用 TLS session 复用，honk 都会拒绝，不会直接忽略。

## 离线解析与探测

`honk-tool sub` 接受需要拉取的订阅 URL，也接受任一种受支持正文格式的本地文件。本地文件不会触发订阅下载，可以离线解析；之后命令仍会执行配置的连通性和延迟探测：

```console
honk-tool sub ./share-links.txt --limit 10
honk-tool sub https://example.com/sub --ua honk-tool
```

传入 `-` 时，从标准输入读一个 HTTP(S) 订阅 URL，不读订阅正文。探测参数和输出见 [CLI 参考](./cli.md)。

## 相关文档

- [节点参考](./nodes.md)
- [组参考](./groups.md)
- [CLI 参考](./cli.md)
