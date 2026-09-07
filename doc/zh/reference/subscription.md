# 订阅参考

本文说明当前 runtime 接受的 `subscription {}` 条目、持久化恢复机制与订阅正文格式。

## `subscription {}` 语法

每个条目支持以下两种形式：

```dae
subscription {
    primary: 'https://example.com/sub'
    compatible: 'https://example.net/sub'(honk/1.0 like)
    detailed: {
        url: 'https://example.org/sub'
        ua: 'honk/1.0'
        interval: '10000s'
    }
}
```

简写 `tag: URL` 使用默认 `honk/<version>` User-Agent；在带引号的 URL 后追加 `(UA)` 即可覆盖。块形式接受 `url`、可选的 `ua` 和可选的 `interval`；`interval` 是 duration，默认 `86400s`，设为 `0` 可禁用定期刷新。

其他情况下 URL 可以使用单引号，也可以不加引号；普通 HTTP(S) URL 必须带 tag，因为解析器按第一个 `:` 分派。`(UA)` 后缀要求 URL 带引号，以免与裸 URL 自身的括号产生歧义。两种形式的 `sub_type` 都保持为 `simple`，会自动识别下文列出的正文格式。

## 内部模型

| 字段 | 类型 | 默认值 | 可在 dae 中设置 | 含义 |
| --- | --- | --- | --- | --- |
| `id` | UUID | 随机 UUID | 否 | runtime 订阅身份；SIGHUP 时，若 fetch 身份（URL + 配置的 `ua` + headers）与已有订阅匹配则保留该值。 |
| `name` | string | `""` | 是，作为 tag | 显示 tag，也是组 `subtag(...)` filter 使用的值。 |
| `url` | string | `""` | 是 | HTTP(S) 拉取 URL。 |
| `sub_type` | enum | `simple` | 否 | 正文解析器：`simple`、`clash`、`sip008` 或 `custom`。 |
| `update_interval` | u64 | `86400` | 是，对应块内 `interval` | 定期刷新间隔，单位为秒；`0` 禁用定期刷新。 |
| `user_agent` | string 或 null | `honk/<version>` | 是，对应 `(UA)` 或块内 `ua` | 可选的 `User-Agent` 覆盖值；未设置时请求标识为 `honk/<version>`。 |
| `headers` | `{key,value}[]` | `[]` | 否 | 有序的额外请求 header。 |
| `enabled` | bool | `true` | 否 | 禁用的订阅不会恢复、拉取或刷新。 |
| `last_updated` | datetime 或 null | null | 否 | 模型元数据；当前 core runtime 不更新它。 |
| `node_count` | u32 | `0` | 否 | 模型元数据；当前 core runtime 不更新它。 |
| `created_at` | datetime | 构造时间 | 否 | 模型构造时间。 |

内部正文选择行为如下：

| `sub_type` | 解析行为 |
| --- | --- |
| `simple` | 自动识别分享链接列表、Clash YAML/JSON、SIP008、sing-box JSON 和受支持的客户端记录。 |
| `clash` | 带顶层 `proxies` sequence 的 YAML 或 JSON。 |
| `sip008` | SIP008 `servers` 对象或裸服务器数组；不是分享链接列表。 |
| `custom` | 与 `simple` 使用相同的格式识别。 |

`honk-tool sub` 的下载正文与本地文件使用同一个解析器。

## 拉取、持久化与恢复

`global.store_subscribe` 默认为 `true`。启用后，runtime 会打开私有订阅存储并立即拉取每个已启用订阅。请求默认使用 `honk/<version>`，可由 `user_agent` 覆盖。非零 `update_interval` 会安排后续刷新。

| 属性 | 当前行为 |
| --- | --- |
| 首选位置 | `<data_dir>/.sub`；`data_dir` 默认值为 `/var/lib/honk`。 |
| 旧位置 | 如果首选存储不存在，依次使用已有的 `/var/share/honk/.sub`（`LEGACY_DATA_DIR`），再使用已有的 `./.sub`。无法打开的旧位置会被跳过；只有所有旧候选均不可用时才创建首选存储。自定义 `data_dir` 也遵循相同顺序。不会自动移动或删除存储；准备迁移时请显式操作。 |
| 权限 | 目录 mode 为 `0700`，文件 mode 为 `0600`。拒绝符号链接形式的存储目录。 |
| 文件名 | 对带长度边界的 URL、配置中的 user agent 覆盖值（未设置或为空时为空）及有序 header key/value 对计算 SHA-256，再用 URL-safe Base64 编码并添加 `.sub`。版本化的默认请求 UA 不参与 key，因此默认订阅升级后仍保留缓存。请求身份不会以明文暴露。 |
| 写入边界 | 只有 HTTP 成功且解析成功后才写入原始响应正文。临时文件完成 sync 后原子 rename，随后对目录执行 sync。 |
| 重定向 | 最多 5 跳。从 `https` 重定向到其他 scheme 会让本次拉取失败；重定向到配置 URL 自身未使用的回环、私有、链路本地或未指定字面地址同样失败。解析到这类地址的主机名不在检测范围内。 |
| 正文大小 | 最多 8 MiB，在读取过程中判定，而不是缓冲完整正文之后。 |

订阅正文及其产生的节点都只属于 runtime 状态；两者都不会写回 dae 配置。

启动时会在开始联网刷新前解析已存正文。有效的已恢复正文会立即提供活动节点，因此该订阅不参与 5 秒首次拉取等待；其联网刷新仍会在后台运行。缺失或无效的已存正文会被忽略，并让该订阅继续参与有界首次拉取等待，直至拉取结束或达到 deadline；后续有效刷新会替换损坏文件。

SIGHUP 时，fetch 身份（URL + 配置的 `ua` + headers）相同的订阅保留 runtime ID。重载会沿用仍处于启用状态的订阅所属活动节点；只有某订阅没有存活节点时才恢复已存正文。随后提交重建后的配置，并立即开始后台刷新。

失败处理会保留可用 runtime，而不会清空它：

- HTTP、解析或没有可用节点的失败不会发布替换节点，也不会写入，因此活动节点与上一次有效正文都会保留。
- 持久化写入在解析成功后失败属于非致命错误：新解析出的节点仍会返回用于发布，而原子写入路径绝不会安装只写了一部分的正文。下次重启因此可以恢复磁盘上保留的任一完整有效正文。
- 不支持或格式错误的节点会逐个跳过。只有没有剩余可用节点时，整个正文才失败；空结果绝不会清空上一代节点。

通过 SIGHUP 修改 `global.store_subscribe` 会因需要重启而被拒绝。

## 订阅正文格式

所有接受的节点都会获得订阅 ID。重复的派生节点 ID 保留第一次出现的节点，即使正文只是重复同一个可用端点也可导入。完整客户端配置只提取节点，不导入其中的 DNS、路由、组或远程 provider 配置。

### 分享链接列表

正文可以是纯文本，或 standard / URL-safe Base64；padding 可以省略，编码块之间允许 ASCII 空白。原始正文与解码正文均接受开头的 UTF-8 BOM。每行包含一个分享链接：

```text
# blank lines and comments are ignored
socks5://user:password@127.0.0.1:1080#local
vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls#edge
```

空行、注释和 Shadowrocket 的 `REMARKS=` / `STATUS=` 元信息行会被忽略，不产生节点警告。其余每行都由 `Node::from_share_link` 解析；不支持或格式错误的行会被跳过并警告。honk 不执行代理插件，因此带有非空插件值的分享链接也会被跳过。若正文没有受支持的节点 URI（包括只有元信息的正文），则拒绝整个正文。规范分享链接字段与协议见[节点参考](./nodes.md)。

### Clash YAML 与 JSON

完整配置或 provider 正文必须包含顶层 `proxies` sequence。缺少受支持的 `type`、服务器地址、有效非零端口或必需凭据的条目会被跳过。端口可以是整数或数字字符串。JSON 使用原生解码，支持显示名称中的 UTF-16 代理对转义。

接受的 `type` 值包括 `socks5`、`ss`/`shadowsocks`、`trojan`、`vmess`、`vless`、`hysteria2`/`hysteria`、`tuic`、`juicity` 与 `anytls`。无关的客户端元信息会被忽略；不支持的线协议传输、代理插件和相互矛盾的安全设置不会被静默替换。

#### 通用代理字段

| Clash 字段 | 内部字段 | 规则 |
| --- | --- | --- |
| `name` | `name` | 默认为 `<type>-<server>:<port>`。 |
| `server`, `port` | `host`, `port`, `address` | 必需的地址和非零 `u16` 端口；接受数字形式的端口字符串。 |
| `username` | `username` | 可选 string。 |
| `password` | `password` | 可选 string；VLESS 使用下文优先级。 |
| `cipher` | `encryption` | 可选 string；VLESS 使用下文优先级。 |
| `plugin`, `plugin-opts` | — | 不支持；任一字段具有非空值时，条目会在发布节点前被跳过，mapping 类型的 options 也会被拒绝。 |
| `network` | `transport` | 可选 transport string。 |
| `tls` | `tls` | 可选 bool。Trojan、AnyTLS、Hysteria2、TUIC 和 Juicity 默认启用 TLS，并拒绝显式关闭。 |
| `servername`, `sni` | `sni` | `servername` 优先，`sni` 作为回退。 |
| `skip-cert-verify` | `skip_cert_verify` | 可选 bool。 |

#### 协议专属选项

Hysteria2 导入 `password`/`auth`、`obfs: salamander` 与 `obfs-password`、上传/下载带宽、`ports`/`mport` 跳跃端口范围、`hop-interval`/`mhop`、接收窗口、MTU 与 MTU 发现设置。TUIC 导入 UUID/password、拥塞控制、ALPN、接收窗口和 MTU。AnyTLS 导入 `idle-session-check-interval`、`idle-session-timeout` 和 `min-idle-session`。支持的拼写别名会在派生节点身份前规范化。

显式关闭的功能 block 按禁用处理，不会误判为启用未支持功能。原生支持 UDP 的协议接受 `udp: true`；节点模型无法保留显式 UDP 限制时会拒绝导入。TUIC 允许省略 password 或使用空密码。Hysteria2 和 Juicity 接受与运行时固定选择一致的 `h3` ALPN；Juicity 接收窗口固定为 8 MiB，因此拒绝非默认覆盖值。

#### VLESS transport 与 REALITY

VLESS 字段会在派生节点身份前应用：

| Clash 输入 | 映射 |
| --- | --- |
| `uuid`, then `password` | 凭据；`uuid` 优先，旧 `password` 作为回退。 |
| `encryption`, then `cipher` | VLESS Encryption；`encryption` 优先。 |
| `flow` | 非空 VLESS flow。 |
| `network` | Transport。 |
| `reality-opts.public-key` | 启用 REALITY TLS 承载；必须是非空 string。 |
| `reality-opts.short-id` | 可选 REALITY short ID。 |
| `reality-opts.spider-x` | REALITY spider path；缺失或为空时使用 `/`。 |
| `ws-opts.path` | WebSocket path；回退到扁平别名 `ws-path`。 |
| `ws-opts.headers.Host` | WebSocket Host header，key 匹配不区分大小写；依次回退到 scalar `ws-headers`、`ws-host`。 |
| `grpc-opts.grpc-service-name` | gRPC service name；回退到 `grpc-service`。 |
| `client-fingerprint` | 有意不导入。TLS 指纹由进程级 `global.tls_implementation` 与 `global.utls_imitate` 选择。 |

嵌套 WS/gRPC 值优先于其扁平别名。启用的 `reality-opts` 必须是 mapping 且含非空 `public-key`；无效的启用声明绝不会降级成普通 TLS。空 block 或显式禁用的功能 block 会被忽略。

#### VLESS packet mode

| Clash 表示 | 规范化 mode | 条件 |
| --- | --- | --- |
| 没有启用 packet/multiplex 选项，也没有 `udp: true` | `legacy` | 禁用的 block 与 `xudp: false` 不选择 mode。 |
| `smux` 或 `multiplex` 且 `enabled: true` | `h2mux` 或 `h2mux-padded` | 必须有 `protocol: h2mux` 或显式 bool `padding`。`padding: true` 选择 `h2mux-padded`，否则选择 `h2mux`。 |
| `udp-over-tcp: true` | `uot-v2` | Boolean 简写。 |
| `udp-over-tcp: { enabled: true, version: 0|2 }` | `uot-v2` | 缺失 `version` 按 `0` 处理；也接受 `_` 别名。 |
| `packet-encoding: xudp` | `xudp` | `packet_encoding` 是扁平别名。 |
| `xudp: true` | `xudp` | Boolean 简写。 |
| 未声明其他 packet 设置时的 `udp: true` | `xudp` | 对齐常见 Clash VLESS UDP 默认行为；显式 mode 优先。 |
| 规范分享链接 `vless_mode=mux-cool` | `mux-cool` | Clash packet/mux 别名不接受 `mux-cool`。 |

VLESS Clash 条目出现下列任一情况时会被拒绝：

- 别名值相互冲突或重复 XUDP 表示；
- H2MUX、UoT 与 XUDP 中启用多个 mode；
- 启用 `packet-addr`/`packet_addr` 或顶层 `mux`；
- 已启用的 `smux`/`multiplex` block 既没有 `protocol: h2mux`，也没有显式 `padding` bool；
- multiplex 协议不是 `h2mux`、`only-tcp: true`、启用 Brutal 设置，或 `max-connections`、`min-streams`、`max-streams` 调优值非零；
- `udp-over-tcp` version 不是 `0` 或 `2`；
- `udp: true` 与显式禁用的 packet mode 冲突，或非 `legacy` mode 搭配 `udp: false`；
- 未支持的 packet encoding（接受空值、`none`、`legacy` 与 `xudp`）；packetaddr 和 `mux-cool` 别名仍不支持；
- 非 `legacy` mode 与 VLESS Encryption 组合，或与受支持的 `xudp` + `xtls-rprx-vision` 之外的 `flow` 组合。

规范 VLESS 分享链接使用 `vless_mode=legacy|uot-v2|h2mux|h2mux-padded|xudp|mux-cool`。`smux`、`udp-over-tcp`、`packet-encoding` 等含义模糊的第三方分享链接 key 会被拒绝，不会猜测其语义。

### SIP008 与 sing-box JSON

SIP008 version 1/2 wrapper（`{"servers":[...]}`）及裸服务器数组会导入 Shadowsocks 的 `server`、`server_port`、`method`、`password` 和 `remarks`。空插件字段不会导致拒绝；有效的插件配置仍不受支持。

sing-box 配置从 `outbounds` 导入受支持的 Shadowsocks、SOCKS5、VMess、VLESS、Trojan、Hysteria2、TUIC、Juicity 和 AnyTLS 条目。结构性 `selector`、`urltest`、`direct`、`block` 与 `dns` 条目不是代理节点。TLS/SNI、REALITY、WebSocket/gRPC、VLESS packet mode 和受支持的协议调优会通过共同的节点构建逻辑规范化。只有未启用 multiplex/UoT、未限制为仅 TCP 且没有显式 packet encoding 时，VLESS 才默认使用 XUDP。gRPC service name 为空或省略时保留 sing-box 的空 service，不套用 honk 的 `GunService` 默认值。Hysteria2 可以只提供 `server_ports`，以第一个跳跃端口作为名义端点。不支持的链式代理、线协议功能和认证要求不会被静默丢弃。每节点 uTLS 指纹提示不会覆盖 honk 的进程级 TLS 设置。

显式 sing-box 原生 VLESS UDP（`packet_encoding: ""` 且未限制为仅 TCP、未启用 wrapper）尚不支持，会跳过；启用 H2MUX 时由它承载 packet 路径，即使来源同时显式写出 `packet_encoding: "xudp"`。

### Surge、Surfboard、Loon 与 Quantumult X

导入器接受 Surge/Surfboard/Loon 的具名逗号分隔记录，以及 Quantumult X 的 `protocol=endpoint,...,tag=name` 记录。完整配置使用 `[Proxy]` 或 `[server_local]`；其他 section 会被忽略。带引号的名称/密码可以包含逗号、等号、转义引号和有意保留的首尾空格。

受支持的记录把凭据、TLS/SNI、WebSocket/gRPC、REALITY 和已实现的协议选项映射到同一节点模型。Quantumult X 的 `obfs=wss` 同时使用 `obfs-host` 作为 WebSocket Host 和默认 TLS SNI；显式 TLS 主机名优先。SSR、不支持的插件/混淆及传输方式会被跳过，不会冒充另一种协议导入。

Surge `server-cert-fingerprint-sha256` 映射到 honk 的叶证书 pin：两者都替代标准 X.509 验证。独立的 `server-cert-verify-name`、客户端证书、`sni=off` 和 Shadow TLS 无法表达，会被拒绝，不会静默丢弃（[Surge TLS 参考](https://manual.nssurge.com/policies/tls.html)）。

有效的 Quantumult X `tls-cert-sha256` / `tls-pubkey-sha256` 固定证书设置会被拒绝：honk 的叶证书 pin 会替代 PKI，不能拿它替换尚未确认等价的外部验证约定。显式设置 `tls-verification=false` 时，QX 会忽略两类 pin，导入会保留该禁用验证行为。有效的 QX REALITY 会按[官方配置](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf)忽略自定义 `tls-alpn` 和 session-ticket 设置；普通 TLS 不适用该例外。旧 VMess `aead=false`、启用的 Shadowsocks UoT/SSR、不支持的 TLS ALPN 和禁用 TLS session 复用会被拒绝，不会静默丢弃。

## 离线解析与探测

`honk-tool sub` 接受需要拉取的订阅 URL，或任一种受支持正文格式的本地文件。本地文件不会触发订阅下载，适合离线解析；随后命令仍会执行所配置的连通性与延迟探测：

```console
honk-tool sub ./share-links.txt --limit 10
honk-tool sub https://example.com/sub --ua honk-tool
```

下载正文与本地文件使用相同的自动识别。传入 `-` 会从标准输入读取一个 HTTP(S) 订阅 URL，而不是从标准输入读取订阅正文。探测 flag 与输出见 [CLI 参考](./cli.md)。

## 相关文档

- [节点参考](./nodes.md)
- [组参考](./groups.md)
- [CLI 参考](./cli.md)
