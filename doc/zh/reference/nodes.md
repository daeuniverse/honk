# 节点与分享链接

`node { ... }` 从分享链接声明可拨号的出站，并为每个节点分配稳定的运行时身份。

## `node {}` 声明

每个非注释行是一个分享链接。tag 与链接都可加引号或裸写：

配对引号之外的 `#` 位于语句开头或紧跟 ASCII 空格、制表符时，会开始注释。裸分享链接中紧贴前文的 `#` 仍是数据：`ss://…#hk1 # note` 保留名称 `hk1`，而 `ss://…#hk2#note` 保留 `hk2#note`。链接结束引号之后紧贴的 `#` 作为注释接受，并在该字节处产生 `legacy-glued-hash` 警告：`'ss://…#hk1'#note` 保留 `hk1`。注释前应留空白。结束引号后的其他文本使条目被跳过，并产生 `trailing-entry-text` 诊断。引号错误与块结构规则见[方言参考](./dialect.md)。

```dae
node {
    iris: 'socks5://10.10.10.1:2077'
    'hk1': 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@hk1.example.com:8388#fragment-name'
    'trojan://secret@example.com:443?sni=example.com#trojan1'
    socks5://10.10.10.2:1080
}
```

当前解析器同时接受带 tag 和不带 tag 的条目。非空 dae tag 会替换链接的 `#fragment` 名称。不带 tag 的链接保留解码后的 fragment；没有 fragment 时使用不含凭据的 `{scheme}-{host}` 回退名称。

VMess JSON 的 `ps` 备注缺失或为空时，先使用 `vmess-{host}` 通过校验，再由非空 dae tag 替换名称。

识别 tag 与链接的结束引号时，反斜杠会转义下一个字符；解析后的文本保留原始转义序列。

协议已识别但格式错误的链接会被丢弃，并产生 `invalid-node-entry` 诊断。诊断使用原始节点条目序号，不包含链接或节点名称。数据接口返回诊断而不记录日志；普通接口只报告一次。未知协议属于配置硬错误。独立的 `mux:` 或 `mux=` 行也会被拒绝；VLESS 传输行为必须写在各链接的 `vless_mode=` 查询参数中。

旧版 `ss://base64(method:password@host:port)` 格式按字面值读取解码后的凭据，不做 URL 解码：`%20` 保持为 `%20`，`?`、`/`、`#`、`:` 和 `@` 仍是密码字符。最后一个 `@` 分隔凭据与端点；userinfo 本身也可以是 `base64(method:password)`。解码后的载荷缺少 `@`，或凭据无法解析为方法与密码时，拒绝解析。URL userinfo 格式仍按百分号解码凭据。端点、路径、query（包括 `/?plugin=...`）和 fragment 继续按 URL 处理。

## 节点身份

`Node::derive_id()` 是唯一的身份派生路径。它对以下材料计算 UUID v5：

```text
protocol|host|port|credential-fingerprint|dial-shape
```

凭据指纹遵循各 handler 的字段优先级。旧版 dial shape 包含 `sni`、transport、WebSocket/gRPC 形态、Hysteria2 混淆、REALITY 参数、`flow` 以及每种非 `legacy` VLESS mode。非空的结构化 `tls_alpn` 以旧 ID 为 namespace、JSON 元组 `["tls-alpn", <有序列表>]` 为 name 派生子 UUID v5，从而将 ALPN 与任意凭据文本分离。空 `tls_alpn` 保留旧 ID。调优参数与显示元数据不参与。

拼接前，每个原始凭据字段、拨号形态字段和有效的 `host` 值都会将 `\` 转义为 `\\`，将 `|` 转义为 `\|`。拼接后的指纹不再转义。对于通过 `Config::validate` 的节点，不同的身份字段会产生不同的哈希输入。完整配置校验拒绝的节点不在此保证范围内，即使 `Node::from_share_link` 能为其派生 ID。

本次升级时，上述以 `|` 拼接的身份字段中含有 `|` 或 `\` 的节点，其 ID 会变更一次，以 ID 为键的健康状态和预热状态会重新建立。这些字段不含两种字符的节点保留原 ID。ALPN 使用独立的 JSON 子 UUID 派生步骤，因此仅 ALPN 含有 `|` 或 `\` 不会在本次升级时改变已有 ID。Selector 选择按成员名称迁移。连接池中的就绪流原本就会在所属配置版本退出时移除。`name`/`subtag` 筛选器不受影响。

因此，只要可拨号端点不变，身份在改名、reload 和订阅刷新后仍保持稳定。配置/运行时组装会拒绝重复的派生 ID。`Node::default()` 的 ID 为 nil；构造路径会派生 ID，出站运行时注册表会拒绝任何抵达该处的 nil ID。

## 节点字段

Node 模型包含下列字段。分享链接从 scheme、userinfo、authority、fragment 和 query 填充面向操作者的字段；明确标为元数据的行由结构化 loader、导入或运行时管理。它们都不是 dae `node {}` 中的独立键。下表默认值是模型默认值；URL 形分享链接省略端口时使用 `443`，而 v2rayN VMess payload 必须包含有效端口。

| 字段 | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `id` | UUID | 派生 | 上述稳定内容身份；运行时不允许 nil |
| `name` | string | `""` | dae tag、解码后的 fragment、`remark` query、VMess `ps` 或不含凭据的回退名称 |
| `protocol` | enum | `ss` | 从分享链接 scheme 派生 |
| `address` | string | `""` | 解析后的链接存储 `host:port` |
| `host` | string | `""` | 显式服务端主机；否则 `Node::host()` 从 `address` 派生 |
| `port` | u16 | `0` | 服务端端口；URL 形链接省略时使用 `443` |
| `username` / `password` | string? | null | 来自 userinfo 的认证、UUID 或密钥 |
| `encryption` | string? | null | SS/VMess cipher 或 VLESS Encryption 客户端字符串 |
| `vless_mode` | `WireMode` | `legacy` | `legacy`、`uot-v2`、`h2mux`、`h2mux-padded`、`xudp` 或 `mux-cool` |
| `plugin` / `plugin_opts` | string? | null | 解析后的 SIP002 插件元数据；代理插件不受支持，订阅导入会拒绝非空值 |
| `transport` | string | `"tcp"` | 流 transport；校验只接受空值/`tcp`、`ws` 或 `grpc` |
| `tls` | bool | `false` | 流 TLS 标志；Trojan/AnyTLS 链接开启，规范 VLESS 链接历史默认开启 |
| `sni` | string? | null | TLS 服务端名称；非空的 `sni` 与 `peer` 必须一致，未被传输层使用的 `host` 作为回退值 |
| `tls_alpn` | string[] | `[]` | 结构化配置/订阅导入的普通裸 TCP TLS ALPN；空列表保留 TLS profile 默认值。非空值支持 AnyTLS 与 TCP Trojan/VMess/VLESS，不支持关闭 TLS、REALITY、WS/gRPC 或 QUIC。TUIC 继续使用 `tuic_alpn`；这不是分享链接 query。 |
| `skip_cert_verify` | bool | `false` | 跳过证书校验；`allowInsecure`、`allow_insecure` 与 `insecure` 的有效声明必须一致，安全影响见下文 |
| `ech_enabled` | bool | `false` | 存在静态 ECH 配置，或 `ech=1`/`true` |
| `ech_config` | string? | null | 来自 `ech_config` 或 `echconfig` 的 Base64 ECHConfigList |
| `ech_config_path` | string? | null | 结构化 loader 中指向 base64 ECHConfigList 的路径；不是分享链接 query |
| `reality_public_key` | string? | null | 来自 `pbk` 的 REALITY X25519 公钥 |
| `reality_short_id` | string? | null | 来自 `sid` 的 REALITY short ID |
| `reality_spider_x` | string? | null | 存储的 `spx`；REALITY 链接默认设为 `/` |
| `flow` | string? | null | 来自非空 `flow` 或 Shadowrocket `xtls=2` 的 VLESS flow；只支持 `xtls-rprx-vision` |
| `network` | string? | null | 受支持协议的数据包网络能力；与 VMess JSON `net` 等流传输字段独立 |
| `ws_path` / `ws_host` | string? | null | WebSocket `path` 与 Host header |
| `grpc_service` | string? | null | gRPC `serviceName` 或 `service_name` |
| `hy2_auth` / `hy2_obfs` | string? | null | Hysteria2 认证与 salamander 密码 |
| `hy2_up_mbps` / `hy2_down_mbps` | u32? | null | Hysteria2 brutal 发送端/接收端带宽提示 |
| `hy2_port_hopping` / `hy2_hop_interval` | string? / u64? | null | Hysteria2 `mport` 列表与 `mhop` 秒数；有效间隔为 30 秒 |
| `hy2_init_stream_recv_window` / `hy2_init_conn_recv_window` | u64? | null | Hysteria2 QUIC 接收窗口；有效默认值为 8 MiB / 8 MiB（conn 窗口同时是每连接内存预算，慢消费者最多缓冲约 3 倍该值；内存占用 ≈ 活跃连接数 × 3 × conn 窗口） |
| `hy2_disable_mtu_discovery` | bool? | null | Hysteria2 `disablePathMTUDiscovery` |
| `quic_mtu` | u16? | null | 来自 `mtu` 的 QUIC UDP payload 大小；默认 1252，接受范围 1200–65527；显式设置大于 1252 时启用 GSO，`HONK_QUIC_GSO=0` 可强制关闭 |
| `tls_pin_sha256` | string? | null | 来自 `pinSHA256` 或 `pin_sha256` 的叶证书 SHA-256 pin |
| `tuic_uuid` / `tuic_password` | string? | null | TUIC 凭据；扁平字段须与别名 `username` / `password` 一致 |
| `tuic_congestion` / `tuic_alpn` | string? | null | TUIC `congestion_control` 与逗号分隔的 `alpn` |
| `tuic_init_stream_recv_window` / `tuic_init_conn_recv_window` | u64? | null | TUIC QUIC 接收窗口；有效默认值为 8 MiB / 8 MiB |
| `juicity_uuid` / `juicity_password` | string? | null | Juicity 凭据；扁平字段须与别名 `username` / `password` 一致 |
| `anytls_password` | string? | null | 从链接 userinfo 复制的 AnyTLS 密钥 |
| `anytls_min_idle_session` | usize? | null | 来自 `min_idle_session` 的空闲 session 目标下限；有效默认值 0，受两条 session 的池上限约束 |
| `anytls_idle_session_check_interval` | u64? | null | 解析后的 `idle_session_check_interval` 秒数；当前运行时 janitor 周期仍固定为 30 秒 |
| `anytls_idle_session_timeout` | u64? | null | 来自 `idle_session_timeout` 的空闲驱逐；有效默认值 30 秒 |
| `mark` | u32? | null | 结构化模型中的出站 `SO_MARK`；不是 dae 分享链接 query |
| `tags` | string[] | `[]` | 分类元数据；不是 dae 分享链接 query |
| `subscription_id` / `group_id` | UUID? | null | 导入/运行时归属元数据 |
| `created_at` / `updated_at` | datetime | now | 运行时元数据 |

节点自身校验要求非空名称、有效主机和显式非零 `port`。`address` 不会补充缺失的端口；仅提供 IPv6 地址时须显式设置 `host`。只有身份与注入规则完全一致的 `direct`/`block` 内置节点可省略端点。

### 结构化 loader 兼容性

TOML、YAML 与 JSON 继续使用旧的扁平节点键。加载时只读取所选 `protocol` 自己的字段；其他协议遗留的非默认字段会被剥离而不会拒绝节点，并由一条警告列出被剥离的字段名。例如，`ss` 节点上的 `tls: true` 会被忽略并告警，而不会开启 TLS。对 Trojan、VLESS、Hysteria2 与 AnyTLS，`username` 不是凭证别名；缺少该协议实际凭证字段时，单独提供的 `username` 会被剥离并触发针对性警告，从而保持旧版行为与 ID。所选协议实际使用的值仍会正常解析与校验。Honk 自身输出仍可安全 round-trip。启用 `store_subscribe` 时，原始订阅正文仅在解析成功后持久化；被拒绝的刷新不会覆盖上一份有效正文。

扁平凭据别名在剥离不兼容字段前比较：Hysteria2 的 `hy2_auth`/`password`，TUIC 和 Juicity 的专用 UUID/`username`、专用密码/`password`，以及 AnyTLS 的 `password`/`anytls_password`。缺失或 null 表示未提供；已提供的字符串须逐字节一致，空字符串和首尾空格也参与比较。空凭据仍须满足对应协议的要求。扁平凭据字段仍须使用字符串；数字转换仅适用于订阅导入。

新增 `tls_alpn` 字段不沿用旧字段剥离规则：不支持的协议或 TLS 上下文带有非空值时，会拒绝节点，而不是静默改变握手。

分享链接的证书校验布尔值忽略首尾空白和 ASCII 大小写。`true`、`yes`、`1`、`on` 会关闭证书校验；`false`、`f`、`no`、`n`、`0`、`off`、`t`、`y` 保持校验开启。空文本、未知文本或别名冲突会使链接被拒绝。**安全行为变更：**`yes` 和 `on` 以前不会关闭校验，现在会关闭校验并产生警告。升级前请检查这些链接，改用明确的 `true` 或 `false`。结构化布尔值仍须使用原生布尔类型，不转换字符串或数字。

VMess 加密方式接受 `auto` 和 `aes-128-gcm`，忽略大小写并存储为小写；空的可选声明使用默认值。JSON 的 `scy`/`security`、编码分享链接的 `encryption`/`scy`/表示加密方式的 `security`，以及订阅支持的加密方式别名，须在赋值前比较。不支持的值或冲突会使节点被拒绝。编码分享链接中的 `security=none` 和 `security=tls` 仍控制 TLS，不表示加密方式。记录格式的位置参数仍是低优先级备用值。

TUIC 分享链接和订阅的转发模式只接受未指定、空值或 `native`；即使存在有效别名，不支持的 `udp-relay-mode`/`udp_relay_mode` 仍会使条目被拒绝。Hy2 分享链接只接受小写的 `obfs=salamander`；未指定或空值关闭混淆，未知名称（包括 `SALAMANDER`）会被拒绝。Salamander 未提供非空密码时仍关闭混淆。重复密码声明与 `obfs-password`/`obfs_password` 须一致。Clash 仍接受不区分大小写的 Salamander，并要求非空白密码；sing-box 仍要求小写类型，并拒绝已配置有效字段但缺少类型或密码的混淆对象。

时长转换拒绝负数、非有限值和超出范围的值，不再截为零或上限。结构化订阅的秒数字段将整数毫秒向上取整（`500ms` 和 `1000ms` 均为 `1`，零仍为零），再比较别名。Hy2 分享链接的 `mhop` 仍只接受无后缀的无符号整数秒数；`500ms` 和 `1s` 会被忽略，并产生不含原值的警告。AnyTLS 分享链接保留秒数解析规则；dae 毫秒字段仍只接受裸数值、ms 或 s，并截去不足一毫秒的部分。

sing-box 的 `hop_interval`、`idle_session_timeout` 和 `idle_session_check_interval` 保留原生数字零，缺失或 null 仍表示未提供。Hysteria2 记录会将每个 `mhop`、`hop-interval` 和 `hop_interval` 值转换为秒后比较；即使存在有效别名，冲突或无效值仍会使记录被拒绝。

Hysteria2 端口跳跃集合在拨号前拒绝重复端口和重叠范围，包括 `443,443`。单端口集合仍然有效。有效配置保留原写法；地址中的端口列表仍拒绝空项。出站构造函数对直接构造的节点使用同一个检查函数。

普通分享链接、VMess JSON、独立扁平 Node 反序列化和订阅导入都在构造完成时校验节点。使用 UUID 的协议要求有效 UUID；不支持的加密方式、传输类型、数据包能力、flow、ALPN 上下文或端口跳跃集合，会在派生身份前被拒绝。Vision 要求 TLS 或 REALITY。直接构造的节点也不能使用本应由适配器归一化掉的空 SNI、flow 或 network。订阅格式特有的非空密码要求仍留在对应适配器；SOCKS 可选认证及处理器支持的空凭据仍然有效。无效 dae 节点行和订阅条目仍按原策略跳过，有效条目保留。仅解析 Config 片段的 API 仍不执行整份配置准入，但片段内的无效节点现在会在构造时被拒绝。独立反序列化保留传入的 ID；运行时身份准入是另一项检查。

直接调用 `Node::validate()` 与适配器完成构造时使用相同的固定脱敏错误。校验错误不包含传入的节点名称或凭据值。

详细 Config 加载接口和配置／注册表准入保留节点校验的字段与原因，并补上从 1 开始的原始节点序号，不再替换为笼统的无效节点错误。凭据冲突指向规范别名字段，不输出任一值。独立 `NodeSeed` 和 Node 反序列化仍返回脱敏的通用 serde 错误。

VMess JSON 使用 `net: "ws"` 时，缺失或为空的 `host` 会让 WebSocket 握手使用节点服务器主机；提供非空 `host` 时仍以它为显式覆盖值。

## 协议

| 协议 | 别名 | TCP | UDP | 说明 |
| --- | --- | --- | --- | --- |
| `ss` | `shadowsocks` | 是 | 是 | AEAD 与 Shadowsocks 2022 |
| `trojan` | — | 是 | 是* | TLS；TCP/WS/gRPC transport |
| `vmess` | — | 是 | 否 | AEAD；TCP/WS/gRPC 与 REALITY；handler 需要 `rprx` |
| `vless` | — | 是 | 取决于 mode* | Legacy、UoT v2、H2MUX、XUDP、Mux.Cool、Encryption、REALITY 与 Vision；handler 需要 `rprx` |
| `socks5` | — | 是 | 是 | CONNECT 与 UDP ASSOCIATE |
| `hysteria2` | — | 是 | 是 | QUIC/H3、salamander、brutal/BBR 与端口跳跃 |
| `tuic` | — | 是 | 是 | QUIC 上的 TUIC v5 |
| `juicity` | — | 是 | 是 | QUIC 上的 Juicity |
| `anytls` | — | 是 | 是* | 多路复用 TLS session 与 UoT v2 |
| `direct` | — | 是 | 是 | 保留的内置直连出站；没有分享链接 scheme |
| `block` | — | 否 | 否 | 保留的内置拒绝出站；没有分享链接 scheme |

`network` 还可关闭 Trojan、AnyTLS 与非 legacy VLESS 的 packet 拨号。AnyTLS 会拒绝超过 16 KiB 的 UDP payload，与 anytls-go 0.0.13 的 relay buffer 一致。Legacy VLESS 没有 UDP，VMess UDP 尚未实现。

对于支持 `network` 的协议，扁平结构化输入接受逗号分隔的 `tcp`/`udp`，忽略各项首尾空白和 ASCII 大小写。`tcp` 关闭 UDP；`udp` 与 `tcp,udp` 都允许 UDP。空文本或纯空白规范化为未指定，保留协议的默认能力。`quic` 等未知值，或非空列表中的空项，会使节点被拒绝。该字段只控制 UDP 准入；`udp` 不会额外禁止 TCP。

没有 `rprx` Cargo feature 时，VMess 与 VLESS 节点仍能解析，但不会注册 handler，拨号以 `No handler for protocol` 失败。`honk-core` 默认启用 `rprx`。

`honk-core` 在启动和 reload 时注入具有固定保留 ID 的 `direct` 与 `block`。用户节点不得使用这些名称或协议。

## 协议参数

### Shadowsocks 2022

| 方法 | Base64 解码后的 PSK 长度 |
| --- | --- |
| `2022-blake3-aes-128-gcm` | 16 字节 |
| `2022-blake3-aes-256-gcm` | 32 字节 |
| `2022-blake3-chacha20-poly1305` | 32 字节 |

长度错误或不是 base64 的密钥会导致 handler 构造失败。

### 流传输

支持流传输的分享链接用 `type=` 或其 `network=` 别名选择传输方式。空文本和 `tcp` 表示裸 TCP；`ws`、`grpc` 分别选择 WebSocket、gRPC。赋值前会比较所有已提供的别名，包括兼容的 `obfs` 声明和重复查询键；不一致则拒绝链接。`h2`、`kcp` 等不支持的名称会在解析时被拒绝。对于 `ws`，`path` 映射到 `ws_path`，`host` 映射到 `ws_host`；对于 `grpc`，`serviceName` 或 `service_name` 映射到 `grpc_service`。`sni` 独立生效。`alpn` 为兼容而接受，但不会存储。

```dae
node {
    trojan_ws: 'trojan://secret@example.com:443?type=ws&sni=example.com&host=example.com&path=/path#trojan_ws'
    vless_grpc: 'vless://uuid@example.com:443?security=tls&type=grpc&serviceName=GunService#vless_grpc'
}
```

VMess 接受 v2rayN Base64 JSON（`net`、`host`、`path`、`sni`），也接受 Shadowrocket 的 `vmess://base64(auto:UUID@host:port)?...` authority 形式。后者映射 `tls`、`peer`/`sni`、`obfs=websocket|grpc`、`obfsParam`、`path` 和 `remark`；接受 standard / URL-safe Base64，有无 padding 均可。编码 authority 的 VMess 要求 AEAD 认证及 `auto`/`aes-128-gcm`；不支持的 cipher 和 REALITY 参数会被拒绝，不会静默替换。

VMess JSON 的 `net` 和 Shadowrocket 传输参数只选择流传输方式，不再写入数据包网络能力字段。未指定数据包限制时，保留原有默认 UDP 能力；已有的有效空传输字段也保留原始写法。

VLESS 已完成以下 live 互通验证：TCP+REALITY+Vision、TCP+REALITY、TCP+WS、TCP+WS+TLS 与 TCP+gRPC。Vision 支持的 direct-copy 组合是带 TLS 或 REALITY 的裸 TCP，而不是 WS/gRPC。

### Shadowrocket VLESS

统一解析器接受 `vless://base64(auto:UUID@host:port)?...`，以及省略 `auto:` 的编码 authority。支持 standard / URL-safe Base64，有无 padding 均可；IPv6 端点必须使用方括号。编码内容必须包含有效 UUID 和显式非零端口。格式错误的编码 authority 会被拒绝，不再误当作主机名或显示名称。

query 映射遵循 [Shadowrocket 导出器](https://github.com/cedar2025/Xboard/blob/master/app/Protocols/Shadowrocket.php)：

| 输入 | 含义 |
| --- | --- |
| `tls=0` / `tls=1` | 关闭 / 开启 TLS。编码链接没有安全选项时默认明文；规范 `UUID@host:port` 链接保留默认开启 TLS 的行为。 |
| 未指定 `security` 时的 `pbk`、`sid`、`spx` | 选择 REALITY，必须提供非空 `pbk`。仍支持显式 `security=reality`。 |
| `xtls=0` / `xtls=2` | 无 flow / `xtls-rprx-vision`。拒绝已淘汰的 XTLS Direct（`xtls=1`）及未知值。 |
| `remark` | 没有非空 fragment 时用作显示名称，作为 query 值只解码一次。 |
| `peer` | 显式 SNI 别名；非空的 `sni` 与 `peer` 必须一致。空值或纯空白名称视为未指定。 |
| `obfs=websocket`、`obfsParam`、`path` | WebSocket transport、Host header 回退值和路径。 |
| `obfs=grpc`、`path` | gRPC transport 和 service name 回退值。 |

TLS/REALITY、flow 或传输声明相互冲突时会拒绝链接，不会静默降级。VLESS 的 `obfs` 仅接受空值/`none`、`websocket` 或 `grpc`，不会把不支持的传输方式当作 TCP。`host` 和 `serviceName`/`service_name` 保留原有回退顺序。显式 SNI 别名在赋值前按原始字节比较：相同值合并，不同值报错，不转换大小写。空值或纯空白的 SNI 和 flow 在派生节点 ID 前规范化为未指定；非空 flow 必须为 `xtls-rprx-vision`。

Clash 导入会比较 `servername`、`server-name` 和 `sni`；记录格式还会比较 `tls-name` 和 `tls-host`，并保留较低优先级的 `obfs_sni` 回退值，包括 Quantumult X 的 WSS Host。记录中的 `off` 仍为无效值。分享链接和 VMess JSON 的 WebSocket `host` 仅用作 Host 请求头；非 WebSocket 传输则将其作为较低优先级的 SNI 回退值。TLS 使用方最终仍可回退到节点主机名。

### Hysteria2

同时接受 `hysteria2://` 和 `hy2://`。完整的 percent-decoded userinfo 是认证字符串：字面 `user:password` 保留两部分及冒号，与 percent-encoded `user%3Apassword` 等价。

| 链接输入 | 节点字段 / 行为 |
| --- | --- |
| userinfo 密钥 | `hy2_auth`；保留完整 `user:password`，而不是只取 password |
| `obfs=salamander&obfs-password=...` | 非空密码成为 `hy2_obfs`；其他/不完整 obfs 输入保持关闭 |
| `upmbps` / `downmbps` | `hy2_up_mbps` / `hy2_down_mbps`；`upmbps` 为正值时启用 Brutal，否则使用 BBR；下载值按 bytes/s 通告 |
| `mport` / `mhop` | 端口列表/范围与以秒为单位的跳跃间隔；间隔默认 30，并钳制到上游规定的最小值 5。官方客户端把跳跃端口写在 authority 里的形式（`:443,5000-6000`）与 `mport` 等价；两者同时指定会被拒绝，非法的内嵌列表在解析期报错 |
| `pinSHA256` | `tls_pin_sha256`，替代 PKI/主机名校验 |
| `initStreamReceiveWindow` / `initConnReceiveWindow` | QUIC 接收窗口覆盖值 |
| `disablePathMTUDiscovery` | 值为 `1`/`true` 时关闭 QUIC PMTU 发现 |
| `mtu` | 共用 QUIC UDP-payload 上限；只接受 1200–65527 |
| `sni` / `peer`、insecure 别名、ECH 参数 | 共用 TLS 行为；非空的显式 SNI 别名必须一致 |

```dae
node {
    hy2: 'hysteria2://secret@example.com:443?sni=example.com&obfs=salamander&obfs-password=obfspw&upmbps=50&downmbps=200&mport=20000-30000&mhop=30#hy2'
}
```

### TUIC 与 Juicity

| 协议 | 链接输入 | 节点字段 / 行为 |
| --- | --- | --- |
| TUIC | `uuid:password` userinfo | 通用 `username` / `password`；供 `tuic_uuid` / `tuic_password` 的 handler 回退使用 |
| TUIC | `congestion_control` | `cubic`、`new_reno` 或 `bbr`；未知值告警并回退到 cubic |
| TUIC | `alpn` | 逗号分隔的 ALPN 覆盖值；默认 `tuic` |
| TUIC | `initStreamReceiveWindow` / `initConnReceiveWindow` | 接收窗口覆盖值 |
| Juicity | `uuid:password` userinfo | 通用 `username` / `password`；供 `juicity_uuid` / `juicity_password` 的 handler 回退使用 |
| Juicity | 协议默认值 | ALPN `h3`、BBR，以及固定的 8 MiB / 8 MiB 接收窗口 |
| 两者 | `mtu`、`sni`、insecure 别名、pin、ECH | 共用 QUIC/TLS 参数 |

### AnyTLS

| 链接输入 | 节点字段 / 行为 |
| --- | --- |
| userinfo 密钥 | `password` 与 `anytls_password` |
| `min_idle_session` | `anytls_min_idle_session`；按 u16 解析并用作请求的待机下限，受两条 session 的池上限约束 |
| `idle_session_check_interval` | 以秒存储的 duration；当前不生效，因为 janitor 周期固定为 30 秒 |
| `idle_session_timeout` | 以秒存储的 duration；默认 30 秒 |

Duration 接受裸秒数以及 `ms`、`s`、`m`、`h` 后缀。

## VLESS

### Mode

`vless_mode` 是唯一、互斥的规范化 mode，绝不协商。

| Mode | TCP | UDP | 行为 |
| --- | --- | --- | --- |
| `legacy` | 普通 VLESS stream | 否 | 向后兼容默认值；省略时保留 legacy 身份 |
| `uot-v2` | 普通 VLESS stream | 直连 UoT v2 | 每个 UDP transport 一条 connected UoT stream |
| `h2mux` | H2MUX 逻辑 stream | 原生 connected sing-mux UDP | TCP 与 UDP 共用节点所有的 HTTP/2 carrier pool |
| `h2mux-padded` | H2MUX 逻辑 stream | 原生 connected sing-mux UDP | 带 sing-mux v1 padding 的 `h2mux` |
| `xudp` | 普通 VLESS stream | Single XUDP | 每个 UDP transport 一条不入池的 mux-command carrier，session ID 0 |
| `mux-cool` | Mux.Cool 逻辑 stream | 池化 XUDP | TCP 与 UDP 共用节点所有的 Xray Mux.Cool carrier pool |

规范 query 为 `vless_mode=legacy|uot-v2|h2mux|h2mux-padded|xudp|mux-cool`。旧别名 `packetEncoding=xudp` 映射为 `xudp`。重复的 mode 表示会被拒绝。

每个非 `legacy` mode 都拒绝非空且非 `none` 的 VLESS Encryption。Vision 只支持与 `legacy` 或 `xudp`、TLS 或 REALITY，以及裸 TCP transport 组合。不会发生 mode 协商、回退或首包重放。

解析器拒绝而不是猜测以下含义模糊的第三方 query 形式：`mux`、`smux`、`multiplex`、`udp-over-tcp`、`udp_over_tcp`、`packet-encoding`、`packet_encoding`、`packet-addr`、`packet_addr`、`xudp`、`only-tcp`、`only_tcp`、`brutal`、`brutal-opts`、`brutal_opts`、`max-connections`、`max_connections`、`min-streams`、`min_streams`、`max-streams` 与 `max_streams`。

本参考只描述配置表面。carrier 所有权与 wire framing 见[出站设计](../design/outbound.md)。

### Encryption

`encryption=` 接受的基本客户端字符串形式为：

```text
mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<base64url-key>
```

密钥解码后可以是 32 字节 X25519 密钥或 1184 字节 ML-KEM-768 密钥；也接受链式认证密钥。`0rtt` 使用缓存 ticket，冷启动时走 1-RTT 路径。VLESS Encryption 位于所选 TCP/TLS/REALITY/WS/gRPC transport 内层，但要求 `legacy` mode，且不能与 `flow` 组合。

### REALITY 与 Vision

对于 VLESS URL 链接，`security=reality` 开启 TLS 并映射 REALITY query 字段；`flow` 选择 Vision。

| Query | 含义 |
| --- | --- |
| `security=reality` | 选择 REALITY 并开启 TLS。选择了 REALITY 却没有 `pbk` 的节点会在校验时被拒绝，而不是降级成普通 TLS |
| `pbk` | Base64url 编码的 32 字节 X25519 服务端公钥；无效输入 fail-closed |
| `sid` | 偶数长度十六进制 short ID，最多 8 字节；允许为空 |
| `spx` | 存储 spider path；选择 REALITY 时默认为 `/` |
| `flow=xtls-rprx-vision` | 开启受支持的 Vision flow |
| `fp` | 接受但忽略；ClientHello 指纹由全局 TLS mode 控制 |

显式 `security=` 会覆盖 VLESS 历史默认值：`none` 关闭 TLS，其他值开启。没有 `security` 时 VLESS 默认开启 TLS。标准 VMess 链接改用其 v2rayN JSON `tls` 字段。

REALITY 用其 REALITY key 认证对端并 fail-closed；它不需要 CA 校验或 `skip_cert_verify`。服务端 REALITY `dest`/客户端 SNI 应选择 TLS Certificate 消息小于 8 KiB 的目标，因为 sing-box REALITY 缓冲区为 8192 字节；已知 `dl.google.com` 可容纳，`www.microsoft.com` 不可容纳。

## TLS 指纹与 ECH

全局 `tls_implementation` 同时作用于代理 TCP TLS 与 QUIC：

| 取值 | 行为 |
| --- | --- |
| `tls` | 原生 BoringSSL ClientHello |
| `utls` | Chrome 形 ClientHello，包含 GREASE、扩展乱序、Chrome 算法/曲线、证书压缩、ALPS 与 ECH GREASE |

按节点的 ECH 控制项为：

| 输入 | 行为 |
| --- | --- |
| `ech_config=<base64>` / `echconfig=<base64>` | 静态 ECHConfigList；隐含 `ech_enabled` 且优先 |
| `ech_config_path` | 结构化 loader 文件路径；两者同时存在时 `ech_config` 优先 |
| `ech=1` / `ech=true` | 没有静态配置时开启 DNS HTTPS-RR 发现 |

静态配置会提供真实 ECH，ECH 被拒绝时握手 fail-closed。发现是尽力而为且 fail-open：找不到 ECHConfigList 时，握手不带真实 ECH 继续；`utls` 仍发送 ECH GREASE。发现使用 bootstrap resolver，未配置时使用系统首个 nameserver，并按域名缓存结果。同一组控制项也适用于 QUIC 协议。

## 分享链接 scheme

| Scheme | 格式与映射 |
| --- | --- |
| `ss://` | SIP002 userinfo/完整 authority base64 形式，以及 `plugin` |
| `vmess://` | 宽松 base64 v2rayN JSON（`add`、`port`、`id`、`scy`、`net`、`host`、`path`、`tls`、`sni`、`ps`） |
| `vless://` | URL userinfo UUID，加 transport、TLS/REALITY、flow、Encryption 与规范 mode query |
| `trojan://` | URL userinfo 密钥，加 transport 与 TLS query |
| `anytls://` | URL userinfo 密钥，加 TLS 与池 query |
| `hysteria2://` | 上述 Hysteria2 query 映射；也接受 `hysteria://` |
| `tuic://` | 上述 TUIC userinfo 与 QUIC 调优 |
| `juicity://` | Juicity userinfo 与共用 QUIC/TLS query |
| `socks5://` | SOCKS userinfo；`socks4://` 与 `socks4a://` 也导入同一种节点协议 |

对于写成 `a -> b` 的链，只解析 `a`。自动名称只来自解码后的 `#fragment`、VMess `ps` 或 `{scheme}-{host}`；解析器绝不以原始 URI 或 userinfo 作为回退，因此生成名称不会泄漏凭据。显式 tag、fragment 与 `ps` 值仍由用户控制。

## 相关文档

- [订阅参考](./subscription.md)
- [组参考](./groups.md)
- [出站设计](../design/outbound.md)
