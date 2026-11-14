# 节点与分享链接

`node { ... }` 从分享链接声明可拨号的出站，并为每个节点分配稳定的运行时身份。

## 示例

```dae
node {
    iris: 'socks5://10.10.10.1:2077'
    'hk1': 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@hk1.example.com:8388#fragment-name'
    'trojan://secret@example.com:443?sni=example.com#trojan1'
    socks5://10.10.10.2:1080
}
```

## 字段

Node 模型包含下列字段。分享链接会从协议方案、userinfo、地址部分、片段和查询参数填充供用户配置的字段；其余字段由结构化 loader、导入或运行时填充。这些字段都不是 dae `node {}` 里的独立 key；节点写成链接和标签，见 [`node {}` 声明](#node--声明)。

扁平结构化输入必须包含 `name`、`protocol`、`address` 和 `port`，即使已设置 `host`。表中的默认值是模型默认值。

| Key | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `id` | UUID | 派生 | 稳定内容身份；运行时不允许 nil。见[节点身份](#节点身份)。 |
| `name` | string | `""` | dae 标签、解码后的片段、`remark` 查询参数、VMess `ps` 或不含凭据的 `{scheme}-{host}` 回退名称。 |
| `protocol` | enum | `ss` | 从分享链接协议方案派生。 |
| `address` | string | `""` | 从链接解析的 `host:port`；它不补充缺失的端口。 |
| `host` | string | `""` | 显式服务端主机；否则 `Node::host()` 从 `address` 派生。 |
| `port` | u16 | `0` | 服务端端口；URL 形链接省略端口时使用 `443`，v2rayN VMess 载荷则必须带有效端口。 |
| `username` / `password` | string? | `null` | 协议凭据；扁平 VMess 和 VLESS 从 `password` 读取用户 UUID。 |
| `encryption` | string? | `null` | SS/VMess 加密方式或 VLESS Encryption 客户端字符串；Shadowsocks 省略时在拨号阶段回退到 `aes-128-gcm`。见 [Encryption](#encryption)。 |
| `packet_encoding` | `VlessUdpEncoding` | VLESS 为 `auto` | VLESS 回退编码：`auto`、`native`、`xudp` 或 `uot-v2`；规范 URI 的 `packetEncoding=none` 映射为 `native`。 |
| `multiplex` | `VlessMultiplex` | VLESS 为 `{"protocol":"off"}` | VLESS carrier 选择：`off`、`h2` 或 `xray`；形态见 [VLESS UDP 与多路复用](#vless-udp-and-multiplexing)。 |
| `plugin` / `plugin_opts` | string? | `null` | SIP002 插件元数据；代理插件不受支持，订阅导入会拒绝非空值。 |
| `transport` | string | `"tcp"` | 流传输：空值或 `tcp`、`ws`、`grpc`，或输入 `splithttp` 规范化成的 `xhttp`；见[流传输](#流传输)。 |
| `tls` | bool | `false` | 流 TLS 标志；Trojan 与 AnyTLS 链接会开启它，规范 VLESS 链接保留历史上默认开启的行为。 |
| `sni` | string? | `null` | TLS 服务端名称；非空的 `sni` 与 `peer` 必须一致，未被传输层使用的 `host` 作为回退值。 |
| `tls_alpn` | string[] | `[]` | AnyTLS 与 TCP 传输的 Trojan/VMess/VLESS 使用的裸 TCP TLS ALPN 名称。见 [`tls_alpn`](#tls_alpn)。 |
| `skip_cert_verify` | bool | `false` | 由 `allowInsecure`、`allow_insecure` 和 `insecure` 声明得出的证书校验旁路。见 [`skip_cert_verify`](#skip_cert_verify)。 |
| `ech_enabled` | bool | `false` | 存在静态 ECH 配置，或 `ech=1`/`true`。 |
| `ech_config` | string? | `null` | 来自 `ech_config` 或 `echconfig` 的 Base64 ECHConfigList。 |
| `ech_config_path` | string? | `null` | 结构化 loader 中指向 base64 ECHConfigList 的路径；不是分享链接查询参数。 |
| `reality_public_key` | string? | `null` | 来自 `pbk` 的 REALITY X25519 public key。 |
| `reality_short_id` | string? | `null` | 来自 `sid` 的 REALITY short ID。 |
| `reality_spider_x` | string? | `null` | 存储的 `spx`；REALITY 链接默认设为 `/`。 |
| `flow` | string? | `null` | VLESS `xtls-rprx-vision` 或 `xtls-rprx-vision-udp443`；Shadowrocket `xtls=2` 选择基础 flow。 |
| `network` | string? | `null` | 受支持协议的数据包 capability；与 VMess JSON `net` 等流传输字段独立。 |
| `ws_path` / `ws_host` | string? | `null` | WebSocket `path` 与 Host header。 |
| `ws_headers` | object | `{}`；输出时省略空 map | 附加的 WebSocket 升级 header。见 [`ws_headers`](#ws_headers)。 |
| `grpc_service` | string? | `null` | gRPC `serviceName` 或 `service_name`。 |
| `xhttp` | object? | 省略 | 扁平结构化输入与输出中的规范 XHTTP 参数。见 [`xhttp`](#xhttp)。 |
| `hy2_auth` / `hy2_obfs` | string? | `null` | Hysteria2 认证与 salamander 密码。 |
| `hy2_up_mbps` / `hy2_down_mbps` | u32? | `null` | Hysteria2 brutal 发送端与接收端带宽提示。 |
| `hy2_port_hopping` / `hy2_hop_interval` | string? / u64? | `null` | Hysteria2 `mport` 端口列表与 `mhop` 跳跃秒数。见 [`hy2_port_hopping` / `hy2_hop_interval`](#hy2_port_hopping--hy2_hop_interval)。 |
| `hy2_init_stream_recv_window` / `hy2_init_conn_recv_window` | u64? | `null` | Hysteria2 QUIC 接收窗口。见 [`hy2_init_stream_recv_window` / `hy2_init_conn_recv_window`](#hy2_init_stream_recv_window--hy2_init_conn_recv_window)。 |
| `hy2_disable_mtu_discovery` | bool? | `null` | Hysteria2 `disablePathMTUDiscovery`。 |
| `quic_mtu` | u16? | `null` | 来自 `mtu` 的 QUIC UDP 载荷大小。见 [`quic_mtu`](#quic_mtu)。 |
| `tls_pin_sha256` | string? | `null` | 来自 `pinSHA256` 或 `pin_sha256` 的叶证书 SHA-256 pin。见 [`tls_pin_sha256`](#tls_pin_sha256)。 |
| `tuic_uuid` / `tuic_password` | string? | `null` | TUIC 凭据；扁平字段须与 `username` / `password` 一致。 |
| `tuic_congestion` / `tuic_alpn` | string? | `null` | TUIC `congestion_control` 与逗号分隔的 `alpn`；见 [TUIC 与 Juicity](#tuic-与-juicity)。 |
| `tuic_init_stream_recv_window` / `tuic_init_conn_recv_window` | u64? | `null` | TUIC QUIC 接收窗口；有效默认值为 8 MiB / 8 MiB，conn 窗口自动增长至最多 32 MiB。 |
| `juicity_uuid` / `juicity_password` | string? | `null` | Juicity 凭据；扁平字段须与 `username` / `password` 一致。 |
| `anytls_password` | string? | `null` | 从链接 userinfo 复制的 AnyTLS secret。 |
| `anytls_min_idle_session` | usize? | `null` | 来自 `min_idle_session` 的空闲 session 目标下限；有效默认值 `0`，受八条 session 的池上限约束。 |
| `anytls_idle_session_check_interval` | u64? | `null` | 解析后的 `idle_session_check_interval` 秒数；当前运行时 janitor 周期仍固定为 30 秒。 |
| `anytls_idle_session_timeout` | u64? | `null` | 来自 `idle_session_timeout` 的空闲驱逐；有效默认值 30 秒。 |
| `mark` | u32? | `null` | 结构化模型中的出站 `SO_MARK`；不是 dae 分享链接查询参数。 |
| `tags` | string[] | `[]` | 分类元数据；不是 dae 分享链接查询参数。 |
| `subscription_id` / `group_id` | UUID? | `null` | 导入与运行时归属元数据。 |
| `created_at` / `updated_at` | datetime | 当前时间 | 运行时元数据。 |

节点自身校验要求非空名称、有效主机和显式非零 `port`。`address` 不会补充缺失的端口；仅提供 IPv6 地址时须显式设置 `host`。只有身份与注入规则完全一致的 `direct`/`block` 内置节点可省略 endpoint。

URL userinfo 中，Trojan、AnyTLS、VLESS 和 VMess 取 `user:pass` 的密码部分，没有冒号时取整个 userinfo。Hysteria2 保留完整的 `user:pass`，TUIC 和 Juicity 读取 `uuid:password`，SOCKS5 分别保留两部分。凭据会进行百分号解码，结果必须是有效 UTF-8。secret 中的字面 `:` 或 `@` 须写成 `%3A` 或 `%40`。

### `tls_alpn`

设置裸 TCP TLS ALPN 列表，用于 AnyTLS 以及 TCP 传输上的 Trojan、VMess、VLESS。每个名称须为 1–255 字节；默认 `[]`。

XHTTP 将省略或 `h2` 规范化为 `["h2"]`，包括 REALITY 和显式明文 H2。

其他协议、关闭 TLS 的上下文、REALITY、WS/gRPC 或 QUIC override 带有非空值时，honk 拒绝该节点。TUIC 保留自己的 `tuic_alpn`。

只有结构化输入与导入会设置该列表；XHTTP 以外，分享链接的 `alpn` 仅为兼容而接受，不会存储。

### `skip_cert_verify`

跳过证书校验。取值来自相互一致的 `allowInsecure`、`allow_insecure` 和 `insecure` 声明；默认 `false`。

分享链接的布尔值忽略首尾空白和 ASCII 大小写：

| 值 | 证书校验 |
| --- | --- |
| `true`、`yes`、`1`、`on` | 关闭 |
| `false`、`f`、`no`、`n`、`0`、`off`、`t`、`y` | 开启 |
| 空文本、未知文本或别名冲突 | 拒绝链接 |

**安全行为变更：** `yes` 和 `on` 以前保持校验开启，现在会关闭校验并产生 warning。升级前应检查这些链接，改用明确的 `true` 或 `false`。结构化布尔值仍须使用原生布尔类型，不转换字符串或数字。

### `ws_headers`

以 string map 形式添加 WebSocket 升级 header。名称规范化为小写；等值别名合并，冲突别名拒绝。最多 64 项，名称与值合计 16 KiB；控制字节拒绝。默认 `{}`，空 map 在输出时省略。

honk 拒绝以下保留名称：`host`、`connection`、`upgrade`、`sec-websocket-key`、`sec-websocket-version`、`sec-websocket-extensions`、`sec-websocket-accept`、`sec-websocket-protocol`、`content-length`、`transfer-encoding`。

honk 拒绝非 WebSocket 流传输上的非空 map。没有流传输的协议会丢弃该字段。`null` 无效。

只有订阅与结构化输入能提供 header；任何分享链接方言都不携带它们。

### `xhttp`

在扁平结构化输入与输出中保存规范 XHTTP 参数。`{}` 选择默认值；`null` 会被拒绝。

其他传输携带该对象时，honk 拒绝该节点。

参数名、范围与规范化见 [H2 上的 XHTTP](#h2-上的-xhttp)。

### `hy2_port_hopping` / `hy2_hop_interval`

选择 Hysteria2 端口跳跃：`mport` 端口列表与以秒为单位的 `mhop` 跳跃间隔。

`mport` 接受逗号分隔的端口和包含两端的范围，例如 `443,5000-5010`；空段跳过。重复端口或重叠范围会在拨号前拒绝该节点，包括 `443,443`；单端口集合仍然有效。官方客户端把跳跃端口写进地址部分（`:443,5000-6000`），效果与 `mport` 相同；两者同时指定会被拒绝，非法的内嵌列表在解析期报错。地址中的端口列表仍拒绝空项。

`mhop` 只接受无后缀的无符号整数秒：写 `30`，不能写 `30s`。`500ms` 和 `1s` 会被忽略，并产生不含原值的 warning。默认值为 `30`；配置值钳制到上游规定的最小值 `5`。

有效配置保留原写法。

```dae
node {
    hy2: 'hysteria2://secret@example.com:443?mport=20000-30000&mhop=30#hy2'
}
```

### `hy2_init_stream_recv_window` / `hy2_init_conn_recv_window`

以字节为单位覆盖 Hysteria2 的两个 QUIC 接收窗口。每个值为无符号整数。有效默认值为 8 MiB / 8 MiB，应用读取足够快时 conn 窗口自动增长到最多 32 MiB。

conn 窗口同时是每连接内存预算，因此慢消费者最多缓冲约 3 倍该值。

分享链接里格式错误或超出范围的值会被忽略，不会使链接被拒绝。

### `quic_mtu`

用 `mtu` 设置 QUIC UDP 载荷大小。取 1200 到 65527 之间的整数。通告的接收大小默认为 `1252`，范围相同。

发送 MTU 从 1200 开始，通过路径 MTU 发现增长。显式 `mtu` 同时设置初始发送 MTU 和发现上限。

大于 1252 时在常规 socket 上启用 GSO，但不包括 Hysteria2 混淆和跳端口 socket。`HONK_QUIC_GSO=0` 强制关闭 GSO。

分享链接里格式错误或超出范围的 `mtu` 会被忽略，不会使链接被拒绝。

```dae
node {
    quic_mtu: 'tuic://00000000-0000-4000-8000-000000000001:secret@edge.example:443?mtu=1300#quic-mtu'
}
```

### `tls_pin_sha256`

固定叶证书：匹配后，在任何 TLS 或 QUIC 协议上代替证书链与主机名校验。取 64 个十六进制字符，忽略冒号和空白。

链接来源为 `pinSHA256`，缺失时取 `pin_sha256`。默认 `null`。

honk 会拒绝空值或格式错误的 pin，不回退到 PKI。

```dae
node {
    hy2_pin: 'hysteria2://secret@example.com:443?pinSHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef#hy2-pin'
}
```

### 结构化 loader 兼容性

TOML、YAML 与 JSON 继续使用旧的扁平节点 key。加载时只读取所选 `protocol` 的字段。其他协议遗留的非默认字段会被移除，但不会拒绝节点；一条 warning 列出所有移除的字段名。例如，`ss` 节点上的 `tls: true` 会被忽略并产生 warning，不会开启 TLS。

VMess 和 VLESS 从 `password` 读取用户 UUID；`id` 是节点身份，不是凭据。

对 Trojan、VLESS、Hysteria2 和 AnyTLS，`username` 不是凭据别名。缺少该协议实际使用的凭据字段时，单独提供的 `username` 会被移除，并触发一条针对性 warning；旧版行为和 ID 保持不变。

所选协议使用的值仍会正常解析与校验。honk 自身的输出仍可安全地再次导入。启用 `store_subscribe` 时，原始订阅正文只在解析成功后持久化；被拒绝的刷新不会覆盖上一份有效正文。

VLESS 扁平输入已删除 `vless_mode`，改用 `network` 表示数据包权限、`packet_encoding` 表示回退、`multiplex` 表示 carrier 选择。只要原始输入中出现该字段，节点就会被拒绝，包括值为 `null` 或任一旧版已知拼写。唯一保留的 `vless_mode: "legacy"` 是非 VLESS 扁平格式序列化时使用的兼容占位字段。它不配置 VLESS，非 VLESS 行为与身份保持不变。

扁平凭据别名在移除不兼容字段前比较：

| 协议 | 必须一致的别名 |
| --- | --- |
| Hysteria2 | `hy2_auth` / `password` |
| TUIC | `tuic_uuid` / `username`；`tuic_password` / `password` |
| Juicity | `juicity_uuid` / `username`；`juicity_password` / `password` |
| AnyTLS | `password` / `anytls_password` |

缺失或 null 表示未提供。已提供的字符串须逐字节一致，空字符串和首尾空格也参与比较。空凭据仍须满足对应协议的要求。扁平凭据字段仍须使用字符串；数字转换仅适用于订阅导入。

新增 `tls_alpn` 字段不沿用旧字段剥离规则；见 [`tls_alpn`](#tls_alpn)。

VMess 加密方式接受 `auto` 和 `aes-128-gcm`，忽略大小写并存储为小写；空的可选声明使用默认值。所有加密方式来源必须在赋值前比较一致，包括：JSON 里的 `scy` 和 `security`；编码分享链接里的 `encryption`、`scy`，以及表示加密方式的 `security`；订阅支持的加密方式别名。值不受支持或彼此冲突时，节点被拒绝。编码分享链接中的 `security=none` 和 `security=tls` 仍控制 TLS，不表示加密方式。记录格式的位置参数仍是低优先级备用值。

TUIC 分享链接和订阅的转发模式只接受未指定、空值或 `native`。即使存在有效别名，不支持的 `udp-relay-mode`/`udp_relay_mode` 仍会使条目被拒绝。

| Hysteria2 来源 | 混淆规则 |
| --- | --- |
| 分享链接 | 只接受小写的 `obfs=salamander`。未指定或空值关闭混淆；未知名称（包括 `SALAMANDER`）会被拒绝。缺失或空密码关闭 Salamander。重复密码声明与 `obfs-password`/`obfs_password` 须一致。 |
| Clash | 接受不区分大小写的 Salamander，要求非空白密码。 |
| sing-box | 要求小写类型；拒绝已配置有效字段但缺少类型或密码的混淆对象。 |

时长转换会拒绝负数、非有限值和超出范围的值，不再截断为零或上限。结构化订阅的秒数字段先把整数毫秒向上取整，`500ms` 和 `1000ms` 都变成 `1`，零仍为零，然后再比较别名。Hy2 分享链接的 `mhop` 遵循 [`hy2_port_hopping` / `hy2_hop_interval`](#hy2_port_hopping--hy2_hop_interval)。AnyTLS 分享链接保留自己的秒数解析规则；dae 毫秒字段仍只接受裸数值、ms 或 s，不足一毫秒的部分截去。

sing-box 的 `hop_interval`、`idle_session_timeout` 和 `idle_session_check_interval` 保留原生数字零，缺失或 null 仍表示未提供。Hysteria2 记录会将每个 `mhop`、`hop-interval` 和 `hop_interval` 值转换为秒后比较；即使存在有效别名，冲突或无效值仍会使记录被拒绝。

出站构造函数对直接构造的节点使用同一个检查函数。

普通分享链接、VMess JSON、独立扁平 Node 反序列化和订阅导入都在构造完成时校验节点。

- 使用 UUID 的协议要求有效 UUID。不支持的加密方式、传输类型、数据包 capability、flow、ALPN 上下文或端口跳跃集合，会在派生身份前被拒绝。
- 未启用 VLESS Encryption 时，Vision 要求 TLS 或 REALITY。直接构造的节点也不能带空 SNI、flow 或 network，这些值本应由适配器规范化掉。
- 订阅格式特有的非空密码要求仍由对应适配器执行。SOCKS 可选认证及 handler 支持的空凭据仍然有效。
- 无效 dae 节点行和订阅条目仍按原策略跳过，有效条目保留。
- 仅解析 Config 片段的 API 仍不执行整份配置 admission，但片段内的无效节点现在会在构造时被拒绝。
- 独立反序列化保留传入的 ID；运行时身份 admission 是另一项检查。

直接调用 `Node::validate()` 与适配器完成构造时使用相同的固定脱敏错误。校验错误不包含传入的节点名称或凭据值。

详细的 Config 加载接口以及配置／注册表 admission 会保留节点校验给出的字段和原因，并补上从 1 开始的原始节点序号，不再用笼统的无效节点错误代替。凭据冲突会指向规范别名字段，不输出任何一个值。独立的 `NodeSeed` 和 Node 反序列化仍返回脱敏的通用 serde 错误。

VMess JSON 使用 `net: "ws"` 时，缺失或为空的 `host` 会让 WebSocket 握手使用节点服务器主机；提供非空 `host` 时仍以它为显式覆盖值。

## `node {}` 声明

每个非注释行是一个分享链接。标签与链接都可加引号或裸写。两种写法都见[示例](#示例)。

配对引号之外，如果 `#` 位于语句开头，或紧跟 ASCII 空格、制表符，就表示注释开始。

| `#` 的位置 | 处理结果 | 示例 |
| --- | --- | --- |
| 裸链接的空白之后 | 开始注释 | `ss://…#hk1 # note` 保留名称 `hk1`。 |
| 紧接裸链接中的文本 | 保留为链接数据 | `ss://…#hk2#note` 保留 `hk2#note`。 |
| 紧接链接的结束引号 | 按兼容规则开始注释，并在该字节处产生 `legacy-glued-hash` warning | `'ss://…#hk1'#note` 保留 `hk1`。 |

注释前应留空白。结束引号后出现其他文本时，honk 跳过该条目，并产生 `trailing-entry-text` 诊断。引号错误与块结构规则见[方言参考](./dialect.md)。

解析器同时接受带标签和不带标签的条目。非空 dae 标签就是节点名称；没有标签时，URL 链接依次取非空的解码后片段、非空的 `remark` 查询值、`{scheme}-{host}`。

VMess JSON 的 `ps` 备注缺失或为空时，节点先以 `vmess-{host}` 通过校验；非空 dae 标签随后替换该名称。

确定标签与链接的结束引号位置时，反斜杠转义下一个字符；解析后的文本保留原始转义序列。

解析器按以下规则处理无效条目：

| 输入 | 处理结果 |
| --- | --- |
| 协议已识别但格式错误的链接 | 丢弃条目并产生 warning。已知无效字段保留具体的安全原因和模式路径；未知解析失败使用 `invalid-node-entry`。 |
| 未知协议或已删除的 VLESS `vless_mode` | 拒绝配置。 |
| 独立的 `mux:` 或 `mux=` 行 | 拒绝配置。VLESS 数据包与 carrier 选项须使用链接中的精确查询参数 `packetEncoding=`、`mux=` 和 `udp=`。 |

诊断会保留原始节点条目的序号和来源位置，但不含原始链接、值或节点名称。返回数据的接口只把诊断交给调用方，不写日志；普通接口只报告一次。

被接受的链接只会产生 `legacy-*` 代码的 warning；节点条目上出现其他 warning，就说明解析器已丢弃该条目。客户端可以用 `syntax` 模式校验单条 `node { name: 'link' }` 声明，只看诊断代码就能区分被跳过和被接受的链接。

旧版 `ss://base64(method:password@host:port)` 格式把解码后的凭据当作字面值，不再做 URL 解码：`%20` 保持为 `%20`，`?`、`/`、`#`、`:` 和 `@` 仍是密码字符。凭据与 endpoint 由最后一个 `@` 分隔，userinfo 本身也可以是 `base64(method:password)`。解码后的载荷缺少 `@`，或凭据拆不出方法和密码时，解析失败。URL userinfo 格式仍会对凭据做百分号解码。endpoint、路径、查询参数和片段继续按 URL 处理，查询参数包括 `/?plugin=...`。

## 节点身份

`Node::derive_id()` 是唯一的身份派生路径。它对以下材料计算 UUID v5：

```text
protocol|host|port|credential-fingerprint|dial-shape
```

凭据指纹遵循各 handler 的字段优先级。拨号形态包含：

- `sni`、传输方式和 WebSocket/gRPC 形态；
- Hysteria2 混淆、REALITY 参数和 `flow`；
- 有效的 VLESS TLS 安全配置、UDP 权限、回退编码和多路复用路径。

明文 VLESS 与 TLS 使用不同身份。REALITY key 选择认证传输，不受冗余 TLS 标志影响。

| 结构化 `tls_alpn` | 身份派生方式 |
| --- | --- |
| 非空 | 以基础 ID 为命名空间、JSON 元组 `["tls-alpn", <ordered list>]` 为名称派生子 UUID v5。这将 ALPN 与任意凭据文本分离。 |
| 空值 | 保留基础 ID。 |

调优参数与显示元数据不参与派生；例外是改变物理路径的 VLESS 多路复用上限。

XHTTP 身份还包含有效的 TLS/明文安全配置，以及全部已接受的规范 XHTTP 参数，包括 header、填充和 POST 间隔。输入别名、header 名称大小写与等价范围表示会在派生前规范化。新增 XHTTP 不改变已有 TCP/WS/gRPC 身份材料。

WebSocket 的非空规范 header map 也参与身份派生。header 名称大小写、插入顺序与等值别名不改变身份，值不同则改变身份；省略或空 map 保留原有身份。

拼接前，每个原始凭据字段、拨号形态字段和有效的 `host` 值都会将 `\` 转义为 `\\`，将 `|` 转义为 `\|`。拼接后的指纹不再转义。通过 `Config::validate` 的节点，不同身份字段必然产生不同的 hash 输入。完整配置校验拒绝的节点不受此保证，即使 `Node::from_share_link` 能为其派生 ID。

**破坏性升级：** 所有成功重新派生身份的 VLESS 节点都会获得新 ID，包括从未填写 `vless_mode`、关闭 UDP 或设置 ALPN 的节点。以 ID 为 key 的健康、预热及 session 状态会重新建立。同一次迁移里，其他协议只在一种情况下改变 ID：上文用 `|` 拼接的身份字段中含有 `|` 或 `\`。ALPN 使用独立的 JSON 子 UUID 步骤，因此只有 ALPN 含这两个字符时，不会触发该变化。

**逐包带地址的 UDP 分帧：** 有效 UDP 路径在 53、443 或 54 端口使用 UoT v2 或 H2MUX 的 VLESS 节点会再次获得新 ID。这包括 `packetEncoding=uot-v2`、`mux=h2mux`，以及回退到这两条路径的池，因为这些路径现在逐包携带地址。

Auto、native、XUDP、Mux.Cool 与关闭 UDP 的节点 ID 不变。直接选择节点的 Selector 以节点 ID 为 key，ID 改变时该选择丢失。结构化 JSON/YAML/TOML 配置若在代理组的 `nodes` 中引用旧 ID，加载时会关联到新 ID。

不要为了迁移 ID 而删除缓存。持久化已启用且可读时：

| 状态 | 节点 ID 变化的影响 |
| --- | --- |
| 直接选择节点的 Selector 固定选择 | 以节点 ID 为 key，因此丢失。 |
| 选择子组的 Selector 固定选择 | 以组名为 key，因此保留。 |
| 有效且不超过 24 小时的 TCP-v4 延迟样本 | 启动时按节点名关联到新 ID。样本只用于排名，不恢复存活状态。改名或重复名称不能保证恢复同一个叶节点。 |

就绪流原本就随所属 generation 退役。`name`/`subtag` 筛选语义不变。

只要可拨号 endpoint 和拨号形态不变，身份在改名、reload 和订阅刷新后都保持稳定。配置与运行时组装会拒绝重复的派生 ID。`Node::default()` 的 ID 为 nil；构造路径会派生 ID，出站运行时注册表会拒绝任何传入的 nil ID。

## 协议

| 协议 | 别名 | TCP | UDP | 说明 |
| --- | --- | --- | --- | --- |
| `ss` | `shadowsocks`，仅限 Clash 与 sing-box `type` | 是 | 是 | AEAD 与 Shadowsocks 2022 |
| `trojan` | — | 是 | 是* | TLS；TCP/WS/gRPC/XHTTP 传输 |
| `vmess` | — | 是 | 否 | AEAD；TCP/WS/gRPC/XHTTP 与 REALITY；handler 需要 `rprx` |
| `vless` | — | 是 | 可配置* | 原生 UDP、UoT v2、H2MUX、XUDP、Mux.Cool、Encryption、REALITY 与 Vision；handler 需要 `rprx` |
| `socks5` | — | 是 | 是 | CONNECT 与 UDP ASSOCIATE |
| `hysteria2` | — | 是 | 是 | QUIC/H3、salamander、brutal/BBR 与端口跳跃 |
| `tuic` | — | 是 | 是 | QUIC 上的 TUIC v5 |
| `juicity` | — | 是 | 是 | QUIC 上的 Juicity |
| `anytls` | — | 是 | 是* | 多路复用 TLS session 与 UoT v2 |
| `direct` | — | 是 | 是 | 保留的内置直连出站；没有分享链接协议方案 |
| `block` | — | 否 | 否 | 保留的内置拒绝出站；没有分享链接协议方案 |

`network` 可独立于流传输方式关闭 Trojan、AnyTLS 和 VLESS 的数据包拨号。VMess UDP 尚未实现。

| 协议 | UDP 行为 |
| --- | --- |
| AnyTLS | 拒绝超过 16 KiB 的载荷，与 anytls-go 0.0.13 的中继缓冲区一致。非连接模式 UoT v2 逐数据报携带目的地和服务端的真实源地址。一条流服务一个客户端源的全部目的地；未经请求的回复也保留真实源地址。 |
| Trojan | 每个客户端源使用一条 associate 流承载全部目的地，返回每个回复的真实源地址。配合服务端可获得 EIM/EIF 行为。各目的地共享队头阻塞，且流故障会影响全部目的地。 |

SOCKS5 UDP ASSOCIATE 为每个客户端源保持一条控制 TCP 连接和一个中继 socket，该源的所有目的地共用它，并返回每个应答头中的真实远端对端。从未联系过的对端能否到达客户端取决于服务器：Dante 默认的 `udp.connectdst: yes` 仅在只使用过单一目的地期间才会连接其出站 socket。

以下支持 UDP 的代理协议实现 UDP 全锥形：一个客户端源的全部目的地共用一个 association，每个回复都带上真实的远端地址。

- Hysteria2、TUIC、Juicity、SOCKS5，以及 AEAD 与 2022 两种 Shadowsocks；
- Trojan、AnyTLS；
- VLESS XUDP/Mux.Cool、UoT v2、H2MUX。

VLESS 原生 UDP 是例外，其流只指定一个目标。这包括显式 `native`，以及未启用 Vision 时 UDP/53 和 UDP/443 上的 `auto`。

来自此前未联系过的对端的回复，会保留该对端的源地址。这实现了 RFC 5780 全锥形的客户端部分。服务端还须为每个 association 使用一个未连接 socket，并转发任意对端的回复。honk 无法绕过服务端过滤；`direct` 流量遵循宿主机自身的 NAT。限制如下：

- 按域名拨号的流会为每个原始目的地各保留一条 association，回复也投影回该目的地，因此得不到与 endpoint 无关的映射。
- 一个源的各目的地只在同一节点上共用 association。组可能把新目的地或 Score 试探流送到另一节点，那里有自己的映射。
- 协议回退路径不由 H2MUX 或 Xray UDP 池承载。未启用 Vision 的节点里，`packetEncoding=auto` 在 53 和 443 端口使用已连接的原生 UDP。这类流只指定一个目标，所以这两个端口无法实现全锥形。Vision 节点和其他端口使用 Single XUDP。设置 `packetEncoding=xudp`，可以在原本走原生路径的地方显式启用 Single XUDP。
- Single XUDP 未设为默认值，原因是测得的性能成本。在 loopback 环境中对 sing-box 1.12.4 使用不限速的 1200 字节数据报时，吞吐约为原生路径的一半。每 MB 客户端 CPU 消耗是原生路径的 1.9–3.3 倍，p99.9 尾延迟也更高。中位数与冷启动延迟没有可测量差异。XUDP 还会拒绝超过 7,526 字节的数据报。
- 当 VLESS 源在不同端口上选了不同路径时，即使在同一节点上，也会按所选路径各有一条 association。例如 Xray UDP 池加上 UDP/443 的 `skip`，443 就走协议回退，而不是池。
- Trojan、Juicity 和 AnyTLS 把一个源的全部目的地放在一条可靠流上。某个目的地停滞会拖慢同流的其他目的地，写失败会终止所有目的地。数据报 carrier 没有这个问题，例如 Hysteria2、TUIC、Shadowsocks 和 SOCKS5。
- 53 端口的流不会在数据路径里发布客户端回复的 framing，因此针对 53 端口流的主动回复要靠宿主机转发。
- 所有客户端源共用一个进程级的外来回复 socket 池，每个对端地址一个 socket。上限按 endpoint 容量算，每个 endpoint 对应七个 socket。达到上限后，新的外来对端会淘汰最久未使用的 socket。清理任务会关闭超过一个 NAT 超时时间未使用的 socket。
- 一个源最近关闭的 64 个目的地，其回复会被丢弃，honk 不会把它们当作外来回复投递。连接关闭和不可用节点清理都算在内。重新绑定会把目的地移出列表；第 65 次关闭会移除最早的记录。空闲超时和传输错误不加入记录，因此只要源仍存在，这些对端仍可发送外来回复。仍绑定的流不受影响。
- VMess 没有 UDP 后端。

在支持 `network` 的协议中，扁平结构化输入接受逗号分隔的 `tcp`/`udp`，忽略各项首尾空白和 ASCII 大小写。`tcp` 关闭 UDP；`udp` 与 `tcp,udp` 都允许 UDP。空文本或纯空白规范化为未指定，保留协议的默认 capability。`quic` 等未知值，或非空列表中的空项，会使节点被拒绝。该字段只控制 UDP admission；`udp` 不会额外禁止 TCP。

未启用 Cargo feature `rprx` 时，VMess 与 VLESS 节点仍能解析，但不会注册 handler，拨号以 `No handler for protocol` 失败；未启用该 feature 的正常构建不会分配 VLESS 池或 carrier 信号量。`honk-core` 与 `honk-tool` 默认启用 `rprx`。

`honk-core` 在启动和 reload 时注入具有固定保留 ID 的 `direct` 与 `block`。用户节点不得使用这些名称或协议。组不会自动从节点池纳入它们；只有精确匹配名称的 `filter: name(direct)` 或 `name(block)` 才会选中，见[组参考](./groups.md#过滤解析)。

## 协议参数

### Shadowsocks 2022

传统 AEAD 方法 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305` 及其别名 `chacha20-poly1305` 使用普通密码。方法名称不区分大小写；其他方法会在构造 handler 时失败。Shadowsocks 2022 方法使用标准 Base64 PSK：

| 方法 | Base64 解码后的 PSK 长度 |
| --- | --- |
| `2022-blake3-aes-128-gcm` | 16 字节 |
| `2022-blake3-aes-256-gcm` | 32 字节 |
| `2022-blake3-chacha20-poly1305` | 32 字节 |

key 长度错误或不是 base64 时，handler 构造失败。

AES 2022 方法接受在 `password` 中用冒号分隔的 PSK 链，从首个身份 key 排到用户 key。每个 key 解码后的长度都须符合该方法。`2022-blake3-chacha20-poly1305` 只接受一个 PSK；使用 key 链会报 `Shadowsocks 2022 EIH support only available in AES ciphers`。

UDP 重放保护为当前 session 和前一个服务端 session 分别保留一个窗口。前一个 session 连续 60 秒没有活动后，才接受第三个 session。只有认证和响应头校验成功后，honk 才修改接收 session 状态；无效包不能重置重放历史。

Shadowsocks UDP（传统 AEAD 与 2022）为每个客户端源的所有目的地只保留一个面向服务端的 socket；2022 在这些目的地之间共用一个 session ID、一个递增的包计数器和一组重放窗口。

回包返回服务端报告的真实远端地址，因此只要服务端转发，从未联系过的主机也能到达客户端；声明为非拨号域名的回包会被丢弃。

与拨号目标不同的名称从不逐数据报发送。真实服务端，例如 sing-box 1.12.4，会按首个目的地固定 outbound 形态；之后出现不同名称就会终止 association，因此这类名称以数值目标发出。

### 流传输

支持流传输的分享链接通过 `type=` 或其别名 `network=` 选择传输方式：

| 值 | 传输方式 | 字段映射 |
| --- | --- | --- |
| 空文本或 `tcp` | 裸 TCP | — |
| `ws` | WebSocket | `path` → `ws_path`；`host` → `ws_host`；升级 header 没有分享链接字段 |
| `grpc` | gRPC | `serviceName` 或 `service_name` → `grpc_service` |
| `xhttp` 或输入别名 `splithttp` | XHTTP | 见下文的 H2 兼容范围。 |

`type`、`network` 与兼容的 `obfs` 传输选择声明必须一致，重复的选择参数也须一致。`h2`、`kcp` 等不支持的名称在解析时被拒绝。`sni` 独立生效。除 XHTTP 外，分享链接的 `alpn` 仍只为兼容而接受，不会存储。

XHTTP 以外，重复的查询 key 取最后一个值，`serviceName`、`pinSHA256` 和 `ech_config` 分别优先于 `service_name`、`pin_sha256` 和 `echconfig`。TLS、SNI、证书校验与 VMess 加密方式的声明仍须一致。编码地址形式的 VMess 拒绝值不同的重复 key。XHTTP 要求重复的 `host`、`path`、`mode`、`alpn` 和 `extra` 一致。

WebSocket 路径和 gRPC 服务名里无法直接放进 URI 的字符会做百分号编码，例如空格和非 ASCII 文字。已有的 `%XX` 转义和查询分隔符保持不变；查询值里的空格和非 ASCII 文字也会编码，例如 `?tag=a b` 变成 `?tag=a%20b`。XHTTP 沿用下文的转义规则。

```dae
node {
    trojan_ws: 'trojan://secret@example.com:443?type=ws&sni=example.com&host=example.com&path=/path#trojan_ws'
    vless_grpc: 'vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=grpc&serviceName=GunService#vless_grpc'
}
```

VMess 接受 v2rayN Base64 JSON（`net`、`host`、`path`、`sni`），也接受 Shadowrocket 的 `vmess://base64(auto:UUID@host:port)?...` 地址部分形式。后者映射 `tls`、`peer`/`sni`、`obfs=websocket|grpc`、`obfsParam`、`path` 和 `remark`；接受 standard / URL-safe Base64，有无填充均可。编码地址部分的 VMess 要求 AEAD 认证及 `auto`/`aes-128-gcm`；不支持的加密方式和 REALITY 参数会被拒绝，不会静默替换。

编码地址可以省略 `auto:`，规则与 [Shadowrocket VLESS](#shadowrocket-vless) 相同。`alterId` 只能省略或为 `0`。

v2rayN JSON 形式要求 `add`、UUID 格式的 `id`，以及 1 到 65535 之间的 `port`，端口可写成数字或数字字符串。只有 `"tls":"tls"` 开启 TLS。`aid` 会被忽略；认证始终使用 AEAD。

```json
{"add":"edge.example","port":443,"id":"00000000-0000-4000-8000-000000000001","ps":"vmess-tls","tls":"tls"}
```

用 Base64 编码整个对象，接在 `vmess://` 之后。Base64 后再接 `?query` 或 `#fragment` 会使链接无效；节点名称用 `ps` 或 dae 标签指定。

VMess JSON 的 `net` 和 Shadowrocket 传输参数只选择流传输方式，不再写入数据包网络 capability 字段。未指定数据包限制时，对有 UDP 后端的协议保留原有默认 UDP capability，VMess 没有 UDP 后端。已有的有效空传输字段也保留原始写法。非 XHTTP 传输仍沿用旧行为，忽略无关的导出字段 `mode`、`extra`；这些字段不会选择 XHTTP。传输声明显式冲突时仍会拒绝节点。

VLESS 支持 TCP+REALITY+Vision、TCP+REALITY、TCP+WS、TCP+WS+TLS、TCP+gRPC 与下述 H2 XHTTP 配置方案。未加密 Vision 的 direct-copy 要求使用 TLS 1.3 或 REALITY 的裸 TCP，不能使用 WS/gRPC/XHTTP；加密 Vision 遵循下文的组合规则。

Vision 添加上行填充并移除下行填充。上行 Direct 要求在第一个完整的应用数据记录前已观察到符合条件的 TLS 1.3 ServerHello；出现早期数据，或检查预算耗尽时仍未决定，都会改用 End 结束填充并保留外层传输。两个方向各自独立切换。参见 [Vision 支持边界](../design/outbound.md)。

#### H2 上的 XHTTP

Trojan、VMess 与 VLESS 共用该出站传输。VMess 仍仅支持 TCP。本实现只支持 H2 上的 XHTTP，不提供完整的 Xray 或 mihomo 配置兼容性。

| 安全模式 | H2 要求 |
| --- | --- |
| 普通 TLS | 必须协商 `h2`。 |
| 认证后的 REALITY | 按传输约定选择 H2，即使服务端未返回 ALPN。 |
| 显式明文 | 对端必须支持 H2。 |

不提供 H1/H3 回退。

```dae
node {
    xhttp: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&type=xhttp&mode=stream-up&path=%2Fxhttp%2F&sni=edge.example&alpn=h2#xhttp'
}
```

`mode` 默认为 `auto`；空字符串也表示 `auto`：

| 模式 | 请求形式 |
| --- | --- |
| `auto` | 普通 TLS 或明文选择 `packet-up`，REALITY 选择 `stream-one`。 |
| `packet-up` | 有序的有限长度 POST 正文，以及同一 session 的 GET。 |
| `stream-up` | 独立的流式 POST 和 GET。 |
| `stream-one` | 单个双向 POST。 |

VMess JSON 在 `net=xhttp|splithttp` 时也接受 v2rayN 的 `type` 作为模式字段。显式 `mode` 与 `type` 必须一致。JSON 的 `fp`、`insecure` 和 `allowInsecure` 与旧有 VMess 传输一样，接受但忽略。证书校验保持开启。

URI、VMess JSON 和 Mihomo 导入会去除 ALPN 字符串及列表成员的首尾空白，再忽略空值。未指定时选择 `h2`。即使 header 伪装为 gRPC/SSE，正文仍是原始代理字节。

| XHTTP 请求字段 | 规范化与校验 |
| --- | --- |
| `path` | 默认为 `/`。在查询部分之前补齐首尾斜杠，不清理点路径段或百分号转义。 |
| HTTP `host` | 独立于拨号地址和 SNI。须为 `cdn.example:8443` 这样的 authority，不含 scheme、路径、userinfo 或空白。为空或未指定时依次回退到 SNI、服务器主机名。 |
| 路径部分 | 解码后的字面值。发送时按 Xray 规则将字面 `%` 转为 `%25`，并对空格、`<`、`>` 和 UTF-8 字节进行百分号编码。 |
| 查询部分 | 原样发送，按原始 HTTP URI 语法校验。字面空格须预先进行百分号编码。 |
| 路径与查询整体 | 最多 16 KiB。任何位置的控制字节、DEL 和 `#` 均被拒绝。 |

URI 分享链接参数只解码一次，因此 `path=%2Fxhttp%2F` 发送 `/xhttp/`；Mihomo 路径使用 YAML 字符串字面值。

直接构造节点时，必须先调用 `normalize_stream_transport()`，再派生 ID。不可变 admission 会拒绝非规范 XHTTP 名称、选项和 ALPN。

URI `extra` 接受百分号编码的 JSON 对象，可含 `host`、`path`、`mode`，其含义、规范化和校验与顶层字段相同，且只支持下表列出的选项。Extra 中的请求字段只填充缺失的顶层字段；显式顶层字段即使为空也优先。重复的 URI extra 仅在有效规范选项一致时合并。

VMess JSON 的 `extra` 可以是对象，也可以是内容为同一 JSON 的字符串。URI 中的 `extra` 是经过百分号编码的对象。下面的对象设置一个 header、一个填充范围和独立的下载 endpoint：

```json
{
  "headers": {"X-Client": "honk"},
  "xPaddingBytes": "100-200",
  "downloadSettings": {
    "address": "download.example",
    "port": 443,
    "network": "xhttp",
    "security": "tls",
    "tlsSettings": {"serverName": "download.example", "alpn": ["h2"]},
    "xhttpSettings": {"path": "/download/", "host": "cdn.example"}
  }
}
```

压缩并百分号编码后，得到以下链接：

```dae
node {
    xhttp_split: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&type=xhttp&extra=%7B%22headers%22%3A%7B%22X-Client%22%3A%22honk%22%7D%2C%22xPaddingBytes%22%3A%22100-200%22%2C%22downloadSettings%22%3A%7B%22address%22%3A%22download.example%22%2C%22port%22%3A443%2C%22network%22%3A%22xhttp%22%2C%22security%22%3A%22tls%22%2C%22tlsSettings%22%3A%7B%22serverName%22%3A%22download.example%22%2C%22alpn%22%3A%5B%22h2%22%5D%7D%2C%22xhttpSettings%22%3A%7B%22path%22%3A%22%2Fdownload%2F%22%2C%22host%22%3A%22cdn.example%22%7D%7D%7D#xhttp-split'
}
```

| Xray extra key | flat `xhttp` 字段 | 默认值 | 支持边界 |
| --- | --- | --- | --- |
| `headers` | `headers` | `{}` | 最多 64 项，名称和值总共不超过 16 KiB |
| `xPaddingBytes` | `x_padding_bytes`；别名 `x-padding-bytes` | `100-1000` | 1–8192 字节 |
| `noGRPCHeader` | `no_grpc_header`；别名 `no-grpc-header` | `false` | 布尔值 |
| `scMaxEachPostBytes` | `sc_max_each_post_bytes`；别名 `sc-max-each-post-bytes` | `1000000` | 1–16777216 字节 |
| `scMinPostsIntervalMs` | `sc_min_posts_interval_ms`；别名 `sc-min-posts-interval-ms` | `30` | 0–60000 ms；零关闭最小间隔 |

kebab-case 别名只适用于扁平 `xhttp` 对象。

范围接受无符号整数、`"30"` 这样的数字字符串、`min-max` 字符串或 `{"min":N,"max":N}`。空字符串恢复上表中的默认值。header 名称规范化为小写，等价别名合并；冲突别名、控制字符，以及传输层管理的 header，例如 `host`、`content-type`、`content-length`、`referer`、hop-by-hop header 和 trailers，都会被拒绝。URI/VMess extra JSON 在转为 map 前拒绝重复成员。Padding 始终启用。这些范围是本地安全上限，不保证每个对端或 CDN 都接受。

未配置 `User-Agent` 时，XHTTP 请求使用 Xray 默认的 Chrome `fetch()` header：

| header | 行为 |
| --- | --- |
| Windows Chrome `User-Agent` 与 `Sec-CH-UA` 品牌 | 主版本遵循 [Xray 的估算](https://github.com/XTLS/Xray-core/blob/836a6fed385b902e437dde43ee9adc82d23a5303/common/utils/browser.go#L26-L34)，随机延迟在每个进程内只抽取一次。 |
| `Sec-CH-UA-Mobile`、`Sec-CH-UA-Platform`、`DNT`、`Accept-Language`、`Sec-Fetch-Mode: cors`、`Sec-Fetch-Dest: empty`、`Sec-Fetch-Site: same-origin` | 与 Xray 一样，覆盖已配置的同名值。 |
| `Accept`、`Priority`、`Cache-Control`、`Pragma` | 仅在未配置时补充。 |

CDN 的机器人过滤规则可能拒绝不含这些 header 的 XHTTP 请求。配置 `User-Agent` 后，不再添加这组默认 header，而是原样发送配置值。Xray 的 `chrome`、`firefox`、`edge`、`golang` 关键字不会被解释。这些 header 只在运行时添加，不改变节点身份。

存在 `extra` 时，顶层 `host`、`path` 和 `mode` 仍优先。

| 兼容输入 | 处理方式 |
| --- | --- |
| URI `fp` | 接受但忽略；指纹由全局 TLS 模式控制。 |
| 值为 `none` 或空值的 `headerType` / `quicSecurity`；空 `serviceName` | 接受但忽略，因为 XHTTP 自行管理 HTTP 分帧。 |
| `headers` 查询参数 | 仅接受只有 `Referer` 成员的 JSON 对象，随后丢弃。Xray 的填充会覆盖该 header，因此不会发送。 |
| `allowInsecure`、`allow_insecure`、`insecure` | 保留共用 TLS 语义；别名必须一致。 |
| Extra 中的 `noSSEHeader`、`scMaxBufferedPosts`、`scStreamUpServerSecs` | 仅作用于 Xray 服务端；检查类型后丢弃。 |
| `xmux` | 仅在全为零或恰好等于 Xray 的缺省 XMUX 填充值时接受并丢弃：`maxConcurrency` 为 1、`hMaxRequestTimes` 为 600–900、`hMaxReusableSecs` 为 1800–3000，其余为 0。其他值拒绝。 |

未知或不支持的参数会使整个节点被拒绝，即使值为 null 或空值也不例外。这包括其他 session、序号或载荷位置、自定义上传方法和填充混淆配置。Mihomo 订阅使用对应的 `xhttp-opts` 字段。官方 sing-box 和客户端记录格式仍不支持 XHTTP 传输。

Extra 中的 `downloadSettings` 是 Xray StreamConfig，用于把 GET 发往独立 endpoint。下载端不继承上传端的任何设置，包括 header。因此，即使上传端配置了 `User-Agent`，下载 GET 仍携带默认的 Chrome `fetch()` header。

| 下载设置 | 要求或映射 |
| --- | --- |
| 必需字段 | `address`、`port`、`network: xhttp`、`security: tls`。 |
| `address` | 去除首尾空白并转为小写。必须是主机名或 IPv4 字面量，因为拨号时按文本与端口拼接。 |
| `tlsSettings.serverName`、`xhttpSettings.path`、`xhttpSettings.host` | 映射到 `xhttp.download.server_name`、`path`、`host`。扁平 `xhttp.download` 对象还包含 `address`、`port` 和默认值为 `100-1000` 的 `x_padding_bytes`。 |
| 顶层或 `tlsSettings` 的 ALPN | 只能缺省或为 `h2`。 |
| `tlsSettings.fingerprint`、`xhttpSettings.mode` | 检查后忽略。 |
| 值为 null 的已知成员 | 视为缺省。 |
| HTTP 主机名 | 依次回退到下载端的服务器名称、地址。 |

下载端始终校验 TLS。上传端的证书固定、不安全校验、ECH 和 REALITY 设置不作用于下载端。`allowInsecure: true`、REALITY、`sockopt`、下载端 `headers` 或 `extra`，以及其他任何成员都会使节点被拒绝。下载设置也不能与 `stream-one` 模式或 REALITY 上传端组合。

每个对端各有独立的 carrier 池。因此，Trojan 或 VMess 节点最多可持有四条不占 VLESS 进程 permit 的可复用 carrier。延迟探测与 `honk-tool sub` 的地址族列只反映上传 endpoint。

XHTTP 禁止 TCP Mux.Cool，但保留 UDP-only XUDP carrier。已有 VLESS UDP 权限、数据包编码与 UDP/443 策略不变。Packet-up 的协议里没有表示上传 EOF 的标记：shutdown 会刷新已经接受的上传字节，并保留 GET 等待应用的最终回复；只有关闭逻辑流才结束该请求。


### Shadowrocket VLESS

统一解析器接受 `vless://base64(auto:UUID@host:port)?...`，以及省略 `auto:` 的编码地址部分。支持 standard / URL-safe Base64，有无填充均可；IPv6 endpoint 必须使用方括号。编码内容必须包含有效 UUID 和显式非零端口。格式错误的编码地址部分会被拒绝，不再误当作主机名或显示名称。

查询参数映射遵循 [Shadowrocket 导出器](https://github.com/cedar2025/Xboard/blob/master/app/Protocols/Shadowrocket.php)：

| 输入 | 含义 |
| --- | --- |
| `tls=0` / `tls=1` | 关闭 / 开启 TLS。编码链接没有安全选项时默认明文；规范 `UUID@host:port` 链接保留默认开启 TLS 的行为。 |
| 未指定 `security` 时的 `pbk`、`sid`、`spx` | 选择 REALITY，必须提供非空 `pbk`。仍支持显式 `security=reality`。 |
| `xtls=0` / `xtls=2` | 无 flow / `xtls-rprx-vision`。拒绝已淘汰的 XTLS Direct（`xtls=1`）及未知值。 |
| `remark` | 没有非空片段时用作显示名称，作为查询参数值只解码一次。 |
| `peer` | 显式 SNI 别名；非空的 `sni` 与 `peer` 必须一致。空值或纯空白名称视为未指定。 |
| `obfs=websocket`、`obfsParam`、`path` | WebSocket 传输、Host header 回退值和路径。 |
| `obfs=grpc`、`path` | gRPC 传输和 service name 回退值。 |

TLS/REALITY、flow 或传输声明相互冲突时会拒绝链接，不会静默降级。VLESS 的 `obfs` 仅接受空值/`none`、`websocket` 或 `grpc`，不会把不支持的传输方式当作 TCP。`host` 和 `serviceName`/`service_name` 保留原有回退顺序。显式 SNI 别名在赋值前按原始字节比较：相同值合并，不同值报错，不转换大小写。空值或纯空白的 SNI 和 flow 在派生节点 ID 前规范化为未指定；非空 flow 必须为 `xtls-rprx-vision` 或 `xtls-rprx-vision-udp443`。

Clash 导入会比较 `servername`、`server-name` 和 `sni`；记录格式还会比较 `tls-name` 和 `tls-host`，并保留较低优先级的 `obfs_sni` 回退值，包括 Quantumult X 的 WSS Host。记录中的 `off` 仍为无效值。分享链接和 VMess JSON 的 WebSocket `host` 仅用作 Host header；非 WebSocket 传输则将其作为较低优先级的 SNI 回退值。TLS 使用方最终仍可回退到节点主机名。

### Hysteria2

解析器同时接受 `hysteria2://` 和 `hy2://`。完整的百分号解码后 userinfo 是认证字符串：字面 `user:password` 保留两部分及冒号，与百分号编码的 `user%3Apassword` 等价。

| 链接输入 | 节点字段 / 行为 |
| --- | --- |
| userinfo secret | `hy2_auth`；保留完整 `user:password`，而不是只取 password |
| `obfs=salamander&obfs-password=...` | 小写 `salamander` 配合非空密码设置 `hy2_obfs`。混淆名称缺失或为空，或密码缺失或为空时关闭混淆。未知混淆名称使链接被拒绝。 |
| `upmbps` / `downmbps` | `hy2_up_mbps` / `hy2_down_mbps`；以 Mbps 为单位的整数，不带单位。上传值为正时启用 Brutal，否则使用 BBR；下载值按 bytes/s 通告。 |
| `mport` / `mhop` | `hy2_port_hopping` / `hy2_hop_interval`；见 [`hy2_port_hopping` / `hy2_hop_interval`](#hy2_port_hopping--hy2_hop_interval)。 |
| `pinSHA256` | `tls_pin_sha256`，替代 PKI/主机名校验 |
| `initStreamReceiveWindow` / `initConnReceiveWindow` | QUIC 接收窗口覆盖值，单位为字节 |
| `disablePathMTUDiscovery` | 值为 `1`/`true` 时关闭 QUIC PMTU 发现 |
| `mtu` | 共用 QUIC UDP-payload 上限；只接受 1200–65527 |
| `sni` / `peer`、insecure 别名、ECH 参数 | 共用 TLS 行为；非空的显式 SNI 别名必须一致 |

`mport` 接受逗号分隔的端口和包含两端的范围，例如 `443,5000-5010`；空段会被跳过。格式错误或超出范围的 `upmbps`、`downmbps`、接收窗口和 `mtu` 会被忽略，不会使链接被拒绝。TUIC 的接收窗口和 `mtu` 按同样方式解析。

```dae
node {
    hy2: 'hysteria2://secret@example.com:443?sni=example.com&obfs=salamander&obfs-password=obfspw&upmbps=50&downmbps=200&mport=20000-30000&mhop=30#hy2'
}
```

### TUIC 与 Juicity

| 协议 | 链接输入 | 节点字段 / 行为 |
| --- | --- | --- |
| TUIC | `uuid:password` userinfo | 通用 `username` / `password`；供 `tuic_uuid` / `tuic_password` 的 handler 回退使用 |
| TUIC | `congestion_control` | `cubic`、`new_reno` 或 `bbr`；`bbr` 即 quinn 原有的 BBR 或 BBRv3，由 `HONK_QUIC_BBR` 选择。省略时为 `cubic`；未知值产生 warning 并回退到 cubic |
| TUIC | `alpn` | 逗号分隔的 ALPN 覆盖值；分享链接默认 `tuic`；原始 Clash/Mihomo 导入使用下述来源默认值 |
| TUIC | `initStreamReceiveWindow` / `initConnReceiveWindow` | 接收窗口覆盖值 |
| Juicity | `uuid:password` userinfo | 通用 `username` / `password`；供 `juicity_uuid` / `juicity_password` 的 handler 回退使用 |
| Juicity | 协议默认值 | ALPN `h3`、BBR，以及 8 MiB / 8 MiB 的初始接收窗口（共享自适应流控可使其增长） |
| Juicity | UDP | 每个客户端源一条 QUIC bi 流承载所有目的地；回复返回真实的远端对端，取决于服务端自身的 UDP socket 与出口策略 |
| 两者 | `mtu`、`sni`、insecure 别名、pin、ECH | 共用 QUIC/TLS 参数 |

```dae
node {
    tuic: 'tuic://00000000-0000-4000-8000-000000000001:secret@edge.example:443?congestion_control=bbr&alpn=h3#tuic'
    juicity: 'juicity://00000000-0000-4000-8000-000000000001:secret@edge.example:443?sni=edge.example#juicity'
}
```

`HONK_QUIC_BBR` 选择 `congestion_control=bbr` 使用的 BBR 版本，见[环境变量](cli.md#环境变量)。

原始 Clash/Mihomo `proxies` 条目中的 TUIC `alpn` 缺失或为 null 时，会补为 `h3`。显式非空列表保留顺序；显式空列表或空白字符串继续使用 honk 既有的 `tuic` 回退，并不表示不发送 ALPN。该来源默认值不适用于原生分享链接、扁平节点、sing-box `outbounds` 或文本记录格式。

**升级注意：** 依赖此前 `tuic` 回退的导入节点须显式设置 `alpn: [tuic]` 才能保留旧行为。协议专用 ALPN 不改变节点 UUID，但有效配置变化会为新请求重建运行时；已有流继续遵循正常的 generation 退休机制。

### AnyTLS

| 链接输入 | 节点字段 / 行为 |
| --- | --- |
| userinfo secret | `password` 与 `anytls_password` |
| `min_idle_session` | `anytls_min_idle_session`；0–65535 的整数，默认 0，作为请求的待机下限，受八条 session 的池上限约束。无效值会被忽略。 |
| `idle_session_check_interval` | 以秒存储的时长；当前不生效，因为清理周期固定为 30 秒 |
| `idle_session_timeout` | 以秒存储的时长；默认 30 秒 |

时长为整数秒，可不带后缀，也可带 `s`、`m` 或 `h` 后缀。`ms` 值向上取整为秒，因此 `500ms` 为 1 秒。无效值会被忽略，保留默认值。

```dae
node {
    anytls: 'anytls://secret@edge.example:443?sni=edge.example&min_idle_session=1&idle_session_timeout=1m#anytls'
}
```

## VLESS

<a id="vless-udp-and-multiplexing"></a>

### UDP 与多路复用

VLESS 有三个独立选择。`udp=0|1` 控制是否允许数据包拨号，`packetEncoding=auto|none|xudp|uot-v2` 选择回退数据包协议，`mux=off|h2mux|xray` 选择 TCP/UDP carrier 路径。这些选择不会协商。

| 规范 URI 查询参数 | 默认值 | 接受值与作用 |
| --- | --- | --- |
| `udp` | 允许 | `1`/`true` 允许数据包拨号；`0`/`false` 关闭 UDP 而不关闭 TCP。文本布尔值不区分 ASCII 大小写；重复声明必须一致。 |
| `packetEncoding` | `auto` | `auto`、`none`（原生 VLESS command-UDP）、`xudp`（Single XUDP）或 `uot-v2`。mux 不接管 UDP 路径时使用该回退值。 |
| `mux` | `off` | `off`、`h2mux` 或 `xray`。 |
| `padding` | `false` | 只接受精确的 `true` 或 `false`，仅对 `mux=h2mux` 有效；选择 sing-mux v1 填充。与 `udp` 不同，`1`、`TRUE` 等其他写法会被拒绝。 |
| `concurrency` | `0` | 仅对 `mux=xray` 有效的有符号 `i16`：负值关闭 TCP mux；零允许每条 TCP carrier 同时承载 8 个逻辑 child；正值设置每条 carrier 的并发上限，最多 128。它不设置物理 carrier 数量。 |
| `xudpConcurrency` | `0` | 仅对 `mux=xray` 有效的有符号 `i16`：负值使用协议回退；零在 TCP mux 启用时共享 TCP 池及其 carrier 并发，否则使用协议回退；正值建立独立 UDP 池，每条 carrier 的逻辑 child 并发使用该值，最多 128。 |
| `xudpProxyUDP443` | `allow` | 仅对 `mux=xray` 有效的 `reject`、`skip` 或 `allow`；UDP/443 的精确优先级见下文。 |

`packetEncoding`、`mux` 与每个 mux 控制项最多出现一次。重复的 `udp` 声明仅在所有值一致时接受。

| `mux` 值 | TCP 与 UDP 路径 |
| --- | --- |
| `off` | 保留普通 VLESS TCP，UDP 使用 `packetEncoding`。UoT v2 为每个客户端源建立一条非连接模式流，承载全部目的地并返回每个回复的真实源地址。 |
| `h2mux` | 逻辑 TCP 与 sing-mux PacketAddr UDP 共用节点所属的 HTTP/2 carrier 池。UDP 每个客户端源使用一条流，逐数据报携带地址。`padding=true` 选择现有的填充 H2MUX 线协议格式。 |
| `xray` | 两个并发设置所启用的连接池分别使用 Xray Mux.Cool。TCP 与 UDP 池化相互独立。 |

H2MUX 接管两类路径，因此回退编码不会替换其 UDP 路径。H2MUX 保留现有池策略，不采用 Mux.Cool 在每条 carrier 分配 128 个逻辑 child 后更换连接的行为。

以下是规范示例（使用合成 UUID）：

```dae
node {
    auto: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&packetEncoding=auto&mux=off&udp=1#auto'
    h2_padded: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&packetEncoding=auto&mux=h2mux&padding=true&udp=1#h2-padded'
    xray_shared: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&packetEncoding=auto&mux=xray&concurrency=0&xudpConcurrency=0&xudpProxyUDP443=skip&udp=1#xray-shared'
    vision_udp_pool: 'vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&flow=xtls-rprx-vision&packetEncoding=auto&mux=xray&concurrency=-1&xudpConcurrency=8&xudpProxyUDP443=skip&udp=1#vision-udp-pool'
}
```

结构化 TOML/YAML/JSON 使用以下独立字段：

| 字段 | 含义 |
| --- | --- |
| `network` | 数据包权限：`tcp` 关闭 UDP；省略、`udp` 或 `tcp,udp` 允许 UDP。 |
| `packet_encoding` | 回退编码：`auto`、`native`、`xudp`、`uot-v2`。 |
| `multiplex` | 带类型标记的 carrier 选择，具体结构如下。 |

| 多路复用协议 | 结构化形式 |
| --- | --- |
| 关闭 | `{"protocol":"off"}` |
| H2 | `{"protocol":"h2","padding":true\|false}` |
| Xray | `{"protocol":"xray","tcp":N\|null,"udp":"protocol"\|"shared-tcp"\|{"separate":N},"udp443":"reject"\|"skip"\|"allow"}` |

省略的成员默认为 `padding: false`、`tcp: null`、`udp: "protocol"` 和 `udp443: "allow"`。因此结构化的 `{"protocol":"xray"}` 不启用任何多路复用池；URI `mux=xray` 则默认使用并发为 8 的 TCP 池，UDP 共享该池。

`tcp` 和每个 `separate` 值都是正数，表示每条 carrier 的逻辑 child 并发上限，最多 128。省略 `tcp` 或设为 null 会关闭 TCP 多路复用池。

`udp: "shared-tcp"` 要求非 null 的 `tcp` 并发值。超出 `1..=128` 的值，或没有 TCP 池的共享 UDP 池，都会使节点被拒绝，即使配置了 `network: "tcp"` 也一样；这些无效值不会被截断或归一化成关闭的池。这与上文有符号 URI 控制项不同，也与对应的 Clash 控制项不同：它们会把大于 128 的正值截断为 128。

#### 从 `vless_mode` 迁移

**破坏性配置变更：** `vless_mode` 已删除，不是兼容别名。升级前应迁移静态链接与 provider 内容。静态 `node {}` 中出现该字段会拒绝候选配置；订阅只丢弃对应条目，保留其他有效节点。如果订阅缓存全部使用旧模式，离线状态下无法恢复节点。离线升级前应确保本地已有迁移后的正文，并且不要删除仍可用的 Selector 或延迟状态。单个 provider 恢复失败本身不导致启动退出，但最终组装的配置仍须通过校验。

每种旧模式都有保留原有 capability 的替代组合：

| 已移除的 `vless_mode` | `packetEncoding` | `mux` | `udp` | 额外查询参数 |
| --- | --- | --- | --- | --- |
| `auto` | `auto` | `off` | `1` | — |
| `native` | `none` | `off` | `1` | — |
| `legacy` | `auto` | `off` | `0` | 保留仅 TCP 行为；不保留旧身份。 |
| `uot-v2` | `uot-v2` | `off` | `1` | — |
| `h2mux` | `auto` | `h2mux` | `1` | `padding=false` |
| `h2mux-padded` | `auto` | `h2mux` | `1` | `padding=true` |
| `xudp` | `xudp` | `off` | `1` | — |
| `mux-cool` | `auto` | `xray` | `1` | `concurrency=0&xudpConcurrency=0&xudpProxyUDP443=skip` |

最后一行保留 TCP/UDP 可用性；`skip` 的 UDP/443 目标使用协议回退，而不是 pooled XUDP。现在默认允许 UDP/443，包括 Vision；需要阻断 QUIC 时使用路由规则。本次升级中所有接纳的 VLESS 节点都使用新的身份派生规则，见[节点身份](#节点身份)。

旧版 `vless_mode` URI 语法会被拒绝。解析器也拒绝 `smux`、`multiplex`、`udp-over-tcp`、`packet-encoding`、`packet_encoding`、`packet-addr`、`xudp`、`only-tcp`、Brutal 控制项与 H2 流数量调优等含义不明确的第三方 URI 拼写；只有上表中的精确规范参数会配置这些选择。

非 VLESS 链接把 `packetEncoding=none` 当作不生效的兼容值接受。其他 `packetEncoding` 值或 `vless_mode` key 会使链接被拒绝。

#### 目标选择与组合

未启用 Vision 时，`packetEncoding=auto` 对目标端口 53、443 使用原生 VLESS UDP，其他端口使用 Single XUDP。启用 Vision 时，获准目标使用 Single XUDP。原生 UDP 发送范围为 1–8190 字节，Single XUDP 为 1–7526 字节；空包或超长包是数据包局部拒绝，接收到的零长度 frame 仍是数据报。

默认允许 UDP/443，包括基础 `xtls-rprx-vision`。需要阻断时，在更宽泛的匹配规则之前配置 `l4proto(udp) && dport(443) -> block`。

| `mux=xray` 的 UDP/443 策略 | 结果 |
| --- | --- |
| `reject` | 即使两个多路复用池均关闭，仍拒绝 UDP/443。 |
| `skip` | 选择 `packetEncoding`。 |
| `allow`（默认） | 使用配置的 UDP 池；没有池时使用协议回退。 |

`xtls-rprx-vision-udp443` 规范化为基础 Vision，不再改变权限或身份；线上附加字段仍为基础 flow。策略和容量拒绝会终止本次尝试，且不影响健康状态或 Score。它们不会触发其他节点或 `direct` 回退，也不会自动重放数据包。

Vision 始终要求 direct TCP 路径：`mux=off`，或 `mux=xray` 且关闭 TCP mux。所有 H2MUX TCP 组合都无效，包括使用 Encryption 时。

Vision 可以使用仅 UDP 的 Xray 池；`concurrency=-1` 时，用正数 `xudpConcurrency` 建立该池。

未加密 Vision 还要求使用协商 TLS 1.3 或 REALITY 的裸 TCP。加密 Vision 可以保留已选 outer 流传输与 random-XOR 处理，但仍不能启用 TCP mux、H2MUX UDP、原生 UDP 或 UoT v2；XUDP/Xray UDP 或关闭 UDP 均有效。

VLESS carrier slot 和 UDP endpoint slot 都出自进程级的文件描述符预算。carrier slot 先划分，所以可复用的 carrier 容量和 endpoint 数量会互相挤占。容量耗尽按本地容量问题报告，不算远端协议失败。honk 还按自己的可复用 source/session 所有权和按目的地路由语义，限定 XUDP Global ID 的 scope。它既不是 Xray 的仅源身份，也不承诺无冲突的 NAT 身份。规范的生命周期与 scope 定义见[源/session 所有权与容量](../design/outbound.md#sourcesession-ownership-and-capacity)。

### Encryption

`encryption` 省略、为空或为 `none` 时不启用 VLESS Encryption。其他值必须以 `mlkem768x25519plus.` 开头；字符串其余部分由 handler 校验。

`encryption=` 接受的基本客户端字符串形式为：

```text
mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<base64url-key>
```

key 为 Base64url，有无填充均可，解码后是 32 字节 X25519 key 或 1184 字节 ML-KEM-768 key。链式 key 作为后续的点分隔段，不是冒号列表。

首个 key 前可以加 `probability-min-max` 填充段，例如 `mlkem768x25519plus.native.1rtt.100-35-35.<key1>.<key2>`。从零计数，偶数段设置以字节为单位的长度，奇数段设置以毫秒为单位的间隔。第一段的概率须为 100、最小长度至少 35 字节，所有长度段最大值之和不得超过 65553 字节。

`0rtt` 使用缓存票据，冷启动时走 1-RTT 路径。VLESS Encryption 位于选定的 outer TCP/TLS/REALITY/WS/gRPC 传输内层。它支持原生或 XUDP 回退以及 Xray UDP 池，但不支持 H2MUX TCP/UDP 或 UoT v2。Encryption 与 Vision 可以在上述 direct-TCP-path 规则下组合。

### REALITY 与 Vision

在 VLESS 与 Trojan URL 链接中，`security=reality` 开启 TLS 并映射 REALITY 查询参数字段，不再静默回退到普通 PKI TLS。其他分享链接协议方案拒绝 REALITY 意图；结构化 VMess REALITY 仍受支持。仅 VLESS 使用 `flow` 选择 Vision。

| Query | 含义 |
| --- | --- |
| `security=reality` | 选择 REALITY 并开启 TLS。选择了 REALITY 却没有 `pbk` 的节点会在校验时被拒绝，而不是降级成普通 TLS。 |
| `pbk` | Base64url 编码的 32 字节 X25519 服务端 public key；无效输入 fail-closed。 |
| `sid` | 偶数长度十六进制 short ID，最多 8 字节；允许为空。 |
| `spx` | 存储 spider path；选择 REALITY 时默认为 `/`。 |
| `flow=xtls-rprx-vision` | 按上述 UDP/443 规则启用 Vision。 |
| `flow=xtls-rprx-vision-udp443` | 规范化为 `xtls-rprx-vision`；默认已经允许 UDP/443。 |
| `fp` | 接受但忽略；ClientHello 指纹由全局 TLS 模式控制。 |

VLESS 按以下规则选择 TLS：

| 输入 | TLS 行为 |
| --- | --- |
| 显式 `security=none` | 关闭 TLS，覆盖历史默认值。 |
| 其他显式 `security=` 值 | 开启 TLS。 |
| 无 `security`，有显式 `tls=0\|1` | 使用显式 TLS 选择。 |
| 普通 VLESS 链接未提供两者 | 默认开启 TLS。 |
| Base64 编码地址的 Shadowrocket 链接未提供两者 | 默认关闭 TLS，除非 REALITY 字段将其开启。 |

标准 VMess 链接改用其 v2rayN JSON `tls` 字段。

重复的 `security` 与已识别的 `tls` 声明必须一致，包括别名之间的 TLS 开关。后值不能覆盖前面的冲突声明。VLESS 与编码 VMess 只接受 `tls=0|1`；其他协议方案保留对未识别 `tls` 文本的处理。Trojan 与 AnyTLS 拒绝显式明文声明，而不是静默保留强制 TLS。

REALITY 仅使用 TLS 1.3，首次尝试依次通告 hybrid `X25519MLKEM768` 与预设 classic `X25519` share。仅当握手完成后收到非 ed25519 叶证书，才向同一对端新建一次仅使用 X25519 的连接；新连接仍须通过配置的 REALITY key/HMAC 认证，之后才能发送代理数据。

两次尝试共享 `3 × connect_timeout` 的 setup deadline，不增加配置项。这个触发结果没有经过认证，不是服务端版本检测。ed25519 HMAC 错误、TLS/IO 错误和 HRR 仍然是最终失败。每条连接只 seal 一次 ClientHello，不复用 key/nonce。参见[兼容与认证边界](../design/outbound.md)。

裸 TCP 池只接纳握手前保持静默的 socket。任何排队的服务端字节，包括致命 TLS 警报，都会让该裸连接在接纳或取出时被拒绝；没有 SNI/警报特例，也不会重试握手。已经完成协议准备的就绪流即使缓冲了有效应用数据，也不会因此被拒绝。

REALITY 不使用 CA 校验或 `skip_cert_verify`。目标 TLS 记录的缓冲限制取决于服务端版本。文档中的 sing-box 1.12 / MetaCubeX-uTLS 1.8.0 对端使用 8192 字节缓冲区，包含分帧开销，这不是 honk 统一的证书上限。参见[服务端版本约束](../design/outbound.md)。REALITY 配置方案还会加入 ed25519；被忽略的 `fp` 和全局 Chrome-oriented 模式都不承诺精确的浏览器身份。

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

`ech_config` 和 `ech_config_path` 文件的内容是 Base64 文本，标准或 URL-safe 均可，填充可选；文件不能是二进制 ECHConfigList。读取或解码失败会使节点被拒绝，不会回退到发现。

静态配置会提供真实 ECH；ECH 被拒绝时，握手 fail-closed。发现是尽力而为且 fail-open：找不到 ECHConfigList 时，握手不带真实 ECH 继续，`utls` 仍发送 ECH GREASE。发现走 bootstrap resolver，未配置时使用系统首个 nameserver，并按域名缓存结果。同一组控制项也适用于 QUIC 协议。

## 分享链接 scheme

XHTTP 以外，未知查询 key 会被忽略，因此拼错 key 名不会报错。XHTTP 链接拒绝未知 key，VLESS 拒绝上文列出的第三方写法。

| Scheme | 格式与映射 |
| --- | --- |
| `ss://` | SIP002 Base64 userinfo 或完整地址，或明文 `ss://method:password@host:port` |
| `vmess://` | 宽松 Base64 v2rayN JSON 或编码地址形式，见流传输一节 |
| `vless://` | URL userinfo UUID，加流传输、TLS/REALITY、flow、Encryption 与上文规范 UDP/mux 查询参数 |
| `trojan://` | URL userinfo secret，加传输与 TLS 查询参数 |
| `anytls://` | URL userinfo secret，加 TLS 与池查询参数 |
| `hysteria2://` | 上述 Hysteria2 查询参数映射；也接受 `hysteria://` |
| `tuic://` | 上述 TUIC userinfo 与 QUIC 调优 |
| `juicity://` | Juicity userinfo 与共用 QUIC/TLS 查询参数 |
| `socks5://` | SOCKS5 userinfo；也接受 `socks4://` 和 `socks4a://`，但仍使用 SOCKS5 协议，因此不能连接仅支持 SOCKS4 的服务端 |

明文 `method:password` userinfo 中的方法本身可以是 Base64，例如 `ss://YWVzLTEyOC1nY20=:password@host:port`。无法得到方法和密码的 userinfo 会整体作为密码，方法回退到 `aes-128-gcm`。

honk 不运行 Shadowsocks 插件。`plugin=name;options`、`plugin-opts` 和 `plugin_opts` 只作为元数据保留；其他 scheme 出现这些 key 会被拒绝。

SOCKS5 只在链接同时带有用户名和密码时提供用户名/密码认证，两者各不得超过 255 字节。

写成 `a -> b` 的链只解析 `a`。节点名称来自 dae 标签、`#fragment`、`remark`、VMess `ps` 或 `{scheme}-{host}`，从不使用原始 URI 或 userinfo，因此名称不会泄露凭据。

## 相关文档

- [订阅参考](./subscription.md)
- [组参考](./groups.md)
- [出站设计](../design/outbound.md)
