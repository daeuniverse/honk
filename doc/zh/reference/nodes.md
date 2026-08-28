# 节点与分享链接

`node { ... }` 从分享链接声明可拨号的出站，并为每个节点分配稳定的运行时身份。

## `node {}` 声明

每个非注释行是一个分享链接。tag 与链接都可加引号或裸写：

```dae
node {
    iris: 'socks5://10.10.10.1:2077'
    'hk1': 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@hk1.example.com:8388#fragment-name'
    'trojan://secret@example.com:443?sni=example.com#trojan1'
    socks5://10.10.10.2:1080
}
```

当前解析器同时接受带 tag 和不带 tag 的条目。非空 dae tag 会替换链接的 `#fragment` 名称。不带 tag 的链接保留解码后的 fragment；没有 fragment 时使用不含凭据的 `{scheme}-{host}` 回退名称。

格式错误但 scheme 已识别的链接会被丢弃，并向 stderr 输出 `node section: skipping unparseable entry: ...`。未知 scheme 是配置硬错误。独立的 `mux:` 或 `mux=` 行也会被拒绝；VLESS wire 行为必须写在各链接的 `vless_mode=` query 中。

## 节点身份

`Node::derive_id()` 是唯一的身份派生路径。它对以下材料计算 UUID v5：

```text
protocol|host|port|credential-fingerprint|dial-shape
```

凭据指纹遵循各 handler 的字段优先级。dial shape 包含 `sni`、transport、WebSocket/gRPC 形态、Hysteria2 混淆、REALITY 参数、`flow` 以及每种非 `legacy` VLESS mode。调优参数与显示元数据不参与。

因此，只要可拨号端点不变，身份在改名、reload 和订阅刷新后仍保持稳定。配置/运行时组装会拒绝重复的派生 ID。`Node::default()` 的 ID 为 nil；构造路径会派生 ID，出站运行时注册表会拒绝任何抵达该处的 nil ID。

## 节点字段

Node 模型包含下列字段。分享链接从 scheme、userinfo、authority、fragment 和 query 填充面向操作者的字段；明确标为元数据的行由结构化 loader、导入或运行时管理。它们都不是 dae `node {}` 中的独立键。下表默认值是模型默认值；URL 形分享链接省略端口时使用 `443`，而 v2rayN VMess payload 必须包含有效端口。

| 字段 | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `id` | UUID | 派生 | 上述稳定内容身份；运行时不允许 nil |
| `name` | string | `""` | dae tag、解码后的 fragment、VMess `ps` 或不含凭据的回退名称 |
| `protocol` | enum | `ss` | 从分享链接 scheme 派生 |
| `address` | string | `""` | 解析后的链接存储 `host:port` |
| `host` | string | `""` | 显式服务端主机；否则 `Node::host()` 从 `address` 派生 |
| `port` | u16 | `0` | 服务端端口；URL 形链接省略时使用 `443` |
| `username` / `password` | string? | null | 来自 userinfo 的认证、UUID 或密钥 |
| `encryption` | string? | null | SS/VMess cipher 或 VLESS Encryption 客户端字符串 |
| `vless_mode` | `WireMode` | `legacy` | `legacy`、`uot-v2`、`h2mux`、`h2mux-padded`、`xudp` 或 `mux-cool` |
| `plugin` / `plugin_opts` | string? | null | 解析后的 SIP002 插件元数据；代理插件不受支持，订阅导入会拒绝非空值 |
| `transport` | string | `"tcp"` | 流 transport；校验只接受空值/`tcp`、`ws` 或 `grpc` |
| `tls` | bool | `false` | 流 TLS 标志；Trojan/AnyTLS 链接开启，VLESS 历史默认开启 |
| `sni` | string? | null | 来自 `sni` 或未被 transport 消耗的 `host` query 的 TLS 服务端名称 |
| `skip_cert_verify` | bool | `false` | `allowInsecure`、`allow_insecure` 或 `insecure` 等于 `1`/`true` |
| `ech_enabled` | bool | `false` | 存在静态 ECH 配置，或 `ech=1`/`true` |
| `ech_config` | string? | null | 来自 `ech_config` 或 `echconfig` 的 Base64 ECHConfigList |
| `ech_config_path` | string? | null | 结构化 loader 中指向 base64 ECHConfigList 的路径；不是分享链接 query |
| `reality_public_key` | string? | null | 来自 `pbk` 的 REALITY X25519 公钥 |
| `reality_short_id` | string? | null | 来自 `sid` 的 REALITY short ID |
| `reality_spider_x` | string? | null | 存储的 `spx`；REALITY 链接默认设为 `/` |
| `flow` | string? | null | 来自 `flow` 的 VLESS flow；只支持 `xtls-rprx-vision` |
| `network` | string? | null | 协议网络/能力提示；VMess JSON `net` 与订阅导入会填充它 |
| `ws_path` / `ws_host` | string? | null | WebSocket `path` 与 Host header |
| `grpc_service` | string? | null | gRPC `serviceName` 或 `service_name` |
| `hy2_auth` / `hy2_obfs` | string? | null | Hysteria2 认证与 salamander 密码 |
| `hy2_up_mbps` / `hy2_down_mbps` | u32? | null | Hysteria2 brutal 发送端/接收端带宽提示 |
| `hy2_port_hopping` / `hy2_hop_interval` | string? / u64? | null | Hysteria2 `mport` 列表与 `mhop` 秒数；有效间隔为 30 秒 |
| `hy2_init_stream_recv_window` / `hy2_init_conn_recv_window` | u64? | null | Hysteria2 QUIC 接收窗口；有效默认值为 8 MiB / 8 MiB（conn 窗口同时是每连接内存预算，慢消费者最多缓冲约 3 倍该值；内存占用 ≈ 活跃连接数 × 3 × conn 窗口） |
| `hy2_disable_mtu_discovery` | bool? | null | Hysteria2 `disablePathMTUDiscovery` |
| `quic_mtu` | u16? | null | 来自 `mtu` 的 QUIC UDP payload 大小；默认 1252，接受范围 1200–65527；显式设置大于 1252 时启用 GSO，`HONK_QUIC_GSO=0` 可强制关闭 |
| `tls_pin_sha256` | string? | null | 来自 `pinSHA256` 或 `pin_sha256` 的叶证书 SHA-256 pin |
| `tuic_uuid` / `tuic_password` | string? | null | TUIC 专用凭据；handler 会回退到通用 userinfo 字段 |
| `tuic_congestion` / `tuic_alpn` | string? | null | TUIC `congestion_control` 与逗号分隔的 `alpn` |
| `tuic_init_stream_recv_window` / `tuic_init_conn_recv_window` | u64? | null | TUIC QUIC 接收窗口；有效默认值为 8 MiB / 8 MiB |
| `juicity_uuid` / `juicity_password` | string? | null | Juicity 专用凭据；handler 会回退到通用 userinfo 字段 |
| `anytls_password` | string? | null | 从链接 userinfo 复制的 AnyTLS 密钥 |
| `anytls_min_idle_session` | usize? | null | 来自 `min_idle_session` 的空闲 session 目标下限；有效默认值 0，受两条 session 的池上限约束 |
| `anytls_idle_session_check_interval` | u64? | null | 解析后的 `idle_session_check_interval` 秒数；当前运行时 janitor 周期仍固定为 30 秒 |
| `anytls_idle_session_timeout` | u64? | null | 来自 `idle_session_timeout` 的空闲驱逐；有效默认值 30 秒 |
| `mark` | u32? | null | 结构化模型中的出站 `SO_MARK`；不是 dae 分享链接 query |
| `tags` | string[] | `[]` | 分类元数据；不是 dae 分享链接 query |
| `subscription_id` / `group_id` | UUID? | null | 导入/运行时归属元数据 |
| `created_at` / `updated_at` | datetime | now | 运行时元数据 |

校验要求每个非内置节点名称非空，并且 `address` 或 `host` 至少一个非空。

### 结构化 loader 兼容性

TOML、YAML 与 JSON 继续使用旧的扁平节点键。加载时只读取所选 `protocol` 自己的字段，并忽略其他协议遗留的字段；例如，`ss` 节点上的 `tls: true` 既不会开启 TLS，也不会导致节点被拒绝。所选协议实际使用的值仍会正常解析与校验。Honk 自身输出仍可安全 round-trip。启用 `store_subscribe` 时，原始订阅正文仅在解析成功后持久化；被拒绝的刷新不会覆盖上一份有效正文。

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

`network` 还可关闭 Trojan、AnyTLS 与非 legacy VLESS 的 packet 拨号。Legacy VLESS 没有 UDP，VMess UDP 尚未实现。

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

Trojan 与 VLESS URL 链接用 `type=` 或其 `network=` 别名选择 transport。对于 `ws`，`path` 映射到 `ws_path`，`host` 映射到 `ws_host`；对于 `grpc`，`serviceName` 或 `service_name` 映射到 `grpc_service`。`sni` 独立生效。`alpn` 为兼容而接受，但不会存储。配置校验只允许 TCP、WebSocket 与 gRPC。

```dae
node {
    trojan_ws: 'trojan://secret@example.com:443?type=ws&sni=example.com&host=example.com&path=/path#trojan_ws'
    vless_grpc: 'vless://uuid@example.com:443?security=tls&type=grpc&serviceName=GunService#vless_grpc'
}
```

VMess 使用 v2rayN base64 JSON 而不是 URL query 参数：`net`、`host`、`path` 与 `sni` 会填充对应字段。

VLESS 已完成以下 live 互通验证：TCP+REALITY+Vision、TCP+REALITY、TCP+WS、TCP+WS+TLS 与 TCP+gRPC。Vision 支持的 direct-copy 组合是带 TLS 或 REALITY 的裸 TCP，而不是 WS/gRPC。

### Hysteria2

| 链接输入 | 节点字段 / 行为 |
| --- | --- |
| userinfo 密钥 | `username`、`password` 与 `hy2_auth` |
| `obfs=salamander&obfs-password=...` | 非空密码成为 `hy2_obfs`；其他/不完整 obfs 输入保持关闭 |
| `upmbps` / `downmbps` | `hy2_up_mbps` / `hy2_down_mbps`；`upmbps` 为正值时启用 Brutal，否则使用 BBR；下载值按 bytes/s 通告 |
| `mport` / `mhop` | 端口列表/范围与以秒为单位的跳跃间隔；间隔默认 30，并钳制到上游规定的最小值 5 |
| `pinSHA256` | `tls_pin_sha256`，替代 PKI/主机名校验 |
| `initStreamReceiveWindow` / `initConnReceiveWindow` | QUIC 接收窗口覆盖值 |
| `disablePathMTUDiscovery` | 值为 `1`/`true` 时关闭 QUIC PMTU 发现 |
| `mtu` | 共用 QUIC UDP-payload 上限；只接受 1200–65527 |
| `sni`、insecure 别名、ECH 参数 | 共用 TLS 行为 |

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
| `security=reality` | 选择 REALITY 并开启 TLS |
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
