# 订阅参考

本文说明当前 runtime 接受的 `subscription {}` 条目、持久化恢复机制与订阅正文格式。

## `subscription {}` 语法

每个非空、非注释行都采用 `tag: URL`。URL 值可以使用单引号，也可以不加引号：

```dae
subscription {
    primary: 'https://example.com/sub'
    backup: https://example.net/sub
}
```

这里的“裸 URL”是指不加引号的 URL 值。普通 HTTP(S) URL 必须带 tag：当前解析器按第一个 `:` 分派，因此无 tag 的 URL 不会被解析成无 tag 条目。

dae 配置面只设置订阅 tag（`name`）和 `url`。其他所有字段都保留模型默认值，不能在 dae 语法中设置。特别是，dae 订阅始终为 `sub_type: simple`，不会自动检测 Clash YAML。

## 内部模型

| 字段 | 类型 | 默认值 | 可在 dae 中设置 | 含义 |
| --- | --- | --- | --- | --- |
| `id` | UUID | 随机 UUID | 否 | runtime 订阅身份；SIGHUP 时，若 URL 与已有订阅匹配则保留该值。 |
| `name` | string | `""` | 是，作为 tag | 显示 tag，也是组 `subtag(...)` filter 使用的值。 |
| `url` | string | `""` | 是 | HTTP(S) 拉取 URL。 |
| `sub_type` | enum | `simple` | 否 | 正文解析器：`simple`、`clash`、`sip008` 或 `custom`。 |
| `update_interval` | u64 | `86400` | 否 | 定期刷新间隔，单位为秒；`0` 禁用定期刷新。 |
| `user_agent` | string 或 null | `honk/<version>` | 否 | 可选的 `User-Agent` 覆盖值；未设置时请求标识为 `honk/<version>`。 |
| `headers` | `{key,value}[]` | `[]` | 否 | 有序的额外请求 header。 |
| `enabled` | bool | `true` | 否 | 禁用的订阅不会恢复、拉取或刷新。 |
| `last_updated` | datetime 或 null | null | 否 | 模型元数据；当前 core runtime 不更新它。 |
| `node_count` | u32 | `0` | 否 | 模型元数据；当前 core runtime 不更新它。 |
| `created_at` | datetime | 构造时间 | 否 | 模型构造时间。 |

内部正文选择行为如下：

| `sub_type` | 解析行为 |
| --- | --- |
| `simple` | Standard Base64 或纯文本分享链接列表。 |
| `clash` | 带顶层 `proxies` sequence 的 Clash YAML。 |
| `sip008` | 当前使用与 `simple` 相同的分享链接列表解析器。 |
| `custom` | 先尝试 `simple`，再尝试 Clash YAML。 |

只有非 dae 模型使用方才能设置这些值。`honk-tool sub` 拉取 URL 时使用 `custom`。

## 拉取、持久化与恢复

`global.store_subscribe` 默认为 `true`。启用后，runtime 会打开私有订阅存储并立即拉取每个已启用订阅。请求默认使用 `honk/<version>`，可由 `user_agent` 覆盖。非零 `update_interval` 会安排后续刷新。

| 属性 | 当前行为 |
| --- | --- |
| 首选位置 | `<data_dir>/.sub`；`data_dir` 默认值为 `/var/share/honk`。 |
| 旧位置 | 若首选目录不存在而 `./.sub` 存在，则继续使用旧目录，直至手动迁移。两者同时存在时优先使用首选目录。 |
| 权限 | 目录 mode 为 `0700`，文件 mode 为 `0600`。拒绝符号链接形式的存储目录。 |
| 文件名 | 对带长度边界的 URL、配置中的 user agent 覆盖值（未设置或为空时为空）及有序 header key/value 对计算 SHA-256，再用 URL-safe Base64 编码并添加 `.sub`。版本化的默认请求 UA 不参与 key，因此默认订阅升级后仍保留缓存。请求身份不会以明文暴露。 |
| 写入边界 | 只有 HTTP 成功且解析成功后才写入原始响应正文。临时文件完成 sync 后原子 rename，随后对目录执行 sync。 |

订阅正文及其产生的节点都只属于 runtime 状态；两者都不会写回 dae 配置。

启动时会在开始联网刷新前解析已存正文。有效的已恢复正文会立即提供活动节点，因此该订阅不参与 5 秒首次拉取等待；其联网刷新仍会在后台运行。缺失或无效的已存正文会被忽略，并让该订阅继续参与有界首次拉取等待，直至拉取结束或达到 deadline；后续有效刷新会替换损坏文件。

SIGHUP 时，URL 相同的订阅保留 runtime ID。重载会沿用仍处于启用状态的订阅所属活动节点；只有某订阅没有存活节点时才恢复已存正文。随后提交重建后的配置，并立即开始后台刷新。

失败处理会保留可用 runtime，而不会清空它：

- HTTP、解析或没有可用节点的失败不会发布替换节点，也不会写入，因此活动节点与上一次有效正文都会保留。
- 持久化写入在解析成功后失败属于非致命错误：新解析出的节点仍会返回用于发布，而原子写入路径绝不会安装只写了一部分的正文。下次重启因此可以恢复磁盘上保留的任一完整有效正文。
- 单个不支持的分享链接或 Clash proxy 会被跳过。只有没有剩余受支持节点时，整个正文才失败；空结果绝不会清空上一代节点。

通过 SIGHUP 修改 `global.store_subscribe` 会因需要重启而被拒绝。

## 订阅正文格式

所有接受的节点都会获得订阅 ID。解析结束后会丢弃重复的派生节点 ID，并保留第一次出现的节点。如果正文中的受支持条目最终全部折叠为同一个重复身份，则拒绝正文，不会替换活动订阅。

### `simple`

`simple` 正文可以是 standard Base64（padding 可省略）编码的一行一个分享链接，也可以直接是纯文本列表：

```text
# blank lines and comments are ignored
socks5://user:password@127.0.0.1:1080#local
vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls#edge
```

每个非注释行都由 `Node::from_share_link` 解析。不支持或格式错误的行会被跳过。honk 不执行代理插件，因此带有非空插件值的分享链接也会被跳过。若正文没有受支持的节点 URI，则拒绝整个正文。规范分享链接字段与协议见[节点参考](./nodes.md)。

### Clash YAML

Clash 正文必须包含顶层 `proxies` sequence。非 mapping 条目、缺少 string `type` 或 `server` 的条目、缺少可装入 `u16` 的整数 `port` 的条目，以及不支持的 proxy type 都会被跳过。

接受的 `type` 值包括 `socks5`、`ss`/`shadowsocks`、`trojan`、`vmess`、`vless`、`hysteria2`/`hysteria`、`tuic`、`juicity` 与 `anytls`。导入器只映射下文列出的字段；无关 Clash key 会被忽略，但列为 VLESS 拒绝输入的 key 除外。

#### 通用代理字段

| Clash 字段 | 内部字段 | 规则 |
| --- | --- | --- |
| `name` | `name` | 默认为 `<type>-<server>:<port>`。 |
| `server`, `port` | `host`, `port`, `address` | 分别必须为 string 和 integer。 |
| `username` | `username` | 可选 string。 |
| `password` | `password` | 可选 string；VLESS 使用下文优先级。 |
| `cipher` | `encryption` | 可选 string；VLESS 使用下文优先级。 |
| `plugin`, `plugin-opts` | — | 不支持；任一字段具有非空值时，条目会在发布节点前被跳过，mapping 类型的 options 也会被拒绝。 |
| `network` | `transport` | 可选 transport string。 |
| `tls` | `tls` | 可选 bool。 |
| `servername`, `sni` | `sni` | `servername` 优先，`sni` 作为回退。 |
| `skip-cert-verify` | `skip_cert_verify` | 可选 bool。 |

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

嵌套 WS/gRPC 值优先于其扁平别名。若存在 `reality-opts`，但它不是 mapping 或缺少非空 `public-key`，则跳过该条目；绝不会降级成普通 TLS。

#### VLESS packet mode

| Clash 表示 | 规范化 mode | 条件 |
| --- | --- | --- |
| 没有启用 packet/multiplex 选项 | `legacy` | 禁用的 block 与 `xudp: false` 不选择 mode。 |
| `smux` 或 `multiplex` 且 `enabled: true` | `h2mux` 或 `h2mux-padded` | 必须有 `protocol: h2mux` 或显式 bool `padding`。`padding: true` 选择 `h2mux-padded`，否则选择 `h2mux`。 |
| `udp-over-tcp: true` | `uot-v2` | Boolean 简写。 |
| `udp-over-tcp: { enabled: true, version: 0|2 }` | `uot-v2` | 缺失 `version` 按 `0` 处理；也接受 `_` 别名。 |
| `packet-encoding: xudp` | `xudp` | `packet_encoding` 是扁平别名。 |
| `xudp: true` | `xudp` | Boolean 简写。 |
| 规范分享链接 `vless_mode=mux-cool` | `mux-cool` | Clash packet/mux 别名不接受 `mux-cool`。 |

VLESS Clash 条目出现下列任一情况时会被拒绝：

- 重复别名或重复 XUDP 表示；
- H2MUX、UoT 与 XUDP 中启用多个 mode；
- 启用 `packet-addr`/`packet_addr` 或顶层 `mux`；
- 已启用的 `smux`/`multiplex` block 既没有 `protocol: h2mux`，也没有显式 `padding` bool；
- multiplex 协议不是 `h2mux`、`only-tcp: true`、启用 Brutal 设置，或 `max-connections`、`min-streams`、`max-streams` 调优值非零；
- `udp-over-tcp` version 不是 `0` 或 `2`；
- 没有显式非 `legacy` packet mode 的 `udp: true`，或非 `legacy` mode 搭配 `udp: false`；
- packet encoding 既不是空值也不是 `xudp`，包括 packetaddr 与 `mux-cool` 别名；
- 非 `legacy` mode 与 VLESS Encryption 组合，或与受支持的 `xudp` + `xtls-rprx-vision` 之外的 `flow` 组合。

规范 VLESS 分享链接使用 `vless_mode=legacy|uot-v2|h2mux|h2mux-padded|xudp|mux-cool`。`smux`、`udp-over-tcp`、`packet-encoding` 等含义模糊的第三方分享链接 key 会被拒绝，不会猜测其语义。

## 离线解析与探测

`honk-tool sub` 接受需要拉取的订阅 URL，或一行一个分享链接的本地文件。本地文件不会触发订阅下载，适合离线解析；随后命令仍会执行所配置的连通性与延迟探测：

```console
honk-tool sub ./share-links.txt --limit 10
honk-tool sub https://example.com/sub --ua honk-tool
```

拉取 URL 时，工具使用 `custom`，因此先尝试 simple list，再尝试 Clash YAML。传入 `-` 会从标准输入读取一个 HTTP(S) 订阅 URL，而不是从标准输入读取订阅正文。探测 flag 与输出见 [CLI 参考](./cli.md)。

## 相关文档

- [节点参考](./nodes.md)
- [组参考](./groups.md)
- [CLI 参考](./cli.md)
