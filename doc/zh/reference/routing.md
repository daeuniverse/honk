# 路由参考

`routing { ... }` 定义有序的流量匹配器及其出站目标。

## 规则语法

```text
condition [&& condition ...] -> outbound[(must)]
fallback: outbound
```

- 规则按源码顺序确定优先级：解析器依次分配 `0, 1, ...` 的 `priority` 值，值越小越先执行。第一个最终匹配生效。
- `default:` 是 `fallback:` 的别名。没有规则最终确定结果时使用 fallback 目标；省略时默认为 `direct`。
- 同一个 matcher 内以逗号分隔的参数互为备选。不同的非空条件组必须全部匹配。
- matcher 的括号参数列表可以跨物理行。语句一直延续到右括号和 `-> outbound`。
- 前缀 `!` 只对紧随其后的单个 matcher 取反。规则仅在正向条件匹配且所有取反 matcher 都未命中时匹配。
- 对取反的域名或 geosite matcher，未知或尚未嗅探到的域名视为“不是 x”，因此不会否决该规则。

```dae
routing {
    sip(
        10.10.10.24/32,
        10.10.10.25/32
    ) && !dport(53) -> direct(must)
    default: proxy
}
```

## 条件函数

| 函数 | 接受的参数 | 内部 `RoutingCondition` 字段 |
| --- | --- | --- |
| `domain(...)` | 裸值或 `suffix:` 表示后缀；`keyword:` 表示子串；`full:` 表示完整名称；`regex:` 表示正则表达式；`geosite:` 表示 geosite 代码 | `domain_suffix`, `domain_keyword`, `domain`, `domain_regex`, `geosite` |
| `dip(...)` | 目的 IP/CIDR；`geoip: code` | `ip`, `geo_ip` |
| `sip(...)` | 源 IP/CIDR | `source_ip` |
| `dport(...)` | 目的端口或闭区间 `start-end` | `port` |
| `sport(...)` | 源端口或闭区间 `start-end` | `source_port` |
| `l4proto(...)` | `tcp`, `udp` | `protocol` |
| `pname(...)` | `argv[0]` 的可执行文件 basename，最多 15 字节；运行时 BTF 偏移或 cgroup verifier 拒绝内核 argv 读取时，cgroup hook 同步使用调用线程的 `comm` | `process_name` |
| `mac(...)` | 源 MAC 地址 | `mac` |
| `ipversion(...)` | `4`/`ipv4`, `6`/`ipv6` | `ip_version` |
| `dscp(...)` | DSCP 值 | `dscp` |

每个正向字段在 `RoutingCondition.not` 下都有对应列表；解析器把 `!matcher(...)` 放入该列表。同一字段中的多个值互为备选。

`mac(...)` 放行不能让客户端免于 DNS 拦截：LAN 接口上 53 端口快速路径先于路由引擎执行，任何路由规则都无法豁免 DNS。只有明确绑定的本机非 honk `:53` 监听能在快速路径之前取得流量（见 DNS 设计文档）。

## 出站目标与 `must`

| 目标 | 含义 |
| --- | --- |
| `direct` | 内建直连出站 |
| `block` | 内建阻断出站 |
| 组名 | 按该出站组及其策略解析 |

裸节点名不是合法的出站目标，`Config::validate` 会拒绝：把节点包进一个组（例如 `filter: name('node')`）后引用组名。组与节点也不允许同名。

追加 `(must)` 会启用兼容 Go dae 的 must 语义。must 规则命中后不会结束规则搜索；匹配继续，并把 must 状态传播到最终出站。Clash `Global` 和 `Direct` 模式绝不会覆盖 must 结果，也绝不会覆盖 `block`。

## Geo 资源

`geoip:` 和 `geosite:` 条件使用 `geoip.dat` 与 `geosite.dat`。引擎按以下顺序选择第一个已存在的普通文件：

| 优先级 | 位置 |
| --- | --- |
| 1 | `$DAE_LOCATION_ASSET/<file>` |
| 2 | `global.data_dir/<file>` |
| 3 | `/var/share/honk/<file>`（`LEGACY_DATA_DIR`） |
| 4 | 进程工作目录中的 `./<file>` |
| 5 | `/usr/local/share/honk/<file>` |
| 6 | `/usr/share/honk/<file>` |
| 7 | `/usr/local/share/dae/<file>` |
| 8 | `/usr/share/dae/<file>` |
| 9 | `/etc/dae/<file>` |

运行时资源解析规则见[全局参考](./global.md)。`geoip: private` 使用内建 CIDR 集，不需要 `geoip.dat`。

找不到被引用的 Geo 资源时，引擎会记录包含缺失文件名的警告。未使用的资源不会触发缺失文件警告。

geosite 代码可以用 `category@attr` 选择属性。属性名按大小写不敏感方式比较。第一个 `@` 后的全部内容都是选择器，包括后续的 `@`。未知类目或没有条目命中的选择器会记录告警、展开为零个 matcher，并且永不匹配。

## 自动注入的本地规则

honk 在启动、reload 和接口拓扑变化时，为配置的 LAN 与 WAN 接口当前分配的每个地址刷新一条生成规则：

```dae
dip(<each LAN/WAN interface address>) -> direct(must)
```

地址会转换为主机 CIDR（`/32` 或 `/128`）。不存在的接口和无法解析的 `auto` 接口会被跳过。这些规则让 SSH、管理界面和 Clash API 等网关本地服务保持可达，而不依赖代理健康状态。

## Fail-closed 行为

健康检查把出站标记为死亡后，eBPF 数据面通常会用 `TC_ACT_SHOT` 丢弃路由到该出站的新流，绝不会静默泄漏到 `direct`。未配置 `final` 且只有一个唯一叶节点的 TCP 组会让同一代理继续作为最后尝试，使真实流量可以证明恢复。UDP 和全部叶节点失活的多叶节点组仍保持 fail-closed；但含有 `direct`/`block` 内建成员的组永不失活：内建节点永远不会被判定死亡，因此 group-OR 槽保持开放。TCP 和 UDP 的目的端口 `53` 均受豁免，因此 DNS 仍可到达控制面。

要让网关能承受节点故障：

- 添加 `dip(geoip: private) -> direct(must)`，使私有网络流量不依赖代理健康状态。
- 让 `fallback:` 指向至少包含两个节点的 [`fallback` 策略组](./groups.md)，而不是单个节点。
- 至少保留一个走直连路径的 DNS 上游。

## 完整示例

```dae
routing {
    domain(suffix: doubleclick.net) -> block
    pname(NetworkManager, systemd-resolved) && l4proto(udp) && dport(53) -> direct(must)
    dip(geoip: private) -> direct(must)
    sip(
        10.10.10.24/32,
        10.10.10.25/32
    ) && !dport(53) -> direct(must)
    mac(aa:bb:cc:dd:ee:ff) && ipversion(4) -> direct
    domain(
        full: api.example.com,
        suffix: example.org,
        keyword: tracker,
        regex: '^bad[0-9]+\.example$',
        geosite: category-games@cn
    ) -> proxy
    dip(geoip: cn, 203.0.113.0/24) && sport(1024-65535) && dscp(46) -> hk
    l4proto(tcp) && dport(80, 443, 8080-8090) -> proxy
    !domain(geosite: category-ads-all) && !dip(geoip: cn) -> resilient
    fallback: resilient
}
```

这里 `proxy`、`hk` 和 `resilient` 都是组名。

## 相关文档

- [路由设计](../design/routing.md)
- [全局参考](./global.md)
- [组参考](./groups.md)
