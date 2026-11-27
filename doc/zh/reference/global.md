# 全局配置参考

`global { ... }` 定义进程级设置。

## 示例

```dae
global {
    tproxy_port: 12345
    log_level: info
    log_file: 'honk.log'
    data_dir: '/var/lib/honk'
    store_subscribe: true
    nfqueue_enable: true

    lan_interface: br0
    wan_interface: auto

    tcp_check_url: 'https://www.gstatic.com/generate_204'
    tcp_check_http_method: HEAD
    # 显式列出目标才会授权路由 UDP 恢复。
    # udp_check_dns: 'dns.google:53', '8.8.8.8', '2001:4860:4860::8888'
    check_interval: 30s
    check_tolerance: 50ms

    dial_mode: domain++
    bootstrap_resolver: '223.5.5.5:53'

    preconnect_node_count: 'auto'
    udp_warm_node_count: 0
    max_concurrent_dials: 64
}
```

## 字段

下表列出 `global` 的字段及其运行时效果。部分 key 只为兼容已有的 dae 配置而接受：解析器会把它们存入 `GlobalConfig`，运行时并不读取；每个这样的字段都在含义栏或所链接的小节里注明。

所有字段都可省略，省略时使用表中的默认值。启用 DNS 审计时，`syslog_addr` 必填。

以下字段需重启才能改动：`tproxy_port`、`tproxy_port_protect`、`pprof_port`、`so_mark_from_dae`、`log_level`、`log_file`（解析后的实际目标变化时）、`syslog_addr`、`syslog_dns_enabled`、`syslog_cee_enabled`、`syslog_hostname`、`syslog_app_name`、`lan_interface`、`wan_interface`、`auto_config_kernel_parameter`、`nfqueue_enable`（启动时确实降级的情况除外）、`data_dir`、`store_subscribe`，以及 [reload 健康检查与 TLS 模式](#reload-健康检查与-tls-模式) 列出的健康检查输入。reload 若改动健康检查输入会被拒绝，当前生效配置保持不变。

Key 栏为 `—（dae 语法中不可配置）` 的五行是 dae 语法无法设置的内部字段。

| Key | 内部字段 | 默认值 | 含义 |
| --- | -------- | ------ | ---- |
| `tproxy_port` | `tproxy_port` | `12345` | TCP/UDP 透明代理端口；见 [`tproxy_port`](#tproxy_port)。 |
| `tproxy_port_protect` | `tproxy_port_protect` | `true` | 用于避免透明代理端口被再次拦截的兼容开关；当前运行时不读取它。 |
| `pprof_port` | `pprof_port` | `0` | pprof HTTP 端口兼容字段；见 [`pprof_port`](#pprof_port)。 |
| `so_mark_from_dae` | `so_mark_from_dae` | `0`（实际 `0x100`） | honk 主动创建的 socket 使用的进程级 `SO_MARK`，数据路径也用它做精确旁路匹配；见 [socket mark](#socket-mark)。 |
| `log_level` | `log_level` | `"info"` | 启动日志过滤器，语法同 `RUST_LOG`；见 [`log_level`](#log_level)。 |
| `log_file` | `log_file` | `""` | 追加写日志路径；见 [`log_file`](#log_file)。 |
| `syslog_addr` | `syslog_addr` | `""` | TCP syslog 接收端；见 [`syslog_addr`](#syslog_addr)。 |
| `syslog_dns_enabled` | `syslog_dns_enabled` | `false` | 通过 RFC 5424 syslog 发送客户端 DNS 审计；见 [`syslog_dns_enabled`](#syslog_dns_enabled)。 |
| `syslog_cee_enabled` | `syslog_cee_enabled` | `false` | 为 JSON 正文加 `@cee: ` 前缀，供支持 CEE 的接收端使用；见 [`syslog_cee_enabled`](#syslog_cee_enabled)。 |
| `syslog_hostname` | `syslog_hostname` | `""` | RFC 5424 头中的发送端主机名；见 [`syslog_hostname`](#syslog_hostname)。 |
| `syslog_app_name` | `syslog_app_name` | `"honk"` | RFC 5424 头中的应用名：1–48 字节、不含空格的可打印 ASCII。 |
| `disable_waiting_network` | `disable_waiting_network` | `false` | 兼容 key；当前启动路径不读取它。未解析的 `auto` 网卡本就保持待定，不会阻塞启动。 |
| `shutdown_wait_connections` | `shutdown_wait_connections` | `false` | 退出时给业务连接的宽限等待；见[关闭](#关闭)。 |
| `lan_interface` | `lan_interface` | `[]` | 逗号分隔的 LAN 网卡，其 hook 拦截转发流量；见[网卡语义](#网卡语义)。 |
| `wan_interface` | `wan_interface` | `[]` | 逗号分隔的 WAN 网卡，其 hook 拦截本机发起的 TCP/UDP；见[网卡语义](#网卡语义)。 |
| `auto_config_kernel_parameter` | `auto_config_kernel_parameter` | `false` | sysctl 自动设置的兼容开关；见 [`auto_config_kernel_parameter`](#auto_config_kernel_parameter)。 |
| `nfqueue_enable` | `nfqueue_enable` | `true` | 把有歧义的 LAN 转发 UDP 留在 NFQUEUE；见 [`nfqueue_enable`](#nfqueue_enable)。 |
| `data_dir` | `data_dir` | `"/var/lib/honk"` | 生成状态和相对运行时资源的根目录；见[数据目录与资源路径](#数据目录与资源路径)。 |
| `store_subscribe` | `store_subscribe` | `true` | 将每个订阅最近一次有效正文持久化到 `data_dir/state/honk.db`，仅供启动恢复；reload 沿用活动节点，不读取已存正文。 |
| `tcp_check_url` | `tcp_check_url` | `["https://www.gstatic.com/generate_204"]` | TCP/HTTP 健康检查 URL；见 [`tcp_check_url`](#tcp_check_url)。 |
| `tcp_check_http_method` | `tcp_check_http_method` | `"HEAD"` | URL 健康检查使用的 HTTP 方法，例如 `HEAD` 或 `GET`。空值按 `HEAD` 处理；无效方法会让每次 HTTP 探测都因请求无效而失败。 |
| `udp_check_dns` | `udp_check_dns` | `["dns.google:53", "8.8.8.8", "2001:4860:4860::8888"]` | UDP 健康检查的 DNS 目标；见 [`udp_check_dns`](#udp_check_dns)。 |
| `check_interval` | `check_interval_secs` | `30s` | 全局健康检查间隔，单位是整秒；见 [`check_interval`](#check_interval)。 |
| `check_tolerance` | `check_tolerance_ms` | `50ms` | URLTest 切换成员前要求的延迟改善量；见 [`check_tolerance`](#check_tolerance)。 |
| `dial_mode` | `dial_mode` | `"domain"` | 目的域名发现和路由模式；见 [`dial_mode`](#dial_mode)。 |
| `allow_insecure` | `allow_insecure` | `false` | 全局 TLS 校验回退兼容字段；见 [`allow_insecure`](#allow_insecure)。 |
| `sniffing_timeout` | `sniffing_timeout_ms` | `30ms` | 嗅探超时兼容字段；见 [`sniffing_timeout`](#sniffing_timeout)。 |
| `tls_implementation` | `tls_implementation` | `"tls"` | 写 `utls`（不区分大小写）会启用 honk 的 Chrome 风格 ClientHello 模拟，不承诺精确的浏览器身份。其他任何值，包括空值和拼写错误，都会选择常规 BoringSSL 客户端配置，不报错也不产生 warning。 |
| `utls_imitate` | `utls_imitate` | `"chrome_auto"` | 兼容指纹请求；见 [`utls_imitate`](#utls_imitate)。 |
| `tls_fragment` | `tls_fragment` | `false` | TLS ClientHello 分片兼容开关；当前 TLS connector 不读取它。 |
| `tls_fragment_length` | `tls_fragment_length` | `""` | 分片长度范围兼容字段；当前 TLS connector 不读取它。 |
| `tls_fragment_interval` | `tls_fragment_interval` | `""` | 分片间隔范围兼容字段；当前 TLS connector 不读取它。 |
| `mptcp` | `mptcp` | `false` | MPTCP 兼容开关；当前拨号路径不读取它。 |
| `bootstrap_resolver` | `bootstrap_resolver` | `""` | 节点主机名和控制面拨号使用的带 mark UDP/TCP resolver；见 [`bootstrap_resolver`](#bootstrap_resolver)。 |
| `fallback_resolver` | `fallback_resolver` | `"8.8.8.8:53"` | 回退 resolver 兼容值；当前运行时不读取它。 |
| `bandwidth_max_tx` | `bandwidth_max_tx` | `""` | 发送带宽提示兼容值，例如 `'200 mbps'`；当前运行时不读取它。 |
| `bandwidth_max_rx` | `bandwidth_max_rx` | `""` | 接收带宽提示兼容值；当前运行时不读取它。 |
| `preconnect_node_count` | `preconnect_node_count` | `"auto"` | 启动时预热裸 TCP 的节点数；见 [`preconnect_node_count`](#preconnect_node_count)。 |
| `udp_warm_node_count` | `udp_warm_node_count` | `0` | 每个代理组的 UDP 预热候选数；见 [`udp_warm_node_count`](#udp_warm_node_count)。 |
| `max_concurrent_dials` | `max_concurrent_dials` | `64` | 每个 generation 的代理连接和握手上限；见 [`max_concurrent_dials`](#max_concurrent_dials)。 |
| —（dae 语法中不可配置） | `tproxy_mark` | `0x08000000` | 用户态策略路由与编译后的 eBPF 数据路径共享的固定 fwmark。 |
| —（dae 语法中不可配置） | `udphop_interval_secs` | `30s` | 旧全局 UDP hop 间隔。当前拨号器不读取它；协议特定的端口跳跃使用节点字段。 |
| —（dae 语法中不可配置） | `connect_timeout_ms` | `3000ms` | 代理连接、协议准备、预连接、健康检查和控制面拨号使用的阶段超时。透明 TCP 候选 race 与 UDP transport preparation 还共用绝对总预算 `max(10s, 4 × connect_timeout)`；不新增配置 key。 |
| —（dae 语法中不可配置） | `dns_resolve_timeout_ms` | `2000ms` | 控制面 DNS 解析超时，包括拨号前必须转换为 IP 的目标。 |
| —（dae 语法中不可配置） | `relay_idle_timeout_secs` | `300s` | 旧中继空闲超时；当前中继路径不读取它。 |

### tproxy_port

把 TCP/UDP 透明代理端口写入用户态 listener 和 eBPF 数据路径。

取值为十进制端口号。其他文本（包括十六进制）会产生 `legacy-config-warning`，并回退到 `12345`。

### pprof_port

pprof HTTP 端口兼容字段；`0` 表示关闭。honk 当前不启动 pprof 服务，也不读取该字段。

不是十进制端口号的值会产生 warning，并回退到 `0`。

### log_level

启动时的日志过滤器，语法同 `RUST_LOG`，例如 `info` 或 `'info,honk_core=debug'`。值为空白时按 `info` 处理。

优先级从高到低是有效的 `RUST_LOG`、`--debug`、该值。

`info` 覆盖运行状态：启动、reload、健康检查和订阅。逐条连接的分流记录（`TCP connection`、`UDP connection`、eBPF 卸载）在 `debug` 级别，以免路由器的 syslog 被逐连接日志占满。

通过 SIGHUP 修改不会生效，必须重启。原生 API 的 `log.level` PATCH 会替换该过滤器，直到下一次激活。

要核对分流结果，就用 `debug` 运行，或从 API 读取 `/logs?level=debug`。

### log_file

追加写日志路径。空值或只有空白的值关闭文件输出，控制台日志仍然启用。

相对路径在 `data_dir` 下解析；见[数据目录与资源路径](#数据目录与资源路径)。

解析后的实际目标不变时，SIGHUP 不要求重启，变了才要求。`--log-file` 优先于此配置值。

### syslog_addr

TCP syslog 接收端：数字 IP 加端口，例如 `192.0.2.10:514` 或 `[2001:db8::10]:514`。

启用 DNS 审计时必填。此时必须是单播 IP 加非零端口，否则以 `invalid-config-value` 校验失败。

### syslog_dns_enabled

需要 `dns-syslog` Cargo feature。启用后，honk 发送客户端 DNS 结果：消息按 RFC 5424 固定，正文为 JSON，经一条 TCP 长连接传输，分帧使用 RFC 6587 的长度前缀。

审计独立于原生 API 历史记录和日志级别。发送按批进行且有上限，重连采用退避；没有应用层确认，也不落盘。

见 [DNS 审计](../design/dns-syslog.md)。

### syslog_cee_enabled

为固定 JSON 正文添加 `@cee: ` 前缀，用于支持 CEE 的接收端，例如 VictoriaLogs。普通 JSON 保持 `false`。

该字段不会启用审计，也不会编译 `dns-syslog` feature。

### syslog_hostname

设置 RFC 5424 头中的发送端主机名。空值在启动时读取一次系统主机名，失败回退 `-`。

显式值必须是 1–255 字节、不含空格的可打印 ASCII，关闭 DNS 审计时同样校验。

### auto_config_kernel_parameter

自动配置 sysctl 的兼容开关。运行时不再按该字段分支；真实数据路径总会执行固定的 best-effort sysctl 设置。

该设置把 `net.ipv6.conf.all.forwarding` 固定为 1，因此会为每个 WAN 根接口写入 `net.ipv6.conf.<wan>.accept_ra=2`，包括同时作为 LAN 的接口。接口出现在网卡拓扑中时立即写入，启动时存在还是之后才出现都一样；写入不等待该接口的 hook，也不要求链路 UP。这样，SLAAC/RA 学来的 IPv6 默认路由不会因为 forwarding 被固定而过期消失。

该设置还会为第一个已解析、存在且未被拒绝的 LAN 名称写入 `net.ipv4.conf.<lan>.rp_filter=0`，按配置原样写入，不做规范化。

每个值约一秒后会再写一次：新设备加入时，udev 的 `systemd-sysctl` 会在首次写入后立即恢复发行版默认值。此后 honk 不再改动，直到该设备被重建。

使用 systemd-networkd 的主机，建议在 WAN 的 `.network` 文件中显式配置 `IPv6AcceptRA=yes`。

### nfqueue_enable

把有歧义的 LAN 转发 UDP 原始包留在 NFQUEUE，直到用户态给出终态决策。此功能需要真实 eBPF 后端。

启动降级会记录 `NFQUEUE is unavailable at startup; continuing with NFQUEUE staging disabled`，并带 `reason` 字段：`the mock eBPF backend was selected`、`honk-core was built without the ebpf feature`，或固定队列前置检查的错误。honk 不改写配置文件，在本进程内保持关闭。

单实例交接后，固定队列不可用，或数据路径 admission 之前队列、规则、健康检查失败时，honk 会记一条 warning，并在本进程内关闭该功能，不改写配置。安装阶段会回收保留的 nftables table。

持久化 token generation 恢复失败，以及 [admission 后的失败](../design/nfqueue.md#启用与范围)，仍然是 fatal。

`experimental.udp_nfqueue.enabled` 已弃用，改用 `nfqueue_enable`。旧写法仍被接受，并产生迁移 warning；两者同时存在时以 `nfqueue_enable` 为准。

只有确实发生过降级时，写入和 reload 才能继续请求 `nfqueue_enable: true`，而 NFQUEUE 的生效值保持关闭。省略该 key、采用默认值 `true`，也算这种请求。降级分两种：启动早期的降级（mock、不带 `ebpf` feature，或固定队列的前置检查失败），以及数据路径 admission 之前较晚发生的队列、规则或健康检查降级。此时请求的源文本保持原样，生效值在本进程整个生命周期内都是 `false`。honk 不会自动重试启用，只有重启才会重试。没有发生降级时，开关的变更仍需重启。[公共 reload 流程](../design/control-plane.md#reload-与运行时-generation) 在指纹/no-op 检查之前归一化生效配置；原生 API 的写入检查沿用同一规则。

`0.1.0-beta.4` 及更早版本没有这个豁免：启动降级后，该字段仍在需重启的比较范围内，所以请求 `true`（包括省略该 key）的写入和 reload 都会因需重启而被拒绝，重启后也一样。只有在源文件里写 `nfqueue_enable: false` 才能写入。

`nfqueue_enable` 同时控制 [LAN UDP/53 分片交付](../design/nfqueue.md#lan-dns-分片)：DNS 控制器和 raw group 处理的分片都要求 NFQUEUE 处于 ready，否则直接丢弃，不能绕过 DNS 策略。原生 `direct(must)` 和未分片的 DNS 不变。

### tcp_check_url

设置逗号分隔的 TCP/HTTP 健康检查 URL。健康检查循环只用第一个值；首项缺失或为空时退回普通 TCP 检查。

只支持 `http://`、`https://` 和没有 scheme 的 URL。其他 scheme 或端口 `0` 仍能加载，但每次 HTTP 探测都会因为请求无效而失败。

URI 解析分别处理 userinfo、带方括号的 IPv6、端口、路径、查询和片段。userinfo 不会变成授权头。请求保留路径和查询，不发送片段，没有斜杠的查询以 `/?query` 发送。

显式 HTTP/HTTPS 目标默认使用 80/443。没有 scheme 的健康检查目标走 HTTP/80；URLTest 的无 scheme 目标走 HTTPS/443，并向解码后的路径和查询串发送 HEAD。

第一个 URL 同时也是 Score 的 QUIC 探测目标；见 [reload 健康检查与 TLS 模式](#reload-健康检查与-tls-模式)。

```dae
global {
    tcp_check_url: 'https://www.gstatic.com/generate_204'
}
```

### udp_check_dns

设置逗号分隔的 UDP 健康检查 DNS 目标。裸 IPv4/IPv6、`[IPv6]` 和域名默认使用端口 `53`；显式端口必须是 `1..65535` 内的整数。

括号或端口无效时，校验失败并产生带位置的诊断。

普通节点探测优先选择第一个 IP 字面量，没有就解析第一个域名。解析与 Score 共用解码后的主机和端口，域名解析后仍保留域名身份。省略该项时使用上表所列的默认值。

对于[路由 UDP 恢复](./groups.md#出口存活)，请列出授权 honk 经受影响的链或组出口查询的 DNS 服务器。省略该项或提供空列表时，不会发出恢复查询。恢复优先选择配置中第一个与受影响的健康地址族相同的 IP 字面量。没有时，仅使用配置的 DNS 服务查找已配置域名的同族地址，不回退到 bootstrap DNS。封装 UDP 的跳点必须允许目的端口。

```dae
global {
    udp_check_dns: 'dns.google:53', '8.8.8.8', '2001:4860:4860::8888'
}
```

### check_interval

设置全局健康检查间隔，单位是整秒。取整数，可以不带后缀，也可以带 `s`、`m`、`h`；`ms` 值向上取整到秒（`500ms` 变为 `1s`），`1.5s` 无效。

该值必须为正。解析失败的值会变成零，在校验时被拒绝。

UDP 预热协调器也使用该间隔，但实际下限为 10 秒。

```dae
global {
    check_interval: 30s
}
```

### check_tolerance

设置 URLTest 切换所选成员前要求的延迟改善量，单位为整毫秒。接受裸毫秒数、带 `ms` 的整数或带 `s` 的值，包括零。

不足一毫秒的部分被截去，因此 `0.0005s` 变为 `0ms`，`0.5ms` 无效。其他写法保留默认值 `50ms` 并记录 warning。

```dae
global {
    check_tolerance: 50ms
}
```

### dial_mode

选择目的域名发现和路由模式：`ip`、`domain`、`domain+` 或 `domain++`。拼写不区分大小写。

未知名称以 `invalid-config-value` 拒绝校验。各模式见[拨号模式](#拨号模式)。

```dae
global {
    dial_mode: domain++
}
```

### allow_insecure

全局 TLS 校验回退兼容字段。当前 TLS connector 不读取该字段。

跳过证书校验需在节点分享链接中按节点配置。

### sniffing_timeout

嗅探超时兼容字段；当前控制面不使用它。解析规则和无效值处理同 [`check_tolerance`](#check_tolerance)，无效值保留默认的 `30ms` 并记录 warning。

### utls_imitate

兼容指纹请求。`utls` 模式只使用一个 Chrome 风格配置，此值不会切换配置。

非空且不以小写 `chrome` 开头的值会在启动时记录 warning。

### bootstrap_resolver

设置用于解析节点主机名和控制面拨号目标的带 mark UDP/TCP resolver。取值是数字 IP 加端口：`223.5.5.5:53`、`udp://223.5.5.5:53`、`tcp://223.5.5.5:53` 或 `[2001:4860:4860::8888]:53`。

只有 `tcp://` 选 TCP，其他 scheme 比如 `tls://` 都按明文 UDP 处理。写成主机名或缺少端口时，resolver 不生效，也不报错。

bootstrap 为空或查询失败时，honk 先查 `/etc/hosts`，再向 `/etc/resolv.conf` 里第一个数字 nameserver 发带 mark 的 DNS；它不调用 libc NSS，也不追加搜索后缀。

去掉 scheme 后的同一地址还会用作周期性 `direct` 健康检查目标，无效时回退到 `223.5.5.5:53`。

DNS [`subtag()` 规则](./dns.md#节点服务器域名)可以改为接管某个订阅的节点主机名。

```dae
global {
    bootstrap_resolver: '223.5.5.5:53'
}
```

### preconnect_node_count

启动时执行一轮裸 TCP 预热，只执行一次。`"auto"` 最多选择八个合格节点，并发四次尝试；显式 `N` 最多选择 `N` 个，并发不超过 `min(N, 8)`。各组当前选择优先，之后按节点配置顺序补充。`0` 关闭这一轮预热。

可接受的取值见[预热与拨号预算](#预热与拨号预算)。

### udp_warm_node_count

启用独立 UDP 预热协调器，并设置每个代理组的 UDP 预热候选数。`0` 关闭。

正值 `N` 表示每组、每个 IP family 最多挑选 `min(N, 3)` 个可复用 UDP 叶子，去重后全局最多保留 `4 × N` 个。最多并发四次尝试。

第一轮预热立即开始。之后每批完成再等 `max(check_interval, 10s)`，组的选择变化时会提前开始。

### max_concurrent_dials

请求每个 generation 的物理代理连接和协议握手上限。运行时资源预算可能进一步收紧。

实际值至少为一，最多为 `1024`；更大的配置值会被接受并收紧。重叠 reload generation 还共享一个由文件描述符推导出的上限。

Ready pool 命中、已热 transport 上的逻辑流以及 `direct`/`block` 不占 permit。

## 列表取值

默认值栏中的 `[]` 表示空列表。dae 没有列表字面量，`lan_interface: []` 会创建名为 `[]` 的网卡；清空网卡列表请写 `lan_interface: ''` 或 `wan_interface: ''`。`tcp_check_url: ''` 保留一个空项，从而关闭 HTTP 探测。

`tcp_check_url` 和 `udp_check_dns` 的列表项应逐项加引号或不加引号。整串加引号，例如 `'dns.google:53,8.8.8.8'`，仍可使用，但会产生 `legacy-quoted-list` warning。

## 已移除的键

`syslog_dns_template` 和 `syslog_dns_json` 已移除，因为 DNS syslog 使用固定 JSON schema。无论取值如何，出现任一 key 都会以 `removed-config-setting` 拒绝配置；请删除该 key。

## HTTP 健康检查请求

HTTP 健康检查和 URLTest 请求的 `Host` 只含主机与端口，不含凭据。IPv6 保留方括号，非默认端口不会省略。建立连接和处理 TLS 服务端名称时，使用的是不带方括号的主机。

请求路径和查询字符串保留配置中的原始点路径段和百分号编码。构造请求之前，honk 会拒绝 authority 含多余斜杠、包含反斜杠或内嵌 ASCII 空白／控制字符的 URL。健康检查的 warning 不会回显被拒绝的 URL。

HTTP 探测把 `200–499` 的任何最终状态码视为成功，因此重定向或 `404` 也算通过。响应头超过 16 KiB 或不完整时探测失败。

## 关闭

TC 后端仅在设为 `shutdown_wait_connections: true`，且正常关闭、数据路径健康并存在活动 runtime epoch 时，才给已接受连接最多五秒自然结束，再关闭并 join 剩余连接。其他情况跳过宽限等待，不区分长短连接。

关闭使用最近接受的配置；reload 被拒绝时保留旧值。这个开关不影响 reload 退役、DNS/状态持久化、NFQUEUE/eBPF 清理，也不影响原生 API 独立的[五秒 HTTP 宽限期](./api.md#原生-api)。


XDP 后端先关闭抓包准入并 detach 物理 link，再等待 packet endpoint 输出/CQ 拆卸完成。此开关不为 XDP packet TCP 连接提供自然结束宽限期。

TUN 先关闭准入、移除活动 capture route，再 join Endpoint 清理，整个排空期间
保留 blackhole guard。正常确认停止后才移除自有策略资源；失败时保留 guard 与
setup receipt。该开关不为 TUN packet 连接提供自然结束宽限。

这不是优雅重启，也不限制总退出时间：[已持有的清理和阻塞工作](../design/control-plane.md#终止所有权)仍须完成。

## socket mark

`so_mark_from_dae: 0` 或省略该项时，保留历史上的实际 mark `0x100`。非零值替换 `0x100`，不会和它按位 OR。honk 在 connect/send 之前原样应用该 mark，作用于代理 carrier、bootstrap/DNS、健康检查、订阅和 UI 下载。数据路径按配置值做精确旁路匹配，仅仅带有 `0x100` 这一位并不能免于拦截。 TC 清除透明监听接受的 TCP socket 上的继承 mark。TUN 和启用 Host 的 XDP 在绑定 DNS、Clash 和原生 API 监听前设置并核验旁路 mark，服务端接受的 socket 保留该值。必须设置 mark 的物理出站 socket 会传播权限拒绝等错误。

dae 全局标量沿用 honk 既有的十六进制优先规则：`10` 和 `0x10` 都表示 16。格式错误或溢出的文本会产生诊断，并回退到原始值 `0`，实际生效的是 `0x100`，建议显式写 `0x`。这与[直连规则 mark](./routing.md#策略路由-mark) 不同：后者无前缀时按十进制解析，错误值直接拒绝配置。

全局与规则 mark 的校验都拒绝保留位 `0xc0000000`；全局 mark 还拒绝 TPROXY 位 `0x08000000`，daens 会把该位路由到自己的 listener，因此全局 mark 保留的是 `0xc8000000`。

这个值在启动网络 I/O 之前确定，作用于整个进程；修改需要重启，不能通过 SIGHUP 切换。非零直连规则 mark 会替换该直连流的全局策略路由有效位，代理 carrier 和 bootstrap 仍使用全局值。直连流还携带内部分类元数据；请使用 [路由参考](./routing.md#策略路由-mark) 中带掩码的 IPv4/IPv6 `ip rule` 示例。honk 不负责安装用户的 WAN 策略路由表、路由、源地址规则或 NAT 配置。

## reload 健康检查与 TLS 模式

以下参数在启动时确定。reload 若改变生效值，会被拒绝；当前配置与已安装的探测器保持不变：

- `check_interval`。
- 第一个 `tcp_check_url`，包括回退地址、路径和查询字符串。缺失或空的首项均关闭 HTTP 探测；后续项不参与比较。
- HTTP 探测启用时的 `tcp_check_http_method`。空值与 `HEAD` 等价。
- 普通节点探测用到的 `udp_check_dns` 生效目标。选择时去除首尾空白、忽略空项，依次取第一个 IP 字面量、第一个域名或最终的 `8.8.8.8:53`。reload 检查只比较配置中的地址或域名及其端口，不解析 DNS。域名比较不区分大小写，并忽略一个尾随句点，因此 `dns.example:53` 和 `DNS.EXAMPLE.:53` 是同一目标。保留该生效目标时，reload 可以更新路由恢复所用的显式列表。
- `tls_implementation` 在原生 TLS 与 uTLS 之间的切换。比较 `utls` 时不区分大小写。

dae 配置中的 `check_tolerance` 仍可通过 reload 更新 URLTest 组的容差。组级检查 URL 和直接连接探测仍沿现有路径动态更新。reload `utls_imitate` 只保存兼容配置值，不改变指纹。

Score 组还会对第一个 `tcp_check_url` 发起 QUIC 握手探测。该 URL 必须以小写 `https://` 开头，否则此探测关闭，Score 只使用其他探测，并由 `quic_probe` 降级项报告。QUIC 目标只在启动时建立，因此 reload 新增第一个 Score 组时会报告原因 `restart_required`，直到下次重启。

UDP DNS 目标在启动时按健康检查超时尝试初始化。本地拒绝或初始化超时会让配置目标保持待定，留给后续健康检查周期重试；honk 不替换默认目标，也不降低节点健康状态，独立的 QUIC 检查仍可继续。首次成功解析出的地址随后保持固定。延后的解析和 DNS 交换共用同一次探测的绝对期限；普通解析失败保留原有的默认回退。

## 流量入口与拦截

默认由 TC 拦截流量。可通过 datapath 配置显式选择 [Linux TUN Endpoint](#linux-tun-endpoint)。

- `lan_interface` 上的 hook 拦截 LAN 客户端经本机转发的流量，例如把本机设为网关的客户端。
- `wan_interface` 上的 hook 拦截本机发起的 TCP/UDP。
- 需要用户态处理的流量由数据路径经 `dae0` 送进 `daens` 命名空间，再由 `sk_lookup` 交给 `tproxy_port` 上的透明代理 TCP 或 UDP listener。有歧义的 LAN 转发 UDP 则由 NFQUEUE 暂存（`nfqueue_enable`）。
- mock 后端不拦截任何流量。

honk 不提供 `mixed-port`、`redir-port`、HTTP 或 SOCKS 代理监听。Clash API 的 `GET /configs` 将 `port`、`socks-port` 和 `mixed-port` 报告为 `0`。`tun` 对象报告已接受的 TUN 配置（包括 `enable`）。就绪状态单独报告。除透明代理监听外，honk 只监听可选的 [DNS 地址](./dns.md#独立-listenerbind)和 [experimental](./experimental.md) 中配置的 API 地址。参见 [TC 报文路径](../design/overview.md#报文路径)。

## 网卡语义

`lan_interface` 为空时，honk 不安装 LAN TC hook，也绝不会用 `lo` 替代。WAN-only 网关因此只使用 `wan_interface`；经过这些 WAN hook 的本机 TCP/UDP 流量仍会被代理，但不会额外安装 LAN 拦截。

多个网卡使用 `lan_interface: 'eth0', 'eth1'`，`wan_interface` 也采用相同语法。将整个逗号分隔列表放在一组引号内，例如 `lan_interface: 'eth0,eth1'`，会创建一个网卡名称，而不是两个。

在以太网父设备上，VID 非零的 VLAN 标签帧属于 VLAN 设备。要管理该子网，请列出 `eth1.20`；VLAN-aware bridge 则列出 `br0.N`。VLAN-aware bridge 拓扑还没有经过真实流量验证。参见[接口 hook 集合](../design/datapath.md#接口-hook-集合)。

`auto` 在所有使用处都会去除首尾空白，并不区分 ASCII 大小写，所以 `AUTO`、` auto ` 和只剩空白的条目都算 `auto`。`.dae` 的列表解析器会丢弃真正为空的项，因此空列表仍表示没有接口。`auto` 解析为拥有 metric 最低 IPv4 默认路由的网卡。没有这条路由时，该项保持待定，绝不回退到 `lo`，直到默认路由出现。同一列表里显式命名的网卡照常工作。只有存在 `auto` 项时才会读取路由表；路由表读不出来是错误，不能当作没有默认路由：启动时失败，运行期间失败则保持现有绑定不变。

网卡存在即绑定，不要求 `IFF_UP`。角色按网卡区分，见[接口 hook 集合](../design/datapath.md#接口-hook-集合)，因此 LAN/WAN 共用的网卡不会改变其他 LAN 网卡的 hook。bond、bridge 或其他 master 的成员通过该 master 绑定，`vrf` 和 `openvswitch` 的成员则保持自身。LAN bridge 还会以 LAN 角色绑定它的端口；bond 的 hook 只挂在逻辑 master 上，不挂成员。

每个已配置的条目都是 lazy 绑定，不会导致启动失败。网卡尚不存在、没有默认路由的 `auto` 条目，或被拒绝的链路类型，都不会绑定任何 hook，其流量在绑定之前不被拦截。TCX link 创建、更新或校验失败时，条目可能只绑定了部分 hook，此时有效的 hook 仍可能拦截流量。条目完全没绑定 hook，或只绑定了部分 hook，都会由 `interface_binding` [降级](./api.md#原生-api)报告；`lifecycle.state` 仍是 `running`，监控必须读取这条降级。匹配只看内核的主名称，altname 视为不存在。设备出现时会绑定，消失时会释放 hook，以新网卡 index 重建的设备会重新绑定。属于尚不存在网卡的 `dns.bind` 地址不算网卡条目：绑定它仍会导致启动失败，错误为 `EADDRNOTAVAIL`。

链路类型决定程序族：

| 链路类型（`ifi_type`） | 帧格式 |
| --- | --- |
| 以太网：eth、bond/team（其第一个端口为以太网时）、bridge、vlan、macvlan/macvtap、ipvlan、veth、netkit、vxlan、geneve、gretap、tap、dummy、macsec | `_l2` |
| `ARPHRD_NONE`（wireguard、tun、`collect_md` GRE、无 MAC 模式的 geneve/VXLAN-GPE）、PPP、RAWIP、IPIP、IP6TNL、SIT | `_l3` |
| GRE / IP6GRE | 仅当置位 `IFF_POINTOPOINT` 且未置位 `IFF_BROADCAST` 时为 `_l3`；否则拒绝 |
| `lo`、`vcan`、InfiniBand、802.15.4、nlmon 及其他所有类型 | 拒绝 |

这张表描述的是分类器，不是经过验证的设备支持矩阵。IPv4 GRE 和 `collect_md` GRE 的内核测试只检查标志与 TCX hook，不验证隧道负载转发。本次变更没有验证真实的 IP6GRE、IPIP、SIT、IP6TNL、PPP、RAWIP、tun 和 wireguard 设备。GRE 以及这些 L3/NONE 程序族也都缺少端到端流量覆盖。

如果内核报告网络头位于帧起点后 14 字节，且第 12–13 字节与数据包协议一致，`_l3` 程序就按以太网头解析，而不是按裸 IP 解析。先设成以太网、再改为 RAWIP 的设备就会这样。线性头超过 65550 字节的帧仍按裸 IP 解析。L3 bond 上经 AF_PACKET raw socket 发出的裸 IP，如果源地址字节恰好等于 EtherType，会被误当作以太网解析；这类发送方需要 `CAP_NET_RAW`，而该权限本身就能设置 honk 的 bypass mark。内核测试覆盖了改类型为 RAWIP 的 TAP，不包括真实蜂窝模组。

IP6GRE 如果只有单播 remote、没有显式 local 地址，可能不带 `IFF_POINTOPOINT`；即使它的数据包本可按裸 IP 处理，也会被拒绝。已有 IP6GRE 不支持用 `ip link change` 原地修改：内核可能改掉点对点标志却不清理 `header_ops`，于是隧道头仍在时，分类器会选择 `_l3`。请删除并重建设备，不要原地修改。IP6GRE 的创建和流量都还没有验证。

被拒绝的项不绑定任何 hook，并会按每个 episode 记一次错误日志，写明网卡和原因。原因包括：链路类型不受支持；不支持的 bond/bridge 嵌套，或自身即是 master；`vrf` 设备，此时应配置它的成员，VRF 成员绑定自身；`dae0` 或 `dae0peer`。降级以原因 `unsupported_type` 报告。即使被拒绝的是第一个已解析的 LAN 或 WAN 项，也不会导致启动失败，或阻止其他项绑定。类型不受支持的 bridge 端口会被静默跳过。bond 或 team master 的类型取自它当前第一个端口，因此 InfiniBand bond 会被拒绝。L3S 模式的 ipvlan 和 `reorder_hdr off` 的 VLAN 设备属于不支持的组合。

`IfaceWatcher` 订阅链路、地址和 IPv4/IPv6 路由事件，每 60 秒协调一次。如果无法订阅或无法注册轮询，它仍每 60 秒协调一次，但没有事件通知，并报告 `iface_watch` 降级。它会随网卡和默认路由的变化创建、更新或释放所需的 LAN/WAN hook。拓扑变化仍用于 ECS 刷新，并立即唤醒受健康状态控制的出站探测；不过 honk 不再生成网关地址的 `direct(must)` 规则，也没有隐藏的内核地址白名单。网卡列表配置本身变化仍需重启；网关管理访问请用[显式用户路由](./routing.md#显式本地路由)。启动顺序和会导致启动失败的条件见[接口协调](../design/datapath.md#接口协调)。

真实 LAN 绑定还会执行提示性的[自保覆盖检查](./routing.md#显式本地路由)。无法确认时只记 warning，不拒绝启动或 reload，也不插入路由规则。

## 拨号模式

| 模式 | 嗅探 | 域名校验 | 路由与拨号行为 |
| ---- | ---- | -------- | -------------- |
| `ip` | 否 | 不适用 | 保留原始目的 IP；不嗅探，也不重新执行路由。 |
| `domain` | 是 | 嗅探到的名称必须通过与目的 IP 的 reality check。 | 校验通过后可按域名重新执行路由；没有域名规则命中时，仍由普通 IP/端口规则决定。代理出站可按已校验域名拨号。 |
| `domain+` | 是 | 否 | 保留初始 IP 规则决策，但允许代理出站使用嗅探域名作为目标。 |
| `domain++` | 是 | 否 | 根据嗅探到的 SNI/Host 重新计算非保留决策，再使用所得代理域名目标。 |

直连、阻断、`must` 及其他保留 handoff 保持最终决策，并保留原始 IP 目标。

## 数据目录与资源路径

`data_dir` 默认为 `/var/lib/honk`，必须是非空绝对路径，并在进程内只设置一次。启动时 honk 会递归创建目录，再用一个私有随机文件做 create-new/remove 探测。候选目录不可用时，只有通过同一探测的进程工作目录能作为回退；两者都不可用时，启动失败并报告两项原因。使用 `--store db` 或启用原生 API 密码登录时，启动过程不允许这种回退。旧根目录是 `/var/share/honk`，也称 `LEGACY_DATA_DIR`，用于复用已有资源。旧缓存和订阅导入会把符合条件的状态复制到 `state/honk.db`。即使使用自定义 `data_dir`，也遵循相同的回退顺序。绝对的子路径保持原样。

`geoip.dat` 和 `geosite.dat` 严格使用以下顺序中第一个已存在的普通文件：

1. `$DAE_LOCATION_ASSET/<name>`
2. `<data_dir>/<name>`
3. `/var/share/honk/<name>`，也就是 `LEGACY_DATA_DIR`
4. 进程工作目录中的 `./<name>`
5. `/usr/local/share/honk/<name>`，然后 `/usr/share/honk/<name>`
6. `/usr/local/share/dae/<name>`、`/usr/share/dae/<name>`，然后 `/etc/dae/<name>`

其他相对运行时路径按下表保留旧安装。除日志外，每次查找先检查实际生效数据目录中已有的副本，再检查 `/var/share/honk` 中已有的副本，最后检查各调用方的已有旧候选路径。都不存在时，返回 `data_dir` 下的路径用于创建；绝对路径保持原样。

| 路径 | 解析与旧路径回退 |
| ---- | ---------------- |
| 节点 `ech_config_path` | 依次优先使用已存在的 `<data_dir>/<path>`、已存在的 `/var/share/honk/<path>`，以及已存在的工作目录相对路径。都不存在时解析为 `<data_dir>/<path>`，使读取错误指出预期位置。 |
| `global.log_file` | 相对路径始终通过一个只用于创建的路径 helper 解析为 `<data_dir>/<path>`，启动时创建父目录；它不会读取或迁移 `/var/share/honk` 里已有的日志。绝对路径保持原样。在 Linux 上，新日志文件使用 mode `0600`；符号链接和非普通文件会被拒绝，已有普通文件的权限保持不变。honk 追加写入，文件达到 10 MiB 时轮转：当前文件改名为 `<name>.1`，覆盖旧副本，然后按相同检查打开新文件，因此日志最多占用 20 MiB。重启交接期间两个实例共用该文件时，只有文件仍在原路径上的实例执行改名，另一个实例直接切换到新文件，所以不会互相覆盖轮转副本。轮转失败时，例如新文件打不开，honk 不再尝试轮转，继续写当前文件直到 20 MiB，之后丢弃日志行，并在 stderr 输出一次 warning，直到重启。控制台和文件里的时间戳都是本机本地时间，带 UTC 偏移，例如 `2026-09-12T02:30:15.123456+10:00`。 |
| `experimental.cache_file.path` | 不再决定存储位置，状态保存在 `<data_dir>/state/honk.db`。首次启动时按旧的解析顺序读取一次，用于导入旧 `cache.db`。见[升级说明](./experimental.md#从-cachedb-升级)。 |
| `experimental.clash_api.external_ui` | 依次优先使用已存在的 `<data_dir>/<path>`、已存在的 `/var/share/honk/<path>`，以及已存在的工作目录相对目录。都不存在时，dashboard 下载使用 `<data_dir>/<path>`。 |
| 订阅存储 | 正文保存在 `<data_dir>/state/honk.db` 中。每次启动时，honk 依次在 `<data_dir>/.sub`、`/var/share/honk/.sub`、`./.sub` 中查找第一个私有的旧存储，导入已启用订阅的正文，然后删除已复制的文件。见[订阅参考](./subscription.md#拉取持久化与恢复)。 |

## 预热与拨号预算

`preconnect_node_count`、`udp_warm_node_count` 和 `max_concurrent_dials` 取非负整数，例如 `4`；`preconnect_node_count` 还接受不区分大小写的 `auto`。其他值以 `invalid-config-value` 拒绝配置。这三个字段与代理组的交互见[组设计](../design/groups.md)。

## 捕获后端选择

省略 `datapath` 会保持现有 TC 后端。XDP 是 Linux 上的显式选择：

```dae
global {
    nfqueue_enable: false
    dial_mode: ip
}
datapath {
    backend: xdp
    direct: core
    interface {
        lan0: lan
        wan0: wan
    }
}
```

`direct` 必须显式选择 `core`（最终 Direct 数据包由 CoreForward 转发）或
`endpoint`（Direct TCP 终止后中继）。防火墙/NAT 仍仅限 `direct: core`。

接口角色是可信的 LAN/WAN 入站分区，不是执行方式；必须绑定发现的全部 RX 队列。
XDP 不可同时配置
`global.lan_interface` 或 `global.wan_interface`。
后端、Direct 方式、有效 AF_XDP 绑定模式及接口/分区变更需要重启；受支持的
防火墙/NAT 规则沿用事务式发布。未知字段及不支持的非零标记续送请求会被拒绝，
不会被静默忽略。
物理接口声明为 `名称: lan` 或 `名称: wan`。XDP Endpoint 还可用 `名称: l3_lan`
声明[辅助 IP 接口](#辅助-l3-lan)。接口条目不接受子块，包括空子块。

物理捕获的 `datapath.xsk_mode` 接受 `copy`、`zerocopy` 或 `auto`。省略仍强制 ZeroCopy；Auto 按每个成员的能力与所需 segment 选择。每次 bind 均回读验证，选定模式失败不会重试其他模式。省略与显式 `zerocopy` 在重载时等价，模式变更需重启。TC 和 TUN 拒绝显式模式；Host 不使用 AF_XDP 队列。

`datapath.workers` 是仅限 XDP 的整数，只接受 `1`（默认）或 `2`，修改需要重启。
双 worker 要求至少两个真实物理队列 owner，且有效 cpuset 至少有两个 CPU。
每个 worker 在 OS 线程上独占其队列和 Stack 分片；Host 与 Core 协调仍在
worker 0。逻辑 realm、DNS/UDP source 所有权及内存/流总上限不会翻倍。
两个 worker 共享原有单个可选 Busy grant；校准包含双方队列/CPU context，
旧单 owner 的校准证据不能使新配置获得资格。

**从原 Copy 默认值迁移：**已有 XDP 配置若省略 `xsk_mode`，现在要求全部选中
队列实际支持 ZeroCopy。若要保留 Copy 行为，请在升级前向原有 `datapath` 块加入
`xsk_mode: copy`。否则，不支持 ZeroCopy 会拒绝启动，不会静默降级。省略
`datapath` 的配置仍使用 TC，不受影响。

Core Direct 要求 `dial_mode: ip`；域名谓词使用 packet 入口 scope 内学到的事实。物理入口提供源 MAC，但没有经认证的进程事实。未启用 Host 时 pname 使用 Missing 语义，并通过现有 `pname_routing` 报告降级；路由器本机发起的流留在内核。Endpoint 接受带地址的以太网和 bond 接口，启动时检查所有默认路由不能从捕获口输出；运行期由操作者保持。物理 link 由 FD 持有，进程退出时 detach；honk 修改的 VLAN RX stripping 位在正常停止或启动失败时恢复，SIGKILL 后保持关闭。参阅[完整 XDP 启动与限制](../design/datapath.md)。

Core 的输入上下文 FIB 契约拒绝非零 IPv6 flow label 及无法保持语义的路由器扩展头/options；Endpoint 支持 IPv6 不证明 Core 对这些组合具有等价授权。

### 辅助 L3 LAN

```dae
datapath {
    backend: xdp
    direct: endpoint
    interface {
        eth1: lan
        wg0: l3_lan
    }
}
```

至少配置一个物理 XDP `lan` 或 `wan` 后，可额外声明最多八个名称不同的
`l3_lan`。辅助口不算物理 worker 或 RX 队列。按实际链路判断：只接收裸 IP
设备（`ARPHRD_NONE`），MTU 至少 1280，且不得作为默认路由的出口。以太网、
PPP、GRE 不会因接口名而获准。TC、TUN 和 Core Direct 不能与该角色组合。Host 出口必须与该接口分开。物理口 XDP 准入失败不会降级成 TCX。

尚不存在的辅助口可进入 `waiting_link`；启动时已存在却不合规的接口会拒绝
启动。在役绑定使用 TCX ingress 与专有、无地址、非持久的 `honk-l3-<n>` TUN。
不要把这些生成名用作配置的接口名。honk 不为内口添加地址、路由或策略规则，
也不删除既有入向过滤器：若 Endpoint 重定向会跳过传统 ingress 分类器，则不
绑定该口。若 WireGuard 服务在**被物理捕获的接口**上监听 UDP 53，须为该监听
显式配置静态 `direct(must)` 流量规则；端口 53 不享受本机服务豁免。

### XDP Endpoint DNS 投影

`datapath.dns_projection` 是可选布尔值，仅适用于 `backend: xdp`、
`direct: endpoint` 且至少有一个 `lan`、`l3_lan` 或 Host 出口的配置。省略或显式写
`true` 都会启用 DNS 投影，写 `false` 可关闭。有效值变更需要重启。TC、
TUN、XDP Core 和没有合格接口的 XDP Endpoint 必须省略该字段，显式写任一
布尔值均会被拒绝。跨合并分段或 include 重复声明，以及结构化输入中的显式
`null` 也会被拒绝。

只有在同一逻辑 LAN realm 接受的透明 DNS 应答才能提供事实。bond 成员共用 bond 的 realm；每个 VLAN 使用自己的 realm 并继承配置根接口的角色。每个辅助 LAN 的 scope 独立，绑定失效时撤回该域的事实。WAN、Host 和独立 `dns.bind` 均不为 LAN 提供事实。

对于目的端口非 53 的纯 TCP SYN 或完整 UDP 数据报，有序策略选中无 mark 的 `direct(must)`，或在 `dial_mode: ip` 且为 Rule 模式时选中普通无 mark 的 `direct`，才可交内核路由。事实缺失、过期或冲突不能授权新的原生流；既有静态 D1（含 `:53 direct(must)`）不变。

UDP 数据报可以是零长度 payload，也可以带无需重组的 IPv6 atomic fragment 头。真正需要重组的第一片不能建立或续签 DNS 原生归属：新流走 Endpoint；已有原生 pending 且未命中 conntrack 时，只丢当前包。后续片没有端口，只沿用既有分片判定，不另查 DNS。静态 Direct 和已确认的 conntrack 匹配保持原行为。

TCP 与 UDP 共享 8,192 个等待对应 conntrack 证据的 DNS 原生名额。满额时新流改为争取 Endpoint 归属。conntrack 接管之前，重复 SYN 或同流后续 UDP 报文仍须满足当下的策略；许可撤回就丢当前包，不拆分同一条流。同键竞争且有界复查仍无法确定归属时，也只丢当前包。命中同键 conntrack 或满足 30 秒空闲回收条件可退役 pending 记录；30 秒不是删除期限。

一旦观测到 `notrack`，honk 会告警，并在本次 capture 的剩余时间关闭 DNS 许可。静态 D1 和 Endpoint 继续工作。运行期 legacy raw 表是周期抽查，不能与并发防火墙更改构成原子屏障。采样计数和回退原因见 [XDP 诊断](./api.md)。

### XDP Host Endpoint

使用启用了 `ebpf` 的构建，可在指定出口对本机发起的 TCP/UDP 分流：

```dae
global { nfqueue_enable: false }
datapath {
    backend: xdp
    direct: endpoint
    host { interface { eth0 } }
}
```

配置 1–4 个不同接口名。不接受 `lo`、`auto`、与物理捕获口（包括 bond 成员与 VLAN）或辅助 LAN 重叠的接口，也不再接受 `host.xsk_mode`。见[迁移说明](../../migration/zh/gateway-host.md)。纯 Host 配置不需要物理队列；`workers: 2` 仍需两个实际物理队列 owner。更改出口列表需重启。

支持的以太网、VLAN、网桥或裸 IP 出口（例如 WireGuard）要求 MTU 至少为 1280，不支持 PPP 和 GRE。尚未出现的接口可等待上线；不合规的设备不能挂载。每个活动出口独占一个无地址、非持久的 `honk-host-<n>` TUN。不要给这些私有设备添加地址、路由或改写报文的程序。honk 不修改主路由，也不要求清空防火墙。

已证明的 Direct 保留原 socket，Endpoint 流固定在原出口，回复从该出口注入 Linux。进程名称来自 socket，不能证明每次 `sendmsg` 的调用者。honk 自发 socket、管理和 DNS 监听必须使用有效 bypass mark。容量与延迟包见 [Host 来源托管](../design/datapath.md#host-来源托管)。`backend: tun` 的 `host_facts` 契约独立。

### Linux TUN Endpoint

通过 `backend: tun` 和 `direct: endpoint` 显式选择 TUN。honk 新建并独占一个
非持久化 Linux TUN。下列资源由操作者选择。

```dae
global {
    nfqueue_enable: false
    so_mark_from_dae: 0x100
    dial_mode: ip
}
datapath {
    backend: tun
    direct: endpoint
    tun {
        name: honk0
        mtu: 1500
        queues: 1
        host_facts: true
        address4: 198.18.0.1/32
        address6: fd00:686f:6e6b:100::1/128
        table: 202
        rule_priority: 10000
        capture {
            0.0.0.0/0
            ::/0
        }
    }
}
routing {
    fallback: direct
}
```

| `tun` 字段 | 必需值与准入 |
| --- | --- |
| `name` | 必填；1–15 个 ASCII 字节，仅限 `[A-Za-z0-9_.-]`，拒绝 `lo` 和 `auto`。该 netns 内必须尚无同名链路，绝不接管或替换已有链路。 |
| `mtu` | 可省略，默认 `1500`；整数 `1280..=65535`。 |
| `queues` | 可省略，默认 `1`。接受 1 到 8 的整数，包括非 2 的幂。大于 1 时要求 `host_facts: false`。变更需重启。 |
| `address4` / `address6` | 至少配置一个，严格使用 `/32`、`/128` 主机前缀。拒绝 unspecified、multicast、broadcast、mapped IPv6、link-local 及重复的本地地址。 |
| `table` | 必填；`1..=0xfffffffe`，排除 `253..=255`。任何现存 route/rule 都不得使用此专用表。 |
| `rule_priority` | 必填，首优先级 P；`P >= 1` 且 checked `P+4 < 32766`。五个优先级 `[P,P+4]` 必须全部空闲。 |
| `host_facts` | 可选严格布尔值，默认 `false`。`true` 要求 `queues: 1`、`ebpf` 构建与真实来源捕获。变更需重启。 |
| `capture { ... }` | 必填，1–64 条已配置地址族内的规范 CIDR 网络。拒绝 host bits 及互相包含的冗余前缀；排序并去重。仅接受裸前缀，不接受键值条目或嵌套块。 |

TUN 必须恰有一个 `tun` 块；TC/XDP 拒绝该块。TUN 拒绝 `interface`、
`xsk_mode`、显式 `poll_mode`、`dns_projection`、`busy_poll`、`firewall`、
非空 `nat` 及 `direct: core`。未知字段以及
合并 sections/includes 后重复的标量/块均拒绝；结构化输入使用同一校验。
这是新增的显式选择，既有配置不改变含义，无须 TUN 迁移。

要求 Linux、`/dev/net/tun`、创建/配置 TUN 和应用 `SO_MARK` 的权限，不能传
`--mock-ebpf`。必须显式关闭 NFQUEUE，并保持 `global.lan_interface`/
`wan_interface` 为空。拒绝非零 traffic rule/default mark、MAC 谓词及其否定；
进程名谓词要求单队列 HostFacts。既有四种 dial mode 均可使用。参见 [pname](./routing.md#pname)。

对每个已启用地址族，honk 验证系统 priority-0 local rule，并安装恰好五条自有
RPDB rule；M 为有效 `global.so_mark_from_dae`，T 为 `tun.table`，P 为
`tun.rule_priority`：

| 优先级 | 精确匹配 | 动作 |
| --- | --- | --- |
| P | `fwmark M/0xffffffff` | `lookup main` |
| P+1 | `fwmark M/0xffffffff` | `prohibit` |
| P+2 | `iif <tun.name>` | `lookup main` |
| P+3 | `iif <tun.name>` | `prohibit` |
| P+4 | 全部流量 | `lookup T` |

系统 local rule 先执行，32766/32767 的普通 main/default rule 保留。T 中每条
capture prefix 先安装 metric 32760 的 static blackhole guard，Endpoint 启动后
才加入经 TUN 的 metric-1024 unicast route。不复制 main 表，不合成私网豁免。
daemon socket 经 P/P+1 旁路；写入 TUN 的回复作为新 interface ingress 进入
内核，经 P+2/P+3 回程。main 缺路由时终止，不重新进入 TUN。

两个地址族的 active capture 都使用 metric 1024：Linux 会规范化 IPv6 的
metric 0，而 IPv4 删除时 metric 0 表示通配。这是相对初始 metric-0 设计的
明确 Linux 表示调整。Exclusive create、回读与删除均使用完整 route key：
table、地址族、prefix、output interface 和 metric。Blackhole guard 保持 32760。

操作者持有 main/default 路由、WAN/LAN 地址、NAT、防火墙及 forwarding 开关，
并须保持拓扑稳定。每个已启用族都须有可用源地址和非 TUN 的 main uplink；拒绝
main/default 中经 TUN 的路径、额外 local rule、P 之前的其他 rule、VRF/l3mdev、
未知 selector/action 及其他对 T 的引用。capture/reply 腿必须保持实际 L3 策略
输入，不宣称外部 NAT 等价。拓扑变化或通知丢失关闭捕获；watcher 不是抵御并发
特权路由修改的原子栅栏。仅自有 TUN 设置 `rp_filter=0`，IPv6 关闭自动地址生成/
RA，明确配置 NODAD 地址。

启用 IPv4 时，TUN 启动会在创建任何资源前读取
`net.ipv4.conf.all.rp_filter`。接受 `0` 和 `2`；严格模式（`1`）、未知值或
读取失败均拒绝启动。请在启动 honk 前将其设为 `0` 或 `2`。Linux 验证本地
交付回复的源地址时，使用 `iif=lo` 和数据包的 mark（未标记的物理承载回复为
`0`）进行反向查路由。在 TUN capture RPDB 下，该查询命中经 TUN 的捕获路由，
与真实入站接口不符，因此严格模式会丢弃代理/Direct 承载回复。有效设置取
`max(all, interface)`，自有 TUN 的 `0` 无法降低全局 `1`。honk 从不写入全局值，
也不修改 WAN/LAN 的 `rp_filter`。操作者在启动后改为严格模式不会被运行时检测。
仅 IPv6 的 TUN 不读取也不因该 IPv4 设置而拒绝启动；IPv6 没有对应的
`rp_filter` 设置。

Setup 以 create-new、拒绝符号链接、mode 0600 创建
`<data_dir>/state/tun-<netns_cookie>-<instance_nonce>.json` receipt，记录完整源码
SHA、PID/starttime、netns cookie、link/attachment identity 及精确 address/route/
rule key。每次外部变更前先持久化 Intent；ACK 与 Removed 状态均持久化并 fsync。
它只供操作者精确核对清理，不授权重放 setup、接管资源或删除归属不明对象。
详见 [TUN setup 与拆卸](../design/datapath.md#linux-tun-endpoint)。

Direct TCP/UDP 明确使用 Endpoint relay：真实 TUN FD read → scoped Stack →
canonical Router → 新建 direct/proxy outbound → 生成回复 → 所属分片的 FD。启用
`host_facts: true` 时，经认证的应用 socket 记录携带原始来源事实进入独立 Host
scope；见证过但无归属的记录仍走 plain，不代表已证明 Transit。进程名仅在经认证
Host 来源且存在时可用；Missing 不匹配正向谓词，但匹配其否定。两个 scope 共用
384 MiB capture 预算。独立 DNS 只在 plain scope 学习，透明 DNS 使用对应 packet
scope；均不借用 HOST DNS 事实。来源准入要求真实支持，来源错误不能回退 plain；
读取延迟不刷新原始来源有效期。生成回复不提供原 operation 或 pre-NAT/TTL 等价。

整个规范 TUN setup（含 `queues` 与 `host_facts`）、backend 与 Direct profile 变更均需重启。
省略时分别等同于 MTU 1500、`queues: 1` 与 `host_facts: false`。
policy/group/DNS/订阅/mode 更新沿用既有 FD 与 scope。`dns.bind` 语义变化仍需重启。正常 joined stop 先撤销 capture，等待真实 owner
退出，再移除自有 rule/guard 与 receipt，恢复 main 路由。失败或未确认清理时保留
blackhole、rule 与 receipt，供停源后核对并精确清理；不自动重开、接管或回退后端。

`/configs.tun` 报告已接受配置（`enable`、`device`、`mtu`、`stack: "honk"`），
IPv6 投影由 `address6` 决定；这些字段不是就绪证明。就绪由 `capture_ready()`
后的 lifecycle Running、`TUN datapath ready` 与 sd_notify 表达；native datapath
可见性仍为 unknown。

### 有界自适应轮询

XDP 的 `datapath.poll_mode` 接受 `event` 或 `adaptive`。省略表示选择 adaptive **策略**，
不是立即进入 Busy：owner 从 Event 开始。显式 `event` 禁止主动轮询，但允许保留
完全相同的调参与校准块，用于 Event/adaptive 对照。TC/TUN 拒绝任何显式模式（包括
`event`）及任何 `busy_poll` 块。轮询与校准可重载而不重建设备；变更清除本地
资格累计，但不重置进程配额或债务。

`datapath.busy_poll` 是可选单例块；出现时下列九个整数全部必填，不提供已校准的
PPS 默认值。值采用无符号十进制整数，不接受 duration 字符串或浮点数。

| 字段 | 类型 | 接受的安全/表示边界 |
| --- | --- | --- |
| `pps_enter` | `u32` | `1..=4294967295` |
| `pps_exit` | `u32` | `0 <= pps_exit < pps_enter` |
| `observation_window_us` | `u32` | `1..=60000000` 微秒 |
| `enter_windows` | `u16` | `2..=65535` 个连续完整窗口 |
| `exit_windows` | `u16` | `1..=65535` 个连续完整窗口 |
| `max_busy_us` | `u32` | `1..=1000` 微秒且 `<= budget_us` |
| `empty_rounds` | `u16` | `1..=65535` 个完整空设备轮次 |
| `budget_window_us` | `u32` | `1..=60000000` 微秒（W） |
| `budget_us` | `u32` | `0 < budget_us < budget_window_us`（B） |

唯一可选子块是单例 `datapath.busy_poll.calibration`。出现时全部字段必填：正整数
`schema: u16`、正整数 `counting_revision: u32`、`executable_sha256`、
`context_sha256`、`parameter_sha256`、`status: candidate | qualified` 和
`evidence_manifest_sha256`。四个摘要各为恰好 64 个小写十六进制字符。消费方要求
schema 1/counting revision 1；格式正确的其他版本保持 Event 并报告不匹配原因，
不会假定其兼容。

`candidate` 的 `evidence_manifest_sha256` 绑定**已预注册的实验清单**，不是未来
补交结果的空承诺。候选资格还要求进程启动时显式选择校准实验模式，不能靠配置
重载开启。`qualified` 的摘要绑定经过评审的已完成资格证据清单。两种状态都必须
精确匹配可执行文件、实际设备/上下文及参数。摘要/状态不是签名、下载的测量结果
或收益证明；配置不提供清单路径或 URL。

未知键/块、重复字段/块（包括合并 section/include）、不完整块、正负号、小数、
溢出及非法边界均拒绝准入。类型化适配器沿用相同准入规则；新增可选字段的显式
`null` 被拒绝，原有类型化适配器的 `xsk_mode: null` 行为不变。不提供 global/顶层
calibration 别名或逐接口配额。

缺少调参/校准、证据不匹配、必要上下文不可用或无法证明共享进程记账时，仍可
使用正常 Event 网络处理，并保留资格原因。Busy 还要求独立 RX 或 TX PPS 持续
达标、具体可轮询设备义务及进程额度。RX 统计已证明准入的结果而非源地址收据；
TX 统计完整 producer 发布而非描述符/CQ 事件。进程账本同时至多允许一个 Busy
区间，初始额度为零，按完整 BOOTTIME 流逝时间（含停顿）收费，跨重载保留债务，
并放弃未结算区间跨越的补充额度。Busy 到达边界/截止时间后退出并让出执行，再
重新评估；仅有配额不会唤醒空闲 owner。Event 不是对有效业务或总 CPU 的限额。

这些是协作式安全边界，不是实测阈值或硬实时保证。时钟连续性观察不能排除低于
保留的非原子读取/分辨率不确定性的 suspend。未经与精确绑定上下文一致的完整
证据和评审，不宣称吞吐、延迟、CPU 或能耗收益。

## 相关文档

- [配置指南](../configuration.md)
- [节点参考](./nodes.md)
- [组参考](./groups.md)
- [组设计](../design/groups.md)
