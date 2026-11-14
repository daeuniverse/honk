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
    udp_check_dns: 'dns.google:53', '8.8.8.8', '2001:4860:4860::8888'
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

单实例交接后，固定队列不可用，或数据路径 admission 之前队列、规则、健康检查失败时，honk 会记一条 warning，并在本进程内关闭该功能，不改写配置。安装阶段会回收保留的 nftables table。

持久化 token generation 恢复失败，以及 [admission 后的失败](../design/nfqueue.md#启用与范围)，仍然是 fatal。

`experimental.udp_nfqueue.enabled` 已弃用，改用 `nfqueue_enable`。旧写法仍被接受，并产生迁移 warning；两者同时存在时以 `nfqueue_enable` 为准。

只有确实发生过降级时，写入和 reload 才能继续请求 `nfqueue_enable: true`，而 NFQUEUE 的生效值保持关闭。省略该 key、采用默认值 `true`，也算这种请求。降级分两种：启动早期的降级（mock、不带 `ebpf` feature，或固定队列的前置检查失败），以及数据路径 admission 之前较晚发生的队列、规则或健康检查降级。此时请求的源文本保持原样，生效值在本进程整个生命周期内都是 `false`。honk 不会自动重试启用，只有重启才会重试。没有发生降级时，开关的变更仍需重启。[公共 reload 流程](../design/control-plane.md#reload-与运行时-generation) 在指纹/no-op 检查之前归一化生效配置；原生 API 的写入前检查与完整校验使用同一套重启策略。

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

优先选择第一个 IP 字面量，没有就解析第一个域名。解析结果与 Score 共用同一个解码后的主机和端口；域名解析完成后仍保留域名身份。

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

`shutdown_wait_connections: true` 让 honk 在退出时给已接受的连接最多五秒自然结束，然后关闭并 join 剩余连接。这个宽限只在关闭过程正常、数据路径健康、且存在活动的 runtime epoch 时生效。其他情况跳过等待，不分长短连接。

关闭使用最近接受的配置；reload 被拒绝时保留旧值。这个开关不影响 reload 退役、DNS/状态持久化、NFQUEUE/eBPF 清理，也不影响原生 API 独立的[五秒 HTTP 宽限期](./api.md#原生-api)。

这不是优雅重启，也不限制总退出时间：[已持有的清理和阻塞工作](../design/control-plane.md#终止所有权)仍须完成。

## socket mark

`so_mark_from_dae: 0` 或省略该项时，保留历史上的实际 mark `0x100`。非零值替换 `0x100`，不会和它按位 OR。honk 在 connect/send 之前原样应用该 mark，作用于代理 carrier、bootstrap/DNS、健康检查、订阅和 UI 下载。数据路径按配置值做精确旁路匹配，仅仅带有 `0x100` 这一位并不能免于拦截。透明 listener socket 使用同一个 mark 供内核识别；accept 得到的 TCP 客户端 socket 会清除这个 mark。独立 `dns.bind` 入口仍是普通的无 mark 本地服务。

dae 全局标量沿用 honk 既有的十六进制优先规则：`10` 和 `0x10` 都表示 16。格式错误或溢出的文本会产生诊断，并回退到原始值 `0`，实际生效的是 `0x100`，建议显式写 `0x`。这与[直连规则 mark](./routing.md#策略路由-mark) 不同：后者无前缀时按十进制解析，错误值直接拒绝配置。

全局与规则 mark 的校验都拒绝保留位 `0xc0000000`；全局 mark 还拒绝 TPROXY 位 `0x08000000`，daens 会把该位路由到自己的 listener，因此全局 mark 保留的是 `0xc8000000`。

这个值在启动网络 I/O 之前确定，作用于整个进程；修改需要重启，不能通过 SIGHUP 切换。非零直连规则 mark 会替换该直连流的全局策略路由有效位，代理 carrier 和 bootstrap 仍使用全局值。直连流还携带内部分类元数据；请使用 [路由参考](./routing.md#策略路由-mark) 中带掩码的 IPv4/IPv6 `ip rule` 示例。honk 不负责安装用户的 WAN 策略路由表、路由、源地址规则或 NAT 配置。

## reload 健康检查与 TLS 模式

以下参数在启动时确定。reload 若改变生效值，会被拒绝；当前配置与已安装的探测器保持不变：

- `check_interval`。
- 第一个 `tcp_check_url`，包括回退地址、路径和查询字符串。缺失或空的首项均关闭 HTTP 探测；后续项不参与比较。
- HTTP 探测启用时的 `tcp_check_http_method`。空值与 `HEAD` 等价。
- `udp_check_dns` 选中的目标。处理时先去除首尾空白、忽略空项，优先取列表里第一个 IP 字面量，没有就取第一个域名，两者都没有时使用 `8.8.8.8:53`。reload 检查只比较配置中的地址或域名及其端口，不解析 DNS。域名比较不区分大小写，并忽略一个尾随句点，因此 `dns.example:53` 和 `DNS.EXAMPLE.:53` 是同一目标。未选中项的变化仍可 reload。
- `tls_implementation` 在原生 TLS 与 uTLS 之间的切换。比较 `utls` 时不区分大小写。

dae 配置中的 `check_tolerance` 仍可通过 reload 更新 URLTest 组的容差。组级检查 URL 和直接连接探测仍沿现有路径动态更新。reload `utls_imitate` 只保存兼容配置值，不改变指纹。

Score 组还会对第一个 `tcp_check_url` 发起 QUIC 握手探测。该 URL 必须以小写 `https://` 开头，否则此探测关闭，Score 只使用其他探测，并由 `quic_probe` 降级项报告。QUIC 目标只在启动时建立，因此 reload 新增第一个 Score 组时会报告原因 `restart_required`，直到下次重启。

UDP DNS 目标在启动时按健康检查超时尝试初始化。本地拒绝或初始化超时会让配置目标保持待定，留给后续健康检查周期重试；honk 不替换默认目标，也不降低节点健康状态，独立的 QUIC 检查仍可继续。首次成功解析出的地址随后保持固定。延后的解析和 DNS 交换共用同一次探测的绝对期限；普通解析失败保留原有的默认回退。

## 流量入口与拦截

honk 通过所配置网卡上的 eBPF TC hook 接收流量，不提供供客户端连接的代理端口。

- `lan_interface` 上的 hook 拦截 LAN 客户端经本机转发的流量，例如把本机设为网关的客户端。
- `wan_interface` 上的 hook 拦截本机发起的 TCP/UDP。
- 需要用户态处理的流量由数据路径经 `dae0` 送进 `daens` 命名空间，再由 `sk_lookup` 交给 `tproxy_port` 上的透明代理 TCP 或 UDP listener。有歧义的 LAN 转发 UDP 则由 NFQUEUE 暂存（`nfqueue_enable`）。
- 拦截需要真实 eBPF 后端；mock 后端不拦截任何流量。

honk 没有 TUN 入站，也没有 `mixed-port`、`redir-port` 或 HTTP/SOCKS 入站。Clash API 的 `GET /configs` 把 `port`、`socks-port` 和 `mixed-port` 报告为 `0`，把 `tun.enable` 报告为 `false`。除透明代理 listener 外，honk 只监听可选的 [`dns.bind`](./dns.md#独立-listenerbind) 地址，以及 [`experimental`](./experimental.md) 中配置的 API listener。流量经过各个 hook 的过程见[报文路径](../design/overview.md#报文路径)。

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

## 相关文档

- [配置指南](../configuration.md)
- [节点参考](./nodes.md)
- [组参考](./groups.md)
- [组设计](../design/groups.md)
