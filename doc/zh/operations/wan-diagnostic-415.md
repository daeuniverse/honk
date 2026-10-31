# Issue #415：用 honk-tool 采集 WAN 诊断信息

本构建用于排查 issue #415，只增加采样，不改变转发行为，**不是 SIPA 问题的修复版**。该设备请用 aarch64 musl 包：`honk-core-*` 内含静态 core/tool，也可单独下载 `honk-tool-debug-aarch64-unknown-linux-musl.tar.gz`。BPF 已嵌入 core。设备上不需要 bpftool、tracefs 或编译器。

需要 root/BPF 权限、Linux TCX 和可读的 `/sys/devices/system/cpu/possible`。core/tool 必须来自同一诊断 tag，并选择相同的架构和 libc。curl 只用来发起测试请求。

## 启动前

备份原可执行文件和配置，正常停止原服务，确认没有 honk 进程，再运行包内的 `honk-core --config /etc/honk/config.dae`。不要覆盖运行中的文件或启动第二份引擎。保留原数据目录及 `UDP_DECISION_SEQUENCE`、`ROUTING_GENERATION_SEQUENCE`，不要清空 bpffs。

工具不加载程序或挂载 hook，只写诊断开关 `WAN_DIAG_CFG`，不改数据面状态或清零计数。它检查 map 布局及其与接口上 TCX 程序的对应关系，清理只操作原先打开的 map，不会写入重启后的替代 map。program/link 检查只在采集前后进行；采集期间不要重载或改配置。

采样默认关闭。**一次只运行一个采集器，不要同时执行恢复命令。** 启动检查不是并发锁；遇到已有非零 filter 会拒绝启动，需先停止原采集器或恢复。

## IPv4：两个终端

终端 A（改为实际 WAN 接口；使用自定义 pin root 时加 `--pin-root PATH`）：

```sh
umask 077
./honk-tool bpf wan-diag --interface sipa_eth0 \
  --source-port 41500 --seconds 20 > wan4.json
```

等 stderr 出现 `WAN diagnostic sampling ready:` 后，在终端 B 执行：

```sh
umask 077
(
  date -u
  RC=0
  curl -q -4 --noproxy '*' --http1.1 --local-port 41500 \
    --connect-timeout 5 --max-time 15 --verbose \
    --write-out '\nlocal=%{local_ip}:%{local_port} remote=%{remote_ip}:%{remote_port}\n' \
    https://api.ip.sb/ip || RC=$?
  date -u
  printf 'curl_exit=%s\n' "$RC"
) > wan4-curl.txt 2>&1
```

到时自动关闭采样，stdout 输出一份含 `before` / `after` 的 JSON，不逐包打印。确认命令成功退出且 JSON 可解析；失败产生的空文件不代表没有流量。

保持 `-q` 为 curl 的首个参数，忽略 `.curlrc`；`--noproxy '*'` 排除代理环境变量。不要绑定 WAN 设备，以免改变 socket 行为。已知目标 IP 时可加 `--resolve api.ip.sb:443:ADDRESS`（IPv6 加方括号），不要用 `-k` 跳过 TLS 校验。DNS 失败或错过采集窗口，不能说明 TC 未运行。

IPv4 结束后再测 IPv6：两处端口都改为 **41501**，curl 改 `-6`，输出改为 `wan6.json` / `wan6-curl.txt`。端口被占用时同步换一个，也要避免 LAN 流量使用同一端口。

## 中断与恢复

`--seconds` 接受 1–300，默认 15。INT/TERM/HUP 会尝试关闭采样后输出已有结果；`end_reason` 和 `elapsed_ms` 记录结束原因与耗时。时限限制采样，不保证输出管道阻塞时进程能及时退出。

写出 JSON 或报告清理错误前，工具会释放 map/program FD。输出阻塞不会继续保留旧引擎的生产 map。

SIGKILL、系统故障或关闭写入失败可能留下开启的采样。确认原采集器已停止后执行（自定义 pin root 时加对应参数）：

```sh
./honk-tool bpf wan-diag --interface sipa_eth0 --disable
```

已关闭时可重复执行。若 map/接口检查失败，不要强写 map；正常停止并重启同版本的诊断引擎，不要清空 bpffs。

## 读取 JSON

顶层记录接口、program/link/map ID、源端口、时长和结束原因。`before` / `after` 只列出计数非零的 reason/CPU-slot 行。

每行包含累计包数 `packets`、单调时间 `timestamp_ns`、`socket_cookie`、出入口 ifindex、`mark`、EtherType `protocol`、包长、`parse_result`、`first_byte`、`link_h_len` 和五元组 `tuple`。`tuple=null` 表示没有五元组；`first_byte=-1` 表示读取失败。这两个结果字段有符号；protocol 和端口用主机字节序，IPv4-mapped 地址显示为 IPv4。

| reason_index | reason | 现有路径 |
| --- | --- | --- |
| 0 | scratch_unavailable | scratch 不可用，丢弃 |
| 1 | parse_pass | 解析未成功，继续 |
| 2 | parse_drop | 已确认应丢弃的分片或本地 NDP Redirect |
| 3 | queue_carrier_drop | NFQUEUE DNS carrier 丢弃 |
| 4 | vlan_pass | 交给后续 VLAN 设备 |
| 5 | not_ready_pass | datapath 未 ready，继续 |
| 6 | special_pass | 广播/组播/特殊目的地址 |
| 7 | local_destination_pass | 目的地址匹配 PARAM.local_ip |
| 8 | forwarded_pass | ingress_ifindex 非零，按转发包继续 |
| 9 | marked_pass | 精确 bypass/classified mark，PASS |
| 10 | tuple_fence_drop | tuple fence 拒绝 |
| 11 | tcp_acquire_drop | TCP publication acquire 拒绝 |
| 12 | dispatch | 进入 TCP/UDP handler，不是已代理成功 |

注意：

- **原因 0/1/2 记录整个接口上未解析的包，不受源端口筛选，不能归到 curl 请求上。**
- 计数累加，每种原因/CPU 只保留最后一个样本。比较 before/after；未变的旧样本不是本次请求。
- `cpu_slot` 是 possible-CPU 缓冲区的位置，不一定是 CPU 编号。计数可汇总，样本字段不能跨 slot 拼接。
- `coherent_snapshot=false`：关闭采样不等待在途写入，读取时仍可能发生写入或样本覆盖。
- 相同源端口也可能来自 LAN。按 curl 输出核对完整五元组、协议族和时间窗口；cookie 不能证明本机来源，读取时也可能首次分配它。
- 只有匹配该次 curl 的 `forwarded_pass` 才能确认 ingress_ifindex 判据放行。`dispatch` 只表示进入 TCP/UDP handler，不表示代理成功；空或不匹配的样本无法定因。

回传两个 JSON、两份 curl 输出、两个程序的 `--version`、包校验和、启动/绑定日志及接口信息。JSON 含 IP，不含应用数据、配置或凭据；分享前请脱敏。

## 恢复原服务

导出结果、确认采样关闭，正常停止诊断引擎，再换回原可执行文件并启动服务。关闭时只尝试删除自有 pin，残留 pin 不代表 hook 仍活跃。重启会新建诊断 map，SIGHUP 不会清空它们；不要跨重启比较计数。保留上述两个持久化分配器 pin。
