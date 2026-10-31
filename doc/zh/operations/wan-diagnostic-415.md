# Issue #415：使用 honk-tool 采集 WAN 诊断

本分支只增加观测，不修改路由、mark、conntrack 或本机/转发判据。诊断包同时提供匹配版本的静态 `honk-core`、`honk-tool` 和 BPF 对象；**不需要 bpftool、tracefs 或设备端编译器**。

需要 root/BPF 权限、Linux TCX、可读的 `/sys/devices/system/cpu/possible`，以及带本次诊断 map 的引擎。下面的 curl 只负责触发原问题，不是采集器依赖。不要把新版 tool/object 与旧版引擎混用。

## 启动与边界

保留原二进制和配置，正常停止原服务，确认没有残留 honk 进程，再用包内 `honk-core --config /etc/honk/config.dae` 启动。不要覆盖运行中的二进制或启动第二份引擎；保留原数据目录、`UDP_DECISION_SEQUENCE`、`ROUTING_GENERATION_SEQUENCE`，不要清空 bpffs。

`honk-tool bpf wan-diag` 复用已有原始 `bpf(2)` 设施，不加载程序、不挂载 hook。它只写 `WAN_DIAG_CFG` 开关，不写数据面状态或清零计数。工具自动校验 map 实际名称、类型、尺寸、条目数，以及它们确实由指定接口同一个 TCX egress 程序使用；捕获开始和结束检查 program/link 身份，持有旧 map FD，绝不把清理写入重启后的替代 map。边界检查不证明整个区间没有发生中间更新；探测期间不要重载或改配置。

采样默认关闭。**同一引擎一次只运行一个采集器，关闭命令也不能与采集并发使用**；启用检查不是原子占有协议。已有非零 filter 会被拒绝而不改写，需先结束原采集器或明确恢复。

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

工具到时自动关闭采样，stdout 输出一份包含 `before` / `after` 的 JSON；不持续打印逐包日志。确认终端 A 正常退出，文件可解析，不能把失败产生的空文件当作零流量。

`-q` 必须是 curl 的第一个参数，避免 `.curlrc`；`--noproxy '*'` 排除代理环境变量。不绑定 WAN 设备，以免改变原问题的 socket 语义。可用已知目标地址加 `--resolve api.ip.sb:443:ADDRESS`（IPv6 地址加方括号）固定目标，保留 TLS 主机名校验，不使用 `-k`。DNS 失败或未在窗口内发出请求都不能证明 TC 未运行。

IPv6 顺序再做一轮：工具和 curl 的源端口都改为 **41501**，curl 改 `-6`，输出改为 `wan6.json` / `wan6-curl.txt`。不要并发两轮；端口占用时换新端口，两处保持一致，避免 LAN 客户端复用相同端口。

## 中断与恢复

`--seconds` 接受 1–300，默认 15。INT/TERM/HUP 会尝试先关闭，再输出部分采集结果；JSON 的 `end_reason` 和 `elapsed_ms` 区分到时与信号中断。时限约束采样启用时间，不保证阻塞的输出管道能在同一期限内退出。

采集与 `--disable` 都在生成已拥有的报告后、向 stdout 序列化和写入前释放 map/program FD。输出背压因此不会继续保留旧引擎的生产 map；正常错误路径中的关闭失败也在 owner 释放后返回，Drop 的尽力清理不执行标准流 I/O。

SIGKILL、系统故障或关闭写入失败可能留下开启的 filter。确认原采集器已停止后，用独立命令恢复（自定义 pin root 时同样添加）：

```sh
./honk-tool bpf wan-diag --interface sipa_eth0 --disable
```

已经关闭时可重复执行。该命令仍核对 map/接口归属；归属检查失败时不要绕过检查强写 map，按原启动流程正常停止并重启匹配的诊断引擎。不得用清空 bpffs 代替恢复。

## JSON 解释

顶层包含接口/ifindex、program/link/map ID、选定源端口、请求时长、实际耗时、结束原因和 `before` / `after`。两个数组只输出非零计数的 reason/cpu_slot 行。

每行保留累计 `packets`、单调时钟 `timestamp_ns`、`socket_cookie`、出口/入口 ifindex、真实 `mark`、主机序 EtherType `protocol`、包长、带符号 `parse_result` 和 `first_byte`、`link_h_len`，以及可读五元组 `tuple`。`tuple=null` 表示不能归属；`first_byte=-1` 是读取失败。IPv4-mapped 地址显示为普通 IPv4；端口为主机序。

| reason_index | reason | 现有路径 |
| --- | --- | --- |
| 0 | scratch_unavailable | scratch 不可用，丢弃 |
| 1 | parse_pass | 解析未成功，继续 |
| 2 | parse_drop | 已确认应丢弃的分片或本地 NDP Redirect |
| 3 | queue_carrier_drop | NFQUEUE DNS carrier 丢弃 |
| 4 | vlan_pass | 交给后续 VLAN 设备 |
| 5 | not_ready_pass | datapath 未 ready，继续 |
| 6 | special_pass | 广播/组播/特殊地址继续 |
| 7 | local_destination_pass | 目的地址匹配 PARAM.local_ip |
| 8 | forwarded_pass | ingress_ifindex 非零，按转发包继续 |
| 9 | marked_pass | 精确 bypass/classified mark，PASS |
| 10 | tuple_fence_drop | tuple fence 拒绝 |
| 11 | tcp_acquire_drop | TCP publication acquire 拒绝 |
| 12 | dispatch | 进入 TCP/UDP handler，不是已代理成功 |

关键限制：

- **0/1/2 是接口级未解析证据，不受源端口筛选，不能直接归属给 curl。**
- 计数是累计包数，每种原因/CPU 只有最后一个样本，历史样本可以原样出现在新窗口。对比 before/after，不把旧样本当作本次请求。
- `cpu_slot` 是 possible-CPU 缓冲区的位置，不一定是稀疏系统的 CPU 编号。可以汇总计数，不能跨 slot 拼接样本字段。
- `coherent_snapshot=false`：关闭不是在途 writer 的 grace barrier；转储仍可能与最后一次写入竞争，且样本可能被覆盖。
- 源端口匹配也可能包含 LAN 流量。必须与 curl 实测的完整五元组、IP family 和窗口匹配。cookie 不是本机归属判据；读取可能首次分配 cookie。
- 只有匹配该 curl 的 `forwarded_pass` 样本才能确认 ifindex guard 放行。`dispatch` 需要继续查 handler；空或不匹配的样本均不能下结论。

请保留并脱敏共享：两个 JSON、两个 curl 文件、两个二进制的 `--version`、包校验和、启动/绑定日志和接口信息。JSON 含 IP 地址，不含应用 payload、配置或认证凭据。

## 结束

导出证据、确认采样关闭，再正常停止诊断引擎，恢复原二进制并启动原服务。正常关闭只尝试删除自有 pin，残留 pin 不证明 hook 活跃。重启新建诊断 map，SIGHUP 不清空它们；不要跨重启比较同一计数窗口。保留持久化 allocator pin。
