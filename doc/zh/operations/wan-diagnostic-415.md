# Issue #415 WAN 诊断构建

仅用于 `diag/issue-415-rawip-wan`；不是修复版本。保持原有路由、mark、转发判断和 conntrack 行为。需要 root、`bpftool-full` 和 curl，不需要 tracefs、设备端编译器或 `kernel.bpf_stats_enabled`。新增两个临时 BTF map，默认不采样。

## 安全启动

保存原二进制及配置，正常停止原 honk 服务并确认没有残留 honk 进程，然后用本包 `honk-core --config /etc/honk/config.dae` 启动。不要同时启动两份引擎，不要覆盖正在运行的二进制。保留原有数据目录、原配置和 `UDP_DECISION_SEQUENCE` / `ROUTING_GENERATION_SEQUENCE` pin；不要运行清空 bpffs 的命令。

本包基于本次记录的 main 源码，不是第三方 beta.4 APK 的原样重编译。不得只把此对象混配到旧版 honk-core。诊断字段不依赖 debug 日志。停止诊断前先保存 map 转储；正常关闭尝试删除自有诊断 pin，失败可能留下旧 pin，其存在不证明 hook 仍在运行。重启创建新 map，SIGHUP 不重置它们。

## 核对 program 与 map 身份

```sh
bpftool net
bpftool prog show id PROGRAM_ID
bpftool prog dump xlated id PROGRAM_ID
bpftool map show pinned /sys/fs/bpf/WAN_DIAG_CFG
bpftool map show pinned /sys/fs/bpf/WAN_DIAG
```

`PROGRAM_ID` 必须是 sipa_eth0 的当前 TCX egress 程序，入口为 `wan_egress_l3`。两个 pin 的 map ID 必须都在此程序的 `map_ids` 中，否则停止，不读写可能过期的 pin。使用自定义 `--bpf-pin-root` 时相应改路径。

核对类型/布局：`WAN_DIAG_CFG` 是 array，key 4 bytes、value 8 bytes、1 entry；`WAN_DIAG` 是 percpu_array，key 4 bytes、value 104 bytes、13 entries。两者应带 BTF ID；用 `bpftool btf dump id BTF_ID format c` 核对 `Filter { ifindex, source_port }` 和 `Sample` 字段。重启后重新取得 program/map ID。

## 单次 IPv4 探测

暂停不必要的并发探测，按本机实际路由选出口。不要假定 ifindex 仍为 issue 中的 3。只采样一个确定源端口，避免与 LAN 流量同时复用它。

```sh
(
set -eu
umask 077
DEV=sipa_eth0
IFINDEX=$(cat /sys/class/net/$DEV/ifindex)
CFG=/sys/fs/bpf/WAN_DIAG_CFG
DATA=/sys/fs/bpf/WAN_DIAG
le32() { printf '%02x %02x %02x %02x' "$(($1 & 255))" "$(($1 >> 8 & 255))" "$(($1 >> 16 & 255))" "$(($1 >> 24 & 255))"; }
off() { bpftool map update pinned "$CFG" key hex 00 00 00 00 value hex 00 00 00 00 00 00 00 00; }
trap 'off' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
off
bpftool -j -p map dump pinned "$DATA" > wan4-before.json
bpftool map update pinned "$CFG" key hex 00 00 00 00 value hex $(le32 "$IFINDEX") $(le32 41500)
date -u
RC=0
curl -q -4 --noproxy '*' --http1.1 --local-port 41500 \
  --connect-timeout 5 --max-time 15 --verbose \
  --write-out '\nlocal=%{local_ip}:%{local_port} remote=%{remote_ip}:%{remote_port}\n' \
  https://api.ip.sb/ip || RC=$?
date -u
off
printf 'curl_exit=%s\n' "$RC"
bpftool -j -p map dump pinned "$DATA" > wan4-after.json
)
```

这里 `-q` 必须为 curl 第一个选项，禁止读取 `.curlrc`；`--noproxy '*'` 排除代理环境变量。没有绑定 WAN 设备，避免改变原问题的 socket 语义。记录 curl 的完整输出；若 DNS 解析失败，不能据空样本推断 TC 未执行。若已知实际目标 IP，可用 `--resolve api.ip.sb:443:ADDRESS` 固定地址，IPv6 ADDRESS 使用方括号，TLS 主机名仍保留。不要用 `-k`。

顺序运行 IPv6：把 `-4` 改为 `-6`，源端口和筛选端口都改为 **41501**，文件名用 `wan6-*`。若端口占用，选新的空闲端口，同时修改两处；不使用端口范围或并发 curl。两次探测都要先关闭、保存 before、启用、curl、关闭、保存 after。子 shell 在正常退出或收到可捕获信号时尝试关闭采样；若终端被强制终止或关闭命令报错，重新执行关闭 map 更新命令。

## 解读

| key | 原路径 |
| --- | --- |
| 0 | Packet scratch 不可用，丢弃；无 tuple 证据 |
| 1 | 解析未成功，原样继续；无 tuple 证据 |
| 2 | 解析识别到需丢弃的分片或本地 NDP Redirect；无 tuple 证据 |
| 3 | NFQUEUE DNS carrier 丢弃 |
| 4 | VLAN 交给后续设备 |
| 5 | datapath 未 ready，继续 |
| 6 | 广播/组播/特殊地址继续 |
| 7 | PARAM.local_ip 目的地址继续 |
| 8 | `ingress_ifindex != 0`，按转发包继续 |
| 9 | 精确 bypass mark 或 classified mark，PASS |
| 10 | tuple fence 拒绝 |
| 11 | TCP publication acquire 拒绝 |
| 12 | 进入 TCP/UDP handler；不是“已代理成功” |

`source`/`destination` 为网络序 16-byte 地址，IPv4 使用 IPv4-mapped IPv6；port 为主机序整数，`protocol` 是主机序 EtherType（2048/34525），`first_byte=-1` 表示读取失败，非负值是链路头之后的第一个字节。`parse_result` 保留有符号 parser 返回值；仅 `tuple_valid=1` 能用于五元组归属。

**key 0/1/2 是整个接口的未解析样本，不受源端口筛选，不能归属给 curl。** 其 tuple/L4 字段强制归零，避免泄露上一包的 scratch。其余记录匹配所选源端口，但可能包含同端口 LAN 流量，必须把同一条 sample 的完整 tuple 与 curl 实测 tuple、IP family、时间窗口匹配。cookie 只是辅助观察，非零不是本机流量的充分条件，零也不能排除本机流量；读取 cookie 可能首次分配 socket cookie，不参与判据。

每个 CPU、每个 key 只保留累计包数与最后一个样本；计数不是连接数。各 CPU 计数可求和，样本字段不可跨 CPU 拼接。对比 before/after，最新样本可能已被覆盖，空结果或不匹配结果都不能证明原因。`timestamp_ns` 是单调时钟纳秒，不是 UTC。配置在每个探测窗口保持不变，启用时不要清计数；配置更新不是原子发布协议，off 也不是在途程序的 grace barrier，转储可能与最后一次写入竞争。

仅当确认为该 curl 的 sample 落在 key 8 且 `ingress_ifindex != 0`，才能确认它在这一 guard 被放行。key 1 且 IPv4/IPv6 header 与 `protocol` 不符是另一条待调查线索。进入 key 12 需要继续追踪 handler/route，不能继续坚持 ifindex 假说。

请保留并脱敏共享：构建版本与 SHA256、启动/绑定日志、program/map 身份输出、IPv4/IPv6 curl 完整输出、before/after JSON、`ip -details link show dev sipa_eth0`。JSON 含 IP 地址；不含 payload、域名、配置或认证凭据。

## 恢复

关闭采样的独立命令如下（自定义 pin root 时修改路径），不依赖前面子 shell 的函数；重新连接设备后也可执行：

```sh
bpftool map update pinned /sys/fs/bpf/WAN_DIAG_CFG \
  key hex 00 00 00 00 value hex 00 00 00 00 00 00 00 00
```

先关闭采样、导出证据，再正常停止诊断实例，恢复原二进制并启动原服务。不要删除持久化 allocator pin，不用重启设备，不把 unpin 当作清空仍在运行的 map。
