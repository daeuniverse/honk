# Benchmark 实验环境与结果

本文档描述 honk 可复现的 benchmark 环境、测量方法学,以及与
[dae](https://github.com/daeuniverse/dae) 的同时刻 A/B 最新结果。文档放在仓库里,
以便实验方法和数据与代码保持同步。

## 实验拓扑

```text
┌──────────────────────────────────────┐       ┌─────────────────────────────┐
│ 引擎机(每轮选择一台)                  │       │ 10.10.10.70(物理机,50G)     │
│                                      │       │                             │
│ x86: 10.10.10.49,4 vCPU / 2 GiB     │  LAN  │ 协议服务端:                 │
│ ARM: 10.10.10.118,R2S / 1 GiB        ├──────►│  hy2/tuic/SS/Trojan/AnyTLS │
│                                      │       │ 目标服务:                   │
│  ┌───────────────┐                   │       │  HTTP  :8001-8006,8080      │
│  │ netns "lab"   │ veth              │       │  iperf:5201-5206,5300      │
│  │ 192.168.222.2 ├──► 真实 eBPF 路径 │       │  UDP echo:53531-53536      │
│  └───────────────┘                   │       └─────────────────────────────┘
│ honk / dae(同一时刻只跑一个)          │
│ LAN: veth-lab                        │
│ WAN: ens3(x86) / USB GbE(ARM)        │
└──────────────────────────────────────┘
```

- **x86 引擎机(`10.10.10.49`)**:Debian 13 VM,4 个 host-passthrough
  i5-13600K vCPU、2 GiB RAM,WAN 为 `ens3`。客户端在 network namespace
  `lab` 中(`veth-lab` ↔ `veth-client`,192.168.222.0/24,nftables
  masquerade),direct 对照约 9.4 Gbps。
- **ARM 引擎机(`10.10.10.118`)**:NanoPi R2S,RK3328 四核 Cortex-A53,
  可用内存 968 MiB,WAN 为 `eth0`。使用相同 `lab` netns 拓扑,direct 对照
  约 0.8–0.9 Gbps。
- **真实数据面**:两台机器均只运行 honk 或 dae 之一。全部被测客户端流量都
  经过真实 eBPF/TPROXY 路径,不测 loopback 捷径。
- **服务端(`10.10.10.70`)**:协议服务端(官方 hysteria、tuic-server、
  sing-box、Go anytls-server)加本地目标服务。服务端直接出 WAN,所以
  "internet" 测试经过 服务端 → 外网。
- **隔离**:这里的一切不触碰生产网关(`10.10.10.1`)；生产验证另行标注。

### 已知的实验室限制

- 不对跨架构绝对吞吐作归一化:`.49` 是虚拟多千兆路径,`.118` 同时受 USB
  GbE 和 A53 CPU 限制。公平结论必须比较**同一机器**上的 honk-vs-dae；
  两台机器用于判断结论能否跨架构复现。
- loaded-latency 阶段会在同一路由上同时跑一条 reverse iperf3。尾延迟包含
  engine scheduling、crypto、softirq 竞争和 NIC 上限,不是空载网络 RTT。
- 共享基础设施的轮间方差约 ±5%。其他会话若中途重启引擎或在 ARM 板编译,
  该 arm 即失效,发布前必须重跑。
- x86 VM 使用 host CPU 透传(AES-NI + AVX2)。下文无 SIMD 的旧 qemu64
  数字只保留为明确标日期的历史,不是当前 x86 基线。
- 当前 SSH 凭据无法读取 `.70` 上 rprx server 的 process/version。精确客户端
  wire 参数和两端 client binary hash 已保留,但这些行不能当作 server-version
  回归基线。
- 2026-08-08 代理矩阵覆盖实验室已配置且可达的全部 endpoint:HY2、TUIC、
  SS2022、Trojan、两个 AnyTLS server、VLESS Vision/REALITY 与 VMess。
  SOCKS5/Juicity 没有可用的配对 A/B 代理 endpoint；Block 没有吞吐路径,
  Direct 是对照。下文较早的 Juicity direct-UDP 卸载结果不是 Juicity 代理对比。

## 各组件位置

| 组件 | 二进制 | 配置 |
| --- | --- | --- |
| hy2 server | 官方 `hysteria` | `:8443`,密码 `testpass123`,证书 CN `hy2.test` |
| TUIC server | `tuic-server` 1.0.0 | `:2444`,uuid `00000000-0000-0000-0000-000000000001` / `testpass123`,要求 SNI `hy2.test` |
| AnyTLS server | sing-box | `:2445`,密码 `testpass123` |
| AnyTLS server | Go 参考实现 `anytls-server` | `:2443`,`-p testpass123` |
| SS 2022 server | sing-box | `:2447`,`2022-blake3-aes-128-gcm`,psk `8JCsHssyVTFyPy5lYdNhZg==` |
| Trojan server | sing-box | `:2446`,密码 `testpass123`,SNI `hy2.test` |
| 目标服务 | python http.server, iperf3 | 端口 `8001-8006` + `8080`(direct),`5201-5206` + `5300`(direct);UDP echo `53531-53536` |

常规引擎配置按目标端口路由,无需 API 切换：`5201/8001 → hy2`、
`5202/8002 → tuic`、`5203/8003 → ss2022`、`5204/8004 → trojan`、
`5205/8005 → anytls-sb`、`5206/8006 → anytls-go`。专用 honk-only rprx
配置通过 harness index override 把 VLESS Vision/REALITY/VMess 复用到在线
目标槽 1–3。当前 x86 kdae build 包含 AnyTLS；ARM honk-vs-dae 只比较双方
共有的四协议。节点服务端口为 `direct(must)`,其余全部回落 direct。

## 方法学

统一 harness——`bench/lab-bench.sh`(在本仓库,于引擎机上运行)——
取代了旧的 bench.sh / bench-cold.sh / bench-cpu.sh / bench-honest.sh
四个脚本。用法和实验室要求见 `bench/README.md`。

每个 引擎 × 协议 测量:

- **cold**——全新重启引擎后的首个请求延迟,3 次取中位数。两个实验室配置的
  健康检查间隔都是 3600s,首个探测不会抢跑测量。
- **hot p50/p95**——对每协议 HTTP 目标连发 15 个请求的开流延迟(代理会话已
  热)。QUIC 协议这项主要由连接/会话恢复决定,mux 协议由池化会话决定。
  常规 HTTP 样本必须得到成功的 2xx/3xx；连接或 status 失败会把该行标为
  invalid,不会把 curl 的失败耗时当成延迟。
- **bw**——iperf3 `-R` 下载,单流,3 次取接收端中位数。
- **udp**——每协议:echo RTT(对路由 echo 端口 5353x 发 15 个 ping 取
  中位数)和 iperf3 `-u -b 10G -l 1200 -R`(饱和供给下的接收带宽 +
  丢包率;数据报固定 1200B,因为 QUIC datagram 上限就在那附近)。
- **loaded 延迟稳定性**——常规吞吐测量之后,同一路由启动一条 reverse
  iperf3；有界 worker pool 按绝对 250ms deadline 打开 200 条独立 HTTP
  stream(共 50s),单次 timeout 不会串行阻塞后续样本。报告 p50/p95/p99、
  最大值、失败数与调度偏差；逐次结果保存为 JSONL,并保留对应 iperf3 JSON,
  避免把负载失败或压力不足误报成“稳定”。
- **cpu**——中位数带宽那一轮期间的引擎 CPU 核数
  (`/proc/<pid>/stat` utime+stime 差值除以墙钟时间)。honk 的 pid 锚定
  clash API 监听者,停在单实例锁上的第二实例(零 CPU)不会污染指标。
- **rss**——带宽轮结束后的引擎 RSS。
- **direct 基线**——同样方法测量未代理路径(`8080`/`5300`)。

```bash
scp bench/lab-bench.sh bench/latency_stability.py root@10.10.10.49:/root/
ssh root@10.10.10.49 \
  "HONK_BIN=/root/honk-candidate bash /root/lab-bench.sh \
   'honk dae' 'hy2 tuic ss2022 trojan anytls-sb anytls-go'"

# ARM 使用其 dae 构建与 honk 共有的协议面。
scp bench/lab-bench.sh bench/latency_stability.py root@10.10.10.118:/root/
ssh root@10.10.10.118 \
  "HONK_BIN=/root/honk-candidate bash /root/lab-bench.sh \
   'honk dae' 'hy2 tuic ss2022 trojan'"
```

`lab-bench.sh` 会在 stderr 记录 host/kernel 与二进制 SHA-256。常规行追加到
`TSV`,loaded-stability summary 追加到 `STABILITY_TSV`,原始 sample 与 load
JSON 保存在 `STABILITY_DIR`。collector fixture 用
`python3 bench/tests/latency_stability_test.py` 验证。

### VLESS Vision codec 候选基准

`crates/honk-outbound/benches/vless_vision.rs` 以明文 loopback 承载隔离响应
解码开销；生产 Vision 仍只允许 TLS/REALITY。两个用例都从确定性的
16 KiB 源写入中解码恰好 **16 MiB**，且每个二进制会在 Criterion 计时前
校验解码字节数：

- `vision_framed_16m`：多组 content/padding frame，最后为 `End`；
- `vision_direct_16m`：一个 `Direct` frame，随后为 raw tail。

配对的 release-musl 二进制仅在已确认的 x86-64 Debian 主机
`root@10.10.10.50` 上执行，并在同一 Criterion 目录中背靠背运行：

```bash
ssh root@10.10.10.50 \
  'mkdir -p /root/vless-vision-criterion && cd /root/vless-vision-criterion && \
   /root/vless-vision-bench.before --bench --save-baseline vless-before-final'
ssh root@10.10.10.50 \
  'cd /root/vless-vision-criterion && \
   /root/vless-vision-bench.after --bench --baseline vless-before-final'
```

候选仅在 framed 点估计改善、其 95% 区间排除超过 3% 的降速，且 Direct
点估计回退不超过 3% 时通过。

## 结果(2026-08-26,QUIC profile 与优化门槛)

本轮对 source `0bd6135` 的现有有界 GSO 实现及独立 Juicity 候选
`429c540` 进行 profile。x86 主机固定使用同一个 musl 二进制
(`e8750633...`)、同一份 1452 字节配置、8 秒 iperf3 窗口及 5 轮交替 arm。
`reverse` 是 server-to-client 下载,`forward` 是 client-to-server 上传。
硬件 PMU event 不可用,故 profile 证据由 userspace `cpu-clock` sample、进程
task-clock、syscall 计数及端到端吞吐/CPU 结果组成。

完整 harness 复现沿用现有 3-cold / 15-hot / bandwidth 3 轮中位数 /
200-loaded-stream contract：

| 路径 | Cold / hot p50 / p95 ms | Bandwidth Mbps / CPU / RSS MiB | Loaded Mbps / p99 / max ms / 失败 |
| --- | ---: | ---: | ---: |
| direct | 16.225 / - / - | 9403 / 0.00 / 45 | 8918 / 8.177 / 13.614 / 0 |
| HY2 | 8.561 / 1.076 / 3.060 | 6037 / 0.55 / 52 | 5852 / 6.462 / 10.375 / 6 |
| TUIC | 2.759 / 1.101 / 1.988 | 3355 / 0.34 / 43 | 3428 / 4.189 / 11.539 / 0 |

### 实测瓶颈

| 协议/方向 | 基线中位数 Mbps / CPU 核 | 最大 userspace self sample |
| --- | ---: | --- |
| HY2 reverse | 6369 / 0.636 | AES-GCM decrypt 14.0%；`memcpy` 12.9% |
| HY2 forward | 5035 / 1.037 | `memcpy` 15.6%；AES-GCM encrypt 10.7%；mutex contention 6.9% |
| TUIC reverse | 3758 / 0.367 | `memcpy` 13.7%；AES-GCM decrypt 11.7% |
| TUIC forward | 5279 / 0.855 | `memcpy` 12.3%；mutex contention 9.3%；AES-GCM encrypt 8.5% |

其余领先 sample 为 Quinn packet assembly/decoding、connection driver 及
receive reassembly。主要成本因此位于共享 QUIC crypto 与 buffer movement,
而非某一个协议的 framing。诊断用 `strace` arm 在一个 forward 窗口内观测到
约 9.5–10.2 万次 `sendmsg` 与 7.8–9.3 万次 `recvmmsg`,但 tracing 将吞吐降至
约 1.1–1.2 Gbps；这些计数不作为生产性能对比。

Instrumented endpoint 实报 MTU 1452、kernel GSO capacity 64、application cap
16 及 GRO 64。在 43 个 connection snapshot 中,connection 与 stream
flow-control blocked counter 均未增长。这既确认实际 GSO cap,也没有为扩大
receive window 提供实测依据。

### GSO 与 MTU

权威 x86 对比在每轮中交替执行 disabled、cap-4 与 cap-16。delta 是同轮
配对百分比变化的中位数,不是聚合中位数的比值。

| 模式 | HY2 Mbps / CPU | HY2 配对 delta | TUIC Mbps / CPU | TUIC 配对 delta |
| --- | ---: | ---: | ---: | ---: |
| GSO off | 6365 / 0.628 | control | 3319 / 0.343 | control |
| GSO cap 4 | 6231 / 0.618 | +1.88% | 3280 / 0.328 | -7.65% |
| GSO cap 16 | 6576 / 0.635 | +3.63% | 3367 / 0.340 | -0.15% |

Cap 16 重现现有 HY2 增益,但未改善 CPU,TUIC 也没有同等增益。单次 cap-8
arm 噪声较大,cap-32 HY2 arm 未产生有效吞吐。没有证据支持放宽现有 cap,
也没有证据支持改变抗黑洞的 1252 字节 scalar 默认值。

最终 ARM arm 使用同一二进制/配置 contract,并以 monotonic nanosecond
clock 计算进程 CPU：

| 模式 | HY2 Mbps / CPU | HY2 配对 delta | TUIC Mbps / CPU | TUIC 配对 delta |
| --- | ---: | ---: | ---: | ---: |
| GSO off | 334 / 1.419 | control | 249 / 1.059 | control |
| GSO cap 4 | 330 / 1.440 | -1.29% | 227 / 1.001 | -8.99% |
| GSO cap 16 | 335 / 1.423 | -0.10% | 233 / 1.020 | -7.73% |

ARM 未呈现 GSO 增益。TUIC sample 波动较大,但两个启用模式的中位数都更低；
其 CPU 降低伴随 delivered throughput 降低,不构成效率改善。

### Owned QUIC stream relay 原型

该原型仅对 concrete Quinn stream 以 `RecvStream::read_chunk` 与
`SendStream::write_chunk` 替换 generic `AsyncRead` buffering,并保留现有
half-close、字节计数、取消及 idle-drain 语义。

| TUIC 模式/方向 | 中位数 Mbps / CPU | 配对吞吐 delta |
| --- | ---: | ---: |
| 现有 relay,reverse | 3368 / 0.344 | control |
| owned-chunk relay,reverse | 3327 / 0.334 | -1.22% |
| 现有 relay,forward | 5611 / 0.952 | control |
| owned-chunk relay,forward | 5852 / 0.957 | +0.01% |

reverse 回退、配对 forward 吞吐不变且 CPU 仅降低 2.6–2.9%,未通过无回退及
10% CPU 门槛。原型已回滚；concrete QUIC stream 继续使用现有 relay。

### TUIC congestion 受控 sweep

| 算法 | Reverse Mbps / CPU / retransmits | Forward Mbps / CPU / retransmits |
| --- | ---: | ---: |
| cubic | 3474 / 0.346 / 1 | 5709 / 0.924 / 9 |
| BBR | 3454 / 0.337 / 0 | 5488 / 1.042 / 154 |
| New Reno | 3511 / 0.353 / 0 | 5407 / 0.867 / 15 |

Cubic 保持最高 forward 中位数。BBR 在该方向消耗更多 CPU 且 retransmit
更多；New Reno 的 forward 吞吐更低。因此 TUIC 保留现有 cubic 默认值。
在没有 changed bottleneck metric 时,未推广 window、ACK、PMTUD、fairness
或 buffer tuning。

### Allocation 清理与最终决策

Juicity 候选 `429c540` 以 `write_chunk(Bytes)` 将编码 frame 交给 Quinn,
并把 UDP payload 直接解码到调用方 buffer。3 轮配对的 500-packet allocation
实验约测得 4,828 对 5,839 次 allocation call,即 call 减少 17.3%、allocated
bytes 约减少 15%。聚焦 receive 测试也在 4096 个 frame 间保持同一个调用方
buffer。该 allocation-specific cleanup 作为 `d4fd31a` 由
[PR #73](https://github.com/daeuniverse/honk/pull/73) 合并。
4 个聚焦测试与全部 546 个 `honk-outbound` 测试均通过,format 与 Clippy
也保持 clean。

本地 Juicity 端到端 arm 噪声过大,不足以声称吞吐增益。外围 UDP endpoint
receive path 已复用一个固定 buffer 并直接从中发送；更广泛的 ownership
改动只会增加 API 与 lifetime 复杂度,却不能删除已测 allocation,故未修改。
吞吐 fixture 也不含 Salamander,因此未作推测性优化。

其他端到端候选均未能在一个稳定方向达到至少 3% 中位吞吐或 10% CPU
改善且不让另一方向回退,故未再开 performance PR。完整 hash、raw JSON、
profile、交替结果、聚焦测试证据及原样 runner 位于
[`quic-analysis-2026-08-26`](../bench/results/quic-analysis-2026-08-26/)。

## 结果(2026-08-25,Hysteria2 互操作与有界 QUIC GSO)

本轮以官方 Hysteria v2.12.2 服务端验证候选 `c1b8749`,并测量共享 QUIC
socket 改动。它补充而不替代下方 2026-08-24 honk/dae 配对基线。吞吐 fixture
使用明文 HY2/TUIC 与显式 **1452 字节 QUIC UDP payload**；不覆盖
Salamander、端口跳跃或 Juicity。

官方服务端矩阵覆盖 PKI 与证书 pin、自签名 TLS、Salamander、认证失败、
带宽提示、禁用 UDP 的明确拒绝、MTU/PMTUD/window、UDP 分片及公网端口
跳跃限制。见
[脱敏功能矩阵](../bench/results/quic-gso-2026-08-25/remote-hy2-feature-matrix.txt)。

### x86 有界 GSO 决策

两个启用 arm 与禁用 control 使用同一个最终 musl 二进制
(`dadefe68...`)及相同配置。control 以 `HONK_QUIC_GSO=0` 禁用 GSO；
启用 arm 不设置该变量,因此显式 1452 字节 payload 选择 GSO,应用层最多
16 个 segment。TCP 带宽单位为 Mbps,CPU 为核,RSS 为 MiB；loaded 单元格为
`Mbps / p99 ms / 200 次中的失败数`。

| 模式 | HY2 TCP / CPU / RSS | TUIC TCP / CPU / RSS | HY2 loaded | TUIC loaded |
| --- | ---: | ---: | ---: | ---: |
| 文档中的 2026-08-24 基线 | 6140 / 0.61 / 48 | 3350 / 0.34 / 43 | 6033 / 8.075 / 3 | 3366 / 2.609 / 0 |
| 最终二进制,GSO off | 6479 / 0.63 / 50 | 3273 / 0.33 / 42 | 6570 / 6.387 / 2 | 3335 / 2.574 / 0 |
| 最终二进制,GSO cap 16,arm A | 6845 / 0.63 / 55 | 3176 / 0.32 / 52 | 6568 / 3.879 / 0 | 3246 / 3.243 / 0 |
| 最终二进制,GSO cap 16,arm B | 6713 / 0.64 / 48 | 3264 / 0.31 / 43 | 6563 / 3.685 / 0 | 3199 / 2.328 / 4 |

相对同二进制 control,有界 GSO 将 HY2 TCP 容量提高 3.6–5.6%,同时 direct
锚点保持 9401–9406 Mbps。TUIC TCP 落在已知的 run-level 波动范围内,因此
不声称 TCP 加速。在刻意饱和的 10-Gbps UDP offer 下,HY2 从
831 Mbps / 81.1% loss 变为 902–935 Mbps / 77.3–78.6%；TUIC 从
814 / 80.3% 变为 979–1079 / 74.4–77.6%。这是过载容量结果,不是 WAN
丢包率。

启用时 HY2 RSS 为 48–55 MiB,TUIC 为 43–52 MiB；第二个 arm 回到文档基线
的 48/43 MiB。这排除了本样本中的持续 RSS 回退,并不等同于 allocation
计数结论。loaded 的稀疏失败随 arm 波动,表中原样保留而未取平均隐藏。

### ARM 探索性开关

ARM 板使用 pre-auto-GSO 候选及其已有 `HONK_QUIC_GSO=0|1` 开关,不是
最终 16-segment 二进制：

| 模式 | HY2 TCP / RSS；UDP | HY2 loaded Mbps / p99 / 失败 | TUIC TCP / RSS；UDP | TUIC loaded Mbps / p99 / 失败 |
| --- | ---: | ---: | ---: | ---: |
| GSO off | 345 / 39；2 Mbps (83.1%) | 344 / 125.828 / 0 | 245 / 25；3 Mbps (91.6%) | 257 / 37.010 / 0 |
| GSO on | 346 / 42；1 Mbps (84.7%) | 344 / 125.411 / 8 | 254 / 29；1 Mbps (92.4%) | 253 / 43.357 / 2 |

该板没有呈现 GSO 吞吐收益,启用 arm 的稀疏失败更多。本结果保留为板级
负面信号,不能证明最终 cap-16 的 ARM 性能。因此交付策略继续让抗黑洞的
1252 字节默认值使用 scalar send,仅在操作者选择更大 MTU 后启用有界 GSO,
并保留 `HONK_QUIC_GSO=0` 逃生开关。共享路径覆盖明文 HY2、TUIC 与
Juicity,但没有可用 Juicity benchmark endpoint,故不作其性能声明。

完整 provenance、hash、TSV、loaded-run JSON/sample、探索性 arm 与清理状态
位于
[`quic-gso-2026-08-25`](../bench/results/quic-gso-2026-08-25/)。

## 结果(2026-08-24,当前跨架构配对 A/B)

这是当前配对轮：x86 `10.10.10.49` 与 ARM `10.10.10.118`。ARM 使用更新后的
kdae 配置(`eth0` 与 `disable_waiting_network: true`),kdae 版本为
`unstable-20260824.r1142.ec957346`。候选基于 main
`39f92eb51c62a9a330f56612c6671ae678a03585`;二进制、kernel、配置、harness
及结果 hash 以 [`metadata.txt`](../bench/results/cross-arch-2026-08-24/metadata.txt)
为准。

两种引擎均逐一运行,所有流量经过真实数据面。常规表为 3 次 cold、15 次
hot、3 次 8 秒带宽运行取中位数。loaded 表为同一路由上一条 reverse iperf3
负载下,每 250ms 发起一个请求,共 200 个。ARM 的 `lab` namespace holder
贯穿引擎 teardown/recreate,避免 honk 删除 `daens` 时客户端 namespace 消失。

### x86-64(`10.10.10.49`,4 vCPU / 2 GiB)

#### TCP 常规结果

延迟单位为 ms,带宽为 Mbps,CPU 为核数,RSS 为 MiB。

| 协议 | honk cold / hot p50 / hot p95 | dae cold / hot p50 / hot p95 | honk Mbps / 核 / RSS | dae Mbps / 核 / RSS | 带宽比 |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 3.772 / – / – | 1.789 / – / – | 9403 / 0.00 / 46 | 9403 / 0.00 / 39 | 1.00× |
| hy2 | 1.627 / 0.870 / 2.347 | 3.060 / 0.719 / 0.930 | 6140 / 0.61 / 48 | 6466 / 0.79 / 51 | 0.95× |
| tuic | 1.708 / 0.795 / 3.429 | 18.096 / 16.352 / 16.921 | 3350 / 0.34 / 43 | 3877 / 0.52 / 54 | 0.86× |
| ss2022 | 3.310 / 1.174 / 1.385 | 2.080 / 1.083 / 2.241 | 9401 / 0.31 / 48 | 9368 / 0.37 / 53 | 1.00× |
| trojan | 5.320 / 0.891 / 7.515 | 2.208 / 1.381 / 2.961 | 9288 / 0.36 / 43 | 9381 / 0.44 / 46 | 0.99× |
| anytls-sb | 1.833 / 0.724 / 1.972 | 5.431 / 0.738 / 2.097 | 9361 / 0.43 / 46 | 9352 / 0.43 / 52 | 1.00× |
| anytls-go | 2.926 / 0.761 / 3.287 | 4.332 / 1.175 / 2.490 | 9391 / 0.47 / 42 | 9200 / 0.44 / 54 | 1.02× |

#### UDP 饱和

| 协议 | honk RTT ms | dae RTT ms | honk Mbps / loss / 核 | dae Mbps / loss / 核 | 带宽比 |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 0.112 | 0.158 | 823 / 79.8% / 0.43 | 902 / 78.0% / 0.45 | 0.91× |
| tuic | 0.090 | 0.103 | 1049 / 75.3% / 0.47 | 937 / 76.7% / 0.48 | 1.12× |
| ss2022 | 0.079 | 0.154 | 1814 / 52.6% / 0.67 | 2513 / 34.3% / 0.64 | 0.72× |
| trojan | 0.112 | 0.070 | 1572 / 59.4% / 0.67 | 2870 / 23.7% / 0.60 | 0.55× |
| anytls-sb | 0.147 | 0.109 | 1156 / 68.0% / 0.43 | 1104 / 66.1% / 0.29 | 1.05× |
| anytls-go | 0.082 | 0.109 | 1299 / 64.7% / 0.48 | 1418 / 64.7% / 0.34 | 0.92× |

#### loaded 稳定性

percentile 只统计成功 HTTP 响应,失败数单列。

| 引擎 | 协议 | 负载 Mbps | p50 / p95 / p99 / max ms | 失败 |
| --- | --- | ---: | ---: | ---: |
| honk | direct | 9408 | 1.517 / 1.994 / 2.475 / 3.426 | 0/200 |
| honk | hy2 | 6033 | 1.708 / 3.005 / 8.075 / 9.802 | 3/200 |
| honk | tuic | 3366 | 1.400 / 2.061 / 2.609 / 2.767 | 0/200 |
| honk | ss2022 | 9403 | 1.885 / 3.177 / 4.869 / 6.013 | 4/200 |
| honk | trojan | 9323 | 1.671 / 4.362 / 7.895 / 11.469 | 0/200 |
| honk | anytls-sb | 9317 | 1.625 / 2.863 / 2089.764 / 3107.546 | 0/200 |
| honk | anytls-go | 9304 | 2.121 / 4.875 / 8.950 / 11.094 | 0/200 |
| dae | direct | 9406 | 1.687 / 2.306 / 2.551 / 4.937 | 0/200 |
| dae | hy2 | 6083 | 2.106 / 4.457 / 7.427 / 7.786 | 6/200 |
| dae | tuic | 4014 | 16.179 / 17.111 / 17.637 / 18.310 | 0/200 |
| dae | ss2022 | 9404 | 2.244 / 4.025 / 5.689 / 13.743 | 0/200 |
| dae | trojan | 9390 | 3.454 / 7.135 / 12.618 / 17.764 | 0/200 |
| dae | anytls-sb | 8770 | 1.626 / 3.889 / 42.709 / 58.435 | 4/200 |
| dae | anytls-go | 9244 | 2.278 / 11.220 / 16.807 / 20.968 | 2/200 |

x86 上,honk 的 SS2022、Trojan、sing-box AnyTLS 吞吐与 dae 相差不超过
1%,且所有 TCP 代理行 CPU 不高于 dae。HY2 慢 5%,TUIC 慢 14%,但 TUIC 热态
p95 为 3.429ms,明显低于 dae 的 16.921ms。UDP 结果混合：honk 只在 TUIC
和 sing-box AnyTLS 略占优,其余行落后。honk AnyTLS-sing-box 的 2.09 秒
p99 是原始样本中的真实离群值,没有删除。

### ARM64(`10.10.10.118`,NanoPi R2S / 1 GiB)

#### TCP 常规结果

| 协议 | honk cold / hot p50 / hot p95 | dae cold / hot p50 / hot p95 | honk Mbps / 核 / RSS | dae Mbps / 核 / RSS | 带宽比 |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 3.544 / – / – | 3.379 / – / – | 862 / 0.02 / 22 | 860 / 0.01 / 41 | 1.00× |
| hy2 | 6.827 / 5.557 / 18.128 | 21.981 / 5.782 / 7.017 | 344 / 1.27 / 39 | 218 / 0.80 / 45 | 1.58× |
| tuic | 5.912 / 5.445 / 6.854 | 32.721 / 21.513 / 22.089 | 233 / 0.93 / 29 | 238 / 0.81 / 43 | 0.98× |
| ss2022 | 5.939 / 4.889 / 31.721 | 8.166 / 6.855 / 7.625 | 430 / 0.76 / 28 | 281 / 0.82 / 36 | 1.53× |
| trojan | 59.571 / 13.261 / 59.743 | 15.561 / 15.397 / 17.603 | 416 / 0.79 / 30 | 205 / 0.79 / 40 | 2.03× |

#### UDP 饱和

| 协议 | honk RTT ms | dae RTT ms | honk Mbps / loss / 核 | dae Mbps / loss / 核 | 带宽比 |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 2.176 | 2.434 | 2 / 87.1% / 1.56 | 99 / 97.1% / 0.86 | 0.02× |
| tuic | 2.428 | 2.601 | 2 / 88.2% / 1.52 | 101 / 97.2% / 0.86 | 0.02× |
| ss2022 | 1.807 | 2.101 | 95 / 91.6% / 0.90 | 117 / 93.9% / 0.79 | 0.81× |
| trojan | 1.626 | 2.340 | 106 / 97.2% / 0.91 | 171 / 95.6% / 0.79 | 0.62× |

#### loaded 稳定性

| 引擎 | 协议 | 负载 Mbps | p50 / p95 / p99 / max ms | 失败 |
| --- | --- | ---: | ---: | ---: |
| honk | direct | 866 | 12.155 / 49.531 / 74.952 / 139.534 | 0/200 |
| honk | hy2 | 344 | 51.847 / 104.086 / 123.511 / 133.456 | 3/200 |
| honk | tuic | 263 | 21.895 / 32.327 / 39.561 / 58.102 | 0/200 |
| honk | ss2022 | 458 | 16.002 / 27.524 / 40.067 / 72.338 | 0/200 |
| honk | trojan | 392 | 11.988 / 21.573 / 31.547 / 73.303 | 0/200 |
| dae | direct | 524 | 8.907 / 50.834 / 84.706 / 91.599 | 0/200 |
| dae | hy2 | 216 | 35.539 / 56.397 / 74.111 / 74.429 | 8/200 |
| dae | tuic | 237 | 48.835 / 60.541 / 64.923 / 80.709 | 0/200 |
| dae | ss2022 | 279 | 14.374 / 20.924 / 24.875 / 47.538 | 0/200 |
| dae | trojan | 202 | 22.171 / 35.989 / 45.613 / 60.581 | 3/200 |

ARM 上,honk 的 TCP HY2、SS2022、Trojan 吞吐领先, TUIC 基本持平,且代理
RSS 全部更低。hot 尾延迟并非全面更好：TUIC 明显更低,HY2、SS2022、Trojan
更高。UDP 是本轮明确的 honk 回退：固定 10Gbps 供给下,HY2/TUIC 仅收到
2Mbps,dae 为 99/101Mbps；SS2022/Trojan 也落后。loaded 运行中 honk
失败更少(HY2 为 3 对 8,Trojan 为 0 对 3),但 HY2 与 SS2022 的 p99 更高。
这些是容量边缘结果,不是空载 WAN 延迟结论。

原始证据：[x86 常规 TSV](../bench/results/cross-arch-2026-08-24/x86-standard.tsv)、
[x86 loaded TSV](../bench/results/cross-arch-2026-08-24/x86-stability.tsv)、
[x86 raw](../bench/results/cross-arch-2026-08-24/x86-stability-raw/)、
[ARM 常规 TSV](../bench/results/cross-arch-2026-08-24/arm64-standard.tsv)、
[ARM loaded TSV](../bench/results/cross-arch-2026-08-24/arm64-stability.tsv)、
[ARM raw](../bench/results/cross-arch-2026-08-24/arm64-stability-raw/) 与
[输入文件](../bench/results/cross-arch-2026-08-24/arm64-inputs/)。

下面较早章节是历史记录,其中 `.45`/`.43` ARM 地址对应已替换的实验室主机；
当前 ARM 主机为上文的 `.118`。

## 结果(2026-08-08,x86-64 + ARM64 配对 A/B 与 loaded tail)

候选为基于 main `2e6d63a` 的当前 worktree；二进制、kernel、精确配置与
harness hash 以 [`metadata.txt`](../bench/results/cross-arch-2026-08-08/metadata.txt)
为准。两个候选都是 static musl、size-oriented release、默认 mimalloc。
常规表来自完整的 3 次 cold、15 次 hot、3×8s 带宽取中位数。loaded tail
另跑最终 fixed-cadence arm：同一路由有一条 self-saturating reverse TCP,
同时每 250ms 新开一条 HTTP stream,共 200 条。它测容量边缘,**不是等负载
延迟对比**；所以每个 percentile 旁都列出实际负载。探索阶段的串行 collector
在一次 timeout 后被确认会打乱节拍,其数据未发布。最终 raw run 的 p99
调度偏差最多 0.677ms,最大偏差 2.555ms。

原始证据：[x86 常规 TSV](../bench/results/cross-arch-2026-08-08/x86-standard.tsv)、
[x86 loaded TSV](../bench/results/cross-arch-2026-08-08/x86-stability.tsv)、
[x86 raw](../bench/results/cross-arch-2026-08-08/x86-stability-raw/) 与
[HY2/TUIC 复测](../bench/results/cross-arch-2026-08-08/x86-stability-repeat.tsv)。

### x86-64(`10.10.10.49`,4 vCPU / 2 GiB)

#### TCP 吞吐、CPU、内存与空载延迟

| 协议 | honk cold / hot p95(ms) | dae cold / hot p95(ms) | honk Mbps / 核 / RSS MiB | dae Mbps / 核 / RSS MiB | honk/dae 带宽 |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 4.81 / – | 4.52 / – | 9404 / 0.00 / 50 | 9408 / 0.00 / 48 | 1.00× |
| hy2 | 2.47 / 1.92 | 31.73 / 1.83 | 5792 / 0.59 / 53 | 5046 / 1.09 / 66 | 1.15× |
| tuic | 2.36 / 1.82 | 80.64 / 78.61 | 6906 / 0.66 / 50 | 5065 / 1.02 / 65 | 1.36× |
| ss2022 | 3.50 / 11.92 | 7.45 / 6.62 | 9151 / 0.37 / 51 | 9259 / 0.42 / 54 | 0.99× |
| trojan | 6.40 / 6.08 | 7.04 / 16.78 | 9097 / 0.42 / 46 | 9100 / 0.64 / 58 | 1.00× |
| anytls-sb | 2.78 / 3.07 | 7.89 / 5.33 | 8532 / 0.46 / 46 | 7905 / 0.55 / 59 | 1.08× |
| anytls-go | 2.98 / 4.15 | 7.59 / 2.52 | 9105 / 0.49 / 53 | 9036 / 0.61 / 61 | 1.01× |

本机 TCP 结论：direct 完全持平；honk 的 HY2 +14.8%、TUIC +36.3%、
sing-box AnyTLS +7.9%,其余三项在 1.2% 内,而所有代理行的 engine CPU 都
更少。honk 代理行 RSS 为 46–53MiB,dae 为 54–66MiB。反例也必须保留：
honk 空载 SS2022 hot p95 为 11.92ms,dae 为 6.62ms；AnyTLS-Go 为
4.15ms 对 2.52ms；反过来 dae TUIC 热态仍约 79ms。

#### UDP 饱和

这里固定以 10Gbps 供给,高 `loss` 是预期饱和结果；应将接收 Mbps 与 loss
一起比较,不能把它解释为公网丢包率。

| 协议 | honk RTT ms | dae RTT ms | honk Mbps / loss / 核 | dae Mbps / loss / 核 | honk/dae 带宽 |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 0.108 | 0.105 | 1490 / 58.9% / 0.84 | 828 / 79.8% / 0.72 | 1.80× |
| tuic | 0.158 | 0.134 | 1982 / 46.5% / 1.23 | 1922 / 49.8% / 1.48 | 1.03× |
| ss2022 | 0.222 | 0.184 | 1456 / 59.7% / 1.24 | 2675 / 30.1% / 1.64 | 0.54× |
| trojan | 0.135 | 0.099 | 1739 / 57.4% / 1.26 | 2916 / 24.3% / 1.59 | 0.60× |
| anytls-sb | 0.193 | 0.084 | 1194 / 69.1% / 0.73 | 1211 / 68.4% / 0.70 | 0.99× |
| anytls-go | 0.071 | 0.090 | 1249 / 66.2% / 0.79 | 1250 / 65.4% / 0.75 | 1.00× |

UDP 不是单边胜利：honk HY2 快 80%、TUIC 快 3%,两种 AnyTLS 持平；但
SS2022/Trojan 只达到 dae 的 54%/60%。

#### loaded 开流稳定性

percentile 只统计成功 HTTP 响应；失败数单列,因此 5s timeout 不会被低 p99
掩盖。

| 协议 | honk 负载 Mbps | honk p50 / p95 / p99 / max ms;失败 | dae 负载 Mbps | dae p50 / p95 / p99 / max ms;失败 |
| --- | ---: | --- | ---: | --- |
| direct | 9382 | 2.352 / 4.722 / 6.118 / 11.582; 0/200 | 9394 | 2.353 / 3.341 / 5.272 / 12.440; 0/200 |
| hy2 | 5597 | 2.391 / 3.359 / 6.095 / 16.981; 0/200 | 3465 | 3.195 / 13.755 / 176.642 / 399.369; 0/200 |
| tuic | 6197 | 2.683 / 6.694 / 16.031 / 16.927; 2/200 | 4848 | 77.108 / 82.733 / 87.135 / 88.816; 4/200 |
| ss2022 | 9319 | 2.573 / 5.011 / 17.161 / 18.311; 0/200 | invalid | invalid(3/3 load arm 中断) |
| trojan | 9300 | 2.272 / 4.873 / 12.416 / 17.280; 0/200 | 9124 | 5.940 / 18.994 / 23.151 / 31.855; 5/200 |
| anytls-sb | 8852 | 4.777 / 6.101 / 8.510 / 13.487; 0/200 | 8156 | 2.480 / 5.367 / 14.031 / 17.097; 3/200 |
| anytls-go | 9027 | 5.944 / 12.324 / 16.813 / 21.436; 0/200 | 9071 | 3.577 / 15.278 / 17.282 / 17.465; 1/200 |

dae SS2022 没有被强行换算成 percentile：三次 55s arm 都在 30s 丢失
iperf control connection,错误均为 `control socket has closed unexpectedly`。
中断前负载为 9.07–9.35Gbps；三轮 HTTP 失败分别为 0/200、5/200、0/200。
这是可复现的长流稳定性失败,不是吞吐为零。

因为一个 x86 arm 出现明显的整轮 tail,又对 HY2/TUIC 做了复测：

| 引擎 / 协议 | fixed-cadence arm A:负载 / p99 / 失败 | arm B:负载 / p99 / 失败 |
| --- | --- | --- |
| honk / hy2 | 5597Mbps / 6.095ms / 0/200 | 5104Mbps / 7.225ms / 1/200 |
| honk / tuic | 6197Mbps / 16.031ms / 2/200 | 6078Mbps / 8.048ms / 0/200 |
| dae / hy2 | 3465Mbps / 176.642ms / 0/200 | 5323Mbps / 11.284ms / 0/200 |
| dae / tuic | 4848Mbps / 87.135ms / 4/200 | 4603Mbps / 81.657ms / 0/200 |

honk HY2 两轮 p99 保持 6.1–7.2ms；dae HY2 在两轮间呈双峰。TUIC 持续分离：
honk 8.0–16.0ms,dae 81.7–87.1ms p99。双方都有稀疏失败(每轮 0–1%),
不能把这些样本外推为长期失败率。

### ARM64(`10.10.10.45`,NanoPi R2S / 1 GiB)

ARM 配对表只列该 dae build 也支持的四协议。原始证据：
[常规](../bench/results/cross-arch-2026-08-08/arm64-standard.tsv)、
[loaded](../bench/results/cross-arch-2026-08-08/arm64-stability.tsv)、
[raw](../bench/results/cross-arch-2026-08-08/arm64-stability-raw/) 与
[复测](../bench/results/cross-arch-2026-08-08/arm64-stability-repeat.tsv)。
所有已发布且有效的 ARM arm 中，最坏 p99 调度偏差为 17.390ms，单次最大
发起偏差为 41.592ms，仍远小于 250ms 发起间隔。

#### TCP 吞吐、CPU、内存与空载延迟

| 协议 | honk cold / hot p95(ms) | dae cold / hot p95(ms) | honk Mbps / 核 / RSS MiB | dae Mbps / 核 / RSS MiB | honk/dae 带宽 |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 6.66 / – | 6.63 / – | 889 / 0.00 / 57 | 899 / 0.01 / 42 | 0.99× |
| hy2 | 10.43 / 11.13 | 38.96 / 8.30 | 269 / 1.33 / 61 | 189 / 1.84 / 60 | 1.42× |
| tuic | 12.35 / 9.77 | 109.89 / 84.80 | 262 / 1.35 / 53 | 197 / 1.79 / 51 | 1.33× |
| ss2022 | 15.76 / 8.15 | 10.57 / 13.07 | 350 / 0.87 / 57 | 252 / 0.87 / 43 | 1.39× |
| trojan | 16.22 / 16.28 | 39.12 / 19.46 | 279 / 0.88 / 49 | 173 / 0.78 / 44 | 1.61× |

direct 是链路上限下持平。四个共有代理协议上,honk TCP 多 33–61%；HY2
少用 28% CPU,TUIC 少 25%,SS2022 CPU 持平,Trojan 多 13%。与 x86 不同,
ARM 内存不是 honk 优势：代理行 RSS 49–61MiB,dae 为 43–60MiB。空载延迟
也有取舍：honk 的 TUIC/SS2022/Trojan hot p95 更低,dae 的 HY2 更低。

#### UDP 饱和

| 协议 | honk RTT ms | dae RTT ms | honk Mbps / loss / 核 | dae Mbps / loss / 核 | honk/dae 带宽 |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 2.921 | 3.121 | 35 / 97.3% / 1.84 | 29 / 97.3% / 2.15 | 1.21× |
| tuic | 2.675 | 3.513 | 54 / 97.9% / 1.76 | 31 / 94.1% / 2.20 | 1.74× |
| ss2022 | 2.021 | 2.581 | 35 / 71.8% / 0.92 | 39 / 89.4% / 1.29 | 0.90× |
| trojan | 2.366 | 2.675 | 32 / 96.5% / 0.86 | 49 / 97.0% / 1.47 | 0.65× |

换到 ARM 没有改变 x86 的 UDP 分裂：honk 的 HY2/TUIC 更快,dae 的
SS2022/Trojan 更快。绝对值是 A53/USB 网卡饱和结果,不是公网预期。

#### loaded 开流稳定性

| 协议 | honk 负载 Mbps | honk p50 / p95 / p99 / max ms;失败 | dae 负载 Mbps | dae p50 / p95 / p99 / max ms;失败 |
| --- | ---: | --- | ---: | --- |
| direct | 877 | 13.263 / 16.429 / 253.604 / 2040.151; 0/200 | 896 | 12.817 / 22.490 / 240.131 / 1032.783; 0/200 |
| hy2 | 267 | 75.391 / 144.587 / 171.303 / 209.632; 0/200 | 188 | 45.731 / 84.419 / 104.706 / 120.980; 1/200 |
| tuic | 261 | 30.032 / 67.089 / 78.956 / 137.535; 0/200 | 191 | 104.555 / 114.873 / 120.645 / 124.333; 0/200 |
| ss2022 | 356 | 17.586 / 31.881 / 41.419 / 192.975; 0/200 | invalid | invalid(3/3 load arm 中断) |
| trojan | 293 | 14.632 / 30.428 / 38.831 / 39.198; 1/200 | 173 | 23.968 / 29.960 / 36.468 / 52.650; 0/200 |

direct 对照说明 ARM tail 必须结合负载看：两个引擎在约 0.9Gbps 时 p99
都约 240–254ms,最大超过 1s,但 engine CPU 近零；瓶颈是饱和 host/USB
路径。HY2 是容量/延迟取舍：honk 多 42% 吞吐,dae 在更低负载下 self-
saturated p99 更低。TUIC 更明确偏向 honk：负载多 37% 且 p99 更低。
Trojan p99 基本持平,但 honk 负载多 69%。

定向复测的负载稳定,同时暴露了整轮失败数的变化：

| 引擎 / 协议 | arm A:负载 / p99 / 失败 | arm B:负载 / p99 / 失败 |
| --- | --- | --- |
| honk / hy2 | 267Mbps / 171.303ms / 0/200 | 269Mbps / 164.253ms / 5/200 |
| honk / tuic | 261Mbps / 78.956ms / 0/200 | 260Mbps / 114.847ms / 0/200 |
| dae / hy2 | 188Mbps / 104.706ms / 1/200 | 188Mbps / 87.126ms / 0/200 |
| dae / tuic | 191Mbps / 120.645ms / 0/200 | 193Mbps / 118.337ms / 0/200 |

dae SS2022 与 x86 完全复现：每个 load arm 都在 30s 以
`control socket has closed unexpectedly` 结束。中断前为 246–260Mbps；
三次 HTTP 失败为 0/200、5/200、6/200。相同时间点和错误跨架构重现,
说明这是 dae 长流生命周期结果,不是 host 噪声。

### honk-only AnyTLS 与 rprx 覆盖

ARM dae build 没有 AnyTLS/rprx handler,所以下表不标成 A/B 胜利。专用
rprx 配置复用实际在线的 `8001-8003` / `5201-5203` 目标；原先预留的
`8007-8009` / `5207-5209` 未启动,对应探索数据已丢弃。VLESS/VMess 没有
UDP 实现；归档中的空值/`0(-)` UDP 字段代表 capability N/A,不是回退或
性能退化,修正后的 harness 会显式输出 `n/a`。

原始证据：[ARM AnyTLS](../bench/results/cross-arch-2026-08-08/arm64-honk-anytls.tsv)、
[ARM AnyTLS loaded](../bench/results/cross-arch-2026-08-08/arm64-honk-anytls-stability.tsv)、
[ARM AnyTLS raw](../bench/results/cross-arch-2026-08-08/arm64-honk-anytls-stability-raw/)、
[ARM rprx](../bench/results/cross-arch-2026-08-08/arm64-honk-rprx.tsv)、
[ARM rprx loaded](../bench/results/cross-arch-2026-08-08/arm64-honk-rprx-stability.tsv)、
[ARM rprx raw](../bench/results/cross-arch-2026-08-08/arm64-honk-rprx-stability-raw/)、
[x86 rprx](../bench/results/cross-arch-2026-08-08/x86-honk-rprx.tsv)、
[x86 rprx loaded](../bench/results/cross-arch-2026-08-08/x86-honk-rprx-stability.tsv) 与
[x86 rprx raw](../bench/results/cross-arch-2026-08-08/x86-honk-rprx-stability-raw/)。

| 协议 | x86 cold / hot p95 ms; Mbps / 核 | ARM cold / hot p95 ms; Mbps / 核 | x86 loaded Mbps / p99 / 失败 | ARM loaded Mbps / p99 / 失败 |
| --- | --- | --- | --- | --- |
| anytls-sb | 2.78 / 3.07; 8532 / 0.46 | 9.08 / 7.20; 324 / 0.97 | 8852 / 8.510ms / 0/200 | 336 / 168.274ms / 0/200 |
| anytls-go | 2.98 / 4.15; 9105 / 0.49 | 8.24 / 8.55; 313 / 0.96 | 9027 / 16.813ms / 0/200 | 318 / 515.541ms / 0/200 |
| vless-vision | 4.88 / 4.03; 9372 / 0.60 | 23.47 / 20.23; 154 / 0.71 | 9353 / 16.677ms / 0/200 | 168 / 39.023ms / 8/200 |
| vless-reality | 4.69 / 8.03; 9367 / 0.45 | 17.78 / 13.48; 282 / 0.87 | 9320 / 16.910ms / 0/200 | 274 / 53.338ms / 0/200 |
| vmess | 2.33 / 2.35; 9373 / 0.51 | 9.42 / 7.88; 342 / 1.29 | 7789 / 48.780ms / 0/200 | 335 / 37.198ms / 0/200 |

x86 三项 rprx 的常规吞吐都为 9.37Gbps；VMess 在 50s 混合负载中降到
7.79Gbps,p99 升到 48.8ms。ARM 上 Vision 是明显异常项：154Mbps,loaded
时有 8 个聚集的 5s HTTP timeout。Reality 和 VMess 无失败。AnyTLS-Go
的 ARM p99 515ms 来自小段长尾(p50 156ms,max 1.006s),不是失败请求。

### 跨架构决策

- **TCP 容量**：honk 在 ARM 四个共有协议上领先 33–61%；x86 除 SS2022
  (-1.2%)外领先或持平；direct 持平。
- **效率**：honk 在全部 x86 代理行以及 ARM HY2/TUIC 上 CPU 更少；ARM
  Trojan 与内存是反例,所以不能泛化。
- **延迟稳定性**：x86 总体偏向 honk,尤其 TUIC,但仍观察到稀疏 timeout。
  ARM 与负载相关：dae HY2 在低 30% 负载下 tail 更低；honk TUIC 则负载
  更高且 tail 更低。只按吞吐或只按 p99 排名都不诚实。
- **UDP**：两个架构上 honk 都赢 HY2/TUIC、输 SS2022/Trojan。
- **长流失败**：dae SS2022 的 30s control closure 在每台机器都 3/3
  复现,是矩阵里最强的稳定性缺陷。
- **资源适配**：x86 honk 节省 RSS,1GiB R2S 上则没有。rprx 在 x86
  line-rate；Vision 的 ARM 吞吐与 4% 样本 timeout 率仍需改进,不能称为
  饱和负载下 gateway-safe。

## 结果(2026-08-06,UDP post-decision 卸载验证轮 @ NanoPi R2S)

验证 UDP QUIC 卸载(drop-and-reinject 重构版,`HONK_UDP_POST_DECISION_OFFLOAD=1`)。
标准 UDP 行(iperf3/echo,代理协议组)不受此功能影响——数值与上轮逐行吻合
(噪声内)即为正确结果;另增 QUIC 型 direct UDP 负载补测(juicity 隧道穿
`domain(suffix:hy2.test)->direct`,domain++):

| 负载 | 卸载开 | 卸载关 |
| --- | --- | --- |
| QUIC direct UDP(juicity) | **149.1 Mbps @ 0.00 核**(endpoint hits=0) | 33.2 Mbps @ 0.78 核(hits=13588) |

吞吐 4.5×、引擎 CPU 归零(149Mbps 上限来自 juicity 客户端自身在 A53 上的
QUIC crypto)。direct 行保持 874 Mbps @ 0.00 核(dae 889 持平),TCP 协议行
偏差 ≤2.3% 无回归。

## 结果(2026-08-06,direct 内核卸载验证轮 @ NanoPi R2S)

验证 PR #17(Rule 模式 direct 流全量内核卸载,按流缓存决策,零每包开销)。
引擎为 feat/rprx(含 main `ac5ffbb`)aarch64 musl,lab 的 8080/5300 目标走
`fallback: direct`(非 must)——正是本功能的目标路径。两轮交替,dae 同窗口
重测。

| 引擎 | 协议 | cold | bw (Mbps) | cpu | RSS |
| --- | --- | --- | --- | --- | --- |
| honk | direct(卸载后) | 0.0043 | **880**(上轮 370) | **0.01**(上轮 0.71) | 61 |
| dae | direct | 0.0041 | 896 | 0.01 | 39 |

协议行两轮全部在上轮噪声内(hy2 267/268、tuic 260/262、ss2022 353/353、
trojan 279/282),无回归。honk direct 与 dae 同量级(差距 1.8% 属链路噪声),
cold 同步改善(6.2→4.3ms,与 dae 4.1ms 持平)。

## 结果(2026-08-05,ARM A/B: honk vs dae @ NanoPi R2S)

双引擎对照轮,引擎机 NanoPi R2S(两轮:.43 板载网口 / .45 USB 网卡复测),
honk 为 feat/rprx `2ad0a93` aarch64 musl,dae 为 kdae `ae056a6a`(go1.26.5)。
方法学不变;两引擎同一时刻只跑一个。dae 仅支持共有协议行(hy2/tuic/
ss2022/trojan)。两轮交替取均值,轮内偏差 <5%。**注意 .45 复测用 USB 网卡,
绝对带宽整体下移 ~10–15%,引擎间比值才是可比项。**

### TCP(.45 复测值;`→` 后为 .43 首轮值)

| 引擎 | 协议 | cold | hot p50 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0062 | – | 370 →458 | 0.71 | 52 |
| dae | direct | 0.0057 | – | 895 →931 | 0.01 | 39 |
| honk | hy2 | 0.0091 | 0.0081 | 268 →303 | 1.34 | 59 |
| dae | hy2 | 0.0367 | 0.0079 | 191 →197 | 1.86 | 57 |
| honk | tuic | 0.0070 | 0.0070 | 262 →293 | 1.36 | 59 |
| dae | tuic | 0.1040 | 0.0834 | 196 →208 | 1.80 | 49 |
| honk | ss2022 | 0.0070 | 0.0058 | 353 →385 | 0.88 | 51 |
| dae | ss2022 | 0.0114 | 0.0092 | 247 →265 | 0.87 | 41 |
| honk | trojan | 0.0221 | 0.0061 | 282 →328 | 0.88 | 53 |
| dae | trojan | 0.0228 | 0.0163 | 171 →201 | 0.78 | 42 |

### UDP(.45 复测值;echo RTT 秒 / 饱和接收 Mbps / cpu)

| 引擎 | 协议 | RTT | bw | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2/udp | 0.0029 | 33 | 1.85 |
| dae | hy2/udp | 0.0034 | 31 | 2.14 |
| honk | tuic/udp | 0.0028 | 53 | 1.76 |
| dae | tuic/udp | 0.0034 | 33 | 2.21 |
| honk | ss2022/udp | 0.0021 | 34 (73.8%) | 0.93 |
| dae | ss2022/udp | 0.0027 | 40 (87.9%) | 1.29 |
| honk | trojan/udp | 0.0019 | 31 | 0.88 |
| dae | trojan/udp | 0.0031 | 49 | 1.45 |

解读:

- **honk TCP 吞吐领先 35–65% 且可复现**:hy2 1.40×、tuic 1.34×、trojan
  1.65×、ss2022 1.43×(与 .43 轮比值漂移 ≤0.1);每 Mbps 的 CPU 成本约为
  dae 的一半(hy2: 1.34 核@268 vs 1.86 核@191)。A53 弱核上 Go 运行时的
  每字节成本在 QUIC 协议上被放大得最厉害。
- **延迟**:dae tuic 热 p50 83ms/冷 104ms(每连接重建 QUIC 会话)两轮原样
  重现;honk 全协议热 p50 ≤8ms。UDP echo RTT honk 各行稳定低 0.5–1.2ms。
- **direct 行差异是路径而非引擎**:dae 把 fallback direct 全量 eBPF 卸载
  (895Mbps@0.01 核),honk 只对 must 标记的 direct 卸载,fallback direct
  走用户态 relay(370@0.71)——可作 honk 后续优化点。
- **UDP** 两引擎都触及 A53 平台瓶颈(30–57Mbps),互有胜负;内存 dae 略省
  (38–59MB vs 48–61MB),1GB 设备上均非约束。
- 公平性:双方 TCP relay 均在用户态(dae 日志确认 eBPF offload 关闭)。

## 结果(2026-08-05,ARM 轮: NanoPi R2S / RK3328)

引擎机 10.10.10.43(NanoPi R2S: 4×Cortex-A53 @1.3GHz, 968MB RAM, end0
1Gbps, kernel 6.18, cpuinfo 含 `aes pmull sha1 sha2`),引擎为 feat/rprx
`2ad0a93` aarch64 musl 构建。方法学不变(netns lab → 真实 eBPF 数据面 →
.70)。**线速锚点: 关闭引擎后 netns+NAT 路径打满 941 Mbps**,以下数字的
瓶颈全在引擎用户态。CPU 列仅含 honk 进程 utime/stime,不含 softirq。

### TCP

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0064 | – | – | 437 | 0.74 | 50 |
| honk | hy2 | 0.0100 | 0.0084 | 0.0090 | 301 | 1.34 | 61 |
| honk | tuic | 0.0097 | 0.0073 | 0.0082 | 304 | 1.33 | 56 |
| honk | ss2022 | 0.0105 | 0.0057 | 0.0065 | 388 | 0.83 | 55 |
| honk | trojan | 0.0213 | 0.0060 | 0.0205 | 329 | 0.91 | 50 |
| honk | anytls-sb | 0.0066 | 0.0061 | 0.0065 | 336 | 0.98 | 51 |
| honk | anytls-go | 0.0116 | 0.0065 | 0.0076 | 337 | 0.96 | 51 |
| honk | vless-reality-vision | 0.0225 | 0.0181 | 0.0196 | 183 | 0.74 | 51 |
| honk | vless-reality | 0.0208 | 0.0174 | 0.0287 | 332 | 0.88 | 52 |
| honk | vmess (tcp) | 0.0076 | 0.0067 | 0.0087 | 416 | 1.50 | 47 |

### UDP(热态,`udp_warm_node_count: 8`)

| 协议 | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- |
| hy2 | 2.77 ms | 34 (97.8%) | 1.91 |
| tuic | 2.88 ms | 46 (98.1%) | 1.86 |
| ss2022 | 2.09 ms | 42 (91.0%) | 0.92 |
| trojan | 2.12 ms | 38 (98.1%) | 0.90 |
| anytls-sb | 2.23 ms | 50 (89.3%) | 1.79 |
| anytls-go | 2.54 ms | 57 (87.7%) | 1.80 |

解读(A53 小核 vs x86 E-13600K,同方法学对照 08-04 轮):

- **全部 CPU-bound**:direct 437(x86 9390);TCP 类被压平在 330–390
  Mbps(行间扁平 = 瓶颈在公共 relay+crypto 路径);QUIC 每核效率差 ~20 倍。
  vmess 416 最接近 direct 基线,印证 `5dc47cf` 的 BoringSSL AEAD 在 ARM
  crypto extensions 下同样有效;其 cpu 1.50 仍是 TCP 类最高(跨平台共同
  优化点)。vless-vision 183 为 TCP 最低行;vision/reality 行 hot p50
  ~18ms(x86 3.3ms)是 REALITY 握手在慢 crypto 上的每连接成本。
- **UDP 是重灾区**:34–57 Mbps、丢包 88–98%——A53 上逐包路径(TPROXY
  recvmsg provenance + anyfrom 回复 + 隧道组帧)完全饱和,echo RTT 比
  x86 慢一个量级。
- **RSS 47–61MB 与 x86 相同**,1GB 设备全程无内存压力——瓶颈纯 CPU。
- rprx 行的 .70 目标服务(8007-8009/5207-5209/53537-53539)本轮处于半坏
  状态,三行用等价变体(工作目标 8001/5201 重路由到对应 group)测量,
  方法学不变。

## 结果(2026-08-05,rprx 协议族: VLESS+REALITY(±vision)/VMess 入列)

本轮覆盖 feat/rprx(PR #12)新增的协议行,引擎为 feat/rprx musl+mimalloc 构建
(vless 行于 `67b5a56` 测量,vmess 行在 `5dc47cf` AEAD 修复后重建测量;修复
内容见该分支)。方法学与上文完全一致。新增服务端矩阵(10.10.10.70,sing-box
1.13.14):vless+reality+vision `:2448`、vless+reality `:2449`、vmess 裸 tcp
`:2450`;目标服务 http `8007-8009`、iperf3 `5207-5209`、udp echo
`53537-53539`;引擎按端口路由(`5207/8007/53537→vision`、`…8→reality`、
`…9→vmess`)。reality 伪装目标为本地 TLS 服务(注意:dest 的 TLS Certificate
消息必须 <8KiB,否则 reality 服务端的 CH 缓存放不下会判定失败)。

校准锚点(本轮 vs 08-04 轮):direct 9411/9390、ss2022 9399/9398、
anytls-sb 9406/9388 Mbps——环境判定一致,下表可直接与 08-04 轮横向比较。

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | vless-reality-vision | 0.0037 | 0.0033 | 0.0050 | 9372 | 0.60 | 45 |
| honk | vless-reality | 0.0043 | 0.0034 | 0.0042 | 9383 | 0.49 | 54 |
| honk | vmess (tcp) | 0.0022 | 0.0010 | 0.0014 | 9313 | 0.78 | 50 |

- 三行全部贴线速(~9.4G)。vmess 行是 `5dc47cf`(body AEAD 从 RustCrypto
  切到 BoringSSL)之后的结果;修复前同路径 handler 级测量仅 ~420 MB/s
  (单核 105%)。vmess cpu 0.78 核仍是 TCP 类协议中最高(每 chunk 的
  SHAKE 长度掩码 + 帧处理),可作后续优化点。
- vision vs 无 vision 无带宽差异(10G 内非 vision 的 BoringSSL AES-NI 已
  贴线速);vision 行 cpu 略高(0.60 vs 0.49)为组帧开销,cold 含 reality
  握手。
- vless/vmess 在 honk 无 UDP 数据面(README TODO),UDP 行无数据,非测量
  失败。

## 结果(2026-08-04,honk outbound-v2 重构回归验证)

本轮是 outbound-v2 重构合并的单引擎回归验证,不含 dae/sing-box 对照臂;
对照基线为 08-02 轮(`49b166d`)。引擎机 10.10.10.59,服务端 10.10.10.70,
测量方法不变。

- honk: main `d00cb5e`(musl, mimalloc)——outbound-v2 重构(协议面收缩为
  Direct/Block/SOCKS5/SS2022/Trojan/VMess/VLess/AnyTLS/Hysteria2/TUIC/Juicity;
  `ProtocolDescriptor` 能力表;能力 trait 取代大接口 `ProxyHandler`;内容派生
  稳定 NodeId;QUIC client 归 generation 所有且未变节点跨 reload 复用;TCP 拨号
  路径固定准入 generation;拨号预算 per-generation),外加下述 AnyTLS 溢出修复。

**本轮抓到一个 main 上的真实回归。** `85d6b61`(限制慢消费者溢出,已随
v0.0.1.beta.33/34 发布)在流溢出达到 2 MiB 上限的瞬间即 reset——但快 LAN
对端约 4ms 就能 burst 超过这个量,此时 reader 任务尚未被首次调度,于是单流
iperf3 在重构前(`8a32149`)与重构后的二进制上都只有 2–3 Mbps(bisect 确认:
父提交 `c7cbd67` 正常,8.8 Gbps)。修复(`caa95b0` + `d00cb5e`)恢复基于进展的
语义:流字节上限在 3 秒无 flush 进展宽限内为软上限——parked 字节不等于停滞;
session 级上限触顶时 demux 以 500ms 轮次等待 reader 进展(暂停读取借 TCP 窗口
施加背压),超时的轮次只 reset 最停滞的 parked 流。实验室验证:anytls-sb 9388 /
anytls-go 9396 Mbps,零溢出误杀,relay 计数器确认走隧道。

### TCP

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0022 | – | – | 9390¹ | 0.27 | 54 |
| honk | hy2 | 0.0024 | 0.0011 | 0.0020 | 6156 | 1.03 | 56 |
| honk | tuic | 0.0024 | 0.0013 | 0.0019 | 5293 | 0.71 | 54 |
| honk | ss2022 | 0.0019 | 0.0013 | 0.0016 | 9398 | 0.37 | 54 |
| honk | trojan | 0.0046 | 0.0010 | 0.0034 | 9377 | 0.47 | 50 |
| honk | anytls-sb | 0.0025 | 0.0012 | 0.0015 | 9388 | 0.47 | 51 |
| honk | anytls-go | 0.0023 | 0.0013 | 0.0017 | 9396 | 0.49 | 50 |

### UDP(热态,`udp_warm_node_count: 8`)

| 引擎 | 协议 | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.12 ms | 1814 (72.7%) | 1.25 |
| honk | tuic | 0.37 ms | 58 (68.6%)² | 0.07 |
| honk | ss2022 | 0.15 ms | 1889 (68.7%) | 1.32 |
| honk | trojan | 0.06 ms | 1394 (79.7%) | 1.08 |
| honk | anytls-sb | 0.07 ms | 1370 (77.4%) | 0.92 |
| honk | anytls-go | 0.22 ms | 1735 (71.7%) | 1.24 |

¹ direct 行首次读数 6841 处于实验室负载窗口;随后三次复测为 9388/9389/9390。
² 本轮 TUIC UDP 对所有引擎都塌陷——.70→.59 UDP 链路接近饱和(与 08-02 轮
相同的实验室条件 artifact),非引擎回归。

### 08-04 结果解读

- **重构无回归**:与当天重构前对照臂(`8a32149`)相比,非 AnyTLS 行全部在
  实验室波动内持平(hy2 6156 vs 5966,tuic 5293 vs 5546,ss2022/trojan 双双
  线速)。相对 08-02 轮的更高读数(hy2 2858、tuic 4134)来自空闲实验室,而非
  重构提速——QUIC 数据面代码未变。
- **AnyTLS 是最大收益**:停滞宽限修复把 anytls-sb 从回归前基线 4575 提到 9388
  (线速),anytls-go 到 9396——demux 背压设计同时消除了旧 park 路径在快对端下
  的溢出抖动。重构前二进制两行均只有 2–3 Mbps(bug 存在)。
- TUIC UDP 仍是已知弱点(见上实验室链路说明)。

## 结果(2026-08-02,三引擎:honk vs dae vs sing-box)

本轮引擎机为 **10.10.10.59**(同实验室的另一台 VM,服务端仍为物理机
10.10.10.70;生产网关 10.10.10.1 已加 `sip(10.10.10.59/32) -> direct(must)`
规则,基准流量不经过网关代理面)。配置与测量方法与 08-01 轮一致。

- honk: main `49b166d`(musl, mimalloc)——含 eBPF 数据面准入门、LB/Fallback
  按 TCP/UDP 分离、AnyTLS TLS connector 懒加载、日志短路修复、拨号失败罚样本、
  TPROXY listener 标记、URLTest 减半递推移动平均。
- dae: kdae `ae056a6a`(Go 1.26.0;自 08-01 轮的 `eee7c88b` 更新,含 outbound
  fork 修复)。
- sing-box: v1.13.14(lab netns 内 TUN 客户端,按端口路由)。

延迟单位秒,TCP 带宽为 iperf3 接收端中位数,CPU 单位核,RSS 为跑后值。

### TCP

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0082 | – | – | 9399 | 0.26 | 54 |
| dae | direct | 0.0034 | – | – | 9402 | 0.00 | 50 |
| sing-box | direct | 0.0052 | – | – | 9403 | 0.43 | 47 |
| honk | hy2 | 0.0060 | 0.0034 | 0.0047 | 2858 | 0.49 | 59 |
| dae | hy2 | 0.0104 | 0.0032 | 0.0036 | 2757 | 0.82 | 61 |
| sing-box | hy2 | 0.0108 | 0.0039 | 0.0053 | 2570 | 0.87 | 51 |
| honk | tuic | 0.0060 | 0.0037 | 0.0054 | 4134 | 0.59 | 54 |
| dae | tuic | 0.0858 | 0.0797 | 0.0804 | 2940 | 0.82 | 62 |
| sing-box | tuic | 0.0083 | 0.0039 | 0.0051 | 2618 | 0.89 | 51 |
| honk | ss2022 | 0.0052 | 0.0036 | 0.0061 | 9333 | 0.39 | 57 |
| dae | ss2022 | 0.0041 | 0.0041 | 0.0049 | 9372 | 0.51 | 53 |
| sing-box | ss2022 | 0.0057 | 0.0041 | 0.0069 | 9342 | 1.30 | 51 |
| honk | trojan | 0.0113 | 0.0023 | 0.0107 | 9244 | 0.46 | 50 |
| dae | trojan | 0.0104 | 0.0075 | 0.0106 | 9162 | 0.71 | 55 |
| sing-box | trojan | 0.0098 | 0.0090 | 0.0124 | 9187 | 0.86 | 49 |
| honk | anytls-sb | 0.0055 | 0.0043 | 0.0061 | 4575 | 0.30 | 50 |
| dae | anytls-sb | 0.0089 | 0.0037 | 0.0047 | 4522 | 0.40 | 56 |
| sing-box | anytls-sb | 0.0131 | 0.0035 | 0.0053 | 4512 | 0.50 | 48 |
| honk | anytls-go | 0.0052 | 0.0032 | 0.0049 | 8937 | 0.54 | 52 |
| dae | anytls-go | 0.0080 | 0.0038 | 0.0049 | 8892 | 0.69 | 61 |
| sing-box | anytls-go | 0.0113 | 0.0039 | 0.0046 | 8741 | 1.05 | 48 |

### UDP (iperf3 `-u -b 10G -l 1200 -R`)

| 引擎 | 协议 | echo RTT p50 | bw Mbps (丢包) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.20 ms | 1743 (71.5%) | 1.16 |
| dae | hy2 | 0.22 ms | 931 (85.5%) | 0.95 |
| sing-box | hy2 | 0.33 ms | 1561 (75.0%) | 1.41 |
| honk | tuic | 0.20 ms | 1577 (70.6%) | 1.33 |
| dae | tuic | 0.33 ms | 108 (76.2%) | 0.13 |
| sing-box | tuic | 0.30 ms | 27 (80.9%) | 0.05 |
| honk | ss2022 | 0.20 ms | 1207 (78.6%) | 1.23 |
| dae | ss2022 | 0.13 ms | 2367 (58.6%) | 1.76 |
| sing-box | ss2022 | 0.17 ms | 2509 (55.6%) | 1.34 |
| honk | trojan | 0.10 ms | 1629 (70.1%) | 1.28 |
| dae | trojan | 0.18 ms | 2903 (49.5%) | 1.67 |
| sing-box | trojan | 0.13 ms | 3330 (41.6%) | 1.66 |
| honk | anytls-sb | 0.23 ms | 1287 (79.2%) | 0.91 |
| dae | anytls-sb | 0.26 ms | 1290 (77.9%) | 0.91 |
| sing-box | anytls-sb | 0.36 ms | 1262 (79.1%) | 1.18 |
| honk | anytls-go | 0.24 ms | 1539 (75.6%) | 1.10 |
| dae | anytls-go | 0.22 ms | 1493 (76.0%) | 1.01 |
| sing-box | anytls-go | 0.18 ms | 1368 (77.7%) | 1.24 |

### UDP:预热稳态三引擎对比(08-02)

方法同 08-01 稳态轮:每引擎启动后等 30s 健康检查收敛,各协议 5 次 TCP 预热,
静置 10s 后测量。`iperf3 -u -b 10G -l 1200 -R` 单流与 `-P 8` 聚合。

| 引擎 | 协议 | echo RTT (ms) | 单流 Mbps(丢包) | P8 聚合 Mbps(丢包) |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.22 | 1663 (73.8%) | 1582 (95.8%) |
| dae | hy2 | 0.36 | 938 (85.6%) | 864 (97.6%) |
| sing-box | hy2 | 0.42 | 1607 (74.4%) | 1588 (95.7%) |
| honk | tuic | 0.11 | 359 (67.1%) | FAIL |
| dae | tuic | 0.11 | 325 (75.1%) | 1 (27.3%) |
| sing-box | tuic | 0.14 | 101 (74.2%) | FAIL |
| honk | ss2022 | 0.19 | 1851 (67.2%) | 2928 (88.0%) |
| dae | ss2022 | 0.21 | 2448 (55.6%) | 2382 (89.8%) |
| sing-box | ss2022 | 0.19 | 2475 (56.5%) | 2944 (87.9%) |
| honk | trojan | 0.06 | 1623 (72.0%) | 3159 (91.8%) |
| dae | trojan | 0.13 | 2864 (49.6%) | 2631 (92.3%) |
| sing-box | trojan | 0.09 | 3226 (42.7%) | 4092 (88.9%) |
| honk | anytls-sb | 0.69 | 1294 (78.5%) | 1266 (96.5%) |
| dae | anytls-sb | 0.15 | 1278 (78.8%) | 2610 (91.1%) |
| sing-box | anytls-sb | 0.67 | 1268 (79.1%) | 2760 (90.7%) |
| honk | anytls-go | 0.12 | 1484 (76.5%) | 1269 (96.5%) |
| dae | anytls-go | 0.21 | 1435 (76.9%) | 2259 (93.2%) |
| sing-box | anytls-go | 0.98 | 1375 (77.8%) | 2248 (93.1%) |

注:第一轮稳态测量时实验室配置**未启用** `udp_warm_node_count`(honk 的 UDP
预热;生产配置为 8)。补上 `udp_warm_node_count: 8` 后重测 honk 各行如下
(dae/sing-box 无此开关,行不变):

| 引擎 | 协议 | 单流 Mbps(丢包) | P8 聚合 Mbps(丢包) |
| --- | --- | --- | --- |
| honk(开 udp_warm) | hy2 | 1622 (74.1%) | 1650 (95.5%) |
| honk(开 udp_warm) | tuic | **1252 (72.3%)** | FAIL |
| honk(开 udp_warm) | ss2022 | 1796 (68.7%) | 2916 (88.0%) |
| honk(开 udp_warm) | trojan | 1562 (73.2%) | 3283 (91.3%) |
| honk(开 udp_warm) | anytls-sb | 1254 (79.9%) | 1297 (96.2%) |
| honk(开 udp_warm) | anytls-go | 1400 (77.4%) | 1298 (96.3%) |

tuic 单流从 359 提升到 1252 Mbps——冷会话建立确实占了未预热测量的主要部分;
其余行在噪声范围内。anytls P8 垫底与 tuic P8 FAIL 与预热无关,为真实短板。

**稳态 UDP 解读(08-02):**

- **hy2**:honk 1663 ≈ sing-box 1607 > dae 938;P8 三家均不扩展(0.9–1.6 Gbps,
  丢包 96%+),与 08-01 稳态轮 honk hy2 单流 5.91 Gbps 相差甚远——见下方实验
  室条件备注。
- **tuic UDP 三引擎全部崩塌**(101–359 Mbps):同轮 direct UDP 基线(5300 端口,
  不过代理)实测也只有 1954 Mbps / 61% 丢包,说明本轮 .70→.59 的 UDP 链路本身
  已接近饱和上限。tuic 的绝对值不可与 08-01 稳态轮(6.18 Gbps)直接比较;
  该现象为实验室条件所致,待链路空闲后重测。
- **ss2022**:单流 sing-box 2475 ≈ dae 2448 > honk 1851;P8 honk 2928 ≈
  sing-box 2944 > dae 2382。honk 单流仍落后,P8 已追平。
- **trojan**:单流 sing-box 3226 > dae 2864 > honk 1623;P8 sing-box 4092 >
  honk 3159 > dae 2631。honk 的 trojan UDP-over-TCP 单流仍是三方最低,为
  头号 UDP 优化目标。
- **anytls UoT**:单流三方持平(~1.3–1.5 Gbps);**P8 honk 明显最低**
  (1266/1269 vs dae 2610/2259 vs sing-box 2760/2248)——anytls 多流 UDP 是
  新暴露的短板,值得专项分析。

### 08-02 结果解读

- **延迟**:honk 全面最优——cold 5–11ms(dae tuic 仍为每连接完整 QUIC 握手
  86ms;sing-box 8–13ms),hot p50 2.3–4.7ms。
- **TCP 带宽**:线速行(ss2022、trojan、anytls-go)三方基本持平
  (~8.7–9.4 Gbps)。QUIC 协议 honk 领先:hy2 2858(+3.7% vs dae、+11% vs
  sing-box),tuic 4134(+41% / +58%)。与 08-01 轮相比,dae 的 hy2/tuic
  带宽从 4467/4537 回落到 2757/2940,honk 的 hy2 恢复至同档。
- **UDP**:QUIC 协议 honk 大幅领先——hy2 1743(vs 931/1561),tuic 1577
  (vs 108/27,dae 与 sing-box 的 tuic UDP 本轮接近不可用)。**短板仍在
  UDP-over-TCP**:ss2022 1207 vs 2367/2509,trojan 1629 vs 2903/3330——
  honk 约为对手一半,仍是 UDP 方向头号优化目标。anytls-sb/go 三方持平
  (~1.3–1.5 Gbps)。
- **CPU**:honk 多数行最低(ss2022 0.39 vs 0.51/1.30 核;hy2 0.49 vs
  0.82/0.87;tuic 0.59 vs 0.82/0.89)。
- **RSS**:三方持平(47–62 MB)。

## 结果(2026-08-01,三引擎:honk vs dae vs sing-box)

honk: dev `ed640c7` (musl, mimalloc, reuseport-2 合入,单 UDP listener/协议族)。
dae: kdae 分支, Go 1.26.0。
sing-box: v1.13.14 (lab netns 内 TUN 客户端,按端口路由协议)。
三者同时间在实验室测试。延迟单位秒,TCP 带宽为 iperf3 接收端中位数,
CPU 单位核,RSS 为跑后值。sing-box 未测 CPU(TUN 客户端模式下无法分离
单协议进程 CPU)。

### TCP

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0060 | – | – | 9411 | 0.24 | 58 |
| dae | direct | 0.0035 | – | – | 9395 | – | 50 |
| sing-box | direct | 0.0085 | – | – | – | – | 59 |
| honk | hy2 | 0.0085 | 0.0042 | 0.0053 | 3050 | 0.50 | 60 |
| dae | hy2 | 0.0102 | 0.0023 | 0.0045 | 4467 | 1.07 | 66 |
| sing-box | hy2 | 0.0451 | 0.0046 | 0.0059 | 2998 | – | – |
| honk | tuic | 0.0051 | 0.0032 | 0.0051 | 4400 | 0.60 | 57 |
| dae | tuic | 0.0851 | 0.0037 | 0.0046 | 4537 | 0.98 | 64 |
| sing-box | tuic | 0.0151 | 0.0035 | 0.0041 | 2620 | – | – |
| honk | ss2022 | 0.0046 | 0.0028 | 0.0035 | 9205 | 0.36 | 52 |
| dae | ss2022 | 0.0076 | 0.0047 | 0.0058 | 9405 | 0.45 | 55 |
| sing-box | ss2022 | 0.0220 | 0.0027 | 0.0040 | 8717 | – | – |
| honk | trojan | 0.0103 | 0.0018 | 0.0084 | 9328 | 0.43 | 52 |
| dae | trojan | 0.0076 | 0.0018 | 0.0020 | 9369 | 0.66 | 57 |
| sing-box | trojan | 0.0150 | 0.0053 | 0.0064 | 9214 | – | – |
| honk | anytls-sb | 0.0053 | 0.0034 | 0.0046 | 4792 | 0.28 | 45 |
| dae | anytls-sb | 0.0139 | 0.0039 | 0.0047 | 5586 | 0.43 | 57 |
| sing-box | anytls-sb | 0.0083 | 0.0018 | 0.0023 | 8244 | – | – |
| honk | anytls-go | 0.0132 | 0.0031 | 0.0037 | 9249 | 0.48 | 56 |
| dae | anytls-go | 0.0232 | 0.0023 | 0.0027 | 9006 | – | – |
| sing-box | anytls-go | 0.0065 | 0.0019 | 0.0021 | 8823 | – | – |

### UDP (iperf3 `-u -b 10G -l 1200 -R`,单流,冷引擎)

| 引擎 | 协议 | echo RTT p50 | bw Mbps (丢包) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.19 ms | 286 (95.3%) | 2.27 |
| dae | hy2 | 0.21 ms | 907 (85.9%) | 0.93 |
| sing-box | hy2 | 0.26 ms | 1629 (73.8%) | – |
| honk | tuic | 0.40 ms | 11 (99.2%) | 0.01 |
| dae | tuic | 0.27 ms | 1702 (67.4%) | 1.48 |
| sing-box | tuic | 0.15 ms | 100 (96.4%) | – |
| honk | ss2022 | 0.17 ms | 2010 (65.1%) | 1.31 |
| dae | ss2022 | 0.30 ms | 2742 (51.6%) | 1.79 |
| sing-box | ss2022 | 0.15 ms | 1984 (54.7%) | – |
| honk | trojan | 0.13 ms | 1659 (70.7%) | 1.28 |
| dae | trojan | 0.10 ms | 3062 (47.2%) | 1.70 |
| sing-box | trojan | 0.10 ms | 3557 (41.2%) | – |
| honk | anytls-sb | 0.28 ms | 1316 (79.0%) | 0.84 |
| dae | anytls-sb | – | – | – |
| sing-box | anytls-sb | 0.21 ms | 608 (78.8%) | – |
| honk | anytls-go | 0.19 ms | 1600 (74.5%) | 1.07 |
| dae | anytls-go | 0.12 ms | 1566 (74.3%) | – |
| sing-box | anytls-go | 0.10 ms | 640 (77.6%) | – |

### 三引擎对照解读

**TCP 带宽:**
- 线速协议(ss2022, trojan, anytls-go):三者均达 ~8.7–9.4 Gbps。honk 和
  dae 差距在噪声范围内;sing-box 略低(ss2022 8717 vs 9405,anytls-go
  8823 vs 9249)。
- QUIC 协议(hy2, tuic):dae 领先 4467/4537 Mbps。honk 3050/4400,sing-box
  2998/2620。honk 的 hy2 相对 07-30 轮(5239→3050)有回退,疑似实验室宿
  主机负载影响。
- anytls-sb: sing-box 8244 领先,dae 5586,honk 4792。这是 sing-box 参考
  实现;honk anytls handler 落后约 40%。

**CPU 效率:**
- 在可比较的 QUIC 行上,honk CPU 约为 dae 的 50%(hy2:0.50 vs 1.07,
  tuic:0.60 vs 0.98)。
- TCP 类协议 honk 也持续比 dae 低 0.3–0.5 核。

**延迟:**
- dae tuic 冷延迟仍为每次连接完整 QUIC 握手(85ms vs honk ticket-cache
  恢复 5ms)。
- sing-box 冷延迟全面最高(TUN + 用户态路由增加 ~10–35ms)。
- 热延迟三者均在个位数 ms。

**UDP(冷引擎,单流):**
- 本轮在冷引擎上测量(健康检查未收敛),UDP 数值比稳态低 3–5 倍。稳态
  数据见下方"稳态三引擎对比"。
- TUIC UDP 三引擎冷启动全挂(11–100 Mbps),但预热后 honk 单流达 6.18
  Gbps——冷启动是会话建立的假象,不是协议限制。

### UDP:稳态三引擎对比

三个引擎分别启动,等待 30s 健康检查收敛,随后通过各协议进行 TCP 预热,
再等 10s 稳定后测量。单流和 8 流聚合(`iperf3 -u -b 10G -l 1200 -R` /
`-P 8`)。报文固定 1200B。

| 引擎 | 协议 | echo RTT | 单流(丢包) | P8 聚合(丢包) |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.12 ms | 5.91 Gbps (5.9%) | P8 失败† |
| dae | hy2 | 0.59 ms | 915 Mbps (85.8%) | 827 Mbps (97.6%) |
| sing-box | hy2 | 0.42 ms | 1.61 Gbps (74.4%) | 1.58 Gbps (95.9%) |
| honk | tuic | 0.32 ms | **6.18 Gbps (2.1%)** | **9.40 Gbps (0.8%)** |
| dae | tuic | 0.15 ms | 1.57 Gbps (71.4%) | 21 Mbps (45.3%) |
| sing-box | tuic | 0.14 ms | 31 Mbps (80.1%) | 失败 |
| honk | ss2022 | 0.23 ms | 5.67 Gbps (11.5%) | 8.83 Gbps (6.8%) |
| dae | ss2022 | 0.21 ms | 2.52 Gbps (55.1%) | 2.59 Gbps (88.8%) |
| sing-box | ss2022 | 0.17 ms | 2.57 Gbps (55.1%) | 3.00 Gbps (87.3%) |
| honk | trojan | 0.07 ms | **6.31 Gbps (0.06%)** | 8.74 Gbps (7.8%) |
| dae | trojan | 0.13 ms | 2.96 Gbps (49.6%) | 2.87 Gbps (91.8%) |
| sing-box | trojan | 0.09 ms | 3.52 Gbps (39.1%) | 4.31 Gbps (88.6%) |
| honk | anytls-sb | 0.06 ms | 5.54 Gbps (13.6%) | **9.24 Gbps (2.5%)** |
| dae | anytls-sb | 0.25 ms | 1.31 Gbps (78.8%) | 2.87 Gbps (89.9%) |
| sing-box | anytls-sb | 1.78 ms | 1.26 Gbps (79.2%) | 2.85 Gbps (90.9%) |
| honk | anytls-go | 0.08 ms | **6.44 Gbps (0.4%)** | **9.37 Gbps (1.1%)** |
| dae | anytls-go | 0.13 ms | 1.58 Gbps (74.2%) | 2.45 Gbps (92.6%) |
| sing-box | anytls-go | 0.10 ms | 1.45 Gbps (76.3%) | 2.36 Gbps (92.9%) |

† honk hy2 P8 本轮失败(iperf3 返回 0);此前稳态曾录得 9.18 Gbps / 3.1%
丢包。空闲实验室重测可确认。

### 稳态 UDP 解读

**Honk 在稳态 UDP 上全面领先:**
- 单流:5.5–6.4 Gbps,丢包 0.06–13.6%。dae 和 sing-box 仅 0.9–3.5 Gbps,
  丢包 40–86%——honk **快 2–6 倍,丢包低 5–15 倍**。
- P8 聚合:honk 达 8.7–9.4 Gbps(接近线速),丢包 0.8–7.8%。dae 和
  sing-box P8 崩溃,丢包 88–98%——它们的 UDP 数据面无法承载 8 条并行饱
  和流。
- **TUIC UDP** 从冷启动 11 Mbps 跃升至 **6.18 Gbps**(560 倍提升)。协议
  本身没问题;冷启动数据是会话建立的假象,不是协议限制。
- **Trojan UDP** 6.31 Gbps / 0.06% 丢包——honk 的 UDP-over-TCP 组帧在线
  速下无可测开销。
- **anytls-go** 6.44 Gbps / 0.4% 单流,9.37 Gbps / 1.1% P8,综合最强。

**dae 和 sing-box P8 崩溃不是实验室假象:**
两者表现一致——单流 1–3.5 Gbps 丢包尚可,P8 吞吐量不升反降,丢包飙至
88–98%。这说明它们的 UDP 接收路径存在根本瓶颈(共享 socket buffer 竞
争、缺少逐流排队或内核级 UDP socket 锁竞争),而这正是 honk 的
`UdpEndpointPool` 和逐流有界队列专门设计要解决的问题。

## 结果(2026-07-31,honk dev `ac64fe1` vs dae kdae `eee7c88b`)

实验室同时刻 A/B。honk 为 musl release 构建(mimalloc,周期性
`mi_collect` 已移至 blocking 线程并延迟首个周期,drain 改为空闲超时);
dae 为 kdae 分支 `eee7c88b`(新增 DNS group override 修复,outbound
fork 升至 `perf/complete-optimizations@670df833`)。延迟单位秒,带宽为
iperf3 接收端中位数,CPU 单位核,RSS 为跑后值。本轮新情况:**kdae 的
direct 基线已修复**(07-30 轮是坏的)。

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0052 | – | – | 9406 | 0.24 | 52 |
| honk | hy2 | 0.0101 | 0.0032 | 0.0046 | 2921 | 0.48 | 59 |
| honk | tuic | 0.0093 | 0.0034 | 0.0043 | 3961 | 0.55 | 59 |
| honk | ss2022 | 0.0044 | 0.0027 | 0.0040 | 9392 | 0.36 | 52 |
| honk | trojan | 0.0072 | 0.0019 | 0.0120 | 9341 | 0.45 | 53 |
| honk | anytls-sb | 0.0050 | 0.0031 | 0.0039 | 4790 | 0.30 | 57 |
| honk | anytls-go | 0.0122 | 0.0032 | 0.0040 | 9226 | 0.49 | 56 |
| dae | direct | 0.0051 | – | – | 9397 | 0.00 | 52 |
| dae | hy2 | 0.0090 | 0.0032 | 0.0037 | 3005 | 0.82 | 63 |
| dae | tuic | 0.0827 | 0.0792 | 0.0800 | 4280 | 0.93 | 64 |
| dae | ss2022 | 0.0040 | 0.0036 | 0.0062 | 9404 | 0.42 | 57 |
| dae | trojan | 0.0105 | 0.0078 | 0.0100 | 9340 | 0.65 | 57 |
| dae | anytls-sb | 0.0112 | 0.0029 | 0.0038 | 4742 | 0.37 | 58 |
| dae | anytls-go | 0.0069 | 0.0034 | 0.0046 | 9301 | 0.63 | 60 |

UDP(iperf3 `-u -b 10G -l 1200 -R`,接收端 Mbps + 丢包):

| 引擎 | 协议 | echo RTT p50 | bw Mbps (丢包) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.43 ms | 1708 (72.9%) | 1.07 |
| honk | tuic | 0.31 ms | 142 (64.5%) | 0.13 |
| honk | ss2022 | 0.22 ms | 1879 (66.6%) | 1.28 |
| honk | trojan | 0.18 ms | 1609 (71.9%) | 1.27 |
| honk | anytls-sb | 0.49 ms | 1308 (78.2%) | 0.86 |
| honk | anytls-go | 0.18 ms | 1607 (74.2%) | 1.04 |
| dae | hy2 | 0.27 ms | 929 (85.9%) | 0.95 |
| dae | tuic | 0.28 ms | 60 (52.4%) | 0.06 |
| dae | ss2022 | 0.16 ms | 2705 (52.4%) | 1.74 |
| dae | trojan | 0.11 ms | 2972 (48.7%) | 1.69 |
| dae | anytls-sb | 0.13 ms | 1305 (78.8%) | 0.85 |
| dae | anytls-go | 0.10 ms | 1413 (76.0%) | 0.92 |

### 07-31 结果解读

- **TCP 带宽**基本持平:线速行(direct、ss2022、trojan、anytls-go)
  两边都在 ~9.3–9.4 Gbps;anytls-sb 也首次打平(4790 vs 4742——新
  kdae 在这一行不再领先)。hy2/tuic 略偏 dae(3005/4280 vs 2921/3961)。
- **每 Gbps CPU** 依然是 honk 的强项,全部 QUIC 行:hy2 0.48 vs
  0.82 核,tuic 0.55 vs 0.93,trojan 同带宽下 0.45 vs 0.65。
- **延迟**:dae 的 tuic 仍为每条连接付完整 QUIC 握手(cold 82.7ms、
  hot p50 79.2ms;honk 靠票据缓存恢复,9.3/3.4ms)。其余行都在个位
  数毫秒。
- **UDP**:honk 领先 hy2(1708 vs 929)与 anytls-go;ss2022/trojan 的
  UDP-over-TCP 差距仍在(dae 2705/2972 vs honk 1879/1609),仍是 UDP
  方向的头号优化目标。tuic UDP 两边都差(142/60 Mbps)。
- honk 的 hy2/tuic TCP 带宽较 07-30 轮下降明显(5239→2921、
  5351→3961)而 dae 基本持平;本轮跑测时 .70 实验宿主机有高并发负
  载,这两行标记为存疑,待实验室空闲时复测确认。

## 结果(2026-07-30,honk dev session 各阶段完成后 vs dae kdae,AES-NI)

实验室同时刻 A/B(引擎 VM 已换 host 透传 CPU;更早的软件加密时代见
"已知的实验室限制")。延迟单位为秒(curl `time_total`),带宽为
iperf3 接收端中位数,CPU 为核数,RSS 为跑完后值。honk 为 musl 发布
二进制(mimalloc)。

| 引擎 | 协议 | cold | hot p50 | hot p95 | 带宽 (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0052 | – | – | 9413 | 0.16 | 53 |
| honk | hy2 | 0.0058 | 0.0018 | 0.0032 | 5239 | 1.06 | 64 |
| honk | tuic | 0.0024 | 0.0038 | 0.0049 | 5351 | 1.06 | 66 |
| honk | ss2022 | 0.0038 | 0.0018 | 0.0025 | 9388 | 0.37 | 57 |
| honk | trojan | 0.0053 | 0.0014 | 0.0055 | 9366 | 0.42 | 49 |
| honk | anytls-sb | 0.0052 | 0.0020 | 0.0031 | 4954¹ | – | 58 |
| honk | anytls-go | 0.0126 | 0.0035 | 0.0046 | 9272¹ | – | 55 |
| dae | direct | 故障² | – | – | – | – | – |
| dae | hy2 | 0.0109 | 0.0030 | 0.0043 | 2996 | 0.75 | 62 |
| dae | tuic | 0.0852 | 0.0797 | 0.0809 | 3920 | 0.84 | 64 |
| dae | ss2022 | 0.0063 | 0.0040 | 0.0042 | 9396 | 0.49 | 52 |
| dae | trojan | 0.0093 | 0.0084 | 0.0107 | 9370 | 0.66 | 57 |
| dae | anytls-sb | 0.0088 | 0.0014 | 0.0023 | 9155 | 0.60 | 58 |
| dae | anytls-go | 0.0044 | 0.0017 | 0.0021 | 9379 | 0.62 | 59 |
| sing-box | direct | 0.0044 | – | – | 9410 | 0.41 | 47 |
| sing-box | hy2 | 0.0143 | 0.0014 | 0.0018 | 2930 | 0.88 | 52 |
| sing-box | tuic | 0.0102 | 0.0029 | 0.0048 | 2808 | 0.86 | 50 |
| sing-box | ss2022 | 0.0042 | 0.0040 | 0.0056 | 9390 | 1.19 | 49 |
| sing-box | trojan | 0.0112 | 0.0068 | 0.0104 | 9368 | 0.78 | 47 |
| sing-box | anytls-sb | 0.0113 | 0.0035 | 0.0041 | 5996 | 0.59 | 49 |
| sing-box | anytls-go | 0.0129 | 0.0023 | 0.0028 | 9252 | 0.95 | 46 |

dae 各行为 **kdae 分支构建**(`2a007b39`,`unstable-20260729.r987`,
在压测机上从 `../dae` 构建)——第一个支持 AnyTLS 的 dae 构建。
sing-box 各行为 **1.13.14**,以 TUN 客户端身份跑在 lab netns **内部**
(`bench/sb-client.json` 部署到引擎机;按端口的路由规则与引擎配置一致,
outbound 绑定 `veth-client`)。

¹ honk 的 anytls 两行有一段历史:单流 iperf3 曾只有 2–3 Mbps。根因在
honk 自身——单流 demux 队列满(64 帧)会**立即**杀流,单流测试中服务器
的初始飞行快过新建 relay 任务,22ms 就触发杀流;随后服务器继续向池化
会话灌死 sid 的 PSH 垃圾帧。上表实测使用第一版有界 HOL 修复,即最多
等待 5s 再杀。当前路径不等待:按流分桶并设置 512 帧、每流 2 MiB、每会话
8 MiB 的硬上限;触及上限时,已接纳数据排空后立即只 reset 肇事流。
历史实测中 anytls-go 与 dae 持平;anytls-sb 落后(sing-box 服务端的帧模式
dae 容忍得更好——后续工作)。

² dae 的 direct 路径在本实验室内核上故障(kdae 构建):direct 流超时,
代理流正常。上表 dae 各协议行有效;无 dae direct 基线。

### UDP 结果(iperf3 `-u -b 10G -l 1200 -R` + echo RTT)

同一轮 A/B。供给速率固定 10 Gbps——远超任何隧道的承载,所以丢包列
反映的是饱和而不是质量;接收端带宽才是容量数字。数据报长度固定
1200B:QUIC datagram 上限就在那附近(honk hy2/tuic 会丢超限数据报
——iperf3 按路径 MTU 的默认 ~1448B 测到的是上限而不是隧道)。
echo RTT 为每协议路由 echo 端口(53531–53536)15 次 ping 的中位数。

| 引擎 | 协议 | echo RTT p50 | 带宽 Mbps(丢包) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.37 ms | 1738 (73.1%) | 1.30 |
| honk | tuic | 0.38 ms | 293 (54.3%) | 0.22 |
| honk | ss2022 | 0.11 ms | 1158 (52.4%) | 0.81 |
| honk | trojan | 0.21 ms | 1506 (77.3%) | 1.26 |
| honk | anytls-sb | 0.12 ms | 1148 (82.2%) | 0.80 |
| honk | anytls-go | 0.10 ms | 1519 (76.6%) | 1.11 |
| dae | hy2 | 0.14 ms | 932 (85.9%) | 0.96 |
| dae | tuic | 0.13 ms | 9 (75.8%) | 0.03 |
| dae | ss2022 | 0.10 ms | 2668 (53.1%) | 1.76 |
| dae | trojan | 0.13 ms | 2957 (49.2%) | 1.67 |
| dae | anytls-sb | 0.10 ms | 1208 (80.7%) | 0.78 |
| dae | anytls-go | 0.19 ms | 1561 (75.2%) | 0.99 |
| sing-box | hy2 | 0.20 ms | 1372 (75.2%) | 1.18 |
| sing-box | tuic | 0.15 ms | 16 (63.4%) | 0.04 |
| sing-box | ss2022 | 0.07 ms | 2730 (53.0%) | 1.35 |
| sing-box | trojan | 0.07 ms | 3380 (45.5%) | 1.56 |
| sing-box | anytls-sb | 0.09 ms | 1244 (79.3%) | 1.12 |
| sing-box | anytls-go | 0.13 ms | 1447 (76.9%) | 1.21 |

- **hy2 UDP**:honk 领先(1738 vs 932 / 1372),三家都约 1 核。
- **TUIC UDP** 三家都弱(293 / 9 / 16 Mbps)——QUIC-datagram TUIC 在
  本实验室是协议级短板,honk 是其中最好的。
- **UDP-over-TCP 隧道**(ss2022、trojan):dae/sing-box 领先
  (2.7–3.4 Gbps vs honk 1.1–1.5)。honk 的 UDP endpoint/分帧路径是
  当前瓶颈——anytls-sb 之后的下一个优化目标。
- **anytls UoT**:三方持平,约 1.1–1.5 Gbps。
- echo RTT 全部亚毫秒,没有协议是延迟受限的。

### 结果解读

- **带宽**:honk 全面领先或打平。hy2 5239(+75% vs dae、+79% vs
  sing-box)、tuic 5351(+36% / +90%)、trojan 和 ss2022 与两家同为
  线速、anytls-go 9272(三方持平)。唯一剩余的差距是对 sing-box
  服务端的 anytls:honk 4954 vs dae 9155 / sing-box 5996。ss2022 靠
  BoringSSL AEAD 替换达成线速:RustCrypto aes-gcm 实测 0.4–0.5 GB/s
  (AES-NI 路径未启用)vs BoringSSL 3.3–6.7 GB/s(`benches/ss_aead.rs`),
  替换把该行从 5339 Mbps / 1.01 核提到 9388 / 0.37 核——CPU 也反超
  dae(0.37 vs 0.49)。
- **每核带宽**:honk 在每一行线速协议上效率最高——trojan 0.42 核
  (dae 0.66、sing-box 0.78),ss2022 0.37 核(dae 0.49、sing-box
  1.19)。QUIC 协议 honk 用 ~1.06 核跑 5.2+ Gbps;dae/sing-box 要
  0.75–0.88 核跑 2.8–3.9 Gbps。
- **延迟**:TUIC 仍是极端案例——热开流 3.8 ms vs dae 79.7 ms(honk 有
  进程级 TLS 1.3 票据缓存,dae 每条连接完整 QUIC 握手;冷启动同样,
  2.4 vs 85.2 ms)。其他行在几 ms 内互有胜负。
- **内存**:honk 的 musl 构建用 mimalloc,它会保留回收的内存
  arena——RSS 49–66 MB,与 dae(52–64 MB)持平。这是刻意的交换:
  mimalloc 比 musl 原生 malloc 带来约 +50% 的 QUIC 吞吐(A/B:5096 vs
  3037 Mbps),代价是约 40 MB 驻留内存。

### 更早的结果(软件加密实验室,AES-NI 之前)

引擎 VM 换 host 透传 CPU 之前,QUIC 数字对两个引擎都受限于软件加密:
honk hy2/tuic 2289/2383 Mbps vs dae(kdae)2511/2669,honk 的 BoringSSL
卡在 `nohw` C 版 ChaCha20(占引擎 CPU 34%)。那些行已被上表取代。
QUIC socket 缓冲修复(8 MiB SO_RCVBUF/SO_SNDBUF + rmem_max/wmem_max
提到 16 MiB)和 8/32 MiB 接收窗口默认值先于两张表,对两者都适用。

## DNS 微基准(criterion)

`cargo bench -p honk-core --bench dns`——纯 loopback,不需要外部网络。
最近一次结果(2026-07-30,x86_64):

| 基准 | 均值 |
| --- | --- |
| endpoint 解析(udp/dot/doh/doq/h3) | 70–97 ns |
| 缓存 get(命中) | 60 ns |
| 缓存 put | 133 ns |
| 缓存 90% 读 / 10% 写混合 | 32 ns |
| 路由匹配(每查询规则求值) | 29–79 ns |
| force/restore txid | 1.4 ns |
| 构造 A 查询 | 114 ns |
| forwarder resolve(缓存命中) | 283 ns |
| TCP 池 exchange(连接复用) | 18 µs |
| UDP 上游 exchange | 19 µs |
| 长度前缀 framing(duplex) | 6 µs |

单查询总成本(路由 + 缓存命中)远低于 1 µs;上游 exchange 符合 loopback RTT
量级。基准代码在 `crates/honk-core/benches/dns.rs`;mock server 必须开
nodelay——否则 Nagle + delayed-ACK 会给每次 TCP exchange 加约 40 ms,
测出来的是操作系统而不是代码。

`cargo bench -p honk-outbound --bench ss_aead` 对比 AEAD 后端在 SS 分块
尺寸下的吞吐(RustCrypto aes-gcm 0.4–0.5 GB/s vs BoringSSL AeadCtx
3.3–6.7 GB/s,AES-NI 硬件——SS 数据面用 BoringSSL 的原因)。

## Candidate UDP 微基准（绝对值，不是 A/B）

UDP Criterion suite 只记录 candidate 的绝对行为。固定调用为：

```bash
cd /root/code/honk-feat-udp-to-1
CARGO_TARGET_DIR=/root/code/honk/target cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate
```

| Case | 固定工作量 |
| --- | --- |
| steady enqueue | 一个 Ready flow 上 1,000,000 次 128-byte `fast_path_enqueue`，每次立即 drain 以保持 steady state |
| reserve / rollback | 10,000 次 endpoint reservation 后 rollback |
| histogram | 1,000,000 次 record/snapshot operation |
| queue saturation | 先接纳 64 个 datagram，再丢弃一个最新 datagram |

记录 candidate 的 Criterion mean、median、MAD 与绝对吞吐。`udp-candidate`
只是重复运行标签，不是与 `be587b1` 的比较：该 revision 没有可用于有效 A/B
的 source-level 等价接口。Criterion 也不提供 merge gate 的 p95 estimate；不得
从该 suite 推断 p95。

## Deployment UDP A/B gate

`bench/udp-latency.sh` 是真实部署驱动，而非 CI 替代品。它要求两个 binary 使用
相同的 TPROXY topology 与真实 upstream。固定调用为：

```bash
sudo bench/udp-latency.sh \
  --baseline-bin /opt/honk/be587b1/honk-core \
  --candidate-bin /opt/honk/udp-to-1/honk-core \
  --config /etc/honk/bench.dae \
  --echo-target 10.0.2.2:9000 \
  --dns-target 10.0.2.2:53 \
  --samples 10000 --runs 5 --offered-rate 5000
```

该固定调用刻意不传 timeout 或 hook flag。请在 root 环境配置
`HONK_UDP_TIMEOUT_SEC`（默认 `30`）以及
`HONK_UDP_{START,READY,SETUP,PROBE,STATS,TEARDOWN,TOPOLOGY}_HOOK`；CLI flag
可覆盖这些值。使用 `sudo` 时，须以 `--preserve-env` 保留这些变量，或在 root
环境中配置它们。driver 不提供 built-in topology；缺少 live hook 会 fail closed。

每个 executable hook 都通过 `env` 运行，不会把 shell snippet `eval`。它会获得
`variant`、`case`、`run`、`workdir`、`pid`、`pgid`、`selected_bin`、
`baseline_bin`、`candidate_bin`、`config`、`echo_target`、`dns_target`、
`samples`、`offered_rate` 与 `timeout`；`start` 和 `topology` 的 `pid`/`pgid`
为空。`start` 必须先完成同步 setup，再执行 `exec "$selected_bin" ...`；driver
会把所选文件的 device/inode 与 `/proc/$pid/exe` 核对，并在 ready、setup、probe、
stats 后重新验证同一 PID/session/start-time/executable。只有 teardown 完成且在
bounded wait 内确认所属 process group 已消失后才输出 row；残留 descendant 会
fail closed。旧 positional arguments 仍兼容。target 可为 IPv4、`[IPv6]` 或
带端口的合法 hostname。`probe` 必须报告 `sent == samples`。

它为每个 case/run 输出一个 JSONL object，顶层字段严格为：`schema_version`、
`variant`、`commit`、`binary_sha256`、`kernel`、`topology`、`case`、`run`、
`samples`、`offered_rate`、`sent`、`received`、`latency_unit`、`p50`、`p95`、
`p99`、`max`、`loss`、`cpu_pct`、`rss_kib`、`fd_count`、`queue_drops` 与
`warm_hit`。`schema_version` 为 `1`；延迟 quantile 的单位为 microseconds；
`loss` 为 sample loss ratio，`cpu_pct` 为进程 CPU usage，`rss_kib` 为 KiB 的
resident memory，`fd_count` 为打开的 file-descriptor count。固定 case 为
`cold_endpoint`、`steady_hit`、`warm_session_cold_endpoint`、`dns_hit`、
`dns_miss`、`healthy_candidate` 与 `blackholed_candidate`。driver interface 与
JSONL shape 由 `bash bench/tests/udp-latency-cli.sh` 检查。

部署 gate 在相同 topology 与 offered rate 下比较五轮各 10,000 sample：healthy
cold 的 p50/p95 回退最多 5%；首个 candidate 被 blackhole 时 p95 至少改善 20%、
p99 至少改善 30%；steady path 在目标吞吐 70% 以下须保持 p99 至多 250 microseconds
且零 drop；AnyTLS warm hit 须达 80%，且 first reply 减少一个 RTT 或至少 20%；
steady CPU 与 p50 回退最多 5%；IPv4/IPv6 client-observed reply tuple 必须不变。
**本地 worktree 未运行 deployment gate，因此不声称达到任何网络延迟 gate。**

## Release profile 与 allocator 矩阵

`bench/release-matrix.sh` 对比显式的 `release-size`、
`release-size-thin`、`release-speed` 与 `release-speed-thin` profile，并配对
三种 allocator arm：关闭 collect 的 mimalloc、60 秒 collect 的 mimalloc，以及
系统 allocator。每个 cell 使用隔离的 Cargo、workload cache 与 run 目录，并输出
machine metadata、JSONL/CSV build 和 performance 记录。

不编译即可验证全部四种受支持 target 配置：

```bash
bench/release-matrix.sh --all-targets --dry-run --output /tmp/honk-release-matrix
```

主机实测需要提供可执行的 `--benchmark-hook`；其 RSS/PSS/fault/CPU/throughput/
latency 字段契约可由 `bench/release-matrix.sh --help` 查看。完整矩阵期间必须把
所有 CPU policy 固定到同一 governor，并保持 turbo 状态不变；`machine.json` 会记录两项
设置。只能在同一机器和 workload 下比较 cell。该矩阵记录证据；没有部署吞吐
与尾延迟结果时，不据此切换发布 profile。

profile 晋级采用显式门禁，不能只看二进制尺寸。以 `release-size` 为基线，同一
实验室的五轮配对结果中，candidate 的每项吞吐回退不得超过 3%、每项 p99
延迟回退不得超过 5%、RSS 增幅不得超过 20%。三个门禁全部通过前，发布默认
保持尺寸版。

2026-08-02 完成了一轮初步配对部署：x86_64 musl、mimalloc、60 秒 collect，
对比 `release-size` 与 `release-speed`。每个协议执行三轮 8 秒反向吞吐；
warm-up 后另测 200 次请求的尾延迟。

| profile | 二进制 | direct | hy2 | tuic | 最大 RSS | hy2 p99 | tuic p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| release-size | 19.50 MB | 9.407 Gbps | 2.756 Gbps | 4.253 Gbps | 56 MB | 5.426 ms | 4.705 ms |
| release-speed | 24.79 MB | 9.388 Gbps | 3.314 Gbps | 5.152 Gbps | 59 MB | 3.409 ms | 3.136 ms |

速度版没有吞吐或 p99 回退，最大 RSS 增加 5.4%，因此这一个样本通过数值门禁。
但单轮配对尚未满足五轮证据要求，且二进制增大 27.2%，所以不执行晋级，
`release-size` 继续作为默认。

## 生产备注(10.10.10.1 网关)

- 每次部署后 TCP(google/baidu/cloudflare)与 HTTP/3(cloudflare)通过;
  网关日志干净。
- HTTP/3 停顿突发(首字节快、正文停约 14s)以分钟级波动出现,与订阅 UDP
  线路质量相关而非引擎构建——相邻构建的 A/B 部署在同一小时内两种结果都
  出现过。客户端 qlog 显示约 12% 的 datagram 被先判丢后到(延迟假象,非
  内核/socket 丢包)。
- 每次部署后跑 60 分钟 canary,采样 FD / established / CLOSE-WAIT /
  warn 速率;Ready 池指标(`/stats` → `pool`:hits、misses、entries)
  以同样节奏检查。

## 回归门禁

- `just outbound-ci`——fmt、clippy、honk-config + honk-outbound 测试套件。
- `just clash-ci`——fmt、clippy、clash_api_test + integration_test。
- `just dns-ci`——DNS 子系统门禁。
- `cargo bench -p honk-core --bench dns`——DNS 微基准(见上)。
- `cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate`——仅 candidate 的绝对 UDP 测量；不是历史 A/B 或 p95 merge gate。
- `bash bench/tests/udp-latency-cli.sh`——deployment driver 的 CLI/JSONL fixture；上文真实 UDP A/B gate 仍需要 TPROXY 与 upstream。
- `bash bench/tests/runtime-memory-cli.sh`——配对 runtime-memory driver 的 CLI、顺序、identity 与 fail-closed JSONL fixture。
- 发布 CI(`.github/workflows/release.yml`)——workspace 测试门禁 +
  四目标构建(x86_64/aarch64 × gnu/musl)+ BTF 检查 + tarballs。
