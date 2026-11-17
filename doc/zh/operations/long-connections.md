# 长连接与 keepalive

honk 不会合成应用保活包。传输载体保持打开，不等于其中每条 UDP 流都保持存活。

## UDP：回复维持 endpoint 存活

Endpoint 在 **120 s 没有回复**后退役；成功发送与 carrier keepalive 不重置该计时器。纯上行流即使持续发送也会到期，之后的数据包在准入允许时可创建新 endpoint；旧包不重放。从未回复的流按超时结算 Score；成功交付过回复后，后续空闲退役不影响健康，并按成功结算 Score。

普通 endpoint 每次无回复到期都计为一次 `DataUdp` 健康失败。节点的 60 s 注册宽限期结束后，连续 50 次计入统计的失败会使其在对应探测域/地址族上不可用。同一键上的回复交付或探测成功重置连续计数，仅发送成功不重置。共享 UDP association 只有发送过数据且从未收到回复，才上报一次无回复健康失败：其他目的地已回复后，没有回复的 view 仍可到期并按超时结算 Score，但不会使整个 source 降级或退役。见[健康与 Score](../design/groups.md)。

内核状态有独立的 [UDP 空闲续期规则](../design/datapath.md#udp-生存期续期)；内核条目尚未过期，不会阻止用户态回复空闲计时到期。用户态不会为静默内核条目续期；内核状态回收也会退役所属 endpoint，之后的数据包需要新建 endpoint。传输 keepalive 不配置外部 NAT/conntrack。

达到进程级 **32,768 个 endpoint 硬上限**（两个地址族合计），或更低的启动描述符或内存预算（`MemTotal` 的四分之一，每个 endpoint 按 64 KiB 计，2 GiB 为 8,192）时，新映射丢弃；不淘汰已有映射，也不排队保留被拒数据报。NFQUEUE 原包同样丢弃。检查经过鉴权的 Clash `GET /stats` 中的 `udp.capacity.rejected`；只有描述符是较小限制时，提高服务 `RLIMIT_NOFILE` 才有效。[慢路径/队列预算](../design/control-plane.md#queue-与描述符预算)可能更早拒绝工作。

## TCP：空闲不是中继期限

已建立中继没有通用的用户态空闲超时；`global.relay_idle_timeout_secs` 无效。已接受中继在存活期间保留其内核记录。首次 EOF 后，剩余方向只在 **30 s 没有字节进展**后结束；连接/嗅探/握手期限只作用于建立阶段。

Linux TCP keepalive 在面向客户端的透明 socket 上为 **空闲 3600 s / 间隔 15 s / 4 次探测**，在出站 dial 与 TCP carrier 上为 **15 s / 10 s / 3 次探测**。在线空闲对端可持续应答；探测只证明传输可达，不证明应用进展。见 [TCP 中继所有权](../design/control-plane.md#tcp-中继与-conn-state-所有权)。

## Carrier keepalive

H2/gRPC（含 VLESS H2MUX、XHTTP 与 DNS-over-HTTPS H2）不发送周期性 HTTP/2 PING，依赖实际流量与 TCP keepalive。TCP 健康不保证远端应用会话可用。

QUIC keepalive 间隔：Hysteria2/TUIC 为 **10 s**，Juicity 为 **5 s**，DNS-over-QUIC/HTTP3 为 **15 s**。TUIC datagram 模式还按同一间隔发送 heartbeat；UDP-over-stream 只用 QUIC keepalive。

Hysteria2/TUIC/Juicity 在本地未使用连接空闲 120 s 后回收，不切断仍有活跃逻辑使用者的连接。对端协商的 QUIC 空闲超时与远端应用策略相互独立。QUIC PING 与 TUIC heartbeat 不等于被封装 UDP 流的回复。

## 检查项

- 检查最后一次应用回复与终态结果，不只看上传计数或传输载体活性。
- 区分计时器到期、[出站健康门控](../design/datapath.md#出站存活状态)与容量拒绝。
- 单独检查外部防火墙/NAT 与远端应用的空闲策略。

## 采集 Native publication 证据

调查 Native policy/DNS/mode 发布或 runtime maintenance 期间的中断时，使用预期的 [Native publication 产物契约](../reference/api.md#native-publication-产物)。本次实现交接中，本流程及 exporter/consumer、故障注入、真实 hook 检查均为 **NOT_RUN**。在绑定实际 build 的证据证明之前，保留原有 timeout/failure 判定。

1. 在 attempt 前保留公布精确 `<data_dir>/state/native-publication/<pid>-<starttime_ticks>-<publication_serial>.json` 路径的 structured startup/readiness 输出。复制初始 `final=false` manifest，将 boot ID、PID/starttime、publication serial 和 root map 身份绑定到本次运行。另行保留 executable hash、source/build/object receipt 和 attached program/map 身份；自报 build version 不能认证二进制。Manifest/path 缺失或记录初始化失败属于前提缺失，不能当成零转换。
2. 保留本地 `CLOCK_BOOTTIME`/`CLOCK_MONOTONIC` 的 attempt 与 shutdown 时间区间，以及有界 peer-clock 关联。Suspend、跨主机误差、capture loss 和 peer snapshot 缺失必须显式保留。不能由时间重叠推断某个丢包，也不能把 hook 计数相加当成去重包数。
3. 移除 custody 前先停止流量源。请求正常 daemon shutdown，保留完整 structured result，**包括 Err 结果**。在 map/journal owner 仍存活时，等待真实 terminal closure、卸载引用 counter 的 hook 或替换为无引用 guard、join/drain 加 reader grace、counter 封存与 final export 完成。最后 writer commit、link FD 关闭、`honk-core stopped` 日志或 pin 存活都不足以证明 join。
4. 在 namespace/pin/artifact teardown 或下一次运行前，复制发现路径的产物并计算 hash，将 structured shutdown result 持久保留并绑定同一 publication 身份/路径。发布成功时验证 result 的 streaming digest 与采集字节一致，将 digest 与副本一同保留。同时保留 shutdown 原错误及独立 export 错误；可达 failed-retained 路径必须在 forget owner 前尝试不完整部分导出。Failed-retained custody 仍遵循既有精确 owner 清理流程。
5. 完整证据必须有匹配的 `export_publication_result=PUBLISHED_DURABLE`。`NOT_PUBLISHED` 留下初始不完整 manifest；`PUBLISHED_DURABILITY_UNKNOWN` 表示 rename 成功但目录 sync 失败，可见替换 JSON 可能已含 `final=true`。拒绝未知持久性、结果缺失/未绑定/矛盾或 digest 不匹配。即使结果为 `PUBLISHED_DURABLE`，仍须 `final=true`、`hooks_joined=true`、collection end 晚于工作、身份完整、event 匹配、所有 covered hook/epoch 已封存、seq 连续为 `1..last_seq`、`total_appended=last_seq=count(events)`、`first_retained_seq=1`、`overwritten_events=0`，且无 recording/clock/accounting/overflow 故障。保留十进制字符串，不经浮点数转换。

4,096 条 ring 可能淘汰早期历史，不保证固定保留秒数。连续后缀或 provisional 计数不能满足整次运行完整性。Crash/SIGKILL/断电可能只留下初始 manifest，或可见 terminal JSON 却无匹配持久结果；不承诺 crash 后存活的连续 journal。将这些观测标为 incomplete。即使完整产物也仅证明已记录的转换顺序和封存后的精确 closed 分支 hook 执行次数：零不证明流量到达 hook，计数不证明 socket custody、应用交付、没有其他丢弃或超时原因。

