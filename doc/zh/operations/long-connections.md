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
