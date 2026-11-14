# 长连接与 keepalive

honk 不自行生成应用层保活报文。carrier 保持打开，不代表它承载的每条 UDP 流都还存活。

## UDP：回复维持 endpoint 存活

endpoint 连续 120 s 没有回复就退役。成功发送和 carrier keepalive 都不会重置这个计时器，所以纯上行流即使一直在发数据也会到期。到期后，后续数据包在 admission 允许时会新建 endpoint，旧数据包不会重放。从未收到回复的流按超时结算 Score；成功交付过回复的流，之后因空闲退役不影响健康，仍按成功结算 Score。

每个普通 endpoint 因没有回复而到期，都计一次 `DataUdp` 健康失败。节点的 60 s 注册宽限期结束后，连续 50 次被计入统计的失败，会让该节点在那个探测域和地址族上不可用。同一 key 收到回复或探测成功会清零连续计数，单靠成功发送不会清零。共享 UDP association 只在发送过数据、且从未收到任何回复时，才上报一次无回复健康失败。其他目的地收到过回复后，仍无回复的 view 可以到期并按超时结算 Score，但不会让整个 source 降级或退役。见[健康与 Score](../design/groups.md)。

内核状态另有独立的 [UDP 空闲续期规则](../design/datapath.md#udp-生存期续期)。内核条目还没过期，不会阻止用户态的回复空闲计时到期；用户态也不会替静默的内核条目续期。内核状态被回收时，所属 endpoint 一并退役，之后的数据包需要新建 endpoint。transport keepalive 不会配置外部 NAT/conntrack 状态。

honk 在达到下列任一上限时丢弃新映射：进程级 32,768 个 endpoint，两个地址族合计；启动时的描述符预算；内存预算，即 `MemTotal` 的四分之一，每个 endpoint 按 64 KiB 计，2 GiB 时为 8,192。honk 不淘汰已有映射，也不排队保留被拒绝的数据报，NFQUEUE 里的原始数据包同样丢弃。被拒绝的次数见经过认证的 Clash `GET /stats` 中的 `udp.capacity.rejected`。只有描述符是较小的那个限制时，提高服务的 `RLIMIT_NOFILE` 才有效。[慢路径/队列预算](../design/control-plane.md#queue-与描述符预算)可能更早拒绝工作。

## TCP：空闲不是中继期限

已建立的中继没有通用的用户态空闲超时，`global.relay_idle_timeout_secs` 不起作用。已接受的中继只要仍存活，就保留它的内核记录。首次 EOF 后，剩余方向要连续 30 s 没有字节进展才结束；连接、嗅探与握手期限只作用于建立阶段。

Linux TCP keepalive 在面向客户端的透明 socket 上取空闲 3600 s、间隔 15 s、4 次探测，在出站 dial 和 TCP carrier 上取 15 s、10 s、3 次探测。在线的空闲对端可以一直应答；探测只证明传输可达，不证明应用层有进展。见 [TCP 中继所有权](../design/control-plane.md#tcp-中继与-conn-state-所有权)。

## Carrier keepalive

H2/gRPC 不发周期性 HTTP/2 PING，包括 VLESS H2MUX、XHTTP 和 DNS-over-HTTPS H2，只依赖实际流量和 TCP keepalive。TCP 连接健康，并不代表远端应用的 session 可用。

QUIC keepalive 间隔：Hysteria2/TUIC 为 10 s，Juicity 为 5 s，DNS-over-QUIC/HTTP3 为 15 s。TUIC datagram 模式按同一间隔发送 heartbeat；UDP-over-stream 只用 QUIC keepalive。

Hysteria2/TUIC/Juicity 在连接本地空闲 120 s 后回收，有活跃逻辑使用者的连接不会被切断。对端协商的 QUIC 空闲超时和远端应用策略各自独立。QUIC PING 和 TUIC heartbeat 都不算被封装 UDP 流的回复。

## 检查项

- 查看最后一次应用回复和终态结果，不要只看上传计数或 carrier 是否存活。
- 分清计时器到期、[出站健康门控](../design/datapath.md#出站存活状态)和容量拒绝。
- 外部防火墙/NAT 和远端应用的空闲策略要单独检查。
