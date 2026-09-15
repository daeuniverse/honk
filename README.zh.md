# honk

[English](./README.md) | 中文

---

<a id="chinese"></a>

## honk 是什么？

**honk** 是面向 Linux 的 Rust 透明代理引擎，其 eBPF 数据面与配置形态受 [dae](https://github.com/daeuniverse/dae) 启发，出站组、多协议拨号器和 Clash 兼容 API 则受 [sing-box](https://github.com/SagerNet/sing-box) 启发。

它**不是**任一项目的逐行移植。报文路径保留 dae 的 TC + `dae0`/`daens` 模型；唯一的用户态路由 IR 在 Linux 6.12+ 上编译为按代管理的 BPF 策略函数。出站与控制栈采用面向 sing-box 的设计。

> **状态：实验版本（`v0.0.1-alpha`）。** honk 处于早期 alpha 阶段。接口可能发生破坏性变更，部分功能尚未完成（见 TODO），真实环境验证也仍然有限。不建议用于生产环境。

许可证：**GPL-3.0-only**。

可靠性优先的 Score 组策略始终随程序编译，并通过 `policy: score` 显式选择；省略 policy 时仍默认使用 Selector。Score 只在进程内存中从真实流量以及 DNS、真实 QUIC 握手、探测、delay test、预热和直连或经代理的 UI 下载中学习。经鉴权的 `GET /stats` 只导出按组汇总的安全选路原因计数；scorer cell、目标键和其他私有 scorer 数据绝不会写入日志、持久化或导出。详见[组参考](doc/zh/reference/groups.md#score-策略)。

## 实验性首包保留 UDP 决策

UDP NFQUEUE 路径默认开启。它只保留已经过 LAN TC、尚未进入 conntrack/NAT，且仍有歧义的 **LAN 转发**首包。通过进程配置关闭：

```dae
global {
    nfqueue_enable: false
}
```

修改 `global.nfqueue_enable` 后必须重启。若使用 `--mock-ebpf`、不带 `ebpf` 的构建，或固定队列不可用，honk 会记录 warning，并仅在本进程禁用 NFQUEUE 暂存；它不会改写配置文件。真实启动会先等待单实例交接，再探测队列，并在安装阶段回收保留的 nftables table。本机发起的 WAN 出口流量仍走规范 TPROXY 路径。DNS 端口 53、`must`、`block` 和已经可以安全地在路由时直连的决策不会进入 NFQUEUE；只暂存仍可能在用户态改变的决策。

该路径拥有 raw-netlink 队列 `320` 和 nftables 对象 `inet honk_nfqueue` / `udp_decision`；honk 运行期间，同一网络命名空间中的防火墙管理器必须保持这些对象不变。Direct 释放被保留的 skb，proxy 把一份保留的 payload 提交给正常 UDP 初始化器，block/取消则丢弃报文。ingest actor 最多保留 256 个报文和 8 MiB payload；每个报文从 listener 收到时起都保留固定的三秒绝对期限。启用 Clash API 后，`/stats.udp.nfqueue` 会暴露 actor 深度、字节数、最老年龄，以及明确的内核统计可用状态和读取失败数。完整不变量与指标 schema 见 [NFQUEUE 设计](doc/zh/design/nfqueue.md)和 [API 参考](doc/zh/reference/api.md)。

## VLESS UDP 与多路复用

VLESS 现由三个独立选项组合：`udp=0|1` 控制 packet 权限，`packetEncoding=auto|none|xudp|uot-v2` 选择非复用 UDP 回退路径，`mux=off|h2mux|xray` 选择 carrier 多路复用。规范链接默认允许 UDP、使用 `packetEncoding=auto` 和 `mux=off`；例如 `vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&packetEncoding=auto&mux=off&udp=1#edge`。未启用 Vision 时，Auto 对 53/443 使用原生 VLESS UDP；其他获准目标使用 Single XUDP。

Vision 始终禁止 TCP 多路复用，但允许仅 UDP 的 Xray mux。基础 Vision 会在协议回退路径拒绝 UDP/443；实际 Xray UDP mux 只有 `allow` 策略能绕过该门槛。VLESS Encryption 可在 direct-TCP 与合法 XUDP/关闭 UDP 的路径规则下和 Vision 组合。Carrier 容量来自进程级文件描述符预算；容量耗尽属于本地且不影响健康的拒绝，不会触发回退或 packet 重放。XUDP Global ID 使用有作用域的所有权边界，不具备进程级无碰撞 NAT 语义。规范链接、迁移、组合及 REALITY 握手/pool 行为见[节点参考](doc/zh/reference/nodes.md#vless-udp-and-multiplexing)，生命周期及所有权见规范的 [VLESS 出站设计](doc/zh/design/outbound.md#sourcesession-ownership-and-capacity)。

**升级注意：**`vless_mode` 已删除，所有 VLESS 节点 ID 都会重新派生。升级前请迁移静态链接与缓存/provider 内容，尤其是离线升级。按名称保存的 Selector 选择及近期持久化延迟样本可继续使用，不要删除它们。见[迁移说明](doc/zh/reference/nodes.md#从-vless_mode-迁移)。

## 使用本仓库前

### 重要：Review 状态

以下复选框表示维护者 review 状态，而非功能是否可用：

- [x] eBPF 路由、map 与语义
- [x] 控制面
- [x] AnyTLS / Shadowsocks（含 2022）/ SOCKS5
- [ ] RPRX（VLESS / XTLS / XHTTP / WSS / REALITY）
- [ ] Trojan-GFW（需要 UoT 实现）
- [x] DNS 逻辑
- [ ] 配置解析器（dae 扩展）
- [ ] 重载逻辑
- [x] 工具

### TODO

- [x] 添加始终编译的 Score 组策略
- [x] 通过出站 `PacketTransport` 上的 quinn `AsyncUdpSocket` adapter 添加代理 DoQ/DoH3
- [ ] 评估 AF_XDP 与 XDP 路径以进一步提升性能
- [ ] 添加 honk REST API
- [ ] 添加入站支持
- [ ] 通过 GitHub [Issues](https://github.com/Glassyiris/honk/issues) 和 [Discussions](https://github.com/Glassyiris/honk/discussions) 跟踪其他工作

> 在所有当前尚未 review 的代码完成 review，并处理所有未经验证的 AI 生成实现前，不会发布 `test.1` release tag。

## 致谢

- [dae](https://github.com/daeuniverse/dae) / [daed-rs](https://github.com/daeuniverse/daed-rs) — eBPF 透明代理谱系
- [sing-box](https://github.com/SagerNet/sing-box) — 出站组与 Clash API 模式
- [daeuniverse/outbound](https://github.com/daeuniverse/outbound) — 协议参考
- [juicity-rs](https://github.com/juicity/juicity-rs)（Markson Pigeonzilla Plus）— Juicity 协议实现参考；honk 的 Juicity 出站 wire 格式对齐与真实互通测试均以该项目为基准
- [aya-rs](https://github.com/aya-rs/aya) — Rust eBPF

## 许可证

```text
SPDX-License-Identifier: GPL-3.0-only
Copyright (c) 2025, glassyiris <honk@catmint.cc> and honk contributors
```
