# honk

[English](./README.md) | [中文](./README_CN.md)

---

<a id="chinese"></a>

## honk 是什么？

**honk** 是面向 Linux 的 Rust 透明代理引擎，其 eBPF 数据面与配置形态受 [dae](https://github.com/daeuniverse/dae) 启发，出站组、多协议拨号器和 Clash 兼容 API 则受 [sing-box](https://github.com/SagerNet/sing-box) 启发。

它**不是**任一项目的逐行移植。内核路径遵循 dae 的 TC + match_set + `dae0`/`daens` 模型，用户态出站与控制栈则采用面向 sing-box 的设计。该项目结合了 dae 的数据面模型与受 sing-box 启发的用户态行为。

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

## VLESS UDP、H2MUX 与 XUDP

VLESS 分享链接通过 `vless_mode=legacy|uot-v2|h2mux|h2mux-padded|xudp|mux-cool` 选择一个明确模式。`legacy` 是向后兼容的 TCP-only 默认值。`uot-v2` 保留该 TCP 路径，并为 UDP 增加直连 UoT v2。`h2mux` 在共享 HTTP/2 carrier 上承载逻辑 TCP 与原生 connected sing-mux UDP；`h2mux-padded` 再增加 sing-mux v1 padding。`xudp` 保留普通 VLESS TCP，并为每个 UDP transport 打开一条 Single XUDP carrier。`mux-cool` 让逻辑 TCP 与 XUDP 共用节点所有的 Xray Mux.Cool carrier。

这些模式不协商，绝不降级或重放 UDP 首包。非 legacy 模式不能使用 VLESS Encryption；只有 `xudp` 可与 `flow=xtls-rprx-vision` 组合。官方互通套件覆盖 sing-box 与 Xray：全部六种明文模式、TLS 和 REALITY 上的 H2MUX、padding，以及 XUDP Vision。wire、生命周期和导入规则见[节点参考](doc/zh/reference/nodes.md#mode)。

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
- [ ] 添加 inbound 支持
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
