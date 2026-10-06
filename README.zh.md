# honk

[English](./README.md) | 中文

<a id="chinese"></a>

honk 是用 Rust 编写的实验性 Linux 透明代理引擎。其 eBPF 数据面和配置语法受 [dae](https://github.com/daeuniverse/dae) 启发；出站组、多协议拨号器和 Clash 兼容 API 沿用 [sing-box](https://github.com/SagerNet/sing-box) 的设计思路。honk 是独立实现，并非任一项目的逐行移植。

> **早期 alpha（`v0.0.1-alpha`），不建议用于生产。** 可能发生破坏性变更，部分功能尚未完成，真实环境验证仍然有限。

## 功能概览

- 透明 TCP/UDP：通过 TC eBPF、`dae0`/`daens` 和 Linux 6.12+ 上的编译路由处理 LAN 转发及本机发起的流量。
- 出站：SOCKS5、Shadowsocks/2022、Trojan、AnyTLS、Hysteria2、TUIC、Juicity、VMess、VLESS，以及内建的 `direct` 和 `block`。Trojan/VMess/VLESS 支持 H2 XHTTP profile（`packet-up`、`stream-up`、`stream-one`）；VMess 仍仅支持 TCP。各协议限制见[节点参考](doc/zh/reference/nodes.md)。
- 组策略：Selector、URLTest、LoadBalance、Fallback 和 Score。Score 使用业务观测与有界验证，通过 `policy: score` 选择；省略策略仍为 Selector。详见[组参考](doc/zh/reference/groups.md#score-策略)。
- DNS：支持 UDP、TCP、DoT、DoH、DoQ、DoH3 上游，可经节点或组出站，并提供路由和缓存。
- 配置与控制：dae 语法、订阅、重载、Clash 兼容 REST/WebSocket API，以及 `honk-tool` CLI 工具箱。

已实现不等于完成 review，见 [Review 状态](#review-状态)。不提供 FakeIP 引擎、完整 mihomo 兼容性或 Windows/macOS 数据面。

## 开始使用

真实透明代理需要 **root、Linux 6.12+、所需内核选项和 bpffs**。首次部署会修改网络 hook、命名空间和 sysctl；须保留带外管理通道。

1. 按[启动指南](doc/zh/how-to-start.md)检查内核、安装程序、准备 direct-only 配置并验证连通性。
2. 从 [Releases](https://github.com/daeuniverse/honk/releases) 下载匹配的二进制，或按指南准备源码构建依赖。发布二进制内嵌 eBPF 对象；源码构建需要启用 `ebpf` feature。仅运行 `cargo build --release` **不会**启用真实数据面。
3. 按[配置指南](doc/zh/configuration.md)添加节点、组、路由和 DNS。仓库提供[完整示例](config.dae)和[最小开发示例](config.min.dae)；使用前须调整接口和节点地址。

[文档索引](doc/README.md)汇总双语指南、参考和子系统设计。实现细节可从[架构概览](doc/zh/design/overview.md)、[节点参考](doc/zh/reference/nodes.md)或 [API 参考](doc/zh/reference/api.md)开始。

## 运行与升级注意事项

- **UDP NFQUEUE 默认开启：**它在 conntrack/NAT 前保留仍有歧义的 LAN 转发首包。设置 `global.nfqueue_enable: false` 可关闭；修改后需要重启。Mock 模式、不带 `ebpf` 的构建或队列不可用时，会记录 warning 并在本进程禁用暂存。honk 独占队列 `320` 和 nftables `inet honk_nfqueue` / `udp_decision`；同一网络命名空间中的防火墙管理器不得修改它们。详见 [NFQUEUE 设计](doc/zh/design/nfqueue.md)。
- **VLESS 升级：**`vless_mode` 已删除，所有 VLESS 节点 ID 都会重新派生。升级前须迁移静态链接及缓存/provider 内容，离线升级尤其需要提前迁移。仍可用的按名称保存的 Selector 选择和持久化延迟样本应保留。UDP 权限、packet encoding 和多路复用是独立设置。详见[迁移指南](doc/zh/reference/nodes.md#从-vless_mode-迁移)和 [VLESS 设计](doc/zh/design/outbound.md#vless-wire-契约)。

## 开发

工作区包含配置、共享 eBPF 类型、NFQUEUE、出站、核心和工具 crate。`crates/honk-ebpf` 中的内核程序单独构建。构建依赖和命令见[启动指南](doc/zh/how-to-start.md#从源码构建)与 [Justfile](Justfile)。

无 root 的用户态开发可使用 [mock 模式](doc/zh/how-to-start.md#无-root-开发)。`--mock-ebpf` 不会拦截流量，不能代替数据面测试。

### Debug 构建

维护者推送 `debug.*` tag 会更新滚动的 [Debug 预发布](https://github.com/daeuniverse/honk/releases/tag/debug)，而不是 Latest。这些是 release profile 二进制，并非 Cargo debug profile 构建。滚动 tag 和附件会被替换；源 tag 保留，release 说明记录源 commit 和 workflow run。等待中的中间运行可能被后续运行取代。

发布要求八个预期归档齐全且非空。若 artifact 已过期或被删除，使用 **Re-run all jobs**。发布不是原子操作；更新失败可能使 tag、说明和附件暂时不一致，需恢复后才能重新一致。

## Review 状态

多数用户态子系统主要由 AI 编写，维护者只完成了部分 review，主要关注 eBPF。以下复选框表示**维护者 review 状态，而非功能是否可用**：

- [x] eBPF 路由、map 与语义
- [x] 控制面
- [x] AnyTLS / Shadowsocks（含 2022）/ SOCKS5
- [x] RPRX（VLESS / XTLS / XHTTP / WSS / REALITY），不含 XHTTP
- [ ] Trojan-GFW（需要 UoT 实现）
- [x] DNS 逻辑
- [ ] 配置解析器（dae 扩展）
- [x] 重载逻辑
- [x] 工具

在所有当前尚未 review 的代码完成 review，并处理所有未经验证的 AI 生成实现前，不会发布 `test.1` release tag。

### TODO

- [ ] 评估 AF_XDP 与 XDP 路径以进一步提升性能
- [ ] 在 Clash 兼容 API 之外添加 honk 专用 REST API
- [ ] 添加入站支持

其他工作见 [Issues](https://github.com/daeuniverse/honk/issues) 和 [Discussions](https://github.com/daeuniverse/honk/discussions)。

## 致谢

- [dae](https://github.com/daeuniverse/dae) / [daed-rs](https://github.com/daeuniverse/daed-rs)：eBPF 透明代理谱系
- [sing-box](https://github.com/SagerNet/sing-box)：出站组与 Clash API 模式
- [daeuniverse/outbound](https://github.com/daeuniverse/outbound)：协议参考
- [juicity-rs](https://github.com/juicity/juicity-rs)（Markson Pigeonzilla Plus）：Juicity 协议参考、wire 格式对齐及真实互通测试
- [aya-rs](https://github.com/aya-rs/aya)：Rust eBPF

## 许可证

```text
SPDX-License-Identifier: GPL-3.0-only
Copyright (c) 2025, glassyiris <honk@catmint.cc> and honk contributors
```

仅用于开发的 [dae 解析器 oracle](tools/dae-parse/README.md)链接了 dae（AGPL-3.0-only）。它不随发布物分发，也不链接进 `honk-core`。
