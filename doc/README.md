# Documentation / 文档

The **honk** design, configuration, and operations docs are in [en/](./en/) for English and [zh/](./zh/) for Chinese. Both trees have the same layout.

**honk** 的设计、配置与运维文档按语言分目录：英文在 [en/](./en/)，中文在 [zh/](./zh/)。两个目录结构相同。

Start with the Startup guide to install honk and choose a minimal configuration, then use the Configuration guide to add routing, DNS and subscriptions. Use Reference for exact fields, Operations for deployment checks, and Migration when upgrading. The root [README.md](../README.md) gives the project overview.

先读启动指南，完成安装并选择最小配置，再用配置指南添加路由、DNS 和订阅。查字段时看参考文档，检查部署时看运维文档，升级时看迁移说明。项目概览见仓库根目录 [README.md](../README.md)。

## Guide / 指南

| Document | English | 中文 |
| ---------- | --------- | ------ |
| Startup guide | [en/how-to-start.md](./en/how-to-start.md) | [zh/how-to-start.md](./zh/how-to-start.md) |
| Configuration guide | [en/configuration.md](./en/configuration.md) | [zh/configuration.md](./zh/configuration.md) |

## Reference / 参考

Field-by-field configuration and API reference. / 逐字段的配置与 API 参考。

| Document | English | 中文 |
| ---------- | --------- | ------ |
| `global { }` | [en/reference/global.md](./en/reference/global.md) | [zh/reference/global.md](./zh/reference/global.md) |
| `node { }` + share links | [en/reference/nodes.md](./en/reference/nodes.md) | [zh/reference/nodes.md](./zh/reference/nodes.md) |
| `group { }` | [en/reference/groups.md](./en/reference/groups.md) | [zh/reference/groups.md](./zh/reference/groups.md) |
| `routing { }` | [en/reference/routing.md](./en/reference/routing.md) | [zh/reference/routing.md](./zh/reference/routing.md) |
| `dns { }` | [en/reference/dns.md](./en/reference/dns.md) | [zh/reference/dns.md](./zh/reference/dns.md) |
| `subscription { }` | [en/reference/subscription.md](./en/reference/subscription.md) | [zh/reference/subscription.md](./zh/reference/subscription.md) |
| `assets { }` | [en/reference/assets.md](./en/reference/assets.md) | [zh/reference/assets.md](./zh/reference/assets.md) |
| `experimental { }` | [en/reference/experimental.md](./en/reference/experimental.md) | [zh/reference/experimental.md](./zh/reference/experimental.md) |
| Native API, Clash API and `/stats` | [en/reference/api.md](./en/reference/api.md) | [zh/reference/api.md](./zh/reference/api.md) |
| CLI (`honk-core` + `honk-tool`) | [en/reference/cli.md](./en/reference/cli.md) | [zh/reference/cli.md](./zh/reference/cli.md) |
| dae syntax and compatibility | [en/reference/dialect.md](./en/reference/dialect.md) | [zh/reference/dialect.md](./zh/reference/dialect.md) |

## Migration / 迁移

Per-release configuration changes that affect an existing configuration. One file per release tag, named after the tag. / 每个发行版中会影响已有配置的变更；每个发行 tag 一个文件，以 tag 命名。

| Release | English | 中文 |
| --------- | --------- | ------ |
| `v0.1.0-beta.1` | [en/v0.1.0-beta.1.md](./migration/en/v0.1.0-beta.1.md) | [zh/v0.1.0-beta.1.md](./migration/zh/v0.1.0-beta.1.md) |
| `v0.1.0-beta.3` | [en/v0.1.0-beta.3.md](./migration/en/v0.1.0-beta.3.md) | [zh/v0.1.0-beta.3.md](./migration/zh/v0.1.0-beta.3.md) |

## Operations / 运维

| Document | English | 中文 |
| ---------- | --------- | ------ |
| DNS canary and rollback runbook | [en/operations/dns-rollout.md](./en/operations/dns-rollout.md) | [zh/operations/dns-rollout.md](./zh/operations/dns-rollout.md) |
| Long connections and keepalive / 长连接与保活 | [en/operations/long-connections.md](./en/operations/long-connections.md) | [zh/operations/long-connections.md](./zh/operations/long-connections.md) |
| Issue #415 diagnostic build / 诊断构建 | [en/operations/wan-diagnostic-415.md](./en/operations/wan-diagnostic-415.md) | [zh/operations/wan-diagnostic-415.md](./zh/operations/wan-diagnostic-415.md) |

## Design / 设计

How honk works, by subsystem. / honk 的工作原理，按子系统划分。

| Document | English | 中文 |
| ---------- | --------- | ------ |
| Architecture overview | [en/design/overview.md](./en/design/overview.md) | [zh/design/overview.md](./zh/design/overview.md) |
| eBPF datapath | [en/design/datapath.md](./en/design/datapath.md) | [zh/design/datapath.md](./zh/design/datapath.md) |
| Routing engine | [en/design/routing.md](./en/design/routing.md) | [zh/design/routing.md](./zh/design/routing.md) |
| Held-first-packet UDP (NFQUEUE) | [en/design/nfqueue.md](./en/design/nfqueue.md) | [zh/design/nfqueue.md](./zh/design/nfqueue.md) |
| Userspace control plane | [en/design/control-plane.md](./en/design/control-plane.md) | [zh/design/control-plane.md](./zh/design/control-plane.md) |
| DNS subsystem | [en/design/dns.md](./en/design/dns.md) | [zh/design/dns.md](./zh/design/dns.md) |
| Outbound stack | [en/design/outbound.md](./en/design/outbound.md) | [zh/design/outbound.md](./zh/design/outbound.md) |
| Groups, health, warm-up | [en/design/groups.md](./en/design/groups.md) | [zh/design/groups.md](./zh/design/groups.md) |

---

Conventions / 约定：

- Links between translated documentation pages use the same language. / 已翻译的文档页面之间使用同一语言的链接。
- The reference files are exhaustive for their config section; the design files explain mechanisms and invariants. / 参考文档穷尽对应配置小节的字段，设计文档解释机制与不变量。
- The [AGENTS.md](../AGENTS.md) at the repo root carries agent-oriented layout notes. / 仓库根目录的 [AGENTS.md](../AGENTS.md) 提供面向代理的结构说明。
