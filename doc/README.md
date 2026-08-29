# Documentation / 文档

This directory holds the design, configuration, and operations docs for **honk**, split by language: English under [en/](./en/), Chinese under [zh/](./zh/). Both trees have the same layout.

本目录存放 **honk** 的设计、配置与运维文档，按语言分目录：英文在 [en/](./en/)，中文在 [zh/](./zh/)。两棵树结构相同。

Start from the root [README.md](../README.md) for a project overview. New to the configuration format? Read the **Guide** first, then the per-section **Reference** files.

项目概览请先看仓库根目录 [README.md](../README.md)。初次接触配置格式？先读**指南**，再按需查阅各小节的**参考**文档。

## Guide / 指南

| Document | English | 中文 |
| ---------- | --------- | ------ |
| Configuration guide | [en/configuration.md](./en/configuration.md) | [zh/configuration.md](./zh/configuration.md) |
| Startup guide | [en/how-to-start.md](./en/how-to-start.md) | [zh/how-to-start.md](./zh/how-to-start.md) |

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
| `experimental { }` | [en/reference/experimental.md](./en/reference/experimental.md) | [zh/reference/experimental.md](./zh/reference/experimental.md) |
| Clash API + `/stats` | [en/reference/api.md](./en/reference/api.md) | [zh/reference/api.md](./zh/reference/api.md) |
| CLI (`honk-core` + `honk-tool`) | [en/reference/cli.md](./en/reference/cli.md) | [zh/reference/cli.md](./zh/reference/cli.md) |

## Operations / 运维

| Document | English | 中文 |
| ---------- | --------- | ------ |
| DNS canary and rollback runbook | [en/operations/dns-rollout.md](./en/operations/dns-rollout.md) | [zh/operations/dns-rollout.md](./zh/operations/dns-rollout.md) |

---

Conventions / 约定:

- Files under `en/` link only within `en/`; files under `zh/` link only within `zh/`. / `en/` 内文档只链接 `en/`，`zh/` 内文档只链接 `zh/`。
- The reference files are exhaustive for their config section; the design files explain mechanisms and invariants. / 参考文档穷尽对应配置小节的字段，设计文档解释机制与不变量。
- The [AGENTS.md](../AGENTS.md) at the repo root carries agent-oriented layout notes. / 仓库根目录的 [AGENTS.md](../AGENTS.md) 提供面向代理的结构说明。
