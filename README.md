# honk

[English](./README.md) | [中文](./README_CN.md)

---

<a id="english"></a>

## What Is honk?

**honk** is a Rust transparent-proxy engine for Linux, inspired by [dae](https://github.com/daeuniverse/dae) for its eBPF datapath and configuration surface, and by [sing-box](https://github.com/SagerNet/sing-box) for its outbound groups, multi-protocol dialers, and Clash-compatible API.

It is **not** a line-for-line port of either project. The kernel path follows dae's TC + match_set + `dae0`/`daens` model, while the userspace outbound and control stacks follow sing-box-oriented designs. The project combines dae's datapath model with sing-box-inspired userspace behavior.

> **Status: experimental (`v0.0.1-alpha`).** honk is an early alpha release. Expect breaking changes, incomplete features (see TODO), and limited real-world validation. It is not recommended for production use.

License: **GPL-3.0-only**.

The always-compiled, reliability-first Score group policy is selected explicitly with `policy: score`; omitted policy still defaults to Selector. Score learns only in process memory from actual traffic plus DNS, real QUIC handshakes, probes, delay tests, warm-up, and direct or proxied UI downloads. Authenticated `GET /stats` exports only safe aggregate selection-reason counters by group; scorer cells, target keys, and other private scorer data are never logged, persisted, or exported. See the [group reference](doc/en/reference/groups.md#score-policy).

## Experimental held-first-packet UDP decisions

The UDP NFQUEUE path is enabled by default. It holds only ambiguous **LAN-forwarded** first packets after LAN TC and before conntrack/NAT. Disable it with a process configuration change:

```dae
global {
    nfqueue_enable: false
}
```

Changing `global.nfqueue_enable` requires a restart. If NFQUEUE is requested with `--mock-ebpf`, a build without `ebpf`, or an unavailable fixed queue, honk logs a warning and runs with NFQUEUE staging disabled for that process; it does not rewrite the config file. Real startup waits for the singleton instance handoff before probing the queue and reclaims the reserved nftables table during installation. Host-originated WAN egress remains on the canonical TPROXY path. DNS port 53, `must`, `block`, and already-safe route-time direct decisions never enter NFQUEUE; only decisions that can still change in userspace are staged.

The path owns raw-netlink queue `320` and nftables objects `inet honk_nfqueue` / `udp_decision`; same-namespace firewall managers must leave them untouched while honk runs. Direct releases the held skb, proxy submits one retained payload to the normal UDP initializer, and block/cancellation drops it. The ingest actor is bounded to 256 packets and 8 MiB of payload, and every packet keeps a three-second absolute deadline from listener receipt. With the Clash API enabled, `/stats.udp.nfqueue` exposes actor depth/bytes/oldest age plus explicit kernel-stat availability and read failures. See the [NFQUEUE design](doc/en/design/nfqueue.md) and [API reference](doc/en/reference/api.md) for invariants and the full metric schema.

## VLESS UDP, H2MUX, and XUDP

VLESS share links select one explicit mode with `vless_mode=legacy|uot-v2|h2mux|h2mux-padded|xudp|mux-cool`. `legacy` is the backward-compatible TCP-only default. `uot-v2` keeps that TCP path and adds direct UoT v2 for UDP. `h2mux` carries logical TCP and native connected sing-mux UDP over shared HTTP/2 carriers; `h2mux-padded` adds sing-mux v1 padding. `xudp` keeps ordinary VLESS TCP and opens one Single XUDP carrier per UDP transport. `mux-cool` shares node-owned Xray Mux.Cool carriers across logical TCP and XUDP.

Modes are not negotiated and never fall back or replay a UDP first packet. Non-legacy modes cannot use VLESS Encryption; only `xudp` may combine with `flow=xtls-rprx-vision`. The official interop suite covers sing-box and Xray: all six cleartext modes, H2MUX over TLS and REALITY, padding, and XUDP Vision. See the [node reference](doc/en/reference/nodes.md#vless-modes) for wire, lifecycle, and import rules.

## Before Using This Repository

### Important: Review Status

These checkboxes indicate maintainer review status, not feature availability:

- [x] eBPF routing, maps, and semantics
- [x] Control plane
- [x] AnyTLS / Shadowsocks (including 2022) / SOCKS5
- [ ] RPRX (VLESS / XTLS / XHTTP / WSS / REALITY)
- [ ] Trojan-GFW (needs UoT implementation)
- [x] DNS logic
- [ ] Configuration parser (dae extensions)
- [ ] Reload logic
- [x] Tooling

### TODO

- [x] Add the always-compiled Score group policy
- [ ] Add proxied DoQ/DoH3 through a quinn `AsyncUdpSocket` adapter over outbound `PacketTransport`
- [ ] Evaluate AF_XDP and XDP paths for further performance gains
- [ ] Add a honk REST API
- [ ] Add inbound support
- [ ] Track additional work through GitHub [Issues](https://github.com/Glassyiris/honk/issues) and [Discussions](https://github.com/Glassyiris/honk/discussions)

> No `test.1` release tag will be published until all currently unreviewed code has been reviewed and any unverified AI-generated implementation has been addressed.

## Acknowledgments

- [dae](https://github.com/daeuniverse/dae) / [daed-rs](https://github.com/daeuniverse/daed-rs) — eBPF transparent proxy lineage
- [sing-box](https://github.com/SagerNet/sing-box) — outbound group and Clash API patterns
- [daeuniverse/outbound](https://github.com/daeuniverse/outbound) — protocol reference
- [juicity-rs](https://github.com/juicity/juicity-rs) by Markson Pigeonzilla Plus — Juicity protocol implementation reference; the wire-format alignment and live interop testing of honk's Juicity outbound were done against it
- [aya-rs](https://github.com/aya-rs/aya) — Rust eBPF

## License

```text
SPDX-License-Identifier: GPL-3.0-only
Copyright (c) 2025, glassyiris <honk@catmint.cc> and honk contributors
```
