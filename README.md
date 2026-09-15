# honk

English | [中文](./README.zh.md)

---

<a id="english"></a>

## What Is honk?

**honk** is a Rust transparent-proxy engine for Linux, inspired by [dae](https://github.com/daeuniverse/dae) for its eBPF datapath and configuration surface, and by [sing-box](https://github.com/SagerNet/sing-box) for its outbound groups, multi-protocol dialers, and Clash-compatible API.

It is **not** a line-for-line port of either project. The packet path retains dae's TC + `dae0`/`daens` model; a single userspace routing IR is compiled into generation-owned BPF policy functions on Linux 6.12+. The outbound and control stacks follow sing-box-oriented designs.

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

## VLESS UDP and multiplexing

VLESS now composes three independent choices: `udp=0|1` controls packet permission, `packetEncoding=auto|none|xudp|uot-v2` selects the non-multiplexed UDP fallback, and `mux=off|h2mux|xray` selects carrier multiplexing. Canonical links default to UDP enabled, `packetEncoding=auto`, and `mux=off`; for example, `vless://00000000-0000-4000-8000-000000000001@edge.example:443?security=tls&packetEncoding=auto&mux=off&udp=1#edge`. Without Vision, Auto uses native VLESS UDP on ports 53/443; other permitted targets use Single XUDP.

Vision always forbids TCP multiplexing, but UDP-only Xray mux is valid. Base Vision rejects UDP/443 on the protocol fallback; actual Xray UDP mux requires its `allow` policy to bypass that gate. VLESS Encryption can combine with Vision under the direct-TCP and eligible XUDP/disabled-UDP path rules. Carrier capacity comes from the process-wide file-descriptor budget, so exhaustion is a local, health-neutral refusal rather than fallback or packet replay. XUDP Global IDs have a scoped ownership boundary rather than process-wide collision-free NAT semantics. See the [node reference](doc/en/reference/nodes.md#vless-udp-and-multiplexing) for canonical links, migration, composition, and REALITY handshake/pool behavior, and the canonical [VLESS outbound design](doc/en/design/outbound.md#sourcesession-ownership-and-capacity) for lifecycle and ownership.

**Upgrade warning:** `vless_mode` is removed and every VLESS node ID is re-derived. Migrate static links and cached/provider content before upgrading, especially offline. Name-based Selector choices and recent persisted delay samples can survive; do not delete them. See the [migration guide](doc/en/reference/nodes.md#migration-from-vless_mode).

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
- [x] Add proxied DoQ/DoH3 through a quinn `AsyncUdpSocket` adapter over outbound `PacketTransport`
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
