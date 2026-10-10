# honk

English | [中文](./README.zh.md)

<a id="english"></a>

honk is an experimental Rust transparent-proxy engine for Linux. Its eBPF datapath and configuration syntax are inspired by [dae](https://github.com/daeuniverse/dae); its outbound groups, multi-protocol dialers, and Clash-compatible API follow [sing-box](https://github.com/SagerNet/sing-box) designs. It is an independent implementation, not a line-for-line port.

> **Early alpha (`v0.0.1-alpha`), not recommended for production.** Expect breaking changes, incomplete features, and limited real-world validation.

## Capabilities

- Transparent TCP/UDP: LAN-forwarded and host-originated traffic through TC eBPF, `dae0`/`daens`, and compiled routing on Linux 6.12+.
- Outbounds: SOCKS5, Shadowsocks/2022, Trojan, AnyTLS, Hysteria2, TUIC, Juicity, VMess, and VLESS, plus built-in `direct` and `block`. Trojan/VMess/VLESS support the H2 XHTTP profile (`packet-up`, `stream-up`, `stream-one`); VMess remains TCP-only. Protocol-specific limits are in the [node reference](doc/en/reference/nodes.md).
- Groups: Selector, URLTest, LoadBalance, Fallback, and Score. Score uses business observations and bounded validation; select it with `policy: score`. Omitted policy remains Selector. See the [group reference](doc/en/reference/groups.md#score-policy).
- DNS: UDP, TCP, DoT, DoH, DoQ, and DoH3 upstreams, optionally through a node or group, with routing and caching.
- Configuration and control: dae syntax, subscriptions, reload, a Clash-compatible REST/WebSocket API, and the `honk-tool` CLI toolbox.

Implemented does not mean fully reviewed; see [review status](#review-status). There is no FakeIP engine, full mihomo parity, or Windows/macOS datapath.

## Getting started

Real transparent proxying requires **root, Linux 6.12+, the required kernel options, and bpffs**. Initial deployment changes network hooks, namespaces, and sysctls; keep an out-of-band management path available.

1. Follow the [startup guide](doc/en/how-to-start.md) for kernel checks, installation, a direct-only configuration, and connectivity verification.
2. Download a matching binary from [Releases](https://github.com/daeuniverse/honk/releases), or follow the guide's source-build prerequisites. Release binaries embed the eBPF object; source builds require the `ebpf` feature. Plain `cargo build --release` does **not** enable the real datapath.
3. Add nodes, groups, routing, and DNS using the [configuration guide](doc/en/configuration.md). The repository provides [full](config.dae) and [minimal development](config.min.dae) examples; adapt interfaces and node addresses before use.

The [documentation index](doc/README.md) links all bilingual guides, references, and subsystem designs. Start with the [architecture overview](doc/en/design/overview.md), [node reference](doc/en/reference/nodes.md), or [API reference](doc/en/reference/api.md) for details.

## Operational notes

- **UDP NFQUEUE is enabled by default:** it holds ambiguous LAN-forwarded first packets before conntrack/NAT. Set `global.nfqueue_enable: false` to disable it; changing this setting requires a restart. Mock mode, builds without `ebpf`, or an unavailable queue disable staging for that process with a warning. honk exclusively owns queue `320` and nftables `inet honk_nfqueue` / `udp_decision`; same-namespace firewall managers must not modify them. See the [NFQUEUE design](doc/en/design/nfqueue.md).
- **VLESS upgrade:** `vless_mode` is removed and all VLESS node IDs are re-derived. Migrate static links and cached/provider content before upgrading, especially offline; keep usable name-based Selector choices and persisted delay samples. UDP permission, packet encoding, and multiplexing are independent settings. See the [migration guide](doc/en/reference/nodes.md#migration-from-vless_mode) and [VLESS design](doc/en/design/outbound.md#vless-wire-contracts).

## Opt-in native observation API

Build with `--features native-api` (release builds include it) and configure `experimental.native_api` for independent observations and controls on `127.0.0.1:9527`: bounded flows/logs/DNS history, probes, provider status/refresh, per-network Selector control and exact connection closure. Captured `.dae` sources remain authoritative, with opt-in source/Group PATCH transactions, synchronous main-file node/provider creation and removal, and verified-geodata operations; existing entries are edited through source PUT. `--store db` records accepted sources as revisions in a state database instead. A bearer secret or password login is required unless anonymous loopback is explicitly enabled. Serve a trusted directory, or build `--features native-ui` and set `ui: embedded` for the pinned doona build without runtime downloads. Native runtime_mode and full kernel transparency remain unavailable. See [native settings](doc/en/reference/experimental.md#native_api) and the [API contract](doc/en/reference/api.md#native-api).

## Development

The workspace contains configuration, shared eBPF types, NFQUEUE, outbound, core, and tooling crates. The kernel program in `crates/honk-ebpf` is built separately. Build prerequisites and commands are in the [startup guide](doc/en/how-to-start.md#build-from-source) and [Justfile](Justfile).

For unprivileged userspace development, use [mock mode](doc/en/how-to-start.md#unprivileged-development). `--mock-ebpf` does not intercept traffic and is not a datapath test.

### Debug builds

Maintainer `debug.*` tags update the rolling [Debug prerelease](https://github.com/daeuniverse/honk/releases/tag/debug), not Latest. These are release-profile binaries, not Cargo debug-profile builds. The rolling tag and assets are replaced; source tags remain, and release notes record the source commit and workflow run. Pending intermediate runs may be superseded.

Publication requires all eight expected archives to be present and nonempty. If artifacts have expired or been deleted, use **Re-run all jobs**. Publication is not transactional; a failed update may leave the tag, notes, and assets inconsistent until recovery.

## Review status

Most userspace subsystems were largely AI-authored with partial maintainer review; the maintainer's primary focus is eBPF. These checkboxes record **maintainer review, not feature availability**:

- [x] eBPF routing, maps, and semantics
- [x] Control plane
- [x] AnyTLS / Shadowsocks (including 2022) / SOCKS5
- [x] RPRX (VLESS / XTLS / XHTTP / WSS / REALITY) exclude XHTTP
- [ ] Trojan-GFW (needs UoT implementation)
- [x] DNS logic
- [ ] Configuration parser (dae extensions)
- [x] Reload logic
- [x] Tooling

No `test.1` release tag will be published until all currently unreviewed code has been reviewed and any unverified AI-generated implementation has been addressed.

### TODO

- [ ] Evaluate AF_XDP and XDP paths for further performance gains
- [ ] Add a honk-specific REST API beyond Clash compatibility
- [ ] Add inbound support

Track other work in [Issues](https://github.com/daeuniverse/honk/issues) and [Discussions](https://github.com/daeuniverse/honk/discussions).

## Acknowledgments

- [dae](https://github.com/daeuniverse/dae) / [daed-rs](https://github.com/daeuniverse/daed-rs): eBPF transparent proxy lineage
- [sing-box](https://github.com/SagerNet/sing-box): outbound group and Clash API patterns
- [daeuniverse/outbound](https://github.com/daeuniverse/outbound): protocol reference
- [juicity-rs](https://github.com/juicity/juicity-rs) by Markson Pigeonzilla Plus: Juicity protocol reference, wire-format alignment, and live interop testing
- [aya-rs](https://github.com/aya-rs/aya): Rust eBPF

## License

```text
SPDX-License-Identifier: GPL-3.0-only
Copyright (c) 2025, glassyiris <honk@catmint.cc> and honk contributors
```

The development-only [dae parser oracle](tools/dae-parse/README.md) links dae (AGPL-3.0-only). It is never shipped or linked into `honk-core`.
