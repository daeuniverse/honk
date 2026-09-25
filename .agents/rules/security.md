## Security considerations

Read with: `AGENTS.md` (Runtime invariants: Bypass mark, Netns discipline, NFQUEUE ownership); `deployment.md`; `configuration.md` for the settings named here.

- **Root/privileged execution:** `honk-core` requires root for the operations listed under `deployment.md`.
- **Clash API secret:** when `experimental.clash_api` is enabled, set a strong `secret`; the REST/WS API has no TLS of its own — bind to localhost or front it with a reverse proxy.
- **Config trust:** treat config/BPF objects as privileged input. `honk-core` writes `/proc/sys` directly and loads configured/CLI BPF paths. Netns/link/routes/rules use rtnetlink and an FD-owned namespace, requiring no external `ip`/`nsenter`.
- **Bypass mark discipline:** use the effective process `global.so_mark_from_dae` (zero selects `DAE_BYPASS_MARK`, `0x100`) on originated sockets and transparent listeners. Nonzero direct rules use their low-30-bit mark plus `CLASSIFIED_MARK`, never the global bypass value; WAN bypass accepts exact configured marks or classified-without-pending marks. Policy routing must mask user marks with `0x3fffffff`. Missing marks loop gateway traffic.
- **NFQUEUE ownership:** host-netns firewall automation must honor `crates/honk-nfqueue`'s exact-name/no-bypass rules while enabled. Mutation can fail closed or violate held-skb lifecycle assumptions.
- **Subscription store trust:** `subscription/store.rs` retains a validated directory FD for every read, write, rename, cleanup, and sync; the original path is diagnostic-only after open. Reject foreign-owned or group/other-writable directories and cache files before changing permissions. Open directories and cache files without following the final symlink; validate cache-file ownership and regular-file type on the opened FD. Never replace descriptor-relative operations with fresh pathname resolution.

