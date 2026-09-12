## Security considerations

Read with: `AGENTS.md` (Runtime invariants: Bypass mark, Netns discipline, NFQUEUE ownership); `deployment.md`; `configuration.md` for the settings named here.

- **Root/privileged execution:** `honk-core` requires root for the operations listed under `deployment.md`.
- **Clash API secret:** when `experimental.clash_api` is enabled, set a strong `secret`; the REST/WS API has no TLS of its own — bind to localhost or front it with a reverse proxy.
- **Config trust:** treat config/BPF objects as privileged input. `honk-core` writes `/proc/sys` directly and loads configured/CLI BPF paths. Netns/link/routes/rules use rtnetlink and an FD-owned namespace, requiring no external `ip`/`nsenter`.
- **Bypass mark discipline:** follow the **Bypass mark** rule in `AGENTS.md` (Runtime invariants) for `DAE_BYPASS_MARK`; missing marks loop gateway traffic.
- **NFQUEUE ownership:** host-netns firewall automation must honor `crates/honk-nfqueue`'s exact-name/no-bypass rules while enabled. Mutation can fail closed or violate held-skb lifecycle assumptions.

