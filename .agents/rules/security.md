## Security considerations

- **Root/privileged execution:** `honk-core` requires root for the operations listed under Deployment.
- **Clash API secret:** when `experimental.clash_api` is enabled, set a strong `secret`; the REST/WS API has no TLS of its own — bind to localhost or front it with a reverse proxy.
- **Config trust:** treat config/BPF objects as privileged input. `honk-core` writes `/proc/sys` directly and loads configured/CLI BPF paths. Netns/link/routes/rules use rtnetlink and an FD-owned namespace, requiring no external `ip`/`nsenter`.
- **Bypass mark discipline:** follow runtime **Bypass mark** rules for `DAE_BYPASS_MARK`; missing marks loop gateway traffic.
- **NFQUEUE ownership:** host-netns firewall automation must honor `crates/honk-nfqueue`'s exact-name/no-bypass rules while enabled. Mutation can fail closed or violate held-skb lifecycle assumptions.

