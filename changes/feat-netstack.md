Added

- Add single-peer WireGuard outbounds backed by a bounded sans-I/O IPv4/IPv6 TCP/UDP stack.
- Add opt-in Linux XDP packet termination and Core forwarding with stateful firewall and IPv4 NAT, while keeping TC as the default when datapath configuration is omitted.
- Apply scope-local learned DNS rules to new numeric packet TCP/UDP flows while preserving existing transports and terminal routing decisions.
- Abort packet protocol state before normal shutdown waits for selector retirement, without releasing outstanding output ownership early.
- Avoid a redundant XDP daemon RX refill while preserving receive-owned replenishment and explicit RX/TX wakeup checks.
- Default explicit XDP capture to forced AF_XDP ZeroCopy without fallback; keep TC as the default backend and support explicit `xsk_mode: copy` for existing Copy deployments.
