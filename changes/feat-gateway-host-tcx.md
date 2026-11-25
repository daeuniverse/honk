Changed

- XDP Host capture uses TCX on 1–4 explicit egress interfaces. Proved Direct stays on the original socket; Endpoint traffic uses a private TUN on the original egress. Remove `host.xsk_mode` when upgrading. The `backend: tun` HostFacts setting is unchanged.
- Withdrawing an offline Host binding no longer holds the locks used by physical queue maintenance while the kernel removes its gate and device map entries.
- Fix Host binding initialization on Linux 6.12, which rejects program-access flags on the broadcast map's outer FD array.
