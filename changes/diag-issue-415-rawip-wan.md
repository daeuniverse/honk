Internal

- Add opt-in, bounded WAN entry/exit evidence for the issue #415 diagnostic build without changing forwarding decisions; include IPv4/IPv6 collection and rollback instructions.
- Bundle `honk-tool bpf wan-diag` to validate, collect and stop diagnostic sampling directly, without device-side bpftool or tracefs.
