Internal

- Add opt-in WAN entry/exit sampling with a time limit for issue #415, without changing forwarding decisions or fixing the reported SIPA problem. Document IPv4/IPv6 capture and rollback.
- Publish matching `honk-core` bundles and standalone `honk-tool` archives for each target. Core bundles also keep the tool; BPF stays embedded in core. `honk-tool bpf wan-diag` checks maps, collects samples and disables sampling without device-side bpftool or tracefs.
- Close diagnostic map/program FDs before writing output, so a blocked pipe cannot retain old maps. Move snapshots into the report without copying. Keep real-CLI capture, disable and cleanup-error backpressure regressions in the disposable-VM gate.
