Added

- `global.datapath` selects `ebpf`, `tproxy` or `auto` (default). The new netfilter TPROXY datapath intercepts LAN and host traffic with iptables `mangle` rules and fwmark policy routing on kernels the eBPF datapath cannot load (verified down to Linux 4.14), routing every flow in userspace; `auto` falls back to it with a warning.
- Android builds (`just build-android`, aarch64 and x86_64) for rooted devices: TPROXY is always selected, the default bypass mark becomes `0x400000` so honk's sockets stay routable under netd, state lives in `/data/adb/honk`, and `process_name` rules match the owning process of host-originated flows.
