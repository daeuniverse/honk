# TPROXY datapath

The TPROXY datapath intercepts traffic with netfilter instead of eBPF. It serves kernels the [eBPF datapath](./datapath.md) cannot load on (older than Linux 5.15) and Android, where netd owns the root-cgroup BPF hooks. `global.datapath` selects it ([Datapath selection](../reference/global.md#datapath-selection)); the code lives in `crates/honk-core/src/tproxy.rs`.

## Interception

Startup installs, per address family, two `mangle` chains through `iptables-restore --noflush` and one policy rule:

| Object | Content |
| --- | --- |
| `HONK_PREROUTING` | Return honk's exact bypass mark and classified direct marks; TPROXY LAN UDP/TCP port 53; return local, broadcast, multicast and link-local destinations; TPROXY all other TCP and UDP to `tproxy_port` with `tproxy_mark`. |
| `HONK_OUTPUT` | The same returns, then `MARK --set-mark tproxy_mark/tproxy_mark` on TCP and UDP. |
| `PREROUTING` jumps | One per `lan_interface`, plus `-i lo` for packets carrying `tproxy_mark` when host traffic is diverted. |
| `OUTPUT` jumps | None without `wan_interface`; one per named interface; all interfaces for an `auto` entry. |
| Policy routing | `fwmark tproxy_mark/tproxy_mark lookup 0x686f` at priority 5000, and `local default dev lo` in table `0x686f`, for IPv4 and (when the host has an IPv6 stack) IPv6. |

Host-originated packets are re-marked in OUTPUT, rerouted to `lo` by the policy rule, and diverted on their way back through PREROUTING. The builtin-chain jumps are inserted first, ahead of other tools' rules.

Requirements: the `mangle` table, the `TPROXY`, `MARK`, `mark` and `addrtype` xtables extensions, `IP_TRANSPARENT`, and `iptables-restore` 1.6.2 or newer (`-w`). Linux 4.19 and Android GKI kernels ship all of them.

## Userspace

The control plane uses the in-memory model backend reporting kind `tproxy`. No kernel routing handoff exists, so every TCP connection and UDP flow takes the userspace routing path that `ControlPlaneRouting` handoffs already use: sniffing, `Router::route_full`, mode override and the ordinary dial. Direct flows are relayed; there is no kernel offload, NFQUEUE staging, kernel `must` finality or conn-state token.

Transparent listeners and UDP reply sockets bind in the host netns with `IP_TRANSPARENT` and keep the configured bypass mark, so honk's own replies and dials always return from both chains. UDP listeners skip `SO_RCVMARK` (Linux 5.19), whose route-carrying marks only the eBPF datapath produces.

Routing inputs: `process_name` is resolved for host-originated flows from `/proc/net/{tcp,udp}{,6}` and the owning uid's `/proc/<pid>/fd`, only when a rule uses it, and yields the process `comm`. LAN clients, `mac` and `dscp` have no source, so those conditions do not match.

## Lifecycle

Rules are installed after the control plane is built and immediately before it runs, replacing any chains and rules left by a crashed instance. They are removed after the control plane stops. Between listener teardown and removal, diverted packets find no socket and are dropped: the datapath fails closed rather than leaking traffic direct. A crash leaves the rules in place with the same effect until the next start. The process holds the singleton instance lock in this mode too.

## Android

Android builds (`just build-android`) always resolve `auto` to TPROXY and refuse `datapath: ebpf`: attaching single-mode root-cgroup programs would replace netd's. The default bypass mark is `0x400000` ([Socket marks](../reference/global.md#socket-marks)); rule priority 5000 precedes netd's rules. Android has no `/etc/resolv.conf`, so `global.bootstrap_resolver` must be set for node hostnames. The default data directory is `/data/adb/honk` and the instance lock is `/dev/honk-core.lock`.
