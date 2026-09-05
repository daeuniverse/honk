# Global configuration reference

This page defines the current `global { ... }` configuration fields and their runtime effect.

## Fields

Compatibility-only keys are accepted by the dae parser and stored in `GlobalConfig`, but the current runtime does not consume them. They are identified explicitly below.

| dae key | Internal field | Default | Meaning |
| ------- | -------------- | ------- | ------- |
| `tproxy_port` | `tproxy_port` | `12345` | TCP and UDP transparent-listener port programmed into the userspace listeners and eBPF datapath. A change requires restart. |
| `tproxy_port_protect` | `tproxy_port_protect` | `true` | Compatibility switch intended to prevent re-interception of the transparent port. The current runtime does not read it. |
| `pprof_port` | `pprof_port` | `0` | Compatibility pprof HTTP port; `0` means disabled. honk currently starts no pprof server and does not read this field. |
| `so_mark_from_dae` | `so_mark_from_dae` | `0` | Compatibility socket-mark value. Validation rejects overlap with datapath-reserved mark bits, but the current runtime does not apply it to sockets. |
| `log_level` | `log_level` | `"info"` | Startup log filter. `--debug` takes precedence, followed by `RUST_LOG`, then this value. A SIGHUP change is restart-required. |
| `log_file` | `log_file` | `""` | Optional append-only log path. Empty disables file output; a relative path resolves below `data_dir`. Console logging remains enabled. SIGHUP requires restart only when the resolved effective destination changes; `--log-file` shadows this value. |
| `disable_waiting_network` | `disable_waiting_network` | `false` | Compatibility key; the current startup path does not read it. Unresolved `auto` interfaces already remain pending without blocking startup. |
| `lan_interface` | `lan_interface` | `[]` | Comma-separated LAN interfaces on which forwarded traffic is intercepted. Empty installs no LAN hooks. See [Interface semantics](#interface-semantics). |
| `wan_interface` | `wan_interface` | `[]` | Comma-separated WAN interfaces whose hooks intercept host-originated TCP and UDP. The literal `auto` follows the lowest-metric IPv4 default route. |
| `auto_config_kernel_parameter` | `auto_config_kernel_parameter` | `false` | Compatibility switch for automatic sysctl setup. The current runtime does not branch on this field; the real datapath applies its fixed best-effort sysctl setup. That setup pins `net.ipv6.conf.all.forwarding=1` and therefore also writes `net.ipv6.conf.<wan>.accept_ra=2` on every resolved WAN interface (including late-attached ones), so an SLAAC/RA-learned IPv6 default route survives the forwarding pin. Hosts running systemd-networkd should prefer the explicit `IPv6AcceptRA=yes` in the WAN `.network` file. |
| `nfqueue_enable` | `nfqueue_enable` | `true` | Hold ambiguous LAN-forwarded UDP originals in NFQUEUE until userspace reaches a terminal decision. The setting requires the real eBPF backend; after the singleton instance handoff, an unavailable fixed queue or a pre-admission queue/rules/health failure logs a warning and disables it for the process without rewriting the config. Persistent token-generation recovery failures remain fatal. Installation reclaims the reserved nftables table. Changing it requires restart. New configurations should use this key; the deprecated `experimental.udp_nfqueue.enabled` spelling is accepted with a migration warning, but this canonical key wins when both are present. |
| `data_dir` | `data_dir` | `"/var/share/honk"` | Absolute, non-empty root for generated state and relative runtime assets. Missing directories are created recursively; each candidate must pass a private create-new/remove probe. An unusable candidate falls back to the equally probed working directory. A change requires restart. |
| `store_subscribe` | `store_subscribe` | `true` | Persist each last valid subscription body under `data_dir/.sub` for startup and reload recovery. A change requires restart. |
| `tcp_check_url` | `tcp_check_url` | `["https://www.gstatic.com/generate_204"]` | Comma-separated TCP/HTTP health-check URLs. The current health loop uses the first value; an empty list falls back to a plain TCP check. |
| `tcp_check_http_method` | `tcp_check_http_method` | `"HEAD"` | HTTP method sent by the URL health check. An empty value is treated as `HEAD`. |
| `udp_check_dns` | `udp_check_dns` | `["dns.google:53", "8.8.8.8", "2001:4860:4860::8888"]` | Comma-separated DNS targets for UDP health checks; a missing port defaults to `53`. |
| `check_interval` | `check_interval_secs` | `30s` | Global health-check interval. Must be positive; a value that fails to parse becomes zero and is rejected at validation. The UDP warm coordinator also uses it, with an effective minimum of 10 seconds. |
| `check_tolerance` | `check_tolerance_ms` | `50ms` | Latency improvement required before URLTest changes its selected member. |
| `dial_mode` | `dial_mode` | `"domain"` | Destination-domain discovery and routing mode: `ip`, `domain`, `domain+`, or `domain++`. See [Dial modes](#dial-modes). |
| `allow_insecure` | `allow_insecure` | `false` | Compatibility global TLS-verification fallback. Current TLS connectors do not read it; certificate skipping is configured per node in its share link. |
| `sniffing_timeout` | `sniffing_timeout_ms` | `30ms` | Compatibility sniffing timeout. The dae parser stores the duration, but the current control plane does not read it. |
| `tls_implementation` | `tls_implementation` | `"tls"` | `tls` uses the regular BoringSSL client profile; `utls` enables honk's real Chrome ClientHello profile. |
| `utls_imitate` | `utls_imitate` | `"chrome_auto"` | Fingerprint profile requested with `utls`. Only `chrome*` is implemented; other values warn and still use Chrome. |
| `tls_fragment` | `tls_fragment` | `false` | Compatibility TLS ClientHello-fragmentation switch. The current TLS connector does not read it. |
| `tls_fragment_length` | `tls_fragment_length` | `""` | Compatibility fragmentation-length range. The current TLS connector does not read it. |
| `tls_fragment_interval` | `tls_fragment_interval` | `""` | Compatibility fragmentation-interval range. The current TLS connector does not read it. |
| `mptcp` | `mptcp` | `false` | Compatibility MPTCP switch. The current dial path does not read it. |
| `bootstrap_resolver` | `bootstrap_resolver` | `""` | Resolver used for node hostnames and control-plane dials, avoiding recursive interception through honk. Empty uses the ordinary bootstrap behavior. |
| `fallback_resolver` | `fallback_resolver` | `"8.8.8.8:53"` | Compatibility fallback-resolver value. The current runtime does not read it. |
| `bandwidth_max_tx` | `bandwidth_max_tx` | `""` | Compatibility transmit-bandwidth hint, such as `'200 mbps'`. The current runtime does not read it. |
| `bandwidth_max_rx` | `bandwidth_max_rx` | `""` | Compatibility receive-bandwidth hint. The current runtime does not read it. |
| `preconnect_node_count` | `preconnect_node_count` | `'auto'` | Number of eligible bare-TCP nodes warmed once at startup; `0` disables it and `'auto'` selects at most eight. |
| `udp_warm_node_count` | `udp_warm_node_count` | `0` | Per-group UDP warm-candidate count. `0` disables the independent UDP warm coordinator. |
| `max_concurrent_dials` | `max_concurrent_dials` | `64` | Requested generation-local cap on physical proxied connects and protocol handshakes; runtime resource budgeting may clamp it. |
| — (not settable in dae syntax) | `tproxy_mark` | `0x08000000` | Fixed fwmark shared by userspace policy routing and the compiled eBPF datapath. |
| — (not settable in dae syntax) | `udphop_interval_secs` | `30s` | Legacy global UDP-hop interval. Current dialers do not read it; protocol-specific hopping uses node fields. |
| — (not settable in dae syntax) | `connect_timeout_ms` | `3000ms` | Timeout used by proxy connects, protocol preparation, preconnect, health probes, and control-plane dials. |
| — (not settable in dae syntax) | `dns_resolve_timeout_ms` | `2000ms` | Timeout for control-plane DNS resolution, including targets that must be converted to an IP before dialing. |
| — (not settable in dae syntax) | `relay_idle_timeout_secs` | `300s` | Legacy relay-idle timeout field. The current relay path does not read it. |

## Interface semantics

An empty `lan_interface` is literal: honk installs no LAN TC hooks and never substitutes `lo`. A WAN-only gateway therefore uses only `wan_interface`; host-originated TCP and UDP that traverse those WAN hooks are still proxied, while no synthetic LAN interception is added.

`auto` resolves to the interface owning the lowest-metric IPv4 default route. If no such route exists, that entry is omitted from the desired hook set and remains pending. Traffic on the unresolved interface stays fail-open because no hook is attached; explicitly named interfaces in the same list continue to work.

`IfaceWatcher` subscribes to link, address, and IPv4 route events and also performs a 60-second reconciliation. It attaches, detaches, or rebinds the required LAN/WAN hooks as interfaces and default routes change, including LAN bridge/bond members and WAN bond slaves. A changed topology refreshes generated gateway-address `direct(must)` rules and immediately wakes health-backed outbound probing. Interface-list configuration changes themselves require restart.

## Dial modes

| Mode | Sniffing | Domain verification | Routing and dial behavior |
| ---- | -------- | ------------------- | ------------------------- |
| `ip` | No | Not applicable | Keep the original destination IP; do not sniff or re-run routing. |
| `domain` | Yes | The sniffed name must pass the destination-IP reality check. | A verified name may re-run routing; if no domain rule matches, normal IP/port rules still decide. Proxy outbounds may dial by the verified name. |
| `domain+` | Yes | No | Keep the initial IP-rule decision, but let proxy outbounds use the sniffed domain as their target. |
| `domain++` | Yes | No | Re-evaluate non-reserved decisions from the sniffed SNI/Host, then use the resulting proxy domain target. |

Direct, block, `must`, and other reserved handoffs remain final and keep the original IP target.

## Data directory and asset paths

`data_dir` defaults to `/var/share/honk`, must be an absolute non-empty path, and is installed once for the process. At startup honk recursively creates it and verifies it with a private random create-new/remove probe. An unusable candidate falls back only to a process working directory that passes the same probe; startup fails and reports both causes when neither is usable. Absolute child paths remain unchanged.

`geoip.dat` and `geosite.dat` use the first existing file in this exact order:

1. `$DAE_LOCATION_ASSET/<name>`
2. `<data_dir>/<name>`
3. `./<name>` in the process working directory
4. `/usr/local/share/honk/<name>`, then `/usr/share/honk/<name>`
5. `/usr/local/share/dae/<name>`, `/usr/share/dae/<name>`, then `/etc/dae/<name>`

Other relative runtime paths preserve legacy installations as follows:

| Path | Resolution and legacy fallback |
| ---- | ------------------------------ |
| Node `ech_config_path` | Prefer an existing `<data_dir>/<path>`, then an existing working-directory-relative path. If neither exists, resolve to `<data_dir>/<path>` so the read error names the intended location. |
| `global.log_file` | Relative paths resolve to `<data_dir>/<path>`; parent directories are created at startup. Absolute paths remain explicit. On Linux, new logs are mode `0600`; symlinks and non-regular destinations are rejected, while permissions on an existing regular file are preserved. honk appends without rotation; use the platform log-rotation facility when needed. |
| `experimental.cache_file.path` | Prefer an existing `<data_dir>/<path>`, then an existing path relative to the original configuration directory. New databases are created below `data_dir`. |
| `experimental.clash_api.external_ui` | Prefer an existing `<data_dir>/<path>`, then an existing working-directory-relative directory. If neither exists, use `<data_dir>/<path>` for the dashboard download. |
| Subscription store | Use `<data_dir>/.sub`; retain an existing legacy `./.sub` until it is moved. |

## Warm-up and dial budget

| Key | Default | Runtime semantics | Details |
| --- | ------- | ----------------- | ------- |
| `preconnect_node_count` | `'auto'` | One startup-only bare-TCP pass. `'auto'` selects at most eight eligible nodes and runs four attempts concurrently; explicit `N` selects up to `N` and runs at most `min(N, 8)` concurrently. Current group picks come first, then node configuration order. `0` disables it. | [Group design](../design/groups.md) |
| `udp_warm_node_count` | `0` | `0` disables it. Positive `N` ranks the top `min(N, 3)` reusable UDP leaves per group and IP family, deduplicates them, and retains at most `4 × N` globally. Up to four attempts run concurrently, immediately and then after each completed batch plus `max(check_interval, 10s)`. | [Group design](../design/groups.md) |
| `max_concurrent_dials` | `64` | Bounds physical proxied connects and handshakes per generation, with a minimum effective value of one and an additional file-descriptor-derived ceiling shared across overlapping reload generations. Ready-pool hits, logical streams on warm transports, and `direct`/`block` do not consume permits. | [Group design](../design/groups.md) |

## Example

```dae
global {
    tproxy_port: 12345
    log_level: info
    log_file: 'honk.log'
    data_dir: '/var/share/honk'
    store_subscribe: true
    nfqueue_enable: true

    lan_interface: br0
    wan_interface: auto

    tcp_check_url: 'https://www.gstatic.com/generate_204'
    tcp_check_http_method: HEAD
    udp_check_dns: 'dns.google:53,8.8.8.8,2001:4860:4860::8888'
    check_interval: 30s
    check_tolerance: 50ms

    dial_mode: domain++
    bootstrap_resolver: '223.5.5.5:53'

    preconnect_node_count: 'auto'
    udp_warm_node_count: 0
    max_concurrent_dials: 64
}
```

## Related docs

- [Configuration guide](../configuration.md)
- [Node reference](./nodes.md)
- [Group reference](./groups.md)
- [Group design](../design/groups.md)
