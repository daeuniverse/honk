# Global configuration reference

`global { ... }` configures process-wide settings.

## Fields

The dae parser accepts compatibility-only keys and stores them in `GlobalConfig`, but the current runtime does not consume them. The table identifies these keys explicitly.

| dae key | Internal field | Default | Meaning |
| ------- | -------------- | ------- | ------- |
| `tproxy_port` | `tproxy_port` | `12345` | TCP and UDP transparent-listener port programmed into the userspace listeners and eBPF datapath. A change requires restart. |
| `tproxy_port_protect` | `tproxy_port_protect` | `true` | Compatibility switch intended to prevent re-interception of the transparent port. The current runtime does not read it. |
| `pprof_port` | `pprof_port` | `0` | Compatibility pprof HTTP port; `0` means disabled. honk currently starts no pprof server and does not read this field. |
| `so_mark_from_dae` | `so_mark_from_dae` | `0` (effective `0x100`) | Process-wide `SO_MARK` for honk-originated sockets and exact datapath bypass. A nonzero value replaces `0x100`, not ORs with it; changing the setting requires restart. Bits `0xc8000000` are reserved and rejected. See [Socket marks](#socket-marks). |
| `log_level` | `log_level` | `"info"` | Startup log filter. A valid `RUST_LOG` takes precedence, followed by `--debug`, then this value. A SIGHUP change is restart-required; a native API `log.level` PATCH replaces the filter until the next activation. `info` covers runtime state (startup, reloads, health, subscriptions); the per-connection routing lines (`TCP connection`, `UDP connection`, eBPF offload) are `debug`, so a router's syslog is not flooded by traffic. To audit routing decisions, run with `debug` or read `/logs?level=debug` from the API. |
| `log_file` | `log_file` | `""` | Optional append-only log path. Empty disables file output; a relative path resolves below `data_dir`. Console logging remains enabled. SIGHUP requires restart only when the resolved effective destination changes; `--log-file` shadows this value. |
| `disable_waiting_network` | `disable_waiting_network` | `false` | Compatibility key; the current startup path does not read it. Unresolved `auto` interfaces already remain pending without blocking startup. |
| `shutdown_wait_connections` | `shutdown_wait_connections` | `false` | Reloadable opt-in business-connection grace; see [Shutdown](#shutdown). |
| `lan_interface` | `lan_interface` | `[]` | Comma-separated LAN interfaces on which forwarded traffic is intercepted. Empty installs no LAN hooks. See [Interface semantics](#interface-semantics). |
| `wan_interface` | `wan_interface` | `[]` | Comma-separated WAN interfaces whose hooks intercept host-originated TCP and UDP. The literal `auto` follows the lowest-metric IPv4 default route. See [Interface semantics](#interface-semantics). |
| `auto_config_kernel_parameter` | `auto_config_kernel_parameter` | `false` | Compatibility switch for automatic sysctl setup. The current runtime does not branch on this field; the real datapath applies its fixed best-effort sysctl setup. That setup pins `net.ipv6.conf.all.forwarding=1` and therefore also writes `net.ipv6.conf.<wan>.accept_ra=2` for every WAN root interface (including one that is also a LAN interface) as soon as that interface is present in the interface topology, at startup or when it appears later, without waiting for its hooks or the link to be up, so an SLAAC/RA-learned IPv6 default route survives the forwarding pin. It also writes `net.ipv4.conf.<lan>.rp_filter=0` for the first resolved LAN name that exists and is not refused, as configured and not canonicalized. Each value is written again about one second later, because udev's `systemd-sysctl` run for a newly added device restores the distribution default right after the first write; after that honk leaves it alone until the device is recreated. Hosts running systemd-networkd should prefer the explicit `IPv6AcceptRA=yes` in the WAN `.network` file. |
| `nfqueue_enable` | `nfqueue_enable` | `true` | Hold ambiguous LAN-forwarded UDP originals in NFQUEUE until userspace reaches a terminal decision. The setting requires the real eBPF backend; after the singleton instance handoff, an unavailable fixed queue or a pre-admission queue/rules/health failure logs a warning and disables it for the process without rewriting the config. Persistent token-generation recovery failures remain fatal. Installation reclaims the reserved nftables table. Changing it requires restart. New configurations should use this key; the deprecated `experimental.udp_nfqueue.enabled` spelling is accepted with a migration warning, but this canonical key wins when both are present. |
| `data_dir` | `data_dir` | `"/var/lib/honk"` | Absolute, non-empty root for generated state and relative runtime assets. Missing directories are created recursively; each candidate must pass a private create-new/remove probe. An unusable candidate falls back to the equally probed working directory, except with `--store db` or enabled native API password login. Existing artifacts under the legacy `/var/share/honk` (`LEGACY_DATA_DIR`) root remain usable through the path-specific fallback rules below; legacy cache and subscription imports instead copy eligible state into `state/honk.db`. A change requires restart. |
| `store_subscribe` | `store_subscribe` | `true` | Persist each last valid subscription body in the state db, `data_dir/state/honk.db`, for startup recovery only; reload carries active nodes without reading stored bodies. A change requires restart. |
| `tcp_check_url` | `tcp_check_url` | `["https://www.gstatic.com/generate_204"]` | Comma-separated TCP/HTTP health-check URLs. The health loop uses the first value; an empty list falls back to a plain TCP check. URI parsing separates userinfo, bracketed IPv6, port, path, query and fragment. Userinfo adds no authorization header; path/query are sent without the fragment, including `/?query` for a slashless query. Explicit HTTP/HTTPS default to 80/443; schemeless health targets use HTTP/80. URLTest defaults schemeless targets to HTTPS/443 and sends HEAD to the decoded path/query. |
| `tcp_check_http_method` | `tcp_check_http_method` | `"HEAD"` | HTTP method sent by the URL health check. An empty value is treated as `HEAD`. |
| `udp_check_dns` | `udp_check_dns` | `["dns.google:53", "8.8.8.8", "2001:4860:4860::8888"]` | Comma-separated DNS targets for UDP health checks. Bare IPv4/IPv6, `[IPv6]`, and hostnames default to port `53`; explicit ports must be numeric and in `1..65535`. Malformed brackets or ports fail validation with a located diagnostic. The first literal wins over domain entries; otherwise the first domain is resolved. Resolution and Score use the same decoded host/port, retaining domain identity after resolution. |
| `check_interval` | `check_interval_secs` | `30s` | Global health-check interval. Must be positive; a value that fails to parse becomes zero and is rejected at validation. The UDP warm coordinator also uses it, with an effective minimum of 10 seconds. |
| `check_tolerance` | `check_tolerance_ms` | `50ms` | Latency improvement required before URLTest changes its selected member. Accepts bare milliseconds, `ms`, or `s`; anything else keeps this default and logs a warning. |
| `dial_mode` | `dial_mode` | `"domain"` | Destination-domain discovery and routing mode: `ip`, `domain`, `domain+`, or `domain++`. See [Dial modes](#dial-modes). |
| `allow_insecure` | `allow_insecure` | `false` | Compatibility global TLS-verification fallback. Current TLS connectors do not read it; certificate skipping is configured per node in its share link. |
| `sniffing_timeout` | `sniffing_timeout_ms` | `30ms` | Compatibility sniffing timeout, currently unused by the control plane. Duration syntax and invalid-value handling match `check_tolerance`. |
| `tls_implementation` | `tls_implementation` | `"tls"` | `tls` uses the regular BoringSSL client profile; `utls` enables honk's Chrome-oriented ClientHello emulation, not exact browser identity. |
| `utls_imitate` | `utls_imitate` | `"chrome_auto"` | Compatibility fingerprint request. The `utls` mode uses one Chrome-oriented profile; this value does not switch profiles. |
| `tls_fragment` | `tls_fragment` | `false` | Compatibility TLS ClientHello-fragmentation switch. The current TLS connector does not read it. |
| `tls_fragment_length` | `tls_fragment_length` | `""` | Compatibility fragmentation-length range. The current TLS connector does not read it. |
| `tls_fragment_interval` | `tls_fragment_interval` | `""` | Compatibility fragmentation-interval range. The current TLS connector does not read it. |
| `mptcp` | `mptcp` | `false` | Compatibility MPTCP switch. The current dial path does not read it. |
| `bootstrap_resolver` | `bootstrap_resolver` | `""` | Marked UDP/TCP resolver for node hostnames and control-plane dials. Empty or failed bootstrap resolution uses `/etc/hosts`, then marked DNS to the first numeric `/etc/resolv.conf` nameserver; no libc NSS or search suffixes. |
| `fallback_resolver` | `fallback_resolver` | `"8.8.8.8:53"` | Compatibility fallback-resolver value. The current runtime does not read it. |
| `bandwidth_max_tx` | `bandwidth_max_tx` | `""` | Compatibility transmit-bandwidth hint, such as `'200 mbps'`. The current runtime does not read it. |
| `bandwidth_max_rx` | `bandwidth_max_rx` | `""` | Compatibility receive-bandwidth hint. The current runtime does not read it. |
| `preconnect_node_count` | `preconnect_node_count` | `'auto'` | Number of eligible bare-TCP nodes warmed once at startup; `0` disables it and `'auto'` selects at most eight. |
| `udp_warm_node_count` | `udp_warm_node_count` | `0` | Per-group UDP warm-candidate count. `0` disables the independent UDP warm coordinator. |
| `max_concurrent_dials` | `max_concurrent_dials` | `64` | Requested generation-local cap on physical proxied connects and protocol handshakes; runtime resource budgeting may clamp it. |
| — (not settable in dae syntax) | `tproxy_mark` | `0x08000000` | Fixed fwmark shared by userspace policy routing and the compiled eBPF datapath. |
| — (not settable in dae syntax) | `udphop_interval_secs` | `30s` | Legacy global UDP-hop interval. Current dialers do not read it; protocol-specific hopping uses node fields. |
| — (not settable in dae syntax) | `connect_timeout_ms` | `3000ms` | Stage timeout used by proxy connects, protocol preparation, preconnect, health probes, and control-plane dials. Transparent TCP candidate races and UDP transport preparation additionally share an absolute budget of `max(10s, 4 × connect_timeout)`; this adds no configuration key. |
| — (not settable in dae syntax) | `dns_resolve_timeout_ms` | `2000ms` | Timeout for control-plane DNS resolution, including targets that must be converted to an IP before dialing. |
| — (not settable in dae syntax) | `relay_idle_timeout_secs` | `300s` | Legacy relay-idle timeout field. The current relay path does not read it. |

`nfqueue_enable` also controls [fragmented LAN UDP/53 delivery](../design/nfqueue.md#fragmented-lan-dns): controller/raw-group fragments require ready NFQUEUE and otherwise drop, without bypassing DNS policy. Native `direct(must)` and unfragmented DNS are unchanged.

HTTP health checks and URLTest send a credential-free authority in `Host`: IPv6 stays bracketed, and non-default ports are retained. Connection and TLS server-name handling use the unbracketed host.

The configured request path and query retain their original dot segments and percent-encoding. URLs with surplus authority slashes, backslashes, or embedded ASCII whitespace/control characters are rejected before building a request; rejected URLs are not echoed in the health-check warning.

## Shutdown

Setting `shutdown_wait_connections: true` gives accepted connections up to five seconds to finish on ordinary, healthy shutdown with an active runtime epoch; remaining connections are then closed and joined. Other cases skip this grace. It does not distinguish short and long connections.

Shutdown uses the latest accepted configuration; rejected reloads preserve the previous value. The flag does not change reload retirement, DNS/state persistence, NFQUEUE/eBPF cleanup or the native API's independent [five-second HTTP grace](./api.md#native-api).

This is neither graceful restart nor a total exit deadline: [owned cleanup and blocking work](../design/control-plane.md#runtime-teardown) still have to finish.

## Socket marks

`so_mark_from_dae: 0` (or omission) retains the historical effective mark `0x100`.
A nonzero value is applied exactly before connect/send, including proxy carriers,
bootstrap/DNS traffic, health checks, subscriptions and UI downloads. The datapath
bypass compares this exact configured value: merely containing bit `0x100` is not
an exemption. Transparent listeners use the same mark for socket recognition;
accepted TCP client sockets have it cleared. Standalone `dns.bind` ingress stays
an ordinary unmarked local service.

The dae global scalar keeps honk's existing hexadecimal-first lexical behavior:
`10` and `0x10` both mean 16; malformed or overflowing text emits a diagnostic and
falls back to raw `0`, hence effective `0x100`. Prefer explicit `0x` notation.
This differs from [direct rule marks](./routing.md#policy-routing-marks), where
unprefixed values are decimal and malformed values reject the configuration.
Both global and rule marks reject reserved bits `0xc0000000` at validation; the global mark also rejects the TPROXY bit `0x08000000`, which daens routes to its local listeners.

The setting is captured before startup network I/O and is process-scoped; use a
restart, not SIGHUP, to change it. A nonzero direct-rule mark replaces the global
mark for that direct flow's policy-routing payload, while proxy carriers and
bootstrap traffic keep the global value. Direct traffic also carries internal
classification metadata; use the masked IPv4/IPv6 `ip rule` examples in the
[routing reference](./routing.md#policy-routing-marks). honk does not install your
WAN policy tables, routes, source-address rules or NAT configuration.

## Reloading health checks and TLS mode

These inputs are captured at startup. A reload that changes their effective values is rejected, preserving the active configuration and installed probes:

- `check_interval`.
- The first `tcp_check_url`, including its fallback, path, and query text. A missing or empty first value disables HTTP probing; later values do not affect this comparison.
- `tcp_check_http_method` while HTTP probing is enabled. Empty and `HEAD` are equivalent.
- The selected `udp_check_dns` target: trim and ignore empty entries, prefer the first IP literal anywhere in the list, otherwise use the first domain, otherwise `8.8.8.8:53`. Admission compares configured address/domain and port, without resolving DNS. Changes to unselected entries remain admissible.
- Switching `tls_implementation` between native TLS and uTLS. The `utls` comparison is case-insensitive.

DAE `check_tolerance` still updates URLTest group tolerances on reload. Group-specific check URLs and direct checks retain their existing live-update paths. Reloading `utls_imitate` stores the compatibility value but does not change the fingerprint.

UDP DNS target initialization is attempted at startup within the health-check
timeout. A local refusal or initialization timeout leaves the configured target
pending for a later health cycle, without a default substitution or node-health
penalty; independent QUIC checks can continue. The first successfully resolved
address remains pinned. Deferred resolution and the DNS exchange share one probe
deadline; ordinary resolution failures retain the existing default fallback.

## Interface semantics

An empty `lan_interface` is literal: honk installs no LAN TC hooks and never substitutes `lo`. A WAN-only gateway therefore uses only `wan_interface`; host-originated TCP and UDP that traverse those WAN hooks are still proxied, while no synthetic LAN interception is added.

On an Ethernet parent, frames with a non-zero VLAN ID belong to the VLAN device; list `eth1.20` (or `br0.N` on a VLAN-aware bridge) to manage that subnet. The VLAN-aware bridge topology has not been verified by the real-traffic tests. See [Interface hook sets](../design/datapath.md#interface-hook-sets).

`auto` (trimmed and ASCII case-insensitive, so `AUTO`, ` auto ` and a whitespace-only entry all count, in every consumer; the `.dae` list parser drops a truly empty item, so an empty list still means no interfaces) resolves to the interface owning the lowest-metric IPv4 default route. If no such route exists, that entry stays pending (never `lo`) until a default route appears. Explicitly named interfaces in the same list continue to work. The routing table is read only when an entry is `auto`; an unreadable table is an error, not "no default route": it fails startup, and a failure later in the run leaves the bindings as they were.

An interface is bound as soon as it exists; `IFF_UP` is not required. Roles are per interface (see [Interface hook sets](../design/datapath.md#interface-hook-sets)), so a shared LAN/WAN interface does not change the hooks of the other LAN interfaces. A member of a bond, bridge or other master is bound through that master, except `vrf` and `openvswitch` members, which stay themselves; a LAN bridge also binds its ports in the LAN role, and bond hooks stay on the logical master, never its members.

Every configured entry is bound lazily and never fails startup. An interface that does not exist yet, an `auto` entry without a default route or a refused link type (below) binds nothing: its traffic is not intercepted until it is bound. A TCX link that cannot be created, updated or verified can leave the entry only partly bound, so working hooks may still intercept traffic. The `interface_binding` [degradation](./api.md#native-api) reports either case; `lifecycle.state` stays `running`, so monitoring must read that degradation. Only the kernel's primary interface name matches; an altname is treated as absent. A device that appears is bound, a device that disappears has its hooks released, and a device recreated with a new interface index is bound again. A `dns.bind` address that belongs to an interface that does not exist yet is not an interface entry: binding it still fails startup (`EADDRNOTAVAIL`).

The link type chooses the program family:

| Link type (`ifi_type`) | Framing |
| --- | --- |
| Ethernet: eth, bond/team (while their first port is Ethernet), bridge, vlan, macvlan/macvtap, ipvlan, veth, netkit, vxlan, geneve, gretap, tap, dummy, macsec | `_l2` |
| `ARPHRD_NONE` (wireguard, tun, `collect_md` GRE, geneve/VXLAN-GPE in no-MAC mode), PPP, RAWIP, IPIP, IP6TNL, SIT | `_l3` |
| GRE / IP6GRE | `_l3` only when `IFF_POINTOPOINT` is set and `IFF_BROADCAST` is not; otherwise refused |
| `lo`, `vcan`, InfiniBand, 802.15.4, nlmon, and every other type | refused |

The table describes the classifier, not a verified-device support matrix. The IPv4 GRE and `collect_md` GRE kernel tests inspect flags and TCX hooks, not tunnel payload forwarding. Real IP6GRE, IPIP, SIT, IP6TNL, PPP, RAWIP, tun and wireguard devices are unverified by this change; GRE and all of these L3/NONE families also lack end-to-end traffic coverage.

IP6GRE with a unicast remote but no explicit local address may lack `IFF_POINTOPOINT` and is refused even when its packets would be bare IP. Changing an existing IP6GRE device with `ip link change` is unsupported: the kernel can change the point-to-point flags without clearing `header_ops`, so the flags can make this classifier select `_l3` while a tunnel header remains. Delete and recreate the tunnel rather than changing it in place; IP6GRE creation and traffic remain unverified.

A refused entry binds nothing and is logged as an error naming the interface and reason, once per episode: unsupported link type, unsupported bond/bridge nesting or self-master, `vrf` device (configure a member; members of a VRF bind themselves), or `dae0`/`dae0peer`. The degradation reports it with reason `unsupported_type`; it never fails startup or prevents other entries from binding, even when it is the first resolved LAN or WAN entry. A bridge port of an unsupported type is skipped silently. A bond or team master takes its type from its current first port, so an InfiniBand bond is refused. ipvlan in L3S mode and a VLAN device with `reorder_hdr off` are unsupported combinations.

`IfaceWatcher` subscribes to link, address, and IPv4/IPv6 route events and also performs a 60-second reconciliation. If it cannot subscribe or register for polling, it keeps reconciling every 60 seconds without event notifications and reports the `iface_watch` degradation. It creates, updates, or drops the required LAN/WAN hooks as interfaces and default routes change. A changed topology immediately wakes health-backed outbound probing. Interface addresses remain observed for topology/ECS/health events, but startup, reload, and network events never synthesize gateway-address routing rules. Configure [explicit local rules](./routing.md#explicit-local-rules) when needed. Interface-list configuration changes themselves require restart. The startup sequence and the conditions that fail startup are in [Interface reconciliation](../design/datapath.md#interface-reconciliation).

Real LAN bindings also receive an advisory [self-protection coverage check](./routing.md#explicit-local-rules). An unconfirmed result warns without rejecting startup/reload or inserting routing rules.

## Dial modes

| Mode | Sniffing | Domain verification | Routing and dial behavior |
| ---- | -------- | ------------------- | ------------------------- |
| `ip` | No | Not applicable | Keep the original destination IP; do not sniff or re-run routing. |
| `domain` | Yes | The sniffed name must pass the destination-IP reality check. | A verified name may re-run routing; if no domain rule matches, normal IP/port rules still decide. Proxy outbounds may dial by the verified name. |
| `domain+` | Yes | No | Keep the initial IP-rule decision, but let proxy outbounds use the sniffed domain as their target. |
| `domain++` | Yes | No | Re-evaluate non-reserved decisions from the sniffed SNI/Host, then use the resulting proxy domain target. |

Direct, block, `must`, and other reserved handoffs remain final and keep the original IP target.

## Data directory and asset paths

`data_dir` defaults to `/var/lib/honk`, must be an absolute non-empty path, and is installed once for the process. At startup honk recursively creates it and verifies it with a private random create-new/remove probe. An unusable candidate falls back only to a process working directory that passes the same probe; startup fails and reports both causes when neither is usable. With `--store db` or enabled native API password login, startup refuses this fallback. The legacy root is `/var/share/honk` (`LEGACY_DATA_DIR`), used to retain existing artifacts. Legacy cache and subscription imports copy eligible state into `state/honk.db`. For a custom `data_dir`, the same fallback order applies. Absolute child paths remain unchanged.

`geoip.dat` and `geosite.dat` use the first existing regular file in this exact order:

1. `$DAE_LOCATION_ASSET/<name>`
2. `<data_dir>/<name>`
3. `/var/share/honk/<name>` (`LEGACY_DATA_DIR`)
4. `./<name>` in the process working directory
5. `/usr/local/share/honk/<name>`, then `/usr/share/honk/<name>`
6. `/usr/local/share/dae/<name>`, `/usr/share/dae/<name>`, then `/etc/dae/<name>`

Other relative runtime paths preserve legacy installations as follows. Except for logs, each lookup checks the existing configured-data-directory copy first, then an existing `/var/share/honk` copy, then the existing per-caller legacy candidate. If none exists, the path below `data_dir` is returned for creation. Absolute paths remain explicit.

| Path | Resolution and legacy fallback |
| ---- | ------------------------------ |
| Node `ech_config_path` | Prefer an existing `<data_dir>/<path>`, then an existing `/var/share/honk/<path>`, then an existing working-directory-relative path. If none exists, resolve to `<data_dir>/<path>` so the read error names the intended location. |
| `global.log_file` | Relative paths always resolve to `<data_dir>/<path>` via the creation-only path helper; parent directories are created at startup. Existing `/var/share/honk` logs are not read or migrated. Absolute paths remain explicit. On Linux, new logs are mode `0600`; symlinks and non-regular destinations are rejected, while permissions on an existing regular file are preserved. honk appends and rotates at 10 MiB: the file is renamed to `<name>.1`, replacing an older copy, and a new file is opened with the same checks, so the log takes at most 20 MiB. When two instances share the file during a restart handoff, only the one whose file is still at the path renames it; the other switches to the new file, so neither overwrites the other's copy. If a rotation fails, for example because the new file cannot be opened, honk stops rotating, keeps writing to the file it has up to 20 MiB, then drops log lines with one warning on stderr until restart. Timestamps on the console and in the file are the machine's local time with its UTC offset (`2026-09-12T02:30:15.123456+10:00`). |
| `experimental.cache_file.path` | No longer a storage location; state is kept in `<data_dir>/state/honk.db`. The first start reads it once, with the old resolution order, to import a legacy `cache.db` ([upgrade notes](./experimental.md#upgrading-from-cachedb)). |
| `experimental.clash_api.external_ui` | Prefer an existing `<data_dir>/<path>`, then an existing `/var/share/honk/<path>`, then an existing working-directory-relative directory. If none exists, use `<data_dir>/<path>` for the dashboard download. |
| Subscription store | Bodies live in `<data_dir>/state/honk.db`. Each start imports the enabled bodies from the first private legacy `.sub` found in `<data_dir>/.sub`, `/var/share/honk/.sub`, `./.sub`, and removes the copied files ([subscription reference](./subscription.md#fetch-persistence-and-recovery)). |

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
    data_dir: '/var/lib/honk'
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
