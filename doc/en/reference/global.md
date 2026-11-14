# Global configuration reference

`global { ... }` configures process-wide settings.

## Fields

The dae parser accepts some keys only for dae compatibility. honk stores these in `GlobalConfig`, but the current runtime does not consume them. The table marks each such key in its Meaning column.

| dae key | Internal field | Default | Meaning |
| ------- | -------------- | ------- | ------- |
| `tproxy_port` | `tproxy_port` | `12345` | TCP and UDP transparent-listener port programmed into the userspace listeners and eBPF datapath. Takes a decimal port; for other text, including hexadecimal, honk warns with `legacy-config-warning` and falls back to `12345`. A change requires restart. |
| `tproxy_port_protect` | `tproxy_port_protect` | `true` | Compatibility switch intended to prevent re-interception of the transparent port. The current runtime does not read it. A change requires restart. |
| `pprof_port` | `pprof_port` | `0` | Compatibility pprof HTTP port; `0` means disabled. honk currently starts no pprof server and does not read this field. honk warns and falls back to `0` when the value is not a decimal port. A change requires restart. |
| `so_mark_from_dae` | `so_mark_from_dae` | `0` (effective `0x100`) | Process-wide `SO_MARK` for honk-originated sockets and exact datapath bypass. A nonzero value replaces `0x100` instead of OR-ing with it; changing the setting requires restart. Bits `0xc8000000` are reserved and rejected. See [Socket marks](#socket-marks). |
| `log_level` | `log_level` | `"info"` | Startup log filter in `RUST_LOG` syntax, such as `info` or `'info,honk_core=debug'`. Blank text means `info`. A valid `RUST_LOG` takes precedence, followed by `--debug`, then this value. A SIGHUP change is restart-required; a native API `log.level` PATCH replaces the filter until the next activation. `info` covers runtime state: startup, reloads, health and subscriptions. The per-connection routing lines (`TCP connection`, `UDP connection`, eBPF offload) are `debug`, so a router's syslog is not flooded by traffic. To audit routing decisions, run with `debug` or read `/logs?level=debug` from the API. |
| `log_file` | `log_file` | `""` | Optional append-only log path. Empty or whitespace-only text disables file output; a relative path resolves below `data_dir`. Console logging remains enabled. SIGHUP requires restart only when the resolved effective destination changes; `--log-file` shadows this value. |
| `syslog_addr` | `syslog_addr` | `""` | Numeric TCP syslog destination with port, for example `192.0.2.10:514` or `[2001:db8::10]:514`. Required when DNS audit is enabled; then anything other than a unicast IP with a nonzero port fails validation with `invalid-config-value`. Restart required. |
| `syslog_dns_enabled` | `syslog_dns_enabled` | `false` | Requires the `dns-syslog` Cargo feature. Send client DNS outcomes as fixed RFC 5424 messages with a JSON body over persistent TCP with RFC 6587 octet counting. Independent of native API/history and log level. Bounded batching and reconnect backoff; no application acknowledgment or disk persistence. See [DNS audit](../design/dns-syslog.md). Restart required. |
| `syslog_cee_enabled` | `syslog_cee_enabled` | `false` | Prefix the fixed JSON body with `@cee: ` for receivers that support CEE, such as VictoriaLogs. Leave false for ordinary JSON. Does not enable auditing or compile the feature. Restart required. |
| `syslog_hostname` | `syslog_hostname` | `""` | Syslog sender hostname in the RFC 5424 header only. Empty reads the system hostname once at startup, falling back to `-`. Explicit values must be 1–255 printable ASCII bytes without spaces, even when DNS audit is disabled. Restart required. |
| `syslog_app_name` | `syslog_app_name` | `"honk"` | Application name in the RFC 5424 header only; 1–48 printable ASCII bytes without spaces, even when DNS audit is disabled. Restart required. |
| `disable_waiting_network` | `disable_waiting_network` | `false` | Compatibility key; the current startup path does not read it. Unresolved `auto` interfaces already remain pending without blocking startup. |
| `shutdown_wait_connections` | `shutdown_wait_connections` | `false` | Reloadable opt-in business-connection grace; see [Shutdown](#shutdown). |
| `lan_interface` | `lan_interface` | `[]` | Comma-separated LAN interfaces on which forwarded traffic is intercepted. Empty installs no LAN hooks. See [Interface semantics](#interface-semantics). |
| `wan_interface` | `wan_interface` | `[]` | Comma-separated WAN interfaces whose hooks intercept host-originated TCP and UDP. The literal `auto` follows the lowest-metric IPv4 default route. See [Interface semantics](#interface-semantics). |
| `auto_config_kernel_parameter` | `auto_config_kernel_parameter` | `false` | Compatibility switch for automatic sysctl setup. A change requires restart. The runtime does not branch on this field; the real datapath applies its fixed best-effort sysctl setup. That setup pins `net.ipv6.conf.all.forwarding=1`, so it also writes `net.ipv6.conf.<wan>.accept_ra=2` for every WAN root interface, including one that is also a LAN interface. The write happens as soon as the interface appears in the interface topology, at startup or later, without waiting for its hooks or for the link to come up. An SLAAC/RA-learned IPv6 default route therefore survives the forwarding pin. The setup also writes `net.ipv4.conf.<lan>.rp_filter=0` for the first resolved LAN name that exists and is not refused, as configured and not canonicalized. Each value is written again about one second later, because udev's `systemd-sysctl` run for a newly added device restores the distribution default right after the first write. After that, honk leaves it alone until the device is recreated. Hosts running systemd-networkd should prefer the explicit `IPv6AcceptRA=yes` in the WAN `.network` file. |
| `nfqueue_enable` | `nfqueue_enable` | `true` | Hold ambiguous LAN-forwarded UDP originals in NFQUEUE until userspace reaches a terminal decision. The setting requires the real eBPF backend. After the singleton instance handoff, honk logs a warning and disables the setting for the process, without rewriting the config, when the fixed queue is unavailable or a pre-admission queue, rules or health check fails. Persistent token-generation recovery failures remain fatal. Installing the queue reclaims the reserved nftables table. Changing it requires a restart, except after an actual startup downgrade (see below). New configurations should use this key. The deprecated `experimental.udp_nfqueue.enabled` spelling is accepted with a migration warning, and this canonical key wins when both are present. |
| `data_dir` | `data_dir` | `"/var/lib/honk"` | Absolute, non-empty root for generated state and relative runtime assets. Missing directories are created recursively, and each candidate must pass a private create-new/remove probe. An unusable candidate falls back to the equally probed working directory, except with `--store db` or enabled native API password login. Existing artifacts under the legacy `/var/share/honk` (`LEGACY_DATA_DIR`) root remain usable through the path-specific fallback rules below. Legacy cache and subscription imports instead copy eligible state into `state/honk.db`. A change requires restart. |
| `store_subscribe` | `store_subscribe` | `true` | Persist each last valid subscription body in the state db, `data_dir/state/honk.db`, for startup recovery only; reload carries active nodes without reading stored bodies. A change requires restart. |
| `tcp_check_url` | `tcp_check_url` | `["https://www.gstatic.com/generate_204"]` | Comma-separated TCP/HTTP health-check URLs. The health loop uses the first value; a missing or empty first value falls back to a plain TCP check. Only `http://`, `https://` and schemeless URLs work. Another scheme or port `0` still loads, but every HTTP probe fails as an invalid request. URI parsing separates userinfo, bracketed IPv6, port, path, query and fragment. Userinfo adds no authorization header. Path and query are sent without the fragment, including `/?query` for a slashless query. Explicit HTTP/HTTPS default to 80/443; schemeless health targets use HTTP/80. URLTest defaults schemeless targets to HTTPS/443 and sends HEAD to the decoded path/query. The first URL is also the Score QUIC probe target; see [Reloading health checks and TLS mode](#reloading-health-checks-and-tls-mode). |
| `tcp_check_http_method` | `tcp_check_http_method` | `"HEAD"` | HTTP method sent by the URL health check, such as `HEAD` or `GET`. An empty value is treated as `HEAD`; an invalid method makes every HTTP probe fail as an invalid request. |
| `udp_check_dns` | `udp_check_dns` | `["dns.google:53", "8.8.8.8", "2001:4860:4860::8888"]` | Comma-separated DNS targets for UDP health checks. Bare IPv4/IPv6, `[IPv6]`, and hostnames default to port `53`; explicit ports must be numeric and in `1..65535`. Malformed brackets or ports fail validation with a located diagnostic. The first literal wins over domain entries; otherwise the first domain is resolved. Resolution and Score use the same decoded host/port, retaining domain identity after resolution. |
| `check_interval` | `check_interval_secs` | `30s` | Global health-check interval in whole seconds. Takes an integer, bare or with `s`, `m` or `h`; `ms` values round up to a whole second (`500ms` becomes `1s`), and `1.5s` is invalid. Must be positive; a value that fails to parse becomes zero and is rejected at validation. The UDP warm coordinator also uses it, with an effective minimum of 10 seconds. |
| `check_tolerance` | `check_tolerance_ms` | `50ms` | Latency improvement required before URLTest changes its selected member, in whole milliseconds. Accepts bare milliseconds, an integer with `ms`, or `s`, including zero; fractions of a millisecond are truncated, so `0.0005s` becomes `0ms` and `0.5ms` is invalid. Anything else keeps this default and logs a warning. |
| `dial_mode` | `dial_mode` | `"domain"` | Destination-domain discovery and routing mode: `ip`, `domain`, `domain+`, or `domain++`. Spellings are case-insensitive. Unknown names reject validation with `invalid-config-value`. See [Dial modes](#dial-modes). |
| `allow_insecure` | `allow_insecure` | `false` | Compatibility global TLS-verification fallback. Current TLS connectors do not read it; certificate skipping is configured per node in its share link. |
| `sniffing_timeout` | `sniffing_timeout_ms` | `30ms` | Compatibility sniffing timeout, currently unused by the control plane. Duration syntax and invalid-value handling match `check_tolerance`. |
| `tls_implementation` | `tls_implementation` | `"tls"` | `utls`, in any letter case, enables honk's Chrome-oriented ClientHello emulation, not exact browser identity. Every other value, including empty text and misspellings, selects the regular BoringSSL client profile without an error or warning. |
| `utls_imitate` | `utls_imitate` | `"chrome_auto"` | Compatibility fingerprint request. The `utls` mode uses one Chrome-oriented profile; this value does not switch profiles. A value that is not empty and does not start with lowercase `chrome` logs a warning at startup. |
| `tls_fragment` | `tls_fragment` | `false` | Compatibility TLS ClientHello-fragmentation switch. The current TLS connector does not read it. |
| `tls_fragment_length` | `tls_fragment_length` | `""` | Compatibility fragmentation-length range. The current TLS connector does not read it. |
| `tls_fragment_interval` | `tls_fragment_interval` | `""` | Compatibility fragmentation-interval range. The current TLS connector does not read it. |
| `mptcp` | `mptcp` | `false` | Compatibility MPTCP switch. The current dial path does not read it. |
| `bootstrap_resolver` | `bootstrap_resolver` | `""` | Marked UDP/TCP resolver for node hostnames and control-plane dials. Takes a numeric IP with port: `223.5.5.5:53`, `udp://223.5.5.5:53`, `tcp://223.5.5.5:53` or `[2001:4860:4860::8888]:53`. Only `tcp://` selects TCP; any other scheme, such as `tls://`, means plain UDP. A hostname or missing port disables the resolver without an error. Empty or failed bootstrap resolution uses `/etc/hosts`, then marked DNS to the first numeric `/etc/resolv.conf` nameserver; no libc NSS or search suffixes. The same address, without its scheme, is the target of the periodic `direct` health check, which falls back to `223.5.5.5:53`. A DNS [`subtag()` rule](./dns.md#node-server-hosts) can claim a subscription's node hostnames instead. |
| `fallback_resolver` | `fallback_resolver` | `"8.8.8.8:53"` | Compatibility fallback-resolver value. The current runtime does not read it. |
| `bandwidth_max_tx` | `bandwidth_max_tx` | `""` | Compatibility transmit-bandwidth hint, such as `'200 mbps'`. The current runtime does not read it. |
| `bandwidth_max_rx` | `bandwidth_max_rx` | `""` | Compatibility receive-bandwidth hint. The current runtime does not read it. |
| `preconnect_node_count` | `preconnect_node_count` | `'auto'` | Number of eligible bare-TCP nodes warmed once at startup; `0` disables it and `'auto'` selects at most eight. |
| `udp_warm_node_count` | `udp_warm_node_count` | `0` | Per-group UDP warm-candidate count. `0` disables the independent UDP warm coordinator. |
| `max_concurrent_dials` | `max_concurrent_dials` | `64` | Requested generation-local cap on physical proxied connects and protocol handshakes; runtime resource budgeting may clamp it. |
| — (not settable in dae syntax) | `tproxy_mark` | `0x08000000` | Fixed fwmark shared by userspace policy routing and the compiled eBPF datapath. |
| — (not settable in dae syntax) | `udphop_interval_secs` | `30s` | Legacy global UDP-hop interval. Current dialers do not read it; protocol-specific hopping uses node fields. |
| — (not settable in dae syntax) | `connect_timeout_ms` | `3000ms` | Stage timeout used by proxy connects, protocol preparation, preconnect, health probes, and control-plane dials. Transparent TCP candidate races and UDP transport preparation also share an absolute budget of `max(10s, 4 × connect_timeout)`; this adds no configuration key. |
| — (not settable in dae syntax) | `dns_resolve_timeout_ms` | `2000ms` | Timeout for control-plane DNS resolution, including targets that must be converted to an IP before dialing. |
| — (not settable in dae syntax) | `relay_idle_timeout_secs` | `300s` | Legacy relay-idle timeout field. The current relay path does not read it. |

`syslog_dns_template` and `syslog_dns_json` were removed because DNS syslog uses a fixed JSON schema. Either key rejects the configuration with `removed-config-setting`, whatever its value; delete it.

`[]` in the Default column means an empty list; dae has no list literal, and `lan_interface: []` creates an interface named `[]`. Clear an interface list with `lan_interface: ''` or `wan_interface: ''`. `tcp_check_url: ''` keeps one empty item, which disables HTTP probing.

Quote `tcp_check_url` and `udp_check_dns` items one by one or leave them bare. Quoting the whole list, as in `'dns.google:53,8.8.8.8'`, still works but warns with `legacy-quoted-list`.

If a write or reload requests `nfqueue_enable: true` while effective NFQUEUE stays disabled, honk accepts it only after an actual downgrade. A request that omits the key counts too, because its default is `true`. The downgrade is either an early startup downgrade (mock/no-`ebpf` or failed fixed-queue preflight) or a late queue, rules or health downgrade before datapath admission. The requested source stays unchanged, but effective `false` persists for the process lifetime. Nothing retries activation automatically, so a restart is required to try again. Without that downgrade, toggles remain restart-only. [Common reload normalization](../design/control-plane.md#reload-and-runtime-generations) runs before fingerprint/no-op checks; native pre-write checks and full validation share the same restart policy. Persistent token-generation recovery failures and [post-admission failures](../design/nfqueue.md#activation-and-scope) remain fatal.

`nfqueue_enable` also controls [fragmented LAN UDP/53 delivery](../design/nfqueue.md#fragmented-lan-dns): controller/raw-group fragments require ready NFQUEUE and otherwise drop, without bypassing DNS policy. Native `direct(must)` and unfragmented DNS are unchanged.

HTTP health checks and URLTest send a credential-free authority in `Host`: IPv6 stays bracketed, and non-default ports are retained. Connection and TLS server-name handling use the unbracketed host.

The configured request path and query retain their original dot segments and percent-encoding. URLs with surplus authority slashes, backslashes, or embedded ASCII whitespace/control characters are rejected before building a request. A rejected URL is not echoed in the health-check warning.

HTTP probes count any final status `200–499` as success, so a redirect or `404` passes. Response headers over 16 KiB, or incomplete headers, fail the probe.

## Shutdown

Setting `shutdown_wait_connections: true` gives accepted connections up to five seconds to finish on an ordinary, healthy shutdown with an active runtime epoch. honk then closes and joins the remaining connections. Other cases skip this grace, which does not distinguish short and long connections.

Shutdown uses the latest accepted configuration; rejected reloads preserve the previous value. The flag does not change reload retirement, DNS/state persistence, NFQUEUE/eBPF cleanup or the native API's independent [five-second HTTP grace](./api.md#native-api).

This is neither a graceful restart nor a total exit deadline: [owned cleanup and blocking work](../design/control-plane.md#runtime-teardown) still have to finish.

## Socket marks

`so_mark_from_dae: 0` (or omission) retains the historical effective mark `0x100`.
honk applies a nonzero value exactly before connect/send, including proxy carriers,
bootstrap/DNS traffic, health checks, subscriptions and UI downloads. The datapath
bypass compares this exact configured value: merely containing bit `0x100` is not
an exemption. Transparent listeners use the same mark for socket recognition;
accepted TCP client sockets have it cleared. Standalone `dns.bind` ingress stays
an ordinary unmarked local service.

The dae global scalar keeps honk's hexadecimal-first lexical parsing: `10` and `0x10`
both mean 16. Malformed or overflowing text produces a diagnostic and falls back to
raw `0`, hence effective `0x100`. Prefer explicit `0x` notation.
This differs from [direct rule marks](./routing.md#policy-routing-marks), where
unprefixed values are decimal and malformed values reject the configuration.
Validation rejects the reserved bits `0xc0000000` for both global and rule marks. For the global mark it also rejects the TPROXY bit `0x08000000`, which daens routes to its local listeners.

honk captures the setting before startup network I/O, and the value is
process-scoped; use a restart, not SIGHUP, to change it. A nonzero direct-rule
mark replaces the global mark for that direct flow's policy-routing payload,
while proxy carriers and bootstrap traffic keep the global value. Direct traffic
also carries internal classification metadata; use the masked IPv4/IPv6 `ip rule`
examples in the [routing reference](./routing.md#policy-routing-marks). honk does
not install WAN policy tables, routes, source-address rules or NAT configuration.

## Reloading health checks and TLS mode

honk captures these inputs at startup. It rejects a reload that changes their effective values, preserving the active configuration and installed probes:

- `check_interval`.
- The first `tcp_check_url`, including its fallback, path, and query text. A missing or empty first value disables HTTP probing; later values do not affect this comparison.
- `tcp_check_http_method` while HTTP probing is enabled. Empty and `HEAD` are equivalent.
- The selected `udp_check_dns` target: trim and ignore empty entries, prefer the first IP literal anywhere in the list, otherwise use the first domain, otherwise `8.8.8.8:53`. Admission compares configured address/domain and port, without resolving DNS. Domains compare case-insensitively and ignore one trailing dot, so `dns.example:53` and `DNS.EXAMPLE.:53` are the same target. Changes to unselected entries remain admissible.
- Switching `tls_implementation` between native TLS and uTLS. The `utls` comparison is case-insensitive.

DAE `check_tolerance` still updates URLTest group tolerances on reload. Group-specific check URLs and direct checks retain their existing live-update paths. Reloading `utls_imitate` stores the compatibility value but does not change the fingerprint.

Score groups also run a QUIC handshake probe against the first `tcp_check_url`. It needs a URL starting with lowercase `https://`; otherwise the probe is off, Score uses its other probes, and the `quic_probe` degradation reports it. The QUIC target is built only at startup, so a reload that adds the first Score group reports reason `restart_required` until the next restart.

honk starts UDP DNS target initialization at startup, within the health-check
timeout. A local refusal or an initialization timeout leaves the configured
target pending for a later health cycle. There is no default substitution and no
node-health penalty, and independent QUIC checks can continue. The first
successfully resolved address stays pinned. Deferred resolution and the DNS
exchange share one probe deadline. Ordinary resolution failures keep the
existing default fallback.

## Traffic entry and interception

honk receives traffic through eBPF TC hooks on the configured interfaces, not through a proxy port that clients connect to.

- `lan_interface` hooks intercept traffic that LAN clients send through the host, for example clients that use it as their gateway.
- `wan_interface` hooks intercept TCP and UDP that the host itself originates.
- The datapath sends flows that need userspace handling through `dae0` into the `daens` namespace. There, `sk_lookup` assigns them to the transparent TCP or UDP listener on `tproxy_port`. NFQUEUE staging (`nfqueue_enable`) holds ambiguous LAN-forwarded UDP instead.
- Interception requires the real eBPF backend; the mock backend intercepts nothing.

honk has no TUN inbound, no `mixed-port`, no `redir-port`, and no HTTP or SOCKS inbound. The Clash API's `GET /configs` reports `port`, `socks-port` and `mixed-port` as `0` and `tun.enable` as `false`. Besides the transparent listeners, honk listens only on the optional [`dns.bind`](./dns.md#standalone-listener-bind) address and on the API listeners configured in [`experimental`](./experimental.md). The [packet walk](../design/overview.md#packet-walk) follows a flow through the hooks.

## Interface semantics

An empty `lan_interface` is literal: honk installs no LAN TC hooks and never substitutes `lo`. A WAN-only gateway therefore uses only `wan_interface`; host-originated TCP and UDP that traverse those WAN hooks are still proxied, while no synthetic LAN interception is added.

Use `lan_interface: 'eth0', 'eth1'` for multiple interfaces; the same syntax applies to `wan_interface`. Quoting the entire comma-separated list, as in `lan_interface: 'eth0,eth1'`, creates one interface name, not two.

On an Ethernet parent, frames with a non-zero VLAN ID belong to the VLAN device; list `eth1.20` (or `br0.N` on a VLAN-aware bridge) to manage that subnet. The VLAN-aware bridge topology has not been verified by the real-traffic tests. See [Interface hook sets](../design/datapath.md#interface-hook-sets).

`auto` resolves to the interface that owns the lowest-metric IPv4 default route. The `auto` keyword is trimmed and ASCII case-insensitive in every consumer, so `AUTO`, ` auto ` and a whitespace-only entry all count. The `.dae` list parser drops a truly empty item, so an empty list still means no interfaces. If no such route exists, that entry stays pending (never `lo`) until a default route appears. Explicitly named interfaces in the same list continue to work. honk reads the routing table only when an entry is `auto`. An unreadable table is an error, not "no default route": it fails startup, and a failure later in the run leaves the bindings as they were.

honk binds an interface as soon as it exists; `IFF_UP` is not required. Roles are per interface (see [Interface hook sets](../design/datapath.md#interface-hook-sets)), so a shared LAN/WAN interface does not change the hooks of the other LAN interfaces. A member of a bond, bridge or other master is bound through that master, except `vrf` and `openvswitch` members, which stay themselves. A LAN bridge also binds its ports in the LAN role. Bond hooks stay on the logical master, never its members.

honk binds each configured entry lazily, and a binding failure never fails startup. Three cases bind nothing and leave traffic unintercepted until binding succeeds: an interface that does not exist yet, an `auto` entry without a default route, and a refused link type (below). If a TCX link cannot be created, updated or verified, the entry can stay only partly bound, so the hooks that work may still intercept traffic. The `interface_binding` [degradation](./api.md#native-api) reports either case, and `lifecycle.state` stays `running`, so monitoring must read that degradation. Only the kernel's primary interface name matches; an altname is treated as absent. honk binds a device that appears, releases the hooks of a device that disappears, and binds again a device that is recreated with a new interface index. A `dns.bind` address that belongs to an interface that does not exist yet is not an interface entry: binding it still fails startup (`EADDRNOTAVAIL`).

The link type chooses the program family:

| Link type (`ifi_type`) | Framing |
| --- | --- |
| Ethernet: eth, bond/team (while their first port is Ethernet), bridge, vlan, macvlan/macvtap, ipvlan, veth, netkit, vxlan, geneve, gretap, tap, dummy, macsec | `_l2` |
| `ARPHRD_NONE` (wireguard, tun, `collect_md` GRE, geneve/VXLAN-GPE in no-MAC mode), PPP, RAWIP, IPIP, IP6TNL, SIT | `_l3` |
| GRE / IP6GRE | `_l3` only when `IFF_POINTOPOINT` is set and `IFF_BROADCAST` is not; otherwise refused |
| `lo`, `vcan`, InfiniBand, 802.15.4, nlmon, and every other type | refused |

The table describes the classifier, not a verified-device support matrix. The IPv4 GRE and `collect_md` GRE kernel tests inspect flags and TCX hooks, not tunnel payload forwarding. Real IP6GRE, IPIP, SIT, IP6TNL, PPP, RAWIP, tun and wireguard devices are unverified by this change; GRE and all of these L3/NONE families also lack end-to-end traffic coverage.

An `_l3` program parses an Ethernet header instead of bare IP when two things hold. The kernel reports the network header 14 bytes into the frame, and bytes 12–13 match the packet's protocol. This happens on a device set up as Ethernet and then retyped, for example to RAWIP. A frame whose linear head exceeds 65550 bytes is still parsed as bare IP. Bare IP sent through an AF_PACKET raw socket on an L3 bond is misread as Ethernet when its source-address bytes equal the EtherType; such a sender needs `CAP_NET_RAW`, which already permits setting honk's bypass mark. Kernel tests cover a TAP retyped to RAWIP, not real modem hardware.

IP6GRE with a unicast remote but no explicit local address may lack `IFF_POINTOPOINT` and is refused even when its packets would be bare IP. Changing an existing IP6GRE device with `ip link change` is unsupported: the kernel can change the point-to-point flags without clearing `header_ops`, so the flags can make this classifier select `_l3` while a tunnel header remains. Delete and recreate the tunnel rather than changing it in place; IP6GRE creation and traffic remain unverified.

A refused entry binds nothing. honk logs one error per episode, naming the interface and the reason: unsupported link type, unsupported bond/bridge nesting or self-master, a `vrf` device (configure a member; members of a VRF bind themselves), or `dae0`/`dae0peer`. The degradation reports reason `unsupported_type` and never fails startup, even when the refused entry is the first resolved LAN or WAN entry; other entries still bind. A bridge port of an unsupported type is skipped silently. A bond or team master takes its type from its current first port, so an InfiniBand bond is refused. ipvlan in L3S mode and a VLAN device with `reorder_hdr off` are unsupported combinations.

`IfaceWatcher` subscribes to link, address, and IPv4/IPv6 route events and also runs a 60-second reconciliation. If it cannot subscribe or register for polling, it keeps reconciling every 60 seconds without event notifications and reports the `iface_watch` degradation. It creates, updates, or drops the required LAN/WAN hooks as interfaces and default routes change. A changed topology immediately wakes health-backed outbound probing. honk still observes interface addresses for topology/ECS/health events, but startup, reload and network events never synthesize gateway-address routing rules. Configure [explicit local rules](./routing.md#explicit-local-rules) when needed. Interface-list configuration changes themselves require a restart. The startup sequence and the conditions that fail startup are in [Interface reconciliation](../design/datapath.md#interface-reconciliation).

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

`data_dir` defaults to `/var/lib/honk`, must be an absolute non-empty path, and is installed once for the process. At startup honk creates it recursively and verifies it with a private random create-new/remove probe. If the candidate is unusable, honk falls back only to a process working directory that passes the same probe. When neither works, startup fails and reports both causes. With `--store db` or enabled native API password login, startup refuses this fallback. The legacy root is `/var/share/honk` (`LEGACY_DATA_DIR`), kept so existing artifacts stay usable. Legacy cache and subscription imports copy eligible state into `state/honk.db`. A custom `data_dir` follows the same fallback order. Absolute child paths remain unchanged.

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
| `global.log_file` | Relative paths always resolve to `<data_dir>/<path>` through the creation-only path helper, and parent directories are created at startup. Existing `/var/share/honk` logs are not read or migrated. Absolute paths remain explicit. On Linux, new logs are mode `0600`; symlinks and non-regular destinations are rejected, while permissions on an existing regular file are preserved. honk appends and rotates at 10 MiB. It renames the file to `<name>.1`, replacing an older copy, and opens a new file with the same checks, so the log takes at most 20 MiB. When two instances share the file during a restart handoff, only the one whose file is still at the path renames it; the other switches to the new file, so neither overwrites the other's copy. If rotation fails, for example because the new file cannot be opened, honk stops rotating. It keeps writing to the file it has up to 20 MiB, then drops log lines with one warning on stderr until restart. Timestamps on the console and in the file are the machine's local time with its UTC offset (`2026-09-12T02:30:15.123456+10:00`). |
| `experimental.cache_file.path` | No longer a storage location; state is kept in `<data_dir>/state/honk.db`. The first start reads it once, with the old resolution order, to import a legacy `cache.db` ([upgrade notes](./experimental.md#upgrading-from-cachedb)). |
| `experimental.clash_api.external_ui` | Prefer an existing `<data_dir>/<path>`, then an existing `/var/share/honk/<path>`, then an existing working-directory-relative directory. If none exists, use `<data_dir>/<path>` for the dashboard download. |
| Subscription store | Bodies live in `<data_dir>/state/honk.db`. Each start imports the enabled bodies from the first private legacy `.sub` found in `<data_dir>/.sub`, `/var/share/honk/.sub`, `./.sub`, and removes the copied files ([subscription reference](./subscription.md#fetch-persistence-and-recovery)). |

## Warm-up and dial budget

`preconnect_node_count`, `udp_warm_node_count` and `max_concurrent_dials` take nonnegative integers such as `4`; `preconnect_node_count` also takes `auto` in any letter case. Anything else rejects the configuration with `invalid-config-value`.

| Key | Default | Runtime semantics | Details |
| --- | ------- | ----------------- | ------- |
| `preconnect_node_count` | `'auto'` | One startup-only bare-TCP pass. `'auto'` selects at most eight eligible nodes and runs four attempts concurrently; explicit `N` selects up to `N` and runs at most `min(N, 8)` concurrently. Current group picks come first, then node configuration order. `0` disables it. | [Group design](../design/groups.md) |
| `udp_warm_node_count` | `0` | `0` disables it. Positive `N` ranks the top `min(N, 3)` reusable UDP leaves per group and IP family, deduplicates them, and retains at most `4 × N` globally. Up to four attempts run concurrently. The first pass starts immediately; later passes wait `max(check_interval, 10s)` after each completed batch, or start sooner when a group selection changes. | [Group design](../design/groups.md) |
| `max_concurrent_dials` | `64` | Bounds physical proxied connects and handshakes per generation, with a minimum effective value of one and an additional file-descriptor-derived ceiling shared across overlapping reload generations. The effective value never exceeds `1024`; larger values are accepted and clamped. Ready-pool hits, logical streams on warm transports, and `direct`/`block` do not consume permits. | [Group design](../design/groups.md) |

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
    udp_check_dns: 'dns.google:53', '8.8.8.8', '2001:4860:4860::8888'
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
