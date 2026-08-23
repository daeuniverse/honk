# Routing reference

`routing { ... }` defines ordered traffic matchers and their outbound targets.

## Rule grammar

```text
condition [&& condition ...] -> outbound[(must)]
fallback: outbound
```

- Rules have source-order priority: the parser assigns `priority` values `0, 1, ...`, and lower values run first. The first final match wins.
- `default:` is an alias of `fallback:`. The fallback target applies when no rule finalizes; if omitted, it defaults to `direct`.
- Comma-separated arguments inside a matcher are alternatives. Different populated condition groups must all match.
- A parenthesized argument list may span physical lines. The statement continues through its closing `)` and `-> outbound`.
- A leading `!` negates only the single matcher immediately following it. A rule matches when its positive conditions match and none of its negated matchers hits.
- An unknown or unsniffed domain counts as “not x” for a negated domain or geosite matcher. It does not veto that rule.

```dae
routing {
    sip(
        10.10.10.24/32,
        10.10.10.25/32
    ) && !dport(53) -> direct(must)
    default: proxy
}
```

## Condition functions

| Function | Accepted arguments | Internal `RoutingCondition` field |
| --- | --- | --- |
| `domain(...)` | Bare value or `suffix:` for a suffix; `keyword:` for a substring; `full:` for an exact name; `regex:` for a regular expression; `geosite:` for a geosite code | `domain_suffix`, `domain_keyword`, `domain`, `domain_regex`, `geosite` |
| `dip(...)` | Destination IP/CIDR; `geoip: code` | `ip`, `geo_ip` |
| `sip(...)` | Source IP/CIDR | `source_ip` |
| `dport(...)` | Destination port or inclusive `start-end` range | `port` |
| `sport(...)` | Source port or inclusive `start-end` range | `source_port` |
| `l4proto(...)` | `tcp`, `udp` | `protocol` |
| `pname(...)` | Executable basename from `argv[0]`, limited to 15 bytes; falls back to the calling thread's `comm` when argv access is unavailable | `process_name` |
| `mac(...)` | Source MAC address | `mac` |
| `ipversion(...)` | `4`/`ipv4`, `6`/`ipv6` | `ip_version` |
| `dscp(...)` | DSCP value | `dscp` |

Every positive field has a corresponding list under `RoutingCondition.not`; the parser sends `!matcher(...)` there. Within one field, listed values are alternatives.

## Outbound targets and `must`

| Target | Meaning |
| --- | --- |
| `direct` | Built-in direct outbound |
| `block` | Built-in blocking outbound |
| Group name | Resolve through that outbound group and its policy |
| Node name | Use that node directly |

Appending `(must)` gives Go dae-compatible must semantics. A matching must rule does not finalize the rule search; evaluation continues and propagates the must state to the resulting outbound. Clash `Global` and `Direct` modes never override a must result. They also never override `block`.

## Geo assets

`geoip:` and `geosite:` conditions use `geoip.dat` and `geosite.dat`. Their lookup order is:

| Priority | Location |
| --- | --- |
| 1 | `$DAE_LOCATION_ASSET/<file>` |
| 2 | `global.data_dir/<file>` |
| 3 | `./<file>` in the process working directory |
| 4 | `/usr/local/share/dae/<file>` |
| 5 | `/usr/share/dae/<file>` |
| 6 | `/etc/dae/<file>` |

See the [global reference](./global.md) for runtime asset resolution. `geoip: private` uses a built-in CIDR set and does not require `geoip.dat`.

A geosite code may select an attribute with `category@attr`. Attribute keys compare case-insensitively. Everything after the first `@` is the selector, including any later `@`. An unknown category or a selector matching no entries logs a warning, expands to zero matchers, and never matches.

## Automatic local rules

At startup, reload, and interface-topology changes, honk refreshes one generated rule for every address currently assigned to configured LAN and WAN interfaces:

```dae
dip(<each LAN/WAN interface address>) -> direct(must)
```

Addresses become host CIDRs (`/32` or `/128`). Missing interfaces and an unresolved `auto` interface are skipped. These rules keep gateway-local services such as SSH, the admin UI, and the Clash API reachable without making them depend on proxy health.

## Fail-closed behavior

When health checking marks an outbound dead, the eBPF datapath normally drops new flows routed to it with `TC_ACT_SHOT`; it never silently leaks them through `direct`. A TCP group with exactly one unique leaf and no `final` instead keeps that same proxy dialable as a last resort, so real traffic can prove recovery. UDP and all-dead multi-leaf groups remain fail-closed. Destination port `53` is exempt for both TCP and UDP so DNS can still reach the control plane.

For an outage-tolerant gateway:

- Add `dip(geoip: private) -> direct(must)` so private-network traffic does not depend on proxy health.
- Point `fallback:` at a [`fallback`-policy group](./groups.md) containing at least two nodes, not at one node.
- Keep at least one DNS upstream on a direct path.

## Full example

```dae
routing {
    domain(suffix: doubleclick.net) -> block
    pname(NetworkManager, systemd-resolved) && l4proto(udp) && dport(53) -> direct(must)
    dip(geoip: private) -> direct(must)
    sip(
        10.10.10.24/32,
        10.10.10.25/32
    ) && !dport(53) -> direct(must)
    mac(aa:bb:cc:dd:ee:ff) && ipversion(4) -> direct
    domain(
        full: api.example.com,
        suffix: example.org,
        keyword: tracker,
        regex: '^bad[0-9]+\.example$',
        geosite: category-games@cn
    ) -> proxy
    dip(geoip: cn, 203.0.113.0/24) && sport(1024-65535) && dscp(46) -> hk-1
    l4proto(tcp) && dport(80, 443, 8080-8090) -> proxy
    !domain(geosite: category-ads-all) && !dip(geoip: cn) -> resilient
    fallback: resilient
}
```

Here `proxy` and `resilient` are group names, while `hk-1` is a node name.

## Related docs

- [Routing design](../design/routing.md)
- [Global reference](./global.md)
- [Group reference](./groups.md)
