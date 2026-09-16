# Routing reference

`routing { ... }` defines ordered traffic matchers and their outbound targets.

## Rule grammar

```text
condition [&& condition ...] -> outbound[(must)]
fallback: outbound
```

- Rules are evaluated by ascending `priority`; lower values run first. Equal priorities retain stable source order. The dae parser assigns `priority` values `0, 1, ...` in source order. honk does not insert local-interface routing rules.
- `default:` is an alias of `fallback:`. The fallback target applies when no rule finalizes; if omitted, it defaults to `direct`.
- Comma-separated arguments inside a matcher are alternatives. Different populated condition groups must all match.
- A parenthesized argument list may span physical lines within one source file. The statement continues through its closing `)` and `-> outbound`; an included file cannot finish another file's unfinished call.
- Single or double quotes protect every interior byte, including whitespace, `#`, braces, `,`, `)`, `&&`, and `->`. Quotes open at the start of a token or immediately after an unquoted `(` or `,`; a prefixed argument may quote its value in a separate token, as in `domain(full: 'example.com')`. Backslashes are preserved, not decoded. An opened quote must close on the same physical line; otherwise the configuration fails with `unterminated-quote`.
- A leading `!` negates only the single matcher immediately following it. A rule matches when its positive conditions match and none of its negated matchers hits.
- An unknown or unsniffed domain counts as “not x” for a negated domain or geosite matcher. It does not veto that rule.
- Unknown nonempty predicates, whitespace before matcher parentheses, and trailing matcher text reject the configuration with a located diagnostic. Unsupported nonempty terms are never removed from a conjunction. Existing empty traffic-term and empty-argument behavior is unchanged.
- An unquoted token-head `#` starts a comment; a glued `#` is data. `domain(x) -> proxy#c` targets the literal name `proxy#c` and emits `legacy-glued-hash`. Write `-> proxy # comment` for a comment. The first unquoted arrow separates the action; later arrows remain target data with `legacy-arrow-target`.

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
| `pname(...)` | Substring patterns normalized to 15 bytes, matched against the executable basename from `argv[0]`; when runtime BTF offsets or verifier-safe kernel argv access are unavailable, the cgroup hook uses the calling thread's `comm` synchronously | `process_name` |
| `mac(...)` | Source MAC address | `mac` |
| `ipversion(...)` | `4`/`ipv4`, `6`/`ipv6` | `ip_version` |
| `dscp(...)` | Decimal or `0x`/`0X`-prefixed hexadecimal DSCP value | `dscp` |

Every positive field has a corresponding list under `RoutingCondition.not`; the parser sends `!matcher(...)` there. Within one field, listed values are alternatives.

Ordinary domain pattern/suffix/keyword alternatives share one condition. When the
same rule also populates `geosite`, that field remains a separate AND-ed condition.

A matching `mac(...) -> direct(must)` can exempt a client from transparent DNS; ordinary `direct` does not. LAN/WAN TCP/UDP destination port `53` evaluates the normal ordered traffic policy once after existing ingress and control-plane exclusions, not a separate must-only scan. LAN port `53` skips local-socket probing, even when dnsmasq or `dns.bind` listens on the destination.

## Outbound targets and `must`

| Target | Meaning |
| --- | --- |
| `direct` | Built-in direct outbound |
| `block` | Built-in blocking outbound |
| Group name | Resolve through that outbound group and its policy |

Bare node names are not valid outbound targets: `Config::validate` rejects them. Wrap the node in a group (for example `filter: name('node')`) and reference the group instead. A group and a node also may not share a name. A configuration may define at most 250 top-level user groups; higher routing ordinals are reserved by the ABI.

Appending `(must)` makes a matched result terminal and skips sniffing and later domain rerouting (`no_sniff` semantics). It preserves the selected direct, block, or group action; it is not a blanket bypass of honk. Clash `Global` and `Direct` modes never override a must result or `block`. It is not the historical internal `MustRules` opcode that continued scanning.

For TCP/UDP destination port `53`, traffic-rule ownership is:

| Ordered policy result | DNS ownership |
| --- | --- |
| `direct(must)` | Native Linux path, including the configured skb mark; no transparent honk DNS interception. A targeted local resolver can receive the query normally. |
| `block(must)` | Drop. |
| `group(must)` | Carry the original TCP/UDP through the group's normal raw transport, bypassing `DnsController`, cache, hosts, request/response policy, and routing projection. |
| Any non-`must` result, including ordinary `block` | Valid DNS queries enter `DnsController`; Clash Direct-mode offload cannot take this ownership. |

Malformed non-`must` UDP53 payloads retain the generic UDP fallback rather than entering `DnsController`; the controller row is not a claim that every port-53 payload is DNS. Route-metadata admission follows the [TCP/UDP distinction](../design/control-plane.md#transparent-ingress).

LAN local-socket precedence applies only to non-53 destinations, independently per transport; wildcard ownership also requires full FIB `NOT_FWDED`, and the non-DNS TCP pure-SYN probe skip remains. Bound `:53` sockets cannot preempt the policy results above. See [DNS ownership](../design/dns.md#dns-ownership-state-machine) for transparent LAN versus native/loopback delivery.

## Geo assets

`geoip:` and `geosite:` conditions use `geoip.dat` and `geosite.dat`. The engine selects the first existing regular file in this order:

| Priority | Location |
| --- | --- |
| 1 | `$DAE_LOCATION_ASSET/<file>` |
| 2 | `global.data_dir/<file>` |
| 3 | `/var/share/honk/<file>` (`LEGACY_DATA_DIR`) |
| 4 | `./<file>` in the process working directory |
| 5 | `/usr/local/share/honk/<file>` |
| 6 | `/usr/share/honk/<file>` |
| 7 | `/usr/local/share/dae/<file>` |
| 8 | `/usr/share/dae/<file>` |
| 9 | `/etc/dae/<file>` |

See the [global reference](./global.md) for runtime asset resolution. `geoip: private` uses a built-in CIDR set and does not require `geoip.dat`.

When a referenced geo asset cannot be found, the engine logs a warning naming the missing file. Unused assets do not produce missing-file warnings.

A geosite code may select an attribute with `category@attr`. Attribute keys compare case-insensitively. Everything after the first `@` is the selector, including any later `@`. An unknown category or a selector matching no entries logs a warning, expands to zero matchers, and never matches.

## Explicit local rules

honk no longer injects interface-address `direct(must)` rules at startup, SIGHUP/reload, or network events. There is no hidden kernel replacement allowlist: native `.dae` rule order stays user-authored. Local interface addresses remain observed for topology, ECS, and health events, not synthesized routing rules. If gateway management should stay native independently of proxy health, add an explicit rule at the intended position, for example:

```dae
dip(192.168.50.1, fd00:50::1) && !dport(53) -> direct(must)
```

This is optional user configuration, not an inserted rule. It leaves port `53` available for transparent DNS unless another terminal `must` result takes ownership. Existing non-53 local-socket ownership remains a pre-routing exclusion, including the non-DNS TCP pure-SYN probe skip; there is no unconditional gateway-management reachability guarantee without explicit routing.

With real LAN bindings, honk warns when the compiled rule order cannot confirm
unconditional `direct(must)` coverage for the observed addresses of configured
LAN/WAN interfaces, for TCP and UDP destination ports `1–65535` except `53`.
Checks run at startup, after a successful traffic-policy change, and on observed
network changes; no-op and node-only reloads do not repeat the policy check.
Missing interfaces and unavailable addresses are reconsidered when discovered.
This is advisory: startup, reload, explicit blocking and routing order are unchanged.
Source/domain/process-dependent rules and split port coverage can be intentional
and still produce an “unconfirmed” warning. The check does not prove listener,
firewall or end-to-end management reachability.

A broad `dip(geoip: private) -> direct(must)` also bypasses LAN private DNS. If you want that DNS intercepted, explicitly add `&& !dport(53)` to the rule; honk does not rewrite it for you. Native `direct(must)` leaves the original source IP/port untouched by honk, subject to external firewall/NAT. For bypassed-answer projection and the difference from `asis`, see [DNS source boundaries](../design/dns.md#ingress-paths).

## Fail-closed behavior

When health checking marks an outbound dead, the eBPF datapath normally drops new flows routed to it with `TC_ACT_SHOT`; it never silently leaks them through `direct`. A TCP group with exactly one unique leaf and no `final` instead keeps that same proxy dialable as a last resort, so real traffic can prove recovery. UDP and all-dead multi-leaf groups remain fail-closed, while a group containing a `direct`/`block` builtin never goes dead: the builtins are never marked dead, so the group-OR slot stays alive. Destination port `53` is exempt from LAN health drops for both TCP and UDP; this does not override a terminal user `must` result.

For an outage-tolerant gateway:

- Add an explicit private-network `direct(must)` rule where appropriate; decide whether it should also bypass private DNS, as described above.
- Point `fallback:` at a [`fallback`-policy group](./groups.md) containing at least two nodes, not at one node.
- Keep at least one DNS upstream on a direct path.

## Full example

```dae
routing {
    domain(suffix: doubleclick.net) -> block
    pname(NetworkManager, systemd-resolved) && l4proto(udp) && dport(53) -> direct(must)
    # This also bypasses private DNS; add && !dport(53) if interception is wanted.
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
    dip(geoip: cn, 203.0.113.0/24) && sport(1024-65535) && dscp(46) -> hk
    l4proto(tcp) && dport(80, 443, 8080-8090) -> proxy
    !domain(geosite: category-ads-all) && !dip(geoip: cn) -> resilient
    fallback: resilient
}
```

Here `proxy`, `hk`, and `resilient` are all group names.

## Related docs

- [Routing design](../design/routing.md)
- [Global reference](./global.md)
- [Group reference](./groups.md)
