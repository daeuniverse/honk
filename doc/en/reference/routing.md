# Routing reference

`routing { ... }` defines ordered traffic matchers and their outbound targets.

## Rule grammar

```text
condition [&& condition ...] -> outbound[(must)]
condition [&& condition ...] -> direct(mark: value[, must])
fallback: outbound[(must)] | direct(mark: value[, must])
```

- Rules are evaluated by ascending `priority`; lower values run first. Equal priorities retain stable source order. The dae parser assigns `priority` values `0, 1, ...` in source order. honk does not insert local-interface routing rules.
- `default:` is an alias of `fallback:`. The fallback target applies when no rule finalizes; if omitted, it defaults to `direct`.
- Comma-separated arguments inside a matcher are alternatives. Different populated condition groups must all match.
- A parenthesized argument list may span physical lines within one source file. The statement continues through its closing `)` and `-> outbound`; an included file cannot finish another file's unfinished call.
- Single or double quotes protect every interior byte, including whitespace, `#`, braces, `,`, `)`, `&&`, and `->`. Quotes open at the start of a token or immediately after an unquoted `(`, `,`, or `:`, so `domain(suffix:'example.com')` equals `domain(suffix: 'example.com')`. Backslashes are preserved, not decoded. An opened quote must close on the same physical line; otherwise the configuration fails with `unterminated-quote`.
- A leading `!` negates only the single matcher immediately following it. A rule matches when its positive conditions match and none of its negated matchers hits.
- Traffic without domain, process-name, MAC or DSCP metadata misses the matching function, so the negated form matches it: an unsniffed domain satisfies `!domain(...)` and `!geosite:...`, and traffic without a process name satisfies `!pname(...)`.
- Unknown nonempty predicates, whitespace before matcher parentheses, and trailing matcher text reject the configuration with a located diagnostic. Unsupported nonempty terms are never removed from a conjunction.
- Empty terms, a lone `!` and empty arguments are skipped: `domain() && dport(443)` is `dport(443)`. A rule left with no condition never matches; use `fallback:` for a catch-all.
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
| `domain(...)` | Bare value or `suffix:` for a raw suffix; `keyword:` for a substring; `full:` for a whole-name glob supporting `*` and `?`; `regex:` for a Rust regular expression; `geosite:` for a geosite code | `domain_suffix`, `domain_keyword`, `domain`, `domain_regex`, `geosite` |
| `dip(...)` | Destination IPv4/IPv6 address or CIDR, not a hostname; `geoip: code`. An address becomes `/32` or `/128`; CIDR host bits are cleared. | `ip`, `geo_ip` |
| `sip(...)` | Source IPv4/IPv6 address or CIDR, read as in `dip(...)` | `source_ip` |
| `dport(...)` | Decimal destination port or inclusive `start-end` range from `0` to `65535`, with `start <= end` | `port` |
| `sport(...)` | Decimal source port or inclusive `start-end` range from `0` to `65535`, with `start <= end` | `source_port` |
| `l4proto(...)` | `tcp`, `udp`, in any case | `protocol` |
| `pname(...)` | Substring patterns normalized to 15 bytes, matched against the executable basename from `argv[0]`; when runtime BTF offsets or verifier-safe kernel argv access are unavailable, the cgroup hook uses the calling thread's `comm` synchronously. Matches only processes on the honk host, not applications on LAN clients. | `process_name` |
| `mac(...)` | Source MAC address as `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff` or `aabbccddeeff`, in any case | `mac` |
| `ipversion(...)` | `4`/`ipv4`, `6`/`ipv6`, in any case | `ip_version` |
| `dscp(...)` | Decimal or `0x`/`0X`-prefixed hexadecimal value; packets carry DSCP values `0` to `63` | `dscp` |
| `user(...)` | Exact authenticated username of an `inbound` session (`socks5` or `http`) | `user` |

Every positive field has a corresponding list under `RoutingCondition.not`; the parser sends `!matcher(...)` there. Within one field, listed values are alternatives.

`user(...)` matches only authenticated inbound sessions, SOCKS5 or HTTP(S) (the mihomo `in-user` analogue); intercepted traffic never carries a user, so a positive `user(...)` can never match it and `!user(...)` always matches intercepted traffic. Because the kernel datapath never sees a username, `user(...)` selects outbound in the userspace control plane only: a rule requiring one is unreachable in the eBPF matcher, and its negation imposes no kernel-side constraint. Only TCP flows can reach `user(...)`.

All domain pattern/suffix/keyword/regex and `geosite` alternatives share one
condition, so `domain(geosite: netflix, suffix: imgur.com)` matches either. Separate
`domain(...)` calls in one rule fill the same fields and are alternatives too.

`full:`, `suffix:` and `keyword:` are case-sensitive. `full:` matches the whole name, with `*` for any run of characters and `?` for one character; every other character is literal. `suffix:` compares raw text, so `suffix: example.com` also matches `notexample.com`. To match a domain and its subdomains on label boundaries, use `domain(regex: '(^|\.)example\.com$')`. Geosite entries compare case-insensitively and match suffixes on label boundaries.

`regex:` uses [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax), not glob syntax; an invalid pattern fails when honk builds the router. An empty prefixed value is kept: `domain(suffix: '')` matches every domain, unlike `domain()`.

Standalone `geosite:`, `geoip:`, `domain:`, `suffix:`, `keyword:`, `full:` and `regex:` predicates also accept a leading `!` and conjunctions. `domain:example.com` is a suffix match, not a `full:` match.

```dae
routing {
    domain(full: '*.example.com') -> proxy
    domain(regex: '(^|\.)example\.com$') -> proxy
    domain(suffix:'example.com') -> proxy
    !geosite:cn -> proxy
    fallback: direct
}
```

The glob above matches subdomains but not the apex `example.com`; the regex includes both. Unlike `suffix: example.com`, neither matches `notexample.com`.

Invalid addresses in `dip(...)` and `sip(...)`, invalid MAC or DSCP values, and unsupported `l4proto` or `ipversion` values are dropped without an error. A function left with no valid value matches nothing, so its negated form matches all traffic the rule's other conditions allow. A malformed port fails with `Invalid port`, and the kernel routing policy compiler rejects a reversed range such as `443-80`.

A matching `mac(...) -> direct(must)` can exempt a client from transparent DNS; ordinary `direct` does not. LAN/WAN TCP/UDP destination port `53` evaluates the normal ordered traffic policy once after existing ingress and control-plane exclusions, not a separate must-only scan. LAN port `53` skips local-socket probing, even when dnsmasq or `dns.bind` listens on the destination.

## Outbound targets and `must`

| Target | Meaning |
| --- | --- |
| `direct` | Built-in direct outbound |
| `block` | Built-in blocking outbound |
| Group name | Resolve through that outbound group and its policy |

`Config::validate` rejects bare node names as outbound targets. Wrap the node in a group (for example `filter: name('node')`) and reference the group instead. A group and a node also may not share a name. A configuration may define at most 250 top-level user groups; higher routing ordinals are reserved by the ABI.

Appending `(must)` makes a matched result terminal and skips sniffing and later domain rerouting (`no_sniff` semantics). It preserves the selected direct, block, or group action; it is not a blanket bypass of honk. Clash `Global` and `Direct` modes never override a must result or `block`. It is not the historical internal `MustRules` opcode that continued scanning.

For TCP/UDP destination port `53`, traffic-rule ownership is:

| Ordered policy result | DNS ownership |
| --- | --- |
| `direct(must)` | No DNS controller. LAN traffic and unmarked WAN traffic use native Linux delivery; a nonzero marked WAN result uses a marked direct socket for a new policy-route lookup. |
| `block(must)` | Drop. |
| `group(must)` | Carry the original TCP/UDP through the group's normal raw transport, bypassing `DnsController`, cache, hosts, request/response policy, and routing projection. |
| Any non-`must` result, including ordinary `block` | Valid DNS queries enter `DnsController`; Clash Direct-mode offload cannot take this ownership. |

Malformed non-`must` UDP53 payloads retain the generic UDP fallback rather than entering `DnsController`; the controller row is not a claim that every port-53 payload is DNS. Route-metadata admission follows the [TCP/UDP distinction](../design/control-plane.md#transparent-ingress).

LAN local-socket precedence applies only to non-53 destinations, independently per transport; wildcard ownership also requires full FIB `NOT_FWDED`, and the non-DNS TCP pure-SYN probe skip remains. Bound `:53` sockets cannot preempt the policy results above. See [DNS ownership](../design/dns.md#dns-ownership-state-machine) for transparent LAN versus native/loopback delivery.

Admission and policy-size limits: [LAN per-source new-flow budget](../design/datapath.md#per-source-new-flow-limit) and [compiled-policy capacity](../design/routing.md#restricted-native-backend).

## Policy-routing marks

`direct(mark: 512)` and `direct(mark: 0x200)` select the same direct mark.
Unprefixed numbers are decimal (including leading zeroes); `0x`/`0X` selects
hexadecimal. The range is `0..=0x3fffffff`: bits `0xc0000000` belong to the
datapath, not user policy. Binary/octal prefixes, underscores, signs, overflow,
unknown options and duplicate `mark`/`must` options reject the configuration.
Unlike the global mark scalar, a malformed direct mark never silently becomes zero.
Marks are supported on `direct`, not proxy/group targets.

`direct(mark: 0x200, must)` and `direct(must, mark: 0x200)` are equivalent;
whitespace inside the direct option list is allowed; `fallback:`/`default:`
accept the same forms. The last merged fallback replaces the whole action (a plain
`direct` clears mark and `must`) and applies after every ordinary rule, even later ones.

For IPv4/IPv6 TCP and UDP, a nonzero direct mark replaces the global socket-mark
payload; it is **not OR-ed with `so_mark_from_dae` or `0x100`**. On native direct,
NFQUEUE-approved direct and userspace direct sockets, honk retains
`CLASSIFIED_MARK` (`0x40000000`) alongside this low-30-bit policy payload.
For example, a configured `0x200` can appear as `0x40000200`; Linux policy rules
must mask off the reserved bits. `mark: 0` means unspecified: userspace-originated
direct sockets use the global mark, while native direct adds no user mark.
Proxy carriers, bootstrap and DNS-controller upstreams use the global mark,
not a mark from the intercepted traffic rule.

For example, select two externally configured WAN routing tables:

```dae
global {
    so_mark_from_dae: 0x200
}
routing {
    domain(suffix: example.net) -> direct(mark: 0x300)
    fallback: direct(mark: 0x200)
}
```

```sh
ip -4 rule add pref 10000 fwmark 0x200/0x3fffffff lookup 100
ip -6 rule add pref 10000 fwmark 0x200/0x3fffffff lookup 100
ip -4 rule add pref 10001 fwmark 0x300/0x3fffffff lookup 200
ip -6 rule add pref 10001 fwmark 0x300/0x3fffffff lookup 200
```

Populate tables `100` and `200` with the appropriate family-specific connected
and default routes, and configure source addresses/NAT/firewall permissions for
each WAN. honk does not manage these tables. LAN native direct marks are applied
before Linux forwarding lookup. A nonzero marked host/WAN direct result uses
userspace direct relay so the new socket performs a marked route lookup; this
also applies to `must`, including raw port-53 traffic, and does not preserve the
client's original source socket. `must` still bypasses the DNS controller.
Unmarked native `direct(must)` retains its existing source-preserving path.
Changing the global mark requires restart; traffic rules can be reloaded.
The compiled policy admits at most 256 distinct nonzero `direct(mark: ..., must)` values, including a marked `must` fallback. WAN raw UDP/53 carries an immutable mark-table index with its routing generation; it never takes a mark from another packet's tuple handoff.

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

`private` covers more than RFC 1918 LAN addresses, including CGNAT, loopback, link-local, documentation and multicast ranges:

| Family | CIDRs |
| --- | --- |
| IPv4 | `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255/32` |
| IPv6 | `::1/128`, `fc00::/7`, `fe80::/10` |

If a referenced geo asset is missing, the engine logs a warning naming the file and starts with that matcher empty. Unused assets do not produce missing-file warnings. An empty geo matcher matches nothing, so `!domain(geosite: ...)` or `!dip(geoip: ...)` then matches all traffic the rule's other conditions allow: a missing asset widens a negated rule instead of disabling it.

Geosite categories and GeoIP codes are case-insensitive. A geosite code may select an attribute with `category@attr`. Attribute keys compare case-insensitively. Everything after the first `@` is the selector, including any later `@`. An unknown geosite category, an unknown GeoIP code or a selector matching no entries logs a warning and expands to nothing, with the same effect on negated rules.

## Explicit local rules

honk no longer injects interface-address `direct(must)` rules at startup, SIGHUP/reload, or network events. There is no hidden kernel replacement allowlist: native `.dae` rule order stays user-authored. Local interface addresses remain observed for topology, ECS, and health events, not synthesized routing rules. If gateway management should stay native independently of proxy health, add an explicit rule at the intended position, for example:

```dae
dip(192.168.50.1, fd00:50::1) && !dport(53) -> direct(must)
```

This is optional user configuration, not an inserted rule. It leaves port `53` available for transparent DNS unless another terminal `must` result takes ownership. Existing non-53 local-socket ownership remains a pre-routing exclusion, including the non-DNS TCP pure-SYN probe skip; there is no unconditional gateway-management reachability guarantee without explicit routing.

With real LAN bindings, honk warns when the compiled rule order cannot confirm
unconditional `direct(must)` coverage (including a `direct(must)` fallback) for the observed addresses of configured
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

When health checking marks an outbound dead, the eBPF datapath normally drops new flows routed to it with `TC_ACT_SHOT`; it never silently leaks them through `direct`. A TCP group with exactly one unique leaf and no `final` instead keeps that same proxy dialable as a last resort, so real traffic can prove recovery. UDP and all-dead multi-leaf groups remain fail-closed, while a group containing a `direct`/`block` builtin never goes dead: the builtins are never marked dead, so the group-OR slot stays alive. Destination port `53` is exempt from health drops on LAN ingress and WAN egress for both TCP and UDP; this does not override a terminal user `must` result.

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

`proxy`, `hk`, and `resilient` are group names.

## Related docs

- [Routing design](../design/routing.md)
- [Global reference](./global.md)
- [Group reference](./groups.md)
