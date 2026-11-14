# Routing reference

`routing { ... }` defines ordered traffic matchers and their outbound targets.

## Rule grammar

```text
condition [&& condition ...] -> outbound[(must)]
condition [&& condition ...] -> direct(mark: value[, must])
fallback: outbound[(must)] | direct(mark: value[, must])
```

- Rules run in ascending `priority`: lower values first. Equal priorities keep source order. The dae parser assigns `priority` values `0, 1, ...` in source order. honk inserts no local-interface routing rules of its own.
- `default:` is another spelling of `fallback:`. The fallback applies when no rule finalizes. If you omit it, the fallback is `direct`.
- Comma-separated arguments inside one matcher are alternatives. Every populated matcher on a line must match.
- A parenthesized argument list may span physical lines within one source file. The statement continues through its closing `)` and `-> outbound`. An included file cannot finish a call that another file left open.
- Single or double quotes protect every interior byte, including whitespace, `#`, braces, `,`, `)`, `&&`, and `->`. A quote opens at the start of a token or right after an unquoted `(`, `,`, or `:`, so `domain(suffix:'example.com')` equals `domain(suffix: 'example.com')`. Backslashes are kept, not decoded. A quote opened on a line must close on the same physical line, otherwise the configuration fails with `unterminated-quote`.
- A leading `!` negates only the matcher that follows it. A rule matches when every positive matcher matches and no negated matcher hits.
- When traffic lacks domain, process-name, MAC or DSCP metadata, the matcher does not hit and its negated form matches. An unsniffed domain therefore satisfies `!domain(...)` and `!geosite:...`, and traffic without a process name satisfies `!pname(...)`.
- Unknown nonempty predicates, whitespace before matcher parentheses, and trailing matcher text reject the configuration with a located diagnostic. honk never drops an unsupported nonempty term from a conjunction.
- Empty terms, a lone `!` and empty arguments are skipped: `domain() && dport(443)` is `dport(443)`. A rule left with no condition never matches, so use `fallback:` for a catch-all.
- An unquoted `#` at the start of a token begins a comment. A `#` glued to text is data: `domain(x) -> proxy#c` targets the literal name `proxy#c` and emits `legacy-glued-hash`. Write `-> proxy # comment` when you want a comment. The first unquoted arrow separates the action; later arrows remain target data with `legacy-arrow-target`.

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
| `pname(...)` | Substring patterns normalized to 15 bytes, matched against the executable basename from `argv[0]`. Without runtime BTF offsets or verifier-safe kernel argv access, the cgroup hook uses the calling thread's `comm` synchronously. Matches processes on the honk host only, not applications on LAN clients. | `process_name` |
| `mac(...)` | Source MAC address as `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff` or `aabbccddeeff`, in any case | `mac` |
| `ipversion(...)` | `4`/`ipv4`, `6`/`ipv6`, in any case | `ip_version` |
| `dscp(...)` | Decimal or `0x`/`0X`-prefixed hexadecimal value; packets carry DSCP values `0` to `63` | `dscp` |

Every positive field has a matching list under `RoutingCondition.not`, where the parser sends `!matcher(...)`. Within one field, listed values are alternatives.

All domain pattern, suffix, keyword, regex and `geosite` alternatives share one
condition, so `domain(geosite: netflix, suffix: imgur.com)` matches either.
Separate `domain(...)` calls in one rule fill the same fields and are
alternatives too.

`full:`, `suffix:` and `keyword:` are case-sensitive. `full:` matches the whole name: `*` stands for any run of characters, `?` for one character, and every other character is literal. `suffix:` compares raw text, so `suffix: example.com` also matches `notexample.com`. To match a domain and its subdomains on label boundaries, use `domain(regex: '(^|\.)example\.com$')`. Geosite entries compare case-insensitively and match suffixes on label boundaries.

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

honk drops invalid addresses in `dip(...)` and `sip(...)`, invalid MAC or DSCP values, and unsupported `l4proto` or `ipversion` values without an error. A function left with no valid value matches nothing, so its negated form matches all traffic the rule's other conditions allow. A malformed port fails with `Invalid port`, and the kernel routing policy compiler rejects a reversed range such as `443-80`.

A matching `mac(...) -> direct(must)` can exempt a client from transparent DNS. Ordinary `direct` does not. For LAN/WAN TCP/UDP destination port `53`, honk evaluates the normal ordered traffic policy once, after the existing ingress and control-plane exclusions; there is no separate must-only scan. honk skips local-socket probing for LAN port `53`, even when dnsmasq or `dns.bind` listens on the destination.

## Outbound targets and `must`

| Target | Meaning |
| --- | --- |
| `direct` | Built-in direct outbound |
| `block` | Built-in blocking outbound |
| Group name | Resolve through that outbound group and its policy |

`Config::validate` rejects bare node names as outbound targets. Wrap the node in a group (for example `filter: name('node')`) and reference the group instead. A group and a node also may not share a name. A configuration may define at most 250 top-level user groups; higher routing ordinals are reserved by the ABI.

Appending `(must)` makes a matched result terminal: honk skips sniffing and later domain rerouting (`no_sniff` semantics). It keeps the selected direct, block, or group action; it is not a blanket bypass of honk. Clash `Global` and `Direct` modes never override a must result or `block`. `(must)` is not the historical internal `MustRules` opcode, which continued scanning.

For TCP/UDP destination port `53`, traffic-rule ownership is:

| Ordered policy result | DNS ownership |
| --- | --- |
| `direct(must)` | No DNS controller. LAN traffic and unmarked WAN traffic use native Linux delivery. A nonzero marked WAN result uses a marked direct socket for a new policy-route lookup. |
| `block(must)` | Drop. |
| `group(must)` | Carry the original TCP/UDP through the group's normal raw transport. This bypasses `DnsController`, cache, hosts, request/response policy, and routing projection. |
| Any non-`must` result, including ordinary `block` | Valid DNS queries enter `DnsController`. Clash Direct-mode offload cannot take this ownership. |

Malformed non-`must` UDP53 payloads keep the generic UDP fallback instead of entering `DnsController`. The controller row does not claim that every port-53 payload is DNS. Route-metadata admission follows the [TCP/UDP distinction](../design/control-plane.md#transparent-ingress).

LAN local-socket precedence applies only to non-53 destinations, independently per transport. Wildcard ownership also requires a full FIB `NOT_FWDED` result, and the non-DNS TCP pure-SYN probe skip remains. Bound `:53` sockets cannot preempt the policy results above. See [DNS ownership](../design/dns.md#dns-ownership-state-machine) for transparent LAN versus native/loopback delivery.

Admission and policy-size limits: [LAN per-source new-flow budget](../design/datapath.md#per-source-new-flow-limit) and [compiled-policy capacity](../design/routing.md#restricted-native-backend).

## Sniffing

honk sniffs only flows that the datapath hands to the control plane. Flows that the TC hooks keep on the native Linux path are never sniffed.

- TCP: honk reads at most 4096 bytes and extracts the TLS SNI or HTTP `Host`. It writes those bytes to the selected outbound before relaying, so sniffing consumes no application data.
- UDP: honk decrypts QUIC v1/v2 Initial packets and extracts the TLS ClientHello SNI.

honk skips sniffing in these cases:

- `dial_mode` is `ip`.
- The datapath handoff is already a final `direct` or `block`.
- The matched rule ends in `(must)`.
- TCP only: three consecutive failures put the destination/outbound signature in a negative cache for ten minutes.

`dial_mode` decides what honk does with a sniffed name; see [Dial modes](./global.md#dial-modes). In `domain` mode the name must first pass a DNS reality check. `sniffing_timeout` is a compatibility key that the control plane does not read. Limits and timeouts are in [Sniffing and flow initialization](../design/control-plane.md#sniffing-and-flow-initialization).

## Policy-routing marks

`direct(mark: 512)` and `direct(mark: 0x200)` select the same direct mark. An
unprefixed number is decimal, even with leading zeroes, and `0x`/`0X` selects
hexadecimal. The range is `0..=0x3fffffff`; bits `0xc0000000` belong to the
datapath, not user policy. Binary and octal prefixes, underscores, signs,
overflow, unknown options and duplicate `mark`/`must` options reject the
configuration. Unlike the global mark scalar, a malformed direct mark never
silently becomes zero. Marks apply to `direct` only, not to proxy or group
targets.

`direct(mark: 0x200, must)` and `direct(must, mark: 0x200)` are equivalent, and
whitespace inside the option list is allowed. `fallback:` and `default:` accept
the same forms. The last merged fallback replaces the whole action, so a plain
`direct` clears mark and `must`. It applies after every ordinary rule, even
later ones.

For IPv4/IPv6 TCP and UDP, a nonzero direct mark replaces the global socket-mark
payload. It is not OR-ed with `so_mark_from_dae` or `0x100`. On native direct,
NFQUEUE-approved direct and userspace direct sockets, honk retains
`CLASSIFIED_MARK` (`0x40000000`) alongside this low-30-bit policy payload. For
example, a configured `0x200` can appear as `0x40000200`, so Linux policy rules
must mask off the reserved bits. `mark: 0` means unspecified:
userspace-originated direct sockets use the global mark, while native direct
adds no user mark. Proxy carriers, bootstrap and DNS-controller upstreams use
the global mark, not a mark from the intercepted traffic rule.

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

Populate tables `100` and `200` with the family-specific connected and default
routes, and configure source addresses, NAT and firewall permissions for each
WAN. honk does not manage these tables. LAN native direct marks are applied
before the Linux forwarding lookup. A nonzero marked host/WAN direct result uses
userspace direct relay, so the new socket performs a marked route lookup. This
also applies to `must`, including raw port-53 traffic, and it does not preserve
the client's original source socket. `must` still bypasses the DNS controller,
and unmarked native `direct(must)` keeps its source-preserving path. Changing
the global mark requires a restart; traffic rules can be reloaded. The compiled
policy admits at most 256 distinct nonzero `direct(mark: ..., must)` values,
including a marked `must` fallback. WAN raw UDP/53 carries an immutable
mark-table index with its routing generation and never takes a mark from another
packet's tuple handoff.

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

If a referenced geo asset is missing, the engine logs a warning naming the file and starts with that matcher empty. Unused assets do not produce missing-file warnings. An empty geo matcher matches nothing, so `!domain(geosite: ...)` or `!dip(geoip: ...)` then matches all traffic the rule's other conditions allow. A missing asset therefore widens a negated rule instead of disabling it.

Geosite categories and GeoIP codes are case-insensitive. A geosite code may select an attribute with `category@attr`. Attribute keys compare case-insensitively. Everything after the first `@` is the selector, including any later `@`. When a geosite category is unknown, a GeoIP code is unknown, or a selector matches no entries, honk logs a warning and the matcher matches nothing. Negated rules behave the same way.

## Explicit local rules

honk no longer injects interface-address `direct(must)` rules at startup, SIGHUP/reload, or network events. There is no hidden kernel replacement allowlist: native `.dae` rule order stays user-authored. honk still observes local interface addresses for topology, ECS, and health events, but never synthesizes routing rules from them. If gateway management should stay native independently of proxy health, add an explicit rule at the intended position, for example:

```dae
dip(192.168.50.1, fd00:50::1) && !dport(53) -> direct(must)
```

This is optional user configuration, not an inserted rule. It leaves port `53` available for transparent DNS unless another terminal `must` result takes ownership. Existing non-53 local-socket ownership remains a pre-routing exclusion, including the non-DNS TCP pure-SYN probe skip; there is no unconditional gateway-management reachability guarantee without explicit routing.

With real LAN bindings, honk warns when the compiled rule order cannot confirm
unconditional `direct(must)` coverage. The check covers TCP and UDP destination
ports `1–65535` except `53`, on the observed addresses of configured LAN/WAN
interfaces; a `direct(must)` fallback counts as coverage. honk runs the check at
startup, after a successful traffic-policy change and on observed network
changes. No-op and node-only reloads skip it. honk reconsiders missing
interfaces and unavailable addresses once it discovers them. The warning is
advisory: startup, reload, explicit blocking and routing order stay unchanged.
Source-, domain- or process-dependent rules and split port coverage can be
intentional and still warn as unconfirmed. The check does not prove listener,
firewall or end-to-end management reachability.

A broad `dip(geoip: private) -> direct(must)` also bypasses LAN private DNS. If that DNS should be intercepted, add `&& !dport(53)` to the rule explicitly; honk does not rewrite the rule. Native `direct(must)` leaves the original source IP/port untouched by honk, subject to external firewall/NAT. For bypassed-answer projection and the difference from `asis`, see [DNS source boundaries](../design/dns.md#ingress-paths).

## Fail-closed behavior

When health checking marks an outbound dead, the eBPF datapath normally drops new flows routed to it with `TC_ACT_SHOT`. It never leaks those flows through `direct`. One case stays dialable: a TCP group with exactly one unique leaf and no `final` keeps that leaf as a last resort, so real traffic can prove recovery. UDP groups and multi-leaf groups with every member dead stay fail-closed. A group containing a `direct`/`block` builtin never goes dead, because the builtins are never marked dead and the group-OR slot stays alive. Destination port `53` is exempt from health drops on LAN ingress and WAN egress, for both TCP and UDP. That exemption does not override a terminal user `must` result.

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
