# DNS configuration reference

`dns { ... }` configures DNS in dae syntax.

## Top-level keys

| Key | Default | Meaning |
| --- | --- | --- |
| `bind` | absent / `""` | Optional standalone DNS listener; an empty value disables only this listener. |
| `use_host` | `false` | Repeatable hosts source: `true` or the path `/etc/hosts` reads standard hosts syntax; any other path reads an OxiDNS-compatible rule file. |
| `client_subnet` | absent / `""` | Optional EDNS Client Subnet preset: IPv4, IPv4 CIDR, `auto`, or `auto(IPv4)`. |
| `upstream { ... }` | `default: 'udp://223.5.5.5:53'` | Named upstream servers. The first explicit `upstream` block replaces the built-in entry. |
| `routing { ... }` | no rules; request fallback `default`; response fallback `accept` | Ordered request and response routing. |
| `ipversion_prefer` | omitted: `both` | `4` selects `preferipv4`; `6` selects `preferipv6`; `0` is dae's no preference, `both`. A value honk cannot parse keeps `both` and is reported as a diagnostic. |
| `optimistic_cache` | `true` | Enables positive and negative cache reads and writes. |
| `optimistic_cache_ttl` | `600` seconds | Fixed cache and wire TTL for every response except NXDOMAIN, SERVFAIL and NODATA; `0` uses the upstream's minimum TTL. |
| `optimistic_stale_reply_ttl` | `30` seconds | TTL for served-stale positive answers; a non-zero value replaces every non-OPT RR TTL, while `0` preserves cached policy-rewritten wire TTLs rather than authoritative TTLs. |
| `max_cache_size` | `10000` | Maximum cache entries, at most 100,000; also determines the per-shard byte budget below. |
| `fixed_domain_ttl { ... }` | empty | Per-domain positive and NODATA TTL overrides; `0` disables caching for every response code, including negatives. |

Scalar values own the remainder of their physical line and split only at the key colon, so bare IPv6 endpoints and `client_subnet: auto(9.9.9.9)` remain intact. Exactly one matched enclosing quote pair is removed. An opened scalar quote must close on the same line; malformed quotes fail the configuration.

For scalar settings, only an unquoted token-head `#` starts a comment. `use_host: /tmp/a#b` selects the literal path `/tmp/a#b` with `legacy-glued-hash`; write `use_host: /tmp/a # comment` for a comment. Repeated `use_host` declarations retain source order and existing deduplication. For `optimistic_cache`, shorthands `t`, `y`, `f`, and `n` still mean false, but emit `legacy-bool-shorthand`; use `true` or `false`.

`optimistic_cache` accepts `true`, `yes`, `1`, `on`, `false`, `no`, `0` and `off` in any case. Any other value turns the cache off and emits a diagnostic.

`hosts_file` was removed and fails the configuration with `removed-dns-hosts-file`; use `use_host` paths instead.

Unknown keys, blocks and statements inside `dns` produce `unknown-key`, `unknown-block` or `unknown-statement` warnings and are ignored. `dns.routing` accepts only `request` and `response` blocks.

## Standalone listener (`bind`)

The standalone listener uses ordinary, unmarked sockets in the host network namespace. Disabling it does not disable transparent TCP/UDP port-53 interception, which follows [traffic-rule ownership](./routing.md#outbound-targets-and-must).

| Value | Result |
| --- | --- |
| absent or `""` | No standalone listener. |
| Numeric `IP:port`, such as `127.0.0.1:1053` or `[::1]:1053` | UDP listener. |
| `udp://host:port` | UDP listener. |
| `tcp://host:port` | TCP listener. |
| `tcp+udp://host:port` | TCP and UDP listeners on the same address and port. |

A hostname requires a scheme, for example `udp://localhost:1053`. IPv6 literals use brackets. An empty host, as in `tcp+udp://:1053`, selects a wildcard address. Every form requires an explicit decimal `u16` port. Port `0` requests an ephemeral port; honk logs the selected address.

A bare hostname is invalid. The parser also rejects userinfo, paths, queries, fragments, backslashes, IPv6 zone identifiers, malformed brackets, unsupported schemes, and out-of-range ports. For a hostname, honk tries addresses in system resolution order and uses the first address on which every requested transport binds. Binding is synchronous and all-or-nothing: any failure closes the other selected sockets and fails startup.

Listener ownership is process-scoped. A SIGHUP reload accepts semantically equivalent spelling, but rejects any change to the host, port, or transport set as restart-required. A wildcard or LAN-facing bind exposes an unauthenticated recursive resolver; restrict source access with the host firewall and never publish it to an untrusted network.

Listening on `:53` does not preempt LAN traffic policy: non-`must` LAN TCP/UDP53 queries use transparent honk DNS even when dnsmasq or `dns.bind` owns the socket. Host-loopback and explicit native `direct(must)` delivery can still reach that ordinary listener; see the [listener matrix](../design/dns.md#dns-ownership-state-machine).

## Hosts snapshot (`use_host`)

`use_host` is repeatable. `true`, `yes`, `1` or `on` in any case adds `/etc/hosts`. `false`, `no`, `0`, `off` or an empty value adds nothing and does not remove earlier sources. Any other value is a path. `/etc/hosts`, whether added by `true` or written as a path, uses standard `IP canonical-name aliases...` syntax; every other path is an OxiDNS-compatible `matcher IP...` rule file. All sources are read once in declaration order and merged into one snapshot; a later source replaces an earlier definition of the same exact name or matcher. Duplicate source paths are loaded once.

```dae
dns {
    use_host: true
    use_host: false # Does not remove /etc/hosts added above.
    use_host: 'hosts.txt'
}
```

Absolute paths remain explicit. Relative paths prefer an existing copy below `global.data_dir`, then an existing `/var/share/honk` copy, then an existing working-directory path. A missing path remains below `global.data_dir`; the query path uses the resulting immutable snapshot and performs no file I/O.

Custom matchers are `full:example.com` (or an unprefixed exact name), `domain:example.com` (the name and all label-boundary subdomains), `keyword:text`, and `regexp:pattern`. Matching precedence is exact, longest domain suffix, first matching regexp, then first matching keyword; redefining the same matcher replaces its addresses. Full, domain, and keyword names are ASCII case-insensitive and normalize trailing dots. Regexps remain case-sensitive and run against the lowercase name without a trailing dot; use `(?i)` when a regexp needs case-insensitive matching. Duplicate addresses are removed.

A rule file has one matcher and at least one IPv4 or IPv6 address per line. `#` always starts a comment, and there is no quoting, so a matcher cannot contain whitespace or `#`. An example `hosts.txt`:

```text
full:api.example.com 192.0.2.10 2001:db8::10
domain:example.org 192.0.2.20
keyword:internal 192.0.2.30
regexp:^(foo|bar)\.example$ 192.0.2.40 # Shared address
```

After hard `ipv4only`/`ipv6only` filtering, a known IN-class A or AAAA name takes precedence over request rules (including `reject`), cache lookup, and upstream exchange. If an address entry has no address in the requested family, honk returns NOERROR/NODATA without querying an upstream. Other classes and qtypes continue through the normal pipeline. Local address records use a 60-second TTL and hosts answers bypass honk's DNS cache.

As a honk extension to the OxiDNS format, a rule may name exactly one domain instead of addresses. The name then becomes an alias of that domain:

```text
full:a.example b.example
domain:corp.example gateway.example
```

The target is normalized like a matcher name and must be a valid hostname; mixing names with addresses, naming two domains, or an exact name aliasing itself is an invalid rule. An A or AAAA query for an alias resolves the target with the same type through the whole pipeline (hosts, request rules, cache, upstream). The answer contains `CNAME` records from the queried name through any further aliases to the target, followed by the target's CNAME and requested address records. Local alias CNAMEs and local address records use a 60-second TTL; records from the target's answer retain the target's own TTL policy. The composed answer is uncached; the target lookup keeps the caller's cache policy, including an explicit cache bypass.

The derived target query requires exactly one question (`QD=1`), empty answer and authority sections (`AN=NS=0`), and either no additional records or exactly one OPT (`AR=0` or `1`). It replaces QNAME while preserving the transaction ID, all header flags, QTYPE and QCLASS. When present, the OPT keeps its exact class, TTL and option bytes, with its root owner encoded independently of the original question. Any other section shape fails before target I/O; honk does not silently strip records or fall back to querying the original name.

A target NODATA answers NOERROR with the CNAME chain only, and a target NXDOMAIN answers NXDOMAIN with the CNAME chain, as RFC 6604 specifies. Other full 12-bit response codes are returned without answer records: EDNS clients receive the full code, while a code that cannot be represented without EDNS becomes SERVFAIL without records. A failed target lookup fails the query. The composed answer preserves the final target response's `TC` bit, even when the composed packet fits within the client's size limit.

After all sources are merged, every alias target must reach a name that is not an alias within eight aliases: a loop or a longer chain is invalid, and the error names the matcher and target. Aliases also apply to hostnames honk resolves through its [node host hook](#node-server-hosts).

SIGHUP builds a new snapshot. Any unreadable source or invalid custom rule aborts startup; on reload the replacement generation fails before publication and the active generation remains in use.

## EDNS Client Subnet (`client_subnet`)

ECS reveals an approximate client network to upstream authoritative servers. Leave `client_subnet` empty unless CDN locality requires it. The setting applies only to named upstreams.

- Explicit value: an IPv4 address is a `/32`; honk normalizes an IPv4 CIDR to its network, so `203.0.113.7/24` sends `203.0.113.0/24`. IPv6, hostnames and ports fail the configuration.
- Automatic value: `auto` in any case sends bypass-marked UDP probes toward `1.1.1.1`, to destination ports `33434` through `33469`; `auto(IPv4)` changes only the target address. honk uses the route-selected local address when it is public. Otherwise, it checks at most 12 TTLs with three independent UDP flows per TTL and selects the first public ICMP hop. The result is always a `/24`. Inference gives up after two seconds. The probe needs neither DNS nor an HTTP service.
- Refresh: startup, SIGHUP and route/link/address changes resolve a new immutable value for the replacement DNS generation. A bounded failure disables generated ECS for that generation.

To probe toward another target:

```dae
dns {
    client_subnet: auto(9.9.9.9)
}
```

honk never overrides client-supplied ECS, including `/0`. A client query carrying any EDNS option, ECS included, is neither cached nor coalesced; ECS that honk adds does not affect caching. For generated ECS:

- The resolved dial route applies after both explicit `-> tag` selection and ordinary traffic routing. Direct attempts, including `-> direct`, are eligible; attempts with a proxy leaf omit ECS.
- honk judges each UDP address retry separately. ECS from a failed direct attempt cannot reach a proxied retry.
- For an eligible named-upstream query without ECS, honk adds the configured option after cache/singleflight admission, validates any echoed ECS, and removes only its injected state before caching or replying.
- The effective prefix partitions DNS policy identity, so answers cannot cross a changed automatic prefix. `asis` requests remain byte-for-byte unchanged.

## Upstreams

Each line has the form `name: 'uri'`, optionally followed by `-> node-or-group`:

```dae
upstream {
    default: 'udp://223.5.5.5:53'
    google_doh: 'https://dns.google/dns-query' -> proxy
}
```

Upstream declaration names preserve their spelling. Both request and response dae action parsers trim the token and apply Rust `to_lowercase()` before recognizing keywords or producing an upstream target; lookup then compares that lowercased target exactly with the preserved declaration name. Use lowercase declaration names (for example, `alidns`) so mixed-case dae actions resolve predictably. Legacy structured targets are not normalized and are matched verbatim.

Whole-config validation checks every effective named request and response rule or fallback against the declarations. This check runs at startup and reload, while parse-only loading APIs accept unresolved names for callers that do not validate the whole configuration. The first explicit `upstream` block replaces the built-in `default`: retain a declaration named `default`, select a declared fallback, or use a terminal request fallback such as `reject` or `asis`. A catch-all request rule does not waive fallback validation.

Later `upstream` blocks append to the first. When a name is declared more than once, the last declaration is used.

### URI schemes and defaults

| URI form | Runtime protocol | Default port / path |
| --- | --- | --- |
| `host[:port]` or `udp://host[:port]` | UDP, with TCP retry when the response has `TC` set | `53` |
| `tcp://host[:port]` | TCP DNS | `53` |
| `tcp+udp://host[:port]` or `udp+tcp://host[:port]` | Same as UDP | `53` |
| `tls://host[:port]` | DNS over TLS (DoT) | `853` |
| `https://host[:port][/path]` | DNS over HTTPS (DoH, HTTP/2) | `443`, path `/dns-query` |
| `h3://host[:port][/path]` or `http3://host[:port][/path]` | DNS over HTTP/3 (DoH3) | `443`, path `/dns-query` |
| `quic://host[:port]` | DNS over QUIC (DoQ) | `853` |

Schemes are lowercase only. honk does not reject an unknown or uppercase scheme; it treats the whole string as a UDP address, so check the spelling.

An IPv6 literal with a port needs brackets, as in `[2606:4700:4700::1111]:53`; a bare IPv6 literal uses the default port.

```dae
upstream {
    default: 'udp://[2606:4700:4700::1111]:53'
    cloudflare_v6_dot: 'tls://[2606:4700:4700::1111]:853?tls_server_name=cloudflare-dns.com'
}
```

For TLS-based protocols, the parser derives `tls_server_name` from a hostname. An IP-literal endpoint needs an explicit query parameter when certificate validation requires a DNS name:

```dae
cloudflare_dot: 'tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com'
```

The parameter is removed from the dial address and overrides a hostname-derived value. The key is case-sensitive, its value is not percent-decoded, and the last non-empty occurrence wins. Other query pairs stay in the address; after a DoH or DoH3 path they become part of the request URI.

DoH and DoH3 send `POST` requests with `application/dns-message`. The HTTP authority is the endpoint's host and port; `tls_server_name` changes only SNI and certificate validation, so an IP-literal DoH server must accept the IP as authority.

### Outbound selection

A trailing `-> tag` forces the upstream through that node or group. `-> direct` dials directly without consulting traffic routing, and `-> block` fails every query. When the tag matches no node or group, or the group has no available node, the query fails; it does not fall back to direct. Without a suffix, honk resolves the upstream destination and applies the ordinary traffic `routing { ... }` rules; that route can still select a proxy leaf. The legacy same-line form `name: 'uri' outbound: tag` remains accepted.

```dae
upstream {
    default: 'udp://223.5.5.5:53' -> direct
}
```

Traffic routing sees the upstream as a honk-originated flow: the upstream hostname when there is one, the resolved IP and port, source `0.0.0.0:0`, and `l4proto` `udp` for UDP, DoQ and DoH3 or `tcp` for TCP, DoT and DoH. A UDP upstream is routed as `udp` even when the selected proxy carries it as TCP-DNS.

Only unquoted `->` and `outbound:` suffixes select detours. Inside a quoted URI they remain data; a changed legacy split emits `legacy-upstream-separator`. An unquoted token-head `#` starts a trailing comment, with `legacy-upstream-comment` for the changed interpretation. Put comments and outbound suffixes outside URI quotes.

| Protocol | Through a selected node/group |
| --- | --- |
| UDP (`udp`, bare, `tcp+udp`, `udp+tcp`) | Carried as TCP-DNS through the outbound. |
| TCP | Supported through the outbound TCP stream. |
| DoT | Supported; TLS runs over the outbound TCP stream. |
| DoH | Supported; TLS and HTTP/2 run over the outbound TCP stream. |
| DoQ | Supported through the outbound's UDP-capable `PacketTransport`. |
| DoH3 | Supported through the outbound's UDP-capable `PacketTransport`. |

## DNS routing

`routing` contains ordered `request` and `response` rules. The first matching rule wins. Arguments inside one condition are OR-ed; conditions joined with `&&` are AND-ed. Prefix a condition with `!` to negate it.

In request and response rules, single or double quotes protect `,`, `)`, `&&`, `->`, `#`, and `//` inside matcher arguments. Only an unquoted token-head `#` starts a comment, after a space or tab; glued hashes remain data. `//` is not a comment: trailing slash-comment text omits the malformed rule with `legacy-slash-comment`. Replace it with `#`. A quoted QTYPE list such as `qtype('a,aaaa')` still selects both types with `legacy-quoted-list`; prefer bare or individually quoted items.

Unknown or malformed conditions and unsupported predicates omit the whole rule with a located warning, never just one conjunct. Unknown QTYPE names produce `invalid-qtype`, including mixed and negated lists; correct the name or use its numeric code. Explicit `qtype()` remains match-nothing. An invalid `qname` or `subtag` regexp and an empty `sip()` pass parsing but fail startup or reload.

Put each complete call and action on one physical line. Incomplete nonblank lines are omitted with located `incomplete-dns-rule`; DNS never joins them. Text after a complete matcher produces `trailing-matcher-text` and omits the whole rule. Leading and argument-position quotes must close on the same line. An unterminated quote produces one lexical diagnostic and omits the line only if every open block has a surviving closer; otherwise the document fails. Required closers hidden by the malformed quote cannot close blocks.

### Conditions

| Syntax | Scope | Meaning |
| --- | --- | --- |
| `qname(suffix: example.com)` | Request and response | Dot-boundary suffix; a bare argument also means suffix. |
| `qname(keyword: ads)` | Request and response | Substring match. |
| `qname(full: api.example.com)` | Request and response | Exact domain match. |
| `qname(regex: ...)` | Request and response | Rust regular expression match; quote it when it contains parentheses. |
| `qname(geosite: cn)` | Request and response | Match domains expanded from the named geosite category; `category@attr` keeps only entries carrying that attribute. |
| `qtype(a, aaaa, ...)` | Request and response | Match QTYPE names or a numeric `u16`. Recognized names are `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `PTR`, `SOA`, `SRV`, `HTTPS`, `SVCB`, `ANY`, and `*`. `*` is an alias for `ANY`, not a wildcard. |
| `sip(192.168.50.1, 100.64.0.0/10, 2001:db8::/32)` | Request only | Match the logical client source against any listed IP host or CIDR. |
| `subtag(MyAirport, keyword: Air, regex: ^Paid)` | Request only | Match the subscription tags of a [node server host](#node-server-hosts) lookup: exact, `keyword:` or `regex:`, case-sensitive. |
| `upstream(name, ...)` | Response only | Match the upstream that produced the current response. Names compare exactly and, unlike action targets, are not lowercased. |
| `ip(192.0.2.0/24, geoip: private, ...)` | Response only | Match when any answer IP belongs to a listed CIDR or GeoIP set. |

`qname` matches the lowercase query name without a trailing dot. `full:` and `suffix:` patterns are lowercased, but a trailing dot in a pattern is kept and never matches. `keyword:` and `regex:` patterns are case-sensitive; write them in lowercase or add `(?i)`.

The first unquoted `)` ends a condition, so quote a regexp that contains parentheses:

```dae
dns {
    routing {
        request {
            qname('regex: ^(foo|bar)\.example$') -> default
            qname(geosite: geolocation-!cn@cn) -> default
            qtype(*) -> reject
            qtype(a, aaaa) -> default
        }
    }
}
```

When `geosite.dat` or `geoip.dat` is unavailable, its expansion matches nothing. An unknown category, code or attribute warns and also matches nothing, so negating it alone makes the condition always true. `geoip: private` is built in and needs no asset file; see [asset locations](./global.md#data-directory-and-asset-paths).

A fully quoted `subtag` argument is an exact tag: `subtag('keyword: Air')` matches the tag `keyword: Air`, while `subtag(keyword: Air)` matches any tag containing `Air`.

For transparent port-53 and `dns.bind` ingress, the logical source is the socket peer. DNS resolution for an admitted TCP/UDP flow uses that flow's client address. Internal, bootstrap, prefetch, and Clash API queries have no logical source. An unknown source makes both positive and negated `sip` conditions false, so request routing continues to the next rule or fallback. `sip` is not valid in response routing.

DNS `sip()` and `ip()` share one IP-or-CIDR decoder. Bare IPv4 and IPv6 addresses mean `/32` and `/128`; CIDR host bits are truncated with `dns-network-host-bits`. Malformed networks produce located `invalid-dns-network` diagnostics and omit the whole dae rule; constructed invalid routing fails router/policy construction. Equivalent network spellings use the same policy identity without reordering or deduplicating arguments.

### Node server hosts

Node server hosts resolve through `global.bootstrap_resolver`, then `/etc/hosts` and the system nameserver, not through DNS routing. A request rule containing `subtag(...)` instead claims the server hosts, including XHTTP download hosts, of nodes from matching subscriptions:

```dae
dns {
    upstream {
        alidns: 'udp://223.5.5.5:53'
        providerdoh: 'https://doh.provider.example/dns-query' -> direct
    }
    routing {
        request {
            subtag(MyAirport) && qname(suffix: private.provider.example) -> providerdoh
            fallback: alidns
        }
    }
}
```

- Only `subtag()` rules are evaluated for node hosts; ordinary rules, the fallback and unmatched hosts keep bootstrap resolution. Other queries carry no subscription, so `subtag()` and `!subtag()` are false for them.
- A claimed lookup queries only the selected upstream, honors `strategy` and `use_host`, skips the cache and response rules, and never falls back: its failure fails the physical node or probe connection.
- Claims are hostname-based, not an end-to-end download destination policy. A download's preliminary URL lookup for routing is best effort; proxied URL domains are still resolved by the proxy, while that proxy's own node-server lookup obeys the rule. Downloads using an explicit bootstrap resolver bypass the hook.
- Tags attach to the hostname, not the node: nodes from different subscriptions that share a hostname share the union of their tags, so the first matching rule picks one upstream for that hostname.
- The rule may combine only with `qname()` and must select an upstream whose every declaration is `-> direct`; otherwise validation fails with `subtag-dns-condition`, `subtag-dns-action` or `subtag-dns-upstream-route`.
- The upstream's own hostname, ECH discovery and the offline `delay` subcommand still use the bootstrap resolver.
- A host matching a `use_host` [alias](#hosts-snapshot-use_host) resolves to its target instead: to the addresses when the alias chain ends at an address entry, otherwise as a node host with that name would, through a `subtag()` rule claiming the target or else bootstrap. A direct address entry matching the original hostname does not claim it through this hook; an address entry at the end of an alias chain is used. Every claimed lookup, including a local address result or a bootstrap target, obeys DNS runtime admission and cancellation. Once the target/subtag path is selected, its failure is authoritative. A reload that removes the alias before the lookup runs resolves the original host as if it had no alias.
- Aliases are matched against every hostname that reaches the bootstrap resolver, not only node server hosts: the URL host of a subscription, geodata or external UI download that names no explicit bootstrap resolver, a SOCKS5 node's UDP relay host, and the bootstrap fallback of health checks, latency tests, connectivity probes and internal name resolution. DNS upstream hostnames and ECH discovery do not reach the hook.
- Each DNS generation precomputes node-host policy outcomes, including nonmatching hosts, from the subscription tags and ordered rules. Native flow traces report `partial` with `not_instrumented` when consuming these outcomes: the node-host rule decision is not captured.

### Request actions

| Action | Result |
| --- | --- |
| `reject` | Return an empty successful response. |
| `asis` | Create a new query to the intercepted original DNS destination using honk-originated sockets, not the client's network source IP/port. A transparent query preserves its ingress transport; UDP retries the same destination over TCP when the response has `TC` set. A standalone query has no original destination and fails instead of recursing into the listener. |
| Upstream name | Query that named upstream. |
| `fallback: reject\|asis\|<upstream>` | Action used when no request rule matches; default is upstream `default`. |

Both routing blocks accept `default:` as a legacy alias for `fallback:`.

A source-aware lookup made for an admitted flow carries no intercepted DNS-server destination. If its request policy selects `asis`, resolution fails closed; it never falls through to the compatibility/default upstream.

Native `direct(must)` bypass differs from `asis` re-querying; see [DNS source/NAT and projection caveats](../design/dns.md#ingress-paths).

### Response actions

| Action | Result |
| --- | --- |
| `accept` | Return the current response. |
| `reject` | Replace the current response with an empty successful response. |
| Upstream name | Re-query through the named upstream, then evaluate response routing again. |
| `fallback: accept\|reject\|<upstream>` | Verdict or named upstream used when no response rule matches; default is `accept`. |

NXDOMAIN and SERVFAIL skip response rules and fallback. When the upstream exchange fails or returns SERVFAIL for a cacheable query, honk serves a retained [expired answer](#cache-and-fixed-ttl) instead if one exists; a local packet refusal never does.

A response traversal allows at most three upstreams, including the initial upstream. The planner rejects a fourth exchange and any re-query cycle.

### Legacy conversion

The compatibility schema retains flat `routing.rules` entries with `domain` and `upstream`, plus a named `fallback`. These are structured compatibility fields, not additional current dae statements. `suffix:`, `keyword:`, `full:`, and `regex:` prefixes select the matcher; a bare legacy domain is an exact `full` match.

Structured YAML, TOML or JSON input cannot carry request or response rules: `dns.routing.request` and `dns.routing.response` must be absent or `null`. Write those rules in dae.

Effective request selection follows this precedence:

1. Nonempty new-style `request.rules` selects those rules and their fallback, ignoring all legacy fields.
2. Otherwise, nonempty legacy `rules` are converted. Their verbatim legacy fallback wins even over a separately populated new-style fallback.
3. Without either rule set, use the configured request routing. Only when its fallback is `Upstream("default")` does a legacy fallback other than `""`, `"upstream"`, or `"default"` replace it.

The `"upstream"` sentinel is ignored only in the third branch; with legacy rules it is an ordinary named target requiring a declaration. Legacy targets are matched exactly, without dae action normalization.

Validation diagnostics preserve original field paths: new-style rules and fallbacks use `dns.routing.request.rules[i].action` and `dns.routing.request.fallback`; converted legacy rules use `dns.routing.rules[i].upstream`; converted or promoted fallbacks use `dns.routing.fallback`.
With active legacy rules, an undeclared default `upstream` fallback reports `missing-dns-fallback`, an undeclared empty fallback reports `empty-dns-fallback`, and other undeclared targets report `unknown-dns-upstream`. These diagnostics retain field paths but do not echo target names or list declared names. Omitting the legacy fallback is equivalent to explicitly setting `upstream`; either remains valid when that upstream is declared. Empty and `upstream` sentinels remain ignored when no legacy rules are active.

## Address-family strategy

| dae setting | Internal strategy | Behavior |
| --- | --- | --- |
| omitted | `both` | Run eligible A and AAAA work concurrently; suppress neither family. |
| `ipversion_prefer: 4` | `preferipv4` | Prefer IPv4 while retaining IPv6 fallback. |
| `ipversion_prefer: 6` | `preferipv6` | Prefer IPv6 while retaining IPv4 fallback. |

In a preference mode, both families remain queryable. For a non-preferred A/AAAA request, honk issues the preferred-family sibling query through the same pipeline while preserving the caller's logical source, original destination, ingress profile, and wire profile except QTYPE. If the preferred family has an address, the non-preferred answer is suppressed as NODATA; if it has none or the sibling has an ordinary availability failure, the non-preferred answer is returned. A typed local packet refusal, including carrier Capacity, instead terminates resolution with that cause and cannot be replaced by a stale answer. This adds one upstream query on a relevant cache miss.

The same strategy orders bootstrap-resolved addresses for an upstream hostname. `both` and `preferipv4` dial IPv4 first; `preferipv6` dials IPv6 first. TCP, DoT, DoH, DoQ, DoH3, and proxied DNS try subsequent addresses after a failed dial. Direct UDP uses its one retry for the other family before another address in the same family, then reuses the successful socket. The compatibility-only `ipv4only` and `ipv6only` strategies filter upstream dial candidates to that family.

The internal `ipv4only` and `ipv6only` modes are not expressible with dae `ipversion_prefer` syntax.

## Cache and fixed TTL

| Key | Default | Behavior |
| --- | --- | --- |
| `optimistic_cache` | `true` | Enables cache reads and publications. With `false`, replies keep upstream TTLs. |
| `optimistic_cache_ttl` | `600` seconds | Overrides the cache lifetime and the returned RR TTLs; NXDOMAIN, SERVFAIL and NODATA follow [Negative answers](#negative-answers). `0` uses the upstream's minimum TTL. Decimal seconds only: a value such as `10m` emits a diagnostic and selects `60`, not `600`. |
| `optimistic_stale_reply_ttl` | `30` seconds | Served-stale positive answers use this TTL; a non-zero value replaces every non-OPT RR TTL. `0` preserves cached policy-rewritten wire TTLs rather than authoritative TTLs; in that case, the outcome TTL derives from `extract_min_ttl` of that wire, falling back to 60 seconds when no positive TTL exists. For a non-zero value, the outcome TTL is the configured value even when no positive TTL exists. An invalid value emits a diagnostic and selects `30`. |
| `max_cache_size` | `10000` | Entry limit, divided across at most 16 shards. Each shard's answer-byte budget is `max(entry capacity × 1 KiB, 65,535 bytes)`; it evicts LRU entries until both limits hold. Individual answers over 65,535 bytes are not cached. Values above 100,000 clamp to 100,000 and `0` to one entry, each with a warning. An invalid value emits a diagnostic and selects `10000`. |
| `fixed_domain_ttl { domain: seconds }` | empty | Per-domain override applied before `optimistic_cache_ttl`; `0` disables caching for every response code, including NXDOMAIN and SERVFAIL. Keys match one exact name, written in lowercase without a trailing dot; they do not cover subdomains. |

Request routing runs before cache lookup. Clients share a cache entry only when their queries are identical apart from the transaction ID, arrive through the same ingress type, and select the same DNS policy and the same upstream or `asis` destination; the raw client source is not part of the key. Preferred-family rendering still retains source metadata, so source-dependent sibling policy cannot leak through foreground singleflight.

With `optimistic_cache_ttl: 0` and no `fixed_domain_ttl` override, a positive NOERROR answer uses the minimum TTL across all non-OPT answer, authority, and additional records. A cached answer has every non-OPT record TTL rewritten to that minimum. If any such TTL is zero, honk does not cache the response and supersedes the exact cache slot, preventing either an old address or an older negative from returning. A nonzero configured or fixed TTL still overrides that zero.

honk rewrites reply TTLs only for a response it caches; an uncacheable query or `optimistic_cache: false` leaves upstream TTLs unchanged. Failure codes other than NXDOMAIN and SERVFAIL, such as REFUSED, follow `optimistic_cache_ttl` and are cached for 600 seconds by default.

Expired answers, including cached NODATA, stay available for serve-stale for one hour unless evicted; `optimistic_stale_reply_ttl` sets the reply TTL, not this window. A cache hit with at most `max(original TTL / 10, 1)` seconds left starts one background refresh.

Disabling cache retention does not disable DNS routing projection. An accepted uncacheable positive answer (including `fixed_domain_ttl: 0`) uses the minimum positive non-OPT wire TTL for projection, falling back to 60 seconds when all such TTLs are zero. This does not rewrite the reply or make it cacheable; cache-hit remaining lifetimes and served-stale lifetimes are unchanged.

### Negative answers

NXDOMAIN is cached for `min(SOA TTL, SOA MINIMUM, 300)` seconds. Missing SOA or a zero SOA lifetime prevents caching and removes the existing positive and negative values for the exact cache key, so an old address cannot return as stale. A foreground result replaces whichever publication is present; a refresh removes only the revision it started from. `fixed_domain_ttl: 0` prevents caching without removing an existing entry. SERVFAIL otherwise retains its SOA-derived lifetime, defaulting to 60 seconds and clamped to `1..=300`.

NODATA here means NOERROR with no answer records (`ANCOUNT=0`); a nonempty answer, including a CNAME/DNAME-only answer, remains positive. NODATA retains its full wire response in the positive slot for `min(SOA TTL, SOA MINIMUM, 300)` seconds. A nonzero `fixed_domain_ttl` takes precedence over both SOA and the cap, including when SOA is absent. Without that override, missing SOA or zero lifetime supersedes the exact slot without caching, just as for NXDOMAIN.

Cached NODATA remains eligible for serve-stale; the stale rewrite changes the SOA record TTL, not SOA MINIMUM. A response-policy `reject` applied to upstream NODATA produces an empty NOERROR wire; its cache lifetime follows the same TTL rules using the rejected answer's SOA, not the synthetic wire. Subsequent requests reuse the synthetic response for that lifetime.

Cache lifetime selection uses the original upstream answer's class, response code, and TTL even when response-policy `reject` replaces the reply with synthetic NOERROR. A rejected REFUSED therefore keeps the failure-code TTL rules; a rejected positive NOERROR uses its original TTLs when no configured or fixed override applies.

Cache hits do not count down wire record TTLs. Supersession affects memory only; it does not delete a saved persistence row.

For example, `www.example.com` needs its own entry:

```dae
fixed_domain_ttl {
    example.com: 120
    www.example.com: 120
    ddns.example.org: 10
    nocache.test: 0
}
```

Each fixed TTL requires exactly one unsigned 32-bit decimal scalar. Bare and quoted values are accepted, including `0` and `4294967295`; newly accepted quoted decimals emit `legacy-ttl-quoting`. Invalid or overflowing values emit `invalid-ttl`, and extra tokens emit `trailing-value`; either omits the entry. Put explanations after ` # `, not directly after the number.

## Example

```dae
dns {
    # Omit bind to keep the standalone listener disabled.
    # bind: 'tcp+udp://:1053'
    use_host: true
    ipversion_prefer: 4

    upstream {
        default: 'udp://223.5.5.5:53'
        cloudflare_dot: 'tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com'
        google_doh: 'https://dns.google/dns-query' -> proxy
    }

    routing {
        request {
            sip(192.168.50.0/24, 100.64.0.0/10) -> google_doh
            qname(geosite: category-ads-all) -> reject
            qname(suffix: cn) -> default
            qtype(https) -> reject
            fallback: default
        }
        response {
            upstream(google_doh) -> accept
            ip(geoip: private) && !qname(geosite: cn) -> google_doh
            fallback: accept
        }
    }

    optimistic_cache: true
    optimistic_cache_ttl: 600
    max_cache_size: 10000
    fixed_domain_ttl {
        ddns.example.org: 10
        nocache.test: 0
    }
}
```

## Related docs

- [DNS design](../design/dns.md)
- [Experimental reference (`store_dns`)](./experimental.md)
- [Global reference](./global.md)
