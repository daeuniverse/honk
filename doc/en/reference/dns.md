# DNS configuration reference

This page defines the current dae-syntax `dns { ... }` section and its runtime semantics.

## Top-level keys

| Key | Default | Meaning |
| --- | --- | --- |
| `bind` | absent / `""` | Optional standalone DNS listener; an empty value disables only this listener. |
| `use_host` | `false` | Repeatable hosts source: `true` selects `/etc/hosts`; a path selects an OxiDNS-compatible rule file. |
| `client_subnet` | absent / `""` | Optional EDNS Client Subnet preset: IPv4, IPv4 CIDR, `auto`, or `auto(IPv4)`. |
| `upstream { ... }` | `default: 'udp://223.5.5.5:53'` | Named upstream servers. The first explicit `upstream` block replaces the built-in entry. |
| `routing { ... }` | no rules; request fallback `default`; response fallback `accept` | Ordered request and response routing. |
| `ipversion_prefer` | omitted: `both` | `4` selects `preferipv4`; `6` selects `preferipv6`; `0` is dae's no preference, `both`. A value honk cannot parse keeps `both` and is reported as a diagnostic. |
| `optimistic_cache` | `true` | Enables positive and negative cache reads and writes. |
| `optimistic_cache_ttl` | `600` seconds | Fixed positive-answer cache and wire TTL, excluding NODATA; `0` preserves the answer TTL. |
| `optimistic_stale_reply_ttl` | `30` seconds | TTL for served-stale positive answers; a non-zero value replaces every non-OPT RR TTL, while `0` preserves cached policy-rewritten wire TTLs rather than authoritative TTLs. |
| `max_cache_size` | `10000` | Maximum cache entries and the input to the retained wire-byte budget. |
| `fixed_domain_ttl { ... }` | empty | Per-domain positive and NODATA TTL overrides; `0` disables caching for every response code, including negatives. |

Scalar values own the remainder of their physical line and split only at the key colon, so bare IPv6 endpoints and `client_subnet: auto(9.9.9.9)` remain intact. Exactly one matched enclosing quote pair is removed. An opened scalar quote must close on the same line; malformed quotes fail the configuration.

For scalar settings, only an unquoted token-head `#` starts a comment. `use_host: /tmp/a#b` selects the literal path `/tmp/a#b` with `legacy-glued-hash`; write `use_host: /tmp/a # comment` for a comment. Repeated `use_host` declarations retain source order and existing deduplication. For `optimistic_cache`, shorthands `t`, `y`, `f`, and `n` still mean false, but emit `legacy-bool-shorthand`; use `true` or `false`.

## Standalone listener (`bind`)

The standalone listener uses ordinary, unmarked sockets in the host network namespace. Transparent TCP and UDP port-53 interception remains active when the standalone listener is disabled.

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

## Hosts snapshot (`use_host`)

`use_host` is repeatable. `true` contributes `/etc/hosts` in standard `IP canonical-name aliases...` format; `false` contributes no source; each path contributes an OxiDNS-compatible `matcher IP...` rule file. All sources are read once in declaration order and merged into one snapshot; a later source replaces an earlier definition of the same exact name or matcher. Duplicate source paths are loaded once.

```dae
dns {
    use_host: true
    use_host: 'hosts.txt'
}
```

Absolute paths remain explicit. Relative paths prefer an existing copy below `global.data_dir`, then an existing `/var/share/honk` copy, then an existing working-directory path. A missing path remains below `global.data_dir`; the query path uses the resulting immutable snapshot and performs no file I/O.

Custom matchers are `full:example.com` (or an unprefixed exact name), `domain:example.com` (the name and all label-boundary subdomains), `keyword:text`, and `regexp:pattern`. Matching precedence is exact, longest domain suffix, first matching regexp, then first matching keyword; redefining the same matcher replaces its addresses. Full, domain, and keyword names are ASCII case-insensitive and normalize trailing dots. Regexps remain case-sensitive and run against the lowercase name without a trailing dot; use `(?i)` when a regexp needs case-insensitive matching. Duplicate addresses are removed.

After hard `ipv4only`/`ipv6only` filtering, a known IN-class A or AAAA name takes precedence over request rules—including `reject`—and over cache lookup and upstream exchange. If the name exists but has no address in the requested family, honk returns NOERROR/NODATA without querying an upstream. Other classes and qtypes continue through the normal pipeline. Hosts answers use a 60-second TTL and bypass honk's DNS cache.

SIGHUP builds a new snapshot. Any unreadable source or invalid custom rule aborts startup; on reload the replacement generation fails before publication and the active generation remains in use.

## EDNS Client Subnet (`client_subnet`)

`client_subnet` applies only to named upstreams. An IPv4 address is a `/32`; an IPv4 CIDR is normalized to its network. `auto` sends bypass-marked UDP probes toward `1.1.1.1:33434`, while `auto(IPv4)` changes only that probe target. It uses the route-selected public local address when available; otherwise it checks at most 12 TTLs with three independent UDP flows per TTL and selects the first public ICMP hop as a `/24`. The probe needs neither DNS nor an HTTP service. Startup, SIGHUP, and route/link/address changes resolve a new immutable value for the replacement DNS generation. A bounded failure disables generated ECS for that generation.

honk never overrides client-supplied ECS, including `/0`. Generated ECS follows the resolved dial route after both explicit `-> tag` selection and ordinary traffic routing: direct attempts, including `-> direct`, are eligible; attempts with a proxy leaf omit it. UDP address retries are judged separately, so ECS from a failed direct attempt cannot reach a proxied retry. For an eligible named-upstream query without ECS, honk adds the configured option after cache/singleflight admission, validates any echoed ECS, and removes only its injected state before caching or replying. The effective prefix partitions DNS policy identity, so answers cannot cross a changed automatic prefix. `asis` requests remain byte-for-byte unchanged. ECS reveals an approximate client network to upstream authoritative servers; leave the field empty unless CDN locality requires it.

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

### URI schemes and defaults

| URI form | Runtime protocol | Default port / path |
| --- | --- | --- |
| `host[:port]` or `udp://host[:port]` | UDP, with TCP retry when the response has `TC` set | `53` |
| `tcp://host[:port]` | TCP DNS | `53` |
| `tcp+udp://host[:port]` | Current parser normalizes this to the UDP behavior above | `53` |
| `tls://host[:port]` | DNS over TLS (DoT) | `853` |
| `https://host[:port][/path]` | DNS over HTTPS (DoH, HTTP/2) | `443`, path `/dns-query` |
| `h3://host[:port][/path]` or `http3://host[:port][/path]` | DNS over HTTP/3 (DoH3) | `443`, path `/dns-query` |
| `quic://host[:port]` | DNS over QUIC (DoQ) | `853` |

For TLS-based protocols, the parser derives `tls_server_name` from a hostname. An IP-literal endpoint needs an explicit query parameter when certificate validation requires a DNS name:

```dae
cloudflare_dot: 'tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com'
```

The parameter is removed from the dial address and overrides a hostname-derived value.

### Outbound selection

A trailing `-> tag` forces the upstream through that node or group. Without it, honk resolves the upstream destination and applies the ordinary traffic `routing { ... }` rules; that route can still select a proxy leaf. The legacy same-line form `name: 'uri' outbound: tag` remains accepted.

Only unquoted `->` and `outbound:` suffixes select detours. Inside a quoted URI they remain data; a changed legacy split emits `legacy-upstream-separator`. An unquoted token-head `#` starts a trailing comment, with `legacy-upstream-comment` for the changed interpretation. Put comments and outbound suffixes outside URI quotes.

| Protocol | Through a selected node/group |
| --- | --- |
| UDP (`udp`, bare, `tcp+udp`) | Carried as TCP-DNS through the outbound. |
| TCP | Supported through the outbound TCP stream. |
| DoT | Supported; TLS runs over the outbound TCP stream. |
| DoH | Supported; TLS and HTTP/2 run over the outbound TCP stream. |
| DoQ | Supported through the outbound's UDP-capable `PacketTransport`. |
| DoH3 | Supported through the outbound's UDP-capable `PacketTransport`. |

## DNS routing

`routing` contains ordered `request` and `response` rules. The first matching rule wins. Arguments inside one condition are OR-ed; conditions joined with `&&` are AND-ed. Prefix a condition with `!` to negate it.

In request and response rules, single or double quotes protect `,`, `)`, `&&`, `->`, `#`, and `//` inside matcher arguments. Only an unquoted token-head `#` starts a comment, after a space or tab; glued hashes remain data. `//` is not a comment: trailing slash-comment text omits the malformed rule with `legacy-slash-comment`. Replace it with `#`. A quoted QTYPE list such as `qtype('a,aaaa')` still selects both types with `legacy-quoted-list`; prefer bare or individually quoted items.

Unknown or malformed conditions and unsupported predicates omit the whole rule with a located warning, never just one conjunct. Unknown QTYPE names produce `invalid-qtype`, including mixed and negated lists; correct the name or use its numeric code. Explicit `qtype()` remains match-nothing.

Put each complete call and action on one physical line. Incomplete nonblank lines are omitted with located `incomplete-dns-rule`; DNS never joins them. Text after a complete matcher produces `trailing-matcher-text` and omits the whole rule. Leading and argument-position quotes must close on the same line. An unterminated quote produces one lexical diagnostic and omits the line only if every open block has a surviving closer; otherwise the document fails. Required closers hidden by the malformed quote cannot close blocks.

### Conditions

| Syntax | Scope | Meaning |
| --- | --- | --- |
| `qname(suffix: example.com)` | Request and response | Dot-boundary suffix; a bare argument also means suffix. |
| `qname(keyword: ads)` | Request and response | Substring match. |
| `qname(full: api.example.com)` | Request and response | Exact domain match. |
| `qname(regex: ...)` | Request and response | Rust regular expression match. |
| `qname(geosite: cn)` | Request and response | Match domains expanded from the named geosite code. |
| `qtype(a, aaaa, ...)` | Request and response | Match QTYPE names or a numeric `u16`. Recognized names are `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `PTR`, `SOA`, `SRV`, `HTTPS`, `SVCB`, `ANY`, and `*`. |
| `sip(192.168.50.1, 100.64.0.0/10, 2001:db8::/32)` | Request only | Match the logical client source against any listed IP host or CIDR. |
| `upstream(name, ...)` | Response only | Match the upstream that produced the current response. |
| `ip(192.0.2.0/24, geoip: private, ...)` | Response only | Match when any answer IP belongs to a listed CIDR or GeoIP set. |

For transparent port-53 and `dns.bind` ingress, the logical source is the socket peer. DNS resolution performed for an admitted TCP/UDP flow uses that flow's client address. Internal, bootstrap, prefetch, and Clash API queries have no logical source. An unknown source makes both positive and negated `sip` conditions false, so request routing continues to the next rule or fallback. `sip` is not valid in response routing.

DNS `sip()` and `ip()` share one IP-or-CIDR decoder. Bare IPv4 and IPv6 addresses mean `/32` and `/128`; CIDR host bits are truncated with `dns-network-host-bits`. Malformed networks produce located `invalid-dns-network` diagnostics and omit the whole dae rule; constructed invalid routing fails router/policy construction. Equivalent network spellings use the same policy identity without reordering or deduplicating arguments.

### Request actions

| Action | Result |
| --- | --- |
| `reject` | Return an empty successful response. |
| `asis` | Dial the intercepted original DNS destination. A transparent query preserves its ingress transport; UDP retries the same destination over TCP when the response has `TC` set. A standalone query has no original destination and fails instead of recursing into the listener. |
| Upstream name | Query that named upstream. |
| `fallback: reject\|asis\|<upstream>` | Action used when no request rule matches; default is upstream `default`. |

A source-aware lookup made for an admitted flow carries no intercepted DNS-server destination. If its request policy selects `asis`, resolution fails closed; it never falls through to the compatibility/default upstream.

### Response actions

| Action | Result |
| --- | --- |
| `accept` | Return the current response. |
| `reject` | Replace the current response with an empty successful response. |
| Upstream name | Re-query through the named upstream, then evaluate response routing again. |
| `fallback: accept\|reject\|<upstream>` | Verdict or named upstream used when no response rule matches; default is `accept`. |

NXDOMAIN and SERVFAIL bypass response routing and are returned directly, without applying response rules or fallback.

A response traversal has a maximum re-query depth of three upstreams, including the initial upstream; a fourth exchange is rejected. Re-query cycles are also rejected.

### Legacy conversion

The compatibility schema retains flat `routing.rules` entries with `domain` and `upstream`, plus a named `fallback`. These are structured compatibility fields, not additional current dae statements. `suffix:`, `keyword:`, `full:`, and `regex:` prefixes select the matcher; a bare legacy domain is an exact `full` match.

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

In a preference mode, both families remain queryable. For a non-preferred A/AAAA request, honk issues the preferred-family sibling query through the same pipeline while preserving the caller's logical source, original destination, ingress profile, and wire profile except QTYPE. If the preferred family has an address, the non-preferred answer is suppressed as NODATA; if it has none or its sibling query fails, the non-preferred answer is returned. This adds one upstream query on a relevant cache miss.

The same strategy orders bootstrap-resolved addresses for an upstream hostname. `both` and `preferipv4` dial IPv4 first; `preferipv6` dials IPv6 first. TCP, DoT, DoH, DoQ, DoH3, and proxied DNS try subsequent addresses after a failed dial. Direct UDP uses its one retry for the other family before another address in the same family, then reuses the successful socket. The compatibility-only `ipv4only` and `ipv6only` strategies filter upstream dial candidates to that family.

The internal `ipv4only` and `ipv6only` modes are not expressible with dae `ipversion_prefer` syntax.

## Cache and fixed TTL

| Key | Default | Behavior |
| --- | --- | --- |
| `optimistic_cache` | `true` | Enables cache reads and publications. |
| `optimistic_cache_ttl` | `600` | Overrides the positive answer's minimum TTL for cache lifetime and returned wire RR TTLs, but never applies to NODATA. `0` keeps the answer TTL. |
| `optimistic_stale_reply_ttl` | `30` seconds | Served-stale positive answers use this TTL; a non-zero value replaces every non-OPT RR TTL. `0` preserves cached policy-rewritten wire TTLs rather than authoritative TTLs; in that case, the outcome TTL derives from `extract_min_ttl` of that wire, falling back to 60 seconds when no positive TTL exists. For a non-zero value, the outcome TTL is the configured value even when no positive TTL exists. |
| `max_cache_size` | `10000` | Entry limit. It also scales the retained query/response wire-byte budget at 4 KiB per configured entry, with at least 65,535 bytes per shard and a 64 MiB global cap. `0` is warned and clamped to one entry. |
| `fixed_domain_ttl { domain: seconds }` | empty | Per-domain override applied before `optimistic_cache_ttl`; `0` disables caching for every response code, including NXDOMAIN and SERVFAIL. |

Request routing runs before cache lookup. Cache and background-refresh identity uses the selected upstream or exact `asis` destination, not the raw client source: clients selecting the same exchange scope share entries, while different selected upstreams or `asis` destinations remain isolated. Preferred-family rendering still retains source metadata, so source-dependent sibling policy cannot leak through foreground singleflight.

With `optimistic_cache_ttl: 0` and no `fixed_domain_ttl` override, a positive NOERROR answer uses the minimum TTL across all non-OPT answer, authority, and additional records. If any such TTL is zero, honk does not cache the response and supersedes the exact cache slot, preventing either an old address or an older negative from returning. A nonzero configured or fixed TTL still overrides that zero. Other failure response codes retain their existing TTL behavior.

Disabling cache retention does not disable DNS routing projection. An accepted uncacheable positive answer (including `fixed_domain_ttl: 0`) uses the minimum positive non-OPT wire TTL for projection, falling back to 60 seconds when all such TTLs are zero. This does not rewrite the reply or make it cacheable; cache-hit remaining lifetimes and served-stale lifetimes are unchanged.

### Negative answers

NXDOMAIN is cached for `min(SOA TTL, SOA MINIMUM, 300)` seconds. Missing SOA or a zero SOA lifetime prevents caching and removes the existing positive and negative values for the exact cache key, so an old address cannot return as stale. A foreground result replaces whichever publication is present; a refresh removes only the revision it started from. `fixed_domain_ttl: 0` prevents caching without removing an existing entry. SERVFAIL otherwise retains its SOA-derived lifetime, defaulting to 60 seconds and clamped to `1..=300`.

NODATA here means NOERROR with no answer records (`ANCOUNT=0`); a nonempty answer, including a CNAME/DNAME-only answer, remains positive. NODATA retains its full wire response in the positive slot for `min(SOA TTL, SOA MINIMUM, 300)` seconds. A nonzero `fixed_domain_ttl` takes precedence over both SOA and the cap, including when SOA is absent. Without that override, missing SOA or zero lifetime supersedes the exact slot without caching, just as for NXDOMAIN.

Cached NODATA remains eligible for serve-stale; the stale rewrite changes the SOA record TTL, not SOA MINIMUM. A response-policy `reject` applied to upstream NODATA produces an empty NOERROR wire; its cache lifetime follows the same TTL rules using the rejected answer's SOA, not the synthetic wire. Subsequent requests reuse the synthetic response for that lifetime.

Cache lifetime selection uses the original upstream answer's class, response code, and TTL even when response-policy `reject` replaces the reply with synthetic NOERROR. A rejected REFUSED therefore keeps the failure-code TTL rules; a rejected positive NOERROR uses its original TTLs when no configured or fixed override applies.

Cache hits do not count down wire record TTLs. Supersession affects memory only; it does not delete a saved persistence row.

For example:

```dae
fixed_domain_ttl {
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
