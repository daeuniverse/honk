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
| `ipversion_prefer` | omitted: `both` | `4` selects `preferipv4`; `6` selects `preferipv6`. |
| `optimistic_cache` | `true` | Enables positive and negative cache reads and writes. |
| `optimistic_cache_ttl` | `600` seconds | Fixed positive-answer cache and wire TTL; `0` preserves the answer TTL. |
| `max_cache_size` | `10000` | Maximum cache entries and the input to the retained wire-byte budget. |
| `fixed_domain_ttl { ... }` | empty | Per-domain positive TTL overrides; `0` means never cache that domain. |

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
| `reject` | Return an empty successful response. |
| Upstream name | Re-query through the named upstream, then evaluate response routing again. |
| `fallback: accept\|reject` | Verdict used when no response rule matches; default is `accept`. |

A response traversal has a maximum re-query depth of three upstreams, including the initial upstream; a fourth exchange is rejected. Re-query cycles are also rejected.

### Legacy conversion

The compatibility schema retains flat `routing.rules` entries with `domain` and `upstream`, plus a named `fallback`. When no new-style request rules exist, honk converts them to request rules at load time. `suffix:`, `keyword:`, `full:`, and `regex:` prefixes select the matcher; a bare legacy domain is an exact `full` match. The legacy fallback becomes the request fallback. These are structured compatibility fields, not additional current dae statements.

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
| `optimistic_cache_ttl` | `600` | Overrides the positive answer's minimum TTL for cache lifetime and returned wire RR TTLs. `0` keeps the answer TTL. |
| `max_cache_size` | `10000` | Entry limit. It also scales the retained query/response wire-byte budget at 4 KiB per configured entry, with at least 65,535 bytes per shard and a 64 MiB global cap. `0` is warned and clamped to one entry. |
| `fixed_domain_ttl { domain: seconds }` | empty | Per-domain override applied before `optimistic_cache_ttl`; `0` makes that domain uncacheable. |

Request routing runs before cache lookup. Cache and background-refresh identity uses the selected upstream or exact `asis` destination, not the raw client source: clients selecting the same exchange scope share entries, while different selected upstreams or `asis` destinations remain isolated. Preferred-family rendering still retains source metadata, so source-dependent sibling policy cannot leak through foreground singleflight.

For example:

```dae
fixed_domain_ttl {
    ddns.example.org: 10
    nocache.test: 0
}
```

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
