# honk Configuration Guide

Use this guide to assemble and operate a honk configuration. For installation and for the direct-only, proxy and UI/API starting points, begin with the [startup guide](./how-to-start.md#minimal-configuration). The reference docs list individual fields.

honk uses a dialect of dae configuration syntax; the [dialect reference](./reference/dialect.md) lists known differences. The table below lists the runtime sections and the CLI entry point. `include {}` composes files.

| Section | Purpose | Reference |
| --- | --- | --- |
| `global` | Select interfaces, dial behavior, health checks, and runtime paths. | [Global reference](./reference/global.md) |
| `node` | Declare static proxy nodes as share links. | [Node reference](./reference/nodes.md) |
| `group` | Select among nodes and nested groups. | [Group reference](./reference/groups.md) |
| `routing` | Apply ordered traffic rules and a fallback outbound. | [Routing reference](./reference/routing.md) |
| `dns` | Configure listeners, upstreams, request/response policy, and cache behavior. | [DNS reference](./reference/dns.md) |
| `subscription` | Fetch remote node lists. | [Subscription reference](./reference/subscription.md) |
| `assets` | Set download defaults for geodata, the external UI, and subscriptions. | [Assets reference](./reference/assets.md) |
| `experimental` | Enable the independent native API, Clash API, or persistent cache. | [Experimental reference](./reference/experimental.md) |
| CLI | Select a config, backend, object file, or local command. | [CLI reference](./reference/cli.md) |

honk injects the built-in outbounds `direct` and `block` at startup. Use them in groups and routing rules.

## Configuration format

The entry file and included `.dae` files must be UTF-8; other encodings are rejected.

- Put settings in `section { ... }` blocks as one `key: value` pair per line. One-line blocks such as `global { log_level: debug }` and nested one-line blocks are accepted.
- Prefer quoting URLs, values containing whitespace, and values containing syntax characters such as `:`, `+`, or `#`. Scalar values and `include`, `node`, and `subscription` entries accept single or double quotes.
- Quoted text is literal: escapes such as `\n` are not decoded, and a backslash only keeps the next quote from closing the string. A quote must close on the same line. `filter: name(regex: '^edge\.example$')` passes `^edge\.example$` to the regex engine.
- Matching single or double quotes keep commas, closing parentheses, `&&`, and `->` literal in matcher arguments and filter/routing expressions. `group(...)` and `qtype(...)` still interpret quoted comma-separated text as lists.
- Write lists accepted by a setting or matcher with commas: `lan_interface: eth0, eth1` or `dport(80, 443)`.
- Second-based durations such as `check_interval` and subscription `interval` take whole seconds, bare or with an `s`, `m`, or `h` suffix; `1.5s` is invalid. An `ms` value rounds up to whole seconds, so `500ms` becomes `1s`. An invalid value warns and becomes `0`, which `check_interval` rejects with `check_interval must be a positive duration`.
- Millisecond settings such as `check_tolerance` take bare milliseconds, an integer with `ms`, or seconds with `s`, so `1.5s` is 1500 ms. Fractions of a millisecond are dropped; `1.5ms` and the `m` and `h` suffixes are invalid. An invalid value warns and keeps the default.
- An unquoted token-head `#` starts a comment; hashes inside bare values remain data. Entry readers also accept a glued `#` after a closing link quote or subscription `(UA)` suffix, with `legacy-glued-hash`; put whitespace before comments. Braces inside a token-head comment never close a block.
- Braces inside matching single or double quotes are data. An unmatched closing `}` is ignored with a diagnostic; an unclosed block rejects the document. Detailed diagnostics carry physical line numbers where the current reader provides them; error text never echoes arbitrary input.
- Unknown scalar keys are diagnosed and ignored. Unknown nested blocks are skipped as complete balanced subtrees, not flattened into their parent. Only documented node/subscription wrapper compatibility remains. Some unknown content is an error instead: unknown outer `experimental` settings, unknown content in `experimental.native_api`, unsupported legacy NFQUEUE content, and a block named after a group scalar such as `tolerance`. See the [dialect reference](./reference/dialect.md#sections-and-includes).

### Splitting a configuration with `include {}`

```dae
include {
    config.d/*.dae
    config.d/*/*.dae
    'config.d/extra config.dae'
}
```

`include` entries are file patterns, bare or quoted, with `*`, `?`, and `[]` globs. An empty path, a nested block, or an invalid glob is a configuration error. Patterns run in declaration order. Each pattern's matches load in lexical order. Unmatched patterns, directories, and files without the `.dae` extension are skipped. A `**` path component matches one directory level like `*` and is not recursive, so the example lists `config.d/*/*.dae` for files one level below `config.d`.

Empty or comment-only included `.dae` files contribute no sections; the dae entry-document block requirement does not apply to these fragments.

Only top-level `include` accepts an opener on a later line, with a `legacy-include-opener` warning; prefer `include {` on one line. Include comments follow the token rule: `path.dae # note` includes `path.dae`, but `path.dae#note` is a literal glob and emits `legacy-include-hash`. Quote literal hashes to avoid the migration warning. String parsing checks include structure but never opens included files. Includes do not splice fragments into an open block.

Every relative include, including one in a nested included file, resolves against the directory containing the entry config passed to `--config`. The loader canonicalizes the entry directory and every match. It rejects any absolute path or symlink target that resolves outside that directory. It also rejects loading the same canonical file twice, directly or through a cycle.

The entry file's own sections merge first regardless of where its `include` block appears, followed by each included file and its descendants. Later scalar keys override earlier values. Collection entries such as nodes, subscriptions, groups, DNS upstreams, fixed TTLs, and routing rules append in merge order.

## Runtime data directory

`global.data_dir` is the process-wide root for runtime state and relative runtime-supplied files. It defaults to `/var/lib/honk` and must be a non-empty absolute path. Changing it requires restart.

At startup, honk recursively creates the directory and probes it by creating and removing a new private file. If the candidate is unusable, honk falls back only to a directory that passes the same probe. `--store db` and an enabled native API password login refuse this fallback.

Relative writable artifacts and read-only dependencies use the first existing candidate:

1. `<data_dir>/<path>`.
2. `/var/share/honk/<path>`.
3. The caller's legacy location: the original config directory for cache, or the working directory for other dependencies.

If none exists, honk returns `<data_dir>/<path>` for creation. Existing artifacts under `/var/share/honk` (`LEGACY_DATA_DIR`) remain usable through these fallbacks. Legacy cache and subscription imports are the exception: they copy eligible state into `state/honk.db`. Relative logs always use `<data_dir>/<path>` for creation. Absolute paths stay literal.

Geo assets use an independent regular-file search order: `$DAE_LOCATION_ASSET`, `<data_dir>`, `/var/share/honk`, the working directory, honk share directories, then dae share directories.

See the [global reference](./reference/global.md).

## Minimal configuration

Replace `eth0` and the example node address before deployment. The comments give one purpose per setting or rule.

```dae
# Set the interception baseline.
global {
    # Follow the IPv4 default-route interface.
    wan_interface: auto
    # Intercept forwarded traffic from this LAN interface.
    lan_interface: eth0
    # Emit normal operational logs.
    log_level: info
    # Also append logs to <data_dir>/honk.log.
    log_file: 'honk.log'
    # Sniff domains and verify their destination IP.
    dial_mode: domain
    # Accepted for dae compatibility; honk applies its own fixed sysctl setup.
    auto_config_kernel_parameter: true
    # Resolve proxy hostnames without self-interception.
    bootstrap_resolver: '1.1.1.1:53'
}

# Declare one static proxy node.
node {
    # Name the SOCKS5 share link `edge`.
    edge: 'socks5://192.0.2.2:1080'
}

# Turn the node into a selectable outbound.
group {
    proxy {
        # Include only the named node.
        filter: name('edge')
        # Pin the first matching member.
        policy: fixed(0)
    }
}

# Route private destinations directly and web traffic through the group.
routing {
    # Keep private destinations off the proxy.
    # This also bypasses private DNS; add && !dport(53) if interception is wanted.
    dip(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) -> direct(must)
    # Proxy common web ports.
    dport(80, 443) -> proxy
    # Send everything else directly.
    fallback: direct
}

# Keep DNS usable on a direct path.
dns {
    upstream {
        # Use a plain direct DNS server.
        public: 'udp://1.1.1.1:53' -> direct
    }
    routing {
        request {
            # Send unmatched questions to `public`.
            fallback: public
        }
    }
}
```

## Fuller configuration

This example combines a subscription, a static backup, a `subtag` filter, geo routing, proxied DoH, the Clash API, and persistent state.

```dae
global {
    wan_interface: auto
    lan_interface: br-lan
    log_level: info
    log_file: 'honk.log'
    dial_mode: domain++
    auto_config_kernel_parameter: true
    data_dir: '/var/lib/honk'
    bootstrap_resolver: '1.1.1.1:53'
    store_subscribe: true
}

node {
    backup: 'socks5://192.0.2.2:1080'
}

subscription {
    paid: 'https://subscription.example/sub' {
        interval: 3600s
    }
}

assets {
    subscription {
        ua: 'clash.meta'
    }
    ui {
        url: 'https://example.com/dashboard.zip'
        route: proxy
    }
}

group {
    proxy {
        filter: subtag('paid') && !name(keyword: 'ExpireAt-')
        filter: name('backup')
        policy: fallback
        final: block
    }
}

routing {
    # This also bypasses private DNS; add && !dport(53) if interception is wanted.
    dip(geoip: private) -> direct(must)
    domain(geosite: geolocation-cn) -> direct
    domain(geosite: geolocation-!cn) -> proxy
    fallback: proxy
}

dns {
    ipversion_prefer: 4
    # client_subnet: auto  # Optional: infer one public-path /24 for named upstreams.
    upstream {
        direct_dns: 'udp://1.1.1.1:53' -> direct
        proxy_doh: 'https://dns.google/dns-query' -> proxy
    }
    routing {
        request {
            qname(geosite: geolocation-cn) -> direct_dns
            fallback: proxy_doh
        }
        response {
            fallback: accept
        }
    }
}

experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'ui'
        secret: 'replace-me'
        default_mode: 'Rule'
    }
    cache_file {
        enabled: true
        store_dns: true
    }
}
```

## Choosing interfaces

- Set `lan_interface` to the interface receiving forwarded LAN traffic; separate multiple interfaces with commas.
- Set `wan_interface` to the interface carrying host-originated traffic. `auto` follows the IPv4 default-route interface. Without a default route it stays pending, rather than falling back to loopback, and reconciles on link, address or route changes.
- For a WAN-only host proxy, omit `lan_interface`: configured WAN hooks still process host-originated TCP and UDP. Never add `lo` as a synthetic LAN interface.

An absent, refused (`lo`, a VRF device, `dae0`) or unattachable interface never stops startup. See [interface semantics](./reference/global.md#interface-semantics).

See the [global reference](./reference/global.md).

## Choosing a dial mode

| Mode | When to use it |
| --- | --- |
| `ip` | Route only on IP metadata; disables domain sniffing. |
| `domain` | Default: sniff a domain, verify its destination IP, and re-run routing only when that verification succeeds. A miss falls through to ordinary IP/port rules. Proxy outbounds may dial by the verified name. |
| `domain+` | Sniff without the destination-IP reality check; keep the initial route and use the sniffed name only as a proxy target. |
| `domain++` | Sniff without verification and force non-reserved routing to run again from SNI/HTTP Host. |

See the [global reference](./reference/global.md).

## Declaring nodes

Each `node` line is a share link: `tag: 'scheme://...'` or a bare quoted link. An explicit tag becomes the routing/API name and overrides a name embedded in the link. A bare link uses its fragment or a generated protocol/host name. Keep credentials, TLS/REALITY, transport, and protocol tuning in the link's userinfo and query parameters. A malformed link is skipped with a diagnostic. An unknown or removed scheme, the removed VLESS `vless_mode` parameter, or a standalone `mux` line is a configuration error. Set `mux=` on each VLESS link instead.

`direct` and `block` are reserved for the built-in outbounds and cannot name a node. A group cannot share a name with a node.

See the [node reference](./reference/nodes.md).

## Building groups

Build a group in this order:

1. Select members with `filter: name(...)` for static names, `filter: subtag(...)` for subscription provenance, or `filter: group(...)` for nested groups.
2. Combine `name(...)` and `subtag(...)` predicates with `&&` for AND and `!` to negate one predicate. `group(...)` must be the whole `filter:` value; a line combining it with `&&` or `!` is ignored with a diagnostic. Separate `filter:` lines mean OR. A group with neither filters nor nested groups includes all nodes; a group with only nested-group filters does not.
3. Choose `selector`/`fixed`, `urltest`/`min_moving_avg`, `loadbalance`/`roundrobin`, `fallback`, or `score`. Set `final` for an empty policy selection.

Leave group names unquoted in the group header and after `->` or `fallback:`, even when they contain spaces. Quotes in these positions become part of the name, so `fallback: 'proxy'` does not find group `proxy`. `group(...)`, `final`, and `default` strip the quotes. Put subgroup and node selections on separate filter lines:

```dae
group {
    Hong Kong {
        filter: name(regex: '^edge\.example$')
    }
    proxy {
        filter: group('Hong Kong')
        filter: name('edge')
    }
}
routing {
    dport(443) -> Hong Kong
    fallback: Hong Kong
}
```

Selector TCP and UDP follow the chosen member and never switch to a sibling because of health. The same-leaf TCP last resort does not bypass nested Selector choices. Group dials always resolve to one leaf node.

A configuration may define at most 250 top-level user groups; the routing ABI reserves higher ordinals.

See the [group reference](./reference/groups.md).

## Writing routing rules

Rules are evaluated by ascending `priority`. The dae parser assigns `0, 1, ...` in source order, and stable equal-priority ordering preserves source order. Targets are `direct`, `block`, or a group. A bare node name is rejected at load, so wrap it in a group (for example, `filter: name('node')`). A `(must)` decision is final: sniffing is skipped, and Clash Global/Direct mode never overrides `must` or `block`. Use `dip(geoip: private)`/`dip(geoip: cn)` for GeoIP and `domain(geosite: category)` for geosite data.

For gateway management and private-DNS bypass, use the [explicit local-rule migration](./reference/routing.md#explicit-local-rules); honk does not synthesize interface rules. Dead outbounds normally fail closed: honk drops new flows instead of leaking them through `direct`. A TCP group with exactly one unique leaf and no `final` may retry that same proxy, but only within current Selector member paths. UDP groups and all-dead multi-leaf groups remain fail-closed. Point an internet `fallback` at a multi-member group with `policy: fallback` and an explicit fail-closed `final`. Keep at least one DNS upstream forced through `direct`.

See the [routing reference](./reference/routing.md).

## DNS setup

Upstream forms are bare `host:port` (UDP) or `udp://`, `tcp://`, `tcp+udp://`/`udp+tcp://`, `tls://`, `https://`, `quic://`, and `h3://` or its alias `http3://`. Add `-> node-or-group` to force the dial path. Every listed transport can use a proxy outbound when the selected leaf supplies its required capability. DoQ and DoH3 require the leaf's UDP-capable `PacketTransport`; a missing proxy registry or packet capability fails closed. Request routing chooses `reject`, `asis`, or a named upstream. Response routing chooses `accept`, `reject`, or a named upstream for a bounded re-query:

```dae
dns {
    upstream {
        home: 'udp://223.5.5.5:53' -> direct
        lan_proxy: 'https://dns.google/dns-query' -> proxy
    }
    routing {
        request {
            sip(192.168.50.0/24, 100.64.0.0/10) -> lan_proxy
            sip(127.0.0.0/8, ::1/128) && qname(suffix: example-isp.cn) -> asis
            fallback: home
        }
    }
}
```

`sip(...)` is request-only and matches the logical DNS client IP against host addresses or CIDRs. Transparent port-53 and `dns.bind` queries use their socket peer. DNS lookups made for an admitted TCP/UDP flow use that flow's client address. Internal, bootstrap, prefetch, and Clash API queries have no client source, so neither `sip(...)` nor `!sip(...)` matches and routing falls through. A source-aware flow lookup still lacks an intercepted DNS-server destination, so selecting `asis` fails closed.

Leave `bind` empty to disable only standalone listening, not transparent port-53 interception. Transparent port-53 interception still follows [traffic-rule ownership](./reference/routing.md#outbound-targets-and-must). Standalone forms require an explicit port: bare numeric `IP:port` (UDP), `udp://host:port`, `tcp://host:port`, or `tcp+udp://host:port`; an empty host binds wildcard addresses. Bind loopback unless a host firewall protects LAN exposure. Omit `ipversion_prefer` for `both`, or set `4`/`6` to prefer that family for both DNS results and bootstrap-resolved upstream dials; a failed preferred-family dial falls back to the other family.

`client_subnet` is off by default. Use a fixed IPv4/CIDR for deterministic ECS, or `auto` to infer the first public path hop as a `/24` without DNS or HTTP. Automatic inference is refreshed on reload and network changes; a bounded failure sends no generated ECS. Existing client ECS always wins. See the privacy warning in the reference before enabling it.

See the [DNS reference](./reference/dns.md).

## Subscriptions

Declare each source as `tag: 'url'`; `subtag(...)` matches that tag. To override `ua`, `interval`, `cache` or `route` for one subscription, add a block after its quoted URL.

- Shared defaults: `assets.subscription` supplies `ua`, `interval` and `cache`; `assets.route` supplies the download route unless the entry overrides it.
- Request identity: requests use `honk/<version>` unless the entry or `assets.subscription` sets `ua`. The cache key includes the configured override, so distinct request identities keep distinct stored bodies.
- Persistence: honk stores a successfully fetched and parsed raw body in the state db only when both `global.store_subscribe` (default `true`) and the entry's effective `cache` are true. Changing `store_subscribe` requires restart.
- Startup and reload: startup restores valid non-empty stored bodies before background refresh. SIGHUP carries active subscription nodes but does not restore from the store.
- Failure: fetch, parse or no-usable-node failures keep the active nodes and last valid body. Subscription nodes remain runtime-only.

See the [subscription reference](./reference/subscription.md).

## Enabling the Clash API, cache file, and held-first-packet UDP

**Native API.** `native-api` is opt-in: build with `--features native-api` (or `native-ui`), and the full and `-native-api` release artifacts include it. The listener requires `experimental.native_api.enabled: true` and one of a bearer `secret`, `password_auth: true`, or `allow_anonymous_loopback: true` on a loopback `listen`. honk sets no minimum `secret` length, so use a long random value. The default address is `127.0.0.1:9527`; explicitly anonymous loopback is for local development only. All effective native fields require a restart. An optional `ui` directory needs a readable `index.html`. Alternatively, `--features native-ui` enables `ui: embedded` with pinned real doona. The `ui: embedded-lite` value selects the lighter doona lite edition (preview) and requires `native-ui`. None of these modes downloads or builds the UI at runtime. Traffic and memory histories default on and retain at most 600 points over 600 seconds. See [native settings](./reference/experimental.md#native_api) and the [API contract](./reference/api.md#native-api).

For a captured `.dae` startup, source metadata, offline validation, and real reload operations share the existing engine. Configuration reads return the accepted content and mask only listener-secret values, including duplicate or overridden values and their other occurrences. Credential-bearing sources remain read-only and carry original-byte hashes. Source `path` remains relative and `absolute_path` adds the canonical absolute path. Admitted anonymous loopback requests read the same data as bearer-authenticated requests. `config_write` defaults false and requires a nonempty secret or `password_auth`. Creating and deleting nodes or providers in the main source, an authorized whole-source PUT, and a restricted Group PATCH reuse this authority. All accepted noncredential includes qualify for source edits when `config_write` is enabled, but not for dedicated entry deletion. Configured geodata updates use verified immutable bytes and the same reload owner. Written bytes are not automatically rolled back after activation failure. Avoid concurrent external edits; see [configuration safety](./reference/api.md#accepted-configuration-and-reload-operations) and [entry and geodata management](./reference/api.md#managed-entries-and-geodata).

With `--store db`, honk runs the active db revision; at startup it imports the `-c` file only when the db is empty. See [configuration db](./reference/api.md#configuration-db---store-db).

**Clash API.** A non-empty `experimental.clash_api.external_controller` enables the server. Keep it on loopback unless a firewall and non-empty `secret` protect it; an empty secret disables API authentication. A relative `external_ui` prefers an existing directory below `data_dir`, then `/var/share/honk`, then the working directory; if none exists, the dashboard is downloaded under `data_dir`. `assets.ui.url` selects the ZIP source, while `assets.ui.route` selects the download route, defaulting to `assets.route`. Without a configured URL or route, the built-in URL and normal traffic routing apply. `HONK_UI_DOWNLOAD_URL` overrides the ZIP URL.

**Cache file.** By default, Selector choices and delay samples persist in `<data_dir>/state/honk.db`. Setting `experimental.cache_file.enabled: true` also persists the Clash mode and GLOBAL selection when the native API is disabled; an enabled native API keeps them transient. With `store_dns: true`, it persists eligible DNS answers too. `enabled: false` persists none of them. `path`, `cache_id` and `store_fakeip` no longer have an effect; the first start imports and removes a legacy `cache.db` ([upgrade notes](./reference/experimental.md#upgrading-from-cachedb)).

**Held-first-packet UDP.** `global.nfqueue_enable` defaults to `true`, which stages ambiguous LAN-forwarded UDP through NFQUEUE. Set it to `false` to disable that staging. Changing the setting requires a restart. If startup uses mock eBPF, lacks the `ebpf` feature, or fails the fixed-queue preflight, honk logs a warning and disables NFQUEUE for that process without rewriting the config file. After the real-instance lock is acquired, startup binds queue `320` and reclaims the stale owned nftables table before publishing `inet honk_nfqueue` / `udp_decision`. A firewall manager must not mutate those reserved objects while honk runs.

See the [global reference](./reference/global.md), [experimental reference](./reference/experimental.md), and [UDP NFQUEUE design](./design/nfqueue.md).

## Warm-up and dial budget

These mechanisms are independent and bounded by configured groups or explicit budgets rather than raw subscription size. On-demand Clash delay tests are separate: cold session/QUIC nodes use a throwaway warm transport for measurement and close it afterward.

| Mechanism | Key | Default | Behavior |
| --- | --- | --- | --- |
| Bare TCP preconnect | `preconnect_node_count` | `'auto'` | One startup pass. `'auto'` tries up to 8 eligible nodes, group picks first; `0` disables it. Explicit `N` may cover all eligible nodes with at most 8 concurrent attempts. Session-owning AnyTLS/VLESS modes, QUIC, `direct`, and `block` are skipped. |
| Selector pin | — | Always on | Keeps every Selector's configured leaf warm, including an unhealthy explicit choice. It retains a reusable session/client or one bare server TCP as the protocol permits; choice changes and reload transfer ownership without cutting active flows. |
| UDP warm set | `udp_warm_node_count` | `0` | Takes the top `min(N,3)` UDP leaves per group and IP family, runs at most 4 attempts concurrently, and caps retained nodes at `4×N`. UDP and Selector ownership are independent. |
| Concurrent dial cap | `max_concurrent_dials` | `64` | Bounds physical proxy connects and handshakes per generation. Ready-pool hits, logical streams on warm transports, `direct`, and `block` are exempt; overlapping reload generations also share the startup descriptor gate. |

Periodic HTTP health checks use the same throwaway warm-path timing as Clash delay tests. Cold reusable transports warm outside the timer and close afterward. The reported latency is the second request on the warmed connection: one round trip, with dial and TLS excluded. Only a successful post-warm target exchange reports health and supplies selection RTT; setup and exchange failures update liveness/cooldown without a latency sample or ranking strike. Scans never retain one idle tunnel per node.

See the [group selection design](./design/groups.md).

## Running

```bash
# Real eBPF with the embedded object.
sudo ./target/release/honk-core --config /etc/honk/config.dae

# Real eBPF with an external object.
sudo ./target/release/honk-core \
  --config /etc/honk/config.dae \
  --bpf-object /etc/honk/honk-ebpf.o

# Unprivileged development with the mock backend.
cargo run --release -p honk-core -- \
  --config config.min.dae --mock-ebpf --debug
```

See the [CLI reference](./reference/cli.md).

## Validation tips

1. Start from the repository's `config.min.dae` or `config.dae` and replace its interfaces, endpoints, and credentials.
2. Check that every routing rule, fallback, DNS fallback, group `final` and `->` proxy target names an existing group, node, `direct` or `block`.
3. For first-connection domain rules, use `dial_mode: domain`/`domain++` or make client DNS pass through honk, so the domain routing map is populated.
4. After changing groups or policies, SIGHUP rebuilds `GroupManager`; a still-valid Selector choice migrates to the replacement generation.
5. Changing `global.nfqueue_enable` requires a restart. To enable staging, verify the real eBPF backend and startup prerequisites, and confirm that the firewall manager leaves `inet honk_nfqueue` / `udp_decision` untouched.
6. When adding or changing configuration fixtures, run `cargo test -p honk-config` to keep parser examples valid.

## Related docs

- [Design overview](./design/overview.md)
- [Global configuration reference](./reference/global.md)
- [DNS rollout operations](./operations/dns-rollout.md)
