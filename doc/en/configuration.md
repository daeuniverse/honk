# honk Configuration Guide

Use this guide to assemble and operate a honk configuration; the reference docs list individual fields.

honk uses a dialect of dae configuration syntax; the [dialect reference](./reference/dialect.md) lists known differences. The table lists runtime sections and the CLI entry point. `include {}` composes files.

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

honk injects the built-in outbounds `direct` and `block` at startup. They may be used in groups and routing rules.

## Configuration format

- Put settings in `section { ... }` blocks as one `key: value` pair per line. One-line blocks such as `global { log_level: debug }` and nested one-line blocks are accepted.
- Quote URLs, values containing whitespace, and values containing syntax characters such as `:`, `+`, or `#`. Scalar values plus `include` and `node` entries accept single or double quotes; use single quotes for quoted `subscription` URLs.
- Matching single or double quotes keep commas, closing parentheses, `&&`, and `->` literal in matcher arguments and filter/routing expressions. `group(...)` and `qtype(...)` still interpret quoted comma-separated text as lists.
- Write lists accepted by a setting or matcher with commas: `lan_interface: eth0, eth1` or `dport(80, 443)`.
- Second-based durations accept bare seconds or `ms`, `s`, `m`, and `h` suffixes. Millisecond settings such as `check_tolerance` accept bare milliseconds, `ms`, or `s`.
- An unquoted token-head `#` starts a comment; hashes inside bare values remain data. Entry readers also accept a glued `#` after a closing link quote or subscription `(UA)` suffix, with `legacy-glued-hash`; put whitespace before comments. Token-head comment braces never close blocks.
- Braces inside matching single or double quotes are data. An unmatched closing `}` is ignored with a diagnostic; an unclosed block rejects the document. Detailed diagnostics carry physical line numbers where the current reader provides them; error text never echoes arbitrary input.
- Unknown scalar keys are diagnosed and ignored. Unknown nested blocks are skipped as complete balanced subtrees, not flattened into their parent. Only documented node/subscription wrapper compatibility remains; unknown outer experimental settings and unsupported legacy NFQUEUE content are errors.

### Splitting a configuration with `include {}`

```dae
include {
    config.d/*.dae
    'config.d/extra config.dae'
}
```

`include` entries may be bare or quoted and support `*`, `?`, and `[]` glob patterns. Patterns run in declaration order; each pattern's matches load in lexical order. Unmatched patterns, directories, and files without the `.dae` extension are skipped.

Empty or comment-only included `.dae` files contribute no sections; the dae entry-document block requirement does not apply to these fragments.

Only top-level `include` accepts an opener on a later line, with a `legacy-include-opener` warning; prefer `include {` on one line. Include comments follow the token rule: `path.dae # note` includes `path.dae`, but `path.dae#note` is a literal glob and emits `legacy-include-hash`. Quote literal hashes to avoid the migration warning. String parsing checks include structure but never opens included files; includes do not splice fragments into an open block.

Every relative include, including one in a nested included file, resolves against the directory containing the entry config passed to `--config`. The loader canonicalizes the entry directory and every match; an absolute path or symlink target outside that directory is rejected. Loading the same canonical file twice, directly or through a cycle, is also rejected.

The entry file's own sections merge first regardless of where its `include` block appears, followed by each included file and its descendants. Later scalar keys override earlier values. Collection entries such as nodes, subscriptions, groups, DNS upstreams, fixed TTLs, and routing rules append in merge order.

## Runtime data directory

`global.data_dir` is the process-wide root for runtime state and relative runtime-supplied files. It defaults to `/var/lib/honk`, must be a non-empty absolute path, and is restart-required. At startup honk recursively creates the directory and probes it with a private create-new/remove file; an unusable candidate falls back only to a working directory that passes the same probe. Existing artifacts under `/var/share/honk` (`LEGACY_DATA_DIR`) remain usable without automatic migration; reused writable state continues to be updated in place. For relative writable artifacts and read-only dependencies, honk checks an existing `<data_dir>/<path>`, then an existing `/var/share/honk/<path>`, then the existing per-caller legacy candidate (the original config directory for cache, or the working directory for other dependencies), and otherwise returns `<data_dir>/<path>` for creation. Relative logs are creation-only and always use `<data_dir>/<path>`; absolute paths stay literal. Geo assets use an independent regular-file search order: `$DAE_LOCATION_ASSET`, `<data_dir>`, `/var/share/honk`, the working directory, honk share directories, then dae share directories.

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
    # Apply the recommended gateway sysctls.
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

Set `lan_interface` to the interface or comma-separated interfaces receiving forwarded LAN traffic, and `wan_interface` to the interface carrying host-originated traffic. `auto` follows the IPv4 default-route interface; it stays pending rather than falling back to loopback when no default route exists, then reconciles on link, address, or route changes. For a WAN-only host proxy, omit `lan_interface`: configured WAN hooks still process host-originated TCP and UDP. Never add `lo` as a synthetic LAN interface.

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

Each `node` line is a share link: `tag: 'scheme://...'` or a bare quoted link. An explicit tag becomes the routing/API name and overrides a name embedded in the link; a bare link uses its fragment or a generated protocol/host name. Keep credentials, TLS/REALITY, transport, and protocol tuning in the link's userinfo and query parameters. Unparseable entries are skipped with a diagnostic, while removed protocols are hard configuration errors.

See the [node reference](./reference/nodes.md).

## Building groups

Use `filter: name(...)` for static names, `filter: subtag(...)` for subscription provenance, and `filter: group(...)` for nested groups. Predicates joined by `&&` are ANDed and `!` negates one predicate; separate `filter:` lines are ORed. No filters and no nested groups include all nodes, while nested groups alone do not. Choose `selector`/`fixed`, `urltest`/`min_moving_avg`, `loadbalance`/`roundrobin`, or `fallback`; set `final` for an empty policy selection. Selector TCP and UDP follow the chosen member and never switch to a sibling because of health; the same-leaf TCP last resort does not bypass nested Selector choices. Group dials always resolve to one leaf node. A configuration may define at most 250 top-level user groups; higher ordinals are reserved by the routing ABI.

See the [group reference](./reference/groups.md).

## Writing routing rules

Rules are evaluated by ascending `priority`; the dae parser assigns `0, 1, ...` in source order, and stable equal-priority ordering preserves source order. Targets are `direct`, `block`, or a group; a bare node name is rejected at load — wrap it in a group (e.g. `filter: name('node')`). A `(must)` decision is final: sniffing is skipped, and Clash Global/Direct mode never overrides `must` or `block`. Use `dip(geoip: private)`/`dip(geoip: cn)` for GeoIP and `domain(geosite: category)` for geosite data.

For gateway management and private-DNS bypass, use the [explicit local-rule migration](./reference/routing.md#explicit-local-rules); honk does not synthesize interface rules. Dead outbounds normally fail closed: new flows are dropped rather than leaked through `direct`. A TCP group with exactly one unique leaf and no `final` may retry that same proxy only within current Selector member paths; UDP and all-dead multi-leaf groups remain fail-closed. Point internet `fallback` at a multi-member group with `policy: fallback` and an explicit fail-closed `final`, and keep at least one DNS upstream forced through `direct`.

See the [routing reference](./reference/routing.md).

## DNS setup

Upstream forms are bare `host:port` (UDP) or `udp://`, `tcp://`, `tcp+udp://`/`udp+tcp://`, `tls://`, `https://`, `quic://`, and `h3://`. Add `-> node-or-group` to force the dial path; every listed transport can use a proxy outbound when the selected leaf supplies its required capability. DoQ and DoH3 require the leaf's UDP-capable `PacketTransport`; a missing proxy registry or packet capability fails closed. Request routing chooses `reject`, `asis`, or a named upstream; response routing chooses `accept`, `reject`, or a named upstream for a bounded re-query:

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

`sip(...)` is request-only and matches the logical DNS client IP against host addresses or CIDRs. Transparent port-53 and `dns.bind` queries use their socket peer; DNS lookups made for an admitted TCP/UDP flow use that flow's client address. Internal, bootstrap, prefetch, and Clash API queries have no client source, so neither `sip(...)` nor `!sip(...)` matches and routing falls through. A source-aware flow lookup still has no intercepted DNS-server destination, so selecting `asis` fails closed.

Leave `bind` empty to disable only standalone listening, not transparent port-53 interception; [traffic-rule ownership](./reference/routing.md#outbound-targets-and-must) still applies. Standalone forms require an explicit port: bare numeric `IP:port` (UDP), `udp://host:port`, `tcp://host:port`, or `tcp+udp://host:port`; an empty host binds wildcard addresses. Bind loopback unless a host firewall protects LAN exposure. Omit `ipversion_prefer` for `both`, or set `4`/`6` to prefer that family for both DNS results and bootstrap-resolved upstream dials; a failed preferred-family dial falls back to the other family.

`client_subnet` is off by default. Use a fixed IPv4/CIDR for deterministic ECS, or `auto` to infer the first public path hop as a `/24` without DNS or HTTP. Automatic inference is refreshed on reload and network changes; a bounded failure sends no generated ECS. Existing client ECS always wins. See the privacy warning in the reference before enabling it.

See the [DNS reference](./reference/dns.md).

## Subscriptions

Declare each source as `tag: 'url'`; add a block after the quoted URL for per-subscription `ua`, `interval`, `cache`, or `route` overrides. `assets.subscription` supplies shared `ua`, `interval`, and `cache` defaults; `assets.route` supplies the download route unless an entry overrides it. The tag is what `subtag(...)` matches. A successfully fetched and parsed raw body is stored in the state db only when `global.store_subscribe` (default `true`) and the entry's effective `cache` are both true. Requests use `honk/<version>` unless the entry or `assets.subscription` sets `ua`; the cache key includes the configured override, so distinct request identities keep distinct stored bodies. Startup restores valid non-empty stored bodies before background refresh; SIGHUP carries active subscription nodes but does not restore from the store. Fetch, parse, or no-usable-node failures keep the active nodes and last valid body. Subscription nodes remain runtime-only. Changing `store_subscribe` requires restart.

See the [subscription reference](./reference/subscription.md).

## Enabling the Clash API, cache file, and held-first-packet UDP

**Native API.** `native-api` is opt-in: build with `--features native-api` (or `native-ui`); release builds include it. The listener requires `experimental.native_api.enabled: true` and one of a bearer `secret`, `password_auth: true`, or `allow_anonymous_loopback: true` on a loopback `listen`. honk sets no minimum `secret` length; use a long random value. The default address is `127.0.0.1:9527`; explicitly anonymous loopback is for local development only. All effective native fields require restart. An optional `ui` directory needs readable `index.html`; alternatively `--features native-ui` enables `ui: embedded` with pinned real doona. Neither mode downloads/builds the UI at runtime. Traffic/memory histories default on and retain at most 600 points/600 seconds. See [native settings](./reference/experimental.md#native_api) and the [API contract](./reference/api.md#native-api).

For a captured `.dae` startup, source metadata, offline validation and real reload operations share the existing engine. Configuration reads return accepted content with only listener-secret values masked, including duplicate/overridden values and their other occurrences; credential-bearing sources remain read-only with original-byte hashes. Source `path` remains relative and `absolute_path` adds the canonical absolute path. Admitted anonymous loopback requests read the same data as bearer-authenticated requests. `config_write` defaults false and requires a nonempty secret or `password_auth`. Main-source node/provider creation and deletion, authorized whole-source PUT and restricted Group PATCH reuse this authority; all accepted noncredential includes qualify for source edits when `config_write` is enabled, but not dedicated entry deletion. Configured geodata updates use verified immutable bytes and the same reload owner. Written bytes are not automatically rolled back after activation failure. Avoid concurrent external edits; see [configuration safety](./reference/api.md#accepted-configuration-and-reload-operations) and [entry and geodata management](./reference/api.md#managed-entries-and-geodata).

**Clash API.** A non-empty `experimental.clash_api.external_controller` enables the server. Keep it on loopback unless a firewall and non-empty `secret` protect it; an empty secret disables API authentication. A relative `external_ui` prefers an existing directory below `data_dir`, then `/var/share/honk`, then the working directory; if none exists, the dashboard is downloaded under `data_dir`. `assets.ui.url` selects the ZIP source, while `assets.ui.route` selects the download route, defaulting to `assets.route`. Without a configured URL or route, the built-in URL and normal traffic routing apply. `HONK_UI_DOWNLOAD_URL` overrides the ZIP URL.

**Cache file.** By default, Selector choices and delay samples persist in `<data_dir>/state/honk.db`. `experimental.cache_file.enabled: true` also persists the Clash mode and GLOBAL selection, and with `store_dns: true` eligible DNS answers; `enabled: false` persists none of them. `path`, `cache_id` and `store_fakeip` no longer have an effect; the first start imports and removes a legacy `cache.db` ([upgrade notes](./reference/experimental.md#upgrading-from-cachedb)).

**Held-first-packet UDP.** `global.nfqueue_enable` defaults to `true`; set it to `false` to disable NFQUEUE staging for ambiguous LAN-forwarded UDP. The setting is restart-required. If startup uses mock eBPF, lacks the `ebpf` feature, or fails the fixed-queue preflight, honk logs a warning and disables NFQUEUE for that process without rewriting the config file. After the real-instance lock is acquired, startup binds queue `320` and reclaims the stale owned nftables table before publishing `inet honk_nfqueue` / `udp_decision`; a firewall manager must not mutate those reserved objects while honk runs.

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
2. Ensure every routing rule/fallback, DNS fallback, group `final`, and `->` proxy target names an existing group, node, `direct`, or `block` as appropriate.
3. For first-connection domain rules, use `dial_mode: domain`/`domain++` or ensure client DNS passes through honk so the domain routing map is populated.
4. After changing groups or policies, SIGHUP rebuilds `GroupManager`; a still-valid Selector choice migrates to the replacement generation.
5. Changing `global.nfqueue_enable` requires a restart. To enable staging, verify the real eBPF backend and startup prerequisites, and ensure the firewall manager leaves `inet honk_nfqueue` / `udp_decision` untouched.
6. When adding or changing configuration fixtures, run `cargo test -p honk-config` to keep parser examples valid.

## Related docs

- [Design overview](./design/overview.md)
- [Global configuration reference](./reference/global.md)
- [DNS rollout operations](./operations/dns-rollout.md)
