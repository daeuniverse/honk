# Group reference

This page defines the current `group { ... }` configuration surface and member-selection semantics.

## Syntax

Each group is a named subsection of `group { ... }`:

```dae
group {
    hk {
        filter: subtag('airport') && name(keyword: 'HK')
        filter: name(regex: '^Hong Kong ')
        policy: min_moving_avg
        check_url: 'https://www.gstatic.com/generate_204'
        final: direct
    }

    proxy {
        filter: group('hk')
        filter: name('backup')
        policy: select
        default: 'hk'
        final: direct
    }
}
```

## Keys

| dae key | Internal field | Default | Meaning |
| ------- | -------------- | ------- | ------- |
| (section name) | `name` | required | Group tag used as an outbound in routing and APIs. |
| `policy` | `policy` | `selector` | Member-selection policy; accepted spellings are listed below. |
| `filter: name(...)` | `filters` + `nodes` | `[]` | Select nodes by node name. The parser resolves matches to node UUIDs. |
| `filter: subtag(...)` | `filters` + `nodes` | `[]` | Select nodes by the current tag of the subscription that produced them. |
| `filter: group(...)` | `groups` | `[]` | Add nested group tags. Comma-separated arguments and pipe-separated tags are accepted. |
| `default` | `default` | `null` | Initial or fallback member tag for `selector`. |
| `final` | `final_outbound` | `null` | Node, group, `direct`, or `block` used when no member is alive. |
| `check_url` | `check_url` | `null` | Per-group TCP health-check target for non-Selector policies. A Selector ignores it with a warning. |
| — (not in dae) | `check_interval` | `null` | Per-group interval field in seconds. The current runtime does not consult it and uses the global interval. |
| — (not in dae) | `tolerance` | `50` | URLTest switch threshold in milliseconds. dae URLTest groups receive `global.check_tolerance`; the runtime applies an effective minimum of 1 ms. |
| — (not in dae) | `idle_timeout` | `null` | URLTest probe-suspension threshold after inactivity, in seconds. With `null`, the health layer uses 1800 seconds. |
| — (not in dae) | `interrupt_connections` | `false` | Close tracked connections on an actual Selector, URLTest, or Fallback selection change. LoadBalance rotation does not trigger it. |
| — (not in dae) | `id` | random UUID | Internal group identity generated when the field is absent. |

## Policies

| Canonical name | Accepted dae spellings | Behavior |
| -------------- | ---------------------- | -------- |
| `selector` | `selector`, `select`, `fixed`, `fixed(0)` | Uses the runtime choice, then `default`, then the first alive member; the choice may be a direct node or nested group tag. |
| `urltest` | `urltest`, `min_moving_avg`, `min_avg10`, `min_last_delay` | Selects the lowest-latency alive member using the halving moving average `(prev + sample) / 2` and tolerance; TCP and UDP selections are independent. |
| `loadbalance` | `loadbalance`, `roundrobin`, `round_robin`, `balance` | Round-robins over alive members with independent counters per group and TCP/UDP network. |
| `fallback` | `fallback` | Pins the first alive member in declaration order independently for TCP and UDP; recovery of an earlier member does not immediately fail back. |
| `score` | `score` | Always compiled; when explicitly selected, automatically chooses one alive member from per-target reliability-first scores. TCP/UDP and the target's IPv4/IPv6 family are independent. |

Policy matching is ASCII case-insensitive. The parser removes a parenthesized suffix when present before matching, which accepts `fixed(0)`. An unrecognized policy silently becomes `selector`. Legacy `honk` is invalid; use `score`.

If a group has exactly one unique leaf, no `final`, and that leaf is excluded by TCP health, honk still dials the same leaf as a last resort. The node remains marked dead until real traffic or probes recover it; this never implies a `direct` fallback. UDP keeps normal dead-member exclusion.

Every configured Selector proxy leaf stays warm. After resolving a nested choice, honk retains a reusable multiplexed session, a QUIC client, or one bare server TCP connection according to the leaf protocol; `direct` and `block` need no warm resource.

### Score policy

`policy: score` explicitly enables Score; it is always compiled and has no runtime tuning fields. An omitted policy remains `selector`, so merely compiling Score does not change default group behavior. Score is reliability-first; latency and throughput only fine-tune candidates whose reliability is already close.

Score makes one authoritative member selection after the ordinary health filter has removed dead candidates. Health uses the proxy server's reachable IPv4/IPv6 family, independently of the business target family used for scoring; an IPv4 proxy server can therefore carry an IPv6 target. Among the remaining members, Score first applies a Beta-prior lower-confidence useful-outcome reliability band. Inside that band, decayed setup/first-response latency is normalized to the group's fastest observed candidate and qualified dominant-direction bytes per second is normalized to the group's highest observed rate. Only untrained candidates receive deterministic cold exploration; trained attempt count earns no routing bonus. Final ties use declaration order and stable node identity, so selection neither races members nor revives a dead one.

Cold exploration samples every candidate for groups of up to four members. Larger groups sample `ceil(sqrt(n)) + 1` candidates, capped by the group size, and periodically revisit the non-incumbent with the highest Beta upper-confidence reliability bound; periodic checks occur every `2n` Score selections, clamped to 16–64. The cadence is scoped to `(group, TCP/UDP, target IPv4/IPv6 family or none)`, never an exact target, node, proxy-health family, address, or port. This keeps small groups fully covered while directing large-group probes toward candidates that can plausibly beat the incumbent.

All historical counters and weighted sums decay exponentially with a fixed 30-minute half-life. Incumbent protection grows linearly from zero to the full `0.01` utility margin over eight effective completions, so new winners are easier to correct and proven winners receive full hysteresis. Fresh failure evidence bypasses that margin; the global, target-family, and exact-target failure envelopes combine by their maximum, never their sum, and ordinary protection returns once that effective decayed value falls below `0.01` of one sample. Latency is a decayed weighted mean, not a fixed-alpha EWMA. A throughput sample qualifies only when a successful exchange moves bytes in both directions, lasts at least 1 second, and moves at least 64 KiB in its dominant direction. Qualifying samples pool dominant-direction bytes per second; smaller or shorter exchanges may still affect reliability and latency but not throughput. These constants are not configurable.

Scores are isolated by group, TCP or UDP, target IPv4 or IPv6 family, normalized exact target (lowercase domain or IP plus port), and node identity. Exact-target evidence blends with bounded group/network/family aggregate evidence until it is sufficiently trained, and may become cold again as old evidence decays. Work with a real target updates both levels; targetless warm-up updates aggregates only. Nested selection attributes one completed attempt to every Score group traversed.

Feedback covers every actual attempt that traverses a Score group: transparent TCP and UDP, DNS upstream exchanges, periodic HTTP/UDP health probes, on-demand Clash delay tests, startup/Selector/UDP warm-up, and external UI downloads. Target-bearing work uses its real host/IP, port, transport, and target family; server-only preconnect and session warm-up update aggregates without inventing a business target. Each periodic UDP cycle also runs a real TLS-in-QUIC handshake with ALPN `h3` through every node in a Score group, targeting the first HTTPS `global.tcp_check_url`; this independent `DataUdp` evidence does not change the DNS-based UDP health verdict. Instrumentation is demand-driven: non-Score paths create no `ScoreReporter` and allocate no score cell.

Score state is memory-only and process-local, with one 4,096-entry LRU for exact node-target cells and another 4,096-entry LRU for aggregate cells. Exact-target evidence measures observed transport quality, not whether a service is semantically unlocked; use existing routing or geosite rules to select a dedicated service-specific Score group when that coarse cohort is needed. A successful in-process reload shares the same state and removes cells for deleted groups or members; process restart clears it. Score cells and scorer-only domain/IP keys are never logged, persisted, or returned by Clash APIs. Established connection metadata is unaffected.

Each authorized applied multi-candidate rank records exactly one reason in this order: initial exploration (`coldExplore`), periodic exploration (`periodicExplore`), held incumbent (`incumbentHeld`), fresh-failure bypass (`freshFailureBypass`), reliability winner (`reliabilityWinner`), or performance winner (`performanceWinner`). Separately, `deadFiltered` counts unique leaf candidates removed by liveness filtering. `switchFlap` counts a committed winner returning to its previous winner within eight selections; exploration is excluded from that window. Peek and display/API reads are neutral. Authenticated `/stats.score.groups[]` exports only these aggregate TCP/UDP counters and group names; it exports no cells, nodes, targets, cadence, or manager-authority data.

For Clash compatibility, Score remains automatic but is represented as `type: "url_test"`; `now` is the current aggregate TCP winner, and `PUT /proxies/{name}` is rejected.

## Filter resolution

1. `group('tag')` adds nested tags to `groups`; it is not evaluated as a node predicate. A nested tag may contribute the leaf selected by that group's current policy.
2. `name(...)` matches `Node.name`. `subtag(...)` maps `Node.subscription_id` to the current subscription tag and matches that tag. Plain arguments are exact matches, `keyword:` is a substring match, and `regex:` is a raw regular expression. Matching is case-sensitive; multiple arguments in one predicate are alternatives.
3. Predicates joined by `&&` on one line are AND-ed. Prefixing a predicate with `!` negates it. Separate `name(...)` and `subtag(...)` `filter:` lines are OR-ed; `group(...)` lines add nested candidates.
4. Filter-derived membership is rebuilt after every subscription refresh. Stable node UUIDs therefore do not retain stale membership after their subscription provenance changes.
5. A group with neither node filters nor nested groups receives all current nodes. A group with nested groups but no node filters receives only its nested candidates, not all nodes.

## Nested groups

Nested selection is depth-capped at 8. When the group manager builds the graph, it removes each cycle-closing edge and logs a warning; an unknown nested tag contributes no candidate. Each nested group contributes the single leaf selected by its own policy, so every dial ultimately resolves to one node.

Clash-facing group output preserves member tags: the `all` field lists direct node names and nested group tags rather than expanding nested groups. Leaf-facing health and connectivity traversal expands the real nodes below those tags.

## Related docs

- [Node reference](./nodes.md)
- [Routing reference](./routing.md)
- [Group design](../design/groups.md)
