# Group reference

`group { ... }` configures group members and selection policies. A configuration may define at most 250 top-level user groups. Higher routing ordinals are reserved by the ABI.

## Syntax

Each group is a named subsection of `group { ... }`. Declarations with the same name do not merge: the last one wins. Do not repeat a group name to extend a definition from an included file.

```dae
group {
    hk {
        filter: subtag('airport') && name(keyword: 'HK')
        filter: name(regex: '^Hong Kong ')
        policy: min_moving_avg
        check_url: 'https://probe.example:8443/check,192.0.2.10,2001:db8::10'
        icon: 'https://example.com/icon.svg'
        tolerance: 50
        idle_timeout: 1800
        interrupt_connections: true
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
| `icon` | `icon` | `null` | Absolute HTTP(S) URL with a host and no credentials, or a data URI. At most 2048 characters, without whitespace; any other value rejects the configuration. Native group reads mask listener-secret values of at least 8 bytes and never guess an icon. |
| `filter: name(...)` | `filters` + `nodes` | `[]` | Select nodes by node name. The parser resolves matches to node UUIDs. |
| `filter: subtag(...)` | `filters` + `nodes` | `[]` | Select nodes by the current tag of the subscription that produced them. |
| `filter: group(...)` | `groups` | `[]` | Add nested group tags. Comma-separated arguments and pipe-separated tags are accepted. |
| `default` | `default` | `null` | Initial or fallback member tag for `selector`. |
| `final` | `final_outbound` | `null` | Node, group, `direct`, or `block` used when the group's policy has no eligible selection, including when the group is nested. An unknown target rejects the configuration at startup or reload with `invalid-group-final-target`. Final nodes remain health-gated. A final path that loops back selects nothing and never falls back to `direct`. |
| `check_url` | `check_url` | `null` | Per-group TCP health-check target for non-Selector policies. Do not set it on a Selector: honk logs a warning and never probes the URL. The Selector still reads that URL's health for TCP, and an unprobed URL counts as healthy, so TCP health stops gating the group. |
| — (not in dae) | `check_interval` | `null` | Per-group interval field in seconds. The current runtime does not consult it and uses the global interval. |
| `tolerance` | `tolerance` | `50` | URLTest switch threshold in milliseconds, written as a plain integer: `tolerance: 50`, not `50ms`. Without an explicit value, dae URLTest groups inherit `global.check_tolerance`. The effective minimum is 1 ms. |
| `idle_timeout` | `idle_timeout` | `null` | Seconds without a selection after which a URLTest group pauses member probes, written as a plain integer: `idle_timeout: 1800`, not `30m`. With `null`, honk uses 1800 seconds. |
| `interrupt_connections` | `interrupt_connections` | `false` | Close affected live userspace transports when the selection changes, using captured group identities and network. This retires transports rather than removing tracking, and shared UDP carriers keep unaffected views. LoadBalance rotation never closes connections. Accepts `true`/`false`, `yes`/`no`, `on`/`off` or `1`/`0` in any ASCII case. Any other value rejects the configuration. |
| — (not in dae) | `id` | random UUID | Internal group identity generated when the field is absent. |

`filter:` entries accumulate. Every other key keeps its last occurrence, and honk does not validate earlier occurrences.

`check_url` takes an HTTP(S) URL; a target without a scheme uses HTTP. Comma-separated entries after the URL are literal IPv4 or IPv6 addresses on the URL's port, tried before the addresses DNS returns. Invalid entries are ignored.

A URLTest group is idle until its first selection and again after `idle_timeout` seconds without one. Periodic probes of its members pause while it is idle and resume on the next selection. `idle_timeout: 0` makes the group idle between selections; it does not time out connections. A node keeps being probed while any non-URLTest group or any active URLTest group reaches it.

## Policies

| Canonical name | Accepted dae spellings | Behavior |
| -------------- | ---------------------- | -------- |
| `selector` | `selector`, `select`, `fixed`, `fixed(0)` | For TCP and UDP independently, the group uses that network's runtime choice, then `default`, then the first existing member before health filtering. Health never replaces a valid choice with a sibling. The choice may be a direct node or nested group. |
| `urltest` | `urltest`, `min_moving_avg`, `min_avg10`, `min_last_delay` | Selects the alive member with the lowest halving moving average `(prev + sample) / 2`; members with recent unrecovered failures rank after all others. `tolerance` limits switching. TCP and UDP selections are independent. |
| `loadbalance` | `loadbalance`, `roundrobin`, `round_robin`, `balance` | Round-robins over alive members, with independent counters per group and TCP/UDP network. Consecutive connections to one destination leave through different nodes, and TCP and UDP rotate separately. A service that ties a session to the client address loses the session: sign-ins end, and Cloudflare clearances are challenged again. Use `urltest` or `score` when sessions must persist. |
| `fallback` | `fallback` | Pins the first alive member in member order independently for TCP and UDP; recovery of an earlier member does not immediately fail back. |
| `score` | `score` | Always compiled; chooses one alive member using observed reliability, fresh target quality and bounded validation. TCP/UDP and target IPv4/IPv6 evidence remain separate. |

Policy matching is ASCII case-insensitive. Before matching, the parser removes any parenthesized suffix, so it accepts `fixed(0)`. honk maps an unrecognized policy to `selector` and emits a diagnostic naming the group. Legacy `honk` is invalid; use `score`.

Direct members keep the order of the node list, not the order of filter lines or arguments: `filter: name(backup, primary)` does not put `backup` first. Nested groups follow all direct members, in the order their tags were written. This order decides the Selector's first member, Fallback preference and LoadBalance rotation.

To set a Fallback preference explicitly, put each node in its own subgroup and list the subgroups in order:

```dae
group {
    primary-only {
        filter: name('primary')
    }
    backup-only {
        filter: name('backup')
    }
    preferred {
        filter: group('primary-only', 'backup-only')
        policy: fallback
    }
}
```

A URLTest group keeps its current member until another member is faster by more than `max(tolerance, 1 ms)`. A current member without a fresh measurement or with recent failures gets no such hold.

TCP ranks by TCP probe latency, or by the group's `check_url` probes when set. UDP ranks by data UDP probe latency, then DNS UDP; a member without UDP measurements ranks last instead of borrowing its TCP latency. `check_url` does not affect UDP. Until any member has a UDP measurement, UDP reuses the group's TCP choice.

Only missing or no-longer-member choices fall through to `default` or the first declared member. An existing chosen member without an eligible leaf does not fall back to a sibling, on either TCP or UDP: the only continuations are an explicit `final` or the same-leaf TCP last-resort rule below. A chosen nested group still applies its own policy, so URLTest may select another leaf inside that group.

Each selected subgroup resolves its own explicit `final` before returning an empty result to its parent. This does not allow the parent to choose a different Selector sibling or to retry a terminal protocol refusal. For IPv6 targets, an ordinary selected leaf reachable through IPv4 proxy health is tried before a final route.

UDP eligibility requires protocol/configuration support as well as health. VMess and explicitly TCP-only leaves are excluded before selection and Score comparison; TCP remains unaffected. An incapable Selector choice does not authorize a sibling, and built-in `block` remains terminal. This capability filter does not bypass a selected node's target-specific UDP policy refusal.

When distinct nodes share a display tag, name-based defaults and Clash writes bind the first matching member in declaration order before health filtering. Native member IDs can select a particular direct member. Health cannot retarget either choice to a healthy same-name sibling.
Named `final` nodes likewise resolve the first matching configuration declaration; a healthy duplicate cannot replace it. Selection and final-node health registration use that same identity.

Native `PUT /api/v1/groups/{groupId}/selection` accepts a direct `member_id` and `network: "tcp"|"udp"|"both"`. A both-network change validates and publishes in one step. A Clash selection writes both networks and displays TCP. Per-network choices survive reload and persistence, and interruption is acknowledged only after the actual closes. On an automatic group, the same write pins the member until DELETE selection or the next configuration activation clears it.

Restricted native Group PATCH edits parser-owned source spans, but only when the group's accepted source is writable. It supports policy, default member, final, tolerance, idle timeout, interruption and check URL; it does not support icon, name or filters. It uses the quoted accepted group/config revision, independently of source disk hashes. Full validation, durable write and reload still apply, and a write is not activation success. See the [group API contract](./api.md#nodes-and-groups).

If a group has exactly one unique leaf, no `final`, and that leaf is excluded by TCP health, honk can still dial the same leaf as a last resort. It does so only when the current Selector choices lead to that leaf. This cannot bypass a chosen empty sub-group or imply a `direct` fallback. The node remains marked dead until real traffic or probes recover it; UDP keeps normal dead-member exclusion. honk logs a rate-limited warning when it serves a last resort (60s per group).

Every configured Selector TCP proxy leaf stays warm. After resolving its TCP choice, honk retains a reusable multiplexed session, a QUIC client, or one bare server TCP connection according to the leaf protocol. `direct` and `block` need no warm resource. The separate UDP warm set follows UDP selection.

### URLTest cold start

Before any member has a latency measurement, a connection routed to a URLTest group races members and keeps the first that connects. TCP starts at most three members, 200 ms apart. UDP starts members at 0, 30, 80 and 160 ms, then every further 80 ms, with at most three attempts at once, and sends no application data until one wins. A cold URLTest group nested in another group contributes one member and does not race.

### Score policy

`policy: score` explicitly enables Score. Score is always compiled and has no runtime tuning fields. An omitted policy remains `selector`. Reliability protects admission, but extra historical successes alone do not exclude a less-sampled, validated faster node.

Score chooses one authoritative leaf after ordinary health filtering. Proxy-health family is independent of business-target family. First-choice utility and its `WeightedMean` performance heuristic stay unchanged. Once a candidate has enough observations, comparison uses its actual failure risk rather than the most-sampled node's lower bound. Sparse evidence gets bounded trials. Configured probe quality supplies a baseline that fresh, trustworthy target evidence can override. Equal values fall back to declaration order and stable identity. Healthy-incumbent promotion uses separate bounded comparison evidence, not the heuristic alone.

Optional trials use a budget for each retained `(group, TCP/UDP, target family)` scope:

- Initial allowance: the scope freezes member count `n` and cold allowance `B`. `B` covers all members up to four; otherwise it is `ceil(sqrt(n)) + 1`.
- Earned credit: each original business start (counted in `N`) adds `1/q`, normally with `q = 16`. It uses `q = 8` only while two conditions hold. The group's recent original business on that network (five-minute half-life) must imply at least two flows per second, and the scope must have at least three recent optional-trial outcomes with at least 80% success (ten-minute half-life; decayed weight above 2.5). Evidence needs a fixed number of trials, so busy groups whose trials pay off fund it sooner. Quiet groups keep the smaller share. Target refusals do not count as trial outcomes, and reload clears these outcomes.
- Low-yield pause: two or more recent failures pause optional trials until those failures decay. The pause applies while the ordinary selection is observed usable and every scope behind a read has recent outcomes under 20% success. With one recent failure, trials proceed one at a time. Each candidate refused by a paused scope counts in `budgetBlocked` and reads as a `budget` wait, just like exhausted credit. A member with a trial already in flight still reads `inFlight`. Without a usable selection, exploration continues so Score can escape. Recovery continuations are unaffected.
- Budget ceiling: spent trials `V` plus unbegun reservations `R` never exceed `B` plus the whole earned credit. Unspent earned credit is capped at eight.
- Counting: `N` includes chosen trials, but retries, clones and repeated nested attribution cannot multiply it. The root count deduplicates nested groups. Time, reads, new targets and evidence expiry grant no credit. Retained scopes preserve currency through reload and membership changes.
- Spending and refunds: node-specific work spends credit before DNS/admission waits, separately from the physical/logical reporter start. Releasing the last reference before work begins refunds a reservation; cancellation after work begins does not. Recovery retries are separate, budget-neutral work.
- In-flight limit: each member has at most one unanswered trial for its open question on a target. Except for recovery, a member is dispatched only while its completions plus unfinished work stay below the selection's completions.
- Failure handling: trials do not become ordinary incumbents. Real failures retain exponential backoff and three-failure normal exclusion; recovery remains possible after backoff expires.

Business reliability keeps its 30-minute half-life. Heuristic performance confidence ages on its own and expires after 120 seconds, whatever the sample count. Setup and first response publish immediately. Accepted transfer progress uses nonoverlapping 1–10 second windows, with at least 64 KiB in the measured direction, bidirectional flow progress and a response. Windows never multiply terminal outcomes. Goodput depends on the workload, not on link capacity, and silence is not congestion. Mature switching protection stays at `0.005` after eight effective completions, using the maximum separately decayed support across applicable layers. Ineligible incumbents and unresolved business failures bypass holding. Recovered historical failure mass alone does not.

Only a real switch to another leaf takes priority over optional validation. A failed incumbent that stays selected does not block a funded, actionable challenger trial, and the trial does not clear the failure or its backoff.

Promotion compares every eligible challenger in the shared serving pool against one fixed incumbent. Pool capacity k follows demand, with a √n ceiling for larger groups. Every ordinary or trial selection is in-pool, and no extra winner slot exists (see [conditional verification](../design/groups.md#conditional-verification)). The comparison uses paired exact targets: at most eight common targets, canonically selected and response-qualified, or the same current configured-probe cohort. Common-target qualification runs before the cap and never selects by measured value. Skipped unqualified or capped matched targets leave only a partial comparison, and that member's response gap stays pending. Directional metrics intersect over the same selected response cohort. Business proof uses four shared 15-second blocks, expiring at block start plus 60 seconds. Configured probes use four blocks of `max(15s, 2I)` for their actual interval `I`, with expiry capped by the weaker side's latest support plus `max(60s, 2I)`. Each metric still needs four distinct reporters per side, and a changed cadence cannot inherit earlier probe support. Directional gain requires at least 10% improvement, no more than 10% regression in another known direction, response no more than 10% slower, and equal or better qualified terminal reliability. Unknown directions stay unknown. Opposing changes are reported as a tradeoff instead of being hidden by a best-direction score. Paired response and qualified reliability gains still feed the existing hold-margin decision. honk adds no Score tuning field; see [the lifecycle design](../design/groups.md#score-scoring-and-lifecycle).

Readonly pairwise relations are separate from that switching decision. They compare actual response values with symmetric 10% practical equivalence, not completion maturity or a millisecond floor, and they describe response time only. Reliability and directional protections stay with switching. A missing pair response requests budgeted comparable business traffic, not bandwidth testing. See [conditional verification](../design/groups.md#conditional-verification).

Targeted Traffic RX after setup/TX can open budgeted half-open recovery before a flow ends. Four distinct reporters in the exact cell's uninterrupted post-failure cohort clear its hard episode and grant a current 60-second qualification lease. Neither one reply nor another target's recovered aggregate suffices. Historical failures remain in utility and promotion, and no terminal successes are invented. Initial cold qualification still requires four effective useful completions. RX may renew an earned lease, but a reload alone does not grant recovery. Publication is event-driven: at most once per second per reporter, after the first eligible RX. Target-path failures affect only exact-target hard state, while numeric aggregate outcomes remain. Explicit carrier/proxy faults and unknown pre-setup failures remain node-scoped and fence dependent evidence. See [scoped recovery and optional validation](../design/groups.md#score-scoring-and-lifecycle).

Business scores remain scoped by group, transport, target family, normalized target and node identity. honk blends global, family and exact reliability without adding overlapping completions. Target performance overrides its baseline only while fresh and comparable. Probe RTT keeps separate protocol/family and normalized HTTP URI/method identity, and warm-up supplies setup quality only. Nested paths attribute a real outcome once to every traversed Score group.

Transparent TCP/UDP, supported DNS exchanges and UI downloads report actual business attempts. Configured HTTP/UDP/QUIC probes provide fresh quality without adding business successes or clearing traffic streaks. Manual Clash delay measurements keep their Alive/API history, but they do not feed a configured Score baseline or turn arbitrary target failure into real-dial demotion. Actual preparation remains warm-up evidence. Independent Score QUIC handshakes preserve existing DataUdp health recovery without inventing byte volume.

Sustained measured carrier pressure may reopen bounded comparison without adding business failures or directly changing the winner. This is honk-to-proxy advisory evidence, not end-to-end UDP loss or a first-request guarantee. Unsupported paths remain unknown. See [carrier-pressure scope](../design/groups.md#score-scoring-and-lifecycle).

Score state is memory-only and process-local, with one 4,096-entry LRU for exact node-target cells and another 4,096-entry LRU for aggregate cells. Exact-target evidence measures observed transport quality, not whether a service is semantically unlocked. When that coarse cohort is needed, use existing routing or geosite rules to select a dedicated service-specific Score group. A successful in-process reload shares the same state and removes cells for deleted groups or members; a process restart clears it. Score cells and scorer-only domain/IP keys are never logged, persisted, or returned by Clash APIs. Established connection metadata is unaffected.

The separate comparison store has at most 512 cells and a 1 MiB logical-allocation limit, including owned key and vector capacity. This is not a process RSS limit; allocator overhead and other state sit outside it. Missing or evicted support remains unknown.

After a retryable TCP setup failure, a Score-owned request may try one different permitted leaf, even when ordinary ranking still prefers the failed node. Both attempts share a deadline and existing dial admission. Selector boundaries and actual primary final-edge provenance remain authoritative; honk adds no direct/final route and replays no application payload. A committed reload invalidates probe baselines but retains valid in-flight business evidence, and neutral cells stay within the existing bounded LRUs.

Each authorized applied multi-candidate rank records exactly one reason: `coldExplore`, `periodicExplore`, `incumbentIneligible`, `freshFailureBypass`, `insufficientEvidenceHeld`, `directionalTradeoffHeld`, `incumbentHeld`, `reliabilityWinner` or `performanceWinner`. `ordinarySwitch` counts committed same-scope A→B changes, excluding first choices and trials. `switchFlap` counts the subset that returns to the previous winner within eight ordinary choices. Candidate filtering and backoff counters stay separate. Peek and display/API reads are neutral. Authenticated `/stats.score.groups[]` exposes fixed group/network reason, verification and budget fields, and `/stats.score.cache` describes evidence and comparison storage. Trial outcomes and setup/elapsed costs are observations, not causal extra failure or overhead estimates. See [API reason semantics](./api.md#score-selection-reason-fields); honk exports no scorer-private node or target identities.

For Clash compatibility, Score remains automatic but is represented as `type: "url_test"`; `now` is the current aggregate TCP winner, and `PUT /proxies/{name}` is rejected.

Sampling resolves availability, response, ordinary qualification and recovery gaps within the shared budget. Fresh equivalent cohorts stop forced sampling once qualification and recovery gaps also close. Missing transfer waits for real offered load. `scoreVerification` distinguishes provisional forwarding, observed usability, fresh pairwise `challengers` relations, the evidence `question` and `waitReason`. Aggregate reads inspect retained IPv4/IPv6 waits without spending credit. See [API verification](./api.md#score-verification). Relations are retractable empirical observations, not a guarantee of best-arm identification or future network behavior.

Each challenger's pair with the selection is judged on its own shared blocks; there is no joint alignment across challengers. One dispatch order serves optional work: untrained members first, then the most progress toward a member's open question, then the least recently selected member. Trials preserve business currency and in-flight bounds and never replay requests. Readonly `question`, `nextAction` and `waitReason` report the first member of that order without exposing target identities.

## Filter resolution

1. A standalone `group('tag')` line adds nested tags to `groups`. It is not evaluated as a node predicate. A nested tag may contribute the leaf selected by that group's current policy. A `group(...)` line containing another predicate or trailing text is reported as a diagnostic and ignored. A group whose only filter is such a line remains empty.
2. `name(...)` matches `Node.name`. `subtag(...)` maps `Node.subscription_id` to the current subscription tag and matches that tag. Plain arguments are exact matches, `keyword:` is a substring match, and `regex:` uses [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax). Matching is case-sensitive; multiple arguments in one predicate are alternatives. An invalid regex makes honk ignore that filter line; other filter lines still contribute members.
3. `&&` combines predicates on one line with AND. Prefixing a predicate with `!` negates it. Separate `name(...)` and `subtag(...)` `filter:` lines combine with OR; standalone `group(...)` lines add nested candidates.
4. Filter-derived membership is rebuilt after every subscription refresh. Stable node UUIDs therefore do not retain stale membership after their subscription provenance changes.
5. A group with neither node filters nor nested groups selects all current nodes. Explicit `group()`, an empty filter, an empty nested group, or a filter emptied by subscription refresh selects nothing. Empty contributions remain explicit through JSON/YAML/TOML round-trips and refresh; valid sibling filters still contribute by OR, and `final` remains independent.

A filter honk cannot parse is ignored. Its diagnostic reports the ordinal among the group's node filters, counting mixed lines but excluding nonempty standalone `group(...)` lines. `group()` emits `empty-subgroup`. To include all nodes, remove the filter, because an explicit `group()` now selects none. The injected `direct` and `block` are outbounds, not pool members. An unfiltered group, `keyword:`, `regex:` and `subtag(...)` never select them, and only a filter that spells the name exactly (`filter: name(direct)`) admits one.

```dae
group {
    paid-nodes {
        filter: subtag(paid, regex: '^premium-') && !name(keyword: 'Expired')
    }
    named-nodes {
        filter: name('primary', 'backup')
    }
    literal-names {
        filter: name('a&&b', 'a,b', 'keyword: HK')
    }
    provider-only {
        filter: subtag('paid') && !subtag('expired-provider')
    }
}
```

Quote values that contain `&&` or `,`, as in `name('a&&b')`. `name(keyword: 'HK')` matches a substring, but `name('keyword: HK')` matches a node named exactly `keyword: HK`.

A node without a current subscription tag, such as an inline node, never matches `subtag(...)`, so it does match `!subtag(...)`. Add a positive `subtag(...)` when only subscription nodes should qualify.

For nested groups, prefer `group('hk', 'jp')`; `group(hk|jp)` also works. Quotes do not protect `|` or `,` here: `group('hk|jp')` still adds two groups and emits `legacy-quoted-list`. Repeated tags are dropped.

## Nested groups

Nested tags must name declared groups. An unknown tag rejects the configuration at startup or reload with `invalid-nested-group-reference`. When the group manager builds the graph, it removes each cycle-closing edge and logs a warning. Nested selection is capped at depth 8. Each nested group contributes the single leaf selected by its own policy, so every dial ends at one node.

Clash-facing group output preserves member tags: the `all` field lists direct node names and nested group tags rather than expanding nested groups. Leaf-facing health and connectivity traversal expands the real nodes below those tags.

## Related docs

- [Node reference](./nodes.md)
- [Routing reference](./routing.md)
- [Group design](../design/groups.md)
