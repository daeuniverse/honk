# Group reference

This page defines the current `group { ... }` configuration surface and member-selection semantics. A configuration may define at most 250 top-level user groups; higher routing ordinals are reserved by the ABI.

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
| `final` | `final_outbound` | `null` | Node, group, `direct`, or `block` used when the group's policy has no eligible selection, including when that group is nested. Final nodes remain health-gated; missing or cyclic finals fail closed, never implicitly direct. |
| `check_url` | `check_url` | `null` | Per-group TCP health-check target for non-Selector policies. A Selector ignores it with a warning. |
| — (not in dae) | `check_interval` | `null` | Per-group interval field in seconds. The current runtime does not consult it and uses the global interval. |
| — (not in dae) | `tolerance` | `50` | URLTest switch threshold in milliseconds. dae URLTest groups receive `global.check_tolerance`; the runtime applies an effective minimum of 1 ms. |
| — (not in dae) | `idle_timeout` | `null` | URLTest probe-suspension threshold after inactivity, in seconds. With `null`, the health layer uses 1800 seconds. |
| — (not in dae) | `interrupt_connections` | `false` | Requests tracking removal on selection changes, not cancellation of live relays. A true value emits `ineffective-option` at `groups[index].interrupt_connections`, including structured and constructed configurations. |
| — (not in dae) | `id` | random UUID | Internal group identity generated when the field is absent. |

## Policies

| Canonical name | Accepted dae spellings | Behavior |
| -------------- | ---------------------- | -------- |
| `selector` | `selector`, `select`, `fixed`, `fixed(0)` | Uses the runtime choice, then `default`, then the first existing member before health filtering, identically for TCP and UDP. Health never replaces a valid choice with a sibling. The choice may be a direct node or nested group tag. |
| `urltest` | `urltest`, `min_moving_avg`, `min_avg10`, `min_last_delay` | Selects the lowest-latency alive member using the halving moving average `(prev + sample) / 2` and tolerance; TCP and UDP selections are independent. |
| `loadbalance` | `loadbalance`, `roundrobin`, `round_robin`, `balance` | Round-robins over alive members with independent counters per group and TCP/UDP network. |
| `fallback` | `fallback` | Pins the first alive member in declaration order independently for TCP and UDP; recovery of an earlier member does not immediately fail back. |
| `score` | `score` | Always compiled; chooses one alive member using observed reliability, fresh target quality and bounded validation. TCP/UDP and target IPv4/IPv6 evidence remain separate. |

Policy matching is ASCII case-insensitive. The parser removes a parenthesized suffix when present before matching, which accepts `fixed(0)`. An unrecognized policy becomes `selector` and a diagnostic names the group. Legacy `honk` is invalid; use `score`.

Only missing or no-longer-member choices fall through to `default` or the first declared member. An existing chosen member without an eligible leaf does not fall back to a sibling, on either TCP or UDP: the only continuations are an explicit `final` or the same-leaf TCP last-resort rule below. A chosen nested group still applies its own policy, so URLTest may select another leaf inside that group.

Each selected subgroup resolves its own explicit `final` before returning an empty result to its parent. This is not permission to choose a different Selector sibling or retry a terminal protocol refusal. For IPv6 targets, an ordinary selected leaf reachable through IPv4 proxy health is tried before a final route.

UDP eligibility requires protocol/configuration support as well as health. VMess and explicitly TCP-only leaves are excluded before selection and Score comparison; TCP remains unaffected. An incapable Selector choice does not authorize a sibling, and built-in `block` remains terminal. This capability filter does not bypass a selected node's target-specific UDP policy refusal.

When distinct nodes share a display tag, Selector binds the first matching member in the group's declaration order by `NodeId`, before health filtering. A healthy same-name node cannot replace that member.
Named `final` nodes likewise resolve the first matching configuration declaration; a healthy duplicate cannot replace it. Selection and final-node health registration use that same identity.

If a group has exactly one unique leaf, no `final`, and that leaf is excluded by TCP health, honk can still dial the same leaf as a last resort, but only if the current Selector choices lead to it. This cannot bypass a chosen empty sub-group or imply a `direct` fallback. The node remains marked dead until real traffic or probes recover it; UDP keeps normal dead-member exclusion. Last-resort serving logs a rate-limited warning (60s per group).

Every configured Selector proxy leaf stays warm. After resolving a nested choice, honk retains a reusable multiplexed session, a QUIC client, or one bare server TCP connection according to the leaf protocol; `direct` and `block` need no warm resource.

### Score policy

`policy: score` explicitly enables Score; it is always compiled and has no runtime tuning fields. An omitted policy remains `selector`. Reliability protects admission, but additional historical successes alone do not exclude a less-sampled, validated faster node.

Score chooses one authoritative leaf after ordinary health filtering. Proxy-health family is independent of business-target family. First-choice utility and its `WeightedMean` performance heuristic remain unchanged; sufficiently observed candidates compare actual failure risk rather than the most-sampled node's lower bound. Sparse evidence gets bounded trials. Configured probe quality is a baseline, not an infallible judge: fresh trustworthy target evidence can override it. Equal values use declaration order and stable identity. Healthy-incumbent promotion uses separate bounded comparison evidence, not the heuristic alone.

Each retained `(group, TCP/UDP, target family)` scope freezes member count `n`, cold allowance `B` (all members up to four, otherwise `ceil(sqrt(n)) + 1`) and the fixed earning period `q = 16`. Original business starts `N` fund optional work: spent trials `V` plus unbegun reservations `R` never exceed `B + floor(N/q)`; unspent earned credit is capped at eight. `N` includes chosen trials, but retries, clones and repeated nested attribution cannot multiply it. The root count deduplicates nested groups. Time, reads, new targets and evidence expiry grant no credit; retained scopes preserve currency through reload/membership changes. Spending begins with node-specific work before DNS/admission waits, separately from the physical/logical reporter start. Last-reference release before work begins refunds a reservation; begun cancellation does not. Recovery retries are separate, budget-neutral work. Each member has at most one unanswered trial for its open question on a target, and except for recovery a member is dispatched only while its completions plus unfinished work stay below the selection's. Trials do not become ordinary incumbents; real failures retain exponential backoff and three-failure normal exclusion, with backoff-expired recovery still possible.

Business reliability retains its 30-minute half-life. Heuristic performance confidence ages independently and expires after 120 seconds regardless of sample count. Setup and first response publish immediately; accepted transfer progress uses nonoverlapping 1–10 second windows with at least 64 KiB in the measured direction, bidirectional flow progress and a response. Windows never multiply terminal outcomes. Goodput is workload-dependent, not link capacity; silence is not congestion. Mature switching protection remains `0.005` after eight effective completions, using the maximum separately decayed support across applicable layers. Ineligible incumbents and unresolved business failures bypass holding; recovered historical failure mass alone does not.

Only an actual ordinary move to another leaf takes priority over optional validation. A failed incumbent that remains selected does not prevent a funded, actionable challenger trial; this does not clear failure or backoff.

Promotion considers every eligible challenger in the demand-sized evaluation set (capacity k is 3–25; including the decision reference, at most k + 1 members; see [conditional verification](../design/groups.md#conditional-verification)) against one fixed incumbent, using paired exact targets, at most eight canonically selected response-qualified common targets, or the same current configured-probe cohort. Common-target qualification precedes the cap without selecting by measured value; skipped unqualified or capped matched targets leave only a partial comparison, and that member's response gap stays pending. Directional metrics intersect over the same selected response cohort. Business proof uses four shared 15-second blocks expiring at block start plus 60 seconds; configured probes use four blocks of `max(15s, 2I)` for their actual interval `I`, with expiry additionally capped by the weaker side's latest support plus `max(60s, 2I)`. Each metric still requires four distinct reporters per side, and changed cadence cannot inherit prior probe support. Directional gain requires at least 10% improvement, no greater than 10% regression in another known direction, response no more than 10% slower, and equal-or-better qualified terminal reliability. Unknown directions stay unknown; opposing changes are reported as a tradeoff rather than hidden by a best-direction score. Paired response and qualified reliability gains still participate in the existing hold-margin decision. No additional Score tuning field is introduced; see [the lifecycle design](../design/groups.md#score-scoring-and-lifecycle).

Readonly pairwise relations are separate from that switching decision: they compare actual response values with symmetric 10% practical equivalence, not completion maturity or a millisecond floor, and describe response time only; reliability and directional protections stay with switching. A missing pair response requests budgeted comparable business traffic, not bandwidth testing. See [conditional verification](../design/groups.md#conditional-verification).

Targeted Traffic RX after setup/TX can open budgeted half-open recovery before a flow ends. Four distinct reporters in the exact cell's uninterrupted post-failure cohort clear its hard episode and grant a current 60-second qualification lease; neither one reply nor another target's recovered aggregate suffices. Historical failures remain in utility and promotion, and no terminal successes are invented. Initial cold qualification still requires four effective useful completions; RX may renew an earned lease but reload alone does not grant recovery. Publication is event-driven, at most once per second per reporter after the first eligible RX. Target-path failures affect only exact-target hard state while retaining numeric aggregate outcomes; explicit carrier/proxy faults and unknown pre-setup failures remain node-scoped and fence dependent evidence. See [scoped recovery and optional validation](../design/groups.md#score-scoring-and-lifecycle).

Business scores remain scoped by group, transport, target family, normalized target and node identity. Global/family/exact reliability is blended without adding overlapping completions. Target performance overrides its baseline only while fresh and comparable. Probe RTT has separate protocol/family and normalized HTTP URI/method identity; warm-up supplies setup quality only. Nested paths attribute a real outcome once to every traversed Score group.

Transparent TCP/UDP, supported DNS exchanges and UI downloads report actual business attempts. Configured HTTP/UDP/QUIC probes provide fresh quality without adding business successes or clearing traffic streaks. Manual Clash delay measurements retain their Alive/API history but do not feed a configured Score baseline or turn arbitrary target failure into real-dial demotion. Actual preparation remains warm-up evidence. Independent Score QUIC handshakes preserve existing DataUdp health recovery without invented byte volume.

Sustained measured carrier pressure may reopen bounded comparison without adding business failures or directly changing the winner. This is honk-to-proxy advisory evidence, not end-to-end UDP loss or a first-request guarantee; unsupported paths remain unknown. See [carrier-pressure scope](../design/groups.md#score-scoring-and-lifecycle).

Score state is memory-only and process-local, with one 4,096-entry LRU for exact node-target cells and another 4,096-entry LRU for aggregate cells. Exact-target evidence measures observed transport quality, not whether a service is semantically unlocked; use existing routing or geosite rules to select a dedicated service-specific Score group when that coarse cohort is needed. A successful in-process reload shares the same state and removes cells for deleted groups or members; process restart clears it. Score cells and scorer-only domain/IP keys are never logged, persisted, or returned by Clash APIs. Established connection metadata is unaffected.

The separate comparison store has at most 256 cells and a 1 MiB logical-allocation limit, including owned key and vector capacity. This is not a process RSS limit; allocator overhead and other state are outside it. Missing or evicted support remains unknown.

After a retryable TCP setup failure, a Score-owned request may try one different permitted leaf even if ordinary ranking still prefers the failed node. Both attempts share a deadline and existing dial admission. Selector boundaries and actual primary final-edge provenance remain authoritative; no new direct/final route or application payload replay is introduced. A committed reload invalidates probe baselines while retaining valid in-flight business evidence; neutral cells stay within the existing bounded LRUs.

Each authorized applied multi-candidate rank records one exclusive reason: `coldExplore`, `periodicExplore`, `incumbentIneligible`, `freshFailureBypass`, `insufficientEvidenceHeld`, `directionalTradeoffHeld`, `incumbentHeld`, `reliabilityWinner` or `performanceWinner`. `ordinarySwitch` counts committed same-scope A→B changes, excluding first choices and trials; `switchFlap` counts the subset returning to the previous winner within eight ordinary choices. Candidate filtering/backoff counters remain separate. Peek and display/API reads are neutral. Authenticated `/stats.score.groups[]` exposes fixed group/network reason, verification and budget fields; `/stats.score.cache` describes evidence and comparison storage. Trial outcomes and setup/elapsed costs are observations, not causal extra failure or overhead estimates. See [API reason semantics](./api.md#score-selection-reason-fields); no scorer-private node or target identities are exported.

For Clash compatibility, Score remains automatic but is represented as `type: "url_test"`; `now` is the current aggregate TCP winner, and `PUT /proxies/{name}` is rejected.

Sampling resolves availability, response, ordinary qualification and recovery gaps within the shared budget. Fresh equivalent cohorts stop forced sampling once qualification/recovery gaps also close; missing transfer waits for real offered load. `scoreVerification` distinguishes provisional forwarding, observed usability, fresh pairwise `challengers` relations, the evidence `question` and `waitReason`; aggregate reads inspect retained IPv4/IPv6 waits without spending credit. See [API verification](./api.md#score-verification). Relations are retractable empirical observations, not a guarantee of best-arm identification or future network behavior.

Each challenger's pair with the selection is judged on its own shared blocks; there is no joint alignment across challengers. One dispatch order serves optional work: untrained members first, then the most progress toward a member's open question, then the least recently selected member. Trials preserve business currency and in-flight bounds and never replay requests. Readonly `question`, `nextAction` and `waitReason` report the first member of that order without exposing target identities.

## Filter resolution

1. A standalone `group('tag')` line adds nested tags to `groups`; it is not evaluated as a node predicate. A nested tag may contribute the leaf selected by that group's current policy. A `group(...)` line containing another predicate or trailing text is reported as a diagnostic and ignored; a group whose only filter is such a line remains empty.
2. `name(...)` matches `Node.name`. `subtag(...)` maps `Node.subscription_id` to the current subscription tag and matches that tag. Plain arguments are exact matches, `keyword:` is a substring match, and `regex:` is a raw regular expression. Matching is case-sensitive; multiple arguments in one predicate are alternatives.
3. Predicates joined by `&&` on one line are AND-ed. Prefixing a predicate with `!` negates it. Separate `name(...)` and `subtag(...)` `filter:` lines are OR-ed; standalone `group(...)` lines add nested candidates.
4. Filter-derived membership is rebuilt after every subscription refresh. Stable node UUIDs therefore do not retain stale membership after their subscription provenance changes.
5. A group with neither node filters nor nested groups receives all current nodes. Explicit `group()`, an empty filter, an empty nested group, or a filter emptied by subscription refresh selects nothing. Empty contributions remain explicit through JSON/YAML/TOML round-trips and refresh; valid sibling filters still contribute by OR, and `final` remains independent.

A filter honk cannot parse is ignored and reported by its ordinal among the group's node filters, excluding only nonempty standalone `group(...)` lines; mixed lines are counted. `group()` emits `empty-subgroup`. Remove the filter for all nodes; explicit `group()` now selects none. The injected `direct` and `block` are outbounds, not pool members: an unfiltered group, `keyword:`, `regex:` and `subtag(...)` never select them, and only a filter that spells the name exactly (`filter: name(direct)`) admits one.

## Nested groups

Nested selection is depth-capped at 8. When the group manager builds the graph, it removes each cycle-closing edge and logs a warning; an unknown nested tag contributes no candidate. Each nested group contributes the single leaf selected by its own policy, so every dial ultimately resolves to one node.

Clash-facing group output preserves member tags: the `all` field lists direct node names and nested group tags rather than expanding nested groups. Leaf-facing health and connectivity traversal expands the real nodes below those tags.

## Related docs

- [Node reference](./nodes.md)
- [Routing reference](./routing.md)
- [Group design](../design/groups.md)
