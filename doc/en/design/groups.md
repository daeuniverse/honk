# Group Selection, Health, and Warm-up Design

This document explains how honk resolves groups to leaf outbounds, tracks their health, and retains bounded warm resources.

## Scope

The scope is `GroupManager`, `AliveDialerSet`, the always-compiled Score scorer, cold URLTest preparation, and the warm-resource coordinators. Group fields and policy syntax belong in the [group reference](../reference/groups.md); process-wide health, warm-up, and dial keys belong in the [global reference](../reference/global.md).

## Group manager and selection pipeline

`SharedGroupManager` is a stable, hot-swappable handle:

`SharedGroupManager = Arc<parking_lot::RwLock<Arc<GroupManager>>>`

A reload builds a complete replacement `GroupManager`, migrates Selector choices whose group and member tag still exist via `migrate_selector_choices_from`, installs interrupt, warm-up, and persistence callbacks before publication, and swaps the inner `Arc`. Readers therefore see either the old or the new manager, never a partially rebuilt graph.

The `src/group/` facade and its internals are split by responsibility:

| Module | Responsibility |
| --- | --- |
| `mod.rs` | `GroupManager` types, shared handle, and selection-plan entry points |
| `resolver.rs` | Nested-group expansion, member/leaf introspection, cycle cutting, and Selector-choice migration |
| `filter.rs` | Network- and family-specific liveness filtering |
| `policy.rs` | Selector, URLTest, LoadBalance, and Fallback picks and latency ranking |
| `score.rs`, `score/selection.rs` | Always-compiled target-aware Score state, evidence, reporters, counters, and candidate ranking/selection; `score/tests/` contains the scenario suites |
| `state.rs` | URLTest/Fallback caches, Selector choices, idle timestamps, and callbacks |

Selection follows one invariant (sing-box semantics): after resolution and liveness filtering, the dial path uses exactly the policy pick. Selector returns its effective manual choice, URLTest its current winner, LoadBalance its next member, Fallback its pin, and Score its ranked eligible leaf, including deterministic cold exploration. The only multi-candidate exception at selection time is an unmeasured top-level URLTest group; all warm URLTest and non-URLTest plans are authoritative single-leaf plans. Post-failure retry racing belongs to `connection.rs`, not here, and parallel racing is added nowhere else. If a group with no `final` has exactly one unique leaf and TCP liveness excludes it, that same leaf remains an authoritative last resort only when reachable through the current Selector choices: its health stays dead, but a real dial can prove recovery without leaking to another member or `direct`. UDP keeps normal liveness exclusion. Last-resort serving logs a rate-limited warning (60s per group); warm-up peeks stay silent.

## Policy semantics

| Policy | Runtime behavior |
| --- | --- |
| Selector | TCP and UDP resolve the runtime choice, then `group.default`, then the first declared member independently of health; only missing/non-member tags fall through. No eligible candidate for that member means an empty plan, except for the same-leaf TCP last resort above; an explicit `final` remains available to the caller. The Clash API changes the runtime choice. `PersistCallback` stores effective writes in `cache.db` via honk-core's `cachedb`; when `interrupt_connections` is enabled, `InterruptCallback` removes tracking records but does not cancel live relays. Typed configuration diagnostics warn about this limitation. |
| URLTest | Chooses the lowest halving moving average, keeps independent TCP and UDP selections, applies tolerance hysteresis, and re-evaluates lazily on dial and selection queries. A real selection change may invoke `InterruptCallback`. |
| LoadBalance | Round-robins eligible members in declaration order. Every group owns independent `AtomicUsize` cursors for TCP and UDP. Rotation never invokes `InterruptCallback`. |
| Fallback | Pins the first eligible member in declaration order independently for TCP and UDP. The pin stays until that member dies; recovery of an earlier member does not cause failback. |
| Score | When explicitly selected with `policy: score`, chooses one authoritative alive member using automatic target-aware, reliability-first scoring and bounded deterministic cold-start exploration. Selector remains the omitted/default policy. |

### Score scoring and lifecycle

Score first runs the same liveness filter as every other policy. The filter's health family describes connectivity to the proxy server; the separately carried target family selects the scoring bucket. Consequently a server reached over IPv4 remains eligible for an IPv6 business target, while no score can return a node already excluded as dead.

The exact key is `(group, TCP/UDP, target IPv4/IPv6, normalized target, NodeId)`. Domains are ASCII-lowercased with one trailing dot removed and retain their port; IP targets retain the socket address. A second bounded `(group, TCP/UDP, target family or no family, NodeId)` aggregate supplies the prior for cold targets and receives targetless warm-up samples. Global aggregate, family aggregate, and exact-target evidence blend hierarchically until the more specific layer has enough evidence. Recursive selection carries the same target context and attributes the leaf outcome to every Score group traversed.

Every historical counter and weighted sum uses fixed exponential decay with a 30-minute half-life. Decay is applied lazily when evidence is recorded or ranked, so no timer or configuration knob is required. Setup and first-response latency are decayed weighted means rather than fixed-alpha EWMAs; their decayed weights also reduce the influence of stale or sparse latency. Reliability is a Beta-prior lower-confidence estimate over decayed setup and useful-outcome evidence, with setup failure carrying the strongest penalty.

Throughput evidence admits only a successful, useful bidirectional exchange that lasts at least 1 second and moves at least 64 KiB in its dominant direction. Qualifying windows pool dominant-direction bytes and elapsed seconds into bytes per second, avoiding request/response double-counting. Utility normalizes that rate against the fastest qualifying candidate in the current group and scales it by decayed window confidence. Short probes and small control exchanges can still update reliability and latency but cannot inflate throughput.

`ScoreFeedback::start()` creates a cloneable `ScoreReporter` only when a physical dial, logical stream, transport preparation, or exchange associated with a Score group actually starts. The reporter records setup, first response, transmitted/received bytes, and exactly one of success, timeout, `io::ErrorKind`, cancellation, shutdown, or other; the first terminal call wins and dropping the last unfinished handle reports cancellation. Cancellation and shutdown remove the attempt rather than degrading reliability. A retry starts a new reporter, while speculative work that never starts and all non-Score paths create neither a reporter nor a score cell.

Admission-scoped TCP dialing starts its reporter at the first admitted physical attempt or immediately before a logical open on a reused session or QUIC connection, not while waiting for cold physical admission. The callback is one-shot; completed paths without either boundary retain the completion fallback.

Ordinary and post-race TCP ready/bare refills retain setup-quality evidence, but their successes and failures never alter real-flow failure streaks or exploration backoff. UDP drivers classify their terminal result before their health callback can synchronously retire the endpoint, so that callback cannot turn an error into neutral cancellation or success. Intentional retirement remains neutral without a reply and successful after a reply; process shutdown and packet-local congestion stay neutral, and reply-idle expiry is a timeout only when no reply was received.

On live endpoints, a proven QUIC path stall takes precedence and remains a timeout even when the immediate error would otherwise be classified as packet-local congestion or idle-after-reply.

The same reporter path covers transparent TCP relay and UDP endpoint lifetime, supported DNS upstream exchanges, periodic HTTP/UDP health probes, on-demand Clash delay measurements, startup preconnect, Selector/session and UDP warm-up, and external UI downloads. DNS feedback follows the carrier actually attempted: direct UDP, DoQ, and DoH3 use the UDP bucket; TCP, DoT, DoH, and proxied UDP (carried as pooled TCP-DNS, so TCP health and the TCP bucket apply) use TCP; and a TCP retry after a truncated UDP answer switches buckets.

Ranking is reliability-first: the Beta-prior lower-confidence estimate excludes candidates outside the fixed close-reliability band, and relative performance only fine-tunes candidates inside that band. Latency penalty is relative to the group's fastest observed candidate, while throughput bonus is relative to its highest pooled bytes-per-second rate. Evidence that decays below the trained threshold becomes cold again. Groups with at most four candidates cold-explore all members; larger groups explore `ceil(sqrt(n)) + 1` members and every `2n` selections, bounded to 16–64, revisit the non-incumbent with the highest Beta upper-confidence reliability bound. That cadence is scoped only by `(group, TCP/UDP, target IPv4/IPv6 family or none)`, never an exact target, node, health family, address, or port. Consecutive failures back a leaf out of cold and periodic exploration exponentially — a 5-minute delay doubling per failure up to a 6-hour cap, tracked outside the decaying evidence — while a success rejoins exploration immediately but only steps the streak down by one. Only real-flow outcomes move that streak — probe, urltest, and warm-up results are streak-neutral, so a healthy check target cannot wash out consecutive real failures. The same streak gates ranking: at three consecutive fresh failures a leaf leaves the reliability band while any healthier candidate exists, and full-set ranking resumes only when every candidate is failing, so the pick never disappears. Incumbent hysteresis scales linearly from zero to the full `0.01` margin over eight effective completions; global, target-family, and exact-target fresh-failure envelopes compose by `max`, not addition, before deciding whether to bypass it. Exploration and remaining ties are deterministic, with declaration order and stable `NodeId` as the final tie-breakers. The resulting plan always contains one authoritative leaf rather than racing candidates.

Score state is demand-driven, memory-only, process-local, and non-configurable. Exact cells use a 4,096-entry LRU and aggregate cells use a separate 4,096-entry LRU. Exact-target evidence is transport-quality evidence, not a semantic-unlock capability result; existing routing or geosite rules can select a dedicated service-specific Score group when that coarse cohort is desired. A successful in-process reload shares the same state `Arc`, publishes the new valid `(group, member)` set, and prunes removed cells; late feedback for deleted membership is ignored. Process restart clears everything. Score cells and scorer-only target data are never logged, persisted, or returned by Clash APIs; the existing `/connections` destination metadata remains unchanged.

An authorized applied multi-candidate rank increments exactly one final reason in precedence order: `coldExplore`, `periodicExplore`, `incumbentHeld`, `freshFailureBypass`, `reliabilityWinner`, then `performanceWinner`. `deadFiltered` independently counts unique leaf candidates removed by liveness filtering. `switchFlap` independently counts a committed winner switching back to its prior winner within eight selections of the same `(group, network, family, target)` scope, so unrelated targets interleaving their own winners never count; targetless selections share one bucket, and history is bounded by a 4,096-entry LRU. Cold and periodic exploration do not mutate this regret window. `failStreakExcluded` sums, per authorized rank, the candidates dropped by the three-consecutive-fresh-failure gate, and `exploreBackedOff` sums the candidates currently in exploration backoff. Peek, proxy/stat reads, singleton bypasses, and last-resort selection are neutral. The authenticated `/stats.score.groups[]` snapshot exposes only those per-group TCP/UDP counters; it contains no cells, nodes, targets, cadence, or manager authority. `/stats.score.cache` exposes each 4,096-entry evidence LRU's current cell count and cumulative eviction total, still without any group, node, or target identity.

Clash represents a Score group as `type: "url_test"`, reports the current aggregate TCP winner in `now`, and rejects `PUT /proxies/{name}`.

### URLTest ranking and hysteresis

Latency uses a halving moving average:

`next = (previous + sample) / 2`

The first sample initializes the average. This is dae `min_moving_avg` behavior: recent changes matter quickly without making one jitter sample authoritative.

`SelectionNetwork::Tcp` and `SelectionNetwork::Udp` retain separate winners. TCP uses the TCP probe average, or the `(member tag, check_url)` average when the group has a custom target. UDP first uses `DataUdp`, then `DnsUdp`; if no eligible candidate has real UDP ranking evidence in either domain's retained moving average for the selected address family, it mirrors the TCP selection. Synthetic dial-failure samples alone do not disable this mirror; evicting real samples from the history ring does not erase retained ranking evidence. This gives the effective fallback order `DataUdp → DnsUdp → TCP`.

The effective tolerance is `max(configured tolerance, 1 ms)` (`group.tolerance.max(1)`). The incumbent stays selected while:

`best latency + tolerance >= incumbent current measured latency`

The incumbent baseline is read again at selection time, not retained from the moment it won. A degraded incumbent can therefore be replaced; this matches sing-box `Select()` behavior. Hysteresis is skipped for an incumbent carrying failure strikes — a just-failed incumbent is replaced immediately.

Probe failures update only liveness and cooldown; they never create synthetic latency samples or ranking strikes. Only two consecutive real dial failures append a display-excluded synthetic 10-second placeholder plus one failure strike — a lone transient failure (the retry race rescues that flow) leaves no selection state, and only a real dial success resets the streak, so a probe-alive but dial-dead node still accumulates. Real history and moving average are retained, but a candidate with pending dial-failure strikes ranks below every non-demoted candidate. Strikes clear only after `max(strikes, 2)` consecutive real successes — this is the flap guard that stops a fast-but-flaky node from reclaiming first place with one lucky probe.

Real traffic also feeds ranking directly (TCP only). Each node keeps a self-referential EMA (α=1/8, after 3 warmup dials) of fresh dial latencies; pool-ready hits are excluded because they perform no network round trip. Three consecutive dials slower than `max(min(2×EMA, EMA+500 ms), 250 ms)` (`max(min(2×ema, ema+500ms), 250ms)` in `report_dial_latency`) append one failure strike and fire an emergency probe; the 250 ms floor keeps a fast incumbent's normal load jitter (e.g. 60→120 ms) from tripping the detector. The probe moving average is never touched, and a false positive (a shifted target mix rather than node decay) self-heals when the emergency probe succeeds and consecutive probe successes clear the strike. Gradual drift stays owned by the probe cycle; UDP degradation keeps the probe-cycle plus `DataUdp` traffic-threshold path.

When an authoritative single-candidate dial fails, `connection.rs` retries the flow exactly once by racing the URLTest latency-ordered top-3: when the just-recorded strike moved the pick the incumbent is replaced, otherwise it re-races alongside its alternates — a lone transient failure leaves no strike and must not hard-fail the flow. Non-URLTest plans (Selector pin, Fallback pin) and single-leaf outcomes yield no retry candidates and fail the flow, except that Score records the failure, re-ranks the exact target, and retries only a different replacement.

A group `check_url` creates independent TCP-only liveness and latency state keyed by `(member tag, check_url)`. A failure removes that member only from groups using that target. Selector groups ignore `check_url` and emit a warning. URLTest probing sleeps after `idle_timeout`; an unset timeout uses the 30-minute health-layer default, and the next real selection wakes probes immediately.

## Nested groups and member identity

`Group.groups` names sub-groups. Each sub-group contributes exactly one candidate: the leaf selected by that sub-group's own policy for the current network and address family. The parent ranks or pins that candidate as one member rather than merging every descendant into its policy.

Resolution is bounded by `MAX_GROUP_DEPTH = 8` and a per-walk visited set. Construction also runs DFS over group edges and cuts every cycle-closing edge with a warning. These checks prevent a malformed graph from hanging selection or introspection.

Selector captures a concrete node or sub-group member before candidate expansion and health filtering; repeated node tags bind the first matching declared `NodeId`. Parents retain the existing subgroup Peek, parent-health gate, and serving-commit order, so unchosen Score state is not advanced. For both TCP and UDP, a failed serving commit yields an empty parent plan rather than restoring the earlier peek. Candidates retain their originating subgroup reference instead of rediscovering it from a display tag. A chosen automatic sub-group may still select a different leaf within its own membership. The sole TCP leaf's last-resort walk also respects every nested Selector choice, while explicit delay tests may inspect all members for recovery.

Display and API output retain member tags even when the physical dial reaches a deeper leaf; serving selection retains concrete node or subgroup identity separately:

| API | Output |
| --- | --- |
| `node_names_in_group` | Direct node tags plus sub-group tags |
| `leaf_node_names_in_group` | Deduplicated real leaf nodes reachable below the group |
| `delay_test_members` | One `(member tag, current leaf)` pair (`(tag, leaf)`) per effective member |
| `selection_chain` | Current chain from group through selected sub-groups to the leaf |

Custom-URL probes resolve `delay_test_members` again on every cycle. A sub-group is probed through its current pick, but the result is recorded under the sub-group tag. The parent therefore treats the sub-group as one stable member, matching sing-box RealTag semantics.

## Cold URLTest UDP preparation

Only a top-level URLTest plan with no usable measurement may prepare several UDP transports. Candidate starts use absolute offsets `0 ms`, `30 ms`, `80 ms`, then one every `80 ms`; at most three preparations are in flight. Absolute scheduling prevents an earlier slow attempt from shifting all later starts.

The first successful candidate that is still eligible wins. honk aborts and drains every started loser before binding the winner to an endpoint, rechecks eligibility, then commits protocol state before endpoint publication or the first application send.

Only an observed preparation `Err` affects traffic health. Never-started work, cancellation, an ineligible successful result, and successfully drained losers are neutral; a completed error discovered while draining is still an observed error and counts. AnyTLS uses caller-owned provisional pool slots so losers never publish sessions. QUIC protocols build detached clients and publish only the finalized winner; losing clients are closed with their speculative work.

## Health state and probes

`AliveDialerSet` keys node health, registrations, histories, emergency triggers, and latency collections by the node's `NodeId` UUID (`Uuid`). Display names are metadata for logs and probe lookup, not identity. Every node has six independent states: three domains across IPv4 and IPv6.

| Failure source | `Tcp` | `DnsUdp` | `DataUdp` |
| --- | ---: | ---: | ---: |
| Periodic probe | 3 | 3 | 3 |
| Real traffic | 10 | 3 | 50 |

Go dae's TCP=1 let transient probe loss eject URLTest incumbents through tolerance hysteresis.

Probe and traffic failures have separate counters. Probe failures apply exponential cooldown from 5 seconds to 300 seconds. A separate `min(5s, check_interval)` recovery scheduler considers only dead domain/family states whose cooldown is due; deep-backoff states continue at the 300-second cadence rather than stopping permanently.

A dead state normally needs two consecutive probe successes to recover. `notify_network_change` clears stale cooldowns after a relevant link, address, or route change, primes dead states, and triggers probes so one fresh success can verify recovery. Newly registered nodes receive a 60-second grace period during which non-forced failures are recorded but do not count toward death. Probe history retains 100 entries per node, domain, and address family.

| Probe path | Behavior |
| --- | --- |
| TCP | Sends the configured HTTP method to `tcp_check_url` through the node, or performs a raw TCP connect when no HTTP probe applies. `ProxyHttpProber` delegates HTTP execution to the shared outbound measurement path below; only its successful warm-path RTT enters the matching TCP family state. Setup and target-exchange failures update liveness/cooldown without contributing latency or ranking strikes. |
| UDP health | honk-core injects `ProxyUdpProber` via `set_udp_probe`: sends one minimal DNS query to the first `udp_check_dns` target (`global.udp_check_dns`, default 8.8.8.8:53) through the node's own `dial_udp_transport`, measuring the complete DNS exchange. It uses the same `NodeRuntime::is_warm_or_stateless` reuse condition and guarded cold-runtime teardown as TCP probes. Success records the measured RTT and marks both `DnsUdp` and `DataUdp` alive; failure adds one probe failure to each UDP domain — unless the independent Score QUIC handshake succeeded in the same cycle, in which case only `DnsUdp` records the failure and `DataUdp` is marked alive from the handshake (a blocked `:53` check target must not condemn a working UDP path). TCP and UDP probes never change each other's state. |
| Score QUIC evidence | Every periodic UDP cycle separately performs a real TLS-in-QUIC handshake with ALPN `h3` through a new packet transport for each node in a Score group, targeting the first HTTPS `global.tcp_check_url`, regardless of the DNS probe outcome. Success or failure updates the exact `DataUdp` score and aggregate prior through `ScoreFeedback`/`ScoreReporter`, without awarding unobserved byte volume; a success on a DNS-failed node additionally revives `DataUdp` liveness as described above. Missing/non-HTTPS URLs disable only this probe; non-Score nodes are not handshaken and create neither reporters nor score cells. |
| Per-group URL | Probes the dynamically resolved `(member tag, current leaf)` pairs with the same throwaway warm-path timing as the global TCP probe. State is TCP-only, dies after three consecutive failures, and uses the same cooldown and two-success recovery. `sync_group_check_urls` replaces the active group/URL registry on reload. |

`has_udp_state(node)` distinguishes a node with no UDP observations from one explicitly observed dead. Established endpoint terminal send/receive errors and reply-idle expiry without any reply report `DataUdp` traffic failures. Packet-local congestion, idle expiry after a reply, intentional endpoint retirement, node-death cancellation, and process shutdown are health-neutral. Endpoint DataUdp health follows the **UDP transport invariant** [here](../../../AGENTS.md#notes-for-agents).

An alive-to-dead transition invokes the control-plane death callback with `(NodeId, name)`, which purges the node's pooled connections and UDP endpoints so no stale reusable object is handed to new traffic. Skip UDP-domain death while its sibling UDP domain is explicitly alive, preventing blocked `:53` probes from purging working flows.

The last real TCP delay sample per node is written to `cache.db` every 60 seconds and restored at startup only when it is at most 24 hours old. Liveness is never restored from the cache. Synthetic 10-second placeholders are flagged, excluded from display history and the moving average, and never persisted as the last real sample; selection demotion lives on the failure-strike counters, not on the placeholder.

- `src/alive/` APIs include `register_node`, `notify_check_*`, `report_*_traffic`, and `record_dial_failure`. Group tables and `(member tag, check_url)` state remain name-keyed: groups have no NodeId; members may be sub-groups (sing-box RealTag).
  `mod.rs`: state, thresholds, registries, eBPF connectivity-push callback, `StickyCache`. `probe.rs`: HTTP/raw-connect `probe_node`, DNS-through-`dial_udp_transport` `probe_node_udp`, concurrent cycles. `collection.rs`: `DialerCollection` latencies/moving average/alive flag. `latencies.rs`: O(1), cap-10 ring; measurement `SystemTime` gives real Clash history times. `last_real_sample()` excludes synthetic entries, preventing bogus dashboard 10000ms.
- `src/urltest.rs` owns shared HTTP request construction and measurement; URL interpretation delegates to the canonical `honk-config::check` decoders. Core and generation URLTest also share explicit cold-session preparation, retaining fallible node admission before resources or feedback; standalone tool calls retain handler-owned setup and their outer CLI deadline. Requests use credential-free authority with non-default ports, omit fragments, and preserve raw path/query including dot segments; query-only URLs use `/?query`. HTTPS verifies certificates and negotiates `h2,http/1.1`, with server push disabled. A HEAD warm-up precedes the configured method (HEAD for delay tests), and both final responses must have valid decoded 200–499 statuses. HTTP/1 informational heads are consumed before the final response, except unsupported protocol switching; their cumulative size per round is capped at 16 KiB. HTTP/2 response header lists use the same size cap.
  Every protocol reports the second request's warm-path RTT, excluding proxy dial, target TLS, and session preparation. A second-round I/O failure or timeout may fall back to the validated first sample; HTTP/1 requires that no response bytes have arrived, and HTTP/2 also treats graceful GOAWAY as transport closure. Malformed, truncated, oversized or partially received timed-out HTTP/1 heads fail. Warm/stateless generation runtimes are reused; cold reusable generation probes use guarded temporary runtimes that close afterward, and HTTP/2 drivers are released on completion or cancellation. Session preparation, dial, TLS, HTTP/2 startup and each request have separate phase budgets; core retains its configured connection timeout separately. Empty delay URLs use `https://www.gstatic.com/generate_204`. Health scheduling/accounting remains in `alive`; only delay wrappers feed dial-failure strikes, and group delay concurrency remains capped at 10.

Known upstream limitation: [`h2` 0.4.19 defaults a missing response `:status` to 200](https://github.com/hyperium/h2/issues/958). The probe validates the decoded status and cannot recover the omitted pseudo-header, so that malformed HTTP/2 response can appear healthy. This dependency fix is deferred pending upstream; no local fork or vendor patch is applied.

## UDP candidate eligibility

`filter_alive_candidates` decides UDP selection per node and address family:

- `DataUdp` alive or `DnsUdp` alive: selectable.
- Both UDP domains explicitly dead: excluded, even if TCP is alive.
- No UDP state has ever been recorded: inherit TCP liveness.

This keeps a TCP-healthy but UDP-broken node from attracting packet flows without penalizing deployments that have not enabled UDP probing yet.

## eBPF connectivity publication

The eBPF alive slot belongs to a group, not to one node. For every domain and address family, publication uses the OR of all reachable leaf-member states, plus the existing TCP admission exception for exactly one unique leaf and no `final`. A callback caused by one node transition recomputes that group value; it never writes the transitioning node's value directly. Admission does not override userspace selection: a chosen empty Selector path still refuses traffic even when this slot remains alive.

Reload first sets every slot needed by the old or new group layout to alive, making the transition fail-open. After the new routing generation is published, honk writes the exact new group snapshot. Reordered groups therefore cannot inherit stale ordinal state; if exact publication fails partway, unfilled transition slots remain fail-open rather than falsely killing a group.

## Warm-up and ownership

Warm-up has three independent mechanisms:

| Mechanism | Candidate and lifetime | Retained resource | Bounds |
| --- | --- | --- | --- |
| Startup preconnect | One startup-only pass; current group picks first, then config order. Only bare-TCP-poolable proxy nodes qualify. | One bare server TCP connection deposited in the pool | `'auto'` selects at most 8 nodes; `0` disables it. It owns no policy-retention bit. |
| Selector pin | Always tracks every Selector's configured leaf, including an unhealthy explicit choice; shared leaves are UUID-deduplicated. | One AnyTLS, VLESS H2MUX, or VLESS Mux.Cool pool session; one QUIC client/connection; otherwise one bare server TCP | Effective-choice changes wake immediately; a 10-second pass repairs lost, consumed, or expired state. |
| UDP warm set | Opt-in; re-ranks each group's top `min(N, 3)` reusable UDP leaves for each address family on every pass, then UUID-deduplicates globally. | The protocol's reusable UDP-capable generation session or QUIC client | At most 4 warm attempts run concurrently; the retained process set is re-ranked and capped at `4 × N`. |

Selector and UDP ownership are independent bits on reusable node runtimes. Removing one owner leaves the resource retained for the other; only the final owner release drains future reusable state. Active flows keep their own stream or connection handles and are not cut. Startup preconnect is only a pool seed and does not participate in these bits.

On reload, unchanged node configurations transfer their existing `NodeRuntime`, including live AnyTLS, VLESS H2MUX/Mux.Cool, and QUIC state, to the replacement generation. The old generation becomes terminal to new warm work while active flows drain normally; UDP warm-up is generation-owned, and a node whose configuration did change gets a replacement runtime that owns a fresh pool.

## Dial admission budget

`max_concurrent_dials` defaults to 64 and creates a generation-local semaphore for physical proxied connects and protocol handshakes. The configured value is clamped to the immutable process-wide descriptor gate computed at startup. Reload may change the replacement generation's local limit, but overlapping old and new generations still share that same process gate.

Ready-pool hits and logical streams opened on an already warm generation transport are exempt. `block` never dials; `DirectHandler::dial` goes through `admit_physical_dial` like other physical connects. Datapath-offloaded direct flows and direct UI downloads through reqwest do not use this handler's gate. A bare-TCP pool hit still runs its protocol handshake and therefore remains admitted by the dial budget.

## Related docs

- [Outbound design](./outbound.md)
- [Control-plane design](./control-plane.md)
- [Group reference](../reference/groups.md)
- [Global reference](../reference/global.md)
