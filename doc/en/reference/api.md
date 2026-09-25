# Clash API and `/stats` reference

This reference describes honk's implemented Clash-compatible HTTP surface and its userspace statistics snapshot.

## Enablement and authentication

The API server starts only when `experimental.clash_api.external_controller` is non-empty and the binary includes the default-on `clash-api` feature. The controller requires a numeric socket address such as `127.0.0.1:9090` or `[::1]:9090`, not a DNS hostname; a leading `:port` binds `0.0.0.0:port`. An invalid address is logged and does not stop the engine.

When `experimental.clash_api.secret` is non-empty, API requests require:

```http
Authorization: Bearer <secret>
```

A WebSocket upgrade may instead pass `?token=<percent-encoded-secret>`. honk percent-decodes the token before exact comparison. Query-token authentication is limited to WebSocket upgrades; ordinary HTTP requests use the Bearer header. An empty `secret` disables authentication. The `/ui` static tree is outside the API authentication layer.

**The API has no TLS.** Bind it to localhost or place a TLS reverse proxy in front of it, and set a strong `secret` when untrusted clients can reach the listener.

The shipped `config.dae` binds to `127.0.0.1:9090`. A non-loopback controller with an empty `secret` emits a startup warning but is still allowed; this applies to wildcard and assigned addresses, regardless of firewall configuration.

## Endpoint map

The table follows the router in `crates/honk-core/src/clash_api.rs`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Return the Clash hello document, or redirect a non-JSON client to `/ui/` when external UI hosting is enabled. |
| GET | `/version` | Return `honk <build-version>` (including the release tag, using the same build identity as the CLI) and Clash premium/meta capability flags. |
| GET | `/configs` | Return the current mode, the implemented Clash-compatible configuration snapshot, and safe active-generation diagnostics under `honk-diagnostics`. |
| PUT | `/configs` | Compatibility no-op; accepts the request and returns `204 No Content`. |
| PATCH | `/configs` | Set `mode` to `Rule`, `Global`, or `Direct`; matching is case-insensitive. |
| GET | `/proxies` | Return every node and group plus the synthetic `GLOBAL` selector. |
| GET | `/proxies/{name}` | Return one node, group, or `GLOBAL` selector. |
| PUT | `/proxies/{name}` | Select a direct member of a Selector group with `{"name":"member"}`; also mutates the synthetic `GLOBAL` selector. Automatic groups, including Score, reject writes. |
| GET | `/proxies/{name}/delay` | Run an on-demand proxied delay test against the caller's `?url=` for a node or group. Already-warm transports are reused; every cold reusable session or QUIC client is warmed in a throwaway runtime before timing. |
| GET | `/group/{name}/delay` | Test all group members against the caller's `?url=` with up to `URLTEST_MAX_CONCURRENT` (10) proxied dials, returning successful member delays with the same timing semantics. |
| GET | `/rules` | Return one row per route. Simple matchers use native Clash rule types; compound, negated, and `must` rules use `complex` with the full dae statement. |
| GET | `/connections` | Return a connection snapshot, or stream snapshots after a WebSocket upgrade. |
| DELETE | `/connections` | Close all tracked connections. |
| DELETE | `/connections/{id}` | Close one tracked connection. |
| GET | `/traffic` | Stream per-second traffic JSON over WebSocket or chunked JSON lines. |
| GET | `/memory` | Stream process RSS JSON over WebSocket or chunked JSON lines. |
| GET | `/stats` | Return the userspace outbound, ready-pool, warm-resource, Score selection-reason, and UDP snapshot documented below. |
| GET | `/logs` | Stream tracing events over WebSocket or chunked JSON lines from one shared 256-slot broadcast queue; `?level=` defaults to `info`. |
| GET | `/dns/query` | Resolve `?name=` through honk DNS and return DoH-style JSON; `?type=` defaults to `A`. |
| POST | `/cache/fakeip/flush` | Flush persisted FakeIP-prefixed cache entries when the cache database exists. |
| POST | `/cache/dns/flush` | Flush the live DNS cache and its persisted DNS state. |
| GET | `/providers/proxies` | Expose non-empty groups as Clash proxy providers. |
| GET | `/providers/rules` | Return the current stub document `{"providers":[]}`. |
| GET | `/ui`, `/ui/*` | Redirect `/ui` to `/ui/` and serve the configured external UI directory. |

`/traffic`, `/memory`, and `/logs` send one JSON document per line for a plain HTTP GET. `/logs` installs dynamic tracing interest only while subscribers exist; with no subscribers, the Clash tracing layer does not format events. Each subscriber's level filter runs after the shared queue. Lagged clients skip overwritten events without a gap marker.

### Diagnostics in `/configs`

`GET /configs` preserves the existing Clash fields and adds `honk-diagnostics`.
Settings and diagnostics are read from one committed configuration snapshot.
Startup publishes only admitted file and subscription diagnostics. Failed reloads
and rejected subscription refreshes leave the active list unchanged; there is no
last-failed-attempt cache.

A successful reload with unchanged effective settings can replace diagnostics
without advancing the generation. An authorized, admitted provider refresh replaces
only that provider's diagnostics, even when its nodes are unchanged; static-file
and other-provider diagnostics remain.

Library callers pass `DiagnosticBuckets` to `ControlPlane::reload_runtime_config(config, diagnostics)`, keeping static and provider-body diagnostics separate; programmatic inputs without diagnostics use `DiagnosticBuckets::default()`. `merge_subscription_nodes(provider, nodes, diagnostics)` accepts that provider's diagnostic vector, including for admitted providers without worker declarations. Full configuration replacement moves the complete candidate provenance into place, while provider replacement affects only that provider. SIGHUP retains the buckets of provider bodies actually retained by rebasing. Generated topology/ECS updates preserve source provenance. All changes publish under the existing configuration write barrier, acquiring the diagnostics lock only after the configuration lock.

Full-replacement provider buckets must have unique UUIDs. Duplicate UUIDs reject the entire reload before publication, including when the effective configuration is unchanged; the active configuration and diagnostics remain intact.

| Field | Meaning |
| --- | --- |
| `honk-diagnostics.generation` | Active configuration generation; startup begins at `0`. |
| `honk-diagnostics.sources` | Metadata-only source rows referenced by retained diagnostics or their parents. |
| `sources[].id` | Opaque numeric source ID used by `diagnostics[].source` in this snapshot. |
| `sources[].ordinal` | Original zero-based ordinal within the attempt-local source table. |
| `sources[].parent` | Opaque `id` of the parent source, or `null` for a root source. |
| `honk-diagnostics.diagnostics` | Safe diagnostics retained for the active configuration and admitted providers. |
| `diagnostics[].code` | Stable diagnostic code. |
| `diagnostics[].severity` | Lower-case severity: `info`, `warning`, or `error`. |
| `diagnostics[].source` | Opaque `sources[].id`. |
| `diagnostics[].span` | Zero-based byte range `{start, end}` with exclusive `end`, or `null` when unavailable. |
| `diagnostics[].line` | Optional physical line number, or `null`. |
| `diagnostics[].byte_column` | Optional byte column, or `null`. |
| `diagnostics[].setting` | Fixed schema path with original sequence ordinals; it never contains operator-supplied names. |
| `diagnostics[].value` | Safe value representation; private values are redacted. |
| `diagnostics[].message` | Static diagnostic message. |
| `diagnostics[].entry_index` | Optional original entry ordinal, or `null`. |
| `diagnostics[].related_indices` | Related original entry ordinals. |
| `diagnostics[].terminal` | Whether this diagnostic represents the terminal failure. |

The generation matches the active DNS runtime generation. Source IDs are
snapshot-local, not filesystem identifiers. Sources are ordered static-file first,
then providers in configured declaration order, followed by admitted non-worker
providers in retained bucket order. Each source table keeps its original order;
only referenced sources and their ancestors are included.
Paths, raw input, credentials, and provider names or IDs are never exported.

### Delay measurement

The caller selects the test URL with `?url=`. A group request fans out to at most `URLTEST_MAX_CONCURRENT` (10) proxied measurements at once.

Delay tests use the canonical HTTP check-target decoder: HEAD preserves the raw path/query (including dot segments and query-only `/?query`), while authority omits credentials/default ports and fragments are never sent. They share periodic health checks' HTTP implementation and report the second request's warm-path RTT, excluding proxy dial, target TLS and the first request. HTTPS verifies certificates, negotiates HTTP/2 or HTTP/1.1, and disables server push. Both final responses must have valid decoded 200–499 statuses. A measured-round transport failure or timeout can fall back to the validated first sample; HTTP/1 partial responses never fall back, including on timeout, while graceful HTTP/2 GOAWAY can. HTTP/1 informational and final response heads share a 16 KiB per-round cap; H2 response header lists also have a 16 KiB cap. Session warm-up, dial, target TLS, H2 startup and each request have separate timeout budgets. Cold reusable generation probes use guarded temporary runtimes that close afterward; HTTP/2 drivers are released on completion or cancellation, so group scans retain no new reusable runtime per tested node.

Known limitation of the locked dependency: [`h2` 0.4.19 can report 200 for a response missing `:status`](https://github.com/hyperium/h2/issues/958). Such a malformed HTTP/2 response may still yield a successful delay result. [Upstream fix #959](https://github.com/hyperium/h2/pull/959) is merged but not included in this locked release; adoption awaits a published release containing it, without a local fork/vendor patch.

Successful measurements update the node latency history. Failures return `503` for a single node, are omitted from the group result, and append a failure strike used by URLTest selection.

On-demand delay exchanges retain Alive/API latency history but do not report business outcomes or populate configured Score comparison cohorts. Actual preliminary server/session preparation may report aggregate warm-up setup only; it does not fabricate the caller's URL as its own target or provide promotion proof.

### Score group representation

A configured `policy: score` group is represented as Clash `type: "url_test"` for compatibility. Its `all` list keeps the same direct member tags as other groups, while `now` reports the current aggregate TCP winner rather than any one exact target's private selection. Score remains automatic and authoritative: `PUT /proxies/{name}` is rejected rather than pinning a member. No score cell or scorer-only target data is added to proxy documents; `/stats.score` contains only the safe aggregate counters documented below. `/connections` retains its established destination metadata.

## Mode and selector mutations

`PATCH /configs` accepts a JSON object such as:

```json
{"mode":"Global"}
```

The mode update goes through `DatapathFlagsHandle`, the sole serialized writer for the shared mode and `DATAPATH_FLAGS_MAP`. Mode changes therefore compose atomically with reload's NFQUEUE fence, reopen, and disable operations instead of republishing stale readiness bits. Rule-derived feature bits belong to the immutable routing policy descriptor. A cache database, when enabled, stores the normalized mode.

`PUT /proxies/{name}` accepts the body regardless of `Content-Type`. For a configured Selector group, the target must be a direct member tag; a leaf reachable only through a nested group is not a direct member. An actual choice change invokes the group manager's cache callback, so an enabled `cache_file` persists the choice in `cache.db`. If that group sets `interrupt_connections`, honk removes tracked connections associated with the group, its member tags, and reachable leaves so subsequent traffic redials through the new choice. Writing the existing choice does nothing. URLTest, LoadBalance, Fallback, and Score groups reject the mutation.

`GLOBAL` is synthetic, but every member in its `all` list is a concrete configured group or node with a matching top-level proxy document. `PUT /proxies/GLOBAL` accepts only one of those names and updates it through the same `DatapathFlagsHandle`; the cache database stores it under the `GLOBAL` selector key when enabled. Empty, removed, unknown, and legacy virtual selections fall back to the first concrete member.

## External UI hosting

Set `experimental.clash_api.external_ui` to serve a static dashboard directory. If the directory is missing or empty, honk starts a background ZIP download; startup does not wait, and the static route returns `404` until files are available. `external_ui_download_url` replaces the built-in zashboard URL, while `HONK_UI_DOWNLOAD_URL` remains the highest-precedence override.

Every download hop accepts only HTTP(S), with at most five redirects and a 128 MiB limit on the downloaded ZIP body. HTTPS-to-HTTP redirects and IP-literal hosts are allowed; each hop still follows routing or the explicit `external_ui_download_detour`.

A non-empty `external_ui_download_detour` forces the initial request and redirects through that node or group. When empty, each URL follows honk's current traffic routing decision: `direct` uses the direct HTTP client, `block` aborts, and a proxy result uses the selected outbound leaf. Each direct or proxied HTTP exchange reports the real host/IP, port, setup, first response, bytes, and terminal outcome to its traversed Score groups; paths that traverse no Score group create no score reporter or cell. Download or extraction failures are logged and do not stop the engine.

## `GET /stats`

`GET /stats` is a userspace snapshot. It is not the eBPF `OUTBOUND_STATS` map and does not expose its packet counters. The fixed TCP, UDP, and NFQUEUE schemas create no dynamic per-node labels.

```text
{
  outbounds: [{ name, totalConns, activeConns, upload, download, errors }],
  pool: { readyHits, readyMisses, entries },
  quic: {
    activeConnections, srttUs, cwndBytes, flowReceivedBytes, flowSentBytes,
    receiveWindowBytes, receiveWindowAvailableBytes, streamReceiveWindowBytes,
    sendWindowBytes, sendWindowAvailableBytes, lossRatePpm, sentPackets,
    ackFrames, lostPackets,
    sentPlpmtudProbes, lostPlpmtudProbes, currentMtu, blackHoles,
    congestionEvents, txBytes, rxBytes, txDatagrams, rxDatagrams, txIos, rxIos,
    transportTxWouldBlock, transportTxDrops, transportRxDrops, sessionRxDrops,
    sendTimeouts, pathStalls
  },
  warm: {
    nodes: { preconnect, health, udp, selector, traffic },
    sessions: { anytls, vless, tuic, juicity, hysteria2 }
  },
  tcp: {
    activeFlows, limit, capacity: { rejected }
  },
  score: {
    groups: [{ name, tcp: R, udp: R, verification: { tcp: V, udp: V }, budget: { tcp: B, udp: B } }],
    businessStarts,
    cache: {
      exactCells, aggregateCells, exactEvictions, aggregateEvictions,
      comparisonCells, comparisonLogicalBytes, comparisonLogicalCapacity,
      comparisonEvictions, comparisonExpired, comparisonRejected
    }
  },
  udp: {
    endpoint: { hits, misses },
    latency: {
      route: H, dial: H, replyReady: H, firstSend: H, firstReply: H
    },
    capacity: { rejected },
    slowPermit: { accepted, rejected, closed },
    queue: { accepted, full, flowFull, globalPayloadFull, closed },
    firstSend: { failures },
    stagger: { attempts, winners, cancellations },
    warm: { attempts, successes, failures },
    nfqueue: {
      received, activeFlows, kernelQueueDepth, kernelStatsAvailable,
      kernelStatsReadErrors, kernelDropped, kernelUserDropped, heldPackets,
      heldPeak, socketReceiveBufferBytes, actorQueueFull, correlatorFull,
      actorQueueDepth, actorQueuedBytes, actorOldestAgeNanos, directAccepted,
      proxyCopied, proxyDropped, block, cancel, drop, tokenMismatch,
      tokenExhaustion, tokenRollovers, verdictErrors, receiptToVerdict: H
    }
  }
}
H = { count, sumNanos, buckets }  // buckets has 64 fixed log2 slots
R = {
  coldExplore, periodicExplore, reliabilityWinner, performanceWinner,
  incumbentHeld, insufficientEvidenceHeld, directionalTradeoffHeld, incumbentIneligible,
  freshFailureBypass, deadFiltered, ordinarySwitch, switchFlap,
  failStreakExcluded, exploreBackedOff, carrierPressure, carrierRttPressure,
  carrierLossPressure, carrierValidation
} // every R value is a u64 count
V = { provisionalSelections, usableSelections, validationSelections }
B = { businessStarts, sources: { cold, periodic, recovery }, trialStarts,
      reserved, spent, budgetBlocked, inFlightBlocked, refunded, expired,
      coldAllowance, coldAvailable, earnedAvailable, earningPeriod, scopes,
      trialSuccess, trialFailure, trialCancelled, trialSetupHistogram,
      trialSetupMillis, trialElapsedMillis }
```

### TCP fields

| Field | Meaning |
| --- | --- |
| `activeFlows` | Accepted transparent TCP flows currently holding an admission permit. |
| `limit` | Current process-wide TCP-flow admission ceiling; it starts at the descriptor-derived floor and scales with idle descriptor headroom. |
| `capacity.rejected` | Monotonic count of accept-loop iterations that waited for a permit because the TCP budget was full; accepted sockets remain in the kernel backlog rather than being dropped. |

### QUIC fields

`srttUs`, `cwndBytes`, `currentMtu`, `receiveWindowBytes`,
`receiveWindowAvailableBytes`, `streamReceiveWindowBytes`, `sendWindowBytes`, and
`sendWindowAvailableBytes` are averages across active connections and are zero
when none are active. `flowReceivedBytes` counts stream bytes delivered to
applications, and `flowSentBytes` counts stream bytes acknowledged by peers;
like the packet, UDP-byte, I/O, loss, black-hole, and congestion counters, they
include completed pooled connections.

Pooled TUIC, Juicity, and Hysteria2 connections sample this flow-control state
once per second. Ten-second receive and send goodput EWMAs require at least
80 ms RTT and three consecutive high-BDP samples before honk raises the live
connection receive or send floor toward `2 x BDP`. Peer `DATA_BLOCKED` and
`STREAM_DATA_BLOCKED` frames are direct evidence that an advertised window is
the constraint: they bypass the RTT gate and double the connection or stream
receive floor instead — the goodput-derived estimate is understated exactly
while a window throttles the flow. A
zero-progress sample preserves but does not advance a connection-level streak
only while its credit remains pressured. Each floor has its own five-minute
promotion cooldown, and automatic promotions are capped at 32 MiB without
lowering a larger explicit configuration. honk never shrinks a learned window
from low application demand and never changes congestion control on a live
connection.

`ackFrames` counts received ACK frames and is a path-progress signal; duplicate
ACK frames may count more than once. `lossRatePpm` excludes PLPMTUD probes: its
denominator is `sentPackets - sentPlpmtudProbes`, while `lostPackets` likewise
excludes probe losses. `sentPlpmtudProbes` and `lostPlpmtudProbes` expose those
probes separately. `txIos` and `rxIos` expose batching efficiency.
`transportTxWouldBlock` counts full 64-packet adapter queues (Quinn retries);
`transportTxDrops` counts datagrams intentionally discarded after the proxied
transport reports congestion or timeout. `transportRxDrops` counts full adapter
receive queues, and `sessionRxDrops` counts full 256-packet TUIC/Hysteria2
session queues. `sendTimeouts` and `pathStalls` are process-lifetime recovery
events.

### Score selection-reason fields

`score.groups` is an additive part of the authenticated `/stats` response. It is an empty array when no group currently uses `policy: score`; otherwise it contains every current Score group, including groups with no resolved leaves, sorted lexicographically by `name`. Each group always has both `tcp` and `udp` objects, and each object always has every `R` field above. Missing network activity is represented by zeroes, never omitted fields.

Each `R` value is a saturating `u64` count, not a latency, throughput or health measurement. One authorized multi-candidate Score Apply records one final reason: `coldExplore` or `periodicExplore` for validation; `incumbentIneligible` for leaving an incumbent outside ordinary eligibility; `freshFailureBypass` for an eligible incumbent's unresolved business failure; `insufficientEvidenceHeld` when no challenger earns promotion and the ordinary utility winner lacks a qualified shared performance comparison; `directionalTradeoffHeld` when none earns promotion and a comparison has at least 10% gain in one known direction but greater than 10% loss in another; `incumbentHeld` when comparison does not clear the hold margin; otherwise `reliabilityWinner` or `performanceWinner` retain their alternative-eligibility classification. `performanceWinner` does not by itself prove improvement or a switch, and `insufficientEvidenceHeld` does not mean reliability history is absent. `ordinarySwitch` counts actual committed normal A→B choices; `switchFlap` counts returns to the prior winner within eight same-target ordinary choices. First choices, trials and missing prior history cannot add switches. `deadFiltered`, `failStreakExcluded` and `exploreBackedOff` count affected candidates per rank. Peek, API reads, singleton bypass and last resort do not increment these reason counters; ranks in nested groups are not a one-to-one count of dispatched connections.

For UDP, `deadFiltered` also counts candidates excluded by protocol/configuration incapability. It is a candidate-filter count, not a count of newly failed nodes or business attempts; these exclusions do not add Score failures or exploration backoff.

`carrierPressure` counts fresh carrier-family episodes admitted into an existing group/network aggregate cell, not packets or failed connections; duplicate heartbeat reads do not increment it. `carrierValidation` counts periodic validation selections while the ordinary winner has a carrier hint newer than the previous validation. It is an overlapping diagnostic count, not another exclusive reason or proof that the hint alone caused the selection. Hints do not alter business reliability, qualification or health. These fields are readonly on API reads; carrier observations arrive from the control heartbeat independently of selection calls.

`carrierRttPressure` and `carrierLossPressure` retain the accepted episode's reason. An episode indicating both increments both reason counters but increments `carrierPressure` only once. These overlapping counts do not identify a specific carrier/transport, measure an application loss rate, or add failures; duplicate or stale hints increment none of them. TCP loss pressure means retransmission pressure, not confirmed application packet loss.

Counters begin at zero on process start and accumulate in process memory only. They survive a successful reload while the group name remains configured, including zero-leaf and temporary Score-to-non-Score-to-Score transitions; non-Score groups are hidden from this response. A committed deletion prunes that name's counters, and a recreated name starts at zero. Generation-fenced superseded managers cannot mutate counters after replacement, including after same-name recreation. The snapshot is copied before JSON serialization, so reading it cannot mutate selection state.

`/stats.score` exports group names, fixed TCP/UDP reason, verification and budget fields, a root business count, and bounded evidence-cache totals. It contains no node identity, target/domain/IP/port, raw cell, cadence key, authority or credential. Existing public member names in `/proxies` and destination metadata in `/connections` remain unchanged.

### Score verification

Score group objects in `/proxies` and `/proxies/{name}` add `scoreVerification`. Its fixed objective is `responseQualityWithAvailability`, and its scope is `aggregate`, not a certificate for every exact destination. `tcp` and `udp` each contain:

| Field | Meaning |
| --- | --- |
| `selected` | Existing public member tag for this readonly evaluation, or null with no ordinary eligible candidate. TCP `now` uses this same evaluated choice when present. |
| `state` | `provisional` or `observedUsable`; the latter requires four distinct targeted Traffic reporters with RX after setup/TX in one uninterrupted cohort, whose latest eligible RX is less than 60 seconds old. Applicable failure/reload or a 60-second gap resets the cohort; clones/repeats cannot add credits. This does not grant cold qualification. In a genuine post-failure cohort the same four credits may independently earn scoped recovery; aggregate usability does not qualify every exact target. |
| `challengers` | Fresh pairwise response comparisons between `selected` and evaluated challengers; see below. |
| `nextAction` | `nextBusinessFlow` names future real-work demand for evidence, ordinary qualification or recovery, not a reservation or dispatched I/O; inspect `waitReason`. `backoff` retains failure isolation; `none` means no actionable missing work. Missing transfer evidence never creates work; directional goodput waits for real offered load. |
| `question` | `none`, `availability`, `response`, `qualification` or `recovery`: the next unresolved evidence question. No remaining action reports `none`; backoff retains the blocked candidate's question rather than the settled winner's. |
| `waitReason` | `none`; `budget` for unavailable credit; `comparableTraffic` for future comparable business; `inFlight` for sufficient matching-target work or the separate four-work node ceiling; or `backoff` for failure isolation. Aggregate reads inspect retained IPv4/IPv6 scopes without creating them: both budget-blocked yields `budget`, either available/unseen scope leaves future comparable traffic possible, otherwise an in-flight wait remains. A wait is not proof that work will succeed. |
| `coverage` | `scope` (`all` or `bounded`), `candidates`, `evaluated`, `unevaluated` and `pending` counts. Explicit bounded identities determine evaluation membership even across filtered views. Unevaluated members receive no comparisons. `pending` counts evaluated members with an open question, including qualification or recovery work for members that already have a comparison. |
| `network`, `targetFamily`, `healthFamily`, `targetSpecific` | Transport and scope dimensions. This aggregate endpoint has no exact target and exports no domain/IP/port or raw node ID. |

Readonly/Peek uses committed participant membership without reranking. Apply initializes and refreshes that membership. Before initialization, readonly reads use a temporary bounded projection. See [evaluation-set lifecycle](../design/groups.md#conditional-verification).

`challengers` lists the selected member's current original pairs, the same pairs ordinary promotion reads, that hold a fresh qualified response metric. Members without one are omitted; the list is empty when none has one. Each entry has `name` (the public member tag, a display label that need not be unique across nested paths), `basis` (`targetResponse`, `commonTargets` or `configuredProbe`), `relation` (`selectedFaster`, `equivalent` or `challengerFaster`), `reporters` and `validForMs`. `equivalent` uses the inclusive symmetric band `high - low <= 0.1 × low` on actual response values, including zero and sub-millisecond values. `reporters` is the weaker side's retained distinct-reporter support: each of four blocks retains up to four IDs, and their deduplicated union can reach sixteen; this is not the exact count of every observed reporter. `validForMs` is the remaining validity of that response metric. Business blocks last 15 seconds and expire at block start plus 60 seconds. Configured-probe blocks use `max(15s, 2I)` for the producer's interval `I`, with validity bounded by both the oldest supporting block's four-block retention deadline and the weaker side's latest support plus `max(60s, 2I)`. Existing failure/reload/incarnation fences remain. `commonTargets` uses at most eight canonical equal-weight response-qualified shared targets, not unrelated aggregate averages; setup and warm-up are not comparison evidence.

A relation describes measured response time only. It is not a promotion decision, a reliability or bandwidth verdict, an error probability or a guaranteed optimum, and it does not certify the selected member against members absent from the list. Ordinary switching still applies its own completion-dependent margin and reliability, availability and directional protections. Reads do not dispatch validation or change counters.

`/stats.score.groups[].verification.tcp` and `.udp` add saturating counters: `provisionalSelections`, `usableSelections` and `validationSelections`. They advance only on authorized Apply.

### Score work budget and observed costs

`/stats.score.businessStarts` counts unique original Score business starts across nested groups. `/stats.score.groups[].budget.tcp` and `.udp` aggregate retained target-family scopes; nested group totals must not be summed as unique businesses. Original work counts even when selected as a trial; continuations, including a different network or target family, earn no additional original credit. Node-specific work starts before proxy DNS or physical-dial admission waits, independently of the reporter's physical/logical I/O boundary. DNS query lifecycle admission is a synchronous open/closed check before that work, not a physical-admission wait.

Budget counters report recorded ledger values. Readonly wait and cold-start decisions also account for credit refundable from expired pending reservations; they do not update `refunded`, `expired` or other counters.

| Fields | Meaning |
| --- | --- |
| `businessStarts`, `scopes`, `earningPeriod` | Original starts summed over retained scopes, scope count, and the fixed earning period `q = 16` (0 before any scope exists). It is not a denominator for a combined-scope budget formula: each scope freezes cold allowance `B` at creation, and `spent + reserved <= B + floor(businessStarts/q)` applies per scope. |
| `sources.cold`, `sources.periodic`, `sources.recovery` | Started work by source: cold-token trial, earned-token trial, or budget-neutral continuation. `recovery` includes TCP replacement, DNS rerouting/UDP-to-TCP fallback and UI redirects, not only retries after errors; it is neither an optional trial nor new original business. Ordinary non-trial work has no source bucket. |
| `trialStarts`, `spent`, `reserved` | Begun optional trials, cumulative spent tokens, and outstanding unbegun token reservations. Begin spends once; cancellation after begin does not refund. |
| `coldAllowance`, `coldAvailable`, `earnedAvailable` | Summed frozen initial allowances and current available credit. Each scope retains at most eight unspent earned tokens. Time, reads, target churn and evidence expiry earn none; retained reload/membership changes do not reset currency. |
| `budgetBlocked`, `inFlightBlocked`, `refunded`, `expired` | Denied reservation counts, last-reference/unbegun invalidation refunds, and expired in-flight tracking entries. Only unbegun reservations refund; tracking expiry never refunds begun work. |
| `trialSuccess`, `trialFailure`, `trialCancelled` | Exactly-once outcomes of begun optional trials. Rejection/shutdown/neutral cancellation belongs to `trialCancelled`. `trialFailure` is actual observed failure, not the extra failures caused by choosing a trial instead of an unobserved alternative. |
| `trialSetupHistogram`, `trialSetupMillis`, `trialElapsedMillis` | Eight fixed log2-millisecond setup buckets (slot 0 includes 0–1 ms; final slot includes 128 ms and above), summed observed setup duration, and summed start-to-settlement duration. These measure actual trial cost, not causal extra latency or overhead. |

`/stats.score.cache.comparisonCells` is capped at 256. `comparisonLogicalBytes` charges the comparison store, vector capacity and owned key capacity; `comparisonLogicalCapacity` is its implementation-sized worst-case allocation bound, no greater than 1 MiB. Neither is measured process RSS or the size of all Score state; allocator overhead and other process allocations are excluded. `comparisonEvictions`, `comparisonExpired` and `comparisonRejected` count store removal/admission events; readonly expiry can invalidate support before physical removal increments a counter. Existing exact/aggregate LRU fields are unchanged.

### Outbound and ready-pool fields

| Field | Meaning |
| --- | --- |
| `outbounds[].name` | Outbound name. |
| `outbounds[].totalConns` | Connections started through the outbound. |
| `outbounds[].activeConns` | Connections currently open through the outbound. |
| `outbounds[].upload` | Userspace bytes from client to proxy. |
| `outbounds[].download` | Userspace bytes from proxy to client. |
| `outbounds[].errors` | Failed connection attempts attributed to the outbound. |
| `pool.readyHits` | Ready bare-connection pool hits. |
| `pool.readyMisses` | Ready bare-connection pool misses. |
| `pool.entries` | Current ready bare-connection entries. |

### Histogram format

Each `H` is `{count, sumNanos, buckets}`. `count` is the number of observations and `sumNanos` is their nanosecond sum. `buckets` is a 64-element array of non-cumulative counts: slot $n$ covers $2^n$ through $2^{n+1}-1$ ns, slot 0 also includes zero, and the final slot saturates at `u64::MAX`.

### UDP fields

| Field | Meaning |
| --- | --- |
| `endpoint.hits` | Packets handled by an already-established UDP endpoint fast path. |
| `endpoint.misses` | Cold-flow endpoint lookup misses. |
| `latency.route` | Cold route-selection latency. |
| `latency.dial` | Cold UDP dial-attempt latency. |
| `latency.replyReady` | Synchronous reply-socket preparation before endpoint-driver commit. |
| `latency.firstSend` | First-send attempt latency. |
| `latency.firstReply` | Time until the first reply is successfully reinjected to the client. |
| `capacity.rejected` | Exact endpoint-capacity reservation rejections. |
| `slowPermit.accepted` | Admissions into the active UDP slow path. |
| `slowPermit.rejected` | Slow-path admissions rejected because the shared connection semaphore is full. |
| `slowPermit.closed` | Slow-path admissions rejected while the generation is draining. |
| `queue.accepted` | Packets admitted to a bounded endpoint-driver queue. |
| `queue.full` | Aggregate retained-queue drop-newest events. |
| `queue.flowFull` | Drop-newest events caused by one flow's packet-slot bound. |
| `queue.globalPayloadFull` | Drop-newest events caused by the global retained-payload byte bound. |
| `queue.closed` | Queue attempts against a closing or closed endpoint driver. |
| `firstSend.failures` | First-send errors or timeouts; both are treated as ambiguous sends. |
| `stagger.attempts` | Cold URLTest speculative preparation attempts started. |
| `stagger.winners` | First eligible staggered preparations that succeeded. |
| `stagger.cancellations` | Started speculative preparations cancelled after another candidate won. |
| `warm.attempts` | Generation-owned UDP warm dispatches started. |
| `warm.successes` | Warm dispatches returning `Ready`. |
| `warm.failures` | True warm failures while the generation remains live. `NotApplicable` is neutral. |

`queue` measures the endpoint-driver queue. It is distinct from `slowPermit`, which measures admission to the UDP slow path.

### NFQUEUE fields

| Field | Meaning |
| --- | --- |
| `received` | Packets delivered by the NFQUEUE listener. |
| `activeFlows` | Current flow cells owned by the pending-verdict correlator. |
| `kernelQueueDepth` | Current queued packet count for the active kernel queue instance. |
| `kernelStatsAvailable` | Whether the latest kernel queue-statistics read succeeded. |
| `kernelStatsReadErrors` | Cumulative kernel queue-statistics read failures. |
| `kernelDropped` | Packets dropped because the kernel NFQUEUE reached its queue limit, accumulated for the process lifetime across hard queue rebinds. |
| `kernelUserDropped` | Packets dropped while the kernel delivered NFQUEUE messages to userspace, accumulated for the process lifetime across hard queue rebinds. |
| `heldPackets` | Current delivered packets whose verdict guards remain held. |
| `heldPeak` | Peak simultaneous held verdict guards reported by the queue service. |
| `socketReceiveBufferBytes` | Effective netlink socket receive-buffer size. |
| `actorQueueFull` | Packets dropped fail-closed because the bounded ingest actor queue was full. |
| `correlatorFull` | Packets dropped at either hard correlator limit: 4,096 flow cells or 64 retained verdicts per flow. |
| `actorQueueDepth` | Current ingest actor queue entries. |
| `actorQueuedBytes` | Current payload bytes retained in the ingest actor queue. |
| `actorOldestAgeNanos` | Age in nanoseconds of the oldest current ingest actor item. |
| `directAccepted` | Successful marked `NF_ACCEPT` verdicts for direct decisions. |
| `proxyCopied` | Payload ownership transfers into the canonical UDP initializer. |
| `proxyDropped` | Successful original-packet `NF_DROP` verdicts for proxy decisions. |
| `block` | Successful policy-block drop verdicts. |
| `cancel` | Successful cancellation drop verdicts. |
| `drop` | Other successful fail-closed drop verdicts. |
| `tokenMismatch` | Stale or mismatched decision-token/flow-identity events. |
| `tokenExhaustion` | Observations that the persistent decision-token allocator is exhausted. |
| `tokenRollovers` | Successful exhausted-token generation rotations. |
| `verdictErrors` | Failed `NF_ACCEPT` or `NF_DROP` operations. |
| `receiptToVerdict` | Histogram from listener receipt to a successful terminal verdict; it is not kernel queue residence time. |

A one-second sampler reads the owned kernel queue independently of packet dispatch. After a failed read, the previous `kernelQueueDepth`, `kernelDropped`, and `kernelUserDropped` remain visible, while local held-packet and receive-buffer gauges continue to refresh.

### Warm-resource fields

| Field | Meaning |
| --- | --- |
| `warm.nodes.preconnect` | Warm nodes attributed to startup bare-TCP preconnect. |
| `warm.nodes.health` | Warm nodes observed during health probing. |
| `warm.nodes.udp` | Warm nodes attributed to the UDP warm coordinator. |
| `warm.nodes.selector` | Warm nodes retained as configured Selector leaves. |
| `warm.nodes.traffic` | Warm nodes with no explicit attribution mark, therefore attributed to traffic. |
| `warm.sessions.anytls` | Retained AnyTLS pool sessions. |
| `warm.sessions.vless` | Retained VLESS pool sessions. |
| `warm.sessions.tuic` | Occupied TUIC client slots. |
| `warm.sessions.juicity` | Occupied Juicity client slots. |
| `warm.sessions.hysteria2` | Occupied Hysteria2 client slots. |

A node may count under several explicit reasons. The gauges follow the current runtime generation; drained resources disappear from the next snapshot.

## Related docs

- [Experimental configuration](./experimental.md)
- [NFQUEUE design](../design/nfqueue.md)
- [Control-plane design](../design/control-plane.md)
