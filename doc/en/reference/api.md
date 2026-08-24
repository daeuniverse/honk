# Clash API and `/stats` reference

This reference describes honk's implemented Clash-compatible HTTP surface and its userspace statistics snapshot.

## Enablement and authentication

The API server starts only when `experimental.clash_api.external_controller` is non-empty and the binary includes the default-on `clash-api` feature. The controller accepts `host:port`; a leading `:port` binds `0.0.0.0:port`. An invalid address is logged and does not stop the engine.

When `experimental.clash_api.secret` is non-empty, API requests require:

```http
Authorization: Bearer <secret>
```

A WebSocket upgrade may instead pass `?token=<percent-encoded-secret>`. honk percent-decodes the token before exact comparison. Query-token authentication is limited to WebSocket upgrades; ordinary HTTP requests use the Bearer header. An empty `secret` disables authentication. The `/ui` static tree is outside the API authentication layer.

**The API has no TLS.** Bind it to localhost or place a TLS reverse proxy in front of it, and set a strong `secret` when untrusted clients can reach the listener.

## Endpoint map

The table follows the router in `crates/honk-core/src/clash_api.rs`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Return the Clash hello document, or redirect a non-JSON client to `/ui/` when external UI hosting is enabled. |
| GET | `/version` | Return honk version and Clash premium/meta capability flags. |
| GET | `/configs` | Return the current mode and the implemented Clash-compatible configuration snapshot. |
| PUT | `/configs` | Compatibility no-op; accepts the request and returns `204 No Content`. |
| PATCH | `/configs` | Set `mode` to `Rule`, `Global`, or `Direct`; matching is case-insensitive. |
| GET | `/proxies` | Return every node and group plus the synthetic `GLOBAL` selector. |
| GET | `/proxies/{name}` | Return one node, group, or `GLOBAL` selector. |
| PUT | `/proxies/{name}` | Select a direct member of a Selector group with `{"name":"member"}`; also mutates the synthetic `GLOBAL` selector. Automatic groups, including Score, reject writes. |
| GET | `/proxies/{name}/delay` | Run an on-demand URL delay test for a node or group. Already-warm transports are reused; every cold reusable session or QUIC client is warmed in a throwaway runtime before timing. |
| GET | `/group/{name}/delay` | Test all group members concurrently (maximum 10) and return successful member delays with the same timing semantics. |
| GET | `/rules` | Return one row per route. Simple matchers use native Clash rule types; compound, negated, and `must` rules use `complex` with the full dae statement. |
| GET | `/connections` | Return a connection snapshot, or stream snapshots after a WebSocket upgrade. |
| DELETE | `/connections` | Close all tracked connections. |
| DELETE | `/connections/{id}` | Close one tracked connection. |
| GET | `/traffic` | Stream per-second traffic JSON over WebSocket or chunked JSON lines. |
| GET | `/memory` | Stream process RSS JSON over WebSocket or chunked JSON lines. |
| GET | `/stats` | Return the userspace outbound, ready-pool, warm-resource, Score selection-reason, and UDP snapshot documented below. |
| GET | `/logs` | Stream tracing events over WebSocket or chunked JSON lines; `?level=` defaults to `info`. |
| GET | `/dns/query` | Resolve `?name=` through honk DNS and return DoH-style JSON; `?type=` defaults to `A`. |
| POST | `/cache/fakeip/flush` | Flush persisted FakeIP-prefixed cache entries when the cache database exists. |
| POST | `/cache/dns/flush` | Flush the live DNS cache and its persisted DNS state. |
| GET | `/providers/proxies` | Expose non-empty groups as Clash proxy providers. |
| GET | `/providers/rules` | Return the current stub document `{"providers":[]}`. |
| GET | `/ui`, `/ui/*` | Redirect `/ui` to `/ui/` and serve the configured external UI directory. |

`/traffic`, `/memory`, and `/logs` send one JSON document per line for a plain HTTP GET. `/logs` installs dynamic tracing interest only while subscribers exist; with no subscribers, the Clash tracing layer does not format events.

### Delay measurement

Delay tests time the proxied HTTP `HEAD` exchange through receipt of response headers; HTTPS includes the target TLS handshake. Cold reusable transports—AnyTLS, VLESS H2MUX/Mux.Cool, Hysteria2, TUIC, and Juicity—first establish their session or QUIC client in a temporary runtime, then run one measured exchange through it. The temporary runtime closes afterward, so scanning a large group does not leave reusable state per tested node resident. This warm-up has its own timeout before the measured timeout; a cold request can therefore take up to twice the requested timeout.

Hysteria2 additionally follows sing-box's lazy-handshake rule: timing starts after its outbound dial returns because the target request is coalesced with the first application write. TUIC and Juicity complete the target request header inside the now-warm dial. All three QUIC protocols therefore exclude cold QUIC connection/authentication setup, while preserving their wire-specific target-handshake boundary. Reported values can be lower than releases that included cold setup.

Successful measurements update the node latency history. Failures return `503` for a single node, are omitted from the group result, and append a failure strike used by URLTest selection.

Each delay-test exchange through a proxy or built-in `direct` leaf reports its real URL target and success or failure to every Score group containing the tested leaf. Any preliminary server/session warm-up reports aggregate setup only; it does not fabricate the URL as its own target. Non-Score paths create no score reporter or cell.

### Score group representation

A configured `policy: score` group is represented as Clash `type: "url_test"` for compatibility. Its `all` list keeps the same direct member tags as other groups, while `now` reports the current aggregate TCP winner rather than any one exact target's private selection. Score remains automatic and authoritative: `PUT /proxies/{name}` is rejected rather than pinning a member. No score cell or scorer-only target data is added to proxy documents; `/stats.score` contains only the safe aggregate counters documented below. `/connections` retains its established destination metadata.

## Mode and selector mutations

`PATCH /configs` accepts a JSON object such as:

```json
{"mode":"Global"}
```

The mode update goes through `DatapathFlagsHandle`, the sole serialized writer for the shared mode and `DATAPATH_FLAGS_MAP`. Mode changes therefore compose atomically with reload's NFQUEUE fence, reopen, disable, and static-flag updates instead of republishing stale readiness bits. A cache database, when enabled, stores the normalized mode.

`PUT /proxies/{name}` accepts the body regardless of `Content-Type`. For a configured Selector group, the target must be a direct member tag; a leaf reachable only through a nested group is not a direct member. An actual choice change invokes the group manager's cache callback, so an enabled `cache_file` persists the choice in `cache.db`. If that group sets `interrupt_connections`, honk removes tracked connections associated with the group, its member tags, and reachable leaves so subsequent traffic redials through the new choice. Writing the existing choice does nothing. URLTest, LoadBalance, Fallback, and Score groups reject the mutation.

`GLOBAL` is synthetic. `PUT /proxies/GLOBAL` accepts `Proxy`, any configured group, or any configured node and updates it through the same `DatapathFlagsHandle`; the cache database stores it under the `GLOBAL` selector key when enabled.

## External UI hosting

Set `experimental.clash_api.external_ui` to serve a static dashboard directory. If the directory is missing or empty, honk starts a background download of the latest zashboard `dist.zip`; startup does not wait, and the static route returns `404` until files are available. `HONK_UI_DOWNLOAD_URL` overrides the archive URL.

The download follows honk's current traffic routing decision. A `direct` result uses the direct HTTP client, `block` aborts the download, and a proxy result uses the selected outbound leaf. Redirect targets are routed again. Each direct or proxied HTTP exchange reports the real host/IP, port, setup, first response, bytes, and terminal outcome to its traversed Score groups; paths that traverse no Score group create no score reporter or cell. Download or extraction failures are logged and do not stop the engine.

## `GET /stats`

`GET /stats` is a userspace snapshot. It is not the eBPF `OUTBOUND_STATS` map and does not expose its packet counters. The fixed TCP, UDP, and NFQUEUE schemas create no dynamic per-node labels.

```text
{
  outbounds: [{ name, totalConns, activeConns, upload, download, errors }],
  pool: { readyHits, readyMisses, entries },
  warm: {
    nodes: { preconnect, health, udp, selector, traffic },
    sessions: { anytls, vless, tuic, juicity, hysteria2 }
  },
  tcp: {
    activeFlows, limit, capacity: { rejected }
  },
  score: {
    groups: [{ name, tcp: R, udp: R }]
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
  incumbentHeld, freshFailureBypass, deadFiltered
} // every R value is a u64 count
```

### TCP fields

| Field | Meaning |
| --- | --- |
| `activeFlows` | Accepted transparent TCP flows currently holding an admission permit. |
| `limit` | Current process-wide TCP-flow admission ceiling; it starts at the descriptor-derived floor and scales with idle descriptor headroom. |
| `capacity.rejected` | Monotonic count of accept-loop iterations that waited for a permit because the TCP budget was full; accepted sockets remain in the kernel backlog rather than being dropped. |

### Score selection-reason fields

`score.groups` is an additive part of the authenticated `/stats` response. It is an empty array when no group currently uses `policy: score`; otherwise it contains every current Score group, including groups with no resolved leaves, sorted lexicographically by `name`. Each group always has both `tcp` and `udp` objects, and each object always has every `R` field above. Missing network activity is represented by zeroes, never omitted fields.

Each value is a saturating `u64` count, not a latency, byte, duration, target, or health metric. The first six fields classify one authorized multi-candidate Score **Apply** in this fixed precedence: `coldExplore` for initial-budget exploration; `periodicExplore` for a periodic forced cold non-incumbent; `incumbentHeld` for a successful incumbent hold; `freshFailureBypass` when fresh failure evidence alone breaks a small trained utility-margin hold; `reliabilityWinner` when every alternative is outside the selected reliability band; otherwise `performanceWinner`. `deadFiltered` is independent: it counts unique leaf candidates removed by liveness filtering during an authorized Apply and can increase beside one of the first six fields. Peek, `/proxies`, `/stats`, singleton bypasses, and last-resort selection do not count.

Counters begin at zero on process start and accumulate in process memory only. They survive a successful reload while the group name remains configured, including zero-leaf and temporary Score-to-non-Score-to-Score transitions; non-Score groups are hidden from this response. A committed deletion prunes that name's counters, and a recreated name starts at zero. Generation-fenced superseded managers cannot mutate counters after replacement, including after same-name recreation. The snapshot is copied before JSON serialization, so reading it cannot mutate selection state.

`/stats.score` exposes only a group name and the fourteen TCP/UDP aggregate counts. It never contains a node, node ID/tag, target/domain/IP/port, target family, score cell, cadence key, manager authority, credential, or other scorer-private value; those values are also excluded from new Score logs and persistence. This addition does not change established node names in `/proxies` or `/stats.outbounds`, or established destination metadata in `/connections`.

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
