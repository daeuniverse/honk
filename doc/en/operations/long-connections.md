# Long connections and keepalive

honk does not synthesize application keepalives. Keeping a transport carrier open does not keep every UDP flow inside it alive.

## UDP: replies keep the endpoint alive

An endpoint retires after **120 s without a reply**; successful sends and carrier keepalives do not reset that timer. Pure-uplink flows expire even while sending. The next packet may create a new endpoint if admission permits; old packets are not replayed. A never-replied flow settles Score as timeout. After a delivered reply, later idle retirement is health-neutral and settles Score as success.

Each ordinary no-reply expiry counts as a `DataUdp` health failure. After a node's 60 s registration grace, 50 consecutive counted failures make it unavailable for that probe domain/address family. Delivered replies or successful probes for the same key reset the run, not sends alone. A shared UDP association reports one no-reply health failure only if it sent data and never received a reply: once another destination has replied, an unreplied view can still expire with a Score timeout, but neither demotes nor retires the whole source. See [health and Score](../design/groups.md).

Kernel state has independent [UDP idle-renewal rules](../design/datapath.md#udp-lifetime-renewal); a fresh kernel entry does not prevent userspace reply-idle expiry. Userspace does not keep silent kernel entries fresh; kernel-state reclamation also retires the owning endpoint, so the next packet needs a new one. Transport keepalives do not configure external NAT/conntrack.

New mappings drop at the process-wide **32,768-endpoint hard cap** (both families combined), or the lower startup descriptor or memory budget (a quarter of `MemTotal` at 64 KiB per endpoint, 8,192 at 2 GiB); existing mappings are not evicted and rejected datagrams are not queued. NFQUEUE originals drop too. Check `udp.capacity.rejected` in authenticated Clash `GET /stats`; raising the service `RLIMIT_NOFILE` helps only while descriptors are the smaller limit. [Slow-path/queue budgets](../design/control-plane.md#queue-and-descriptor-budgets) can reject work earlier.

## TCP: idle is not a relay deadline

Established relays have no general userspace idle timeout; `global.relay_idle_timeout_secs` has no effect. Accepted relays retain their kernel records while alive. After the first EOF, the remaining direction ends only after **30 s without byte progress**; connect/sniff/handshake deadlines apply only during setup.

Linux TCP keepalive uses **3600 s idle / 15 s interval / 4 probes** on client-facing transparent sockets, and **15 s / 10 s / 3 probes** on outbound dials and TCP carriers. A live idle peer can answer indefinitely; probes prove transport reachability, not application progress. See [TCP relay ownership](../design/control-plane.md#tcp-relay-and-conn-state-ownership).

## Carrier keepalives

H2/gRPC, including VLESS H2MUX, XHTTP and DNS-over-HTTPS H2, sends no periodic HTTP/2 PING; it relies on traffic and TCP keepalive. A healthy TCP connection does not guarantee a usable remote application session.

QUIC keepalive intervals are **10 s** for Hysteria2/TUIC, **5 s** for Juicity, and **15 s** for DNS-over-QUIC/HTTP3. TUIC datagram mode also sends heartbeats at its keepalive interval; UDP-over-stream uses only QUIC keepalive.

Hysteria2/TUIC/Juicity reap locally unused connections after 120 s of inactivity, not active logical users. Peer-negotiated QUIC idle timeouts and remote application policies remain separate. QUIC PINGs and TUIC heartbeats are not replies to encapsulated UDP flows.

## What to check

- Inspect last application reply and terminal outcome, not just upload counters or carrier liveness.
- Distinguish timer expiry from [outbound health gating](../design/datapath.md#outbound-liveness) or capacity rejection.
- Check external firewall/NAT and remote application idle policies separately.

## Collecting Native publication evidence

Use the intended [Native publication artifact contract](../reference/api.md#native-publication-artifact) when investigating interruptions during Native policy/DNS/mode publication or runtime maintenance. This procedure and its exporter/consumer, fault-injection and real-hook checks are **NOT_RUN** in this implementation handoff. Keep existing timeout/failure verdicts until evidence from a bound build establishes otherwise.

1. Before attempts, retain structured startup/readiness output announcing the exact `<data_dir>/state/native-publication/<pid>-<starttime_ticks>-<publication_serial>.json` path. Copy the initial `final=false` manifest and bind boot ID, PID/starttime, publication serial and root map identity to this run. Retain executable hash, source/build/object receipts and attached program/map identities separately; a self-reported build version does not authenticate the binary. Missing manifest/path or recording initialization failure is a missing prerequisite, not zero transitions.
2. Retain local `CLOCK_BOOTTIME`/`CLOCK_MONOTONIC` attempt and shutdown brackets and any bounded peer-clock correlation. Suspend, cross-host uncertainty, capture loss and missing peer snapshots stay explicit. Do not infer a particular lost packet from timestamp overlap or sum hook counts into a deduplicated packet total.
3. Stop traffic sources before removing custody. Request normal daemon shutdown and retain its complete structured result, **including an Err result**. Allow actual terminal closure, detach or replacement of counter-referencing hooks by non-counting guards, join/drain plus reader grace, counter sealing and final export to finish while maps/journal owners still exist. A final writer commit, closed link FD, `honk-core stopped` line or surviving pin is insufficient proof of this join.
4. Before namespace/pin/artifact teardown or the next run, copy/hash the discovered artifact and durably retain its structured shutdown result bound to the same publication identity/path. For a published artifact, verify the result's streamed digest matches the collected bytes and retain that digest with the copy. Keep the shutdown failure and any separate export error together; a reachable failed-retained path must attempt an incomplete partial export before forgetting owners. Preserve failed-retained custody for the existing exact-owner cleanup procedure.
5. Require matching `export_publication_result=PUBLISHED_DURABLE` for complete evidence. `NOT_PUBLISHED` leaves the initial incomplete manifest; `PUBLISHED_DURABILITY_UNKNOWN` may expose replacement JSON with `final=true` after successful rename but failed directory sync. Reject unknown durability, absent/unbound/contradictory results or digest mismatches. `PUBLISHED_DURABLE` still requires `final=true`, `hooks_joined=true`, collection end after the work, complete identities, matched events, every covered hook/epoch sealed, contiguous sequence `1..last_seq`, `total_appended=last_seq=count(events)`, `first_retained_seq=1`, `overwritten_events=0` and no recording/clock/accounting/overflow faults. Preserve decimal strings without floating-point conversion.

A 4,096-entry ring can evict earlier history; no fixed number of retained seconds is guaranteed. A contiguous suffix or provisional count cannot satisfy whole-run completeness. Crash/SIGKILL/power loss can leave only the initial manifest, or visible terminal JSON without a matching durable result; no crash-surviving continuous journal is promised. Mark these observations incomplete. Even a complete artifact establishes recorded transition order and exact sealed closed-branch hook executions only: zero does not prove traffic reached a hook, and counts do not establish socket custody, application delivery, other-drop absence or a timeout's cause.

