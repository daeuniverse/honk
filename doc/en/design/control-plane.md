# Userspace control plane

This document describes the `honk-core` userspace engine between the kernel datapath and the outbound stack.

## Scope

The control plane owns transparent ingress, kernel handoff consumption, userspace routing, sniffing, outbound selection, relay, resource admission, and runtime publication. The kernel mechanisms that deliver flows are covered in [Datapath design](./datapath.md). Group policy and health-driven selection are covered in [Group design](./groups.md), and DNS runtime behavior is covered in [DNS design](./dns.md).

The main implementation is `crates/honk-core/src/control/`. It consumes `EbpfBackend` state and hands TCP streams or the `PacketTransport` UDP contract to `honk-outbound`.

Module map:

- `src/control/`:
    - `mod.rs` — `ControlPlane` [startup and shutdown](#startup-and-shutdown).
    - `connection/` — canonical [flow initializer](#sniffing-and-flow-initialization).
    - `nfqueue/` — `PendingUdpVerdicts` correlator; [held-packet protocol](./nfqueue.md).
    - `sockets.rs` — [transparent ingress](#transparent-ingress), anyfrom replies; `udp_ingress.rs` owns `udp_fast_path`.
    - `dns_control.rs` — `DnsController`; [query admission and projection](./dns.md#resolution-pipeline).
    - `dns_listener.rs` — `DnsListener`; [standalone ingress lifecycle](./dns.md#ingress-paths).
    - `reload/` — `apply_runtime_config`; [runtime publication](#reload-and-runtime-generations).
    - `routing_matcher.rs` — [atomic routing publication](./routing.md#synchronous-slots-and-atomic-publication) and [kernel rule lowering](./routing.md#restricted-native-backend).
    - `quic.rs`, `packet_sniffer.rs`, `tcp_sniff.rs` — QUIC decryption/reassembly, per-flow sniff sessions, and TCP negative cache, respectively.
    - `udp_endpoint/mod.rs` — `UdpEndpointPool`; [endpoint transactions](#udp-endpoint-pipeline).
    - `probers.rs` — `ProxyHttpProber`, `ProxyUdpProber`; [health probes](./groups.md#health-state-and-probes).
    - `janitor.rs` — `BpfJanitor`; [map maintenance](./datapath.md#userspace-maintenance-and-accounting).
    - `drain.rs` — `DrainTracker`; [accepted-flow drain](#reload-and-runtime-generations).

## Startup and shutdown

- `src/lib.rs` — `run()`, `Cli`/`ClashCommand`, resource limits, backend selection, fixed-queue startup preflight ([Configuration](../configuration.md)). Real instances hold `/run/honk-core.lock` and publish the `reload` PID. Via rtnetlink, create FD-owned `daens` and L2 netkit `dae0`; fall back to veth only on `EOPNOTSUPP`. Load/reuse the persistent allocator pin, then start NFQUEUE before datapath admission.

Configuration diagnostics are collected before tracing setup. An early load or operator-validation failure writes prior nonterminal diagnostics to stderr once, then lets the binary return the redacted terminal cause once. Successful loading defers diagnostics to the configured tracing subscriber. Later runtime fatal errors retain their existing log-file mirror.

Startup keeps kernel admission closed until userspace can receive every redirected flow:

1. Real mode takes `/run/honk-core.lock`, waiting up to 240 seconds for a previous instance to exit, and publishes the process PID in the locked file; `honk-core reload` reads that PID and sends `SIGHUP`. A successor that cannot take the lock exits before it reads the configuration or opens the state db. Mock mode does not take the process-global lock.
2. Load and validate the configuration, select `global.data_dir`, initialize the process bypass mark before any network I/O, raise `RLIMIT_NOFILE`, and take one immutable descriptor-budget snapshot.
3. Restore persisted subscriptions before network refresh. Only subscriptions without a valid restored body participate in the five-second first-fetch grace period.
4. After the real-instance lock handoff, probe the fixed NFQUEUE queue prerequisites. Mock/no-`ebpf` mode or a failed preflight logs a warning and disables NFQUEUE for this process; the preflight does not reject the reserved nftables table because installation reclaims stale owned state.
5. In real mode, create the FD-owned `daens` namespace and the `dae0`/`dae0peer` link through rtnetlink. The engine tries an L2 netkit pair first and falls back to veth only when the kernel reports netkit unsupported. The process stays in the host namespace; only synchronous socket, link, and attachment operations enter `daens` through scoped `setns` calls.
6. Load the BPF object and attach the real datapath. The default object is embedded with `include_bytes!`; `--bpf-object` supplies a runtime override. With the `ebpf` feature, `build.rs` locates the object, rejects stale or BTF-less output, rebuilds it with nightly after removing inherited `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS`, verifies `.BTF`, and copies it into `OUT_DIR` for embedding.
7. Reuse or create the pinned `UDP_DECISION_SEQUENCE` allocator and validate its map ABI, BTF, locked value, token range, and exhaustion state. NFQUEUE startup rechecks the locked allocator status and leaves staging fenced if no rollback-safe generation is available.
8. Build the userspace router, outbound runtime registry, DNS runtime, group manager, cache DB, optional Clash API, and control-plane supervisors.
9. Bind the transparent TCP/UDP listeners, publish the complete listener FD set, start the standalone DNS and UDP receive loops, then start the NFQUEUE service and its ingest actor, correlator, watchdog, and independent one-second queue-pressure sampler when the effective flag remains enabled.
10. Check NFQUEUE health, publish its ready state, open pending verdict admission, and set `DATAPATH_STATE_MAP[0]` ready last. The TCP accept loop then runs in the control-plane supervisor.

`RealEbpfBackend` owns aya programs, maps, links, persistent allocator handling, and real NFQUEUE integration. `MockEbpfBackend` provides the same control-plane interface without privileged kernel resources. A requested NFQUEUE path that cannot pass the post-lock fixed-queue preflight is disabled with a warning; failures after the service is admitted remain fatal.

Shutdown reverses ownership before resources disappear: fence NFQUEUE, close datapath admission, reject new userspace work, cancel and drain held verdicts and UDP initializers, stop UDP drivers and removal processing, stop the interface watcher, detach BPF hooks, drain accepted flows for up to five seconds, retire the outbound runtime, stop NFQUEUE, stop the DNS controller and persistence, and clean up generation-owned BPF state. Ordinary cleanup preserves the pinned allocator. Listener and `daens`/link-pair ownership then falls out of scope.

When UDP receive-priority ancillary metadata is unavailable, the real backend owns the receive-trace fallback's links and maps. `cleanup()` detaches ingress hooks, joins its ring consumers and drops `receive_trace` before dropping the BPF object, even if the backend itself stays alive; ordinary cleanup still preserves both persistent sequence pins.

## Transparent ingress

Real TCP and UDP listeners are created inside `daens` with transparent socket options and the effective `global.so_mark_from_dae` (zero selects `0x100`). The mark lets the datapath recognize honk's own listeners rather than treating them as ordinary local services. Accepted TCP sockets inherit the mark, so each accept loop clears it before handling the flow. Mock listeners are ordinary host-namespace sockets without privileged transparent options.

Original destinations are recovered as follows:

| Ingress | Primary source | Fallback |
| --- | --- | --- |
| TCP/IPv4 | `SO_ORIGINAL_DST` | Transparent socket `local_addr()` |
| TCP/IPv6 | `IP6T_SO_ORIGINAL_DST` | Transparent socket `local_addr()` |
| UDP | `IP_RECVORIGDSTADDR` / IPv6 original-destination cmsg | Guarded provenance rules described below |

For ordinary flows, userspace forms the canonical tuple and consumes `ROUTING_HANDOFF_MAP` with `routing_handoff_take`. A missing handoff, or an outbound of `ControlPlaneRouting`, falls back to `Router::route_action`. Final `must` and `block` results cannot be overridden by Clash mode. This fallback is not the transparent DNS ownership boundary.

Port-53 controller versus raw-transport ownership follows the [ordered traffic-rule contract](../reference/routing.md#outbound-targets-and-must), including the malformed non-`must` UDP fallback.

Real transparent UDP53 requires valid per-packet `SO_RCVMARK` / `SOL_SOCKET` `SO_MARK` provenance and the current committed routing generation for both controller and raw ownership; a tuple handoff cannot substitute. Transparent TCP53 requires a SYN handoff. Only raw-`must` TCP additionally requires the current routing generation and pins the config, semantic group, and outbound runtime before raw I/O; non-`must` TCP retains controller query admission without that generation check. Missing required metadata or a failed required generation check rejects admission before I/O. Physical compatibility belongs to the [handoff ABI and UDP carrier](./datapath.md#map-inventory).

## Sniffing and flow initialization

TCP sniffing reads at most 4096 bytes and extracts TLS SNI or HTTP `Host`. The returned buffer is part of the flow state and is written to the selected outbound before relay starts, so sniffing consumes no application bytes. TCP sniffing is skipped for `dial_mode: ip`, a final direct/block or `must` handoff, or a TCP negative-cache hit. Three consecutive failures suppress the same destination/outbound signature for ten minutes; a successful sniff removes the negative entry.

UDP domain discovery decrypts QUIC v1/v2 Initial packets, reassembles CRYPTO fragments, and parses the TLS ClientHello SNI. Per-flow sessions expire after five seconds, inspect at most eight Initial packets, and cap the CRYPTO stream at 64 KiB. When the first ClientHello is fragmented, the initializer retains up to eight FIFO followers for at most 250 ms. Failed-DCID caches bound repeated non-QUIC or undecryptable work.

`dial_mode: domain` applies a DNS reality check to a sniffed TCP or QUIC name. An exact answer for the destination family is accepted; an answer only in the other family is retained for dual-stack compatibility. A same-family mismatch, lookup failure, or timeout discards the sniffed name and continues by IP.

The sniffers feed the canonical initializer and may resolve a staged decision, but they do not own verdicts or a separate offload path.

`connection/` is the canonical per-flow route/sniff/mode/selection boundary. Socket UDP ingress and NFQUEUE-owned payloads both reserve the same `UdpInitLease` in the same `UdpEndpointPool`; NFQUEUE has no second router, dialer, cloned packet, replay, or deliberate retransmission path. A staged flow computes one final outbound and mark before its token-checked terminal transition.

`build_tuples_key` must initialize `TuplesKey` with `mem::zeroed()`. The `#[repr(C)]` key has 37 field bytes in a 40-byte layout, and the kernel hashes all 40 bytes, including its three padding bytes. Field-wise initialization can therefore create keys that userspace cannot look up or delete reliably.

An authoritative URLTest setup failure retains one retry round over its latency-ordered top three. A Score-owned failure can try one different permitted leaf sequentially, excluding the failed identity before ranking even if its ordinary score remains highest. Score attempts share one absolute deadline; request-local recovery preserves the pinned generation, Selector choices and actual primary final-edge provenance. Typed refusal, local admission-capacity exhaustion, cancellation and shutdown remain terminal, including completed refusals found while draining a race. Application writes and established relays are never replayed.

- `src/sniffing.rs` — **TCP only**: TLS SNI + HTTP Host (≤4096 bytes; buffered bytes returned for forwarding); `parse_client_hello_body` shared with the QUIC sniffer in `control/quic.rs`.

## UDP endpoint pipeline

### Destination provenance

`udp_ingress.rs` owns destination validation and bounded admission; `sockets.rs` owns syscall/cmsg decoding. Real transparent listeners require authoritative ORIGDST. Plain/mock listeners retain the following fallback rules; every path rejects invalid metadata before endpoint reservation:

1. A present, valid, specified ORIGDST cmsg is authoritative. An unspecified ORIGDST is invalid and cannot fall through to another source.
2. Without ORIGDST, an exact DNS query plus a specified `PKTINFO` destination forms `IP:53`.
3. Otherwise, only a non-wildcard listener bind can supply the destination.
4. Missing, malformed, duplicate, truncated, or unspecified metadata is dropped before slow-path reservation or payload retention.

UDP ingress captures the initializer epoch before any awaited validation. Raw UDP53 admission holds the `Config` read lock followed by the backend read lock; marked-direct admission first holds the Router read lock. It validates the committed routing generation and snapshots either the semantic group or the packet's immutable direct-mark table entry. Reservation and enqueue remain under the existing epoch gates. An incompatible ordinary/raw/group/direct-mark owner on the same tuple is rejected, not silently borrowed. Valid non-`must` DNS instead enters its separate query budgets. UDP53 never allocates ordinary conn-state or NFQUEUE decision tokens.

Reassembled [LAN DNS fragments](./nfqueue.md#fragmented-lan-dns) share this admission through NFQUEUE; work publication follows confirmed removal of the original queued packet.

Malformed controller-owned UDP53 retains compatible controller handoff facts for generic routing, but discards an incompatible terminal raw handoff together with its stale packet facts.

### Transport and transaction

Ordinary transports use `PacketTransport`; native handlers wrap a real socket
and tunnels frame packets directly. Source-shared VLESS XUDP/Mux.Cool instead
commits a typed source attachment whose endpoint views share one transport
receiver. The control plane creates no loopback bridge for either shape.

Endpoint creation is transactional:

1. Reserve `(client, original destination)` as `Initializing`; the lease owns the first datagram, queue permits, slow-path permit, token, generation, and cancellation epoch.
2. Route, sniff, select, and prepare eligible transports. Create the transparent anyfrom reply socket before publication.
3. Select one candidate and commit only its `PreparedUdpTransport<T>` or VLESS source preparation; the fallible commit returns the selected `Arc<T>`/attachment while dropped losers roll back.
4. Spawn the endpoint driver and wait for its ready barrier.
5. Atomically replace the exact `Initializing` identity with `Ready` under the shared epoch fence.
6. Transfer the retained first packet, send it through the committed transport, and wait for acknowledgement.
7. Send sniff-retained fragments and untouched queue followers in FIFO order, then run steady send and receive paths.

Transparent UDP preparation starts after routing and selection and ends only
when the selected transport's protocol-state commit completes. Authoritative
and cold URLTest paths share one absolute `max(10s, 4 × connect_timeout)`
deadline across resolution, physical-dial admission, control negotiation,
stagger/full-capacity waits, and commit. Expiry starts no later candidate and
drains every started preparation before returning. Sniffing/routing precede
this boundary; reply-socket creation, publication, and packet I/O follow under
their existing transaction and I/O bounds. There is no automatic packet replay.

For source-shared VLESS, `udp_endpoint/source.rs` indexes one owner by reused
runtime identity, normalized client, UDP path, and `ActualPeer` or
`RewriteTo(original destination)`. It owns one XUDP session, one receiver, and
multiple endpoint send views. The full `(client, destination)` endpoint map is
still canonical for routing, token, generation, and per-flow Score. Reply
classification never treats an occupied wrong-owner, `Initializing`, or
`Retiring` entry as foreign; only an absent `ActualPeer` key is eligible for
foreign delivery, without per-flow Score. Domain routes remain scoped to their
original destination. Late send/reply/removal callbacks revalidate owner,
token, generation, and endpoint identity before acting.
Source sharing does not merge kernel/NFQUEUE flow ownership: every canonical
endpoint keeps its own decision token, generation, terminal transition, and
five-tuple retirement fence.

Each transparent socket consumes at most eight datagrams per readiness turn with `recvmmsg`. Every slot retains independent ORIGDST, PKTINFO, and per-packet `SO_MARK` metadata, packets remain in kernel order, and malformed metadata drops only that slot. After a drained queue, the next wake starts with one slot; a full read immediately reopens the eight-slot batch, avoiding sparse-traffic setup cost. The cap bounds scheduler fairness and payload storage to 512 KiB per socket, or 4 MiB across the current four sockets per family when both families are active. The listener loop only validates, reserves, and enqueues; it never awaits `PacketTransport` I/O. The endpoint driver owns all transport calls. First and steady sends each have a five-second timeout. A timeout or error is ambiguous because the transport may have accepted part of the packet, so the driver never replays that datagram or advances to later followers.

SOCKS5 UDP keeps its TCP `UDP ASSOCIATE` control stream alive for the endpoint lifetime and treats control EOF or unexpected control data as endpoint failure. Its connected UDP socket sends to the physical server `BND.ADDR` relay, resolving a domain reply and replacing an unspecified address with the control peer IP. `PacketTransport::relay_addr()` and received source metadata expose the logical target instead, so endpoint first-reply validation does not confuse the SOCKS relay with the remote peer.

Replies use anyfrom sockets created inside `daens` and bound transparently to the packet's original destination. After transport peer validation, domain-target endpoints always reply from that original IP, port, and address family, even when remote DNS selects a different address. IP-target endpoints retain their original-destination socket and cache accepted alternate full-cone sources per endpoint. Port-53 replies additionally share a per-family transparent socket and choose the exact source IP with `IP_PKTINFO` or `IPV6_PKTINFO`. Replying from the TPROXY listener would use the internal `dae0` source and is not valid.

Reload advances a cancellation epoch before waiting. Initializers capture that epoch and an incarnation generation; a cancellation that linearizes before `commit_ready` prevents publication. Reload drains `Initializing` leases and their retained resources. A successful compiled traffic-plan change retires direct `Ready` endpoints only when the old or new policy includes direct marks, so later traffic cannot reuse their old socket marks. No-op/unrelated reloads and routing changes with no direct marks in either policy preserve them. Every retirement, including its `Retiring` tombstone and acknowledgement, names the token and generation, so delayed work cannot remove a replacement mapping. Explicitly userspace-owned WAN UDP decisions, including marked `direct(must)`, retire their token-zero conn state, handoff and redirect track together under the tuple/reader fence; native LAN direct/offloaded decisions and newer nonzero tokens survive.

A compatible same-name raw-group `Ready` session may persist across reload. This does not extend initializer lifetime: `Initializing` never survives reload, and stale queued route metadata still fails admission after a compiled-policy publication.

For NFQUEUE ingress, client/destination-keyed `PendingUdpVerdicts` carries only token, endpoint generation, phase, FIFO verdict guards, and final direct mark. Endpoint admission takes owned `Bytes` for the one retained NFQUEUE payload allocation. Direct/block completion removes the initializer as a kernel handoff; proxy completion transfers its token/generation into `Ready`. The [NFQUEUE protocol](./nfqueue.md#terminal-transitions) defines ordered terminal transitions, the absolute deadline, and fatal failure handling.

## Queue and descriptor budgets

Each UDP flow retains at most 64 datagrams including its first packet. All flows share an exact 8 MiB payload-permit budget. Admission obtains per-flow slots and global byte permits before copying; FIFO saturation drops the newest datagram. NFQUEUE has a separate ingest actor bounded to 256 entries and 8 MiB of queued payload.

At startup, `honk-core` tries to raise the soft `RLIMIT_NOFILE`, snapshots the
active value once, and caps the budgeting input at 1,048,576. VLESS carrier
capacity is carved out as `min(after_dials / 8, 8192)` before the remaining
descriptor budget determines UDP endpoint count. At the cap the fixed partition
is:

| Owner | Capacity | Descriptor accounting |
| --- | ---: | ---: |
| Fixed/runtime reserve | 256 | 256 |
| Accepted TCP flows | 16,384 | 6 each = 98,304 |
| Retained TCP pool | 2048 | 1 each = 2048 |
| Transient outbound dials | 1024 | 1 each = 1024 |
| VLESS physical carriers | 8192 | 1 each = 8192 |
| UDP endpoints | 8192 | 10 each = 81,920 |
| **Total** |  | **191,744** |

One UDP endpoint budgets a relay socket, a possible SOCKS5 control stream, and
all eight possible anyfrom reply sockets. One TCP flow budgets the accepted and
outbound sockets plus two two-FD splice pipes. Smaller limits use the same
saturating partition; a zero VLESS-carrier result stays zero.

The process VLESS-carrier semaphore is shared by traffic generations and DNS
runtime forks. A carrier holds its permit during actual I/O through provisional,
active, draining, and idle lifecycle states, releasing it only when its task
tears down. This process gate, not a sum of per-node pool limits, is the
authoritative physical-FD bound. Exhaustion is a typed local capacity rejection
and is neutral to node health and Score.

The remaining headroom is deliberately unassigned: a high `RLIMIT_NOFILE` is
not proof of equivalent memory or scheduler capacity. TCP starts with a
descriptor-derived floor capped at 16,384 flows and may borrow idle non-TCP
headroom while retaining half that budget as burst reserve, never exceeding
twice its floor. Existing flows are never cut, and the fixed reserve protects
control-plane descriptors.

Admission ceilings are distinct:

| Admission | Ceiling |
| --- | ---: |
| TCP flow permits | Descriptor-derived floor plus bounded borrowing of observed idle non-TCP headroom |
| VLESS physical carriers | Startup `min(after_dials / 8, 8192)` process gate |
| Cold non-DNS UDP slow path | `min(udp_endpoints, 256)` |
| Port-53 ingress slow path | `min(transient_dials, 256)` |
| NFQUEUE ingest actor | 256 entries and 8 MiB |

There is no separate 256-entry TCP slow-path ceiling. TCP accepts use the descriptor-derived flow budget. The endpoint-removal channel is bounded to 1024 messages and drains in batches of 128. If nonblocking delivery finds it full, a deduplicating `removal_dirty` set retains compensation; the worker flushes that set after each batch before acknowledging exact endpoint tombstones.

Transparent TCP waits for either IP-family listener to become readable before reserving a shared flow permit, then completes the accept with a nonblocking syscall. An idle listener therefore consumes no flow capacity, while connections that arrive at the limit remain in the kernel listen backlog. The `tcp` object in `/stats` exposes `activeFlows`, `limit`, and `capacity.rejected`; the latter counts accept-loop waits for a permit rather than drops after accept. Startup warns when the elastic ceiling is below 256; raise the service `RLIMIT_NOFILE` limit for gateway deployments.

## TCP relay and conn-state ownership

When both sides are plain `TcpStream`, `relay_splice` runs two concurrent `splice(2)` pumps. Each direction owns one nonblocking pipe of at most 64 KiB, so a full-duplex relay requests at most four pipe FDs and 128 KiB of pipe pages. EOF half-closes the opposite write side and lets the reverse direction drain.

The first splice in each direction is also a capability probe. `EINVAL`, `ENOSYS`, `EXDEV`, or policy denial (`EPERM`) before any byte has been staged permits a lossless userspace-copy fallback and sets a process-wide latch; later connections skip the probe. Pipe creation failure also happens before any byte moves, so only that connection copies and nothing is latched. Other errors, or an unsupported result after bytes have been staged, fail the relay rather than risk loss. Wrapped TLS or protocol streams use `relay_auto`, which always uses the select-based copy loop.

Unencrypted Vision TLS/REALITY carriers start in the copy loop. Once both directions are Direct and the connection has moved 256 KiB, the relay hands over where neither direction holds unwritten bytes: one direction at its read boundary, the other suspended in a read. It lends the carrier's TCP socket to the same bidirectional splice engine while still owning the Vision/TLS stack, and carrier pressure sampling continues on the lent socket. An unsupported probe or failed pipe creation moves no bytes, so the relay resumes the same Vision stream in the copy loop; each connection attempts the handover once. Both phases count into the connection counters, so statistics cover the whole connection and the first-response callback fires once.

The copy pumps flush bytes buffered by sniffing or protocol setup before reading
new input, and flush pending writes whenever input becomes idle. Each direction
starts with an 8 KiB buffer; the first read that fills it marks a bulk flow, and that direction then uses a 65,535-byte buffer, so saturated reads fit one maximum AnyTLS frame rather than fragmenting into 8 KiB writes or leaving a one-byte tail (only the first frame is small). Idle and chatty flows never grow, so a held connection costs 16 KiB of copy buffers instead of 128 KiB. Buffering never
requires the application to send another request or close before its current request leaves.

After the first EOF, both relay paths bound only idle drain time: `DRAIN_DEADLINE` is 30 seconds without a byte of progress. An active survivor may run longer than 30 seconds; a silent survivor cannot pin accepted sockets indefinitely.

A client that disappears without FIN or RST is bounded separately: the TPROXY TCP listeners enable TCP keepalive (3600 s idle, 15 s interval, 4 probes) and accepted sockets inherit it. A silent client ends its relay after about an hour; a live idle client answers the probes, so long idle connections stay open. Its error is a client-side `TimedOut`, which settles Score as cancellation.

An accepted TCP socket is adopted only if its canonical forward `CONN_STATE_MAP` entry still exists. `TcpFlowPins` reference-counts that directional tuple for every accepted owner. The BPF janitor skips pinned conn-state and matching redirect metadata. When the final owner retires, it reads the current entry and conditionally removes it only if the state and timestamp still match the observed incarnation; an older relay cannot delete a reused tuple.

After a real relay completes, the TCP owner settles its actual Score outcome and relay-error statistics once before propagating any retirement failure. Successful relay evidence is not changed to cancellation by failed retirement. TCP pool replenishment still requires both relay success and confirmed retirement; intentional cancellation retains its separate neutral path.

`splice.rs`: `relay_splice` uses bidirectional zero-copy `splice(2)` and half-close propagation between plain `TcpStream`s. First splice per direction probes capability: EINVAL/ENOSYS/EXDEV/EPERM before any bytes are staged ⇒ lossless copy fallback and process-wide latch; pipe creation failure ⇒ copy fallback without the latch. **Never restore unidirectional splice** (caused timeouts). `relay_auto` uses the same select-based copy loop for TLS/protocol-wrapped streams. `vision.rs` lends a Direct Vision carrier's socket to the same bidirectional engine. Both paths half-close the peer at first EOF and bound remaining drain by **idle** `DRAIN_DEADLINE`: 30s without byte progress, never cutting an active survivor. This prevents silent peers pinning tasks/sockets in CLOSE-WAIT. UDP uses `UdpEndpointPool`.

## Reload and runtime generations

SIGHUP uses an attempt-local diagnostic list. Load and operator-validation warnings are reported once on either outcome; a rejected attempt reports one redacted cause and never reaches runtime publication. Attempt reporting does not replace active runtime state or introduce a last-failed-attempt cache.

`apply_runtime_config` first builds the replacement router, group manager, outbound registry, DNS runtime, and routing plan without mutating live state. Commit ordering is:

1. Fence NFQUEUE readiness and wait for the kernel reader-epoch grace period.
2. Reject new transparent admission.
3. Cancel correlator cells and token-bound originals, advance the UDP initializer epoch, drain `Initializing` leases, wait for the correlator to become empty, and drain exact endpoint retirements.
4. Under the publication guards below, call `EbpfBackend::publish_routing_plan(&plan, learned_domains)` when the compiled plan or learned facts changed, or datapath health requires recovery. The backend stages the inactive slot's generation-owned facts and generated functions and switches `ROUTING_POLICY_ROOT` last. A native explicit activation then resets mode using the already-owned backend, before publishing the replacement registry, DNS pointer, router, config, groups and projection. A post-root mode-reset failure commits the new generation as degraded and leaves admission fenced.
5. Reopen pending admission and NFQUEUE last. Rule-derived feature bits live in the policy descriptor, not a separately published static-flags map.

`control/reload/transaction.rs` holds `reload_lock` around candidate preparation and commit. The changed-generation publication takes `router` → `config` → `datapath_flags.publication()` (native explicit source activation only) → `ebpf`, then the DNS projection-publication guard → `group_manager` → `outbound_id_map` → `active_routing_plan` → `runtime_registry`. The provider's DNS publication guard is prepared within those guards. Native no-op activation takes `config` → flags publication → `ebpf`, without a router replacement. `mode.rs` standalone mode/fence updates take the flags mutex → `ebpf`; `reset_for_activation` takes neither again and performs no await. NFQUEUE fence/reopen runs outside the router/config publication guards. This records existing lock edges, not permission to add new ones; changes remain subject to CONTRIBUTING §2/§11 and human review.

`RoutingPushPlan::compile` is the only userspace lowering path; there is no caller-selected slot or separate domain-publication handshake. The `routing_policy.rs` ABI is `RoutingInput` 128 bytes, `RoutingDecision` 24 bytes, and `RoutingPolicyDescriptor` 24 bytes. Real eBPF requires Linux 6.12+; generated process-name matching checks `pname_len` before fixed-offset reads for the 6.12 verifier. Loaded routing slots must expose the current output layout in BTF.

Pre-commit failures leave the active code and facts intact. After a fenced publication rejection, the controller restores group connectivity and reopens the old generation. A failed connectivity restoration keeps admission rejected. Once the root has switched, the new generation is committed; a subsequent NFQUEUE-reopen failure keeps that generation published but admission fenced until a later successful reload repairs it.

Candidate construction reuses the immutable userspace `Router` and compiled DNS router only when their routing inputs and content fingerprints are unchanged. Hosts and referenced geo assets are fingerprinted before parsing; changed content forces a replacement. Native routing publication is skipped only when the complete `RoutingPushPlan` and learned-domain projection bytes are unchanged; datapath health still forces recovery publication.

Compiled-routing publication has a [process-lifetime ceiling](./routing.md#synchronous-slots-and-atomic-publication), separate from DNS runtime generations. Publication can reject queued UDP53 and raw-`must` TCP53 metadata under the admission rules above; already admitted DNS queries retain their generation leases.

`DnsServiceProvider` is the coherent DNS-generation pointer. A request lease retains its generation's forwarder, projection, transport pools, and outbound runtime until retirement. The outbound registry is also generation-owned: unchanged node runtimes transfer only at the commit point, the old registry marks those runtimes as moved, and then begins graceful retirement. Existing streams and `Ready` UDP endpoints keep their references while old reusable pools stop accepting new work and drain.

Selector and UDP warm ownership stay generation-bound; see [warm-up ownership](./groups.md#warm-up-and-ownership).

`DrainTracker` is the process-wide accepted-flow gate. Reload and shutdown set reject-new before a drain and wait up to five seconds; shutdown then continues teardown with the remaining count.

- `src/mode.rs` — `DatapathFlagsHandle` serializes `ModeState` and `DATAPATH_FLAGS_MAP` updates under one async mutex. Initialize/mode/GLOBAL/static updates compose with NFQUEUE fence/reopen/disable so a concurrent API update cannot republish ready during reload. Fence completion follows READY=false publication, a kernel reader-epoch grace period, and removal of every undelivered Preparing/Pending state.

### Restart-required changes

The current process-scoped consumers reject a SIGHUP reload when any of these values changes:

| Area | Restart-required fields |
| --- | --- |
| Listener/datapath | `global.tproxy_port`, `global.tproxy_mark`, `global.tproxy_port_protect`, `global.pprof_port`, `global.so_mark_from_dae`, `global.lan_interface`, `global.wan_interface`, `global.auto_config_kernel_parameter` |
| Process state | `global.log_level`, `global.data_dir`, `global.store_subscribe` |
| DNS listener | Semantic `dns.bind` endpoint or transport change |
| Clash API | `experimental.clash_api.external_controller`, `external_ui`, `secret`, `default_mode`; effective `assets.ui.url` and `assets.ui.route` |
| Native API | Any `experimental.native_api` change; effective `assets.geodata.geosite`, `assets.geodata.geoip`, `assets.geodata.route` |
| Persistence | `experimental.cache_file.enabled`, `store_dns` |
| NFQUEUE | `global.nfqueue_enable` |
| Health probes and TLS | `global.check_interval`, the effective first `global.tcp_check_url`, `global.tcp_check_http_method` when HTTP probing is enabled, the selected `global.udp_check_dns` target, or a native TLS/uTLS mode change ([health-check reload semantics](../reference/global.md#reloading-health-checks-and-tls-mode)) |

The effective UI and geodata settings include the fallback from `assets.route`; changing that fallback requires restart when it changes either startup-owned download route. `assets.subscription` defaults and individual subscription options are handled by subscription reconciliation.

Semantic comparison of `dns.bind` uses the parsed bind endpoint when both old and new values parse, so spelling-only changes that describe the same endpoint do not force a restart.

`EbpfBackend`: token/state inspection, `commit_udp_decision(key, token, transition)`, token-checked abort/removal, kernel staging quiescence, rollback-compatible persistent allocator validation/status/reset, routing/map operations. The 12-byte pin stores full raw token in `next`: two-bit generation + 28-bit sequence; startup never rewrites it. Reset only after fencing/draining staging, with the candidate **and every higher generation through 3** absent from live conn-state/handoff/redirect/retirement-fence maps. This suffix must be empty because rolled-back legacy allocators advance monotonically from reset.

## Subscription orchestration

With `global.store_subscribe`, validated raw responses live in the fixed state db's `subscription_body` table (`<data_dir>/state/honk.db`), keyed by the request URL, configured user-agent override and ordered headers. Writes replace the complete body in one SQLite transaction, bounded to 8 MiB per body and 32 MiB total. Startup imports enabled bodies once from the first private legacy `.sub` directory found under `<data_dir>`, `/var/share/honk` or CWD; existing rows win, copied files and temporary files are removed, and unimported bodies remain for a later eligible start. Detailed migration and failure rules are in the [subscription reference](../reference/subscription.md#fetch-persistence-and-recovery).

Startup parses stored bodies before starting network refresh. A valid non-empty restore immediately supplies nodes and removes that subscription from the five-second first-fetch wait. Only direct subscriptions without a valid restore enter this shared grace; routed fetches wait for routing readiness, not for startup. Network refresh continues in the background afterward.

`ControlPlane::run` takes ownership of the control-command receiver on its first poll, before awaiting startup work. Returning or dropping that started future closes the channel even if listener startup fails, so subscription deliveries blocked on a full queue are released before the caller waits for supervisor shutdown.

On `SIGHUP`, subscription IDs are stabilized by fetch identity (URL + configured User-Agent + headers) and active subscription nodes are carried into the candidate config; SIGHUP does not restore cached bodies. Network, parse, or no-usable-node failures keep active nodes and do not replace the last valid body. A persistence failure is non-fatal: validated nodes may still be merged, while the previous stored body remains available. Periodic and immediate refreshes use the same serialized runtime-publication path, and subscription nodes are never written back to the config file.

Body acceptance and runtime publication are reported separately. A collection-admission rejection emits one redacted diagnostic and retains the active generation; it does not roll back an already stored body.

- `src/subscription.rs` owns fetching and parsing; `subscription/store.rs` owns SQLite raw-body persistence and the FD-relative legacy import. `subscription/supervisor.rs` keeps current authorization and deferred/refresh-eligible scheduling in one provider record; `supervisor/startup.rs` restores cached bodies and applies the direct-only shared five-second startup grace. Startup and steady-state share one supervisor state. In-flight work retains its captured revision and publication acknowledgement independently of replacement scheduling; pause/shutdown joins it, rather than reconciliation discarding a possibly committed reply.
- Daemon fetch/restore and `honk-tool sub` local files share body detection. Simple/Custom accept BOM, wrapped standard/URL-safe Base64, raw share links, Clash YAML/JSON, SIP008, sing-box JSON, Surge/Surfboard/Loon/Quantumult X records. `src/subscription/json.rs` and `records.rs` normalize foreign records; `clash.rs` constructs/validates typed nodes. Never import full-profile routing/DNS/groups. Native JSON preserves Unicode surrogate-pair names. Skip unsupported nodes, retain first usable duplicate identity, preserve active subscriptions on empty results. Imported Trojan/AnyTLS/QUIC require TLS, never silent plaintext.
  Clash and sing-box TCP ALPN normalize to the shared TLS model, not TUIC's QUIC field. Shared-builder skip warnings expose only a one-based proxy index and static rejection reason, never raw node records or credentials.

## Native observation API

The independent, opt-in `native-api` feature (build with `--features native-api` or `native-ui`; release builds include it) supplies a default-off listener; when enabled, it binds before control-plane admission. Its optional phase watch reports running only after the real admission-open result, and draining before shutdown fencing; the existing health handle can refine running to degraded. Reads hold the config publication barrier through generation and health observation without changing publication lock order. HTTP availability is not datapath health.

`native_api/server.rs` owns its listener, 64-connection JoinSet, one one-second sampler and native tracker consumer through joined shutdown. Header budget is five seconds; the 30-second read-idle deadline applies only while no request is in flight on that connection (from the end of a request body until its response resolves), and stalled writes have an independent 30-second deadline, so healthy SSE and slow handlers can outlive 30 seconds. Accept errors are logged and retried, backing off 100 ms on EMFILE/ENFILE/ENOBUFS/ENOMEM; a failed connection task is logged, never fatal to the server. Shutdown has one five-second HTTP connection grace budget, followed by the actual join of any admitted blocking credential job. `crate::observe` (`observe.rs` `Observation`, flows, rules, catalog identity, `DnsRecorder`) retains process identity and bounded engine-side stores independently of clients; `native_api` holds only the HTTP projection. Without `native-api` the observation hooks compile as zero-cost inert twins. Actual TCP/UDP/DNS producer hooks capture immutable source evidence; accepted publication emits generation events under existing barriers. Per-flow completeness describes the captured execution frontier, independently of lifecycle and global coverage. Native-only final handoffs still avoid legacy rule recomputation. Traffic/memory histories share the sampler, skip missed ticks and retain at most 600 points/600 seconds; unreadable RSS/cgroup fields remain null. Backend-owned datapath observations are partial, never full kernel transparency or kernel-memory accounting.

`native_api/handlers.rs` registers each resource's methods once; the shared security boundary still precedes method and resource validation. `observe/flows/record.rs` owns typed summaries, inputs and evidence steps; retention counts owned heap capacity, snapshots and the bounded kernel-dictionary reservation, and JSON projection stays at the wire boundary. Core lifecycle and mode commands return typed outcomes rather than HTTP errors or JSON.

`observe/flows/producer.rs` owns FlowGuard updates and generic selection evidence shared by TCP/UDP and DNS. DNS wire input models live with the other records; `observe/flows/dns.rs` retains only its lookup/catalog scopes and DNS-specific capture. `auth.rs` owns sessions, bounded admission and one tracked blocking job; its storage child publishes short-lived credential state without holding that state lock across KDF or SQL.

`control/connection/observation.rs` owns TCP/UDP evidence assembly from captured handoff, route, selection and transport facts. Connection orchestration does not construct wire records or re-evaluate current configuration for historical evidence; disabled recording avoids capture allocation, and exact connection closure remains independent of recording.

`observe/flows/dns.rs` and the outbound flow observer bind actual lookup, attempt and generation identities across scoped and retained work. Session attachment and logical-open/readiness retries remain distinct from new physical connections and protocol confirmation. Optional async scopes borrow caller-pinned operations rather than copying large future states; pins stay within the operation's ownership/drop boundary. Kernel evidence uses immutable compiled dictionaries and packet-bound witnesses; UDP receive priority uses native ancillary metadata or a receiver-owned fallback with exact syscall/batch alignment. Loss changes evidence, never routing or packet delivery.

TCP copy reads and successful splice writes increment the existing per-outbound atomics live; accepted sniff-prefix writes are counted once, including partial failures. Closing or cancelling a relay never adds its totals again. The same counters serve existing statistics and native sampling; UDP's per-packet accounting remains unchanged. Wire contract, limits and unknown fields: [API reference](../reference/api.md#native-api).

For a captured `.dae` startup, `configuration/accepted.rs` owns the accepted source snapshot and publication fences; `native_api/config.rs` supplies permission and HTTP projections. The native coordinator serializes source writes and API/SIGHUP loading before disk parsing, while `configuration::Activation` owns the common reload/reply/subscription-reconciliation sequence for both native and nonnative callers. The daemon, not HTTP, owns admitted work; the shared operation store also serves probes, provider refresh, group updates and lifecycle requests. Offline validation reads authorized local dependencies without network, filesystem mutation, workers or publication. Source PUT validates the overlay, rechecks disk hashes/dependencies, then replaces and syncs before 202. Restricted Group PATCH checks accepted revision before writing and again under the reload lock before activation. A racing publication can reject activation after replacement (`written:true,committed:false`); neither this nor post-rename sync failure rolls back files. No-op may accept comments without a new generation; committed-degraded retains the new generation while reporting failure. Native file settings/credentials still require local edits and restart.

`native_api/config/http.rs` owns the source HTTP adapters. Database recording stays with the coordinator through an awaited blocking promotion, including HTTP cancellation and shutdown; pending accepted sources are not falsely labeled as the old durable revision.

Main-source create/delete uses the same coordinator, parser spans, revision fence and reload reply, but waits for actual activation before returning 201/200. The subscription supervisor owns identity-bound initial deferrals, and all offline admission carries those exclusions plus the effective runtime data directory. Geodata work stages and validates all assets before FD-relative replacement; a transient immutable `SourceUpdate.geo_sources` feeds both reload paths and is dropped from accepted source metadata afterward. Retained Router/DnsRouter metadata describes actual loaded bytes; observation takes router before config and never rereads disk. Partial file replacement and committed degradation remain explicit, not rollback.

The staged writer returns the retained installed-file descriptor and its durability outcome. Geodata advances from pending staged files to installed guards without reopening files to reconstruct ownership; namespace, inode and content rechecks still fence external edits, and a visible but undurable replacement remains explicitly reported.

Activation execution returns one typed completion for separate operation, management and SIGHUP projections. Creation replies retain the committed resource representation before the coordinator accepts another mutation. Source metadata is prepared before the config writer and checked against its captured revision/generation at publication. Pre-rename dependency recapture binds each logical reader to its canonical target and bytes: ordered hosts/ECH references, subscription declaration positions and geodata kinds. It rediscovers source/glob and dependency selection without recompiling an unchanged admitted candidate; swapping two readers' targets is still a conflict.

Typed probes pin config/group/registry ownership, resolved addresses and measurement dimensions before network attempts, within fixed job/member/rate/deadline bounds. Provider status is supplied by the subscription supervisor, and refresh success waits for authorized runtime publication. Rule dictionaries and resolve-none simulations pin router/config/generation together; parser source spans provide editor locations with entry-relative display paths, which grant no filesystem authority. Native logs capture audited structured fields rather than formatted console/Clash text. Logs and native events resume with ready → replay → live. One settings owner validates a full merge before changing any recorder; accepted explicit activation resets overrides, whereas provider/network refresh preserves them.

Automatic diagnostic recording uses independent demands owned by `native_api/settings.rs`: a successful flow GET or explicit flow-event kind/`flow_id` enables flows; a logs stream enables logs; a successful DNS-log GET enables DNS logging. Ordinary events retain their own attachment but enable none of these three recorders. Admission failure and ordinary API/validation requests add no diagnostic demand. Each stream lease releases exactly the set it acquired; each recorder has its own 60-second last-demand grace, so unrelated reads/streams do not renew it. Configuration permission and explicit runtime On/Off remain authoritative, and explicit activation resets overrides while provider/network refresh preserves them.

The existing native sampler reconciles effective flow demand through `DatapathFlagsHandle`, which preserves mode/NFQUEUE bits and commits trace admission only after the backend write succeeds. It rechecks demand after waiting for backend ownership and reconciles once more after sampler shutdown; there is no new writer, timer or routing recompilation. The kernel uses one invocation-local flags snapshot for optional witness production, while retained captures and the actual routing decision remain independent of later demand changes.

Probe preparation consumes a captured plan into concrete-address attempts or explicit unavailable-family results. Its DNS-owned resolver retains the generation and canonical accepted-positive answer eligibility; a terminal packet refusal rejects the whole preparation even if a sibling family has an address. Health tickets are captured under the same publication guards as the probe configuration.

Native cold/warm HTTP probes share dial/TLS/ALPN and H1/H2 exchanges with URLTest. Native retains one outer deadline and no Score feedback; legacy callers retain per-phase budgets. Joined ephemeral cleanup returns a typed result: a private child panic fails the operation and future pause acknowledgement while retaining completed measurement evidence; intentional cancellation does not fabricate unhealthy samples.

### Runtime teardown

`control/lifecycle/teardown.rs` owns shared network cleanup with or without a listener epoch, including partial startup. Standalone DNS supervisors retain failures from already-reaped children and propagate them through joined teardown; intentional shutdown cancellation is neutral, but an owner panic fails teardown.

Network maintenance belongs to `RuntimeEpoch`. The cache delay writer is process-owned and is joined only at terminal shutdown.

Shutdown preserves the existing accepted-flow drain grace before joined teardown. Cleanup/fence ambiguity is fatal. Generic cleanup/join stages use the 10-second `STAGE_TIMEOUT`; timed-out joined async tasks are aborted and teardown reports failure. `control/cache.rs::StateTick` is an exception: after ten seconds it warns and continues joining the actual maintenance task, including its in-flight blocking SQLite write, without aborting it. A cancelled join leaves the handle with the owner for another wait; dropping the owner signals stop while the outer task retains its blocking write. Thus total shutdown is not strictly bounded to ten seconds. A panicking TCP connection task is logged and reaped; it does not stop the engine. Mock operation success does not establish real-kernel forwarding correctness.

The health-check owner also waits for its real drain, including health-owned blocking resolver jobs, after its five-second deadline, then returns the deadline error. A child failure observed during that late cleanup takes precedence over the deadline error.

When native is enabled, the engine and Clash share one transient mode/target/origin owner: startup and accepted explicit activation (including no-op) reset rule/settings; provider/network refresh preserves them. A backend mode-reset failure retains previous mode/source: before commit it rejects activation; after routing commit it reports committed-degraded and fences admission. Settings still reset at accepted commit. Global mode retains stable identity and fails closed if that target disappears. With native disabled, existing Clash cached/default mode behavior is unchanged. Native mode remains gated.

## Clash API and cache DB

The optional Clash-compatible axum server is a userspace view and mutation surface over shared engine handles; endpoint details are in the [API reference](../reference/api.md). Connection tracking starts when an API binds or any group enables `interrupt_connections`; exact transport closure also works without a dashboard. Selector writes serialize with accepted manager replacement, write both networks from Clash and display TCP. Runtime cache tables live in the fixed state db `<data_dir>/state/honk.db`; old `cache_file.path` and `cache_id` only select a one-time legacy `cache.db` import, not the live database location. On upgrade, omitting `cache_file.enabled` retains Selector choices and delay samples by default; `true` additionally enables mode/GLOBAL and, with `store_dns`, DNS answers, while `false` disables that cache persistence. Mode persists only with native disabled. The directory lock remains held for the lifetime of every owned SQLite connection, including the cache writer's connection through thread exit. See the [experimental reference](../reference/experimental.md).

- `src/stats.rs` — `StatsManager` owns the fixed allocation-free `GET /stats` UDP schema. `udp.nfqueue` includes listener/correlator counts, actor depth/queued bytes/oldest age, current queue depth, process-lifetime kernel drops accumulated across hard rebinds, explicit latest-read availability and cumulative read errors, held/peak guard gauges, effective receive-buffer size, terminal verdicts, token exhaustion/rotation, verdict errors, and `receiptToVerdict`. The latency is listener receipt-to-successful-verdict, not kernel queue residence. Top-level `warm.sessions` reports retained `anytls` and `vless` pool sessions plus per-protocol QUIC clients.
- `src/clash_api.rs` + `clash_api/{logs,doh,ui}.rs` — Clash REST/WS API and external UI. Missing/empty UI directories trigger background downloads; URL/detour precedence is in [Configuration](../configuration.md). `GET /stats` returns userspace, not eBPF `OUTBOUND_STATS`, including authenticated `/stats.score.groups[]` entries with `name`, TCP/UDP reason counters, `verification`, and `budget`. Mode/GLOBAL mutations use `DatapathFlagsHandle`, atomically composing reload fencing with latest mode/static bits; Selector mutations use the group manager. Score groups retain `type: "url_test"`, show the current aggregate TCP winner in `now`, and reject `PUT /proxies/{name}`. Never return score cells/private target data.
- Lazy connection metadata tracking starts on successful Clash API bind or any `interrupt_connections` group. API shutdown removes only its consumer; group-driven interruption continues.


## Related docs

- [Datapath design](./datapath.md)
- [Routing design](./routing.md)
- [NFQUEUE design](./nfqueue.md)
- [Outbound design](./outbound.md)
- [Group design](./groups.md)
