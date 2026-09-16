# Userspace control plane

This document describes the `honk-core` userspace engine between the kernel datapath and the outbound stack.

## Scope

The control plane owns transparent ingress, kernel handoff consumption, userspace routing, sniffing, outbound selection, relay, resource admission, and runtime publication. The kernel mechanisms that deliver flows are covered in [Datapath design](./datapath.md). Group policy and health-driven selection are covered in [Group design](./groups.md), and DNS runtime behavior is covered in [DNS design](./dns.md).

The main implementation is `crates/honk-core/src/control/`. It consumes `EbpfBackend` state and hands TCP streams or the `PacketTransport` UDP contract to `honk-outbound`.

Module map:

- `src/control/`:
    - `mod.rs` — `ControlPlane` [startup and shutdown](#startup-and-shutdown).
    - `connection.rs` — canonical [flow initializer](#sniffing-and-flow-initialization).
    - `nfqueue.rs` — `PendingUdpVerdicts` correlator; [held-packet protocol](./nfqueue.md).
    - `sockets.rs` — [transparent ingress](#transparent-ingress), anyfrom replies, and `udp_fast_path`.
    - `dns_control.rs` — `DnsController`; [query admission and projection](./dns.md#resolution-pipeline).
    - `dns_listener.rs` — `DnsListener`; [standalone ingress lifecycle](./dns.md#ingress-paths).
    - `reload.rs` — `apply_runtime_config`; [runtime publication](#reload-and-runtime-generations).
    - `routing_matcher.rs` — [atomic routing publication](./routing.md#synchronous-slots-and-atomic-publication) and [kernel rule lowering](./routing.md#restricted-native-backend).
    - `quic.rs`, `packet_sniffer.rs`, `tcp_sniff.rs` — QUIC decryption/reassembly, per-flow sniff sessions, and TCP negative cache, respectively.
    - `udp_endpoint.rs` — `UdpEndpointPool`; [endpoint transactions](#udp-endpoint-pipeline).
    - `probers.rs` — `ProxyHttpProber`, `ProxyUdpProber`; [health probes](./groups.md#health-state-and-probes).
    - `janitor.rs` — `BpfJanitor`; [map maintenance](./datapath.md#userspace-maintenance-and-accounting).
    - `drain.rs` — `DrainTracker`; [accepted-flow drain](#reload-and-runtime-generations).

## Startup and shutdown

- `src/lib.rs` — `run()`, `Cli`/`ClashCommand`, resource limits, backend selection, fixed-queue startup preflight ([Configuration](../configuration.md)). Real instances hold `/run/honk-core.lock` and publish the `reload` PID. Via rtnetlink, create FD-owned `daens` and L2 netkit `dae0`; fall back to veth only on `EOPNOTSUPP`. Load/reuse the persistent allocator pin, then start NFQUEUE before datapath admission.

Configuration diagnostics are collected before tracing setup. An early load or operator-validation failure writes prior nonterminal diagnostics to stderr once, then lets the binary return the redacted terminal cause once. Successful loading defers diagnostics to the configured tracing subscriber. Later runtime fatal errors retain their existing log-file mirror.

Startup keeps kernel admission closed until userspace can receive every redirected flow:

1. Load and validate the configuration, select `global.data_dir`, raise `RLIMIT_NOFILE`, and take one immutable descriptor-budget snapshot.
2. Restore persisted subscriptions before network refresh. Only subscriptions without a valid restored body participate in the five-second first-fetch grace period.
3. Select the backend. Real mode takes `/run/honk-core.lock` and publishes the process PID in the locked file; `honk-core reload` reads that PID and sends `SIGHUP`. Mock mode does not take the process-global lock.
4. After the real-instance lock handoff, probe the fixed NFQUEUE queue prerequisites. Mock/no-`ebpf` mode or a failed preflight logs a warning and disables NFQUEUE for this process; the preflight does not reject the reserved nftables table because installation reclaims stale owned state.
5. In real mode, create the FD-owned `daens` namespace and the `dae0`/`dae0peer` link through rtnetlink. The engine tries an L2 netkit pair first and falls back to veth only when the kernel reports netkit unsupported. The process stays in the host namespace; only synchronous socket, link, and attachment operations enter `daens` through scoped `setns` calls.
6. Load the BPF object and attach the real datapath. The default object is embedded with `include_bytes!`; `--bpf-object` supplies a runtime override. With the `ebpf` feature, `build.rs` locates the object, rejects stale or BTF-less output, rebuilds it with nightly after removing inherited `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS`, verifies `.BTF`, and copies it into `OUT_DIR` for embedding.
7. Reuse or create the pinned `UDP_DECISION_SEQUENCE` allocator and validate its map ABI, BTF, locked value, token range, and exhaustion state. NFQUEUE startup rechecks the locked allocator status and leaves staging fenced if no rollback-safe generation is available.
8. Build the userspace router, outbound runtime registry, DNS runtime, group manager, cache DB, optional Clash API, and control-plane supervisors.
9. Bind the transparent TCP/UDP listeners, publish the complete listener FD set, start the standalone DNS and UDP receive loops, then start the NFQUEUE service and its ingest actor, correlator, watchdog, and independent one-second queue-pressure sampler when the effective flag remains enabled.
10. Check NFQUEUE health, publish its ready state, open pending verdict admission, and set `DATAPATH_STATE_MAP[0]` ready last. The TCP accept loop then runs in the control-plane supervisor.

`RealEbpfBackend` owns aya programs, maps, links, persistent allocator handling, and real NFQUEUE integration. `MockEbpfBackend` provides the same control-plane interface without privileged kernel resources. A requested NFQUEUE path that cannot pass the post-lock fixed-queue preflight is disabled with a warning; failures after the service is admitted remain fatal.

Shutdown reverses ownership before resources disappear: fence NFQUEUE, close datapath admission, reject new userspace work, cancel and drain held verdicts and UDP initializers, stop UDP drivers and removal processing, stop the interface watcher, detach BPF hooks, drain accepted flows for up to five seconds, retire the outbound runtime, stop NFQUEUE, stop the DNS controller and persistence, and clean up generation-owned BPF state. Ordinary cleanup preserves the pinned allocator. Listener and `daens`/link-pair ownership then falls out of scope.

## Transparent ingress

Real TCP and UDP listeners are created inside `daens` with transparent socket options and `DAE_BYPASS_MARK` (`0x100`). The mark lets the datapath recognize honk's own listeners rather than treating them as ordinary local services. Accepted TCP sockets inherit the mark, so each accept loop clears it before handling the flow. Mock listeners are ordinary host-namespace sockets without privileged transparent options.

Original destinations are recovered as follows:

| Ingress | Primary source | Fallback |
| --- | --- | --- |
| TCP/IPv4 | `SO_ORIGINAL_DST` | Transparent socket `local_addr()` |
| TCP/IPv6 | `IP6T_SO_ORIGINAL_DST` | Transparent socket `local_addr()` |
| UDP | `IP_RECVORIGDSTADDR` / IPv6 original-destination cmsg | Guarded provenance rules described below |

For ordinary flows, userspace forms the canonical tuple and consumes `ROUTING_HANDOFF_MAP` with `routing_handoff_take`. A missing handoff, or an outbound of `ControlPlaneRouting`, falls back to `Router::route_with_must`. Final `must` and `block` results cannot be overridden by Clash mode. This fallback is not the transparent DNS ownership boundary.

Port-53 controller versus raw-transport ownership follows the [ordered traffic-rule contract](../reference/routing.md#outbound-targets-and-must), including the malformed non-`must` UDP fallback.

Real transparent UDP53 requires valid per-packet `SO_RCVMARK` / `SOL_SOCKET` `SO_MARK` provenance and the current committed routing generation for both controller and raw ownership; a tuple handoff cannot substitute. Transparent TCP53 requires a SYN handoff. Only raw-`must` TCP additionally requires the current routing generation and pins the config, semantic group, and outbound runtime before raw I/O; non-`must` TCP retains controller query admission without that generation check. Missing required metadata or a failed required generation check rejects admission before I/O. Physical compatibility belongs to the [handoff ABI and UDP carrier](./datapath.md#map-inventory).

## Sniffing and flow initialization

TCP sniffing reads at most 4096 bytes and extracts TLS SNI or HTTP `Host`. The returned buffer is part of the flow state and is written to the selected outbound before relay starts, so sniffing consumes no application bytes. TCP sniffing is skipped for `dial_mode: ip`, a final direct/block or `must` handoff, or a TCP negative-cache hit. Three consecutive failures suppress the same destination/outbound signature for ten minutes; a successful sniff removes the negative entry.

UDP domain discovery decrypts QUIC v1/v2 Initial packets, reassembles CRYPTO fragments, and parses the TLS ClientHello SNI. Per-flow sessions expire after five seconds, inspect at most eight Initial packets, and cap the CRYPTO stream at 64 KiB. When the first ClientHello is fragmented, the initializer retains up to eight FIFO followers for at most 250 ms. Failed-DCID caches bound repeated non-QUIC or undecryptable work.

`dial_mode: domain` applies a DNS reality check to a sniffed TCP or QUIC name. An exact answer for the destination family is accepted; an answer only in the other family is retained for dual-stack compatibility. A same-family mismatch, lookup failure, or timeout discards the sniffed name and continues by IP.

The sniffers feed the canonical initializer and may resolve a staged decision, but they do not own verdicts or a separate offload path.

`connection/` is the canonical per-flow route/sniff/mode/selection boundary. Socket UDP ingress and NFQUEUE-owned payloads both reserve the same `UdpInitLease` in the same `UdpEndpointPool`; NFQUEUE has no second router, dialer, cloned packet, replay, or deliberate retransmission path. A staged flow computes one final outbound and mark before its token-checked terminal transition.

`build_tuples_key` must initialize `TuplesKey` with `mem::zeroed()`. The `#[repr(C)]` key has 37 field bytes in a 40-byte layout, and the kernel hashes all 40 bytes, including its three padding bytes. Field-wise initialization can therefore create keys that userspace cannot look up or delete reliably.

An authoritative single-candidate TCP transport failure is retried exactly once, only if re-resolution offers a useful alternative. URLTest races the latency-ordered top three from the target-aware retry plan; Score records failure, re-ranks the exact target, and retries only a different replacement. Local typed refusals remain terminal, including already-completed refusals discovered while draining a race. Never retry other policies or true single-leaf outcomes.

- `src/sniffing.rs` — **TCP only**: TLS SNI + HTTP Host (≤4096 bytes; buffered bytes returned for forwarding); `parse_client_hello_body` shared with the QUIC sniffer in `control/quic.rs`.

## UDP endpoint pipeline

### Destination provenance

`udp_ingress.rs` owns destination validation and bounded admission; `sockets.rs` owns syscall/cmsg decoding. Real transparent listeners require authoritative ORIGDST. Plain/mock listeners retain the following fallback rules; every path rejects invalid metadata before endpoint reservation:

1. A present, valid, specified ORIGDST cmsg is authoritative. An unspecified ORIGDST is invalid and cannot fall through to another source.
2. Without ORIGDST, an exact DNS query plus a specified `PKTINFO` destination forms `IP:53`.
3. Otherwise, only a non-wildcard listener bind can supply the destination.
4. Missing, malformed, duplicate, truncated, or unspecified metadata is dropped before slow-path reservation or payload retention.

UDP ingress captures the initializer epoch before any awaited validation. Raw UDP53 admission then holds the `Config` read lock followed by the backend read lock to validate the committed routing generation and pin the semantic group. Reservation and enqueue remain under the existing epoch gates. An incompatible ordinary/raw/group owner on the same tuple is rejected, not silently borrowed. Valid non-`must` DNS instead enters its separate query budgets. UDP53 never allocates ordinary conn-state or NFQUEUE decision tokens.

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

Each transparent socket consumes at most eight datagrams per readiness turn with `recvmmsg`. Every slot retains independent ORIGDST and PKTINFO metadata, packets remain in kernel order, and malformed metadata drops only that slot. After a drained queue, the next wake starts with one slot; a full read immediately reopens the eight-slot batch, avoiding sparse-traffic setup cost. The cap bounds scheduler fairness and payload storage to 512 KiB per socket, or 4 MiB across the current four sockets per family when both families are active. The listener loop only validates, reserves, and enqueues; it never awaits `PacketTransport` I/O. The endpoint driver owns all transport calls. First and steady sends each have a five-second timeout. A timeout or error is ambiguous because the transport may have accepted part of the packet, so the driver never replays that datagram or advances to later followers.

SOCKS5 UDP keeps its TCP `UDP ASSOCIATE` control stream alive for the endpoint lifetime and treats control EOF or unexpected control data as endpoint failure. Its connected UDP socket sends to the physical server `BND.ADDR` relay, resolving a domain reply and replacing an unspecified address with the control peer IP. `PacketTransport::relay_addr()` and received source metadata expose the logical target instead, so endpoint first-reply validation does not confuse the SOCKS relay with the remote peer.

Replies use anyfrom sockets created inside `daens` and bound transparently to the packet's original destination. After transport peer validation, domain-target endpoints always reply from that original IP, port, and address family, even when remote DNS selects a different address. IP-target endpoints retain their original-destination socket and cache accepted alternate full-cone sources per endpoint. Port-53 replies additionally share a per-family transparent socket and choose the exact source IP with `IP_PKTINFO` or `IPV6_PKTINFO`. Replying from the TPROXY listener would use the internal `dae0` source and is not valid.

Reload advances a cancellation epoch before waiting. Initializers capture that epoch and an incarnation generation; a cancellation that linearizes before `commit_ready` prevents publication. Reload drains `Initializing` leases and their retained resources but preserves `Ready` endpoints. Every retirement, including its `Retiring` tombstone and acknowledgement, names the token and generation, so delayed work cannot remove a replacement mapping.

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

The first splice in each direction is also a capability probe. `EINVAL`, `ENOSYS`, or `EXDEV` before any byte has reached a destination permits a lossless userspace-copy fallback and sets a process-wide latch; later connections skip the probe. Other errors, or an unsupported result after bytes have been staged, fail the relay rather than risk loss. Wrapped TLS or protocol streams use `relay_auto`, which always uses the select-based copy loop.

The copy pumps flush bytes buffered by sniffing or protocol setup before reading
new input, and flush pending writes whenever input becomes idle. Each direction
uses a 65,535-byte buffer, so saturated reads fit one maximum AnyTLS frame rather
than fragmenting into 8 KiB writes or leaving a one-byte tail. Buffering never
requires the application to send another request or close before its current request leaves.

After the first EOF, both relay paths bound only idle drain time: `DRAIN_DEADLINE` is 30 seconds without a byte of progress. An active survivor may run longer than 30 seconds; a silent survivor cannot pin accepted sockets indefinitely.

An accepted TCP socket is adopted only if its canonical forward `CONN_STATE_MAP` entry still exists. `TcpFlowPins` reference-counts that directional tuple for every accepted owner. The BPF janitor skips pinned conn-state and matching redirect metadata. When the final owner retires, it reads the current entry and conditionally removes it only if the state and timestamp still match the observed incarnation; an older relay cannot delete a reused tuple.

`splice.rs`: `relay_splice` uses bidirectional zero-copy `splice(2)` and half-close propagation between plain `TcpStream`s. First splice per direction probes capability: EINVAL/ENOSYS/EXDEV before any bytes ⇒ lossless copy fallback and process-wide latch. **Never restore unidirectional splice** (caused timeouts). `relay_auto` uses the same select-based copy loop for TLS/protocol-wrapped streams. Both paths half-close the peer at first EOF and bound remaining drain by **idle** `DRAIN_DEADLINE`: 30s without byte progress, never cutting an active survivor. This prevents silent peers pinning tasks/sockets in CLOSE-WAIT. UDP uses `UdpEndpointPool`.

## Reload and runtime generations

SIGHUP uses an attempt-local diagnostic list. Load and operator-validation warnings are reported once on either outcome; a rejected attempt reports one redacted cause and never reaches runtime publication. Attempt reporting does not replace active runtime state or introduce a last-failed-attempt cache.

`apply_runtime_config` first builds the replacement router, group manager, outbound registry, DNS runtime, and routing plan without mutating live state. Commit ordering is:

1. Fence NFQUEUE readiness and wait for the kernel reader-epoch grace period.
2. Reject new transparent admission.
3. Cancel correlator cells and token-bound originals, advance the UDP initializer epoch, drain `Initializing` leases, wait for the correlator to become empty, and drain exact endpoint retirements.
4. Compile the generation's `RoutingPushPlan`, then call `EbpfBackend::publish_routing_plan(&plan, learned_domains)` once. The backend chooses the inactive slot, stages all generation-owned IP/source/MAC/domain fact maps with full 256-bit predicate values, attaches the generated function to every relevant target, and switches `ROUTING_POLICY_ROOT` last. Only after that succeeds does userspace publish the outbound registry, DNS runtime pointer, router, config, groups, and projection snapshot under the same serialization boundary.
5. Reopen pending admission and NFQUEUE last. Rule-derived feature bits live in the policy descriptor, not a separately published static-flags map.

`RoutingPushPlan::compile` is the only userspace lowering path; there is no caller-selected slot or separate domain-publication handshake. The stable `routing_policy.rs` ABI remains `RoutingInput` 128 bytes, `RoutingDecision` 20 bytes, and `RoutingPolicyDescriptor` 24 bytes. Real eBPF requires Linux 6.12+; generated process-name writes check fixed offsets before pointer construction for the 6.12 verifier.

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
| Clash API | `experimental.clash_api.external_controller`, `external_ui`, `external_ui_download_url`, `external_ui_download_detour`, `secret`, `default_mode` |
| Persistence | Any `experimental.cache_file` change |
| NFQUEUE | `global.nfqueue_enable` |
| Health probes and TLS | `global.check_interval`, the effective first `global.tcp_check_url`, `global.tcp_check_http_method` when HTTP probing is enabled, the selected `global.udp_check_dns` target, or a native TLS/uTLS mode change ([health-check reload semantics](../reference/global.md#reloading-health-checks-and-tls-mode)) |

Semantic comparison of `dns.bind` uses the parsed bind endpoint when both old and new values parse, so spelling-only changes that describe the same endpoint do not force a restart.

`EbpfBackend`: token/state inspection, `commit_udp_decision(key, token, transition)`, token-checked abort/removal, kernel staging quiescence, rollback-compatible persistent allocator validation/status/reset, routing/map operations. The 12-byte pin stores full raw token in `next`: two-bit generation + 28-bit sequence; startup never rewrites it. Reset only after fencing/draining staging, with the candidate **and every higher generation through 3** absent from live conn-state/handoff/redirect/retirement-fence maps. This suffix must be empty because rolled-back legacy allocators advance monotonically from reset.

## Subscription orchestration

When `global.store_subscribe` is enabled, validated raw bodies are stored under `<global.data_dir>/.sub`. During the data-directory cutover, if the configured store is absent, an existing `/var/share/honk/.sub` and then an existing `./.sub` remain usable; honk never moves or deletes them automatically. The directory is a non-symlink directory with mode `0700`; files use mode `0600` and URL-safe SHA-256 names derived from the request URL, the configured user-agent override (unset or empty contributes an empty component), and headers. Requests identify as `honk/<version>` unless a subscription override is configured. Writes use a new temporary file, `sync_all`, atomic rename, and directory sync.

Startup parses stored bodies before starting network refresh. A valid non-empty restore immediately supplies nodes and removes that subscription from the five-second first-fetch wait; missing, invalid, or empty stores wait only within that shared grace. All fetches continue in the background afterward.

`ControlPlane::run` takes ownership of the control-command receiver on its first poll, before awaiting startup work. Returning or dropping that started future closes the channel even if listener startup fails, so subscription deliveries blocked on a full queue are released before the caller waits for supervisor shutdown.

On `SIGHUP`, subscription IDs are stabilized by fetch identity (URL + configured User-Agent + headers) and active subscription nodes are carried into the candidate config. Cache restore runs only for an enabled subscription whose active node set is empty, then an immediate network refresh is scheduled. Network, parse, or no-usable-node failures keep active nodes and do not replace the last valid body. A persistence failure is non-fatal: validated nodes may still be merged, while the previous stored body remains available. Periodic and immediate refreshes use the same serialized runtime-publication path, and subscription nodes are never written back to the config file.

Body acceptance and runtime publication are reported separately. A collection-admission rejection emits one redacted diagnostic and retains the active generation; it does not roll back an already stored body.

- `src/subscription.rs` — fetch/parse and atomic raw-body persistence: `<global.data_dir>/.sub` mode `0700`, hash-named files `0600`; existing `/var/share/honk/.sub`, then `./.sub` are legacy fallbacks. Never move/delete automatically or write subscription nodes into config. `src/subscription/supervisor.rs` owns revision-authorized startup/immediate/periodic workers; reconcile/shutdown joins replaced workers. Startup/reload in `src/lib.rs` restores valid bodies before network refresh, skips restored subscriptions' five-second first-fetch wait, and reconciles workers only after SIGHUP commit. Fetch/parse/write failure preserves active nodes and the last valid body.
- Daemon fetch/restore and `honk-tool sub` local files share body detection. Simple/Custom accept BOM, wrapped standard/URL-safe Base64, raw share links, Clash YAML/JSON, SIP008, sing-box JSON, Surge/Surfboard/Loon/Quantumult X records. `src/subscription/json.rs` and `records.rs` normalize foreign records; `clash.rs` constructs/validates typed nodes. Never import full-profile routing/DNS/groups. Native JSON preserves Unicode surrogate-pair names. Skip unsupported nodes, retain first usable duplicate identity, preserve active subscriptions on empty results. Imported Trojan/AnyTLS/QUIC require TLS, never silent plaintext.
  Clash and sing-box TCP ALPN normalize to the shared TLS model, not TUIC's QUIC field. Shared-builder skip warnings expose only a one-based proxy index and static rejection reason, never raw node records or credentials.

## Clash API and cache DB

The optional Clash-compatible axum server is a userspace view and mutation surface over the current config, group manager, mode/flags handle, connection tracker, DNS service, statistics, and outbound runtime pointer; endpoint details are in the [API reference](../reference/api.md). Connection metadata is enabled when the API binds successfully or when any configured group uses `interrupt_connections`, so selection-change interruption works without the API. The optional SQLite `cachedb` is opened before datapath admission and persists Selector choices, Clash mode, and optionally DNS answers. Relative paths prefer an existing `global.data_dir` file, then `/var/share/honk`, then an existing config-relative file; missing databases are created below `global.data_dir`. Configuration and persistence semantics are in the [experimental reference](../reference/experimental.md).

- `src/stats.rs` — `StatsManager` owns the fixed allocation-free `GET /stats` UDP schema. `udp.nfqueue` includes listener/correlator counts, actor depth/queued bytes/oldest age, current queue depth, process-lifetime kernel drops accumulated across hard rebinds, explicit latest-read availability and cumulative read errors, held/peak guard gauges, effective receive-buffer size, terminal verdicts, token exhaustion/rotation, verdict errors, and `receiptToVerdict`. The latency is listener receipt-to-successful-verdict, not kernel queue residence. Top-level `warm.sessions` reports retained `anytls` and `vless` pool sessions plus per-protocol QUIC clients.
- `src/clash_api.rs` + `clash_api/{logs,doh,ui}.rs` — Clash REST/WS API and external UI. Missing/empty UI directories trigger background downloads; URL/detour precedence is in [Configuration](../configuration.md). `GET /stats` returns userspace, not eBPF `OUTBOUND_STATS`, including authenticated `/stats.score.groups[]` aggregate reason counters only. Mode/GLOBAL mutations use `DatapathFlagsHandle`, atomically composing reload fencing with latest mode/static bits; Selector mutations use the group manager. Score groups retain `type: "url_test"`, show the current aggregate TCP winner in `now`, and reject `PUT /proxies/{name}`. Never return score cells/private target data.
- Lazy connection metadata tracking starts on successful Clash API bind or any `interrupt_connections` group. API shutdown removes only its consumer; group-driven interruption continues.


## Related docs

- [Datapath design](./datapath.md)
- [Routing design](./routing.md)
- [NFQUEUE design](./nfqueue.md)
- [Outbound design](./outbound.md)
- [Group design](./groups.md)
