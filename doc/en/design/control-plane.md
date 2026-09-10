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
    - `routing_matcher.rs` — [atomic routing publication](./routing.md#atomic-routing-publication) and [kernel rule lowering](./routing.md#lpm-and-learned-domain-maps).
    - `quic.rs`, `packet_sniffer.rs`, `tcp_sniff.rs` — QUIC decryption/reassembly, per-flow sniff sessions, and TCP negative cache, respectively.
    - `udp_endpoint.rs` — `UdpEndpointPool`; [endpoint transactions](#udp-endpoint-pipeline).
    - `probers.rs` — `ProxyHttpProber`, `ProxyUdpProber`; [health probes](./groups.md#health-state-and-probes).
    - `janitor.rs` — `BpfJanitor`; [map maintenance](./datapath.md#userspace-maintenance-and-accounting).
    - `drain.rs` — `DrainTracker`; [accepted-flow drain](#reload-and-runtime-generations).

## Startup and shutdown

- `src/lib.rs` — `run()`, `Cli`/`ClashCommand`, resource limits, backend selection, fixed-queue startup preflight ([Configuration](../configuration.md)). Real instances hold `/run/honk-core.lock` and publish the `reload` PID. Via rtnetlink, create FD-owned `daens` and L2 netkit `dae0`; fall back to veth only on `EOPNOTSUPP`. Load/reuse the persistent allocator pin, then start NFQUEUE before datapath admission.

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

After forming the canonical tuple, userspace consumes `ROUTING_HANDOFF_MAP` with `routing_handoff_take`. A missing handoff, or an outbound of `ControlPlaneRouting`, falls back to `Router::route_with_must`. Final `must` and `block` results cannot be overridden by Clash mode.

## Sniffing and flow initialization

TCP sniffing reads at most 4096 bytes and extracts TLS SNI or HTTP `Host`. The returned buffer is part of the flow state and is written to the selected outbound before relay starts, so sniffing consumes no application bytes. TCP sniffing is skipped for `dial_mode: ip`, a final direct/block or `must` handoff, or a TCP negative-cache hit. Three consecutive failures suppress the same destination/outbound signature for ten minutes; a successful sniff removes the negative entry.

UDP domain discovery decrypts QUIC v1/v2 Initial packets, reassembles CRYPTO fragments, and parses the TLS ClientHello SNI. Per-flow sessions expire after five seconds, inspect at most eight Initial packets, and cap the CRYPTO stream at 64 KiB. When the first ClientHello is fragmented, the initializer retains up to eight FIFO followers for at most 250 ms. Failed-DCID caches bound repeated non-QUIC or undecryptable work.

`dial_mode: domain` applies a DNS reality check to a sniffed TCP or QUIC name. An exact answer for the destination family is accepted; an answer only in the other family is retained for dual-stack compatibility. A same-family mismatch, lookup failure, or timeout discards the sniffed name and continues by IP.

The sniffers feed the canonical initializer and may resolve a staged decision, but they do not own verdicts or a separate offload path.

`connection.rs` is the canonical per-flow route/sniff/mode/selection boundary. Socket UDP ingress and NFQUEUE-owned payloads both reserve the same `UdpInitLease` in the same `UdpEndpointPool`; NFQUEUE has no second router, dialer, cloned packet, replay, or deliberate retransmission path. A staged flow computes one final outbound and mark before its token-checked terminal transition.

`build_tuples_key` must initialize `TuplesKey` with `mem::zeroed()`. The `#[repr(C)]` key has 37 field bytes in a 40-byte layout, and the kernel hashes all 40 bytes, including its three padding bytes. Field-wise initialization can therefore create keys that userspace cannot look up or delete reliably.

An authoritative single-candidate TCP failure is retried exactly once, only if re-resolution offers a useful alternative. URLTest races latency-ordered top-3 `urltest_retry_candidates`; Score records failure, re-ranks the exact target, and retries only a different replacement. Never retry other policies or true single-leaf outcomes.

- `src/sniffing.rs` — **TCP only**: TLS SNI + HTTP Host (≤4096 bytes; buffered bytes returned for forwarding); `parse_client_hello_body` shared with the QUIC sniffer in `control/quic.rs`.

## UDP endpoint pipeline

### Destination provenance

UDP admission is fail-closed and runs before endpoint reservation:

1. A present, valid, specified ORIGDST cmsg is authoritative. An unspecified ORIGDST is invalid and cannot fall through to another source.
2. Without ORIGDST, an exact DNS query plus a specified `PKTINFO` destination forms `IP:53`.
3. Otherwise, only a non-wildcard listener bind can supply the destination.
4. Missing, malformed, duplicate, truncated, or unspecified metadata is dropped before slow-path reservation or payload retention.

### Transport and transaction

`PacketTransport` is the only production UDP interface. Native UDP handlers wrap a real socket; tunnel handlers implement framing directly and expose `relay_addr()`, `send_packet`, `send_packet_confirmed`, and `recv_packet`. The control plane does not create a loopback socket bridge for framed transports.

Endpoint creation is transactional:

1. Reserve `(client, original destination)` as `Initializing`; the lease owns the first datagram, queue permits, slow-path permit, token, generation, and cancellation epoch.
2. Route, sniff, select, and finalize one eligible transport. Create the transparent anyfrom reply socket before publication.
3. Spawn the endpoint driver and wait for its ready barrier.
4. Atomically replace the exact `Initializing` identity with `Ready` under the shared epoch fence.
5. Transfer the retained first packet, send it with `send_packet_confirmed`, and wait for its acknowledgement.
6. Send sniff-retained fragments and untouched queue followers in FIFO order, then run steady send and receive paths.

Each transparent socket consumes at most eight datagrams per readiness turn with `recvmmsg`. Every slot retains independent ORIGDST and PKTINFO metadata, packets remain in kernel order, and malformed metadata drops only that slot. After a drained queue, the next wake starts with one slot; a full read immediately reopens the eight-slot batch, avoiding sparse-traffic setup cost. The cap bounds scheduler fairness and payload storage to 512 KiB per socket, or 4 MiB across the current four sockets per family when both families are active. The listener loop only validates, reserves, and enqueues; it never awaits `PacketTransport` I/O. The endpoint driver owns all transport calls. First and steady sends each have a five-second timeout. A timeout or error is ambiguous because the transport may have accepted part of the packet, so the driver never replays that datagram or advances to later followers.

SOCKS5 UDP keeps its TCP `UDP ASSOCIATE` control stream alive for the endpoint lifetime and treats control EOF or unexpected control data as endpoint failure. Its connected UDP socket sends to the physical server `BND.ADDR` relay, resolving a domain reply and replacing an unspecified address with the control peer IP. `PacketTransport::relay_addr()` and received source metadata expose the logical target instead, so endpoint first-reply validation does not confuse the SOCKS relay with the remote peer.

Replies use anyfrom sockets created inside `daens` and bound transparently to the packet's original destination. After transport peer validation, domain-target endpoints always reply from that original IP, port, and address family, even when remote DNS selects a different address. IP-target endpoints retain their original-destination socket and cache accepted alternate full-cone sources per endpoint. Port-53 replies additionally share a per-family transparent socket and choose the exact source IP with `IP_PKTINFO` or `IPV6_PKTINFO`. Replying from the TPROXY listener would use the internal `dae0` source and is not valid.

Reload advances a cancellation epoch before waiting. Initializers capture that epoch and an incarnation generation; a cancellation that linearizes before `commit_ready` prevents publication. Reload drains `Initializing` leases and their retained resources but preserves `Ready` endpoints. Every retirement, including its `Retiring` tombstone and acknowledgement, names the token and generation, so delayed work cannot remove a replacement mapping.

For NFQUEUE ingress, client/destination-keyed `PendingUdpVerdicts` carries only token, endpoint generation, phase, FIFO verdict guards, and final direct mark. Endpoint admission takes owned `Bytes` for the one retained NFQUEUE payload allocation. Direct/block completion removes the initializer as a kernel handoff; proxy completion transfers its token/generation into `Ready`. The [NFQUEUE protocol](./nfqueue.md#terminal-transitions) defines ordered terminal transitions, the absolute deadline, and fatal failure handling.

## Queue and descriptor budgets

Each UDP flow retains at most 64 datagrams including its first packet. All flows share an exact 8 MiB payload-permit budget. Admission obtains per-flow slots and global byte permits before copying; FIFO saturation drops the newest datagram. NFQUEUE has a separate ingest actor bounded to 256 entries and 8 MiB of queued payload.

At startup, `honk-core` tries to raise the soft `RLIMIT_NOFILE`, snapshots the active value once, and caps the budgeting input at 1,048,576. At that cap the fixed partition is:

| Owner | Capacity | Descriptor accounting |
| --- | ---: | ---: |
| Fixed/runtime reserve | 256 | 256 |
| Accepted TCP flows | 16,384 | 6 each = 98,304 |
| Retained TCP pool | 2048 | 1 each = 2048 |
| Transient outbound dials | 1024 | 1 each = 1024 |
| UDP endpoints | 8192 | 3 each = 24,576 |
| **Total** |  | **126,208** |
The remaining descriptor headroom is deliberately unassigned: a high `RLIMIT_NOFILE` is not treated as proof of equivalent memory or scheduler capacity. TCP starts with a descriptor-derived fixed partition capped at 16,384 flows and elastically borrows idle non-TCP descriptor headroom while retaining half of the non-TCP budget as burst reserve. At the 1,048,576 cap that raises the current target to 18,688 when the reserved non-TCP owners are idle; a 4,096-descriptor service scales from 160 to 320. Existing flows are never cut, and a fixed reserve protects control-plane descriptors.

A TCP flow budgets the accepted socket, outbound socket, and two two-FD splice pipes. A UDP endpoint budgets the worst common ownership shape: relay socket, SOCKS5 control stream, and anyfrom reply socket. Smaller `RLIMIT_NOFILE` values scale the same partition with saturating arithmetic.

Admission ceilings are distinct:

| Admission | Ceiling |
| --- | ---: |
| TCP flow permits | Descriptor-derived floor; 16,384 at the 1,048,576 cap, reaching 18,688 from idle reserved headroom |
| Cold non-DNS UDP slow path | `min(udp_endpoints, 256)` |
| Port-53 ingress slow path | `min(transient_dials, 256)` |
| NFQUEUE ingest actor | 256 entries and 8 MiB |

There is no separate 256-entry TCP slow-path ceiling. TCP accepts use the descriptor-derived flow budget. The endpoint-removal channel is bounded to 1024 messages and drains in batches of 128. If nonblocking delivery finds it full, a deduplicating `removal_dirty` set retains compensation; the worker flushes that set after each batch before acknowledging exact endpoint tombstones.

Transparent TCP waits for either IP-family listener to become readable before reserving a shared flow permit, then completes the accept with a nonblocking syscall. An idle listener therefore consumes no flow capacity, while connections that arrive at the limit remain in the kernel listen backlog. The `tcp` object in `/stats` exposes `activeFlows`, `limit`, and `capacity.rejected`; the latter counts accept-loop waits for a permit rather than drops after accept. Startup warns when the elastic ceiling is below 256; raise the service `RLIMIT_NOFILE` limit for gateway deployments.

## TCP relay and conn-state ownership

When both sides are plain `TcpStream`, `relay_splice` runs two concurrent `splice(2)` pumps. Each direction owns one nonblocking pipe of at most 64 KiB, so a full-duplex relay requests at most four pipe FDs and 128 KiB of pipe pages. EOF half-closes the opposite write side and lets the reverse direction drain.

The first splice in each direction is also a capability probe. `EINVAL`, `ENOSYS`, or `EXDEV` before any byte has reached a destination permits a lossless userspace-copy fallback and sets a process-wide latch; later connections skip the probe. Other errors, or an unsupported result after bytes have been staged, fail the relay rather than risk loss. Wrapped TLS or protocol streams use `relay_auto`, which always uses the select-based copy loop.

After the first EOF, both relay paths bound only idle drain time: `DRAIN_DEADLINE` is 30 seconds without a byte of progress. An active survivor may run longer than 30 seconds; a silent survivor cannot pin accepted sockets indefinitely.

An accepted TCP socket is adopted only if its canonical forward `CONN_STATE_MAP` entry still exists. `TcpFlowPins` reference-counts that directional tuple for every accepted owner. The BPF janitor skips pinned conn-state and matching redirect metadata. When the final owner retires, it reads the current entry and conditionally removes it only if the state and timestamp still match the observed incarnation; an older relay cannot delete a reused tuple.

`splice.rs`: `relay_splice` uses bidirectional zero-copy `splice(2)` and half-close propagation between plain `TcpStream`s. First splice per direction probes capability: EINVAL/ENOSYS/EXDEV before any bytes ⇒ lossless copy fallback and process-wide latch. **Never restore unidirectional splice** (caused timeouts). `relay_auto` uses the same select-based copy loop for TLS/protocol-wrapped streams. Both paths half-close the peer at first EOF and bound remaining drain by **idle** `DRAIN_DEADLINE`: 30s without byte progress, never cutting an active survivor. This prevents silent peers pinning tasks/sockets in CLOSE-WAIT. UDP uses `UdpEndpointPool`.

## Reload and runtime generations

`apply_runtime_config` first builds the replacement router, group manager, outbound registry, DNS runtime, and routing plan without mutating live state. Commit ordering is:

1. Fence NFQUEUE readiness and wait for the kernel reader-epoch grace period.
2. Reject new transparent admission.
3. Cancel correlator cells and token-bound originals, advance the UDP initializer epoch, drain `Initializing` leases, wait for the correlator to become empty, and drain exact endpoint retirements.
4. Compile the generation's `RoutingPushPlan`, then call `EbpfBackend::publish_routing_plan(&plan, learned_domains)` once. The backend chooses the inactive slot, stages all generation-owned IP/source/MAC/domain fact maps with full 256-bit predicate values, attaches the generated function to every relevant target, and switches `ROUTING_POLICY_ROOT` last. Only after that succeeds does userspace publish the outbound registry, DNS runtime pointer, router, config, groups, and projection snapshot under the same serialization boundary.
5. Reopen pending admission and NFQUEUE last. Rule-derived feature bits live in the policy descriptor, not a separately published static-flags map.

`RoutingPushPlan::compile` is the only userspace lowering path; there is no caller-selected slot or separate domain-publication handshake. The stable `routing_policy.rs` ABI remains `RoutingInput` 128 bytes, `RoutingDecision` 20 bytes, and `RoutingPolicyDescriptor` 24 bytes. Real eBPF requires Linux 6.12+; generated process-name writes check fixed offsets before pointer construction for the 6.12 verifier.

Pre-commit failures leave the active code and facts intact. After a fenced publication rejection, the controller restores group connectivity and reopens the old generation. A failed connectivity restoration keeps admission rejected. Once the root has switched, the new generation is committed; a subsequent NFQUEUE-reopen failure keeps that generation published but admission fenced until a later successful reload repairs it.

Candidate construction reuses the immutable userspace `Router` and compiled DNS router only when their routing inputs and content fingerprints are unchanged. Hosts and referenced geo assets are fingerprinted before parsing; changed content forces a replacement. Native routing publication is skipped only when the complete `RoutingPushPlan` and learned-domain projection bytes are unchanged; datapath health still forces recovery publication.

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

Semantic comparison of `dns.bind` uses the parsed bind endpoint when both old and new values parse, so spelling-only changes that describe the same endpoint do not force a restart.

`EbpfBackend`: token/state inspection, `commit_udp_decision(key, token, transition)`, token-checked abort/removal, kernel staging quiescence, rollback-compatible persistent allocator validation/status/reset, routing/map operations. The 12-byte pin stores full raw token in `next`: two-bit generation + 28-bit sequence; startup never rewrites it. Reset only after fencing/draining staging, with the candidate **and every higher generation through 3** absent from live conn-state/handoff/redirect/retirement-fence maps. This suffix must be empty because rolled-back legacy allocators advance monotonically from reset.

## Subscription orchestration

When `global.store_subscribe` is enabled, validated raw bodies are stored under `<global.data_dir>/.sub`. During the data-directory cutover, if the configured store is absent, an existing `/var/share/honk/.sub` and then an existing `./.sub` remain usable; honk never moves or deletes them automatically. The directory is a non-symlink directory with mode `0700`; files use mode `0600` and URL-safe SHA-256 names derived from the request URL, the configured user-agent override (unset or empty contributes an empty component), and headers. Requests identify as `honk/<version>` unless a subscription override is configured. Writes use a new temporary file, `sync_all`, atomic rename, and directory sync.

Startup parses stored bodies before starting network refresh. A valid non-empty restore immediately supplies nodes and removes that subscription from the five-second first-fetch wait; missing, invalid, or empty stores wait only within that shared grace. All fetches continue in the background afterward.

On `SIGHUP`, subscription IDs are stabilized by fetch identity (URL + configured User-Agent + headers) and active subscription nodes are carried into the candidate config. Cache restore runs only for an enabled subscription whose active node set is empty, then an immediate network refresh is scheduled. Network, parse, or no-usable-node failures keep active nodes and do not replace the last valid body. A persistence failure is non-fatal: validated nodes may still be merged, while the previous stored body remains available. Periodic and immediate refreshes use the same serialized runtime-publication path, and subscription nodes are never written back to the config file.

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
