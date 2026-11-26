# Linux capture datapaths

Linux capture delivers traffic to the shared userspace policy and outbound path. [Control plane](./control-plane.md) describes that path; [NFQUEUE](./nfqueue.md) describes TC held-first-packet UDP.

## Linux TUN Endpoint

`backend: tun; direct: endpoint` selects the daemon-owned Linux TUN path. The
[global reference](../reference/global.md#linux-tun-endpoint) gives the full syntax,
required resource values, validation and exact five RPDB rules. TUN is a real FD
consumer of the existing scoped Stack, canonical Router, DNS projector and
outbound flow initializers. It creates no TC hooks, NFQUEUE, `dae0` or `daens`.
Only `host_facts: true` requires the `ebpf` feature. It rejects `--mock-ebpf`.

A single `TunDevice` owns `/dev/net/tun`, opened `O_RDWR|O_NONBLOCK|O_CLOEXEC`.
`TUNSETIFF` requests `IFF_TUN|IFF_NO_PI|IFF_VNET_HDR|IFF_TUN_EXCL`;
`TUNGETIFF` verifies TUN/NO_PI/VNET_HDR and rejects multi-queue, persistence,
NAPI and unexpected flags. The creation-only EXCL bit is not required in readback.
Setup sets and reads back a 10-byte little-endian vnet header, then enables only
`TUN_F_CSUM|TUN_F_TSO4|TUN_F_TSO6`; unsupported setup refuses explicitly.
There is one reader/writer, no duplicate/inherited FD, persistent device,
external-FD input or pre-existing-link adoption. UFO, USO and TSO ECN are not enabled.

### Setup and readiness

1. Complete static/runtime admission, take the real instance lock and initialize
   the required exact bypass mark M. `prepare_dns_bind(&Config)` resolves and
   retains the enabled bind endpoint's actual `SocketAddr` candidates; disabled
   listening returns `None`. Fund runtime/RX storage and the plain non-HOST
   `PacketScope`; true additionally funds a separate Host scope and source owner,
   all under the same 384 MiB budget before capture activation.
2. Verify the required mark on actual TCP/UDP sockets, subscribe to rtnetlink and
   snapshot. Refuse occupied name/table/all five priorities and unsupported
   RPDB/main/default topology. Create the private setup receipt and persist the
   create intent before the exclusive TUN ioctl. Record
   actual netns cookie, ifindex and attachment incarnation immediately; set MTU,
   explicit addresses, owned-link sysctls and UP, recording ACK/readback.
   After the UP ACK, wait for the exact owned link, permanent host addresses and
   local host routes before installing any guard or rule. IPv6 NODAD still queues
   local-route work; only its absent `/128` route may wait on notifications, within
   one two-second deadline covering every readback. Conflicting or foreign
   topology and malformed observations fail immediately, before diversion.
3. Write each mutation intent ahead of installing capture-prefix blackholes
   (static, metric 32760) and the five rules. Do not install unicast capture yet:
   selected prefixes are contained while Endpoint startup is incomplete.
4. Pass the funded scopes and original owners to the driven packet supervisor,
   with retained prepared DNS candidates and explicit plain standalone DNS scope.
   Service every driver during readiness and failed-startup cleanup. DNS bind,
   software flags and subscription authorizations must be ready. Bind the true-mode
   source owner to the actual FD and attachment before capture becomes active.
5. Read back link/address/rules, install and read back metric-1024 capture
   routes, then establish the final `Topology::admit_tun` subscription and full
   snapshot while retaining the old watch. Only after successful final admission
   open the shared gate, call `capture_ready()`, and report `TUN datapath ready`,
   lifecycle Running and sd_notify READY. Close cannot lose this readiness race.

The receipt at `<data_dir>/state/tun-<netns_cookie>-<instance_nonce>.json` is
create-new, mode 0600 and nonsymlink. It journals full source SHA, PID/starttime,
actual namespace/link/attachment identity and exact address/route/rule keys with
Intent/Acknowledged/Removed states, persisting and fsyncing each transition.
Only confirmed instance-owned objects can be removed. Ambiguity retains the
receipt and object; a receipt never authorizes adoption or automatic recovery.

Active capture routes use metric 1024 in both families, while static blackhole
guards retain metric 32760. Linux normalizes IPv6 metric 0, and IPv4 route delete
with metric 0 is a wildcard; choosing 1024 is a deliberate representation
adjustment from the initial metric-0 design. Exclusive create, readback and exact
delete all include table, family, prefix, output interface and metric, preventing
active-route removal from selecting its guard.

The operator keeps main/WAN/LAN routes, source addresses, forwarding, NAT and
firewall stable. Enabled families need a valid non-TUN main uplink and source;
main/default must not refer to TUN through unicast, multipath, nexthop, VRF or lwt
paths. Additional early/local rules, VRF/l3mdev and unknown selectors/actions are
refused rather than approximated. Route/address/link/rule changes, ENOBUFS,
interrupted/unknown dumps or replaced ifindex cause sticky invalidation and close
capture. Subscription is not an atomic fence against arbitrary concurrent root
route writes, and retained guards are not a whole-host firewall kill switch.

### FD packet pipeline

Kernel egress appears on FD read; FD write injects a **new interface-ingress
packet**, never the original skb. Plain records follow the existing plain scope;
with `host_facts: true`, the exact read's authenticated application-socket facts
select the Host scope, while witnessed unattributed records remain plain. Source
failures never become plain records. Both paths use decoded vnet metadata, the
canonical initializer/Router, real outbound and generated output lease on the same
FD. Direct makes a new dial; neither scope/tuple/mark nor generated replies grant
original-operation or pre-NAT/TTL equivalence.

RX uses one funded 65,586-byte buffer (10 vnet + 65,575 ordinary IPv6 + 1 sentinel)
and one ingress timestamp per turn. A full-buffer read is rejected as possibly
truncated; exact IP extent and vnet flags/type/family/header/checksum bounds must
validate before the combined metadata/source/admission path. TCPv4/TCPv6 GSO enters
as one contiguous run; normal UDP partial checksums work without USO. IPv4 headers,
ICMP and completed reassembly still verify checksums; Endpoint/WireGuard trust rules
are unchanged. Borrowed UDP is accepted/copied through funded ingress before the
next read. The source callback checks the live reverse consumer for this scope and
attachment; it never writes the FD, blocks or re-enters the scope mutex.

TX funds 65,535-byte CPU frames separately from logical MTU; MSS/PMTU and ordinary
UDP MTU behavior do not increase. Every output includes a 10-byte vnet header,
including plain ACK/UDP/control records. One writev submits that header and the
immutable lease bytes; the kernel segments TSO and completes partial checksums.

The owner services every driver before and after bounded RX. RX is limited to 32
syscall attempts/packets, 1 MiB or 1 ms per turn. TX rotates scope/class groups,
retaining pending leases and sharing one bounded syscall/byte/time output turn.
EINTR counts; limits are scheduler bounds, not preemptible syscall deadlines.

| TUN write result | Ownership |
| --- | --- |
| Full vnet+IP record length | Kernel accepted this one record; release the lease outside the scope lock. This is neither remote delivery nor TCP ACK. |
| EAGAIN/EWOULDBLOCK | Retain the same lease, metadata, bytes, scope and original FlowId at its class head; register writable and retry that record. |
| EINTR | Retain the same lease, metadata and bytes; retry/yield within the finite syscall budget. |
| Zero or short write | Fatal packet-boundary violation; never write a suffix or replay the whole packet. Preserve the reported partial outcome and dispose local ownership explicitly. |
| Other error | Fatal owner I/O failure; no backend fallback or replay through another executor. An ambiguous submission stays ambiguous. |

Readiness is cleared only after EAGAIN. Idle waits register readable, writable
only for blocked pending output, topology/driver/close/supervisor wakers and the
earliest real driver deadline, then recheck. No flow/deadline/pending work means
no periodic dataplane timer; TUN has no XSK CQ/FILL fallback. No scope/config/Router
or projection lock crosses an await.

### Stop and failure custody

Normal operator stop first closes admission, removes metric-1024 capture routes so
prefixes hit guards, and stops FD RX while retaining setup/watcher/FD/driver.
`endpoints.close()` closes protocol admission before DNS/command admission stops.
No new protocol output is sent: pending/closing leases are explicitly disposed
outside locks while driver service and `owner.poll_join_plane` continue until
TCP/UDP initializers, sources/receivers, retirement, DNS and original scope owners
actually join. `shutdown_wait_connections` supplies no natural-completion grace.

After the supervisor returns its real `(ControlPlane, result)`, close the only FD,
drain the source owner while its required resources remain live, confirm owned-link
disappearance, and remove only receipt-backed objects still
proven to belong to this instance. Once business cleanup succeeds, remove P+4
first, then guards/table and bypass/return rules, and finally the receipt. This
explicit stop restores ordinary main routing. Software policy cleanup and the
existing API/subscription shutdown follow.

Runtime failure, crash or unconfirmed cleanup retains blackholes/rules and the
receipt and returns an error. Stop sources and inspect exact ownership before
operator cleanup; do not restart by deleting a name/table blindly. Drop only
closes local admission/endpoints, disposes local leases, returns driving rights
and closes the FD; it performs no rtnetlink cleanup or successful-cleanup ack.
The original supervisor retains joined cleanup on its original Tokio runtime,
which an embedder must keep alive. There is no automatic FD reopen, resource
adoption or TC/XDP fallback.

## Full-XDP startup

The default remains TC when `datapath` is absent. Full-XDP is an explicit daemon backend, not the XSK fixture or a TC/NFQUEUE/TUN fallback:

```dae
global {
    dial_mode: ip
    nfqueue_enable: false
    so_mark_from_dae: 0x100
}
datapath {
    backend: xdp
    direct: core
    interface {
        dut0: lan
        dut1: wan
    }
}
routing {
    fallback: direct
}
```

Use `direct: endpoint` to terminate Direct TCP/UDP through the existing packet Endpoint and outbound relay; `direct: core` preserves transit through the Core forwarding owner and input-context kernel FIB. `lan`/`wan` (`Lan`/`Wan` in the model) describe physical interface roles, not execution profiles. XDP selection requires `backend: xdp` and an explicit Direct profile; invalid admission is rejected before kernel attachment. Do not combine this selection with the TC `global.lan_interface`/`wan_interface` settings. All RX queues of every selected physical interface are opened, with one ring owner per queue and one routing-domain owner across ports/queues. Backend, profile and device changes require restart; firewall/NAT policy uses transactional generation publication, retaining the previous policy on rejected updates.

Each Port reserves `R * 1024` bytes for retained RX slots, where `R = min(rx_frames, ring_size)`. These share the 384 MiB `CAPTURE_MEMORY` budget with UMEM and other capture resources (see `honk-xsk/src/port.rs::RetainedRxSlots::{layout,new}` and `honk-core/src/xdp.rs::prepare`).

Borrowed RX does not consume a retained slot. It validates and leases the whole packet before the callback, and publishes the RX consumer and replenishes FILL at batch end. A malformed suffix commits only the admitted prefix. If the callback unwinds, the Port closes without publishing that batch or recycling the interrupted packet; a later receive call cannot undo that decision. TX owner slots return to the free list only after the packet's final descriptor completes, even if an earlier frame has already been reused.

For Endpoint, startup checks every installed default route in every table, including multipath and nexthop objects, and refuses any possible output through a captured port or its descendants. The operator must maintain this condition: route changes are not monitored at runtime. Captured Ethernet and bond interfaces may have addresses. Core has its own input-context FIB requirements. Physical ingress has no authenticated process identity; without Host capture, router-originated connections stay in the kernel.

Endpoint's local-address set includes all valid namespace addresses, including deprecated but valid IPv6 addresses. Classifiable TCP/UDP to a local address passes to the kernel except port 53, which still evaluates policy. Later fragments use the first-fragment verdict; a later fragment arriving first is dropped. This matters for unconnected UDP and replies with options, extensions or fragments; configure an ordered static `direct(must)` rule when a local DNS listener should receive port 53 traffic.

TUN uses a separate watcher: unrelated link/address/route/rule changes trigger dependency rechecks without closing TUN, while changes to its owned link, addresses, routes or rules and malformed or lost notifications remain fatal.

Endpoint reply identities use a shared 4096-entry table keyed by logical scope and
source IP. Reclamation considers only entries no longer retained by protocol state,
TIME_WAIT, initializer/source receivers, DNS work or queued/exported output. A live
owner's identity cannot be replaced by a conflicting MAC/VLAN claim; an unknown RST
cannot learn or poison a peer. Quiescent conflicts retain their 60-second hold even
under table pressure. Full tables of retained owners reject new peers rather than
stealing a reply path. Complete VLAN TCI is captured with exported output, including
TX-credit waits. Firewall/NAT predicates requiring unavailable original MAC/process
provenance are rejected before capture admission.

Every captured logical realm must have MTU at least 1280, including Core profiles
that may hand traffic to Endpoint; incompatible realms reject before attachment.
Captured ingress uses one of two contracts selected before attachment. A physical
device with verified RX VLAN stripping disabled and no recovered-tag requirement
uses wire-only decoding: ingress device/queue authority comes from its owned XSK,
and inline L2 facts come from the received bytes; no metadata prefix is read or
fabricated. The metadata-required path keeps the 32-byte v2 producer record and
uses the real device-bound `bpf_xdp_metadata_rx_vlan_tag` kfunc, resolved through
kernel BTF. Veth requires this path because local RX-off flags do not constrain
its peer's TX tag insertion. One recovered tag plus inline tags may total at most
two; missing/malformed metadata never triggers a fallback to wire-only mode.
Minimum-frame padding permits four additional bytes per **inline** VLAN tag.

Device facts and the topology subscription are revalidated before readiness.
Generic `data_meta` capability is not advertised: a required metadata-adjustment
failure drops the frame and is counted separately from captures; the runtime
samples that counter at most once per second and fails capture closed when it
observes a failure, without claiming a hard one-second bound or arbitrary-driver
preflight proof. Device-bound programs require real-ingress verification, not
`BPF_PROG_TEST_RUN`.

L2 group addresses cannot grant unicast IP a native socket exemption. Existing
native ARP/ND and IP special-address handling remains; directed broadcasts come
from at most 64 exact local-table `RTN_BROADCAST` routes, never suffix guesses.

Physical capture defaults to forced ZeroCopy; `xsk_mode: copy` requests Copy and `xsk_mode: auto` selects per member using advertised capabilities and required segments. Auto does not retry Copy after a selected ZeroCopy bind fails. Every bind is read back; mode changes require restart. Host has no AF_XDP queue.

Read-only startup admission collects up to 256 issues, reporting omitted counts and `NOT_CHECKED` for checks whose prerequisites failed. It checks capture layout, queues, device capabilities, foreign XDP, topology, memory, and, for Endpoint, zone-0 CT and uplink prerequisites. Only after admission does it prepare VLAN features, load programs, create FD-owned links and bind queues; supervisor readiness and topology validation precede activation. Failure unwinds previously created links, including failure on a later queue. Physical Endpoint/Core links and programs are not pinned; foreign XDP is refused. Process exit or SIGKILL closes link FDs and restores kernel forwarding, although existing proxy sessions may need to reconnect. Host egress has its own FD-owned TCX binding.

The physical coordinator drains RTNL notifications on readiness. A Core turn that can send cached traffic from RX queue zero still performs the full check before consuming that input. On a quiet link the coordinator schedules an identity read of each owned link FD after one second, independently of Core policy readers. This check detects a lost or replaced attachment; it does not query other XDP modes or take a fresh topology snapshot. Each live RTNL watcher charges its own 64 KiB receive buffer, including the overlap during final startup admission.

When Linux marks a topology dump with `NLM_F_DUMP_INTR`, honk discards the partial snapshot and restarts the full read on a fresh dump socket in the same network namespace. XDP and TUN topology reads allow up to eight attempts within one two-second deadline. If all attempts are interrupted, admission fails closed. Invalid topology and lost watch notifications retain their existing failure handling.

On stop, honk freezes physical workers and withdraws the XSK map entries. From entry to capture close, policy withdrawal, physical TX completion and the second worker's acknowledgement share one 100 ms wait budget. Only TX with outstanding descriptors may request a wakeup. Timeout or device error still triggers a detach attempt and fails shutdown; neither is a completion. After detach, physical queues only reap real CQ entries. The budget does not bound an in-flight syscall or wall-clock time from SIGTERM to kernel forwarding.

With no VLAN upper, honk disables the two RX VLAN stripping features it changes and restores them on normal stop or startup failure. SIGKILL leaves them off; the kernel handles VLAN in software. An identity-loss failure abandons restoration because the device may have been replaced. Veth still requires VLAN metadata.

Local non-53 traffic goes to the kernel before the hold lookup; local port 53 still follows policy. Endpoint hold takes precedence over zone-0 conntrack. For a DNS-native pending hold, confirmed CT takes over; without CT, a repeated SYN or complete UDP datagram must qualify again. The pending hold alone cannot authorize delivery. Without a hold or CT match, TCP reaches D1 only on a pure SYN; a non-SYN miss goes to the kernel. A true UDP first fragment cannot acquire or renew DNS-native ownership. Non-TCP/UDP normally passes; ICMP errors inspect the quoted flow. Unclassifiable transport headers drop. A later fragment follows a cached first-fragment verdict for up to 30 seconds; if no verdict is available it drops. See [gateway DNS routing](../reference/global.md#xdp-endpoint-dns-projection).

Only zone 0 is supported. Startup refuses nonzero or unprovable nft and legacy zones. Unsafe runtime nft zone state or a CT lookup contract error remains fatal. A periodic legacy raw-table scan can disable DNS-derived forwarding but does not establish full runtime legacy zone admission. Stop honk before changing legacy zones and restart afterward.

An admitted 802.3ad bond is one logical realm, with XDP on its physical Ethernet or veth members; other bond modes and unsupported hash policies are refused. A peer can move between members of that realm; already exported output keeps its original member. Multi-member realms use CPU output rather than generated output, a performance cost; a single-member bond may use generated output. Realm workers are limited by the smallest member queue count. Captured identity changes, a new bond member, ENOBUFS or `Desynchronized` are fatal; carrier, LACP state, statistics and unrelated device changes are ignored. Address updates refresh the local set; the published map remains until successful resynchronization, and failure is fatal. Interrupted FIB dumps are retried within three synchronization rounds.

Kernel map/program memory is charged alongside UMEM to the shared 384 MiB capture budget; reload temporarily charges old and new generations. See [reload limitations](./control-plane.md#reload-and-runtime-generations).

A configured [auxiliary L3 LAN](../reference/global.md#auxiliary-l3-lan) enters this policy at TCX ingress without a MAC fact. Native decisions continue the kernel chain; Endpoint redirects go to the binding's exclusive, unnumbered TUN. The TCX program uses its own per-CPU scratch and skb conntrack lookup. It bounds header reads by both the declared IP extent and the linear skb extent, pulling only missing header bytes. ICMP errors with a known Endpoint owner reach the Stack for quote validation; an unresolved transport quote does not create an owner.

The shared-runtime TUN task owns the reads, writes and packet driver; it does not service a physical AF_XDP queue. Both directions check the binding's device pair, so a reused numeric ifindex is not permission to redirect. A device-owned terminal drop on the private TUN remains effective if its FD-owned return program disappears first. Replacement unregisters the old TUN and retires that binding's packet work and DNS permissions before admitting a new one. A successful `writev` is not evidence that the old kernel backlog was empty. Reload replaces physical and active auxiliary links in order, with reverse-order rollback; Linux does not change all links at a single packet boundary.

SG/multi-buffer capability advertisement and successful binding are not runtime
proof of jumbo traffic. The manual veth smoke exercises MTU 1500 and 9000 in Copy
mode: each UDP reply must arrive as one complete datagram, and the jumbo cases
also require complete, unfragmented IP packets larger than 4096 bytes in both
directions at the client interface. Physical-NIC zero-copy, jumbo performance
and DMA release still need their own evidence.

Endpoint output is generated directly into one reserved UMEM frame only for eligible single-member realms whose checked `14 + 4 * vlan_count + logical_mtu.max(1280)` fits `FRAME_SIZE`. Multi-member and jumbo/ineligible realms retain CPU output and whole-chain SG, even for control packets. Application UDP first packets/fragments, unfragmented and zero-length datagrams and controller DNS replies remain funded CPU output; older CPU prefixes cannot be bypassed by later direct fragments.

`Port::transmit_generated(class, max_length, generate)` reserves actual single-frame/ring/sidecar capacity before invoking its synchronous generator; scope credit is also reserved before Stack emission. Private guards cancel unpublished reservations on no output, error or panic. Original FlowId retention is installed under the scope mutex, then exact peer/header completion runs unlocked without await or RX service. Only the actual length, padded with zeroes to the Ethernet minimum, is published at the unshifted frame base; published ownership survives later errors until real CQ. CPU and direct Endpoint owners share mixed exact-scope CQ batch return. The existing 32 considered outputs/class/realm and 64 CQ-descriptor bounds, independent ACK/retransmission/CQ lifetimes, E3.1 handoff and process-lifetime UMEM charges remain. Eligible driver turns skip only CPU pulling and finalize timers/events/close/deadlines after direct emission; they add no busy polling. Only one intermediate Endpoint CPU-IP-frame-to-UMEM copy is removed, not TCP payload/checksum or relay copies; this is not universal UDP zero-copy, a resident-memory reduction or measured gains.

XDP owns canonical routing, domain and health publication through the userspace backend. The native API reports datapath kind `userspace` without claiming hardware counters or program/attachment inventory. TC listener/token and kernel witness APIs remain unsupported.

Fixed aggregate counters distinguish queue/credit/capacity refusals from native-ID
history precision loss and successful peer reclamation. Only actual refusal
episodes emit a warning; recurring pressure is summarized at debug level rather
than logged per packet.
The same owner sampler acquires each queue's six kernel socket counters and raw
ring indices outside DEBUG filtering, at most once per second on existing owner
turns. DEBUG reuses that sample and reports port counters. Readiness takes one
initial sample and normal close takes a final sample before socket teardown.
There is no new idle sampling timer.
`StatsManager` shares only the latest bounded observations with native
`/api/v1/datapath` (`x-honk.xdp`) and Clash `/stats` (`xdp`); neither GET samples
the kernel or changes polling. Exact admitted queue storage and its shared
owner are funded before construction, with funding retained through the last
diagnostic reader. No diagnostic retains a Port, FD or packet lease.
Queue identity is the real namespace/attachment/ifindex/queue, with actual bind
mode and capacities. Sampling time/sequence, unavailable/error/recovery and
starting/active/closing/closed/failed-retained lifecycle remain explicit.
Reads are sequential, not atomic across rings or queues. Empty-FILL events and
wakeup errors are not additive packet-loss counts; a current populated FILL
ring cannot disprove earlier starvation. See the [API semantics](../reference/api.md#connection-closing-mode-and-datapath-lifecycle).

### Event and bounded adaptive service

`datapath.poll_mode` selects Event or adaptive policy; both start in Event. Adaptive requires a matching exact-executable/counting/device/offload/parameter calibration, sustained separate RX or TX PPS across at least two complete nonoverlapping windows, real pollable device obligations and shared process quota. Unknown source receipts, asynchronous SYN/Initializing/DNS admission, queue refusals, descriptors, CQ and empty probes are not qualification. TX counts complete producer publications, including generated and SG packets, not a send method's returned success or descriptor count. Parameter bounds and the candidate/qualified record are in the [global reference](../reference/global.md).

The same capture Runtime services drivers, timers, completion/FILL, control, bounded RX/TX and close. A pending real policy reader stays pinned beside that service; blocked-ready alone does not spin. Each active interval ends with settlement and cooperative Event re-evaluation/yield. Quota replenishes only when an actual owner boundary observes elapsed time; there is no idle quota/sample timer. Required Event fallback deadlines for real device visibility/completion obligations remain.

Every selected device, metadata/veth included, has a cold-funded retained ethtool descriptor and bounded query buffers. Actual active bits are queried before each bounded Busy probe round; query/compare time is charged inside the interval. A mutation during a round is observed at the next scan, not atomically excluded. MONOTONIC-before/BOOTTIME/MONOTONIC-after samples intersect their offset intervals; ordinary overlapping uncertainty permits qualification, while disjoint/error/backwards/long-gap observations clear it. Reported resolution and non-atomic-read uncertainty cannot prove that a smaller suspend was absent. Protocol Instant and final scoped publication/authority checks retain their original semantics.

Event startup emits reproducible executable/context/counting identities even without calibration, and a complete numeric block adds its parameter digest. A candidate record can therefore bind a preregistered manifest before measurements exist; only the explicit laboratory CLI flag admits that candidate. Qualified status remains a privileged, externally reviewed evidence assertion, not runtime scientific certification. No unmeasured throughput or energy benefit is implied, and an unqualified platform remains Event.

The ignored `xdp::tests::driven_kernel::adaptive` entries
`actual_owner_clock_budget_fairness_and_live_features` (Copy) and
`actual_zerocopy_owner_clock_budget_fairness_and_live_features` (ZeroCopy) run
the same complete fixture. A Core owner and a separate Endpoint owner share one
process ledger, including every reconstruction of the Endpoint owner. A single
45-second absolute deadline starts before initialization and includes traffic,
clock/publication gaps, real socket app/retransmission/timer/close work, every
queue's progress, both Core egress devices, same-thread fairness, quota/debt,
independent publication, actual feature mutation/restoration, retained-query
`ENODEV` and joined cleanup. The ZeroCopy entry requires actual `igb` driver
identity, exactly queues `[0, 1]` and actual ZeroCopy on every bound port,
including every reconstruction.

The separate recent-kernel igb rig requires six igb NICs on three closed hubs,
two KVM vCPUs and 1536 MiB, a read-only host root and one private writable
export. It uses no host TAP, bridge or socket network backend. Each capture
device must read back two combined queues, UDP IPv4 hash fields `sdfn` and a
two-queue RSS indirection table (`ethtool -N DEV rx-flow-hash udp4 sdfn` and
`ethtool -X DEV equal 2`). The producer varies 64 UDP source ports; only actual
per-queue RX advancement satisfies the queue witness. Under
`HONK_XDP_ARTIFACT_ROOT`, `adaptive-runtime.bindings.jsonl` and matching
`adaptive-runtime.binding ` stdout records retain five startup events: A once
and B four times. Each records its actual capture incarnation (`startup_id`),
namespace/inode, driver, device/ifindex, configured mode and every observed
queue bind mode. `adaptive-runtime.joined` is written only after actual peer,
scope/CQ, socket, worker and OS-thread joins and owned link detach. This source coverage requires a passing rig execution before any run
is accepted; it establishes no virtio equivalence, physical-NIC performance or
DMA-release result. Existing Copy and virtio Event profiles remain separate.


### Host source custody

Host TCX egress applies after normal route selection and POSTROUTING. Forwarded packets and honk's exact bypass mark pass untouched. A service reply exemption requires tracked **reply** information from this skb and the same zone-zero conntrack object: finding a reverse tuple, or an existing ORIGINAL entry, cannot grant the exemption. Unsupported link frames, non-transport traffic, DHCP, special destinations and local non-53 traffic keep their kernel paths.

New local flows use the ordered gateway policy. Five FD-owned cgroup hooks record the first available process identity in non-cloned socket storage (argv0, or thread name when unavailable). Only TCP uses a second socket-storage value for its connection decision; disconnect/reconnect is a new decision. UDP ownership is per tuple, never socket-wide. Endpoints keep their original egress, binding incarnation and flow ownership through retirement. New-flow process metadata is checked against the hold; it is not a per-packet source receipt and cannot resume a past syscall. `backend: tun` HostFacts remain separate. A shared UDP receiver keeps the binding and address, not the first target’s process. This does not erase a physical reply path or authenticated TUN source facts.

Proved Direct stays native. Only if the hold table is actually full may a new UDP packet **already proved Direct** pass unrecorded; its next packet is evaluated again. Same-key contention, an unknown decision, and missing Endpoint capacity do not authorize Direct. The 8,192-entry process metadata table is not a quota on Direct. The LAN's 8,192 native-pending credits are separate. A separate 8,192-row table records native TCP ownership, including control packets without a full socket. Exhausting the 65,536-row Host UDP/Endpoint table does not exhaust TCP Direct or physical/L3 LAN holds. Exhausting the TCP Direct table can refuse a new native SYN; it cannot send an unrecorded SYN.

Host Endpoint records use a private single-queue TUN for each egress. A new packet after an idle connection is not a late packet. The driver rejects a redirected packet delayed **more than 30 seconds** before entering the private FIFO; the internal timestamp is not IP payload. Idle collection waits for a sampled kernel-reader grace period and the sole reader's drain of earlier records, and checks protocol, application and outstanding output before reusing a row. A TUN write or a timer alone is not a drain receipt. No packet is replayed on a different egress.

An external link is FD-owned. A return enters the original live interface at ingress, with the checked local MAC on Ethernet. Closing a binding revokes both redirects and its outstanding work before replacement; an unplugged device or reused ifindex cannot acquire an old return. The terminal device guard lives only on the exclusive private TUN until that device disappears. There is no Host XSK, pinned external program, persistent Host receipt or fallback to TC/NFQUEUE. Native firewall, routing, NAT and strict reverse-path checks still decide what injected packets can reach; their presence alone proves neither success nor failure.

Closed Host bindings retire in FIFO order. The head removes its gate and device map entries without holding either the capture registry or binding lock. An error keeps the original device pair and its budget; that realm cannot rebind until its rows have been swept.

### Physical capture and smoke

A physical UDP datagram validated just before Endpoint admission closes keeps its validated source. If the queue refuses it because admission has closed, it is neither taken over nor counted as qualified RX. That refusal does not fail the device owner.

Physical link FDs detach on shutdown or process exit. An invalid CQ/completion is fatal, not a successful drain: unreturned buffers and their owners remain retained through process exit. Foreign XDP attachment is refused; no physical guard or program pins need manual removal.

`.github/ci/xdp-daemon-smoke.sh` belongs to the disposable floor/recent VM gate with matching prebuilt daemon and test executables. The D3 contract checks link detachment and kernel forwarding after process exit or SIGKILL, and unwinds all links on a later queue startup failure. Retain the separate Host custody lane and TC/NFQUEUE selections. Virtual coverage does not certify physical NIC performance or DMA release.

The smoke keeps daemon state on its private `/run` tmpfs, then archives it after
shutdown. Its guest cgroup2 mount lives outside `/sys`, so `ip netns exec` cannot
hide the hierarchy when remounting sysfs for the TC regression.

## Namespace and hook architecture

The ordinary proxy path redirects packets through an isolated network namespace. It does not rely on a host-side TPROXY rule:

```mermaid
flowchart LR
  LAN[LAN traffic] --> LI[lan_ingress]
  LOCAL[Host-originated traffic] --> WE[wan_egress]
  LI -->|local/special or native direct| HOST[Host routing]
  LI -->|proxy, non-must DNS, or raw DNS group must| DAE0[dae0]
  WE -->|proxy, non-must DNS, or raw DNS group must| DAE0
  DAE0 --> PEER[dae0peer in daens]
  PEER --> ASSIGN[dae0peer_ingress / sk_lookup]
  ASSIGN --> SOCK[LISTEN_SOCKET_MAP]
  SOCK --> TPROXY[Transparent listeners]
  TPROXY --> USER[Userspace control plane]
  USER -->|transparent reply socket| PEER
  PEER --> DI[dae0_ingress]
  DI --> LAN
```

### Namespace lifecycle

A short-lived helper thread calls `unshare(CLONE_NEWNET)`, opens `/proc/thread-self/ns/net`, and hands the resulting `OwnedFd` to the process. That FD pins `daens` for the process lifetime. `/var/run/netns/daens` is only a best-effort compatibility bind mount; the engine does not use it as the namespace owner.

Rtnetlink creates `dae0`/`dae0peer` as an L2 netkit pair when the kernel supports it, otherwise as a veth pair. It moves `dae0peer` by namespace FD and configures links, addresses, neighbors, policy rules, and routes. The addresses are:

| Side | IPv4 | IPv6 |
| --- | --- | --- |
| Host `dae0` | `169.254.0.1/32` | `fd00:686f:6e6b::1/64` |
| `daens` `dae0peer` | `169.254.0.11/32` | `fd00:686f:6e6b::2/64` |

The IPv4 endpoints are separate `/32` addresses, not a shared `/30`. Link-scope routes and static neighbors make the peer reachable. In `daens`, fwmark `TPROXY_MARK` selects table `100`, whose IPv4 and IPv6 local default routes deliver packets to local transparent sockets.

The process otherwise remains in the host namespace. `with_daens_netns` serializes each switch with a process-wide mutex. It saves `/proc/thread-self/ns/net`, enters `daens`, runs a fully synchronous closure, and restores the saved namespace on every return or panic path. The closure must never cross `.await` because `setns(2)` is per-thread. A failed restore aborts the process rather than leaving a worker to originate later dials from `daens`.

### Interface hook sets

Each link's [framing classification](../reference/global.md#interface-semantics) selects `_l2` or `_l3`. Startup verifies only the variants its plan needs, plus a routing target when one applies. Later variants are verified outside the shared backend lock before they can be bound.

Each configured name resolves to a canonical root. A member of a bond or bridge resolves to that master; a bond that is a bridge port resolves to the bridge; a member of any other master resolves to that master. `vrf` and `openvswitch` members stay themselves. Supported nesting is one bond/bridge level, plus a bond that is a bridge port. For any other bond/bridge nesting, or for an interface that is its own master, honk refuses that configured entry as `unsupported_type`. The other entries still bind at startup and reconcile normally.

Roots are planned independently. A root named only in `lan_interface` is LAN, one named only in `wan_interface` is WAN, and one named in both is shared LAN/WAN:

| Root role | Hooks |
| --- | --- |
| LAN | `lan_ingress` + `lan_egress` |
| WAN | `wan_ingress` + `wan_egress` |
| Shared LAN/WAN | `lan_ingress` + `wan_egress`; `lan_egress` and `wan_ingress` are skipped |

The role is per interface, so a shared interface in a multi-LAN configuration does not change the hooks of the other LAN interfaces. Traffic can bypass a bridge master's hooks, so a LAN bridge root also binds every port in the LAN role. A WAN name never upgrades that role. A bond root binds only its logical master, with the role's hooks from the table, and never binds its members. A bond that is a LAN bridge port stays one logical LAN port with `lan_ingress` + `lan_egress`; its members are not expanded. For LAN `br0` and WAN `bond0` with `bond0` in `br0`, the bridge is shared LAN/WAN while `bond0` and the other ports remain LAN. A WAN-only deployment without `lan_interface` installs no LAN hooks.

Bond interception covers the normal software skb path through the logical master's TC hooks. Bonding decides which received frames reach the master before honk classifies them. honk does not take over an inactive member's frames ahead of that decision. Raw `AF_PACKET` injection directly on a member and TC-bypassing paths, including hardware offload that bypasses these hooks, are outside this boundary.

For intercepted LAN TCP and non-DNS UDP on a bond, `REDIRECT_TRACK` captures the master ifindex. Eligible LAN UDP `CLIENT_REPLY_TRACK` entries keep that same index. Replies return through master TX (`dev_queue_xmit`), so bonding selects the current egress member. WAN-local interception captures the master ifindex with `from_wan=1` and returns replies through master RX (`BPF_F_INGRESS`) to the host socket; it does not need `CLIENT_REPLY_TRACK`. Active-member changes and member hotplug require no honk member hooks. A WAN-local reply is addressed to the bond's MAC as read at capture, so `fail_over_mac=active` is unsupported and unverified; the kernel forces that mode when a member cannot set its MAC. If failover changes the bond MAC, later replies on an existing flow no longer reach the host socket as local.

`lan_ingress` classifies forwarded client traffic. `wan_egress` independently classifies traffic created by the host. The reverse-direction ingress/egress hooks refresh existing connection state where the topology provides separate directions. Only a forward TCP SYN publishes TCP state: a reverse-direction pure SYN neither creates nor refreshes it.

On Linux 6.12+, honk creates interface hooks as FD-owned TCX BPF links, appended after any other TCX programs; startup, rebind and shutdown drop only owned links. honk neither creates nor deletes `clsact` qdiscs or legacy filters on physical interfaces; remove unwanted leftovers manually. Startup recreates the stale `dae0`/`dae0peer` pair. Kernel options are listed in [Getting started](../how-to-start.md#kernel-configuration).

Mark-preserving, unguarded passes return `TC_ACT_UNSPEC` (`-1`, TCX `NEXT`), including reverse refresh and DNS skip, so subsequent TCX programs can run. `TC_ACT_PIPE` is not continuation on the floor kernel. Mark writers return `TC_ACT_OK` (`0`, TCX `PASS`) and terminate the chain; an explicit WAN zero counts as a write. The same applies to LAN classified and pending ownership guards, and to the WAN exact socket-mark and classified guards.

Frames that belong to another device also continue with `NEXT`, so later TCX programs and legacy `clsact`/`cls_bpf` filters on the same device see them:

- **VLAN-tagged frames.** On an Ethernet (`_l2`) parent, `lan_ingress` and `wan_egress` leave frames with a still-present, non-zero VID to the VLAN device. That device's own hook classifies the untagged frame. Redirecting the tagged frame into `daens` would drop it there as `PACKET_OTHERHOST`. Only these two hooks skip; the reverse hooks `lan_egress` and `wan_ingress` still refresh connection state. A VID 0 priority tag is delivered by the parent and classified normally. `_l3` programs see a tag only on frames they parse as Ethernet ([framing](../reference/global.md#interface-semantics)).
- **Unsupported LAN ingress frames.** A non-IP EtherType (ARP, MACsec) or an IP packet with an unsupported L4 protocol (GRE, IPIP, ESP, ICMPv4, ICMPv6 other than Redirect) is returned as `NEXT` without `CLASSIFIED_MARK`, so an upper device such as `macsec0` classifies its own decrypted frames. NDP Redirects, non-initial fragments and malformed packets keep the terminal classified `PASS`, as does an untagged frame that already carries `CLASSIFIED_MARK` or the pending mark: the ownership guard runs before parsing.

### Interface reconciliation

One `InterfaceBindings` owner holds the loaded TC program FDs and one FD-owned TCX link per owned `(ifindex, direction)`. Startup opens the rtnetlink subscription, reads one topology snapshot, derives the plan, resolves `local_ip`, loads the BPF object, then binds. An interrupted link dump is retried up to three times. Configured-entry behavior is defined in [Interface semantics](../reference/global.md#interface-semantics). Startup fails in only these cases:

- The topology cannot be read. Any error other than an interrupted dump fails at once.
- The default route cannot be read while an entry is `auto`.
- A TC variant of the startup set cannot be loaded. The startup set is the variants the startup plan binds, plus `lan_ingress_l2`, or `wan_egress_l2` without a LAN list, when it binds no routing target.
- An internal link (`dae0`/`dae0peer`, cgroup, `sk_lookup`) fails. A zero `dae0`/`dae0peer` ifindex or an all-zero `dae0peer` MAC counts as a failure.

The startup sequence is one function shared with the real-eBPF VM tests, and completes before datapath admission or READY. A variant that a later plan needs first, for example `auto` moving to a PPP or WireGuard device, is verified on a blocking thread without holding the shared backend lock. Commit attaches the routing generation active at that moment before making the variant bindable. Independent variants are attempted even when another load or extension fails. Original map FDs embedded in unloaded programs remain owned by the loader; logging and event consumers use duplicate handles, so their failure or cancellation cannot invalidate a later load.

`/proc/thread-self/net/route` is read only when an entry is `auto`. A read error does not mean "no default route": at startup it is fatal, and later it is a reconcile failure that keeps the current bindings.

The [API reference](../reference/api.md#native-api) defines the `interface_binding` degradation and its reason priority. Reconcile-level failures preserve the bindings and degradation from the most recently completed apply/commit round.

`IfaceWatcher` takes over the rtnetlink subscription that startup opened before its topology dump. A 60-second tick backs up event delivery, and an unconditional initial reconcile covers changes during startup. If the subscription or its poll registration failed, the tick alone drives reconciliation and the `iface_watch` degradation is reported. Topology discovery, verification and TCX link I/O run outside the backend lock. The watcher takes the read lock to prepare a verifier job or copy a link snapshot. It takes the write lock to attach the current routing extension, publish a prepared variant, or transfer a link commit. Neither routing publication nor receive-trace preparation waits for a TC verifier while holding that lock. An unchanged plan with healthy links commits nothing, and a role change updates the existing link in place rather than stacking another.

Shutdown sends stop and joins the watcher. The watcher awaits any in-flight batch before the BPF hooks are dropped; a warning follows the stage timeout, but the join continues.

A change to a link, address, route, or interface role updates topology observations, clears health-check cooldowns, and triggers fresh probes. Interface addresses also remain available for ECS; no startup, reload, or network event synthesizes `direct(must)` routing rules or a hidden kernel replacement allowlist. Dead UDP and multi-leaf outbounds remain fail-closed until a fresh probe succeeds; a sole TCP leaf with no `final` remains a userspace last resort.

## Program inventory

| Program | Hook | Kernel responsibility |
| --- | --- | --- |
| `lan_ingress_l2`, `lan_ingress_l3` | TC ingress on LAN | Admission check, special/control-plane and non-DNS local bypass, per-source new-flow limit, ordered routing including port-53 ownership, connection state, direct offload, proxy redirect, TX accounting, fragment-verdict recording, and optional ambiguous-UDP staging. |
| `wan_ingress_l2`, `wan_ingress_l3` | TC ingress on WAN | Refresh reverse-direction connection state; not attached on a shared LAN/WAN interface. |
| `lan_egress_l2`, `lan_egress_l3` | TC egress on LAN | Refresh reverse connection state without creating UDP entries from `dae0`; suppress locally generated ICMPv6 Redirects. Skipped on a shared LAN/WAN interface. |
| `wan_egress_l2`, `wan_egress_l3` | TC egress on WAN | Route host-originated TCP/UDP, apply process-name and control-plane bypass data, check outbound connectivity, cache decisions, and redirect proxy traffic; suppress locally generated ICMPv6 Redirects (a shared LAN/WAN interface's LAN-egress hook is skipped). |
| `dae0_ingress` | TC ingress on host `dae0` | Restore reply framing and RX attribution from `REDIRECT_TRACK`, or uncounted client-only fallback; [renew eligible UDP owners](#udp-lifetime-renewal). |
| `dae0peer_ingress` | TC ingress on `daens` `dae0peer` | Restore UDP53 provenance and SYN incarnation after link scrub; assign UDP listeners. TCP retains native established/TIME_WAIT lookup. |
| `tproxy_sk_lookup` | `sk_lookup` in `daens` | Override ordinary socket lookup with a transparent listener from `LISTEN_SOCKET_MAP`. |
| `tproxy_wan_cg_sock_create` | cgroup `sock_create` | Retain the socket's first process identity; capture failure is counted and creation proceeds. |
| `tproxy_wan_cg_connect4`, `tproxy_wan_cg_connect6` | cgroup `connect4`, `connect6` | Preserve existing identity or capture it before connect; capture failure is counted and the connect proceeds. |
| `tproxy_wan_cg_sendmsg4`, `tproxy_wan_cg_sendmsg6` | cgroup `sendmsg4`, `sendmsg6` | Preserve existing identity or capture it before sending; capture failure is counted and the send proceeds. |
| `honk_tcp_passive` | Required `sock_ops` on the cgroup2 root | On `PASSIVE_ESTABLISHED_CB` for a child in the owned `daens`, validate the child's tuple, ISN and the conn/handoff/redirect incarnations, then write the proven handoff into the child's socket storage. |

`LISTEN_SOCKET_MAP` keys are fixed: `0` TCP4, `1` TCP6, `2..=5` UDP4, and `6..=9` UDP6. All UDP paths use `udp_listener_index` over the low source/destination address words and ports in host byte order. In `tproxy_sk_lookup` (`src/sk_lookup.rs`), keep IPv4/IPv6 context reads in separate `#[inline(never)]` subprograms: at optimization level 2, inlining can produce computed-offset reads rejected as a dereference of a modified context pointer.

- TC entry points are raw
  `#[unsafe(no_mangle)] #[unsafe(link_section = "classifier")]` functions taking
  `*mut __sk_buff`. They do not use Aya's `#[tc]`, whose structured argument
  shape triggers a verifier rejection on kernels ≥7.0. Bodies return
  `Verdict = Result<c_long, c_long>` (`action::Verdict`): `Ok` means normal
  processing and `Err` an early exit. Both carry real `TC_ACT_*` values, reduced
  to kernel `i32` by `flatten` (`action::flatten`). `src/action.rs` owns
  `TC_ACT_*`. Keep parser and helper sentinels separate from verdicts, for
  example `transport::ERR_FALLBACK`, `ERR_FRAGMENT` and `PASS_UNSUPPORTED`. The
  `bpf_loop` callback's continuation values are separate as well. `src/sk.rs`:
  `sk_assign_by_index` is TC's counterpart to aya `SockMap::redirect_sk_lookup`
  (which accepts only `SkLookupContext`); `probe_udp_socket` looks up non-DNS
  local UDP sockets. All helpers release implicit lookup references. Programs:
    - `lan_ingress_l2/l3`: LAN classify/route/redirect, ordered-policy DNS ownership, `CLASSIFIED_MARK` dedup, and unique-token staging of only ambiguous non-DNS UDP decisions into Pending when NFQUEUE is enabled and ready; enabled-but-not-ready staging fails closed (`src/ingress.rs`).
    - `wan_ingress_l2/l3`: reverse-direction conntrack refresh (skipped on a shared LAN/WAN interface).
    - `lan_egress_l2/l3`, `wan_egress_l2/l3` (`src/egress.rs`): reverse conn state; routing of locally originated traffic (process name from the actual skb socket's `SOCKET_IDENTITY`, control-plane bypass, `OUTBOUND_CONNECTIVITY_MAP` aliveness, redirect to control plane). Live non-DNS WAN UDP entries take a lookup-only cached-route path; misses route once and then publish complete conntrack metadata.
    - `dae0_ingress`: reply MAC rewrite and redirect to the original LAN interface. Unknown-peer UDP replies use client-only framing without outbound attribution; honk's own link sources never use it.
    - LAN and WAN egress suppress only locally originated ICMPv6 Redirects, using the parser's ICMPv6 header after extension traversal; forwarded Redirects and other ICMPv6 remain pass-through. The WAN hook carries this invariant on a shared LAN/WAN interface, where `lan_egress` is not attached. `honk-core/tests/ebpf_datapath_test.rs` checks L2 through `BPF_PROG_TEST_RUN` and L3 on isolated TUN interfaces, alongside exact-tuple RX accounting and cached-route policy.
    - `dae0peer_ingress`: restores UDP53 provenance and TCP SYN incarnation; assigns UDP with `bpf_sk_assign` from the redirect site's `cb[4]` marker `0x100 | index`, without parsing packet bytes. Missing markers leave UDP to `sk_lookup`; TCP SYN retains its `cb[3]`/`cb[4]` incarnation carrier and native established/TIME_WAIT processing.
    - cgroup sock_create/connect4/6/sendmsg4/6 (`src/cgroup.rs`): the first captured `SocketIdentity{pid, pname}` is retained in native socket storage for process-name rules and control-plane bypass. `pname` is the 15-byte `argv[0]` executable basename, read through runtime kernel-BTF offsets, with thread `comm` as the fallback when it is unavailable or the read fails. Kernel socket destruction reclaims the storage; there is no release hook or cookie janitor. Missing required cgroup/storage support aborts startup. These hooks sit on the root cgroup, so a capture failure from storage allocation or an optmem charge never denies the host operation. The failure is counted, the socket's traffic carries no identity, and process-name rules do not match it. honk's own sockets remain recognized by `dae_socket_mark`.

## Map inventory

`crates/honk-ebpf/src/maps.rs` declares these maps:

| Map | Shape and role |
| --- | --- |
| `CONN_STATE_MAP` | Non-preallocated plain hash, maximum 524,288 entries. Stores a native value lock plus per-flow TCP/UDP state and published routing metadata; userspace owns physical reclamation. |
| `REDIRECT_TRACK` | Non-preallocated 65,536-entry token-bound hash. Locked directional five-tuple payloads retain original MAC/interface, outbound, timestamp and decision identity for reply restoration. |
| `CLIENT_REPLY_TRACK` | 16,384-entry LRU hash. Maps a UDP client address and port for non-53 destinations, including client source port 53, to the framing payload of `REDIRECT_TRACK` with destination zeroed, without its lock header and with token cleared. Replies from uncontacted peers can reach the client without host forwarding. Kernel eviction is approximate: a client that has not sent recently can be evicted before capacity, especially with many CPUs, and such replies then fall back to host forwarding. This cache owns no flow attribution or userspace sweep. |
| `ROUTING_HANDOFF_MAP` | Non-preallocated 65,536-entry hash. TCP SYN handoffs include the committed routing generation; staged UDP carries the decision token. Raw-must UDP53 publishes no tuple handoff: ownership uses per-packet marks. Non-must UDP53 retains facts for malformed-payload fallback. |
| `ROUTING_POLICY_ROOT` | One-entry map-in-map selecting an immutable policy descriptor and one of two synchronous generated-function slots. Successful root replacement supplies the old non-sleepable readers' grace period. |
| Generation-owned IP/MAC indexes | Separate destination/source IPv4 and IPv6 LPM maps plus a MAC LPM map. Values are full per-generation predicate bitmaps, with ancestor bits inherited into more-specific prefixes. |
| Generation-owned domain map | Non-preallocated IP-to-domain-predicate bitmap hash. DNS/sniff facts include positive and negated predicates; a present zero bitmap is known-false. The descriptor exposes its map ID for diagnostics. |
| `OUTBOUND_CONNECTIVITY_MAP` | 1,536-entry array. Six liveness slots per outbound cover TCP/UDP class and IPv4/IPv6; an absent slot is treated as alive. |
| `OUTBOUND_STATS` | 256-entry (`MAX_OUTBOUNDS`) per-CPU array indexed directly by the `u8` outbound index. Each packed 32-byte `OutboundStatsCounters` value contains `tx_packets`, `tx_bytes`, `rx_packets`, and `rx_bytes`; the current ABI does not use `outbound * 4 + counter` indexing. |
| `LISTEN_SOCKET_MAP` | 16-slot `SockMap`; keys `0..=9` hold the two TCP and eight UDP transparent listeners. |
| `DATAPATH_STATE_MAP` | One-slot admission array. Zero passes traffic untouched; nonzero enables classification and redirect. |
| `DATAPATH_FLAGS_MAP` | One-slot runtime policy word: Rule/Direct offload properties plus `global.nfqueue_enable` and NFQUEUE ready fencing. New-flow classification reads it; established direct offload uses cached metadata. |
| `SOCKET_IDENTITY` | Non-cloned `SK_STORAGE` containing the socket's first PID/executable basename. Storage follows the actual socket lifetime, without a fixed hash-entry ceiling or userspace expiry. WAN TC performs lookup only; cgroup create/connect/sendmsg capture missing identity synchronously. |
| `CONN_STATE_OCCUPANCY` | Two-slot per-CPU insert/kernel-delete counters combined with actual userspace delete accounting. Kernel tuple deletion is disabled, so its delete counter remains zero on this path. |
| `AUX_OCCUPANCY` | Two-slot per-CPU redirect/handoff insert counters; userspace subtracts actual deletes. |
| `ADMISSION_PRESSURE` | Janitor-written conn-state pressure latch; auxiliary-map pressure does not set it. |
| `NEW_FLOW_RATE` | 16,384-entry per-CPU LRU hash keyed by LAN source address. Each CPU holds a one-second `(second, count)` window for the per-source new-flow limit. |
| `FRAG_VERDICT` | 4,096-entry LRU keyed by source, destination and IP identification (plus the protocol for IPv4); [fragment verdict retention](#fragments-of-redirected-datagrams). |
| `BPF_STATS_MAP` | Counters exposed by [`honk-tool bpf stats`](../reference/cli.md#bpf); labels and layout-mismatch guidance live there. |
| `EVENT_RINGBUF` | 262,144-byte ring of 80-byte events, including functional tuple/incarnation expiry hints. Producers reserve and initialize ring storage directly instead of copying an event through the bounded TC stack. |
| `FLOW_EXPIRY_HINT` | Private 4,096-entry per-CPU LRU hash keyed by tuple, storing the last hinted incarnation and timestamp. Best-effort suppression of repeated `FlowExpired` hints, never flow ownership or reclamation authority. |
| `UDP_DECISION_SEQUENCE` | Persistent one-slot pinned, spin-locked allocator state for NFQUEUE decision identities; protocol details live in [NFQUEUE](./nfqueue.md). |
| `FLOW_INCARNATION_SEQUENCE` | Generation-owned, spin-locked, nonwrapping 56-bit identity domain represented as `u64`; independent of persistent UDP decision tokens. |
| `RETIRE_FENCE`, `RETIRE_ACTIVE` | Non-preallocated 65,536-entry canonical-tuple fence plus one active flag. Each fence retains its unique operation owner and separate decision token. |
| `RETIRE_GRACE_ROOT` | Private one-entry map-in-map; successful same-inner replacement synchronously drains pre-fence non-sleepable kernel readers. |
| `TCP_PUBLISHING` | Non-preallocated 65,536-entry same-key SYN publisher exclusion. Ownership lasts one TC invocation; a competing SYN refuses before mutation. No userspace sweep or established-packet acquisition. |
| `TCP_SOCKET_BINDING` | Non-cloned socket storage: the accepted child's original tuple/handoff, written by `honk_tcp_passive`. Userspace reads it by accepted FD before adoption. |
| `TCP_LIVE_PINS` | Non-preallocated 65,536-entry incarnation-to-presence hash. A verified accepted owner acquires one exact pin; only aged TCP lookups consult it. Each guard releases its own incarnation, independent of tuple-local refcounts. |

Kernel/userspace map keys and values are `#[repr(C)]` ABI. IPv4 addresses in shared flow structures are IPv4-mapped IPv6 values in network byte order.

`ConnState`, `RedirectEntry`, and `RoutingHandoffEntry` payloads are 72, 40, and 72 bytes, with independent `incarnation: u64` fields. Their tuple maps store `FlowMapValue<T>`: a native lock at offset 0 and payload at offset 8, so the stored values are 80, 48, and 80 bytes. Payload decision-token offsets are unchanged. `ConnState` also records the original SYN ISN and the committed-interception flag; its `reserved` word at payload offset 68 is always zero. `TuplesKey` stays 40 bytes with explicit zeroed trailing padding. The immutable `TcpSocketBinding` payload is 120 bytes, including `syn_isn` at offset 116, and the persistent `UDP_DECISION_SEQUENCE` stays exactly 12 bytes. Core validates actual map BTF/value layouts before attachment; the toolbox validates stored layouts before decoding. Use matching core/tool/object versions, not a compatibility shim.

Existing tuple elements are updated in place and never replaced. Ordinary Linux hash replacement can recycle storage while an RCU reader still holds its old pointer. Kernel readers take coherent native-lock snapshots or narrow projections; mutations compare the captured identity while locked. Apart from unlock, no helper is called while a value lock is held. Physical deletion still requires the tuple fence, successful kernel grace, and post-grace ownership checks. External toolbox enumeration uses bucket-protected batches with locked value copies, not an unsafe singleton fallback.

Stateless UDP tuple metadata uses token/incarnation `0/0`. Each newly evaluated packet rewrites complete handoff/redirect payloads in place, but only over another `0/0` entry. It cannot overwrite ordinary or staged owners. Raw-must destination-53 traffic keeps its per-packet carrier instead of a tuple handoff. Stateless redirect writes retain the existing timestamp until its refresh cadence is due.

`auxiliary.rs` owns initial and cadence-driven client-only framing publication. Exact LAN UDP traffic to non-53 destinations, including source port 53, can replenish an evicted client record on the existing one-second timestamp-refresh cadence in either direction. The current stored MAC/interface payload is copied under its native lock and projected after unlocking; unknown-peer fallback never renews that cache or gains outbound attribution. This remains best effort, without a new timer or per-packet LRU write.

`RoutingMeta` bit 58 marks WAN UDP userspace ownership; bit 57 (`OFFLOAD`) distinguishes native direct state. Failed unpublished UDP claims become exact-owner `Aborted` markers with the actually allocated token, and keep their auxiliaries until fenced userspace cleanup. A preparing or aborted packet cannot renew the claim. An `Aborted` entry is immediately eligible for expiry but is never forwarded or activated; advisory hint loss still has the existing janitor backstop.

After validating a new object, startup removes only the six obsolete honk pins (`COOKIE_PID_MAP`, `UDP_DECISION_EPOCH`, `UDP_DECISION_INFLIGHT`, `UDP_DECISION_RETIRE_FENCE`, `TCP_REQUEST_BINDINGS`, `REQUEST_FENCE`). It never sweeps unrelated pins or removes the persistent UDP allocator.

`crates/honk-ebpf-common/src/lib.rs`: shared marks and NFQUEUE token packing, `OutboundIndex`, `RoutingMeta`, `DaeParam`, and `OutboundStatsCounters`/map constants.
`crates/honk-ebpf-common/src/routing_policy.rs`: fixed `RoutingInput`/`RoutingDecision`/`RoutingPolicyDescriptor` ABI (128/24/24 bytes), feature bits, and process-name normalization limits. `RoutingDecision` includes a direct-mark index (`u32::MAX` when absent); the loader rejects older external objects by checking the slot's BTF output layout.
`crates/honk-ebpf-common/src/redirect_need.rs`: `TuplesKey`, `Tuples`, token-carrying `RoutingResult`/`RoutingHandoffEntry`, 256-bit `DomainRouting`, and `SocketIdentity`.
`crates/honk-ebpf-common/src/conn.rs`: `ConnState` (including `UdpDecisionState` and `decision_token`), `ParseTransportCtx`, `BpfStatsKey`, `TcpState`, and the auxiliary expiry timeouts shared with userspace.
`crates/honk-ebpf/src/maps.rs`: static TC map declarations and their kernel-side capacities.
`crates/honk-ebpf/src/contrack.rs` owns incarnation allocation, the kernel-private `ConntrackArgs` scratch and shared lifecycle checks; `contrack/tcp.rs` owns SYN classification and TCP publication, `contrack/udp.rs` the UDP claim/publish/abort protocol. `flow.rs` owns locked snapshots/projections; `auxiliary.rs` owns auxiliary expiry, the shared `AuxPrep` publication policy used by LAN and WAN, matching refresh and stable publication.

`crates/honk-ebpf/src/route.rs`: static root/slot facade and fixed-ABI dispatch; generated policy code is loaded by userspace.
`crates/honk-ebpf/src/tcp_binding.rs` and `honk-core/src/ebpf/real/tcp_binding.rs` own the required SYN publication bridge and the `honk_tcp_passive` child proof. Neither reads kernel memory, so TCP needs no kernel-structure offsets. The SYN's low 24 mark bits and 32 priority bits carry its 56-bit identity only after peer ingress restores them; no TCP reader of that carrier remains since the request proof was removed, and removing its writer is deferred. Exhaustion refuses identity publication instead of wrapping.

An intercepted SYN is classified in TC without reading kernel memory. `bpf_skc_lookup_tcp` queries the FD-owned `daens`; a null result, `LISTEN` and `NEW_SYN_RECV` all count as absent, so the request itself is never inspected. `TIME_WAIT` publishes a new incarnation. For an existing child, the decision comes from its socket storage: missing child storage refuses, a different ISN publishes a new incarnation, and a valid proof reuses the stored incarnation.

When the lookup is absent, honk applies the first matching rule to the conn-state entry:

- Its ISN differs from the SYN's: publish a new incarnation.
- It is not Active: publish a new incarnation.
- A live relay pins its incarnation: publish a new incarnation.
- Its handoff or redirect auxiliaries are missing: refuse.
- Its auxiliaries are present but aged: publish a new incarnation.
- Otherwise: reuse the cached incarnation and original routing snapshot, even after policy changes.

A committed interception with missing evidence refuses the retry rather than reconstructing ownership or passing it natively. Because TC never learns a request's ISN, a retransmission can reuse the cache while the kernel still holds a request from an earlier SYN with a different ISN. The ACK for that earlier request then fails the callback's ISN check, stays unproven and is closed. Native-direct flows do not acquire interception proof.

`honk_tcp_passive` attaches as a BPF link to the cgroup2 root and is required: startup fails without it, and TCP admission cannot open. It ignores every callback except `PASSIVE_ESTABLISHED_CB`, and ignores any socket outside the owned `daens`. A socket counts as inside only when its netns cookie equals the `SO_NETNS_COOKIE` that userspace read from a `daens` socket before load; a zero cookie disables the program. The accepted child's tuple comes from the callback context, and the ISN is `rcv_nxt - 1`.

Under the existing value locks, the callback requires all of the following:

- The tuple is not retiring.
- The conn-state incarnation is nonzero, carries `ORIGINAL_INTERCEPT`, and has the same ISN.
- The handoff and redirect incarnations equal it.
- The handoff is within the established timeout.

The conn-state may already be Closing: TC marks Closing on any FIN or RST, and one can arrive before, or on, the segment that completes the handshake. The callback then writes the complete `TcpSocketBinding` with a single `bpf_sk_storage_get(F_CREATE)`.

The callback always returns success, so a rejection or a storage failure never blocks the connection. The child then carries no proof and adoption closes it, and a storage failure increments the child-proof counter. A child can exist for a moment before its storage is written; a SYN retransmission refused in that window is retried by the client. Context reads stay family-separated `#[inline(never)]` constant-offset reads, the same shape as `tproxy_sk_lookup`, and the callback uses only stack scratch.

Owned `daens` disables and verifies SYN cookies, request migration and Fast Open. Only an absent `tcp_syncookies` key is optional for kernels without that feature; inspection, write and verification errors remain fatal. Startup refuses a `sock_ops` attachment that cannot be made, including when a legacy flags=0 program already holds the root cgroup's slot. A child proof that is missing, unproven, failed on allocation or superseded closes the accepted socket without authorizing tuple deletion. A proven child's socket storage follows its actual lifetime, with no separate expiry. Backlog overflow relies on client retry, not on guessed cookie attribution. A LAN host that floods unanswered SYNs can therefore fill the transparent listener's backlog and delay new intercepted TCP connections until its requests expire. Enabling IPv6 after an IPv4-only startup still requires a restart: the IPv6 socket-family probe is fixed at load and the TCP6 listener binds at startup.

Two timing windows trade a refusal for a retry or a re-publication. The kernel queues a child before it runs the `PASSIVE_ESTABLISHED_CB` callback, so an acceptor that is already running can see the child before its proof exists. This window measured about 1 µs median and 17 µs at worst on x86 loopback; on ARM64 it is bounded by source analysis only. `adopt_tcp_flow` retries a missing proof three times, 1 ms apart, before closing the socket. A retransmitted SYN for a live request that arrives after the 30 s handoff timeout finds the publication aged and publishes a new incarnation and routing snapshot while the old request lives on. A child whose ISN matches binds to whichever incarnation is current, so it takes the replacement's route.

The largest classifier in a historical ownership-proof build verified 464,596 instructions on Linux 6.12.94 aarch64 (`verified_insns`), against 74,469 in release beta.82 before ownership proofs. Changes that add state checks should report `verified_insns` before and after on the same fixture.

`crates/honk-ebpf-common/src/event.rs`: fixed-layout ring events including conntrack overflow and UDP decision-token exhaustion. `crates/honk-ebpf-common/src/dae_ip.rs`: `In6Addr` union and v4-mapped helpers.
`crates/honk-core/src/routing/ir.rs`: canonical `CompiledPredicate` and userspace `PortRange`; `crates/honk-core/src/control/routing_matcher.rs` lowers them into the generated function ABI.

## Marks and mark ownership

| Constant | Value | Meaning |
| --- | --- | --- |
| `TPROXY_MARK` | `0x08000000` | Selects the `daens` table-100 local-delivery route and tags redirected packets for listener delivery. `global.tproxy_mark` must equal this compiled value. |
| `DAE_BYPASS_MARK` | `0x00000100` | Default when `global.so_mark_from_dae` is zero; otherwise honk sockets and listener recognition use the configured value exactly. |
| `CLASSIFIED_MARK` | `0x40000000` | Prevents a packet attached at both bridge master and slave from being classified twice; also marks final direct verdicts. |
| `NFQUEUE_PENDING_MARK` | `0x80000000` | Identifies traffic that must be held before conntrack/NAT; a valid staged mark also carries `CLASSIFIED_MARK` and a nonzero token. |
| `NFQUEUE_TOKEN_MASK` | `0x3fffffff` | Selects the low 30 skb-mark bits that carry a decision token on NFQUEUE-staged packets. |

`SKB_MARK_RESERVED_MASK` is `0xc0000000`, the union of `CLASSIFIED_MARK` and `NFQUEUE_PENDING_MARK`. Configuration validation rejects `global.so_mark_from_dae` and routing-rule marks that overlap those bits. NFQUEUE direct completion repeats the same check before accepting a rule mark.

Final marked direct packets carry `rule_mark | CLASSIFIED_MARK`, including native LAN, NFQUEUE acceptance and userspace TCP/UDP sockets. Match only user-owned bits in Linux policy rules: `fwmark 0x200/0x3fffffff`. WAN egress bypasses the exact nonzero configured socket mark or a classified mark without `NFQUEUE_PENDING_MARK`; merely containing bit `0x100` is not a bypass. Host-originated nonzero direct marks are sent through userspace, since changing an skb mark at WAN TC is too late for the original Linux route lookup.

Real transparent UDP53 uses `SO_RCVMARK` and per-packet `SOL_SOCKET`/`SO_MARK` ancillary data for DNS/raw ownership. The same skb carries the route code and nonwrapping 20-bit committed routing generation through `cb[2]` across link scrub; mandatory `dae0peer` TC restores it. The signature mask is `0xc8000000` and variable carrier bits are `0x37ffffff`. Bit `0x100` selects an immutable direct-mark index instead of an outbound code; the 8-bit index resolves through the active Router's sorted mark table. Owned `daens` fwmark routing ignores these variable bits. User mark reservations and `UDP_DECISION_SEQUENCE` remain unchanged. Raw direct/group ownership never takes authority from a mutable tuple handoff.

For non-DNS traffic, local-socket probing distinguishes honk's transparent listeners from ordinary local services by comparing the full socket mark with `PARAM.dae_socket_mark`. Host-namespace `dns.bind` sockets are ordinary unmarked listeners, but their presence does not bypass LAN port-53 policy.

## Packet behavior and invariants

### DNS and local-listener precedence

After existing ingress and control-plane exclusions, LAN/WAN TCP/UDP destination port `53` evaluates the normal ordered policy once, not a separate must-only scan. [Traffic-rule ownership](../reference/routing.md#outbound-targets-and-must) determines native, drop, raw, or controller handling. An exact or wildcard local `:53` listener does not override that policy. Port `53` remains exempt from outbound-health drops on LAN ingress and WAN egress, not from the selected user `must` result.

The local-socket probe remains before traffic routing only for non-DNS traffic. It uses the packet's current network namespace (negative netns ID), not relative namespace ID `0`. A matching non-honk socket may receive locally; wildcard matches additionally require full FIB `NOT_FWDED`. The existing TCP pure-SYN probe skip remains. For parsed destination `53`, an exact nonzero control-plane bypass mark preserves native request delivery; ordinary requests continue to routing instead of probing a local listener. Backend replies remain subject to existing non-53 policy. There is no unconditional gateway-management reachability guarantee; configure [explicit user rules](../reference/routing.md#explicit-local-rules) when needed.

Native direct is subject to external firewall/NAT; see [DNS source boundaries](./dns.md#ingress-paths) for its distinction from `asis` and client-facing anyfrom replies.

UDP53 stays outside ordinary UDP conn-state and decision-token allocation. Fragmented LAN queries requiring controller/raw delivery use [native reassembly and NFQUEUE](./nfqueue.md#fragmented-lan-dns); unfragmented queries retain TC redirection. A pinned routing-generation counter fences queued metadata across restart. Other datagrams follow [fragment verdict retention](#fragments-of-redirected-datagrams).

### Per-source new-flow limit

Each LAN source has an always-on, nonconfigurable budget of 1024 new-flow attempts/s/CPU, counted in fixed one-second windows. A new-flow attempt is one of:

- a pure TCP SYN, including a retransmission;
- the first ordinary UDP packet of an uncached flow;
- any routed UDP packet with either port 53.

Direct and proxied flows share this budget, as do all clients behind one NAT-router or access-point source address; each IPv6 address is its own source. Excess attempts drop before state allocation, increment `new_flow_rate_limited` in `honk-tool bpf stats`, and trigger a janitor WARN when the counter grows. Local-service reply learning shares the budget without dropping requests; see [reverse learning](#reverse-udp-learning-and-conn-pressure). LRU eviction forgets recent counts. Host-originated WAN traffic, cached-flow auxiliary rebuilds and many spoofed or rotating source addresses are not covered.

Because the window is per CPU, the effective ceiling is the CPU count times 1024/s. The budget slows but does not bound one source's use of the shared auxiliary maps. One CPU's budget lets a single host fill `REDIRECT_TRACK` with UDP flows; that map holds 65,536 entries with a 120-second idle expiry. If its flows spread over three or more CPUs, it can fill `ROUTING_HANDOFF` with new flows of either protocol; that map holds 65,536 entries with a 30-second expiry. Janitor pressure cadence and reclamation are the backstop, and a full map is counted by `redirect_track_insert_failure` / `routing_handoff_insert_failure`.

### Fragments of redirected datagrams

On `lan_ingress`/`wan_egress`, a first fragment with more-fragments set and offset 0 enters `FRAG_VERDICT` for 30 seconds when its verdict is `TC_ACT_SHOT` or `TC_ACT_REDIRECT`. Matching later fragments drop; no proxy reassembly happens. Any other first-fragment verdict erases an older record, preserving direct/staged/pending traffic. UDP with either port 53 is excluded; LAN DNS retains [native reassembly](./nfqueue.md#fragmented-lan-dns). Tiny unparseable first fragments pass. Later fragments can pass if they arrive first, or if the record expires, is evicted or cannot be inserted. IPv6 matches on source, destination and identification only, so extension headers before UDP do not separate a datagram's fragments.

### Reverse UDP learning and conn pressure

Local non-honk UDP requests pass natively. Creating their reversed reply tuple consumes the [source budget](#per-source-new-flow-limit); cached requests and replies bypass socket/FIB probing. Budget exhaustion skips learning without dropping the request or incrementing `new_flow_rate_limited`, so replies may route as new flows. `wan_ingress`/`lan_egress` also learn reverse tuples without that budget. No reverse observation overwrites forward authority. Continued requests renew a learned entry even after the local service closes, keeping native bypass until the [UDP idle timeout](#udp-lifetime-renewal).

While `ADMISSION_PRESSURE` is set, reverse learning is lookup-only. A miss increments `udp_reverse_learning_suspended`, and replies of newly observed services may route as new flows. Existing entries work. Outside pressure, an unsolicited reverse observation can pre-empt a later forward flow on the same tuple, making it pass natively.

### UDP lifetime renewal

UDP conn state has a 120-second idle timeout. Forward traffic, the available `wan_ingress`/`lan_egress` reverse hooks, and exact non-DNS `REDIRECT_TRACK` replies through `dae0_ingress` renew it at most once per second. Exact replies renew only the live matching owner, including token-bound proxy flows, after locked identity/state/fence checks; they never create state. Stateless port-53 UDP, `Preparing`, `Aborted`, expired, `Pending`, `DirectArmed` and `CLIENT_REPLY_TRACK` fallback do not renew. Proxied replies work on single- and dual-homed gateways; single-homed native-direct traffic gains no reverse hook. See [long connections](../operations/long-connections.md) for userspace timers.

### Special and internal traffic

On LAN ingress/egress and WAN egress, `dst_is_special` passes traffic before routing and conntrack when it sees:

- an L2 destination MAC with the individual/group bit set, covering broadcast and multicast;
- IPv4 `255.255.255.255`, `224.0.0.0/4`, or `0.0.0.0`;
- IPv6 `ff00::/8`.

This keeps DHCP, mDNS, SSDP, LLMNR, and similar link traffic out of the proxy. The internal link address space is `169.254.0.0/16` and `fd00:686f:6e6b::/64`. Control-plane UDP admission rejects proxy initialization when either endpoint is in those ranges, while `dae0`/`dae0peer` hooks handle the engine's own delivery path.

### Outbound liveness

Userspace publishes health per group into `OUTBOUND_CONNECTIVITY_MAP`. A new LAN flow routed to a slot explicitly marked dead is dropped with `TC_ACT_SHOT`. A TCP group with exactly one unique leaf and no `final` can keep its slot open for a last-resort attempt on the same selected path. TCP and UDP destination port `53` are exempt from health drops on LAN ingress and WAN egress alike, subject to the DNS ownership rules above. The exemption preserves the selected policy. Gateway-native routing requires user-authored rules.

For a group with exit routes or UDP-capable configured chains, UDP slot publication evaluates eligible paths in the committed group manager for each domain and family. It follows current Selector choices and explicit `final` edges, checks the full path's capabilities and health, and includes the ordinary IPv4 health fallback for an IPv6 slot. A matching hop or ordered-prefix fault can close the slot when no eligible path remains. Recovery of that path can reopen it. An eligible terminal `block` can keep the slot open for userspace to reject the traffic. Ordinary UDP groups retain the group-OR of reachable UDP-capable leaves and terminal `block`.

Reload can raise a numeric group slot’s minimum routing generation when the slot changes owners or when the same group gains or loses composed UDP support. A cached flow that needs a new userspace endpoint on an affected slot must supply a generation at or above that minimum. A missing or too-old generation drops the flow before dialing, even if the slot now selects an ordinary node. An existing endpoint keeps its admitted transport. A rejected full reload preserves the previous minimum.

TCP health gates only fresh SYN publication; established and cached retransmitted TCP survive health changes. UDP health gates each packet on ordinary LAN redirect and WAN routed/cached paths, except native-direct offload and committed token-bound LAN `Proxy` redirects. Configured UDP block remains final.

### Route-time direct offload

For non-DNS traffic, the decision to keep a non-`must` flow in kernel direct routing is made once and cached in `RoutingMeta` bit 57. Established packets test the cached bit instead of rereading `DATAPATH_FLAGS_MAP`. Direct-mode offload cannot take ownership from non-`must` DNS.

| Effective mode | Route-time policy |
| --- | --- |
| `Rule` (also no Clash mode override) | A non-`must` `direct` result is offloaded only when SNI cannot change it: no domain-class reevaluation is possible, DNS learning supplied the flow's domain bitmap, or the matching direct action has no live domain predicate in its rule prefix including itself. Domain rules after that first match do not prevent offload; earlier or current unresolved domain predicates remain conservative. |
| `Direct` | LAN ingress, WAN TCP and WAN UDP normalize every non-`must`, non-`block` flow to `direct` and offload it; no proxy health gate applies. A rule mark is kept only when the rule itself routed `direct`. Unlike the userspace override, SNI is not consulted, so a `block` or `must` rule reachable only through a sniffed domain does not apply. |
| `Global` | An exact global selection of `direct` uses the same all-direct policy. Other global selections keep non-final flows in userspace for the selected outbound. |

`direct(must)` always stays direct and needs no bit-57 flag. Ordinary non-DNS `block` and `block(must)` remain final; non-`must` DNS instead retains controller ownership. Full rule evaluation and mode semantics are documented in [Routing](./routing.md).

### Host-originated WAN UDP

`wan_egress` only classifies locally generated traffic; forwarded packets have a real ingress ifindex and pass untouched. honk-owned marked sockets and a matching control-plane socket identity also bypass it. For a live non-DNS UDP flow with published connection state, the program uses a lookup-only cached-route path. A miss runs routing once and publishes complete state before subsequent packets use the cache. DNS remains short-lived and does not create this UDP cache entry. If preparing the redirect fails (a full or mismatched handoff/redirect map), WAN TCP and UDP packets are dropped rather than passed natively; the existing insertion-failure counters record full maps.

## Admission sequencing

`DATAPATH_STATE_MAP[0]` stays zero, so traffic passes untouched, until all of the following hold: the internal hooks are ready, the listeners have bound and published the complete TCP/UDP FD set, the receive loops have started, and enabled NFQUEUE is ready. Configured interfaces bind lazily and are not an admission precondition; see [interface reconciliation](#interface-reconciliation). `dae0_ingress` attachment is mandatory even for WAN-only deployments; failure aborts startup before admission.

Shutdown fences new NFQUEUE staging where applicable, closes `DATAPATH_STATE_MAP[0]` before listener teardown, then drains and detaches producers. Admission-map failure is fatal rather than silently continuing with ambiguous ownership.

## Userspace maintenance and accounting

`BpfJanitor` wakes every two seconds. Accepted TCP relays pin their conn and redirect entries for their lifetime. An unpinned closing TCP flow expires after 10 seconds, an unpinned active TCP flow uses a 120-second backstop, and UDP follows [idle renewal](#udp-lifetime-renewal). Unpinned TCP and stateless token/incarnation `0/0` UDP53 redirects reclaim after 30 seconds without deleting conn state; other redirects retain the kernel's 120-second expiry.

Per map, the highest conn/redirect/handoff utilization selects the cleanup cadence and candidate budget: 60 seconds/1,024 normally, 15 seconds/2,048 at 70%, two-second ticks/4,096 at 85%. Growing overflow counters and incomplete or ≥85%-full auxiliary scans also trigger pressure cadence. Per-map cursors resume bounded scans; only a complete traversal calibrates occupancy from fresh insert/delete counters and userspace deletion accounting. The separate `ADMISSION_PRESSURE` latch uses conn-state utilization alone: it is set at 70% and cleared below 60%. Socket identity is never swept.

Failed overflow, conn/auxiliary-occupancy or health-statistics reads retain the previous sample, initially zero, warn with the failed signal at most once per 10 seconds, and do not stop sweeping. A missed overflow read is not a quiet round toward leaving pressure; calibration requires fresh counters. Logs separate conn/redirect/handoff utilization, and overflow WARNs require counter growth. Retirement and admission-pressure publication failures remain fatal, logged with their cause chain.

Kernel expiry refuses the packet and emits an advisory hint rather than deleting state. A UDP handoff that matches its live conn's token/incarnation renews in place even after its nominal 30-second age, after a locked identity check and at most once per second; mismatches are refused. `FLOW_EXPIRY_HINT` coalesces a cached tuple/incarnation to one hint/s/CPU, recorded only after the ring accepted the hint; a new incarnation resets suppression, and eviction/insertion failure may forget it. A full ring therefore never silences a tuple, at the cost of one failed reservation per qualifying packet while it stays full. Hints are independent of diagnostic log throttling and grant no reclamation authority; ring/queue loss falls back to janitor sweeping, without a prompt-recovery guarantee under overload.

The removal worker batches up to 1,024 TCP/UDP/expiry requests under the [NFQUEUE fence/grace protocol](./nfqueue.md#exact-tuple-retirement), deduplicating canonical tuples while preserving the first token and acquisition/release order. Current TCP pins are rechecked under backend write ownership, and admitted cleanup stays joined beyond shutdown warnings. Actual UDP conn deletion triggers [exact endpoint retirement](./control-plane.md#tcp-relay-and-conn-state-ownership).

Per-outbound traffic counters are per CPU. TX packets and bytes are counted at `lan_ingress` when the route lands, for both redirect and direct-offload outcomes. RX packets and bytes are counted at `dae0_ingress` after `REDIRECT_TRACK` identifies the returning outbound; a reply delivered from `CLIENT_REPLY_TRACK` has no returning outbound and is not counted. Unclassified pass-through traffic and drops have no outbound counter.

The backend API uses `TuplesKey`/`ConnState`, bounded map scans, and conditional retirement. Legacy `ConnTuple` CRUD, string IP/domain routes, cached parameter setters, and backend statistics adapters are removed. Load-time `DaeParam` globals, generation-owned IP/MAC/domain fact maps, `StatsManager`, and pinned `OUTBOUND_STATS` remain the authoritative paths.

`just test-netns` includes production TC packet regressions: exact reverse-tuple RX accounting, cached-route health/readiness, and locally generated ICMPv6 Redirect suppression on LAN and WAN egress. L2 cases use `BPF_PROG_TEST_RUN`; L3 uses actual TUN interfaces in an isolated network namespace, including forwarded and hook-detached controls.

## Core forwarding firewall and IPv4 NAT

The optional [typed firewall/NAT configuration](../reference/routing.md#core-forwarding-firewall-and-ipv4-nat)
extends the existing CoreForward owner; it is not another executor or an nftables
configuration importer. The ordered stages are captured domain/interface identity,
existing original/reply binding, original-fact firewall and DNAT, real input FIB,
translated-fact forwarding firewall, SNAT, then the existing TTL/MTU/checksum and
device-output path. Canonical traffic conditions compile through the same compiler
and matcher, while allow/drop/reject and translation remain typed actions.

One bounded table reserves original and DNAT aliases under the exact logical ingress
identity; equal private tuples on different LAN/VLAN interfaces may coexist. Fully
translated reply aliases and the public address/port allocator remain shared in the
namespace/scope domain. Each direction pins its actual ifindex and attachment
incarnation; arriving on the wrong interface cannot borrow a grant. TCP admission
starts with SYN and requires the matching SYN-ACK sequence/acknowledgement and final
ACK before establishment. Established owners retain the observed handshake proofs:
matching SYN/SYN-ACK retransmissions, including prior SYN data and simultaneous
open, remain admissible, but a new SYN sequence cannot take over the tuple. UDP
reverse ownership is exact-peer, not a wildcard external-port grant. The first
packet's receive timestamp fences older queued input; idle freshness also follows
receive events, while current processing time drives expiration and capacity cleanup.
IPv6 uses the same firewall owner without address translation. IPv4 NAT addresses
must satisfy the transit unicast validator, excluding `0.0.0.0/8` and `240.0.0.0/4`
as well as loopback, multicast and limited broadcast addresses.

Established TCP bindings use a 7440-second idle horizon and UDP bindings 120 seconds;
opening/closing proof states retain their 30-second horizon. FIN/RST flags alone
cannot shorten established protection without receive-window authority. Current
traffic Block precedes mutable lookup: a refused packet neither renews a binding
nor allocates a translated IPv4 ID.

Table storage and each binding's Arc metadata are charged before allocation;
packet rewrites use the Core owner's already-funded bytes. Port searches skip
candidate-dependent self-alias collisions; a collision or exhausted pool publishes
no aliases. Expiry, policy revocation and MASQUERADE
address removal close admission immediately, but output leases keep the binding,
ports and charges alive until actual resource return. Route-only edits preserve the
security epoch; firewall/NAT or relevant captured GeoIP changes advance it before
publication, and removing/re-enabling the feature never resets it. Failed candidates
retain the prior compiled sidecar. A route refresh does not migrate an owner.
The runtime table has 1024 entries (the pure API permits at most 4096) and uses linear
lookup/allocation; this is deliberately not a fast-path/offload claim.

NAT assigns distinct IPv4 IDs to translated DF-clear datagrams, including packets
that only fragment downstream; DF-set atomic traffic avoids this allocation.
The funded global identity directory holds `min(binding_capacity × 64, 65536)`
datagrams (65536 in the daemon), retaining binding/quote authority through output
and CQ ownership. Reuse waits 120 seconds after observing the final owner return.
This uses the conventional RFC 6864 maximum datagram lifetime, not a guarantee
against arbitrary longer remote fragment queues or network delays. Exhaustion
drops the affected packet without reusing a live ID. The conservative global pool
can limit sustained DF-clear translation to roughly 546 datagrams/s even before
additional hold time; it is not a high-rate NAT performance claim.

Core also records non-authorizing native IPv4 ID history before any firewall/NAT
policy is enabled. Both native-before-NAT and NAT-before-native share the output
reassembly domain: unchanged IDs are remembered, and a plain packet is remapped
only if its ID collides with retained translated output. These output/quote leases
carry no conntrack grant and survive CQ, policy changes and first NAT enable.
Authorization uses received wire facts; restoring a retained native quote's ID
occurs only at the final forwarding frontier, never before lookup or a neighbor
wait. ICMP echo identity remains part of quote matching.

Exact native history has a separate `min(capacity × 64, 65536)` row bound; repeated
raw IDs reuse history without spending the managed-ID pool. At exact-history or
budget exhaustion, pre-funded per-ID counters conservatively retain the unknown
ID globally instead of dropping ordinary plain forwarding or imposing the
translated-packet rate ceiling on it. Overflow exclusion lasts final owner return
plus 120 seconds and the bounded Core reassembly horizon (currently 30 seconds);
completed quotes acquire independent retention before expiry or queueing. Domain
precision decreases only at saturation. A required translation with no provably
safe ID is still refused; no live identity is reused.

History and actual conntrack/managed-ID storage are separately funded; the latter
is allocated only when needed. The overflow owner retains 65536 atomic reference
counts and retirement ticks plus bounded bitmaps through its last output/quote
guard. Dynamic identity records own their reservations, so table Drop cannot
refund memory still held by an exported lease. These are logical bounds, not
whole-process RSS or high-rate NAT performance claims.

Fragments use the existing reassembler, never a parallel NAT reassembler or
invented non-first-fragment ports. Live/completing reassemblies and exported
timeout quotes retain only their possible scoped address/protocol domains;
tombstones and unrelated fragments cannot reset all identity retirement clocks.
Translation occurs only after complete packet/checksum validation;
subsequent fragmentation stays with CoreForward. Known admitted IPv4 ICMP error
quotes restore inner addresses, ports, original ID and available checksum fields,
including eight-byte TCP quotes without a checksum field. Non-first fragment
quotes use retained ID authority and never interpret payload bytes as ports.
IPv4 UDP zero checksums remain zero. Unknown/truncated quotes and unsupported
quoted extension layouts fail closed. Related IPv6 errors do not imply IPv6 NAT.

Focused unprivileged regressions live in `honk-datapath::firewall::tests`,
`honk-core::routing::firewall::tests`, and `honk-config/tests/firewall.rs`.
After the integration owner builds the test artifacts, these are no-build smoke
entries: run the existing datapath test executable with `firewall::tests`, the
existing core test executable with `routing::firewall::tests`, and the config
`firewall` integration-test executable directly. No host interfaces, BPF load or
network namespaces are needed. Source implementation and these packet tests do
not establish device/hardware, real-kernel or performance validation; the full
cross-backend validation matrix remains separate.

## Related docs

- [Routing design](./routing.md)
- [NFQUEUE held-packet path](./nfqueue.md)
- [Control plane](./control-plane.md)

