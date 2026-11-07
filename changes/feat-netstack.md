Added

- Add single-peer WireGuard outbounds backed by a bounded sans-I/O IPv4/IPv6 TCP/UDP stack.
- Add opt-in Linux XDP packet termination and Core forwarding with stateful firewall and IPv4 NAT, while keeping TC as the default when datapath configuration is omitted.
- Apply scope-local learned DNS rules to new numeric packet TCP/UDP flows while preserving existing transports and terminal routing decisions.
- Abort packet protocol state before normal shutdown waits for selector retirement, without releasing outstanding output ownership early.
- Avoid a redundant XDP daemon RX refill while preserving receive-owned replenishment and explicit RX/TX wakeup checks.
- Default explicit XDP capture to forced AF_XDP ZeroCopy without fallback; keep TC as the default backend and support explicit `xsk_mode: copy` for existing Copy deployments.
- Amortize AF_XDP transmit wakeup checks within synchronous device turns without delaying packet publication or releasing outstanding owners on failure.
- Keep packet-scope statistics and quiescence reads passive, and skip retirement locking when no application has closed.
- Separate shared policy publication from borrowed TC-only authority, rejecting software-backend kernel operations without fabricating kernel state.
- Sleep the XDP owner on actual readiness and deadlines, retaining bounded fallbacks for unresolved device visibility, completion and budget obligations.
- Batch scoped packet output and completed-owner returns while preserving class order, bounded device credit and last-descriptor CQ ownership.
- Drive XDP packet-scope timers and output from the device owner with joined accounted cleanup, real policy readers and failed-startup owner cleanup; keep DNS resolver hooks from retaining packet-scope registration budgets.
- Apply scope-local DNS predicates to mixed Core forwarding and fence prepared output against same-generation fact withdrawal, replacement and exact expiry; routed-only Core embeddings now reject domain predicates without a packet fact scope.
- Skip empty passive-accept work before reserving packet TCP/channel capacity, without delaying queued SYN admission behind the receive batch.
- Generate eligible single-frame XDP Endpoint output directly in reserved UMEM, removing one intermediate CPU-IP-frame copy while preserving CPU UDP/DNS, jumbo SG, original flow retention and real CQ ownership; this is not universal zero-copy or a measured performance gain.
- Add opt-in daemon-owned Linux TUN Endpoint capture with explicit resource admission, exact bypass/return routing, blackhole guards and setup receipts; Direct TCP/UDP is a real outbound relay, without HostFacts or Native/captured-return claims.
- Require exact socket marks before TUN service listeners bind/listen, learn standalone DNS facts in the actual packet realm, and preserve joined shutdown with guards retained on failure; device changes require restart while policy updates retain the live FD and scope.
- Preserve ordinary TUN shutdown across concurrent UDP admission and finalize early setup errors; await owned IPv6 local-route readiness before diversion and avoid rejecting strict reverse-path filtering solely by its global value.
