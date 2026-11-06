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
