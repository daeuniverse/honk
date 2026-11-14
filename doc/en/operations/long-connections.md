# Long connections and keepalive

honk does not synthesize application keepalives. Keeping a transport carrier open does not keep every UDP flow inside it alive.

## UDP: replies keep the endpoint alive

An endpoint retires after 120 s without a reply. Successful sends and carrier keepalives do not reset that timer, so a pure-uplink flow expires even while it sends. The next packet may create a new endpoint if admission permits; old packets are not replayed. A flow that never received a reply settles Score as a timeout. After a delivered reply, later idle retirement is health-neutral and settles Score as success.

Each ordinary no-reply expiry counts as a `DataUdp` health failure. After a node's 60 s registration grace, 50 consecutive counted failures make it unavailable for that probe domain/address family. Only a delivered reply or a successful probe for the same key resets the run; sends alone do not. A shared UDP association reports one no-reply health failure, and only if it sent data and never received a reply. Once another destination has replied, an unreplied view can still expire with a Score timeout. That expiry neither demotes nor retires the whole source. See [health and Score](../design/groups.md).

Kernel state follows its own [UDP idle-renewal rules](../design/datapath.md#udp-lifetime-renewal). A fresh kernel entry does not prevent the userspace reply-idle expiry. Userspace does not keep silent kernel entries fresh. Kernel-state reclamation also retires the endpoint that owns the entry, so the next packet needs a new endpoint. Transport keepalives do not configure external NAT or conntrack state.

New mappings are rejected at the process-wide 32,768-endpoint hard cap, counting both families. A lower startup descriptor or memory budget rejects them earlier: a quarter of `MemTotal` at 64 KiB per endpoint, which is 8,192 endpoints at 2 GiB. honk does not evict existing mappings, and it does not queue rejected datagrams. It also drops the NFQUEUE original packets of rejected datagrams. Check `udp.capacity.rejected` in authenticated Clash `GET /stats`. Raising the service `RLIMIT_NOFILE` helps only while descriptors are the smaller limit. [Slow-path/queue budgets](../design/control-plane.md#queue-and-descriptor-budgets) can reject work earlier.

## TCP: idle is not a relay deadline

Established relays have no general userspace idle timeout; `global.relay_idle_timeout_secs` has no effect. Accepted relays keep their kernel records while they are alive. After the first EOF, the remaining direction ends only after 30 s without byte progress. Connect, sniff and handshake deadlines apply only during setup.

Linux TCP keepalive uses 3600 s idle / 15 s interval / 4 probes on client-facing transparent sockets. Outbound dials and TCP carriers use 15 s / 10 s / 3 probes. A live idle peer can answer indefinitely; probes prove transport reachability, not application progress. See [TCP relay ownership](../design/control-plane.md#tcp-relay-and-conn-state-ownership).

## Carrier keepalives

H2/gRPC sends no periodic HTTP/2 PING. This covers VLESS H2MUX, XHTTP and DNS-over-HTTPS H2. It relies on traffic and TCP keepalive instead. A healthy TCP connection does not guarantee a usable remote application session.

QUIC keepalive intervals are 10 s for Hysteria2/TUIC, 5 s for Juicity, and 15 s for DNS-over-QUIC/HTTP3. TUIC datagram mode also sends heartbeats at its keepalive interval; UDP-over-stream uses only QUIC keepalive.

Hysteria2/TUIC/Juicity reap locally unused connections after 120 s of inactivity. They do not reap a connection that still has active logical users. Peer-negotiated QUIC idle timeouts and remote application policies remain separate. QUIC PINGs and TUIC heartbeats are not replies to encapsulated UDP flows.

## What to check

- Check the last application reply and the terminal outcome, not only upload counters or carrier liveness.
- Tell timer expiry apart from [outbound health gating](../design/datapath.md#outbound-liveness) or capacity rejection.
- Check external firewall/NAT and remote application idle policies separately.
