use super::{
    Attached, Fixture, LIMIT, NAME, NEW_IP, OLD_IP, assert_fact, config, realm, reload, write_hosts,
};
use anyhow::{Context as _, Result, ensure};
use bytes::Bytes;
use honk_ebpf_common::xdp_gateway::{GatewayKey, GatewayReason};
use honk_xsk::GatewayMaps;
use quinn::{
    AsyncUdpSocket, ClientConfig, Connection, Endpoint, Runtime as _, ServerConfig, TokioRuntime,
    UdpPoller, ZeroRttAccepted,
    rustls::{RootCertStore, pki_types::PrivatePkcs8KeyDer},
    udp::{RecvMeta, Transmit},
};
use std::{
    future::poll_fn,
    io::{self, IoSliceMut},
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    process::Command,
    sync::mpsc,
    time::{sleep, timeout},
};

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const OBSERVE_INTERVAL: Duration = Duration::from_millis(5);
const CLEANUP_LIMIT: Duration = Duration::from_secs(5);

fn in_netns<T: Send>(name: &str, bind: impl FnOnce() -> Result<T> + Send) -> Result<T> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let net = std::fs::File::open(format!("/run/netns/{name}"))?;
                nix::sched::setns(net, nix::sched::CloneFlags::CLONE_NEWNET)?;
                bind()
            })
            .join()
            .map_err(|_| anyhow::anyhow!("{name} socket owner panicked"))?
    })
}

fn bind_on(ip: Ipv4Addr, device: &[u8]) -> Result<UdpSocket> {
    let socket = UdpSocket::bind((ip, 0))?;
    socket2::SockRef::from(&socket).bind_device(Some(device))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn tls_configs() -> Result<(ClientConfig, ServerConfig)> {
    let cert = rcgen::generate_simple_self_signed(vec![NAME.into()])?;
    let cert_der = cert.cert.der().clone();
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone())?;
    // Quinn's rustls constructors enable client early data and stateful server tickets.
    let mut client = ClientConfig::with_root_certificates(Arc::new(roots))?;
    let mut server = ServerConfig::with_single_cert(
        vec![cert_der],
        PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )?;
    let mut transport = quinn::TransportConfig::default();
    transport.enable_segmentation_offload(false);
    let transport = Arc::new(transport);
    client.transport_config(transport.clone());
    server.transport_config(transport);
    Ok((client, server))
}

async fn warm(server: &Endpoint, socket: UdpSocket, config: ClientConfig) -> Result<()> {
    let client = Endpoint::new(Default::default(), None, socket, Arc::new(TokioRuntime))?;
    let connecting = client.connect_with(config, server.local_addr()?, NAME)?;
    let connecting = connecting
        .into_0rtt()
        .err()
        .context("cold client had early keys")?;
    let (connection, peer) =
        tokio::try_join!(async { Ok::<_, anyhow::Error>(connecting.await?) }, async {
            Ok::<_, anyhow::Error>(server.accept().await.context("warm Initial")?.await?)
        },)?;
    // A post-handshake server stream puts the ticket on the wire before we retire the warm flow.
    let ticket_barrier = b"ticket";
    let mut marker = peer.open_uni().await?;
    marker.write_all(ticket_barrier).await?;
    marker.finish()?;
    ensure!(
        connection
            .accept_uni()
            .await?
            .read_to_end(ticket_barrier.len())
            .await?
            == ticket_barrier
    );
    peer.close(0u32.into(), b"");
    client.close(0u32.into(), b"");
    tokio::join!(client.wait_idle(), server.wait_idle());
    Ok(())
}

#[derive(Debug)]
struct HeldDatagram {
    bytes: Vec<u8>,
    dest: SocketAddr,
    ecn: Option<quinn::udp::EcnCodepoint>,
    src: Option<std::net::IpAddr>,
}

impl HeldDatagram {
    async fn send(&self, socket: &Arc<dyn AsyncUdpSocket>) -> io::Result<()> {
        let mut writable = socket.clone().create_io_poller();
        let transmit = Transmit {
            destination: self.dest,
            ecn: self.ecn,
            contents: &self.bytes,
            segment_size: None,
            src_ip: self.src,
        };
        poll_fn(|cx| {
            loop {
                ready!(writable.as_mut().poll_writable(cx))?;
                match socket.try_send(&transmit) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    result => return Poll::Ready(result),
                }
            }
        })
        .await
    }

    fn v1_dcid(&self, kind: u8) -> Result<&[u8]> {
        let data = &self.bytes;
        // Long-header type, version and DCID are visible through header protection.
        ensure!(
            data.len() >= 6 && data[0] & 0xb0 == kind && data[1..5] == [0, 0, 0, 1],
            "unexpected Quinn datagram type, wanted v1 long header {kind:#x}"
        );
        data.get(6..6 + usize::from(data[5]))
            .context("QUIC destination CID")
    }
}

#[derive(Debug)]
struct HeldSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    queue: parking_lot::Mutex<Option<mpsc::Sender<HeldDatagram>>>,
}

impl AsyncUdpSocket for HeldSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let queue = self.queue.lock();
        let Some(queue) = queue.as_ref() else {
            return self.inner.try_send(transmit);
        };
        if transmit.segment_size.is_some() {
            return Err(io::Error::other(
                "fixture requires one UDP datagram per transmit",
            ));
        }
        queue
            .try_send(HeldDatagram {
                bytes: transmit.contents.to_vec(),
                dest: transmit.destination,
                ecn: transmit.ecn,
                src: transmit.src_ip,
            })
            .map_err(io::Error::other)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

struct EarlyFlight {
    endpoint: Endpoint,
    socket: Arc<HeldSocket>,
    _held: mpsc::Receiver<HeldDatagram>,
    connection: Connection,
    accepted: ZeroRttAccepted,
    initial: HeldDatagram,
    early: HeldDatagram,
    token: Bytes,
}

impl EarlyFlight {
    async fn capture(socket: UdpSocket, config: ClientConfig, target: SocketAddr) -> Result<Self> {
        let (send, mut held) = mpsc::channel(8);
        let runtime = Arc::new(TokioRuntime);
        let socket = Arc::new(HeldSocket {
            inner: runtime.wrap_udp_socket(socket)?,
            queue: parking_lot::Mutex::new(Some(send)),
        });
        let endpoint =
            Endpoint::new_with_abstract_socket(Default::default(), None, socket.clone(), runtime)?;
        let (connection, mut accepted) =
            endpoint
                .connect_with(config, target, NAME)?
                .into_0rtt()
                .map_err(|_| anyhow::anyhow!("resumption ticket did not supply early keys"))?;
        // Stage distinct UDP datagrams before releasing either one to the bound socket.
        let initial = held.recv().await.context("held Quinn Initial")?;
        let dcid = initial.v1_dcid(0x80)?;
        let token = Bytes::copy_from_slice(&rand::random::<[u8; 16]>());
        connection.send_datagram(token.clone())?;
        let early = held.recv().await.context("held Quinn 0-RTT packet")?;
        ensure!(!dcid.is_empty() && early.v1_dcid(0x90)? == dcid);
        ensure!(initial.dest == target && early.dest == target && initial.bytes != early.bytes);
        ensure!(
            futures::poll!(&mut accepted).is_pending(),
            "handshake completed before wire release"
        );
        Ok(Self {
            endpoint,
            socket,
            _held: held,
            connection,
            accepted,
            initial,
            early,
            token,
        })
    }

    fn report(&self, case: &str, key: GatewayKey) -> Result<()> {
        println!(
            "{case} client={} server={} ingress=dut0 realm={} dcid={} initial_bytes={} initial_sha256={} zero_rtt_bytes={} zero_rtt_sha256={}",
            self.endpoint.local_addr()?,
            self.initial.dest,
            key.realm_id,
            crate::configuration::encode_digest(self.initial.v1_dcid(0x80)?),
            self.initial.bytes.len(),
            crate::configuration::digest(&self.initial.bytes),
            self.early.bytes.len(),
            crate::configuration::digest(&self.early.bytes),
        );
        Ok(())
    }
}

struct WireCounters(String);

impl WireCounters {
    async fn install(target: SocketAddr, native: SocketAddr, revoked: SocketAddr) -> Result<Self> {
        let table = format!("honk_quic_{}", std::process::id());
        let path = format!(
            "iifname dut0 ip saddr {CLIENT} ip daddr {OLD_IP} udp dport {}",
            target.port()
        );
        let native = native.port();
        let revoked = revoked.port();
        nft(&[&format!(
            "create table inet {table}\n\
             add chain inet {table} raw {{ type filter hook prerouting priority -300; policy accept; }}\n\
             add chain inet {table} forward {{ type filter hook forward priority filter; policy accept; }}\n\
             add counter inet {table} native\n\
             add counter inet {table} revoked_raw\n\
             add counter inet {table} revoked_forward\n\
             add rule inet {table} forward oifname dut1 {path} udp sport {native} ct state {{ new, established }} counter name native\n\
             add rule inet {table} raw {path} udp sport {revoked} counter name revoked_raw drop\n\
             add rule inet {table} forward oifname dut1 {path} udp sport {revoked} counter name revoked_forward",
        )])
        .await?;
        Ok(Self(table))
    }

    async fn packets(&self, counter: &str) -> Result<u64> {
        let output = nft(&["-j", "list", "counter", "inet", &self.0, counter]).await?;
        let counters: serde_json::Value = serde_json::from_slice(&output)?;
        counters["nftables"]
            .as_array()
            .context("nft counters")?
            .iter()
            .find(|entry| entry["counter"]["name"] == counter)
            .and_then(|entry| entry["counter"]["packets"].as_u64())
            .with_context(|| format!("missing fixture counter {counter}"))
    }

    async fn wait_packets(&self, counter: &str, count: u64) -> Result<()> {
        loop {
            let packets = self.packets(counter).await?;
            ensure!(
                packets <= count,
                "{counter} saw {packets} packets, expected {count}"
            );
            if packets == count {
                return Ok(());
            }
            sleep(OBSERVE_INTERVAL).await;
        }
    }

    async fn remove(mut self) -> Result<()> {
        nft(&["delete", "table", "inet", &self.0]).await?;
        self.0.clear();
        Ok(())
    }
}

impl Drop for WireCounters {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            let _ = std::process::Command::new("nft")
                .args(["delete", "table", "inet", &self.0])
                .output();
        }
    }
}

async fn nft(args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("nft")
        .args(args)
        .kill_on_drop(true)
        .output()
        .await?;
    ensure!(
        output.status.success(),
        "QUIC fixture nft {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Decisions {
    dns: u64,
    retry: u64,
    conflict: u64,
    ct_original: u64,
    ct_reply: u64,
    endpoint_new: u64,
    endpoint_hold: u64,
}

impl Decisions {
    fn read(maps: &GatewayMaps) -> Result<Self> {
        use GatewayReason::*;
        Ok(Self {
            dns: maps.reason_count(PassDnsD1)?,
            retry: maps.reason_count(PassDnsD1PendingRetry)?,
            conflict: maps.reason_count(DropNativePendingConflict)?,
            ct_original: maps.reason_count(PassCtOriginal)?,
            ct_reply: maps.reason_count(PassCtReply)?,
            endpoint_new: maps.reason_count(XskNewFlow)?,
            endpoint_hold: maps.reason_count(XskEndpointHold)?,
        })
    }
}

fn key(flight: &EarlyFlight, lan: u32) -> Result<GatewayKey> {
    Ok(GatewayKey {
        realm_id: lan,
        family: 4,
        src: CLIENT.to_ipv6_mapped().octets(),
        dst: OLD_IP.to_ipv6_mapped().octets(),
        sport: flight.endpoint.local_addr()?.port().to_be(),
        dport: flight.initial.dest.port().to_be(),
        proto: libc::IPPROTO_UDP as u8,
        reserved: [0; 3],
    })
}

async fn native(
    server: &Endpoint,
    mut flight: EarlyFlight,
    wire: &WireCounters,
    maps: &GatewayMaps,
    lan: u32,
    epoch: u64,
) -> Result<()> {
    let key = key(&flight, lan)?;
    ensure!(
        maps.lookup_hold(&key)?.is_none(),
        "resumed tuple already owned"
    );
    let before = Decisions::read(maps)?;
    flight.initial.send(&flight.socket.inner).await?;
    let incoming = server
        .accept()
        .await
        .context("native Initial on server/s0")?;
    ensure!(incoming.remote_address() == flight.endpoint.local_addr()?);
    ensure!(incoming.local_ip() == Some(flight.initial.dest.ip()));
    ensure!(&*incoming.orig_dst_cid() == flight.initial.v1_dcid(0x80)?);
    ensure!(wire.packets("native").await? == 1);
    let first = Decisions::read(maps)?;
    ensure!(
        first
            == Decisions {
                dns: before.dns + 1,
                ..before
            },
        "Initial decisions {before:?} -> {first:?}"
    );
    ensure!(
        maps.lookup_hold(&key)?
            .is_some_and(|row| row.is_native_pending())
    );

    // Incoming owns the original peer metadata while the server handshake is still gated.
    flight.early.send(&flight.socket.inner).await?;
    wire.wait_packets("native", 2).await?;
    let early = Decisions::read(maps)?;
    ensure!(
        early
            == Decisions {
                ct_original: first.ct_original + 1,
                ..first
            },
        "0-RTT decisions {first:?} -> {early:?}"
    );
    ensure!(
        maps.lookup_hold(&key)?.is_none(),
        "confirmed CT did not take the tuple"
    );
    // Only the two captured datagrams may carry the token before this read completes.
    let (peer, _) = incoming
        .accept()?
        .into_0rtt()
        .map_err(|_| anyhow::anyhow!("server early receive unavailable"))?;
    let received = peer.read_datagram().await?;
    ensure!(
        received == flight.token,
        "peer did not receive the token in the captured 0-RTT datagram"
    );
    ensure!(wire.packets("native").await? == 2);
    *flight.socket.queue.lock() = None;
    ensure!(
        (&mut flight.accepted).await,
        "client did not observe accepted 0-RTT"
    );
    peer.send_datagram(received)?;
    ensure!(
        flight.connection.read_datagram().await? == flight.token,
        "client did not receive early token echo"
    );
    peer.close(0u32.into(), b"");
    flight.endpoint.close(0u32.into(), b"");
    tokio::join!(flight.endpoint.wait_idle(), server.wait_idle());
    let after = Decisions::read(maps)?;
    ensure!(
        (before.endpoint_new, before.endpoint_hold) == (after.endpoint_new, after.endpoint_hold),
        "Endpoint capture during resumed flow: {before:?} -> {after:?}"
    );
    flight.report("quic_0rtt_native", key)?;
    println!(
        "quic_0rtt_native result=PASS dns_epoch={epoch} pass_dns_d1_delta=1 pass_ct_original_early_delta=1 endpoint_redirect_delta=0 forwarded_preaccept=2 peer_ingress=s0 accepted=true echo_sha256={}",
        crate::configuration::digest(&flight.token),
    );
    Ok(())
}

async fn revoke(
    fixture: &mut Fixture,
    hosts: &tempfile::NamedTempFile,
    mut flight: EarlyFlight,
    wire: &WireCounters,
    lan: u32,
    epoch: u64,
) -> Result<()> {
    let attached = Attached::read(fixture)?;
    let bank = attached.bank.context("live DNS bank")?;
    let maps = fixture
        .runtime
        .gateway_maps
        .clone()
        .context("gateway maps")?;
    let key = key(&flight, lan)?;
    ensure!(
        maps.lookup_hold(&key)?.is_none(),
        "revocation tuple already owned"
    );
    let before = Decisions::read(&maps)?;
    flight.initial.send(&flight.socket.inner).await?;
    wire.wait_packets("revoked_raw", 1).await?;
    ensure!(wire.packets("revoked_forward").await? == 0);
    let first = Decisions::read(&maps)?;
    ensure!(
        first
            == Decisions {
                dns: before.dns + 1,
                ..before
            },
        "pre-CT Initial decisions {before:?} -> {first:?}"
    );
    let pending = maps
        .lookup_hold(&key)?
        .context("QUIC Initial did not publish its native hold")?;
    ensure!(pending.is_native_pending());

    write_hosts(hosts, NEW_IP)?;
    let same_policy = fixture.config.clone();
    reload(fixture, same_policy).await?;
    ensure!(Attached::read(fixture)? == attached);
    let withdrawn = bank.epoch(lan)?;
    ensure!(withdrawn > epoch && bank.fact(lan, withdrawn, OLD_IP)?.is_none());
    let published = assert_fact(fixture, bank, lan, NEW_IP).await?;
    ensure!(published >= withdrawn && bank.fact(lan, published, OLD_IP)?.is_none());
    ensure!(maps.lookup_hold(&key)? == Some(pending));

    let before = Decisions::read(&maps)?;
    flight.early.send(&flight.socket.inner).await?;
    let after = loop {
        let observed = Decisions::read(&maps)?;
        if observed != before {
            break observed;
        }
        sleep(OBSERVE_INTERVAL).await;
    };
    ensure!(
        after
            == Decisions {
                conflict: before.conflict + 1,
                ..before
            },
        "post-revocation decisions {before:?} -> {after:?}"
    );
    let retained = maps
        .lookup_hold(&key)?
        .context("revoked datagram retired the pending owner")?;
    ensure!(
        retained.stamp == pending.stamp && retained.last_seen_ns >= pending.last_seen_ns,
        "revoked datagram changed owner or moved activity backwards: {pending:?} -> {retained:?}"
    );
    ensure!(wire.packets("revoked_raw").await? == 1 && wire.packets("revoked_forward").await? == 0);
    ensure!(
        futures::poll!(&mut flight.accepted).is_pending(),
        "fenced client reached a handshake outcome"
    );
    flight.endpoint.close(0u32.into(), b"");
    flight.endpoint.wait_idle().await;
    flight.report("quic_0rtt_revoked", key)?;
    println!(
        "quic_0rtt_revoked result=PASS dns_epoch={epoch}->{published} pending_stamp={} pre_ct_packets=1->1 forwarded=0 drop_native_pending_conflict_delta=1 ct_delta=0 endpoint_redirect_delta=0",
        pending.stamp,
    );
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let hosts = tempfile::NamedTempFile::new()?;
    write_hosts(&hosts, OLD_IP)?;
    let server_socket = in_netns("server", || bind_on(OLD_IP, b"s0"))?;
    let client_sockets = in_netns("client", || {
        Ok([
            bind_on(CLIENT, b"c0")?,
            bind_on(CLIENT, b"c0")?,
            bind_on(CLIENT, b"c0")?,
        ])
    })?;
    // Ticket setup must still work when the production UDP DNS authorization hunk is absent.
    let mut startup = config(&hosts)?;
    let mut warm_policy = honk_config::parser::parse_dae_config(&format!(
        "routing {{ sip({CLIENT}/32) && dip({OLD_IP}/32) && l4proto(udp) && sport({}) && dport({}) -> direct(must)\nfallback: block }}",
        client_sockets[0].local_addr()?.port(),
        server_socket.local_addr()?.port(),
    ))?;
    warm_policy.routing.rules.append(&mut startup.routing.rules);
    startup.routing.rules = warm_policy.routing.rules;
    let mut fixture = timeout(LIMIT, Fixture::start_config(startup))
        .await
        .context("QUIC gateway startup")??;
    let result = exercise(&mut fixture, &hosts, server_socket, client_sockets).await;
    let close = timeout(LIMIT, fixture.finish())
        .await
        .context("QUIC gateway teardown")
        .and_then(|result| result);
    result.and(close)
}

async fn exercise(
    fixture: &mut Fixture,
    hosts: &tempfile::NamedTempFile,
    server_socket: UdpSocket,
    [warm_socket, native_socket, revoke_socket]: [UdpSocket; 3],
) -> Result<()> {
    let (client_config, server_config) = tls_configs()?;
    let server = Endpoint::new(
        Default::default(),
        Some(server_config),
        server_socket,
        Arc::new(TokioRuntime),
    )?;
    let target = server.local_addr()?;
    let wire = timeout(
        CLEANUP_LIMIT,
        WireCounters::install(
            target,
            native_socket.local_addr()?,
            revoke_socket.local_addr()?,
        ),
    )
    .await
    .context("QUIC fixture nft setup")??;
    let result = timeout(LIMIT, async {
        let lan = realm(fixture, "dut0")?;
        let bank = Attached::read(fixture)?.bank.context("live DNS bank")?;
        let epoch = assert_fact(fixture, bank, lan, OLD_IP).await?;
        let maps = fixture
            .runtime
            .gateway_maps
            .clone()
            .context("gateway maps")?;
        fixture
            .drive(warm(&server, warm_socket, client_config.clone()))
            .await
            .context("warm TLS ticket")?;
        fixture
            .drive(async {
                let flight =
                    EarlyFlight::capture(native_socket, client_config.clone(), target).await?;
                native(&server, flight, &wire, &maps, lan, epoch).await
            })
            .await
            .context("accepted QUIC 0-RTT native case")?;
        let flight = EarlyFlight::capture(revoke_socket, client_config, target).await?;
        revoke(fixture, hosts, flight, &wire, lan, epoch)
            .await
            .context("revoked QUIC 0-RTT case")
    })
    .await
    .context("bounded QUIC wire cases")
    .and_then(|result| result);
    server.close(0u32.into(), b"");
    let quic_close = timeout(CLEANUP_LIMIT, server.wait_idle())
        .await
        .context("QUIC peer teardown");
    let wire_close = timeout(CLEANUP_LIMIT, wire.remove())
        .await
        .context("QUIC nft teardown")
        .and_then(|result| result);
    result.and(quic_close).and(wire_close)
}
