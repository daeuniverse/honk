//! A client kernel's SYN retry must retain the original publication's incarnation and
//! routing snapshot. Ordinary proxy cases also require the accepted child to forward
//! real payload.

use super::super::support::bytes_of;
use super::*;
use crate::control::routing_matcher::RoutingPushPlan;
use honk_ebpf_common::{OutboundIndex, RedirectEntry};
use std::io::{BufRead, Write};
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) mod native_direct;

const UP: &[u8] = b"client bytes through the original request route";
const DOWN: &[u8] = b"server bytes through the original request route";
// The first SYN retry is due about one second after connect().
const SYN_RETRY_DEADLINE: Duration = Duration::from_secs(5);
const FORWARD_DEADLINE: Duration = Duration::from_secs(10);
const HELPER_TEST: &str =
    "control::tests::tcp_binding::retransmit::netns_tcp_wan_retransmit_client_helper";
const HELPER: &str = "HONK_TCP_BINDING_WAN_CLIENT";
const TAG: &str = "HONK_WAN_CLIENT";

pub(super) fn listen(netns: &OwnedFd, target: SocketAddr) -> anyhow::Result<std::net::TcpListener> {
    in_test_netns(netns, || -> anyhow::Result<_> {
        let listener = std::net::TcpListener::bind(target)?;
        listener.set_nonblocking(true)?;
        Ok(listener)
    })
}

/// Counts the admission, then performs the real marked dial to the server namespace.
#[derive(Debug)]
pub(super) struct ForwardDial(pub(super) Arc<AtomicUsize>);

#[async_trait::async_trait]
impl TcpOutbound for ForwardDial {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.0.fetch_add(1, Ordering::SeqCst);
        super::super::support::netns::KernelTcpDial
            .dial(node, target, domain, timeout)
            .await
    }
}

/// Raw capture inside daens: a SYN seen here already crossed the host production TC.
pub(super) struct SynTap(OwnedFd);

impl SynTap {
    pub(super) fn new() -> anyhow::Result<Self> {
        crate::daens::with_daens_netns("tap daens SYNs", || Ok(Self(packet_socket()?)))
    }

    /// Client pure SYNs toward `target` from `source_ip` since the last call, as
    /// (source port, ISN). Draining consumes every queued frame.
    pub(super) fn drain_syns(
        &self,
        source_ip: IpAddr,
        target: SocketAddr,
    ) -> anyhow::Result<Vec<(u16, u32)>> {
        let mut syns = Vec::new();
        let octets = |ip: IpAddr| match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let (source_ip, target_ip) = (octets(source_ip), octets(target.ip()));
        let mut bytes = [0u8; 2048];
        while let Some(length) = recv_frame(&self.0, &mut bytes)? {
            let Some((src, dst, tcp)) = tcp_segment(&bytes[..length], target.is_ipv6()) else {
                continue;
            };
            if src == source_ip
                && dst == target_ip
                && u16::from_be_bytes([tcp[2], tcp[3]]) == target.port()
                && tcp[13] & 0x12 == 0x02
            {
                syns.push((
                    u16::from_be_bytes([tcp[0], tcp[1]]),
                    u32::from_be_bytes(tcp[4..8].try_into().unwrap()),
                ));
            }
        }
        Ok(syns)
    }

    /// Sequence numbers of client pure SYNs for this connection since the last call.
    pub(super) fn drain(&self, source: SocketAddr, target: SocketAddr) -> anyhow::Result<Vec<u32>> {
        Ok(self
            .drain_syns(source.ip(), target)?
            .into_iter()
            .filter(|(port, _)| *port == source.port())
            .map(|(_, isn)| isn)
            .collect())
    }
}

/// SYNACK capture/replay for a host-originated flow: the daens side of the real reply
/// path, so the replay re-enters the host through dae0's production ingress.
fn daens_wire() -> anyhow::Result<Wire> {
    crate::daens::with_daens_netns("capture dae0peer", || Wire::on("dae0peer"))
}

/// The original SYN's SYNACK, caught while the client gate holds it.
pub(super) async fn gated_synack(
    client: &mut Client,
    wire: &Wire,
    source: SocketAddr,
    target: SocketAddr,
) -> anyhow::Result<Vec<u8>> {
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        tokio::select! {
            result = client.crossed_gate() => anyhow::bail!("client crossed SYNACK gate: {result}"),
            frame = wire.synack(source, target) => frame,
        }
    })
    .await
    .context("original SYNACK deadline")?
}

/// The original SYNACK with the one client SYN that produced it.
async fn original_synack(
    client: &mut Client,
    wire: &Wire,
    tap: &SynTap,
    source: SocketAddr,
    target: SocketAddr,
) -> anyhow::Result<(Vec<u8>, Vec<u32>)> {
    let synack = gated_synack(client, wire, source, target).await?;
    let syns = tap.drain(source, target)?;
    ensure!(
        syns.len() == 1,
        "expected only the original client SYN before the retry, saw {syns:?}"
    );
    Ok((synack, syns))
}

/// Waits for the client's SYN retry, which must reuse the original ISN.
async fn await_retry(
    tap: &SynTap,
    source: SocketAddr,
    target: SocketAddr,
    syns: &mut Vec<u32>,
) -> anyhow::Result<()> {
    tokio::time::timeout(SYN_RETRY_DEADLINE, async {
        while syns.len() < 2 {
            syns.extend(tap.drain(source, target)?);
            if syns.len() < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("client SYN retry never reached the tap")??;
    ensure!(
        syns[1] == syns[0],
        "retry ISN {:#x} differs from the original {:#x}",
        syns[1],
        syns[0]
    );
    Ok(())
}

#[derive(Debug)]
pub(super) struct Lineage {
    pub(super) conn: ConnState,
    pub(super) handoff: RoutingHandoffEntry,
    pub(super) redirect: RedirectEntry,
}

impl Lineage {
    pub(super) async fn read(handle: &ControlPlaneHandle, key: &TuplesKey) -> anyhow::Result<Self> {
        let backend = tokio::sync::RwLockReadGuard::map(handle.ebpf.read().await, |backend| {
            backend.tc().unwrap()
        });
        Ok(Self {
            conn: backend
                .conn_state_lookup(key)?
                .context("conn-state missing")?,
            handoff: backend
                .routing_handoff_lookup(key)?
                .context("routing handoff missing")?,
            redirect: backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(key))?
                .context("redirect missing")?,
        })
    }
}

// Lifecycle timestamps may legitimately refresh; every routing byte may not.
pub(super) fn routing_view(lineage: &Lineage) -> impl PartialEq + '_ {
    let conn = &lineage.conn;
    let (mut handoff, mut redirect) = (lineage.handoff, lineage.redirect);
    handoff.last_seen_ns = 0;
    redirect.last_seen_ns = 0;
    (
        (
            conn.is_wan_ingress_direction,
            conn.decision_token,
            unsafe { conn.meta.raw },
            conn.mac,
            &conn.pname[..],
            conn.pid,
            conn.trace_id,
            conn.incarnation,
        ),
        bytes_of(&handoff).to_vec(),
        bytes_of(&redirect).to_vec(),
    )
}

fn expect(violations: &mut Vec<String>, ok: bool, what: impl FnOnce() -> String) {
    if !ok {
        violations.push(what());
    }
}

fn compare(before: &Lineage, after: &Lineage, violations: &mut Vec<String>) {
    expect(
        violations,
        routing_view(before) == routing_view(after),
        || format!("SYN retry changed the original lineage:\n{before:#?}\n->\n{after:#?}"),
    );
}

fn port_plan(port: u16, outbound: &str, must: bool) -> anyhow::Result<RoutingPushPlan> {
    let mut config = lab_config(&udp_test_node());
    config
        .routing
        .rules
        .push(honk_config::routing::RoutingRule {
            name: "changed-port-route".into(),
            condition: honk_config::routing::RoutingCondition {
                port: vec![port.to_string()],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple(outbound.into()),
            priority: 0,
            must,
            mark: 0,
        });
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
    ControlPlane::compile_routing_plan(&config, &router)
}

fn client_socket(ns: &OwnedFd, ip: IpAddr, gated: bool, reuse: bool) -> anyhow::Result<TcpSocket> {
    in_test_netns(ns, || -> anyhow::Result<_> {
        let socket = if ip.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if reuse {
            socket.set_reuseaddr(true)?;
        }
        socket.bind(SocketAddr::new(ip, 0))?;
        if gated {
            hold_synack(socket.as_raw_fd(), true)?;
        }
        Ok(socket)
    })
}

type Connect = Pin<Box<dyn Future<Output = std::io::Result<TcpStream>>>>;

/// LAN: a client in the client namespace. WAN: a second process in the host/router
/// namespace, so its PID is not the control plane's exemption.
pub(super) enum Client {
    Lan {
        gate: Option<OwnedFd>,
        connect: Connect,
    },
    Wan(Helper),
}

impl Client {
    pub(super) fn lan(
        ns: &OwnedFd,
        ip: IpAddr,
        target: SocketAddr,
        reuse: bool,
    ) -> anyhow::Result<(Self, SocketAddr)> {
        let socket = client_socket(ns, ip, true, reuse)?;
        let source = socket.local_addr()?;
        let gate = Some(socket.as_fd().try_clone_to_owned()?);
        let connect: Connect = Box::pin(socket.connect(target));
        Ok((Self::Lan { gate, connect }, source))
    }

    async fn wan(ip: IpAddr, target: SocketAddr) -> anyhow::Result<(Self, SocketAddr)> {
        let mut helper = Helper::spawn("gated", ip, target)?;
        let source = helper.expect("bound").await?.parse()?;
        Ok((Self::Wan(helper), source))
    }
    pub(super) async fn retry_count(&mut self) -> anyhow::Result<u32> {
        match self {
            Self::Lan { gate, .. } => {
                tcp_retries(gate.as_ref().context("client gate released")?.as_raw_fd())
            }
            Self::Wan(helper) => Ok(helper.expect("retry").await?.parse()?),
        }
    }

    async fn crossed_gate(&mut self) -> String {
        match self {
            Self::Lan { connect, .. } => format!("{:?}", connect.as_mut().await),
            Self::Wan(_) => std::future::pending().await,
        }
    }

    pub(super) fn release(&mut self) -> anyhow::Result<()> {
        match self {
            Self::Lan { gate, .. } => {
                let gate = gate.take().context("SYNACK gate already released")?;
                hold_synack(gate.as_raw_fd(), false)
            }
            Self::Wan(helper) => helper.release(),
        }
    }

    pub(super) async fn handshake(&mut self) -> anyhow::Result<Option<TcpStream>> {
        match self {
            Self::Lan { connect, .. } => Ok(Some(
                tokio::time::timeout(NETNS_TEST_TIMEOUT, connect.as_mut())
                    .await
                    .context("client handshake deadline")?
                    .context("client handshake")?,
            )),
            Self::Wan(_) => Ok(None),
        }
    }

    async fn exchange(&mut self, stream: Option<TcpStream>) -> anyhow::Result<()> {
        match (self, stream) {
            (_, Some(mut stream)) => exchange_stream(&mut stream).await,
            (Self::Wan(helper), None) => {
                helper.expect("done").await?;
                helper.exit()
            }
            (Self::Lan { .. }, None) => anyhow::bail!("LAN client lost its stream"),
        }
    }
}

/// The client half of every relayed exchange: UP out, DOWN back, then a clean close.
async fn exchange_stream(stream: &mut TcpStream) -> anyhow::Result<()> {
    stream.write_all(UP).await?;
    let mut received = vec![0; DOWN.len()];
    stream.read_exact(&mut received).await?;
    ensure!(received == DOWN, "client received the wrong bytes");
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await?;
    ensure!(rest.is_empty(), "relay sent unexpected trailing bytes");
    stream.shutdown().await?;
    Ok(())
}

/// The WAN client process. Its stdout lines carry the fixture's tiny protocol; its
/// stdin line releases the SYNACK gate.
pub(super) struct Helper {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    lines: tokio::sync::mpsc::UnboundedReceiver<String>,
}

impl Helper {
    fn spawn(mode: &str, ip: IpAddr, target: SocketAddr) -> anyhow::Result<Self> {
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args([HELPER_TEST, "--ignored", "--exact", "--nocapture"])
            .env(HELPER, format!("{mode} {ip} {target}"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .context("spawn WAN client process")?;
        let stdout = child.stdout.take().context("helper stdout")?;
        let stdin = child.stdin.take();
        let (sender, lines) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                if let Some(rest) = line.strip_prefix(TAG) {
                    let _ = sender.send(rest.trim().to_owned());
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines,
        })
    }

    async fn expect(&mut self, prefix: &str) -> anyhow::Result<String> {
        loop {
            let line = tokio::time::timeout(FORWARD_DEADLINE, self.lines.recv())
                .await
                .with_context(|| format!("WAN client never reported {prefix}"))?
                .with_context(|| format!("WAN client exited before reporting {prefix}"))?;
            if let Some(rest) = line.strip_prefix(prefix) {
                return Ok(rest.trim().to_owned());
            }
        }
    }

    fn release(&mut self) -> anyhow::Result<()> {
        let mut stdin = self.stdin.take().context("WAN client already released")?;
        writeln!(stdin)?;
        Ok(())
    }

    fn exit(&mut self) -> anyhow::Result<()> {
        let status = self.child.wait()?;
        ensure!(status.success(), "WAN client process failed: {status}");
        Ok(())
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "helper process of the WAN SYN retransmission regression"]
fn netns_tcp_wan_retransmit_client_helper() -> anyhow::Result<()> {
    let Some(spec) = std::env::var_os(HELPER) else {
        return Ok(());
    };
    let spec = spec
        .into_string()
        .map_err(|_| anyhow::anyhow!("invalid helper spec"))?;
    let parts: Vec<_> = spec.split(' ').collect();
    let [mode, ip, target] = parts.as_slice() else {
        anyhow::bail!("malformed helper spec {spec:?}")
    };
    let (gated, ip, target) = (*mode == "gated", ip.parse::<IpAddr>()?, target.parse()?);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let socket = if ip.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            socket.bind(SocketAddr::new(ip, 0))?;
            if gated {
                hold_synack(socket.as_raw_fd(), true)?;
            }
            let gate = socket.as_fd().try_clone_to_owned()?;
            let fd = gate.as_raw_fd();
            println!("{TAG} bound {}", socket.local_addr()?);
            let mut release = tokio::task::spawn_blocking(|| {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).map(|_| line)
            });
            let mut connect = Box::pin(socket.connect(target));
            if gated {
                let mut reported_retry = false;
                loop {
                    tokio::select! {
                        result = &mut connect => anyhow::bail!("helper crossed SYNACK gate: {result:?}"),
                        line = &mut release => {
                            line??;
                            hold_synack(fd, false)?;
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(100)), if !reported_retry => {
                            let count = tcp_retries(fd)?;
                            if count != 0 {
                                println!("{TAG} retry {count}");
                                reported_retry = true;
                            }
                        }
                    }
                }
            }
            let mut stream = tokio::time::timeout(FORWARD_DEADLINE, connect)
                .await
                .context("helper handshake deadline")??;
            if !gated {
                println!("{TAG} connected");
                release.await??;
                return Ok(());
            }
            exchange_stream(&mut stream).await?;
            println!("{TAG} done");
            Ok::<_, anyhow::Error>(())
        })
}

pub(super) fn lan(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Forward, async |lab| {
        proxy(lab, false, false).await
    })
}

pub(super) fn lan_policy(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Forward, async |lab| {
        proxy(lab, false, true).await
    })
}

pub(super) fn wan(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Forward, async |lab| {
        proxy(lab, true, false).await
    })
}

pub(super) fn wan_policy(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Forward, async |lab| {
        proxy(lab, true, true).await
    })
}

/// Both families' proxy cases: the client SYN retries with its SYNACK gated, and the
/// original publication's route must survive; `policy` republishes routing before the retry.
async fn proxy(lab: &Lab, wan: bool, policy: bool) -> anyhow::Result<()> {
    let (handle, listener, target, dials) = (&lab.handle, &lab.listener, lab.target, &lab.dials);
    let (client_ns, client, wan_ip) = (&lab.client_ns, lab.client, lab.wan);
    let server = lab.server()?;
    let tap = SynTap::new()?;
    let wire = if wan {
        daens_wire()?
    } else {
        Wire::on("honk-lan0")?
    };
    let (mut client_side, source) = if wan {
        Client::wan(wan_ip, target).await?
    } else {
        Client::lan(client_ns, client, target, false)?
    };
    let (synack, mut syns) = original_synack(&mut client_side, &wire, &tap, source, target).await?;
    let isn = syns[0];
    let key = conn_key(source, target);

    // The original SYN's publication is real; the client then retries with SYNACK gated.
    let original = Lineage::read(handle, &key).await?;
    let incarnation = original.conn.incarnation;
    ensure!(
        incarnation != 0
            && original.conn.tcp_syn_isn == isn
            && original.handoff.incarnation == incarnation
            && original.redirect.incarnation == incarnation,
        "original SYN did not publish one coherent incarnation: {original:?}"
    );

    let mut new_generation = 0;
    if policy {
        let plan = port_plan(target.port(), "block", false)?;
        let mut backend =
            tokio::sync::RwLockWriteGuard::map(handle.ebpf.write().await, |backend| {
                backend.tc_mut().unwrap()
            });
        let old = backend.routing_policy_generation();
        backend.publish_routing_plan(&plan, &[])?;
        new_generation = backend.routing_policy_generation();
        drop(backend);
        ensure!(
            new_generation != old,
            "policy publication kept generation {old}"
        );
        syns.extend(tap.drain(source, target)?);
        ensure!(
            syns.len() == 1,
            "client retried before the new policy was published: {syns:?}"
        );
    }

    await_retry(&tap, source, target, &mut syns).await?;

    // The retry already crossed host TC: this read follows its publication decision.
    let retry = Lineage::read(handle, &key).await?;
    let mut violations = Vec::new();
    compare(&original, &retry, &mut violations);

    let outcome = async {
        client_side.release()?;
        wire.replay(&synack)?;
        let client_stream = client_side.handshake().await?;
        let (accepted, peer) = tokio::time::timeout(NETNS_TEST_TIMEOUT, listener.accept())
            .await
            .context("accept deadline")??;
        ensure!(
            peer == source && accepted.local_addr()? == target,
            "wrong transparent socket endpoints"
        );
        let ownership = handle
            .ebpf
            .read()
            .await
            .tc().unwrap().tcp_socket_ownership(accepted.as_fd());
        let binding = match ownership {
            Ok(TcpSocketOwnership::Kernel(binding)) => binding,
            Ok(TcpSocketOwnership::Model) => anyhow::bail!("real backend returned model ownership"),
            Err(error) => {
                violations.push(format!("accepted FD has no native ownership: {error:#}"));
                return Ok(());
            }
        };
        expect(
            &mut violations,
            binding.handoff.incarnation == incarnation && binding.syn_isn == isn,
            || format!("accepted FD proves a different SYN: {binding:?}"),
        );
        expect(
            &mut violations,
            bytes_of(&binding.tuples) == bytes_of(&key),
            || "accepted FD proves different endpoints".into(),
        );
        let (mut proven, mut published) = (binding.handoff, original.handoff);
        proven.last_seen_ns = 0;
        published.last_seen_ns = 0;
        expect(
            &mut violations,
            bytes_of(&proven) == bytes_of(&published),
            || {
                format!(
                    "accepted FD handoff differs from the original publication: {proven:?} vs {published:?}"
                )
            },
        );
        if !violations.is_empty() {
            return Ok(());
        }

        // Real adoption, dial and relay: the child must carry the original route to
        // the real server, not merely be admitted.
        let pins = HashMap::<_, u64, u8>::try_from(pinned_map(Path::new(ROOT), "TCP_LIVE_PINS")?)?;
        ensure!(
            pins.get(&incarnation, 0).is_err(),
            "unadopted child was pinned"
        );
        let upstream = async {
            let (mut stream, upstream_peer) = server.accept().await?;
            ensure!(
                upstream_peer != source,
                "upstream saw the client, not the relay"
            );
            let mut received = vec![0; UP.len()];
            stream.read_exact(&mut received).await?;
            ensure!(received == UP, "upstream received the wrong bytes");
            ensure!(
                pins.get(&incarnation, 0)? == 1,
                "live relay lacks its exact native pin"
            );
            stream.write_all(DOWN).await?;
            stream.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        let (relayed, upstream, user) = tokio::join!(
            tokio::time::timeout(FORWARD_DEADLINE, handle.serve_connection(accepted, peer)),
            tokio::time::timeout(FORWARD_DEADLINE, upstream),
            tokio::time::timeout(FORWARD_DEADLINE, client_side.exchange(client_stream)),
        );
        relayed.context("relay deadline")?.context("relay")?;
        upstream.context("upstream deadline")?.context("upstream")?;
        user.context("client deadline")?.context("client")?;
        ensure!(
            dials.load(Ordering::SeqCst) == 1,
            "expected exactly one outbound admission, saw {}",
            dials.load(Ordering::SeqCst)
        );
        tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
            while pins.get(&incarnation, 0).is_ok() || handle.tcp_flow_pins.contains(&key) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .context("exact native/local pin outlived the relay")?;

        if policy {
            if wan {
                let mut helper = Helper::spawn("fresh", wan_ip, target)?;
                let fresh_source: SocketAddr = helper.expect("bound").await?.parse()?;
                let fresh_key = conn_key(fresh_source, target);
                tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
                    loop {
                        if let Some(state) = handle.ebpf.read().await.tc().unwrap().conn_state_lookup(&fresh_key)? {
                            let raw = unsafe { state.meta.raw };
                            if raw & honk_ebpf_common::ROUTING_META_FLAG_PUBLISHED != 0 {
                                ensure!(raw as u8 == OutboundIndex::Block as u8,
                                    "fresh WAN tuple retained the old route: {state:?}");
                                return Ok::<_, anyhow::Error>(());
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }).await.context("fresh WAN tuple never reached the new policy")??;
                return Ok(());
            }
            let socket = client_socket(client_ns, client, false, false)?;
            let (_stream, accepted) = tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
                tokio::join!(socket.connect(target), listener.accept())
            }).await.context("fresh tuple handshake deadline")?;
            let _stream = _stream.context("fresh tuple client handshake")?;
            let fresh = accepted.context("fresh tuple accept")?.0;
            let TcpSocketOwnership::Kernel(fresh_binding) = handle
                .ebpf
                .read()
                .await
                .tc().unwrap().tcp_socket_ownership(fresh.as_fd())?
            else {
                anyhow::bail!("real backend returned model ownership")
            };
            ensure!(
                fresh_binding.handoff.result.outbound == OutboundIndex::Block as u8
                    && fresh_binding.handoff.routing_generation == new_generation
                    && new_generation != original.handoff.routing_generation,
                "a fresh tuple did not use the newly published policy: {fresh_binding:?}"
            );
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;

    match (violations.is_empty(), outcome) {
        (true, outcome) => outcome,
        (false, outcome) => anyhow::bail!(
            "SYN retransmit lineage violated (ISN {isn:#x}, original incarnation {incarnation:#x}):\n- {}\nafterwards: {}",
            violations.join("\n- "),
            outcome
                .err()
                .map_or("completed".into(), |e| format!("{e:#}"))
        ),
    }
}

fn tcp_retries(fd: std::os::fd::RawFd) -> anyhow::Result<u32> {
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&info) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut libc::tcp_info).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        length as usize >= std::mem::offset_of!(libc::tcp_info, tcpi_total_retrans) + 4,
        "TCP_INFO lacks the client retransmission counter"
    );
    Ok(info.tcpi_total_retrans)
}
