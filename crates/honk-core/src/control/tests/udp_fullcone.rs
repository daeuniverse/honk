use super::support::netns::{
    add_address, build_lab, lab_config, pinned_map, run_isolated, tuples_key,
};
use super::support::shared_udp::{SharedUdpMode, SharedUdpPeer};
use super::support::{QuicUdpMode, QuicUdpPeer};
use super::{NETNS_TEST_TIMEOUT, configure_test_edge, in_test_netns, udp_test_forwarder};
use crate::control::{ControlCommand, ControlPlane};
use crate::daens;
use crate::dns::DnsResolver;
use crate::ebpf::{EbpfBackend, real::RealEbpfBackend};
use crate::routing::Router;
use anyhow::{Context, ensure};
use aya::maps::{Array, HashMap};
use honk_ebpf_common::dae_ip::In6Addr;
use honk_ebpf_common::{RedirectEntry, RedirectTuple};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::UdpSocket;

const CASE: &str = "control::tests::udp_fullcone::netns_udp_full_cone_source_contract";
const CHILD: &str = "HONK_UDP_FULLCONE_CHILD";

#[test]
#[ignore = "requires Linux 5.15+, root, bpffs and eBPF TC support in an isolated VM"]
fn netns_udp_full_cone_source_contract() -> anyhow::Result<()> {
    run_isolated(
        CASE,
        CHILD,
        ["v4", "v6"].into_iter().flat_map(|family| {
            [
                "hy2",
                "tuic-datagram",
                "tuic-stream",
                "ss",
                "socks5",
                "trojan",
                "socks5-source53",
            ]
            .map(|protocol| format!("{family}/{protocol}"))
        }),
        run_child,
    )
}

fn run_child(case: &str) -> anyhow::Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "full-cone acceptance requires root"
    );
    let (family, protocol) = case.split_once('/').context("missing child case family")?;
    let source53 = protocol == "socks5-source53";
    let protocol = if source53 { "socks5" } else { protocol };
    let ips: [&str; 5] = match family {
        "v4" => [
            "10.70.0.1",
            "10.70.0.2",
            "198.51.100.1",
            "198.51.100.2",
            "198.51.100.3",
        ],
        "v6" => ["fd70::1", "fd70::2", "fd71::1", "fd71::2", "fd71::3"],
        _ => anyhow::bail!("unknown family {family}"),
    };
    let [lan_ip, client_ip, wan_ip, server_ip, foreign_ip] =
        ips.map(|ip| ip.parse::<IpAddr>().unwrap());
    let (client_netns, server_netns) = build_lab(lan_ip, wan_ip)?;
    let client = configure_test_edge(
        &client_netns,
        "honk-c0",
        client_ip,
        lan_ip,
        &[if source53 { 53 } else { 0 }],
    )
    .pop()
    .context("client socket")?;
    let mut targets =
        configure_test_edge(&server_netns, "honk-s0", server_ip, wan_ip, &[41001, 41002]);
    let foreign = in_test_netns(&server_netns, || -> anyhow::Result<_> {
        let mut netlink = crate::netlink::NlSock::new()?;
        let (index, _) = netlink.get_link("honk-s0")?;
        add_address(&mut netlink, index, "honk-s0", foreign_ip)?;
        let socket = std::net::UdpSocket::bind(SocketAddr::new(foreign_ip, 41003))?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    })?;
    let target_b = targets.pop().context("target B socket")?;
    let target_a = targets.pop().context("target A socket")?;
    let (_dae0, dae0_setup) = daens::create_dae0_link()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut peer = Peer::start(protocol, SocketAddr::new(wan_ip, 0)).await?;
            let scenario = async {
                let config = lab_config(peer.node());
                let pin_root = Path::new("/sys/fs/bpf/fullcone");
                let local_ip = RealEbpfBackend::test_local_ip(&["honk-lan0"], &["honk-wan0"]);
                let mut backend = RealEbpfBackend::load(
                    crate::DEFAULT_BPF_OBJECT,
                    pin_root,
                    config.global.tproxy_port,
                    &dae0_setup,
                    local_ip,
                )
                .await?;
                backend.bind_test_interfaces(&["honk-lan0"], &["honk-wan0"]);
                backend.attach_dae0_programs()?;
                daens::setup_daens_namespace(config.global.tproxy_mark, config.global.tproxy_port)?;
                backend.attach_sk_lookup()?;
                backend.attach_dae0peer_ingress()?;
                let ready = Array::<_, u32>::try_from(pinned_map(pin_root, "DATAPATH_STATE_MAP")?)?;
                let clients = HashMap::<_, RedirectTuple, RedirectEntry>::try_from(pinned_map(
                    pin_root,
                    "CLIENT_REPLY_TRACK",
                )?)?;
                let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
                let mut control = ControlPlane::new(
                    config,
                    Box::new(backend),
                    router,
                    Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver()?),
                    DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
                    udp_test_forwarder(),
                )?;
                control.set_mode_state(Arc::new(parking_lot::RwLock::new(
                    crate::mode::ModeState::new("Rule", "fullcone"),
                )));
                control.start_datapath_flags_coordinator()?;
                if source53 {
                    // Real ownership lookup must refuse an ordinary socket datagram
                    // with no kernel conn-state, even though port 53 is exempt.
                    let ingress = crate::control::udp_ingress::UdpLoopState::new(&control, true);
                    let destination = SocketAddr::new(server_ip, 41001);
                    ingress
                        .dispatch_datagram_at(
                            b"unowned ordinary UDP",
                            SocketAddr::new(client_ip, 40053),
                            &crate::control::sockets::UdpRecvMeta {
                                original_dst_cmsg: Some(destination),
                                packet_dst_ip: Some(server_ip),
                                packet_ifindex: None,
                                packet_mark: None,
                                packet_priority: None,
                                local_addr: destination,
                            },
                            crate::control::udp_endpoint::queue_now(),
                        )
                        .await;
                    ensure!(
                        control.udp_pool.is_empty(),
                        "unowned ordinary UDP was admitted"
                    );
                }
                let udp_pool = Arc::clone(&control.udp_pool);
                let ebpf = Arc::clone(&control.spawn_handle().ebpf);
                // No probe traffic may create C's association or change route eligibility.
                control.alive_set().shutdown_health_checks().await?;
                let commands = control.command_sender();
                let shutdown = control.shutdown_requested.clone();
                let task = tokio::spawn(async move {
                    let result = control.run().await;
                    (control, result)
                });
                let exercise = async {
                    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
                        while ready.get(&0, 0)? == 0 {
                            ensure!(
                                !task.is_finished(),
                                "control stopped before listener readiness"
                            );
                            tokio::task::yield_now().await;
                        }
                        Ok::<_, anyhow::Error>(())
                    })
                    .await??;
                    let client = UdpSocket::from_std(client)?;
                    let target_a = UdpSocket::from_std(target_a)?;
                    let target_b = UdpSocket::from_std(target_b)?;
                    let foreign = UdpSocket::from_std(foreign)?;
                    let client_addr = client.local_addr()?;
                    let a = target_a.local_addr()?;
                    let b = target_b.local_addr()?;
                    let c = foreign.local_addr()?;
                    let first =
                        send_and_observe(&client, &target_a, &mut peer, b"client-to-A").await?;
                    let second =
                        send_and_observe(&client, &target_b, &mut peer, b"client-to-B").await?;
                    ensure!(
                        first.association == second.association,
                        "A/B used different wire associations"
                    );
                    ensure!(
                        first.mapping == second.mapping,
                        "A/B changed remote UDP mapping"
                    );
                    for destination in [a, b] {
                        ebpf.read()
                            .await
                            .redirect_track_lookup(&redirect_key(client_addr, destination))?
                            .context("contacted target must have exact redirect framing")?;
                    }
                    let mut client_key = redirect_key(client_addr, c);
                    client_key.dst_ip = In6Addr::zero();
                    client_key.dst_port = 0;
                    let framing = clients.get(&client_key, 0)?;
                    ensure!(
                        framing.decision_token == 0 && framing.from_wan == 0,
                        "foreign reply framing must be LAN client-only and token-free"
                    );
                    ensure!(framing.ifindex == crate::netlink::ifindex_of("honk-lan0")?);
                    let c_key = redirect_key(client_addr, c);
                    let forward = tuples_key(client_addr, c, 17);
                    let reverse = tuples_key(c, client_addr, 17);
                    for after_reply in [false, true] {
                        if after_reply {
                            foreign
                                .send_to(b"uncontacted-C-to-client", first.mapping)
                                .await?;
                            receive(&client, c, b"uncontacted-C-to-client").await?;
                        }
                        ensure!(
                            ebpf.read().await.redirect_track_lookup(&c_key)?.is_none(),
                            "C unexpectedly acquired exact redirect framing"
                        );
                        ensure!(
                            ebpf.read().await.conn_state_lookup(&forward)?.is_none(),
                            "foreign reply learned client-to-C UDP state"
                        );
                        ensure!(
                            ebpf.read().await.conn_state_lookup(&reverse)?.is_none(),
                            "foreign reply learned C-to-client UDP state"
                        );
                    }
                    // This is C's first client-originated packet: no reverse bypass is allowed.
                    let cold_payload = if source53 {
                        super::support::dns_query_payload()
                    } else {
                        b"first-client-to-C".to_vec()
                    };
                    let third =
                        send_and_observe(&client, &foreign, &mut peer, &cold_payload).await?;
                    ensure!(
                        third.association == first.association && third.mapping == first.mapping,
                        "first C send did not reuse A/B's association"
                    );
                    foreign.send_to(b"C-after-contact", third.mapping).await?;
                    receive(&client, c, b"C-after-contact").await?;
                    target_a.send_to(b"A-after-C", first.mapping).await?;
                    receive(&client, a, b"A-after-C").await?;
                    if source53 {
                        ensure!(client_addr.port() == 53);
                        // DNS-shaped bytes on a non-53 destination still belong to
                        // the SOCKS transport, never the controller DNS parser.
                        let dns = super::support::dns_query_payload();
                        let packet = send_and_observe(&client, &target_a, &mut peer, &dns).await?;
                        ensure!(packet.association == first.association);
                        for destination in [a, b, c] {
                            for tuple in [
                                tuples_key(client_addr, destination, 17),
                                tuples_key(destination, client_addr, 17),
                            ] {
                                ensure!(
                                    ebpf.read().await.conn_state_lookup(&tuple)?.is_none(),
                                    "stateless source53 traffic created ordinary conn-state"
                                );
                            }
                            ensure!(udp_pool.get(client_addr, destination).is_some());
                            udp_pool.remove(client_addr, destination);
                        }
                        tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
                            while !udp_pool.is_empty() {
                                ensure!(
                                    !task.is_finished(),
                                    "control failed retiring stateless UDP"
                                );
                                tokio::task::yield_now().await;
                            }
                            Ok::<_, anyhow::Error>(())
                        })
                        .await??;
                        for destination in [a, b, c] {
                            for tuple in [
                                tuples_key(client_addr, destination, 17),
                                tuples_key(destination, client_addr, 17),
                            ] {
                                ensure!(
                                    ebpf.read().await.conn_state_lookup(&tuple)?.is_none(),
                                    "stateless retirement acquired ordinary conn-state"
                                );
                            }
                        }
                    }
                    ensure!(
                        !task.is_finished(),
                        "control stopped during full-cone exercise"
                    );
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                shutdown.store(true, Ordering::Release);
                let command = if task.is_finished() {
                    Ok(())
                } else {
                    commands
                        .send(ControlCommand::Shutdown)
                        .await
                        .map_err(anyhow::Error::from)
                };
                // Keep the owner alive through its ordered ingress/source/receiver drain.
                let joined = task.await;
                let (control, stopped) = joined.context("control task panicked")?;
                stopped.context("control shutdown failed")?;
                command?;
                drop(control);
                exercise
            }
            .await;
            let closed = peer.close().await;
            scenario?;
            closed
        })
        .with_context(|| format!("full-cone scenario {case}"))
}

fn redirect_key(source: SocketAddr, destination: SocketAddr) -> RedirectTuple {
    RedirectTuple::from_tuples(&tuples_key(source, destination, 17))
}

async fn receive(
    socket: &UdpSocket,
    expected_source: SocketAddr,
    expected: &[u8],
) -> anyhow::Result<()> {
    let mut buffer = [0; 128];
    let (size, source) =
        tokio::time::timeout(NETNS_TEST_TIMEOUT, socket.recv_from(&mut buffer)).await??;
    ensure!(
        source == expected_source,
        "expected source {expected_source}, got {source}"
    );
    ensure!(&buffer[..size] == expected, "unexpected UDP payload");
    Ok(())
}

async fn send_and_observe(
    client: &UdpSocket,
    target: &UdpSocket,
    peer: &mut Peer,
    payload: &[u8],
) -> anyhow::Result<Observed> {
    let destination = target.local_addr()?;
    client.send_to(payload, destination).await?;
    let packet = tokio::time::timeout(NETNS_TEST_TIMEOUT, peer.next())
        .await?
        .context("peer stopped before observing client packet")?;
    ensure!(
        packet.target == destination && packet.payload == payload,
        "fixture did not observe the exact proxied client packet"
    );
    receive(target, packet.mapping, payload).await?;
    Ok(packet)
}

/// What every fixture reports for one relayed client datagram.
struct Observed {
    /// Equal values mean one wire association (QUIC connection and session, or
    /// the shared protocol's UDP source / control stream).
    association: (u64, u32),
    target: SocketAddr,
    mapping: SocketAddr,
    payload: Vec<u8>,
}

enum Peer {
    Quic(QuicUdpPeer),
    Shared(SharedUdpPeer),
}

impl Peer {
    async fn start(protocol: &str, bind: SocketAddr) -> anyhow::Result<Self> {
        let quic = match protocol {
            "hy2" => Some(QuicUdpMode::Hysteria2),
            "tuic-datagram" => Some(QuicUdpMode::TuicDatagram),
            "tuic-stream" => Some(QuicUdpMode::TuicStream),
            _ => None,
        };
        if let Some(mode) = quic {
            return Ok(Self::Quic(QuicUdpPeer::start(mode, bind).await?));
        }
        let mode = match protocol {
            "ss" => SharedUdpMode::Shadowsocks,
            "socks5" => SharedUdpMode::Socks5,
            "trojan" => SharedUdpMode::Trojan,
            _ => anyhow::bail!("unknown protocol {protocol}"),
        };
        Ok(Self::Shared(SharedUdpPeer::start(mode, bind).await?))
    }

    fn node(&self) -> &honk_config::node::Node {
        match self {
            Self::Quic(peer) => &peer.node,
            Self::Shared(peer) => &peer.node,
        }
    }

    async fn next(&mut self) -> Option<Observed> {
        match self {
            Self::Quic(peer) => peer.packets.recv().await.map(|packet| Observed {
                association: (packet.connection, packet.session),
                target: packet.target,
                mapping: packet.mapping,
                payload: packet.payload,
            }),
            Self::Shared(peer) => peer.packets.recv().await.map(|packet| Observed {
                association: (packet.association, 0),
                target: packet.target,
                mapping: packet.mapping,
                payload: packet.payload,
            }),
        }
    }

    async fn close(self) -> anyhow::Result<()> {
        match self {
            Self::Quic(peer) => peer.close().await,
            Self::Shared(peer) => peer.close().await,
        }
    }
}
