use super::support::netns::{KernelTcpDial, build_lab, lab_config, pinned_map, run_isolated};
use super::{
    NETNS_TEST_TIMEOUT, configure_test_edge, in_test_netns, udp_test_forwarder, udp_test_node,
};
use crate::control::{ControlCommand, ControlPlane};
use crate::daens;
use crate::dns::DnsResolver;
use crate::ebpf::{EbpfBackend, real::RealEbpfBackend};
use crate::routing::Router;
use anyhow::{Context, ensure};
use aya::maps::Array;
use honk_outbound::proxy::{ProtocolEntry, ProxyRegistry};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};

const CASE: &str = "control::tests::tcp_tuple_reuse::netns_tcp_reuses_tuple_during_daens_time_wait";
const CHILD: &str = "HONK_TCP_TUPLE_REUSE_CHILD";
const REQUESTS: [&[u8]; 2] = [b"first-transparent-request", b"reused-tuple-request"];
const REPLIES: [&[u8]; 2] = [b"first-server-active-close", b"second-server-active-close"];

#[test]
#[ignore = "requires Linux 6.12+, root, bpffs and eBPF TC support in an isolated VM"]
fn netns_tcp_reuses_tuple_during_daens_time_wait() -> anyhow::Result<()> {
    run_isolated(CASE, CHILD, ["v4", "v6"], run_child)
}

fn run_child(family: &str) -> anyhow::Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "TCP tuple reuse requires root"
    );
    let ips = match family {
        "v4" => ["10.70.0.1", "10.70.0.2", "198.51.100.1", "198.51.100.2"],
        "v6" => ["fd70::1", "fd70::2", "fd71::1", "fd71::2"],
        _ => anyhow::bail!("unknown family {family}"),
    };
    let [lan_ip, client_ip, wan_ip, server_ip] = ips.map(|ip| ip.parse::<IpAddr>().unwrap());
    let (client_ns, server_ns) = build_lab(lan_ip, wan_ip)?;
    // An empty port list configures the existing edge fixture without UDP sockets.
    configure_test_edge(&client_ns, "honk-c0", client_ip, lan_ip, &[]);
    configure_test_edge(&server_ns, "honk-s0", server_ip, wan_ip, &[]);
    let listener = in_test_netns(&server_ns, || -> anyhow::Result<_> {
        let listener = std::net::TcpListener::bind(SocketAddr::new(server_ip, 41001))?;
        listener.set_nonblocking(true)?;
        Ok(listener)
    })?;
    let target = listener.local_addr()?;
    let (_dae0, dae0_setup) = daens::create_dae0_link()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let config = lab_config(&udp_test_node());
            let pin_root = Path::new("/sys/fs/bpf/tcp-tuple-reuse");
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
            let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
            let mut registry = ProxyRegistry::new();
            registry.register(ProtocolEntry::new(
                honk_config::types::NodeProtocol::Socks5,
                Arc::new(KernelTcpDial),
            ));
            let mut control = ControlPlane::new(
                config,
                Box::new(backend),
                router,
                Arc::new(registry),
                DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
                udp_test_forwarder(),
            )?;
            control.set_mode_state(Arc::new(parking_lot::RwLock::new(
                crate::mode::ModeState::new("Rule", "fullcone"),
            )));
            control.start_datapath_flags_coordinator()?;
            control.alive_set().shutdown_health_checks().await?;
            let commands = control.command_sender();
            let shutdown = control.shutdown_requested.clone();
            let task = tokio::spawn(async move {
                let result = control.run().await;
                (control, result)
            });
            let listener = TcpListener::from_std(listener)?;
            let server = tokio::spawn(async move {
                for (request, reply) in REQUESTS.into_iter().zip(REPLIES) {
                    let (mut stream, source) = listener.accept().await?;
                    ensure!(
                        source.ip() == wan_ip,
                        "exchange bypassed the transparent relay"
                    );
                    let mut received = vec![0; request.len()];
                    stream.read_exact(&mut received).await?;
                    ensure!(received == request, "server received the wrong request");
                    stream.write_all(reply).await?;
                    // Upstream closes first; the relay must actively close its daens child.
                    stream.shutdown().await?;
                }
                Ok::<_, anyhow::Error>(())
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
                let source = exchange(&client_ns, SocketAddr::new(client_ip, 0), target, 0)
                    .await
                    .context("first transparent TCP exchange")?;
                tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
                    loop {
                        let time_wait = daens::with_daens_netns("observe exact TIME_WAIT", || {
                            tuple_state(target, source)
                        })?;
                        let client_closed =
                            in_test_netns(&client_ns, || tuple_state(source, target))?;
                        if time_wait.as_deref() == Some("06") && client_closed.is_none() {
                            break;
                        }
                        ensure!(
                            !task.is_finished(),
                            "control stopped while awaiting TIME_WAIT"
                        );
                        tokio::task::yield_now().await;
                    }
                    Ok::<_, anyhow::Error>(())
                })
                .await
                .context("exact first tuple never reached daens TIME_WAIT with client closed")??;
                let reused = exchange(&client_ns, source, target, 1)
                    .await
                    .context("second transparent exchange reusing the live TIME_WAIT tuple")?;
                ensure!(
                    reused == source,
                    "second connection changed its client tuple"
                );
                ensure!(!task.is_finished(), "control stopped during tuple reuse");
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if exercise.is_err() {
                server.abort();
            }
            let served = tokio::time::timeout(NETNS_TEST_TIMEOUT, server).await;
            shutdown.store(true, Ordering::Release);
            let command = if task.is_finished() {
                Ok(())
            } else {
                commands
                    .send(ControlCommand::Shutdown)
                    .await
                    .map_err(anyhow::Error::from)
            };
            let (control, stopped) = task.await.context("control task panicked")?;
            stopped.context("control shutdown failed")?;
            command?;
            drop(control);
            exercise?;
            served.context("server did not finish both exchanges")??
        })
        .with_context(|| format!("TCP tuple reuse {family}"))
}

async fn exchange(
    client_ns: &OwnedFd,
    source: SocketAddr,
    target: SocketAddr,
    index: usize,
) -> anyhow::Result<SocketAddr> {
    let socket = in_test_netns(client_ns, || -> anyhow::Result<_> {
        let socket = if source.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        socket.bind(source)?;
        Ok(socket)
    })?;
    let source = socket.local_addr()?;
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        let mut stream = socket
            .connect(target)
            .await
            .context("client TCP handshake")?;
        ensure!(stream.local_addr()? == source && stream.peer_addr()? == target);
        stream
            .write_all(REQUESTS[index])
            .await
            .context("write client request")?;
        let mut reply = Vec::new();
        // Do not send FIN first: EOF proves the peer actively closed before us.
        stream
            .read_to_end(&mut reply)
            .await
            .context("read client reply through EOF")?;
        ensure!(reply == REPLIES[index], "client received the wrong reply");
        stream.shutdown().await?;
        Ok::<_, anyhow::Error>(source)
    })
    .await?
}

// /proc exposes each address as native-endian 32-bit words, including tcp6.
fn proc_endpoint(address: SocketAddr) -> String {
    let ip = match address.ip() {
        IpAddr::V4(ip) => format!("{:08X}", u32::from_ne_bytes(ip.octets())),
        IpAddr::V6(ip) => ip
            .octets()
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| format!("{:08X}", u32::from_ne_bytes(*word)))
            .collect::<String>(),
    };
    format!("{ip}:{:04X}", address.port())
}

fn tuple_state(local: SocketAddr, remote: SocketAddr) -> anyhow::Result<Option<String>> {
    let table = if local.is_ipv4() { "tcp" } else { "tcp6" };
    let entries = std::fs::read_to_string(format!("/proc/thread-self/net/{table}"))?;
    let local = proc_endpoint(local);
    let remote = proc_endpoint(remote);
    Ok(entries.lines().skip(1).find_map(|line| {
        let mut fields = line.split_ascii_whitespace().skip(1);
        let (entry_local, entry_remote, state) = (fields.next()?, fields.next()?, fields.next()?);
        (entry_local == local && entry_remote == remote).then(|| state.to_owned())
    }))
}
