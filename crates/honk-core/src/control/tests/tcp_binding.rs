//! Real SYN/accepted-FD proof. Packet replay only releases a captured SYNACK or replays a
//! captured SYN; every SYN and the final ACK traverse the production TC and sock_ops hook.

use super::support::TestRetirement;
use super::support::netns::{
    build_lab, lab_config, pinned_hash_snapshot, pinned_map, run_isolated,
};
use super::support::wire::{
    Wire, hold_synack, packet_socket, recv_frame, syn_isn, tcp_segment, with_source_port,
    with_syn_isn,
};
use super::{
    NETNS_TEST_TIMEOUT, configure_test_edge, fresh_test_netns, in_test_netns, udp_test_forwarder,
    udp_test_node,
};
use crate::control::{ControlPlane, ControlPlaneHandle};
use crate::daens;
use crate::dns::DnsResolver;
use crate::ebpf::{EbpfBackend, TcpSocketOwnership, real::RealEbpfBackend};
use crate::routing::Router;
use anyhow::{Context, ensure};
use aya::maps::{Array, HashMap};
use honk_config::node::Node;
use honk_ebpf_common::{
    FlowMapValue, RedirectEntry, RedirectTuple,
    conn::{ConnState, FlowIncarnationSequence, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS},
    redirect_need::{RoutingHandoffEntry, TCP_BINDING_CHILD, TuplesKey},
};
use honk_outbound::proxy::{ProtocolEntry, ProxyRegistry, ProxyStream, TcpOutbound};
use maps::{
    MAP_LOCK, await_conn, conn_map, handoff_map, mutate_conn, mutate_handoff, redirect_map,
};
use retransmit::{Client, Lineage, SynTap, gated_synack, routing_view};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use tokio::net::{TcpListener, TcpSocket, TcpStream};

mod callback;
mod lifetime;
mod maps;
mod retransmit;
mod syn_state;

const CHILD: &str = "HONK_TCP_BINDING_CHILD";
const ROOT: &str = "/sys/fs/bpf/tcp-binding";
const FIRST_PUBLISHED_INCARNATION: u64 = 0x005a_1234_5678_9abc;

/// What the lab's outbound consumer and retirement worker look like.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// Counts the admission and refuses the dial.
    Proxy,
    /// Counts the admission, then really dials a server in the server namespace.
    Forward,
    /// As `Proxy`, but the case runs its own retirement worker.
    Manual,
}

// Cases whose branch is family-independent (shared TC/userspace code, no v4/v6 ctx read or
// socket lookup of its own) run once on v4; `accepted`, the absent-owner and the full-child
// cases cover both families.
macro_rules! kernel_case {
    ($name:ident, [$($family:literal),+], $case:path) => {
        #[test]
        #[ignore = "requires Linux 6.12+, root and the disposable kernel VM gate"]
        fn $name() -> anyhow::Result<()> {
            run_isolated(
                concat!("control::tests::tcp_binding::", stringify!($name)),
                CHILD,
                [$($family),+],
                $case,
            )
        }
    };
}

// Ablate the sock_ops child storage CREATE or the TC SYN publication it proves.
kernel_case!(
    netns_tcp_accepted_fd_proves_original_syn,
    ["v4", "v6"],
    accepted
);
// Ablate adopt_tcp_flow's binding/current incarnation equality.
kernel_case!(
    netns_tcp_queued_closed_child_cannot_adopt_newer_tuple,
    ["v4"],
    queued_closed_child
);
// Ablate the callback's read of the live incarnation: the child binds the replacement.
kernel_case!(
    netns_tcp_superseded_syn_binds_replacement_incarnation,
    ["v4"],
    superseded_syn
);
// Ablate the callback's age check of the live handoff.
kernel_case!(
    netns_tcp_aged_handoff_leaves_child_unproven,
    ["v4", "v6"],
    aged_handoff
);
// Ablate one callback predicate at a time (ISN, ORIGINAL_INTERCEPT, handoff).
kernel_case!(
    netns_tcp_callback_rejects_each_invalid_publication,
    ["v4"],
    callback::predicates
);
// Restore an Active requirement in the callback: a FIN before the final ACK unproves the child.
kernel_case!(
    netns_tcp_closing_publication_still_proves_child,
    ["v4"],
    callback::closing
);
// Ablate the callback's netns guard.
kernel_case!(
    netns_tcp_foreign_netns_twin_is_not_proven,
    ["v4"],
    callback::foreign_twin
);
// A cookie-created child still binds from the final ACK's sequence number.
kernel_case!(
    netns_tcp_forced_syn_cookie_child_is_proven,
    ["v4", "v6"],
    cookie_child
);
// Ablate the storage-failure fail-closed path: no tuple authority may replace the proof.
kernel_case!(
    netns_tcp_child_storage_allocation_failure_fails_closed,
    ["v4"],
    child_storage_full
);

// SYN classification once the request is not read: each case pins the exact action.
kernel_case!(
    netns_tcp_absent_owner_after_request_history_is_cached,
    ["v4", "v6"],
    syn_state::absent_after_history
);
kernel_case!(
    netns_tcp_request_a_fresh_b_cached_b_leaves_ack_a_unproven,
    ["v4"],
    syn_state::request_a_then_b
);
kernel_case!(
    netns_tcp_stale_publication_gets_fresh_syn,
    ["v4"],
    syn_state::stale
);
kernel_case!(
    netns_tcp_missing_handoff_refuses_syn,
    ["v4"],
    syn_state::missing_handoff
);
kernel_case!(
    netns_tcp_missing_redirect_refuses_syn,
    ["v4"],
    syn_state::missing_redirect
);
kernel_case!(
    netns_tcp_closing_tuple_same_isn_gets_fresh_syn,
    ["v4"],
    syn_state::closing
);
// Ablate the live-pin branch: the existing superseding_syn case reaches Fresh through
// Closing and a new ISN instead.
kernel_case!(
    netns_tcp_pinned_tuple_same_isn_gets_fresh_syn,
    ["v4"],
    lifetime::pinned_same_isn
);
kernel_case!(
    netns_tcp_full_child_syn_follows_stored_isn,
    ["v4", "v6"],
    syn_state::full_child
);
kernel_case!(
    netns_tcp_full_child_without_storage_refuses_syn,
    ["v4", "v6"],
    syn_state::full_child_unproven
);

// Ablate the cold native-pin consult in auxiliary/Closing age refusal.
kernel_case!(
    netns_tcp_live_pin_survives_redirect_age,
    ["v4", "v6"],
    lifetime::idle
);
kernel_case!(
    netns_tcp_client_half_close_survives_closing_age,
    ["v4", "v6"],
    lifetime::client_fin
);
kernel_case!(
    netns_tcp_server_half_close_survives_redirect_age,
    ["v4", "v6"],
    lifetime::server_fin
);
kernel_case!(
    netns_tcp_unowned_redirect_age_refuses_without_deletion,
    ["v4", "v6"],
    lifetime::unowned_redirect
);
kernel_case!(
    netns_tcp_unowned_closing_age_refuses_without_deletion,
    ["v4", "v6"],
    lifetime::unowned_closing
);
kernel_case!(
    netns_tcp_other_incarnation_pin_cannot_rescue_aged_tuple,
    ["v4", "v6"],
    lifetime::other_incarnation
);
kernel_case!(
    netns_tcp_duplicate_admission_and_cancel_release_exact_pin,
    ["v4", "v6"],
    lifetime::cancel
);
kernel_case!(
    netns_tcp_superseding_syn_cannot_inherit_old_live_pin,
    ["v4", "v6"],
    lifetime::new_syn
);
kernel_case!(
    netns_tcp_native_pin_drop_error_reaches_current_worker_epoch,
    ["v4", "v6"],
    lifetime::pin_drop_error
);
kernel_case!(
    netns_tcp_native_pin_retirement_error_is_unconfirmed_once,
    ["v4", "v6"],
    lifetime::pin_retire_error
);

// Ablate the shared fresh-versus-cached SYN classification: a client retry must
// neither mint a new incarnation nor replace the original publication's route.
kernel_case!(
    netns_tcp_retransmitted_syn_keeps_original_incarnation_and_route,
    ["v4", "v6"],
    retransmit::lan
);
// Same, with a different real routing policy published before the retry.
kernel_case!(
    netns_tcp_retransmitted_syn_keeps_original_route_after_policy_change,
    ["v4", "v6"],
    retransmit::lan_policy
);
// WAN is a genuine second process in the router namespace: this test process is the
// control plane, whose PID the datapath deliberately exempts.
kernel_case!(
    netns_tcp_wan_retransmitted_syn_keeps_original_incarnation_and_route,
    ["v4", "v6"],
    retransmit::wan
);
kernel_case!(
    netns_tcp_wan_retransmitted_syn_keeps_original_route_after_policy_change,
    ["v4", "v6"],
    retransmit::wan_policy
);
kernel_case!(
    netns_tcp_native_direct_syn_retry_reaches_server,
    ["v4", "v6"],
    retransmit::native_direct::lan
);
kernel_case!(
    netns_tcp_wan_native_direct_syn_retry_reaches_server,
    ["v4", "v6"],
    retransmit::native_direct::wan
);

kernel_case!(
    netns_tcp_namespace_disables_handshake_shortcuts,
    ["v4", "v6"],
    namespace
);

#[derive(Debug)]
struct CountDial(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl TcpOutbound for CountDial {
    async fn dial(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _domain: Option<&str>,
        _timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.0.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("binding regression reached the outbound consumer")
    }
}

/// The namespaces and addresses of one family's lab.
struct Net {
    client_ns: OwnedFd,
    server_ns: OwnedFd,
    server: Option<std::net::TcpListener>,
    client: IpAddr,
    wan: IpAddr,
    target: SocketAddr,
}

impl Net {
    fn build(family: &str, kind: Kind) -> anyhow::Result<Self> {
        let ips = match family {
            "v4" => ["10.72.0.1", "10.72.0.2", "198.51.100.1", "198.51.100.2"],
            "v6" => ["fd72::1", "fd72::2", "fd73::1", "fd73::2"],
            _ => anyhow::bail!("unknown family {family}"),
        };
        let [lan, client, wan, destination] = ips.map(|ip| ip.parse::<IpAddr>().unwrap());
        let (client_ns, server_ns) = build_lab(lan, wan)?;
        configure_test_edge(&client_ns, "honk-c0", client, lan, &[]);
        configure_test_edge(&server_ns, "honk-s0", destination, wan, &[]);
        let target = SocketAddr::new(destination, 41002);
        let server = (kind == Kind::Forward)
            .then(|| retransmit::listen(&server_ns, target))
            .transpose()?;
        Ok(Self {
            client_ns,
            server_ns,
            server,
            client,
            wan,
            target,
        })
    }
}

/// The booted production control plane over the real datapath, with the transparent
/// listener of the client's family.
struct Lab {
    handle: ControlPlaneHandle,
    _plane: ControlPlane,
    dials: Arc<AtomicUsize>,
    listener: TcpListener,
    server: Option<TcpListener>,
    client_ns: OwnedFd,
    server_ns: OwnedFd,
    client: IpAddr,
    wan: IpAddr,
    target: SocketAddr,
}

impl Lab {
    async fn boot(
        net: Net,
        kind: Kind,
        dae0: &daens::Dae0Setup,
    ) -> anyhow::Result<(Self, Option<TestRetirement>)> {
        let object = std::env::var_os("HONK_TEST_BPF_OBJECT")
            .map(std::fs::read)
            .transpose()?;
        let config = lab_config(&udp_test_node());
        let local_ip = RealEbpfBackend::test_local_ip(&["honk-lan0"], &["honk-wan0"]);
        let mut backend = RealEbpfBackend::load(
            object.as_deref().unwrap_or(crate::DEFAULT_BPF_OBJECT),
            Path::new(ROOT),
            config.global.tproxy_port,
            dae0,
            local_ip,
        )
        .await?;
        backend.bind_test_interfaces(&["honk-lan0"], &["honk-wan0"]);
        backend.attach_dae0_programs()?;
        daens::setup_daens_namespace(config.global.tproxy_mark, config.global.tproxy_port)?;
        backend.attach_sk_lookup()?;
        backend.attach_dae0peer_ingress()?;
        let tcp4 = crate::control::sockets::bind_tproxy_tcp(
            SocketAddr::new("0.0.0.0".parse()?, config.global.tproxy_port),
            config.global.tproxy_mark,
        )?;
        // Only an actual missing IPv6 family may omit the listener; a v6 scenario needs it.
        let tcp6 = match crate::control::sockets::bind_tproxy_tcp(
            SocketAddr::new("::".parse()?, config.global.tproxy_port),
            config.global.tproxy_mark,
        ) {
            Ok(listener) => Some(listener),
            Err(error)
                if net.client.is_ipv4()
                    && error
                        .chain()
                        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
                        .any(|cause| cause.raw_os_error() == Some(libc::EAFNOSUPPORT)) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        backend.publish_listener_sockets(
            tcp4.as_raw_fd(),
            tcp6.as_ref().map(AsRawFd::as_raw_fd),
            &[],
            &[],
        )?;
        let listener = TcpListener::from_std(if net.client.is_ipv4() {
            tcp4
        } else {
            tcp6.context("IPv6 scenario has no IPv6 transparent listener")?
        })?;
        let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
        let dials = Arc::new(AtomicUsize::new(0));
        let protocol = honk_config::types::NodeProtocol::Socks5;
        let mut registry = ProxyRegistry::new();
        registry.register(if kind == Kind::Forward {
            ProtocolEntry::new(
                protocol,
                Arc::new(retransmit::ForwardDial(Arc::clone(&dials))),
            )
        } else {
            ProtocolEntry::new(protocol, Arc::new(CountDial(Arc::clone(&dials))))
        });
        let mut plane = ControlPlane::new(
            config,
            Box::new(backend),
            router,
            Arc::new(registry),
            DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
            udp_test_forwarder(),
        )?;
        plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
            crate::mode::ModeState::new("Rule", "fullcone"),
        )));
        plane.start_datapath_flags_coordinator()?;
        plane.alive_set().shutdown_health_checks().await?;
        let handle = plane.spawn_handle();
        let retirement = (kind != Kind::Manual).then(|| TestRetirement::start(&handle));
        handle.ebpf.write().await.set_datapath_ready(true)?;
        let lab = Self {
            handle,
            _plane: plane,
            dials,
            listener,
            server: net.server.map(TcpListener::from_std).transpose()?,
            client_ns: net.client_ns,
            server_ns: net.server_ns,
            client: net.client,
            wan: net.wan,
            target: net.target,
        };
        Ok((lab, retirement))
    }

    async fn finish(
        self,
        retirement: Option<TestRetirement>,
        result: anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.handle.ebpf.write().await.set_datapath_ready(false)?;
        let joined = match retirement {
            Some(retirement) => retirement.join(&self.handle).await,
            None => Ok(()),
        };
        let cleaned = self.handle.ebpf.write().await.cleanup().await;
        result?;
        joined?;
        cleaned?;
        Ok(())
    }

    fn server(&self) -> anyhow::Result<&TcpListener> {
        self.server
            .as_ref()
            .context("lab has no server namespace listener")
    }

    async fn ownership(&self, stream: &TcpStream) -> anyhow::Result<TcpSocketOwnership> {
        self.handle
            .ebpf
            .read()
            .await
            .tcp_socket_ownership(stream.as_fd())
    }
}

/// `DAENS_FD` is process-lifetime state, so `run_isolated` gives every case a process.
fn run_child(
    family: &str,
    kind: Kind,
    case: impl AsyncFnOnce(&Lab) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let net = Net::build(family, kind)?;
    let (_dae0, dae0_setup) = daens::create_dae0_link()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (lab, retirement) = Lab::boot(net, kind, &dae0_setup).await?;
            let result = case(&lab).await;
            lab.finish(retirement, result).await
        })
        .with_context(|| format!("TCP binding {family}"))
}

fn namespace(family: &str) -> anyhow::Result<()> {
    let _net = Net::build(family, Kind::Proxy)?;
    let (_dae0, _) = daens::create_dae0_link()?;
    daens::setup_daens_namespace(honk_ebpf_common::TPROXY_MARK, 12345)?;
    daens::with_daens_netns("verify handshake shortcut settings", || {
        for name in ["tcp_syncookies", "tcp_migrate_req", "tcp_fastopen"] {
            match std::fs::read_to_string(format!("/proc/sys/net/ipv4/{name}")) {
                Ok(value) => ensure!(value.trim() == "0", "{name} remains enabled"),
                Err(error)
                    if name == "tcp_syncookies" && error.kind() == std::io::ErrorKind::NotFound => {
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    })
}

/// A real client SYN whose SYNACK is held at the client gate, and the native
/// evidence the SYN left behind.
struct Handshake<'a> {
    lab: &'a Lab,
    wire: Wire,
    /// The client's own edge: replays SYNs exactly as its kernel emitted them.
    inject: Wire,
    /// SYNs that crossed host TC into the daens.
    tap: SynTap,
    /// (client port, ISN) of every SYN `tap` has reported from this client address.
    arrived: Vec<(u16, u32)>,
    /// Distinct client ports already used as ordering markers by `assert_refused`.
    markers: u16,
    client: Option<Client>,
    synack: Vec<u8>,
    syn: Vec<u8>,
    isn: u32,
    source: SocketAddr,
    key: TuplesKey,
    original: ConnState,
    handoff: RoutingHandoffEntry,
}

/// Both ends of the completed handshake; `stream` is the transparent accepted FD.
struct Child {
    stream: TcpStream,
    client: TcpStream,
    peer: SocketAddr,
}

impl<'a> Handshake<'a> {
    async fn open(lab: &'a Lab, reuse: bool) -> anyhow::Result<Self> {
        let tap = SynTap::new()?;
        let inject = in_test_netns(&lab.client_ns, || Wire::on("honk-c0"))?;
        let wire = Wire::on("honk-lan0")?;
        let (mut client, source) = Client::lan(&lab.client_ns, lab.client, lab.target, reuse)?;
        let synack = gated_synack(&mut client, &wire, source, lab.target).await?;
        let syn = tokio::time::timeout(NETNS_TEST_TIMEOUT, inject.syn(source, lab.target))
            .await
            .context("client SYN capture deadline")??;
        let isn = syn_isn(&syn, lab.target.is_ipv6())?;
        let arrived = tap.drain_syns(source.ip(), lab.target)?;
        ensure!(
            arrived == [(source.port(), isn)],
            "expected only the original SYN {isn:#x} in the daens, saw {arrived:x?}"
        );
        let key = conn_key(source, lab.target);
        let backend = lab.handle.ebpf.read().await;
        let original = backend
            .conn_state_lookup(&key)?
            .context("real SYN did not publish conn-state")?;
        let handoff = backend
            .routing_handoff_lookup(&key)?
            .context("real SYN did not publish a handoff")?;
        drop(backend);
        ensure!(original.incarnation != 0, "real SYN has no incarnation");
        ensure!(
            original.tcp_syn_isn == isn,
            "conn-state stored ISN {:#x} but the wire carried {isn:#x}",
            original.tcp_syn_isn
        );
        Ok(Self {
            lab,
            wire,
            inject,
            tap,
            client: Some(client),
            synack,
            syn,
            isn,
            source,
            key,
            original,
            handoff,
            arrived,
            markers: 0,
        })
    }

    fn ipv6(&self) -> bool {
        self.lab.target.is_ipv6()
    }

    async fn release(&mut self) -> anyhow::Result<Child> {
        let client = self.client.as_mut().context("client already closed")?;
        client.release()?;
        self.wire.replay(&self.synack)?;
        let connected = client.handshake().await;
        let accepted = tokio::time::timeout(NETNS_TEST_TIMEOUT, self.lab.listener.accept()).await;
        let client = connected?.context("LAN client lost its stream")?;
        let (stream, peer) = accepted.context("accept deadline")??;
        ensure!(
            peer == self.source && stream.local_addr()? == self.lab.target,
            "wrong transparent socket endpoints"
        );
        Ok(Child {
            stream,
            client,
            peer,
        })
    }

    async fn assert_proven(&self, child: &Child) -> anyhow::Result<()> {
        self.assert_proven_as(child, self.original.incarnation)
            .await
    }

    /// The accepted FD carries the SYN's own identity under `incarnation`: tuple, wire ISN
    /// and handoff equal what TC published, apart from the age stamp.
    async fn assert_proven_as(&self, child: &Child, incarnation: u64) -> anyhow::Result<()> {
        let TcpSocketOwnership::Kernel(binding) = self.lab.ownership(&child.stream).await? else {
            anyhow::bail!("real backend returned model ownership")
        };
        ensure!(
            binding.kind == TCP_BINDING_CHILD,
            "accepted FD storage is not a child proof"
        );
        ensure!(
            binding.handoff.incarnation == incarnation,
            "accepted FD bound incarnation {} instead of {incarnation}",
            binding.handoff.incarnation
        );
        ensure!(
            binding.syn_isn == self.isn,
            "accepted FD stored ISN {:#x} but the wire carried {:#x}",
            binding.syn_isn,
            self.isn
        );
        ensure!(
            super::support::bytes_of(&binding.tuples) == super::support::bytes_of(&self.key),
            "accepted FD captured different SYN endpoints"
        );
        let (mut proven, mut published) = (binding.handoff, self.handoff);
        published.incarnation = incarnation;
        proven.last_seen_ns = 0;
        published.last_seen_ns = 0;
        ensure!(
            super::support::bytes_of(&proven) == super::support::bytes_of(&published),
            "accepted FD did not preserve the SYN handoff: {proven:?} vs {published:?}"
        );
        Ok(())
    }

    /// The child has no FD ownership, so admission must refuse it and leave the
    /// tuple's `authority` publications untouched.
    async fn unproven(&self, child: Child, authority: Authority) -> anyhow::Result<()> {
        ensure!(
            self.lab.ownership(&child.stream).await.is_err(),
            "unproven child unexpectedly has FD ownership"
        );
        let result =
            refused_without_cleanup(self.lab, child.stream, child.peer, &self.key, authority).await;
        drop(child.client);
        result
    }
}

/// The incarnation each native publication must still carry after a refusal.
#[derive(Clone, Copy)]
struct Authority {
    conn: u64,
    handoff: Option<u64>,
    redirect: u64,
}

impl Authority {
    fn all(incarnation: u64) -> Self {
        Self {
            conn: incarnation,
            handoff: Some(incarnation),
            redirect: incarnation,
        }
    }
}

fn conn_key(source: SocketAddr, target: SocketAddr) -> TuplesKey {
    crate::control::connection::build_tuples_key(
        target.ip(),
        target.port(),
        source.ip(),
        source.port(),
        6,
    )
}

/// A real boot clock cannot represent a 120s-old proof before uptime120s.
async fn await_established_age() -> anyhow::Result<()> {
    let now = monotonic_ns()?;
    let age = TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS + 1;
    if now <= age {
        tokio::time::sleep(Duration::from_nanos(age - now + 1)).await;
    }
    Ok(())
}

fn accepted(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        {
            let _backend = lab.handle.ebpf.write().await;
            let mut sequence = Array::<_, FlowIncarnationSequence>::try_from(pinned_map(
                Path::new(ROOT),
                "FLOW_INCARNATION_SEQUENCE",
            )?)?;
            sequence.set(
                0,
                &FlowIncarnationSequence {
                    next: FIRST_PUBLISHED_INCARNATION - 1,
                    ..Default::default()
                },
                aya_obj::generated::BPF_F_LOCK as u64,
            )?;
        }
        let mut hs = Handshake::open(lab, false).await?;
        ensure!(
            hs.original.incarnation == FIRST_PUBLISHED_INCARNATION,
            "SYN did not retain the configured full-width incarnation"
        );
        let child = hs.release().await?;
        hs.assert_proven(&child).await?;
        admit(lab, child).await
    })
}

/// The proven child reaches its one outbound consumer through real adoption.
async fn admit(lab: &Lab, child: Child) -> anyhow::Result<()> {
    let result = tokio::time::timeout(
        NETNS_TEST_TIMEOUT,
        lab.handle.serve_connection(child.stream, child.peer),
    )
    .await?;
    ensure!(
        lab.dials.load(Ordering::SeqCst) == 1,
        "proven child did not reach its one outbound consumer: {result:?}"
    );
    drop(child.client);
    Ok(())
}

fn queued_closed_child(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let mut hs = Handshake::open(lab, false).await?;
        let child = hs.release().await?;
        hs.assert_proven(&child).await?;
        // Only competing tuple authority is injected; the old child's storage
        // remains the real hook-created immutable proof while queued for admission.
        let incarnation = supersede(&lab.handle, &hs.key).await?;
        drop(child.client);
        refused_without_cleanup(
            lab,
            child.stream,
            child.peer,
            &hs.key,
            Authority::all(incarnation),
        )
        .await
    })
}

/// Supersession keeps the ISN, so a child accepted afterwards proves the replacement.
fn superseded_syn(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let mut hs = Handshake::open(lab, false).await?;
        let replacement = supersede(&lab.handle, &hs.key).await?;
        ensure!(
            replacement != hs.original.incarnation,
            "fixture did not replace the incarnation"
        );
        let child = hs.release().await?;
        hs.assert_proven_as(&child, replacement).await?;
        admit(lab, child).await
    })
}

/// The callback reads the LIVE handoff's age, not the SYN's.
fn aged_handoff(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        await_established_age().await?;
        let mut hs = Handshake::open(lab, false).await?;
        let aged = monotonic_ns()?
            .checked_sub(TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS + 1)
            .context("kernel uptime too short to age the handoff")?;
        mutate_handoff(&lab.handle, &hs.key, |handoff| handoff.last_seen_ns = aged).await?;
        let child = hs.release().await?;
        hs.unproven(child, Authority::all(hs.original.incarnation))
            .await
    })
}

fn cookie_child(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let before = daens::with_daens_netns("force owned-netns SYN cookies", || {
            std::fs::write("/proc/sys/net/ipv4/tcp_syncookies", "2")?;
            ensure!(
                std::fs::read_to_string("/proc/sys/net/ipv4/tcp_syncookies")?.trim() == "2",
                "SYN cookies not forced"
            );
            cookie_count()
        })?;
        let mut hs = Handshake::open(lab, false).await?;
        let child = hs.release().await?;
        ensure!(
            daens::with_daens_netns("observe forced cookie child", cookie_count)? > before,
            "fixture did not send a SYN cookie"
        );
        hs.assert_proven(&child).await?;
        admit(lab, child).await
    })
}

fn child_storage_full(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let mut hs = Handshake::open(lab, false).await?;
        let child = release_without_storage(&mut hs).await?;
        hs.unproven(child, Authority::all(hs.original.incarnation))
            .await
    })
}

/// Completes the handshake while the daens cannot allocate socket storage, so the child
/// exists without any proof.
async fn release_without_storage(hs: &mut Handshake<'_>) -> anyhow::Result<Child> {
    let optmem =
        daens::with_daens_netns("deny child storage allocation", || -> anyhow::Result<_> {
            let old = std::fs::read_to_string("/proc/sys/net/core/optmem_max")?;
            std::fs::write("/proc/sys/net/core/optmem_max", "0")?;
            Ok(old)
        })?;
    let child = hs.release().await;
    daens::with_daens_netns("restore child storage allocation", || {
        std::fs::write("/proc/sys/net/core/optmem_max", optmem).map_err(anyhow::Error::from)
    })?;
    child
}

async fn refused_without_cleanup(
    lab: &Lab,
    accepted: TcpStream,
    peer: SocketAddr,
    key: &TuplesKey,
    authority: Authority,
) -> anyhow::Result<()> {
    let result = tokio::time::timeout(
        NETNS_TEST_TIMEOUT,
        lab.handle.serve_connection(accepted, peer),
    )
    .await?;
    ensure!(result.is_err(), "unproven/superseded child was admitted");
    ensure!(
        lab.dials.load(Ordering::SeqCst) == 0,
        "unproven/superseded child reached outbound dial"
    );
    let backend = lab.handle.ebpf.read().await;
    ensure!(
        backend
            .conn_state_lookup(key)?
            .map(|value| value.incarnation)
            == Some(authority.conn),
        "rejected adoption deleted/rebound conn-state"
    );
    ensure!(
        backend
            .routing_handoff_lookup(key)?
            .map(|value| value.incarnation)
            == authority.handoff,
        "rejected adoption consumed authoritative handoff"
    );
    ensure!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(key))?
            .map(|value| value.incarnation)
            == Some(authority.redirect),
        "rejected adoption deleted authoritative redirect"
    );
    Ok(())
}

fn monotonic_ns() -> anyhow::Result<u64> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } == 0,
        "read monotonic clock"
    );
    let time = unsafe { time.assume_init() };
    Ok(time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
}

fn cookie_count() -> anyhow::Result<u64> {
    let text = std::fs::read_to_string("/proc/thread-self/net/netstat")?;
    let mut lines = text.lines();
    while let (Some(names), Some(values)) = (lines.next(), lines.next()) {
        if names.starts_with("TcpExt:") {
            let index = names
                .split_ascii_whitespace()
                .position(|name| name == "SyncookiesSent")
                .context("missing cookie counter")?;
            return Ok(values
                .split_ascii_whitespace()
                .nth(index)
                .context("missing cookie value")?
                .parse()?);
        }
    }
    anyhow::bail!("TcpExt counters missing")
}

async fn supersede(handle: &ControlPlaneHandle, key: &TuplesKey) -> anyhow::Result<u64> {
    let root = Path::new(ROOT);
    let mut conns = HashMap::<_, TuplesKey, FlowMapValue<ConnState>>::try_from(pinned_map(
        root,
        "CONN_STATE_MAP",
    )?)?;
    let mut handoffs = HashMap::<_, TuplesKey, FlowMapValue<RoutingHandoffEntry>>::try_from(
        pinned_map(root, "ROUTING_HANDOFF_MAP")?,
    )?;
    let mut backend = handle.ebpf.write().await;
    let mut next = conns.get(key, aya_obj::generated::BPF_F_LOCK as u64)?.value;
    next.incarnation += 1;
    conns.insert(
        key,
        &FlowMapValue::new(next),
        2 | aya_obj::generated::BPF_F_LOCK as u64,
    )?;
    let mut handoff = handoffs
        .get(key, aya_obj::generated::BPF_F_LOCK as u64)?
        .value;
    handoff.incarnation = next.incarnation;
    handoffs.insert(
        key,
        &FlowMapValue::new(handoff),
        2 | aya_obj::generated::BPF_F_LOCK as u64,
    )?;
    let redirect_key = RedirectTuple::from_tuples(key);
    let mut redirect = backend
        .redirect_track_lookup(&redirect_key)?
        .context("missing SYN redirect")?;
    redirect.incarnation = next.incarnation;
    backend.redirect_track_store(&redirect_key, &redirect)?;
    Ok(next.incarnation)
}
