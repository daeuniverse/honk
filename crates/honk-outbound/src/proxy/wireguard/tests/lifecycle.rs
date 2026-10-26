use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use honk_config::node::Node;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use honk_netstack::ConnectError;

use super::peer::{Fixture, PEER_IP, STALL, endpoint, key_pair, wg_key};
use super::{ECHO, TIMEOUT, dial, echo_roundtrip, generation, proxies, successor};
use crate::group::ScoreOutcome;
use crate::proxy::wireguard::registry::{DEFAULT_SHARE, Limits, Registry};
use crate::proxy::wireguard::tunnel::Failure;
use crate::proxy::wireguard::{
    Gone, RuntimeClosed, Tunnel, TunnelConfig, TunnelRegistry, WireGuardHandler,
};
use crate::proxy::{
    PacketRejection, ProbeableOutbound as _, TcpOutbound as _, WarmOutcome, node_failure,
    packet_rejection,
};
use crate::runtime::{NodeRuntime, OutboundRuntimeRegistry, WarmRetention};

/// A tunnel from the process-wide registry of runtime-less dials.
async fn acquire(cfg: TunnelConfig) -> anyhow::Result<Tunnel> {
    TunnelRegistry::standalone().acquire(cfg).await
}

async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn closed_by_runtime(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.downcast_ref::<RuntimeClosed>().is_some())
}

#[tokio::test]
async fn identical_configs_share_one_tunnel_across_runtimes_and_dns_forks() {
    let fixture = Fixture::new().await;
    let first = generation(&fixture.node);
    let second = successor(&first, &fixture.node);
    let fork = Arc::new(first.fork_for_dns().unwrap());
    let mut streams = Vec::new();
    for generation in [&first, &second, &fork] {
        streams.push(dial(generation, &fixture.node, ECHO).await.unwrap());
    }
    let tunnels: Vec<_> = [&first, &second, &fork]
        .iter()
        .map(|generation| {
            let runtime = generation.get(&fixture.node.id).unwrap();
            runtime.wireguard().unwrap().cached().unwrap()
        })
        .collect();
    assert!(Arc::ptr_eq(&tunnels[0].0, &tunnels[1].0));
    assert!(Arc::ptr_eq(&tunnels[0].0, &tunnels[2].0));
    assert_eq!(
        fixture.peer.control.handshakes.load(Ordering::Relaxed),
        1,
        "one session: a second one would invalidate the first"
    );
    for stream in &mut streams {
        echo_roundtrip(stream, b"shared").await;
    }
}

#[tokio::test]
async fn concurrent_first_dials_converge_on_one_tunnel() {
    let fixture = Fixture::new().await;
    let config = TunnelConfig::from_node(&fixture.node).unwrap();
    let (a, b) = tokio::join!(acquire(config.clone()), acquire(config));
    assert!(Arc::ptr_eq(&a.unwrap().0, &b.unwrap().0));

    let generation = generation(&fixture.node);
    let (a, b) = tokio::join!(
        dial(&generation, &fixture.node, ECHO),
        dial(&generation, &fixture.node, ECHO)
    );
    drop((a.unwrap(), b.unwrap()));
    assert_eq!(fixture.peer.control.handshakes.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_conflicting_config_replaces_the_tunnel_and_closes_its_flows_without_blaming_the_node() {
    let fixture = Fixture::new().await;
    let old = generation(&fixture.node);
    let mut first = dial(&old, &fixture.node, ECHO).await.unwrap();
    let mut second = dial(&old, &fixture.node, ECHO).await.unwrap();
    echo_roundtrip(&mut first, b"before").await;
    let old_tunnel = old
        .get(&fixture.node.id)
        .unwrap()
        .wireguard()
        .unwrap()
        .cached()
        .unwrap();

    let replacement = fixture.variant(|config| config.mtu = 1400);
    let new = successor(&old, &replacement);
    let mut fresh = dial(&new, &replacement, ECHO).await.unwrap();
    echo_roundtrip(&mut fresh, b"after").await;
    assert!(old_tunnel.is_dead());

    for stream in [&mut first, &mut second] {
        let error = tokio::time::timeout(TIMEOUT, stream.stream.read(&mut [0; 8]))
            .await
            .unwrap()
            .unwrap_err();
        assert!(closed_by_runtime(&error), "{error:?}");
        assert!(
            !ScoreOutcome::from_io_error(&error).is_node_failure(),
            "a reload of this node's own settings is not its failure: {error:?}"
        );
    }
    let write = first.stream.write_all(b"x").await.unwrap_err();
    assert!(closed_by_runtime(&write), "{write:?}");
    assert!(!ScoreOutcome::from_io_error(&write).is_node_failure());
}

#[tokio::test]
async fn warming_completes_the_handshake_and_release_keeps_live_flows() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let runtime = generation.get(&fixture.node.id).unwrap();
    assert_eq!(runtime.warm_counts().clients, Some(0));
    let outcome = proxies()
        .warm_session(Arc::clone(&generation), fixture.node.id, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(outcome, WarmOutcome::Ready);
    let tunnel = runtime.wireguard().unwrap().cached().unwrap();
    assert!(tunnel.is_established(), "warm-up is the handshake");
    assert_eq!(runtime.warm_counts().clients, Some(1));
    assert!(runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session));

    let mut stream = dial(&generation, &fixture.node, ECHO).await.unwrap();
    runtime.release_warm(WarmRetention::Selector).await;
    assert_eq!(runtime.warm_counts().clients, Some(0), "slot released");
    assert!(!runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session));
    echo_roundtrip(&mut stream, b"still flowing").await;
    assert!(!tunnel.is_dead());
}

#[tokio::test]
async fn warm_retention_pins_an_idle_tunnel_and_release_lets_it_expire() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let runtime = generation.get(&fixture.node.id).unwrap();
    proxies()
        .warm_udp(Arc::clone(&generation), fixture.node.id, TIMEOUT)
        .await
        .unwrap();
    let tunnel = runtime.wireguard().unwrap().cached().unwrap();
    tunnel.set_idle_timeout(Duration::from_millis(300));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!tunnel.is_dead(), "a warm hold keeps an idle tunnel");
    runtime.release_warm(WarmRetention::Udp).await;
    wait_until("idle teardown after release", || tunnel.is_dead()).await;
}

#[tokio::test]
async fn an_idle_tunnel_retires_and_the_next_dial_builds_a_fresh_one() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let runtime = generation.get(&fixture.node.id).unwrap();
    let stream = dial(&generation, &fixture.node, ECHO).await.unwrap();
    let old = runtime.wireguard().unwrap().cached().unwrap();
    old.set_idle_timeout(Duration::from_millis(300));
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(!old.is_dead(), "an open flow keeps the tunnel");
    drop(stream);
    wait_until("idle teardown", || old.is_dead()).await;
    assert_eq!(old.flow_count(), 0);

    let mut stream = dial(&generation, &fixture.node, ECHO).await.unwrap();
    let fresh = runtime.wireguard().unwrap().cached().unwrap();
    assert!(!Arc::ptr_eq(&old.0, &fresh.0));
    echo_roundtrip(&mut stream, b"reborn").await;
}

#[tokio::test]
async fn a_failed_warm_up_is_a_node_failure_and_leaves_nothing_retained() {
    let fixture = Fixture::new().await;
    fixture.peer.control.mute.store(true, Ordering::Relaxed);
    let generation = generation(&fixture.node);
    let runtime = generation.get(&fixture.node.id).unwrap();
    let error = proxies()
        .warm_session(
            Arc::clone(&generation),
            fixture.node.id,
            Duration::from_millis(600),
        )
        .await
        .unwrap_err();
    assert!(node_failure(&error), "{error:#}");
    assert_eq!(runtime.warm_counts().clients, Some(0));
}

#[tokio::test]
async fn connectivity_probe_performs_a_handshake() {
    let reachable = Fixture::new().await;
    let handler = WireGuardHandler::new();
    assert!(handler.test_connectivity(&reachable.node).await);
    assert!(reachable.peer.control.handshakes.load(Ordering::Relaxed) >= 1);

    // A host that merely accepts the datagrams proves nothing about the tunnel.
    let silent = Fixture::new().await;
    silent.peer.control.mute.store(true, Ordering::Relaxed);
    assert!(!handler.test_connectivity(&silent.node).await);
}

#[tokio::test]
async fn closing_a_runtime_wakes_its_blocked_io_and_spares_other_runtimes() {
    let fixture = Fixture::new().await;
    let closing = generation(&fixture.node);
    let other = Arc::new(closing.fork_for_dns().unwrap());
    let mut survivor = dial(&other, &fixture.node, ECHO).await.unwrap();
    let mut idle_reader = dial(&closing, &fixture.node, ECHO).await.unwrap();
    let mut blocked_writer = dial(&closing, &fixture.node, STALL).await.unwrap();

    let read = tokio::spawn(async move { idle_reader.stream.read(&mut [0; 16]).await });
    let write = tokio::spawn(async move {
        let chunk = vec![0u8; 16 * 1024];
        loop {
            blocked_writer.stream.write_all(&chunk).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        !read.is_finished() && !write.is_finished(),
        "both are blocked"
    );

    closing.get(&fixture.node.id).unwrap().close().await;
    let read = tokio::time::timeout(TIMEOUT, read).await.unwrap().unwrap();
    let write = tokio::time::timeout(TIMEOUT, write).await.unwrap().unwrap();
    for error in [read.unwrap_err(), write.unwrap_err()] {
        assert!(closed_by_runtime(&error), "{error:?}");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    }
    echo_roundtrip(&mut survivor, b"unaffected").await;
}

#[tokio::test]
async fn dropping_an_ephemeral_runtime_guard_closes_its_flows() {
    let fixture = Fixture::new().await;
    let guard = NodeRuntime::try_ephemeral_guarded(&fixture.node).unwrap();
    let mut stream = WireGuardHandler::new()
        .dial_runtime(guard.runtime(), endpoint(PEER_IP, ECHO), None, TIMEOUT)
        .await
        .unwrap();
    echo_roundtrip(&mut stream, b"probe").await;
    drop(guard);
    let error = tokio::time::timeout(TIMEOUT, stream.stream.read(&mut [0; 8]))
        .await
        .unwrap()
        .unwrap_err();
    assert!(closed_by_runtime(&error), "{error:?}");
}

#[tokio::test]
async fn warming_a_tunnel_the_slot_already_caches_holds_it_too() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let runtime = generation.get(&fixture.node.id).unwrap();
    drop(dial(&generation, &fixture.node, ECHO).await.unwrap());
    let tunnel = runtime.wireguard().unwrap().cached().unwrap();
    proxies()
        .warm_session(Arc::clone(&generation), fixture.node.id, TIMEOUT)
        .await
        .unwrap();
    tunnel.set_idle_timeout(Duration::from_millis(300));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!tunnel.is_dead(), "retention attached to the cached tunnel");
    runtime.release_warm(WarmRetention::Selector).await;
    wait_until("expiry after release", || tunnel.is_dead()).await;
}

fn cached(generation: &Arc<OutboundRuntimeRegistry>, node: &Node) -> Tunnel {
    generation
        .get(&node.id)
        .unwrap()
        .wireguard()
        .unwrap()
        .cached()
        .unwrap()
}

async fn promptly(what: &str, condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(1), wait_until(what, condition))
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen within a second"));
}

#[tokio::test]
async fn nodes_sharing_a_key_pair_on_other_endpoints_keep_their_own_tunnels() {
    let first = Fixture::new().await;
    let second = first.sibling().await;
    assert_ne!(first.node.id, second.node.id);
    let (a, b) = (generation(&first.node), generation(&second.node));
    let mut stream_a = dial(&a, &first.node, ECHO).await.unwrap();
    let mut stream_b = dial(&b, &second.node, ECHO).await.unwrap();
    let (tunnel_a, tunnel_b) = (cached(&a, &first.node), cached(&b, &second.node));
    assert!(!tunnel_a.same(&tunnel_b));
    assert!(
        !tunnel_a.is_dead(),
        "dialing the sibling must not replace this tunnel"
    );
    echo_roundtrip(&mut stream_a, b"first").await;
    echo_roundtrip(&mut stream_b, b"second").await;
    for peer in [&first.peer, &second.peer] {
        assert_eq!(peer.control.handshakes.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn one_waiters_timeout_leaves_the_handshake_to_longer_waiters() {
    let fixture = Fixture::new().await;
    fixture.peer.control.mute.store(true, Ordering::Relaxed);
    let tunnel = acquire(TunnelConfig::from_node(&fixture.node).unwrap())
        .await
        .unwrap();
    let patient = tokio::spawn({
        let tunnel = tunnel.clone();
        async move { tunnel.ready(TIMEOUT).await.is_ok() }
    });
    let short = tunnel.ready(Duration::from_millis(200)).await;
    assert!(matches!(short, Err(Gone::Failed(_))));
    assert!(
        !tunnel.is_dead(),
        "a short budget is the waiter's own failure"
    );
    fixture.peer.control.mute.store(false, Ordering::Relaxed);
    assert!(
        patient.await.unwrap(),
        "the patient waiter completes the handshake"
    );
    assert!(tunnel.is_established());
}

#[tokio::test]
async fn timeouts_of_one_handshake_attempt_report_one_failure_episode() {
    let fixture = Fixture::new().await;
    fixture.peer.control.mute.store(true, Ordering::Relaxed);
    let tunnel = acquire(TunnelConfig::from_node(&fixture.node).unwrap())
        .await
        .unwrap();
    let (first, second) = (
        tunnel.ready(Duration::from_millis(100)).await,
        tunnel.ready(Duration::from_millis(100)).await,
    );
    let (Err(Gone::Failed(first)), Err(Gone::Failed(second))) = (first, second) else {
        panic!("both waiters time out");
    };
    assert!(first.episode().is_some());
    assert_eq!(first.episode(), second.episode());
}

#[tokio::test]
async fn a_lost_initiation_is_resent_within_a_default_dial_budget() {
    let fixture = Fixture::new().await;
    fixture.peer.control.drop_inits.store(1, Ordering::Relaxed);
    let generation = generation(&fixture.node);
    let started = std::time::Instant::now();
    let mut stream = proxies()
        .dial_runtime(
            Arc::clone(&generation),
            fixture.node.id,
            endpoint(PEER_IP, ECHO),
            None,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    echo_roundtrip(&mut stream, b"after the loss").await;
    let initiations = fixture
        .peer
        .wire
        .lock()
        .iter()
        .filter(|first| first[0] == 1)
        .count();
    assert!(
        (2..=3).contains(&initiations),
        "one resend, not a flood: {initiations}"
    );
}

#[tokio::test]
async fn closing_the_last_runtime_retires_the_tunnel_at_once_but_not_a_shared_one() {
    let fixture = Fixture::new().await;
    let closing = generation(&fixture.node);
    let other = Arc::new(closing.fork_for_dns().unwrap());
    let streams = [
        dial(&closing, &fixture.node, ECHO).await.unwrap(),
        dial(&other, &fixture.node, ECHO).await.unwrap(),
    ];
    let tunnel = cached(&closing, &fixture.node);
    drop(streams);
    closing.get(&fixture.node.id).unwrap().close().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !tunnel.is_dead(),
        "the other runtime still caches the tunnel"
    );
    other.get(&fixture.node.id).unwrap().close().await;
    promptly("retirement of the unheld tunnel", || tunnel.is_dead()).await;
}

#[tokio::test]
async fn shutting_a_generation_down_retires_its_tunnel_despite_a_live_flow() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let mut stream = dial(&generation, &fixture.node, ECHO).await.unwrap();
    let tunnel = cached(&generation, &fixture.node);
    generation.shutdown().await;
    promptly("tunnel retirement", || tunnel.is_dead()).await;
    let error = tokio::time::timeout(TIMEOUT, stream.stream.read(&mut [0; 8]))
        .await
        .unwrap()
        .unwrap_err();
    assert!(closed_by_runtime(&error), "{error:?}");
}

#[tokio::test]
async fn a_tunnel_acquired_for_a_runtime_that_closed_meanwhile_is_not_left_running() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let runtime = generation.get(&fixture.node.id).unwrap();
    runtime.close().await;
    let tunnel = runtime
        .wireguard()
        .unwrap()
        .registry()
        .acquire(TunnelConfig::from_node(&fixture.node).unwrap())
        .await
        .unwrap();
    assert!(
        runtime
            .wireguard()
            .unwrap()
            .install(tunnel.clone())
            .is_err()
    );
    promptly("retirement of the orphan", || tunnel.is_dead()).await;
}

#[tokio::test]
async fn plane_shutdown_closes_flows_without_blame_and_joins_the_owner() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let mut stream = dial(&generation, &fixture.node, ECHO).await.unwrap();
    let tunnel = cached(&generation, &fixture.node);
    let config = TunnelConfig::from_node(&fixture.node).unwrap();
    let closed = generation.shutdown_wireguard_tunnels().await;
    assert_eq!(closed, 1);
    assert!(tunnel.is_dead());
    assert!(
        !generation
            .get(&fixture.node.id)
            .unwrap()
            .wireguard()
            .unwrap()
            .registry()
            .contains(&config),
        "the owner task had ended when shutdown returned"
    );
    let error = tokio::time::timeout(TIMEOUT, stream.stream.read(&mut [0; 8]))
        .await
        .unwrap()
        .unwrap_err();
    assert!(closed_by_runtime(&error), "{error:?}");
    assert!(!ScoreOutcome::from_io_error(&error).is_node_failure());
    let mut again = dial(&generation, &fixture.node, ECHO).await.unwrap();
    echo_roundtrip(&mut again, b"nothing is latched").await;
}

#[tokio::test]
async fn two_planes_never_share_a_tunnel_and_one_closing_spares_the_other() {
    let fixture = Fixture::new().await;
    let config = TunnelConfig::from_node(&fixture.node).unwrap();
    let (a, b) = (generation(&fixture.node), generation(&fixture.node));
    let acquire = |plane: &Arc<OutboundRuntimeRegistry>| {
        let runtime = plane.get(&fixture.node.id).unwrap();
        let config = config.clone();
        async move {
            runtime
                .wireguard()
                .unwrap()
                .registry()
                .acquire(config)
                .await
                .unwrap()
        }
    };
    let (tunnel_a, tunnel_b) = (acquire(&a).await, acquire(&b).await);
    assert!(
        !tunnel_a.same(&tunnel_b),
        "identical configs, separate planes"
    );

    assert_eq!(a.shutdown_wireguard_tunnels().await, 1);
    assert!(tunnel_a.is_dead());
    assert!(!tunnel_b.is_dead(), "another plane's teardown is not ours");
    assert_eq!(b.shutdown_wireguard_tunnels().await, 1);
    assert!(tunnel_b.is_dead());
}

#[tokio::test]
async fn reinstalling_the_cached_tunnel_keeps_its_warm_pin() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let runtime = generation.get(&fixture.node.id).unwrap();
    proxies()
        .warm_session(Arc::clone(&generation), fixture.node.id, TIMEOUT)
        .await
        .unwrap();
    let tunnel = cached(&generation, &fixture.node);
    // A speculative preparation committing the tunnel the slot already caches.
    runtime
        .wireguard()
        .unwrap()
        .install(tunnel.clone())
        .unwrap();
    tunnel.set_idle_timeout(Duration::from_millis(300));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!tunnel.is_dead(), "the slot is still retained");
    runtime.release_warm(WarmRetention::Selector).await;
    wait_until("expiry after release", || tunnel.is_dead()).await;
}

#[tokio::test]
async fn junk_from_the_peers_address_never_ends_the_tunnel() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let mut stream = dial(&generation, &fixture.node, ECHO).await.unwrap();
    let tunnel = cached(&generation, &fixture.node);
    for _ in 0..2 {
        fixture.peer.send_garbage(5000);
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(!tunnel.is_dead());
    }
    echo_roundtrip(&mut stream, b"unharmed").await;
}

#[tokio::test]
async fn an_under_load_cookie_reply_neither_moves_the_endpoint_nor_reaches_the_peer() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let mut stream = dial(&generation, &fixture.node, ECHO).await.unwrap();
    let tunnel = cached(&generation, &fixture.node);
    assert_eq!(tunnel.endpoint(), fixture.peer.addr);
    fixture.peer.send_forged_initiations(64);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        tunnel.endpoint(),
        fixture.peer.addr,
        "an unauthenticated sender must not redirect the tunnel"
    );
    assert!(
        fixture.peer.wire.lock().iter().all(|first| first[0] != 3),
        "no cookie reply goes to the real peer"
    );
    echo_roundtrip(&mut stream, b"still the peer").await;
}

/// A tunnel whose peer never answers, with its own key pair: it costs the registry a slot and the
/// budget whatever flows its stack admits.
fn silent(
    template: &TunnelConfig,
    registry: &Arc<Registry>,
    limits: &Limits,
) -> anyhow::Result<Tunnel> {
    let mut config = template.clone();
    config.wg.private_key = Some(wg_key(&key_pair().0));
    registry.install(config, vec!["127.0.0.1:9".parse().unwrap()], limits)
}

/// Opens inner flows on `tunnel` until its stack or the shared budget refuses one.
fn connect_once(tunnel: &Tunnel) -> Result<(), ConnectError> {
    tunnel
        .0
        .with(|inner| {
            inner
                .stack
                .tcp_connect(std::time::Instant::now(), endpoint(PEER_IP, ECHO))
        })
        .map(drop)
}

#[tokio::test]
async fn live_tunnels_are_bounded_by_their_fixed_cost() {
    const MIB: usize = 1 << 20;
    assert_eq!(Limits::new(64 * MIB).max_tunnels, 16);
    assert_eq!(Limits::new(256 * MIB).max_tunnels, 64);
    assert_eq!(Limits::new(1 << 40).max_tunnels, 128);
    assert_eq!(
        Limits::new(MIB).max_tunnels,
        1,
        "a share below one tunnel's cost still admits a tunnel"
    );

    let limits = Limits::new(16 * MIB);
    assert_eq!(limits.max_tunnels, 4);
    let template = TunnelConfig::from_node(&Fixture::new().await.node).unwrap();
    let registry = Registry::new();
    let mut tunnels: Vec<_> = (0..4)
        .map(|_| silent(&template, &registry, &limits).unwrap())
        .collect();
    assert!(
        tunnels
            .iter()
            .all(|tunnel| tunnel.memory_limit() == 16 * MIB),
        "every stack may use the whole share, the shared budget keeps the sum"
    );
    // Full of unused tunnels: the oldest makes room.
    tunnels.push(silent(&template, &registry, &limits).unwrap());
    assert!(tunnels[0].is_dead());
    tunnels.remove(0);
    assert_eq!(tunnels.iter().filter(|tunnel| !tunnel.is_dead()).count(), 4);
    // Full of tunnels in use: refused as local capacity, not a node failure.
    let holds: Vec<_> = tunnels
        .iter()
        .map(|tunnel| tunnel.hold(1).unwrap())
        .collect();
    let refused = silent(&template, &registry, &limits)
        .err()
        .expect("no room while every tunnel is held");
    assert_eq!(packet_rejection(&refused), Some(PacketRejection::Capacity));
    assert!(!node_failure(&refused));
    drop(holds);
    silent(&template, &registry, &limits).unwrap();
}

#[tokio::test]
async fn many_tunnels_live_under_one_budget_that_their_commitments_never_exceed() {
    const MIB: usize = 1 << 20;
    // A 256 MiB share used to admit 16 tunnels of 16 MiB each.
    let limits = Limits::new(256 * MIB);
    let template = TunnelConfig::from_node(&Fixture::new().await.node).unwrap();
    let registry = Registry::new();
    let tunnels: Vec<_> = (0..40)
        .map(|_| silent(&template, &registry, &limits).unwrap())
        .collect();
    assert!(
        tunnels.iter().all(|tunnel| !tunnel.is_dead()),
        "40 tunnels fit: nothing was evicted to make room"
    );
    let committed = || -> usize {
        tunnels
            .iter()
            .map(|tunnel| tunnel.0.with(|inner| inner.stack.stats().memory_committed))
            .sum()
    };
    let mut exhausted = false;
    'fill: for _ in 0..1000 {
        for tunnel in &tunnels {
            match connect_once(tunnel) {
                Ok(()) => {}
                Err(ConnectError::Memory) => {
                    exhausted = true;
                    break 'fill;
                }
                Err(other) => panic!("unexpected refusal: {other}"),
            }
        }
        assert!(committed() <= limits.budget.limit());
    }
    assert!(
        exhausted,
        "the shared budget, not a per-stack limit, ran out"
    );
    assert!(committed() <= limits.budget.limit());
    assert_eq!(committed(), limits.budget.used());
    // Every tunnel gave its charge back with its stack.
    registry.shutdown_where(|_| true).await;
    drop((tunnels, registry));
    assert_eq!(limits.budget.used(), 0);
}

#[tokio::test]
async fn a_flow_admitted_under_shared_pressure_still_progresses() {
    let fixture = Fixture::new().await;
    let limits = Limits::new(64 << 20);
    let registry = Registry::new();
    let tunnel = registry
        .install(
            TunnelConfig::from_node(&fixture.node).unwrap(),
            vec![fixture.peer.addr],
            &limits,
        )
        .unwrap();
    tunnel
        .ready(TIMEOUT)
        .await
        .map_err(|_| "no handshake")
        .unwrap();
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut flow = tunnel
        .dial_tcp(0, endpoint(PEER_IP, ECHO), deadline)
        .await
        .ok()
        .expect("tunnel is live")
        .unwrap();

    // Other tunnels take every flow the budget has room for.
    let template = TunnelConfig::from_node(&fixture.node).unwrap();
    let hog = silent(&template, &registry, &limits).unwrap();
    while connect_once(&hog).is_ok() {}
    let refused = tunnel
        .dial_tcp(0, endpoint(PEER_IP, ECHO), deadline)
        .await
        .ok()
        .expect("tunnel is live")
        .expect_err("no budget left for another flow");
    assert_eq!(packet_rejection(&refused), Some(PacketRejection::Capacity));
    assert!(!node_failure(&refused));

    // The admitted flow keeps its floor: a request goes out and the answer comes back.
    let payload = vec![0x5a; 4000];
    flow.write_all(&payload).await.unwrap();
    let mut back = vec![0; payload.len()];
    tokio::time::timeout(TIMEOUT, flow.read_exact(&mut back))
        .await
        .expect("echo reply under pressure")
        .unwrap();
    assert_eq!(back, payload);
}

#[tokio::test]
async fn an_unanswering_candidate_address_falls_back_to_the_next() {
    let fixture = Fixture::new().await;
    let registry = Registry::new();
    // IPv4 first, and IPv6 first (a dual-stack socket carrying the IPv4 peer mapped).
    for dead in ["127.0.0.1:9", "[::1]:9"] {
        let config = TunnelConfig::from_node(&fixture.node).unwrap();
        let candidates = vec![dead.parse().unwrap(), fixture.peer.addr];
        let tunnel = registry
            .install(config, candidates, &Limits::new(DEFAULT_SHARE))
            .unwrap();
        assert!(tunnel.ready(Duration::from_secs(4)).await.is_ok(), "{dead}");
        assert_eq!(tunnel.endpoint(), fixture.peer.addr, "{dead}");
        tunnel.0.fail(Failure::Closed);
    }
}

#[tokio::test]
async fn a_tunnel_without_a_session_adopts_re_resolved_addresses() {
    let fixture = Fixture::new().await;
    let registry = Registry::new();
    let config = TunnelConfig::from_node(&fixture.node).unwrap();
    let tunnel = registry
        .install(
            config,
            vec!["127.0.0.1:9".parse().unwrap()],
            &Limits::new(DEFAULT_SHARE),
        )
        .unwrap();
    assert!(tunnel.ready(Duration::from_millis(300)).await.is_err());
    assert!(
        tunnel.0.take_resolve_due(),
        "a timed-out handshake asks for a new lookup"
    );
    tunnel.0.set_candidates(vec![fixture.peer.addr]);
    assert!(tunnel.ready(Duration::from_secs(4)).await.is_ok());
}

#[tokio::test]
async fn an_aged_out_session_is_not_warm_and_warming_handshakes_again() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let runtime = generation.get(&fixture.node.id).unwrap();
    proxies()
        .warm_session(Arc::clone(&generation), fixture.node.id, TIMEOUT)
        .await
        .unwrap();
    let tunnel = cached(&generation, &fixture.node);
    assert!(runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session));
    // Short enough to see, long enough that the second session outlives the assertions.
    tunnel.set_session_lifetime(Duration::from_millis(1500));
    wait_until("the session to age out", || !tunnel.is_established()).await;
    assert!(!runtime.is_warm_or_stateless_for(crate::proxy::WarmRequirement::Session));
    proxies()
        .warm_session(Arc::clone(&generation), fixture.node.id, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(
        fixture.peer.control.handshakes.load(Ordering::Relaxed),
        2,
        "warming an expired session handshakes again"
    );
}

#[tokio::test]
async fn a_probe_retries_on_a_tunnel_that_retired_while_it_waited() {
    let fixture = Fixture::new().await;
    fixture.peer.control.mute.store(true, Ordering::Relaxed);
    let first = acquire(TunnelConfig::from_node(&fixture.node).unwrap())
        .await
        .unwrap();
    let probe = tokio::spawn({
        let node = fixture.node.clone();
        async move { WireGuardHandler::new().test_connectivity(&node).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    first.0.fail(Failure::Idle);
    fixture.peer.control.mute.store(false, Ordering::Relaxed);
    assert!(tokio::time::timeout(TIMEOUT, probe).await.unwrap().unwrap());
}

#[tokio::test]
async fn local_flow_exhaustion_is_a_capacity_refusal_not_a_node_failure() {
    let fixture = Fixture::new().await;
    let registry = Registry::new();
    let limits = Limits::new(16 << 20);
    let tunnel = registry
        .install(
            TunnelConfig::from_node(&fixture.node).unwrap(),
            vec![fixture.peer.addr],
            &limits,
        )
        .unwrap();
    assert!(tunnel.ready(TIMEOUT).await.is_ok());
    let deadline = std::time::Instant::now() + Duration::from_millis(1500);
    // More concurrent connects than a 16 MiB stack has per-flow floors for.
    let results = futures_util::future::join_all(
        (0..900).map(|_| tunnel.dial_tcp(0, endpoint(PEER_IP, STALL), deadline)),
    )
    .await;
    let refused: Vec<_> = results
        .into_iter()
        .filter_map(|result| result.ok()?.err())
        .filter(|error| packet_rejection(error) == Some(PacketRejection::Capacity))
        .collect();
    assert!(!refused.is_empty(), "the stack ran out of flows");
    assert!(refused.iter().all(|error| !node_failure(error)));
}
