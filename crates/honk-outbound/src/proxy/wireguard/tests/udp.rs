use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use std::net::SocketAddr;

use super::peer::{Fixture, PEER_IP, PEER_IP2, UDP_ECHO, UDP_SPOOF, endpoint};
use super::{TIMEOUT, generation, proxies};
use crate::group::ScoreOutcome;
use crate::proxy::{
    MultiTargetTransport, PacketRejection, is_packet_rejection, node_failure, target_failure,
};
use crate::runtime::OutboundRuntimeRegistry;

async fn source(
    generation: &Arc<OutboundRuntimeRegistry>,
    node: &honk_config::node::Node,
    speculative: bool,
) -> Arc<dyn MultiTargetTransport> {
    let runtime = generation.get(&node.id).unwrap();
    proxies()
        .prepare_shared_source(
            runtime,
            endpoint(PEER_IP, UDP_ECHO),
            None,
            TIMEOUT,
            speculative,
        )
        .await
        .unwrap()
        .commit()
        .await
        .unwrap()
}

async fn recv(transport: &dyn MultiTargetTransport) -> (Vec<u8>, std::net::SocketAddr) {
    let mut buf = [0u8; 2048];
    let (n, from) = tokio::time::timeout(TIMEOUT, transport.recv_packet(&mut buf))
        .await
        .expect("datagram")
        .unwrap();
    (buf[..n].to_vec(), from)
}

#[tokio::test]
async fn one_association_reaches_two_targets_and_reports_the_real_peer() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let transport = source(&generation, &fixture.node, false).await;
    let admitted = AtomicBool::new(false);
    transport
        .send_to(
            endpoint(PEER_IP, UDP_ECHO),
            None,
            b"one",
            true,
            Some(&admitted),
        )
        .await
        .unwrap();
    assert!(admitted.load(std::sync::atomic::Ordering::Acquire));
    transport
        .send_to(endpoint(PEER_IP2, UDP_ECHO), None, b"two", false, None)
        .await
        .unwrap();
    let mut replies = [recv(&*transport).await, recv(&*transport).await];
    replies.sort();
    assert_eq!(replies[0], (b"one".to_vec(), endpoint(PEER_IP, UDP_ECHO)));
    assert_eq!(replies[1], (b"two".to_vec(), endpoint(PEER_IP2, UDP_ECHO)));
    let runtime = generation.get(&fixture.node.id).unwrap();
    let tunnel = runtime.wireguard().unwrap().cached().unwrap();
    assert_eq!(
        tunnel.flow_count(),
        1,
        "both targets share one inner socket"
    );
}

#[tokio::test]
async fn oversize_is_a_local_size_refusal_that_keeps_the_association() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let transport = source(&generation, &fixture.node, false).await;
    let error = transport
        .send_to(endpoint(PEER_IP, UDP_ECHO), None, &[0; 2000], false, None)
        .await
        .unwrap_err();
    assert_eq!(
        crate::proxy::io_packet_rejection(&error),
        Some(PacketRejection::InvalidSize)
    );
    assert_eq!(ScoreOutcome::from_io_error(&error), ScoreOutcome::Rejected);
    transport
        .send_to(
            endpoint(PEER_IP, UDP_ECHO),
            None,
            b"still works",
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(recv(&*transport).await.0, b"still works");
}

#[tokio::test]
async fn policy_and_spoofed_sources_are_refused_in_both_directions() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let transport = source(&generation, &fixture.node, false).await;
    let outside = endpoint(std::net::Ipv4Addr::new(192, 0, 2, 1), 53);
    let error = transport
        .send_to(outside, None, b"x", false, None)
        .await
        .unwrap_err();
    assert_eq!(
        crate::proxy::io_packet_rejection(&error),
        Some(PacketRejection::Policy)
    );
    // The peer answers from 10.9.9.9, which its allowed IPs do not cover: cryptokey routing drops it.
    transport
        .send_to(endpoint(PEER_IP, UDP_SPOOF), None, b"spoof", false, None)
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(700), transport.recv_packet(&mut buf))
            .await
            .is_err()
    );
    transport
        .send_to(endpoint(PEER_IP, UDP_ECHO), None, b"ok", false, None)
        .await
        .unwrap();
    assert_eq!(recv(&*transport).await.0, b"ok");
}

#[tokio::test]
async fn speculative_preparation_publishes_nothing_until_commit() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let runtime = generation.get(&fixture.node.id).unwrap();
    let registry = proxies();
    let prepare = |speculative| {
        registry.prepare_shared_source(
            Arc::clone(&runtime),
            endpoint(PEER_IP, UDP_ECHO),
            None,
            TIMEOUT,
            speculative,
        )
    };
    let loser = prepare(true).await.unwrap();
    assert!(runtime.wireguard().unwrap().cached().is_none());
    assert_eq!(runtime.warm_counts().clients, Some(0));
    drop(loser);
    assert_eq!(runtime.warm_counts().clients, Some(0));

    let winner = prepare(true).await.unwrap();
    let transport = winner.commit().await.unwrap();
    assert_eq!(runtime.warm_counts().clients, Some(1));
    transport
        .send_to(endpoint(PEER_IP, UDP_ECHO), None, b"won", true, None)
        .await
        .unwrap();
    assert_eq!(recv(&*transport).await.0, b"won");
}

#[tokio::test]
async fn a_closed_runtime_rejects_a_late_speculative_commit() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let runtime = generation.get(&fixture.node.id).unwrap();
    let prepared = proxies()
        .prepare_shared_source(
            Arc::clone(&runtime),
            endpoint(PEER_IP, UDP_ECHO),
            None,
            TIMEOUT,
            true,
        )
        .await
        .unwrap();
    runtime.close().await;
    assert!(prepared.commit().await.is_err());
    assert!(runtime.wireguard().unwrap().cached().is_none());
}

#[tokio::test]
async fn per_target_transport_dials_and_receives_from_its_target() {
    let fixture = Fixture::new().await;
    let transport = proxies()
        .dial_udp_transport(&fixture.node, endpoint(PEER_IP, UDP_ECHO), None, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(transport.relay_addr(), endpoint(PEER_IP, UDP_ECHO));
    transport.send_packet_confirmed(b"dns").await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(TIMEOUT, transport.recv_packet(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (&buf[..n], from),
        (&b"dns"[..], endpoint(PEER_IP, UDP_ECHO))
    );
}

#[tokio::test]
async fn an_unroutable_udp_target_is_a_target_failure_at_dial_like_tcp() {
    let fixture = Fixture::new().await;
    let error = proxies()
        .dial_udp_transport(
            &fixture.node,
            endpoint(std::net::Ipv4Addr::new(192, 0, 2, 1), 53),
            None,
            TIMEOUT,
        )
        .await
        .unwrap_err();
    assert!(target_failure(&error), "{error:#}");
    assert!(!is_packet_rejection(&error), "{error:#}");
    assert!(!node_failure(&error), "{error:#}");
}

#[tokio::test]
async fn a_udp_target_in_a_family_without_a_tunnel_address_is_a_target_failure() {
    // Allowed, but the tunnel has no IPv6 address to source packets from.
    let fixture = Fixture::with(None, |config| {
        config.allowed_ips.push("::/0".parse().unwrap());
    })
    .await;
    let v6 = SocketAddr::new("fd00::1".parse().unwrap(), 53);
    let error = proxies()
        .dial_udp_transport(&fixture.node, v6, None, TIMEOUT)
        .await
        .unwrap_err();
    assert!(target_failure(&error), "{error:#}");
}
