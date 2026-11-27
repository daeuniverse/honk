use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::peer::{ABORT, Fixture, PEER_IP, SUM, UDP_ECHO, endpoint};
use super::{ECHO, TIMEOUT, dial, echo_roundtrip, generation, proxies};
use crate::group::ScoreOutcome;
use crate::proxy::{node_failure, target_failure};

#[tokio::test]
async fn bulk_transfer_is_exact_in_both_directions() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let stream = dial(&generation, &fixture.node, ECHO).await.unwrap();
    let (mut read, mut write) = tokio::io::split(stream.stream);
    let total = 2 * 1024 * 1024;
    let pattern = |i: usize| (i.wrapping_mul(31) ^ (i >> 8)) as u8;
    let writer = tokio::spawn(async move {
        let mut sent = 0;
        while sent < total {
            let n = (total - sent).min(16 * 1024 + 7);
            let chunk: Vec<u8> = (sent..sent + n).map(pattern).collect();
            write.write_all(&chunk).await.unwrap();
            sent += n;
        }
        write.shutdown().await.unwrap();
    });
    let mut received = 0;
    let mut buf = vec![0u8; 32 * 1024];
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let n = read.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            for (offset, byte) in buf[..n].iter().enumerate() {
                assert_eq!(
                    *byte,
                    pattern(received + offset),
                    "byte {}",
                    received + offset
                );
            }
            received += n;
        }
    })
    .await
    .expect("bulk transfer finished");
    writer.await.unwrap();
    assert_eq!(received, total);
}

#[tokio::test]
async fn write_shutdown_keeps_the_read_half_open() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let mut stream = dial(&generation, &fixture.node, SUM).await.unwrap();
    stream.stream.write_all(&vec![7u8; 100_000]).await.unwrap();
    stream.stream.shutdown().await.unwrap();
    let mut reply = String::new();
    tokio::time::timeout(TIMEOUT, stream.stream.read_to_string(&mut reply))
        .await
        .expect("peer answers after our FIN")
        .unwrap();
    assert_eq!(reply, "done:100000");
}

#[tokio::test]
async fn inner_rst_on_syn_is_a_target_failure() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let error = dial(&generation, &fixture.node, 1).await.unwrap_err();
    assert!(target_failure(&error), "{error:#}");
    assert!(!node_failure(&error));
    assert_eq!(
        ScoreOutcome::from_error(&error),
        ScoreOutcome::TargetFailure
    );
}

#[tokio::test]
async fn inner_rst_after_connect_surfaces_as_connection_reset() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let mut stream = dial(&generation, &fixture.node, ABORT).await.unwrap();
    stream.stream.write_all(b"x").await.unwrap();
    let error = tokio::time::timeout(TIMEOUT, stream.stream.read(&mut [0; 8]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn handshake_timeout_is_one_node_failure_episode() {
    let fixture = Fixture::new().await;
    fixture.peer.control.mute.store(true, Ordering::Relaxed);
    let generation = generation(&fixture.node);
    let timeout = Duration::from_millis(2500);
    // Two dialers time out in the same instant; a third joins later and still sees the same failure.
    let (first, second, late) = tokio::join!(
        dial_with(&generation, &fixture.node, timeout),
        dial_with(&generation, &fixture.node, timeout),
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            dial_with(&generation, &fixture.node, Duration::from_secs(10)).await
        }
    );
    let outcomes: Vec<_> = [first, second, late]
        .into_iter()
        .map(|result| ScoreOutcome::from_error(&result.unwrap_err()))
        .collect();
    assert!(
        matches!(outcomes[0], ScoreOutcome::SharedNodeFailure(_)),
        "{outcomes:?}"
    );
    assert!(
        outcomes.iter().all(|outcome| *outcome == outcomes[0]),
        "one failure episode for every waiter: {outcomes:?}"
    );
}

async fn dial_with(
    generation: &std::sync::Arc<crate::runtime::OutboundRuntimeRegistry>,
    node: &honk_config::node::Node,
    timeout: Duration,
) -> anyhow::Result<crate::proxy::ProxyStream> {
    proxies()
        .dial_runtime(
            std::sync::Arc::clone(generation),
            node.id,
            endpoint(PEER_IP, ECHO),
            None,
            timeout,
        )
        .await
}

#[tokio::test]
async fn unanswered_syn_with_a_silent_peer_stays_node_conservative() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    // Establish the tunnel, then make the path silent: no inner packet answers the SYN.
    drop(dial(&generation, &fixture.node, ECHO).await.unwrap());
    fixture.peer.control.mute.store(true, Ordering::Relaxed);
    let error = dial_with(&generation, &fixture.node, Duration::from_millis(1500))
        .await
        .unwrap_err();
    assert_eq!(
        ScoreOutcome::from_error(&error),
        ScoreOutcome::Timeout,
        "{error:#}"
    );
    assert!(!target_failure(&error));
}

#[tokio::test]
async fn unanswered_syn_while_the_peer_answers_other_traffic_is_a_target_failure() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    drop(dial(&generation, &fixture.node, ECHO).await.unwrap());
    fixture.peer.control.drop_tcp.store(true, Ordering::Relaxed);
    let udp = proxies()
        .dial_udp_transport_runtime(
            std::sync::Arc::clone(&generation),
            fixture.node.id,
            endpoint(PEER_IP, UDP_ECHO),
            None,
            TIMEOUT,
        )
        .await
        .unwrap();
    let chatter = tokio::spawn(async move {
        loop {
            let _ = udp.send_packet(b"ping").await;
            let _ = udp.recv_packet(&mut [0; 64]).await;
        }
    });
    let error = dial_with(&generation, &fixture.node, Duration::from_millis(1500))
        .await
        .unwrap_err();
    chatter.abort();
    assert!(target_failure(&error), "{error:#}");
    assert!(
        fixture
            .peer
            .control
            .inner_tcp_dropped
            .load(Ordering::Relaxed)
            > 0
    );
}

#[tokio::test]
async fn targets_outside_allowed_ips_are_refused_before_any_packet() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let outside = endpoint(std::net::Ipv4Addr::new(192, 0, 2, 1), 80);
    let error = proxies()
        .dial_runtime(generation, fixture.node.id, outside, None, TIMEOUT)
        .await
        .unwrap_err();
    assert!(target_failure(&error), "{error:#}");
    assert!(
        fixture.peer.wire.lock().is_empty(),
        "no handshake for a refused target"
    );
}

#[tokio::test]
async fn a_standalone_dial_and_reserved_bytes_reach_the_wire() {
    let fixture = Fixture::with(Some([7, 8, 9]), |_| {}).await;
    let mut stream = proxies()
        .dial(&fixture.node, endpoint(PEER_IP, ECHO), None, TIMEOUT)
        .await
        .unwrap();
    echo_roundtrip(&mut stream, b"reserved").await;
    let wire = fixture.peer.wire.lock().clone();
    assert!(wire.len() >= 3);
    for header in &wire {
        assert_eq!(
            &header[1..],
            &[7, 8, 9],
            "every datagram carries the reserved bytes"
        );
    }
    assert_eq!(
        wire[0][0], 1,
        "the first datagram is the handshake initiation"
    );
}

#[tokio::test]
async fn a_zero_capacity_read_completes_without_waiting_for_data() {
    let fixture = Fixture::new().await;
    let generation = generation(&fixture.node);
    let mut stream = dial(&generation, &fixture.node, ECHO).await.unwrap();
    let n = tokio::time::timeout(Duration::from_millis(500), stream.stream.read(&mut []))
        .await
        .expect("an empty buffer never blocks")
        .unwrap();
    assert_eq!(n, 0);
    echo_roundtrip(&mut stream, b"unharmed").await;
}

#[tokio::test]
async fn bare_tcp_reuse_is_refused() {
    use crate::proxy::TcpOutbound as _;
    let fixture = Fixture::new().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let handler = super::super::WireGuardHandler::new();
    let error = handler
        .dial_with_tcp(&fixture.node, endpoint(PEER_IP, ECHO), None, tcp, TIMEOUT)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("bare TCP"));
}

#[tokio::test]
async fn a_tcp_target_in_a_family_without_a_tunnel_address_is_refused_before_the_handshake() {
    // Allowed, but the tunnel has no IPv6 address to source packets from.
    let fixture = Fixture::with(None, |config| {
        config.allowed_ips.push("::/0".parse().unwrap());
    })
    .await;
    let generation = generation(&fixture.node);
    let v6 = SocketAddr::new("fd00::1".parse().unwrap(), 80);
    let error = proxies()
        .dial_runtime(generation, fixture.node.id, v6, None, TIMEOUT)
        .await
        .unwrap_err();
    assert!(target_failure(&error), "{error:#}");
    assert!(!node_failure(&error), "{error:#}");
    assert_eq!(
        fixture.peer.control.handshakes.load(Ordering::Relaxed),
        0,
        "refused locally: no handshake for a flow that cannot be sent"
    );
}
