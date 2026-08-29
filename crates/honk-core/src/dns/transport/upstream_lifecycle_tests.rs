use std::sync::Arc;
use std::time::Duration;

use honk_config::dns::{DnsRouting, DnsUpstream};
use honk_config::node::Node;
use honk_config::types::{DnsProtocol, NodeProtocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::dns::forwarder::DnsUpstreamPool;
use crate::dns::routing::DnsRouter;
use crate::dns::upstream_pool::UpstreamPool;
use crate::routing::Router;

#[tokio::test]
async fn tcp_transport_lifecycle_is_single_flight_and_closes_once() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        for _ in 0..128 {
            let (mut stream, _) = listener.accept().await.expect("accept");
            connections.spawn(async move {
                let mut length = [0_u8; 2];
                stream.read_exact(&mut length).await.expect("query length");
                let query_length = usize::from(u16::from_be_bytes(length));
                let mut query = vec![0_u8; query_length];
                stream.read_exact(&mut query).await.expect("query");
                let mut response = vec![0_u8; 12];
                response[..2].copy_from_slice(&query[..2]);
                response[2] = 0x81;
                response[3] = 0x80;
                stream
                    .write_all(&(response.len() as u16).to_be_bytes())
                    .await
                    .expect("response length");
                stream.write_all(&response).await.expect("response");
            });
        }
        while let Some(connection) = connections.join_next().await {
            connection.expect("connection task");
        }
    });
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            fallback: "tcp".to_string(),
            ..Default::default()
        })
        .expect("router"),
    );
    let pool = Arc::new(
        UpstreamPool::new(
            &[DnsUpstream {
                name: "tcp".to_string(),
                address: address.to_string(),
                protocol: DnsProtocol::Tcp,
                tls_server_name: None,
                outbound: None,
            }],
            router,
        )
        .expect("pool"),
    );
    let query = Arc::new(vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let gate = Arc::new(tokio::sync::Barrier::new(128));
    let mut callers = tokio::task::JoinSet::new();
    for _ in 0..128 {
        let pool = Arc::clone(&pool);
        let query = Arc::clone(&query);
        let gate = Arc::clone(&gate);
        callers.spawn(async move {
            gate.wait().await;
            pool.query("tcp", &query).await
        });
    }

    // When
    while let Some(response) = callers.join_next().await {
        assert_eq!(
            response.expect("query task").expect("query response").len(),
            12
        );
    }
    pool.close().await;
    pool.close().await;
    server.await.expect("server task");

    // Then
    let stats = pool.lifecycle_stats();
    assert_eq!(stats.init_count, 1);
    assert_eq!(stats.close_count, 1);
    assert_eq!(stats.tasks, 0);
    assert!(pool.query("tcp", &query).await.is_err());
}

#[tokio::test]
async fn proxied_quic_transports_use_packet_outbound() {
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            fallback: "doq".to_string(),
            ..Default::default()
        })
        .expect("router"),
    );
    let proxy = Node {
        name: "proxy".to_string(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Block),
        ..Default::default()
    };
    let upstreams = [
        DnsUpstream {
            name: "doq".to_string(),
            address: "127.0.0.1:853".to_string(),
            protocol: DnsProtocol::Quic,
            tls_server_name: Some("dns.test".to_string()),
            outbound: Some("proxy".to_string()),
        },
        DnsUpstream {
            name: "doh3".to_string(),
            address: "127.0.0.1:443/dns-query".to_string(),
            protocol: DnsProtocol::H3,
            tls_server_name: Some("dns.test".to_string()),
            outbound: Some("proxy".to_string()),
        },
    ];
    let registry = Arc::new(crate::proxy::ProxyRegistry::default_resolver().expect("registry"));
    let pool =
        UpstreamPool::new_with_proxy(&upstreams, router, Some(registry), vec![proxy], Vec::new())
            .expect("pool");
    let query = [0_u8; 12];

    let doq = pool.query("doq", &query).await.expect_err("blocked DoQ");
    let doh3 = pool.query("doh3", &query).await.expect_err("blocked DoH3");
    let doq_chain = format!("{doq:#}");
    let doh3_chain = format!("{doh3:#}");

    assert!(doq_chain.contains("UDP connection blocked"), "{doq_chain}");
    assert!(
        doh3_chain.contains("UDP connection blocked"),
        "{doh3_chain}"
    );
    assert!(!doq_chain.contains("does not support outbound"));
    assert!(!doh3_chain.contains("does not support outbound"));
    assert_eq!(pool.lifecycle_stats().init_count, 2);
}

#[tokio::test]
async fn proxied_quic_without_registry_fails_closed() {
    let upstream = DnsUpstream {
        name: "doq".into(),
        address: "127.0.0.1:853".into(),
        protocol: DnsProtocol::Quic,
        tls_server_name: Some("dns.test".into()),
        outbound: Some("proxy".into()),
    };
    let proxy = Node {
        name: "proxy".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Block),
        ..Default::default()
    };
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            fallback: "doq".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    let pool =
        UpstreamPool::new_with_proxy(&[upstream], router, None, vec![proxy], vec![]).unwrap();

    let error = pool.query("doq", &[0; 12]).await.unwrap_err();
    let error_chain = format!("{error:#}");
    assert!(
        error_chain.contains("without a proxy registry"),
        "{error_chain}"
    );
}

#[tokio::test]
async fn overlapping_close_waits_for_inflight_query_drain() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("listener address");
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut length = [0_u8; 2];
        stream.read_exact(&mut length).await.expect("query length");
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut query).await.expect("query");
        let _ = request_tx.send(());
        let _ = response_rx.await;
        let mut response = vec![0_u8; 12];
        response[..2].copy_from_slice(&query[..2]);
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .expect("response length");
        stream.write_all(&response).await.expect("response");
    });
    let pool = Arc::new(
        UpstreamPool::new(
            &[DnsUpstream {
                name: "tcp".to_string(),
                address: address.to_string(),
                protocol: DnsProtocol::Tcp,
                tls_server_name: None,
                outbound: None,
            }],
            Arc::new(
                DnsRouter::new(&DnsRouting {
                    fallback: "tcp".to_string(),
                    ..Default::default()
                })
                .expect("router"),
            ),
        )
        .expect("pool"),
    );
    let query_pool = Arc::clone(&pool);
    let query = tokio::spawn(async move { query_pool.query("tcp", &[0_u8; 12]).await });
    request_rx.await.expect("query reached server");
    let first_pool = Arc::clone(&pool);
    let first_close = tokio::spawn(async move { first_pool.close().await });
    tokio::task::yield_now().await;
    let second_pool = Arc::clone(&pool);
    let mut second_close = tokio::spawn(async move { second_pool.close().await });

    // When
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut second_close)
            .await
            .is_err(),
        "second close returned before the inflight transport drained"
    );
    response_tx.send(()).expect("release response");
    query
        .await
        .expect("query task")
        .expect("query response after release");
    first_close.await.expect("first close task");
    second_close.await.expect("second close task");
    server.await.expect("server task");

    // Then
    let stats = pool.lifecycle_stats();
    assert_eq!(stats.close_count, 1);
    assert_eq!(stats.tasks, 0);
}

#[tokio::test]
async fn query_paused_in_leaf_routing_cannot_publish_after_close() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut length = [0_u8; 2];
        stream.read_exact(&mut length).await.expect("query length");
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut query).await.expect("query");
        let response = vec![0_u8; 12];
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .expect("response length");
        stream.write_all(&response).await.expect("response");
    });
    let pool = Arc::new(
        UpstreamPool::new(
            &[DnsUpstream {
                name: "tcp".to_string(),
                address: address.to_string(),
                protocol: DnsProtocol::Tcp,
                tls_server_name: None,
                outbound: None,
            }],
            Arc::new(
                DnsRouter::new(&DnsRouting {
                    fallback: "tcp".to_string(),
                    ..Default::default()
                })
                .expect("dns router"),
            ),
        )
        .expect("pool"),
    );
    let traffic = Arc::new(tokio::sync::RwLock::new(
        Router::new(&[], "direct").expect("traffic router"),
    ));
    pool.set_traffic_router(Some(Arc::clone(&traffic)));
    let baseline_refs = Arc::strong_count(&traffic);
    let write_guard = traffic.write().await;
    let query_pool = Arc::clone(&pool);
    let query = tokio::spawn(async move { query_pool.query("tcp", &[0_u8; 12]).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&traffic) == baseline_refs {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("query paused in leaf routing");

    // When
    pool.close().await;
    drop(write_guard);
    let result = query.await.expect("query task");
    server.abort();
    let _ = server.await;

    // Then
    assert!(
        result
            .expect_err("closed pool rejects publication")
            .to_string()
            .contains("closed")
    );
    let stats = pool.lifecycle_stats();
    assert_eq!(stats.init_count, 0);
    assert_eq!(stats.close_count, 0);
    assert_eq!(stats.tasks, 0);
}

#[tokio::test]
async fn stalled_tls_setups_use_dial_timeout_for_dot_and_doh() {
    for protocol in [DnsProtocol::Tls, DnsProtocol::Https] {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let mut _connections = Vec::new();
            for _ in 0..2 {
                _connections.push(listener.accept().await.expect("accept").0);
            }
            std::future::pending::<()>().await;
        });
        let endpoint = match protocol {
            DnsProtocol::Https => format!("localhost:{}/dns-query", address.port()),
            _ => address.to_string(),
        };
        let pool = UpstreamPool::new(
            &[DnsUpstream {
                name: "tls".to_string(),
                address: endpoint,
                protocol,
                tls_server_name: Some("localhost".to_string()),
                outbound: None,
            }],
            Arc::new(
                DnsRouter::new(&DnsRouting {
                    fallback: "tls".to_string(),
                    ..Default::default()
                })
                .expect("router"),
            ),
        )
        .expect("pool")
        .with_timeouts(Duration::from_secs(5), Duration::from_millis(20));

        let result = tokio::time::timeout(Duration::from_secs(1), pool.query("tls", &[0_u8; 12]))
            .await
            .expect("TLS setup ignored dial timeout")
            .expect_err("stalled TLS setup must fail");
        let error_chain = format!("{result:#}");

        assert!(
            error_chain.contains("timed out"),
            "unexpected {protocol:?} setup error: {error_chain}"
        );
        pool.close().await;
        assert_eq!(pool.lifecycle_stats().tasks, 0);
        server.abort();
        let _ = server.await;
    }
}
