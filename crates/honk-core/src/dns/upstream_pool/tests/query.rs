use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use honk_config::dns::DnsStrategy;
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};

use super::*;
use crate::dns::forwarder::DnsUpstreamPool;
use crate::routing::Router;

async fn bind_matching_tcp_udp(
    tcp_ip: IpAddr,
    udp_ip: IpAddr,
) -> (TcpListener, UdpSocket, SocketAddr) {
    const MAX_ATTEMPTS: usize = 8;
    let mut last_error = None;

    for _ in 0..MAX_ATTEMPTS {
        let tcp = TcpListener::bind(SocketAddr::new(tcp_ip, 0)).await.unwrap();
        let address = SocketAddr::new(udp_ip, tcp.local_addr().unwrap().port());
        match UdpSocket::bind(address).await {
            Ok(udp) => return (tcp, udp, address),
            Err(error) => last_error = Some(error),
        }
    }

    panic!(
        "could not bind matching TCP/UDP listeners after {MAX_ATTEMPTS} attempts: {}",
        last_error.unwrap()
    );
}

#[tokio::test]
async fn test_udp_query() {
    let response = mock_dns_response(0x1234);
    let response_clone = response.clone();
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (length, source) = server.recv_from(&mut buffer).await.unwrap();
        assert!(length > 0);
        let mut response = response_clone;
        response[..2].copy_from_slice(&buffer[..2]);
        server.send_to(&response, source).await.unwrap();
    });

    let upstream = make_upstream("test-udp", &server_address.to_string(), DnsProtocol::Udp);
    let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
    let result = pool
        .query("test-udp", &mock_dns_query(0x1234))
        .await
        .expect("UDP query should succeed");

    assert_eq!(result, response);
    server_handle.await.unwrap();
}

#[tokio::test]
async fn configured_ecs_is_added_for_direct_route() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (length, source) = server.recv_from(&mut buffer).await.unwrap();
        let request = buffer[..length].to_vec();
        let mut response = request.clone();
        response[2] |= 0x80;
        server.send_to(&response, source).await.unwrap();
        request
    });

    let upstream = DnsUpstream {
        outbound: Some("direct".into()),
        ..make_upstream("ecs-direct", &server_address.to_string(), DnsProtocol::Udp)
    };
    let pool = UpstreamPool::new(&[upstream], make_router())
        .unwrap()
        .with_client_subnet(Some("203.0.113.0/24".parse().unwrap()));
    let query = mock_dns_query(0x1234);
    let response = pool.query("ecs-direct", &query).await.unwrap();

    let seen = server_handle.await.unwrap();
    assert!(seen.ends_with(&[0, 8, 0, 7, 0, 1, 24, 0, 203, 0, 113]));
    let mut expected = query;
    expected[2] |= 0x80;
    assert_eq!(response, expected);
}

#[tokio::test]
async fn udp_prefer_ipv6_falls_back_to_ipv4_and_reuses_winner() {
    let upstream_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_server.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        for _ in 0..2 {
            let (_, source) = upstream_server.recv_from(&mut buffer).await.unwrap();
            let mut response = mock_dns_response(0);
            response[..2].copy_from_slice(&buffer[..2]);
            upstream_server.send_to(&response, source).await.unwrap();
        }
    });
    let (bootstrap_address, bootstrap_task) = spawn_dual_stack_bootstrap(2).await;
    let resolver =
        honk_outbound::bootstrap::BootstrapResolver::parse(&format!("udp://{bootstrap_address}"));
    let upstream = make_upstream(
        "dual",
        &format!("dual.test:{}", upstream_address.port()),
        DnsProtocol::Udp,
    );
    let pool = UpstreamPool::new_with_proxy_and_bootstrap(
        &[upstream],
        make_router(),
        None,
        Vec::new(),
        Vec::new(),
        resolver,
        DnsStrategy::PreferIpv6,
    )
    .unwrap()
    .with_timeouts(Duration::from_millis(50), Duration::from_millis(100));

    for transaction_id in [0x1234, 0x5678] {
        let response = pool
            .query("dual", &mock_dns_query(transaction_id))
            .await
            .expect("IPv4 fallback response");
        assert_eq!(response, mock_dns_response(transaction_id));
    }
    assert!(pool.entries["dual"].udp.lock().current.unwrap().is_ipv4());

    pool.close().await;
    upstream_task.await.unwrap();
    bootstrap_task.await.unwrap();
}

#[tokio::test]
async fn udp_cold_retry_rechecks_route_for_alternate_address() {
    let (tcp_server, udp_server, upstream_address) =
        bind_matching_tcp_udp(Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()).await;
    let upstream_port = upstream_address.port();
    let udp_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (length, _) = udp_server.recv_from(&mut buffer).await.unwrap();
        buffer[..length].to_vec()
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp_server.accept().await.unwrap();
        let mut length = [0_u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut query).await.unwrap();
        let response = mock_dns_response(u16::from_be_bytes([query[0], query[1]]));
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&response).await.unwrap();
        query
    });
    let (bootstrap_address, bootstrap_task) = spawn_dual_stack_bootstrap(4).await;
    let resolver =
        honk_outbound::bootstrap::BootstrapResolver::parse(&format!("udp://{bootstrap_address}"));
    let node = Node {
        protocol: honk_config::types::NodeProtocol::Direct,
        ..test_node("retry-proxy")
    };
    let traffic = Arc::new(tokio::sync::RwLock::new(
        Router::new(
            &[RoutingRule {
                name: "alternate-proxy".into(),
                condition: RoutingCondition {
                    ip: vec!["::1/128".into()],
                    ..Default::default()
                },
                outbound: RoutingOutbound::Simple(node.name.clone()),
                priority: 0,
                must: false,
                mark: 0,
            }],
            "direct",
        )
        .unwrap(),
    ));
    let upstream = make_upstream(
        "route-diff",
        &format!("route-diff.test:{upstream_port}"),
        DnsProtocol::Udp,
    );
    let pool = UpstreamPool::new_with_proxy_and_bootstrap(
        &[upstream],
        make_router(),
        Some(Arc::new(
            crate::proxy::ProxyRegistry::default_resolver().expect("proxy registry"),
        )),
        vec![node],
        Vec::new(),
        resolver,
        DnsStrategy::PreferIpv4,
    )
    .unwrap()
    .with_traffic_router(traffic)
    .with_timeouts(Duration::from_millis(50), Duration::from_secs(1))
    .with_client_subnet(Some("203.0.113.0/24".parse().unwrap()));

    let query = mock_dns_query(0x1234);
    let response = pool
        .query("route-diff", &query)
        .await
        .expect("alternate address follows its proxy route");
    assert_eq!(response, mock_dns_response(0x1234));

    let direct_query = udp_task.await.unwrap();
    let proxy_query = tcp_task.await.unwrap();
    assert!(direct_query.ends_with(&[0, 8, 0, 7, 0, 1, 24, 0, 203, 0, 113]));
    assert_eq!(proxy_query[2..], query[2..]);
    pool.close().await;
    bootstrap_task.await.unwrap();
}

#[tokio::test]
async fn udp_warm_pool_answers_after_bootstrap_stops() {
    let upstream_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_server.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        for _ in 0..2 {
            let (_, source) = upstream_server.recv_from(&mut buffer).await.unwrap();
            let mut response = mock_dns_response(0);
            response[..2].copy_from_slice(&buffer[..2]);
            upstream_server.send_to(&response, source).await.unwrap();
        }
    });
    let (bootstrap_address, bootstrap_task) = spawn_dual_stack_bootstrap(2).await;
    let resolver =
        honk_outbound::bootstrap::BootstrapResolver::parse(&format!("udp://{bootstrap_address}"));
    let upstream = make_upstream(
        "warm",
        &format!("warm.test:{}", upstream_address.port()),
        DnsProtocol::Udp,
    );
    let pool = UpstreamPool::new_with_proxy_and_bootstrap(
        &[upstream],
        make_router(),
        None,
        Vec::new(),
        Vec::new(),
        resolver,
        DnsStrategy::PreferIpv4,
    )
    .unwrap()
    .with_timeouts(Duration::from_millis(100), Duration::from_millis(100));

    let first = pool
        .query("warm", &mock_dns_query(0x1234))
        .await
        .expect("initial UDP response");
    assert_eq!(first, mock_dns_response(0x1234));
    bootstrap_task.await.unwrap();

    let second = pool
        .query("warm", &mock_dns_query(0x5678))
        .await
        .expect("warm UDP response without bootstrap");
    assert_eq!(second, mock_dns_response(0x5678));

    pool.close().await;
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn udp_literals_respect_strict_family_strategy() {
    for (address, strategy) in [
        ("127.0.0.1:9", DnsStrategy::Ipv6Only),
        ("[::1]:9", DnsStrategy::Ipv4Only),
    ] {
        let upstream = make_upstream("literal", address, DnsProtocol::Udp);
        let pool = UpstreamPool::new_with_proxy_and_bootstrap(
            &[upstream],
            make_router(),
            None,
            Vec::new(),
            Vec::new(),
            None,
            strategy,
        )
        .unwrap();

        let error = pool
            .query("literal", &mock_dns_query(0x1234))
            .await
            .expect_err("opposite-family literal must be rejected");
        assert!(
            error.to_string().contains("no addresses allowed"),
            "unexpected family-filter error: {error:#}"
        );
    }
}

#[tokio::test]
async fn replacing_same_family_pool_preserves_in_flight_exchange() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let replacement_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let replacement_address = replacement_server.local_addr().unwrap();
    let (in_flight_tx, in_flight_rx) = tokio::sync::oneshot::channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let server_release = Arc::clone(&release);
    let server_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];

        let (_, source) = server.recv_from(&mut buffer).await.unwrap();
        let mut response = mock_dns_response(0);
        response[..2].copy_from_slice(&buffer[..2]);
        server.send_to(&response, source).await.unwrap();

        let (_, source) = server.recv_from(&mut buffer).await.unwrap();
        in_flight_tx.send(()).unwrap();
        server_release.notified().await;
        let mut response = mock_dns_response(0);
        response[..2].copy_from_slice(&buffer[..2]);
        server.send_to(&response, source).await.unwrap();
    });
    let upstream = make_upstream("replace", &address.to_string(), DnsProtocol::Udp);
    let pool = Arc::new(
        UpstreamPool::new(&[upstream], make_router())
            .unwrap()
            .with_timeouts(Duration::from_secs(1), Duration::from_secs(1)),
    );
    pool.query("replace", &mock_dns_query(0x1234))
        .await
        .expect("initial UDP response");

    let query_pool = Arc::clone(&pool);
    let in_flight =
        tokio::spawn(async move { query_pool.query("replace", &mock_dns_query(0x5678)).await });
    in_flight_rx.await.unwrap();

    let replacement = pool
        .udp_pool(&pool.entries["replace"], replacement_address)
        .await
        .unwrap();
    release.notify_one();

    let response = in_flight
        .await
        .expect("query task")
        .expect("in-flight exchange survives replacement");
    assert_eq!(response, mock_dns_response(0x5678));
    {
        let state = pool.entries["replace"].udp.lock();
        assert_eq!(state.current, None);
        assert_eq!(
            state.pools[0].as_ref().map(|(address, _)| *address),
            Some(replacement_address)
        );
    }

    drop(replacement);
    pool.close().await;
    server_task.await.unwrap();
}

async fn spawn_dual_stack_bootstrap(
    requests: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..requests {
            let mut query = [0_u8; 512];
            let (length, source) = server.recv_from(&mut query).await.unwrap();
            let query = &query[..length];
            let qtype = u16::from_be_bytes([query[length - 4], query[length - 3]]);
            let mut response = query.to_vec();
            response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            response[6..8].copy_from_slice(&1_u16.to_be_bytes());
            if qtype == 1 {
                response.extend_from_slice(&[
                    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 127, 0,
                    0, 1,
                ]);
            } else {
                response.extend_from_slice(&[
                    0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]);
            }
            server.send_to(&response, source).await.unwrap();
        }
    });
    (address, task)
}

#[tokio::test]
async fn test_tcp_query_pooled() {
    let response = mock_dns_response(0x5678);
    let response_clone = response.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_address = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        for _ in 0..2 {
            let mut length_buffer = [0_u8; 2];
            stream.read_exact(&mut length_buffer).await.unwrap();
            let query_length = usize::from(u16::from_be_bytes(length_buffer));
            let mut query_buffer = vec![0_u8; query_length];
            stream.read_exact(&mut query_buffer).await.unwrap();
            assert!(!query_buffer.is_empty());

            let response_length = u16::try_from(response_clone.len()).unwrap();
            stream
                .write_all(&response_length.to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response_clone).await.unwrap();
        }
    });

    let upstream = make_upstream("test-tcp", &server_address.to_string(), DnsProtocol::Tcp);
    let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
    let query = mock_dns_query(0x5678);
    let first = pool.query("test-tcp", &query).await.expect("TCP query 1");
    let second = pool.query("test-tcp", &query).await.expect("TCP query 2");
    assert_eq!(first, response);
    assert_eq!(second, response);
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_udp_hedged_retry_on_loss() {
    let response = mock_dns_response(0x1234);
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let response_clone = response.clone();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let _ = server.recv_from(&mut buffer).await.unwrap();
        let (_, source) = server.recv_from(&mut buffer).await.unwrap();
        let mut response = response_clone;
        response[..2].copy_from_slice(&buffer[..2]);
        server.send_to(&response, source).await.unwrap();
    });

    let upstream = make_upstream("hedged", &server_address.to_string(), DnsProtocol::Udp);
    let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
    let result = pool
        .query("hedged", &mock_dns_query(0x1234))
        .await
        .expect("hedged retry should succeed");
    assert_eq!(result, response);
}

#[tokio::test]
async fn test_udp_txid_mismatch_discarded() {
    let wrong = mock_dns_response(0x9999);
    let right = mock_dns_response(0x1234);
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let right_clone = right.clone();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (_, source) = server.recv_from(&mut buffer).await.unwrap();
        server.send_to(&wrong, source).await.unwrap();
        let mut response = right_clone;
        response[..2].copy_from_slice(&buffer[..2]);
        server.send_to(&response, source).await.unwrap();
    });

    let upstream = make_upstream("txid", &server_address.to_string(), DnsProtocol::Udp);
    let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
    let result = pool
        .query("txid", &mock_dns_query(0x1234))
        .await
        .expect("query should succeed");
    assert_eq!(result, right);
}

#[tokio::test]
async fn udp_truncated_fallback_reuses_tcp_connection_and_closes_once() {
    let mut truncated = mock_dns_response(0x1234);
    truncated[2] |= 0x02;
    let full = mock_dns_response(0x1234);
    let (tcp_listener, udp_server, address) =
        bind_matching_tcp_udp(Ipv4Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()).await;
    let udp_responder = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        for _ in 0..2 {
            let (_, source) = udp_server.recv_from(&mut buffer).await.unwrap();
            let mut response = truncated.clone();
            response[..2].copy_from_slice(&buffer[..2]);
            udp_server.send_to(&response, source).await.unwrap();
        }
    });
    let full_clone = full.clone();
    let tcp_responder = tokio::spawn(async move {
        let (mut stream, _) = tcp_listener.accept().await.unwrap();
        for _ in 0..2 {
            let mut length_buffer = [0_u8; 2];
            stream.read_exact(&mut length_buffer).await.unwrap();
            let query_length = usize::from(u16::from_be_bytes(length_buffer));
            let mut query_buffer = vec![0_u8; query_length];
            stream.read_exact(&mut query_buffer).await.unwrap();
            let response_length = u16::try_from(full_clone.len()).unwrap();
            stream
                .write_all(&response_length.to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&full_clone).await.unwrap();
        }
    });

    let upstream = make_upstream("tc", &address.to_string(), DnsProtocol::Udp);
    let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
    let query = mock_dns_query(0x1234);
    for _ in 0..2 {
        let result = pool
            .query("tc", &query)
            .await
            .expect("TC upgrade should succeed");
        assert_eq!(result, full);
    }
    assert_eq!(pool.lifecycle_stats().init_count, 1);

    pool.close().await;
    udp_responder.await.unwrap();
    tcp_responder.await.unwrap();
    let stats = pool.lifecycle_stats();
    assert_eq!(stats.close_count, 1);
    assert_eq!(stats.tasks, 0);
}

#[test]
fn parses_encrypted_upstream_at_construction() {
    let upstreams = [
        make_upstream("dot", "dns.google", DnsProtocol::Tls),
        make_upstream("doh", "cloudflare-dns.com/dns-query", DnsProtocol::Https),
        make_upstream("doq", "dns.adguard.com", DnsProtocol::Quic),
        make_upstream("h3", "cloudflare-dns.com/dns-query", DnsProtocol::H3),
    ];
    let pool = UpstreamPool::new(&upstreams, make_router()).unwrap();
    assert_eq!(pool.upstream_count(), 4);
}
