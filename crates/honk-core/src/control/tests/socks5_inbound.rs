//! End-to-end checks for `inbound.socks5` listeners: the RFC 1929 gate and
//! per-user routing with `user()` rules (mihomo's `in-user` analogue).

use super::support::test_dns_forwarder;
use crate::control::ControlPlane;
use crate::control::inbound_listener::{BoundInboundListener, InboundKind};
use crate::dns::DnsResolver;
use crate::ebpf::mock::MockEbpfBackend;
use crate::proxy::ProxyRegistry;
use crate::routing::Router;
use honk_config::Config;
use honk_config::inbound::Socks5User;
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Greeting plus RFC 1929 subnegotiation; returns the two status bytes.
async fn socks5_auth(proxy: SocketAddr, user: &str, password: &str) -> (Vec<u8>, TcpStream) {
    let mut stream = TcpStream::connect(proxy).await.expect("connect");
    stream.write_all(&[5, 1, 2]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 2], "username/password method is accepted");
    let mut request = vec![1, user.len() as u8];
    request.extend_from_slice(user.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password.as_bytes());
    stream.write_all(&request).await.unwrap();
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await.unwrap();
    (status.to_vec(), stream)
}

/// CONNECT an IPv4 target and return the 10-byte command reply.
async fn socks5_connect(stream: &mut TcpStream, target: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(target) = target else {
        unreachable!("test targets are IPv4");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = vec![0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    reply
}

fn user_rule(user: &str, outbound: &str) -> RoutingRule {
    RoutingRule {
        name: format!("{user}-route"),
        condition: RoutingCondition {
            user: vec![user.into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple(outbound.into()),
        priority: 0,
        must: false,
        mark: 0,
    }
}

#[tokio::test]
async fn socks5_inbound_authenticates_then_routes_by_user() -> anyhow::Result<()> {
    // The echo origin stands in for the real destination of a direct flow.
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut client, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut payload = [0u8; 4];
                if client.read_exact(&mut payload).await.is_ok() {
                    let _ = client.write_all(&payload).await;
                }
            });
        }
    });

    let mut config = Config::default();
    config.routing.default_outbound = "block".into();
    config.routing.rules.push(user_rule("alice", "direct"));
    config.routing.rules.push(user_rule("bob", "block"));
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let plane = ControlPlane::new(
        config,
        Box::new(MockEbpfBackend::new()),
        router,
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        test_dns_forwarder(),
    )
    .unwrap();
    let bound = BoundInboundListener::bind(
        InboundKind::Socks5,
        "127.0.0.1:0",
        &[
            Socks5User {
                username: "alice".into(),
                password: "pw-a".into(),
            },
            Socks5User {
                username: "bob".into(),
                password: "pw-b".into(),
            },
            Socks5User {
                username: "carol".into(),
                password: "pw-c".into(),
            },
        ],
    )?;
    let proxy_addr = bound.local_addr()?;
    let mut listener = bound.spawn(
        plane.spawn_handle(),
        plane.concurrency_limit.clone(),
        plane.drain_tracker.clone(),
    )?;

    // A client offering only the no-auth method is refused before any credential.
    {
        let mut stream = TcpStream::connect(proxy_addr).await?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        assert_eq!(reply, [5, 0xFF]);
    }
    // A wrong password is refused at the subnegotiation gate.
    let (status, _rejected) = socks5_auth(proxy_addr, "alice", "wrong").await;
    assert_eq!(status, vec![1, 1]);

    // alice matches the direct user() rule and relays bytes end to end.
    let (status, mut stream) = socks5_auth(proxy_addr, "alice", "pw-a").await;
    assert_eq!(status, vec![1, 0]);
    let reply = socks5_connect(&mut stream, echo_addr).await;
    assert_eq!(reply[1], 0, "alice routes direct");
    assert_eq!(reply[3], 1, "IPv4 binding field is set");
    stream.write_all(b"ping").await?;
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"ping");
    drop(stream);

    // bob is routed to block by his own user() rule.
    let (status, mut stream) = socks5_auth(proxy_addr, "bob", "pw-b").await;
    assert_eq!(status, vec![1, 0]);
    let reply = socks5_connect(&mut stream, echo_addr).await;
    assert_eq!(reply[1], 2, "bob routes block");
    drop(stream);

    // carol authenticates but matches no rule; the block fallback applies.
    let (status, mut stream) = socks5_auth(proxy_addr, "carol", "pw-c").await;
    assert_eq!(status, vec![1, 0]);
    let reply = socks5_connect(&mut stream, echo_addr).await;
    assert_eq!(
        reply[1], 2,
        "unmatched users fall back like intercepted flows"
    );
    drop(stream);

    listener.stop_accepting();
    listener.abort_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn socks5_inbound_refuses_non_connect_commands_and_bad_requests() -> anyhow::Result<()> {
    let mut config = Config::default();
    config.routing.default_outbound = "direct".into();
    let router = Router::new(&[], "direct").unwrap();
    let plane = ControlPlane::new(
        config,
        Box::new(MockEbpfBackend::new()),
        router,
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        test_dns_forwarder(),
    )
    .unwrap();
    let bound = BoundInboundListener::bind(
        InboundKind::Socks5,
        "127.0.0.1:0",
        &[Socks5User {
            username: "alice".into(),
            password: "pw-a".into(),
        }],
    )?;
    let proxy_addr = bound.local_addr()?;
    let mut listener = bound.spawn(
        plane.spawn_handle(),
        plane.concurrency_limit.clone(),
        plane.drain_tracker.clone(),
    )?;

    // UDP ASSOCIATE (CMD 3) is refused with the RFC 1928 code 0x07.
    let (status, mut stream) = socks5_auth(proxy_addr, "alice", "pw-a").await;
    assert_eq!(status, vec![1, 0]);
    let request = vec![5, 3, 0, 1, 127, 0, 0, 1, 0, 53];
    stream.write_all(&request).await?;
    let mut reply = vec![0u8; 10];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x07);
    drop(stream);

    // An unknown address type is refused with 0x08 after authentication.
    let (status, mut stream) = socks5_auth(proxy_addr, "alice", "pw-a").await;
    assert_eq!(status, vec![1, 0]);
    stream.write_all(&[5, 1, 0, 9, 0, 0]).await?;
    let mut reply = vec![0u8; 10];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x08);

    listener.stop_accepting();
    listener.abort_and_join().await?;
    Ok(())
}
