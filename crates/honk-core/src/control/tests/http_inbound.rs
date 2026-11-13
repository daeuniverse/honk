//! End-to-end checks for `inbound.http` listeners: the Basic auth gate,
//! CONNECT tunnels, absolute-URI rewriting, and per-user routing with
//! `user()` rules — one credential table shared with the SOCKS5 inbound.

use super::support::test_dns_forwarder;
use crate::control::ControlPlane;
use crate::control::inbound_listener::{BoundInboundListener, InboundKind};
use crate::dns::DnsResolver;
use crate::ebpf::mock::MockEbpfBackend;
use crate::proxy::ProxyRegistry;
use crate::routing::Router;
use base64::Engine as _;
use honk_config::Config;
use honk_config::inbound::ProxyUser;
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn basic(user: &str, password: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
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

fn test_plane() -> ControlPlane {
    let mut config = Config::default();
    config.routing.default_outbound = "block".into();
    config.routing.rules.push(user_rule("alice", "direct"));
    config.routing.rules.push(user_rule("bob", "block"));
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    ControlPlane::new(
        config,
        Box::new(MockEbpfBackend::new()),
        router,
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        test_dns_forwarder(),
    )
    .unwrap()
}

/// Send one proxied request over a fresh connection and return the whole
/// response; every refusal path answers with `Connection: close` so the
/// read terminates.
async fn request(proxy: SocketAddr, lines: &[&str]) -> String {
    let mut stream = TcpStream::connect(proxy).await.expect("connect");
    let mut payload = String::new();
    for line in lines {
        payload.push_str(line);
        payload.push_str("\r\n");
    }
    payload.push_str("\r\n");
    stream.write_all(payload.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

/// Send raw bytes (bypassing the line joiner) and read the whole response.
async fn raw_request(proxy: SocketAddr, payload: &[u8]) -> String {
    let mut stream = TcpStream::connect(proxy).await.expect("connect");
    stream.write_all(payload).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

async fn read_head(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        bytes.push(byte[0]);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn http_inbound_challenges_unauthenticated_requests() -> anyhow::Result<()> {
    let plane = test_plane();
    let bound = BoundInboundListener::bind(
        InboundKind::Http,
        "127.0.0.1:0",
        &[ProxyUser {
            username: "alice".into(),
            password: "pw-a".into(),
        }],
    )?;
    let proxy = bound.local_addr()?;
    let mut listener = bound.spawn(
        plane.spawn_handle(),
        plane.concurrency_limit.clone(),
        plane.drain_tracker.clone(),
    )?;

    // No credential at all: expect a Basic challenge.
    let response = request(
        proxy,
        &[
            "GET http://example.invalid/ HTTP/1.1",
            "Host: example.invalid",
        ],
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 407"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("proxy-authenticate: basic"),
        "{response}"
    );

    // A wrong password earns the same challenge.
    let response = request(
        proxy,
        &[
            "GET http://example.invalid/ HTTP/1.1",
            "Host: example.invalid",
            &format!("Proxy-Authorization: Basic {}", basic("alice", "wrong")),
        ],
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 407"), "{response}");

    // An unknown scheme in the credential header is no credential either.
    let response = request(
        proxy,
        &[
            "GET http://example.invalid/ HTTP/1.1",
            "Host: example.invalid",
            "Proxy-Authorization: Bearer zzz",
        ],
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 407"), "{response}");

    listener.stop_accepting();
    listener.abort_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn http_inbound_connects_tunnel_and_refuses_blocked_user() -> anyhow::Result<()> {
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

    let plane = test_plane();
    let bound = BoundInboundListener::bind(
        InboundKind::Http,
        "127.0.0.1:0",
        &[
            ProxyUser {
                username: "alice".into(),
                password: "pw-a".into(),
            },
            ProxyUser {
                username: "bob".into(),
                password: "pw-b".into(),
            },
        ],
    )?;
    let proxy = bound.local_addr()?;
    let mut listener = bound.spawn(
        plane.spawn_handle(),
        plane.concurrency_limit.clone(),
        plane.drain_tracker.clone(),
    )?;

    // CONNECT as alice: 200, then the tunnel relays bytes end to end.
    let mut stream = TcpStream::connect(proxy).await?;
    stream
        .write_all(
            format!(
                "CONNECT {echo_addr} HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
                basic("alice", "pw-a")
            )
            .as_bytes(),
        )
        .await?;
    let reply = read_head(&mut stream).await;
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    stream.write_all(b"ping").await?;
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"ping");
    drop(stream);

    // bob is routed to block by his own user() rule: 403.
    let response = request(
        proxy,
        &[
            &format!("CONNECT {echo_addr} HTTP/1.1"),
            &format!("Proxy-Authorization: Basic {}", basic("bob", "pw-b")),
        ],
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");

    listener.stop_accepting();
    listener.abort_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn http_inbound_forwards_absolute_form_to_origin() -> anyhow::Result<()> {
    // A tiny origin server: read the request head, answer 200 "ok", close.
    let origin = TcpListener::bind("127.0.0.1:0").await?;
    let origin_addr = origin.local_addr()?;
    let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = origin.accept().await {
            let tx = seen_tx.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if client.read(&mut byte).await.unwrap() == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let _ = tx.send(String::from_utf8_lossy(&head).into_owned());
                let _ = client
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });

    let plane = test_plane();
    let bound = BoundInboundListener::bind(
        InboundKind::Http,
        "127.0.0.1:0",
        &[ProxyUser {
            username: "alice".into(),
            password: "pw-a".into(),
        }],
    )?;
    let proxy = bound.local_addr()?;
    let mut listener = bound.spawn(
        plane.spawn_handle(),
        plane.concurrency_limit.clone(),
        plane.drain_tracker.clone(),
    )?;

    let response = request(
        proxy,
        &[
            &format!("GET http://{origin_addr}/path?q=1 HTTP/1.1"),
            &format!("Host: {origin_addr}"),
            &format!("Proxy-Authorization: Basic {}", basic("alice", "pw-a")),
            "Connection: keep-alive",
        ],
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("ok"), "{response}");

    let forwarded = seen_rx.recv().await.expect("origin saw the request");
    assert!(
        forwarded.starts_with("GET /path?q=1 HTTP/1.1\r\n"),
        "{forwarded}"
    );
    let lowered = forwarded.to_ascii_lowercase();
    assert!(!lowered.contains("proxy-authorization"), "{forwarded}");
    // The client's Connection token list is dropped in favor of `close`.
    assert!(!lowered.contains("keep-alive"), "{forwarded}");
    assert!(lowered.contains("connection: close"), "{forwarded}");
    assert!(lowered.contains("host: 127.0.0.1:"), "{forwarded}");

    listener.stop_accepting();
    listener.abort_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn http_inbound_refuses_unroutable_request_lines() -> anyhow::Result<()> {
    let plane = test_plane();
    let bound = BoundInboundListener::bind(
        InboundKind::Http,
        "127.0.0.1:0",
        &[ProxyUser {
            username: "alice".into(),
            password: "pw-a".into(),
        }],
    )?;
    let proxy = bound.local_addr()?;
    let mut listener = bound.spawn(
        plane.spawn_handle(),
        plane.concurrency_limit.clone(),
        plane.drain_tracker.clone(),
    )?;

    // Origin-form has no routable host for a proxy to act on.
    let response = request(
        proxy,
        &[
            "GET /index.html HTTP/1.1",
            "Host: example.invalid",
            &format!("Proxy-Authorization: Basic {}", basic("alice", "pw-a")),
        ],
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    // Unsupported schemes are refused before any dial.
    let response = request(
        proxy,
        &[
            "GET ftp://example.invalid/ HTTP/1.1",
            "Host: example.invalid",
            &format!("Proxy-Authorization: Basic {}", basic("alice", "pw-a")),
        ],
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 501"), "{response}");

    listener.stop_accepting();
    listener.abort_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn http_inbound_refuses_control_bytes_and_malformed_credentials() -> anyhow::Result<()> {
    let plane = test_plane();
    let bound = BoundInboundListener::bind(
        InboundKind::Http,
        "127.0.0.1:0",
        &[ProxyUser {
            username: "alice".into(),
            password: "pw-a".into(),
        }],
    )?;
    let proxy = bound.local_addr()?;
    let mut listener = bound.spawn(
        plane.spawn_handle(),
        plane.concurrency_limit.clone(),
        plane.drain_tracker.clone(),
    )?;
    let auth = format!("Proxy-Authorization: Basic {}", basic("alice", "pw-a"));

    // A bare LF inside the request target would be rewritten verbatim into
    // the forwarded request line, injecting a header line upstream. The
    // head must be refused outright instead.
    let response = raw_request(
        proxy,
        format!("GET http://example.invalid/\nInjected: 1 HTTP/1.1\r\n{auth}\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    // A lone CR inside a header value earns the same refusal.
    let response = raw_request(
        proxy,
        format!(
            "GET http://example.invalid/ HTTP/1.1\r\nHost: exam\rple.invalid\r\n{auth}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    // NUL and other control bytes are refused too.
    let response = raw_request(
        proxy,
        b"GET http://example.invalid/ HTTP/1.1\r\nHost: exa\x00mple.invalid\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    // Malformed Basic credentials never authenticate: invalid base64 and a
    // decoded value without the user/password separator both challenge.
    let response = request(
        proxy,
        &[
            "GET http://example.invalid/ HTTP/1.1",
            "Proxy-Authorization: Basic ----",
        ],
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 407"), "{response}");
    let response = request(
        proxy,
        &[
            "GET http://example.invalid/ HTTP/1.1",
            "Proxy-Authorization: Basic bm9jb2xvbg==",
        ],
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 407"), "{response}");

    // The scheme token is case-insensitive: lowercase `basic` still
    // authenticates (the request reaches routing, so no challenge).
    let response = request(
        proxy,
        &[
            "GET http://example.invalid/ HTTP/1.1",
            &format!("Proxy-Authorization: basic {}", basic("alice", "pw-a")),
        ],
    )
    .await;
    assert!(!response.starts_with("HTTP/1.1 407"), "{response}");

    listener.stop_accepting();
    listener.abort_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn http_inbound_refuses_empty_and_zero_authorities() -> anyhow::Result<()> {
    let plane = test_plane();
    let bound = BoundInboundListener::bind(
        InboundKind::Http,
        "127.0.0.1:0",
        &[ProxyUser {
            username: "alice".into(),
            password: "pw-a".into(),
        }],
    )?;
    let proxy = bound.local_addr()?;
    let mut listener = bound.spawn(
        plane.spawn_handle(),
        plane.concurrency_limit.clone(),
        plane.drain_tracker.clone(),
    )?;
    let auth = format!("Proxy-Authorization: Basic {}", basic("alice", "pw-a"));

    // An absolute URI with no authority names no target: 400, not a dial.
    let response = raw_request(
        proxy,
        format!("GET http:// HTTP/1.1\r\n{auth}\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    // An empty bracketed host and a zero port are refused the same way.
    let response = raw_request(
        proxy,
        format!("GET http://[]:80/ HTTP/1.1\r\n{auth}\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    let response = raw_request(
        proxy,
        format!("CONNECT example.invalid:0 HTTP/1.1\r\n{auth}\r\n\r\n").as_bytes(),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    listener.stop_accepting();
    listener.abort_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn http_inbound_connects_ipv6_literal_targets() -> anyhow::Result<()> {
    let echo = TcpListener::bind("[::1]:0").await?;
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

    let plane = test_plane();
    let bound = BoundInboundListener::bind(
        InboundKind::Http,
        "127.0.0.1:0",
        &[ProxyUser {
            username: "alice".into(),
            password: "pw-a".into(),
        }],
    )?;
    let proxy = bound.local_addr()?;
    let mut listener = bound.spawn(
        plane.spawn_handle(),
        plane.concurrency_limit.clone(),
        plane.drain_tracker.clone(),
    )?;

    // The SocketAddr Display form is already bracketed for IPv6.
    let mut stream = TcpStream::connect(proxy).await?;
    stream
        .write_all(
            format!(
                "CONNECT {echo_addr} HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
                basic("alice", "pw-a")
            )
            .as_bytes(),
        )
        .await?;
    let reply = read_head(&mut stream).await;
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    stream.write_all(b"ping").await?;
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"ping");
    drop(stream);

    listener.stop_accepting();
    listener.abort_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn http_inbound_strips_headers_named_by_any_connection_header() -> anyhow::Result<()> {
    let origin = TcpListener::bind("127.0.0.1:0").await?;
    let origin_addr = origin.local_addr()?;
    let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = origin.accept().await {
            let tx = seen_tx.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if client.read(&mut byte).await.unwrap() == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let _ = tx.send(String::from_utf8_lossy(&head).into_owned());
                let _ = client
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });

    let plane = test_plane();
    let bound = BoundInboundListener::bind(
        InboundKind::Http,
        "127.0.0.1:0",
        &[ProxyUser {
            username: "alice".into(),
            password: "pw-a".into(),
        }],
    )?;
    let proxy = bound.local_addr()?;
    let mut listener = bound.spawn(
        plane.spawn_handle(),
        plane.concurrency_limit.clone(),
        plane.drain_tracker.clone(),
    )?;

    // Both Connection headers name a header to drop: tokens from every
    // Connection header — not just the first — must reach the skip set.
    let response = request(
        proxy,
        &[
            &format!("GET http://{origin_addr}/p HTTP/1.1"),
            &format!("Proxy-Authorization: Basic {}", basic("alice", "pw-a")),
            "Connection: X-Secret",
            "Connection: X-Also",
            "X-Secret: leak1",
            "X-Also: leak2",
        ],
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let forwarded = seen_rx.recv().await.expect("origin saw the request");
    let lowered = forwarded.to_ascii_lowercase();
    assert!(!lowered.contains("x-secret"), "{forwarded}");
    assert!(!lowered.contains("x-also"), "{forwarded}");
    assert!(lowered.contains("connection: close"), "{forwarded}");

    listener.stop_accepting();
    listener.abort_and_join().await?;
    Ok(())
}
