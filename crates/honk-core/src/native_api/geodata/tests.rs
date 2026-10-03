use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use honk_config::Config;
use honk_config::group::Group;
use honk_config::node::{Node, OutboundConfig};
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_config::types::NodeProtocol;
use honk_outbound::group::GroupManager;
use honk_outbound::proxy::{ProtocolEntry, ProxyRegistry, ProxyStream, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use super::*;
use crate::download_route::Outbounds;
use crate::routing::Router;

/// Serves `body` at every path but a checksum, which is a 404; counts the
/// requests that reach it.
async fn server(body: &'static [u8]) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            counted.fetch_add(1, Ordering::SeqCst);
            let checksum = String::from_utf8_lossy(&head)
                .split(' ')
                .nth(1)
                .is_some_and(|path| path.ends_with(".sha256sum"));
            let (status, body) = if checksum {
                ("404 Not Found", &b""[..])
            } else {
                ("200 OK", body)
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            let _ = stream.shutdown().await;
        }
    });
    (address, requests)
}

/// A tunnel that connects to the target itself, refusing `refused` ports.
struct Tunnel {
    dials: Arc<AtomicUsize>,
    refused: Vec<u16>,
}

#[async_trait::async_trait]
impl TcpOutbound for Tunnel {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        if self.refused.contains(&target.port()) {
            anyhow::bail!("proxy refused");
        }
        Ok(ProxyStream {
            stream: Box::new(tokio::net::TcpStream::connect(target).await?),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }
}

struct World {
    router: RwLock<Router>,
    config: RwLock<Arc<Config>>,
    group_manager: honk_outbound::group::SharedGroupManager,
    proxy_registry: ProxyRegistry,
    runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    dials: Arc<AtomicUsize>,
}

/// Group `proxy` holds one node whose tunnel refuses `refused`; group `empty`
/// holds none. Loopback traffic is routed to `proxy`.
fn world(refused: Vec<u16>) -> World {
    let dials = Arc::new(AtomicUsize::new(0));
    let tunnel = Tunnel {
        dials: Arc::clone(&dials),
        refused,
    };
    world_with(Arc::new(tunnel), dials)
}

fn world_with(outbound: Arc<impl TcpOutbound + 'static>, dials: Arc<AtomicUsize>) -> World {
    let mut node = Node {
        name: "tunnel".into(),
        outbound: OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: "192.0.2.1".into(),
        port: 1080,
        ..Default::default()
    };
    node.id = node.derive_id();
    let config = Config {
        groups: vec![
            Group {
                name: "proxy".into(),
                nodes: vec![node.id],
                ..Default::default()
            },
            Group {
                name: "empty".into(),
                ..Default::default()
            },
        ],
        nodes: vec![node],
        ..Default::default()
    };
    let rules = vec![RoutingRule {
        name: "loopback".into(),
        condition: RoutingCondition {
            ip: vec!["127.0.0.1/32".into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple("proxy".into()),
        priority: 0,
        must: false,
        mark: 0,
    }];
    let mut proxy_registry = ProxyRegistry::new();
    proxy_registry.register(ProtocolEntry::new(NodeProtocol::Socks5, outbound));
    World {
        router: RwLock::new(Router::new(&rules, "direct").unwrap()),
        group_manager: Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
            &config.groups,
            &config.nodes,
        )))),
        config: RwLock::new(Arc::new(config)),
        proxy_registry,
        runtime_registry: Arc::new(parking_lot::RwLock::new(Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap(),
        ))),
        dials,
    }
}

impl World {
    async fn fetch(&self, route: Route, urls: &[String]) -> Result<(Arc<[u8]>, Fetched), Failure> {
        self.fetch_with(route, urls, true).await
    }

    async fn fetch_with(
        &self,
        route: Route,
        urls: &[String],
        verify_checksum: bool,
    ) -> Result<(Arc<[u8]>, Fetched), Failure> {
        let egress = Egress {
            bootstrap: "udp://127.0.0.1:9",
            route: &route,
            outbounds: Outbounds {
                router: &self.router,
                config: &self.config,
                group_manager: &self.group_manager,
                proxy_registry: &self.proxy_registry,
                runtime_registry: &self.runtime_registry,
            },
        };
        fetch("geosite", urls, &egress, 1024, verify_checksum).await
    }
}

fn url(address: SocketAddr) -> String {
    format!("http://{address}/geosite.dat")
}

#[tokio::test]
async fn a_group_route_downloads_through_the_group() {
    let (address, requests) = server(b"through the group").await;
    let world = world(Vec::new());
    let (bytes, fetched) = world
        .fetch(Route::Group("proxy".into()), &[url(address)])
        .await
        .unwrap();
    assert_eq!(&*bytes, b"through the group");
    assert_eq!(world.dials.load(Ordering::SeqCst), 2, "file and checksum");
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(fetched.route, Route::Group("proxy".into()));
    assert_eq!(fetched.group.as_deref(), Some("proxy"));
}

#[tokio::test]
async fn the_routing_route_follows_the_rules() {
    let (address, _) = server(b"routed").await;
    let world = world(Vec::new());
    let (bytes, fetched) = world.fetch(Route::Routing, &[url(address)]).await.unwrap();
    assert_eq!(&*bytes, b"routed");
    assert_eq!(world.dials.load(Ordering::SeqCst), 2);
    assert_eq!(fetched.route, Route::Routing);
    assert_eq!(
        fetched.group.as_deref(),
        Some("proxy"),
        "the group the rules chose"
    );
}

#[tokio::test]
async fn the_direct_route_ignores_the_rules() {
    let (address, requests) = server(b"direct").await;
    let world = world(Vec::new());
    let (bytes, fetched) = world.fetch(Route::Direct, &[url(address)]).await.unwrap();
    assert_eq!(&*bytes, b"direct");
    assert_eq!(world.dials.load(Ordering::SeqCst), 0);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(fetched.route, Route::Direct);
    assert_eq!(fetched.group, None);
}

#[tokio::test]
async fn a_url_the_group_cannot_reach_falls_back_to_the_next_through_the_group() {
    let (refused, refused_requests) = server(b"unreachable").await;
    let (address, _) = server(b"second url").await;
    let world = world(vec![refused.port()]);
    let (bytes, fetched) = world
        .fetch(Route::Group("proxy".into()), &[url(refused), url(address)])
        .await
        .unwrap();
    assert_eq!(&*bytes, b"second url");
    assert_eq!(fetched.url, url(address));
    assert_eq!(fetched.group.as_deref(), Some("proxy"));
    assert_eq!(
        refused_requests.load(Ordering::SeqCst),
        0,
        "never retried direct"
    );
    assert_eq!(world.dials.load(Ordering::SeqCst), 3);
}

/// At startup a group may have no member it can use yet. Every URL fails and
/// nothing is fetched direct.
#[test]
fn an_empty_detour_follows_routing_without_a_state_db() {
    let file = |detour: &str| NativeApiConfig {
        geodata_download_detour: detour.into(),
        ..Default::default()
    };
    assert_eq!(route(&file(""), None), Route::Routing);
    assert_eq!(route(&file("routing"), None), Route::Routing);
    assert_eq!(route(&file("direct"), None), Route::Direct);
}

#[tokio::test]
async fn a_group_not_ready_at_startup_fails_every_url_without_going_direct() {
    let (first, first_requests) = server(b"first").await;
    let (second, second_requests) = server(b"second").await;
    let urls = [url(first), url(second)];
    let world = world(vec![first.port(), second.port()]);
    assert_eq!(
        world
            .fetch(Route::Group("proxy".into()), &urls)
            .await
            .unwrap_err()
            .code,
        "connection_failed"
    );
    assert_eq!(
        world.fetch(Route::Routing, &urls).await.unwrap_err().code,
        "connection_failed",
        "the rules send the URLs to the group"
    );
    assert_eq!(
        world
            .fetch(Route::Group("empty".into()), &urls)
            .await
            .unwrap_err()
            .code,
        "group_unavailable"
    );
    assert_eq!(
        world
            .fetch(Route::Group("removed".into()), &urls)
            .await
            .unwrap_err()
            .code,
        "group_unavailable"
    );
    assert_eq!(first_requests.load(Ordering::SeqCst), 0);
    assert_eq!(second_requests.load(Ordering::SeqCst), 0);
}

/// A tunnel whose far end is an in-memory server, so paused time never
/// races real sockets: the file comes after `file_delay` and its correct
/// checksum after `checksum_delay`, or `status` with no body when one is given.
/// With `pace: Some((size, pause))` the file's body follows its headers in
/// pieces of `size` bytes, each after `pause`. `dials` counts the requests.
struct Slow {
    body: &'static [u8],
    file_delay: Duration,
    checksum_delay: Duration,
    status: Option<&'static str>,
    pace: Option<(usize, Duration)>,
    dials: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl TcpOutbound for Slow {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let Slow {
            body,
            file_delay,
            checksum_delay,
            status,
            pace,
            ..
        } = *self;
        tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(server.read_u8().await.unwrap());
            }
            let checksum = String::from_utf8_lossy(&head)
                .split(' ')
                .nth(1)
                .is_some_and(|path| path.ends_with(".sha256sum"));
            let (delay, reply) = if checksum {
                (
                    checksum_delay,
                    crate::configuration::digest(body).into_bytes(),
                )
            } else {
                (file_delay, body.to_vec())
            };
            tokio::time::sleep(delay).await;
            let (status, reply) = status.map_or(("200 OK", reply), |status| (status, Vec::new()));
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            let _ = server.write_all(head.as_bytes()).await;
            match pace.filter(|_| !checksum) {
                Some((size, pause)) => {
                    for piece in reply.chunks(size) {
                        tokio::time::sleep(pause).await;
                        let _ = server.write_all(piece).await;
                    }
                }
                None => {
                    let _ = server.write_all(&reply).await;
                }
            }
            let _ = server.shutdown().await;
        });
        Ok(ProxyStream {
            stream: Box::new(client),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }
}

async fn fetch_slow(slow: Slow) -> Result<(Arc<[u8]>, Fetched), Failure> {
    let dials = Arc::clone(&slow.dials);
    let world = world_with(Arc::new(slow), dials);
    let address = SocketAddr::from(([127, 0, 0, 1], 8080));
    world
        .fetch(Route::Group("proxy".into()), &[url(address)])
        .await
}

#[tokio::test(start_paused = true)]
async fn a_slow_file_leaves_its_checksum_a_deadline_of_its_own() {
    let (bytes, fetched) = fetch_slow(Slow {
        body: b"slow file",
        file_delay: IDLE_TIMEOUT - Duration::from_secs(5),
        checksum_delay: CHECKSUM_TIMEOUT - Duration::from_secs(2),
        status: None,
        pace: None,
        dials: Arc::default(),
    })
    .await
    .unwrap();
    assert_eq!(&*bytes, b"slow file");
    assert!(fetched.verified);
}

#[tokio::test(start_paused = true)]
async fn a_checksum_still_has_to_arrive_within_its_deadline() {
    let failure = fetch_slow(Slow {
        body: b"slow checksum",
        file_delay: Duration::ZERO,
        checksum_delay: CHECKSUM_TIMEOUT + Duration::from_secs(1),
        status: None,
        pace: None,
        dials: Arc::default(),
    })
    .await
    .unwrap_err();
    assert_eq!(failure, Failure::from("checksum_unavailable"));
}

#[tokio::test(start_paused = true)]
async fn a_rejected_status_is_kept_with_the_failure() {
    let failure = fetch_slow(Slow {
        body: b"",
        file_delay: Duration::ZERO,
        checksum_delay: Duration::ZERO,
        status: Some("429 Too Many Requests"),
        pace: None,
        dials: Arc::default(),
    })
    .await
    .unwrap_err();
    assert_eq!(
        failure,
        Failure {
            code: "http_status_rejected",
            status: Some(429),
        }
    );
}

#[tokio::test(start_paused = true)]
async fn without_verification_no_checksum_is_requested() {
    let slow = Slow {
        body: b"unverified",
        file_delay: Duration::ZERO,
        checksum_delay: Duration::ZERO,
        status: None,
        pace: None,
        dials: Arc::default(),
    };
    let dials = Arc::clone(&slow.dials);
    let world = world_with(Arc::new(slow), Arc::clone(&dials));
    let address = SocketAddr::from(([127, 0, 0, 1], 8080));
    let (bytes, fetched) = world
        .fetch_with(Route::Group("proxy".into()), &[url(address)], false)
        .await
        .unwrap();
    assert_eq!(&*bytes, b"unverified");
    assert_eq!(dials.load(Ordering::SeqCst), 1, "the file only");
    assert!(!fetched.verified);
    assert_eq!(fetched.sha256, crate::configuration::digest(b"unverified"));
}

/// Paces `body` in pieces of `size` bytes, each after `pause`.
async fn fetch_paced(
    body: &'static [u8],
    size: usize,
    pause: Duration,
) -> Result<(Arc<[u8]>, Fetched), Failure> {
    fetch_slow(Slow {
        body,
        file_delay: Duration::ZERO,
        checksum_delay: Duration::ZERO,
        status: None,
        pace: Some((size, pause)),
        dials: Arc::default(),
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_file_that_keeps_arriving_may_take_longer_than_the_idle_timeout() {
    let body = b"one piece, two pieces, three pieces";
    let pause = IDLE_TIMEOUT - Duration::from_secs(10);
    let started = tokio::time::Instant::now();
    let (bytes, fetched) = fetch_paced(body, 12, pause).await.unwrap();
    assert!(started.elapsed() > IDLE_TIMEOUT, "{:?}", started.elapsed());
    assert_eq!(&*bytes, body);
    assert!(fetched.verified);
    assert_eq!(fetched.sha256, crate::configuration::digest(body));
}

#[tokio::test(start_paused = true)]
async fn a_file_that_stalls_for_the_idle_timeout_fails() {
    let started = tokio::time::Instant::now();
    let failure = fetch_paced(b"stalled", 3, IDLE_TIMEOUT + Duration::from_secs(1))
        .await
        .unwrap_err();
    assert_eq!(failure, Failure::from("download_timeout"));
    assert!(started.elapsed() < IDLE_TIMEOUT + Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn a_trickle_ends_at_the_download_limit() {
    // One byte every 20 seconds needs 800 seconds for the whole file.
    let body = &[b'x'; 40];
    let started = tokio::time::Instant::now();
    let failure = fetch_paced(body, 1, Duration::from_secs(20))
        .await
        .unwrap_err();
    assert_eq!(failure, Failure::from("download_timeout"));
    assert_eq!(started.elapsed(), DOWNLOAD_LIMIT);
}

#[test]
fn a_display_url_keeps_nothing_that_may_hold_a_credential() {
    for (url, shown) in [
        (
            "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
            Some("https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"),
        ),
        (
            "https://example.com/geoip.dat?sig=abc&key=xyz",
            Some("https://example.com/geoip.dat"),
        ),
        (
            "https://example.com/token/abc123/geoip.dat",
            Some("https://example.com/token/[redacted]/geoip.dat"),
        ),
        (
            "https://raw.githubusercontent.com/o/r/0123456789abcdef0123456789abcdef01234567/geoip.dat",
            Some(
                "https://raw.githubusercontent.com/o/r/0123456789abcdef0123456789abcdef01234567/geoip.dat",
            ),
        ),
        (
            "https://example.com/d/0F3C9A7E-51b2-4c1d-9e8f-2a6b7c8d9e0f/geoip.dat",
            Some("https://example.com/d/[redacted]/geoip.dat"),
        ),
        (
            "https://example.com/s/0123456789abcdef0123456789abcdef/geoip.dat",
            Some("https://example.com/s/[redacted]/geoip.dat"),
        ),
        (
            "https://example.com/release-2026-09-29/geoip.dat",
            Some("https://example.com/release-2026-09-29/geoip.dat"),
        ),
        (
            "https://example.com/20260929120000123/geoip.dat",
            Some("https://example.com/20260929120000123/geoip.dat"),
        ),
        (
            "https://example.com/d/Xk7pQ2mZ9vLb4RtY8wNc3HsJ/geoip.dat",
            Some("https://example.com/d/[redacted]/geoip.dat"),
        ),
        (
            "https://example.com/d/ghp_16C7e42F292c6912E7710c838347Ae178B4a/geoip.dat",
            Some("https://example.com/d/[redacted]/geoip.dat"),
        ),
        (
            "https://example.com/auth_token/v4lue/geoip.dat",
            Some("https://example.com/auth_token/[redacted]/geoip.dat"),
        ),
        (
            "https://example.com/token/",
            Some("https://example.com/token/"),
        ),
        (
            "https://example.com/bot123:abc/geoip.dat",
            Some("https://example.com/[redacted]/geoip.dat"),
        ),
        ("https://user:pass@example.com/geoip.dat", None),
        ("https://user@example.com/geoip.dat", None),
    ] {
        assert_eq!(display_url(url, |_| false).as_deref(), shown, "{url}");
    }
}
