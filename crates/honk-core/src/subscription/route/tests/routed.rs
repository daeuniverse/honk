use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use honk_config::Config;
use honk_config::group::Group;
use honk_config::node::{Node, OutboundConfig};
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_config::subscription::{Subscription, SubscriptionHeader};
use honk_config::types::NodeProtocol;
use honk_outbound::group::GroupManager;
use honk_outbound::proxy::{ProtocolEntry, ProxyRegistry, ProxyStream, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use super::super::failure_code;
use crate::download_route::SharedOutbounds;
use crate::routing::Router;
use crate::subscription::SubscriptionManager;
#[cfg(feature = "native-api")]
use crate::subscription::{SubscriptionStore, SubscriptionSupervisor};

const BODY: &str = "socks5://127.0.0.1:1080#node";

type Heads = Arc<parking_lot::Mutex<Vec<String>>>;

/// Answers each request with `respond(path)`, and keeps each request head,
/// lowercased.
async fn serve<R: Into<Vec<u8>>>(
    respond: impl Fn(&str) -> R + Send + 'static,
) -> (SocketAddr, Heads) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            let head = String::from_utf8_lossy(&head).to_lowercase();
            let response: Vec<u8> = respond(head.split(' ').nth(1).unwrap_or_default()).into();
            seen.lock().push(head);
            stream.write_all(&response).await.unwrap();
            let _ = stream.shutdown().await;
        }
    });
    (address, requests)
}

fn ok() -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    )
}

fn redirect(status: &str, location: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

/// Serves `BODY` to every request.
async fn server() -> (SocketAddr, Heads) {
    serve(|_| ok()).await
}

/// A tunnel that connects to the target itself.
struct Tunnel {
    dials: Arc<AtomicUsize>,
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
        Ok(ProxyStream {
            stream: Box::new(tokio::net::TcpStream::connect(target).await?),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }
}

/// Group `proxy` holds one node dialed through [`Tunnel`]; group `own` holds
/// none, like a group of nodes a subscription has not delivered yet. The rules
/// send loopback traffic to `target`.
fn routing(target: &str) -> (SharedOutbounds, Arc<AtomicUsize>) {
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
                name: "own".into(),
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
        outbound: RoutingOutbound::Simple(target.into()),
        priority: 0,
        must: false,
        mark: 0,
    }];
    let dials = Arc::new(AtomicUsize::new(0));
    let mut proxy_registry = ProxyRegistry::new();
    proxy_registry.register(ProtocolEntry::new(
        NodeProtocol::Socks5,
        Arc::new(Tunnel {
            dials: Arc::clone(&dials),
        }),
    ));
    let routing = SharedOutbounds {
        router: Arc::new(RwLock::new(Router::new(&rules, "direct").unwrap())),
        group_manager: Arc::new(parking_lot::RwLock::new(Arc::new(GroupManager::new(
            &config.groups,
            &config.nodes,
        )))),
        config: Arc::new(RwLock::new(Arc::new(config))),
        proxy_registry: Arc::new(proxy_registry),
        runtime_registry: Arc::new(parking_lot::RwLock::new(Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&[]).unwrap(),
        ))),
    };
    (routing, dials)
}

fn subscription(address: SocketAddr, detour: &str) -> Subscription {
    Subscription {
        name: "own-provider".into(),
        url: format!("http://{address}/sub"),
        download_detour: detour.into(),
        headers: vec![SubscriptionHeader {
            key: "x-token".into(),
            value: "abc".into(),
        }],
        ..Default::default()
    }
}

fn manager(routing: SharedOutbounds) -> SubscriptionManager {
    let manager = SubscriptionManager::new().unwrap();
    manager.route_through(routing);
    manager
}

#[tokio::test]
async fn the_default_fetch_goes_through_routing() {
    let (address, requests) = server().await;
    let (routing, dials) = routing("proxy");
    let nodes = manager(routing)
        .fetch(&subscription(address, ""))
        .await
        .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(dials.load(Ordering::SeqCst), 1, "the rules chose the group");
    let requests = requests.lock();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("user-agent: honk/"));
    assert!(requests[0].contains("x-token: abc"));
}

#[tokio::test]
async fn the_routing_rules_can_send_the_fetch_direct() {
    let (address, requests) = server().await;
    let (routing, dials) = routing("direct");
    let nodes = manager(routing)
        .fetch(&subscription(address, "routing"))
        .await
        .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(dials.load(Ordering::SeqCst), 0);
    assert_eq!(requests.lock().len(), 1);
}

#[tokio::test]
async fn the_direct_override_ignores_the_rules_and_needs_no_routing() {
    let (address, requests) = server().await;
    let (routing, dials) = routing("proxy");
    let nodes = manager(routing)
        .fetch(&subscription(address, "direct"))
        .await
        .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(dials.load(Ordering::SeqCst), 0);
    let nodes = SubscriptionManager::new()
        .unwrap()
        .fetch(&subscription(address, "direct"))
        .await
        .unwrap();
    assert_eq!(nodes.len(), 1, "before routing starts");
    assert_eq!(requests.lock().len(), 2);
}

#[tokio::test]
async fn a_group_override_goes_through_the_group_whatever_the_rules_say() {
    let (address, requests) = server().await;
    let (routing, dials) = routing("direct");
    let nodes = manager(routing)
        .fetch(&subscription(address, "proxy"))
        .await
        .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    assert_eq!(requests.lock().len(), 1);
}

/// On a fresh install the rules may send a subscription to a group of the
/// nodes it supplies itself. The fetch fails with a specific error and never
/// goes direct.
#[tokio::test]
async fn a_route_with_no_usable_node_fails_specifically_and_never_goes_direct() {
    let (address, requests) = server().await;
    for (rules, detour) in [("own", ""), ("direct", "own")] {
        let (routing, dials) = routing(rules);
        let error = manager(routing)
            .fetch(&subscription(address, detour))
            .await
            .unwrap_err();
        assert_eq!(failure_code(&error), "route_unavailable", "{error:#}");
        let message = error.to_string();
        assert!(message.contains("'own-provider'"), "{message}");
        assert!(message.contains("'own'"), "{message}");
        assert!(message.contains("route: direct"), "{message}");
        assert_eq!(dials.load(Ordering::SeqCst), 0);
    }
    assert!(requests.lock().is_empty(), "nothing reached the host");
}

/// Routing starts after the first fetch grace period, so a routed
/// subscription restores its cache there and fetches once routing is handed
/// over. A failure then is recorded for the provider and the cache stays.
#[cfg(feature = "native-api")]
#[tokio::test]
async fn cached_content_keeps_working_while_the_route_cannot_carry_the_fetch() {
    let (address, requests) = server().await;
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let sub = subscription(address, "");
    store
        .store_content(&sub, "socks5://127.0.0.1:1081#cached".into())
        .await
        .unwrap();
    let mut config = Config {
        subscriptions: vec![sub.clone()],
        ..Default::default()
    };
    let mut supervisor =
        SubscriptionSupervisor::prepare(&mut config, Some(store.clone()), Vec::new())
            .await
            .unwrap();
    assert!(
        config
            .nodes
            .iter()
            .any(|node| node.name.ends_with("cached")),
        "the cache is restored at startup"
    );
    assert!(requests.lock().is_empty(), "the fetch waits for routing");

    let (routing, _) = routing("own");
    supervisor.route_through(routing);
    let (merge_tx, _merges) = tokio::sync::mpsc::channel(4);
    supervisor.start(merge_tx);
    let handle = supervisor.handle();
    let load = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let load = handle.observation(&sub);
            if load.error.is_some() {
                return load;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(load.error, Some("route_unavailable"));
    assert!(load.cached, "the restored nodes stay in service");
    assert!(requests.lock().is_empty(), "never fetched direct");
    let cached = store.load_nodes(&sub).await.unwrap().unwrap();
    assert_eq!(cached.len(), 1);
    supervisor.shutdown().await.unwrap();
}

fn credentialed(address: SocketAddr) -> Subscription {
    let mut subscription = subscription(address, "");
    subscription.url = format!("http://user:pass@{address}/sub");
    subscription.headers.push(SubscriptionHeader {
        key: "Cookie".into(),
        value: "session=1".into(),
    });
    subscription
}

/// base64("user:pass"), lowercased like the kept heads.
const BASIC: &str = "authorization: basic dxnlcjpwyxnz";

#[tokio::test]
async fn userinfo_is_sent_as_basic_auth_and_never_in_host() {
    let (address, requests) = server().await;
    let (routing, _) = routing("direct");
    manager(routing)
        .fetch(&credentialed(address))
        .await
        .unwrap();
    let head = &requests.lock()[0];
    assert!(head.contains(&format!("host: {address}\r\n")), "{head}");
    assert!(!head.contains("user:pass") && !head.contains('@'), "{head}");
    assert!(head.contains(BASIC), "{head}");
}

#[tokio::test]
async fn a_redirect_to_another_origin_drops_credentials() {
    let (target, target_requests) = server().await;
    let location = format!("http://{target}/sub");
    let (origin, origin_requests) = serve(move |_| redirect("302 Found", &location)).await;
    let (routing, _) = routing("direct");
    manager(routing).fetch(&credentialed(origin)).await.unwrap();
    let first = &origin_requests.lock()[0];
    assert!(
        first.contains(BASIC) && first.contains("cookie: session=1"),
        "{first}"
    );
    let second = &target_requests.lock()[0];
    assert!(
        !second.contains("authorization") && !second.contains("cookie"),
        "{second}"
    );
    assert!(second.contains("x-token: abc"), "other headers stay");
}

#[tokio::test]
async fn a_redirect_within_the_origin_keeps_credentials() {
    let (address, requests) = serve(|path| {
        if path == "/sub" {
            redirect("307 Temporary Redirect", "/next")
        } else {
            ok()
        }
    })
    .await;
    let (routing, _) = routing("direct");
    manager(routing)
        .fetch(&credentialed(address))
        .await
        .unwrap();
    let requests = requests.lock();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|head| head.contains(BASIC) && head.contains("cookie: session=1"))
    );
}

/// A configured Host names the first authority, so a hop to another origin
/// drops it and the request names the new one.
#[tokio::test]
async fn a_redirect_to_another_origin_drops_a_configured_host() {
    let (target, target_requests) = server().await;
    let location = format!("http://{target}/sub");
    let (origin, origin_requests) = serve(move |_| redirect("302 Found", &location)).await;
    let mut sub = subscription(origin, "");
    sub.headers.push(SubscriptionHeader {
        key: "Host".into(),
        value: "subscription.example".into(),
    });
    let (routing, _) = routing("direct");
    manager(routing).fetch(&sub).await.unwrap();
    let first = &origin_requests.lock()[0];
    assert!(first.contains("host: subscription.example\r\n"), "{first}");
    let second = &target_requests.lock()[0];
    assert!(second.contains(&format!("host: {target}\r\n")), "{second}");
    assert!(!second.contains("subscription.example"), "{second}");
}

/// Each followed hop names the previous URL as Referer, without its userinfo
/// or fragment.
#[tokio::test]
async fn each_followed_redirect_sends_the_previous_url_as_referer() {
    let (address, requests) = serve(|path| match path {
        "/sub" => redirect("302 Found", "/next#part"),
        "/next" => redirect("307 Temporary Redirect", "/last"),
        _ => ok(),
    })
    .await;
    let (routing, _) = routing("direct");
    manager(routing)
        .fetch(&credentialed(address))
        .await
        .unwrap();
    let requests = requests.lock();
    assert_eq!(requests.len(), 3);
    assert!(!requests[0].contains("referer"), "{}", requests[0]);
    for (head, previous) in requests[1..].iter().zip(["/sub", "/next"]) {
        assert!(
            head.contains(&format!("referer: http://{address}{previous}\r\n")),
            "{head}"
        );
    }
}

/// The Referer rule is the direct fetch's, so an https page never names
/// itself to a plaintext hop.
#[test]
fn a_redirect_from_https_to_http_sends_no_referer() {
    use crate::subscription::follow_subscription_redirect;
    let referer = |previous: &str, next: &str| {
        let mut headers = http::HeaderMap::new();
        follow_subscription_redirect(
            &previous.parse().unwrap(),
            &next.parse().unwrap(),
            &mut headers,
        );
        headers.get(http::header::REFERER).cloned()
    };
    assert_eq!(
        referer("https://a.example/sub", "http://a.example/next"),
        None
    );
    assert_eq!(
        referer("https://u:p@a.example/sub#part", "https://b.example/next").unwrap(),
        "https://a.example/sub"
    );
}

/// A configured Authorization wins over the URL's userinfo; only one is sent.
#[tokio::test]
async fn a_configured_authorization_wins_over_userinfo() {
    let (address, requests) = server().await;
    let mut sub = credentialed(address);
    sub.headers.push(SubscriptionHeader {
        key: "Authorization".into(),
        value: "Bearer configured".into(),
    });
    let (routing, _) = routing("direct");
    manager(routing).fetch(&sub).await.unwrap();
    let head = &requests.lock()[0];
    assert_eq!(head.matches("authorization:").count(), 1, "{head}");
    assert!(head.contains("authorization: bearer configured"), "{head}");
}

/// As on the direct fetch, only a redirect status with a Location is
/// followed, only 4xx and 5xx fail, and any other answer's body is taken.
#[tokio::test]
async fn only_followed_redirects_are_followed_and_other_3xx_bodies_are_taken() {
    for (status, location) in [
        ("300 Multiple Choices", "Location: /next\r\n"),
        ("302 Found", ""),
    ] {
        let (address, requests) = serve(move |_| {
            format!(
                "HTTP/1.1 {status}\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                BODY.len()
            )
        })
        .await;
        let (routing, _) = routing("direct");
        let nodes = manager(routing)
            .fetch(&subscription(address, ""))
            .await
            .unwrap();
        assert_eq!(nodes.len(), 1, "{status}");
        assert_eq!(requests.lock().len(), 1, "{status} is not followed");
    }
    let (address, _) = serve(|_| redirect("404 Not Found", "/next")).await;
    let (routing, _) = routing("direct");
    let error = manager(routing)
        .fetch(&subscription(address, ""))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("404"), "{error}");
}

/// A followed redirect whose Location is not text fails on both paths; its
/// body is never taken.
#[tokio::test]
async fn a_followed_redirect_with_a_location_that_is_not_text_fails() {
    let (address, _) = serve(|_| {
        let mut response = b"HTTP/1.1 302 Found\r\nLocation: /n\xffxt\r\n".to_vec();
        response.extend_from_slice(
            format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                BODY.len()
            )
            .as_bytes(),
        );
        response
    })
    .await;
    let (routing, _) = routing("direct");
    let routed = manager(routing).fetch(&subscription(address, "")).await;
    assert!(routed.is_err(), "routed fetch took the redirect body");
    let direct = SubscriptionManager::new()
        .unwrap()
        .fetch(&subscription(address, "direct"))
        .await;
    assert!(direct.is_err(), "direct fetch took the redirect body");
}

/// A redirect past the bound fails on the bound on both paths, before its
/// Location is read, even when that Location would fail on its own.
#[tokio::test]
async fn a_sixth_redirect_fails_on_the_bound_before_its_location_is_checked() {
    let (address, _) = serve(|path| match path {
        "/sub" => redirect("302 Found", "/1").into_bytes(),
        "/5" => b"HTTP/1.1 302 Found\r\nLocation: /n\xffxt\r\nContent-Length: 0\r\n\r\n".to_vec(),
        path => {
            let hop: u8 = path[1..].parse().unwrap();
            redirect("302 Found", &format!("/{}", hop + 1)).into_bytes()
        }
    })
    .await;
    let (routing, _) = routing("direct");
    let routed = manager(routing)
        .fetch(&subscription(address, ""))
        .await
        .unwrap_err();
    let direct = SubscriptionManager::new()
        .unwrap()
        .fetch(&subscription(address, "direct"))
        .await
        .unwrap_err();
    for error in [routed, direct] {
        assert!(
            format!("{error:#}").contains("redirected too many times"),
            "{error:#}"
        );
    }
}

/// The request asks for identity, so an answer that names identity is
/// taken and one that names a real encoding is not.
#[tokio::test]
async fn an_identity_content_encoding_is_accepted() {
    for (encoding, accepted) in [(" Identity ", true), ("gzip", false)] {
        let (address, _) = serve(move |_| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding:{encoding}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                BODY.len()
            )
        })
        .await;
        let (routing, _) = routing("direct");
        let result = manager(routing).fetch(&subscription(address, "")).await;
        assert_eq!(result.is_ok(), accepted, "{encoding}: {result:?}");
    }
}

/// The configured User-Agent goes out whether the rules pick a group or
/// direct.
#[tokio::test]
async fn the_configured_user_agent_is_sent_on_every_route() {
    for (rules, dialed) in [("proxy", 1), ("direct", 0)] {
        let (address, requests) = server().await;
        let (routing, dials) = routing(rules);
        let mut sub = subscription(address, "");
        sub.user_agent = Some("Clash-Verge/2.0".into());
        manager(routing).fetch(&sub).await.unwrap();
        assert_eq!(dials.load(Ordering::SeqCst), dialed, "{rules}");
        let head = &requests.lock()[0];
        assert_eq!(head.matches("user-agent:").count(), 1, "{rules}: {head}");
        assert!(
            head.contains("user-agent: clash-verge/2.0\r\n"),
            "{rules}: {head}"
        );
    }
}
