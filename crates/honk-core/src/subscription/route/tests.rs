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

use crate::download_route::SharedOutbounds;
use crate::routing::Router;
use crate::subscription::SubscriptionManager;

mod failures;
mod routed;

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

/// A tunnel that connects to the target itself, or refuses to when `refuse`.
struct Tunnel {
    dials: Arc<AtomicUsize>,
    refuse: bool,
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
        anyhow::ensure!(!self.refuse, "node unreachable");
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
    routing_via(target, false)
}

/// As [`routing`], with a node that cannot connect when `refuse`.
fn routing_via(target: &str, refuse: bool) -> (SharedOutbounds, Arc<AtomicUsize>) {
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
            refuse,
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
