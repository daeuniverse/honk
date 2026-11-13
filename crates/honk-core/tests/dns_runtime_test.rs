use std::sync::Arc;

use honk_config::Config;
use honk_config::node::Node;
use honk_core::control::ControlPlane;
use honk_core::dns;
use honk_core::dns::DnsResolver;
use honk_core::ebpf::mock::MockEbpfBackend;
use honk_core::proxy::ProxyRegistry;
use honk_core::routing::Router;
use tempfile::NamedTempFile;

mod dns_surface_support {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use honk_core::dns::forwarder::DnsUpstreamPool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::Notify;
    use tokio::task::JoinHandle;

    pub struct StaticUpstream {
        ip: [u8; 4],
        calls: AtomicUsize,
    }

    impl StaticUpstream {
        pub fn new(ip: [u8; 4]) -> Arc<Self> {
            Arc::new(Self {
                ip,
                calls: AtomicUsize::new(0),
            })
        }

        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl DnsUpstreamPool for StaticUpstream {
        async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(a_response(raw_query, self.ip))
        }
    }

    pub struct BlockingUpstream {
        ip: [u8; 4],
        pub entered: Notify,
        pub release: Notify,
    }

    impl BlockingUpstream {
        pub fn new(ip: [u8; 4]) -> Arc<Self> {
            Arc::new(Self {
                ip,
                entered: Notify::new(),
                release: Notify::new(),
            })
        }
    }

    #[async_trait]
    impl DnsUpstreamPool for BlockingUpstream {
        async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(a_response(raw_query, self.ip))
        }
    }

    pub struct LoopbackServer {
        pub address: SocketAddr,
        calls: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl LoopbackServer {
        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Drop for LoopbackServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    pub async fn spawn_udp_server(ip: [u8; 4]) -> LoopbackServer {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP");
        let address = socket.local_addr().expect("UDP address");
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 4096];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
                observed.fetch_add(1, Ordering::SeqCst);
                let response = a_response(&buffer[..length], ip);
                if socket.send_to(&response, peer).await.is_err() {
                    return;
                }
            }
        });
        LoopbackServer {
            address,
            calls,
            task,
        }
    }

    pub async fn spawn_tcp_server(ip: [u8; 4]) -> LoopbackServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP");
        let address = listener.local_addr().expect("TCP address");
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let observed = Arc::clone(&observed);
                tokio::spawn(async move {
                    let length = match stream.read_u16().await {
                        Ok(length) => usize::from(length),
                        Err(_) => return,
                    };
                    let mut query = vec![0_u8; length];
                    if stream.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    observed.fetch_add(1, Ordering::SeqCst);
                    let response = a_response(&query, ip);
                    if let Ok(length) = u16::try_from(response.len()) {
                        let _ = stream.write_u16(length).await;
                        let _ = stream.write_all(&response).await;
                    }
                });
            }
        });
        LoopbackServer {
            address,
            calls,
            task,
        }
    }

    pub fn a_response(raw_query: &[u8], ip: [u8; 4]) -> Vec<u8> {
        a_response_with_ttl(raw_query, ip, 300)
    }

    pub fn a_response_with_ttl(raw_query: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut response = raw_query.to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&[0, 4, ip[0], ip[1], ip[2], ip[3]]);
        response
    }
}

use dns_surface_support::{
    BlockingUpstream, StaticUpstream, a_response, a_response_with_ttl, spawn_tcp_server,
    spawn_udp_server,
};
use honk_config::dns::DnsUpstream;
use honk_config::types::DnsProtocol;
use honk_core::dns::forwarder::{DnsForwarder, DnsUpstreamPool, build_dns_query};
use honk_core::dns::query::IngressProfile;

fn test_dns_forwarder(config: &Config, upstream: Arc<dyn DnsUpstreamPool>) -> Arc<DnsForwarder> {
    let cache = Arc::new(tokio::sync::Mutex::new(dns::cache::DnsCache::new(32)));
    let router =
        Arc::new(dns::routing::DnsRouter::new_from_dns_config(&config.dns).expect("DNS router"));
    Arc::new(
        DnsForwarder::new(upstream, cache, router)
            .with_cache_enabled(config.dns.cache.enabled)
            .with_cache_ttl(u32::try_from(config.dns.cache.ttl).expect("test TTL fits u32"))
            .with_stale_reply_ttl(config.dns.cache.stale_reply_ttl)
            .with_policy_from_config(&config.dns)
            .expect("DNS policy"),
    )
}

fn config_for_upstream(address: std::net::SocketAddr, protocol: DnsProtocol) -> Config {
    let mut config = Config::default();
    config.dns.upstream = vec![DnsUpstream {
        name: "default".into(),
        address: address.to_string(),
        protocol,
        tls_server_name: None,
        outbound: None,
    }];
    config.dns.cache.enabled = true;
    config.dns.cache.ttl = 300;
    config
}

fn control_plane(mut config: Config, forwarder: Arc<DnsForwarder>) -> ControlPlane {
    config.global.nfqueue_enable = false;
    ControlPlane::new(
        config.clone(),
        Box::new(MockEbpfBackend::new()),
        Router::new(&config.routing.rules, &config.routing.default_outbound).expect("router"),
        Arc::new(ProxyRegistry::default_resolver().expect("proxy registry")),
        DnsResolver::new(&config.dns).expect("DNS resolver"),
        forwarder,
    )
    .expect("control plane")
}

async fn reload_config(control: &ControlPlane, config: Config) {
    assert!(
        control
            .reload_runtime_config(config, Default::default())
            .await,
        "runtime reload should publish"
    );
}

async fn reload_current(control: &ControlPlane) {
    let config = control.config_handle().read().await.as_ref().clone();
    reload_config(control, config).await;
}

async fn try_reload_current(control: &ControlPlane) -> bool {
    let config = control.config_handle().read().await.as_ref().clone();
    control
        .reload_runtime_config(config, Default::default())
        .await
}

#[tokio::test]
async fn public_reload_surface_publishes_a_coherent_runtime() {
    let config = Config::default();
    let upstream = StaticUpstream::new([192, 0, 2, 1]);
    let control = control_plane(config.clone(), test_dns_forwarder(&config, upstream));
    let subscription_id = uuid::Uuid::new_v4();
    let mut replacement = Node {
        name: "published-runtime-node".into(),
        address: "127.0.0.1:1".into(),
        port: 1,
        subscription_id: Some(subscription_id),
        ..Node::default()
    };
    replacement.id = replacement.derive_id();

    control
        .merge_subscription_nodes(subscription_id, vec![replacement], Vec::new())
        .await;

    let active = control.config_handle();
    let active = active.read().await;
    assert!(
        active.nodes.iter().any(|node| {
            node.name == "published-runtime-node" && node.subscription_id == Some(subscription_id)
        }),
        "public reload surface did not activate the replacement generation"
    );
    assert!(control.is_datapath_healthy());
}

#[tokio::test]
async fn public_runtime_reload_replaces_hosts_snapshot_and_rejects_invalid_file() {
    let file = NamedTempFile::new().expect("temporary hosts file");
    std::fs::write(file.path(), "full:reload-hosts.test 192.0.2.60\n")
        .expect("write initial hosts file");
    let config = Config::default();
    let upstream = StaticUpstream::new([192, 0, 2, 1]);
    let control = control_plane(
        config.clone(),
        test_dns_forwarder(&config, upstream.clone()),
    );
    let service = control.dns_service();
    let query = build_dns_query("reload-hosts.test", 1);

    let mut candidate = control.config_handle().read().await.as_ref().clone();
    candidate.dns.hosts = vec![file.path().to_string_lossy().into_owned()];
    reload_config(&control, candidate).await;
    let initial = service
        .resolve(&query, IngressProfile::Internal)
        .await
        .expect("initial hosts answer");
    assert_eq!(initial, a_response_with_ttl(&query, [192, 0, 2, 60], 60));

    std::fs::write(file.path(), "full:reload-hosts.test 192.0.2.61\n").expect("replace hosts file");
    reload_current(&control).await;
    let replaced = service
        .resolve(&query, IngressProfile::Internal)
        .await
        .expect("reloaded hosts answer");
    assert_eq!(replaced, a_response_with_ttl(&query, [192, 0, 2, 61], 60));

    std::fs::write(file.path(), "full:reload-hosts.test 192.0.2.300\n")
        .expect("corrupt hosts file");
    assert!(!try_reload_current(&control).await);
    let retained = service
        .resolve(&query, IngressProfile::Internal)
        .await
        .expect("retained hosts answer");
    assert_eq!(retained, replaced);
    assert_eq!(upstream.calls(), 0);
    assert!(control.is_datapath_healthy());
}

#[tokio::test]
async fn public_runtime_reload_preserves_policy_cache_then_changes_udp_and_tcp_transport() {
    let udp = spawn_udp_server([192, 0, 2, 20]).await;
    let tcp = spawn_tcp_server([192, 0, 2, 30]).await;
    let config = config_for_upstream(udp.address, DnsProtocol::Udp);
    let initial = StaticUpstream::new([192, 0, 2, 10]);
    let control = control_plane(config.clone(), test_dns_forwarder(&config, initial.clone()));
    let service = control.dns_service();
    let query = build_dns_query("reload.example", 1);

    let first = service
        .resolve(&query, IngressProfile::Internal)
        .await
        .expect("initial internal query");
    assert_eq!(first, a_response(&query, [192, 0, 2, 10]));

    reload_current(&control).await;
    let unchanged = service
        .resolve(&query, IngressProfile::Internal)
        .await
        .expect("unchanged-policy internal query");
    assert_eq!(unchanged, first);
    assert_eq!(udp.calls(), 0, "unchanged policy should reuse shared cache");

    let udp_response = service
        .resolve(
            &query,
            IngressProfile::Udp {
                advertised_size: 1232,
            },
        )
        .await
        .expect("UDP query");
    assert_eq!(udp_response, a_response(&query, [192, 0, 2, 10]));
    assert_eq!(
        initial.calls(),
        2,
        "ingress profiles must not share cache keys"
    );
    assert_eq!(
        udp.calls(),
        0,
        "unchanged reload retains the active transport"
    );

    let mut candidate = control.config_handle().read().await.as_ref().clone();
    candidate.dns.cache.ttl = 301;
    reload_config(&control, candidate).await;
    let changed = service
        .resolve(&query, IngressProfile::Internal)
        .await
        .expect("changed-policy internal query");
    assert_eq!(changed, a_response_with_ttl(&query, [192, 0, 2, 20], 301));
    assert_eq!(udp.calls(), 1);

    let mut candidate = control.config_handle().read().await.as_ref().clone();
    candidate.dns.cache.ttl = 302;
    candidate.dns.upstream[0].address = tcp.address.to_string();
    candidate.dns.upstream[0].protocol = DnsProtocol::Tcp;
    reload_config(&control, candidate).await;
    let tcp_query = build_dns_query("tcp.reload.example", 1);
    let tcp_response = service
        .resolve(&tcp_query, IngressProfile::Tcp)
        .await
        .expect("changed-policy TCP query");
    assert_eq!(
        tcp_response,
        a_response_with_ttl(&tcp_query, [192, 0, 2, 30], 302)
    );
    assert_eq!(tcp.calls(), 1);
    assert_eq!(initial.calls(), 2);
    assert!(control.is_datapath_healthy());
}

#[tokio::test]
async fn public_service_rejects_malformed_and_bypasses_cache_for_uncacheable_queries() {
    let config = Config::default();
    let upstream = StaticUpstream::new([192, 0, 2, 40]);
    let service = dns::DnsService::with_forwarder(test_dns_forwarder(&config, upstream.clone()));
    assert!(
        service
            .resolve(&[0_u8; 5], IngressProfile::Api)
            .await
            .is_err()
    );
    assert_eq!(upstream.calls(), 0);

    let mut uncacheable = build_dns_query("uncacheable.example", 1);
    uncacheable[10..12].copy_from_slice(&1_u16.to_be_bytes());
    uncacheable.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 5, 0, 12, 0, 1, 0]);
    for _ in 0..2 {
        service
            .resolve(&uncacheable, IngressProfile::Api)
            .await
            .expect("uncacheable query still resolves");
    }
    assert_eq!(upstream.calls(), 2);
}

#[tokio::test]
async fn flush_cancels_inflight_publication_without_cache_resurrection() {
    let config = Config::default();
    let upstream = BlockingUpstream::new([192, 0, 2, 50]);
    let service = dns::DnsService::with_forwarder(test_dns_forwarder(&config, upstream.clone()));
    let query = build_dns_query("flush.example", 1);
    let resolving = {
        let service = service.clone();
        let query = query.clone();
        tokio::spawn(async move { service.resolve(&query, IngressProfile::Internal).await })
    };
    upstream.entered.notified().await;

    assert!(!service.flush_cache().await.expect("in-memory flush"));
    upstream.release.notify_waiters();
    assert!(
        resolving.await.expect("resolution task").is_err(),
        "flush must cancel an operation from the previous publication epoch"
    );
    assert!(
        service
            .cache()
            .lock()
            .await
            .get("flush.example:1")
            .is_none(),
        "cancelled response must not repopulate the cache"
    );
}
