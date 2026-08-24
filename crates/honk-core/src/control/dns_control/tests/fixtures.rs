use super::*;

pub(super) struct SlowUpstream {
    pub(super) calls: AtomicUsize,
    pub(super) delay: Duration,
    pub(super) response: Vec<u8>,
}

#[async_trait::async_trait]
impl DnsUpstreamPool for SlowUpstream {
    async fn query(&self, _name: &str, _raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        Ok(self.response.clone())
    }
}

pub(super) fn test_controller(
    response: Vec<u8>,
    delay: Duration,
) -> (Arc<DnsController>, Arc<SlowUpstream>) {
    let upstream = Arc::new(SlowUpstream {
        calls: AtomicUsize::new(0),
        delay,
        response,
    });
    let controller = controller_for_upstream(upstream.clone());
    (Arc::new(controller), upstream)
}

pub(super) fn controller_with_limit(
    upstream: Arc<dyn DnsUpstreamPool>,
    max_concurrent_queries: usize,
) -> Arc<DnsController> {
    let mut controller = controller_for_upstream(upstream);
    controller.concurrency_limit = Arc::new(Semaphore::new(max_concurrent_queries));
    Arc::new(controller)
}

pub(super) fn controller_with_dns_config(
    upstream: Arc<dyn DnsUpstreamPool>,
    config: &honk_config::dns::DnsConfig,
) -> Arc<DnsController> {
    Arc::new(controller_for_upstream_and_config(upstream, config))
}

fn controller_for_upstream(upstream: Arc<dyn DnsUpstreamPool>) -> DnsController {
    controller_for_upstream_and_config(upstream, &honk_config::dns::DnsConfig::default())
}

fn controller_for_upstream_and_config(
    upstream: Arc<dyn DnsUpstreamPool>,
    config: &honk_config::dns::DnsConfig,
) -> DnsController {
    let forwarder = Arc::new(DnsForwarder::new(
        upstream,
        Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
            16,
        ))),
        Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(config).expect("router")),
    ));
    DnsController::new(
        forwarder,
        Arc::new(RwLock::new(Box::new(
            crate::ebpf::mock::MockEbpfBackend::new(),
        ))),
        Arc::new(RwLock::new(
            Router::new(&[], "direct").expect("test router"),
        )),
    )
}

pub(super) fn query_with_txid(domain: &str, txid: u16) -> Vec<u8> {
    let mut query = crate::dns::forwarder::build_dns_query(domain, 1);
    query[0..2].copy_from_slice(&txid.to_be_bytes());
    query
}

pub(super) fn response_with_txid(domain: &str, txid: u16) -> Vec<u8> {
    let mut response = query_with_txid(domain, txid);
    response[2] = 0x81;
    response[3] = 0x80;
    response
}

pub(super) struct SnapshotUpstream {
    pub(super) ip: [u8; 4],
    pub(super) calls: AtomicUsize,
    pub(super) entered: Option<Arc<Notify>>,
    pub(super) release: Option<Arc<Notify>>,
}

#[async_trait::async_trait]
impl DnsUpstreamPool for SnapshotUpstream {
    async fn query(&self, _name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0
            && let (Some(entered), Some(release)) = (&self.entered, &self.release)
        {
            entered.notify_one();
            release.notified().await;
        }
        Ok(a_response(raw, self.ip))
    }
}

pub(super) fn a_response(query: &[u8], ip: [u8; 4]) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, ip[0], ip[1], ip[2], ip[3],
    ]);
    response
}

pub(super) fn snapshot_forwarder(upstream: Arc<SnapshotUpstream>) -> Arc<DnsForwarder> {
    Arc::new(
        DnsForwarder::new(
            upstream,
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            Arc::new(
                crate::dns::routing::DnsRouter::new_from_dns_config(
                    &honk_config::dns::DnsConfig::default(),
                )
                .expect("router"),
            ),
        )
        .with_cache_enabled(false),
    )
}

pub(super) fn snapshot_controller(forwarder: Arc<DnsForwarder>) -> Arc<DnsController> {
    Arc::new(DnsController::new(
        forwarder,
        Arc::new(RwLock::new(Box::new(
            crate::ebpf::mock::MockEbpfBackend::new(),
        ))),
        Arc::new(RwLock::new(
            Router::new(&[], "direct").expect("test router"),
        )),
    ))
}

pub(super) async fn publish_snapshot_forwarder(
    controller: &DnsController,
    forwarder: Arc<DnsForwarder>,
) {
    let provider = controller.runtime_provider();
    let current = provider.acquire();
    let runtime = crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
        generation: crate::dns::runtime::RuntimeGeneration::new(
            current.runtime().generation().get().saturating_add(1),
        ),
        forwarder: Arc::clone(&forwarder),
        routing_projection: Arc::clone(current.runtime().routing_projection()),
        outbound_runtime: None,
        transport: Arc::new(NoopRuntimeTransport),
    });
    drop(current);
    provider.publish(runtime);
}

pub(super) struct BlockingFirstUpstream {
    pub(super) first_entered: Notify,
    pub(super) release_first: Notify,
}

#[async_trait::async_trait]
impl DnsUpstreamPool for BlockingFirstUpstream {
    async fn query(&self, _name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (domain, _) = crate::dns::forwarder::parse_dns_question(raw).expect("valid test query");
        if domain == "first.example" {
            self.first_entered.notify_one();
            self.release_first.notified().await;
        }
        Ok(response_with_txid(
            &domain,
            u16::from_be_bytes([raw[0], raw[1]]),
        ))
    }
}

pub(super) async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("listener address");
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (
        client.expect("connect test client"),
        accepted.expect("accept test connection").0,
    )
}

pub(super) async fn write_tcp_query(stream: &mut TcpStream, query: &[u8]) {
    use tokio::io::AsyncWriteExt;
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .expect("write query length");
    stream.write_all(query).await.expect("write query");
}

pub(super) async fn read_tcp_response(stream: &mut TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut length = [0u8; 2];
    stream
        .read_exact(&mut length)
        .await
        .expect("read response length");
    let mut response = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream
        .read_exact(&mut response)
        .await
        .expect("read response");
    response
}
