use super::*;
use crate::control::retirement_worker::RetirementWorker;
use crate::control::tests::{
    store_active_tcp_flow,
    support::{canonical_socks5, test_dns_forwarder},
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "tcp_native_flow_tests/closure.rs"]
mod closure;
#[path = "tcp_native_flow_tests/recording.rs"]
mod recording;

struct Fixture {
    plane: ControlPlane,
    handle: ControlPlaneHandle,
    server: crate::native_api::NativeServer,
    http: reqwest::Client,
    api: String,
    listener: tokio::net::TcpListener,
    client: TcpStream,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    removals: Option<RetirementWorker>,
    removal_errors: mpsc::UnboundedReceiver<anyhow::Error>,
}

impl Fixture {
    async fn new(selected: &str, dial_mode: &str) -> anyhow::Result<Self> {
        Self::with_recording(selected, dial_mode, true).await
    }

    async fn with_recording(
        selected: &str,
        dial_mode: &str,
        recording: bool,
    ) -> anyhow::Result<Self> {
        Self::with_config(selected, dial_mode, recording, |_| {}).await
    }

    async fn with_config(
        selected: &str,
        dial_mode: &str,
        recording: bool,
        configure: impl FnOnce(&mut Config),
    ) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let destination = listener.local_addr()?;
        let client = TcpStream::connect(destination).await?;
        let (accepted, source) = listener.accept().await?;
        let mut config = Config::default();
        config.ensure_builtin_nodes();
        config.nodes.push(canonical_socks5(
            "peer",
            "127.0.0.1",
            destination.port(),
            None,
        ));
        config.global.dial_mode = dial_mode.into();
        config.global.nfqueue_enable = false;
        config.global.store_subscribe = false;
        config.global.connect_timeout_ms = 5_000;
        config.routing.default_outbound = "outer".into();
        config.groups = vec![
            Group {
                name: "outer".into(),
                groups: vec!["inner".into()],
                ..Default::default()
            },
            Group {
                name: "inner".into(),
                nodes: config.nodes.iter().map(|node| node.id).collect(),
                default: Some(selected.into()),
                ..Default::default()
            },
        ];
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.record_flows = recording;
        config.experimental.native_api.allow_anonymous_loopback = true;
        configure(&mut config);
        let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
        let mut plane = ControlPlane::new(
            config,
            Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
            router,
            Arc::new(ProxyRegistry::default_resolver()?),
            DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
            test_dns_forwarder(),
        )?;
        let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = api_listener.local_addr()?;
        let state = crate::native_api::NativeState::new(
            &mut plane,
            address,
            std::time::SystemTime::now(),
            std::time::Instant::now(),
        )
        .await?;
        let server = crate::native_api::NativeServer::start(api_listener, Arc::new(state));
        let http = reqwest::Client::builder().no_proxy().build()?;
        http.get(format!("http://{address}/api/v1/flows"))
            .send()
            .await?
            .error_for_status()?;
        let handle = plane.spawn_handle();
        handle.connection_tracker.disable_api();
        store_active_tcp_flow(&handle, destination, source).await?;
        let (fatal_tx, removal_errors) = mpsc::unbounded_channel();
        let removals = spawn_retirement_worker(
            Arc::clone(&plane.udp_pool),
            handle.tc_kernel.clone().unwrap(),
            Arc::clone(&handle.connection_tracker),
            fatal_tx,
            Arc::clone(&handle.tcp_flow_pins),
            Arc::clone(&handle.retirement),
        );
        let worker = handle.clone();
        let task = tokio::spawn(async move { worker.serve_connection(accepted, source).await });
        Ok(Self {
            plane,
            handle,
            server,
            http,
            api: format!("http://{address}/api/v1"),
            listener,
            client,
            task,
            removals: Some(removals),
            removal_errors,
        })
    }

    async fn finish_removals(&mut self) -> anyhow::Result<()> {
        self.plane.udp_pool.shutdown().await;
        self.handle.retirement.sink.lock().take();
        if let Some(task) = self.removals.take() {
            task.await?;
        }
        assert!(self.removal_errors.try_recv().is_err());
        Ok(())
    }

    async fn flow(&self, state: &str) -> anyhow::Result<Value> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let list: Value = self
                    .http
                    .get(format!("{}/flows", self.api))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                if let Some(row) = list["flows"].as_array().and_then(|rows| rows.first())
                    && row["state"] == state
                {
                    let id = row["id"].as_str().unwrap();
                    return self
                        .http
                        .get(format!("{}/flows/{id}", self.api))
                        .send()
                        .await?
                        .error_for_status()?
                        .json::<Value>()
                        .await
                        .map_err(anyhow::Error::from);
                }
                tokio::task::yield_now().await;
            }
        })
        .await?
    }
}

fn steps(flow: &Value, stage: &str) -> Vec<Value> {
    flow["trace"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["stage"] == stage)
        .cloned()
        .collect()
}

fn leaf_attempts(flow: &Value) -> Vec<Value> {
    steps(flow, "outbound")
        .into_iter()
        .filter(|step| step["data"]["kind"] == "leaf")
        .collect()
}

#[tokio::test]
async fn pinned_tcp_dns_route_keeps_kernel_route_observation() -> anyhow::Result<()> {
    let mut fixture = Fixture::new("direct", "ip").await?;
    let generation = fixture.handle.ebpf.read().await.routing_policy_generation();
    let handoff = super::super::handoff::HandoffResult::from(RoutingHandoffEntry {
        routing_generation: generation,
        result: RoutingResult {
            outbound: OutboundIndex::Direct as u8,
            must: 1,
            ..Default::default()
        },
        ..Default::default()
    });
    let route = fixture.handle.pin_tcp_dns_route(&handoff, true).await?;
    assert_eq!(
        route.decision.native_route.retained_bytes(),
        size_of::<super::super::observation::RouteObservation>()
    );
    let route = fixture.handle.pin_tcp_dns_route(&handoff, false).await?;
    assert_eq!(route.decision.native_route.retained_bytes(), 0);
    fixture.task.abort();
    fixture.finish_removals().await?;
    fixture.server.shutdown().await;
    Ok(())
}
