use super::*;

pub(super) struct Origin {
    address: SocketAddr,
    requests: mpsc::UnboundedReceiver<TcpStream>,
    pub(super) count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Origin {
    pub(super) async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, requests) = mpsc::unbounded_channel();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(socket.read_u8().await.unwrap());
                }
                observed.fetch_add(1, Ordering::SeqCst);
                if sender.send(socket).is_err() {
                    break;
                }
            }
        });
        Self {
            address,
            requests,
            count,
            task,
        }
    }

    pub(super) fn subscription(&self) -> Subscription {
        Subscription {
            name: "private-provider-tag".into(),
            url: format!(
                "http://{}/credential-path?token=private-query#private-fragment",
                self.address
            ),
            update_interval: 0,
            download_detour: "direct".into(),
            headers: vec![honk_config::subscription::SubscriptionHeader {
                key: "Authorization".into(),
                value: "Bearer private-origin-token".into(),
            }],
            ..Default::default()
        }
    }

    pub(super) async fn next(&mut self) -> TcpStream {
        timeout(WAIT, self.requests.recv()).await.unwrap().unwrap()
    }
    pub(super) async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

pub(super) async fn respond(mut socket: TcpStream, body: &str) {
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
}

pub(super) struct Fixture {
    pub(super) address: SocketAddr,
    pub(super) client: reqwest::Client,
    pub(super) state: Arc<NativeState>,
    server: NativeServer,
    subscriptions: SubscriptionSupervisor,
    pub(super) commands: mpsc::Sender<ControlCommand>,
    pub(super) merges: mpsc::Receiver<ControlCommand>,
    control: JoinHandle<anyhow::Result<()>>,
}

impl Fixture {
    pub(super) async fn start(
        mut config: Config,
        store: Option<SubscriptionStore>,
        initial_body: Option<&str>,
        origin: &mut Origin,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        config.global.nfqueue_enable = false;
        config.global.store_subscribe = false;
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.secret = "provider-admin-token".into();
        config.experimental.native_api.listen = address.to_string();
        config.ensure_builtin_nodes();
        let preparation = tokio::spawn(async move {
            let owner = SubscriptionSupervisor::prepare(&mut config, store, Vec::new())
                .await
                .unwrap();
            (config, owner)
        });
        if let Some(body) = initial_body {
            respond(origin.next().await, body).await;
        }
        let (config, mut subscriptions) = timeout(WAIT, preparation).await.unwrap().unwrap();
        let resolver = DnsResolver::new(&config.dns).unwrap();
        let forwarder = resolver.forwarder();
        let mut control = ControlPlane::new(
            config,
            Box::new(MockEbpfBackend::new()),
            Router::new(&[], "direct").unwrap(),
            Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
            resolver,
            forwarder,
        )
        .unwrap();
        control.set_mode_state(Arc::new(RwLock::new(crate::mode::ModeState::new(
            "Rule", "",
        ))));
        control.start_datapath_flags_coordinator().unwrap();
        control
            .install_startup_diagnostics(subscriptions.take_startup_diagnostics())
            .await;
        let state = Arc::new(
            NativeState::new(&mut control, address, SystemTime::now(), Instant::now())
                .await
                .unwrap(),
        );
        let commands = control.command_sender();
        let (merge_tx, merges) = mpsc::channel(16);
        subscriptions.start(merge_tx);
        state.observation.providers.attach(subscriptions.handle());
        let control = tokio::spawn(async move {
            control
                .run_native_config_test_commands(
                    Arc::new(AtomicUsize::new(0)),
                    None,
                    Arc::default(),
                )
                .await
        });
        let server = NativeServer::start(listener, Arc::clone(&state));
        Self {
            address,
            client: reqwest::Client::builder()
                .no_proxy()
                .default_headers(reqwest::header::HeaderMap::from_iter([(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_static("Bearer provider-admin-token"),
                )]))
                .timeout(WAIT)
                .build()
                .unwrap(),
            state,
            server,
            subscriptions,
            commands,
            merges,
            control,
        }
    }

    pub(super) fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
    pub(super) async fn get(&self, path: &str) -> Value {
        let response = self.client.get(self.url(path)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.json().await.unwrap()
    }
    pub(super) async fn refresh(&self, provider: Uuid, key: &str) -> reqwest::Response {
        self.client
            .post(self.url(&format!("/api/v1/providers/{provider}/refresh")))
            .header("idempotency-key", key)
            .send()
            .await
            .unwrap()
    }
    pub(super) async fn publish(&mut self) {
        let command = timeout(WAIT, self.merges.recv()).await.unwrap().unwrap();
        self.commands.send(command).await.unwrap();
    }
    pub(super) async fn terminal(&self, accepted: &Value) -> Value {
        timeout(WAIT, async {
            loop {
                let operation = self.get(accepted["href"].as_str().unwrap()).await;
                if matches!(operation["status"].as_str(), Some("succeeded" | "failed")) {
                    break operation;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap()
    }
    pub(super) async fn reload(&self, config: Config) {
        let (result, wait) = oneshot::channel();
        self.commands
            .send(ControlCommand::ReloadConfig {
                request_id: 1,
                config: Box::new(config),
                diagnostics: Vec::new(),
                sources: None,
                expected_group_revision: None,
                result,
            })
            .await
            .unwrap();
        let reply = timeout(WAIT, wait).await.unwrap().unwrap();
        assert!(reply.outcome.accepted());
        self.subscriptions
            .handle()
            .reconcile(reply.authorized)
            .await
            .unwrap();
    }
    pub(super) async fn stop(self) {
        self.server.shutdown().await;
        // The test bridge is the owner of intentionally gated, not-yet-admitted merges.
        drop(self.merges);
        assert_eq!(
            timeout(WAIT, self.subscriptions.shutdown())
                .await
                .unwrap()
                .unwrap(),
            0
        );
        self.commands.send(ControlCommand::Shutdown).await.unwrap();
        timeout(WAIT, self.control).await.unwrap().unwrap().unwrap();
    }
}
