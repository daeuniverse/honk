use super::*;

pub(super) const DEADLINE: Duration = Duration::from_secs(5);
pub(super) const PREFIX: &str = "/raw/../%2f/";
pub(super) const QUERY: &str = "token=a%2Fb&empty=";

pub(super) enum PeerCommand {
    Goaway(oneshot::Sender<()>),
    Window(u32, oneshot::Sender<()>),
}

pub(super) struct PeerRequest {
    pub(super) carrier: usize,
    pub(super) request: http::Request<h2::RecvStream>,
    pub(super) respond: h2::server::SendResponse<Bytes>,
    pub(super) control: mpsc::Sender<PeerCommand>,
}

pub(super) struct Peer {
    pub(super) address: std::net::SocketAddr,
    pub(super) requests: mpsc::Receiver<PeerRequest>,
    pub(super) settings: mpsc::Receiver<()>,
    pub(super) settings_count: usize,
    pub(super) driver: tokio::task::JoinHandle<()>,
}

impl Peer {
    pub(super) async fn new(window: u32) -> Self {
        Self::with_stream_limit(window, 128).await
    }

    pub(super) async fn with_stream_limit(window: u32, max_streams: u32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (requests_tx, requests) = mpsc::channel(32);
        let (settings_tx, settings) = mpsc::channel(32);
        let driver = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let mut carrier = 0;
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted.unwrap();
                        tcp.set_nodelay(true).unwrap();
                        carrier += 1;
                        let carrier = carrier;
                        let requests = requests_tx.clone();
                        let settings = settings_tx.clone();
                        connections.spawn(async move {
                            let mut connection = h2::server::Builder::new()
                                .initial_window_size(window)
                                .initial_connection_window_size(window * 4)
                                .max_concurrent_streams(max_streams)
                                .max_header_list_size(64 * 1024)
                                .handshake::<_, Bytes>(tcp).await.unwrap();
                            let mut ping = connection.ping_pong().unwrap();
                            ping.send_ping(h2::Ping::opaque()).unwrap();
                            let mut settings_notified = false;
                            let (control, mut commands) = mpsc::channel::<PeerCommand>(1);
                            loop {
                                tokio::select! {
                                    request = connection.accept() => {
                                        let Some(request) = request else { break };
                                        let Ok((request, respond)) = request else { break };
                                        if requests.send(PeerRequest {
                                            carrier, request, respond, control: control.clone(),
                                        }).await.is_err() { break }
                                    }
                                    pong = poll_fn(|cx| ping.poll_pong(cx)), if !settings_notified => {
                                        if pong.is_err() { break }
                                        if settings.send(()).await.is_err() { break }
                                        settings_notified = true;
                                    }
                                    Some(command) = commands.recv() => {
                                        let ack = match command {
                                            PeerCommand::Goaway(ack) => {
                                                connection.graceful_shutdown();
                                                ack
                                            }
                                            PeerCommand::Window(window, ack) => {
                                                connection.set_initial_window_size(window).unwrap();
                                                ack
                                            }
                                        };
                                        let _ = ack.send(());
                                    }
                                }
                            }
                        });
                    }
                    Some(result) = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap();
                    }
                }
            }
        });
        Self {
            address,
            requests,
            settings,
            settings_count: 0,
            driver,
        }
    }

    pub(super) async fn next(&mut self) -> PeerRequest {
        tokio::time::timeout(DEADLINE, self.requests.recv())
            .await
            .expect("XHTTP request did not reach the real H2 peer")
            .expect("H2 peer stopped")
    }

    pub(super) async fn wait_settings(&mut self, runtime: &NodeRuntime) {
        let carriers = runtime.xhttp.as_ref().unwrap().pool.live_session_count();
        // An acknowledged PING follows the server SETTINGS on each physical carrier.
        tokio::time::timeout(DEADLINE, async {
            while self.settings_count < carriers {
                self.settings
                    .recv()
                    .await
                    .expect("peer stopped before SETTINGS receipt");
                self.settings_count += 1;
            }
        })
        .await
        .expect("client did not receive the peer's initial SETTINGS");
    }

    pub(super) fn runtime(&self, mode: XhttpMode, post_limit: u32) -> EphemeralRuntimeGuard {
        let mut node = Node {
            name: "xhttp-real-peer".into(),
            address: self.address.ip().to_string(),
            port: self.address.port(),
            outbound: OutboundConfig::Trojan(Default::default()),
            ..Node::default()
        };
        node.tls_mut().unwrap().enabled = false;
        let transport = node.transport_mut().unwrap();
        transport.transport = "xhttp".into();
        transport.xhttp = Some(XhttpOptions {
            path: format!("{PREFIX}?{QUERY}"),
            host: Some("peer.example".into()),
            mode,
            headers: [("x-peer-test".into(), "raw".into())].into(),
            x_padding_bytes: XhttpRange { min: 7, max: 7 },
            sc_max_each_post_bytes: XhttpRange {
                min: post_limit,
                max: post_limit,
            },
            sc_min_posts_interval_ms: XhttpRange { min: 0, max: 0 },
            ..XhttpOptions::default()
        });
        node.normalize_stream_transport().unwrap();
        node.id = node.derive_id();
        NodeRuntime::try_ephemeral_guarded(&node).unwrap()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl XhttpRuntime {
    pub(super) async fn open(
        self: &Arc<Self>,
        runtime: &Arc<NodeRuntime>,
        tcp: Option<TcpStream>,
        timeout: Duration,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let (stream, preparation) = self.prepare(runtime, tcp, timeout).await?;
        preparation.commit()?;
        Ok(stream)
    }
}
pub(super) async fn open(runtime: &Arc<NodeRuntime>) -> Box<dyn AsyncReadWrite> {
    tokio::time::timeout(
        DEADLINE,
        runtime
            .xhttp
            .as_ref()
            .unwrap()
            .open(runtime, None, DEADLINE),
    )
    .await
    .expect("establishment waited for response headers")
    .unwrap()
}

pub(super) async fn carrier(runtime: &Arc<NodeRuntime>) -> Arc<XhttpSession> {
    runtime
        .xhttp
        .as_ref()
        .unwrap()
        .pool
        .offer(|| async { anyhow::bail!("the test expected the existing carrier") })
        .await
        .unwrap()
}

pub(super) fn assert_headers(request: &http::Request<h2::RecvStream>) {
    assert_eq!(request.uri().scheme_str(), Some("http"));
    assert_eq!(request.uri().authority().unwrap().as_str(), "peer.example");
    assert_eq!(request.uri().query(), Some(QUERY));
    assert_eq!(request.headers()["x-peer-test"], "raw");
    assert_eq!(
        request.headers()["referer"],
        format!("http://peer.example{PREFIX}?x_padding=XXXXXXX")
    );
}

pub(super) fn session_path(request: &http::Request<h2::RecvStream>) -> String {
    assert_headers(request);
    let session = request.uri().path().strip_prefix(PREFIX).unwrap();
    uuid::Uuid::parse_str(session).expect("session must be one UUID path component");
    request.uri().path().to_owned()
}

pub(super) fn response(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: u16,
    end: bool,
) -> h2::SendStream<Bytes> {
    respond
        .send_response(
            http::Response::builder().status(status).body(()).unwrap(),
            end,
        )
        .unwrap()
}

pub(super) async fn receive(body: &mut h2::RecvStream, length: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let data = body
            .data()
            .await
            .expect("request ended before application length")
            .unwrap();
        bytes.extend_from_slice(&data);
        body.flow_control().release_capacity(data.len()).unwrap();
    }
    assert_eq!(
        bytes.len(),
        length,
        "unexpected framing or replayed payload"
    );
    bytes
}

pub(super) async fn eof(body: &mut h2::RecvStream) {
    while let Some(data) = body.data().await {
        assert!(
            data.unwrap().is_empty(),
            "unexpected data after application length"
        );
    }
}

pub(super) async fn send(body: &mut h2::SendStream<Bytes>, mut bytes: Bytes, end: bool) {
    if bytes.is_empty() {
        if end {
            body.send_data(Bytes::new(), true).unwrap();
        }
        return;
    }
    while !bytes.is_empty() {
        body.reserve_capacity(bytes.len());
        if body.capacity() == 0 {
            poll_fn(|cx| body.poll_capacity(cx))
                .await
                .expect("response stream closed")
                .unwrap();
            continue;
        }
        let count = body.capacity().min(bytes.len()).min(16 * 1024);
        let data = bytes.split_to(count);
        body.send_data(data, end && bytes.is_empty()).unwrap();
    }
}

pub(super) async fn wait_released(runtime: &NodeRuntime) {
    tokio::time::timeout(DEADLINE, async {
        while runtime.xhttp.as_ref().unwrap().pool.metrics().streams != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropping logical stream leaked request permits");
}

pub(super) async fn receive_without_releasing(body: &mut h2::RecvStream, length: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let data = body
            .data()
            .await
            .expect("request ended before the initial window was exhausted")
            .unwrap();
        bytes.extend_from_slice(&data);
    }
    assert_eq!(bytes.len(), length);
    bytes
}
