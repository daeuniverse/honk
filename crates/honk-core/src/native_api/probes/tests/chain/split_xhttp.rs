use super::*;
use bytes::{Bytes, BytesMut};
use honk_config::node::{XhttpDownload, XhttpMode, XhttpOptions, XhttpRange};
use sha2::Sha224;
use std::net::Ipv6Addr;
use tokio::{io::AsyncWrite, sync::mpsc};

const DOWNLOAD: &str = "download.chain.test";
const DOWNLOAD_SNI: &str = "tls-download.chain.test";
const DOTTED_LITERAL: &str = "127.0.0.1.";
const DOWNLOAD_AUTHORITY: &str = "http-download.chain.test";
const UPLOAD_AUTHORITY: &str = "http-upload.chain.test";
const OLD_DOWNLOAD: Ipv6Addr = Ipv6Addr::LOCALHOST;
const NEW_DOWNLOAD: Ipv4Addr = Ipv4Addr::LOCALHOST;
const APP_PORT: u16 = 8080;
const EXIT_PORT: u16 = 1080;

const TEST_PREFIX: &str = "native_api::probes::tests::chain::split_xhttp";

struct SplitDns(IpAddr);

#[async_trait::async_trait]
impl DnsUpstreamPool for SplitDns {
    async fn query(&self, _: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (name, qtype) = parse_dns_question(query).unwrap();
        let ip = match name.trim_end_matches('.') {
            ENTRY => LIVE.into(),
            DOWNLOAD => self.0,
            CHECK => CAPTURED.into(),
            other => panic!("unexpected local lookup of {other}"),
        };
        Ok(address_reply(query, qtype, ip))
    }
}

fn address_reply(query: &[u8], qtype: u16, ip: IpAddr) -> Vec<u8> {
    let octets = match (ip, qtype) {
        (IpAddr::V4(ip), 1) => ip.octets().to_vec(),
        (IpAddr::V6(ip), 28) => ip.octets().to_vec(),
        _ => Vec::new(),
    };
    let mut answer = query.to_vec();
    answer[2..4].copy_from_slice(&[0x81, 0x80]);
    if !octets.is_empty() {
        answer[6..8].copy_from_slice(&1u16.to_be_bytes());
        answer.extend_from_slice(&[0xc0, 0x0c]);
        answer.extend_from_slice(&qtype.to_be_bytes());
        answer.extend_from_slice(&[0, 1, 0, 0, 0, 60, 0, octets.len() as u8]);
        answer.extend_from_slice(&octets);
    }
    answer
}

#[async_trait::async_trait]
impl RuntimeTransport for SplitDns {
    async fn close(&self) {}
}

#[derive(Default)]
struct SplitBootstrap(parking_lot::Mutex<Vec<String>>);

impl NodeHostResolver for SplitBootstrap {
    fn lookup(&self, host: &str) -> Option<NodeHostLookup> {
        self.0.lock().push(host.to_owned());
        let ip = match host {
            ENTRY => LIVE,
            DOWNLOAD => NEW_DOWNLOAD,
            DOTTED_LITERAL => CAPTURED,
            other => panic!("unexpected bootstrap lookup of {other}"),
        };
        Some(Box::pin(std::future::ready(Ok(vec![ip.into()]))))
    }
}

async fn download_listeners() -> (Arc<TcpListener>, Arc<TcpListener>) {
    for _ in 0..8 {
        let old = TcpListener::bind((OLD_DOWNLOAD, 0)).await.unwrap();
        match TcpListener::bind((NEW_DOWNLOAD, old.local_addr().unwrap().port())).await {
            Ok(new) => return (Arc::new(old), Arc::new(new)),
            Err(error) if error.kind() == ErrorKind::AddrInUse => continue,
            Err(error) => panic!("bind replacement XHTTP peer: {error}"),
        }
    }
    panic!("could not bind both download peers to the same port");
}

fn download_tls() -> (Arc<rustls::ServerConfig>, bool) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "split probe test CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let issuer = rcgen::Issuer::new(params.clone(), rcgen::KeyPair::generate().unwrap());
    let root = params.self_signed(issuer.key()).unwrap();
    let leaf = rcgen::CertificateParams::new(vec![DOWNLOAD_SNI.into()]).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = leaf.signed_by(&key, &issuer).unwrap();
    // The disposable verification build may add this root to its Mozilla store.
    // The normal test build exercises the TLS selection up to trust rejection.
    let root_file = std::env::var_os("HONK_SPLIT_XHTTP_FIXTURE_ROOT");
    if let Some(path) = &root_file {
        std::fs::write(path, root.der()).unwrap();
    }
    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    (Arc::new(config), root_file.is_some())
}

type H2Request = (
    http::Request<h2::RecvStream>,
    h2::server::SendResponse<Bytes>,
);

async fn drive_h2(
    socket: impl tokio::io::AsyncRead + AsyncWrite + Unpin,
    requests: mpsc::UnboundedSender<H2Request>,
) {
    let mut connection = h2::server::handshake(socket).await.unwrap();
    while let Some(Ok(request)) = connection.accept().await {
        requests
            .send(request)
            .expect("request reached an idle production carrier");
    }
}

async fn upload_peer(listener: Arc<TcpListener>, requests: mpsc::UnboundedSender<H2Request>) {
    let (socket, _) = listener.accept().await.unwrap();
    drive_h2(socket, requests).await;
}

async fn download_hello(
    socket: tokio::net::TcpStream,
) -> tokio_rustls::StartHandshake<tokio::net::TcpStream> {
    let hello = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), socket)
        .await
        .unwrap();
    assert_eq!(hello.client_hello().server_name(), Some(DOWNLOAD_SNI));
    assert!(hello.client_hello().alpn().unwrap().any(|id| id == b"h2"));
    hello
}

async fn download_peer(
    listener: Arc<TcpListener>,
    config: Arc<rustls::ServerConfig>,
    requests: mpsc::UnboundedSender<H2Request>,
    trusted: bool,
    cancel_before_tls: Option<watch::Sender<bool>>,
) {
    let (socket, _) = listener.accept().await.unwrap();
    let hello = download_hello(socket).await;
    if let Some(cancel) = cancel_before_tls {
        cancel.send_replace(true);
    }
    let result = hello.into_stream(config).await;
    if trusted {
        drive_h2(result.unwrap(), requests).await;
    } else {
        assert!(result.is_err());
    }
}

async fn fill_post(body: &mut h2::RecvStream, buffer: &mut BytesMut) {
    let data = body.data().await.expect("truncated XHTTP upload").unwrap();
    body.flow_control().release_capacity(data.len()).unwrap();
    buffer.extend_from_slice(&data);
}

async fn expect_post_bytes(body: &mut h2::RecvStream, buffer: &mut BytesMut, expected: &[u8]) {
    while buffer.len() < expected.len() {
        fill_post(body, buffer).await;
    }
    assert_eq!(&buffer.split_to(expected.len())[..], expected);
}

async fn exchange(
    mut downloads: mpsc::UnboundedReceiver<H2Request>,
    mut uploads: mpsc::UnboundedReceiver<H2Request>,
    warm: bool,
    cancel_last_request: Option<watch::Sender<bool>>,
) {
    use std::io::Write as _;

    let (get, mut responder) = downloads
        .recv()
        .await
        .expect("the captured GET peer closed");
    assert_eq!(get.method(), http::Method::GET);
    assert_eq!(get.uri().authority().unwrap().as_str(), DOWNLOAD_AUTHORITY);
    let session = get.uri().path().strip_prefix("/download/").unwrap();
    Uuid::parse_str(session).unwrap();
    let mut response = responder
        .send_response(http::Response::new(()), false)
        .unwrap();

    let (post, mut responder) = uploads
        .recv()
        .await
        .expect("the private upload peer closed");
    assert_eq!(post.method(), http::Method::POST);
    assert_eq!(post.uri().authority().unwrap().as_str(), UPLOAD_AUTHORITY);
    assert_eq!(post.uri().path(), format!("/upload/{session}"));
    responder
        .send_response(http::Response::new(()), true)
        .unwrap();
    let mut body = post.into_body();
    let mut buffer = BytesMut::new();

    let mut header = Vec::with_capacity(72 + EXIT.len());
    for byte in Sha224::digest(PASSWORD) {
        write!(header, "{byte:02x}").unwrap();
    }
    header.extend_from_slice(b"\r\n\x01\x03");
    header.push(EXIT.len() as u8);
    header.extend_from_slice(EXIT.as_bytes());
    header.extend_from_slice(&EXIT_PORT.to_be_bytes());
    header.extend_from_slice(b"\r\n\x05\x01\x00");
    expect_post_bytes(&mut body, &mut buffer, &header).await;
    response
        .send_data(Bytes::from_static(b"\x05\x00"), false)
        .unwrap();

    let mut connect = vec![5, 1, 0, 1];
    connect.extend_from_slice(&CAPTURED.octets());
    connect.extend_from_slice(&APP_PORT.to_be_bytes());
    expect_post_bytes(&mut body, &mut buffer, &connect).await;
    response
        .send_data(Bytes::from_static(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]), false)
        .unwrap();
    let methods: &[&str] = if warm { &["HEAD", "GET"] } else { &["GET"] };
    for method in methods {
        let end = loop {
            if let Some(pos) = buffer.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break pos + 4;
            }
            fill_post(&mut body, &mut buffer).await;
        };
        let headers = String::from_utf8(buffer.split_to(end).to_vec()).unwrap();
        assert!(headers.starts_with(&format!("{method} /probe HTTP/1.1\r\n")));
        assert!(
            headers
                .to_ascii_lowercase()
                .contains(&format!("\r\nhost: {CHECK}:{APP_PORT}\r\n"))
        );
        if *method == "GET"
            && let Some(cancel) = &cancel_last_request
        {
            cancel.send_replace(true);
            return;
        }
        response
            .send_data(
                Bytes::from_static(b"HTTP/1.1 204 No Content\r\n\r\n"),
                false,
            )
            .unwrap();
    }
    // The handles keep both requests open until the private runtime releases them.
    assert!(downloads.recv().await.is_none());
    assert!(uploads.recv().await.is_none());
}

fn split_config(
    upload_host: &str,
    upload_port: u16,
    download_host: &str,
    download_port: u16,
) -> (Config, Uuid, Uuid) {
    let mut front = Node::from_share_link(&format!(
        "trojan://{PASSWORD}@{upload_host}:{upload_port}#front",
    ))
    .unwrap();
    front.tls_mut().unwrap().enabled = false;
    let transport = front.transport_mut().unwrap();
    transport.transport = "xhttp".into();
    transport.xhttp = Some(XhttpOptions {
        path: "/upload/".into(),
        host: Some(UPLOAD_AUTHORITY.into()),
        mode: XhttpMode::StreamUp,
        download: Some(Box::new(XhttpDownload {
            address: download_host.into(),
            port: download_port,
            server_name: Some(DOWNLOAD_SNI.into()),
            host: Some(DOWNLOAD_AUTHORITY.into()),
            path: "/download/".into(),
            x_padding_bytes: XhttpRange { min: 8, max: 8 },
        })),
        ..Default::default()
    });
    front.normalize_stream_transport().unwrap();
    front.id = front.derive_id();
    let land = Node::from_share_link(&format!("socks5://{EXIT}:{EXIT_PORT}#land")).unwrap();
    let via = Node::chain_from_nodes("via", &[&front, &land]).unwrap();
    let (front_id, via_id) = (front.id, via.id);
    let mut config = Config::default();
    config.nodes.extend([front, land, via]);
    config.global.tcp_check_url = vec![format!("http://{CHECK}:{APP_PORT}/probe")];
    config.global.tcp_check_http_method = "GET".into();
    (config, front_id, via_id)
}

async fn split_probe(warmth: &str, cancelled: bool, test: &str) {
    let name = format!("{TEST_PREFIX}::{test}");
    if crate::test_support::run_exact_in_child("HONK_NATIVE_SPLIT_XHTTP_CHILD", &name) {
        return;
    }
    let (tls, trusted) = download_tls();
    let upload = Arc::new(TcpListener::bind((LIVE, 0)).await.unwrap());
    let (captured, replacement) = download_listeners().await;
    let (config, front_id, via_id) = split_config(
        ENTRY,
        upload.local_addr().unwrap().port(),
        DOWNLOAD,
        captured.local_addr().unwrap().port(),
    );
    let (mut state, control) = state_with_control(config).await;
    let dns = honk_config::dns::DnsConfig::default();
    let probe_dns = Arc::new(DnsServiceProvider::new(dns_runtime(
        0,
        Arc::new(SplitDns(OLD_DOWNLOAD.into())),
        &dns,
    )));
    state.dns = DnsService::with_provider(Arc::clone(&probe_dns));
    let bootstrap = Arc::new(SplitBootstrap::default());
    honk_outbound::bootstrap::set_node_host_resolver(Some(bootstrap.clone()));

    let (prod_post, mut production_uploads) = mpsc::unbounded_channel();
    let (prod_get, mut production_downloads) = mpsc::unbounded_channel();
    let live_upload = tokio::spawn(upload_peer(Arc::clone(&upload), prod_post));
    let live_download = tokio::spawn(download_peer(
        Arc::clone(&replacement),
        tls.clone(),
        prod_get,
        trusted,
        None,
    ));
    let registry = state.runtime_registry.read().clone();
    let live = registry.get(&front_id).unwrap();
    let warmable = state
        .proxy_registry
        .find(live.node.protocol())
        .unwrap()
        .warmable
        .as_ref()
        .unwrap();
    let warm_result = tokio::time::timeout(
        TIMEOUT,
        registry.scope_dials(live.scope_tasks(warmable.warm(
            live.clone(),
            TIMEOUT,
            honk_outbound::proxy::WarmRequirement::Session,
        ))),
    )
    .await
    .unwrap();
    assert_eq!(
        warm_result.is_ok(),
        trusted,
        "XHTTP pool warm-up: {:#?}",
        warm_result.as_ref().err()
    );
    let production_sessions = 1 + usize::from(trusted);
    assert_eq!(live.warm_counts().sessions, production_sessions);
    assert_eq!(*bootstrap.0.lock(), [ENTRY, DOWNLOAD]);

    let mut input = request(
        json!({"type":"node","node_id":via_id.to_string()}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    input["warmth"] = json!(warmth);
    let plan = capture(&state, serde_json::from_value(input).unwrap())
        .await
        .unwrap();
    publish_dns(&state, Arc::new(SplitDns(NEW_DOWNLOAD.into())), &dns);
    let mut plan = prepare(plan).await.unwrap();
    let (stop, receiver) = watch::channel(false);
    let (private_get, downloads) = mpsc::unbounded_channel();
    let download = tokio::spawn(download_peer(
        captured,
        tls,
        private_get,
        trusted,
        (cancelled && !trusted).then(|| stop.clone()),
    ));
    let (private_post, uploads) = mpsc::unbounded_channel();
    let private_upload =
        trusted.then(|| tokio::spawn(upload_peer(Arc::clone(&upload), private_post)));
    let deadline = Instant::now() + TIMEOUT;
    let (result, ()) = tokio::time::timeout(TIMEOUT * 2, async {
        tokio::join!(execute(&state, &mut plan, deadline, receiver), async {
            if trusted {
                exchange(
                    downloads,
                    uploads,
                    warmth == "warm",
                    cancelled.then(|| stop.clone()),
                )
                .await;
            }
        })
    })
    .await
    .expect("split XHTTP probe did not finish");
    result.unwrap();
    tokio::time::timeout(TIMEOUT, download)
        .await
        .expect("captured download peer was not reached or its carrier stayed open")
        .unwrap();
    if let Some(private_upload) = private_upload {
        tokio::time::timeout(TIMEOUT, private_upload)
            .await
            .expect("private upload carrier stayed open")
            .unwrap();
    }
    let row = &plan.result.results[0];
    let (state_name, error, measured_warmth) = if cancelled {
        ("unknown", Some("cancelled"), "unknown")
    } else if trusted {
        ("healthy", None, warmth)
    } else {
        ("unavailable", Some("probe_failed"), "unknown")
    };
    assert_eq!(
        (row.state, row.error, row.warmth),
        (state_name, error, measured_warmth)
    );
    assert_eq!(row.latency_ms.is_some(), error.is_none());
    assert_eq!(live.warm_counts().sessions, production_sessions);
    assert!(!live_upload.is_finished());
    assert!(!trusted || !live_download.is_finished());
    assert!(production_uploads.try_recv().is_err());
    assert!(production_downloads.try_recv().is_err());
    assert!(futures::poll!(std::pin::pin!(replacement.accept())).is_pending());
    assert_eq!(*bootstrap.0.lock(), [ENTRY, DOWNLOAD]);

    drop(plan);
    registry.shutdown().await;
    probe_dns.shutdown().await;
    control.dns_service().provider().unwrap().shutdown().await;
    tokio::time::timeout(TIMEOUT, live_upload)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(TIMEOUT, live_download)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn ordinary_and_split_probes_keep_the_admitted_bootstrap() {
    use honk_outbound::bootstrap::{BootstrapResolver, set_global, set_node_host_resolver};
    use tokio::net::UdpSocket;

    let name = format!("{TEST_PREFIX}::ordinary_and_split_probes_keep_the_admitted_bootstrap");
    if crate::test_support::run_exact_in_child("HONK_PROBE_BOOTSTRAP_OWNER_CHILD", &name) {
        return;
    }
    struct UnusedLiveHook;
    impl NodeHostResolver for UnusedLiveHook {
        fn lookup(&self, _: &str) -> Option<NodeHostLookup> {
            Some(Box::pin(std::future::ready(Err(
                ErrorKind::PermissionDenied.into(),
            ))))
        }
    }

    tokio::time::timeout(TIMEOUT * 3, async {
        let admitted = UdpSocket::bind((LIVE, 0)).await.unwrap();
        let successor = UdpSocket::bind((LIVE, 0)).await.unwrap();
        let plain = TcpListener::bind((LIVE, 0)).await.unwrap();
        let upload = TcpListener::bind((LIVE, 0)).await.unwrap();
        let download = TcpListener::bind((OLD_DOWNLOAD, 0)).await.unwrap();
        let (mut config, _, via) = split_config("127.0.0.1", upload.local_addr().unwrap().port(), DOWNLOAD, download.local_addr().unwrap().port());
        let aliases = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(aliases.path(), format!("full:plain.chain.test {ENTRY}\n")).unwrap();
        config.dns.hosts = vec![aliases.path().to_str().unwrap().into()];
        let leaf = Node::from_share_link(&format!("socks5://plain.chain.test:{}#plain", plain.local_addr().unwrap().port())).unwrap();
        let id = leaf.id;
        config.nodes.push(leaf);
        config.global.bootstrap_resolver = admitted.local_addr().unwrap().to_string();
        config.global.tcp_check_url = vec![format!("http://127.0.0.1:{APP_PORT}/probe")];
        config.global.udp_warm_node_count = 0;
        config.dns.routing.request.fallback = honk_config::dns::DnsRequestAction::AsIs;
        let (state, control) = state_with_control(config).await;
        let new_resolver = successor.local_addr().unwrap().to_string();
        // A lookup of the process resolver is wrong even during admission.
        set_global(BootstrapResolver::parse(&new_resolver));
        set_node_host_resolver(Some(Arc::new(UnusedLiveHook)));
        let mut plans = Vec::new();
        for (node, kind) in [(id, "tcp_connect"), (via, "http")] {
            let input = request(json!({"type":"node","node_id":node.to_string()}), kind, json!(["tcp"]), "ipv4");
            plans.push(capture(&state, serde_json::from_value(input).unwrap()).await.unwrap());
        }
        let mut replacement = state.config.read().await.as_ref().clone();
        replacement.global.bootstrap_resolver = new_resolver;
        assert!(control.reload_runtime_config(replacement, Default::default()).await);

        let serve = async {
            let mut names = Vec::new();
            for _ in 0..4 {
                let mut packet = [0; 512];
                let (len, from) = tokio::select! {
                    r = admitted.recv_from(&mut packet) => r.unwrap(),
                    _ = successor.readable() => panic!("an admitted probe used the successor resolver"),
                };
                let question = &packet[..len];
                let (name, qtype) = parse_dns_question(question).unwrap();
                names.push((name.trim_end_matches('.').to_owned(), qtype));
                let reply = SplitDns(OLD_DOWNLOAD.into()).query("bootstrap", question).await.unwrap();
                admitted.send_to(&reply, from).await.unwrap();
            }
            names.sort();
            assert_eq!(names, [(DOWNLOAD.into(), 1), (DOWNLOAD.into(), 28), (ENTRY.into(), 1), (ENTRY.into(), 28)]);
        };
        let run = async {
            for (i, plan) in plans.into_iter().enumerate() {
                let mut plan = prepare(plan).await.unwrap();
                assert_eq!(plan.attempts.len(), 1);
                let (_stop, cancel) = watch::channel(false);
                let (result, ()) = tokio::join!(execute(&state, &mut plan, Instant::now() + TIMEOUT, cancel), async {
                    if i == 0 {
                        let (mut socket, _) = plain.accept().await.unwrap();
                        assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
                    } else {
                        let (socket, _) = download.accept().await.unwrap();
                        drop(download_hello(socket).await);
                    }
                });
                result.unwrap();
                assert_eq!(plan.result.results[0].error, if i == 0 { None } else { Some("probe_failed") });
            }
        };
        tokio::join!(serve, run);
        assert_eq!(successor.try_recv_from(&mut [0; 512]).unwrap_err().kind(), ErrorKind::WouldBlock);
        state.dns.provider().unwrap().shutdown().await;
    }).await.expect("admitted native probes did not reach their own peers");
}

#[derive(Default)]
struct AliasDns(parking_lot::Mutex<Vec<(String, String, u16)>>);

#[async_trait::async_trait]
impl DnsUpstreamPool for AliasDns {
    async fn query(&self, upstream: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (name, qtype) = parse_dns_question(query).unwrap();
        self.0.lock().push((
            upstream.to_owned(),
            name.trim_end_matches('.').to_owned(),
            qtype,
        ));
        assert_eq!(qtype, 1);
        let ip = if upstream == "target" { CAPTURED } else { LIVE };
        Ok(address_reply(query, qtype, ip.into()))
    }
}

#[async_trait::async_trait]
impl RuntimeTransport for AliasDns {
    async fn close(&self) {}
}

fn install_alias_dns(
    state: &mut NativeState,
    mut dns: honk_config::dns::DnsConfig,
    aliases: &str,
    node_hosts: &[(&str, &str)],
) -> Arc<AliasDns> {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), aliases).unwrap();
    dns.hosts = vec![file.path().to_str().unwrap().to_owned()];
    let pool = Arc::new(AliasDns::default());
    let forwarder = DnsForwarder::new(
        pool.clone(),
        Arc::new(tokio::sync::Mutex::new(DnsCache::new(8))),
        Arc::new(DnsRouter::new_from_dns_config(&dns).unwrap()),
    )
    .with_hosts_from_config(&dns)
    .unwrap()
    .with_strategy(honk_config::dns::DnsStrategy::Ipv4Only)
    .with_node_hosts(
        node_hosts
            .iter()
            .map(|&(host, tag)| (host.to_owned(), vec![tag.to_owned()]))
            .collect(),
    );
    let runtime = DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(0),
        forwarder: Arc::new(forwarder),
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            0,
            Arc::new(crate::routing::Router::new(&[], "direct").unwrap()),
        )),
        outbound_runtime: None,
        transport: pool.clone(),
    });
    state.dns = DnsService::with_provider(Arc::new(DnsServiceProvider::new(runtime)));
    pool
}

async fn observe_bootstrap<T>(
    bootstrap: &tokio::net::UdpSocket,
    probe: impl Future<Output = T>,
) -> (T, usize) {
    tokio::pin!(probe);
    let mut questions = 0;
    let mut packet = [0; 512];
    loop {
        tokio::select! {
            biased;
            received = bootstrap.recv_from(&mut packet) => {
                let (len, peer) = received.unwrap();
                questions += 1;
                let query = &packet[..len];
                let (_, qtype) = parse_dns_question(query).unwrap();
                let reply = address_reply(query, qtype, LIVE.into());
                bootstrap.send_to(&reply, peer).await.unwrap();
            }
            result = &mut probe => return (result, questions),
        }
    }
}

#[tokio::test]
async fn physical_aliases_pin_captured_target_upstreams_independently_of_the_check_url() {
    use honk_outbound::bootstrap::{BootstrapResolver, set_global};
    use tokio::net::UdpSocket;

    let name = format!(
        "{TEST_PREFIX}::physical_aliases_pin_captured_target_upstreams_independently_of_the_check_url"
    );
    if crate::test_support::run_exact_in_child("HONK_PROBE_PHYSICAL_ALIAS_CHILD", &name) {
        return;
    }
    let bootstrap = UdpSocket::bind((LIVE, 0)).await.unwrap();
    let poison = UdpSocket::bind((LIVE, 0)).await.unwrap();
    let (decoy, download) = entry_listeners().await;
    let upload = TcpListener::bind((CAPTURED, 0)).await.unwrap();
    let (mut config, _, via) = split_config(
        ENTRY,
        upload.local_addr().unwrap().port(),
        DOWNLOAD,
        download.local_addr().unwrap().port(),
    );
    config.global.tcp_check_url = vec![format!("http://{DOWNLOAD}:{APP_PORT}/probe")];
    config.global.bootstrap_resolver = bootstrap.local_addr().unwrap().to_string();
    config.global.udp_warm_node_count = 0;
    let (mut state, control) = state_with_control(config).await;
    let dns = honk_config::parser::parse_dae_config(
        "dns {
            routing {
                request {
                    subtag(Original) -> original
                    subtag(Target) -> target
                    fallback: ordinary
                }
            }
        }",
    )
    .unwrap()
    .dns;
    let captured = install_alias_dns(
        &mut state,
        dns,
        "full:entry.chain.test entry-target.chain.test\n\
         full:download.chain.test download-target.chain.test\n",
        &[
            (ENTRY, "Original"),
            ("entry-target.chain.test", "Target"),
            ("download-target.chain.test", "Target"),
        ],
    );
    set_global(BootstrapResolver::parse(
        &poison.local_addr().unwrap().to_string(),
    ));
    let input = request(
        json!({"type":"node","node_id":via.to_string()}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let expected_queries = [
        (
            "ordinary".to_owned(),
            "download-target.chain.test".to_owned(),
            1,
        ),
        ("target".to_owned(), "entry-target.chain.test".to_owned(), 1),
        (
            "target".to_owned(),
            "download-target.chain.test".to_owned(),
            1,
        ),
    ];
    let successor = Arc::new(AliasDns::default());
    let run = async {
        let plan = capture(&state, serde_json::from_value(input).unwrap())
            .await
            .unwrap();
        publish_dns(&state, successor.clone(), &Default::default());

        let mut plan = prepare(plan).await.unwrap();
        assert_eq!(*captured.0.lock(), expected_queries);
        assert!(successor.0.lock().is_empty());
        assert_eq!(plan.attempts.len(), 1);
        assert_eq!(
            plan.attempts[0].addr,
            SocketAddr::new(LIVE.into(), APP_PORT)
        );

        let (_stop, cancel) = watch::channel(false);
        let (result, ()) = tokio::join!(
            execute(&state, &mut plan, Instant::now() + TIMEOUT, cancel),
            async {
                let (socket, _) = download.accept().await.unwrap();
                drop(download_hello(socket).await);
            }
        );
        result.unwrap();
        assert!(futures::poll!(std::pin::pin!(decoy.accept())).is_pending());
        drop(plan);
        state.dns.provider().unwrap().shutdown().await;
        control.dns_service().provider().unwrap().shutdown().await;
    };
    let observed = tokio::time::timeout(
        TIMEOUT * 2,
        observe_bootstrap(&poison, observe_bootstrap(&bootstrap, run)),
    )
    .await;
    set_global(None);
    let (((), bootstrap_questions), global_questions) =
        observed.expect("the captured alias download peer did not receive a TLS hello");
    assert_eq!(*captured.0.lock(), expected_queries);
    assert!(successor.0.lock().is_empty());
    assert_eq!(
        bootstrap_questions, 0,
        "captured bootstrap received queries"
    );
    assert_eq!(global_questions, 0, "global bootstrap received queries");
    for socket in [&bootstrap, &poison] {
        assert_eq!(
            socket.try_recv_from(&mut [0; 512]).unwrap_err().kind(),
            ErrorKind::WouldBlock,
        );
    }
}

#[tokio::test]
async fn check_url_alias_request_rejection_has_no_bootstrap_or_dial() {
    let name = format!("{TEST_PREFIX}::check_url_alias_request_rejection_has_no_bootstrap_or_dial");
    if crate::test_support::run_exact_in_child("HONK_PROBE_ALIAS_REJECT_CHILD", &name) {
        return;
    }
    let bootstrap = tokio::net::UdpSocket::bind((LIVE, 0)).await.unwrap();
    let upload = TcpListener::bind((LIVE, 0)).await.unwrap();
    let download = TcpListener::bind((LIVE, 0)).await.unwrap();
    let (mut config, _, via) = split_config(
        CHECK,
        upload.local_addr().unwrap().port(),
        "127.0.0.1",
        download.local_addr().unwrap().port(),
    );
    config.global.bootstrap_resolver = bootstrap.local_addr().unwrap().to_string();
    config.global.udp_warm_node_count = 0;
    let (mut state, control) = state_with_control(config).await;
    let mut dns = honk_config::dns::DnsConfig::default();
    dns.routing.request.fallback = honk_config::dns::DnsRequestAction::Reject;
    let pool = install_alias_dns(
        &mut state,
        dns,
        "full:check.chain.test entry.chain.test\n",
        &[],
    );
    let input = request(
        json!({"type":"node","node_id":via.to_string()}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let plan = capture(&state, serde_json::from_value(input).unwrap())
        .await
        .unwrap();
    let (_stop, cancel) = watch::channel(false);
    let probe = async {
        let mut plan = prepare(plan).await.unwrap();
        execute(&state, &mut plan, Instant::now() + TIMEOUT, cancel)
            .await
            .unwrap();
        plan
    };
    let (plan, questions) = tokio::time::timeout(TIMEOUT * 2, observe_bootstrap(&bootstrap, probe))
        .await
        .expect("the rejected check URL did not complete");
    assert_eq!(questions, 0);
    assert!(pool.0.lock().is_empty());
    assert_eq!(plan.result.results[0].error, Some("address_unavailable"));
    assert!(futures::poll!(std::pin::pin!(upload.accept())).is_pending());
    assert!(futures::poll!(std::pin::pin!(download.accept())).is_pending());
    drop(plan);
    state.dns.provider().unwrap().shutdown().await;
    control.dns_service().provider().unwrap().shutdown().await;
}

#[tokio::test]
async fn cold_probe_pins_split_xhttp_download_peer() {
    split_probe("cold", false, "cold_probe_pins_split_xhttp_download_peer").await;
}

#[tokio::test]
async fn warm_probe_pins_split_xhttp_download_peer() {
    split_probe("warm", false, "warm_probe_pins_split_xhttp_download_peer").await;
}

#[tokio::test]
async fn cancelled_probe_closes_private_split_xhttp_peers() {
    split_probe(
        "warm",
        true,
        "cancelled_probe_closes_private_split_xhttp_peers",
    )
    .await;
}

#[tokio::test]
async fn dotted_literal_split_download_reaches_the_pinned_peer_without_dns() {
    let name =
        format!("{TEST_PREFIX}::dotted_literal_split_download_reaches_the_pinned_peer_without_dns");
    if crate::test_support::run_exact_in_child("HONK_NATIVE_SPLIT_XHTTP_CHILD", &name) {
        return;
    }
    let upload = TcpListener::bind((LIVE, 0)).await.unwrap();
    let (expected, decoy) = entry_listeners().await;
    let expected_addr = expected.local_addr().unwrap();
    let (config, _, via_id) = split_config(
        "127.0.0.1",
        upload.local_addr().unwrap().port(),
        DOTTED_LITERAL,
        expected_addr.port(),
    );
    let state = state(config).await;
    publish_dns(
        &state,
        Arc::new(SplitDns(OLD_DOWNLOAD.into())),
        &honk_config::dns::DnsConfig::default(),
    );
    let bootstrap = Arc::new(SplitBootstrap::default());
    honk_outbound::bootstrap::set_node_host_resolver(Some(bootstrap.clone()));
    let input = request(
        json!({"type":"node","node_id":via_id.to_string()}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let plan = capture(&state, serde_json::from_value(input).unwrap())
        .await
        .unwrap();
    let mut plan = prepare(plan).await.unwrap();
    let (_stop, receiver) = watch::channel(false);
    let deadline = Instant::now() + TIMEOUT;
    let (result, ()) = tokio::time::timeout(TIMEOUT * 2, async {
        tokio::join!(execute(&state, &mut plan, deadline, receiver), async {
            let accepted = tokio::select! {
                accepted = expected.accept() => accepted,
                accepted = decoy.accept() => accepted,
            };
            let (socket, _) = accepted.unwrap();
            assert_eq!(socket.local_addr().unwrap(), expected_addr);
            drop(download_hello(socket).await);
        })
    })
    .await
    .expect("no ClientHello reached the split download peers");
    result.unwrap();
    assert_eq!(plan.result.results[0].error, Some("probe_failed"));
    assert!(bootstrap.0.lock().is_empty());
    drop(plan);
    state.dns.provider().unwrap().shutdown().await;
}
