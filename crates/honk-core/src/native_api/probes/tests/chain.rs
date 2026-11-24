use super::*;
use crate::dns::{DnsService, forwarder::parse_dns_question, runtime::DnsServiceProvider};
use honk_outbound::bootstrap::{NodeHostLookup, NodeHostResolver};
use sha2::{Digest, Sha256};
use std::{io::ErrorKind, net::Ipv4Addr};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpListener,
};
use tokio_rustls::{TlsAcceptor, rustls};

mod split_xhttp;

const ENTRY: &str = "entry.chain.test";
const EXIT: &str = "exit.chain.test";
const CHECK: &str = "check.chain.test";
const PASSWORD: &str = "probe-password";
const LIVE: Ipv4Addr = Ipv4Addr::LOCALHOST;
const CAPTURED: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const TIMEOUT: Duration = Duration::from_secs(3);

struct ProbeDns {
    entry: Ipv4Addr,
    destination: Ipv4Addr,
}

#[async_trait::async_trait]
impl DnsUpstreamPool for ProbeDns {
    async fn query(&self, _: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (name, qtype) = parse_dns_question(query).unwrap();
        let ip = match name.trim_end_matches('.') {
            ENTRY => self.entry,
            CHECK => self.destination,
            other => panic!("unexpected local resolution of {other}"),
        };
        let mut answer = query.to_vec();
        answer[2..4].copy_from_slice(&[0x81, 0x80]);
        if qtype == 1 {
            answer[6..8].copy_from_slice(&1u16.to_be_bytes());
            answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            answer.extend_from_slice(&ip.octets());
        } else {
            assert_eq!(qtype, 28);
        }
        Ok(answer)
    }
}

#[async_trait::async_trait]
impl RuntimeTransport for ProbeDns {
    async fn close(&self) {}
}

struct LiveBootstrap;

impl NodeHostResolver for LiveBootstrap {
    fn lookup(&self, host: &str) -> Option<NodeHostLookup> {
        assert_eq!(host, ENTRY);
        Some(Box::pin(std::future::ready(Ok(vec![LIVE.into()]))))
    }
}

async fn entry_listeners() -> (TcpListener, TcpListener) {
    for _ in 0..8 {
        let live = TcpListener::bind((LIVE, 0)).await.unwrap();
        match TcpListener::bind((CAPTURED, live.local_addr().unwrap().port())).await {
            Ok(captured) => return (live, captured),
            Err(error) if error.kind() == ErrorKind::AddrInUse => continue,
            Err(error) => panic!("bind captured entry: {error}"),
        }
    }
    panic!("could not bind both physical entry peers to the same port");
}

fn entry_certificate() -> (TlsAcceptor, String) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::fmt::Write as _;

    let certificate = rcgen::generate_simple_self_signed(vec![ENTRY.into()]).unwrap();
    let mut pin = String::with_capacity(64);
    for byte in Sha256::digest(certificate.cert.der().as_ref()) {
        write!(pin, "{byte:02x}").unwrap();
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.signing_key.serialize_der(),
    ));
    let tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate.cert.der().clone()], key)
    .unwrap();
    (TlsAcceptor::from(Arc::new(tls)), pin)
}

const WASTE: u8 = 0;
const SYN: u8 = 1;
const PSH: u8 = 2;
const FIN: u8 = 3;
const SETTINGS: u8 = 4;

async fn read_frame(reader: &mut (impl AsyncReadExt + Unpin)) -> Option<(u8, u32, Vec<u8>)> {
    let command = match reader.read_u8().await {
        Ok(command) => command,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
            ) =>
        {
            return None;
        }
        Err(error) => panic!("AnyTLS frame: {error}"),
    };
    let stream = reader.read_u32().await.unwrap();
    let length = reader.read_u16().await.unwrap();
    let mut payload = vec![0; usize::from(length)];
    reader.read_exact(&mut payload).await.unwrap();
    Some((command, stream, payload))
}

// Serve a single logical AnyTLS stream and keep the carrier open until the
// client closes it. Resolve only the exact remote hop in its address frame.
async fn relay_entry(listener: Arc<TcpListener>, tls: TlsAcceptor, exit: SocketAddr) {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = tls.accept(tcp).await.unwrap();
    assert_eq!(tls.get_ref().1.server_name(), Some(ENTRY));
    let mut authentication = [0; 32];
    tls.read_exact(&mut authentication).await.unwrap();
    assert_eq!(authentication, <[u8; 32]>::from(Sha256::digest(PASSWORD)));
    let padding = tls.read_u16().await.unwrap();
    tls.read_exact(&mut vec![0; usize::from(padding)])
        .await
        .unwrap();

    let sid = loop {
        match read_frame(&mut tls).await.unwrap() {
            (SYN, sid, data) if data.is_empty() => break sid,
            (WASTE | SETTINGS, 0, _) => {}
            command => panic!("unexpected AnyTLS open: {command:?}"),
        }
    };
    let mut address = vec![3, EXIT.len() as u8];
    address.extend_from_slice(EXIT.as_bytes());
    address.extend_from_slice(&exit.port().to_be_bytes());
    loop {
        match read_frame(&mut tls).await.unwrap() {
            (WASTE, 0, _) => {}
            (PSH, stream, payload) => {
                assert_eq!((stream, payload), (sid, address));
                break;
            }
            command => panic!("unexpected AnyTLS target: {command:?}"),
        }
    }

    let upstream = tokio::net::TcpStream::connect(exit).await.unwrap();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let (mut client_read, mut client_write) = tokio::io::split(tls);
    let upload = async {
        while let Some((command, stream, data)) = read_frame(&mut client_read).await {
            if command == WASTE {
                continue;
            }
            assert_eq!(stream, sid);
            match command {
                PSH => upstream_write.write_all(&data).await.unwrap(),
                FIN => upstream_write.shutdown().await.unwrap(),
                _ => panic!("unexpected active AnyTLS stream command {command}"),
            }
        }
        upstream_write.shutdown().await.unwrap();
    };
    let download = async {
        let mut data = [0; 1024];
        loop {
            let length = upstream_read.read(&mut data).await.unwrap();
            if length == 0 {
                break;
            }
            client_write.write_u8(PSH).await.unwrap();
            client_write.write_u32(sid).await.unwrap();
            client_write.write_u16(length as u16).await.unwrap();
            client_write.write_all(&data[..length]).await.unwrap();
            client_write.flush().await.unwrap();
        }
    };
    tokio::join!(upload, download);
}

#[derive(Clone, Copy)]
enum Completion {
    Success,
    HttpError,
    Cancelled,
    Obsolete,
}

#[tokio::test]
async fn captured_chain_probes_use_and_close_private_physical_entry_sessions() {
    if crate::test_support::run_exact_in_child(
        "HONK_NATIVE_CHAIN_PIN_CHILD",
        "native_api::probes::tests::chain::captured_chain_probes_use_and_close_private_physical_entry_sessions",
    ) {
        return;
    }

    let (live_listener, captured_listener) = entry_listeners().await;
    let live_addr = live_listener.local_addr().unwrap();
    let captured_listener = Arc::new(captured_listener);
    let (tls, pin) = entry_certificate();
    let exit = crate::test_support::socks5_relay().await;
    let replacement = crate::test_support::socks5_relay().await;
    let live_peer = tokio::spawn(relay_entry(
        Arc::new(live_listener),
        tls.clone(),
        replacement.addr,
    ));
    let echo_listener = TcpListener::bind((LIVE, 0)).await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_peer = tokio::spawn(async move {
        let (socket, _) = echo_listener.accept().await.unwrap();
        let (mut read, mut write) = socket.into_split();
        tokio::io::copy(&mut read, &mut write).await.unwrap();
    });
    let origin = TcpListener::bind((LIVE, 0)).await.unwrap();
    let origin_addr = origin.local_addr().unwrap();

    let mut front = Node::from_share_link(&format!(
        "anytls://{PASSWORD}@{ENTRY}:{}#front",
        live_addr.port()
    ))
    .unwrap();
    front.tls_mut().unwrap().pin_sha256 = Some(pin);
    front.id = front.derive_id();
    let land =
        Node::from_share_link(&format!("socks5://{EXIT}:{}#land", exit.addr.port())).unwrap();
    let land_id = land.id;
    let replacement_land =
        Node::from_share_link(&format!("socks5://{EXIT}:{}#land", replacement.addr.port()))
            .unwrap();
    let via = Node::chain_from_nodes("via", &[&front, &land]).unwrap();
    let (front_id, via_id) = (front.id, via.id);
    let mut config = Config::default();
    config.nodes.extend([front, land, via]);
    config.global.tcp_check_url = vec![format!("http://{CHECK}:{}/probe", origin_addr.port())];
    config.global.tcp_check_http_method = "GET".into();
    let (mut state, control) = state_with_control(config).await;
    let control_dns = control.dns_service().provider().unwrap();
    let old_control_dns = control_dns.current();
    let dns = honk_config::dns::DnsConfig::default();
    // Give the test resolver its own provider so updates to its answers do
    // not retire the live registry through the real control-plane DNS owner.
    let probe_dns = Arc::new(DnsServiceProvider::new(dns_runtime(
        0,
        Arc::new(ProbeDns {
            entry: CAPTURED,
            destination: LIVE,
        }),
        &dns,
    )));
    state.dns = DnsService::with_provider(Arc::clone(&probe_dns));
    honk_outbound::bootstrap::set_node_host_resolver(Some(Arc::new(LiveBootstrap)));
    let registry = state.runtime_registry.read().clone();
    let live_front = registry.get(&front_id).unwrap();
    let warm = state
        .proxy_registry
        .find(live_front.node.protocol())
        .unwrap()
        .warmable
        .as_ref()
        .unwrap();
    tokio::time::timeout(
        TIMEOUT,
        registry.scope_dials(live_front.scope_tasks(warm.warm(
            Arc::clone(&live_front),
            TIMEOUT,
            honk_outbound::proxy::WarmRequirement::Session,
        ))),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(live_front.warm_counts().sessions, 1);

    let mut plans = Vec::new();
    for (warmth, completion) in [
        ("cold", Completion::Success),
        ("warm", Completion::Success),
        ("cold", Completion::HttpError),
        ("cold", Completion::Cancelled),
        ("cold", Completion::Obsolete),
    ] {
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
        plans.push((warmth, completion, plan));
    }
    publish_dns(
        &state,
        Arc::new(ProbeDns {
            entry: LIVE,
            destination: CAPTURED,
        }),
        &dns,
    );

    for (warmth, completion, plan) in plans {
        let mut plan = prepare(plan).await.unwrap();
        let peer = tokio::spawn(relay_entry(
            Arc::clone(&captured_listener),
            tls.clone(),
            exit.addr,
        ));
        let (cancel, receiver) = watch::channel(false);
        let deadline = Instant::now() + TIMEOUT;
        let origin_exchange = async {
            let (socket, _) = origin.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            let methods: &[&str] = if warmth == "warm" {
                &["HEAD", "GET"]
            } else {
                &["GET"]
            };
            for method in methods {
                let mut headers = String::new();
                while !headers.ends_with("\r\n\r\n") {
                    assert_ne!(socket.read_line(&mut headers).await.unwrap(), 0);
                }
                assert!(headers.starts_with(&format!("{method} /probe HTTP/1.1\r\n")));
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains(&format!("\r\nhost: {CHECK}:{}\r\n", origin_addr.port()))
                );
                let response: &[u8] = match completion {
                    Completion::Cancelled => {
                        cancel.send_replace(true);
                        break;
                    }
                    Completion::Obsolete => {
                        let mut updated = state.config.read().await.as_ref().clone();
                        let land = updated.nodes.iter_mut().find(|node| node.id == land_id);
                        *land.unwrap() = replacement_land.clone();
                        assert!(
                            control
                                .reload_runtime_config(updated, Default::default())
                                .await
                        );
                        b"HTTP/1.1 204 No Content\r\n\r\n"
                    }
                    Completion::HttpError => {
                        b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n"
                    }
                    Completion::Success => b"HTTP/1.1 204 No Content\r\n\r\n",
                };
                socket.get_mut().write_all(response).await.unwrap();
            }
            assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
        };
        let (result, ()) = tokio::time::timeout(TIMEOUT * 2, async {
            tokio::join!(
                execute(&state, &mut plan, deadline, receiver),
                origin_exchange
            )
        })
        .await
        .expect("the probe must reach the pinned origin through the private entry and close it");
        result.unwrap();
        let (status, error) = match completion {
            Completion::Success | Completion::Obsolete => ("healthy", None),
            Completion::HttpError => ("unavailable", Some("probe_failed")),
            Completion::Cancelled => ("unknown", Some("cancelled")),
        };
        let row = &plan.result.results[0];
        assert_eq!((row.state, row.error), (status, error));
        assert_eq!(row.latency_ms.is_some(), error.is_none());
        assert_eq!(row.warmth, if error.is_none() { warmth } else { "unknown" });
        assert_eq!(
            row.health_updated,
            matches!(completion, Completion::Success | Completion::HttpError)
        );
        tokio::time::timeout(TIMEOUT, peer)
            .await
            .expect("probe entry carrier still open after completion")
            .unwrap();
        assert_eq!(live_front.warm_counts().sessions, 1);
    }

    assert!(state.alive_set.health_observations(via_id).is_empty());
    tokio::time::timeout(TIMEOUT, old_control_dns.wait_closed())
        .await
        .unwrap();
    let current = state.runtime_registry.read().clone();
    let current_id = state
        .config
        .read()
        .await
        .nodes
        .iter()
        .find(|node| node.name == "via")
        .unwrap()
        .id;
    assert_ne!(via_id, current_id);
    assert!(registry.is_shutdown());
    assert!(current.get(&via_id).is_none());
    assert!(Arc::ptr_eq(&live_front, &current.get(&front_id).unwrap()));
    assert!(state.alive_set.health_observations(current_id).is_empty());
    let mut live = tokio::time::timeout(
        TIMEOUT,
        state
            .proxy_registry
            .dial_runtime(current, current_id, echo_addr, None, TIMEOUT),
    )
    .await
    .unwrap()
    .expect("the idle production entry carrier must still accept business traffic");
    tokio::time::timeout(TIMEOUT, async {
        live.stream.write_u8(b'A').await.unwrap();
        assert_eq!(live.stream.read_u8().await.unwrap(), b'A');
    })
    .await
    .unwrap();
    assert_eq!(
        *exit.requests.lock(),
        [
            origin_addr,
            origin_addr,
            origin_addr,
            origin_addr,
            origin_addr,
        ]
    );
    assert_eq!(*replacement.requests.lock(), [echo_addr]);
    drop(live);
    control_dns.shutdown().await;
    tokio::time::timeout(TIMEOUT, live_peer)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(TIMEOUT, echo_peer)
        .await
        .unwrap()
        .unwrap();
    probe_dns.shutdown().await;
}
