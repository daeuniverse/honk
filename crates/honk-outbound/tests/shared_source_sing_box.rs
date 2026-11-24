//! Shared-source UDP against REAL sing-box inbounds (Shadowsocks legacy and
//! 2022, Trojan, SOCKS5, AnyTLS, VLESS UoT v2 and H2MUX, and Trojan through a
//! chain fronted by the SOCKS5 inbound), through the public
//! `ProxyRegistry::prepare_shared_source` entry. Needs only `sing-box` (`HONK_SING_BOX_BIN`
//! or PATH); every listener and peer is loopback.
//!
//! `cargo test -p honk-outbound --features rprx --test shared_source_sing_box -- --ignored --nocapture`

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use parking_lot::Mutex;
use std::time::Duration;

use honk_config::node::{
    AnyTlsConfig, Node, OutboundConfig, ShadowsocksConfig, Socks5Config, TlsOptions, TrojanConfig,
};
use honk_outbound::proxy::{MultiTargetTransport, ProxyRegistry};
use honk_outbound::runtime::OutboundRuntimeRegistry;
use tokio::net::UdpSocket;

const REPLY_TIMEOUT: Duration = Duration::from_secs(2);
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const DOMAIN: &str = "localhost";
#[cfg(feature = "rprx")]
const UUID: &str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

struct Echo {
    addr: SocketAddr,
    /// Source address of every datagram this peer received.
    seen: Arc<Mutex<Vec<SocketAddr>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Echo {
    /// Answers on both loopback families under one port so a server that
    /// resolves `localhost` to `::1` still reaches the same peer.
    async fn start() -> Self {
        let v4 = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let addr = v4.local_addr().unwrap();
        let mut sockets = vec![v4];
        if let Ok(v6) = UdpSocket::bind((Ipv6Addr::LOCALHOST, addr.port())).await {
            sockets.push(Arc::new(v6));
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        let tasks = sockets
            .into_iter()
            .map(|socket| {
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let mut buffer = vec![0; 65535];
                    while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
                        seen.lock().push(peer);
                        let _ = socket.send_to(&buffer[..size], peer).await;
                    }
                })
            })
            .collect();
        Self { addr, seen, tasks }
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

struct Proto {
    name: &'static str,
    inbound: String,
    node: Node,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn tls_options() -> TlsOptions {
    TlsOptions {
        enabled: true,
        sni: Some("localhost".into()),
        skip_cert_verify: true,
        ..Default::default()
    }
}

fn node(name: &str, port: u16, outbound: OutboundConfig) -> Node {
    let mut node = Node {
        name: name.into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        outbound,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn protos(cert: &str, key: &str) -> Vec<Proto> {
    let tls = format!(
        r#""tls": {{ "enabled": true, "server_name": "localhost", "certificate_path": "{cert}", "key_path": "{key}" }}"#
    );
    let listen = |kind: &str, port: u16, rest: &str| {
        format!(
            r#"{{ "type": "{kind}", "tag": "in-{port}", "listen": "127.0.0.1", "listen_port": {port}, {rest} }}"#
        )
    };
    let mut out = Vec::new();

    for (name, method, password) in [
        ("ss-aes-128-gcm", "aes-128-gcm", "interop-password"),
        (
            "ss2022-blake3-aes-128-gcm",
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw==",
        ),
    ] {
        let port = free_port();
        out.push(Proto {
            name,
            inbound: listen(
                "shadowsocks",
                port,
                &format!(r#""method": "{method}", "password": "{password}""#),
            ),
            node: node(
                name,
                port,
                OutboundConfig::Shadowsocks(ShadowsocksConfig {
                    password: Some(password.into()),
                    encryption: Some(method.into()),
                    ..Default::default()
                }),
            ),
        });
    }

    let port = free_port();
    out.push(Proto {
        name: "trojan",
        inbound: listen(
            "trojan",
            port,
            &format!(r#""users": [{{ "name": "u", "password": "pw" }}], {tls}"#),
        ),
        node: node(
            "trojan",
            port,
            OutboundConfig::Trojan(TrojanConfig {
                password: Some("pw".into()),
                tls: tls_options(),
                ..Default::default()
            }),
        ),
    });

    let port = free_port();
    out.push(Proto {
        name: "socks5",
        inbound: listen("socks", port, r#""users": []"#),
        node: node(
            "socks5",
            port,
            OutboundConfig::Socks5(Socks5Config::default()),
        ),
    });

    let port = free_port();
    out.push(Proto {
        name: "anytls",
        inbound: listen(
            "anytls",
            port,
            &format!(r#""users": [{{ "name": "u", "password": "pw" }}], {tls}"#),
        ),
        node: node(
            "anytls",
            port,
            OutboundConfig::AnyTls(AnyTlsConfig {
                password: Some("pw".into()),
                tls: tls_options(),
                ..Default::default()
            }),
        ),
    });

    #[cfg(feature = "rprx")]
    {
        use honk_config::node::{VlessMultiplex, VlessUdpEncoding};
        for (name, encoding, multiplex, mux) in [
            (
                "vless-uot-v2",
                VlessUdpEncoding::UotV2,
                VlessMultiplex::Off,
                false,
            ),
            (
                "vless-h2mux",
                VlessUdpEncoding::Auto,
                VlessMultiplex::H2 { padding: false },
                true,
            ),
            (
                "vless-h2mux-padded",
                VlessUdpEncoding::Auto,
                VlessMultiplex::H2 { padding: true },
                true,
            ),
        ] {
            let port = free_port();
            let mut vless = Node::from_share_link(&format!(
                "vless://{UUID}@127.0.0.1:{port}?udp=1&security=none#{name}"
            ))
            .unwrap();
            let config = vless.vless_mut().unwrap();
            config.udp_encoding = encoding;
            config.multiplex = multiplex;
            vless.id = vless.derive_id();
            let rest = if mux {
                format!(r#""users": [{{ "uuid": "{UUID}" }}], "multiplex": {{ "enabled": true }}"#)
            } else {
                format!(r#""users": [{{ "uuid": "{UUID}" }}]"#)
            };
            out.push(Proto {
                name,
                inbound: listen("vless", port, &rest),
                node: vless,
            });
        }
    }
    out
}

struct SingBox {
    child: std::process::Child,
    log: std::path::PathBuf,
}

impl Drop for SingBox {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "sing-box log:\n{}",
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn start_sing_box(directory: &std::path::Path, protos: &[Proto]) -> SingBox {
    let inbounds: Vec<&str> = protos.iter().map(|proto| proto.inbound.as_str()).collect();
    let config = directory.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{
  "log": {{ "level": "warn" }},
  "inbounds": [{}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
            inbounds.join(",\n")
        ),
    )
    .unwrap();
    let log = directory.join("sing-box.log");
    let output = std::fs::File::create(&log).unwrap();
    let bin = std::env::var_os("HONK_SING_BOX_BIN").unwrap_or_else(|| "sing-box".into());
    let mut server = SingBox {
        child: std::process::Command::new(bin)
            .args(["run", "--disable-color", "-c"])
            .arg(&config)
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .expect("start sing-box"),
        log,
    };
    for proto in protos {
        let mut ready = false;
        for _ in 0..200 {
            assert!(
                server.child.try_wait().unwrap().is_none(),
                "sing-box exited"
            );
            if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, proto.node.port))
                .await
                .is_ok()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ready, "sing-box did not bind {}", proto.name);
    }
    server
}

fn is_loopback_of(peer: SocketAddr, expected: SocketAddr) -> bool {
    peer.port() == expected.port() && peer.ip().to_canonical().is_loopback()
}

async fn open(
    runtime: &Arc<honk_outbound::runtime::NodeRuntime>,
    target: SocketAddr,
    domain: Option<&str>,
) -> Result<Arc<dyn MultiTargetTransport>, String> {
    ProxyRegistry::default_resolver()
        .unwrap()
        .prepare_shared_source(Arc::clone(runtime), target, domain, SETUP_TIMEOUT, false)
        .await
        .map_err(|error| format!("prepare: {error:#}"))?
        .commit()
        .await
        .map_err(|error| format!("commit: {error:#}"))
}

/// One datagram to `target` and its echo, or why it did not come back.
async fn exchange(
    transport: &dyn MultiTargetTransport,
    target: SocketAddr,
    domain: Option<&str>,
    payload: &[u8],
) -> Result<(), String> {
    transport
        .send_to(target, domain, payload, true, None)
        .await
        .map_err(|error| format!("send: {error}"))?;
    let mut buffer = vec![0; 65535];
    match tokio::time::timeout(REPLY_TIMEOUT, transport.recv_packet(&mut buffer)).await {
        Err(_) => Err("no-reply".into()),
        Ok(Err(error)) => Err(format!("recv: {error}")),
        Ok(Ok((size, peer))) if &buffer[..size] == payload && is_loopback_of(peer, target) => {
            Ok(())
        }
        Ok(Ok((size, peer))) => Err(format!("unexpected {size}B from {peer}")),
    }
}

fn cell(results: &[Result<(), String>]) -> String {
    let steps: Vec<String> = results
        .iter()
        .map(|result| result.as_ref().map_or_else(Clone::clone, |()| "ok".into()))
        .collect();
    steps.join(" | ")
}

struct Peers {
    a: Echo,
    b: Echo,
    c: UdpSocket,
}

/// (a) EIM across destinations through one transport, (b) EIF from a peer the
/// client never contacted.
async fn eim_eif(
    runtime: &Arc<honk_outbound::runtime::NodeRuntime>,
    peers: &Peers,
) -> (String, String) {
    let (a, b) = (peers.a.addr, peers.b.addr);
    peers.a.seen.lock().clear();
    peers.b.seen.lock().clear();
    let transport = match open(runtime, a, None).await {
        Ok(transport) => transport,
        Err(error) => return (error.clone(), error),
    };
    let mut results = Vec::new();
    for (index, target) in [a, b, a, b].into_iter().enumerate() {
        let payload = vec![index as u8; if index % 2 == 0 { 100 } else { 1200 }];
        results.push(exchange(transport.as_ref(), target, None, &payload).await);
    }
    let mut sources: Vec<SocketAddr> = peers.a.seen.lock().clone();
    sources.extend(peers.b.seen.lock().iter().copied());
    let same = sources.windows(2).all(|pair| pair[0] == pair[1]);
    let eim = format!(
        "{} | {}",
        cell(&results),
        if same && !sources.is_empty() {
            "one source".to_owned()
        } else {
            format!("DIFFERENT sources {sources:?}")
        }
    );
    let Some(&nat) = sources.first() else {
        return (eim, "no server source observed".into());
    };
    peers.c.send_to(b"unsolicited", nat).await.unwrap();
    let mut buffer = vec![0; 65535];
    let eif = match tokio::time::timeout(REPLY_TIMEOUT, transport.recv_packet(&mut buffer)).await {
        Err(_) => "BLOCKED (no packet)".to_owned(),
        Ok(Err(error)) => format!("recv: {error}"),
        Ok(Ok((size, peer))) if &buffer[..size] == b"unsolicited" => {
            if peer == peers.c.local_addr().unwrap() {
                "ok (exact C)".to_owned()
            } else {
                format!("WRONG peer {peer}")
            }
        }
        Ok(Ok((size, peer))) => format!("unexpected {size}B from {peer}"),
    };
    (eim, eif)
}

/// Run `steps` (target, per-packet domain) on a transport prepared with
/// `init`, then a numeric probe that shows whether the association survived.
async fn domain_case(
    runtime: &Arc<honk_outbound::runtime::NodeRuntime>,
    init: (SocketAddr, Option<&str>),
    steps: &[(SocketAddr, Option<&str>)],
    probe: SocketAddr,
) -> String {
    let transport = match open(runtime, init.0, init.1).await {
        Ok(transport) => transport,
        Err(error) => return error,
    };
    let mut results = Vec::new();
    for (index, (target, domain)) in steps.iter().enumerate() {
        results.push(
            exchange(
                transport.as_ref(),
                *target,
                *domain,
                &[0x40 + index as u8; 33],
            )
            .await,
        );
    }
    results.push(exchange(transport.as_ref(), probe, None, &[0x7f; 17]).await);
    let mut text = cell(&results[..steps.len()]);
    text.push_str(if results[steps.len()].is_ok() {
        " | alive"
    } else {
        " | DEAD"
    });
    text
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the official sing-box executable"]
async fn sing_box_shared_source_eim_eif_and_domain_matrix() {
    let directory = std::env::temp_dir().join(format!(
        "honk-shared-source-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = cert.self_signed(&key).unwrap();
    let (cert_path, key_path) = (directory.join("cert.pem"), directory.join("key.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

    let protos = protos(
        &cert_path.display().to_string(),
        &key_path.display().to_string(),
    );
    let _server = start_sing_box(&directory, &protos).await;
    let peers = Peers {
        a: Echo::start().await,
        b: Echo::start().await,
        c: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
    };
    let (a, b) = (peers.a.addr, peers.b.addr);

    let mut cases: Vec<(&str, Vec<Node>)> = protos
        .iter()
        .map(|proto| (proto.name, vec![proto.node.clone()]))
        .collect();
    // sing-box's SOCKS5 inbound fronts its own Trojan inbound.
    let hop = |name: &str| {
        protos
            .iter()
            .find(|proto| proto.name == name)
            .unwrap()
            .node
            .clone()
    };
    let (front, exit) = (hop("socks5"), hop("trojan"));
    let via = Node::chain_from_nodes("via", &[&front, &exit]).expect("bind UDP chain");
    cases.push(("trojan via socks5 chain", vec![via, front, exit]));

    let mut matrix = Vec::new();
    for (name, nodes) in &cases {
        let registry = Arc::new(OutboundRuntimeRegistry::build(nodes).unwrap());
        let runtime = registry.get(&nodes[0].id).unwrap();
        let (eim, eif) = eim_eif(&runtime, &peers).await;
        let rows = [
            ("EIM a,b,a,b numeric", eim),
            ("EIF unsolicited C", eif),
            (
                "init=domain, pkt=domain x2",
                domain_case(
                    &runtime,
                    (a, Some(DOMAIN)),
                    &[(a, Some(DOMAIN)), (a, Some(DOMAIN))],
                    a,
                )
                .await,
            ),
            (
                "init=domain, pkt=numeric a,b",
                domain_case(&runtime, (a, Some(DOMAIN)), &[(a, None), (b, None)], a).await,
            ),
            (
                "init=domain, pkt=other domain (same ip)",
                domain_case(
                    &runtime,
                    (a, Some(DOMAIN)),
                    &[
                        (a, Some(DOMAIN)),
                        (a, Some("LOCALHOST.")),
                        (a, Some(DOMAIN)),
                    ],
                    a,
                )
                .await,
            ),
            (
                "init=domain, pkt=domain,numeric,domain,numeric a",
                domain_case(
                    &runtime,
                    (a, Some(DOMAIN)),
                    &[(a, Some(DOMAIN)), (a, None), (a, Some(DOMAIN)), (a, None)],
                    a,
                )
                .await,
            ),
            (
                "init=domain, pkt=numeric a then domain a",
                domain_case(
                    &runtime,
                    (a, Some(DOMAIN)),
                    &[(a, None), (a, Some(DOMAIN))],
                    a,
                )
                .await,
            ),
            (
                "init=numeric, pkt=domain b",
                domain_case(&runtime, (a, None), &[(b, Some(DOMAIN))], a).await,
            ),
            (
                "init=numeric, pkt=numeric a then domain a",
                domain_case(&runtime, (a, None), &[(a, None), (a, Some(DOMAIN))], a).await,
            ),
        ];
        for (label, result) in rows {
            matrix.push((*name, label, result));
        }
        registry.shutdown().await;
    }

    eprintln!("\nsing-box shared-source matrix");
    for (name, label, result) in &matrix {
        eprintln!("{name:28} {label:42} {result}");
    }
    // Rows outside this list record sing-box behaviour that no core flow
    // produces: B after a domain-dialed association (the scope pins one
    // destination) and a numeric first packet before the dialed name.
    const REQUIRED: &[&str] = &[
        "EIM a,b,a,b numeric",
        "EIF unsolicited C",
        "init=domain, pkt=domain x2",
        "init=domain, pkt=other domain (same ip)",
        "init=domain, pkt=domain,numeric,domain,numeric a",
        "init=numeric, pkt=domain b",
        "init=numeric, pkt=numeric a then domain a",
    ];
    let failures: Vec<_> = matrix
        .iter()
        .filter(|(_, label, result)| {
            REQUIRED.contains(label)
                && !result
                    .split(" | ")
                    .all(|part| matches!(part, "ok" | "one source" | "alive" | "ok (exact C)"))
        })
        .collect();
    let _ = std::fs::remove_dir_all(&directory);
    assert!(failures.is_empty(), "failing cells: {failures:#?}");
}
