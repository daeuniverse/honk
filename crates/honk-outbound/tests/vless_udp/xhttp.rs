use super::*;
use base64::Engine as _;
use std::sync::Arc;

async fn targets() -> (SocketAddr, SocketAddr, EchoTasks) {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_address = tcp.local_addr().unwrap();
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = udp.local_addr().unwrap();
    let tcp_task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = tcp.accept() => {
                    let (stream, _) = accepted.unwrap();
                    connections.spawn(async move {
                        let (mut reader, mut writer) = stream.into_split();
                        tokio::io::copy(&mut reader, &mut writer).await
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    let udp_task = tokio::spawn(async move {
        let mut buffer = [0; 65535];
        loop {
            let (size, peer) = udp.recv_from(&mut buffer).await.unwrap();
            udp.send_to(&buffer[..size], peer).await.unwrap();
        }
    });
    (
        tcp_address,
        udp_address,
        EchoTasks(vec![tcp_task, udp_task]),
    )
}

async fn runtime_roundtrips(node: Node, tcp: SocketAddr, udp: SocketAddr) {
    let registry = ProxyRegistry::default_resolver().unwrap();
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
            .unwrap(),
    );
    for _ in 0..2 {
        bounded("XHTTP pooled TCP duplex", async {
            let stream = registry
                .dial_runtime(
                    Arc::clone(&generation),
                    node.id,
                    tcp,
                    None,
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream.stream);
            let sent = payload(2 * 1024 * 1024, 0x39);
            let mut received = vec![0; sent.len()];
            let upload = async {
                writer.write_all(&sent).await.unwrap();
                writer.flush().await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let download = async {
                reader.read_exact(&mut received).await.unwrap();
            };
            tokio::join!(upload, download);
            assert_eq!(received, sent);
        })
        .await;
    }
    bounded("XHTTP UDP replies", async {
        let transport = registry
            .dial_udp_transport_runtime(
                Arc::clone(&generation),
                node.id,
                udp,
                None,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        for size in [64, 1200, 4096] {
            let sent = payload(size, 0x71);
            transport.send_packet_confirmed(&sent).await.unwrap();
            let mut received = vec![0; size];
            let (size, peer) = transport.recv_packet(&mut received).await.unwrap();
            assert_eq!(size, sent.len());
            assert_eq!(peer, udp);
            assert_eq!(received, sent);
        }
    })
    .await;
    generation.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit HONK_XRAY_BIN official executable"]
async fn official_xray_xhttp_h2_tls_and_reality_tcp_native_xudp() {
    let executable = required_executable("HONK_XRAY_BIN");
    let temp = TempDir::new();
    let (tcp, udp, _targets) = targets().await;
    let (ports, reservations) = reserve_ports(3);
    let [tls_port, reality_port, mask_port]: [u16; 3] = ports.try_into().unwrap();
    let private = [0x51_u8; 32];
    let mut public = [0_u8; 32];
    unsafe { boring_sys::X25519_public_from_private(public.as_mut_ptr(), private.as_ptr()) };
    let private = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private);
    let public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(temp.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(temp.join("key.pem"), key.serialize_pem()).unwrap();
    let tls = serde_json::json!({"alpn":["h2"], "minVersion":"1.3", "maxVersion":"1.3", "certificates":[{"certificateFile":temp.join("cert.pem"),"keyFile":temp.join("key.pem")}]});
    let settings = serde_json::json!({"clients":[{"id":UUID}],"decryption":"none"});
    let config = serde_json::json!({
        "log":{"loglevel":"info"},
        "inbounds":[
            {"listen":"127.0.0.1","port":tls_port,"protocol":"vless","settings":settings,"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":tls,"xhttpSettings":{"path":"/xhttp/","mode":"auto"}}},
            {"listen":"127.0.0.1","port":mask_port,"protocol":"vless","settings":settings,"streamSettings":{"network":"raw","security":"tls","tlsSettings":tls}},
            {"listen":"127.0.0.1","port":reality_port,"protocol":"vless","settings":settings,"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"target":format!("127.0.0.1:{mask_port}"),"serverNames":["localhost"],"privateKey":private,"shortIds":["a1b2"]},"xhttpSettings":{"path":"/xhttp/","mode":"auto"}}}
        ],
        "outbounds":[{"protocol":"freedom","settings":{"finalRules":[
            {"action":"allow","network":"tcp","ip":["127.0.0.1/32"],"port":tcp.port()},
            {"action":"allow","network":"udp","ip":["127.0.0.1/32"],"port":udp.port()},
            {"action":"block","blockDelay":"0"}
        ]}}]
    });
    std::fs::write(temp.join("xray.json"), config.to_string()).unwrap();
    drop(reservations);
    let mut command = Command::new(executable);
    command
        .current_dir(&temp.0)
        .args(["run", "-c"])
        .arg(temp.join("xray.json"));
    let mut server = Server::spawn("Xray XHTTP", command, temp.join("xray.log"));
    wait_ready(&mut server, &[tls_port, reality_port, mask_port]).await;
    for (port, security) in [
        (tls_port, "security=tls&allowInsecure=true".to_string()),
        (
            reality_port,
            format!("security=reality&pbk={public}&sid=a1b2"),
        ),
    ] {
        for mode in ["auto", "stream-one", "stream-up", "packet-up"] {
            for encoding in ["none", "xudp"] {
                let node = canonical_node(
                    port,
                    "xhttp",
                    &format!(
                        "&{security}&sni=localhost&type=xhttp&path=%2Fxhttp%2F&mode={mode}&packetEncoding={encoding}"
                    ),
                );
                runtime_roundtrips(node, tcp, udp).await;
                server.assert_alive();
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_xhttp_h2_peer_preserves_uot_v2_datagrams() {
    const MAGIC: &[u8] = b"sp.v2.udp-over-tcp.arpa";
    for mode in ["stream-one", "stream-up", "packet-up"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let server = async {
            let (requests_tx, mut requests) = tokio::sync::mpsc::channel(16);
            let driver = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (tcp, _) = accepted.unwrap();
                            let requests = requests_tx.clone();
                            connections.spawn(async move {
                                let mut connection = h2::server::Builder::new()
                                    .initial_window_size(128)
                                    .handshake::<_, bytes::Bytes>(tcp).await.unwrap();
                                while let Some(request) = connection.accept().await {
                                    let Ok(request) = request else { break; };
                                    if requests.send(request).await.is_err() { break; }
                                }
                            });
                        }
                        _ = connections.join_next(), if !connections.is_empty() => {}
                    }
                }
            });
            let _driver = EchoTasks(vec![driver]);
            let mut download = None;
            let mut upload_bodies = Vec::new();
            let mut upload_responses = Vec::new();
            let mut received = Vec::new();
            let expected = 23 + MAGIC.len() + 13;
            let mut packet_inputs = std::collections::BTreeMap::new();
            let mut next_sequence = 0_u64;
            while received.len() < expected {
                let (request, mut respond) = requests.recv().await.unwrap();
                if request.method() == http::Method::GET {
                    download = Some(
                        respond
                            .send_response(
                                http::Response::builder().status(200).body(()).unwrap(),
                                false,
                            )
                            .unwrap(),
                    );
                    continue;
                }
                assert_eq!(request.method(), http::Method::POST);
                let sequence = if mode == "packet-up" {
                    Some(
                        request
                            .uri()
                            .path()
                            .rsplit('/')
                            .next()
                            .unwrap()
                            .parse::<u64>()
                            .unwrap(),
                    )
                } else {
                    None
                };
                let mut body = request.into_body();
                if mode == "packet-up" {
                    let mut packet = Vec::new();
                    while let Some(data) = body.data().await {
                        let data = data.unwrap();
                        packet.extend_from_slice(&data);
                        body.flow_control().release_capacity(data.len()).unwrap();
                    }
                    assert!(packet_inputs.insert(sequence.unwrap(), packet).is_none());
                    while let Some(packet) = packet_inputs.remove(&next_sequence) {
                        received.extend_from_slice(&packet);
                        next_sequence += 1;
                    }
                    respond
                        .send_response(
                            http::Response::builder().status(200).body(()).unwrap(),
                            true,
                        )
                        .unwrap();
                } else {
                    while received.len() < expected {
                        let data = body.data().await.unwrap().unwrap();
                        received.extend_from_slice(&data);
                        body.flow_control().release_capacity(data.len()).unwrap();
                    }
                    let response = respond
                        .send_response(
                            http::Response::builder().status(200).body(()).unwrap(),
                            false,
                        )
                        .unwrap();
                    if mode == "stream-one" {
                        download = Some(response);
                    } else {
                        upload_responses.push(response);
                    }
                    upload_bodies.push(body);
                }
            }
            assert_eq!(received.len(), expected);
            assert_eq!(received[0], 0);
            assert_eq!(
                &received[1..17],
                uuid::Uuid::parse_str(UUID).unwrap().as_bytes()
            );
            assert_eq!(&received[17..23], &[0, 1, 0, 0, 2, MAGIC.len() as u8]);
            assert_eq!(&received[23..23 + MAGIC.len()], MAGIC);
            assert_eq!(
                &received[23 + MAGIC.len()..],
                &[1, 1, 8, 8, 8, 8, 0, 53, 0, 3, b'd', b'n', b's']
            );
            let reply = b"\0\0\0\x05first\0\x06second";
            let mut download = download.unwrap();
            for chunk in reply.chunks(3) {
                download
                    .send_data(bytes::Bytes::copy_from_slice(chunk), false)
                    .unwrap();
            }
            download.send_data(bytes::Bytes::new(), true).unwrap();
            finished_rx.await.unwrap();
            drop(upload_bodies);
            drop(upload_responses);
        };
        let client = async {
            let node = canonical_node(
                address.port(),
                "xhttp-uot",
                &format!("&security=none&type=xhttp&mode={mode}&path=/uot/&packetEncoding=uot-v2"),
            );
            let registry = ProxyRegistry::default_resolver().unwrap();
            let transport = registry
                .dial_udp_transport(
                    &node,
                    "8.8.8.8:53".parse().unwrap(),
                    None,
                    Duration::from_secs(3),
                )
                .await
                .unwrap();
            transport.send_packet_confirmed(b"dns").await.unwrap();
            let error = transport.recv_packet(&mut [0; 1]).await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            let mut output = [0; 8];
            let (size, peer) = transport.recv_packet(&mut output).await.unwrap();
            assert_eq!(&output[..size], b"first");
            assert_eq!(peer, "8.8.8.8:53".parse::<SocketAddr>().unwrap());
            let (size, _) = transport.recv_packet(&mut output).await.unwrap();
            assert_eq!(&output[..size], b"second");
            drop(transport);
            finished_tx.send(()).unwrap();
        };
        bounded("independent H2 UoT framing", async {
            tokio::join!(server, client);
        })
        .await;
    }
}
