use super::*;

#[tokio::test]
#[ignore = "requires the official sing-box and Xray executables"]
async fn official_sing_box_and_xray_mux_interop() {
    async fn unused_port() -> u16 {
        tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn exercise(
        registry: &super::super::ProxyRegistry,
        mut node: Node,
        tcp_target: SocketAddr,
        udp_target: SocketAddr,
    ) {
        eprintln!("testing {}", node.name);
        node.id = node.derive_id();
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        let timeout = std::time::Duration::from_secs(5);
        let mut tcp = registry
            .dial_runtime(Arc::clone(&generation), node.id, tcp_target, None, timeout)
            .await
            .unwrap();
        tcp.stream.write_all(node.name.as_bytes()).await.unwrap();
        let mut echoed = vec![0; node.name.len()];
        tcp.stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, node.name.as_bytes());

        let udp = registry
            .dial_udp_transport_runtime(Arc::clone(&generation), node.id, udp_target, None, timeout)
            .await
            .unwrap();
        udp.send_packet_confirmed(node.name.as_bytes())
            .await
            .unwrap();
        let mut echoed = [0; 64];
        let (size, peer) = udp.recv_packet(&mut echoed).await.unwrap();
        assert_eq!(peer, udp_target);
        assert_eq!(&echoed[..size], node.name.as_bytes());
        drop(udp);
        drop(tcp);
        generation.shutdown().await;
    }

    let tcp_echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_target = tcp_echo.local_addr().unwrap();
    let tcp_echo_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = tcp_echo.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                loop {
                    let size = stream.read(&mut buffer).await.unwrap();
                    if size == 0 {
                        break;
                    }
                    stream.write_all(&buffer[..size]).await.unwrap();
                }
            });
        }
    });
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_target = udp_echo.local_addr().unwrap();
    let udp_echo_task = tokio::spawn(async move {
        let mut buffer = [0; 65535];
        loop {
            let (size, peer) = udp_echo.recv_from(&mut buffer).await.unwrap();
            udp_echo.send_to(&buffer[..size], peer).await.unwrap();
        }
    });

    let plain_port = unused_port().await;
    let tls_port = unused_port().await;
    let reality_port = unused_port().await;
    let xray_port = unused_port().await;
    let xray_vision_port = unused_port().await;
    let directory = std::env::temp_dir().join(format!(
        "honk-vless-sing-box-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_path = directory.join("cert.pem");
    let key_path = directory.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let config_path = directory.join("config.json");
    std::fs::write(
            &config_path,
            format!(
                r#"{{
  "log": {{ "level": "warn" }},
  "inbounds": [
    {{ "type": "vless", "tag": "plain", "listen": "127.0.0.1", "listen_port": {plain_port}, "users": [{{ "uuid": "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3" }}], "multiplex": {{ "enabled": true }} }},
    {{ "type": "vless", "tag": "tls", "listen": "127.0.0.1", "listen_port": {tls_port}, "users": [{{ "uuid": "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3" }}], "multiplex": {{ "enabled": true }}, "tls": {{ "enabled": true, "server_name": "localhost", "certificate_path": "{}", "key_path": "{}" }} }},
    {{ "type": "vless", "tag": "reality", "listen": "127.0.0.1", "listen_port": {reality_port}, "users": [{{ "uuid": "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3" }}], "multiplex": {{ "enabled": true }}, "tls": {{ "enabled": true, "server_name": "www.cloudflare.com", "reality": {{ "enabled": true, "handshake": {{ "server": "www.cloudflare.com", "server_port": 443 }}, "private_key": "GCrdIerhJnsv8UEGgVcP6Gpf_d13pziIcua09rRDqEA", "short_id": ["0123456789abcdef"] }} }} }}
  ],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#,
                cert_path.display(),
                key_path.display()
            ),
        )
        .unwrap();
    let xray_config_path = directory.join("xray.json");
    std::fs::write(
            &xray_config_path,
            format!(
                r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "tag": "vless",
    "listen": "127.0.0.1",
    "port": {xray_port},
    "protocol": "vless",
    "settings": {{ "clients": [{{ "id": "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3" }}], "decryption": "none" }},
    "streamSettings": {{ "network": "tcp", "security": "none" }}
  }}, {{
    "tag": "vless-vision",
    "listen": "127.0.0.1",
    "port": {xray_vision_port},
    "protocol": "vless",
    "settings": {{ "clients": [{{ "id": "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3", "flow": "xtls-rprx-vision" }}], "decryption": "none" }},
    "streamSettings": {{ "network": "tcp", "security": "tls", "tlsSettings": {{ "certificates": [{{ "certificateFile": "{}", "keyFile": "{}" }}] }} }}
  }}],
  "outbounds": [{{ "tag": "direct", "protocol": "freedom", "settings": {{ "finalRules": [
    {{ "action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": {} }},
    {{ "action": "allow", "network": "udp", "ip": ["127.0.0.1"], "port": {} }},
    {{ "action": "block", "blockDelay": "0" }}
  ] }} }}]
}}"#,
                cert_path.display(),
                key_path.display(),
                tcp_target.port(),
                udp_target.port()
            ),
        )
        .unwrap();
    let mut sing_box = tokio::process::Command::new("sing-box")
        .args(["run", "--disable-color", "-c"])
        .arg(&config_path)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut ready = false;
    for _ in 0..100 {
        assert!(sing_box.try_wait().unwrap().is_none(), "sing-box exited");
        if tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, plain_port))
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(ready, "sing-box did not bind its VLESS listeners");

    let registry = super::super::ProxyRegistry::default_resolver().unwrap();
    let mut base = vless_node("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3");
    base.host = "127.0.0.1".into();
    let limit = std::num::NonZeroU16::new(8).unwrap();
    for (name, udp_encoding, multiplex) in [
        (
            "uot-v2",
            honk_config::node::VlessUdpEncoding::UotV2,
            honk_config::node::VlessMultiplex::Off,
        ),
        (
            "xudp",
            honk_config::node::VlessUdpEncoding::Xudp,
            honk_config::node::VlessMultiplex::Off,
        ),
        (
            "h2mux",
            honk_config::node::VlessUdpEncoding::Auto,
            honk_config::node::VlessMultiplex::H2 { padding: false },
        ),
        (
            "h2mux-padded",
            honk_config::node::VlessUdpEncoding::Auto,
            honk_config::node::VlessMultiplex::H2 { padding: true },
        ),
        (
            "mux-cool",
            honk_config::node::VlessUdpEncoding::Auto,
            honk_config::node::VlessMultiplex::Xray {
                tcp: Some(limit),
                udp: honk_config::node::VlessUdpMux::SharedTcp,
                udp443: honk_config::node::Udp443Policy::Reject,
            },
        ),
        (
            "mux-cool-separate",
            honk_config::node::VlessUdpEncoding::Auto,
            honk_config::node::VlessMultiplex::Xray {
                tcp: Some(limit),
                udp: honk_config::node::VlessUdpMux::Separate(limit),
                udp443: honk_config::node::Udp443Policy::Reject,
            },
        ),
    ] {
        let mut node = base.clone();
        node.name = name.into();
        node.address = format!("127.0.0.1:{plain_port}");
        node.port = plain_port;
        let vless = node.vless_mut().unwrap();
        vless.udp_encoding = udp_encoding;
        vless.multiplex = multiplex;
        exercise(&registry, node, tcp_target, udp_target).await;
    }

    let mut node = base.clone();
    node.name = "h2mux-tls".into();
    node.address = format!("127.0.0.1:{tls_port}");
    node.port = tls_port;
    node.vless_mut().unwrap().multiplex = honk_config::node::VlessMultiplex::H2 { padding: false };
    let tls = node.tls_mut().unwrap();
    tls.enabled = true;
    tls.skip_cert_verify = true;
    tls.sni = Some("localhost".into());
    exercise(&registry, node, tcp_target, udp_target).await;

    let mut node = base.clone();
    node.name = "h2mux-reality".into();
    node.address = format!("127.0.0.1:{reality_port}");
    node.port = reality_port;
    node.vless_mut().unwrap().multiplex = honk_config::node::VlessMultiplex::H2 { padding: true };
    let tls = node.tls_mut().unwrap();
    tls.enabled = true;
    tls.sni = Some("www.cloudflare.com".into());
    tls.reality_public_key = Some("pYbbKZZ-9WsXODEENCcbisSN6ol6sx5GoVisiyN1oyo".into());
    tls.reality_short_id = Some("0123456789abcdef".into());
    tls.reality_spider_x = Some("/".into());
    exercise(&registry, node, tcp_target, udp_target).await;

    let xray_bin = std::env::var_os("HONK_XRAY_BIN").unwrap_or_else(|| "xray".into());
    let mut xray = tokio::process::Command::new(xray_bin)
        .args(["run", "-c"])
        .arg(&xray_config_path)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut ready = false;
    for _ in 0..100 {
        assert!(xray.try_wait().unwrap().is_none(), "Xray exited");
        if tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, xray_port))
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(ready, "Xray did not bind its VLESS listener");
    for (name, udp_encoding, multiplex) in [
        (
            "xray-xudp",
            honk_config::node::VlessUdpEncoding::Xudp,
            honk_config::node::VlessMultiplex::Off,
        ),
        (
            "xray-mux-cool",
            honk_config::node::VlessUdpEncoding::Auto,
            honk_config::node::VlessMultiplex::Xray {
                tcp: Some(limit),
                udp: honk_config::node::VlessUdpMux::SharedTcp,
                udp443: honk_config::node::Udp443Policy::Reject,
            },
        ),
    ] {
        let mut node = base.clone();
        node.name = name.into();
        node.address = format!("127.0.0.1:{xray_port}");
        node.port = xray_port;
        let vless = node.vless_mut().unwrap();
        vless.udp_encoding = udp_encoding;
        vless.multiplex = multiplex;
        exercise(&registry, node, tcp_target, udp_target).await;
    }

    let mut node = base.clone();
    node.name = "xray-xudp-vision".into();
    node.address = format!("127.0.0.1:{xray_vision_port}");
    node.port = xray_vision_port;
    let vless = node.vless_mut().unwrap();
    vless.udp_encoding = honk_config::node::VlessUdpEncoding::Xudp;
    vless.flow = Some("xtls-rprx-vision".into());
    let tls = node.tls_mut().unwrap();
    tls.enabled = true;
    tls.skip_cert_verify = true;
    tls.sni = Some("localhost".into());
    exercise(&registry, node, tcp_target, udp_target).await;

    xray.start_kill().unwrap();
    xray.wait().await.unwrap();

    sing_box.start_kill().unwrap();
    sing_box.wait().await.unwrap();
    tcp_echo_task.abort();
    udp_echo_task.abort();
    std::fs::remove_dir_all(directory).unwrap();
}

/// Real inner TLS 1.3 through official Vision servers: uplink padding must
/// decode, the uplink must reach Direct, and bulk bytes must survive the
/// switches unchanged. The downlink switch is the server's choice.
#[tokio::test]
#[ignore = "requires the official sing-box and Xray executables"]
async fn official_vision_peers_switch_inner_tls_to_direct() {
    use boring::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion};

    const UUID: &str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
    let directory = std::env::temp_dir().join(format!(
        "honk-vision-direct-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_path = directory.join("cert.pem");
    let key_path = directory.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_certificate_chain_file(&cert_path).unwrap();
    acceptor
        .set_private_key_file(&key_path, boring::ssl::SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let acceptor = Arc::new(acceptor.build());
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = target_listener.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        loop {
            let (tcp, _) = target_listener.accept().await.unwrap();
            let acceptor = Arc::clone(&acceptor);
            tokio::spawn(async move {
                let tls = tokio_boring::accept(&acceptor, tcp).await.unwrap();
                let (mut reader, mut writer) = tokio::io::split(tls);
                tokio::io::copy(&mut reader, &mut writer).await.unwrap();
                writer.shutdown().await.unwrap();
            });
        }
    });

    let port = |listener: std::net::TcpListener| listener.local_addr().unwrap().port();
    let xray_port = port(std::net::TcpListener::bind("127.0.0.1:0").unwrap());
    let sing_box_port = port(std::net::TcpListener::bind("127.0.0.1:0").unwrap());
    let (cert_file, key_file) = (cert_path.display(), key_path.display());
    let target_port = target.port();
    let xray_config = directory.join("xray.json");
    std::fs::write(
        &xray_config,
        format!(
            r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1", "port": {xray_port}, "protocol": "vless",
    "settings": {{ "clients": [{{ "id": "{UUID}", "flow": "xtls-rprx-vision" }}], "decryption": "none" }},
    "streamSettings": {{ "network": "tcp", "security": "tls", "tlsSettings": {{ "certificates": [{{ "certificateFile": "{cert_file}", "keyFile": "{key_file}" }}] }} }}
  }}],
  "outbounds": [{{ "protocol": "freedom", "settings": {{ "finalRules": [
    {{ "action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": {target_port} }},
    {{ "action": "block", "blockDelay": "0" }}
  ] }} }}]
}}"#
        ),
    )
    .unwrap();
    let sing_box_config = directory.join("sing-box.json");
    std::fs::write(
        &sing_box_config,
        format!(
            r#"{{
  "log": {{ "level": "warn" }},
  "inbounds": [{{ "type": "vless", "listen": "127.0.0.1", "listen_port": {sing_box_port}, "users": [{{ "uuid": "{UUID}", "flow": "xtls-rprx-vision" }}], "tls": {{ "enabled": true, "server_name": "localhost", "certificate_path": "{cert_file}", "key_path": "{key_file}" }} }}],
  "outbounds": [{{ "type": "direct" }}]
}}"#
        ),
    )
    .unwrap();
    let xray_bin = std::env::var_os("HONK_XRAY_BIN").unwrap_or_else(|| "xray".into());
    let sing_box_bin = std::env::var_os("HONK_SING_BOX_BIN").unwrap_or_else(|| "sing-box".into());
    let mut peers = [
        tokio::process::Command::new(xray_bin)
            .args(["run", "-c"])
            .arg(&xray_config)
            .kill_on_drop(true)
            .spawn()
            .unwrap(),
        tokio::process::Command::new(sing_box_bin)
            .args(["run", "--disable-color", "-c"])
            .arg(&sing_box_config)
            .kill_on_drop(true)
            .spawn()
            .unwrap(),
    ];

    let payload: Vec<u8> = (0..4 * 1024 * 1024)
        .map(|index: usize| (index % 251) as u8)
        .collect();
    for (name, port) in [("xray", xray_port), ("sing-box", sing_box_port)] {
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let mut node = vless_node(UUID);
        node.name = name.into();
        node.address = format!("127.0.0.1:{port}");
        node.host = "127.0.0.1".into();
        node.port = port;
        node.vless_mut().unwrap().flow = Some("xtls-rprx-vision".into());
        let tls = node.tls_mut().unwrap();
        tls.enabled = true;
        tls.skip_cert_verify = true;
        tls.sni = Some("localhost".into());
        let timeout = std::time::Duration::from_secs(5);
        let vision = VLessHandler::new()
            .dial(&node, target, None, timeout)
            .await
            .unwrap()
            .into_vision_splice()
            .unwrap();
        let raw_ready = vision.ready_signal();
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        connector
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        let config = connector.build().configure().unwrap();
        let inner =
            tokio::time::timeout(timeout, tokio_boring::connect(config, "localhost", vision))
                .await
                .unwrap_or_else(|_| panic!("{name} inner TLS handshake timed out"))
                .unwrap();
        let (mut reader, mut writer) = tokio::io::split(inner);
        let expected = payload.clone();
        let (written, echoed) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::join!(
                async {
                    writer.write_all(&payload).await.unwrap();
                    writer.flush().await.unwrap();
                },
                async {
                    let mut echoed = vec![0; expected.len()];
                    reader.read_exact(&mut echoed).await.unwrap();
                    echoed
                }
            )
        })
        .await
        .unwrap_or_else(|_| panic!("{name} Vision relay timed out"));
        let () = written;
        assert!(echoed == expected, "{name} corrupted the inner TLS stream");
        let inner = reader.unsplit(writer);
        let (uplink, downlink) = inner.get_ref().direct_state();
        assert!(uplink, "{name} did not accept the uplink Direct switch");
        // The server decides the downlink switch from its own read sizes;
        // when it switches, nothing may remain buffered above the socket.
        eprintln!("{name}: downstream Direct = {downlink}");
        assert_eq!(
            raw_ready.load(std::sync::atomic::Ordering::Relaxed),
            downlink
        );
    }

    for peer in &mut peers {
        peer.start_kill().unwrap();
        peer.wait().await.unwrap();
    }
    target_task.abort();
    std::fs::remove_dir_all(directory).unwrap();
}
