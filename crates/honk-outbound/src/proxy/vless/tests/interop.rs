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
  "outbounds": [{{ "tag": "direct", "protocol": "freedom" }}]
}}"#,
                cert_path.display(),
                key_path.display()
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
