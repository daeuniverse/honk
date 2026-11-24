use super::*;

/// Auto UDP through a chain sends VLESS native UDP even on a port where a
/// direct dial would pick XUDP, so the official server must accept native UDP
/// to any port. Xray's own SOCKS5 inbound is the chain's front.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an explicit HONK_XRAY_BIN official executable"]
async fn official_xray_carries_auto_udp_through_a_chain() {
    let xray_bin = required_executable("HONK_XRAY_BIN");
    let temp = TempDir::new();
    let echo = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP echo");
    let echo_addr = echo.local_addr().expect("UDP echo address");
    let _echo = EchoTasks(vec![tokio::spawn(async move {
        let mut buffer = vec![0; 65535];
        while let Ok((size, peer)) = echo.recv_from(&mut buffer).await {
            let _ = echo.send_to(&buffer[..size], peer).await;
        }
    })]);

    let (ports, reservations) = reserve_ports(2);
    let [socks_port, vless_port]: [u16; 2] = ports.try_into().expect("two reserved ports");
    let xray_config = temp.join("xray.json");
    std::fs::write(
        &xray_config,
        format!(
            r#"{{
  "log": {{ "loglevel": "info" }},
  "inbounds": [
    {{
      "tag": "front",
      "listen": "127.0.0.1",
      "port": {socks_port},
      "protocol": "socks",
      "settings": {{ "auth": "noauth", "udp": false }}
    }},
    {{
      "tag": "land",
      "listen": "127.0.0.1",
      "port": {vless_port},
      "protocol": "vless",
      "settings": {{ "clients": [{{ "id": "{UUID}" }}], "decryption": "none" }},
      "streamSettings": {{ "network": "tcp", "security": "none" }}
    }}
  ],
  "outbounds": [{{ "tag": "direct", "protocol": "freedom", "settings": {{ "finalRules": [
    {{ "action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": {vless_port} }},
    {{ "action": "allow", "network": "udp", "ip": ["127.0.0.1"], "port": {echo_port} }},
    {{ "action": "block", "blockDelay": "0" }}
  ] }} }}]
}}"#,
            echo_port = echo_addr.port(),
        ),
    )
    .expect("write Xray config");
    drop(reservations);

    let mut xray_command = Command::new(&xray_bin);
    xray_command
        .current_dir(&temp.0)
        .args(["run", "-c"])
        .arg(&xray_config);
    let mut xray = Server::spawn("Xray", xray_command, temp.join("xray.log"));
    wait_ready(&mut xray, &[socks_port, vless_port]).await;

    let front = Node::from_share_link(&format!("socks5://127.0.0.1:{socks_port}#front"))
        .expect("parse SOCKS5 front");
    let land = canonical_node(vless_port, "land", "&security=none");
    assert_eq!(
        land.vless().expect("VLESS config").udp_encoding,
        VlessUdpEncoding::Auto
    );
    let via = Node::chain_from_nodes("via", &[&front, &land]).expect("bind UDP chain");
    let generation = std::sync::Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[via.clone(), front, land])
            .expect("build chain generation"),
    );
    let registry = ProxyRegistry::default_resolver().expect("build public proxy registry");
    bounded("xray-chain-auto-udp", async {
        let transport = registry
            .dial_udp_transport_runtime(
                std::sync::Arc::clone(&generation),
                via.id,
                echo_addr,
                None,
                Duration::from_secs(3),
            )
            .await
            .unwrap_or_else(|error| panic!("dial through the chain: {error:#}"));
        for salt in [1, 2] {
            let sent = payload(512, salt);
            transport
                .send_packet_confirmed(&sent)
                .await
                .unwrap_or_else(|error| panic!("send: {error}"));
            let mut echoed = vec![0; sent.len()];
            let (received, peer) = transport
                .recv_packet(&mut echoed)
                .await
                .unwrap_or_else(|error| panic!("receive: {error}"));
            assert_eq!(echoed[..received], sent[..]);
            assert_eq!(peer, echo_addr);
        }
    })
    .await;
    generation.shutdown().await;
    xray.assert_alive();
}
