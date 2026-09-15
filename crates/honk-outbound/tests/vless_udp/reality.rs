use super::*;
use base64::Engine as _;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit HONK_XRAY_BIN official executable"]
async fn official_xray_reality_authenticates_first_connection_and_rejects_wrong_key() {
    let xray_bin = required_executable("HONK_XRAY_BIN");
    let temp = TempDir::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = listener.local_addr().unwrap();
    let _echo_task = EchoTasks(vec![tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = socket.into_split();
            tokio::spawn(async move { tokio::io::copy(&mut reader, &mut writer).await });
        }
    })]);
    let (ports, reservations) = reserve_ports(2);
    let reality_port = ports[0];
    let mask_port = ports[1];
    let private = [0x51_u8; 32];
    let mut public = [0_u8; 32];
    unsafe { boring_sys::X25519_public_from_private(public.as_mut_ptr(), private.as_ptr()) };
    let private = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private);
    let public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(temp.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(temp.join("key.pem"), key.serialize_pem()).unwrap();
    let config = format!(
        r#"{{
        "log": {{"loglevel": "info"}},
        "inbounds": [
            {{"tag": "local-mask", "listen": "127.0.0.1", "port": {mask_port},
             "protocol": "vless", "settings": {{"clients": [{{"id": "{UUID}"}}], "decryption": "none"}},
             "streamSettings": {{"network": "raw", "security": "tls", "tlsSettings": {{
                 "minVersion": "1.3", "maxVersion": "1.3",
                 "certificates": [{{"certificateFile": "{cert_path}", "keyFile": "{key_path}"}}]
             }}}}}},
            {{"tag": "local-reality", "listen": "127.0.0.1", "port": {reality_port},
             "protocol": "vless", "settings": {{"clients": [{{"id": "{UUID}"}}], "decryption": "none"}},
             "streamSettings": {{"network": "raw", "security": "reality", "realitySettings": {{
                 "show": true, "target": "127.0.0.1:{mask_port}", "serverNames": ["localhost"],
                 "privateKey": "{private}", "shortIds": ["a1b2"]
             }}}}}}
        ],
        "outbounds": [{{"protocol": "freedom", "settings": {{"finalRules": [
            {{"action":"allow", "network":"tcp", "ip":["127.0.0.1"], "port":{echo_port}}},
            {{"action":"block", "blockDelay":"0"}}
        ]}}}}]
    }}"#,
        echo_port = echo.port(),
        cert_path = temp.join("cert.pem").display(),
        key_path = temp.join("key.pem").display()
    );
    let config_path = temp.join("xray.json");
    std::fs::write(&config_path, config).unwrap();
    drop(reservations);
    let mut command = Command::new(&xray_bin);
    command
        .current_dir(&temp.0)
        .args(["run", "-c"])
        .arg(&config_path);
    let mut server = Server::spawn("Xray REALITY", command, temp.join("reality.log"));
    wait_ready(&mut server, &[reality_port, mask_port]).await;
    let node = canonical_node(
        reality_port,
        "local-reality",
        &format!("&security=reality&sni=localhost&pbk={public}&sid=a1b2"),
    );
    let registry = ProxyRegistry::default_resolver().unwrap();
    tcp_echo(&registry, "first REALITY connection", &node, echo).await;
    tcp_echo(&registry, "second REALITY connection", &node, echo).await;
    let wrong_public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x19; 32]);
    let wrong = canonical_node(
        reality_port,
        "wrong-reality-key",
        &format!("&security=reality&sni=localhost&pbk={wrong_public}&sid=a1b2"),
    );
    let error = bounded(
        "wrong REALITY key",
        registry.dial(&wrong, echo, None, Duration::from_secs(3)),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("REALITY"));
    server.assert_alive();
}
