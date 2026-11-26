use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

async fn spawn_socks5_relay(hits: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                if client.read_exact(&mut greeting).await.is_err() || greeting[0] != 0x05 {
                    return;
                }
                let mut methods = vec![0u8; usize::from(greeting[1])];
                if client.read_exact(&mut methods).await.is_err() {
                    return;
                }
                if client.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }
                let mut head = [0u8; 4];
                if client.read_exact(&mut head).await.is_err() || head[1] != 0x01 {
                    return;
                }
                let target = match head[3] {
                    0x01 => {
                        let mut raw = [0u8; 6];
                        if client.read_exact(&mut raw).await.is_err() {
                            return;
                        }
                        SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
                            u16::from_be_bytes([raw[4], raw[5]]),
                        )
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        if client.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut raw = vec![0u8; usize::from(len[0]) + 2];
                        if client.read_exact(&mut raw).await.is_err() {
                            return;
                        }
                        let host = String::from_utf8_lossy(&raw[..usize::from(len[0])]);
                        let port = u16::from_be_bytes([raw[raw.len() - 2], raw[raw.len() - 1]]);
                        let Ok(ip) = host.parse::<IpAddr>() else {
                            return;
                        };
                        SocketAddr::new(ip, port)
                    }
                    _ => return,
                };
                hits.fetch_add(1, Ordering::SeqCst);
                let Ok(mut upstream) = TcpStream::connect(target).await else {
                    let _ = client
                        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                };
                if client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    addr
}

async fn spawn_http_204_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                loop {
                    let mut buf = Vec::new();
                    let mut byte = [0u8; 1];
                    while !buf.ends_with(b"\r\n\r\n") {
                        match stream.read(&mut byte).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => buf.push(byte[0]),
                        }
                    }
                    if stream
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn sub_probes_imported_detour_chains_and_retains_forward_hops_under_limit() {
    let front_hits = Arc::new(AtomicUsize::new(0));
    let exit_hits = Arc::new(AtomicUsize::new(0));
    let front_addr = spawn_socks5_relay(Arc::clone(&front_hits)).await;
    let exit_addr = spawn_socks5_relay(Arc::clone(&exit_hits)).await;
    let http_addr = spawn_http_204_server().await;

    let closed_sock = TcpSocket::new_v4().unwrap();
    closed_sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let closed_addr = closed_sock.local_addr().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let sub_path = dir.path().join("sub.json");
    let body = format!(
        r#"{{
  "outbounds": [
    {{
      "type": "socks",
      "tag": "live-chain",
      "server": "127.0.0.1",
      "server_port": {},
      "detour": "front"
    }},
    {{
      "type": "trojan",
      "tag": "trojan-chain",
      "server": "127.0.0.1",
      "server_port": {},
      "password": "secret",
      "tls": {{ "enabled": true, "server_name": "example.com" }},
      "detour": "front"
    }},
    {{
      "type": "socks",
      "tag": "front",
      "server": "127.0.0.1",
      "server_port": {}
    }}
  ]
}}"#,
        exit_addr.port(),
        closed_addr.port(),
        front_addr.port(),
    );
    std::fs::write(&sub_path, body).unwrap();

    let sub_arg = sub_path.to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_honk-tool"))
            .args([
                "sub",
                sub_arg.to_str().unwrap(),
                "--limit",
                "4",
                "--target",
                &closed_addr.to_string(),
                "--v4-target",
                &closed_addr.to_string(),
                "--v6-target",
                &closed_addr.to_string(),
                "--url",
                &format!("http://{http_addr}/generate_204"),
                "--udp-check",
                &closed_addr.to_string(),
                "--timeout",
                "2",
            ])
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr={stderr}\nstdout={stdout}");
    assert!(
        !stdout.contains("FAIL(admission)"),
        "chain probes must not fail runtime admission:\n{stdout}"
    );

    let live_line = stdout
        .lines()
        .find(|line| line.starts_with("live-chain "))
        .unwrap_or_else(|| panic!("missing live-chain line:\n{stdout}"));
    assert!(live_line.contains(" chain "), "{live_line}");
    assert!(live_line.contains(" - "), "{live_line}");
    assert!(
        live_line.contains("ms") && !live_line.contains("urltest: FAIL("),
        "live-chain urltest must succeed over 2-hop SOCKS5 chain: {live_line}"
    );
    assert!(live_line.contains("dns: n/a"), "{live_line}");
    assert!(live_line.contains("quic: n/a"), "{live_line}");
    assert!(exit_hits.load(Ordering::SeqCst) >= 2, "{stdout}");

    let trojan_line = stdout
        .lines()
        .find(|line| line.starts_with("trojan-chain "))
        .unwrap_or_else(|| panic!("missing trojan-chain line:\n{stdout}"));
    assert!(trojan_line.contains("dns: FAIL(exchange)"), "{trojan_line}");
    assert!(
        trojan_line.contains("quic: FAIL(exchange)"),
        "{trojan_line}"
    );
}
