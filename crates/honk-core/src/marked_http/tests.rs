use std::time::Duration;

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root and an isolated network namespace"]
fn marked_downloads_netns() {
    const CHILD: &str = "HONK_MARKED_HTTP_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "marked_http::tests::marked_downloads_netns",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .env_remove("http_proxy")
            .env_remove("https_proxy")
            .env_remove("all_proxy")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    honk_outbound::util::init_bypass_mark(0x200).unwrap();
    for args in [
        vec!["link", "set", "lo", "up"],
        vec!["addr", "add", "198.18.0.1/32", "dev", "lo"],
        vec![
            "-4",
            "route",
            "del",
            "local",
            "198.18.0.1/32",
            "dev",
            "lo",
            "table",
            "local",
        ],
        vec![
            "-4",
            "route",
            "add",
            "local",
            "198.18.0.1/32",
            "dev",
            "lo",
            "table",
            "200",
            "src",
            "127.0.0.1",
        ],
        vec![
            "-6",
            "route",
            "add",
            "local",
            "2001:db8::1/128",
            "dev",
            "lo",
            "table",
            "200",
        ],
        vec![
            "-4",
            "rule",
            "add",
            "fwmark",
            "0x200/0xffffffff",
            "lookup",
            "200",
        ],
        vec![
            "-6",
            "rule",
            "add",
            "fwmark",
            "0x200/0xffffffff",
            "lookup",
            "200",
        ],
    ] {
        let output = std::process::Command::new("ip")
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ip {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (bind, address) in [("0.0.0.0:0", "198.18.0.1"), ("[::]:0", "2001:db8::1")] {
            let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
            let target = std::net::SocketAddr::new(address.parse().unwrap(), listener.local_addr().unwrap().port());
            assert!(tokio::net::TcpStream::connect(target).await.is_err(), "unmarked dial must have no route");
            let server = tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut headers = Vec::new();
                    let mut byte = [0];
                    while !headers.ends_with(b"\r\n\r\n") {
                        stream.read_exact(&mut byte).await.unwrap();
                        headers.push(byte[0]);
                    }
                    let body = "socks5://127.0.0.1:1080#marked";
                    let response = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n", body.len());
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            });
            let sub = honk_config::subscription::Subscription { url: format!("http://{target}/subscription"), ..Default::default() };
            let nodes = crate::subscription::SubscriptionManager::new().unwrap().fetch(&sub).await.unwrap();
            assert_eq!(nodes[0].name, "marked");
            let url = reqwest::Url::parse(&format!("http://{target}/archive")).unwrap();
            let response = super::Client::new().unwrap().get(&url, &http::HeaderMap::new(), Duration::from_secs(1)).await.unwrap();
            assert_eq!(response.bytes().await.unwrap().as_ref(), b"socks5://127.0.0.1:1080#marked");
            server.await.unwrap();
        }
    });
}

async fn credential_request(headers: &http::HeaderMap) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
        String::from_utf8(request).unwrap()
    });
    let url = reqwest::Url::parse(&format!("http://us%40er:p%3Ass@127.0.0.1:{port}/sub")).unwrap();
    let response = super::Client::new()
        .unwrap()
        .get(&url, headers, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    let request = server.await.unwrap();
    assert!(request.starts_with("GET /sub HTTP/1.1\r\n"), "{request}");
    request
}

#[tokio::test]
async fn url_credentials_become_basic_authorization() {
    use base64::Engine;
    let request = credential_request(&http::HeaderMap::new()).await;
    let authorization = request
        .lines()
        .find_map(|line| line.strip_prefix("authorization: "))
        .expect("URL credentials must produce an Authorization header");
    assert_eq!(
        authorization,
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("us@er:p:ss")
        )
    );
}

#[tokio::test]
async fn explicit_authorization_overrides_url_credentials() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        "Bearer explicit".parse().unwrap(),
    );
    let request = credential_request(&headers).await;
    let authorization: Vec<_> = request
        .lines()
        .filter_map(|line| line.strip_prefix("authorization: "))
        .collect();
    assert_eq!(authorization, ["Bearer explicit"]);
}
