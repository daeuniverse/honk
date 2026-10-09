use super::*;

#[tokio::test]
async fn all_modes_are_writable_before_headers_and_half_close_preserves_raw_download() {
    for mode in [
        XhttpMode::Auto,
        XhttpMode::PacketUp,
        XhttpMode::StreamUp,
        XhttpMode::StreamOne,
    ] {
        tokio::time::timeout(DEADLINE, async {
            let mut peer = Peer::new(32).await;
            let owner = peer.runtime(mode, 97);
            let runtime = owner.runtime();
            let mut stream = open(&runtime).await;
            let mut download = peer.next().await;
            let path = if mode == XhttpMode::StreamOne {
                assert_headers(&download.request);
                assert_eq!(download.request.method(), http::Method::POST);
                assert_eq!(download.request.uri().path(), WIRE_PREFIX);
                assert_eq!(
                    download.request.headers()["content-type"],
                    "application/grpc"
                );
                WIRE_PREFIX.to_owned()
            } else {
                assert_eq!(download.request.method(), http::Method::GET);
                session_path(&download.request)
            };
            let payload: Vec<u8> = (0..513).map(|i| (i % 251) as u8).collect();
            let expected = payload.clone();
            let server = async {
                if mode == XhttpMode::StreamOne {
                    let body = download.request.body_mut();
                    assert_eq!(receive(body, expected.len()).await, expected);
                    eof(body).await;
                } else if mode == XhttpMode::StreamUp {
                    let mut upload = peer.next().await;
                    assert_eq!(upload.request.method(), http::Method::POST);
                    assert_eq!(session_path(&upload.request), path);
                    assert_eq!(upload.request.headers()["content-type"], "application/grpc");
                    assert_eq!(
                        receive(upload.request.body_mut(), expected.len()).await,
                        expected
                    );
                    eof(upload.request.body_mut()).await;
                    response(&mut upload.respond, 200, true);
                } else {
                    let mut received = Vec::new();
                    let mut seq = 0;
                    // Packet-up has no session EOF request: the application length closes this fixture.
                    while received.len() < expected.len() {
                        let mut upload = peer.next().await;
                        assert_headers(&upload.request);
                        assert_eq!(upload.request.method(), http::Method::POST);
                        assert_eq!(upload.request.uri().path(), format!("{path}/{seq}"));
                        assert!(!upload.request.headers().contains_key("content-type"));
                        let length: usize = upload.request.headers()["content-length"]
                            .to_str()
                            .unwrap()
                            .parse()
                            .unwrap();
                        assert!((1..=97).contains(&length));
                        received.extend(receive(upload.request.body_mut(), length).await);
                        eof(upload.request.body_mut()).await;
                        response(&mut upload.respond, 200, true);
                        seq += 1;
                    }
                    assert_eq!(received, expected);
                }
                let mut reply = response(&mut download.respond, 200, false);
                send(&mut reply, Bytes::from_static(b"\0raw-reply\xff"), true).await;
            };
            let client = async {
                stream.write_all(&payload).await.unwrap();
                stream.flush().await.unwrap();
                stream.shutdown().await.unwrap();
                assert_eq!(
                    stream.write(b"after-close").await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"\0raw-reply\xff");
            };
            tokio::join!(server, client);
        })
        .await
        .unwrap_or_else(|_| panic!("raw/half-close exchange stalled for {mode:?}"));
    }
}

#[tokio::test]
async fn stream_up_drains_large_upload_response_padding_without_exposing_it() {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = Peer::new(64).await;
        let owner = peer.runtime(XhttpMode::StreamUp, 128);
        let runtime = owner.runtime();
        let mut stream = open(&runtime).await;
        let mut download = peer.next().await;
        let mut upload = peer.next().await;
        assert_eq!(download.request.method(), http::Method::GET);
        assert_eq!(upload.request.method(), http::Method::POST);
        let mut padding = response(&mut upload.respond, 200, false);
        let server = async {
            let drain_upload = async {
                assert_eq!(
                    receive(upload.request.body_mut(), 1024).await,
                    vec![0x91; 1024]
                );
                eof(upload.request.body_mut()).await;
            };
            let send_padding = send(
                &mut padding,
                Bytes::from(vec![0xee; RECEIVE_WINDOW as usize * 2 + 1]),
                true,
            );
            tokio::join!(drain_upload, send_padding);
            let mut reply = response(&mut download.respond, 200, false);
            send(&mut reply, Bytes::from_static(b"download-only"), true).await;
        };
        let client = async {
            stream.write_all(&[0x91; 1024]).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"download-only");
        };
        tokio::join!(server, client);
    })
    .await
    .expect("upload response padding was not concurrently drained");
}

#[test]
fn referer_replaces_configured_padding_query_with_sampled_padding() {
    let mut node = node(XhttpMode::StreamUp, 32);
    let options = node.transport_mut().unwrap().xhttp.as_mut().unwrap();
    options.path = "/p/?x_padding=old&token=retained".into();
    options.x_padding_bytes = XhttpRange { min: 5, max: 9 };
    let template = super::super::request::RequestTemplate::new(&node).unwrap();
    for _ in 0..16 {
        let request = template.request("session", None, false, None).unwrap();
        assert_eq!(request.uri().query(), Some("x_padding=old&token=retained"));
        let referer = request.headers()["referer"].to_str().unwrap();
        let padding = referer
            .strip_prefix("http://peer.example/p/?x_padding=")
            .expect("Referer must replace the configured query");
        assert!((5..=9).contains(&padding.len()));
        assert!(padding.bytes().all(|byte| byte == b'X'));
    }
}

#[test]
fn request_escapes_literal_path_without_reencoding_the_query() {
    let mut node = node(XhttpMode::StreamUp, 32);
    for (path, expected) in [
        ("/xhttp/Az09-_.~/", "/xhttp/Az09-_.~/"),
        ("/a%2Fb/", "/a%252Fb/"),
        ("/a b/", "/a%20b/"),
        ("/雪/é/", "/%E9%9B%AA/%C3%A9/"),
        ("/!'()*/", "/%21%27%28%29%2A/"),
        ("/$&+,:;=@/", "/$&+,:;=@/"),
        ("/a#b/", "/a%23b/"),
    ] {
        node.transport_mut().unwrap().xhttp.as_mut().unwrap().path =
            format!("{path}?token=a%2Fb&empty=");
        let template = super::super::request::RequestTemplate::new(&node).unwrap();
        let request = template.request("session", None, false, None).unwrap();
        assert_eq!(
            request.uri().path_and_query().unwrap().as_str(),
            format!("{expected}session?token=a%2Fb&empty=")
        );
        assert_eq!(
            request.headers()["referer"],
            format!("http://peer.example{expected}?x_padding=XXXXXXX")
        );
    }
}

#[test]
fn absent_user_agent_sends_xrays_chrome_fetch_headers() {
    use super::super::browser::{chrome_major, sec_ch_ua};
    // Reference strings from Xray v26.3.27 `getGreasedChUa(major, "chrome")`.
    for (major, expected) in [
        (
            144,
            r#""Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144""#,
        ),
        (
            145,
            r#""Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145""#,
        ),
        (
            151,
            r#""Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151""#,
        ),
        (
            152,
            r#""Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152""#,
        ),
    ] {
        assert_eq!(sec_ch_ua(major), expected);
    }
    assert_eq!(chrome_major(0), 144);
    assert_eq!(chrome_major(1_768_262_400 + 35 * 86_400 - 1), 144);
    assert_eq!(chrome_major(1_768_262_400 + 35 * 86_400), 145);

    let mut node = node(XhttpMode::PacketUp, 32);
    let headers = &mut node
        .transport_mut()
        .unwrap()
        .xhttp
        .as_mut()
        .unwrap()
        .headers;
    headers.insert("accept".into(), "text/plain".into());
    headers.insert("sec-fetch-mode".into(), "navigate".into());
    let template = super::super::request::RequestTemplate::new(&node).unwrap();
    let request = template.request("session", Some(0), true, Some(1)).unwrap();
    let headers = request.headers();
    let user_agent = headers["user-agent"].to_str().unwrap();
    assert!(user_agent.starts_with("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit"));
    let major = user_agent
        .split("Chrome/")
        .nth(1)
        .unwrap()
        .split('.')
        .next()
        .unwrap();
    assert!(
        headers["sec-ch-ua"]
            .to_str()
            .unwrap()
            .contains(&format!("\"Chromium\";v=\"{major}\""))
    );
    for (name, value) in [
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", "\"Windows\""),
        ("dnt", "1"),
        ("accept-language", "en-US,en;q=0.9"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-site", "same-origin"),
        ("priority", "u=1, i"),
        ("cache-control", "no-cache"),
        ("pragma", "no-cache"),
        ("accept", "text/plain"),
        ("x-peer-test", "raw"),
    ] {
        assert_eq!(headers[name], value, "{name}");
    }

    node.transport_mut()
        .unwrap()
        .xhttp
        .as_mut()
        .unwrap()
        .headers = [("user-agent".into(), "custom/1".into())].into();
    let template = super::super::request::RequestTemplate::new(&node).unwrap();
    let headers = template
        .request("session", None, false, None)
        .unwrap()
        .headers()
        .clone();
    assert_eq!(headers["user-agent"], "custom/1");
    assert!(!headers.contains_key("sec-ch-ua") && !headers.contains_key("accept"));
}
