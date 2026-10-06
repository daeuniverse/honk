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
                assert_eq!(download.request.uri().path(), PREFIX);
                assert_eq!(
                    download.request.headers()["content-type"],
                    "application/grpc"
                );
                PREFIX.to_owned()
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

#[tokio::test]
async fn referer_replaces_configured_padding_query_with_sampled_padding() {
    let peer = Peer::new(32).await;
    let owner = peer.runtime(XhttpMode::StreamUp, 32);
    let mut node = (*owner.runtime().node).clone();
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
