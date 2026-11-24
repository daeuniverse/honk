use super::*;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

async fn append_data(recv: &mut h2::RecvStream, output: &mut BytesMut) {
    let data = recv.data().await.unwrap().unwrap();
    output.extend_from_slice(&data);
    recv.flow_control().release_capacity(data.len()).unwrap();
}

async fn upgrade(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) -> (h2::RecvStream, h2::SendStream<Bytes>) {
    assert_eq!(request.method(), http::Method::CONNECT);
    let mut recv = request.into_body();
    let mut send = respond
        .send_response(http::Response::new(()), false)
        .unwrap();
    let mut bytes = BytesMut::new();
    const CONNECT: &[u8] = &[0, 0, 1, 192, 0, 2, 1, 4, 56];
    while bytes.len() < CONNECT.len() {
        append_data(&mut recv, &mut bytes).await;
    }
    assert_eq!(&bytes.split_to(CONNECT.len())[..], CONNECT);
    send.send_data(Bytes::from_static(&[0]), false).unwrap();

    let end = loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        append_data(&mut recv, &mut bytes).await;
    };
    let headers = bytes.split_to(end);
    let headers = std::str::from_utf8(&headers).unwrap();
    assert!(headers.starts_with("GET / HTTP/1.1\r\n"));
    let key = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("sec-websocket-key")
                .then(|| value.trim())
        })
        .unwrap();
    let accept = derive_accept_key(key.as_bytes());
    let reply = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    send.send_data(Bytes::from(reply), false).unwrap();

    while bytes.len() < 6 + TROJAN_REQUEST_LEN {
        append_data(&mut recv, &mut bytes).await;
    }
    assert_eq!(&bytes[..2], &[0x82, 0x80 | TROJAN_REQUEST_LEN as u8]);
    let mask: [u8; 4] = bytes[2..6].try_into().unwrap();
    let header = &mut bytes[6..];
    for (index, byte) in header.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
    assert_trojan_request(header);
    send.send_data(Bytes::from_static(b"\x82\x04pong"), false)
        .unwrap();
    (recv, send)
}

async fn serve(listener: TcpListener, release: oneshot::Receiver<()>) {
    let (stream, _) = listener.accept().await.unwrap();
    stream.set_zero_linger().unwrap();
    let mut driver = accept_mux(stream).await;
    let mut streams = Vec::new();
    for _ in 0..2 {
        let (request, respond) = driver.accept().await.unwrap().unwrap();
        let stream = tokio::select! {
            stream = upgrade(request, respond) => stream,
            result = driver.accept() => panic!("unexpected H2MUX request or closure: {result:?}"),
        };
        streams.push(stream);
    }
    tokio::select! {
        released = release => released.unwrap(),
        result = driver.accept() => panic!("unexpected H2MUX request or closure: {result:?}"),
    }
    // Drop the physical socket with both logical streams still open.
    drop(driver);
    drop(streams);
}

#[tokio::test]
async fn two_upgraded_websockets_share_one_h2mux_carrier_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = node(
        "front",
        "127.0.0.1",
        listener.local_addr().unwrap().port(),
        OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some(UUID.into()),
            multiplex: VlessMultiplex::H2 { padding: false },
            ..Default::default()
        }),
    );
    let last = node(
        "exit",
        NEXT_HOP,
        NEXT_HOP_PORT,
        OutboundConfig::Trojan(TrojanConfig {
            transport: StreamTransportOptions {
                transport: "ws".into(),
                ..Default::default()
            },
            ..Default::default()
        }),
    );
    let via = chain(&[&front, &last]);
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[via.clone(), front, last]).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();
    let (release, released) = oneshot::channel();
    let client = async {
        let mut streams = Vec::new();
        for _ in 0..2 {
            let mut stream = registry
                .dial_runtime(
                    Arc::clone(&generation),
                    via.id,
                    target(),
                    None,
                    Duration::from_secs(3),
                )
                .await
                .unwrap()
                .stream;
            let mut reply = [0; 4];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"pong");
            streams.push(stream);
        }
        release.send(()).unwrap();
        let mut outcomes = Vec::new();
        for stream in &mut streams {
            let error = stream.read_u8().await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            outcomes.push(ScoreOutcome::from_io_error(&error));
        }
        assert!(matches!(outcomes[0], ScoreOutcome::SharedNodeFailure(_)));
        assert_eq!(outcomes[0], outcomes[1]);
        assert_score_failure_scope(&via, &outcomes, true, 1, 1);
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(client, serve(listener, released));
    })
    .await
    .expect("both WS upgrades and shared H2MUX failure must settle");
    generation.shutdown().await;
}
