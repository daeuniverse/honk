use super::*;

/// Serve one SOCKS5 connection and hand back the address bytes
/// (ATYP | DST.ADDR | DST.PORT) of the CONNECT request it received.
async fn run_test_socks5_server() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve_test_socks5(stream).await
    });
    (addr, server)
}

/// No-auth SOCKS5 server that always succeeds. Returns the address bytes
/// (ATYP | DST.ADDR | DST.PORT) of the CONNECT request, read field by field.
async fn serve_test_socks5<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) -> Vec<u8> {
    // Greeting: VER | NMETHODS | METHODS
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting[0], 0x05);
    let mut methods = vec![0u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await.unwrap();
    assert!(methods.contains(&0x00));

    // Reply: no auth
    stream.write_all(&[0x05, 0x00]).await.unwrap();

    // Request: VER | CMD | RSV | ATYP, then the address it names
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[..3], [0x05, 0x01, 0x00]);
    let mut requested = vec![header[3]];
    let addr_len = match header[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.unwrap();
            requested.push(len[0]);
            usize::from(len[0])
        }
        atyp => panic!("unexpected ATYP {atyp:#04x}"),
    };
    // DST.ADDR | DST.PORT
    let mut address = vec![0u8; addr_len + 2];
    stream.read_exact(&mut address).await.unwrap();
    requested.extend_from_slice(&address);

    // Reply: success, bind to 0.0.0.0:0
    let reply = [
        SOCKS5_VERSION,
        REP_SUCCESS,
        0x00, // RSV
        ATYP_IPV4,
        0,
        0,
        0,
        0, // 0.0.0.0
        0,
        0, // port 0
    ];
    stream.write_all(&reply).await.unwrap();
    requested
}

/// ATYP=domain | LEN | "example.com" | port 80
const EXAMPLE_COM_80: &[u8] = &[
    0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x00, 0x50,
];

#[tokio::test]
async fn test_socks5_handshake_no_auth() {
    let (server_addr, server) = run_test_socks5_server().await;

    let node = Node {
        name: "test".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: server_addr.ip().to_string(),
        host: String::new(),
        port: server_addr.port(),
        ..Default::default()
    };

    let handler = Socks5Handler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let result = handler
        .dial(
            &node,
            target,
            Some("example.com"),
            std::time::Duration::from_secs(3),
        )
        .await;
    assert!(result.is_ok());
    assert_eq!(server.await.unwrap(), EXAMPLE_COM_80);
}

#[tokio::test]
async fn connect_request_names_an_ip_target_without_a_domain() {
    let cases: [(&str, &[u8]); 2] = [
        ("93.184.216.34:80", &[0x01, 93, 184, 216, 34, 0x00, 0x50]),
        (
            "[2001:db8::1]:443",
            &[
                0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 0xbb,
            ],
        ),
    ];
    for (target, expected) in cases {
        let (mut client, server) = tokio::io::duplex(4096);
        let server = tokio::spawn(serve_test_socks5(server));
        Socks5Handler::handshake(&mut client, target.parse().unwrap(), None, None, None)
            .await
            .unwrap();
        assert_eq!(server.await.unwrap(), expected, "{target}");
    }
}

#[tokio::test(start_paused = true)]
async fn handshake_flushes_a_carrier_that_buffers_writes() {
    let (client, server) = tokio::io::duplex(4096);
    // Holds every write until it is flushed, as `SsStream` does when its
    // socket returns `Pending` with ciphertext buffered.
    let mut client = tokio::io::BufWriter::with_capacity(4096, client);
    let server = tokio::spawn(serve_test_socks5(server));
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    Socks5Handler::handshake(&mut client, target, Some("example.com"), None, None)
        .await
        .unwrap();
    assert_eq!(server.await.unwrap(), EXAMPLE_COM_80);
}

#[tokio::test(start_paused = true)]
async fn handshake_flushes_credentials_over_a_buffering_carrier() {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut client = tokio::io::BufWriter::with_capacity(4096, client);
        let target = "93.184.216.34:80".parse().unwrap();
        let peer = async {
            let mut greeting = [0; 4];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
            server.write_all(&[0x05, 0x02]).await.unwrap();

            let mut auth = [0; 11];
            server.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth, b"\x01\x04user\x04pass");
            server.write_all(&[0x01, 0x00]).await.unwrap();

            let mut request = [0; 10];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(
                request,
                [0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50]
            );
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        };
        let handshake =
            Socks5Handler::handshake(&mut client, target, None, Some("user"), Some("pass"));
        let (result, ()) = tokio::join!(handshake, peer);
        result.unwrap();
    })
    .await
    .expect("SOCKS5 credential handshake timed out");
}

#[tokio::test]
async fn dial_over_relays_through_the_carrier() {
    let (client, mut server) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let requested = serve_test_socks5(&mut server).await;
        let mut request = [0; 4];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        server.write_all(b"pong").await.unwrap();
        requested
    });
    let mut node = Node {
        name: "socks5-tunnel".into(),
        address: "198.51.100.1:1080".into(),
        host: "must-not-resolve.invalid".into(),
        port: 1080,
        outbound: honk_config::node::OutboundConfig::Socks5(Default::default()),
        ..Default::default()
    };
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let mut stream = Socks5Handler::new()
        .dial_over(
            runtime,
            Box::new(client),
            target,
            Some("example.com"),
            TunnelDialOptions::new(std::time::Duration::from_secs(3)),
        )
        .await
        .unwrap();
    stream.stream.write_all(b"ping").await.unwrap();
    let mut reply = [0; 4];
    stream.stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");
    assert_eq!(server.await.unwrap(), EXAMPLE_COM_80);
}

#[cfg(feature = "flow-observation")]
mod request_observation {
    use super::*;
    use crate::proxy::request_observation_support::{DeferringCarrier, milestones, observed};
    use crate::runtime::flow_observation::{FlowEvent, Milestone};

    #[tokio::test]
    async fn direct_handshake_publishes_request_sent_once() {
        let (client, server) = tokio::io::duplex(4096);
        let server = tokio::spawn(serve_test_socks5(server));
        let (observer, events) = observed();
        observer
            .scope(async move {
                let mut client = client;
                Socks5Handler::handshake(
                    &mut client,
                    "93.184.216.34:80".parse().unwrap(),
                    None,
                    None,
                    None,
                )
                .await
            })
            .await
            .unwrap();
        server.await.unwrap();
        let published_milestones: Vec<_> = events
            .lock()
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Milestone { milestone } => Some(*milestone),
                _ => None,
            })
            .collect();
        assert_eq!(
            published_milestones,
            [Milestone::TargetRequestSent, Milestone::TargetConfirmed]
        );
    }

    #[tokio::test]
    async fn request_sent_waits_for_a_deferring_carrier() {
        let (client, server) = tokio::io::duplex(4096);
        let server = tokio::spawn(serve_test_socks5(server));
        let (carrier, request) = DeferringCarrier::new(client);
        let mut node = Node {
            name: "socks5-observed-tunnel".into(),
            address: "198.51.100.1:1080".into(),
            host: "must-not-resolve.invalid".into(),
            port: 1080,
            outbound: honk_config::node::OutboundConfig::Socks5(Default::default()),
            ..Default::default()
        };
        node.id = node.derive_id();
        let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
        let (observer, events) = observed();
        let _stream = observer
            .scope(Socks5Handler::new().dial_over(
                runtime,
                Box::new(carrier),
                "93.184.216.34:80".parse().unwrap(),
                None,
                TunnelDialOptions::new(std::time::Duration::from_secs(3)),
            ))
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(
            milestones(&events.lock(), Milestone::TargetRequestSent),
            0,
            "published before delivery"
        );
        let (request, position) = request.lock().take().unwrap();
        request.delivered(position);
        assert_eq!(milestones(&events.lock(), Milestone::TargetRequestSent), 1);
    }
}
