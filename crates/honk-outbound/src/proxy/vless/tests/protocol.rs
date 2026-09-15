use super::*;

#[test]
fn test_vless_header_ipv4() {
    let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
    let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let header =
        VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, Some(target), None, None).unwrap();

    // ver(1) + uuid(16) + addon_len(1) + cmd(1) + port(2) + atyp(1) + addr(4)
    assert_eq!(header.len(), 1 + 16 + 1 + 1 + 2 + 1 + 4);
    assert_eq!(header[0], VLESS_VERSION);
    assert_eq!(&header[1..17], &uuid_bytes);
    assert_eq!(header[17], 0x00); // addon_len
    assert_eq!(header[18], CMD_TCP);
    assert_eq!(&header[19..21], &[0x00, 0x50]); // port 80
    assert_eq!(header[21], ATYP_IPV4);
    assert_eq!(&header[22..26], &[93, 184, 216, 34]);
}

#[test]
fn test_vless_header_domain() {
    let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
    let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
    let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let domain = "example.com";

    let header =
        VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, Some(target), Some(domain), None)
            .unwrap();

    // ver(1) + uuid(16) + addon_len(1) + cmd(1) + port(2) + atyp(1) + domain_len(1) + domain(11)
    assert_eq!(header.len(), 1 + 16 + 1 + 1 + 2 + 1 + 1 + domain.len());
    assert_eq!(header[0], VLESS_VERSION);
    assert_eq!(&header[1..17], &uuid_bytes);
    assert_eq!(header[17], 0x00); // addon_len
    assert_eq!(header[18], CMD_TCP);
    assert_eq!(&header[19..21], &[0x01, 0xbb]); // port 443
    assert_eq!(header[21], ATYP_DOMAIN);
    assert_eq!(header[22], domain.len() as u8);
    assert_eq!(&header[23..34], domain.as_bytes());
}

#[test]
fn test_vless_header_ipv6() {
    let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
    let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
    let target: SocketAddr = "[::1]:1080".parse().unwrap();

    let header =
        VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, Some(target), None, None).unwrap();

    // ver(1) + uuid(16) + addon_len(1) + cmd(1) + port(2) + atyp(1) + addr(16)
    assert_eq!(header.len(), 1 + 16 + 1 + 1 + 2 + 1 + 16);
    assert_eq!(header[0], VLESS_VERSION);
    assert_eq!(&header[1..17], &uuid_bytes);
    assert_eq!(header[17], 0x00); // addon_len
    assert_eq!(header[18], CMD_TCP);
    assert_eq!(&header[19..21], &[0x04, 0x38]); // port 1080
    assert_eq!(header[21], ATYP_IPV6);
    // IPv6 ::1 = 15 bytes of 0x00 then 0x01
    assert_eq!(&header[22..37], &[0u8; 15]);
    assert_eq!(header[37], 0x01);
}

#[test]
fn vless_mux_command_carries_no_target() {
    let uuid = VLessHandler::parse_uuid("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3").unwrap();
    let header = VLessHandler::build_request_header(
        &uuid,
        super::super::vless_cool::VLESS_MUX_COMMAND,
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(header.len(), 19);
    assert_eq!(header[18], super::super::vless_cool::VLESS_MUX_COMMAND);

    let target = Some("127.0.0.1:9527".parse().unwrap());
    assert!(
        VLessHandler::build_request_header(
            &uuid,
            super::super::vless_cool::VLESS_MUX_COMMAND,
            target,
            None,
            None,
        )
        .is_err()
    );
}

#[test]
fn vless_header_uses_base_flow_for_udp443_suffix() {
    let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
    let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
    let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let vless = honk_config::node::VlessConfig {
        flow: Some("xtls-rprx-vision-udp443".into()),
        ..Default::default()
    };
    assert!(vless.is_vision());

    let header = VLessHandler::build_request_header(
        &uuid_bytes,
        CMD_TCP,
        Some(target),
        None,
        vless.wire_flow(),
    )
    .unwrap();

    // ver(1) + uuid(16) + addon_len(1) + addon(18) + cmd(1) + port(2) + atyp(1) + addr(4)
    assert_eq!(header.len(), 1 + 16 + 1 + 18 + 1 + 2 + 1 + 4);
    assert_eq!(header[0], VLESS_VERSION);
    assert_eq!(&header[1..17], &uuid_bytes);
    assert_eq!(header[17], 18); // addon_len: 0x0A + len + 16-byte flow
    // Xray encoding.Addons protobuf: field 1 (Flow) = tag 0x0A, length 0x10
    assert_eq!(&header[18..36], b"\x0a\x10xtls-rprx-vision");
    assert_eq!(header[36], CMD_TCP);
    assert_eq!(&header[37..39], &[0x01, 0xbb]); // port 443
    assert_eq!(header[39], ATYP_IPV4);
    assert_eq!(&header[40..44], &[93, 184, 216, 34]);
}

#[test]
fn test_vless_header_rejects_unsupported_flow_and_long_domain() {
    let uuid_bytes = VLessHandler::parse_uuid("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3").unwrap();
    let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

    let flow_error = VLessHandler::build_request_header(
        &uuid_bytes,
        CMD_TCP,
        Some(target),
        None,
        Some("unsupported"),
    )
    .unwrap_err();
    assert_eq!(flow_error.to_string(), "VLESS: unsupported flow");

    let long_domain = "a".repeat(256);
    let domain_error = VLessHandler::build_request_header(
        &uuid_bytes,
        CMD_TCP,
        Some(target),
        Some(&long_domain),
        None,
    )
    .unwrap_err();
    assert_eq!(
        domain_error.to_string(),
        "VLESS: target domain exceeds 255 bytes"
    );

    let empty_flow =
        VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, Some(target), None, Some(""))
            .unwrap();
    assert_eq!(empty_flow[17], 0);
}

#[test]
fn test_parse_uuid_invalid() {
    let result = VLessHandler::parse_uuid("not-a-uuid");
    assert!(result.is_err());
}

/// End-to-end over the WebSocket transport: a mock WS server receives
/// the VLESS request header as the first binary message, replies with
/// the 1-byte acceptance, and then sees relayed payload.
#[tokio::test]
async fn test_vless_dial_over_ws() {
    use futures_util::{SinkExt, StreamExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

        // First binary message carries the VLESS request header,
        // possibly coalesced with the first payload bytes (nothing
        // forces a read between the two writes anymore).
        let msg = ws.next().await.unwrap().unwrap();
        let data = msg.into_data();
        assert_eq!(data[0], VLESS_VERSION);
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        assert_eq!(&data[1..17], &uuid_bytes);
        assert_eq!(data[18], CMD_TCP);

        // Accept with the 2-byte response header (version + addon_len=0),
        // then expect relayed payload.
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            vec![0x00, 0x00].into(),
        ))
        .await
        .unwrap();
        const HEADER_LEN: usize = 1 + 16 + 1 + 1 + 2 + 1 + 4;
        if data.len() > HEADER_LEN {
            assert_eq!(&data[HEADER_LEN..], b"ping");
        } else {
            let msg = ws.next().await.unwrap().unwrap();
            assert_eq!(&msg.into_data()[..], b"ping");
        }
    });

    let node = Node {
        name: "vless-ws".into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some(uuid_str.into()),
            transport: honk_config::node::StreamTransportOptions {
                transport: "ws".into(),
                ws_path: Some("/vless".into()),
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let mut ps = VLessHandler::new()
        .dial(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    ps.stream.write_all(b"ping").await.unwrap();
    ps.stream.flush().await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

/// Bare VLESS over raw TCP (`security=none`): `node.tls` false and an
/// empty transport must not be TLS-wrapped. The lazy response stripper
/// still wraps the stream (bare servers piggyback the response header
/// too), so it no longer downcasts to a plain TcpStream.
#[tokio::test]
async fn test_vless_dial_bare_tcp() {
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 19];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], VLESS_VERSION);
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        assert_eq!(&head[1..17], &uuid_bytes);
        assert_eq!(head[17], 0x00); // addon_len
        assert_eq!(head[18], CMD_TCP);
        // Skip port(2) + atyp(1) + ipv4(4), accept, expect payload.
        let mut addr = [0u8; 7];
        stream.read_exact(&mut addr).await.unwrap();
        stream.write_all(&[0x00, 0x00]).await.unwrap();
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
    });

    let node = Node {
        name: "vless-bare".into(),
        address: format!("127.0.0.1:{port}"),
        host: "127.0.0.1".into(),
        port,
        ..vless_node(uuid_str)
    };
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let mut ps = VLessHandler::new()
        .dial(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    ps.stream.write_all(b"ping").await.unwrap();
    ps.stream.flush().await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn vision_rejects_plaintext_before_vless_header() {
    use tokio::io::AsyncReadExt as _;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut byte = [0; 1];
        stream.read(&mut byte).await.unwrap_or(0) != 0
    });
    let mut node = vless_node("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3");
    node.name = "vless-vision-plaintext".into();
    node.address = format!("127.0.0.1:{port}");
    node.host = "127.0.0.1".into();
    node.port = port;
    node.vless_mut().unwrap().flow = Some("xtls-rprx-vision".into());

    VLessHandler::new()
        .dial(
            &node,
            "93.184.216.34:80".parse().unwrap(),
            None,
            std::time::Duration::from_secs(3),
        )
        .await
        .expect_err("plaintext Vision must fail");
    assert!(!server.await.unwrap(), "VLESS header leaked over plaintext");
}

#[tokio::test]
async fn vision_rejects_tls12_before_vless_header() {
    use boring::pkey::PKey;
    use boring::ssl::{SslAcceptor, SslMethod, SslVersion};
    use boring::x509::X509;
    use std::io::Read as _;

    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_pem(cert.pem().as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    acceptor
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    let acceptor = acceptor.build();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut tls = acceptor.accept(stream).unwrap();
        let mut byte = [0; 1];
        matches!(tls.read(&mut byte), Ok(1))
    });

    let mut node = vless_node("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3");
    node.name = "vless-vision-tls12".into();
    node.address = format!("127.0.0.1:{port}");
    node.host = "127.0.0.1".into();
    node.port = port;
    node.vless_mut().unwrap().flow = Some("xtls-rprx-vision".into());
    let tls = node.tls_mut().unwrap();
    tls.enabled = true;
    tls.skip_cert_verify = true;
    tls.sni = Some("localhost".into());
    VLessHandler::new()
        .dial(
            &node,
            "93.184.216.34:80".parse().unwrap(),
            None,
            std::time::Duration::from_secs(3),
        )
        .await
        .expect_err("TLS 1.2 Vision must fail");
    assert!(!server.join().unwrap(), "VLESS header leaked over TLS 1.2");
}
