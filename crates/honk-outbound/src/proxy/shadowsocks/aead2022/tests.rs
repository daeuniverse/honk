use super::*;
use crate::proxy::shadowsocks::ShadowsocksHandler;
use crate::proxy::{PacketOutbound, TcpOutbound};
use honk_config::node::Node;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Fixed test material (same values fed to the Go reference program).
fn psk1() -> Vec<u8> {
    (0u8..16).collect()
}
fn psk2() -> Vec<u8> {
    (16u8..32).collect()
}
fn salt16() -> Vec<u8> {
    (32u8..48).collect()
}
fn psk32() -> Vec<u8> {
    (0u8..32).collect()
}
fn salt32() -> Vec<u8> {
    (32u8..64).collect()
}

#[test]
fn test_psk_parse_single() {
    let m = Ss2022Method::new("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw==").unwrap();
    assert_eq!(m.psks.len(), 1);
    assert_eq!(m.psks[0], psk1());
    assert!(m.psk_hashes.is_empty());
}

#[test]
fn test_psk_parse_multi() {
    let m = Ss2022Method::new(
        "2022-blake3-aes-128-gcm",
        "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
    )
    .unwrap();
    assert_eq!(m.psks.len(), 2);
    assert_eq!(m.encryption_psk(), &psk2()[..]);
    assert_eq!(m.psk_hashes.len(), 1);
    assert_eq!(m.psk_hashes[0], hex("ea5ff194405ece4f55ae7a150c523884")[..]);
}

#[test]
fn test_psk_parse_bad_length() {
    // 32-byte psk with a 16-byte method.
    assert!(
        Ss2022Method::new(
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        )
        .is_err()
    );
    // 16-byte psk with a 32-byte method.
    assert!(Ss2022Method::new("2022-blake3-aes-256-gcm", "AAECAwQFBgcICQoLDA0ODw==").is_err());
}

#[test]
fn test_psk_parse_bad_base64() {
    assert!(Ss2022Method::new("2022-blake3-aes-128-gcm", "!!!not-base64!!!").is_err());
    assert!(Ss2022Method::new("2022-blake3-aes-128-gcm", "").is_err());
}

#[test]
fn test_psk_parse_chacha_rejects_multi() {
    assert!(Ss2022Method::new(
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        )
        .is_err());
    assert!(
        Ss2022Method::new(
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        )
        .is_ok()
    );
}

// BLAKE3 known-answer tests (generated with the Go reference).

#[test]
fn test_session_subkey_kat() {
    let m = Ss2022Method::new("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw==").unwrap();
    assert_eq!(
        m.session_subkey(&salt16()),
        hex("8180421f8f56092ca7544a64ff852536")
    );
}

#[test]
fn test_session_subkey_kat_32() {
    let m = Ss2022Method::new(
        "2022-blake3-aes-256-gcm",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    )
    .unwrap();
    assert_eq!(
        m.session_subkey(&salt32()),
        hex("374fca03e4dae7f998fd7e59c1edfcc8e3197f4db1c19ca1671be3b66a92ddda")
    );
}

#[test]
fn test_eih_kat() {
    // psk list [psk1, psk2], salt16 → single EIH block, KAT from Go
    // (AES-ECB(identity_subkey, blake3(psk2)[..16])).
    let m = Ss2022Method::new(
        "2022-blake3-aes-128-gcm",
        "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
    )
    .unwrap();
    let eih = m.tcp_identity_headers(&salt16()).unwrap();
    assert_eq!(eih, hex("cfe4b97eb5c29f5dda417a22031c9f08"));
}

#[test]
fn test_aes_block_kat() {
    // AES-ECB(psk1)(0x01020304050607081122334455667788) KAT from Go.
    let block = AesBlock::new(&psk1()).unwrap();
    let mut data: [u8; 16] = hex("01020304050607081122334455667788").try_into().unwrap();
    block.encrypt(&mut data);
    assert_eq!(data, hex("838e4115229deb1b278e7474a56e1893")[..]);
    block.decrypt(&mut data);
    assert_eq!(data, hex("01020304050607081122334455667788")[..]);
}

#[test]
fn test_blake3_xof_kat() {
    let key: [u8; 32] = (0u8..32)
        .map(|i| i * 3)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let mut xof = Blake3Xof::with_key(key);
    let mut out = [0u8; 32];
    xof.fill(&mut out);
    assert_eq!(
        out,
        hex("4a77995a0df1a72023241481d0d6436f3ae93d3509691067cc834db52326b6c2")[..]
    );
}

#[test]
fn test_sliding_window() {
    let mut w = SlidingWindow::new();
    assert!(w.check(0));
    w.add(0);
    assert!(!w.check(0)); // replay
    assert!(w.check(1));
    w.add(1);
    assert!(!w.check(0));
    assert!(!w.check(1));
    // Jump far ahead: old values fall out of the window.
    w.add(SW_SIZE + 200);
    assert!(w.check(SW_SIZE + 201));
    assert!(!w.check(0)); // behind window
    assert!(w.check(SW_SIZE + 199));
    w.add(SW_SIZE + 199);
    assert!(!w.check(SW_SIZE + 199));
}

/// Length of the leading SOCKS5 address, parsed independently of production.
fn addr_len(buf: &[u8]) -> usize {
    match buf[0] {
        0x01 => 7,
        0x03 => 2 + buf[1] as usize + 2,
        0x04 => 19,
        atyp => panic!("unexpected ATYP {atyp:#x}"),
    }
}

fn udp_target() -> (Vec<u8>, SocketAddr) {
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    (
        crate::proxy::addr::encode_address(target, None).unwrap(),
        target,
    )
}

/// Server-side parse of an AES-construction client packet; returns
/// (session_id, packet_id, payload).
fn server_open_aes(method: &Ss2022Method, packet: &[u8]) -> (u64, u64, Vec<u8>) {
    let psk = method.encryption_psk();
    let mut plain_header: [u8; 16] = packet[..16].try_into().unwrap();
    AesBlock::new(psk).unwrap().decrypt(&mut plain_header);
    let session_id = u64::from_be_bytes(plain_header[..8].try_into().unwrap());
    let packet_id = u64::from_be_bytes(plain_header[8..].try_into().unwrap());

    let subkey = method.session_subkey(&plain_header[..8]);
    let cipher = method.aead(&subkey).unwrap();
    let body = cipher.open(&plain_header[4..16], &packet[16..]).unwrap();
    assert_eq!(body[0], HEADER_TYPE_CLIENT);
    let ts = u64::from_be_bytes(body[1..9].try_into().unwrap());
    assert!(unix_timestamp().abs_diff(ts) <= 30);
    let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    let rest = &body[11 + padding_len..];
    let skip = addr_len(rest);
    (session_id, packet_id, rest[skip..].to_vec())
}

/// Server-side build of a response packet for either UDP construction.
fn server_seal_udp(
    method: &Ss2022Method,
    client_session_id: u64,
    server_session_id: u64,
    server_packet_id: u64,
    timestamp: u64,
    socks: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut ids = [0u8; 16];
    ids[..8].copy_from_slice(&server_session_id.to_be_bytes());
    ids[8..].copy_from_slice(&server_packet_id.to_be_bytes());

    let mut body = Vec::with_capacity(16 + 19 + socks.len() + payload.len());
    if method.is_chacha() {
        body.extend_from_slice(&ids);
    }
    body.push(HEADER_TYPE_SERVER);
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(&client_session_id.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(socks);
    body.extend_from_slice(payload);

    if method.is_chacha() {
        let cipher = AeadCipher::new_xchacha20(method.encryption_psk()).unwrap();
        let mut nonce = [0u8; UDP_XNONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce);
        let sealed = cipher.seal(&nonce, &body).unwrap();
        let mut packet = nonce.to_vec();
        packet.extend_from_slice(&sealed);
        return packet;
    }

    let subkey = method.session_subkey(&ids[..8]);
    let cipher = method.aead(&subkey).unwrap();
    let sealed = cipher.seal(&ids[4..], &body).unwrap();
    let mut encrypted_ids = ids;
    AesBlock::new(method.encryption_psk())
        .unwrap()
        .encrypt(&mut encrypted_ids);
    let mut packet = encrypted_ids.to_vec();
    packet.extend_from_slice(&sealed);
    packet
}

#[test]
fn test_udp_2022_aes_roundtrip() {
    let psk_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let method = Ss2022Method::new("2022-blake3-aes-256-gcm", psk_b64).unwrap();
    let mut session = Ss2022UdpSession::new(method).unwrap();
    let server_method = Ss2022Method::new("2022-blake3-aes-256-gcm", psk_b64).unwrap();
    let (socks, target) = udp_target();

    let payload = b"dns query payload";
    let packet = session.seal_packet(&socks, target.port(), payload).unwrap();
    // DNS payload → padding present.
    assert!(packet.len() > 16 + 1 + 8 + 2 + socks.len() + payload.len() + TAG_LEN);

    let (session_id, packet_id, opened) = server_open_aes(&server_method, &packet);
    assert_eq!(packet_id, 0);
    assert_eq!(opened, payload);

    // Second packet increments the packet id.
    let packet2 = session.seal_packet(&socks, target.port(), payload).unwrap();
    let (_, packet_id2, _) = server_open_aes(&server_method, &packet2);
    assert_eq!(packet_id2, 1);

    // Server response.
    let response = server_seal_udp(
        &server_method,
        session_id,
        0xdeadbeef,
        0,
        unix_timestamp(),
        &socks,
        b"dns response",
    );
    let opened = session.open_packet(&response).unwrap();
    assert_eq!(opened.payload(), b"dns response");

    // Replay of the same packet must be rejected.
    assert!(session.open_packet(&response).is_err());
}

#[test]
fn test_udp_2022_aes_eih_multi_psk() {
    // Two psks: identity psk1 + encryption psk2 (16-byte AES method).
    let m = Ss2022Method::new(
        "2022-blake3-aes-128-gcm",
        "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
    )
    .unwrap();
    let mut session = Ss2022UdpSession::new(m).unwrap();
    let (socks, target) = udp_target();
    let payload = b"hello";
    let packet = session.seal_packet(&socks, target.port(), payload).unwrap();
    // Layout: enc_header(16) | EIH(16) | body+tag.
    assert!(packet.len() > 32);

    // Decrypt the separate header with the FIRST psk (server identity psk).
    let mut plain_header: [u8; 16] = packet[..16].try_into().unwrap();
    AesBlock::new(&psk1()).unwrap().decrypt(&mut plain_header);

    // EIH block: AES-ECB(psk1, psk_hash XOR plain_header).
    let mut eih: [u8; 16] = packet[16..32].try_into().unwrap();
    AesBlock::new(&psk1()).unwrap().decrypt(&mut eih);
    let expected_hash = blake3::hash(&psk2());
    for j in 0..16 {
        assert_eq!(eih[j], expected_hash.as_bytes()[j] ^ plain_header[j]);
    }

    // Body opens with SessionKey(encryption psk, session_id).
    let mut material = psk2();
    material.extend_from_slice(&plain_header[..8]);
    let subkey = &blake3::derive_key("shadowsocks 2022 session subkey", &material)[..16];
    let cipher = AeadCipher::new("2022-blake3-aes-128-gcm", subkey).unwrap();
    let body = cipher.open(&plain_header[4..16], &packet[32..]).unwrap();
    assert_eq!(body[0], HEADER_TYPE_CLIENT);
}

#[test]
fn test_udp_2022_chacha_roundtrip() {
    let psk_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let method = Ss2022Method::new("2022-blake3-chacha20-poly1305", psk_b64).unwrap();
    let mut session = Ss2022UdpSession::new(method).unwrap();
    let (socks, target) = udp_target();
    let payload = b"quic payload";

    let packet = session.seal_packet(&socks, target.port(), payload).unwrap();
    assert!(packet.len() > UDP_XNONCE_SIZE + TAG_LEN);

    // Server-side parse: nonce || XChaCha20-Poly1305(psk)(body).
    let psk = psk32();
    let server_cipher = AeadCipher::new_xchacha20(&psk).unwrap();
    let (nonce, ct) = packet.split_at(UDP_XNONCE_SIZE);
    let body = server_cipher.open(nonce, ct).unwrap();
    let client_session_id = u64::from_be_bytes(body[..8].try_into().unwrap());
    let client_packet_id = u64::from_be_bytes(body[8..16].try_into().unwrap());
    assert_eq!(client_packet_id, 0);
    assert_eq!(body[16], HEADER_TYPE_CLIENT);
    let padding_len = u16::from_be_bytes([body[25], body[26]]) as usize;
    let rest = &body[27 + padding_len..];
    let skip = addr_len(rest);
    assert_eq!(&rest[skip..], payload);

    let response = server_seal_udp(
        &Ss2022Method::new("2022-blake3-chacha20-poly1305", psk_b64).unwrap(),
        client_session_id,
        0xcafe,
        0,
        unix_timestamp(),
        &socks,
        b"quic response",
    );

    let opened = session.open_packet(&response).unwrap();
    assert_eq!(opened.payload(), b"quic response");
    assert!(session.open_packet(&response).is_err()); // replay
}

#[test]
fn test_udp_2022_server_session_replay_and_rotation() {
    let methods = [
        (
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
        (
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
    ];
    let (socks, _) = udp_target();
    let now = 1_700_000_000;

    for (method_name, password) in methods {
        let mut session =
            Ss2022UdpSession::new(Ss2022Method::new(method_name, password).unwrap()).unwrap();
        let server_method = Ss2022Method::new(method_name, password).unwrap();
        let client_session_id = session.session_id;
        let packet = |server_session_id: u64, packet_id: u64, timestamp: u64, payload: &[u8]| {
            server_seal_udp(
                &server_method,
                client_session_id,
                server_session_id,
                packet_id,
                timestamp,
                &socks,
                payload,
            )
        };

        let a0 = packet(0xa, 0, now, b"a0");
        assert_eq!(session.open_packet_at(&a0, now).unwrap().payload(), b"a0");
        let b0 = packet(0xb, 0, now, b"b0");
        assert_eq!(session.open_packet_at(&b0, now).unwrap().payload(), b"b0");
        assert!(session.open_packet_at(&a0, now).is_err());

        let a1 = packet(0xa, 1, now + 10, b"a1");
        assert_eq!(
            session.open_packet_at(&a1, now + 10).unwrap().payload(),
            b"a1"
        );
        let c0 = packet(0xc, 0, now + 69, b"c0");
        assert!(session.open_packet_at(&c0, now + 69).is_err());
        let c0 = packet(0xc, 0, now + 70, b"c0");
        assert_eq!(
            session.open_packet_at(&c0, now + 70).unwrap().payload(),
            b"c0"
        );
    }
}

#[test]
fn test_udp_2022_failed_server_packet_does_not_mutate_replay_state() {
    let methods = [
        (
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
        (
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
    ];
    let (socks, _) = udp_target();
    let now = 1_700_000_000;

    for (method_name, password) in methods {
        for corrupt_ciphertext in [true, false] {
            let mut session =
                Ss2022UdpSession::new(Ss2022Method::new(method_name, password).unwrap()).unwrap();
            let server_method = Ss2022Method::new(method_name, password).unwrap();
            let client_session_id = session.session_id;
            let packet = |client_id, server_id, packet_id, payload| {
                server_seal_udp(
                    &server_method,
                    client_id,
                    server_id,
                    packet_id,
                    now,
                    &socks,
                    payload,
                )
            };

            let a0 = packet(client_session_id, 0xa, 0, b"a0");
            assert_eq!(session.open_packet_at(&a0, now).unwrap().payload(), b"a0");

            let failed_client_id = if corrupt_ciphertext {
                client_session_id
            } else {
                client_session_id ^ 1
            };
            let mut failed_b0 = packet(failed_client_id, 0xb, 0, b"b0");
            if corrupt_ciphertext {
                *failed_b0.last_mut().unwrap() ^= 1;
            }
            assert!(session.open_packet_at(&failed_b0, now).is_err());

            let c0 = packet(client_session_id, 0xc, 0, b"c0");
            assert_eq!(session.open_packet_at(&c0, now).unwrap().payload(), b"c0");
            assert!(session.open_packet_at(&a0, now).is_err());
            let a1 = packet(client_session_id, 0xa, 1, b"a1");
            assert_eq!(session.open_packet_at(&a1, now).unwrap().payload(), b"a1");
        }
    }
}

const TCP_TARGET: &str = "93.184.216.34:443";
const TCP_TARGET_HEADER: [u8; 7] = [1, 93, 184, 216, 34, 0x01, 0xbb];

async fn mock_2022_server(
    listener: tokio::net::TcpListener,
    password: &'static str,
    method_name: &'static str,
    expected_target: &[u8],
) {
    let (stream, _) = listener.accept().await.unwrap();
    serve_mock_2022(stream, password, method_name, expected_target).await;
}

/// Validates the request headers and EIH before echoing payloads in SS2022 response frames.
async fn serve_mock_2022<S: AsyncRead + AsyncWrite>(
    stream: S,
    password: &'static str,
    method_name: &'static str,
    expected_target: &[u8],
) {
    let method = Ss2022Method::new(method_name, password).unwrap();
    let (mut rd, mut wr) = tokio::io::split(stream);

    // Salt + EIH.
    let mut salt = vec![0u8; method.key_len];
    rd.read_exact(&mut salt).await.unwrap();
    let eih_len = (method.psks.len() - 1) * 16;
    let mut eihs = vec![0u8; eih_len];
    rd.read_exact(&mut eihs).await.unwrap();
    for (i, chunk) in eihs.chunks(16).enumerate() {
        let mut material = method.psks[i].clone();
        material.extend_from_slice(&salt);
        let identity_subkey = blake3::derive_key("shadowsocks 2022 identity subkey", &material);
        let mut block_data: [u8; 16] = chunk.try_into().unwrap();
        AesBlock::new(&identity_subkey[..method.key_len])
            .unwrap()
            .decrypt(&mut block_data);
        assert_eq!(block_data, method.psk_hashes[i], "EIH {} mismatch", i);
    }

    // Fixed + variable request headers.
    let subkey = method.session_subkey(&salt);
    let cipher = method.aead(&subkey).unwrap();
    let mut nonce = vec![0u8; NONCE_LEN];
    let mut fixed = vec![0u8; 11 + TAG_LEN];
    rd.read_exact(&mut fixed).await.unwrap();
    let fixed = cipher.open(&nonce, &fixed).unwrap();
    increment_nonce(&mut nonce);
    assert_eq!(fixed[0], HEADER_TYPE_CLIENT);
    let ts = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
    assert!(unix_timestamp().abs_diff(ts) <= 30);
    let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
    let mut var = vec![0u8; var_len + TAG_LEN];
    rd.read_exact(&mut var).await.unwrap();
    let var = cipher.open(&nonce, &var).unwrap();
    increment_nonce(&mut nonce);
    let addr_len = addr_len(&var);
    assert_eq!(&var[..addr_len], expected_target, "target address");
    let padding_len = u16::from_be_bytes([var[addr_len], var[addr_len + 1]]) as usize;
    assert!(padding_len > 0, "padding must be present without payload");
    assert_eq!(var.len(), addr_len + 2 + padding_len);

    // Response direction state.
    let mut resp_salt = vec![0u8; method.key_len];
    rand::rng().fill_bytes(&mut resp_salt);
    let resp_subkey = method.session_subkey(&resp_salt);
    let resp_cipher = method.aead(&resp_subkey).unwrap();
    let mut resp_nonce = vec![0u8; NONCE_LEN];
    let mut response_started = false;

    // Echo loop: read chunk payloads, echo them back.
    let mut len_buf = vec![0u8; 2 + TAG_LEN];
    loop {
        if rd.read_exact(&mut len_buf).await.is_err() {
            return;
        }
        let len_plain = cipher.open(&nonce, &len_buf).unwrap();
        increment_nonce(&mut nonce);
        let len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        let mut payload = vec![0u8; len + TAG_LEN];
        rd.read_exact(&mut payload).await.unwrap();
        let plain = cipher.open(&nonce, &payload).unwrap();
        increment_nonce(&mut nonce);

        if !response_started {
            response_started = true;
            // Fixed response header (doubles as first length chunk).
            let mut header = Vec::new();
            header.extend_from_slice(&resp_salt);
            let mut fixed = Vec::new();
            fixed.push(HEADER_TYPE_SERVER);
            fixed.extend_from_slice(&unix_timestamp().to_be_bytes());
            fixed.extend_from_slice(&salt); // echo request salt
            fixed.extend_from_slice(&(plain.len() as u16).to_be_bytes());
            header.extend_from_slice(&resp_cipher.seal(&resp_nonce, &fixed).unwrap());
            increment_nonce(&mut resp_nonce);
            header.extend_from_slice(&resp_cipher.seal(&resp_nonce, &plain).unwrap());
            increment_nonce(&mut resp_nonce);
            wr.write_all(&header).await.unwrap();
        } else {
            let mut chunk = Vec::new();
            chunk.extend_from_slice(
                &resp_cipher
                    .seal(&resp_nonce, &(plain.len() as u16).to_be_bytes())
                    .unwrap(),
            );
            increment_nonce(&mut resp_nonce);
            chunk.extend_from_slice(&resp_cipher.seal(&resp_nonce, &plain).unwrap());
            increment_nonce(&mut resp_nonce);
            wr.write_all(&chunk).await.unwrap();
        }
    }
}

async fn tcp_roundtrip(method_name: &'static str, password: &'static str) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(mock_2022_server(
        listener,
        password,
        method_name,
        &TCP_TARGET_HEADER,
    ));

    let node = Node {
        name: "test-ss2022".into(),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some(method_name.to_string()),
                password: Some(password.to_string()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let handler = ShadowsocksHandler::new();
    let target: SocketAddr = TCP_TARGET.parse().unwrap();
    let mut stream = handler
        .dial(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    assert_2022_echo(&mut stream.stream).await;
}

async fn assert_2022_echo<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(stream: &mut S) {
    // First exchange (drives the response fixed-header path).
    stream.write_all(b"hello ss2022").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello ss2022");

    // Second exchange (drives the regular chunk path).
    stream.write_all(b"second message").await.unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"second message");
}

#[tokio::test]
async fn test_tcp_2022_aes_128_roundtrip() {
    tcp_roundtrip("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw==").await;
}

#[tokio::test]
async fn test_tcp_2022_aes_256_roundtrip() {
    tcp_roundtrip(
        "2022-blake3-aes-256-gcm",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    )
    .await;
}

#[tokio::test]
async fn test_tcp_2022_chacha_roundtrip() {
    tcp_roundtrip(
        "2022-blake3-chacha20-poly1305",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    )
    .await;
}

#[tokio::test]
async fn tcp_2022_roundtrip_over_a_non_tcp_stream() {
    let method_name = "2022-blake3-aes-128-gcm";
    let password = "AAECAwQFBgcICQoLDA0ODw==";
    let (client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(serve_mock_2022(
        server,
        password,
        method_name,
        &TCP_TARGET_HEADER,
    ));

    let mut node = Node {
        name: "test-ss2022-tunnel".into(),
        address: "198.51.100.1:8388".into(),
        host: "must-not-resolve.invalid".into(),
        port: 8388,
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some(method_name.into()),
                password: Some(password.into()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    let target: SocketAddr = TCP_TARGET.parse().unwrap();
    let mut stream = ShadowsocksHandler::new()
        .dial_over(
            runtime,
            Box::new(client),
            target,
            None,
            crate::proxy::TunnelDialOptions::new(std::time::Duration::from_secs(3)),
        )
        .await
        .unwrap();
    assert_2022_echo(&mut stream.stream).await;
}

#[tokio::test]
async fn test_tcp_2022_eih_roundtrip() {
    // Multi-psk: mock server asserts the EIH blocks decrypt correctly.
    tcp_roundtrip(
        "2022-blake3-aes-128-gcm",
        "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
    )
    .await;
}

/// End-to-end UDP test: mock Shadowsocks 2022 server, real
/// `dial_udp_transport`, payload exchange through the framed transport.
#[tokio::test]
async fn test_dial_udp_2022_end_to_end() {
    let psk_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_method = Ss2022Method::new("2022-blake3-aes-256-gcm", psk_b64).unwrap();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let socks = crate::proxy::addr::encode_address(target, None).unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        let mut server_packet_id = 0u64;
        loop {
            let (n, src) = server.recv_from(&mut buf).await.unwrap();
            let (client_session_id, _pid, payload) = server_open_aes(&server_method, &buf[..n]);
            let reply: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
            let packet = server_seal_udp(
                &server_method,
                client_session_id,
                0xbeef,
                server_packet_id,
                unix_timestamp(),
                &socks,
                &reply,
            );
            server_packet_id += 1;
            server.send_to(&packet, src).await.unwrap();
        }
    });

    let node = Node {
        name: "test-ss2022-udp".into(),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some("2022-blake3-aes-256-gcm".into()),
                password: Some(psk_b64.to_string()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let handler = ShadowsocksHandler::new();
    let transport = handler
        .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();

    transport.send_packet(b"quic data").await.unwrap();
    let mut buf = [0u8; 9];
    let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!(src, target);
    assert_eq!(&buf[..n], b"QUIC DATA");

    // Second datagram on the same session (packet id continuity).
    transport.send_packet(b"more data").await.unwrap();
    let (n, _src) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"MORE DATA");
}

mod shared_source;
