use super::*;
use crate::proxy::shadowsocks::{CipherConf, ShadowsocksHandler, hkdf_sha1_derive};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const METHOD: &str = "aes-128-gcm";
const PASSWORD: &str = "test-password";

fn ciphers(master: &[u8], c2s_salt: &[u8], s2c_salt: &[u8]) -> (AeadCipher, AeadCipher) {
    let conf = CipherConf::for_method(METHOD).unwrap();
    let mut c2s_subkey = vec![0u8; conf.key_len];
    hkdf_sha1_derive(master, c2s_salt, &mut c2s_subkey);
    let mut s2c_subkey = vec![0u8; conf.key_len];
    hkdf_sha1_derive(master, s2c_salt, &mut s2c_subkey);
    (
        AeadCipher::new(METHOD, &c2s_subkey).unwrap(),
        AeadCipher::new(METHOD, &s2c_subkey).unwrap(),
    )
}

fn legacy_stream(
    server: TcpStream,
    send_cipher: AeadCipher,
    recv_cipher: AeadCipher,
) -> SsStream<TcpStream> {
    SsStream::new(
        server,
        send_cipher,
        vec![0u8; 12],
        recv_cipher,
        vec![0u8; 12],
    )
}

#[tokio::test]
async fn authenticated_stream_corruption_is_a_node_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut peer, _) = listener.accept().await.unwrap();
    let conf = CipherConf::for_method(METHOD).unwrap();
    let master = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
    let (send, recv) = ciphers(&master, &[7; 16], &[9; 16]);
    let mut stream = legacy_stream(client, send, recv);
    peer.write_all(&[0; 18]).await.unwrap();
    let error = tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        crate::group::ScoreOutcome::from_io_error(&error),
        crate::group::ScoreOutcome::NodeFailure
    );
}

/// AsyncWrite contract: a peer that accepts only a few bytes at a time
/// (forcing Pending flushes) must still receive a byte-exact stream,
/// and a write issued after a Pending must not lose or duplicate data.
#[tokio::test]
async fn poll_write_contract_under_backpressure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conf = CipherConf::for_method(METHOD).unwrap();
    let master = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
    let c2s_salt = vec![7u8; conf.salt_len];
    let s2c_salt = vec![9u8; conf.salt_len];
    let (send_cipher, peer_read_cipher) = ciphers(&master, &c2s_salt, &s2c_salt);

    let peer_salt = c2s_salt;
    let peer = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        // Slow reader: tiny reads with a delay so the writer's flush
        // path repeatedly hits Pending.
        let mut plain_seen = Vec::new();
        let mut buf = vec![0u8; RECV_BUF_CAP];
        let mut carry = 0usize;
        let mut pending_len = None;
        let mut nonce = vec![0u8; 12];
        let conf = CipherConf::for_method(METHOD).unwrap();
        let m = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
        let mut subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(&m, &peer_salt, &mut subkey);
        let read_cipher = AeadCipher::new(METHOD, &subkey).unwrap();
        loop {
            let end = (carry + 977).min(buf.len());
            let n = sock.read(&mut buf[carry..end]).await.unwrap();
            if n == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            let total = carry + n;
            let (out_len, rest) = decrypt_chunks_in_place(
                &read_cipher,
                &mut nonce,
                &mut pending_len,
                &mut buf,
                total,
                conf.tag_len,
            )
            .unwrap();
            plain_seen.extend_from_slice(&buf[..out_len]);
            if rest > 0 {
                buf.copy_within(out_len..out_len + rest, 0);
            }
            carry = rest;
            if plain_seen.len() >= 300_000 {
                break;
            }
        }
        let expected: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(plain_seen, expected);
    });

    let client = TcpStream::connect(addr).await.unwrap();
    let mut stream = legacy_stream(client, send_cipher, peer_read_cipher);
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    // Many writes of varying size; write_all retries transparently.
    let mut off = 0;
    for chunk in [100_000usize, 1, 77, 150_000, 49_922] {
        let end = (off + chunk).min(payload.len());
        stream.write_all(&payload[off..end]).await.unwrap();
        off = end;
    }
    assert_eq!(off, payload.len());
    stream.flush().await.unwrap();
    drop(stream);
    peer.await.unwrap();
}

/// Legacy AEAD: a server that sends its response salt only AFTER the
/// first client payload chunk (the strictest valid behavior) must not
/// deadlock dial() and must receive that first chunk.
#[tokio::test]
async fn legacy_deferred_response_salt() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conf = CipherConf::for_method(METHOD).unwrap();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let m = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
        // Client salt, then the header chunk (sealed).
        let mut c2s_salt = vec![0u8; conf.salt_len];
        sock.read_exact(&mut c2s_salt).await.unwrap();
        let mut subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(&m, &c2s_salt, &mut subkey);
        let c2s_cipher = AeadCipher::new(METHOD, &subkey).unwrap();
        let mut c2s_nonce = vec![0u8; conf.nonce_len];

        // Read until BOTH the header chunk and the first payload chunk
        // have arrived (they may share one TCP segment).
        let mut buf = vec![0u8; 8192];
        let mut carry = 0usize;
        let mut pending_len = None;
        let mut plain_seen: Vec<u8> = Vec::new();
        let header_len = 4usize; // "t:80"
        while plain_seen.len() < header_len + 4 {
            let n = sock.read(&mut buf[carry..]).await.unwrap();
            if n == 0 {
                panic!("client closed before first payload");
            }
            let total = carry + n;
            let (out_len, rest) = decrypt_chunks_in_place(
                &c2s_cipher,
                &mut c2s_nonce,
                &mut pending_len,
                &mut buf,
                total,
                conf.tag_len,
            )
            .unwrap();
            plain_seen.extend_from_slice(&buf[..out_len]);
            if rest > 0 {
                buf.copy_within(out_len..out_len + rest, 0);
            }
            carry = rest;
        }
        assert_eq!(&plain_seen[..header_len], b"t:80");
        assert_eq!(&plain_seen[header_len..header_len + 4], b"ping");
        sock.write_all(&[9u8; 16]).await.unwrap();
        let mut s2c_subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(&m, &[9u8; 16], &mut s2c_subkey);
        let s2c_cipher = AeadCipher::new(METHOD, &s2c_subkey).unwrap();
        let mut s2c_nonce = vec![0u8; conf.nonce_len];
        let mut sealed = Vec::new();
        seal_chunks_into(&s2c_cipher, &mut s2c_nonce, b"pong", &mut sealed).unwrap();
        sock.write_all(&sealed).await.unwrap();
    });

    let node_server = TcpStream::connect(addr).await.unwrap();
    let send_master = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
    let c2s_salt = vec![7u8; conf.salt_len];
    let mut send_subkey = vec![0u8; conf.key_len];
    hkdf_sha1_derive(&send_master, &c2s_salt, &mut send_subkey);
    let send_cipher = AeadCipher::new(METHOD, &send_subkey).unwrap();

    let mut server = node_server;
    server.write_all(&c2s_salt).await.unwrap();
    let mut send_nonce = vec![0u8; conf.nonce_len];
    write_all_sealed(&mut server, &send_cipher, &mut send_nonce, b"t:80")
        .await
        .unwrap();

    let prologue = LegacyPrologue {
        conf,
        master_key: send_master,
        method: METHOD.to_string(),
    };
    // Emulate the handler's legacy dial tail through its production constructor.
    let mut stream = SsStream::new_legacy(server, send_cipher, send_nonce, prologue);
    // The payload goes out BEFORE the server salt exists anywhere.
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut buf),
    )
    .await
    .expect("response timed out")
    .unwrap();
    assert_eq!(&buf, b"pong");
}

/// EOF with a truncated chunk tail is UnexpectedEof, not a clean close.
#[tokio::test]
async fn truncated_tail_is_unexpected_eof() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conf = CipherConf::for_method(METHOD).unwrap();
    let master = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
    let c2s_salt = vec![7u8; conf.salt_len];
    let s2c_salt = vec![9u8; conf.salt_len];
    let (send_cipher, peer_read_cipher) = ciphers(&master, &c2s_salt, &s2c_salt);

    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        // Close immediately after a partial write (garbage tail).
        drop(sock);
    });

    let client = TcpStream::connect(addr).await.unwrap();
    let mut stream = legacy_stream(client, send_cipher, peer_read_cipher);
    // Manually place a truncated chunk into the recv path: seal a chunk
    // with the peer's cipher, feed only half of it via the socket.
    let mut sealed = Vec::new();
    let peer_master = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
    let mut sub = vec![0u8; conf.key_len];
    hkdf_sha1_derive(&peer_master, &s2c_salt, &mut sub);
    let s2c = AeadCipher::new(METHOD, &sub).unwrap();
    let mut nonce = vec![0u8; 12];
    seal_chunks_into(&s2c, &mut nonce, b"hello-tail", &mut sealed).unwrap();
    stream.recv_buf[..sealed.len() / 2].copy_from_slice(&sealed[..sealed.len() / 2]);
    stream.carry = sealed.len() / 2;
    let mut buf = [0u8; 64];
    let err = stream
        .read(&mut buf)
        .await
        .expect_err("must fail on truncated tail");
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn tcp_carrier_samples_transport_pressure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut peer, _) = listener.accept().await.unwrap();
    let quality = std::sync::Arc::new(crate::transport_quality::TransportQuality::default());
    quality.enable();
    let conf = CipherConf::for_method(METHOD).unwrap();
    let master = ShadowsocksHandler::master_key(PASSWORD, conf.key_len);
    let (send, recv) = ciphers(&master, &[7; 16], &[9; 16]);
    let mut stream = quality
        .scope(async move { legacy_stream(client, send, recv) })
        .await;
    assert!(stream.pressure.delivered_sample().is_none());

    let started = std::time::Instant::now();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let flushed = std::time::Instant::now();
    let mut sealed = [0; 2 + 16 + 4 + 16];
    peer.read_exact(&mut sealed).await.unwrap();

    let sample = stream
        .pressure
        .delivered_sample()
        .expect("the authenticated write samples the socket");
    assert!((started..=flushed).contains(&sample.at));
}
