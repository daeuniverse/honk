use super::{RealityConfig, reality_connect_with_key_shares, reality_fixup_cb, setup_reality_ssl};
use std::io::Cursor;
use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine as _;
use boring::derive::Deriver;
use boring::pkey::{Id, PKey, Private};
use boring::ssl::{SslAcceptor, SslMethod, SslVersion};
use boring::x509::X509;
use foreign_types::ForeignTypeRef as _;
use futures_util::FutureExt as _;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use honk_config::node::{Node, OutboundConfig, TlsOptions, TrojanConfig};
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::proxy::transport::{MaybeTls, maybe_tls_wrap_concrete};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const CLIENT_DATA: &[u8] = b"authenticated client data";
const SERVER_DATA: &[u8] = b"authenticated server data";

#[derive(Clone, Copy)]
enum Reply {
    Mask,
    Authenticated,
    InvalidHmac,
    TlsAlert,
}

struct Captured {
    peer: SocketAddr,
    hello: Vec<u8>,
}

fn node(addr: SocketAddr, key: &PKey<Private>, supplied: bool) -> Node {
    let mut public = [0; 32];
    key.raw_public_key(&mut public).unwrap();
    Node {
        // A supplied socket must retry its peer, not resolve the node again.
        host: if supplied {
            "must-not-resolve.invalid".into()
        } else {
            addr.ip().to_string()
        },
        port: addr.port(),
        outbound: OutboundConfig::Trojan(TrojanConfig {
            tls: TlsOptions {
                enabled: true,
                sni: Some("localhost".into()),
                reality_public_key: Some(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public),
                ),
                reality_short_id: Some("1919191919191919".into()),
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn read_hello(tcp: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    let mut record = vec![0; 5];
    tcp.read_exact(&mut record).await.unwrap();
    assert_eq!(record[0], 22);
    let len = u16::from_be_bytes([record[3], record[4]]) as usize;
    record.resize(5 + len, 0);
    tcp.read_exact(&mut record[5..]).await.unwrap();
    assert_eq!(record[5], 1);
    assert_eq!(record[5 + 38], 32);
    record
}

fn key_shares(hello: &[u8]) -> Vec<(u16, &[u8])> {
    let mut cursor = 71;
    cursor += 2 + u16::from_be_bytes([hello[cursor], hello[cursor + 1]]) as usize;
    cursor += 1 + hello[cursor] as usize;
    let end = cursor + 2 + u16::from_be_bytes([hello[cursor], hello[cursor + 1]]) as usize;
    cursor += 2;
    while cursor < end {
        let kind = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
        let len = u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]) as usize;
        cursor += 4;
        if kind == 51 {
            let mut shares = Vec::new();
            let mut share = cursor + 2;
            while share < cursor + len {
                let group = u16::from_be_bytes([hello[share], hello[share + 1]]);
                let size = u16::from_be_bytes([hello[share + 2], hello[share + 3]]) as usize;
                share += 4;
                shares.push((group, &hello[share..share + size]));
                share += size;
            }
            shares.retain(|(group, _)| group >> 8 != group & 0xff || group & 0x0f != 0x0a);
            return shares;
        }
        cursor += len;
    }
    panic!("ClientHello omitted key_share");
}

fn authenticate_hello(hello: &[u8], server_key: &PKey<Private>) -> [u8; 32] {
    let shares = key_shares(hello);
    let classic = shares.iter().find(|(group, _)| *group == 29).unwrap().1;
    // RFC 8410 X25519 SubjectPublicKeyInfo, decoded through the safe API.
    let mut public_der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0,
    ];
    public_der.extend_from_slice(classic);
    let public = PKey::public_key_from_der(&public_der).unwrap();
    let mut derive = Deriver::new(server_key).unwrap();
    derive.set_peer(&public).unwrap();
    let shared = derive.derive_to_vec().unwrap();
    let mut auth_key = [0; 32];
    Hkdf::<Sha256>::new(Some(&hello[6..26]), &shared)
        .expand(b"REALITY", &mut auth_key)
        .unwrap();
    let mut aad = hello.to_vec();
    aad[39..71].fill(0);
    let mut sealed = hello[39..71].to_vec();
    let (plaintext, tag) = sealed.split_at_mut(16);
    boring::aead::AeadCtx::new_default_tag(&boring::aead::Algorithm::aes_256_gcm(), &auth_key)
        .unwrap()
        .open_in_place(&hello[26..38], plaintext, tag, &aad)
        .unwrap();
    assert_eq!(&plaintext[8..], &[0x19; 8]);
    auth_key
}

fn acceptor(reply: Reply, auth_key: &[u8; 32]) -> SslAcceptor {
    let key = if matches!(reply, Reply::Mask) {
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap()
    } else {
        // BoringSSL requires PKCS#8 v1; rcgen's Ed25519 generator emits v2.
        let key = PKey::generate(Id::ED25519).unwrap();
        rcgen::KeyPair::try_from(key.private_key_to_der_pkcs8().unwrap()).unwrap()
    };
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let key = PKey::private_key_from_der(&key.serialize_der()).unwrap();
    let mut der = cert.der().to_vec();
    if !matches!(reply, Reply::Mask) {
        let mut public = [0; 32];
        key.raw_public_key(&mut public).unwrap();
        let mut mac = Hmac::<Sha512>::new_from_slice(auth_key).unwrap();
        mac.update(&public);
        let mut signature = mac.finalize().into_bytes();
        if matches!(reply, Reply::InvalidHmac) {
            signature[0] ^= 1;
        }
        // Ed25519's final DER BIT STRING is 64 signature bytes, no unused bits.
        let offset = der.len() - 64;
        assert_eq!(&der[offset - 3..offset], &[0x03, 0x41, 0]);
        der[offset..].copy_from_slice(&signature);
    }
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    acceptor.set_curves_list("X25519").unwrap();
    acceptor
        .set_certificate(&X509::from_der(&der).unwrap())
        .unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.build()
}

async fn serve(listener: &TcpListener, reply: Reply, key: &PKey<Private>) -> Captured {
    let (mut tcp, peer) = listener.accept().await.unwrap();
    let record = read_hello(&mut tcp).await;
    let hello = record[5..].to_vec();
    let auth_key = if matches!(reply, Reply::Authenticated | Reply::InvalidHmac) {
        authenticate_hello(&hello, key)
    } else {
        [0; 32]
    };
    if matches!(reply, Reply::TlsAlert) {
        tcp.write_all(&[21, 3, 3, 0, 2, 2, 80]).await.unwrap();
        let mut received = Vec::new();
        tcp.read_to_end(&mut received).await.ok();
    } else {
        let (read, write) = tcp.into_split();
        let replay = tokio::io::join(Cursor::new(record).chain(read), write);
        let mut tls = tokio_boring::accept(&acceptor(reply, &auth_key), replay)
            .await
            .unwrap();
        // Send before the client's post-handshake authentication; a failure must
        // never publish this stream or let the client write application bytes.
        tls.write_all(SERVER_DATA).await.ok();
        let mut received = Vec::new();
        tls.read_to_end(&mut received).await.ok();
        if matches!(reply, Reply::Authenticated) {
            assert_eq!(received, CLIENT_DATA);
        } else {
            assert!(
                received.is_empty(),
                "application data escaped failed REALITY auth"
            );
        }
    }
    Captured { peer, hello }
}

async fn exchange(node: &Node, tcp: Option<TcpStream>) -> anyhow::Result<Vec<u8>> {
    let MaybeTls::Tls(mut tls) = maybe_tls_wrap_concrete(node, tcp, CONNECT_TIMEOUT).await? else {
        panic!("REALITY returned plaintext");
    };
    tls.write_all(CLIENT_DATA).await?;
    let mut received = vec![0; SERVER_DATA.len()];
    tls.read_exact(&mut received).await?;
    Ok(received)
}

async fn exercise(replies: &[Reply], supplied: bool) -> Vec<Captured> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let key = PKey::generate(Id::X25519).unwrap();
        let node = node(addr, &key, supplied);
        let (registry, _) =
            crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
                &[],
                1,
                1,
                1,
                None,
            )
            .unwrap();
        let client = async {
            let tcp = if supplied {
                Some(TcpStream::connect(addr).await.unwrap())
            } else {
                None
            };
            exchange(&node, tcp).await
        };
        let server = async {
            let mut captured = Vec::new();
            for reply in replies {
                captured.push(serve(&listener, *reply, &key).await);
            }
            captured
        };
        let (result, captured) = tokio::join!(registry.scope_dials(client), server);
        if matches!(replies.last(), Some(Reply::Authenticated)) {
            assert_eq!(result.unwrap(), SERVER_DATA);
        } else {
            assert!(
                result.is_err(),
                "unauthenticated REALITY connection succeeded"
            );
        }
        assert!(
            listener.accept().now_or_never().is_none(),
            "unexpected extra dial"
        );
        captured
    })
    .await
    .unwrap()
}

fn assert_fresh_classical_retry(captured: &[Captured]) {
    assert_eq!(captured.len(), 2);
    let first = &captured[0];
    let second = &captured[1];
    assert_ne!(first.peer, second.peer);
    let first_shares = key_shares(&first.hello);
    let second_shares = key_shares(&second.hello);
    assert_eq!(
        first_shares
            .iter()
            .map(|(group, _)| *group)
            .collect::<Vec<_>>(),
        [0x11ec, 29]
    );
    assert_eq!(
        second_shares
            .iter()
            .map(|(group, _)| *group)
            .collect::<Vec<_>>(),
        [29]
    );
    assert_ne!(&first.hello[6..38], &second.hello[6..38]);
    assert_ne!(&first.hello[26..38], &second.hello[26..38]);
    assert_ne!(first_shares[1].1, second_shares[0].1);
}

#[tokio::test]
async fn mask_retries_fresh_classical_and_only_authenticated_stream_carries_data() {
    for supplied in [false, true] {
        let captured = exercise(&[Reply::Mask, Reply::Authenticated], supplied).await;
        assert_fresh_classical_retry(&captured);
    }
    assert_eq!(exercise(&[Reply::Authenticated], false).await.len(), 1);
}

#[tokio::test]
async fn supplied_fallback_waits_for_capacity_without_spending_sibling_credit() {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sibling_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let key = PKey::generate(Id::X25519).unwrap();
        let node = node(listener.local_addr().unwrap(), &key, true);
        let (registry, _) =
            crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
                &[],
                2,
                2,
                2,
                None,
            )
            .unwrap();
        let occupied = registry.acquire_dial_permit().await;
        let (sibling, scope) = registry
            .scope_dials(async {
                let sibling = crate::runtime::admit_physical_dial(TcpStream::connect(
                    sibling_listener.local_addr().unwrap(),
                ))
                .await
                .unwrap();
                (sibling, crate::runtime::capture_dial_scope())
            })
            .await;
        let tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let mut client = Box::pin(scope.clone().scope(exchange(&node, Some(tcp))));
        let first = tokio::select! {
            captured = serve(&listener, Reply::Mask, &key) => captured,
            result = &mut client => panic!("fallback completed before mask exchange: {result:?}"),
        };
        assert!(timeout(Duration::from_millis(20), async {
            tokio::select! {
                _ = listener.accept() => panic!("supplied fallback spent a sibling's credit"),
                result = &mut client => panic!("fallback completed without capacity: {result:?}"),
            }
        }).await.is_err());
        drop(occupied);
        let (result, second) = tokio::join!(client, serve(&listener, Reply::Authenticated, &key));
        assert_eq!(result.unwrap(), SERVER_DATA);
        assert_fresh_classical_retry(&[first, second]);
        assert!(
            timeout(Duration::from_millis(20), registry.acquire_dial_permit())
                .await
                .is_err()
        );
        drop((sibling, scope));
        timeout(Duration::from_secs(1), registry.acquire_dial_permit())
            .await
            .unwrap();
        assert!(listener.accept().now_or_never().is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn second_authentication_failure_is_final_without_application_data() {
    for second in [Reply::Mask, Reply::InvalidHmac] {
        let captured = exercise(&[Reply::Mask, second], false).await;
        assert_fresh_classical_retry(&captured);
    }
}

#[tokio::test]
async fn invalid_ed25519_hmac_and_tls_errors_never_retry() {
    for reply in [Reply::InvalidHmac, Reply::TlsAlert] {
        assert_eq!(exercise(&[reply], true).await.len(), 1);
    }
}

#[tokio::test]
async fn cancelling_classical_handshake_drops_the_replacement_socket() {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let key = PKey::generate(Id::X25519).unwrap();
        let node = node(listener.local_addr().unwrap(), &key, false);
        let client =
            tokio::spawn(
                async move { maybe_tls_wrap_concrete(&node, None, CONNECT_TIMEOUT).await },
            );
        serve(&listener, Reply::Mask, &key).await;
        let (mut tcp, _) = listener.accept().await.unwrap();
        read_hello(&mut tcp).await;
        client.abort();
        assert!(client.await.err().unwrap().is_cancelled());
        let mut remaining = Vec::new();
        tcp.read_to_end(&mut remaining).await.unwrap();
        assert!(listener.accept().now_or_never().is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn setup_deadline_includes_the_replacement_handshake() {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let key = PKey::generate(Id::X25519).unwrap();
        let node = node(listener.local_addr().unwrap(), &key, false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let client = tokio::spawn(async move {
            started_tx.send(tokio::time::Instant::now()).unwrap();
            maybe_tls_wrap_concrete(&node, None, CONNECT_TIMEOUT).await
        });
        let started = started_rx.await.unwrap();
        tokio::time::sleep(CONNECT_TIMEOUT).await;
        serve(&listener, Reply::Mask, &key).await;
        let (mut tcp, _) = listener.accept().await.unwrap();
        read_hello(&mut tcp).await;
        tokio::time::pause();
        let remaining = (3 * CONNECT_TIMEOUT).saturating_sub(started.elapsed());
        tokio::time::advance(remaining + Duration::from_millis(50)).await;
        assert!(
            timeout(Duration::from_millis(1), client)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let mut remaining = Vec::new();
        tcp.read_to_end(&mut remaining).await.unwrap();
        assert!(listener.accept().now_or_never().is_none());
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn setup_deadline_includes_initial_dial_admission() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let key = PKey::generate(Id::X25519).unwrap();
    let node = node(listener.local_addr().unwrap(), &key, false);
    let (registry, _) = crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        &[],
        1,
        1,
        1,
        None,
    )
    .unwrap();
    let _occupied = registry.acquire_dial_permit().await;
    let result = timeout(
        4 * CONNECT_TIMEOUT,
        registry.scope_dials(maybe_tls_wrap_concrete(&node, None, CONNECT_TIMEOUT)),
    )
    .await
    .expect("REALITY setup must time out before admission becomes available");
    let error = result
        .err()
        .expect("unadmitted REALITY dial cannot succeed");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert!(listener.accept().now_or_never().is_none());
}

#[tokio::test]
async fn both_tls_and_key_share_profiles_authenticate_the_full_transcript() {
    timeout(Duration::from_secs(3), async {
        let key = PKey::generate(Id::X25519).unwrap();
        let mut public_key = [0; 32];
        key.raw_public_key(&mut public_key).unwrap();
        let config = RealityConfig {
            public_key,
            short_id: [0x19; 8],
            server_name: "localhost".into(),
        };
        for chrome in [false, true] {
            for hybrid in [false, true] {
                let (client, mut peer) = tokio::io::duplex(16 * 1024);
                let server = async {
                    let record = read_hello(&mut peer).await;
                    let hello = &record[5..];
                    let shares: Vec<_> = key_shares(hello)
                        .into_iter()
                        .map(|(group, bytes)| (group, bytes.len()))
                        .collect();
                    let expected = if hybrid {
                        vec![(0x11ec, 1184 + 32), (29, 32)]
                    } else {
                        vec![(29, 32)]
                    };
                    assert_eq!(shares, expected, "chrome={chrome}, hybrid={hybrid}");
                    authenticate_hello(hello, &key);
                    peer.write_all(&[21, 3, 3, 0, 2, 2, 80]).await.unwrap();
                };
                let (result, ()) = tokio::join!(
                    reality_connect_with_key_shares(client, &config, chrome, hybrid),
                    server,
                );
                assert!(result.is_err());
            }
        }
    })
    .await
    .unwrap();
}

#[test]
fn repeated_client_hello_is_rejected_without_resealing() {
    let connector = crate::tls::build_reality_connector(false).unwrap();
    let ssl = connector.configure().unwrap();
    setup_reality_ssl(
        &ssl,
        &RealityConfig {
            public_key: [7; 32],
            short_id: [0; 8],
            server_name: "localhost".into(),
        },
        true,
    )
    .unwrap();
    let mut hello = vec![1, 0, 0, 0x4d, 3, 3];
    hello.extend_from_slice(&[0x33; 32]);
    hello.push(32);
    hello.extend_from_slice(&[0; 32]);
    hello.extend(0xa0..0xb0);
    assert_eq!(
        reality_fixup_cb(ssl.as_ptr(), hello.as_mut_ptr(), hello.len()),
        1
    );
    let sealed = hello.clone();
    assert_eq!(
        reality_fixup_cb(ssl.as_ptr(), hello.as_mut_ptr(), hello.len()),
        0
    );
    assert_eq!(hello, sealed);
}
