//! Fixtures shared by test suites of different modules. A suite's own
//! helpers stay with that suite.

use crate::proxy::shadowsocks::{
    AeadCipher, CipherConf, ShadowsocksHandler, decrypt_chunks_in_place, hkdf_sha1_derive,
    seal_chunks_into,
};
use honk_config::node::{Node, OutboundConfig};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The test binary's allocator, counting so a test can assert that a path
/// allocates nothing. Measure in a child process: the counters are global.
#[global_allocator]
pub(crate) static ALLOCATOR: &stats_alloc::StatsAlloc<std::alloc::System> =
    &stats_alloc::INSTRUMENTED_SYSTEM;

pub(crate) fn node(name: &str, host: &str, port: u16, outbound: OutboundConfig) -> Node {
    let mut node = Node {
        name: name.into(),
        address: format!("{host}:{port}"),
        host: host.into(),
        port,
        outbound,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

pub(crate) fn socks5(name: &str, host: &str, port: u16) -> Node {
    node(name, host, port, OutboundConfig::Socks5(Default::default()))
}

pub(crate) fn chain(hops: &[&Node]) -> Node {
    Node::chain_from_nodes("via", hops).unwrap()
}

pub(crate) fn assert_score_failure_scope(
    via: &Node,
    outcomes: &[crate::group::ScoreOutcome],
    setup_completed: bool,
    exact_failures: usize,
    aggregate_failures: usize,
) {
    use crate::alive::{IpVersion, ProbeDomain};
    use crate::group::{GroupManager, ScoreOutcome, ScoreSelectionContext, SelectionNetwork};
    use honk_config::group::{Group, GroupPolicy};

    let alternate = socks5("alternate", "127.0.0.1", 1);
    let group = Group {
        name: "score".into(),
        policy: GroupPolicy::Score,
        nodes: vec![via.id, alternate.id],
        ..Default::default()
    };
    let manager = GroupManager::new(&[group], &[via.clone(), alternate]);
    let same_target = ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(IpVersion::V4),
        health_family: IpVersion::V4,
        target: Some(TCP_TARGET.parse::<SocketAddr>().unwrap().into()),
    };
    let other_target = ScoreSelectionContext {
        target: Some("198.51.100.2:80".parse::<SocketAddr>().unwrap().into()),
        ..same_target.clone()
    };
    let feedback = manager
        .feedback_for_group_node("score", via.id, same_target.clone())
        .unwrap();
    let report = |outcome, completed| {
        let reporter = feedback.start();
        if completed {
            reporter.setup_succeeded();
        }
        reporter.finish(outcome);
    };
    for &outcome in outcomes {
        report(outcome, setup_completed);
    }

    // First add exact-only failures, then calibrate aggregate failures using the
    // other target. Neither check can cross the threshold via the other scope.
    let exclusions = || manager.score_reason_snapshot()[0].tcp.fail_streak_excluded;
    for (context, failures, calibration) in [
        (&same_target, exact_failures, ScoreOutcome::TargetFailure),
        (&other_target, aggregate_failures, ScoreOutcome::NodeFailure),
    ] {
        for added in 0..=3 {
            let before = exclusions();
            let plan = manager.selection_plan_for_target("score", context);
            let excluded = failures + added >= 3;
            assert_eq!(exclusions() - before, u64::from(excluded), "{context:?}");
            if excluded {
                assert_ne!(plan.entries[0].node.id, via.id);
            }
            if added != 3 {
                report(calibration, true);
            }
        }
    }
}

/// A no-auth SOCKS5 server that relays CONNECT over real sockets, resolving
/// domains through `hosts`, or refuses every request with "connection
/// refused" while `refuse` is set. Records each requested target as written
/// on the wire.
pub(crate) struct Socks5Relay {
    pub(crate) addr: SocketAddr,
    pub(crate) refuse: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Socks5Relay {
    pub(crate) fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

pub(crate) async fn socks5_relay(
    hosts: Vec<(&'static str, SocketAddr)>,
    refuse: bool,
) -> Socks5Relay {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    let refuse = Arc::new(AtomicBool::new(refuse));
    let refusing = Arc::clone(&refuse);
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let hosts = hosts.clone();
            let log = Arc::clone(&log);
            let refuse = refusing.load(Ordering::SeqCst);
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).await.unwrap();
                let mut methods = vec![0u8; greeting[1] as usize];
                client.read_exact(&mut methods).await.unwrap();
                client.write_all(&[5, 0]).await.unwrap();
                let mut head = [0u8; 4];
                client.read_exact(&mut head).await.unwrap();
                let (host, upstream) = match head[3] {
                    1 => {
                        let mut raw = [0u8; 4];
                        client.read_exact(&mut raw).await.unwrap();
                        let port = client.read_u16().await.unwrap();
                        let addr = SocketAddr::from((raw, port));
                        (addr.to_string(), addr)
                    }
                    3 => {
                        let len = client.read_u8().await.unwrap();
                        let mut domain = vec![0u8; len as usize];
                        client.read_exact(&mut domain).await.unwrap();
                        let domain = String::from_utf8(domain).unwrap();
                        let port = client.read_u16().await.unwrap();
                        let (_, upstream) = *hosts
                            .iter()
                            .find(|(name, _)| *name == domain)
                            .expect("test relay knows every domain");
                        (format!("{domain}:{port}"), upstream)
                    }
                    other => panic!("unexpected SOCKS5 address type {other}"),
                };
                log.lock().unwrap().push(host);
                if refuse {
                    client
                        .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    return;
                }
                let mut upstream = TcpStream::connect(upstream).await.unwrap();
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    Socks5Relay {
        addr,
        refuse,
        requests,
    }
}

pub(crate) const TCP_TARGET: &str = "93.184.216.34:80";
pub(crate) const TCP_TARGET_HEADER: [u8; 7] = [1, 93, 184, 216, 34, 0, 80];

pub(crate) async fn mock_legacy_tcp_server<S: AsyncRead + AsyncWrite + Unpin>(
    mut server: S,
    mut expected_target: &[u8],
) {
    let method = "aes-128-gcm";
    let password = "test-password";
    let conf = CipherConf::for_method(method).unwrap();
    let master = ShadowsocksHandler::master_key(password, conf.key_len);

    let mut c2s_salt = vec![0u8; conf.salt_len];
    server.read_exact(&mut c2s_salt).await.unwrap();
    let mut c2s_subkey = vec![0u8; conf.key_len];
    hkdf_sha1_derive(&master, &c2s_salt, &mut c2s_subkey);
    let c2s_cipher = AeadCipher::new(method, &c2s_subkey).unwrap();
    let mut c2s_nonce = vec![0u8; conf.nonce_len];

    let mut s2c_salt = vec![0u8; conf.salt_len];
    rand::rng().fill_bytes(&mut s2c_salt);
    server.write_all(&s2c_salt).await.unwrap();
    let mut s2c_subkey = vec![0u8; conf.key_len];
    hkdf_sha1_derive(&master, &s2c_salt, &mut s2c_subkey);
    let s2c_cipher = AeadCipher::new(method, &s2c_subkey).unwrap();
    let mut s2c_nonce = vec![0u8; conf.nonce_len];

    let mut buf = vec![0u8; 262144];
    let mut carry = 0usize;
    let mut pending_len = None;
    loop {
        let n = server.read(&mut buf[carry..]).await.unwrap();
        if n == 0 {
            return;
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
        if out_len > 0 {
            let start = expected_target.len().min(out_len);
            assert_eq!(&buf[..start], &expected_target[..start], "target address");
            expected_target = &expected_target[start..];
            if start < out_len {
                let upper: Vec<u8> = buf[start..out_len]
                    .iter()
                    .map(|b| b.to_ascii_uppercase())
                    .collect();
                let mut sealed = Vec::new();
                seal_chunks_into(&s2c_cipher, &mut s2c_nonce, &upper, &mut sealed).unwrap();
                server.write_all(&sealed).await.unwrap();
            }
        }
        if rest > 0 {
            buf.copy_within(out_len..out_len + rest, 0);
        }
        carry = rest;
    }
}

/// Writes ~1MB in 8 uneven writes and expects it back uppercased.
pub(crate) async fn assert_legacy_bulk_echo<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    stream: &mut S,
) {
    let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
    let mut off = 0;
    for chunk in [3usize, 65536, 17, 262144, 999, 400_000, 131071, 271_329] {
        let end = (off + chunk).min(payload.len());
        stream.write_all(&payload[off..end]).await.unwrap();
        off = end;
    }
    assert_eq!(off, payload.len());

    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_exact(&mut received),
    )
    .await
    .expect("echo timed out")
    .unwrap();
    let expected: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
    assert_eq!(received, expected);
}
