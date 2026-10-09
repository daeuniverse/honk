//! Split upload/download interop with a live Xray server (`.agents/rules/maintainer-lab.md`).

use super::*;
use crate::proxy::ProxyRegistry;

fn lab_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

async fn echo(
    registry: &ProxyRegistry,
    runtime: Arc<NodeRuntime>,
    target: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let entry = registry
        .find(runtime.node.protocol())
        .expect("handler is registered; VLESS needs --features rprx");
    let stream = entry
        .tcp
        .dial_runtime(runtime, target, None, DEADLINE)
        .await?;
    let (mut reader, mut writer) = tokio::io::split(stream.stream);
    let sent: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let mut received = vec![0; sent.len()];
    tokio::try_join!(
        async {
            writer.write_all(&sent).await?;
            writer.flush().await
        },
        reader.read_exact(&mut received),
    )?;
    anyhow::ensure!(received == sent, "echo payload mismatch");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires HONK_XHTTP_SPLIT_LINK and a TCP+UDP HONK_XHTTP_SPLIT_ECHO from the maintainer lab"]
async fn lab_split_peers_roundtrip_and_an_untrusted_download_fails_closed() {
    let base = Node::from_share_link(&lab_env("HONK_XHTTP_SPLIT_LINK")).unwrap();
    let target = lab_env("HONK_XHTTP_SPLIT_ECHO").parse().unwrap();
    let registry = ProxyRegistry::default_resolver().unwrap();
    for mode in [XhttpMode::Auto, XhttpMode::PacketUp, XhttpMode::StreamUp] {
        let mut node = base.clone();
        node.transport_mut().unwrap().xhttp.as_mut().unwrap().mode = mode;
        node.normalize_stream_transport().unwrap();
        node.id = node.derive_id();
        // The lab certificate is self-signed; production download peers always verify.
        let mut view = node
            .xhttp_download_view()
            .expect("the lab link carries downloadSettings");
        view.tls_mut().unwrap().skip_cert_verify = true;
        let transport = XhttpRuntime::with_download(&node, Some(view));
        let lab = EphemeralRuntimeGuard::with_xhttp(&node, transport.clone());
        // Speculative UDP is the path whose winner commit publishes both peers.
        let udp = registry
            .find(node.protocol())
            .and_then(|entry| entry.packet.clone())
            .expect("UDP handler is registered")
            .dial_udp_transport_speculative_runtime(lab.runtime(), target, None, DEADLINE)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        for pool in transport.pools() {
            assert_eq!(pool.live_session_count(), 1, "{mode:?}");
        }
        for size in [64, 1200, 4096] {
            let sent: Vec<u8> = (0..size).map(|i| (i % 249) as u8).collect();
            udp.send_packet_confirmed(&sent).await.unwrap();
            let mut received = vec![0; size];
            let (length, peer) = udp.recv_packet(&mut received).await.unwrap();
            assert_eq!((&received[..length], peer), (&sent[..], target));
        }
        for _ in 0..2 {
            echo(&registry, lab.runtime(), target).await.unwrap();
        }
        let production = NodeRuntime::try_ephemeral_guarded(&node).unwrap();
        let error = echo(&registry, production.runtime(), target)
            .await
            .expect_err("an untrusted download certificate must fail closed");
        assert!(
            format!("{error:#}").contains("certificate"),
            "{mode:?}: {error:#}"
        );
    }
}
