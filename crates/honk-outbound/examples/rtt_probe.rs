//! Probe QUIC session resumption / 0-RTT acceptance against a live server:
//! runs two sequential handshakes over one shared client config (session
//! ticket cache) and reports handshake times, resumption, and whether the
//! server accepted early data.
//!
//! Usage: rtt_probe <host> <port> <sni> <alpn> [rounds]

use std::net::SocketAddr;
use std::time::Instant;

use honk_config::node::Node;
use honk_outbound::{quic, quic_boring::BoringHandshakeData};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let host = std::env::args().nth(1).expect("host");
    let port: u16 = std::env::args().nth(2).expect("port").parse()?;
    let sni = std::env::args().nth(3).unwrap_or_else(|| host.clone());
    let alpn = std::env::args().nth(4).unwrap_or_else(|| "tuic".into());
    let rounds: usize = std::env::args()
        .nth(5)
        .and_then(|r| r.parse().ok())
        .unwrap_or(2);

    let node = Node {
        name: "probe".into(),
        host: host.clone(),
        port,
        outbound: honk_config::node::OutboundConfig::Hysteria2(
            honk_config::node::Hysteria2Config {
                quic: honk_config::node::QuicOptions {
                    tls: honk_config::node::TlsOptions {
                        sni: Some(sni.clone()),
                        skip_cert_verify: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let config = quic::client_config(&node, &[alpn.as_bytes()], Default::default()).await?;
    let addr: SocketAddr = format!("{host}:{port}").parse()?;

    for i in 0..rounds {
        let mut endpoint = quic::client_endpoint(addr.is_ipv6())?;
        endpoint.set_default_client_config(config.clone());
        let t0 = Instant::now();
        match endpoint.connect(addr, &sni)?.await {
            Ok(conn) => {
                let hs = t0.elapsed();
                let data = conn
                    .handshake_data()
                    .and_then(|d| d.downcast::<BoringHandshakeData>().ok());
                let (suite, reused, early) = data
                    .map(|d| (d.cipher_suite, d.session_reused, d.early_data_accepted))
                    .unwrap_or((0, false, false));
                println!(
                    "hs{i}: {:?} rtt={:?} suite=0x{suite:04x} session_reused={reused} early_data_accepted={early}",
                    hs,
                    conn.rtt()
                );
                conn.close(0u32.into(), b"done");
            }
            Err(e) => println!("hs{i}: connect error: {e}"),
        }
        // Let the session ticket arrive before the next round.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    Ok(())
}
