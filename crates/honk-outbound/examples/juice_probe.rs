//! Probe a juicity/QUIC server's handshake reachability with honk's exact
//! QUIC client stack, comparing Chrome fingerprint mode (X25519MLKEM768,
//! large Initial) vs standard mode (X25519, small Initial).
//!
//! Usage: juice_probe <host> <port> [sni]

use honk_config::node::Node;
use honk_outbound::{quic, tls};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let host = std::env::args().nth(1).expect("host");
    let port: u16 = std::env::args()
        .nth(2)
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);
    let sni = std::env::args().nth(3).unwrap_or_else(|| host.clone());

    for chrome in [true, false] {
        tls::set_tls_mode(if chrome { "utls" } else { "tls" });
        let node = Node {
            name: "probe".into(),
            host: host.clone(),
            port,
            outbound: honk_config::node::OutboundConfig::Juicity(
                honk_config::node::JuicityConfig {
                    uuid: Some("a8eb0027-f7ac-da79-12b4-5433da6fdfce".into()),
                    password: Some("33440f5a7608".into()),
                    quic: honk_config::node::QuicOptions {
                        tls: honk_config::node::TlsOptions {
                            sni: Some(sni.clone()),
                            skip_cert_verify: true,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                },
            ),
            ..Default::default()
        };
        let config = quic::client_config(
            &node,
            &[b"h3"],
            quic::QuicClientOptions::with_congestion(Some("bbr")),
        )
        .await?;
        let ip = honk_outbound::bootstrap::resolve(&host)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("resolve failed"))?;
        let addr = std::net::SocketAddr::new(ip, port);
        let mut endpoint = quic::client_endpoint(ip.is_ipv6())?;
        endpoint.set_default_client_config(config);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            endpoint.connect(addr, &sni)?,
        )
        .await;
        match result {
            Ok(Ok(conn)) => {
                println!("chrome={}: CONNECTED rtt={:?}", chrome, conn.rtt());
                conn.close(0u32.into(), b"done");
            }
            Ok(Err(e)) => println!("chrome={}: connect error: {}", chrome, e),
            Err(_) => println!("chrome={}: TIMEOUT", chrome),
        }
    }
    Ok(())
}
