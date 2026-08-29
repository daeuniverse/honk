//! Manual ECH probe: discover the ECHConfigList via DNS HTTPS RR (or fall
//! back to GREASE), complete a real TLS handshake, and print the negotiated
//! ALPN + `ech_accepted` plus the first bytes of an HTTP response.
//!
//! Usage:
//!   ech_probe <host> [bootstrap-dns] [--skip-verify]
//!
//! Example:
//!   ech_probe defo.ie 223.5.5.5:53
//!   ech_probe www.baidu.com 223.5.5.5:53   # no ECH keys: GREASE only

use honk_config::node::Node;
use honk_outbound::{bootstrap, tls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "defo.ie".to_string());
    let resolver = args.next();
    let skip_verify = std::env::args().any(|a| a == "--skip-verify");

    if let Some(r) = resolver {
        bootstrap::set_global(bootstrap::BootstrapResolver::parse(&r));
    }
    // Chrome mode: real ECH when a config is discovered, ECH GREASE
    // otherwise (what a real browser does).
    tls::set_tls_mode("utls");

    let discovered = tls::discover_ech_config(&host).await;
    println!(
        "ech discovery: {}",
        if discovered.is_some() {
            "found ECHConfigList via DNS HTTPS RR"
        } else {
            "no ECHConfigList (GREASE only)"
        }
    );

    let node = Node {
        name: "ech-probe".into(),
        outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
            tls: honk_config::node::TlsOptions {
                ech_enabled: true,
                skip_cert_verify: skip_verify,
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    let connector = tls::build_connector(&node)?;

    let ip = bootstrap::resolve(&host)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address for {host}"))?;
    let tcp = tokio::net::TcpStream::connect((ip, 443)).await?;
    let mut stream = connector.connect(&host, tcp).await?;

    println!(
        "alpn={} ech_accepted={}",
        stream
            .ssl()
            .selected_alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .unwrap_or_else(|| "<none>".into()),
        stream.ssl().ech_accepted()
    );

    let req = format!(
        "GET /ech-check.php HTTP/1.1\r\nHost: {host}\r\nUser-Agent: honk-ech-probe\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    let body = String::from_utf8_lossy(&buf);
    let show: String = body.chars().take(400).collect();
    println!("--- response head ---\n{show}");
    Ok(())
}
