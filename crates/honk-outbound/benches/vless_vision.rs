//! VLESS Vision framed and direct-copy throughput over loopback TLS 1.3.

use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use honk_config::node::{Node, OutboundConfig, VlessConfig};
use honk_outbound::proxy::TcpOutbound;
use honk_outbound::proxy::vless::VLessHandler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID_TEXT: &str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
const UUID_BYTES: [u8; 16] = [
    0xb5, 0xbc, 0x10, 0xa6, 0x5c, 0x72, 0x4f, 0xd0, 0x9f, 0x62, 0x15, 0xc2, 0xb9, 0xf8, 0xa7, 0xd3,
];
const PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const FRAME_CONTENT_BYTES: usize = 16 * 1024;
const FRAME_PADDING_BYTES: usize = 257;
const SOURCE_CHUNK_BYTES: usize = 16 * 1024;
const REQUEST_HEADER_BYTES: usize = 1 + 16 + 1 + 18 + 1 + 2 + 1 + 4;
const VISION_COMMAND_END: u8 = 1;
const VISION_COMMAND_DIRECT: u8 = 2;

fn append_frame(wire: &mut Vec<u8>, command: u8, content_len: usize, seed: usize) {
    wire.push(command);
    wire.extend_from_slice(&(content_len as u16).to_be_bytes());
    wire.extend_from_slice(&(FRAME_PADDING_BYTES as u16).to_be_bytes());
    wire.extend((0..content_len).map(|offset| ((seed + offset) % 251) as u8));
    wire.resize(wire.len() + FRAME_PADDING_BYTES, 0);
}

fn framed_wire() -> Arc<Vec<u8>> {
    let frame_count = PAYLOAD_BYTES / FRAME_CONTENT_BYTES;
    let mut wire =
        Vec::with_capacity(2 + 16 + PAYLOAD_BYTES + frame_count * (5 + FRAME_PADDING_BYTES));
    wire.extend_from_slice(&[0, 0]);
    wire.extend_from_slice(&UUID_BYTES);
    for frame in 0..frame_count {
        let command = if frame + 1 == frame_count {
            VISION_COMMAND_END
        } else {
            0
        };
        append_frame(
            &mut wire,
            command,
            FRAME_CONTENT_BYTES,
            frame * FRAME_CONTENT_BYTES,
        );
    }
    Arc::new(wire)
}

fn direct_wire() -> Arc<Vec<u8>> {
    let mut wire = Vec::with_capacity(2 + 16 + PAYLOAD_BYTES + 5 + FRAME_PADDING_BYTES);
    wire.extend_from_slice(&[0, 0]);
    wire.extend_from_slice(&UUID_BYTES);
    append_frame(&mut wire, VISION_COMMAND_DIRECT, FRAME_CONTENT_BYTES, 0);
    wire.extend((FRAME_CONTENT_BYTES..PAYLOAD_BYTES).map(|offset| (offset % 251) as u8));
    Arc::new(wire)
}

async fn spawn_server(wire: Arc<Vec<u8>>, direct: bool) -> SocketAddr {
    use boring::pkey::PKey;
    use boring::ssl::{SslAcceptor, SslMethod, SslVersion};
    use boring::x509::X509;

    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_pem(cert.pem().as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap())
        .unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let acceptor = Arc::new(acceptor.build());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let wire = Arc::clone(&wire);
            let acceptor = Arc::clone(&acceptor);
            tokio::spawn(async move {
                let mut socket = tokio_boring::accept(&acceptor, socket).await.unwrap();
                let mut request = [0_u8; REQUEST_HEADER_BYTES];
                socket.read_exact(&mut request).await.unwrap();
                let tls_bytes = if direct {
                    2 + 16 + 5 + FRAME_CONTENT_BYTES + FRAME_PADDING_BYTES
                } else {
                    wire.len()
                };
                for chunk in wire[..tls_bytes].chunks(SOURCE_CHUNK_BYTES) {
                    socket.write_all(chunk).await.unwrap();
                }
                socket.flush().await.unwrap();
                if direct {
                    let raw = socket.get_mut();
                    for chunk in wire[tls_bytes..].chunks(SOURCE_CHUNK_BYTES) {
                        raw.write_all(chunk).await.unwrap();
                    }
                    raw.shutdown().await.unwrap();
                } else {
                    socket.shutdown().await.unwrap();
                }
            });
        }
    });
    address
}

fn benchmark_node(server: SocketAddr) -> Node {
    Node {
        name: "vless-vision-benchmark".into(),
        outbound: OutboundConfig::Vless(VlessConfig {
            uuid: Some(UUID_TEXT.into()),
            flow: Some("xtls-rprx-vision".into()),
            tls: honk_config::node::TlsOptions {
                enabled: true,
                skip_cert_verify: true,
                sni: Some("localhost".into()),
                ..Default::default()
            },
            ..Default::default()
        }),
        address: server.to_string(),
        host: server.ip().to_string(),
        port: server.port(),
        ..Default::default()
    }
}

async fn run_case(node: &Node) -> usize {
    let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let mut stream = VLessHandler::new()
        .dial(node, target, None, Duration::from_secs(5))
        .await
        .unwrap()
        .stream;
    let mut decoded = Vec::with_capacity(PAYLOAD_BYTES);
    stream.read_to_end(&mut decoded).await.unwrap();
    black_box(decoded.len())
}

fn bench_vision(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (framed_node, direct_node) = runtime.block_on(async {
        let framed = spawn_server(framed_wire(), false).await;
        let direct = spawn_server(direct_wire(), true).await;
        (benchmark_node(framed), benchmark_node(direct))
    });

    assert_eq!(runtime.block_on(run_case(&framed_node)), PAYLOAD_BYTES);
    assert_eq!(runtime.block_on(run_case(&direct_node)), PAYLOAD_BYTES);

    c.bench_function("vision_framed_16m", |bencher| {
        bencher
            .to_async(&runtime)
            .iter(|| run_case(black_box(&framed_node)));
    });
    c.bench_function("vision_direct_16m", |bencher| {
        bencher
            .to_async(&runtime)
            .iter(|| run_case(black_box(&direct_node)));
    });
}

criterion_group!(benches, bench_vision);
criterion_main!(benches);
