//! Trojan proxy handler.
//! https://github.com/trojan-gfw/trojan

use async_trait::async_trait;
use honk_config::node::Node;
use sha2::{Digest, Sha224};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use super::addr;
use super::{
    AsyncReadWrite, PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound,
};

const CRLF: &[u8] = b"\r\n";
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x03;

/// Trojan proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrojanHandler;

impl TrojanHandler {
    pub fn new() -> Self {
        Self
    }

    /// Format: `hex(sha224(password)) CRLF cmd address CRLF`.
    fn build_request_header(
        password: &str,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> std::io::Result<Vec<u8>> {
        let mut header = Vec::with_capacity(56 + 2 + 1 + 19 + 2);
        header.extend_from_slice(hex_sha224(password).as_bytes());
        header.extend_from_slice(CRLF);
        header.push(CMD_TCP);
        header.extend_from_slice(&addr::encode_address(target, target_domain)?);
        header.extend_from_slice(CRLF);
        Ok(header)
    }
}

#[async_trait]
impl TcpOutbound for TrojanHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = format!("{}:{}", node.host(), node.port);
        let tcp = crate::util::connect_outbound(&addr, connect_timeout).await?;
        self.dial_with_tcp(node, target, target_domain, tcp, connect_timeout)
            .await
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: TcpStream,
        _connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let password = node.trojan().unwrap().password.as_deref().unwrap_or("");
        let header = Self::build_request_header(password, target, target_domain)?;
        let mut stream = super::transport::wrap_transport(node, tcp).await?;
        stream.write_all(&header).await?;
        stream.flush().await?;
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

#[async_trait]
impl PacketOutbound for TrojanHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        if !crate::descriptor::network_allows_udp(node) {
            anyhow::bail!(
                "Trojan UDP: node network {:?} does not include \"udp\"",
                node.network()
            );
        }
        let password = node.trojan().unwrap().password.as_deref().unwrap_or("");
        let mut control = super::transport::connect_transport(node, connect_timeout).await?;
        let addr_header = addr::encode_address(target, target_domain)?;
        let mut header = Vec::with_capacity(56 + 2 + 1 + 19 + 2);
        header.extend_from_slice(hex_sha224(password).as_bytes());
        header.extend_from_slice(CRLF);
        header.push(CMD_UDP);
        header.extend_from_slice(&addr_header);
        header.extend_from_slice(CRLF);
        control.write_all(&header).await?;
        control.flush().await?;

        let (rd, wr) = tokio::io::split(control);
        Ok(Arc::new(TrojanUdpTransport {
            writer: tokio::sync::Mutex::new(wr),
            reader: tokio::sync::Mutex::new(rd),
            addr_header,
            relay_addr: target,
        }))
    }
}

#[async_trait]
impl ProbeableOutbound for TrojanHandler {}

/// Compute the lowercase hex encoding of SHA224(password).
fn hex_sha224(password: &str) -> String {
    let hash = Sha224::digest(password.as_bytes());
    let mut out = String::with_capacity(hash.len() * 2);
    for byte in hash {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::types::NodeProtocol;

    #[test]
    fn test_trojan_request_header_encoding() {
        let password = "password123";
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let header = TrojanHandler::build_request_header(password, target, None).unwrap();

        // First 56 bytes are the hex-encoded SHA224(password).
        let expected_hash = hex_sha224(password);
        assert_eq!(&header[..56], expected_hash.as_bytes());
        assert_eq!(&header[56..58], CRLF);
        assert_eq!(header[58], CMD_TCP);
        assert_eq!(header[59], addr::ATYP_IPV4);
        assert_eq!(&header[60..64], &[93, 184, 216, 34]);
        assert_eq!(&header[64..66], &[0x00, 0x50]); // port 80
        assert_eq!(&header[66..68], CRLF);
    }

    #[test]
    fn test_trojan_domain_header_encoding() {
        let password = "secret";
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let domain = "example.com";

        let header = TrojanHandler::build_request_header(password, target, Some(domain)).unwrap();

        let expected_hash = hex_sha224(password);
        assert_eq!(&header[..56], expected_hash.as_bytes());
        assert_eq!(&header[56..58], CRLF);
        assert_eq!(header[58], CMD_TCP);
        assert_eq!(header[59], addr::ATYP_DOMAIN);
        assert_eq!(header[60], domain.len() as u8);
        assert_eq!(&header[61..72], domain.as_bytes());
        assert_eq!(&header[72..74], &[0x01, 0xbb]); // port 443
        assert_eq!(&header[74..76], CRLF);
    }

    #[test]
    fn test_hex_sha224_known_value() {
        // SHA224("") is a known constant.
        let hash = hex_sha224("");
        assert_eq!(
            hash,
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn test_pool_ready_streams_transport_gating() {
        let pool_ready_streams =
            crate::descriptor::descriptor(NodeProtocol::Trojan).pool_ready_streams;
        let mut node = Node {
            name: "t".into(),
            address: "127.0.0.1".into(),
            port: 443,
            outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
            ..Default::default()
        };
        node.transport_mut().unwrap().transport.clear();
        assert!(pool_ready_streams(&node));
        node.transport_mut().unwrap().transport = "tcp".into();
        assert!(pool_ready_streams(&node));
        node.transport_mut().unwrap().transport = "ws".into();
        assert!(!pool_ready_streams(&node));
        node.transport_mut().unwrap().transport = "grpc".into();
        assert!(!pool_ready_streams(&node));
    }

    /// A pooled bare server socket must complete and flush the configured
    /// gRPC transport before returning the target-bound Trojan stream.
    #[tokio::test]
    async fn bare_tcp_grpc_flushes_trojan_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let password = "pooled-secret";
        let expected = TrojanHandler::build_request_header(password, target, None).unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(tcp).await.unwrap();
            let (request, _respond) = connection
                .accept()
                .await
                .expect("gRPC request must arrive")
                .expect("gRPC headers must be valid");
            assert_eq!(request.uri().path(), "/pooled/Tun");
            let mut body = request.into_body();
            let driver = tokio::spawn(async move {
                while let Some(request) = connection.accept().await {
                    request.expect("subsequent gRPC request must be valid");
                }
            });

            let mut received = Vec::new();
            loop {
                let data = tokio::time::timeout(std::time::Duration::from_secs(5), body.data())
                    .await
                    .expect("flushed Trojan header must arrive")
                    .expect("gRPC request body must remain open")
                    .expect("gRPC DATA must be valid");
                received.extend_from_slice(&data);
                if received.len() >= 5 {
                    let message_len =
                        u32::from_be_bytes(received[1..5].try_into().unwrap()) as usize;
                    if received.len() >= 5 + message_len {
                        break;
                    }
                }
            }
            driver.abort();

            assert_eq!(received[0], 0, "gRPC message must be uncompressed");
            assert_eq!(
                u32::from_be_bytes(received[1..5].try_into().unwrap()) as usize,
                expected.len() + 2
            );
            assert_eq!(received[5], 0x0a, "protobuf payload must be bytes field 1");
            assert_eq!(received[6] as usize, expected.len());
            assert_eq!(&received[7..], expected.as_slice());
        });

        let mut node = Node {
            name: "trojan-grpc".into(),
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
                password: Some(password.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let transport = node.transport_mut().unwrap();
        transport.transport = "grpc".into();
        transport.grpc_service = Some("pooled".into());

        let tcp = TcpStream::connect(server_addr).await.unwrap();
        let _stream = TrojanHandler::new()
            .dial_with_tcp(&node, target, None, tcp, std::time::Duration::from_secs(3))
            .await
            .unwrap();
        server.await.unwrap();
    }
}

/// Framed UDP-associate transport over the Trojan control stream: packets
/// are framed directly onto the associate stream
/// (`addr | u16 len | CRLF | payload`).
struct TrojanUdpTransport {
    writer: tokio::sync::Mutex<WriteHalf<Box<dyn AsyncReadWrite>>>,
    reader: tokio::sync::Mutex<ReadHalf<Box<dyn AsyncReadWrite>>>,
    addr_header: Vec<u8>,
    relay_addr: SocketAddr,
}

impl std::fmt::Debug for TrojanUdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanUdpTransport")
            .field("relay_addr", &self.relay_addr)
            .finish()
    }
}

#[async_trait]
impl PacketTransport for TrojanUdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "trojan udp frame too large",
            ));
        }
        // The endpoint driver drops this packet on `WouldBlock` without
        // treating writer contention as a dead tunnel.
        let Ok(mut writer) = self.writer.try_lock() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "trojan UDP writer is busy",
            ));
        };
        let mut frame = Vec::with_capacity(self.addr_header.len() + 4 + data.len());
        frame.extend_from_slice(&self.addr_header);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(CRLF);
        frame.extend_from_slice(data);
        writer.write_all(&frame).await?;
        writer.flush().await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut rd = self.reader.lock().await;
        // Source address is parsed (bounds-checked) but discarded: the flow's
        // reply validation keys on relay_addr, not the packet's source field.
        let _src = addr::SocksAddr::read_from_stream(&mut *rd).await?;
        let mut len_buf = [0u8; 2];
        rd.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut crlf = [0u8; 2];
        rd.read_exact(&mut crlf).await?;
        if len > buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trojan udp frame exceeds buffer",
            ));
        }
        rd.read_exact(&mut buf[..len]).await?;
        Ok((len, self.relay_addr))
    }
}

#[cfg(test)]
mod udp_transport_tests {
    use super::*;

    /// send_packet frames `addr|len|CRLF|payload`; recv_packet unframes the
    /// same shape back. Round-tripped over a duplex pair.
    #[tokio::test]
    async fn trojan_udp_transport_frame_roundtrip() {
        let (client, mut server) = tokio::io::duplex(8192);
        let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let (rd, wr) = tokio::io::split(Box::new(client) as Box<dyn AsyncReadWrite>);
        let transport = TrojanUdpTransport {
            writer: tokio::sync::Mutex::new(wr),
            reader: tokio::sync::Mutex::new(rd),
            addr_header: addr::encode_address(target, None).unwrap(),
            relay_addr: target,
        };

        // client → server frame
        transport.send_packet(b"hello-trojan-udp").await.unwrap();
        let mut head = vec![0u8; addr::encode_address(target, None).unwrap().len() + 4];
        server.read_exact(&mut head).await.unwrap();
        let mut payload = [0u8; 16];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello-trojan-udp");

        // server → client frame
        let mut frame = addr::encode_address(target, None).unwrap();
        frame.extend_from_slice(&5u16.to_be_bytes());
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(b"pong!");
        server.write_all(&frame).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong!");
        assert_eq!(src, target);
    }
}
