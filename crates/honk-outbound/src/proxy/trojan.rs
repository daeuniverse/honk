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
    AsyncReadWrite, MultiTargetTransport, PacketOutbound, PacketTransport, PreparedUdpTransport,
    ProbeableOutbound, ProxyStream, SharedSourceOutbound, TcpOutbound, TunnelDialOptions,
    WarmRequirement, WarmableOutbound,
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

    async fn dial_stream(
        node: &Node,
        runtime: Option<&Arc<crate::runtime::NodeRuntime>>,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: Option<TcpStream>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let password = node.trojan().unwrap().password.as_deref().unwrap_or("");
        let header = Self::build_request_header(password, target, target_domain)?;
        let (stream, preparation) =
            Self::prepare_transport(node, runtime, tcp, connect_timeout).await?;
        preparation.commit()?;
        Self::send_request(stream, &header, target, target_domain).await
    }

    /// Sends a request header built before the transport was opened, so an
    /// unencodable target fails without dialing.
    async fn send_request(
        mut stream: Box<dyn AsyncReadWrite>,
        header: &[u8],
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> anyhow::Result<ProxyStream> {
        super::transport::write_request(&mut stream, header).await?;
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }

    async fn dial_udp_stream(
        node: &Node,
        runtime: Option<&Arc<crate::runtime::NodeRuntime>>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::prepare_udp_stream(node, runtime, target, target_domain, connect_timeout)
            .await?
            .commit()
            .await
    }

    async fn prepare_transport(
        node: &Node,
        runtime: Option<&Arc<crate::runtime::NodeRuntime>>,
        tcp: Option<TcpStream>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<(
        Box<dyn AsyncReadWrite>,
        super::transport::TransportPreparation,
    )> {
        match runtime {
            Some(runtime) => {
                super::transport::prepare_transport_runtime(runtime, tcp, timeout).await
            }
            None => Ok((
                super::transport::wrap_transport(node, tcp, timeout).await?,
                super::transport::TransportPreparation::none(),
            )),
        }
    }

    async fn prepare_udp_stream(
        node: &Node,
        runtime: Option<&Arc<crate::runtime::NodeRuntime>>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let (transport, preparation) =
            Self::open_udp_stream(node, runtime, target, domain, timeout).await?;
        Ok(Self::commit_udp_stream(
            transport as Arc<dyn PacketTransport>,
            preparation,
        ))
    }

    /// One association for a whole client source scope: `target` and
    /// `domain` only name the UDP-associate request; every frame carries its
    /// own destination.
    pub(crate) async fn prepare_udp_source(
        runtime: &Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        let (transport, preparation) =
            Self::open_udp_stream(&runtime.node, Some(runtime), target, domain, timeout).await?;
        Ok(Self::commit_udp_stream(
            transport as Arc<dyn MultiTargetTransport>,
            preparation,
        ))
    }

    async fn open_udp_stream(
        node: &Node,
        runtime: Option<&Arc<crate::runtime::NodeRuntime>>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<(
        Arc<TrojanUdpTransport>,
        super::transport::TransportPreparation,
    )> {
        if !crate::descriptor::network_allows_udp(node) {
            anyhow::bail!(
                "Trojan UDP: node network {:?} does not include \"udp\"",
                node.network()
            );
        }
        let (control, preparation) = Self::prepare_transport(node, runtime, None, timeout).await?;
        let tls_handoff = super::chain::native_udp_writer_handoff(node);
        let transport = Self::finish_udp_stream(node, target, domain, control, tls_handoff).await?;
        Ok((transport, preparation))
    }

    /// The UDP associate over `carrier`, a stream tunneled through earlier hops.
    async fn open_udp_over(
        node: &Node,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        domain: Option<&str>,
        options: TunnelDialOptions,
    ) -> anyhow::Result<Arc<TrojanUdpTransport>> {
        if !node.supports_tunneled_udp() {
            return Err(super::TunnelUnsupported("trojan udp").into());
        }
        let control = super::transport::wrap_tunnel(node, carrier, options).await?;
        Self::finish_udp_stream(node, target, domain, control, None).await
    }

    fn commit_udp_stream<T: ?Sized + Send + Sync + 'static>(
        transport: Arc<T>,
        preparation: super::transport::TransportPreparation,
    ) -> PreparedUdpTransport<T> {
        PreparedUdpTransport::new(async move {
            preparation.commit()?;
            Ok(transport)
        })
    }

    async fn finish_udp_stream(
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        mut control: Box<dyn AsyncReadWrite>,
        native_tls_handoff: Option<bool>,
    ) -> anyhow::Result<Arc<TrojanUdpTransport>> {
        let password = node.trojan().unwrap().password.as_deref().unwrap_or("");
        let addr_header = addr::encode_address(target, target_domain)?;
        let mut header = Vec::with_capacity(56 + 2 + 1 + 19 + 2);
        header.extend_from_slice(hex_sha224(password).as_bytes());
        header.extend_from_slice(CRLF);
        header.push(CMD_UDP);
        header.extend_from_slice(&addr_header);
        header.extend_from_slice(CRLF);
        super::transport::write_request(&mut control, &header).await?;

        let (rd, wr) = tokio::io::split(control);
        let exit = super::chain::UDP_EXIT_HOP.try_with(|exit| *exit).ok();
        Ok(Arc::new(TrojanUdpTransport {
            writer: tokio::sync::Mutex::new(wr),
            poison: super::FramePoison::default(),
            reader: tokio::sync::Mutex::new(rd),
            addr_header,
            domain: target_domain.map(Box::from),
            relay_addr: target,
            tls_handoff: exit.map(|exit| exit.tls_handoff).or(native_tls_handoff),
            exit,
        }))
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
        Self::dial_stream(node, None, target, target_domain, None, connect_timeout).await
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: TcpStream,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        Self::dial_stream(
            node,
            None,
            target,
            target_domain,
            Some(tcp),
            connect_timeout,
        )
        .await
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        Self::dial_stream(
            &runtime.node,
            Some(&runtime),
            target,
            target_domain,
            None,
            connect_timeout,
        )
        .await
    }

    async fn dial_over(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        options: TunnelDialOptions,
    ) -> anyhow::Result<ProxyStream> {
        let node = &runtime.node;
        let password = node.trojan().unwrap().password.as_deref().unwrap_or("");
        let header = Self::build_request_header(password, target, target_domain)?;
        let stream = super::transport::wrap_tunnel(node, carrier, options).await?;
        Self::send_request(stream, &header, target, target_domain).await
    }
}

#[async_trait]
impl SharedSourceOutbound for TrojanHandler {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        let _ = speculative;
        Self::prepare_udp_source(&runtime, target, target_domain, connect_timeout).await
    }

    async fn prepare_shared_source_over(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        options: TunnelDialOptions,
    ) -> anyhow::Result<Arc<dyn MultiTargetTransport>> {
        Ok(Self::open_udp_over(&runtime.node, carrier, target, target_domain, options).await?)
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
        Self::dial_udp_stream(node, None, target, target_domain, connect_timeout).await
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::dial_udp_stream(
            &runtime.node,
            Some(&runtime),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<super::PreparedUdpTransport> {
        Self::prepare_udp_stream(
            &runtime.node,
            Some(&runtime),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    async fn dial_udp_over(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        options: TunnelDialOptions,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Ok(Self::open_udp_over(&runtime.node, carrier, target, target_domain, options).await?)
    }
}

#[async_trait]
impl WarmableOutbound for TrojanHandler {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: std::time::Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        super::transport::xhttp::XhttpRuntime::warm(&runtime, connect_timeout).await
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

    #[tokio::test]
    async fn dial_over_sends_the_request_through_the_carrier() {
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let password = "tunnel-secret";
        let (client, mut server) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            // hex(sha224("tunnel-secret")) | CRLF | CONNECT | ATYP=domain |
            // LEN | "example.com" | port 80 | CRLF, then the payload.
            let mut expected = b"e18a99df762a533a40db57010c34dde76778a0ca43091577bf581b2b".to_vec();
            expected.extend_from_slice(b"\r\n\x01\x03\x0bexample.com\x00\x50\r\nping");
            let mut request = vec![0; expected.len()];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected);
            server.write_all(b"pong").await.unwrap();
        });

        let mut node = Node {
            name: "trojan-tunnel".into(),
            address: "198.51.100.1:443".into(),
            host: "must-not-resolve.invalid".into(),
            port: 443,
            outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
                password: Some(password.into()),
                tls: honk_config::node::TlsOptions {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        node.id = node.derive_id();
        let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
        let mut stream = TrojanHandler::new()
            .dial_over(
                runtime,
                Box::new(client),
                target,
                Some("example.com"),
                TunnelDialOptions::new(std::time::Duration::from_secs(3)),
            )
            .await
            .unwrap();
        stream.stream.write_all(b"ping").await.unwrap();
        stream.stream.flush().await.unwrap();
        let mut reply = [0; 4];
        stream.stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        server.await.unwrap();
    }
}

/// Framed UDP-associate transport over the Trojan control stream: packets
/// are framed directly onto the associate stream
/// (`addr | u16 len | CRLF | payload`), each frame naming its own peer.
struct TrojanUdpTransport {
    writer: tokio::sync::Mutex<WriteHalf<Box<dyn AsyncReadWrite>>>,
    /// Poisoned by a write cancelled halfway, so no sibling destination can
    /// append a frame to a torn one.
    poison: super::FramePoison,
    reader: tokio::sync::Mutex<ReadHalf<Box<dyn AsyncReadWrite>>>,
    /// Encoded `relay_addr`/`domain`: the destination of `send_packet`.
    addr_header: Vec<u8>,
    domain: Option<Box<str>>,
    relay_addr: SocketAddr,
    exit: Option<super::chain::UdpExit>,
    tls_handoff: Option<bool>,
}

impl std::fmt::Debug for TrojanUdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanUdpTransport")
            .field("relay_addr", &self.relay_addr)
            .finish()
    }
}

impl TrojanUdpTransport {
    async fn send_frame(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        admitted: Option<&std::sync::atomic::AtomicBool>,
        current: Option<&(dyn Fn() -> bool + Send + Sync)>,
    ) -> std::io::Result<()> {
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
        let mut frame;
        if target == self.relay_addr && domain == self.domain.as_deref() {
            frame = Vec::with_capacity(self.addr_header.len() + 4 + data.len());
            frame.extend_from_slice(&self.addr_header);
        } else {
            let address = addr::SocksAddr::new(target, domain)?;
            frame = Vec::with_capacity(address.encoded_len() + 4 + data.len());
            address.encode(&mut frame);
        }
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(CRLF);
        frame.extend_from_slice(data);
        if let Some(current) = current {
            let tls_handoff = self.tls_handoff.ok_or(super::PacketRejection::Policy)?;
            return self
                .poison
                .write_checked(&mut *writer, &frame, admitted, tls_handoff, current)
                .await;
        }
        let write = self.poison.begin(admitted)?;
        writer.write_all(&frame).await?;
        writer.flush().await?;
        write.complete();
        Ok(())
    }
}

#[async_trait]
impl PacketTransport for TrojanUdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    fn allows_full_cone_replies(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_frame(self.relay_addr, self.domain.as_deref(), data, None, None)
            .await
    }

    async fn send_packet_checked(
        &self,
        data: &[u8],
        current: &(dyn Fn() -> bool + Send + Sync),
    ) -> std::io::Result<()> {
        self.send_frame(
            self.relay_addr,
            self.domain.as_deref(),
            data,
            None,
            Some(current),
        )
        .await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut rd = self.reader.lock().await;
        let framing_error = |error: std::io::Error| match self.exit {
            Some(exit) => {
                let error = std::io::Error::new(error.kind(), super::NodeFailure(error.into()));
                super::error::HopIoFailure::io(exit.index, error, false)
            }
            None => error,
        };
        loop {
            // Only the dialed name projects back and no other is resolved; an
            // unknown ATYP has no derivable length, so it stays terminal.
            let peer = addr::read_reply_source(&mut *rd, self.domain.as_deref(), self.relay_addr)
                .await
                .map_err(|error| {
                    if error
                        .get_ref()
                        .is_some_and(|cause| cause.is::<addr::UnknownReplyAddressType>())
                    {
                        framing_error(error)
                    } else {
                        error
                    }
                })?;
            let mut head = [0u8; 4];
            rd.read_exact(&mut head).await?;
            if &head[2..] != CRLF {
                return Err(framing_error(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid trojan udp frame delimiter",
                )));
            }
            let len = u16::from_be_bytes([head[0], head[1]]) as usize;
            if let Some(peer) = peer {
                if len > buf.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "trojan udp frame exceeds buffer",
                    ));
                }
                rd.read_exact(&mut buf[..len]).await?;
                return Ok((len, peer));
            }
            // The dropped frame must be consumed so the next one decodes.
            let mut left = len;
            let mut discard = [0u8; 512];
            while left > 0 {
                let chunk = left.min(discard.len());
                rd.read_exact(&mut discard[..chunk]).await?;
                left -= chunk;
            }
        }
    }
}

#[async_trait]
impl MultiTargetTransport for TrojanUdpTransport {
    async fn send_to(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        _confirmed: bool,
        admitted: Option<&std::sync::atomic::AtomicBool>,
    ) -> std::io::Result<()> {
        let domain = addr::dialed_name(self.domain.as_deref(), domain);
        self.send_frame(target, domain, data, admitted, None).await
    }

    async fn send_to_checked(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        admitted: Option<&std::sync::atomic::AtomicBool>,
        current: &(dyn Fn() -> bool + Send + Sync),
    ) -> std::io::Result<()> {
        let domain = addr::dialed_name(self.domain.as_deref(), domain);
        self.send_frame(target, domain, data, admitted, Some(current))
            .await
    }

    fn frame_stream_torn(&self) -> bool {
        self.poison.is_set()
    }
}

#[cfg(test)]
mod udp_transport_tests;
