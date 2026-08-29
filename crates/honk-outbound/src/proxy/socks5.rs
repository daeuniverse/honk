//! SOCKS5 (RFC 1928) with no-auth and user/pass (RFC 1929) authentication.

use async_trait::async_trait;
use honk_config::node::Node;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use super::{PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound};

const SOCKS5_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_TTL_EXPIRED: u8 = 0x06;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// Full SOCKS5 proxy handler.
pub struct Socks5Handler;

impl Socks5Handler {
    pub fn new() -> Self {
        Self
    }

    fn username_password_auth_request(username: &str, password: &str) -> anyhow::Result<Vec<u8>> {
        let username_len = u8::try_from(username.len())
            .map_err(|_| anyhow::anyhow!("SOCKS5 username exceeds 255 bytes"))?;
        let password_len = u8::try_from(password.len())
            .map_err(|_| anyhow::anyhow!("SOCKS5 password exceeds 255 bytes"))?;
        let mut request = Vec::with_capacity(3 + username.len() + password.len());
        request.push(0x01);
        request.push(username_len);
        request.extend_from_slice(username.as_bytes());
        request.push(password_len);
        request.extend_from_slice(password.as_bytes());
        Ok(request)
    }

    /// Perform full SOCKS5 handshake.
    async fn handshake(
        stream: &mut TcpStream,
        target: SocketAddr,
        target_domain: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let methods = if username.is_some() && password.is_some() {
                vec![METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]
            } else {
                vec![METHOD_NO_AUTH]
            };

            // Send: VER(1) | NMETHODS(1) | METHODS(N)
            let mut greeting = Vec::with_capacity(2 + methods.len());
            greeting.push(SOCKS5_VERSION);
            greeting.push(methods.len() as u8);
            greeting.extend_from_slice(&methods);
            stream.write_all(&greeting).await?;

            // Read: VER(1) | METHOD(1)
            let mut response = [0u8; 2];
            stream.read_exact(&mut response).await?;

            if response[0] != SOCKS5_VERSION {
                anyhow::bail!("SOCKS5: unsupported server version {}", response[0]);
            }

            match response[1] {
                METHOD_NO_AUTH => {}
                METHOD_USERNAME_PASSWORD => {
                    // Perform username/password auth (RFC 1929)
                    let user = username.unwrap_or("");
                    let pass = password.unwrap_or("");

                    // Send: VER(1) | ULEN(1) | UNAME(ULEN) | PLEN(1) | PASSWD(PLEN)
                    let auth_req = Self::username_password_auth_request(user, pass)?;
                    stream.write_all(&auth_req).await?;

                    // Read: VER(1) | STATUS(1)
                    let mut auth_resp = [0u8; 2];
                    stream.read_exact(&mut auth_resp).await?;

                    if auth_resp[1] != 0x00 {
                        anyhow::bail!("SOCKS5: authentication failed (status {})", auth_resp[1]);
                    }
                }
                METHOD_NO_ACCEPTABLE => {
                    anyhow::bail!("SOCKS5: no acceptable authentication method");
                }
                m => {
                    anyhow::bail!("SOCKS5: unexpected auth method 0x{:02x}", m);
                }
            }

            // Build request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
            let mut request = Vec::with_capacity(6 + 256);
            request.push(SOCKS5_VERSION);
            request.push(CMD_CONNECT);
            request.push(0x00); // reserved

            match target {
                SocketAddr::V4(v4) => {
                    request.push(ATYP_IPV4);
                    request.extend_from_slice(&v4.ip().octets());
                    request.extend_from_slice(&v4.port().to_be_bytes());
                }
                SocketAddr::V6(v6) => {
                    request.push(ATYP_IPV6);
                    request.extend_from_slice(&v6.ip().octets());
                    request.extend_from_slice(&v6.port().to_be_bytes());
                }
            }

            if let Some(domain) = target_domain {
                request[3] = ATYP_DOMAIN;
                request.truncate(4);
                request.push(domain.len() as u8);
                request.extend_from_slice(domain.as_bytes());
                request.extend_from_slice(&target.port().to_be_bytes());
            }

            let atyp_str = if request[3] == ATYP_DOMAIN {
                "domain"
            } else if request[3] == ATYP_IPV4 {
                "ipv4"
            } else if request[3] == ATYP_IPV6 {
                "ipv6"
            } else {
                "unknown"
            };
            debug!(
                "SOCKS5 connect request: ATYP={} target={} addr={}",
                atyp_str,
                target_domain.unwrap_or("<ip>"),
                target
            );

            stream.write_all(&request).await?;

            // Reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
            let mut reply_header = [0u8; 4];
            stream.read_exact(&mut reply_header).await?;

            if reply_header[0] != SOCKS5_VERSION {
                anyhow::bail!("SOCKS5: bad reply version {}", reply_header[0]);
            }

            let reply_code = reply_header[1];
            if reply_code != REP_SUCCESS {
                let msg = match reply_code {
                    REP_GENERAL_FAILURE => "general failure",
                    REP_CONNECTION_NOT_ALLOWED => "connection not allowed",
                    REP_NETWORK_UNREACHABLE => "network unreachable",
                    REP_HOST_UNREACHABLE => "host unreachable",
                    REP_CONNECTION_REFUSED => "connection refused",
                    REP_TTL_EXPIRED => "TTL expired",
                    REP_COMMAND_NOT_SUPPORTED => "command not supported",
                    REP_ADDRESS_TYPE_NOT_SUPPORTED => "address type not supported",
                    _ => "unknown error",
                };
                anyhow::bail!(
                    "SOCKS5: server replied error: {} (0x{:02x})",
                    msg,
                    reply_code
                );
            }

            // Read the bind address (we don't use it, but need to consume it)
            let atyp = reply_header[3];
            match atyp {
                ATYP_IPV4 => {
                    let mut addr = [0u8; 6];
                    stream.read_exact(&mut addr).await?;
                }
                ATYP_DOMAIN => {
                    let mut len_buf = [0u8; 1];
                    stream.read_exact(&mut len_buf).await?;
                    let domain_len = len_buf[0] as usize;
                    let mut domain_and_port = vec![0u8; domain_len + 2];
                    stream.read_exact(&mut domain_and_port).await?;
                }
                ATYP_IPV6 => {
                    let mut addr = [0u8; 18];
                    stream.read_exact(&mut addr).await?;
                }
                a => anyhow::bail!("SOCKS5: unknown bind address type 0x{:02x}", a),
            }

            debug!("SOCKS5 handshake complete");
            Ok(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("SOCKS5 handshake timed out"))?
    }

    /// Build a SOCKS5 UDP request header (RFC 1928 Section 7).
    /// Format: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR(var) | DST.PORT(2) | DATA
    pub fn build_udp_header(
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> io::Result<Vec<u8>> {
        let mut header = Vec::with_capacity(6 + 256);
        header.extend_from_slice(&[0x00, 0x00]); // RSV
        header.push(0x00); // FRAG

        match (target_domain, target) {
            (Some(domain), _) => {
                let domain_len = u8::try_from(domain.len()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "SOCKS5 UDP domain exceeds 255 bytes",
                    )
                })?;
                header.push(ATYP_DOMAIN);
                header.push(domain_len);
                header.extend_from_slice(domain.as_bytes());
                header.extend_from_slice(&target.port().to_be_bytes());
            }
            (None, SocketAddr::V4(v4)) => {
                header.push(ATYP_IPV4);
                header.extend_from_slice(&v4.ip().octets());
                header.extend_from_slice(&v4.port().to_be_bytes());
            }
            (None, SocketAddr::V6(v6)) => {
                header.push(ATYP_IPV6);
                header.extend_from_slice(&v6.ip().octets());
                header.extend_from_slice(&v6.port().to_be_bytes());
            }
        }

        Ok(header)
    }

    /// Perform SOCKS5 UDP ASSOCIATE handshake (RFC 1928 Section 6).
    /// Returns the relay address where UDP datagrams should be sent.
    /// The TCP control connection must be kept alive for the UDP relay to work.
    async fn udp_associate(
        stream: &mut tokio::net::TcpStream,
        username: Option<&str>,
        password: Option<&str>,
    ) -> anyhow::Result<SocketAddr> {
        let methods = if username.is_some() && password.is_some() {
            vec![METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]
        } else {
            vec![METHOD_NO_AUTH]
        };

        let mut greeting = Vec::with_capacity(2 + methods.len());
        greeting.push(SOCKS5_VERSION);
        greeting.push(methods.len() as u8);
        greeting.extend_from_slice(&methods);
        stream.write_all(&greeting).await?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        if response[0] != SOCKS5_VERSION {
            anyhow::bail!("SOCKS5: unsupported server version {}", response[0]);
        }

        match response[1] {
            METHOD_NO_AUTH => {}
            METHOD_USERNAME_PASSWORD => {
                let user = username.unwrap_or("");
                let pass = password.unwrap_or("");
                let auth_req = Self::username_password_auth_request(user, pass)?;
                stream.write_all(&auth_req).await?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp[1] != 0x00 {
                    anyhow::bail!("SOCKS5: authentication failed");
                }
            }
            METHOD_NO_ACCEPTABLE => anyhow::bail!("SOCKS5: no acceptable auth method"),
            m => anyhow::bail!("SOCKS5: unexpected auth method 0x{:02x}", m),
        }

        // VER | CMD=0x03 | RSV | ATYP=0x01 | BND.ADDR=0.0.0.0 | BND.PORT=0
        let request = [
            SOCKS5_VERSION,
            CMD_UDP_ASSOCIATE,
            0x00,
            ATYP_IPV4,
            0x00,
            0x00,
            0x00,
            0x00, // 0.0.0.0
            0x00,
            0x00, // port 0
        ];
        stream.write_all(&request).await?;

        let mut reply_header = [0u8; 4];
        stream.read_exact(&mut reply_header).await?;

        if reply_header[0] != SOCKS5_VERSION {
            anyhow::bail!("SOCKS5 UDP: bad reply version");
        }
        if reply_header[1] != REP_SUCCESS {
            anyhow::bail!(
                "SOCKS5 UDP: server rejected UDP ASSOCIATE (code 0x{:02x})",
                reply_header[1]
            );
        }

        let relay_addr = match reply_header[3] {
            ATYP_IPV4 => {
                let mut addr = [0u8; 6];
                stream.read_exact(&mut addr).await?;
                let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                let port = u16::from_be_bytes([addr[4], addr[5]]);
                SocketAddr::new(std::net::IpAddr::V4(ip), port)
            }
            ATYP_IPV6 => {
                let mut addr = [0u8; 18];
                stream.read_exact(&mut addr).await?;
                let ip = std::net::Ipv6Addr::from([
                    ((addr[0] as u16) << 8) | addr[1] as u16,
                    ((addr[2] as u16) << 8) | addr[3] as u16,
                    ((addr[4] as u16) << 8) | addr[5] as u16,
                    ((addr[6] as u16) << 8) | addr[7] as u16,
                    ((addr[8] as u16) << 8) | addr[9] as u16,
                    ((addr[10] as u16) << 8) | addr[11] as u16,
                    ((addr[12] as u16) << 8) | addr[13] as u16,
                    ((addr[14] as u16) << 8) | addr[15] as u16,
                ]);
                let port = u16::from_be_bytes([addr[16], addr[17]]);
                SocketAddr::new(std::net::IpAddr::V6(ip), port)
            }
            ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;
                let mut domain_and_port = vec![0u8; domain_len + 2];
                stream.read_exact(&mut domain_and_port).await?;
                let port = u16::from_be_bytes([
                    domain_and_port[domain_len],
                    domain_and_port[domain_len + 1],
                ]);
                let domain = std::str::from_utf8(&domain_and_port[..domain_len])?;
                let ip = crate::bootstrap::resolve(domain)
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("SOCKS5 UDP: relay domain resolved empty"))?;
                SocketAddr::new(ip, port)
            }
            a => anyhow::bail!("SOCKS5 UDP: unknown address type 0x{:02x}", a),
        };

        let relay_addr = if relay_addr.ip().is_unspecified() {
            SocketAddr::new(stream.peer_addr()?.ip(), relay_addr.port())
        } else {
            relay_addr
        };

        debug!("SOCKS5 UDP ASSOCIATE: relay address {}", relay_addr);
        Ok(relay_addr)
    }

    async fn udp_association(
        node: &Node,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<(UdpSocket, SocketAddr, TcpStream)> {
        let addr = format!("{}:{}", node.host(), node.port);
        debug!("SOCKS5 UDP: connecting control channel to {}", addr);
        let mut control = crate::util::connect_outbound(&addr, connect_timeout).await?;
        let config = node.socks5().unwrap();
        let relay_addr = Self::udp_associate(
            &mut control,
            config.username.as_deref(),
            config.password.as_deref(),
        )
        .await?;

        // Bind with the relay's address family, not the control connection's
        // family: SOCKS5 may return a v4 relay over a v6 control connection.
        let bind_addr: SocketAddr = if relay_addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("hardcoded IPv4 bind address")
        } else {
            "[::]:0".parse().expect("hardcoded IPv6 bind address")
        };
        let udp_socket = crate::util::udp_marked_bind(bind_addr).await?;
        debug!("SOCKS5 UDP: bound to {}", udp_socket.local_addr()?);

        Ok((udp_socket, relay_addr, control))
    }
}

#[derive(Debug)]
struct Socks5UdpTransport {
    socket: Arc<UdpSocket>,
    control: tokio::sync::Mutex<TcpStream>,
    /// Reused connected-UDP receive scratch; never reallocated per packet.
    recv_buf: tokio::sync::Mutex<Vec<u8>>,
    target_addr: SocketAddr,
    destination_header: Vec<u8>,
}

impl Socks5UdpTransport {
    fn invalid_packet(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    /// Strict RFC 1928 UDP header validation; returns payload offset only.
    /// Wire source is intentionally not resolved — the logical peer is always
    /// `target_addr` for PacketTransport consumers.
    fn parse_packet(packet: &[u8]) -> io::Result<Option<usize>> {
        if packet.len() < 4 {
            return Err(Self::invalid_packet("SOCKS5 UDP: truncated header"));
        }
        if packet[..2] != [0x00, 0x00] {
            return Err(Self::invalid_packet("SOCKS5 UDP: non-zero RSV"));
        }
        if packet[2] != 0 {
            return Ok(None);
        }

        let payload_start = match packet[3] {
            ATYP_IPV4 => {
                if packet.len() < 10 {
                    return Err(Self::invalid_packet("SOCKS5 UDP: truncated IPv4 frame"));
                }
                10
            }
            ATYP_IPV6 => {
                if packet.len() < 22 {
                    return Err(Self::invalid_packet("SOCKS5 UDP: truncated IPv6 frame"));
                }
                22
            }
            ATYP_DOMAIN => {
                if packet.len() < 5 {
                    return Err(Self::invalid_packet("SOCKS5 UDP: truncated domain frame"));
                }
                let domain_len = packet[4] as usize;
                let domain_end = 5 + domain_len;
                if packet.len() < domain_end + 2 {
                    return Err(Self::invalid_packet("SOCKS5 UDP: truncated domain frame"));
                }
                // Validate encoding only; do not resolve or surface wire source.
                let _ = std::str::from_utf8(&packet[5..domain_end])
                    .map_err(|_| Self::invalid_packet("SOCKS5 UDP: invalid domain encoding"))?;
                domain_end + 2
            }
            _ => return Err(Self::invalid_packet("SOCKS5 UDP: unsupported ATYP")),
        };

        Ok(Some(payload_start))
    }
}

#[async_trait]
impl PacketTransport for Socks5UdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target_addr
    }
    fn send_timeout_is_congestion(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        let mut packet = Vec::with_capacity(self.destination_header.len() + data.len());
        packet.extend_from_slice(&self.destination_header);
        packet.extend_from_slice(data);
        self.socket.send(&packet).await?;
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut control = self.control.lock().await;
        let mut packet = self.recv_buf.lock().await;
        let mut control_probe = [0u8; 1];

        loop {
            tokio::select! {
                received = self.socket.recv(&mut packet) => {
                    let n = received?;
                    let Some(payload_start) = Self::parse_packet(&packet[..n])? else {
                        continue;
                    };
                    let payload = &packet[payload_start..n];
                    if payload.len() > buf.len() {
                        return Err(Self::invalid_packet("SOCKS5 UDP: payload exceeds receive buffer"));
                    }
                    buf[..payload.len()].copy_from_slice(payload);
                    // Always report the logical target so core's first-reply
                    // filter matches relay_addr(); wire source is not a peer.
                    return Ok((payload.len(), self.target_addr));
                }
                control_result = control.read(&mut control_probe) => {
                    match control_result? {
                        0 => return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "SOCKS5 UDP control connection closed",
                        )),
                        _ => return Err(Self::invalid_packet(
                            "SOCKS5 UDP control connection sent unexpected data",
                        )),
                    }
                }
            }
        }
    }
}

impl Default for Socks5Handler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TcpOutbound for Socks5Handler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = format!("{}:{}", node.host(), node.port);
        debug!("SOCKS5: connecting to {} for target {}", addr, target);
        let stream = crate::util::connect_outbound(&addr, connect_timeout).await?;
        self.dial_with_tcp(node, target, target_domain, stream, connect_timeout)
            .await
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        mut stream: TcpStream,
        _connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let config = node.socks5().unwrap();
        Self::handshake(
            &mut stream,
            target,
            target_domain,
            config.username.as_deref(),
            config.password.as_deref(),
        )
        .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

#[async_trait]
impl PacketOutbound for Socks5Handler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let destination_header = Self::build_udp_header(target, target_domain)?;
        let (udp_socket, relay_addr, control) =
            Self::udp_association(node, connect_timeout).await?;
        udp_socket.connect(relay_addr).await?;

        Ok(Arc::new(Socks5UdpTransport {
            socket: Arc::new(udp_socket),
            control: tokio::sync::Mutex::new(control),
            recv_buf: tokio::sync::Mutex::new(vec![0u8; u16::MAX as usize]),
            target_addr: target,
            destination_header,
        }))
    }
}

#[async_trait]
impl ProbeableOutbound for Socks5Handler {}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::types::NodeProtocol;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    #[test]
    fn socks5_rfc1929_auth_request_rejects_oversized_credentials() {
        let oversized = "x".repeat(u8::MAX as usize + 1);
        assert!(Socks5Handler::username_password_auth_request(&oversized, "ok").is_err());
        assert!(Socks5Handler::username_password_auth_request("ok", &oversized).is_err());
    }

    #[test]
    fn socks5_rfc1929_auth_request_encodes_checked_lengths() {
        assert_eq!(
            Socks5Handler::username_password_auth_request("user", "pass").unwrap(),
            b"\x01\x04user\x04pass"
        );
    }

    struct UdpAssociateTestServer {
        proxy_addr: SocketAddr,
        relay: tokio::net::UdpSocket,
        control_closed: oneshot::Receiver<()>,
        close_control: Option<oneshot::Sender<()>>,
    }

    impl UdpAssociateTestServer {
        fn close_control(&mut self) {
            self.close_control
                .take()
                .expect("control close signal may only be sent once")
                .send(())
                .expect("SOCKS5 test control task is still running");
        }
    }

    fn socks5_udp_associate_reply(relay_addr: SocketAddr) -> Vec<u8> {
        let mut reply = vec![SOCKS5_VERSION, REP_SUCCESS, 0x00];
        match relay_addr {
            SocketAddr::V4(addr) => {
                reply.push(ATYP_IPV4);
                reply.extend_from_slice(&addr.ip().octets());
            }
            SocketAddr::V6(addr) => {
                reply.push(ATYP_IPV6);
                reply.extend_from_slice(&addr.ip().octets());
            }
        }
        reply.extend_from_slice(&relay_addr.port().to_be_bytes());
        reply
    }

    fn socks5_udp_associate_domain_reply(domain: &str, port: u16) -> Vec<u8> {
        assert!(domain.len() <= u8::MAX as usize);
        let mut reply = vec![
            SOCKS5_VERSION,
            REP_SUCCESS,
            0x00,
            ATYP_DOMAIN,
            domain.len() as u8,
        ];
        reply.extend_from_slice(domain.as_bytes());
        reply.extend_from_slice(&port.to_be_bytes());
        reply
    }

    async fn run_udp_associate_test_server(mut reply: Vec<u8>) -> UdpAssociateTestServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if reply.ends_with(&[0x00, 0x00]) {
            let port = relay.local_addr().unwrap().port().to_be_bytes();
            let reply_len = reply.len();
            reply[reply_len - 2..].copy_from_slice(&port);
        }
        let (control_closed_tx, control_closed) = oneshot::channel();
        let (close_control, mut close_control_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut greeting = [0u8; 2];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [SOCKS5_VERSION, 1]);
            let mut methods = vec![0u8; greeting[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            assert_eq!(methods, [METHOD_NO_AUTH]);
            stream
                .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
                .await
                .unwrap();

            let mut request = [0u8; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(
                request,
                [
                    SOCKS5_VERSION,
                    CMD_UDP_ASSOCIATE,
                    0x00,
                    ATYP_IPV4,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ]
            );
            stream.write_all(&reply).await.unwrap();

            let mut probe = [0u8; 1];
            tokio::select! {
                _ = &mut close_control_rx => {}
                result = stream.read(&mut probe) => {
                    assert_eq!(result.unwrap(), 0, "control channel must only close");
                }
            }
            drop(stream);
            let _ = control_closed_tx.send(());
        });

        UdpAssociateTestServer {
            proxy_addr,
            relay,
            control_closed,
            close_control: Some(close_control),
        }
    }

    fn socks5_test_node(proxy_addr: SocketAddr) -> Node {
        Node {
            name: "test".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
            address: proxy_addr.ip().to_string(),
            host: String::new(),
            port: proxy_addr.port(),
            ..Default::default()
        }
    }

    async fn dial_udp_test_transport(
        server: &UdpAssociateTestServer,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> Arc<dyn super::super::PacketTransport> {
        Socks5Handler::new()
            .dial_udp_transport(
                &socks5_test_node(server.proxy_addr),
                target,
                target_domain,
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap()
    }

    fn expected_socks5_udp_datagram(
        target: SocketAddr,
        target_domain: Option<&str>,
        frag: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut datagram = vec![0x00, 0x00, frag];
        match (target_domain, target) {
            (Some(domain), _) => {
                assert!(domain.len() <= u8::MAX as usize);
                datagram.push(ATYP_DOMAIN);
                datagram.push(domain.len() as u8);
                datagram.extend_from_slice(domain.as_bytes());
            }
            (None, SocketAddr::V4(addr)) => {
                datagram.push(ATYP_IPV4);
                datagram.extend_from_slice(&addr.ip().octets());
            }
            (None, SocketAddr::V6(addr)) => {
                datagram.push(ATYP_IPV6);
                datagram.extend_from_slice(&addr.ip().octets());
            }
        }
        datagram.extend_from_slice(&target.port().to_be_bytes());
        datagram.extend_from_slice(payload);
        datagram
    }

    async fn transport_client_addr(
        server: &UdpAssociateTestServer,
        transport: &Arc<dyn super::super::PacketTransport>,
    ) -> SocketAddr {
        transport.send_packet(b"probe").await.unwrap();
        let mut packet = [0u8; 1024];
        let (_, addr) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.relay.recv_from(&mut packet),
        )
        .await
        .expect("transport should send a UDP datagram")
        .unwrap();
        addr
    }

    async fn assert_udp_transport_request_frame(target: SocketAddr, target_domain: Option<&str>) {
        let server = run_udp_associate_test_server(socks5_udp_associate_reply(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await;
        let transport = dial_udp_test_transport(&server, target, target_domain).await;
        let payload = b"request payload";

        transport.send_packet(payload).await.unwrap();
        let mut received = [0u8; 1024];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.relay.recv_from(&mut received),
        )
        .await
        .expect("relay should receive a request")
        .unwrap();

        assert_eq!(
            &received[..n],
            expected_socks5_udp_datagram(target, target_domain, 0, payload)
        );
    }

    async fn assert_udp_transport_invalid_data(datagram: &[u8]) {
        let server = run_udp_associate_test_server(socks5_udp_associate_reply(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await;
        let transport =
            dial_udp_test_transport(&server, "198.51.100.9:53".parse().unwrap(), None).await;
        let client_addr = transport_client_addr(&server, &transport).await;
        server.relay.send_to(datagram, client_addr).await.unwrap();

        let mut received = [0u8; 1024];
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            transport.recv_packet(&mut received),
        )
        .await
        .expect("malformed SOCKS5 UDP frame should complete with an error")
        .expect_err("malformed SOCKS5 UDP frame should fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn socks5_udp_transport_frames_ipv4_request() {
        assert_udp_transport_request_frame("198.51.100.7:53".parse().unwrap(), None).await;
    }

    #[tokio::test]
    async fn socks5_udp_transport_frames_ipv6_request() {
        assert_udp_transport_request_frame("[2001:db8::7]:53".parse().unwrap(), None).await;
    }

    #[tokio::test]
    async fn socks5_udp_transport_frames_domain_request() {
        assert_udp_transport_request_frame(
            "198.51.100.7:53".parse().unwrap(),
            Some("dns.example.test"),
        )
        .await;
    }

    #[tokio::test]
    async fn socks5_udp_transport_strips_reply_header() {
        let server = run_udp_associate_test_server(socks5_udp_associate_reply(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await;
        let target: SocketAddr = "203.0.113.9:5353".parse().unwrap();
        let transport = dial_udp_test_transport(&server, target, None).await;
        let client_addr = transport_client_addr(&server, &transport).await;
        server
            .relay
            .send_to(
                &expected_socks5_udp_datagram(target, None, 0, b"reply payload"),
                client_addr,
            )
            .await
            .unwrap();

        let mut received = [0u8; 1024];
        let (n, source) = transport.recv_packet(&mut received).await.unwrap();
        assert_eq!(&received[..n], b"reply payload");
        assert_eq!(source, target);
    }

    #[tokio::test]
    async fn socks5_udp_transport_reports_reply_source_as_logical_relay_peer() {
        let server = run_udp_associate_test_server(socks5_udp_associate_reply(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await;
        let target: SocketAddr = "203.0.113.9:5353".parse().unwrap();
        let transport = dial_udp_test_transport(&server, target, None).await;
        let client_addr = transport_client_addr(&server, &transport).await;
        server
            .relay
            .send_to(
                &expected_socks5_udp_datagram(target, None, 0, b"reply payload"),
                client_addr,
            )
            .await
            .unwrap();

        let mut received = [0u8; 1024];
        let (n, source) = transport.recv_packet(&mut received).await.unwrap();
        assert_eq!(&received[..n], b"reply payload");
        assert_eq!(source, target);
        assert_eq!(
            source,
            transport.relay_addr(),
            "honk-core accepts the first reply only when its source matches relay_addr"
        );
    }

    #[tokio::test]
    async fn socks5_udp_transport_maps_mismatched_ipv4_wire_source_to_logical_target() {
        let server = run_udp_associate_test_server(socks5_udp_associate_reply(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await;
        let target: SocketAddr = "203.0.113.9:5353".parse().unwrap();
        let wire_source: SocketAddr = "198.51.100.50:5353".parse().unwrap();
        assert_ne!(wire_source, target);
        let transport = dial_udp_test_transport(&server, target, None).await;
        let client_addr = transport_client_addr(&server, &transport).await;
        server
            .relay
            .send_to(
                &expected_socks5_udp_datagram(wire_source, None, 0, b"mismatched-src"),
                client_addr,
            )
            .await
            .unwrap();

        let mut received = [0u8; 1024];
        let (n, source) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            transport.recv_packet(&mut received),
        )
        .await
        .expect("recv_packet should complete without network I/O")
        .expect("valid RFC1928 frame must be accepted");
        assert_eq!(&received[..n], b"mismatched-src");
        assert_eq!(
            source, target,
            "PacketTransport peer must be logical target_addr, not RFC1928 wire source"
        );
        assert_eq!(source, transport.relay_addr());
    }

    #[tokio::test]
    async fn socks5_udp_transport_maps_domain_wire_source_to_logical_target_without_dns() {
        let server = run_udp_associate_test_server(socks5_udp_associate_reply(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await;
        let target: SocketAddr = "203.0.113.11:5353".parse().unwrap();
        let transport = dial_udp_test_transport(&server, target, None).await;
        let client_addr = transport_client_addr(&server, &transport).await;
        // Domain wire source must not trigger bootstrap/system DNS; peer is logical target.
        server
            .relay
            .send_to(
                &expected_socks5_udp_datagram(
                    target,
                    Some("reply-src.invalid.test"),
                    0,
                    b"domain-wire",
                ),
                client_addr,
            )
            .await
            .unwrap();

        let mut received = [0u8; 1024];
        let (n, source) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            transport.recv_packet(&mut received),
        )
        .await
        .expect("domain wire source must not block on DNS")
        .expect("valid domain ATYP frame must be accepted without resolving");
        assert_eq!(&received[..n], b"domain-wire");
        assert_eq!(
            source, target,
            "domain wire source must map to logical target_addr without DNS"
        );
        assert_eq!(source, transport.relay_addr());
    }

    #[tokio::test]
    async fn socks5_udp_transport_rejects_invalid_domain_encoding() {
        assert_udp_transport_invalid_data(&[
            0x00,
            0x00,
            0x00,
            ATYP_DOMAIN,
            4,
            0xff,
            0xfe,
            0xfd,
            0xfc,
            0x00,
            53,
        ])
        .await;
    }

    #[tokio::test]
    async fn socks5_udp_transport_ignores_malformed_non_relay_datagrams() {
        let server = run_udp_associate_test_server(socks5_udp_associate_reply(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await;
        let target: SocketAddr = "203.0.113.10:5353".parse().unwrap();
        let transport = dial_udp_test_transport(&server, target, None).await;
        let client_addr = transport_client_addr(&server, &transport).await;
        let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        attacker
            .send_to(
                &[0x01, 0x00, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0, 53],
                client_addr,
            )
            .await
            .unwrap();
        server
            .relay
            .send_to(
                &expected_socks5_udp_datagram(target, None, 0, b"accepted"),
                client_addr,
            )
            .await
            .unwrap();

        let mut received = [0u8; 1024];
        let (n, source) = transport.recv_packet(&mut received).await.unwrap();
        assert_eq!(&received[..n], b"accepted");
        assert_eq!(source, target);
    }

    #[tokio::test]
    async fn socks5_udp_transport_skips_fragmented_datagrams() {
        let server = run_udp_associate_test_server(socks5_udp_associate_reply(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await;
        let target: SocketAddr = "203.0.113.10:5353".parse().unwrap();
        let transport = dial_udp_test_transport(&server, target, None).await;
        let client_addr = transport_client_addr(&server, &transport).await;
        server
            .relay
            .send_to(
                &expected_socks5_udp_datagram(target, None, 1, b"fragment"),
                client_addr,
            )
            .await
            .unwrap();
        server
            .relay
            .send_to(
                &expected_socks5_udp_datagram(target, None, 0, b"accepted"),
                client_addr,
            )
            .await
            .unwrap();

        let mut received = [0u8; 1024];
        let (n, source) = transport.recv_packet(&mut received).await.unwrap();
        assert_eq!(&received[..n], b"accepted");
        assert_eq!(source, target);
    }

    #[tokio::test]
    async fn socks5_udp_transport_rejects_nonzero_rsv() {
        assert_udp_transport_invalid_data(&[0x01, 0x00, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0, 53])
            .await;
    }

    #[tokio::test]
    async fn socks5_udp_transport_rejects_unknown_atyp() {
        assert_udp_transport_invalid_data(&[0x00, 0x00, 0x00, 0x7f]).await;
    }

    #[tokio::test]
    async fn socks5_udp_transport_rejects_truncated_frame() {
        assert_udp_transport_invalid_data(&[0x00, 0x00, 0x00, ATYP_IPV4, 127, 0]).await;
    }

    #[tokio::test]
    async fn socks5_udp_transport_keeps_control_open_until_drop() {
        let mut server = run_udp_associate_test_server(socks5_udp_associate_reply(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await;
        let transport =
            dial_udp_test_transport(&server, "198.51.100.11:53".parse().unwrap(), None).await;

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                &mut server.control_closed,
            )
            .await
            .is_err(),
            "UDP transport must retain the control stream"
        );

        drop(transport);
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            &mut server.control_closed,
        )
        .await
        .expect("control stream should close when transport drops")
        .expect("SOCKS5 server should observe the control stream closing");
    }

    #[tokio::test]
    async fn socks5_udp_transport_reports_control_eof() {
        let mut server = run_udp_associate_test_server(socks5_udp_associate_reply(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await;
        let transport =
            dial_udp_test_transport(&server, "198.51.100.12:53".parse().unwrap(), None).await;
        server.close_control();

        let mut received = [0u8; 1024];
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            transport.recv_packet(&mut received),
        )
        .await
        .expect("control EOF should wake recv_packet")
        .expect_err("control EOF should fail recv_packet");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn socks5_udp_association_uses_control_peer_for_unspecified_bnd_addr() {
        let server = run_udp_associate_test_server(socks5_udp_associate_reply(SocketAddr::new(
            "0.0.0.0".parse().unwrap(),
            0,
        )))
        .await;
        let relay_port = server.relay.local_addr().unwrap().port();
        let (_socket, relay_addr, _control) = Socks5Handler::udp_association(
            &socks5_test_node(server.proxy_addr),
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(
            relay_addr,
            SocketAddr::new(server.proxy_addr.ip(), relay_port)
        );
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn socks5_udp_transport_resolves_domain_bnd_addr() {
        let _lock = crate::bootstrap::GLOBAL_TEST_LOCK.lock().unwrap();
        let resolver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        let (query_tx, query_rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut query_tx = Some(query_tx);
            for _ in 0..2 {
                let mut buf = [0u8; 512];
                let (n, peer) = resolver.recv_from(&mut buf).await.unwrap();
                if let Some(query_tx) = query_tx.take() {
                    query_tx.send(buf[..n].to_vec()).unwrap();
                }

                let mut response = buf[..n].to_vec();
                response[2] = 0x81;
                response[3] = 0x80;
                response[6] = 0;
                response[7] = 1;
                response.extend_from_slice(&[0xC0, 0x0C]);
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&60u32.to_be_bytes());
                response.extend_from_slice(&4u16.to_be_bytes());
                response.extend_from_slice(&[127, 0, 0, 1]);
                resolver.send_to(&response, peer).await.unwrap();
            }
        });

        crate::bootstrap::set_global(crate::bootstrap::BootstrapResolver::parse(&format!(
            "udp://{resolver_addr}"
        )));
        let server =
            run_udp_associate_test_server(socks5_udp_associate_domain_reply("socks-relay.test", 0))
                .await;
        let result = Socks5Handler::new()
            .dial_udp_transport(
                &socks5_test_node(server.proxy_addr),
                "198.51.100.14:53".parse().unwrap(),
                None,
                std::time::Duration::from_secs(1),
            )
            .await;
        crate::bootstrap::set_global(None);
        let transport = result.unwrap();

        let query = query_rx.await.unwrap();
        assert!(
            query
                .windows(b"\x0bsocks-relay\x04test".len())
                .any(|window| window == b"\x0bsocks-relay\x04test")
        );
        transport_client_addr(&server, &transport).await;
    }

    #[tokio::test]
    async fn socks5_udp_transport_rejects_long_domain() {
        let server = run_udp_associate_test_server(socks5_udp_associate_reply(
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await;
        let long_domain = "a".repeat(u8::MAX as usize + 1);
        let result = Socks5Handler::new()
            .dial_udp_transport(
                &socks5_test_node(server.proxy_addr),
                "198.51.100.15:53".parse().unwrap(),
                Some(&long_domain),
                std::time::Duration::from_secs(1),
            )
            .await;

        assert!(result.is_err(), "domains longer than 255 bytes must fail");
    }

    async fn run_test_socks5_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        // Simple SOCKS5 server: no auth, always succeed
                        let mut buf = [0u8; 256];

                        // Read greeting
                        let _ = stream.read(&mut buf).await.unwrap();
                        assert!(buf[0] == SOCKS5_VERSION);

                        // Reply: no auth
                        stream
                            .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
                            .await
                            .unwrap();

                        // Read request
                        let _ = stream.read(&mut buf).await.unwrap();
                        assert!(buf[0] == SOCKS5_VERSION);
                        assert!(buf[1] == CMD_CONNECT);

                        // Reply: success, bind to 0.0.0.0:0
                        let reply = [
                            SOCKS5_VERSION,
                            REP_SUCCESS,
                            0x00, // RSV
                            ATYP_IPV4,
                            0,
                            0,
                            0,
                            0, // 0.0.0.0
                            0,
                            0, // port 0
                        ];
                        stream.write_all(&reply).await.unwrap();

                        // Keep connection alive briefly for test
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    });
                }
            }
        });

        addr
    }

    #[tokio::test]
    async fn test_socks5_handshake_no_auth() {
        let server_addr = run_test_socks5_server().await;

        let node = Node {
            name: "test".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
            address: server_addr.ip().to_string(),
            host: String::new(),
            port: server_addr.port(),
            ..Default::default()
        };

        let handler = Socks5Handler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let result = handler
            .dial(
                &node,
                target,
                Some("example.com"),
                std::time::Duration::from_secs(3),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_socks5_connectivity() {
        let server_addr = run_test_socks5_server().await;

        let node = Node {
            name: "test".into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
            address: server_addr.ip().to_string(),
            host: String::new(),
            port: server_addr.port(),
            ..Default::default()
        };

        let handler = Socks5Handler::new();
        assert!(handler.test_connectivity(&node).await);
    }

    #[test]
    fn test_pool_ready_streams_declared() {
        // SOCKS5 completed-CONNECT streams are pure data channels and may
        // be pooled for direct reuse.
        let pool_ready_streams =
            crate::descriptor::descriptor(NodeProtocol::Socks5).pool_ready_streams;
        assert!(pool_ready_streams(&Node::default()));
    }
}
