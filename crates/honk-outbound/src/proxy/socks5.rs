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
#[derive(Default)]
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
            let greeting: &[u8] = if username.is_some() && password.is_some() {
                &[SOCKS5_VERSION, 2, METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]
            } else {
                &[SOCKS5_VERSION, 1, METHOD_NO_AUTH]
            };
            stream.write_all(greeting).await?;

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
                let domain_len = u8::try_from(domain.len())
                    .map_err(|_| anyhow::anyhow!("SOCKS5: domain exceeds 255 bytes"))?;
                request[3] = ATYP_DOMAIN;
                request.truncate(4);
                request.push(domain_len);
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
            crate::runtime::flow_observation::milestone(
                crate::runtime::flow_observation::Milestone::TargetRequestSent,
            );

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
                let error = anyhow::anyhow!(
                    "SOCKS5: server replied error: {} (0x{:02x})",
                    msg,
                    reply_code
                );
                return Err(
                    if (REP_CONNECTION_NOT_ALLOWED..=REP_TTL_EXPIRED).contains(&reply_code)
                        && reply_header[2] == 0
                        && matches!(reply_header[3], ATYP_IPV4 | ATYP_DOMAIN | ATYP_IPV6)
                    {
                        super::TargetFailure(error).into()
                    } else {
                        error
                    },
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
            crate::runtime::flow_observation::milestone(
                crate::runtime::flow_observation::Milestone::TargetConfirmed,
            );
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
        // The TCP path bounds the same exchange at `handshake`; without a
        // deadline here a peer that accepts the connection and then goes
        // silent leaves this await pending, and the caller only bounds the
        // connect that precedes it.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let greeting: &[u8] = if username.is_some() && password.is_some() {
                &[SOCKS5_VERSION, 2, METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]
            } else {
                &[SOCKS5_VERSION, 1, METHOD_NO_AUTH]
            };
            stream.write_all(greeting).await?;

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
            Ok::<(), anyhow::Error>(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("SOCKS5 UDP: negotiation timed out"))??;

        let relay_addr = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
                    let ip = std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(&addr[..16]).expect("slice length"),
                    );
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
                    let resolution = crate::bootstrap::resolve(domain);
                    let (resolution, selection) =
                        crate::runtime::flow_observation::observe_resolution(resolution).await;
                    let ip = resolution?.into_iter().next().ok_or_else(|| {
                        anyhow::anyhow!("SOCKS5 UDP: relay domain resolved empty")
                    })?;
                    if let Some(selection) = selection {
                        selection.selected_ip(ip);
                    }
                    SocketAddr::new(ip, port)
                }
                a => anyhow::bail!("SOCKS5 UDP: unknown address type 0x{:02x}", a),
            };
            Ok::<_, anyhow::Error>(relay_addr)
        })
        .await
        .map_err(|_| anyhow::anyhow!("SOCKS5 UDP: associate timed out"))??;

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
    socket: UdpSocket,
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
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
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
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );

        Ok(Arc::new(Socks5UdpTransport {
            socket: udp_socket,
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
mod tests;
