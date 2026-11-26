//! SOCKS5 (RFC 1928) with no-auth and user/pass (RFC 1929) authentication.

use async_trait::async_trait;
use honk_config::node::Node;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use super::packet::send_with_admission_check;
use super::{
    AsyncReadWrite, MultiTargetTransport, PacketOutbound, PacketTransport, PreparedUdpTransport,
    ProbeableOutbound, ProxyStream, SharedSourceOutbound, TcpOutbound, TunnelDialOptions,
};

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
    async fn handshake<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
        stream: &mut S,
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
            // A tunneled carrier may buffer writes until flushed; a TCP
            // flush is a no-op.
            stream.flush().await?;

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
                    stream.flush().await?;

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

            super::transport::write_request(&mut *stream, &request).await?;

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

    async fn open_udp(
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Socks5UdpTransport> {
        if target_domain.is_some_and(|domain| domain.len() > usize::from(u8::MAX)) {
            anyhow::bail!("SOCKS5 UDP domain exceeds 255 bytes");
        }
        let (socket, relay_addr, control) = Self::udp_association(node, connect_timeout).await?;
        socket.connect(relay_addr).await?;
        Ok(Socks5UdpTransport {
            socket,
            control: tokio::sync::Mutex::new(control),
            recv_buf: tokio::sync::Mutex::new(vec![0u8; u16::MAX as usize]),
            target_addr: target,
            target_domain: target_domain.map(Box::from),
        })
    }
}

/// Source of one inbound datagram as named by its RFC 1928 header.
enum WireSource<'a> {
    Addr(SocketAddr),
    Domain(&'a str, u16),
}

/// One UDP association (control TCP + UDP socket connected to the relay) that
/// carries every destination of a client source.
#[derive(Debug)]
struct Socks5UdpTransport {
    socket: UdpSocket,
    control: tokio::sync::Mutex<TcpStream>,
    /// Reused connected-UDP receive scratch; never reallocated per packet.
    recv_buf: tokio::sync::Mutex<Vec<u8>>,
    /// Default destination of `send_packet`, and the only name a domain
    /// source may project to.
    target_addr: SocketAddr,
    target_domain: Option<Box<str>>,
}

impl Socks5UdpTransport {
    fn invalid_packet(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    /// Strict RFC 1928 UDP header validation; returns the wire source and the
    /// payload offset. A truncated, non-zero-RSV, fragmented (never
    /// reassembled) or badly named datagram is its own UDP packet, so it is
    /// dropped (`None`) without ending the association; an unknown ATYP stays
    /// terminal.
    fn parse_packet(packet: &[u8]) -> io::Result<Option<(WireSource<'_>, usize)>> {
        fn drop_packet<T>(reason: &'static str) -> io::Result<Option<T>> {
            debug!("SOCKS5 UDP: dropped relay datagram: {reason}");
            Ok(None)
        }

        if packet.len() < 4 {
            return drop_packet("truncated header");
        }
        if packet[..2] != [0x00, 0x00] {
            return drop_packet("non-zero RSV");
        }
        if packet[2] != 0 {
            return drop_packet("fragment");
        }

        let (source, payload_start) = match packet[3] {
            ATYP_IPV4 => {
                if packet.len() < 10 {
                    return drop_packet("truncated IPv4 frame");
                }
                let ip = std::net::Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
                let port = u16::from_be_bytes([packet[8], packet[9]]);
                (WireSource::Addr(SocketAddr::new(ip.into(), port)), 10)
            }
            ATYP_IPV6 => {
                if packet.len() < 22 {
                    return drop_packet("truncated IPv6 frame");
                }
                let ip = std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&packet[4..20]).expect("slice length"),
                );
                let port = u16::from_be_bytes([packet[20], packet[21]]);
                (WireSource::Addr(SocketAddr::new(ip.into(), port)), 22)
            }
            ATYP_DOMAIN => {
                if packet.len() < 5 {
                    return drop_packet("truncated domain frame");
                }
                let domain_len = packet[4] as usize;
                let domain_end = 5 + domain_len;
                if packet.len() < domain_end + 2 {
                    return drop_packet("truncated domain frame");
                }
                let Ok(domain) = std::str::from_utf8(&packet[5..domain_end]) else {
                    return drop_packet("invalid domain encoding");
                };
                let port = u16::from_be_bytes([packet[domain_end], packet[domain_end + 1]]);
                (WireSource::Domain(domain, port), domain_end + 2)
            }
            _ => return Err(Self::invalid_packet("SOCKS5 UDP: unsupported ATYP")),
        };

        Ok(Some((source, payload_start)))
    }

    /// One datagram: the request header is written straight into the outgoing
    /// packet, which is the only per-packet allocation.
    async fn send(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        admitted: Option<&AtomicBool>,
    ) -> io::Result<()> {
        let header_len = match (domain, target) {
            (Some(domain), _) => 7 + domain.len(),
            (None, SocketAddr::V4(_)) => 10,
            (None, SocketAddr::V6(_)) => 22,
        };
        let mut packet = Vec::with_capacity(header_len + data.len());
        packet.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG
        match (domain, target) {
            (Some(domain), _) => {
                let domain_len = u8::try_from(domain.len()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "SOCKS5 UDP domain exceeds 255 bytes",
                    )
                })?;
                packet.extend_from_slice(&[ATYP_DOMAIN, domain_len]);
                packet.extend_from_slice(domain.as_bytes());
            }
            (None, SocketAddr::V4(v4)) => {
                packet.push(ATYP_IPV4);
                packet.extend_from_slice(&v4.ip().octets());
            }
            (None, SocketAddr::V6(v6)) => {
                packet.push(ATYP_IPV6);
                packet.extend_from_slice(&v6.ip().octets());
            }
        }
        packet.extend_from_slice(&target.port().to_be_bytes());
        packet.extend_from_slice(data);
        self.socket
            .send(&packet)
            .await
            .map_err(super::send_size_refusal)?;
        if let Some(admitted) = admitted {
            admitted.store(true, Ordering::Release);
        }
        Ok(())
    }
}

#[async_trait]
impl PacketTransport for Socks5UdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target_addr
    }
    /// The relay names the real remote peer in every reply header.
    fn allows_full_cone_replies(&self) -> bool {
        true
    }
    fn send_timeout_is_congestion(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.send(self.target_addr, self.target_domain.as_deref(), data, None)
            .await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut control = self.control.lock().await;
        let mut packet = self.recv_buf.lock().await;
        let mut control_probe = [0u8; 1];

        loop {
            tokio::select! {
                received = self.socket.recv(&mut packet) => {
                    let n = received?;
                    let Some((source, payload_start)) = Self::parse_packet(&packet[..n])? else {
                        continue;
                    };
                    let peer = match source {
                        WireSource::Addr(peer) => {
                            SocketAddr::new(peer.ip().to_canonical(), peer.port())
                        }
                        WireSource::Domain(domain, port) => {
                            let Some(peer) = super::addr::dialed_domain_peer(
                                self.target_domain.as_deref(),
                                self.target_addr,
                                domain,
                                port,
                            ) else {
                                continue;
                            };
                            peer
                        }
                    };
                    let payload = &packet[payload_start..n];
                    if payload.len() > buf.len() {
                        return Err(Self::invalid_packet("SOCKS5 UDP: payload exceeds receive buffer"));
                    }
                    buf[..payload.len()].copy_from_slice(payload);
                    return Ok((payload.len(), peer));
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
impl MultiTargetTransport for Socks5UdpTransport {
    async fn send_to(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        _confirmed: bool,
        admitted: Option<&AtomicBool>,
    ) -> io::Result<()> {
        let domain = crate::proxy::addr::dialed_name(self.target_domain.as_deref(), domain);
        self.send(target, domain, data, admitted).await
    }

    async fn send_to_checked(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        admitted: Option<&AtomicBool>,
        current: &(dyn Fn() -> bool + Send + Sync),
    ) -> io::Result<()> {
        let local_admitted = AtomicBool::new(false);
        let admitted = admitted.unwrap_or(&local_admitted);
        let domain = crate::proxy::addr::dialed_name(self.target_domain.as_deref(), domain);
        send_with_admission_check(
            self.send(target, domain, data, Some(admitted)),
            admitted,
            current,
        )
        .await
    }

    fn carrier_addr(&self) -> Option<SocketAddr> {
        self.socket.peer_addr().ok()
    }
}

#[async_trait]
impl TcpOutbound for Socks5Handler {
    fn confirms_target_on_open(&self) -> bool {
        true
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = format!("{}:{}", node.host(), node.port);
        debug!("SOCKS5: connecting to {} for target {}", addr, target);
        let stream = crate::util::connect_proxy(&addr, connect_timeout).await?;
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

    async fn dial_over(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        mut carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        _options: TunnelDialOptions,
    ) -> anyhow::Result<ProxyStream> {
        let config = runtime.node.socks5().unwrap();
        Self::handshake(
            &mut carrier,
            target,
            target_domain,
            config.username.as_deref(),
            config.password.as_deref(),
        )
        .await?;
        Ok(ProxyStream {
            stream: carrier,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

#[async_trait]
impl SharedSourceOutbound for Socks5Handler {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        let _ = speculative;
        // Publishes no node state, so a losing preparation just drops the
        // control stream and socket.
        let transport = Self::open_udp(
            runtime.node.as_ref(),
            target,
            target_domain,
            connect_timeout,
        )
        .await?;
        Ok(PreparedUdpTransport::ready(Arc::new(transport)))
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
        let transport = Self::open_udp(node, target, target_domain, connect_timeout).await?;
        crate::runtime::flow_observation::milestone(
            crate::runtime::flow_observation::Milestone::TransportReady,
        );
        Ok(Arc::new(transport))
    }
}

#[async_trait]
impl ProbeableOutbound for Socks5Handler {}

#[cfg(test)]
mod tests;
