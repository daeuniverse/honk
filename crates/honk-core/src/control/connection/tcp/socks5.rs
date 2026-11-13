//! SOCKS5 inbound sessions: RFC 1929 username/password authentication and
//! the CONNECT relay onto the ordinary outbound machinery.
//!
//! Everything between authentication and the byte relay lives in `proxy`
//! once, shared with the HTTP(S) inbound; this module keeps only the RFC
//! 1928/1929 framing. The authenticated username is carried as the flow's
//! routing user, so `user()` rules select its outbound like mihomo's
//! `in-user`.

use super::proxy::{ProxyRefusal, ProxyTargetRequest, lookup_user};
use super::*;
use honk_config::inbound::ProxyUser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Bound on the client-driven handshake before dialing; a session that
/// stalls in the handshake is dropped instead of holding admission permits.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

// RFC 1928 reply codes this inbound emits.
const REP_GENERAL: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_COMMAND_UNSUPPORTED: u8 = 0x07;
const REP_ADDRESS_UNSUPPORTED: u8 = 0x08;

fn encode_reply(rep: u8, bound: SocketAddr) -> Vec<u8> {
    let mut reply = Vec::with_capacity(26);
    reply.extend_from_slice(&[5, rep, 0]);
    reply.push(match bound {
        SocketAddr::V4(_) => 1,
        SocketAddr::V6(_) => 4,
    });
    match bound {
        SocketAddr::V4(address) => reply.extend_from_slice(&address.ip().octets()),
        SocketAddr::V6(address) => reply.extend_from_slice(&address.ip().octets()),
    }
    reply.extend_from_slice(&bound.port().to_be_bytes());
    reply
}

/// Failure replies carry no meaningful binding; echo the zeros reference
/// servers do and let the client read the reply field.
async fn write_failure(stream: &mut TcpStream, rep: u8) {
    let _ = stream.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]).await;
}

fn refusal_reply(refusal: ProxyRefusal) -> u8 {
    match refusal {
        ProxyRefusal::ResolveFailed => REP_HOST_UNREACHABLE,
        ProxyRefusal::Blocked => REP_NOT_ALLOWED,
        ProxyRefusal::NoCandidates | ProxyRefusal::DialFailed => REP_GENERAL,
    }
}

impl ControlPlaneHandle {
    /// Serve one accepted SOCKS5 session end to end. A rejected
    /// authentication or a policy refusal completes with `Ok(())` after
    /// sending the protocol-level failure reply; `Err` is reserved for
    /// transport and runtime failures the supervisor logs.
    pub(in crate::control) async fn serve_socks5(
        &self,
        mut stream: TcpStream,
        client_addr: SocketAddr,
        users: &[ProxyUser],
    ) -> anyhow::Result<()> {
        let Some((user, request)) = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            self.socks5_handshake(&mut stream, client_addr, users),
        )
        .await??
        else {
            return Ok(());
        };

        let session = match self
            .proxy_dial(&user, client_addr, request, "SOCKS5")
            .await?
        {
            Ok(session) => session,
            Err(refusal) => {
                write_failure(&mut stream, refusal_reply(refusal)).await;
                return Ok(());
            }
        };

        let bound = stream.local_addr()?;
        stream.write_all(&encode_reply(0, bound)).await?;
        debug!(
            network = "socks5",
            user = %user,
            outbound = %session.outbound_name,
            dialer = %session.node.name,
            target = %session.target_addr,
            sniffed = session.domain.as_deref().unwrap_or(""),
            src = %client_addr,
            "SOCKS5 session established"
        );
        self.proxy_relay(&mut stream, session, client_addr, "SOCKS5")
            .await
    }

    /// Greeting, RFC 1929 subnegotiation, and CONNECT request framing.
    /// `Ok(None)` means the session was refused with a protocol reply (or
    /// the peer closed); the caller then drops the socket without dialing.
    async fn socks5_handshake(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        users: &[ProxyUser],
    ) -> anyhow::Result<Option<(String, ProxyTargetRequest)>> {
        // Greeting (RFC 1928): username/password is the only method offered.
        if stream.read_u8().await? != 5 {
            return Ok(None);
        }
        let method_count = stream.read_u8().await?;
        if method_count == 0 {
            return Ok(None);
        }
        let mut methods = vec![0u8; method_count as usize];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&2) {
            let _ = stream.write_all(&[5, 0xFF]).await;
            return Ok(None);
        }
        stream.write_all(&[5, 2]).await?;

        // Subnegotiation (RFC 1929): 0x01 ULEN UNAME PLEN PASSWD.
        if stream.read_u8().await? != 1 {
            return Ok(None);
        }
        let mut username = vec![0u8; stream.read_u8().await? as usize];
        stream.read_exact(&mut username).await?;
        let mut password = vec![0u8; stream.read_u8().await? as usize];
        stream.read_exact(&mut password).await?;
        let Some(user) = lookup_user(users, &username, &password) else {
            let _ = stream.write_all(&[1, 1]).await;
            debug!(%client_addr, "SOCKS5 authentication failed");
            return Ok(None);
        };
        let user = user.username.clone();
        stream.write_all(&[1, 0]).await?;

        // Request: VER CMD RSV ATYP ADDR PORT.
        if stream.read_u8().await? != 5 {
            return Ok(None);
        }
        let command = stream.read_u8().await?;
        stream.read_u8().await?; // RSV
        let atyp = stream.read_u8().await?;
        let request = match atyp {
            1 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                let port = stream.read_u16().await?;
                ProxyTargetRequest::Address(SocketAddr::from((octets, port)))
            }
            3 => {
                let length = stream.read_u8().await?;
                let mut raw = vec![0u8; length as usize];
                stream.read_exact(&mut raw).await?;
                let port = stream.read_u16().await?;
                let Ok(domain) = String::from_utf8(raw) else {
                    write_failure(stream, REP_ADDRESS_UNSUPPORTED).await;
                    return Ok(None);
                };
                ProxyTargetRequest::Domain { domain, port }
            }
            4 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets).await?;
                let port = stream.read_u16().await?;
                ProxyTargetRequest::Address(SocketAddr::from((octets, port)))
            }
            _ => {
                write_failure(stream, REP_ADDRESS_UNSUPPORTED).await;
                return Ok(None);
            }
        };
        // CONNECT only: BIND and UDP ASSOCIATE are refused, and the request
        // is fully consumed above so the reply is all the client needs.
        if command != 1 {
            write_failure(stream, REP_COMMAND_UNSUPPORTED).await;
            return Ok(None);
        }
        Ok(Some((user, request)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_reply_echoes_the_bound_local_address() {
        let v4 = encode_reply(0, "192.0.2.7:1024".parse().unwrap());
        assert_eq!(
            v4,
            vec![
                5,
                0,
                0,
                1,
                192,
                0,
                2,
                7,
                (1024 >> 8) as u8,
                (1024 & 0xFF) as u8
            ]
        );
        let v6 = encode_reply(0, "[2001:db8::1]:80".parse().unwrap());
        assert_eq!(v6[0..4], [5, 0, 0, 4]);
        assert_eq!(v6.len(), 4 + 16 + 2);
        assert_eq!(
            &v6[4..4 + 16],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].as_slice()
        );
    }
}
