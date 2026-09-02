use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

use super::{AnyTlsSession, StreamEvent};
use crate::proxy::PacketTransport;
use crate::proxy::uot::{
    UotCodec as _, UotV1, UotV2, V1_ATYP_V4 as UOT_V1_ATYP_V4, V1_ATYP_V6 as UOT_V1_ATYP_V6,
};

#[cfg(test)]
use super::{
    CMD_FIN, CMD_PSH, CMD_SETTINGS, CMD_SYN, PaddingScheme, PaddingState, WRITER_CONTROL_RESERVED,
    WRITER_IO_TIMEOUT, WRITER_QUEUE_CAP, read_frame, write_frame,
};
#[cfg(test)]
use crate::proxy::addr;
#[cfg(test)]
use crate::proxy::uot::V1_ATYP_DOMAIN as UOT_V1_ATYP_DOMAIN;
#[cfg(test)]
use crate::session::ManagedSession as _;
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use tokio::io::AsyncReadExt;

/// UoT response framing detected per stream. The sing-box spec's connect
/// mode is `u16be len + payload`, but some third-party servers answer
/// connect requests in the v1 packet layout (`atyp + addr + port +
/// u16be len + payload`) — detected on the first datagram by matching the
/// echoed destination, never by guessing from the length bytes (a v2
/// length high byte can look like a v1 atyp).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UotMode {
    V2Connect,
    V1Packet,
}

/// Framed UoT transport over a multiplexed AnyTLS stream. The connect request
/// and first datagram share one PSH; later datagrams go straight to the session
/// writer. Inbound bytes arrive directly from the demux through a bounded queue;
/// saturation retires the sid rather than corrupting the UoT byte stream.
pub(crate) struct AnyTlsUotTransport {
    pub(super) session: Arc<AnyTlsSession>,
    pub(super) sid: u32,
    pub(super) receive: tokio::sync::Mutex<UotReceiveState>,
    /// UoT v2 connect request, atomically consumed when its first datagram is queued.
    pub(super) setup: tokio::sync::Mutex<Option<bytes::Bytes>>,
    pub(super) target: SocketAddr,
    pub(super) target_domain: Option<String>,
    /// Stream-slot capacity, held for the transport's life.
    pub(super) _permit: crate::session::SessionPermit<AnyTlsSession>,
}

pub(super) struct UotReceiveState {
    rx: mpsc::Receiver<StreamEvent>,
    mode: Option<UotMode>,
    buffered: bytes::BytesMut,
}

impl UotReceiveState {
    pub(super) fn new(rx: mpsc::Receiver<StreamEvent>) -> Self {
        Self {
            rx,
            mode: None,
            buffered: bytes::BytesMut::new(),
        }
    }
}

// The largest valid buffered state is one byte short of a maximum v1
// domain-form datagram followed by one full AnyTLS PSH.
const UOT_MAX_V1_HEADER_BYTES: usize = 1 + 1 + u8::MAX as usize + 2 + 2;
const UOT_MAX_BUFFERED_BYTES: usize =
    UOT_MAX_V1_HEADER_BYTES + u16::MAX as usize + u16::MAX as usize - 1;
// anytls-go 0.0.13 relays through sing v0.5.1's 16 KiB UDP buffer; a larger
// UoT packet makes the reference server close the logical stream.
const UOT_MAX_PACKET_SIZE: usize = 16 * 1024;

impl AnyTlsUotTransport {
    fn detect_uot_mode(&self, data: &[u8]) -> std::io::Result<Option<UotMode>> {
        if data.len() < 2 {
            return Ok(None);
        }
        let v2_frame_len = 2 + u16::from_be_bytes([data[0], data[1]]) as usize;
        match UotV1::header(data) {
            Ok(Some((header, _)))
                if v1_header_matches(data, header, &self.target, self.target_domain.as_deref()) =>
            {
                Ok(Some(UotMode::V1Packet))
            }
            Ok(Some(_)) | Err(_) => Ok(Some(UotMode::V2Connect)),
            Ok(None) if data.len() >= v2_frame_len => Ok(Some(UotMode::V2Connect)),
            Ok(None) => Ok(None),
        }
    }

    fn next_uot_frame(
        &self,
        state: &mut UotReceiveState,
    ) -> std::io::Result<Option<crate::proxy::uot::FrameBounds>> {
        if state.mode.is_none() {
            state.mode = self.detect_uot_mode(&state.buffered)?;
        }
        match state.mode {
            None => Ok(None),
            Some(UotMode::V2Connect) => UotV2::frame_bounds(&state.buffered),
            Some(UotMode::V1Packet) => UotV1::frame_bounds(&state.buffered),
        }
    }
}

/// Whether the v1 header at the start of `data` echoes the connect
/// destination (source == the requested target).
fn v1_header_matches(
    data: &[u8],
    header: usize,
    target: &SocketAddr,
    target_domain: Option<&str>,
) -> bool {
    let addr_end = header - 4; // before port(2) + len(2)
    let port = u16::from_be_bytes([data[addr_end], data[addr_end + 1]]);
    if port != target.port() {
        return false;
    }
    match data[0] {
        UOT_V1_ATYP_V4 => {
            target.ip()
                == std::net::IpAddr::V4(std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]))
        }
        UOT_V1_ATYP_V6 => {
            let ip: [u8; 16] = data[1..17].try_into().unwrap_or([0; 16]);
            target.ip() == std::net::IpAddr::V6(ip.into())
        }
        _ => {
            let domain = String::from_utf8_lossy(&data[2..addr_end]);
            Some(domain.as_ref()) == target_domain
        }
    }
}

/// Per-stream UoT demux queue depth. At ~1.2KB per datagram, 4096 entries
/// absorb a ~40ms burst at 100k pps while the reply handler drains. A full
/// queue retires only this sid; arbitrary chunks cannot be dropped safely.
pub(super) const UOT_DRAIN_QUEUE_CAP: usize = 4096;

impl Drop for AnyTlsUotTransport {
    fn drop(&mut self) {
        self.session.end_uot_stream(self.sid, true);
    }
}

impl std::fmt::Debug for AnyTlsUotTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsUotTransport")
            .field("sid", &self.sid)
            .field("target", &self.target)
            .finish()
    }
}

impl AnyTlsUotTransport {
    async fn send_packet_inner(&self, data: &[u8], confirmed: bool) -> std::io::Result<()> {
        let packet = crate::proxy::uot::encode_packet(data, UOT_MAX_PACKET_SIZE)?;
        self.session.ensure_stream_registered(self.sid)?;
        let mut setup = self.setup.lock().await;
        let Some(request) = setup.as_ref() else {
            drop(setup);
            return if confirmed {
                self.session
                    .write_uot_datagram_confirmed(self.sid, packet)
                    .await
            } else {
                self.session.write_uot_datagram(self.sid, packet).await
            };
        };

        let permit = self.session.acquire_data_permit().await?;
        self.session.ensure_stream_registered(self.sid)?;
        let mut payload = bytes::BytesMut::with_capacity(request.len() + packet.len());
        payload.extend_from_slice(request);
        payload.extend_from_slice(&packet);
        if confirmed {
            let completed = self.session.enqueue_confirmed_data_with_permit(
                self.sid,
                payload.freeze(),
                permit,
            )?;
            setup.take();
            drop(setup);
            AnyTlsSession::wait_for_confirmed_data(completed).await
        } else {
            self.session
                .enqueue_data_with_permit(self.sid, payload.freeze(), permit)?;
            setup.take();
            Ok(())
        }
    }
}

#[async_trait]
impl PacketTransport for AnyTlsUotTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_packet_inner(data, false).await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_packet_inner(data, true).await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut receive = self.receive.lock().await;
        loop {
            if let Some(frame) = self.next_uot_frame(&mut receive)? {
                let payload_len = crate::proxy::uot::copy_frame(&mut receive.buffered, frame, buf)?;
                return Ok((payload_len, self.target));
            }

            let event = receive.rx.recv().await.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "UoT stream closed")
            })?;
            match event {
                StreamEvent::Data(data) => {
                    if receive.buffered.len().saturating_add(data.len()) > UOT_MAX_BUFFERED_BYTES {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "UoT stream frame exceeds buffer limit",
                        ));
                    }
                    receive.buffered.extend_from_slice(&data);
                }
                StreamEvent::Fin => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "UoT stream closed by server",
                    ));
                }
                StreamEvent::Error(error) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        error.to_string(),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod uot_tests {
    use super::*;

    #[test]
    fn test_uot_request_uses_socks5_address_form() {
        let v4 = addr::encode_address("1.2.3.4:53".parse().unwrap(), None).unwrap();
        assert_eq!(v4, vec![0x01, 1, 2, 3, 4, 0, 53]);
        let v6 = addr::encode_address("[2606:4700:4700::1111]:853".parse().unwrap(), None).unwrap();
        assert_eq!(v6[0], 0x04);
        assert_eq!(v6.len(), 1 + 16 + 2);
        let fqdn =
            addr::encode_address("1.2.3.4:443".parse().unwrap(), Some("example.com")).unwrap();
        assert_eq!(fqdn[0], 0x03);
        assert_eq!(fqdn[1], 11);
        assert_eq!(&fqdn[2..13], b"example.com");
        assert_eq!(&fqdn[13..], &[1, 187]);
    }
}

#[cfg(test)]
mod uot_transport_tests {
    use super::*;

    const TEST_AUTH: &[u8] = b"test-auth";
    const TEST_SETTINGS: &[u8] = b"test-settings";

    /// Open a UoT stream on an in-memory test session; returns the
    /// transport and the server end of the session transport.
    async fn uot_test_transport(
        target: SocketAddr,
    ) -> (Arc<AnyTlsUotTransport>, tokio::io::DuplexStream) {
        uot_test_transport_with_capacity(target, 1 << 20).await
    }

    async fn uot_test_transport_with_capacity(
        target: SocketAddr,
        capacity: usize,
    ) -> (Arc<AnyTlsUotTransport>, tokio::io::DuplexStream) {
        let addr = "127.0.0.1:2443";
        let (client_end, mut server_end) = tokio::io::duplex(capacity);
        let (read, write) = tokio::io::split(client_end);
        let padding_state = Arc::new(PaddingState {
            current: parking_lot::RwLock::new(Arc::new(PaddingScheme::parse(b"stop=0").unwrap())),
        });
        let session = AnyTlsSession::establish(
            addr,
            Box::new(read),
            Box::new(write),
            TEST_AUTH,
            bytes::Bytes::from_static(TEST_SETTINGS),
            padding_state,
        )
        .await
        .unwrap();
        session.flush_initial_settings_for_test().unwrap();

        let mut auth = vec![0u8; TEST_AUTH.len()];
        server_end.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, TEST_AUTH);
        let (cmd, _, _) = read_frame(&mut server_end).await.unwrap();
        assert_eq!(cmd, CMD_SETTINGS);
        let permit = session.try_reserve().unwrap();
        let (sid, rx, guard) = session
            .open_uot_stream(vec![0x01, 0, 0, 0, 0, 0, 0], permit)
            .await
            .unwrap();
        let permit = guard.commit();

        let (cmd, _, _) = read_frame(&mut server_end).await.unwrap();
        assert_eq!(cmd, CMD_SYN);
        let (cmd, _, _) = read_frame(&mut server_end).await.unwrap();
        assert_eq!(cmd, CMD_PSH);
        (
            Arc::new(AnyTlsUotTransport {
                session,
                sid,
                receive: tokio::sync::Mutex::new(UotReceiveState::new(rx)),
                setup: tokio::sync::Mutex::new(Some(
                    crate::proxy::uot::connect_request(target, None).unwrap(),
                )),
                target,
                target_domain: None,
                _permit: permit,
            }),
            server_end,
        )
    }

    /// The UoT request and first datagram share one PSH; later datagrams carry
    /// only their length-prefixed payload.
    #[tokio::test]
    async fn uot_transport_frame_roundtrip() {
        let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let request = crate::proxy::uot::connect_request(target, None).unwrap();
        let (transport, mut server) = uot_test_transport(target).await;

        transport.send_packet(b"dns-packet").await.unwrap();
        let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
        assert_eq!(cmd, CMD_PSH);
        assert_eq!(&data[..request.len()], request.as_ref());
        assert_eq!(
            u16::from_be_bytes([data[request.len()], data[request.len() + 1]]),
            10
        );
        assert_eq!(&data[request.len() + 2..], b"dns-packet");

        transport.send_packet(b"next").await.unwrap();
        let (cmd, next_sid, data) = read_frame(&mut server).await.unwrap();
        assert_eq!((cmd, next_sid), (CMD_PSH, sid));
        assert_eq!(data, [&4u16.to_be_bytes()[..], b"next"].concat());

        let mut frame = Vec::new();
        frame.extend_from_slice(&5u16.to_be_bytes());
        frame.extend_from_slice(b"pong!");
        write_frame(&mut server, CMD_PSH, sid, &frame)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong!");
        assert_eq!(src, target);
    }

    #[tokio::test]
    async fn confirmed_uot_send_waits_for_physical_flush() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let request = crate::proxy::uot::connect_request(target, None).unwrap();
        let (transport, mut server) = uot_test_transport_with_capacity(target, 64).await;
        let payload = vec![0x5a; 256];
        let send = transport.send_packet_confirmed(&payload);
        tokio::pin!(send);

        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut send)
                .await
                .is_err(),
            "confirmation must wait while the physical writer is blocked"
        );
        let (sent, frame) = tokio::join!(&mut send, read_frame(&mut server));
        sent.unwrap();
        let (cmd, sid, data) = frame.unwrap();
        assert_eq!((cmd, sid), (CMD_PSH, transport.sid));
        let packet = &data[request.len()..];
        assert_eq!(
            u16::from_be_bytes([packet[0], packet[1]]) as usize,
            payload.len()
        );
        assert_eq!(&packet[2..], payload);
    }

    #[tokio::test]
    async fn uot_send_enforces_anytls_go_packet_limit_without_poisoning_stream() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let request = crate::proxy::uot::connect_request(target, None).unwrap();
        let (transport, mut server) = uot_test_transport(target).await;
        let payload = vec![0x5a; UOT_MAX_PACKET_SIZE];

        transport.send_packet(&payload).await.unwrap();
        let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
        assert_eq!((cmd, sid), (CMD_PSH, transport.sid));
        assert_eq!(&data[..request.len()], request.as_ref());
        assert_eq!(
            u16::from_be_bytes([data[request.len()], data[request.len() + 1]]) as usize,
            payload.len()
        );
        assert_eq!(&data[request.len() + 2..], payload);

        let error = transport
            .send_packet(&vec![0; UOT_MAX_PACKET_SIZE + 1])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

        transport.send_packet(b"kept").await.unwrap();
        let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
        assert_eq!(
            (cmd, sid, data.as_slice()),
            (CMD_PSH, transport.sid, &b"\0\x04kept"[..])
        );
    }

    #[tokio::test]
    async fn cancelled_first_uot_send_preserves_lazy_setup() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let request = crate::proxy::uot::connect_request(target, None).unwrap();
        let (transport, mut server) = uot_test_transport(target).await;
        let capacity = (WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED) as u32;
        let held = Arc::clone(&transport.session.writer_q.data_permits)
            .acquire_many_owned(capacity)
            .await
            .unwrap();

        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                transport.send_packet_confirmed(b"cancelled"),
            )
            .await
            .is_err()
        );
        drop(held);

        transport.send_packet_confirmed(b"kept").await.unwrap();
        let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
        assert_eq!((cmd, sid), (CMD_PSH, transport.sid));
        assert_eq!(&data[..request.len()], request.as_ref());
        assert_eq!(&data[request.len()..], b"\0\x04kept");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), read_frame(&mut server))
                .await
                .is_err(),
            "the cancelled datagram must not be queued"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_anytls_writer_becomes_terminal() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let (transport, _server) = uot_test_transport_with_capacity(target, 64).await;
        let session = Arc::clone(&transport.session);
        let send =
            tokio::spawn(async move { transport.send_packet_confirmed(&vec![0x5a; 256]).await });
        tokio::task::yield_now().await;
        tokio::time::advance(WRITER_IO_TIMEOUT + Duration::from_millis(1)).await;
        let error = send.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        tokio::task::yield_now().await;
        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn uot_transport_reassembles_datagram_across_anytls_frames() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let (transport, mut server) = uot_test_transport(target).await;
        let sid = transport.sid;
        let mut frame = Vec::new();
        frame.extend_from_slice(&12u16.to_be_bytes());
        frame.extend_from_slice(b"quic-initial");

        write_frame(&mut server, CMD_PSH, sid, &frame[..1])
            .await
            .unwrap();
        write_frame(&mut server, CMD_PSH, sid, &frame[1..5])
            .await
            .unwrap();
        write_frame(&mut server, CMD_PSH, sid, &frame[5..])
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let (n, source) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"quic-initial");
        assert_eq!(source, target);
    }

    #[tokio::test]
    async fn uot_v1_max_domain_frame_survives_valid_chunking() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let (mut transport, mut server) = uot_test_transport(target).await;
        let domain = "d".repeat(u8::MAX as usize);
        Arc::get_mut(&mut transport).unwrap().target_domain = Some(domain.clone());
        let sid = transport.sid;

        let mut stream = Vec::with_capacity(UOT_MAX_BUFFERED_BYTES);
        stream.push(UOT_V1_ATYP_DOMAIN);
        stream.push(u8::MAX);
        stream.extend_from_slice(domain.as_bytes());
        stream.extend_from_slice(&target.port().to_be_bytes());
        stream.extend_from_slice(&u16::MAX.to_be_bytes());
        stream.extend(std::iter::repeat_n(0x5a, u16::MAX as usize));
        let first_frame_end = stream.len();
        stream.extend(std::iter::repeat_n(0, u16::MAX as usize - 1));
        assert_eq!(stream.len(), UOT_MAX_BUFFERED_BYTES);

        for chunk in [
            &stream[..32_768],
            &stream[32_768..first_frame_end - 1],
            &stream[first_frame_end - 1..],
        ] {
            write_frame(&mut server, CMD_PSH, sid, chunk).await.unwrap();
        }

        let mut packet = vec![0; u16::MAX as usize];
        let (received, source) = transport.recv_packet(&mut packet).await.unwrap();
        assert_eq!(received, packet.len());
        assert!(packet.iter().all(|byte| *byte == 0x5a));
        assert_eq!(source, target);
    }

    #[tokio::test]
    async fn uot_transport_preserves_coalesced_datagrams() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let (transport, mut server) = uot_test_transport(target).await;
        let sid = transport.sid;
        let mut frame = Vec::new();
        for payload in [b"server-initial".as_slice(), b"server-handshake".as_slice()] {
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            frame.extend_from_slice(payload);
        }
        write_frame(&mut server, CMD_PSH, sid, &frame)
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let (first, _) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..first], b"server-initial");
        let (second, _) =
            tokio::time::timeout(Duration::from_millis(100), transport.recv_packet(&mut buf))
                .await
                .expect("coalesced second datagram must already be buffered")
                .unwrap();
        assert_eq!(&buf[..second], b"server-handshake");
    }

    /// A stalled UoT consumer retires its sid instead of silently dropping a
    /// chunk from the length-delimited receive stream.
    #[tokio::test]
    async fn uot_transport_saturation_retires_stream() {
        let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let (transport, mut server) = uot_test_transport(target).await;
        let sid = transport.sid;

        let mut frame = Vec::new();
        frame.extend_from_slice(&5u16.to_be_bytes());
        frame.extend_from_slice(b"flood");
        for _ in 0..(UOT_DRAIN_QUEUE_CAP * 4) {
            write_frame(&mut server, CMD_PSH, sid, &frame)
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while transport.session.streams.lock().unwrap().contains_key(&sid) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("saturated UoT sid must retire");
        assert!(!transport.session.is_closed());
        let error = transport.send_packet(b"ping").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        let (cmd, fin_sid, _) = read_frame(&mut server).await.unwrap();
        assert_eq!((cmd, fin_sid), (CMD_FIN, sid));
    }
}
