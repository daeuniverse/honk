use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::addr::{self, AtypScheme};

pub(crate) const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
pub(crate) const MAX_PACKET_SIZE: usize = u16::MAX as usize;
#[cfg(any(feature = "rprx", test))]
const MAX_BUFFERED_BYTES: usize = 2 * (2 + MAX_PACKET_SIZE);
/// ATYP + length + 255-byte domain + port: the widest per-datagram address.
#[cfg(any(feature = "rprx", test))]
pub(crate) const MAX_ADDR_LEN: usize = 1 + 1 + u8::MAX as usize + 2;
#[cfg(any(feature = "rprx", test))]
const MAX_ADDR_BUFFERED_BYTES: usize = 2 * (MAX_ADDR_LEN + 2 + MAX_PACKET_SIZE);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct UotFramingError(&'static str);

/// Per-datagram addressed framing `[ATYP][address][port][u16 len][payload]`,
/// shared by non-connect UoT v2 (UoT v1 ATYPs: IPv4=0, IPv6=1, domain=2) and
/// sing-mux PacketAddr (SOCKS5 ATYPs). The v2 request address is SOCKS5-encoded
/// either way.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AddrFraming(AtypScheme);

impl AddrFraming {
    pub(crate) const UOT_V1: Self = Self(AtypScheme {
        ipv4: 0x00,
        domain: 0x02,
        ipv6: 0x01,
    });
    pub(crate) const SOCKS5: Self = Self(addr::ATYP_SOCKS5);

    fn header(self, data: &[u8]) -> io::Result<Option<(usize, usize)>> {
        let Some(&atyp) = data.first() else {
            return Ok(None);
        };
        let scheme = self.0;
        let address_len = if atyp == scheme.ipv4 {
            4
        } else if atyp == scheme.ipv6 {
            16
        } else if atyp == scheme.domain {
            let Some(length) = data.get(1) else {
                return Ok(None);
            };
            1 + usize::from(*length)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                UotFramingError("invalid UoT packet address type"),
            ));
        };
        let payload_start = 1 + address_len + 2 + 2;
        if data.len() < payload_start {
            return Ok(None);
        }
        let length_at = payload_start - 2;
        let payload_len = u16::from_be_bytes([data[length_at], data[length_at + 1]]) as usize;
        Ok(Some((payload_start, payload_len)))
    }

    pub(crate) fn frame_bounds(self, data: &[u8]) -> io::Result<Option<FrameBounds>> {
        let Some((payload_start, payload_len)) = self.header(data)? else {
            return Ok(None);
        };
        let frame_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid UoT datagram"))?;
        Ok((data.len() >= frame_end).then_some(FrameBounds {
            payload_start,
            frame_end,
        }))
    }

    /// Encode `prefix` (a pending request, or empty) followed by one packet
    /// into a single buffer.
    pub(crate) fn encode(
        self,
        prefix: &[u8],
        target: SocketAddr,
        target_domain: Option<&str>,
        data: &[u8],
        max_payload: usize,
    ) -> io::Result<Bytes> {
        self.encode_after(0, prefix, target, target_domain, data, max_payload)
            .map(BytesMut::freeze)
    }

    /// [`Self::encode`] after `headroom` zero bytes the caller fills with its
    /// own header, so the packet is copied once into its final buffer.
    pub(crate) fn encode_after(
        self,
        headroom: usize,
        prefix: &[u8],
        target: SocketAddr,
        target_domain: Option<&str>,
        data: &[u8],
        max_payload: usize,
    ) -> io::Result<BytesMut> {
        validate_packet_len(data, max_payload)?;
        if target_domain
            .is_some_and(|domain| domain.is_empty() || domain.len() > usize::from(u8::MAX))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy target domain must contain 1..=255 bytes",
            ));
        }
        let scheme = self.0;
        let address_len = match (target_domain, target) {
            (Some(domain), _) => 1 + domain.len(),
            (None, SocketAddr::V4(_)) => 4,
            (None, SocketAddr::V6(_)) => 16,
        };
        let mut frame =
            BytesMut::with_capacity(headroom + prefix.len() + 1 + address_len + 2 + 2 + data.len());
        frame.put_bytes(0, headroom);
        frame.extend_from_slice(prefix);
        match (target_domain, target) {
            (Some(domain), _) => {
                frame.put_u8(scheme.domain);
                frame.put_u8(domain.len() as u8);
                frame.extend_from_slice(domain.as_bytes());
            }
            (None, SocketAddr::V4(target)) => {
                frame.put_u8(scheme.ipv4);
                frame.extend_from_slice(&target.ip().octets());
            }
            (None, SocketAddr::V6(target)) => {
                frame.put_u8(scheme.ipv6);
                frame.extend_from_slice(&target.ip().octets());
            }
        }
        frame.put_u16(target.port());
        frame.put_u16(data.len() as u16);
        frame.extend_from_slice(data);
        Ok(frame)
    }

    /// Real peer of a validated frame whose bytes up to the payload are
    /// `header`. Numeric peers are returned (IPv4-mapped IPv6 as IPv4); a
    /// domain is accepted only when it is the captured `target_domain` and
    /// port, then projected to `target`. Anything else is `None`: the caller
    /// drops the frame without resolving the name.
    pub(crate) fn source(
        self,
        header: &[u8],
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> Option<SocketAddr> {
        let port_at = header.len() - 4;
        let port = u16::from_be_bytes([header[port_at], header[port_at + 1]]);
        let atyp = header[0];
        if atyp == self.0.ipv4 {
            let ip: [u8; 4] = header[1..5].try_into().ok()?;
            Some(SocketAddr::new(Ipv4Addr::from(ip).into(), port))
        } else if atyp == self.0.ipv6 {
            let ip: [u8; 16] = header[1..17].try_into().ok()?;
            Some(SocketAddr::new(
                std::net::Ipv6Addr::from(ip).to_canonical(),
                port,
            ))
        } else {
            crate::proxy::addr::dialed_domain_peer(target_domain, target, &header[2..port_at], port)
        }
    }

    /// One complete addressed frame taken off the front of `buffered`. An
    /// unknown ATYP is terminal (no derivable length). A frame whose source is
    /// unprojectable is consumed whole so the next one still decodes; a
    /// delivered frame that does not fit `output` stays buffered.
    pub(crate) fn take_frame(
        self,
        buffered: &mut BytesMut,
        output: &mut [u8],
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> io::Result<Option<AddrFrame>> {
        let Some(frame) = self.frame_bounds(buffered)? else {
            return Ok(None);
        };
        let packet = match self.source(&buffered[..frame.payload_start], target, target_domain) {
            Some(source) => Some((copy_frame(buffered, frame, output)?, source)),
            None => {
                buffered.advance(frame.frame_end);
                None
            }
        };
        Ok(Some(AddrFrame {
            wire_len: frame.frame_end,
            packet,
        }))
    }
}

/// `connect` is the UoT v2 `isConnect` bit: a connected stream carries bare
/// `[u16 length][payload]` packets, otherwise every packet carries its own
/// address ([`AddrFraming`]) in both directions. The request address is
/// SOCKS5-encoded either way.
pub(crate) fn request(
    connect: bool,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> io::Result<Bytes> {
    let mut request = vec![u8::from(connect)];
    request.extend(addr::encode_address(target, target_domain)?);
    Ok(Bytes::from(request))
}

#[cfg(any(feature = "rprx", test))]
pub(crate) fn encode_packet(data: &[u8], max_payload: usize) -> io::Result<Bytes> {
    validate_packet_len(data, max_payload)?;
    let mut frame = BytesMut::with_capacity(2 + data.len());
    frame.put_u16(data.len() as u16);
    frame.extend_from_slice(data);
    Ok(frame.freeze())
}

pub(crate) fn validate_packet_len(data: &[u8], max_payload: usize) -> io::Result<()> {
    if data.len() > max_payload.min(MAX_PACKET_SIZE) {
        return Err(super::PacketRejection::InvalidSize.into());
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct FrameBounds {
    pub(crate) payload_start: usize,
    pub(crate) frame_end: usize,
}

/// Bounds of one connected `[u16 length][payload]` frame.
#[cfg(any(feature = "rprx", test))]
fn connected_frame_bounds(data: &[u8]) -> Option<FrameBounds> {
    if data.len() < 2 {
        return None;
    }
    let frame_end = 2 + usize::from(u16::from_be_bytes([data[0], data[1]]));
    (data.len() >= frame_end).then_some(FrameBounds {
        payload_start: 2,
        frame_end,
    })
}

pub(crate) fn copy_frame(
    buffered: &mut BytesMut,
    frame: FrameBounds,
    output: &mut [u8],
) -> io::Result<usize> {
    let payload_len = frame.frame_end - frame.payload_start;
    if payload_len > output.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UoT datagram exceeds buffer",
        ));
    }
    output[..payload_len].copy_from_slice(&buffered[frame.payload_start..frame.frame_end]);
    buffered.advance(frame.frame_end);
    Ok(payload_len)
}

#[cfg(any(feature = "rprx", test))]
#[derive(Default)]
pub(crate) struct Decoder {
    buffered: BytesMut,
}

#[cfg(any(feature = "rprx", test))]
impl Decoder {
    pub(crate) fn push(&mut self, data: &[u8]) -> io::Result<()> {
        if self.buffered.len().saturating_add(data.len()) > MAX_BUFFERED_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UoT stream frame exceeds buffer limit",
            ));
        }
        self.buffered.extend_from_slice(data);
        Ok(())
    }

    pub(crate) fn next_packet(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(frame) = connected_frame_bounds(&self.buffered) else {
            return Ok(None);
        };
        copy_frame(&mut self.buffered, frame, output).map(Some)
    }
}

/// One complete addressed frame taken off a buffer by [`AddrFraming::take_frame`].
pub(crate) struct AddrFrame {
    /// Wire bytes the frame occupied, delivered or dropped.
    pub(crate) wire_len: usize,
    /// Payload length and real peer; `None` when the source was unprojectable
    /// and the whole frame was dropped.
    pub(crate) packet: Option<(usize, SocketAddr)>,
}

#[cfg(any(feature = "rprx", test))]
pub(crate) struct AddrDecoder {
    buffered: BytesMut,
    framing: AddrFraming,
}

#[cfg(any(feature = "rprx", test))]
impl AddrDecoder {
    pub(crate) fn new(framing: AddrFraming) -> Self {
        Self {
            buffered: BytesMut::new(),
            framing,
        }
    }

    pub(crate) fn push(&mut self, data: &[u8]) -> io::Result<()> {
        if self.buffered.len().saturating_add(data.len()) > MAX_ADDR_BUFFERED_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                UotFramingError("UoT stream frame exceeds buffer limit"),
            ));
        }
        self.buffered.extend_from_slice(data);
        Ok(())
    }

    pub(crate) fn next_packet(
        &mut self,
        output: &mut [u8],
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> io::Result<Option<AddrFrame>> {
        self.framing
            .take_frame(&mut self.buffered, output, target, target_domain)
    }
}

#[cfg(any(feature = "rprx", test))]
pub(in crate::proxy) use stream::StreamUotTransport;

#[cfg(any(feature = "rprx", test))]
mod stream {
    use super::*;
    use crate::proxy::chain::UdpExit;
    use crate::proxy::error::HopIoFailure;
    use crate::proxy::{
        AsyncReadWrite, FramePoison, MultiTargetTransport, NodeFailure, PacketRejection,
        PacketTransport,
    };
    use crate::runtime::flow_observation::request_write;
    use async_trait::async_trait;
    use std::sync::atomic::AtomicBool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
    use tokio::sync::Mutex;

    type Stream = Box<dyn AsyncReadWrite>;

    /// A non-connect UoT v2 association. The request precedes the first datagram;
    /// all datagrams carry their own address, including replies from other peers.
    pub(in crate::proxy) struct StreamUotTransport {
        reader: Mutex<(ReadHalf<Stream>, AddrDecoder)>,
        writer: Mutex<(WriteHalf<Stream>, Bytes)>,
        poison: FramePoison,
        target: SocketAddr,
        target_domain: Option<Box<str>>,
        tls_handoff: Option<bool>,
        exit: Option<UdpExit>,
    }

    impl StreamUotTransport {
        pub(in crate::proxy) fn new(
            stream: Stream,
            target: SocketAddr,
            target_domain: Option<Box<str>>,
            request: Bytes,
            native_tls_handoff: Option<bool>,
            exit: Option<UdpExit>,
        ) -> Self {
            let (reader, writer) = tokio::io::split(stream);
            Self {
                reader: Mutex::new((reader, AddrDecoder::new(AddrFraming::UOT_V1))),
                writer: Mutex::new((writer, request)),
                poison: FramePoison::default(),
                target,
                target_domain,
                tls_handoff: exit.map(|exit| exit.tls_handoff).or(native_tls_handoff),
                exit,
            }
        }

        async fn send_inner(
            &self,
            target: SocketAddr,
            domain: Option<&str>,
            data: &[u8],
            confirmed: bool,
            admitted: Option<&AtomicBool>,
            current: Option<&(dyn Fn() -> bool + Send + Sync)>,
        ) -> io::Result<()> {
            let mut writer = self.writer.lock().await;
            let (stream, setup) = &mut *writer;
            let frame = AddrFraming::UOT_V1.encode(setup, target, domain, data, MAX_PACKET_SIZE)?;
            let write = async {
                if let Some(current) = current {
                    let tls_handoff = self.tls_handoff.ok_or(PacketRejection::Policy)?;
                    return self
                        .poison
                        .write_checked(stream, &frame, admitted, tls_handoff, current)
                        .await;
                }
                let guard = self.poison.begin(admitted)?;
                stream.write_all(&frame).await?;
                stream.flush().await?;
                guard.complete();
                Ok(())
            };
            if confirmed {
                request_write(std::pin::pin!(write)).await?;
            } else {
                write.await?;
            }
            // A withdrawn first send leaves the request available to the next view.
            *setup = Bytes::new();
            Ok(())
        }

        fn framing_error(&self, error: io::Error) -> io::Error {
            if let Some(exit) = self.exit
                && error
                    .get_ref()
                    .is_some_and(|cause| cause.is::<UotFramingError>())
            {
                let error = io::Error::new(error.kind(), NodeFailure(error.into()));
                return HopIoFailure::io(exit.index, error, false);
            }
            error
        }
    }

    impl std::fmt::Debug for StreamUotTransport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("StreamUotTransport")
                .field("target", &self.target)
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl PacketTransport for StreamUotTransport {
        fn relay_addr(&self) -> SocketAddr {
            self.target
        }

        fn allows_full_cone_replies(&self) -> bool {
            true
        }

        async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
            self.send_inner(
                self.target,
                self.target_domain.as_deref(),
                data,
                false,
                None,
                None,
            )
            .await
        }

        async fn send_packet_confirmed(&self, data: &[u8]) -> io::Result<()> {
            self.send_inner(
                self.target,
                self.target_domain.as_deref(),
                data,
                true,
                None,
                None,
            )
            .await
        }

        async fn send_packet_checked(
            &self,
            data: &[u8],
            current: &(dyn Fn() -> bool + Send + Sync),
        ) -> io::Result<()> {
            self.send_inner(
                self.target,
                self.target_domain.as_deref(),
                data,
                true,
                None,
                Some(current),
            )
            .await
        }

        async fn recv_packet(&self, output: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let mut reader = self.reader.lock().await;
            let (stream, decoder) = &mut *reader;
            loop {
                if let Some(frame) = decoder
                    .next_packet(output, self.target, self.target_domain.as_deref())
                    .map_err(|e| self.framing_error(e))?
                {
                    if let Some(packet) = frame.packet {
                        return Ok(packet);
                    }
                    continue;
                }
                let mut chunk = [0; 16 * 1024];
                let size = stream.read(&mut chunk).await?;
                if size == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                decoder
                    .push(&chunk[..size])
                    .map_err(|e| self.framing_error(e))?;
            }
        }
    }

    #[async_trait]
    impl MultiTargetTransport for StreamUotTransport {
        async fn send_to(
            &self,
            target: SocketAddr,
            domain: Option<&str>,
            data: &[u8],
            confirmed: bool,
            admitted: Option<&AtomicBool>,
        ) -> io::Result<()> {
            let domain = addr::dialed_name(self.target_domain.as_deref(), domain);
            self.send_inner(target, domain, data, confirmed, admitted, None)
                .await
        }

        async fn send_to_checked(
            &self,
            target: SocketAddr,
            domain: Option<&str>,
            data: &[u8],
            admitted: Option<&AtomicBool>,
            current: &(dyn Fn() -> bool + Send + Sync),
        ) -> io::Result<()> {
            let domain = addr::dialed_name(self.target_domain.as_deref(), domain);
            self.send_inner(target, domain, data, true, admitted, Some(current))
                .await
        }

        fn frame_stream_torn(&self) -> bool {
            self.poison.is_set()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::chain::UdpExit;
    use crate::proxy::error::{HopIoFailure, io_node_failure};
    use crate::proxy::{
        AsyncReadWrite, DialFailureScope, NodeFailure, PacketRejection, PacketTransport,
        dial_failure_scope, io_packet_rejection, is_frame_interrupted,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn exit_transport(stream: impl AsyncReadWrite + 'static) -> StreamUotTransport {
        let target = SocketAddr::from(([192, 0, 2, 1], 53));
        StreamUotTransport::new(
            Box::new(stream),
            target,
            None,
            request(false, target, None).unwrap(),
            None,
            Some(UdpExit {
                index: 1,
                tls_handoff: false,
            }),
        )
    }

    #[tokio::test]
    async fn checked_packet_preserves_setup_and_fences_partial_writes() {
        use std::sync::atomic::{AtomicBool, Ordering};

        const FIRST: &[u8] = &[
            0, 1, 192, 0, 2, 1, 0, 53, 0, 192, 0, 2, 1, 0, 53, 0, 1, b'x',
        ];
        for (free, interrupt) in [(0, false), (1, false), (1, true)] {
            let (mut stream, mut peer) = tokio::io::duplex(32);
            stream.write_all(&[0; 32][free..]).await.unwrap();
            let transport = exit_transport(stream);
            let current = AtomicBool::new(true);
            let allowed = || current.load(Ordering::Relaxed);
            let mut send = transport.send_packet_checked(b"x", &allowed);
            assert!(futures_util::poll!(send.as_mut()).is_pending());
            current.store(false, Ordering::Relaxed);
            if interrupt {
                drop(send);
                let error = transport.send_packet(b"y").await.unwrap_err();
                assert!(is_frame_interrupted(&error));
                continue;
            }
            peer.read_exact(&mut [0; 32][free..]).await.unwrap();
            if free == 0 {
                assert_eq!(
                    io_packet_rejection(&send.await.unwrap_err()),
                    Some(PacketRejection::Cancelled)
                );
                transport.send_packet_checked(b"x", &|| true).await.unwrap();
            } else {
                send.await.unwrap();
            }
            let mut frame = [0; FIRST.len()];
            peer.read_exact(&mut frame).await.unwrap();
            assert_eq!(frame, FIRST);
        }
    }

    #[tokio::test]
    async fn only_wire_framing_faults_belong_to_the_exit() {
        let (stream, mut peer) = tokio::io::duplex(32);
        let transport = exit_transport(stream);
        peer.write_all(&[0, 192, 0, 2, 7, 0, 53, 0, 1, b'x', 0xff])
            .await
            .unwrap();
        let short = transport.recv_packet(&mut []).await.unwrap_err();
        assert_eq!(short.kind(), io::ErrorKind::InvalidData);
        assert_eq!(dial_failure_scope(&short), DialFailureScope::Unattributed);
        assert!(!io_node_failure(&short));
        let mut data = [0];
        assert_eq!(
            transport.recv_packet(&mut data).await.unwrap(),
            (1, SocketAddr::from(([192, 0, 2, 7], 53)))
        );
        assert_eq!(&data, b"x");
        let invalid = transport.recv_packet(&mut data).await.unwrap_err();
        assert_eq!(dial_failure_scope(&invalid), DialFailureScope::Hop(1));
        assert!(io_node_failure(&invalid));
    }

    #[tokio::test]
    async fn carrier_read_failure_keeps_its_original_hop() {
        #[derive(Debug)]
        struct FailedRead;
        impl tokio::io::AsyncRead for FailedRead {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                let cause = io::Error::other(NodeFailure(anyhow::anyhow!("entry failure")));
                std::task::Poll::Ready(Err(HopIoFailure::io(0, cause, false)))
            }
        }
        let transport = exit_transport(tokio::io::join(FailedRead, tokio::io::sink()));
        let error = transport.recv_packet(&mut [0]).await.unwrap_err();
        assert_eq!(dial_failure_scope(&error), DialFailureScope::Hop(0));
        assert!(io_node_failure(&error));
    }

    #[test]
    fn request_rejects_overlong_domain() {
        let target = "127.0.0.1:53".parse().unwrap();
        assert!(request(true, target, Some(&"a".repeat(255))).is_ok());
        let error = request(true, target, Some(&"a".repeat(256))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn request_mode_byte_and_socks_address() {
        let target = "192.0.2.7:5353".parse().unwrap();
        assert_eq!(
            request(true, target, None).unwrap().as_ref(),
            [1, 1, 192, 0, 2, 7, 0x14, 0xe9]
        );
        assert_eq!(
            request(false, target, Some("a.b")).unwrap().as_ref(),
            [0, 3, 3, b'a', b'.', b'b', 0x14, 0xe9]
        );
    }

    #[test]
    fn codec_supports_full_packets_and_preserves_short_buffer_frames() {
        let payload = vec![0x5a; MAX_PACKET_SIZE];
        let frame = encode_packet(&payload, MAX_PACKET_SIZE).unwrap();
        assert!(encode_packet(&[0; 1], 0).is_err());

        let mut decoder = Decoder::default();
        decoder.push(&frame[..123]).unwrap();
        assert!(decoder.next_packet(&mut []).unwrap().is_none());
        decoder.push(&frame[123..]).unwrap();
        assert!(decoder.next_packet(&mut [0; 1]).is_err());

        let mut output = vec![0; MAX_PACKET_SIZE];
        assert_eq!(
            decoder.next_packet(&mut output).unwrap(),
            Some(MAX_PACKET_SIZE)
        );
        assert_eq!(output, payload);
    }

    #[test]
    fn decoder_preserves_coalesced_packets() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_packet(b"first", MAX_PACKET_SIZE).unwrap());
        wire.extend_from_slice(&encode_packet(b"second", MAX_PACKET_SIZE).unwrap());
        let mut decoder = Decoder::default();
        decoder.push(&wire).unwrap();
        let mut output = [0; 8];
        assert_eq!(decoder.next_packet(&mut output).unwrap(), Some(5));
        assert_eq!(&output[..5], b"first");
        assert_eq!(decoder.next_packet(&mut output).unwrap(), Some(6));
        assert_eq!(&output[..6], b"second");
    }

    #[test]
    fn v1_and_v2_share_the_bounded_codec_contract() {
        let v1 = [0x00, 1, 2, 3, 4, 0, 53, 0, 3, b'a', b'b', b'c'];
        assert!(
            AddrFraming::UOT_V1
                .frame_bounds(&v1[..11])
                .unwrap()
                .is_none()
        );
        let bounds = AddrFraming::UOT_V1.frame_bounds(&v1).unwrap().unwrap();
        assert_eq!(bounds.payload_start, 9);
        assert_eq!(bounds.frame_end, 12);
        assert!(AddrFraming::UOT_V1.frame_bounds(&[0xff]).is_err());

        let v2 = encode_packet(b"abc", MAX_PACKET_SIZE).unwrap();
        let bounds = connected_frame_bounds(&v2).unwrap();
        assert_eq!(bounds.payload_start, 2);
        assert_eq!(bounds.frame_end, 5);
    }
}
